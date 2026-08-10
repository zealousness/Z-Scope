#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  ./install.sh --profile cpp|java|all --asset-dir DIR [--prefix DIR]
  ./install.sh --rollback VERSION [--prefix DIR]

Installs only into user-owned directories. It never edits shell profiles or
system Python. Place the app archive, selected dependency archives,
SHA256SUMS, and optional SHA256SUMS.sig/public-key.pem in one asset directory.
EOF
}

profile=""
asset_dir=""
prefix="${Z_SCOPE_HOME:-${HOME}/.local/share/zscope}"
rollback=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --profile) profile="${2:-}"; shift 2 ;;
    --asset-dir) asset_dir="${2:-}"; shift 2 ;;
    --prefix) prefix="${2:-}"; shift 2 ;;
    --rollback) rollback="${2:-}"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
done

prefix="$(mkdir -p "${prefix}" && cd "${prefix}" && pwd -P)"
case "${prefix}" in
  /|/opt|/usr|/etc|/var) echo "Refusing system-wide prefix: ${prefix}" >&2; exit 2 ;;
esac

if [[ -n "${rollback}" ]]; then
  target="${prefix}/releases/${rollback}"
  [[ -d "${target}" ]] || { echo "Release not installed: ${rollback}" >&2; exit 1; }
  tmp_link="${prefix}/.current-${$}"
  ln -s "releases/${rollback}" "${tmp_link}"
  mv -Tf "${tmp_link}" "${prefix}/current"
  echo "Rolled back Z-SCOPE to ${rollback}"
  exit 0
fi

case "${profile}" in cpp|java|all) ;; *) echo "--profile must be cpp, java, or all" >&2; exit 2 ;; esac
[[ -n "${asset_dir}" ]] || { echo "--asset-dir is required" >&2; exit 2; }
asset_dir="$(cd "${asset_dir}" && pwd -P)"
[[ -f "${asset_dir}/SHA256SUMS" ]] || { echo "Missing SHA256SUMS" >&2; exit 1; }

[[ -f "${asset_dir}/SHA256SUMS.sig" ]] || { echo "Missing SHA256SUMS.sig" >&2; exit 1; }
[[ -f "${asset_dir}/public-key.pem" ]] || { echo "Missing public-key.pem" >&2; exit 1; }
command -v openssl >/dev/null || { echo "openssl is required to verify release signature" >&2; exit 1; }
openssl dgst -sha256 -verify "${asset_dir}/public-key.pem" \
  -signature "${asset_dir}/SHA256SUMS.sig" "${asset_dir}/SHA256SUMS"

(cd "${asset_dir}" && sha256sum --check --strict SHA256SUMS)
command -v tar >/dev/null || { echo "tar is required" >&2; exit 1; }
command -v zstd >/dev/null || { echo "zstd is required to extract .tar.zst assets" >&2; exit 1; }

shopt -s nullglob
app_assets=("${asset_dir}"/zscope-app-*-linux-x86_64.tar.zst)
[[ ${#app_assets[@]} -eq 1 ]] || { echo "Expected exactly one zscope-app archive" >&2; exit 1; }
app_name="$(basename "${app_assets[0]}")"
version="${app_name#zscope-app-}"
version="${version%-linux-x86_64.tar.zst}"
[[ "${version}" =~ ^[0-9]+\.[0-9]+\.[0-9]+([+-][0-9A-Za-z.-]+)?$ ]] || {
  echo "Unable to determine SemVer from ${app_name}" >&2; exit 1;
}

required=("${app_assets[0]}")
if [[ "${profile}" == "cpp" || "${profile}" == "all" ]]; then
  cpp_assets=("${asset_dir}"/zscope-deps-cpp-*-linux-x86_64.tar.zst)
  [[ ${#cpp_assets[@]} -eq 1 ]] || { echo "Expected exactly one C/C++ dependency archive" >&2; exit 1; }
  required+=("${cpp_assets[0]}")
fi
if [[ "${profile}" == "java" || "${profile}" == "all" ]]; then
  java_assets=("${asset_dir}"/zscope-deps-java-*-linux-x86_64.tar.zst)
  [[ ${#java_assets[@]} -eq 1 ]] || { echo "Expected exactly one Java dependency archive" >&2; exit 1; }
  required+=("${java_assets[0]}")
fi

staging="${prefix}/releases/.staging-${version}-${$}"
release_dir="${prefix}/releases/${version}"
cleanup() { [[ -d "${staging}" ]] && rm -rf -- "${staging}"; }
trap cleanup EXIT
mkdir -p "${staging}" "${prefix}/deps" "${HOME}/.local/bin" "${HOME}/.config/zscope" "${HOME}/.cache/zscope"

tar --zstd -xf "${app_assets[0]}" -C "${staging}"
for archive in "${required[@]:1}"; do
  name="$(basename "${archive}")"
  if [[ "${name}" == zscope-deps-cpp-* ]]; then language="cpp"; else language="java"; fi
  toolset="${name#zscope-deps-${language}-}"
  toolset="${toolset%-linux-x86_64.tar.zst}"
  dep_stage="${prefix}/deps/${language}/.staging-${toolset}-${$}"
  dep_target="${prefix}/deps/${language}/${toolset}"
  mkdir -p "${dep_stage}"
  tar --zstd -xf "${archive}" -C "${dep_stage}"
  if [[ ! -e "${dep_target}" ]]; then mv "${dep_stage}" "${dep_target}"; else rm -rf -- "${dep_stage}"; fi
  ln -sfn "${dep_target}" "${staging}/deps-${language}"
done

[[ -x "${staging}/runtime/bin/python3" ]] || { echo "App archive lacks runtime/bin/python3" >&2; exit 1; }
[[ -d "${staging}/wheelhouse" ]] || { echo "App archive lacks wheelhouse" >&2; exit 1; }
"${staging}/runtime/bin/python3" -m venv --without-pip "${staging}/venv"
install_requirement="zscope"
if [[ "${profile}" == "java" || "${profile}" == "all" ]]; then
  install_requirement="zscope[java]"
fi
"${staging}/runtime/bin/python3" "${staging}/bootstrap/pip.pyz" \
  --python "${staging}/venv/bin/python" install --no-index --find-links "${staging}/wheelhouse" \
  "${install_requirement}"
"${staging}/venv/bin/python" -m pip check

cat >"${staging}/zscope-launcher" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
launcher_path="$(readlink -f "${BASH_SOURCE[0]}")"
release_root="$(cd "$(dirname "${launcher_path}")" && pwd -P)"
export Z_SCOPE_CONFIG_HOME="${Z_SCOPE_CONFIG_HOME:-${HOME}/.config/zscope}"
export Z_SCOPE_CACHE_HOME="${Z_SCOPE_CACHE_HOME:-${HOME}/.cache/zscope}"
path_parts=()
[[ -d "${release_root}/deps-cpp/bin" ]] && path_parts+=("${release_root}/deps-cpp/bin")
[[ -d "${release_root}/deps-java/bin" ]] && path_parts+=("${release_root}/deps-java/bin")
if [[ ${#path_parts[@]} -gt 0 ]]; then export PATH="$(IFS=:; echo "${path_parts[*]}"):${PATH}"; fi
exec "${release_root}/venv/bin/zscope" "$@"
EOF
chmod 0755 "${staging}/zscope-launcher"

if [[ -e "${release_dir}" ]]; then
  echo "Release ${version} is already installed; verifying and switching current" >&2
  rm -rf -- "${staging}"
else
  mv "${staging}" "${release_dir}"
fi
tmp_link="${prefix}/.current-${$}"
ln -s "releases/${version}" "${tmp_link}"
mv -Tf "${tmp_link}" "${prefix}/current"
ln -sfn "${prefix}/current/zscope-launcher" "${HOME}/.local/bin/zscope"
trap - EXIT

echo "Installed Z-SCOPE ${version} (${profile}) into ${release_dir}"
echo "Add ${HOME}/.local/bin to PATH if it is not already present. No shell profile was changed."
