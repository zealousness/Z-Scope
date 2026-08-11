#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: scripts/build_release_assets.sh --runtime DIR --wheelhouse DIR \
  --pip-pyz FILE --cpp-deps DIR --java-deps DIR --licenses DIR --private-key FILE \
  [--cpp-toolset NAME] [--java-toolset NAME] [--output DIR]

The runtime must be a relocatable CPython 3.13 tree. Dependency directories
must already contain the approved Linux x86_64 toolchains. CodeQL must not be
present in the Java directory.
EOF
}

runtime=""; wheelhouse=""; pip_pyz=""; cpp_deps=""; java_deps=""; licenses=""; private_key=""
cpp_toolset="stable"; java_toolset="stable"; output="dist/release"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --runtime) runtime="$2"; shift 2 ;;
    --wheelhouse) wheelhouse="$2"; shift 2 ;;
    --pip-pyz) pip_pyz="$2"; shift 2 ;;
    --cpp-deps) cpp_deps="$2"; shift 2 ;;
    --java-deps) java_deps="$2"; shift 2 ;;
    --licenses) licenses="$2"; shift 2 ;;
    --private-key) private_key="$2"; shift 2 ;;
    --cpp-toolset) cpp_toolset="$2"; shift 2 ;;
    --java-toolset) java_toolset="$2"; shift 2 ;;
    --output) output="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown argument: $1" >&2; exit 2 ;;
  esac
done
for value in runtime wheelhouse pip_pyz cpp_deps java_deps licenses private_key; do
  [[ -n "${!value}" ]] || { echo "--${value//_/-} is required" >&2; exit 2; }
done
command -v zstd >/dev/null || { echo "zstd is required" >&2; exit 1; }
command -v openssl >/dev/null || { echo "openssl is required" >&2; exit 1; }
version="$(python3 scripts/verify_release_version.py)"
[[ "$("${runtime}/bin/python3" -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')" == "3.13" ]] || {
  echo "App runtime must be CPython 3.13" >&2; exit 1;
}
if find "${java_deps}" -iname '*codeql*' -print -quit | grep -q .; then
  echo "CodeQL redistribution is forbidden; remove it from Java dependencies" >&2; exit 1
fi

output="$(mkdir -p "${output}" && cd "${output}" && pwd -P)"
if find "${output}" -mindepth 1 -maxdepth 1 -print -quit | grep -q .; then
  echo "Output directory must be empty: ${output}" >&2
  exit 1
fi
stage="$(mktemp -d)"
trap 'rm -rf -- "${stage}"' EXIT
mkdir -p "${stage}/app/runtime" "${stage}/app/wheelhouse" "${stage}/app/bootstrap"
cp -a "${runtime}/." "${stage}/app/runtime/"
cp -a "${wheelhouse}/." "${stage}/app/wheelhouse/"
cp "${pip_pyz}" "${stage}/app/bootstrap/pip.pyz"
cp install.sh "${stage}/app/install.sh"
mkdir -p "${stage}/app/constraints"
cp requirements/release/py313.txt "${stage}/app/constraints/"
python3 scripts/generate_spdx_sbom.py --root "${stage}/app" --version "${version}" --name zscope-app --output "${stage}/app/zscope-${version}.spdx.json"
python3 scripts/generate_spdx_sbom.py --root "${cpp_deps}" --version "${version}" --name "zscope-deps-cpp-${cpp_toolset}" --output "${stage}/zscope-deps-cpp-${cpp_toolset}.spdx.json"
python3 scripts/generate_spdx_sbom.py --root "${java_deps}" --version "${version}" --name "zscope-deps-java-${java_toolset}" --output "${stage}/zscope-deps-java-${java_toolset}.spdx.json"

tar_args=(--sort=name --mtime="@${SOURCE_DATE_EPOCH:-0}" --owner=0 --group=0 --numeric-owner --zstd -cf)
tar "${tar_args[@]}" "${output}/zscope-app-${version}-linux-x86_64.tar.zst" -C "${stage}/app" .
tar "${tar_args[@]}" "${output}/zscope-deps-cpp-${cpp_toolset}-linux-x86_64.tar.zst" -C "${cpp_deps}" .
tar "${tar_args[@]}" "${output}/zscope-deps-java-${java_toolset}-linux-x86_64.tar.zst" -C "${java_deps}" .
cp install.sh "${output}/install.sh"
cp "${stage}/app/zscope-${version}.spdx.json" "${output}/"
cp "${stage}"/zscope-deps-*.spdx.json "${output}/"
cp requirements/release/py313.txt "${output}/release-py313.txt"
tar "${tar_args[@]}" "${output}/third-party-licenses-${version}.tar.zst" -C "${licenses}" .

for asset in "${output}"/*.tar.zst; do
  size="$(stat -c %s "${asset}")"
  (( size < 2147483648 )) || { echo "Asset exceeds 2 GiB: ${asset}" >&2; exit 1; }
done
python3 scripts/generate_release_manifest.py \
  --directory "${output}" \
  --version "${version}" \
  --output "${output}/release-manifest.json"
(cd "${output}" && sha256sum *.tar.zst install.sh *.spdx.json release-py313.txt release-manifest.json > SHA256SUMS)
openssl dgst -sha256 -sign "${private_key}" -out "${output}/SHA256SUMS.sig" "${output}/SHA256SUMS"
openssl pkey -in "${private_key}" -pubout -out "${output}/public-key.pem"
python3 scripts/verify_release_assets.py --asset-dir "${output}" >/dev/null
echo "Release assets written to ${output}"
