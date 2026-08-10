#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
version="$(python3 "${root}/scripts/verify_release_version.py")"
scratch="$(mktemp -d)"
trap 'rm -rf -- "${scratch}"' EXIT
assets="${scratch}/assets"
old_assets="${scratch}/assets-old"
tampered_assets="${scratch}/assets-tampered"
app="${scratch}/app"
mkdir -p "${assets}" "${old_assets}" "${app}/runtime/bin" "${app}/wheelhouse" "${app}/bootstrap" \
  "${scratch}/cpp/bin" "${scratch}/java/bin"

cat >"${app}/runtime/bin/python3" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
if [[ "${1:-}" == "-c" ]]; then
  echo "3.13"
  exit 0
fi
if [[ "${1:-}" == "-m" && "${2:-}" == "venv" ]]; then
  destination="${@: -1}"
  mkdir -p "${destination}/bin"
  cat >"${destination}/bin/python" <<'PY'
#!/usr/bin/env bash
exit 0
PY
  chmod +x "${destination}/bin/python"
  exit 0
fi
target=""
while [[ $# -gt 0 ]]; do
  if [[ "$1" == "--python" ]]; then target="$2"; shift 2; else shift; fi
done
mkdir -p "$(dirname "${target}")"
cat >"$(dirname "${target}")/zscope" <<'ZS'
#!/usr/bin/env bash
echo "Z-SCOPE smoke"
ZS
chmod +x "$(dirname "${target}")/zscope"
EOF
chmod +x "${app}/runtime/bin/python3"
touch "${app}/wheelhouse/zscope-${version}-py3-none-any.whl" "${app}/bootstrap/pip.pyz"
tar --zstd -cf "${assets}/zscope-app-${version}-linux-x86_64.tar.zst" -C "${app}" .
tar --zstd -cf "${old_assets}/zscope-app-1.3.0-linux-x86_64.tar.zst" -C "${app}" .
tar --zstd -cf "${assets}/zscope-deps-cpp-smoke-linux-x86_64.tar.zst" -C "${scratch}/cpp" .
tar --zstd -cf "${assets}/zscope-deps-java-smoke-linux-x86_64.tar.zst" -C "${scratch}/java" .
cp "${assets}"/zscope-deps-*.tar.zst "${old_assets}/"
cp "${root}/install.sh" "${assets}/install.sh"
cp "${root}/install.sh" "${old_assets}/install.sh"
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "${scratch}/private.pem" >/dev/null 2>&1
mkdir -p "${scratch}/licenses" "${scratch}/release-one" "${scratch}/release-two"
printf 'fixture license\n' >"${scratch}/licenses/LICENSE.txt"
for output in "${scratch}/release-one" "${scratch}/release-two"; do
  (
    cd "${root}"
    SOURCE_DATE_EPOCH=1700000000 bash scripts/build_release_assets.sh \
      --runtime "${app}/runtime" \
      --wheelhouse "${app}/wheelhouse" \
      --pip-pyz "${app}/bootstrap/pip.pyz" \
      --cpp-deps "${scratch}/cpp" \
      --java-deps "${scratch}/java" \
      --licenses "${scratch}/licenses" \
      --private-key "${scratch}/private.pem" \
      --cpp-toolset smoke \
      --java-toolset smoke \
      --output "${output}" >/dev/null
  )
done
cmp "${scratch}/release-one/SHA256SUMS" "${scratch}/release-two/SHA256SUMS"
for directory in "${assets}" "${old_assets}"; do
  (cd "${directory}" && sha256sum *.tar.zst install.sh > SHA256SUMS)
  openssl pkey -in "${scratch}/private.pem" -pubout -out "${directory}/public-key.pem" >/dev/null 2>&1
  openssl dgst -sha256 -sign "${scratch}/private.pem" \
    -out "${directory}/SHA256SUMS.sig" "${directory}/SHA256SUMS"
done

cp -a "${assets}" "${tampered_assets}"
printf 'tampered' >>"${tampered_assets}/zscope-app-${version}-linux-x86_64.tar.zst"
if HOME="${scratch}/tamper-home" bash "${root}/install.sh" --profile all --asset-dir "${tampered_assets}" >/dev/null 2>&1; then
  echo "tampered asset was accepted" >&2
  exit 1
fi
HOME="${scratch}/home" bash "${root}/install.sh" --profile all --asset-dir "${old_assets}"
HOME="${scratch}/home" bash "${root}/install.sh" --profile all --asset-dir "${assets}"
HOME="${scratch}/home" "${scratch}/home/.local/bin/zscope" --version | grep -q "Z-SCOPE smoke"
[[ -L "${scratch}/home/.local/share/zscope/current" ]]
[[ "$(readlink "${scratch}/home/.local/share/zscope/current")" == "releases/${version}" ]]
HOME="${scratch}/home" bash "${root}/install.sh" --rollback 1.3.0
[[ "$(readlink "${scratch}/home/.local/share/zscope/current")" == "releases/1.3.0" ]]
echo "offline installer smoke passed"
