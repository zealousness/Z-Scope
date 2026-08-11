#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: scripts/smoke_release_assets.sh --asset-dir DIR --cpp-smoke-script FILE \
  --java-smoke-script FILE --evidence FILE

Run this as a non-root user inside an externally enforced disconnected Ubuntu
24.04 environment. Set Z_SCOPE_NETWORK_ISOLATION_CONFIRMED=1 only when the
runner or container has actually disabled public network access.
EOF
}

asset_dir=""; cpp_script=""; java_script=""; evidence=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --asset-dir) asset_dir="$2"; shift 2 ;;
    --cpp-smoke-script) cpp_script="$2"; shift 2 ;;
    --java-smoke-script) java_script="$2"; shift 2 ;;
    --evidence) evidence="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown argument: $1" >&2; exit 2 ;;
  esac
done
[[ -n "${asset_dir}" && -n "${cpp_script}" && -n "${java_script}" && -n "${evidence}" ]] || {
  usage >&2; exit 2;
}
[[ "$(id -u)" -ne 0 ]] || { echo "offline smoke must run as a non-root user" >&2; exit 1; }
source /etc/os-release
[[ "${ID:-}" == "ubuntu" && "${VERSION_ID:-}" == "24.04" ]] || {
  echo "production offline smoke requires Ubuntu 24.04" >&2; exit 1;
}
python3 - <<'PY'
import platform
name, version = platform.libc_ver()
parts = tuple(int(part) for part in version.split(".")[:2])
if name != "glibc" or parts < (2, 38):
    raise SystemExit("production offline smoke requires glibc >= 2.38")
PY
[[ "${Z_SCOPE_NETWORK_ISOLATION_CONFIRMED:-}" == "1" ]] || {
  echo "network isolation must be externally enforced and confirmed" >&2; exit 1;
}
[[ -f "${cpp_script}" && -f "${java_script}" ]] || {
  echo "both approved language smoke scripts are required" >&2; exit 1;
}

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
asset_dir="$(cd "${asset_dir}" && pwd -P)"
scratch="$(mktemp -d)"
trap 'rm -rf -- "${scratch}"' EXIT
export HOME="${scratch}/home"
export PIP_NO_INDEX=1 PIP_DISABLE_PIP_VERSION_CHECK=1
unset HTTP_PROXY HTTPS_PROXY ALL_PROXY http_proxy https_proxy all_proxy

python3 "${root}/scripts/verify_release_assets.py" --asset-dir "${asset_dir}" \
  >"${scratch}/asset-verification.json"
bash "${asset_dir}/install.sh" --profile all --asset-dir "${asset_dir}" \
  >"${scratch}/install.log" 2>&1
release_root="${HOME}/.local/share/zscope/current"
export PATH="${release_root}/deps-cpp/bin:${release_root}/deps-java/bin:${PATH}"
"${HOME}/.local/bin/zscope" --help >"${scratch}/zscope-help.log" 2>&1
"${release_root}/venv/bin/zscope-doctor" --profile all --json-output \
  >"${scratch}/doctor.json"
bash "${cpp_script}" >"${scratch}/cpp-smoke.log" 2>&1
bash "${java_script}" >"${scratch}/java-smoke.log" 2>&1

python3 - "${asset_dir}/release-manifest.json" "${cpp_script}" "${java_script}" \
  "${scratch}/doctor.json" "${evidence}" <<'PY'
import hashlib, json, platform, sys
from pathlib import Path

manifest, cpp_script, java_script, doctor, output = map(Path, sys.argv[1:])
def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()
checks = json.loads(doctor.read_text(encoding="utf-8"))["checks"]
payload = {
    "schema_version": "zscope.offline-smoke.v1",
    "passed": all(item["ok"] for item in checks if item["required"]),
    "synthetic_payload": False,
    "network_isolation_confirmed": True,
    "ordinary_user": True,
    "platform": platform.platform(),
    "release_manifest_sha256": sha(manifest),
    "cpp_smoke_script_sha256": sha(cpp_script),
    "java_smoke_script_sha256": sha(java_script),
    "doctor_required_checks_passed": all(item["ok"] for item in checks if item["required"]),
}
output.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
if not payload["passed"]:
    raise SystemExit("doctor reported a required failure")
PY
echo "production offline asset smoke passed"
