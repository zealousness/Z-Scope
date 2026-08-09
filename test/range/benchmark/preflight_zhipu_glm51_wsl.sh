#!/usr/bin/env bash
set -euo pipefail

# A deliberately tiny, non-streaming request catches an invalid key or wrong
# OpenAI-compatible endpoint before a multi-hour Range scan begins.  It never
# prints the API key or the provider response body.
repo_root="${Z_SCOPE_REPO_ROOT:-/mnt/c/Users/10273/home/work/Z-Scope}"
cd "${repo_root}"

if [[ -f test/range/zscope.local.env ]]; then
  # shellcheck disable=SC1091
  source test/range/zscope.local.env
fi

if [[ -z "${Z_SCOPE_API_KEY:-}" ]]; then
  echo "[range-preflight] ERROR: Z_SCOPE_API_KEY is not set." >&2
  exit 2
fi

response_file="$(mktemp)"
trap 'rm -f "${response_file}"' EXIT
http_status="$(curl --silent --show-error --output "${response_file}" \
  --write-out '%{http_code}' --max-time 60 \
  --header "Authorization: Bearer ${Z_SCOPE_API_KEY}" \
  --header 'Content-Type: application/json' \
  --data '{"model":"glm-5.1","messages":[{"role":"user","content":"Reply with OK."}],"max_tokens":4,"temperature":0}' \
  'https://open.bigmodel.cn/api/paas/v4/chat/completions')"

if [[ ! "${http_status}" =~ ^2[0-9][0-9]$ ]]; then
  echo "[range-preflight] ERROR: Zhipu GLM-5.1 authentication/request failed (HTTP ${http_status})." >&2
  exit 2
fi

echo "[range-preflight] Zhipu GLM-5.1 authentication: ok (HTTP ${http_status})."
