#!/usr/bin/env bash
set -euo pipefail

if [[ ! -r /proc/version ]] || ! grep -qiE 'microsoft|wsl' /proc/version; then
  echo "[range] ERROR: range benchmark must run inside WSL/Linux for SVF/Saber." >&2
  echo "[range]        Launch with: wsl bash -lc 'cd /mnt/c/Users/10273/home/work/Z-Scope && test/range/benchmark/run_auto_unified_wsl.sh'" >&2
  exit 2
fi

repo_root="${Z_SCOPE_REPO_ROOT:-/mnt/c/Users/10273/home/work/Z-Scope}"
cd "${repo_root}"

if [[ -f test/range/zscope.local.env ]]; then
  # Local secret-bearing config. This file is ignored by git.
  # shellcheck disable=SC1091
  source test/range/zscope.local.env
fi

if [[ -z "${Z_SCOPE_API_KEY:-}" ]]; then
  echo "[range] ERROR: Z_SCOPE_API_KEY is not set." >&2
  echo "[range] Set it in the environment or in test/range/zscope.local.env." >&2
  exit 2
fi

export PATH="$HOME/go/bin:/usr/lib/llvm-18/bin:$HOME/.local/svf/SVF-linux-x86_64/bin:$PATH"
export LD_LIBRARY_PATH="$HOME/.local/svf/SVF-linux-x86_64/lib:$HOME/.local/svf/llvm-18.1.0.obj/lib:${LD_LIBRARY_PATH:-}"
export LLVM_COMPILER=clang
export LLVM_CC_NAME=clang-18

config_path="test/range/zscope.auto_unified.yaml"
knowledge_db_path="test/range/.zscope_knowledge_auto_unified_wsl/code_knowledge.db"
run_id="${1:-auto_unified_wsl_$(date +%Y%m%d_%H%M%S)}"
run_dir="test/range/benchmark_runs/${run_id}"
mkdir -p "${run_dir}"
printf '%s\n' "${run_dir}" > test/range/benchmark_runs/latest_auto_unified_wsl.txt

echo "[range] run_dir=${run_dir}"
echo "[range] enforcing WSL + unified backend + automatic entry discovery"

missing_tools=()
for tool in cmake python3 clangd gclang get-bc llvm-link wpa saber; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    missing_tools+=("$tool")
  fi
done
if ((${#missing_tools[@]})); then
  echo "[range] ERROR: missing required WSL benchmark tools: ${missing_tools[*]}" >&2
  exit 2
fi

python3 - "${config_path}" <<'PY'
import sys
from pathlib import Path

import yaml

path = Path(sys.argv[1])
cfg = yaml.safe_load(path.read_text(encoding="utf-8"))
backend = ((cfg.get("indexing") or {}).get("backend") or "").lower()
entry_cfg = (cfg.get("project") or {}).get("entry_discovery") or {}
semantic_dedup = ((cfg.get("reporting") or {}).get("semantic_dedup") or {})
analysis = cfg.get("analysis") or {}
models = {
    str(model)
    for section in (cfg.get("llms") or {}).values()
    if isinstance(section, dict)
    for model in (section.get("models") or [])
}
base_urls = {
    str(section.get("base_url") or "").rstrip("/")
    for section in (cfg.get("llms") or {}).values()
    if isinstance(section, dict)
}
entry_discovery = bool(entry_cfg.get("enabled"))
header_files = entry_cfg.get("header_files") or []
max_candidates = int(entry_cfg.get("max_candidates") or 0)
max_functions = int(entry_cfg.get("max_functions") or 0)
clangd_path = (cfg.get("indexing") or {}).get("clangd_path")
if backend != "unified":
    raise SystemExit(f"[range] ERROR: expected indexing.backend=unified, got {backend!r}")
if not entry_discovery:
    raise SystemExit("[range] ERROR: expected project.entry_discovery.enabled=true")
if header_files != ["*.h"]:
    raise SystemExit(f"[range] ERROR: expected project.entry_discovery.header_files=['*.h'], got {header_files!r}")
if max_candidates < 200:
    raise SystemExit(f"[range] ERROR: expected project.entry_discovery.max_candidates>=200, got {max_candidates!r}")
if max_functions < 1000:
    raise SystemExit(f"[range] ERROR: expected project.entry_discovery.max_functions>=1000, got {max_functions!r}")
if clangd_path != "clangd":
    raise SystemExit(f"[range] ERROR: WSL config must use clangd_path=clangd, got {clangd_path!r}")
if semantic_dedup.get("enabled", True) is not True:
    raise SystemExit("[range] ERROR: expected reporting.semantic_dedup.enabled to default to true")
if semantic_dedup.get("llm_enabled", False) is not False:
    raise SystemExit("[range] ERROR: final LLM semantic dedup must remain disabled for the benchmark")
for key in (
    "candidate_lifecycle_v3",
    "canonical_outcome_projection",
    "deterministic_proof_routing",
    "enable_evidence_completion_queue",
):
    if analysis.get(key, True) is not True:
        raise SystemExit(f"[range] ERROR: analysis.{key} must be true for the v3 benchmark")
if models != {"glm-5.1"}:
    raise SystemExit(f"[range] ERROR: benchmark must use only glm-5.1, got {sorted(models)!r}")
if base_urls != {"https://open.bigmodel.cn/api/paas/v4"}:
    raise SystemExit(f"[range] ERROR: benchmark must use the Zhipu GLM endpoint, got {sorted(base_urls)!r}")
print("[range] config preflight passed: unified backend + automatic entry discovery + *.h headers + programmatic final dedup")
PY

echo "[range] clean generated WSL benchmark state"
rm -rf test/range/.zscope_snapshots_auto_unified_wsl test/range/.zscope_knowledge_auto_unified_wsl
rm -rf test/range/test/range/.zscope_knowledge_auto_unified_wsl
rm -f test/range/zscope_batch_report.json test/range/zscope_batch_report.md test/range/entry_functions_list.json

echo "[range] configure CMake"
cmake -S test/range -B test/range/build -DCMAKE_EXPORT_COMPILE_COMMANDS=ON \
  > "${run_dir}/cmake.log" 2>&1

echo "[range] build unified CPG with SVF/Saber"
python3 -m zscope.cli.cli -c "${config_path}" --build-cpg \
  > "${run_dir}/build_cpg.log" 2>&1

echo "[range] scan with YAML-configured automatic entry discovery"
start_epoch="$(date +%s)"
set +e
python3 -m zscope.cli.cli -c "${config_path}" --verbose \
  > "${run_dir}/zscope_run.log" 2>&1
scan_rc="$?"
set -e
end_epoch="$(date +%s)"
wall_seconds="$((end_epoch - start_epoch))"

if [[ -f test/range/entry_functions_list.json ]]; then
  cp test/range/entry_functions_list.json "${run_dir}/entry_functions_list.json"
fi
if [[ -f test/range/zscope_batch_report.json ]]; then
  cp test/range/zscope_batch_report.json "${run_dir}/zscope_batch_report.json"
fi
if [[ -f test/range/zscope_batch_report.md ]]; then
  cp test/range/zscope_batch_report.md "${run_dir}/zscope_batch_report.md"
fi
cp "${config_path}" "${run_dir}/zscope.auto_unified.yaml"

entry_coverage_rc=2
if [[ -f "${run_dir}/entry_functions_list.json" ]]; then
  set +e
  python3 test/range/benchmark/check_entry_coverage.py \
    --root test/range \
    --entries "${run_dir}/entry_functions_list.json" \
    --truth test/range/benchmark/ground_truth.json \
    --knowledge-db "${knowledge_db_path}" \
    > "${run_dir}/entry_coverage.json"
  entry_coverage_rc="$?"
  set -e
fi

if [[ -f "${run_dir}/zscope_batch_report.json" ]]; then
  python3 scripts/external_benchmark.py evaluate \
    --report "${run_dir}/zscope_batch_report.json" \
    --truth test/range/benchmark/ground_truth.json \
    --output "${run_dir}/evaluation.json"
  python3 scripts/external_benchmark.py evaluate \
    --report "${run_dir}/zscope_batch_report.json" \
    --truth test/range/benchmark/ground_truth.json \
    --output "${run_dir}/evaluation.with_needs_review.json" \
    --view with_needs_review
fi

python3 - "${run_dir}" "${scan_rc}" "${wall_seconds}" "${entry_coverage_rc}" <<'PY'
import json
import re
import sys
from pathlib import Path

run_dir = Path(sys.argv[1])
scan_rc = int(sys.argv[2])
wall_seconds = int(sys.argv[3])
entry_coverage_rc = int(sys.argv[4])

def load_json(path):
    if path.exists():
        return json.loads(path.read_text(encoding="utf-8"))
    return {}

entries = load_json(run_dir / "entry_functions_list.json")
entry_coverage = load_json(run_dir / "entry_coverage.json")
report = load_json(run_dir / "zscope_batch_report.json")
default_eval = load_json(run_dir / "evaluation.json")
review_eval = load_json(run_dir / "evaluation.with_needs_review.json")
build_log = (run_dir / "build_cpg.log").read_text(encoding="utf-8", errors="replace") if (run_dir / "build_cpg.log").exists() else ""
scan_log = (run_dir / "zscope_run.log").read_text(encoding="utf-8", errors="replace") if (run_dir / "zscope_run.log").exists() else ""
combined_log = build_log + "\n" + scan_log
trace_models = sorted(set(re.findall(r"\[LLM API Trace\] Model:\s*([^|\s]+)", combined_log)))
model_trace_valid = bool(trace_models) and trace_models == ["glm-5.1"]
report_emitted = bool(report)
completion_marker_observed = "Batch Analysis Complete." in scan_log
manifest = report.get("run_manifest") if isinstance(report.get("run_manifest"), dict) else {}
report_completeness = str(
    report.get("completeness") or manifest.get("completeness") or ""
).lower()
manifest_valid = manifest.get("valid") is True
valid_scan_exit = scan_rc in {0, 1}
scan_completed = (
    report_emitted
    and report_completeness == "complete"
    and manifest_valid
    and valid_scan_exit
    and entry_coverage_rc == 0
    and model_trace_valid
)
benchmark_valid = scan_completed

metric_keys = [
    "report_issue_count",
    "ground_truth_count",
    "true_positives",
    "false_positives",
    "false_positives_raw",
    "false_positives_effective",
    "duplicate_of_matched_count",
    "false_negatives",
    "precision",
    "false_positive_rate",
    "recall",
    "f1",
]
summary = {
    "run_id": run_dir.name,
    "scan_return_code": scan_rc,
    "process_ended": True,
    "report_emitted": report_emitted,
    "completion_marker_observed": completion_marker_observed,
    "scan_completed": scan_completed,
    "benchmark_valid": benchmark_valid,
    "report_completeness": report_completeness or None,
    "run_manifest_valid": manifest_valid,
    "model_trace_valid": model_trace_valid,
    "trace_models": trace_models,
    "scan_exit_semantics": (
        "valid_complete_scan_with_actionable_findings"
        if scan_completed and scan_rc == 1
        else "valid_complete_scan"
        if scan_completed
        else "process_ended_with_incomplete_or_invalid_scan"
    ),
    "scan_wall_seconds": wall_seconds,
    "mode": "wsl_auto_discover_entries_unified_backend_with_svf_required",
    "config": str((run_dir / "zscope.auto_unified.yaml").resolve()),
    "artifacts": {
        "report_json": str((run_dir / "zscope_batch_report.json").resolve()),
        "report_md": str((run_dir / "zscope_batch_report.md").resolve()),
        "evaluation_default": str((run_dir / "evaluation.json").resolve()),
        "evaluation_with_needs_review": str((run_dir / "evaluation.with_needs_review.json").resolve()),
        "entries": str((run_dir / "entry_functions_list.json").resolve()),
        "entry_coverage": str((run_dir / "entry_coverage.json").resolve()),
        "build_cpg_log": str((run_dir / "build_cpg.log").resolve()),
        "zscope_run_log": str((run_dir / "zscope_run.log").resolve()),
    },
    "entry_discovery": {
        "entries_discovered": len(entries.get("functions", [])),
        "coverage_return_code": entry_coverage_rc,
        "coverage_mode": entry_coverage.get("mode"),
        "reachable_function_nodes": entry_coverage.get("reachable_function_nodes"),
        "missing_truth_reachability": entry_coverage.get("missing_truth_reachability", []),
    },
    "report_summary": report.get("summary", {}),
    "benchmark_metrics": {
        "default": {k: default_eval.get(k) for k in metric_keys},
        "with_needs_review": {k: review_eval.get(k) for k in metric_keys},
    },
    "backend_evidence": {
        "wsl_detected": "WSL detected" in build_log,
        "unified_backend": True,
        "clangd_lsp_initialized": "clangd LSP initialized successfully" in combined_log,
        "gclang_invoked": "gclang cmd:" in combined_log,
        "wpa_ander_succeeded": "wpa-ander succeeded" in combined_log,
        "saber_succeeded": "saber succeeded" in combined_log,
        "svf_completed": "SVF analysis completed and wrote results to KnowledgeDB" in combined_log,
        "imported_svf_indirect_edges": bool(re.search(r"Imported \d+ indirect call edges from SVF", combined_log)),
        "imported_saber_bugs": bool(re.search(r"Imported \d+ saber bugs", combined_log)),
        "svf_unavailable_mentions": len(re.findall(r"SVF tools unavailable|SVF analysis failed", combined_log)),
    },
}
(run_dir / "run_summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
print(json.dumps(summary, ensure_ascii=False, indent=2))
PY

run_validity="$(python3 - "${run_dir}/run_summary.json" <<'PY'
import json
import sys

summary = json.loads(open(sys.argv[1], encoding="utf-8").read())
if summary.get("benchmark_valid") is True:
    print("valid")
elif int(summary.get("scan_return_code") or 0) in {130, 143}:
    print("interrupted")
else:
    print("invalid")
PY
)"

if [[ "${run_validity}" == "interrupted" ]]; then
  echo "[range] ERROR: scan was interrupted with rc=${scan_rc}; see ${run_dir}/zscope_run.log" >&2
  exit "${scan_rc}"
fi
if [[ "${run_validity}" != "valid" ]]; then
  echo "[range] ERROR: benchmark is incomplete or invalid; see ${run_dir}/run_summary.json" >&2
  exit 2
fi

echo "[range] completed: ${run_dir}"
