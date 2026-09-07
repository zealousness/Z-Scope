"""Official R3 replay: run the adjusted R3 rung over the R2 run's review pool.

Drives ``ValidationRunner.replay_review_candidate`` (answer-free, real routing)
over every needs_review item of the R2 balanced run:

- rejected items  -> ``audit_rejection=True``      (V2b adjudication)
- uncertain items -> ``investigate_uncertain=True`` (V3 re-investigation with the
  positive-case directive) and ``audit_rejection=True`` (bites only if the fresh
  V3 pass ends rejected)

Writes one JSONL result per item; offline truth scoring happens separately.

Usage (WSL, repo root):
    python3 benchmarks/experiments/balanced_confirmed_tp/replay_r3_review_pool.py \
        --run benchmark-artifacts/c_cpp/trial/20260905T130307Z/run-01 \
        --output benchmarks/experiments/balanced_confirmed_tp/r3_replay_results.jsonl \
        [--limit N] [--workers 4]
"""

from __future__ import annotations

import argparse
import json
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from types import SimpleNamespace

REPO_ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPO_ROOT))

from zscope.core.validation.pipeline import ValidationPipeline  # noqa: E402
from zscope.core.validation.runner import ValidationRunner  # noqa: E402
from zscope.framework.llm_client import LLMClient  # noqa: E402
from zscope.retrieval.code_index import CodeIndex  # noqa: E402
from zscope.snapshots.store import SnapshotStore  # noqa: E402
from zscope.tools.registry import build_tool_registry  # noqa: E402

DEFAULT_PROJECT_ROOT = "/tmp/zscope-benchmark-c_cpp-01-soxjqsl0/scan-input"


def build_runtime(config_path: Path, project_root: Path, workers: int, m1: bool = False):
    from zscope.config.v2 import load_user_config_v2

    config = load_user_config_v2(str(config_path))
    analysis = config.analysis
    # R3 arm switches (mirrors runtime_spec_r3.yaml semantics).
    analysis.validation_v2b_adjudication = True
    analysis.validation_positive_case = True
    analysis.validation_v3_reattempt = True
    analysis.validation_review_checkpoint = False
    analysis.validation_checked_proofs = False
    analysis.validation_related_findings = False
    analysis.validation_uncertain_confirm_threshold = None
    analysis.llm_decision_explanation = False
    analysis.validation_cache_entries = 0
    analysis.snapshot_dir = str(project_root / ".zscope_snapshots")
    analysis.validation_uncertain_replay_review = bool(m1)
    config.concurrency.validator_workers = workers

    index = None
    last_error: Exception | None = None
    for attempt in range(1, 6):
        try:
            index = CodeIndex(
                project_root,
                project_root / "build" / "compile_commands.json",
                source_root=str(config.project.source_root or "."),
                indexing_config=config.indexing,
                include_paths=config.project.include_paths,
                exclude_paths=config.project.exclude_paths,
                defer_svf=True,
            )
            break
        except RuntimeError as exc:
            last_error = exc
            print(f"index attempt {attempt} failed: {exc}; retrying", flush=True)
            time.sleep(15)
    if index is None:
        raise RuntimeError(f"CodeIndex failed after retries: {last_error}")

    snapshot_store = SnapshotStore.from_config(config)
    tools = list(build_tool_registry(index, snapshot_store, None).values())

    from zscope.config.user_config_store import UserConfigStore

    user_config = UserConfigStore(project_root / ".zscope_r3_user_config")

    llm_cfg = config.llms["default"]

    def make_client() -> LLMClient:
        return LLMClient(
            api_key=llm_cfg.api_key,
            base_url=getattr(llm_cfg, "base_urls", None) or llm_cfg.base_url,
            models=llm_cfg.models,
            timeout=llm_cfg.timeout,
            max_retries=llm_cfg.max_retries,
            retry_until_available=getattr(llm_cfg, "retry_until_available", False),
            max_tokens=llm_cfg.max_tokens,
        )

    runner = ValidationRunner(
        config=config,
        llm_clients={"default": make_client()},
        validation_pipeline=ValidationPipeline(user_config),
        code_index=index,
        snapshot_store=snapshot_store,
        get_tools=lambda agent_name: list(tools),
        tool_policy_for_agent=lambda agent_name: None,
        attach_agent_contract=lambda context, agent_name: context.update(
            {"agent_contract": agent_name}
        ),
        remember_validation_result=lambda issue, status: None,
    )
    return runner, config


def reconstruct_prior_result(item: dict) -> dict:
    """Rebuild the frozen ValidatorResult v3 from the R2 report projection."""
    return {
        "schema_version": "zscope.validator-result.v3",
        "candidate_uid": item.get("candidate_uid"),
        "validation_cluster_uid": item.get("validation_cluster_uid"),
        "pass": item.get("validator_result_pass") or "investigation_synthesis",
        "verdict": item.get("model_verdict") or item.get("validator_verdict") or "uncertain",
        "reasoning": item.get("validation_reasoning") or "",
        "positive_evidence": list(item.get("positive_evidence") or []),
        "negative_evidence": list(item.get("negative_evidence") or []),
        "evidence_refs": list(item.get("evidence_refs") or []),
        "blocking_negative_evidence": bool(item.get("blocking_negative_evidence")),
        "missing_fact_request": item.get("validator_missing_fact_request"),
        "stop_reason": item.get("validator_stop_reason") or item.get("validator_v2_stop_reason") or "",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--limit", type=int, default=None)
    parser.add_argument("--workers", type=int, default=4)
    parser.add_argument(
        "--project-root", default=DEFAULT_PROJECT_ROOT,
        help="scan root with a valid build/compile_commands.json",
    )
    parser.add_argument(
        "--sub-state", default=None,
        help="optional needs_review_sub_state filter (default: rejected+uncertain)",
    )
    parser.add_argument(
        "--ids", default=None,
        help="comma-separated issue id prefixes to replay (overrides sub-state filter)",
    )
    parser.add_argument(
        "--m1", action="store_true",
        help="enable validation_uncertain_replay_review (uncertain-origin verified -> review)",
    )
    args = parser.parse_args()

    run_dir = Path(args.run)
    report = json.loads((run_dir / "report.json").read_text(encoding="utf-8"))
    confirmed_ids = {issue.get("id") for issue in report.get("issues", [])}
    id_prefixes = tuple(p.strip() for p in args.ids.split(",")) if args.ids else None
    items = []
    for item in report.get("issues_with_needs_review", []):
        if item.get("id") in confirmed_ids:
            continue
        verdict = str(item.get("model_verdict") or item.get("validator_verdict") or "").lower()
        if verdict not in {"rejected", "uncertain"}:
            continue
        if id_prefixes:
            if not str(item.get("id")).startswith(id_prefixes):
                continue
        elif args.sub_state and str(item.get("needs_review_sub_state") or "") != args.sub_state:
            continue
        items.append(item)
    if args.limit:
        items = items[: args.limit]
    rejected_n = sum(1 for i in items if str(i.get("model_verdict")).lower() == "rejected")
    print(
        f"selected {len(items)} review items (rejected={rejected_n}, "
        f"uncertain={len(items) - rejected_n})",
        flush=True,
    )

    patched_text = (run_dir / "zscope.execution.yaml").read_text(encoding="utf-8").replace(
        "root: /tmp/zscope-benchmark-c_cpp-01-inh4c2gj/scan-input",
        f"root: {args.project_root}",
    )
    patched_config = Path(args.project_root) / ".zscope_r3_replay_execution.yaml"
    patched_config.write_text(patched_text, encoding="utf-8")
    runner, _config = build_runtime(
        patched_config, Path(args.project_root), args.workers, m1=args.m1
    )
    print("runtime ready; starting R3 replay", flush=True)

    out_path = Path(args.output)
    write_lock = threading.Lock()
    done_ids: set[str] = set()
    if out_path.is_file():
        for line in out_path.read_text(encoding="utf-8").splitlines():
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue
            if record.get("final_verdict"):
                done_ids.add(str(record.get("id")))
        print(f"resuming with {len(done_ids)} completed items", flush=True)

    counter = {"done": 0}

    def _worker(position: int, item: dict) -> None:
        iid = str(item.get("id"))
        if iid in done_ids:
            return
        verdict = str(item.get("model_verdict") or "").lower()
        started = time.monotonic()
        record = {
            "id": iid,
            "candidate_uid": item.get("candidate_uid"),
            "prior_verdict": verdict,
            "sub_state": item.get("needs_review_sub_state"),
            "category": item.get("category"),
            "function": item.get("function"),
        }
        try:
            result = runner.replay_review_candidate(
                dict(item),
                reconstruct_prior_result(item),
                investigate_uncertain=(verdict == "uncertain"),
                audit_rejection=(verdict == "rejected"),
            )
            issue = result.get("candidate") or {}
            history = list(issue.get("validator_pass_history") or [])
            record.update(
                {
                    "final_verdict": issue.get("model_verdict") or issue.get("validator_verdict"),
                    "final_disposition": issue.get("candidate_disposition"),
                    "final_status": issue.get("status") or issue.get("validation_status"),
                    "reasoning": str(issue.get("validation_reasoning") or "")[:1500],
                    "pass_history": [
                        {k: h.get(k) for k in ("pass", "verdict", "action", "stop_reason")}
                        for h in history
                    ][-4:],
                    "review_adjudication": bool(issue.get("review_adjudication")),
                    "review_priority_signal": issue.get("review_priority_signal"),
                    "elapsed_seconds": round(time.monotonic() - started, 1),
                    "success": True,
                }
            )
        except Exception as exc:  # noqa: BLE001 - keep the batch alive
            record.update(
                {
                    "success": False,
                    "error": f"{type(exc).__name__}: {exc}"[:400],
                    "elapsed_seconds": round(time.monotonic() - started, 1),
                }
            )
        with write_lock:
            counter["done"] += 1
            with out_path.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(record, ensure_ascii=False) + "\n")
        print(
            f"[{counter['done']}/{len(items)}] {iid[:44]} prior={verdict} "
            f"final={record.get('final_verdict') or record.get('error', '')[:40]}",
            flush=True,
        )

    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        futures = [pool.submit(_worker, i + 1, item) for i, item in enumerate(items)]
        for future in futures:
            future.result()
    print("R3 replay done", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
