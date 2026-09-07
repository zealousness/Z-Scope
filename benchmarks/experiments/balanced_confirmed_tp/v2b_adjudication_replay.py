"""M5 R3 replay validation: run V2b adjudication over a prior run's review items.

Reads a benchmark run's ``report.json``, selects the ``model_rejected_unproven``
needs_review items, rebuilds each validation input from the live project index
(same ``build_validation_evidence_pack`` as production), and executes the
agent-side V2b adjudication pass against the real LLM.  No truth is consulted
at runtime; scoring/analysis happens afterwards offline.

Usage (WSL, repo root):
    python3 benchmarks/experiments/balanced_confirmed_tp/v2b_adjudication_replay.py \
        --run benchmark-artifacts/c_cpp/trial/20260905T130307Z/run-01 \
        --output benchmarks/experiments/balanced_confirmed_tp/v2b_replay_results.json \
        [--limit N] [--sub-state model_rejected_unproven]
"""

from __future__ import annotations

import argparse
import json
import sys
import time
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPO_ROOT))

from zscope.agents.validator_agent.agent import ValidatorAgent  # noqa: E402
from zscope.core.validation.evidence import (  # noqa: E402
    build_validation_evidence_pack,
    build_validator_evidence_slice_v3,
)
from zscope.core.validation.pipeline import ValidationPipeline  # noqa: E402
from zscope.framework.llm_client import LLMClient  # noqa: E402
from zscope.retrieval.code_index import CodeIndex  # noqa: E402
from zscope.snapshots.store import SnapshotStore  # noqa: E402
from zscope.tools.registry import build_tool_registry  # noqa: E402


class _MiniUserConfig:
    """Suppression-free user config stand-in for offline replay."""

    def __init__(self):
        self.baseline = None

    def is_false_positive(self, func_name, location, category):
        return False


def build_runtime(config_path: Path, project_root: Path):
    from zscope.config.v2 import load_user_config_v2

    config = load_user_config_v2(str(config_path))
    index = None
    # clangd readiness on /mnt/c flakes intermittently (~half of starts die
    # within seconds of init); retry until the index comes up.
    last_error: Exception | None = None
    for attempt in range(1, 6):
        try:
            index = CodeIndex(
                project_root=project_root,
                compile_commands_path=project_root / "build" / "compile_commands.json",
                source_root=".",
                indexing_config=getattr(config, "indexing", None),
            )
            break
        except RuntimeError as exc:
            last_error = exc
            print(f"index attempt {attempt} failed: {exc}; retrying", flush=True)
            time.sleep(15)
    if index is None:
        raise RuntimeError(f"CodeIndex failed after retries: {last_error}")
    snapshot_store = SnapshotStore.from_config(config)
    user_config = _MiniUserConfig()
    tools = list(build_tool_registry(index, snapshot_store, None).values())
    llm_cfg = config.llms["default"]
    client = LLMClient(
        api_key=llm_cfg.api_key,
        base_url=getattr(llm_cfg, "base_urls", None) or llm_cfg.base_url,
        models=llm_cfg.models,
        timeout=llm_cfg.timeout,
        max_retries=llm_cfg.max_retries,
        retry_until_available=getattr(llm_cfg, "retry_until_available", False),
        max_tokens=llm_cfg.max_tokens,
    )
    pipeline = ValidationPipeline(user_config)

    def agent_factory() -> ValidatorAgent:
        worker_client = LLMClient(
            api_key=llm_cfg.api_key,
            base_url=getattr(llm_cfg, "base_urls", None) or llm_cfg.base_url,
            models=llm_cfg.models,
            timeout=llm_cfg.timeout,
            max_retries=llm_cfg.max_retries,
            retry_until_available=getattr(llm_cfg, "retry_until_available", False),
            max_tokens=llm_cfg.max_tokens,
        )
        return ValidatorAgent(worker_client, tools, tool_policy=None)

    agent = agent_factory()
    return index, agent, pipeline, snapshot_store, agent_factory


def select_items(report: dict, sub_state: str, limit: int | None):
    confirmed_ids = {issue.get("id") for issue in report.get("issues", [])}
    selected = []
    for item in report.get("issues_with_needs_review", []):
        if item.get("id") in confirmed_ids:
            continue
        if str(item.get("needs_review_sub_state") or "") != sub_state:
            continue
        selected.append(item)
    if limit:
        selected = selected[:limit]
    return selected


def adjudicate_one(item: dict, index, agent, pipeline, snapshot_store) -> dict:
    function = str(item.get("function") or "")
    impl = index.get_function_impl(function, warn_missing=False) or {}
    code = str((impl or {}).get("code") or "")
    issue = dict(item)
    state = {
        "pending_new_issues": [issue],
        "agent_context": {
            "func_name": function,
            "code": code,
            "entry_custom_prompt": "",
        },
        "entry_func": function,
        "issues": [],
        "observations": [],
    }
    evidence_pack = build_validation_evidence_pack(
        issue,
        state,
        code,
        code_index=index,
        snapshot_store=snapshot_store,
        score_components_fn=pipeline.score_components,
    )
    prior_passes = list(item.get("validator_pass_history") or [])
    evidence_slice = build_validator_evidence_slice_v3(
        issue,
        evidence_pack,
        code,
        validation_pass="v2b_adjudication",
        evidence_delta={
            "prior_passes": prior_passes,
            "fact_resolution": item.get("validator_fact_resolution") or {},
            "adjudication_context": {
                "rejected_verdict_reasoning": str(item.get("validation_reasoning") or "")[:2000],
                "prior_stop_reason": str(item.get("validator_stop_reason") or ""),
                "adjudication_objective": "audit-the-rejection",
            },
        },
    )
    candidate_uid = str(
        item.get("candidate_uid") or item.get("candidate_id") or item.get("id") or "unknown"
    )
    payload = {
        "finding_uid": candidate_uid,
        "candidate_uid": candidate_uid,
        "validation_cluster_uid": str(
            item.get("validation_cluster_uid") or candidate_uid
        ),
        "validation_pass": "v2b_adjudication",
        "evidence_slice": evidence_slice,
    }
    started = time.monotonic()
    response = agent.investigate(payload, max_iterations=12, pass_kind="v2b_adjudication")
    elapsed = time.monotonic() - started
    metadata = getattr(response, "metadata", {}) or {}
    record = {
        "id": item.get("id"),
        "function": function,
        "category": item.get("category"),
        "location": item.get("location"),
        "elapsed_seconds": round(elapsed, 1),
        "success": bool(response.success),
        "error": str(getattr(response, "error", "") or "")[:300],
        "verdict": None,
        "reasoning": "",
        "facts": [],
        "usage": {
            key: metadata.get(key)
            for key in (
                "cumulative_total_tokens",
                "iterations",
                "tool_call_count",
                "validator_api_call_count",
                "new_fact_count",
            )
        },
    }
    data = response.data if isinstance(response.data, dict) else {}
    if data:
        record["verdict"] = data.get("verdict")
        record["reasoning"] = str(data.get("reasoning") or "")[:1200]
        record["facts"] = [
            {"fact_kind": f.get("fact_kind"), "summary": str(f.get("summary") or "")[:300]}
            for f in (metadata.get("validator_investigation_facts") or [])
            if isinstance(f, dict)
        ][:12]
        record["stop_reason"] = data.get("stop_reason")
    return record


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", required=True, help="run-01 directory of the source run")
    parser.add_argument("--output", required=True, help="results JSON path")
    parser.add_argument("--limit", type=int, default=None)
    parser.add_argument("--workers", type=int, default=4)
    parser.add_argument(
        "--sub-state", default="model_rejected_unproven",
        help="needs_review sub-state to adjudicate",
    )
    parser.add_argument(
        "--project-root",
        default="/tmp/zscope-benchmark-c_cpp-01-soxjqsl0/scan-input",
        help=(
            "project scan root with a valid build/compile_commands.json; "
            "defaults to the preserved R2 run scan-input copy"
        ),
    )
    args = parser.parse_args()

    run_dir = Path(args.run)
    report = json.loads((run_dir / "report.json").read_text(encoding="utf-8"))
    items = select_items(report, args.sub_state, args.limit)
    print(f"selected {len(items)} review items with sub_state={args.sub_state}", flush=True)

    # Load the run's own execution config (isolated llms + state locations) but
    # repoint project.root at the surviving scan-input copy — the original /tmp
    # workspace may be gone, and the repo-level default state DB carries
    # cross-run path contamination that makes tool lookups ambiguous.
    execution_config = run_dir / "zscope.execution.yaml"
    patched_text = execution_config.read_text(encoding="utf-8").replace(
        "root: /tmp/zscope-benchmark-c_cpp-01-inh4c2gj/scan-input",
        f"root: {args.project_root}",
    )
    patched_config = Path(args.project_root) / ".zscope_replay_execution.yaml"
    patched_config.write_text(patched_text, encoding="utf-8")
    print(f"config: {patched_config} (root={args.project_root})", flush=True)

    index, agent, pipeline, snapshot_store, agent_factory = build_runtime(
        patched_config,
        Path(args.project_root),
    )
    print("runtime ready; starting adjudication", flush=True)

    out_path = Path(args.output)
    # Resume: keep records already produced by a previous (possibly killed) run.
    results = []
    done_ids: set[str] = set()
    if out_path.is_file():
        try:
            previous = json.loads(out_path.read_text(encoding="utf-8"))
            results = [
                record
                for record in (previous.get("results") or [])
                if isinstance(record, dict) and record.get("verdict") is not None
            ]
            done_ids = {str(record.get("id")) for record in results}
            print(f"resuming with {len(results)} completed items", flush=True)
        except (json.JSONDecodeError, OSError):
            results = []

    pending = [item for item in items if str(item.get("id")) not in done_ids]
    print(f"{len(pending)} items to adjudicate", flush=True)
    lock = threading.Lock()
    counter = {"done": len(results)}

    def _worker(position: int, item: dict) -> None:
        # One agent (and LLM client) per worker keeps connection pools and any
        # agent-local state thread-isolated; the code index is read-only.
        worker_agent = agent if args.workers <= 1 else agent_factory()
        try:
            record = adjudicate_one(item, index, worker_agent, pipeline, snapshot_store)
        except Exception as exc:  # noqa: BLE001 - keep the batch alive
            record = {
                "id": item.get("id"),
                "function": item.get("function"),
                "success": False,
                "error": f"driver exception: {exc}"[:300],
            }
        with lock:
            results.append(record)
            counter["done"] += 1
            position_now = counter["done"]
            out_path.write_text(
                json.dumps(
                    {"sub_state": args.sub_state, "results": results},
                    ensure_ascii=False,
                    indent=1,
                ),
                encoding="utf-8",
            )
        print(
            f"[{position_now}/{len(items)}] {record.get('id')} "
            f"verdict={record.get('verdict')} ok={record.get('success')}",
            flush=True,
        )

    if args.workers <= 1:
        for position, item in enumerate(pending, 1):
            _worker(position, item)
            time.sleep(2)
    else:
        with ThreadPoolExecutor(max_workers=args.workers) as pool:
            futures = [pool.submit(_worker, i + 1, item) for i, item in enumerate(pending)]
            for future in futures:
                future.result()
    print("done", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
