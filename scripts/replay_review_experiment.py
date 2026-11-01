"""Resume complete review checkpoints in Linux, using production final routing.

This runner consumes no truth/audit files. Score its outputs in a separate
process using the unchanged official scorer and review_experiment accounting.
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from zscope.benchmarking.review_experiment import ARMS, arm_flags
from zscope.config.v2 import load_user_config_v2
from zscope.core.validation.review_checkpoint import ReviewCheckpointStore
from zscope.core.validation.runner import ValidationRunner
from zscope.core.validation.pipeline import ValidationPipeline
from zscope.framework.llm_client import LLMClient
from zscope.retrieval.code_index import CodeIndex
from zscope.retrieval.validation_facts import CompleteFactStore, digest
from zscope.snapshots.store import SnapshotStore
from zscope.tools.registry import build_tool_registry


class NoFeedback:
    def is_false_positive(self, *args):
        return False


class ReplaySourceIndex:
    """Keep generic snippet tools inside the answer-free source surface."""

    def __init__(self, index):
        self.index = index
        self.root = Path(index.project_root).resolve()

    def __getattr__(self, name):
        return getattr(self.index, name)

    def resolve_existing_file(self, value):
        resolved = self.index.resolve_existing_file(value)
        if not resolved:
            return None
        path = Path(resolved).resolve()
        if not path.is_relative_to(self.root) or path.suffix.lower() not in {
            ".c",
            ".cc",
            ".cpp",
            ".cxx",
            ".h",
            ".hh",
            ".hpp",
            ".hxx",
            ".inc",
            ".ph",
        }:
            return None
        return resolved

    def get_file_snippet(self, value, start, end):
        resolved = self.resolve_existing_file(value)
        return self.index.get_file_snippet(resolved, start, end) if resolved else None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True, type=Path)
    parser.add_argument("--checkpoints", required=True, type=Path)
    parser.add_argument(
        "--manifest", required=True, type=Path, help="JSON array of frozen RC_ checkpoint IDs"
    )
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--arm", required=True, choices=ARMS)
    parser.add_argument("--pair-id", required=True)
    parser.add_argument(
        "--audit-commitment",
        required=True,
        help="Frozen AUDIT_ content identity, never the audit file or labels",
    )
    args = parser.parse_args()
    import re

    if not re.fullmatch(r"AUDIT_[0-9a-f]{64}", args.audit_commitment):
        parser.error("audit commitment must be a frozen AUDIT_ SHA-256 identity")
    if platform.system() != "Linux":
        parser.error("Range replay requires Linux/WSL")
    if not all(
        os.environ.get(k) for k in ("Z_SCOPE_LLM_BASE_URL", "Z_SCOPE_LLM_MODEL", "Z_SCOPE_API_KEY")
    ):
        parser.error(
            "Set all three Z_SCOPE_LLM_BASE_URL / Z_SCOPE_LLM_MODEL / Z_SCOPE_API_KEY variables explicitly"
        )
    ids = json.loads(args.manifest.read_text(encoding="utf-8"))
    if not isinstance(ids, list) or not ids or len(set(ids)) != len(ids):
        parser.error("manifest must contain unique checkpoint IDs")
    store = ReviewCheckpointStore(args.checkpoints)
    checkpoints = [store.load(uid) for uid in ids]
    for checkpoint in checkpoints:
        facts = checkpoint["facts"]
        if (
            not facts.get("complete")
            or CompleteFactStore._hash_files(facts["dependencies"]) != facts["dependencies"]
        ):
            parser.error(
                "checkpoint build dependencies are incomplete or stale; collect a new baseline"
            )
    config = load_user_config_v2(str(args.config))
    root = Path(config.project.project_root).resolve()
    if any(not Path(c["facts"]["source"]).resolve().is_relative_to(root) for c in checkpoints):
        parser.error("checkpoint source does not belong to the configured project")
    for flag, enabled in arm_flags(args.arm).items():
        setattr(config.analysis, flag, enabled)
    config.analysis.snapshot_dir = str(args.output.parent / (args.output.stem + "-artifacts"))
    index = CodeIndex(
        project_root=config.project.project_root,
        compile_commands_path=config.project.compile_commands_path,
        source_root=str(config.project.project_root),
        indexing_config=config.indexing,
    )
    snapshots = SnapshotStore.from_config(config)
    tools = list(build_tool_registry(ReplaySourceIndex(index), snapshots, None).values())
    profile = str(
        getattr(getattr(config.scan, "llm_profiles", None), "validation", "") or "default"
    )
    cfg = config.llms[profile]
    client = LLMClient(
        api_key=os.environ.get("Z_SCOPE_API_KEY") or cfg.api_key,
        base_url=os.environ.get("Z_SCOPE_LLM_BASE_URL") or cfg.base_url,
        models=(
            [os.environ["Z_SCOPE_LLM_MODEL"]] if os.environ.get("Z_SCOPE_LLM_MODEL") else cfg.models
        ),
        timeout=cfg.timeout,
        max_retries=cfg.max_retries,
        max_tokens=cfg.max_tokens,
        context_window=cfg.context_window,
        model_context_windows=cfg.model_context_windows,
    )
    runner = ValidationRunner(
        config=config,
        llm_clients={"default": client, profile: client},
        validation_pipeline=ValidationPipeline(NoFeedback()),
        code_index=index,
        snapshot_store=snapshots,
        get_tools=lambda _: tools,
        tool_policy_for_agent=lambda _: None,
        attach_agent_contract=lambda *_: None,
        remember_validation_result=lambda *_: None,
    )
    results = []
    started = time.monotonic()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    for uid, checkpoint in zip(ids, checkpoints):
        candidate = checkpoint["candidate"]
        prior = (
            candidate.get("review_latest_result")
            or (candidate.get("review_prior_results") or [None])[-1]
        )
        if not prior:
            parser.error(
                f"{uid} has no exact prior ValidatorResult; report reconstructions are not replay checkpoints"
            )
        result = runner.replay_review_candidate(
            candidate,
            prior,
            investigate_uncertain=args.arm in {"neutral", "positive", "related"},
            audit_rejection=True,
        )
        results.append(result)
        payload = {
            "schema_version": "zscope.review-replay.v1",
            "arm": args.arm,
            "pair_id": args.pair_id,
            "checkpoint_manifest_hash": digest(ids),
            "audit_commitment": args.audit_commitment,
            "investigation_limits": {"v3": 50, "v2b": 12},
            "runtime": arm_flags(args.arm),
            "model": client.models,
            "complete": len(results) == len(ids),
            "elapsed_seconds": time.monotonic() - started,
            "outcomes": [item for r in results for item in [r["candidate"], *r["related"]]],
            "tokens": sum(r["tokens"].get("total_cumulative_total_tokens", 0) for r in results),
            "results": results,
        }
        temporary = args.output.with_suffix(".tmp")
        temporary.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
        temporary.replace(args.output)
    print(json.dumps({"output": str(args.output), "candidates": len(results), "arm": args.arm}))


if __name__ == "__main__":
    main()
