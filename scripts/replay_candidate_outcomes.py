#!/usr/bin/env python3
"""Replay deterministic candidate outcomes without contacting an LLM.

The tool consumes a frozen schema-v2 report and re-runs only the versioned
fact/proof routing on copies of its canonical validation groups.  It never
rewrites the input report, never reads a secret, and emits an auditable
old-to-new disposition transition table for shadow comparisons.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import sys
from pathlib import Path
from typing import Any, Dict, Iterable, Mapping

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from zscope.core.validation.evidence_completion import EvidenceCompletionQueue
from zscope.core.validation.proofs import deterministic_decision_proof
from zscope.reporting.finding_roots import project_finding_roots


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _load_json(path: Path) -> Dict[str, Any]:
    with path.open(encoding="utf-8") as handle:
        value = json.load(handle)
    if not isinstance(value, dict):
        raise ValueError(f"expected a JSON object: {path}")
    return value


def _input_fingerprints(paths: Mapping[str, Path]) -> Dict[str, str]:
    return {name: _sha256(path) for name, path in paths.items() if path.exists() and path.is_file()}


def _verify_baseline(
    fingerprints: Mapping[str, str],
    baseline_manifest: Path | None,
) -> None:
    if baseline_manifest is None:
        return
    baseline = _load_json(baseline_manifest)
    expected = baseline.get("input_fingerprints")
    if not isinstance(expected, dict):
        raise ValueError("baseline manifest has no input_fingerprints object")
    for name, digest in expected.items():
        actual = fingerprints.get(str(name))
        if actual != digest:
            raise ValueError(
                f"baseline fingerprint mismatch for {name}: expected {digest}, got {actual}"
            )


def _canonical_groups(report: Mapping[str, Any]) -> Iterable[Dict[str, Any]]:
    records = report.get("candidate_terminal_states")
    if not isinstance(records, list):
        records = report.get("issues_with_needs_review") or report.get("issues") or []
    seen: set[str] = set()
    for raw in records:
        if not isinstance(raw, dict):
            continue
        cluster = str(raw.get("validation_cluster_uid") or raw.get("candidate_uid") or "")
        if not cluster or cluster in seen:
            continue
        seen.add(cluster)
        yield raw


def _deterministic_replay(
    issue: Mapping[str, Any],
    *,
    enable_v12: bool = False,
) -> Dict[str, Any]:
    replay = copy.deepcopy(dict(issue))
    old = str(
        replay.get("terminal_disposition") or replay.get("candidate_disposition") or "needs_review"
    ).lower()
    evidence = {
        "function_context": {
            "code": str(replay.get("code_snippet") or ""),
        }
    }
    old_confirmation = deterministic_decision_proof(replay, outcome="confirm")
    old_rejection = deterministic_decision_proof(replay, outcome="reject")
    # Shadow replay must recompute provider decisions under the current code.
    # Retaining an archived proof in any accepted proof collection would make
    # a revoked provider decision self-perpetuating forever.
    for field in ("deterministic_proofs", "decision_proofs", "proofs"):
        replay[field] = []
    pack = replay.get("evidence_pack")
    if isinstance(pack, dict):
        for field in ("deterministic_proofs", "decision_proofs", "proofs"):
            pack[field] = []
    EvidenceCompletionQueue(enable_v12_providers=enable_v12).complete_prevalidation(
        replay,
        validation_evidence=evidence,
    )
    confirmation = deterministic_decision_proof(replay, outcome="confirm")
    rejection = deterministic_decision_proof(replay, outcome="reject")
    if confirmation is not None and rejection is not None:
        new = "needs_review"
        reason = "evidence_conflict"
    elif confirmation is not None:
        new = "confirmed"
        reason = confirmation.proof_kind
    elif rejection is not None:
        new = "rejected_with_proof"
        reason = rejection.proof_kind
    elif old_confirmation is not None or old_rejection is not None:
        new = "needs_review"
        reason = "archived_complete_proof_not_reproduced"
    else:
        new = old
        reason = "no_new_complete_proof"
    return {
        "candidate_uid": replay.get("candidate_uid"),
        "validation_cluster_uid": replay.get("validation_cluster_uid"),
        "old_disposition": old,
        "new_disposition": new,
        "transitioned": old != new,
        "reason": reason,
        "proof": (
            confirmation.to_dict()
            if confirmation is not None and rejection is None
            else rejection.to_dict() if rejection is not None and confirmation is None else None
        ),
    }


def replay_report(
    report: Mapping[str, Any],
    *,
    source_revision: str = "",
    enable_v12: bool = False,
    finding_root_v2: bool = False,
    finding_root_v1: bool = False,
) -> Dict[str, Any]:
    raw_manifest = report.get("run_manifest")
    manifest: Mapping[str, Any] = raw_manifest if isinstance(raw_manifest, dict) else {}
    raw_metadata = report.get("metadata")
    metadata: Mapping[str, Any] = raw_metadata if isinstance(raw_metadata, dict) else {}
    recorded_revision = str(manifest.get("source_revision") or metadata.get("commit_sha") or "")
    if source_revision and recorded_revision and source_revision != recorded_revision:
        raise ValueError(
            f"source revision mismatch: report={recorded_revision}, requested={source_revision}"
        )
    groups = list(_canonical_groups(report))
    transitions = [_deterministic_replay(item, enable_v12=enable_v12) for item in groups]
    changed = [item for item in transitions if item["transitioned"]]
    finding_root_enabled = bool(finding_root_v2 or finding_root_v1)
    result = {
        "schema_version": "zscope.candidate-replay.v1",
        "source_revision": recorded_revision,
        "canonical_group_count": len(transitions),
        "transition_count": len(changed),
        "transitions": transitions,
        "changed_transitions": changed,
        "proof_providers_v12": bool(enable_v12),
        "finding_root_v2": finding_root_enabled,
        "finding_root_v1_compat_flag_used": bool(finding_root_v1),
    }
    if finding_root_enabled:
        by_cluster = {str(item.get("validation_cluster_uid") or ""): item for item in transitions}
        replayed_groups = []
        for raw in groups:
            item = copy.deepcopy(raw)
            transition = by_cluster.get(str(item.get("validation_cluster_uid") or ""))
            if transition:
                item["candidate_disposition"] = transition["new_disposition"]
                item["status"] = transition["new_disposition"]
                if transition.get("proof"):
                    item["decision_proof"] = transition["proof"]
            replayed_groups.append(item)
        projection = project_finding_roots(replayed_groups)
        result["finding_root_count"] = projection.finding_root_count
        result["finding_root_alias_count"] = projection.finding_root_alias_count
        result["finding_root_projection"] = dict(projection.summary)
        result["projected_disposition_counts"] = {
            disposition: sum(
                1
                for item in projection.outcomes
                if str(item.get("candidate_disposition") or "") == disposition
            )
            for disposition in (
                "confirmed",
                "needs_review",
                "rejected_with_proof",
                "deduplicated_alias",
            )
        }
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--config", type=Path)
    parser.add_argument("--truth", type=Path)
    parser.add_argument("--scorer", type=Path)
    parser.add_argument("--log", type=Path)
    parser.add_argument("--baseline-manifest", type=Path)
    parser.add_argument("--source-revision", default="")
    parser.add_argument("--proof-providers-v12", action="store_true")
    parser.add_argument("--finding-root-v2", action="store_true")
    parser.add_argument(
        "--finding-root-v1",
        action="store_true",
        help=argparse.SUPPRESS,
    )
    parser.add_argument(
        "--shadow",
        action="store_true",
        help="Record an immutable comparison only; the input report is never modified in either mode.",
    )
    args = parser.parse_args()

    if not args.report.is_file():
        raise SystemExit(f"report does not exist: {args.report}")
    input_paths = {"report": args.report}
    for name in ("config", "truth", "scorer", "log"):
        value = getattr(args, name)
        if value is not None:
            if not value.is_file():
                raise SystemExit(f"{name} does not exist: {value}")
            input_paths[name] = value
    fingerprints = _input_fingerprints(input_paths)
    try:
        _verify_baseline(fingerprints, args.baseline_manifest)
        result = replay_report(
            _load_json(args.report),
            source_revision=args.source_revision,
            enable_v12=bool(args.proof_providers_v12),
            finding_root_v2=bool(args.finding_root_v2),
            finding_root_v1=bool(args.finding_root_v1),
        )
    except ValueError as exc:
        raise SystemExit(f"replay refused: {exc}") from exc
    result["input_fingerprints"] = fingerprints
    result["shadow"] = bool(args.shadow)
    result["input_report_unchanged"] = _sha256(args.report) == fingerprints["report"]
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
