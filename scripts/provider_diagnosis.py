#!/usr/bin/env python3
"""Deterministic fact-provider diagnosis harness (balanced plan Phase 1.1).

Replays the exact provider dispatch that ``EvidenceCompletionQueue`` performs
at scan time — per issue, per ``missing_fact_kinds`` entry — against the real
issues recorded in a run's ``report.json`` (``issues_with_needs_review``).
Entirely offline, zero LLM cost.  The issue objects keep their real
``evidence_pack`` (the replay bundle flattens evidence and therefore starves
the providers — use the report for diagnosis).

Classification per (issue, fact_kind):

* ``produced``              a local provider generated completion proofs.
* ``engine_facts_present``  the issue already carries ``fact_completion_by_kind``
  payloads for the kind (scan-time engines produced typed facts).
* ``empty_no_proof``        providers ran, produced nothing, no engine facts.
* ``no_provider``           no local provider is registered for the kind.
* ``unsupported_kind``      kind is outside ``SUPPORTED_FACT_KINDS``.
* ``timeout`` / ``error``   the provider boundary failed.

Usage::

    python scripts/provider_diagnosis.py \
        --report benchmark-artifacts/c_cpp/trial/<stamp>/run-01/report.json \
        [--clusters benchmarks/experiments/balanced_confirmed_tp/baseline_fast_*.json] \
        [--output diagnosis.json]

The optional ``--clusters`` file is the frozen baseline artifact; when given,
only its ``no_evidence_gain_clusters`` ids are diagnosed.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from zscope.core.validation.evidence import (  # noqa: E402
    build_validation_evidence_pack,
    normalize_missing_fact_kinds,
)
from zscope.core.validation.evidence_completion import (  # noqa: E402
    SUPPORTED_FACT_KINDS,
    EvidenceCompletionQueue,
)

_CLASSIFICATION_COLUMNS = (
    "produced",
    "engine_facts_present",
    "empty_no_proof",
    "no_provider",
    "unsupported_kind",
    "timeout",
    "error",
)

_ZERO_SCORE_COMPONENTS = {
    "rule_confidence": 0.0,
    "path_completeness": 0.0,
    "contract_consistency": 0.0,
    "validation_confidence": 0.0,
    "history_feedback": 0.0,
    "final_score": 0.0,
}


def _load_json(path: Path) -> Dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def _build_project_context(project_root: Path):
    """Build a regex CodeIndex so diagnosis can rebuild real validation packs."""

    from zscope.retrieval.code_index import CodeIndex

    index = CodeIndex(
        project_root,
        defer_svf=True,
        wait_for_cpg=False,
        priority_functions=[],
    )
    index.ensure_index_ready()
    return index


def _rebuild_validation_pack(index: Any, issue: Dict[str, Any]) -> Dict[str, Any]:
    """Reconstruct the scan-time validation pack (with ``function_context.code``)."""

    issue_func = str(issue.get("function") or issue.get("entry_function") or "")
    impl = None
    if index is not None and issue_func:
        try:
            impl = index.get_function_impl(issue_func, warn_missing=False)
        except Exception:
            impl = None
    issue_code = str((impl or {}).get("code") or "")
    state = {
        "agent_context": {"func_name": issue_func, "code": issue_code},
        "entry_func": str(issue.get("entry_function") or issue_func),
    }
    return build_validation_evidence_pack(
        issue,
        state,
        issue_code,
        code_index=index,
        snapshot_store=None,
        score_components_fn=lambda i, s: dict(i.get("score_components") or _ZERO_SCORE_COMPONENTS),
    )


def _selected_issues(report: Dict[str, Any], cluster_filter: Optional[set]) -> List[Dict[str, Any]]:
    issues = report.get("issues_with_needs_review")
    if not isinstance(issues, list):
        issues = report.get("issues") or []
    selected = []
    for issue in issues:
        if not isinstance(issue, dict):
            continue
        if cluster_filter is not None:
            uid = str(issue.get("validation_cluster_uid") or "")
            if uid not in cluster_filter:
                continue
        selected.append(issue)
    return selected


# First-gate rules allowlists of the narrow local providers, keyed by the
# fact kinds they are registered for (evidence_completion.py dispatch tables).
# A provider whose gate is rule-agnostic (event-shape driven) is marked with
# the empty allowlist and counted as rule-covered.
_PROVIDER_RULE_ALLOWLISTS: Dict[str, Dict[str, frozenset]] = {
    "lockset": {
        "_local_lock_dominance_proof": frozenset(
            {
                "clang_cfg_global_state_write_without_lock",
                "clang_cfg_global_state_written_with_and_without_lock",
            }
        ),
        "_balanced_lock_protocol_proof": frozenset(
            {"clang_cfg_return_with_lock_held", "clang_cfg_unlock_without_matching_lock"}
        ),
        "_lock_held_on_failure_return_proof": frozenset({"clang_cfg_return_with_lock_held"}),
        # v12 event-shaped providers (kept in sync with the queue tables).
        "_caller_lock_context_proof": frozenset(
            {"clang_cfg_unlock_without_matching_lock", "clang_cfg_refcount_update_after_unlock"}
        ),
        "_source_lockset_dominance_proof": (EvidenceCompletionQueue._SOURCE_LOCKSET_RULES),
    },
    "cleanup_coverage": {
        "_failed_member_acquisition_cleanup_proof": frozenset(
            {"clang_cfg_parent_release_without_owned_member_cleanup"}
        ),
        "_incomplete_owner_cleanup_proof": frozenset(),
        "_lifecycle_protocol_confirmation_proof": frozenset(),
        "_source_lifecycle_acquire_exit_proof": frozenset(
            {"svf_value_flow_memory_leak", "svf_value_flow_partial_memory_leak"}
        ),
    },
    "ownership_transfer": {
        "_fd_transfer_or_failure_proof": frozenset({"clang_cfg_fd_open_return_without_close"}),
        "_resource_transfer_proof": frozenset(),
    },
}


def _provider_gate(issue: Dict[str, Any], fact_kind: str) -> str:
    """Name the first structural gate that blocks proof production."""

    allowlists = _PROVIDER_RULE_ALLOWLISTS.get(fact_kind)
    if allowlists is None:
        return "not_analyzed"
    rule = str(issue.get("rule") or "").lower()
    covered = any(not allowlist or rule in allowlist for allowlist in allowlists.values())
    if not covered:
        return "allowlist_uncovered"
    _ast_cfg, path, _events = EvidenceCompletionQueue._ast_pack(issue)
    if path and path.get("complete_in_function") is not True:
        return "path_incomplete"
    return "covered_deep_gate"


def diagnose_issue(
    queue: EvidenceCompletionQueue,
    issue: Dict[str, Any],
    *,
    validation_evidence: Optional[Dict[str, Any]] = None,
) -> List[Dict[str, Any]]:
    pack = validation_evidence
    if pack is None:
        pack = issue.get("evidence_pack") if isinstance(issue.get("evidence_pack"), dict) else {}
    requested = normalize_missing_fact_kinds(issue.get("missing_fact_kinds"))
    rows: List[Dict[str, Any]] = []
    for fact_kind in requested:
        engine_facts: List[Any] = []
        for source in (issue.get("fact_completion_by_kind"), pack.get("fact_completion_by_kind")):
            if isinstance(source, dict) and source.get(fact_kind):
                engine_facts.extend(source[fact_kind])
        if fact_kind not in SUPPORTED_FACT_KINDS:
            classification = "unsupported_kind"
            generated: List[Dict[str, Any]] = []
            provider_error = ""
        else:
            status, generated, provider_error = queue._run_requested_fact_providers(
                fact_kind, issue, pack
            )
            if status == "timeout":
                classification = "timeout"
            elif status == "provider_error":
                classification = "error"
            elif generated:
                classification = "produced"
            elif engine_facts:
                classification = "engine_facts_present"
            else:
                classification = "empty_no_proof"
        rows.append(
            {
                "validation_cluster_uid": issue.get("validation_cluster_uid"),
                "candidate_uid": issue.get("candidate_uid"),
                "rule_id": issue.get("rule_id"),
                "location": issue.get("location"),
                "fact_kind": fact_kind,
                "classification": classification,
                "engine_fact_count": len(engine_facts),
                "generated_proof_count": len(generated) if classification == "produced" else 0,
                "producer_engines": sorted(
                    {
                        str(proof.get("producer_engine") or "local")
                        for proof in (generated or [])
                        if isinstance(proof, dict)
                    }
                ),
                "error": provider_error if classification == "error" else "",
                "provider_gate": _provider_gate(issue, fact_kind),
            }
        )
    return rows


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", required=True, type=Path)
    parser.add_argument(
        "--project-root",
        type=Path,
        help=(
            "Project root to index (regex backend) so validation packs are rebuilt "
            "with function_context.code exactly like a scan would; without it the "
            "report's candidate pack is used as-is."
        ),
    )
    parser.add_argument("--clusters", type=Path, help="Baseline freeze JSON filtering clusters.")
    parser.add_argument("--output", type=Path, help="Write full JSON report here.")
    parser.add_argument(
        "--fact-timeout",
        type=float,
        default=10.0,
        help="Per-provider-call timeout in seconds (default 10).",
    )
    parser.add_argument(
        "--no-v12",
        action="store_true",
        help="Disable v12 providers (production runs them enabled).",
    )
    arguments = parser.parse_args(argv)

    report = _load_json(arguments.report)
    cluster_filter = None
    if arguments.clusters is not None:
        baseline = _load_json(arguments.clusters)
        cluster_filter = {
            str(row.get("validation_cluster_uid"))
            for row in baseline.get("no_evidence_gain_clusters") or []
            if row.get("validation_cluster_uid")
        }

    queue = EvidenceCompletionQueue(
        enabled=True,
        enable_v11_providers=True,
        enable_v12_providers=not arguments.no_v12,
        fact_timeout_seconds=arguments.fact_timeout,
    )

    issues = _selected_issues(report, cluster_filter)
    index = None
    if arguments.project_root is not None:
        index = _build_project_context(arguments.project_root)
    rows: List[Dict[str, Any]] = []
    for issue in issues:
        validation_evidence = None
        if index is not None:
            validation_evidence = _rebuild_validation_pack(index, issue)
        rows.extend(diagnose_issue(queue, issue, validation_evidence=validation_evidence))

    by_kind: Dict[str, Counter] = defaultdict(Counter)
    for row in rows:
        by_kind[row["fact_kind"]][row["classification"]] += 1
    summary = {kind: dict(counter) for kind, counter in sorted(by_kind.items())}

    report_payload = {
        "schema_version": "zscope.provider-diagnosis.v1",
        "report": arguments.report.as_posix(),
        "cluster_filter": arguments.clusters.as_posix() if arguments.clusters else None,
        "issue_count": len(issues),
        "diagnosis_row_count": len(rows),
        "by_fact_kind": summary,
        "rows": rows,
    }
    if arguments.output is not None:
        arguments.output.parent.mkdir(parents=True, exist_ok=True)
        arguments.output.write_text(
            json.dumps(report_payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
        )

    print(f"issues={len(issues)} rows={len(rows)}")
    header = f"{'fact_kind':<28}" + "".join(f"{key:>21}" for key in _CLASSIFICATION_COLUMNS)
    print(header)
    for kind, counter in summary.items():
        line = f"{kind:<28}"
        for key in _CLASSIFICATION_COLUMNS:
            value = counter.get(key, 0)
            line += f"{value:>21}" if value else f"{'-':>21}"
        print(line)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
