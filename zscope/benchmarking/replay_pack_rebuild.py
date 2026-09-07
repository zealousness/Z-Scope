"""Bundle-side validation-pack rebuild for replay arms (plan Phase 5 / M3).

``validator-replay-bundle.v1`` groups carry the answer-free evidence
projection but deliberately omit ``function_context`` (the function body is
project content, resolved at execution time from the mounted answer-free
project).  The validator-arm replay executors and the provider diagnosis
therefore need one shared, hash-faithful way to rebuild the scan-time
validation pair — the provider-facing issue and the validation evidence
pack — for a bundle group.

The rebuild uses the same ``build_validation_evidence_pack`` as production,
fed by the group's candidate projection (issue-level identity fields) and
the project ``CodeIndex``.  It never touches truth or historical outcomes:
group content was already ``_answer_free``-normalized at export.
"""

from __future__ import annotations

from typing import Any, Dict, Mapping, Optional

from zscope.core.validation.evidence import build_validation_evidence_pack

_FACT_STATE_KEYS = (
    "decision_fact_slice",
    "decision_fact_coverage",
    "missing_fact_kinds",
    "deterministic_proofs",
)


def _group_maps(group: Mapping[str, Any]) -> tuple[Mapping[str, Any], Mapping[str, Any]]:
    raw_candidate = group.get("candidate")
    candidate: Mapping[str, Any] = raw_candidate if isinstance(raw_candidate, Mapping) else {}
    raw_evidence = group.get("evidence")
    evidence: Mapping[str, Any] = raw_evidence if isinstance(raw_evidence, Mapping) else {}
    return candidate, evidence


def group_issue_code(group: Mapping[str, Any], index: Any) -> str:
    """Resolve the primary function body for a bundle group via the index."""

    candidate, evidence = _group_maps(group)
    issue_func = str(
        candidate.get("function")
        or candidate.get("entry_function")
        or evidence.get("entry_function")
        or evidence.get("entry_identity")
        or ""
    )
    if not issue_func or index is None:
        return ""
    try:
        impl = index.get_function_impl(issue_func, warn_missing=False)
    except Exception:
        return ""
    return str((impl or {}).get("code") or "")


def rebuild_group_issue(group: Mapping[str, Any], index: Any) -> Dict[str, Any]:
    """Build the provider-facing issue for a bundle group.

    Providers parse line-numbered source (``N | text``); the index body is
    numbered with absolute file lines while the exported candidate snippet
    is raw.  The numbered body therefore replaces the raw snippet so
    providers that read ``code_snippet`` behave identically to the
    scan-time report path.
    """

    candidate, evidence = _group_maps(group)
    issue_func = str(
        candidate.get("function")
        or candidate.get("entry_function")
        or evidence.get("entry_function")
        or evidence.get("entry_identity")
        or ""
    )
    issue_code = group_issue_code(group, index)
    issue: Dict[str, Any] = dict(candidate)
    issue.setdefault("function", issue_func)
    issue.setdefault("entry_function", issue_func)
    # Cluster identity lives on the group root; providers and diagnosis rows
    # key off the issue, so surface it at issue level.
    if not issue.get("validation_cluster_uid"):
        issue["validation_cluster_uid"] = str(group.get("validation_cluster_uid") or "")
    # Production issues carry the full evidence pack (ast_cfg events, call
    # paths, security obligation) at issue level; provider gates read it
    # from there, so the group evidence takes that slot.
    issue["evidence_pack"] = dict(evidence)
    if issue_code:
        issue["code_snippet"] = issue_code
    # The group evidence carries scan-time fact-slice state; production
    # issues expose those at top level and the provider gates read them there.
    for key in _FACT_STATE_KEYS:
        value = evidence.get(key)
        if value not in (None, "", [], {}):
            issue[key] = value
    return issue


def rebuild_group_validation_pack(
    group: Mapping[str, Any],
    index: Any,
    *,
    score_components_fn: Optional[Any] = None,
) -> Dict[str, Any]:
    """Rebuild the scan-time validation pack for one canonical bundle group."""

    candidate, evidence = _group_maps(group)
    issue_func = str(
        candidate.get("function")
        or candidate.get("entry_function")
        or evidence.get("entry_function")
        or evidence.get("entry_identity")
        or ""
    )
    issue = rebuild_group_issue(group, index)
    issue_code = group_issue_code(group, index)
    state = {
        "agent_context": {"func_name": issue_func, "code": issue_code},
        "entry_func": str(candidate.get("entry_identity") or issue_func),
    }
    if score_components_fn is None:

        def score_components_fn(issue: Dict[str, Any], score: Dict[str, Any]) -> Dict[str, Any]:
            return {}

    return build_validation_evidence_pack(
        issue,
        state,
        issue_code,
        code_index=index,
        snapshot_store=None,
        score_components_fn=score_components_fn,
    )
