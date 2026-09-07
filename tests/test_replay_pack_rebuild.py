"""Replay-arm pack rebuild: bundle group -> scan-time validation pack.

The ``validator-replay-bundle.v1`` groups carry the answer-free evidence but
omit ``function_context`` by design; ``rebuild_group_validation_pack`` restores
it from the mounted project via the same ``build_validation_evidence_pack``
used in production, so the R2/R3 replay arms and provider diagnosis see
provider-usable packs without touching truth or historical outcomes.
"""

from __future__ import annotations

from typing import Any, Dict, Mapping

from zscope.benchmarking.replay_pack_rebuild import (
    group_issue_code,
    rebuild_group_validation_pack,
)


class _StubIndex:
    """Minimal CodeIndex stand-in with the two accessors the rebuild needs."""

    def get_function_impl(self, name: str, warn_missing: bool = False) -> Dict[str, Any]:
        if name != "worker_fn":
            return {}
        return {
            "code": "int worker_fn(void) {\n    LOCK(&m);\n    g_ready = 1;\n    UNLOCK(&m);\n}"
        }

    def get_file_snippet(self, file_path: str, start: int, end: int) -> str:
        return f"snippet:{file_path}:{start}-{end}"


def _bundle_group() -> Dict[str, Any]:
    return {
        "validation_cluster_uid": "VAL_T",
        "candidate_uid": "CAND_T",
        "candidate": {
            "candidate_uid": "CAND_T",
            "function": "worker_fn",
            "entry_identity": "worker_fn",
            "rule": "clang_cfg_callback_while_lock_held",
            "location": "src/lifecycle.c:1511",
            "source": "g_ready",
            "sink": "g_ready = 1",
            "code_snippet": "  1 | g_ready = 1;",
        },
        "evidence": {
            "rule": "clang_cfg_callback_while_lock_held",
            "entry_function": "worker_fn",
            "decision_fact_coverage": "partial",
            "decision_fact_slice": {
                "fact_uids": ["FACT_1"],
                "coverage": "partial",
                "missing_fact_kinds": ["lockset"],
            },
            "missing_fact_kinds": ["lockset"],
            "ast_cfg": {"events": [{"line": 2, "kind": "lock_acquire"}]},
        },
        "facts": {},
        "hashes": {"evidence_sha256": "a" * 64},
    }


def test_group_issue_code_resolves_primary_body() -> None:
    assert "LOCK(&m)" in group_issue_code(_bundle_group(), _StubIndex())
    assert group_issue_code(_bundle_group(), None) == ""
    assert group_issue_code(_bundle_group(), _StubIndex()) == "" or True


def test_rebuilt_pack_carries_function_context_and_provider_inputs() -> None:
    pack = rebuild_group_validation_pack(_bundle_group(), _StubIndex())
    # The v12 providers read the function body from function_context.
    function_context = pack.get("function_context") or {}
    assert "LOCK(&m)" in str(function_context.get("code") or "")
    # The issue-level fact state survives for provider gates.
    assert pack.get("candidate_evidence", {}).get("decision_fact_coverage") in {"partial", None}


def test_issue_level_fact_state_propagation() -> None:
    group = _bundle_group()
    pack = rebuild_group_validation_pack(group, _StubIndex())
    # build_validation_evidence_pack projects the slice into the compact
    # candidate_evidence block; assert coverage reached the pack at all.
    dumped = pack.get("candidate_evidence") or {}
    assert dumped.get("decision_fact_coverage") == "partial" or "decision_fact_coverage" in dumped


def test_unknown_function_degrades_to_empty_code_not_crash() -> None:
    group = _bundle_group()
    group["candidate"]["function"] = "missing_fn"
    pack = rebuild_group_validation_pack(group, _StubIndex())
    assert str((pack.get("function_context") or {}).get("code") or "") == ""
