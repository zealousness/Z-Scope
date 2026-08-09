from zscope.core.candidates.decision_facts import (
    DECISION_CONTEXT_V31,
    DECISION_FACT_VERSION,
    DecisionFactGraphCache,
    attach_decision_facts,
)
from zscope.core.validation.proofs import deterministic_decision_proof
from zscope.orchestration.candidate_envelope import annotate_issue_identity


def _signed_length_issue() -> dict:
    return {
        "project_id": "demo",
        "revision": "rev-1",
        "function": "parse_packet(size_t)",
        "file": "src/parser.c",
        "category": "signed_unsigned",
        "source_identity": "recv_result",
        "sink_identity": "memcpy.length",
        "resource_identity": "packet.length",
        "evidence_pack": {
            "dependency_code_hash": "code-v1",
            "path": {"function": "parse_packet(size_t)", "complete_in_function": True},
            "ast_cfg": {
                "events": [
                    {"kind": "signed_io_result", "line": 10, "variable": "count"},
                    {"kind": "signed_to_unsigned_cast", "line": 11, "variable": "count"},
                    {"kind": "unsigned_length_sink", "line": 12, "variable": "count"},
                ]
            },
        },
    }


def test_decision_facts_attach_auditable_signed_length_proof() -> None:
    issue = _signed_length_issue()

    obligation = attach_decision_facts(issue)

    assert issue["decision_fact_version"] == DECISION_FACT_VERSION
    assert obligation.decision_fact_slice is not None
    assert obligation.decision_fact_slice.coverage == "complete"
    proof = deterministic_decision_proof(issue, outcome="confirm")
    assert proof is not None
    assert proof.proof_kind == "out_of_range_value_reaches_sink"
    assert proof.code_hash == "code-v1"
    assert proof.fact_ids


def test_decision_facts_hashes_the_source_snapshot_when_detector_hash_is_missing() -> None:
    issue = _signed_length_issue()
    issue.pop("project_id")
    issue["code_snippet"] = "int parse_packet(int count) { return (size_t)count; }"
    issue["evidence_pack"].pop("dependency_code_hash")

    attach_decision_facts(issue)

    fact_slice = issue["decision_fact_slice"]
    assert fact_slice["dependency_code_hashes"]
    assert fact_slice["dependency_code_hashes"][0].startswith("SNAP_")
    proof = deterministic_decision_proof(issue, outcome="confirm")
    assert proof is not None
    assert proof.code_hash == fact_slice["dependency_code_hashes"][0]


def test_v31_identity_uses_structured_obligation_not_detector_or_wrapper() -> None:
    base = {
        "id": "ISSUE_1",
        "location": "src/parser.c:42",
        "function": "parse_packet(size_t)",
        "category": "bounds",
        "source": "len",
        "sink": "memcpy(dst, src, len)",
        "decision_fact_graph_v1": True,
        "entry_identity": "api_wrapper_a",
        "evidence_pack": {
            "dependency_code_hash": "code-v1",
            "path": {"function": "parse_packet(size_t)", "complete_in_function": True},
            "source": {"expression": "len", "file": "src/parser.c", "line": 38},
            "sink": {"operation": "memcpy(dst, src, len)", "file": "src/parser.c", "line": 42},
            "ast_cfg": {"events": [{"kind": "header_length", "line": 38}, {"kind": "header_length_copy", "line": 42}]},
        },
    }
    first = {**base, "rule": "regex_copy_rule", "evidence_pack": dict(base["evidence_pack"])}
    second = {
        **base,
        "id": "ISSUE_99",
        "rule": "clang_bounds_matcher",
        "entry_identity": "api_wrapper_b",
        "evidence_pack": dict(base["evidence_pack"]),
    }

    first_envelope = annotate_issue_identity(
        first,
        project_id="demo",
        project_root=".",
        revision="rev-1",
        entry_function="api_wrapper_a",
    )
    second_envelope = annotate_issue_identity(
        second,
        project_id="demo",
        project_root=".",
        revision="rev-1",
        entry_function="api_wrapper_b",
    )

    assert first_envelope.decision_context_version == DECISION_CONTEXT_V31
    assert first_envelope.obligation_shape == "sink_sensitive"
    assert first_envelope.candidate_uid == second_envelope.candidate_uid
    assert first_envelope.validation_cluster_uid == second_envelope.validation_cluster_uid
    assert first_envelope.occurrence_uid != second_envelope.occurrence_uid


def test_decision_fact_rejection_requires_explicit_dominance_relation() -> None:
    issue = _signed_length_issue()
    issue["evidence_pack"]["proof_facts"] = {"guard_dominates_sink": True}

    attach_decision_facts(issue)

    assert deterministic_decision_proof(issue, outcome="reject") is not None
    # Both directions are intentionally retained as an evidence conflict.
    assert deterministic_decision_proof(issue, outcome="confirm") is not None


def test_fact_cache_reuses_equivalent_evidence_but_not_another_obligation() -> None:
    cache = DecisionFactGraphCache(max_entries=2)
    first = _signed_length_issue()
    second = _signed_length_issue()
    different = _signed_length_issue()
    different["sink_identity"] = "calloc.size"
    different["evidence_pack"] = {
        **different["evidence_pack"],
        "ast_cfg": {"events": [{"kind": "allocation_size", "line": 42}]},
    }

    assert cache.get_or_build(first) is cache.get_or_build(second)
    assert cache.get_or_build(first) is not cache.get_or_build(different)


def test_partial_fact_slice_is_only_shadow_promotion_ineligible() -> None:
    issue = _signed_length_issue()
    issue["evidence_pack"]["path"] = {"function": "parse_packet(size_t)"}

    attach_decision_facts(issue)

    assert issue["candidate_promotion_eligible"] is False
    assert issue["candidate_promotion_reason"] == "missing_required_decision_facts"
