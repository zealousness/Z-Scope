"""Tests for the source-lifecycle acquire/exit fact provider (plan Phase 1.2).

The provider re-derives ``event:acquire``/``event:exit`` lifecycle facts from
the validator's function source for value-flow leak candidates whose engine
supplied no CFG events, and confirms the path-independent negative existential
(allocation with no release and no ownership transfer in the whole body).
"""

from __future__ import annotations

from typing import Any, Dict, Optional
from dataclasses import asdict
from semantic_fixtures import configured_test_semantics

from zscope.core.validation.evidence_completion import EvidenceCompletionQueue
from zscope.core.validation.proofs import deterministic_decision_proof


def _queue() -> EvidenceCompletionQueue:
    return EvidenceCompletionQueue(
        enabled=True,
        enable_v11_providers=True,
        enable_v12_providers=True,
        fact_timeout_seconds=5.0,
    )


def _issue(**overrides: Any) -> Dict[str, Any]:
    issue: Dict[str, Any] = {
        "id": "ISSUE_SVF_LEAK",
        "rule": "svf_value_flow_memory_leak",
        "function": "allocate_packet",
        "missing_fact_kinds": ["event:acquire", "event:exit"],
    }
    issue.update(overrides)
    return issue


def _pack(code: Optional[str]) -> Dict[str, Any]:
    return {
        "function_context": {"code": code or ""},
        "semantic_contracts": {
            "api_contracts": [asdict(c) for c in configured_test_semantics().contracts.contracts]
        },
    }


def test_names_cannot_create_allocation_proofs() -> None:
    for name in ("_safe_malloc", "fake_malloc", "inspect_malloc"):
        code = f"void f(void) {{ void *p={name}(8); }}"
        _, proofs, _ = _run(_issue(), {"function_context": {"code": code}})
        assert proofs == []


def _run(issue: Dict[str, Any], pack: Dict[str, Any]) -> tuple[str, list, str]:
    queue = _queue()
    return queue._run_requested_fact_providers("cleanup_coverage", issue, pack)


def test_unreleased_allocation_confirms_leak() -> None:
    code = (
        "int allocate_packet(void) {\n"
        "    packet_t *pkt = _safe_malloc(sizeof(packet_t));\n"
        "    if (!pkt->header) {\n"
        "        return -1;\n"
        "    }\n"
        "    pkt->header->len = 8;\n"
        "    return 0;\n"
        "}\n"
    )
    status, generated, error = _run(_issue(), _pack(code))

    assert status == "completed"
    assert error == ""
    assert len(generated) == 1
    proof = generated[0]
    assert proof["outcome"] == "confirm"
    assert proof["proof_kind"] == "source_lifecycle_acquire_without_release"
    assert proof["producer_engine"] == "source_lifecycle_event_facts_v12"
    assert "event:acquire" in proof["facts"]
    assert "event:exit" in proof["facts"]
    assert proof["subject_identity"] == "pkt"
    assert proof["completeness"] == "complete"


def test_freed_allocation_produces_no_proof() -> None:
    code = (
        "int allocate_packet(void) {\n"
        "    packet_t *pkt = _safe_malloc(sizeof(packet_t));\n"
        "    if (!pkt) {\n"
        "        return -1;\n"
        "    }\n"
        "    SAFE_FREE(pkt);\n"
        "    return 0;\n"
        "}\n"
    )
    status, generated, _ = _run(_issue(), _pack(code))

    assert status == "completed"
    assert generated == []


def test_return_transfer_produces_no_proof() -> None:
    code = (
        "packet_t *allocate_packet(void) {\n"
        "    packet_t *pkt = malloc(sizeof(packet_t));\n"
        "    if (!pkt) {\n"
        "        return NULL;\n"
        "    }\n"
        "    return pkt;\n"
        "}\n"
    )
    status, generated, _ = _run(_issue(), _pack(code))

    assert status == "completed"
    assert generated == []


def test_output_param_transfer_produces_no_proof() -> None:
    code = (
        "int serialize_task(uint8_t **buffer) {\n"
        "    uint8_t *data = _safe_malloc(total_len);\n"
        "    *buffer = data;\n"
        "    return 0;\n"
        "}\n"
    )
    status, generated, _ = _run(_issue(), _pack(code))

    assert status == "completed"
    assert generated == []


def test_non_value_flow_rule_is_ignored() -> None:
    code = "int f(void) { char *p = malloc(4); return 0; }\n"
    status, generated, _ = _run(_issue(rule="clang_cfg_use_after_release"), _pack(code))

    assert status == "completed"
    assert generated == []


def test_missing_function_code_produces_no_proof() -> None:
    status, generated, _ = _run(_issue(), _pack(None))

    assert status == "completed"
    assert generated == []


def test_multiple_allocation_sites_pin_unclean_subject() -> None:
    code = (
        "int allocate_two(void) {\n"
        "    packet_t *a = _safe_malloc(sizeof(packet_t));\n"
        "    packet_t *b = _safe_malloc(sizeof(packet_t));\n"
        "    SAFE_FREE(a);\n"
        "    return 0;\n"
        "}\n"
    )
    status, generated, _ = _run(_issue(), _pack(code))

    assert status == "completed"
    assert len(generated) == 1
    assert generated[0]["subject_identity"] == "b"


def test_all_allocations_clean_produces_no_proof() -> None:
    code = (
        "int allocate_two(void) {\n"
        "    packet_t *a = _safe_malloc(sizeof(packet_t));\n"
        "    packet_t *b = _safe_malloc(sizeof(packet_t));\n"
        "    SAFE_FREE(a);\n"
        "    SAFE_FREE(b);\n"
        "    return 0;\n"
        "}\n"
    )
    status, generated, _ = _run(_issue(), _pack(code))

    assert status == "completed"
    assert generated == []


def test_address_of_escape_stays_reviewable() -> None:
    code = (
        "int td_init(void) {\n"
        "    thread_ids = _safe_calloc(count, sizeof(pthread_t));\n"
        "    pthread_create(&thread_ids[0], NULL, worker, NULL);\n"
        "    return 0;\n"
        "}\n"
    )
    status, generated, _ = _run(_issue(), _pack(code))

    assert status == "completed"
    assert generated == []


def test_ownership_transfer_registration_reaches_provider() -> None:
    code = (
        "int allocate_packet(void) {\n"
        "    packet_t *pkt = _safe_malloc(sizeof(packet_t));\n"
        "    return 0;\n"
        "}\n"
    )
    queue = _queue()
    status, generated, _ = queue._run_requested_fact_providers(
        "ownership_transfer", _issue(), _pack(code)
    )

    assert status == "completed"
    assert any(
        proof.get("proof_kind") == "source_lifecycle_acquire_without_release" for proof in generated
    )


# ----------------------------------------------------------------------
# source lockset dominance (unsynchronized-access refutation)
# ----------------------------------------------------------------------


def _lock_issue(**overrides: Any) -> Dict[str, Any]:
    issue: Dict[str, Any] = {
        "id": "ISSUE_UNSYNC",
        "rule": "clang_cfg_unsynchronized_shared_flag_or_counter",
        "function": "td_cleanup",
        "source": "g_running",
        "sink": "g_running = 0;",
        "missing_fact_kinds": ["event:shared_state_access", "lockset"],
    }
    issue.update(overrides)
    return issue


def test_read_sink_stays_reviewable_even_when_writes_locked() -> None:
    code = (
        "void td_cleanup(void) {\n"
        "    LOCK(&g_lifecycle.lock);\n"
        "    g_running = 0;\n"
        "    UNLOCK(&g_lifecycle.lock);\n"
        "}\n"
    )
    queue = _queue()
    status, generated, _ = queue._run_requested_fact_providers(
        "lockset",
        _lock_issue(sink="char *old = g_active_config;"),
        _pack(code),
    )

    assert status == "completed"
    assert generated == []


def test_writes_under_single_lock_rejects_unsynchronized_claim() -> None:
    code = (
        "void td_cleanup(void) {\n"
        "    LOCK(&g_lifecycle.lock);\n"
        "    g_running = 0;\n"
        "    g_active_config = NULL;\n"
        "    UNLOCK(&g_lifecycle.lock);\n"
        "}\n"
    )
    queue = _queue()
    status, generated, _ = queue._run_requested_fact_providers(
        "lockset", _lock_issue(), _pack(code)
    )

    assert status == "completed"
    assert len(generated) == 1
    proof = generated[0]
    assert proof["outcome"] == "reject"
    assert proof["proof_kind"] == "source_lockset_dominates_access"
    assert proof["producer_engine"] == "source_lockset_event_facts_v12"
    assert proof["subject_identity"] == "g_running"
    assert any(
        item.startswith("all_writes_guarded_by:&g_lifecycle.lock") for item in proof["facts"]
    )


def test_unguarded_write_keeps_claim_reviewable() -> None:
    code = (
        "void td_cleanup(void) {\n"
        "    if (g_shutdown_done) {\n"
        "        g_running = 0;\n"
        "    }\n"
        "}\n"
    )
    queue = _queue()
    status, generated, _ = queue._run_requested_fact_providers(
        "lockset", _lock_issue(), _pack(code)
    )

    assert status == "completed"
    assert generated == []


def test_mixed_locks_produce_no_proof() -> None:
    code = (
        "void td_cleanup(void) {\n"
        "    LOCK(&lock_a);\n"
        "    g_running = 0;\n"
        "    UNLOCK(&lock_a);\n"
        "    LOCK(&lock_b);\n"
        "    g_running = 2;\n"
        "    UNLOCK(&lock_b);\n"
        "}\n"
    )
    queue = _queue()
    status, generated, _ = queue._run_requested_fact_providers(
        "lockset", _lock_issue(), _pack(code)
    )

    assert status == "completed"
    assert generated == []


def test_unlock_requirement_holds() -> None:
    code = "void td_cleanup(void) {\n" "    LOCK(&g_lifecycle.lock);\n" "    g_running = 0;\n" "}\n"
    queue = _queue()
    status, generated, _ = queue._run_requested_fact_providers(
        "lockset", _lock_issue(), _pack(code)
    )

    assert status == "completed"
    assert generated == []


def test_happens_before_registration_reaches_new_provider() -> None:
    code = (
        "void td_cleanup(void) {\n"
        "    LOCK(&g_lifecycle.lock);\n"
        "    g_running += 1;\n"
        "    UNLOCK(&g_lifecycle.lock);\n"
        "}\n"
    )
    queue = _queue()
    status, generated, _ = queue._run_requested_fact_providers(
        "happens_before", _lock_issue(), _pack(code)
    )

    assert status == "completed"
    assert any(proof.get("proof_kind") == "source_lockset_dominates_access" for proof in generated)


# ----------------------------------------------------------------------
# Phase 1.3: provider proofs reach the V0 deterministic-proof interface
# ----------------------------------------------------------------------


def _resolver(queue: EvidenceCompletionQueue):
    def resolve(fact_kind: str, issue: Dict[str, Any], pack: Dict[str, Any]):
        synthetic = {
            "verdict": "uncertain",
            "missing_fact_request": {
                "fact_kind": fact_kind,
                "subject_uid": str(issue.get("source") or issue.get("function") or ""),
                "function_uid": str(issue.get("function") or ""),
                "reason": f"security obligation requires {fact_kind}",
            },
        }
        return queue.resolve_requested_fact(
            issue, validator_data=synthetic, validation_evidence=pack
        )

    return resolve


def test_leak_confirm_proof_is_authoritative_and_reaches_v0() -> None:
    code = (
        "int allocate_packet(void) {\n"
        "    packet_t *pkt = _safe_malloc(sizeof(packet_t));\n"
        "    if (!pkt->header) {\n"
        "        return -1;\n"
        "    }\n"
        "    return 0;\n"
        "}\n"
    )
    issue = _issue()
    resolution = _resolver(_queue())("cleanup_coverage", issue, _pack(code))

    assert resolution is not None and resolution.proof_added is True
    assert issue["evidence_completion_status"] == "completed"
    # The accepted proof is promoted into the stable deterministic-proof
    # interface that the pipeline's V0 routing consumes.
    attached = issue.get("deterministic_proofs") or []
    assert any(
        item.get("proof_kind") == "source_lifecycle_acquire_without_release"
        for item in attached
        if isinstance(item, dict)
    )
    decision = deterministic_decision_proof(issue, outcome="confirm")
    assert decision is not None
    assert decision.proof_kind == "source_lifecycle_acquire_without_release"
    assert decision.producer_engine == "source_lifecycle_event_facts_v12"
    assert decision.outcome == "confirm"


def test_leak_confirm_proof_declined_without_release_facts() -> None:
    """A hand-minted proof missing the exact fact set must stay unusable."""

    issue = _issue(
        deterministic_proofs=[
            {
                "outcome": "confirm",
                "proof_kind": "source_lifecycle_acquire_without_release",
                "producer_engine": "source_lifecycle_event_facts_v12",
                "completeness": "complete",
                "scope": "whole function body",
                "facts": ["event:acquire"],
                "fact_ids": ["source_cfg:1"],
                "code_hash": "0" * 64,
                "subject_identity": "p",
            }
        ]
    )

    assert deterministic_decision_proof(issue, outcome="confirm") is None


def test_lockset_reject_proof_is_authoritative_and_reaches_v0() -> None:
    code = (
        "void td_cleanup(void) {\n"
        "    LOCK(&g_lifecycle.lock);\n"
        "    g_running = 0;\n"
        "    UNLOCK(&g_lifecycle.lock);\n"
        "}\n"
    )
    issue = _lock_issue()
    resolution = _resolver(_queue())("lockset", issue, _pack(code))

    assert resolution is not None and resolution.proof_added is True
    attached = issue.get("deterministic_proofs") or []
    assert any(
        item.get("proof_kind") == "source_lockset_dominates_access"
        for item in attached
        if isinstance(item, dict)
    )
    decision = deterministic_decision_proof(issue, outcome="reject")
    assert decision is not None
    assert decision.proof_kind == "source_lockset_dominates_access"
    assert decision.outcome == "reject"


# ----------------------------------------------------------------------
# caller lock context (interprocedural lock-protocol refutation)
# ----------------------------------------------------------------------


class _StubIndex:
    def get_function_impl(self, func_name: str, warn_missing: bool = True, max_lines=None):
        bodies = {
            "td_process_control_message": (
                "void td_process_control_message(void) {\n"
                "    LOCK(&g_lifecycle.lock);\n"
                '    _lifecycle_ref_get("k");\n'
                "    UNLOCK(&g_lifecycle.lock);\n"
                "}\n"
            ),
            "td_unguarded_caller": (
                "void td_unguarded_caller(void) {\n" '    _lifecycle_ref_get("k");\n' "}\n"
            ),
        }
        code = bodies.get(func_name)
        return {"code": code} if code else None


def _caller_lock_issue(**overrides: Any) -> Dict[str, Any]:
    issue: Dict[str, Any] = {
        "id": "ISSUE_UNLOCK",
        "rule": "clang_cfg_unlock_without_matching_lock",
        "function": "_lifecycle_ref_get",
        "line": 2767,
        "call_paths": [["td_process_control_message", "_lifecycle_ref_get"]],
        "missing_fact_kinds": ["event:shared_state_access", "lockset"],
    }
    issue.update(overrides)
    return issue


def test_caller_lock_states_extracted_from_call_paths() -> None:
    from zscope.core.validation.evidence import _caller_lock_states

    states = _caller_lock_states(
        _StubIndex(),
        "_lifecycle_ref_get",
        ["td_process_control_message", "td_unguarded_caller", "td_missing_caller"],
        semantic_contracts=_pack(None)["semantic_contracts"],
    )

    assert len(states) == 3
    guarded = states[0]
    assert guarded["caller"] == "td_process_control_message"
    assert guarded["resolved"] is True
    assert guarded["held_lock"] == "&g_lifecycle.lock"
    assert guarded["call_site_line"] == 3
    unguarded = states[1]
    assert unguarded["resolved"] is True
    assert unguarded["held_lock"] == ""
    missing = states[2]
    assert missing["resolved"] is False


def test_call_site_without_match_is_unresolved() -> None:
    from zscope.core.validation.evidence import _caller_lock_states

    class _DivergentIndex(_StubIndex):
        def get_function_impl(self, func_name: str, warn_missing: bool = True, max_lines=None):
            if func_name == "td_process_control_message":
                return {"code": "void other_func(void) { _unrelated(); }\n"}
            return None

    states = _caller_lock_states(
        _DivergentIndex(), "_lifecycle_ref_get", ["td_process_control_message"]
    )

    assert len(states) == 1
    assert states[0]["resolved"] is False
    assert states[0]["held_lock"] == ""


def test_lexical_caller_context_cannot_reject_unlock_claim() -> None:
    pack = {
        "function_context": {
            "code": "void _lifecycle_ref_get(void) { UNLOCK(&g_lifecycle.lock); }\n"
        },
        "caller_lock_states": [
            {
                "caller": "td_a",
                "call_site_line": 3,
                "held_lock": "g_lifecycle.lock",
                "held_lock_mode": "exclusive",
                "resolved": True,
            },
            {
                "caller": "td_b",
                "call_site_line": 7,
                "held_lock": "g_lifecycle.lock",
                "held_lock_mode": "exclusive",
                "resolved": True,
            },
        ],
    }
    issue = _caller_lock_issue()
    resolution = _resolver(_queue())("lockset", issue, pack)

    assert resolution is not None and not resolution.proof_added
    assert deterministic_decision_proof(issue, outcome="reject") is None


def test_caller_lock_context_declines_unguarded_caller() -> None:
    pack = {
        "function_context": {
            "code": "void _lifecycle_ref_get(void) { UNLOCK(&g_lifecycle.lock); }\n"
        },
        "caller_lock_states": [
            {
                "caller": "td_a",
                "call_site_line": 3,
                "held_lock": "g_lifecycle.lock",
                "resolved": True,
            },
            {"caller": "td_unguarded", "call_site_line": 2, "held_lock": "", "resolved": True},
        ],
    }
    status, generated, _ = _run(_caller_lock_issue(), pack)

    assert status == "completed"
    assert generated == []


def test_caller_lock_context_declines_unresolved_caller() -> None:
    pack = {
        "function_context": {
            "code": "void _lifecycle_ref_get(void) { UNLOCK(&g_lifecycle.lock); }\n"
        },
        "caller_lock_states": [
            {
                "caller": "td_a",
                "call_site_line": 3,
                "held_lock": "g_lifecycle.lock",
                "resolved": True,
            },
            {"caller": "td_missing", "call_site_line": 0, "held_lock": "", "resolved": False},
        ],
    }
    status, generated, _ = _run(_caller_lock_issue(), pack)

    assert status == "completed"
    assert generated == []


def test_caller_lock_context_ignored_for_other_rules() -> None:
    pack = {
        "function_context": {"code": "void f(void) { UNLOCK(&m); }\n"},
        "caller_lock_states": [
            {"caller": "td_a", "call_site_line": 3, "held_lock": "m", "resolved": True}
        ],
    }
    status, generated, _ = _run(_caller_lock_issue(rule="clang_cfg_use_after_release"), pack)

    assert status == "completed"
    assert generated == []
