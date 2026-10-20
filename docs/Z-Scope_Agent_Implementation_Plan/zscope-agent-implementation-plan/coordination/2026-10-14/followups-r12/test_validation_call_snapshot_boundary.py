"""Submitted native call identities must not change with the parent's mutable map."""
import os
from pathlib import Path
import sys
import threading

# Frozen probes can run from artifacts; use the known original coordinator path.
root = Path(os.environ["PYTHONPATH"]).parents[3]
original_probes = root / "docs/Z-Scope_Agent_Implementation_Plan/zscope-agent-implementation-plan/coordination/2026-10-14/followups-r12"
sys.path.insert(0, str(original_probes))
sys.path.insert(0, str(Path(os.environ["PYTHONPATH"]) / "tests"))
from test_validation_callee_rebind_boundary import native_overloads, setup_native
from zscope.core.validation.evidence_completion import EvidenceCompletionQueue
from zscope.core.validation.execution_context import current_execution_context, rebound_execution_context
from zscope.semantics.call_context import bind_call_context, current_call_facts, current_callee_usr


def test_captured_mixed_native_map_is_frozen_against_parent_mutation(native_overloads):
    index, _ = native_overloads
    registry, _, int_usr, _, mixed, _ = setup_native(index)
    with bind_call_context(mixed, registry):
        assert current_callee_usr(registry, "log_event") == ""
        captured = current_execution_context()
        parent_map = current_call_facts()
        parent_map[2]["log_event"] = int_usr
        with rebound_execution_context(captured):
            assert current_callee_usr(registry, "log_event") == "", (
                "a captured mixed native identity cannot change when the parent map changes"
            )
            assert registry.match_call("log_event", "io_acquire", ["mode"]) == []


def test_real_provider_keeps_submit_time_native_identity_snapshot(native_overloads):
    index, _ = native_overloads
    registry, _, int_usr, _, mixed, _ = setup_native(index)
    queue = EvidenceCompletionQueue(enabled=True, max_workers=1, fact_timeout_seconds=30)
    inside, release = threading.Event(), threading.Event()
    parent_bindings, observed, errors = [], [], []

    def provider(fact_kind, issue, validation_evidence):
        inside.set()
        assert release.wait(15)
        observed.append((current_callee_usr(registry, "log_event"), [m.symbol.usr for m in registry.match_call("log_event", "io_acquire", ["mode"])]))
        return []

    queue._requested_completion_proofs = provider

    def resolve():
        try:
            with bind_call_context(mixed, registry):
                parent_bindings.append(current_call_facts())
                queue.resolve_requested_fact({"validation_cluster_uid": "VAL_SNAPSHOT", "evidence_pack": {}}, validator_data={"verdict": "uncertain", "missing_fact_request": {"fact_kind": "lockset"}}, validation_evidence={})
        except BaseException as exc:
            errors.append(exc)

    resolver = threading.Thread(target=resolve)
    try:
        resolver.start()
        assert inside.wait(15)
        parent_bindings[0][2]["log_event"] = int_usr
        release.set()
        resolver.join(30)
        assert not resolver.is_alive() and not errors
        assert observed == [("", [])], (
            "the real fact-provider framework must freeze native call facts at submit"
        )
    finally:
        release.set()
        resolver.join(30)
        queue._fact_provider_executor.shutdown(wait=True)
