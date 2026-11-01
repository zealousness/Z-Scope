"""Retention is source evidence; release responsibility remains a separate contract."""

import os
from types import SimpleNamespace

import pytest

from test_resource_protocol_baseline import protocol_project
from test_wrapper_contract_compiler import publish
from zscope.retrieval.clang_backend import ClangBackend
from zscope.retrieval.code_index import CodeIndex
from zscope.semantics.build_scope import bind_build_scope
from zscope.semantics.contract_compiler import compile_snapshot
from zscope.semantics.contract_conditions import compare
from zscope.semantics.contracts import ApiContract, ContractRegistry
from zscope.semantics.retention_protocols import verify_retention_contract


def proposal(role="reference_retention"):
    return {
        "role": role,
        "carrier": {"kind": "argument", "argument_index": 1},
        "resource_domain": {"kind": "argument", "argument_index": 0},
        "protocol": {"kind": "single_slot_retention", "slot_path": "->pending"},
        "effect_cases": [{"when": compare({"kind": "return"}, "==", 0), "effect": "applies"}],
        "evidence": [{"lines": "2"}],
    }


def context():
    return {
        "func_name": "enqueue",
        "file_path": "queue.c",
        "signature": "int enqueue(Queue *q, Node *p, int reject)",
        "code": "int enqueue(Queue *q, Node *p, int reject) {\n if (reject || q->pending) return -1;\n q->pending = p;\n return 0;\n}\n",
        "program_facts": {
            "complete": True,
            "build_context_id": "build-a",
            "functions": [
                {
                    "fact_version": "zscope.program-events.v7",
                    "resource_protocol_facts_version": "zscope.resource-protocol-facts.v1",
                    "complete": True,
                    "owner": {"name": "enqueue", "usr": "c:@F@enqueue"},
                    "events": [
                        {
                            "event_kind": "assignment",
                            "event_id": "store-1",
                            "expression": "q->pending = p",
                            "contains_macro": False,
                        },
                        {
                            "event_kind": "return",
                            "expression": "return -1",
                            "contains_macro": False,
                        },
                        {"event_kind": "return", "expression": "return 0", "contains_macro": False},
                    ],
                }
            ],
        },
    }


def test_verified_store_never_grants_proposed_ownership_transfer():
    ctx = context()
    result = verify_retention_contract(proposal("ownership_transfer"), ctx)
    assert result
    contract = ApiContract.from_row({"contract": result})
    assert contract.effects_trusted
    assert contract.role == "reference_retention"
    assert contract.protocol["release_responsibility"] == "unresolved"
    registry = ContractRegistry([contract])
    with bind_build_scope(ctx):
        assert not registry.match_call("enqueue", "ownership_transfer", ["queue", "node", "0"], "0")
        transitions = registry.resolved_transitions("enqueue", ["queue", "node", "0"], "0")
        active = [item for item in transitions if item["applicability"] == "applies"]
        assert len(active) == 1
        assert active[0]["actions"] == [
            {"kind": "retain_reference", "object": "node", "new": "queue->pending"}
        ]
        failed = registry.resolved_transitions("enqueue", ["queue", "node", "1"], "-1")
        assert [t["actions"][0]["kind"] for t in failed if t["applicability"] == "applies"] == [
            "retention_unchanged"
        ]
        unchecked = registry.resolved_transitions("enqueue", ["queue", "node", "flag"], "status")
        assert all(t["applicability"] == "unknown" for t in unchecked)
    assert not registry.resolved_transitions("enqueue", ["queue", "node", "0"], "0")


@pytest.mark.parametrize(
    "before,after",
    [
        ("reject || q->pending", "reject && q->pending"),
        ("q->pending = p;", "q->pending = other;"),
        ("q->pending = p;", "q->pending = p; q->pending = 0;"),
        ("return -1;", "return 0;"),
        ("q->pending = p;", "opaque(q, p); q->pending = p;"),
        ("q->pending = p;", "for (;;) { q->pending = p; }"),
    ],
)
def test_unsupported_implementation_never_accepts_proposal(before, after):
    ctx = context()
    ctx["code"] = ctx["code"].replace(before, after)
    assert verify_retention_contract(proposal(), ctx) is None


@pytest.mark.parametrize(
    "problem",
    [
        "incomplete",
        "stale",
        "wrong_build",
        "macro",
        "native_disagreement",
        "missing_native",
        "missing_event_identity",
        "call",
    ],
)
def test_receipt_and_native_negative_cases(problem):
    ctx = context()
    facts = ctx["program_facts"]
    events = facts["functions"][0]["events"]
    if problem == "incomplete":
        facts["complete"] = False
    elif problem == "stale":
        facts["reason"] = "stale_build_dependencies"
    elif problem == "wrong_build":
        ctx["build_context_id"] = "build-b"
    elif problem == "macro":
        events[0]["contains_macro"] = True
    elif problem == "native_disagreement":
        events[0]["expression"] = "q->pending = other"
    elif problem == "missing_native":
        facts["functions"] = []
    elif problem == "missing_event_identity":
        events[0].pop("event_id")
    elif problem == "call":
        events.append({"event_kind": "call", "expression": "operator bool()"})
    assert verify_retention_contract(proposal(), ctx) is None


def test_compiler_and_workbook_publish_only_checked_retention(tmp_path):
    ctx = context()
    snapshot = {**ctx, "interface_contracts": [proposal()]}
    compile_snapshot(snapshot, ctx, ContractRegistry())
    assert len(snapshot["interface_contracts"]) == 1
    assert snapshot["interface_contracts"][0]["role"] == "reference_retention"
    _, semantics, _ = publish(tmp_path, [snapshot])
    with bind_build_scope(ctx):
        matches = semantics.contracts.find_for_call("enqueue")
        assert len(matches) == 1 and matches[0].effects_trusted
        assert matches[0].protocol["release_responsibility"] == "unresolved"


@pytest.mark.parametrize("field_macro", [False, True])
def test_real_native_queue_store_is_checked_without_ground_truth(protocol_project, field_macro):
    tool = os.environ.get("Z_SCOPE_TEST_CLANG_INDEXER")
    if not tool:
        pytest.skip("native protocol verification requires Z_SCOPE_TEST_CLANG_INDEXER")
    root, source, _, database = protocol_project
    if field_macro:
        source.write_text("#define pending saved\n" + source.read_text())
    backend = ClangBackend(frontend="batch", clang_indexer_path=tool, max_threads=1)
    try:
        assert backend.initialize(str(root), compile_commands_path=str(database))
        index = CodeIndex(
            root, database, backend=backend, indexing_config=SimpleNamespace(backend="clang")
        )
        implementation = index.get_function_impl(
            "queue_send", file_path=str(source), include_context=False
        )
        facts = index.get_function_program_facts("queue_send", str(source))
        assert facts["complete"]
        ctx = {
            **implementation,
            "func_name": "queue_send",
            "file_path": str(source),
            "program_facts": facts,
        }
        raw = proposal()
        raw["evidence"] = [{"lines": str(implementation["start_line"])}]
        snapshot = {**ctx, "interface_contracts": [raw]}
        compile_snapshot(snapshot, ctx, ContractRegistry())
        contracts = [
            ApiContract.from_row({"contract": row}) for row in snapshot["interface_contracts"]
        ]
        if field_macro:
            assert all(not contract.effects_trusted for contract in contracts)
            return
        assert len(contracts) == 1 and contracts[0].effects_trusted, snapshot[
            "contract_diagnostics"
        ]
        assert contracts[0].role == "reference_retention"
        assert contracts[0].symbol.build_context_id == facts["build_context_id"]
        assert contracts[0].protocol["release_responsibility"] == "unresolved"
    finally:
        backend.close()


def test_missing_native_owner_usr_cannot_publish_retention_effect():
    ctx = context()
    ctx["program_facts"]["functions"][0]["owner"].pop("usr")
    assert verify_retention_contract(proposal(), ctx) is None
