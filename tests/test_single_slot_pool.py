"""Logical pool contracts retain membership, availability and build guards."""

from copy import deepcopy
from dataclasses import replace
import os
from types import SimpleNamespace

import pytest

from test_resource_protocol_baseline import protocol_project
from test_wrapper_contract_compiler import publish
from zscope.core.candidates.clang_ast_cfg import ClangAstCfgCandidateGenerator
from zscope.core.candidates.regex import RegexCandidateGenerator
from zscope.retrieval.clang_backend import ClangBackend
from zscope.retrieval.code_index import CodeIndex
from zscope.semantics.build_scope import bind_build_scope
from zscope.semantics.contract_compiler import (
    compile_snapshot,
    complete_transparent_pairs,
    deterministic_contract_snapshot,
)
from zscope.semantics.contract_conditions import evaluate, predicate_errors
from zscope.semantics.contracts import ApiContract, ContractRegistry
from zscope.semantics.defaults import default_local_pattern_semantics
from zscope.semantics.pool_protocols import pool_pair_compatible
from zscope.semantics.single_slot_pool import verify_single_slot_pool


def proposal(role):
    return {
        "role": role,
        "carrier": (
            {"kind": "return"} if role == "allocator" else {"kind": "argument", "argument_index": 1}
        ),
        "resource_domain": {"kind": "argument", "argument_index": 0},
        "protocol": {
            "kind": "single_slot_pool",
            "slot_path": "->slot",
            "live_path": "->live",
            "generation_path": "->slot.generation",
            "invalid_return_path": "->duplicate_returns",
        },
        "effect_cases": [{"when": {"op": "unknown"}, "effect": "applies"}],
        "evidence": [{"lines": "1", "description": "Current implementation proposal"}],
    }


def context(role):
    take = role == "allocator"
    name = "pool_take" if take else "pool_give"
    signature = "Node *pool_take(Pool *pool)" if take else "void pool_give(Pool *pool, Node *node)"
    source = (
        "{ if (pool->live) return NULL; pool->live = 1; pool->slot.generation++; return &pool->slot; }"
        if take
        else "{ if (node != &pool->slot || !pool->live) { pool->duplicate_returns++; return; } pool->live = 0; }"
    )
    event_rows = [
        ("assignment", "pool->live = 1" if take else "pool->live = 0"),
        ("increment_decrement", "pool->slot.generation++" if take else "pool->duplicate_returns++"),
        ("return", "return &pool->slot" if take else "return"),
    ]
    if take:
        event_rows += [("statement", "NULL"), ("return", "return NULL")]
    events = [
        {
            "event_id": str(i),
            "event_kind": kind,
            "expression": expression,
            "contains_macro": "NULL" in expression,
            "null_pointer_constant": "NULL" in expression,
        }
        for i, (kind, expression) in enumerate(event_rows)
    ]
    return {
        "func_name": name,
        "file_path": "pool.c",
        "signature": signature,
        "code": signature + source,
        "program_facts": {
            "complete": True,
            "build_context_id": "build-a",
            "functions": [
                {
                    "complete": True,
                    "fact_version": "zscope.program-events.v7",
                    "resource_protocol_facts_version": "zscope.resource-protocol-facts.v1",
                    "owner": {"name": name, "usr": "c:@F@" + name},
                    "parameters": [
                        {
                            "index": 0,
                            "pointee_record_kind": "struct",
                            "pointee_record_usr": "c:@S@Pool",
                        }
                    ],
                    "events": events,
                }
            ],
        },
    }


def checked(role):
    result = verify_single_slot_pool(proposal(role), context(role))
    assert result
    return ApiContract.from_row({"contract": result})


def test_pair_has_logical_effects_without_heap_free_or_ownership_authority():
    acquire, release = checked("allocator"), checked("deallocator")
    assert pool_pair_compatible(acquire, release)
    assert acquire.resource_family == release.resource_family
    assert acquire.protocol["generation_uniqueness"] == "unproven"
    assert not acquire.verification["proof_authority"]
    acquire = replace(acquire, pairs=[release.symbol])
    registry = ContractRegistry()
    registry.add(acquire)
    registry.add(release)
    with bind_build_scope(context("allocator")):
        assert registry.allows("pool_take", "pool_give")
        assert not registry.allows("pool_take", "free")
        assert (
            registry.match_call("pool_take", "allocator", ["a"], "NULL")[0].applicability
            == "does_not_apply"
        )
        assert (
            registry.match_call("pool_take", "allocator", ["a"], "p")[0].applicability == "unknown"
        )
        assert (
            registry.match_call("pool_take", "allocator", ["a"], "p", facts={"p": object()})[
                0
            ].applicability
            == "applies"
        )
        identity = object()
        values = {"p": identity, "&a->slot": identity, "a->live": 1}
        query = dict(
            acquired_object="p", acquired_domain="a", acquired_family=acquire.resource_family
        )
        assert registry.release_status("pool_take", "pool_give", ["a", "p"], **query) == "unknown"
        # pool_take has no native call selecting pool_give. Bind its own
        # deallocator body for the release query; keep the unknown case above.
        with bind_build_scope(context("deallocator")):
            assert (
                registry.release_status("pool_take", "pool_give", ["a", "p"], facts=values, **query)
                == "applies"
            )
            assert (
                registry.release_status(
                    "pool_take", "pool_give", ["a", "p"], facts={**values, "a->live": 0}, **query
                )
                == "does_not_apply"
            )
            assert (
                registry.release_status(
                    "pool_take",
                    "pool_give",
                    ["a", "p"],
                    facts={**values, "&a->slot": object()},
                    **query,
                )
                == "does_not_apply"
            )
            assert (
                registry.release_status("pool_take", "pool_give", ["b", "p"], facts=values, **query)
                == "does_not_apply"
            )
        transitions = registry.resolved_transitions(
            "pool_take", ["&arena"], "p", facts={"p": identity}
        )
        assert transitions[0]["actions"] == [
            {"kind": "acquire_pool_slot", "object": "p", "new": "&arena.slot"},
            {"kind": "advance_generation", "object": "arena.slot.generation"},
        ]
    assert not registry.allows("pool_take", "pool_give")
    assert not pool_pair_compatible(
        acquire, replace(release, symbol=replace(release.symbol, build_context_id="other"))
    )


def test_address_condition_does_not_confuse_slot_value_with_address():
    from zscope.semantics.call_context import branch_values

    predicate = {
        "op": "compare",
        "operator": "==",
        "left": {"kind": "argument", "index": 1},
        "right": {"kind": "argument", "index": 0, "member_path": "->slot", "address_of": True},
    }
    identity = object()
    assert not predicate_errors(predicate)
    guard = {
        **predicate,
        "left": predicate["right"],
        "right": {"kind": "literal", "value": None},
        "operator": "!=",
    }
    assert set(branch_values(guard, ["arena", "p"])) == {"&arena->slot"}
    assert (
        evaluate(predicate, ["&arena", "p"], facts={"p": identity, "arena.slot": identity})
        == "unknown"
    )
    assert (
        evaluate(predicate, ["&arena", "p"], facts={"p": identity, "&arena.slot": identity})
        == "applies"
    )
    for value in ["yes", 1]:
        invalid = deepcopy(predicate)
        invalid["right"]["address_of"] = value
        assert "invalid_predicate_address_of" in predicate_errors(invalid)


@pytest.mark.parametrize("role", ["allocator", "deallocator"])
@pytest.mark.parametrize(
    "failure",
    ["incomplete", "old_native", "wrong_build", "union", "macro", "extra_store", "missing_id"],
)
def test_unusable_native_facts_cannot_establish_pool(role, failure):
    ctx = context(role)
    facts = ctx["program_facts"]
    body = facts["functions"][0]
    if failure == "incomplete":
        facts["complete"] = False
    elif failure == "old_native":
        body.pop("resource_protocol_facts_version")
    elif failure == "wrong_build":
        ctx["build_context_id"] = "build-b"
    elif failure == "union":
        body["parameters"][0]["pointee_record_kind"] = "union"
    elif failure == "macro":
        body["events"][0]["contains_macro"] = True
    elif failure == "extra_store":
        body["events"].append(
            {
                "event_id": "extra",
                "contains_macro": False,
                "event_kind": "assignment",
                "expression": "pool->live=1",
            }
        )
    elif failure == "missing_id":
        body["events"][0].pop("event_id")
    assert verify_single_slot_pool(proposal(role), ctx) is None


@pytest.mark.parametrize(
    "role,before,after",
    [
        ("allocator", "if (pool->live)", "if (!pool->live)"),
        ("allocator", "pool->live = 1", "pool->live = 0"),
        ("allocator", "return &pool->slot", "return external"),
        ("allocator", "pool->slot.generation++", "pool->slot.generation--"),
        ("deallocator", "|| !pool->live", "&& !pool->live"),
        ("deallocator", "node != &pool->slot", "node == &pool->slot"),
        ("deallocator", "pool->live = 0", "pool->live = 1"),
        ("deallocator", "return;", "opaque(node); return;"),
    ],
)
def test_source_mutations_do_not_reuse_old_native_receipts(role, before, after):
    ctx = context(role)
    ctx["code"] = ctx["code"].replace(before, after)
    assert verify_single_slot_pool(proposal(role), ctx) is None


def test_wrapped_guard_keeps_slot_address_and_parameter_mapping():
    registry = ContractRegistry([checked("deallocator")])
    ctx = context("deallocator")
    ctx.update(
        func_name="drop",
        signature="void drop(Node *p, Pool *arena)",
        code="void drop(Node *p, Pool *arena) { pool_give(arena, p); }",
    )
    # This unit fixture supplies the wrapper's own synthetic native frame.
    body = ctx["program_facts"]["functions"][0]
    body["owner"] = {"name": "drop", "usr": "c:@F@drop"}
    body["events"] = [
        {
            "event_id": "call-1",
            "event_kind": "call",
            "expression": "pool_give(arena, p)",
            "arguments": ["arena", "p"],
            "contains_macro": False,
            "callee": {"name": "pool_give", "usr": "c:@F@pool_give"},
        }
    ]
    missing = deepcopy(ctx)
    missing["program_facts"]["functions"][0]["events"][0]["callee"].pop("usr")
    assert deterministic_contract_snapshot(missing, registry) is None
    snapshot = deterministic_contract_snapshot(ctx, registry)
    assert snapshot
    wrapper = ApiContract.from_row({"contract": snapshot["interface_contracts"][0]})
    identity = object()
    known = {"p": identity, "&arena->slot": identity, "arena->live": 1}
    assert wrapper.applicability(["p", "arena"], facts=known) == "applies"
    assert (
        wrapper.applicability(
            ["p", "arena"], facts={"p": identity, "arena->slot": identity, "arena->live": 1}
        )
        == "unknown"
    )


def native_index(root, source, database):
    tool = os.environ.get("Z_SCOPE_TEST_CLANG_INDEXER")
    if not tool:
        pytest.skip("native protocol tests require Z_SCOPE_TEST_CLANG_INDEXER")
    backend = ClangBackend(frontend="batch", clang_indexer_path=tool, max_threads=1)
    assert backend.initialize(str(root), compile_commands_path=str(database))
    return backend, CodeIndex(
        root, database, backend=backend, indexing_config=SimpleNamespace(backend="clang")
    )


def native_context(index, source, name):
    implementation = index.get_function_impl(name, file_path=str(source), include_context=False)
    facts = index.get_function_program_facts(name, str(source))
    assert facts["complete"]
    return {**implementation, "func_name": name, "file_path": str(source), "program_facts": facts}


def test_real_s00_pool_publication_workbook_and_candidate_consumers(protocol_project):
    from test_retention_protocols import proposal as retention_proposal
    from zscope.config.function_entry import FunctionEntry
    from zscope.semantics.security_map import ZeroLLMSecurityMapBuilder

    root, source, _, database = protocol_project
    backend, index = native_index(root, source, database)
    try:
        registry = default_local_pattern_semantics().contracts
        snapshots = []
        for role, name in [("allocator", "pool_take"), ("deallocator", "pool_give")]:
            ctx = native_context(index, source, name)
            raw = proposal(role)
            raw["evidence"][0]["lines"] = str(ctx["start_line"])
            snapshot = {**ctx, "interface_contracts": [raw]}
            compile_snapshot(snapshot, ctx, registry)
            contract = ApiContract.from_row({"contract": snapshot["interface_contracts"][0]})
            assert contract.effects_trusted, snapshot["contract_diagnostics"]
            assert contract.verification["method"] == "source_protocol"
            registry.add(contract)
            snapshots.append(snapshot)
        assert complete_transparent_pairs(snapshots, registry) == 1
        ctx = native_context(index, source, "queue_send")
        raw = retention_proposal()
        raw["evidence"][0]["lines"] = str(ctx["start_line"])
        snapshot = {**ctx, "interface_contracts": [raw]}
        compile_snapshot(snapshot, ctx, registry)
        assert snapshot["interface_contracts"][0]["role"] == "reference_retention"
        snapshots.append(snapshot)
        _, semantics, overlay = publish(root, snapshots)
        ctx = native_context(index, source, "submit_c")
        with bind_build_scope(ctx):
            assert semantics.contracts.allows("pool_take", "pool_give")
            assert not semantics.contracts.allows("pool_take", "free")
        for engine_type in (RegexCandidateGenerator, ClangAstCfgCandidateGenerator):
            engine = engine_type(semantics, program_facts_provider=index.get_function_program_facts)
            issues = engine.generate_issues("submit_c", ctx["code"], str(source))
            # Candidate only; retention does not establish the responsibility
            # endpoint or grant final confirmation for the successful path.
            leaks = [issue for issue in issues if issue["defect_class"] == "memory_leak"]
            assert leaks, (engine_type, issues)
            assert all(
                issue["build_context_id"] == ctx["program_facts"]["build_context_id"]
                for issue in leaks
            )
        semantic_map = ZeroLLMSecurityMapBuilder(
            index,
            project_id="native-protocol",
            revision="fixture",
            profile="balanced",
            semantic_overlay=overlay,
        ).build([FunctionEntry("submit_c", file_path=str(source))])
        retained = [
            claim
            for claim in semantic_map.claims
            if claim.value.get("call_semantics", {}).get("role") == "reference_retention"
        ]
        assert retained
        assert all(
            claim.kind == "resource_transition" and claim.status == "unknown" for claim in retained
        )
        assert all(
            claim.value["call_semantics"]["symbol"]["build_context_id"]
            == ctx["program_facts"]["build_context_id"]
            for claim in retained
        )
    finally:
        backend.close()


@pytest.mark.parametrize("mutation", ["fake_null", "nested_macro", "union"])
def test_real_native_macro_and_union_counterexamples(protocol_project, mutation):
    root, source, _, database = protocol_project
    code = source.read_text()
    if mutation == "fake_null":
        code = code.replace(
            "static Node *pool_take",
            "#undef NULL\n#define NULL ((void *)8)\nstatic Node *pool_take",
            1,
        )
    elif mutation == "nested_macro":
        code = code.replace(
            "static Node *pool_take", "#define live duplicate_returns\nstatic Node *pool_take", 1
        )
    else:
        code = code.replace(
            "typedef struct {\n    Node slot;", "typedef union {\n    Node slot;", 1
        )
    source.write_text(code)
    backend, index = native_index(root, source, database)
    try:
        ctx = native_context(index, source, "pool_take")
        assert verify_single_slot_pool(proposal("allocator"), ctx) is None
    finally:
        backend.close()


def test_same_pool_type_spelling_does_not_pair_different_native_records(protocol_project):
    root, source, _, database = protocol_project
    source.write_text(
        "#include <stddef.h>\n"
        "typedef struct { unsigned generation; } Node;\n"
        "typedef struct { Node slot; unsigned live, duplicate_returns; } A;\n"
        "typedef struct { Node slot; unsigned live, duplicate_returns; } B;\n"
        "#define Pool A\n" + context("allocator")["code"] + "\n"
        "#undef Pool\n#define Pool B\n" + context("deallocator")["code"] + "\n"
    )
    backend, index = native_index(root, source, database)
    try:
        contracts = []
        for role, name in [("allocator", "pool_take"), ("deallocator", "pool_give")]:
            ctx = native_context(index, source, name)
            result = verify_single_slot_pool(proposal(role), ctx)
            assert result
            contracts.append(ApiContract.from_row({"contract": result}))
        assert contracts[0].protocol["pool_type"] == contracts[1].protocol["pool_type"]
        assert contracts[0].symbol.build_context_id == contracts[1].symbol.build_context_id
        assert not pool_pair_compatible(*contracts)
        assert contracts[0].resource_family != contracts[1].resource_family
    finally:
        backend.close()


def test_native_contract_cache_never_rebinds_old_proof_to_new_receipt(protocol_project):
    from test_global_modeler import RecordingAgent
    from test_incremental_semantic_modeling import modeler_for
    from zscope.config.function_entry import FunctionEntry

    root, source, _, database = protocol_project
    backend, index = native_index(root, source, database)
    calls = []

    class Agent(RecordingAgent):
        def run(self, ctx):
            result = super().run(ctx)
            if ctx["func_name"] == "pool_take":
                raw = proposal("allocator")
                raw["evidence"][0]["lines"] = str(ctx["start_line"])
                result.data["interface_contracts"] = [raw]
            return result

    def model():
        current_index = CodeIndex(
            root, database, backend=backend, indexing_config=SimpleNamespace(backend="clang")
        )
        ctx = native_context(current_index, source, "pool_take")
        modeler = modeler_for(root, current_index, calls, lambda: Agent(calls))
        stats = modeler.run([FunctionEntry("pool_take", file_path=str(source))])
        snapshot = modeler.snapshot_store.load_snapshot(ctx["index_name"])
        contract = ApiContract.from_row({"contract": snapshot["interface_contracts"][0]})
        assert contract.effects_trusted
        assert contract.symbol.build_context_id == ctx["program_facts"]["build_context_id"]
        return stats, contract.symbol.build_context_id

    try:
        _, first = model()
        calls.clear()
        source.write_text(source.read_text() + "\n/* changed byte receipt only */\n")
        assert backend._run_full_extraction()
        stats, second = model()
        assert first != second
        assert calls == ["pool_take"]
        assert "build_receipt" in stats.rebuild_reasons.values()
        calls.clear()
        stats, third = model()
        assert third == second and not calls and stats.cache_hit_functions >= 1
    finally:
        backend.close()
