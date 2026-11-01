from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from copy import deepcopy
from threading import Barrier

import pytest

from zscope.semantics.call_context import bind_call_context
from zscope.semantics.contract_compiler import compile_snapshot, derive_contracts
from zscope.semantics.contracts import ApiContract, SymbolIdentity, contract_rows
from zscope.semantics.defaults import default_local_pattern_semantics


def context(build="a", **facts):
    # Synthetic native frame for scope isolation, not native extraction evidence.
    # Real compiler/value-flow coverage lives in test_native_wrapper_inference.
    parameter = {
        "name": "p",
        "usr": "c:unit.c@1@F@dispose@p",
        "referenced_usr": "c:unit.c@1@F@dispose@p",
        "index": 0,
        "value_kind": "parameter",
        "expression": "p",
    }
    body = {
        "complete": True,
        "fact_version": "zscope.program-events.v7",
        "lifecycle_value_facts_version": "zscope.lifecycle-value-facts.v1",
        "owner": {"name": "dispose", "usr": "c:@F@dispose", "file": "unit.c"},
        "parameters": [parameter],
        "return_value_kind": "void",
        "cfg_entry": 1,
        "cfg_exit": 0,
        "cfg_edges": [{"from": 1, "to": 0, "condition": "", "branch": "unknown"}],
        "events": [
            {
                "event_id": "1:0",
                "event_kind": "call",
                "block": 1,
                "ordinal": 0,
                "expression": "free(p)",
                "contains_macro": False,
                "arguments": ["p"],
                "callee": {"name": "free", "usr": "c:@F@free"},
                "location": {"offset": 24},
                "uses": [parameter],
            }
        ],
    }
    return {
        "func_name": "dispose",
        "file_path": "unit.c",
        "signature": "void dispose(void *p)",
        "code": "void dispose(void *p) { free(p); }",
        "program_facts": {
            "complete": True,
            "build_context_id": build,
            "functions": [body],
            **facts,
        },
    }


def registry():
    return default_local_pattern_semantics().contracts


def test_scoped_contract_cannot_release_objects_in_other_or_unspecified_build():
    contracts = registry()
    raw = derive_contracts(context(), contracts)[0]
    contract = ApiContract.from_row({"contract": raw})
    assert contract.effects_trusted
    assert contract.symbol.build_context_id == "a"
    contracts.add(contract)
    assert not contracts.find("dispose")
    assert not contracts.for_context(context("b")).match_call("dispose", "deallocator", ["p"])
    # A build-only view is insufficient to select the native symbol.
    assert not contracts.for_context(context()).match_call("dispose", "deallocator", ["p"])
    with bind_call_context(context(), contracts):
        matches = contracts.for_context(context()).match_call(
            "dispose", "deallocator", ["p"], facts={"p": {"non_null_identity": "p"}}
        )
    assert len(matches) == 1
    assert matches[0].applicability == "applies"
    assert matches[0].symbol.build_context_id == "a"


def test_parallel_call_scopes_are_isolated_and_restored():
    contracts = registry()
    for build in ("a", "b"):
        contracts.add(
            ApiContract.from_row({"contract": derive_contracts(context(build), contracts)[0]})
        )
    barrier = Barrier(2)

    def analyze(build):
        with bind_call_context(context(build), contracts):
            barrier.wait(timeout=10)
            assert {c.symbol.build_context_id for c in contracts.find("dispose")} == {build}
            with bind_call_context(context("other"), contracts):
                assert not contracts.find("dispose")
            return contracts.find("dispose")[0].symbol.build_context_id

    with ThreadPoolExecutor(max_workers=2) as workers:
        assert set(workers.map(analyze, ("a", "b"))) == {"a", "b"}
    assert not contracts.find("dispose")


@pytest.mark.parametrize(
    "facts",
    [
        {"complete": False},
        {"reason": "ambiguous_build_context", "build_context_id": ""},
        {"reason": "stale_build_dependencies"},
        {"functions": []},
    ],
)
def test_incomplete_or_ambiguous_compilation_never_proves_source_effects(facts):
    ctx = context(**facts)
    assert derive_contracts(ctx, registry()) == []
    proposal = {
        "role": "deallocator",
        "carrier": {"kind": "argument", "argument_index": 0},
        "evidence": [{"quote": "free(p)"}],
    }
    snapshot = {"interface_contracts": [proposal]}
    compile_snapshot(snapshot, ctx, registry())
    assert all(
        not ApiContract.from_row({"contract": raw}).effects_trusted
        for raw in snapshot["interface_contracts"]
    )


def test_unexpanded_source_and_mismatched_receipt_cannot_prove_effects():
    ctx = context()
    ctx["code"] = "void dispose(void *p) {\n#ifdef RELEASE\nfree(p);\n#endif\n}"
    assert derive_contracts(ctx, registry()) == []
    ctx = context()
    ctx["build_context_id"] = "b"
    assert derive_contracts(ctx, registry()) == []


def test_scope_survives_snapshot_and_workbook_contract_roundtrip():
    ctx = context()
    snapshot = {**ctx, "interface_contracts": []}
    assert compile_snapshot(snapshot, ctx, registry()) == []
    row = contract_rows([snapshot])["resource"][0]
    assert row["build_context_id"] == "a"
    contract = ApiContract.from_row(row)
    assert contract.symbol.build_context_id == "a"
    assert SymbolIdentity.from_value(contract.to_dict()["symbol"]) == contract.symbol
    assert replace(contract.symbol, build_context_id="b").key != contract.symbol.key


def caller_facts(build="a", usr="c:@F@dispose"):
    # Synthetic isolation fixture; real native extraction is tested separately.
    facts = deepcopy(context(build)["program_facts"])
    body = facts["functions"][0]
    body["owner"] = {"name": "run", "usr": "c:@F@run", "file": "unit.c"}
    body["parameters"][0].update(usr="c:unit.c@1@F@run@p", referenced_usr="c:unit.c@1@F@run@p")
    event = body["events"][0]
    event["expression"] = "dispose(p)"
    event["callee"] = {"name": "dispose", "usr": usr} if usr is not None else {"name": "dispose"}
    return facts


@pytest.mark.parametrize("engine", ["regex", "clang_ast_cfg"])
def test_candidate_semantic_trace_uses_the_observed_build(engine):
    from zscope.core.candidates.regex import RegexCandidateGenerator
    from zscope.core.candidates.clang_ast_cfg import ClangAstCfgCandidateGenerator

    semantics = default_local_pattern_semantics()
    semantics.contracts.add(
        ApiContract.from_row({"contract": derive_contracts(context(), registry())[0]})
    )
    cls = RegexCandidateGenerator if engine == "regex" else ClangAstCfgCandidateGenerator
    generator = cls(semantics)
    generator.program_facts_provider = lambda *_: caller_facts("a")
    generator.generate_issues("run", "void run(void *p) { if (p) dispose(p); }", "unit.c")
    assert any(
        event["symbol"]["name"] == "dispose" and event["build_context_id"] == "a"
        for event in generator.last_semantic_events
    )
    generator.program_facts_provider = lambda *_: caller_facts("b")
    generator.generate_issues("run", "void run(void *p) { if (p) dispose(p); }", "unit.c")
    assert not generator.last_semantic_events


def test_model_audit_identity_separates_builds_and_survives_snapshot_projection():
    from zscope.semantics.contracts import semantic_model_unit_uid

    first = semantic_model_unit_uid(context("a"))
    assert first != semantic_model_unit_uid(context("b"))
    snapshot = {**context(), "build_context_id": "a"}
    snapshot.pop("program_facts")
    assert semantic_model_unit_uid(snapshot) == first
    snapshot.pop("build_context_id")
    assert semantic_model_unit_uid(snapshot) != first


def test_api_registration_and_merge_never_fabricate_unscoped_aliases():
    from zscope.semantics.models import LocalPatternSemantics

    semantics = LocalPatternSemantics()
    for build in ("a", "b"):
        contract = ApiContract.from_row(
            {"contract": derive_contracts(context(build), registry())[0]}
        )
        semantics.contracts.add(contract)
        semantics.add_api(contract.role, contract.symbol.name, contract.source)
    merged = LocalPatternSemantics()
    merged.merge(semantics)
    for result in (semantics, merged):
        declarations = [c for c in result.contracts.contracts if c.symbol.name == "dispose"]
        assert {c.symbol.build_context_id for c in declarations} == {"a", "b"}
        assert len(declarations) == 2
        assert not result.contracts.find_for_call("dispose")
        with bind_call_context(context("a"), result.contracts):
            assert len(result.contracts.find_for_call("dispose")) == 1


@pytest.mark.parametrize("engine", ["regex", "clang_ast_cfg"])
@pytest.mark.parametrize("usr", [None, "", "c:@F@other"])
def test_candidate_semantic_trace_rejects_missing_or_foreign_callee_receipt(engine, usr):
    from zscope.core.candidates.regex import RegexCandidateGenerator
    from zscope.core.candidates.clang_ast_cfg import ClangAstCfgCandidateGenerator

    semantics = default_local_pattern_semantics()
    semantics.contracts.add(
        ApiContract.from_row({"contract": derive_contracts(context(), registry())[0]})
    )
    cls = RegexCandidateGenerator if engine == "regex" else ClangAstCfgCandidateGenerator
    generator = cls(semantics)
    generator.program_facts_provider = lambda *_: caller_facts("a", usr)
    generator.generate_issues("run", "void run(void *p) { if (p) dispose(p); }", "unit.c")
    assert not generator.last_semantic_events
