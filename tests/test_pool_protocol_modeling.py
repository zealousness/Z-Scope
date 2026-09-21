"""Protocol discovery, source verification, publication and real consumers."""

from copy import deepcopy
from dataclasses import asdict, replace
import json
import os
from types import SimpleNamespace

import pytest

from test_wrapper_contract_compiler import context, compile_all, publish
from test_incremental_semantic_modeling import modeler_for
from test_global_modeler import FakeCodeIndex, RecordingAgent
from zscope.config.function_entry import FunctionEntry
from zscope.core.candidates.clang_ast_cfg import ClangAstCfgCandidateGenerator
from zscope.core.candidates.regex import RegexCandidateGenerator
from zscope.core.validation.evidence_completion import EvidenceCompletionQueue
from zscope.core.validation.proofs import deterministic_decision_proof
from zscope.semantics.contracts import ApiContract
from zscope.semantics.contract_compiler import (
    compile_snapshot,
    complete_transparent_pairs,
    deterministic_contract_snapshot,
)
from zscope.semantics.defaults import default_local_pattern_semantics


TAKE = "Node *alpha(Pool *pool) { Node *node = pool->available; if (node) { pool->available = node->link; } return node; }"
GIVE = (
    "void omega(Node *node, Pool *pool) { node->link = pool->available; pool->available = node; }"
)


def proposal(role, paired):
    return {
        "role": role,
        "carrier": (
            {"kind": "return"} if role == "allocator" else {"kind": "argument", "argument_index": 0}
        ),
        "resource_domain": {"kind": "argument", "argument_index": 0 if role == "allocator" else 1},
        "protocol": {
            "kind": "intrusive_freelist",
            "head_path": "->available",
            "link_path": "->link",
        },
        "preconditions": {"op": "true"},
        "effect_cases": [{"when": {"op": "unknown"}, "effect": "applies"}],
        "pairs": [{"name": paired}],
        "confidence": 0.8,
        "evidence": [{"lines": "1", "description": "Pool head and resource link update"}],
    }


def terminal_factory(calls, monkeypatch):
    from test_json_output_agents import _snapshot_payload
    from zscope.agents.semantic_modeler.agent import SemanticModeler
    from zscope.framework.llm_client import LLMClient

    def factory():
        current = {}
        llm = LLMClient(api_key="test", base_url="http://example.invalid", models=["unit-model"])

        def completion(messages, **kwargs):
            name = current["func_name"]
            calls.append(name)
            payload = _snapshot_payload()
            raw = proposal(
                "allocator" if name == "alpha" else "deallocator",
                "omega" if name == "alpha" else "alpha",
            )
            raw["evidence"][0]["lines"] = str(current.get("start_line") or 1)
            payload["interface_contracts"] = [raw] if name in {"alpha", "omega"} else []
            return {
                "choices": [
                    {
                        "finish_reason": "tool_calls",
                        "message": {
                            "role": "assistant",
                            "content": "",
                            "tool_calls": [
                                {
                                    "id": "emit",
                                    "type": "function",
                                    "function": {
                                        "name": "emit_function_snapshot",
                                        "arguments": json.dumps(payload),
                                    },
                                }
                            ],
                        },
                    }
                ],
                "model": "unit-model",
                "usage": {"prompt_tokens": 10, "completion_tokens": 5},
            }

        monkeypatch.setattr(llm, "chat_completion", completion)

        class Agent(SemanticModeler):
            def run(self, ctx):
                current.update(ctx)
                return super().run(ctx)

        return Agent(llm, [])

    return factory


def pool_snapshots():
    registry = default_local_pattern_semantics().contracts
    snapshots = []
    for name, code, role, pair in [
        ("alpha", TAKE, "allocator", "omega"),
        ("omega", GIVE, "deallocator", "alpha"),
    ]:
        ctx = context(name, code)
        snap = {**ctx, "interface_contracts": [proposal(role, pair)]}
        assert compile_snapshot(snap, ctx, registry) == []
        assert snap["interface_contracts"][0]["verification"]["method"] == "source_protocol"
        snapshots.append(snap)
        registry.add(ApiContract.from_row({"contract": snap["interface_contracts"][0]}))
    for name, code in [
        ("outer", "Node *outer(int ignored, Pool *arena) { return alpha(arena); }"),
        ("drop", "void drop(Pool *arena, Node *p) { omega(p, arena); }"),
    ]:
        snap = deterministic_contract_snapshot(context(name, code), registry)
        assert snap is not None
        snapshots.append(snap)
        for raw in snap["interface_contracts"]:
            registry.add(ApiContract.from_row({"contract": raw}))
    complete_transparent_pairs(snapshots, registry)
    return snapshots


def caller(call, *, prefix="", suffix=""):
    lines = [
        "void entry(Pool *a, Pool *b, int flag) {",
        "Node *p = outer(7, a);",
        "if (!p) return;",
        *prefix.splitlines(),
        call,
        *suffix.splitlines(),
        "return;",
        "}",
    ]
    return "\n".join(f"{i + 1} | {line}" for i, line in enumerate(lines))


@pytest.mark.parametrize("engine_type", [ClangAstCfgCandidateGenerator, RegexCandidateGenerator])
@pytest.mark.parametrize(
    "call,prefix,leak",
    [
        ("drop(a, p);", "", False),
        ("drop(b, p);", "", True),
        ("drop(a, q);", "Node *q = outer(7, a);", True),
        ("drop(a, q);", "Node *q = p;", False),
        ("drop(other, p);", "Pool *other = a;", False),
        ("drop(a, p);", "a = b;", True),
        ("free(p);", "", True),
        ("drop(a, q);", "Node *q = 0;\nif (flag) { q = p; }", True),
        ("drop(a, q);", "Node *q = p;\nq = other();", True),
    ],
)
def test_pool_identity_and_resource_identity_through_workbook(
    tmp_path, engine_type, call, prefix, leak
):
    _, semantics, _ = publish(tmp_path, pool_snapshots())
    issues = engine_type(semantics).generate_issues("entry", caller(call, prefix=prefix), "entry.c")
    assert (
        any(
            i["rule"]
            in {
                "clang_cfg_acquire_without_release_on_exit",
                "same_function_allocation_not_released",
            }
            for i in issues
        )
        is leak
    )


@pytest.mark.parametrize("engine_type", [ClangAstCfgCandidateGenerator, RegexCandidateGenerator])
def test_unknown_release_retains_existing_leak_candidate(tmp_path, engine_type):
    snapshots = compile_all(
        [context("maybe", "void maybe(void *p, int flag) { if (flag) free(p); }")]
    )
    _, semantics, _ = publish(tmp_path, snapshots)
    code = (
        "void entry(int flag) {\nvoid *p = malloc(8);\nif (!p) return;\nmaybe(p, flag);\nreturn;\n}"
    )
    issues = engine_type(semantics).generate_issues("entry", code, "entry.c")
    assert any(i["defect_class"] == "memory_leak" for i in issues)
    safe = engine_type(semantics).generate_issues(
        "entry", code.replace("maybe(p, flag)", "maybe(p, 1)"), "entry.c"
    )
    assert not any(i["defect_class"] == "memory_leak" for i in safe)


def test_schema_only_cannot_discharge_after_workbook_reload(tmp_path):
    ctx = context("opaque", "void opaque(void *p, int n) { while (n-- > 0) free(p); }")
    raw = proposal("deallocator", "malloc")
    raw.pop("protocol")
    raw.pop("resource_domain")
    raw["effect_cases"] = [{"when": {"op": "true"}, "effect": "applies"}]
    snap = {**ctx, "interface_contracts": [raw]}
    assert compile_snapshot(snap, ctx, default_local_pattern_semantics().contracts) == []
    _, semantics, _ = publish(tmp_path, [snap])
    assert (
        semantics.contracts.release_status("malloc", "opaque", ["p", "0"], acquired_object="p")
        == "unknown"
    )
    code = "void entry(void) {\nvoid *p=malloc(8);\nif (!p) return;\nopaque(p, 0);\nreturn;\n}"
    generator = ClangAstCfgCandidateGenerator(semantics)
    issues = generator.generate_issues("entry", code, "entry.c")
    issue = next(i for i in issues if i["rule"] == "clang_cfg_acquire_without_release_on_exit")
    proof = EvidenceCompletionQueue._proof_from_ast(
        issue,
        outcome="confirm",
        proof_kind="exact_acquisition_exit_leak",
        producer_engine="cpp_clang_cfg",
        events=[{"kind": "acquire", "line": 2}],
        facts=[
            "successful_acquisition",
            "reachable_exit_without_release",
            "ownership_not_transferred",
        ],
        summary="test",
        scope="test",
    )
    assert proof["completeness"] != "complete"
    proof["code_hash"] = "current-source"
    issue["deterministic_proofs"] = [proof]
    assert deterministic_decision_proof(issue, outcome="confirm") is None


@pytest.mark.parametrize("name", ["inspect_note", "add_note", "put_note", "register_note"])
def test_spelling_does_not_transfer_ownership(name):
    code = f"void entry(void) {{\nvoid *p=malloc(8);\nif (!p) return;\n{name}(p);\nreturn;\n}}"
    issues = ClangAstCfgCandidateGenerator(default_local_pattern_semantics()).generate_issues(
        "entry", code, "entry.c"
    )
    assert {i["rule"] for i in issues} == {"clang_cfg_acquire_without_release_on_exit"}


def test_unsupported_pool_is_discovered_but_not_promoted():
    ctx = context("alpha", TAKE.replace("pool->available = node->link;", "pool->available = node;"))
    snap = {**ctx, "interface_contracts": [proposal("allocator", "omega")]}
    assert compile_snapshot(snap, ctx, default_local_pattern_semantics().contracts) == []
    contract = ApiContract.from_row({"contract": snap["interface_contracts"][0]})
    assert not contract.effects_trusted
    assert deterministic_contract_snapshot(ctx, default_local_pattern_semantics().contracts) is None


@pytest.mark.parametrize("second,duplicate", [("drop(a, q);", True), ("drop(b, p);", False)])
def test_repeated_return_keeps_original_pool_and_alias_identity(tmp_path, second, duplicate):
    _, semantics, _ = publish(tmp_path, pool_snapshots())
    code = caller("drop(a, p);", prefix="Node *q=p;", suffix=second + "\nq->link=0;")
    issues = ClangAstCfgCandidateGenerator(semantics).generate_issues("entry", code, "entry.c")
    assert any(i["rule"] == "clang_cfg_same_object_released_twice" for i in issues) is duplicate


def test_llm_discovers_seed_static_wrappers_and_unreachable_counterpart(tmp_path):
    index = FakeCodeIndex()
    definitions = [
        ("alpha", TAKE, []),
        ("omega", GIVE, []),
        ("outer", "Node *outer(Pool *pool) { return alpha(pool); }", ["alpha"]),
        ("entry", "Node *entry(Pool *pool) { return outer(pool); }", ["outer"]),
    ]
    index.impls = {}
    for name, code, callees in definitions:
        impl = FakeCodeIndex._impl(name, callees)
        impl.update(code=code, signature=code.split("{")[0].strip())
        index.impls[name] = impl
    calls = []

    class Agent(RecordingAgent):
        def run(self, ctx):
            response = super().run(ctx)
            name = ctx["func_name"]
            if name in {"alpha", "omega"}:
                response.data["interface_contracts"] = [
                    proposal(
                        "allocator" if name == "alpha" else "deallocator",
                        "omega" if name == "alpha" else "alpha",
                    )
                ]
            return response

    modeler = modeler_for(tmp_path, index, calls, lambda: Agent(calls))
    first = modeler.run([FunctionEntry("entry")])
    assert sorted(calls) == ["alpha", "omega"]
    assert first.deterministic_snapshot_count == 2
    assert modeler.result.local_semantics.contracts.allows("outer", "omega")
    path = modeler.user_config.workbook.path
    before = (path.read_bytes(), path.stat().st_mtime_ns)
    calls.clear()
    modeler.run([FunctionEntry("entry")])
    assert calls == []
    assert (path.read_bytes(), path.stat().st_mtime_ns) == before
    index.impls["alpha"]["code"] = TAKE.replace(
        "pool->available = node->link;", "pool->available = node;"
    )
    modeler.run([FunctionEntry("entry")])
    assert "alpha" in calls  # Invalid seed cannot keep authorizing outer adapters.
    assert not modeler.result.local_semantics.contracts.find("outer")[0].effects_trusted


def test_native_code_to_real_terminal_tool_workbook_and_pool_consumers(tmp_path, monkeypatch):
    from zscope.retrieval.clang_backend import ClangBackend
    from zscope.retrieval.code_index import CodeIndex

    executable = os.environ.get("Z_SCOPE_TEST_CLANG_INDEXER")
    if not executable:
        pytest.skip("native indexer integration requires Z_SCOPE_TEST_CLANG_INDEXER")
    code = (
        "typedef struct Node { struct Node *link; } Node;\ntypedef struct Pool { Node *available; } Pool;\n"
        + TAKE
        + "\n"
        + GIVE
        + "\n"
        + "Node *outer(int ignored, Pool *arena) { return alpha(arena); }\n"
        + "void drop(Pool *arena, Node *node) { omega(node, arena); }\n"
        + "void entry(Pool *a, Pool *b) { Node *p=outer(7,a); if (!p) return; drop(b,p); }\n"
    )
    (tmp_path / "pool.c").write_text(code, encoding="utf-8")
    cdb = tmp_path / "compile_commands.json"
    cdb.write_text(
        json.dumps(
            [
                {
                    "file": str(tmp_path / "pool.c"),
                    "directory": str(tmp_path),
                    "arguments": ["clang", "-c", str(tmp_path / "pool.c")],
                }
            ]
        )
    )
    backend = ClangBackend(frontend="batch", clang_indexer_path=executable, max_threads=2)
    try:
        assert backend.initialize(str(tmp_path), compile_commands_path=str(cdb))
        index = CodeIndex(
            tmp_path, cdb, backend=backend, indexing_config=SimpleNamespace(backend="clang")
        )
        calls = []
        modeler = modeler_for(tmp_path, index, calls, terminal_factory(calls, monkeypatch))
        modeler.run([FunctionEntry("entry")])
        assert calls.count("alpha") == calls.count("omega") == 1
        assert "outer" not in calls and "drop" not in calls
        assert modeler.result.local_semantics.contracts.allows("outer", "drop")
        for cls in (ClangAstCfgCandidateGenerator, RegexCandidateGenerator):
            engine = cls(modeler.result.local_semantics)
            assert any(
                i["defect_class"] == "memory_leak"
                for i in engine.generate_issues("entry", caller("drop(b,p);"), "pool.c")
            )
            assert not any(
                i["defect_class"] == "memory_leak"
                for i in engine.generate_issues("entry", caller("drop(a,p);"), "pool.c")
            )
        calls.clear()
        modeler.run([FunctionEntry("entry")])
        assert calls == []
    finally:
        backend.close()


def test_manual_pool_contract_seeds_static_outer_without_model_call(tmp_path):
    index = FakeCodeIndex()
    index.impls = {
        "alpha": {**index._impl("alpha", []), "code": TAKE, "signature": TAKE.split("{")[0]},
        "entry": {
            **index._impl("entry", ["alpha"]),
            "code": "Node *entry(Pool *pool) { return alpha(pool); }",
            "signature": "Node *entry(Pool *pool)",
        },
    }
    calls = []
    modeler = modeler_for(tmp_path, index, calls)
    raw = proposal("allocator", "omega")
    raw.pop("protocol")
    raw["resource_family"] = "manual-buffer"
    raw["effect_cases"] = [{"when": {"op": "true"}, "effect": "applies"}]
    modeler.user_config.workbook.write_rows(
        {
            "resource": [
                {"symbol_name": "alpha", "kind": "allocator", "source": "user", "contract": raw}
            ]
        }
    )
    modeler.run([FunctionEntry("entry")])
    assert calls == []
    outer = modeler.result.local_semantics.contracts.find("entry")[0]
    assert outer.effects_trusted and outer.resource_domain.argument_index == 0
    assert outer.verification["assumptions"][0]["source"] == "user"
    assert modeler.result.local_semantics.contracts.find("alpha")[0].source == "user"


def test_manual_pool_edges_are_not_completed_by_protocol_similarity():
    from zscope.semantics.contracts import ContractRegistry, SymbolIdentity
    from zscope.semantics.pool_protocols import pool_pair_compatible

    seeds = pool_snapshots()
    base_a = ApiContract.from_row({"contract": seeds[0]["interface_contracts"][0]})
    base_x = ApiContract.from_row({"contract": seeds[1]["interface_contracts"][0]})
    x, y = SymbolIdentity("x"), SymbolIdentity("y")
    a = replace(base_a, symbol=SymbolIdentity("a"), source="user", pairs=(x, y))
    b = replace(base_a, symbol=SymbolIdentity("b"), source="user", pairs=(y,))
    rx, ry = replace(base_x, symbol=x, source="user"), replace(base_x, symbol=y, source="user")
    registry = ContractRegistry()
    for contract in (a, b, rx, ry):
        registry.add(contract)
    assert not pool_pair_compatible(b, rx)
    snaps = [
        {"func_name": c.symbol.name, "interface_contracts": [asdict(c)]} for c in (a, b, rx, ry)
    ]
    complete_transparent_pairs(snaps, registry)
    assert [p["name"] for p in snaps[1]["interface_contracts"][0]["pairs"]] == ["y"]
    assert registry.allows("a", "x") and registry.allows("a", "y") and registry.allows("b", "y")
    assert not registry.allows("b", "x")


def test_pool_adapter_macro_output_and_unknown_call_boundaries():
    registry = default_local_pattern_semantics().contracts
    for snap in pool_snapshots():
        for raw in snap["interface_contracts"]:
            registry.add(ApiContract.from_row({"contract": raw}))
    macro = {**context("FETCH", "#define FETCH(arena) alpha((arena))"), "is_macro": True}
    snapshot = deterministic_contract_snapshot(macro, registry)
    assert snapshot is not None
    registry.add(ApiContract.from_row({"contract": snapshot["interface_contracts"][0]}))
    ctx = context("out", "void out(Pool *arena, Node **node) { *node = FETCH(arena); }")
    snap = deterministic_contract_snapshot(ctx, registry)
    assert snap is not None
    contract = ApiContract.from_row({"contract": snap["interface_contracts"][0]})
    assert contract.carrier.kind == "output_argument" and contract.carrier.argument_index == 1
    assert contract.resource_domain.argument_index == 0
    assert (
        deterministic_contract_snapshot(
            context("outer", "Node *outer(Pool *pool) { unknown(pool); return alpha(pool); }"),
            registry,
        )
        is None
    )

def test_pool_push_role_is_proved_from_implementation_not_model_label():
    from zscope.semantics.pool_protocols import verify_pool_contract
    raw = proposal("ownership_transfer", "alpha")
    verified = verify_pool_contract(raw, context("omega", GIVE))
    assert verified and verified["role"] == "deallocator"
    assert verified["verification"]["method"] == "source_protocol"
    # A different update is not promoted merely because the model names a pool.
    assert verify_pool_contract(raw, context("omega", GIVE.replace("pool->available = node;", "pool->available = node->link;"))) is None
