"""Source → normalized contract → XLSX → real consumer regression cases."""

from copy import deepcopy
from dataclasses import asdict

import pytest

from zscope.config.user_config_store import UserConfigStore
from zscope.core.candidates.clang_ast_cfg import ClangAstCfgCandidateGenerator
from zscope.core.candidates.graph import GraphCandidateGenerator
from zscope.core.candidates.regex import RegexCandidateGenerator
from zscope.core.candidates.evidence import SemanticOverlayCompiler
from zscope.semantics.contract_compiler import (
    derive_contracts,
    complete_transparent_pairs,
    compile_snapshot,
)
from zscope.semantics.contract_conditions import compare, evaluate
from zscope.semantics.contracts import ApiContract, contract_rows
from zscope.semantics.defaults import default_local_pattern_semantics
from zscope.semantics.inference import LocalPatternSemanticBuilder


def context(name, code, macro=False):
    return {
        "func_name": name,
        "file_path": "interfaces.h" if macro else "interfaces.c",
        "signature": code.split("{")[0] if not macro else code.split(")", 1)[0] + ")",
        "is_macro": macro,
        "code": code,
        "index_name": name + "@interfaces.c:1-1",
        "referenced_globals": [],
        "referenced_types": [],
        "referenced_macros": [],
    }


def compile_all(contexts, registry=None):
    registry = registry or default_local_pattern_semantics().contracts
    snapshots = []
    for ctx in contexts:
        snap = {**ctx, "interface_contracts": derive_contracts(ctx, registry)}
        snapshots.append(snap)
        for raw in snap["interface_contracts"]:
            registry.add(ApiContract.from_row({"contract": raw}))
    complete_transparent_pairs(snapshots, default_local_pattern_semantics().contracts)
    return snapshots


def publish(tmp_path, snapshots):
    store = UserConfigStore(tmp_path / "user_config.xlsx")
    store.workbook.merge_generated(contract_rows(snapshots), covered_symbols=set())
    # Separate reader: no in-memory writer state is available to consumers.
    reader = UserConfigStore(store.workbook.path)
    semantics = LocalPatternSemanticBuilder(None, reader, None, []).semantics_from_user_config()
    overlay = SemanticOverlayCompiler(reader).compile()
    return reader, semantics, overlay


@pytest.mark.parametrize(
    "body",
    [
        "if (pthread_mutex_lock(m) == 0) { work(); pthread_mutex_unlock(m); }",
        "if (pthread_mutex_lock(m) != 0) return; work(); pthread_mutex_unlock(m);",
        "int status = pthread_mutex_lock(m); if (status != 0) return; work(); pthread_mutex_unlock(m);",
        "if (pthread_mutex_lock(m)) return; work(); pthread_mutex_unlock(m);",
        "if (!pthread_mutex_lock(m)) { work(); pthread_mutex_unlock(m); }",
    ],
)
def test_nonzero_mutex_status_cannot_prove_balanced_business(body):
    from zscope.semantics.contract_compiler import read_source_facts

    registry = default_local_pattern_semantics().contracts
    ctx = context("business", "void business(pthread_mutex_t *m) { " + body + " }")
    facts = read_source_facts(ctx, registry)
    assert facts.complete
    assert [call.name for call in facts.calls] == ["pthread_mutex_lock", "pthread_mutex_unlock"]
    # EOWNERDEAD also acquires a robust mutex. These bodies only release on
    # zero; the opaque work branch prevents a verified outward specification.
    assert not any(ApiContract.from_row({"contract": row}).effects_trusted
                   for row in derive_contracts(ctx, registry))


def test_condition_call_with_outward_lock_still_has_contract():
    registry = default_local_pattern_semantics().contracts
    ctx = context(
        "take",
        "int take(pthread_mutex_t *m) { if (pthread_mutex_lock(m) == 0) return 1; return 0; }",
    )
    assert [c["role"] for c in derive_contracts(ctx, registry)] == ["lock"]


def test_short_circuit_operation_does_not_claim_complete_source_facts():
    from zscope.semantics.contract_compiler import read_source_facts

    ctx = context(
        "take",
        "void take(int enabled, pthread_mutex_t *m) { if (enabled && pthread_mutex_lock(m) == 0) work(); }",
    )
    assert not read_source_facts(ctx, default_local_pattern_semantics().contracts).complete


def test_separate_call_results_have_distinct_stable_identities():
    from zscope.semantics.contract_compiler import read_source_facts

    registry = default_local_pattern_semantics().contracts
    code = "void take(pthread_mutex_t *m) { if (pthread_mutex_lock(m) == 0) work(); if (pthread_mutex_lock(m) == 0) work(); }"
    before = read_source_facts(context("take", code), registry)
    after = read_source_facts(context("take", code.replace("{ if", "{ log(); if", 1)), registry)
    ids = [call.result_identity for call in before.calls]
    assert len(set(ids)) == 2
    assert ids == [call.result_identity for call in after.calls]


def test_member_and_global_outputs_keep_actual_carrier(tmp_path):
    member = context("create", "void create(State *s) { s->ptr = malloc(8); }")
    global_output = context("init", "void init(void) { pool.ptr = malloc(8); }")
    global_output["referenced_globals"] = [{"name": "pool"}]
    snapshots = compile_all([member, global_output])
    _, semantics, _ = publish(tmp_path, snapshots)
    registry = semantics.contracts
    created = registry.find("create")[0]
    assert created.carrier.kind == "output_argument"
    assert created.carrier.member_path == "->ptr"
    assert registry.find("init")[0].carrier.global_name == "pool.ptr"
    assert (
        derive_contracts(context("local", "void local(void *p) { p = malloc(8); }"), registry) == []
    )
    fake = context("bad", "void bad(void) { poo.ptr = malloc(8); }")
    fake["referenced_globals"] = [{"name": "pool"}]
    assert derive_contracts(fake, registry) == []


def test_schema_only_contract_keeps_canonical_symbol_identity():
    ctx = context("adapter", "void *adapter(void *p) { return foreign(p); }")
    snapshot = {
        "interface_contracts": [
            {
                "role": "allocator",
                "carrier": {"kind": "return"},
                "preconditions": {"op": "true"},
                "effect_cases": [{"when": {"op": "unknown"}, "effect": "applies"}],
                "evidence": [{"lines": [1]}],
            }
        ]
    }
    assert compile_snapshot(snapshot, ctx, default_local_pattern_semantics().contracts) == []
    contract = ApiContract.from_row({"contract": snapshot["interface_contracts"][0]})
    assert contract is not None
    assert contract.symbol.name == "adapter" and contract.symbol.file_path == "interfaces.c"
    assert contract.verification["method"] == "schema_only"
    assert not contract.verification["proof_authority"]


def test_address_and_pointer_value_are_distinct_objects():
    from zscope.semantics.contracts import ObjectBinding

    registry = default_local_pattern_semantics().contracts
    assert registry.release_status("malloc", "free", ["&p"], acquired_object="p") != "applies"
    assert ObjectBinding("argument", 0).resolve(["&mutex"]) == "&mutex"
    assert ObjectBinding("output_argument", 0).resolve(["&p"]) == "p"
    assert ObjectBinding("output_argument", 0).resolve(["pp"]) == "*pp"
    assert ObjectBinding("output_argument", 0, "->ptr").resolve(["&state"]) == "state.ptr"


@pytest.mark.parametrize("engine_type", [ClangAstCfgCandidateGenerator, RegexCandidateGenerator])
def test_wrong_pointer_address_release_reaches_rule_candidate(engine_type):
    engine = engine_type(default_local_pattern_semantics())
    code = "1 | void f(void) {\n2 | void *p = malloc(8);\n3 | if (!p) return;\n4 | free(%s);\n5 | return;\n6 | }"
    valid = engine.generate_issues("f", code % "p", "probe.c")
    invalid = engine.generate_issues("f", code % "&p", "probe.c")
    assert not valid
    assert any(
        i["rule"] in {"clang_cfg_free_non_owner_pointer_expression", "free_non_owner_pointer"}
        for i in invalid
    )


def test_global_lock_address_matches_direct_unlock(tmp_path):
    ctx = context("on", "#define on() pthread_mutex_lock(&gate)", True)
    ctx["referenced_globals"] = [{"name": "gate"}]
    _, semantics, _ = publish(tmp_path, compile_all([ctx]))
    registry = default_local_pattern_semantics().contracts
    for contract in semantics.contracts.contracts:
        registry.add(contract)
    assert registry.resolve_object("on", "lock", []) == "&gate"
    assert registry.resolve_object("pthread_mutex_unlock", "unlock", ["&gate"]) == "&gate"
    assert registry.resolve_object("pthread_mutex_unlock", "unlock", ["gate"]) != "&gate"


def test_internal_free_uses_mapped_object_and_operation_order():
    registry = default_local_pattern_semantics().contracts
    wrapper = context("drop", "void drop(void *ignored, void *p) { free(p); }")
    for raw in derive_contracts(wrapper, registry):
        registry.add(ApiContract.from_row({"contract": raw}))
    for body in (
        "void *p = malloc(8); free((p)); return p;",
        "void *p = malloc(8); drop(0, p); return p;",
    ):
        assert not any(
            c["role"] == "allocator"
            for c in derive_contracts(
                context("make", "void *make(void) { " + body + " }"), registry
            )
        )
    for body in ("free(p); p = malloc(8); return p;", "void *q = malloc(8); drop(q, p); return q;"):
        assert any(
            c["role"] == "allocator"
            for c in derive_contracts(
                context("make", "void *make(void *p) { " + body + " }"), registry
            )
        )


def test_nested_output_mapping_distinguishes_local_slot_member_and_macro():
    snapshots = compile_all(
        [
            context("out", "void out(void **p) { *p = malloc(8); }"),
            context("local", "void local(void *p) { out(&p); }"),
            context("member", "void member(State *s) { out(&s->ptr); }"),
            context("MAKE", "#define MAKE(p) out(&(p))", True),
        ]
    )
    assert snapshots[1]["interface_contracts"] == []
    member = ApiContract.from_row({"contract": snapshots[2]["interface_contracts"][0]})
    macro = ApiContract.from_row({"contract": snapshots[3]["interface_contracts"][0]})
    assert member.carrier.resolve(["state"]) == "state->ptr"
    assert macro.carrier.resolve(["ptr"]) == "ptr"


def test_source_wrappers_with_conditions_reach_every_consumer(tmp_path):
    snapshots = compile_all(
        [
            context(
                "alpha",
                "void *alpha(size_t n) { void *p = malloc(n); if (!p && n > 0) return NULL; return p; }",
            ),
            context("beta", "void *beta(size_t n, size_t m) { return calloc(n, m); }"),
            context("gamma", "void *gamma(void *p, size_t n) { return realloc(p, n); }"),
            context(
                "omega", "#define omega(p) do { if (p) { free(p); (p) = NULL; } } while(0)", True
            ),
        ]
    )
    store, semantics, overlay = publish(tmp_path, snapshots)
    assert "beta" in semantics.calloc_allocators and "beta" not in semantics.allocators
    assert "gamma" in semantics.reallocators
    for cls in (ClangAstCfgCandidateGenerator, RegexCandidateGenerator):
        engine = cls(semantics)
        assert engine.semantics.contracts.allows("alpha", "omega")
        assert engine.semantics.contracts.resolve_object("omega", "deallocator", ["p"]) == "p"
    graph = GraphCandidateGenerator(object(), semantics, overlay)
    assert graph.semantics.contracts.allows("beta", "omega")
    clang = ClangAstCfgCandidateGenerator(semantics, overlay)
    assert "alpha" in clang._return_acquirers
    assert clang._match_release("omega(p);") == ("omega", "p")
    assert clang._match_release("omega(NULL);") is None
    assert "alpha" in overlay["summary"]["resource_names"]
    assert all(p["source"].startswith("inferred") for p in store.list_paired_functions())
    assert (
        semantics.contracts.release_status("alpha", "omega", ["p"], acquired_object="p")
        == "applies"
    )
    assert (
        semantics.contracts.release_status("alpha", "omega", ["q"], acquired_object="p")
        == "unknown"
    )
    code = "1 | void entry() {\n2 | void *p = alpha(16);\n3 | if (!p) return;\n4 | %s\n5 | return;\n6 | }"
    leaking = clang.generate_issues("entry", code % "use(p);", "entry.c")
    balanced = clang.generate_issues("entry", code % "omega(p);", "entry.c")
    assert any(i["rule"] == "clang_cfg_acquire_without_release_on_exit" for i in leaking)
    assert not any(i["rule"] == "clang_cfg_acquire_without_release_on_exit" for i in balanced)


def test_lock_macro_composes_parameter_mapping_and_keeps_hidden_result_unknown(tmp_path):
    snapshots = compile_all(
        [
            context(
                "alpha",
                "void alpha(int unused, pthread_mutex_t *m) { if (!m) return; int r = pthread_mutex_lock(m); if (r != 0) log_error(r); }",
            ),
            context(
                "omega",
                "int omega(int unused, pthread_mutex_t *m) { return pthread_mutex_unlock(m); }",
            ),
            context("ENTER", "#define ENTER(m) alpha(7, m)", True),
            context("LEAVE", "#define LEAVE(m) omega(7, m)", True),
        ]
    )
    _, semantics, overlay = publish(tmp_path, snapshots)
    clang = ClangAstCfgCandidateGenerator(semantics, overlay)
    # The zero-status effect is proved; EOWNERDEAD/recovery stays unknown.
    assert clang._match_lock("ENTER(&mu);") == ("ENTER", "&mu")
    assert clang._match_unlock("LEAVE(&mu);") == ("LEAVE", "&mu")
    assert semantics.contracts.allows("ENTER", "LEAVE")
    matches = semantics.contracts.match_call("alpha", "lock", ["7", "mu"])
    assert matches and matches[0].applicability == "unknown"
    assert (
        semantics.contracts.match_call("alpha", "lock", ["7", "NULL"])[0].applicability
        == "does_not_apply"  # Null exits before the primitive and opaque recovery.
    )
    assert (
        semantics.contracts.release_status("ENTER", "LEAVE", ["mu"], acquired_object="mu")
        == "unknown"
    )


def test_internal_temporaries_and_extra_cleanup_do_not_mint_transparent_pairs():
    snapshots = compile_all(
        [
            context("alpha", "void *alpha(size_t n) { return malloc(n); }"),
            context("business", "void business(void) { void *p = malloc(4); free(p); }"),
            context("destroy", "void destroy(struct Node *p) { free(p->data); free(p); }"),
        ]
    )
    assert snapshots[1]["interface_contracts"] == []
    assert not any(t["name"] == "destroy" for t in snapshots[0]["interface_contracts"][0]["pairs"])


def test_nested_macro_balance_is_known_before_publication(tmp_path):
    snapshots = compile_all(
        [
            context("enter", "void enter(pthread_mutex_t *m) { pthread_mutex_lock(m); }"),
            context("leave", "int leave(pthread_mutex_t *m) { return pthread_mutex_unlock(m); }"),
            context("TAKE", "#define TAKE(m) enter(m)", True),
            context("DROP", "#define DROP(m) leave(m)", True),
            context("business", "void business(pthread_mutex_t *m) { TAKE(m); use(); DROP(m); }"),
            context(
                "wrong", "void wrong(pthread_mutex_t *a, pthread_mutex_t *b) { TAKE(a); DROP(b); }"
            ),
            context(
                "early",
                "void early(pthread_mutex_t *m, int stop) { TAKE(m); if (stop) return; DROP(m); }",
            ),
        ]
    )
    assert snapshots[4]["interface_contracts"] == []
    assert snapshots[5]["interface_contracts"]
    assert snapshots[6]["interface_contracts"]
    _, semantics, overlay = publish(tmp_path, snapshots)
    code = "void business(pthread_mutex_t *m) {\nTAKE(m);\nuse();\nDROP(m);\nreturn;\n}"
    for engine in (
        ClangAstCfgCandidateGenerator(semantics, overlay),
        RegexCandidateGenerator(semantics),
    ):
        assert not any(
            i["defect_class"] in {"missing_unlock", "lock_leak"}
            or i["rule"] == "return_while_lock_held"
            for i in engine.generate_issues("business", code, "interfaces.c")
        )


def test_output_argument_carrier_survives_source_compilation(tmp_path):
    snapshots = compile_all(
        [
            context("alpha", "int alpha(size_t n, void **out) { *out = malloc(n); return 0; }"),
            context("omega", "void omega(int unused, void *p) { free(p); }"),
        ]
    )
    _, semantics, overlay = publish(tmp_path, snapshots)
    clang = ClangAstCfgCandidateGenerator(semantics, overlay)
    assert "alpha" in clang._out_param_acquirers
    assert clang._match_release("omega(7, ptr);") == ("omega", "ptr")


def test_invalid_model_proposals_are_replaced_only_with_source_backed_contracts():
    ctx = context("alpha", "void *alpha(size_t n, size_t m) { return calloc(n, m); }")
    snapshot = {
        "interface_contracts": [
            {"role": "allocator", "carrier": {"kind": "return"}, "conditions": [], "pairs": []}
        ]
    }
    assert compile_snapshot(snapshot, ctx, default_local_pattern_semantics().contracts) == []
    assert [c["role"] for c in snapshot["interface_contracts"]] == ["calloc"]
    assert snapshot["raw_interface_contracts"][0]["role"] == "allocator"
    bad = {
        "interface_contracts": [
            {
                "role": "lock",
                "carrier": {
                    "kind": "argument",
                    "argument_index": 0,
                    "member_path": "the lock state",
                },
                "preconditions": {"op": "true"},
                "effect_cases": [
                    {
                        "when": {
                            "op": "all",
                            "items": [
                                compare({"kind": "return"}, "==", 0),
                                compare({"kind": "return"}, "!=", 0),
                            ],
                        },
                        "effect": "applies",
                    }
                ],
                "pairs": [],
                "evidence": [{"lines": "1", "description": "source"}],
            }
        ]
    }
    errors = compile_snapshot(bad, ctx, default_local_pattern_semantics().contracts)
    assert "invalid_member_path" in errors and "contradictory_effect_condition" in errors
    assert all(c["role"] != "lock" for c in bad["interface_contracts"])


def test_typed_predicates_do_not_treat_unknown_as_false():
    predicate = compare({"kind": "return"}, "==", 0)
    assert evaluate(predicate, returned="status") == "unknown"
    assert evaluate(predicate, returned="status", facts={"status": 0}) == "applies"
    assert evaluate(predicate, returned="status", facts={"status": 1}) == "does_not_apply"


@pytest.mark.parametrize("constraints", [(("==", 0), ("==", 1)), ((">", 8), ("<=", 4))])
def test_conflicting_typed_conditions_cannot_be_published(constraints):
    from zscope.semantics.contract_conditions import predicate_errors

    expression = {
        "op": "all",
        "items": [compare({"kind": "return"}, op, value) for op, value in constraints],
    }
    assert "contradictory_effect_condition" in predicate_errors(expression)


def test_graph_does_not_prove_held_state_from_unknown_effects(tmp_path):
    from test_graph_candidates import _function_view

    snapshots = compile_all(
        [
            context(
                "maybe_enter", "void maybe_enter(pthread_mutex_t *m) { pthread_mutex_lock(m); }"
            ),
            context(
                "maybe_leave", "void maybe_leave(pthread_mutex_t *m) { pthread_mutex_unlock(m); }"
            ),
        ]
    )
    _, semantics, overlay = publish(tmp_path, snapshots)
    graph = GraphCandidateGenerator(object(), semantics, overlay)
    assert graph._lock_arg("maybe_enter(&m);") == ""
    assert not graph._locks_may_match("left->mutex", "right->mutex")
    caller = _function_view(
        graph,
        "entry",
        "void entry(void) {\npthread_mutex_lock(&m);\nmaybe_leave(&m);\nhelper();\n}",
    )
    helper = _function_view(graph, "helper", "void helper(void) {\npthread_mutex_lock(&m);\n}")
    # Link the source-composed release to the standard acquisition protocol.
    from zscope.semantics.contracts import ApiPair, SymbolIdentity

    graph.semantics.contracts.pairs.append(
        ApiPair(
            SymbolIdentity("pthread_mutex_lock"),
            SymbolIdentity("maybe_leave"),
            [],
            "inferred:semantic_modeling",
        )
    )
    issues = []
    graph._rule_recursive_lock(caller, {"helper": helper}, issues)
    assert not issues
    held = [("&m", caller.lines[1])]
    uncertain = set()
    assert graph._release_held_lock("maybe_leave(&m);", held, uncertain)
    assert held and uncertain == {"&m"}


def test_member_and_global_lock_carriers_and_internal_balance(tmp_path):
    global_enter = context("alpha", "#define alpha() pthread_mutex_lock(&shared_mutex)", True)
    global_leave = context("omega", "#define omega() pthread_mutex_unlock(&shared_mutex)", True)
    for ctx in (global_enter, global_leave):
        ctx["referenced_globals"] = [{"name": "shared_mutex", "type": "pthread_mutex_t"}]
    snapshots = compile_all(
        [
            global_enter,
            global_leave,
            context(
                "enter", "int enter(struct State *s) { return pthread_mutex_lock(&s->mutex); }"
            ),
            context(
                "leave", "int leave(struct State *s) { return pthread_mutex_unlock(&s->mutex); }"
            ),
            context(
                "business",
                "void business(pthread_mutex_t *p) { pthread_mutex_lock(p); use(); pthread_mutex_unlock(p); }",
            ),
        ]
    )
    assert snapshots[-1]["interface_contracts"] == []
    _, semantics, overlay = publish(tmp_path, snapshots)
    clang = ClangAstCfgCandidateGenerator(semantics, overlay)
    assert clang._match_lock("alpha();") == ("alpha", "&shared_mutex")
    assert clang._match_unlock("omega();") == ("omega", "&shared_mutex")
    assert clang._match_lock("enter(state);") == ("enter", "&state->mutex")
    assert clang._match_unlock("leave(other);") == ("leave", "&other->mutex")
    assert (
        semantics.contracts.release_status(
            "enter", "leave", ["other"], acquired_object="state->mutex"
        )
        == "unknown"
    )


def test_unknown_release_retains_leak_candidate_without_free_proof(tmp_path):
    snapshots = compile_all(
        [
            context("alpha", "void *alpha(size_t n) { return malloc(n); }"),
            context("omega", "void omega(int condition, void *p) { if (condition) free(p); }"),
        ]
    )
    _, semantics, overlay = publish(tmp_path, snapshots)
    source = "void entry(int flag) {\nvoid *p = alpha(8);\nif (!p) return;\nomega(flag, p);\nuse(p);\nreturn;\n}"
    for engine in (
        ClangAstCfgCandidateGenerator(semantics, overlay),
        RegexCandidateGenerator(semantics),
    ):
        issues = engine.generate_issues("entry", source, "entry.c")
        assert any(i["defect_class"] == "memory_leak" for i in issues)
        assert not any(i["defect_class"] in {"use_after_free", "double_free"} for i in issues)
        assert any(
            e["symbol"]["name"] == "omega" and e["applicability"] == "unknown"
            for e in engine.last_semantic_events
        )


def test_transparent_contracts_bypass_terminal_tool_and_reuse_hot_cache(tmp_path, monkeypatch):
    import json
    from test_global_modeler import FakeCodeIndex
    from test_incremental_semantic_modeling import modeler_for
    from test_json_output_agents import _snapshot_payload
    from zscope.agents.semantic_modeler.agent import SemanticModeler
    from zscope.framework.llm_client import LLMClient
    from zscope.config.function_entry import FunctionEntry

    index = FakeCodeIndex()
    index.impls = {"alpha": index._impl("alpha", []), "omega": index._impl("omega", [])}
    index.impls["alpha"].update(
        signature="void *alpha(size_t n)", code="void *alpha(size_t n) { return calloc(n, 1); }"
    )
    index.impls["omega"].update(
        signature="void omega(void *p)", code="void omega(void *p) { if (p) free(p); }"
    )
    calls = []

    def factory():
        llm = LLMClient(api_key="test", base_url="http://example.invalid", models=["unit-model"])

        def completion(messages, **kwargs):
            calls.append(messages)
            payload = _snapshot_payload()
            payload["suspicious_points"] = [
                {"category": "api_contract", "lines": "1", "description": "Unverified context."}
            ]
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
        return SemanticModeler(llm, [])

    modeler = modeler_for(tmp_path, index, calls, factory)
    entries = [FunctionEntry("alpha"), FunctionEntry("omega")]
    stats = modeler.run(entries)
    assert stats.stage_complete and not calls and stats.deterministic_snapshot_count == 2
    store = UserConfigStore(modeler.user_config.workbook.path)
    semantics = LocalPatternSemanticBuilder(None, store, None, []).semantics_from_user_config()
    assert "alpha" in semantics.calloc_allocators
    assert (
        semantics.contracts.release_status("alpha", "omega", ["p"], acquired_object="p")
        == "applies"
    )
    assert all(
        p["source"].startswith("inferred") and p["evidence"] for p in store.list_paired_functions()
    )
    assert modeler.result.suspicious_metrics["registered"] == 0
    artifact = json.loads(
        (
            modeler.snapshot_store.snapshot_dir / ".semantic-modeling" / "publication.json"
        ).read_text()
    )
    assert artifact["contract_version"] == modeler.result.contract_version
    assert artifact["snapshots"] and artifact["call_sites"]
    stamp = store.workbook.path.stat().st_mtime_ns
    calls.clear()
    stats = modeler.run(entries)
    assert stats.stage_complete and not calls and stats.cache_hit_functions == 2
    assert store.workbook.path.stat().st_mtime_ns == stamp
