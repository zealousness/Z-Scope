"""Published contracts remain typed, conditional observations in discovery."""

from dataclasses import replace

from test_security_semantic_map import FakeSecurityIndex
from test_wrapper_contract_compiler import compile_all, context, publish
from zscope.config.function_entry import FunctionEntry
from zscope.semantics.contracts import ApiContract, ObjectBinding, SymbolIdentity
from zscope.semantics.contract_conditions import compare
from zscope.semantics.security_map import SecuritySemanticMap, ZeroLLMSecurityMapBuilder


def build(code, contracts=(), **overlay):
    index = FakeSecurityIndex()
    index.impls["entry"]["code"] = "void entry(void) {\n" + code + "\n}"
    index.get_callees = lambda *a, **k: []
    return ZeroLLMSecurityMapBuilder(
        index,
        project_id="contracts",
        revision="rev",
        profile="balanced",
        semantic_overlay={"api_contracts": [c.to_dict() for c in contracts], **overlay},
    ).build([FunctionEntry("entry", file_path="src/demo.c")])


def call_claims(result):
    return [c for c in result.claims if "call_semantics" in c.value]


def test_real_source_and_workbook_lock_events_build_map_without_family_crash(tmp_path):
    contexts = [
        context("begin", "int begin(pthread_mutex_t *p) { return pthread_mutex_lock(p); }"),
        context("end", "void end(pthread_mutex_t *p) { pthread_mutex_unlock(p); }"),
    ]
    _, custom, overlay = publish(tmp_path, compile_all(contexts))
    result = build("begin(&guard); end(&guard);", **overlay)
    claims = call_claims(result)
    assert {c.value["call_semantics"]["role"] for c in claims} == {"lock", "unlock"}
    assert {c.value["call_semantics"]["object"] for c in claims} == {"&guard"}
    assert all(c.kind == "lock_order" for c in claims)
    assert all(c.origin == "program" and c.status == "unknown" for c in claims)
    assert {e.family for f in result.functions for e in f.events} == {"callback_concurrency"}
    assert result.fingerprints["contract_version"] == overlay["contract_version"]
    SecuritySemanticMap.from_dict(result.to_dict())


def test_inferred_contract_is_not_promoted_to_manual_or_program_evidence():
    proposal = ApiContract(
        SymbolIdentity("touch"),
        "lock",
        ObjectBinding("argument", 0),
        source="inferred:semantic_modeling",
        confidence=1.0,
    )
    result = build("touch(&g);", [proposal])
    (claim,) = call_claims(result)
    assert claim.origin == "llm" and claim.status == "unknown"
    assert claim.value["call_semantics"]["applicability"] == "unknown"


def test_manual_contract_preserves_false_and_unknown_effects():
    contract = ApiContract(
        SymbolIdentity("finish"),
        "deallocator",
        ObjectBinding("argument", 0),
        effect_cases=[
            {"when": compare({"kind": "argument", "index": 0}, "==", 0), "effect": "no_effect"},
            {"when": compare({"kind": "argument", "index": 0}, "!=", 0), "effect": "applies"},
        ],
    )
    result = build("finish(NULL); finish(p);", [contract])
    claims = call_claims(result)
    assert len(claims) == 2
    by_object = {c.value["call_semantics"]["object"]: c for c in claims}
    assert by_object["NULL"].value["call_semantics"]["applicability"] == "does_not_apply"
    assert by_object["NULL"].status == "known"
    assert by_object["p"].status == "unknown"
    assert all(c.origin == "user" for c in claims)


def test_summary_names_strings_and_comments_are_not_interface_recognition():
    contract = ApiContract(SymbolIdentity("enter"), "lock", ObjectBinding("argument", 0))
    result = build(
        'pretend(&g); const char *s="enter(&g)"; /* enter(&g); */',
        [contract],
        lock_models=[{"name": "pretend"}],
    )
    assert not call_claims(result)


def test_global_macro_and_all_calls_on_same_line_preserve_actual_objects():
    macro = ApiContract(
        SymbolIdentity("BEGIN", symbol_type="macro"),
        "lock",
        ObjectBinding("global", global_name="guard"),
    )
    normal = ApiContract(SymbolIdentity("end"), "unlock", ObjectBinding("argument", 0))
    result = build("BEGIN; end(&a); end(&b);", [macro, normal])
    assert {c.value["call_semantics"]["object"] for c in call_claims(result)} == {
        "guard",
        "&a",
        "&b",
    }


def test_ambiguous_symbols_and_member_calls_do_not_borrow_bare_contract():
    a = ApiContract(SymbolIdentity("touch", "a.c"), "lock", ObjectBinding("argument", 0))
    b = replace(a, symbol=SymbolIdentity("touch", "b.c"))
    assert not call_claims(build("touch(&g);", [a, b]))
    assert not call_claims(build("obj->touch(&g);", [a]))


def test_assignment_carrier_and_pool_domain_are_resolved_separately():
    contract = ApiContract(
        SymbolIdentity("take"),
        "allocator",
        ObjectBinding("return"),
        resource_domain=ObjectBinding("argument", 0),
        resource_family="pool",
    )
    result = build("void *p=take(&arena);", [contract])
    (claim,) = call_claims(result)
    operation = claim.value["call_semantics"]
    assert (operation["object"], operation["resource_domain"]) == ("p", "&arena")
    assert operation["contract_version"] == result.fingerprints["contract_version"]


def test_inferred_overlay_contract_and_legacy_intent_do_not_become_user_claims():
    proposal = ApiContract(
        SymbolIdentity("entry"),
        "lock",
        ObjectBinding("global", global_name="g"),
        source="inferred:semantic_modeling",
    )
    result = build(
        "return;",
        [proposal],
        function_intent_models=[
            {"name": "entry", "source": "inferred:semantic_modeling", "description": "guess"}
        ],
    )
    relevant = [c for c in result.claims if "api_contract" in c.value or "description" in c.value]
    assert len(relevant) == 2
    assert all(c.origin == "llm" and c.status == "unknown" for c in relevant)
