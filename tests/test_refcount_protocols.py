"""RAPI07: real native facts, descriptive counts and exact pool generations."""

from copy import deepcopy
import json

import pytest

from test_single_slot_pool import native_index, native_context, proposal as pool_proposal
from zscope.semantics.contract_compiler import compile_snapshot
from zscope.semantics.contracts import ApiContract, ContractRegistry
from zscope.semantics.refcount_protocols import verify_refcount_contract
from zscope.semantics.single_slot_pool import verify_single_slot_pool


HEADER = """typedef struct Node {int generation; int refs;} Node;
typedef struct Pool {Node slot; int live; int duplicate_returns;} Pool;
"""
APIS = """
Node *pool_take(Pool *pool) {
    if (pool->live) return 0;
    pool->live=1; pool->slot.generation++; return &pool->slot;
}
int pool_give(Pool *pool, Node *node) {
    if (node != &pool->slot || !pool->live) {pool->duplicate_returns++; return 0;}
    pool->live=0; return 1;
}
void destroy(Pool *pool, Node *node) {pool_give(pool,node);}
void ref_init(Node *node) {node->refs=1;}
int ref_retain(Node *node) {
    if (node->refs<=0 || node->refs==2147483647) return 0;
    node->refs++; return 1;
}
int ref_drop(Pool *pool, Node *node) {
    if (node->refs<=0) return 0;
    node->refs--; if (node->refs==0) {destroy(pool,node);} return 1;
}
int count_only_drop(Node *node) {
    if (node->refs<=0) return 0;
    node->refs--; return 1;
}
static void (*const cleanups[1])(Pool *, Node *) = {destroy};
int table_drop(Pool *pool, Node *node) {
    if (node->refs<=0) return 0;
    node->refs--; if (node->refs==0) {cleanups[0](pool,node);} return 1;
}
"""
SCENARIOS = {
    "two_to_one": "ref_retain(node); ref_drop(&pool,node);",
    "last_drop": "ref_retain(node); Node *alias=node; ref_drop(&pool,alias); ref_drop(&pool,node);",
    "borrow": "Node *borrow=node; ref_drop(&pool,borrow);",
    "failed_retain": "node->refs=0; ref_retain(node);",
    "saturated": "node->refs=2147483647; ref_retain(node);",
    "underflow_guard": "node->refs=0; ref_drop(&pool,node);",
    "negative_guard": "node->refs=-1; ref_drop(&pool,node);",
    "premature_return": "ref_retain(node); pool_give(&pool,node);",
    "missing_destroy": "count_only_drop(node);",
    "after_return": "ref_drop(&pool,node); ref_retain(node);",
    "new_generation": "ref_drop(&pool,node); Node *fresh=pool_take(&pool); ref_init(fresh); ref_retain(node);",
    "fresh_generation": "ref_drop(&pool,node); Node *fresh=pool_take(&pool); ref_init(fresh); ref_drop(&pool,fresh);",
    "explicit_zero": "node->refs=0; pool_give(&pool,node);",
    "counter_overflow": "node->refs=2147483647; node->refs++;",
    "generation_overflow": "node->generation=2147483647; pool_give(&pool,node); pool_take(&pool);",
    "table_cleanup": "table_drop(&pool,node);",
    "wrong_pool": "Pool other={0}; ref_drop(&other,node);",
    "failed_status": "Pool other={0}; int status=pool_give(&other,node); if(status) ref_retain(node);",
}


def entry_source():
    return "\n".join(
        "void scenario_" + name + "(void) {Pool pool={0}; Node *node=pool_take(&pool); "
        "if(!node) return; ref_init(node); " + body + "}\n"
        for name, body in SCENARIOS.items()
    )


NEGATIVES = """
int unguarded_retain(Node *node) {node->refs++; return 1;}
int unguarded_drop(Node *node) {node->refs--; return 1;}
int premature_drop(Pool *pool, Node *node) {
    if (node->refs<=0) return 0;
    node->refs--; if (node->refs==1) {destroy(pool,node);} return 1;
}
int wrong_object_drop(Pool *pool, Node *node, Node *other) {
    if (node->refs<=0) return 0;
    node->refs--; if (node->refs==0) {destroy(pool,other);} return 1;
}
int false_failure(Node *node) {
    if (node->refs<=0 || node->refs==2147483647) return 1;
    node->refs++; return 1;
}
typedef struct Atomic { _Atomic int refs; } Atomic;
typedef struct Volatile { volatile int refs; } Volatile;
typedef struct Unsigned { unsigned int refs; } Unsigned;
typedef struct Bits { int refs:3; } Bits;
typedef struct Wide { long long refs; } Wide;
typedef union Overlap { int refs; int other; } Overlap;
void atomic_init_count(Atomic *node) {node->refs=1;}
void volatile_init_count(Volatile *node) {node->refs=1;}
void unsigned_init_count(Unsigned *node) {node->refs=1;}
void bitfield_init_count(Bits *node) {node->refs=1;}
void wide_init_count(Wide *node) {node->refs=1;}
void qualified_init_count(volatile Node *node) {node->refs=1;}
__attribute__((noinline)) void attributed_init_count(Node *node) {node->refs=1;}
void union_init_count(Overlap *node) {node->refs=1;}
int false_pool_status(Pool *pool, Node *node) {
    if (node != &pool->slot || !pool->live) {pool->duplicate_returns++; return 1;}
    pool->live=0; return 0;
}
"""


def proposal(operation, index=0):
    return {
        "role": "standard_operation",
        "carrier": {"kind": "argument", "argument_index": index},
        "protocol": {"kind": "non_atomic_refcount", "operation": operation, "count_path": "->refs"},
        "effect_cases": [{"when": {"op": "unknown"}, "effect": "applies"}],
        "conditions": [],
        "pairs": [],
        "confidence": 0.9,
        "evidence": [{"lines": "1", "description": "Implementation proposal, not authority"}],
    }


def proposals():
    release = pool_proposal("deallocator")
    release["protocol"]["return_status"] = True
    return {
        "pool_take": pool_proposal("allocator"),
        "pool_give": release,
        "ref_init": proposal("init"),
        "ref_retain": proposal("retain"),
        "ref_drop": proposal("drop", 1),
        "count_only_drop": proposal("drop"),
        "table_drop": proposal("drop", 1),
    }


@pytest.fixture(scope="module")
def ref_project(tmp_path_factory):
    root = tmp_path_factory.mktemp("refcount-native")
    source = root / "reference.c"
    source.write_text(HEADER + APIS + NEGATIVES + entry_source())
    database = root / "compile_commands.json"
    database.write_text(
        json.dumps(
            [
                {
                    "directory": str(root),
                    "file": str(source),
                    "arguments": ["clang", "-std=c11", "-c", str(source)],
                }
            ]
        )
    )
    backend, index = native_index(root, source, database)
    try:
        yield index, source
    finally:
        backend.close()


@pytest.mark.parametrize(
    "name", ["ref_init", "ref_retain", "ref_drop", "count_only_drop", "table_drop"]
)
def test_real_count_protocol_is_not_a_deallocator(ref_project, name):
    index, source = ref_project
    context = native_context(index, source, name)
    verified = verify_refcount_contract(proposals()[name], context)
    assert verified
    contract = ApiContract.from_row({"contract": verified})
    assert contract.effects_trusted and contract.role == "standard_operation"
    assert not contract.verification["proof_authority"]
    assert contract.protocol["terminal_effect"] == "unresolved"
    assert bool(contract.protocol["terminal_call"]) == (name in {"ref_drop", "table_drop"})


@pytest.mark.parametrize(
    "name,operation,index",
    [
        ("unguarded_retain", "retain", 0),
        ("unguarded_drop", "drop", 0),
        ("premature_drop", "drop", 1),
        ("wrong_object_drop", "drop", 1),
        ("false_failure", "retain", 0),
        ("atomic_init_count", "init", 0),
        ("volatile_init_count", "init", 0),
        ("unsigned_init_count", "init", 0),
        ("union_init_count", "init", 0),
        ("bitfield_init_count", "init", 0),
        ("wide_init_count", "init", 0),
        ("qualified_init_count", "init", 0),
        ("attributed_init_count", "init", 0),
    ],
)
def test_unsupported_or_wrong_effects_cannot_authorize_counts(ref_project, name, operation, index):
    code_index, source = ref_project
    assert (
        verify_refcount_contract(
            proposal(operation, index), native_context(code_index, source, name)
        )
        is None
    )


def test_pool_status_matches_actual_membership_and_effect(ref_project):
    index, source = ref_project
    raw = proposals()["pool_give"]
    verified = verify_single_slot_pool(raw, native_context(index, source, "pool_give"))
    assert verified and verified["protocol"]["return_status"] == {"success": 1, "failure": 0}
    assert verified["protocol"]["storage"] == "embedded_slot"
    assert verify_single_slot_pool(raw, native_context(index, source, "false_pool_status")) is None


def test_publication_uses_existing_compiler_and_preserves_non_release_role(ref_project):
    index, source = ref_project
    registry = ContractRegistry()
    for name, raw in proposals().items():
        context = native_context(index, source, name)
        raw["evidence"][0]["lines"] = str(context["start_line"])
        snapshot = {**context, "interface_contracts": [deepcopy(raw)]}
        compile_snapshot(snapshot, context, registry)
        contracts = [
            ApiContract.from_row({"contract": row}) for row in snapshot["interface_contracts"]
        ]
        assert len(contracts) == 1 and contracts[0].effects_trusted, snapshot.get(
            "contract_diagnostics"
        )
        assert contracts[0].role == raw["role"]
        registry.add(contracts[0])
    assert not registry.allows("pool_take", "ref_drop")


def test_missing_native_or_wrong_role_cannot_publish_refcount(ref_project):
    index, source = ref_project
    context = native_context(index, source, "ref_retain")
    raw = proposal("retain")
    raw["role"] = "deallocator"
    assert verify_refcount_contract(raw, context) is None
    context = deepcopy(context)
    context["program_facts"]["functions"][0].pop("lifecycle_value_facts_version")
    assert verify_refcount_contract(proposal("retain"), context) is None


def registered(project):
    index, source = project
    registry = ContractRegistry()
    for name, raw in proposals().items():
        context = native_context(index, source, name)
        checker = verify_single_slot_pool if name.startswith("pool_") else verify_refcount_contract
        verified = checker(raw, context)
        assert verified, name
        registry.add(ApiContract.from_row({"contract": verified}))
    return registry


def analyze(project, name):
    from zscope.core.candidates.cpp_domains.lifecycle_paths import LifecyclePaths

    index, source = project
    return LifecyclePaths(
        index.get_function_program_facts("scenario_" + name, str(source)),
        registered(project),
        index.get_function_program_facts,
    ).run()


@pytest.mark.parametrize(
    "name",
    [
        "two_to_one",
        "last_drop",
        "borrow",
        "failed_retain",
        "saturated",
        "underflow_guard",
        "negative_guard",
        "fresh_generation",
        "explicit_zero",
        "table_cleanup",
    ],
)
def test_concrete_counts_do_not_invent_release_or_ownership(ref_project, name):
    result = analyze(ref_project, name)
    assert result["complete"], result["gaps"]
    assert not result["observations"], result["observations"]
    assert not result["proof_authority"]
    resource = result["resources"][-1]
    assert resource["release_responsibility"] == "unresolved"
    assert resource["state"] == (
        "released"
        if name in {"last_drop", "borrow", "fresh_generation", "explicit_zero", "table_cleanup"}
        else "live"
    )
    events = [e for e in result["trace"] if e["kind"].startswith("refcount_")]
    if name == "two_to_one":
        assert events[-1]["before"] == 2 and events[-1]["after"] == 1
        assert events[-1]["terminal_effect"] == "none_observed"
    if name in {"last_drop", "borrow", "fresh_generation", "table_cleanup"}:
        assert events[-1]["before"] == 1 and events[-1]["after"] == 0
        assert events[-1]["terminal_effect"] == "logical_pool_return"
    if name in {"failed_retain", "saturated", "underflow_guard", "negative_guard"}:
        assert not events[-1]["effect_applies"]
        assert events[-1]["before"] == events[-1]["after"]


@pytest.mark.parametrize(
    "name,expected",
    [
        ("premature_return", {"release_with_live_references"}),
        ("missing_destroy", {"zero_count_unreleased"}),
        ("after_return", {"refcount_after_return"}),
        ("new_generation", {"stale_generation_refcount"}),
        ("wrong_pool", {"wrong_pool_return", "zero_count_unreleased"}),
        ("failed_status", {"wrong_pool_return"}),
    ],
)
def test_refcount_observations_follow_the_actual_object_and_generation(ref_project, name, expected):
    result = analyze(ref_project, name)
    assert result["complete"], result["gaps"]
    assert {o["kind"] for o in result["observations"]} == expected
    if name == "new_generation":
        assert [r["generation"] for r in result["resources"]] == [1, 2]
        assert result["resources"][0]["id"] != result["resources"][1]["id"]
        event = result["observations"][0]["event"]
        assert event["saved_resource_id"] != event["resource_id"]
    if name == "failed_status":
        assert not any(e["kind"] == "refcount_retain" for e in result["trace"])


@pytest.mark.parametrize("name", ["counter_overflow", "generation_overflow"])
def test_integer_and_generation_wrap_remain_unclosed(ref_project, name):
    result = analyze(ref_project, name)
    assert not result["complete"] and result["gaps"] == ["integer_range_unclosed"]
    assert not result["observations"]


def test_current_validator_replay_keeps_serial_context_as_separate_assumption(ref_project):
    from test_lifecycle_paths import candidates
    from zscope.core.candidates.decision_facts import attach_decision_facts
    from zscope.core.validation.protocol_assessment import assess_protocol_candidate

    index, source = ref_project
    registry = registered(ref_project)
    for name in ("missing_destroy", "premature_return", "after_return", "new_generation"):
        (issue,) = candidates((index, source, registry), "scenario_" + name)
        attach_decision_facts(issue)
        assessment = assess_protocol_candidate(issue, index, registry)
        assert assessment["state"] == "conditional", assessment
        assert {a["fact_kind"] for a in assessment["assumptions"]} == {
            "event:business_release_requirement",
            "event:nonconcurrent_reference_count",
        }
        assert not assessment["proof_authority"] and not assessment["technical_gaps"]
