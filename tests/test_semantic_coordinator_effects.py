from concurrent.futures import ThreadPoolExecutor
import threading

import pytest

from zscope.common.cancellation import (
    CancellationError,
    CancellationToken,
    bind_cancellation_token,
    current_cancellation_token,
)
from zscope.orchestration.modeling_coordinator import ModelingCoordinator
from zscope.semantics.defaults import default_local_pattern_semantics
from zscope.semantics.contract_compiler import derive_contracts
from zscope.semantics.contracts import ApiContract
from zscope.semantics.call_context import bind_call_context, branch_values
from zscope.semantics.contract_conditions import compare


def test_owner_local_cancel_does_not_cancel_shared_task():
    coordinator = ModelingCoordinator()
    root = CancellationToken()
    local = root.child()
    entered, finish = threading.Event(), threading.Event()

    def operation():
        assert current_cancellation_token() is root
        entered.set()
        assert finish.wait(5)
        current_cancellation_token().raise_if_cancelled()
        return {"committed": True}

    def first():
        with bind_cancellation_token(local):
            return coordinator.run("version", operation)

    with ThreadPoolExecutor(2) as pool:
        owner = pool.submit(first)
        assert entered.wait(5)
        local.cancel()
        follower = pool.submit(coordinator.run, "version", lambda: pytest.fail("duplicate"))
        finish.set()
        with pytest.raises(CancellationError):
            owner.result()
        assert follower.result() == {"committed": True}
    assert coordinator.metrics()["unique_tasks"] == 1


def test_failures_shared_but_versions_and_independent_symbols_overlap():
    coordinator = ModelingCoordinator()
    error = ValueError("shared failure")
    with pytest.raises(ValueError) as first:
        coordinator.run("failed", lambda: (_ for _ in ()).throw(error))
    with pytest.raises(ValueError) as second:
        coordinator.run("failed", lambda: pytest.fail("retried by follower"))
    assert first.value is second.value is error
    barrier = threading.Barrier(2)

    def operation():
        barrier.wait(timeout=5)
        return 7

    with ThreadPoolExecutor(2) as pool:
        a = pool.submit(coordinator.run, "symbol-a/version-2", operation)
        b = pool.submit(coordinator.run, "symbol-b/version-1", operation)
        assert a.result() == b.result() == 7
    assert coordinator.metrics()["peak_concurrency"] == 2


def test_composite_effects_map_swapped_wrapper_arguments():
    registry = default_local_pattern_semantics().contracts
    raw = derive_contracts(
        {
            "func_name": "resize",
            "file_path": "x.c",
            "code": "void *resize(size_t n, void *p) { return realloc(p, n); }",
        },
        registry,
    )
    assert raw
    registry.add(ApiContract.from_row({"contract": raw[0]}))
    assert registry.reallocation_input("resize", ["32", "old"]) == "old"
    assert registry.reallocation_failure_preservation("resize", ["32", "old"]) == "applies"
    assert registry.reallocation_failure_preservation("resize", ["0", "old"]) == "does_not_apply"
    effects = registry.resolved_transitions(
        "resize",
        ["0", "old"],
        "r",
        facts={"old": {"non_null_identity": "old"}, "r": None, "target.libc": "glibc"},
    )
    assert any(
        t["applicability"] == "applies" and t["actions"] == [{"kind": "release", "object": "old"}]
        for t in effects
    )
    effects = registry.resolved_transitions(
        "pthread_cond_timedwait",
        ["&cond", "&mu", "&deadline"],
        "r",
        facts={"r": 110, "ETIMEDOUT": 110, "EOWNERDEAD": 130},
    )
    assert effects[0]["applicability"] == "applies"
    assert effects[0]["actions"] == [
        {"kind": "release", "object": "&mu"},
        {"kind": "acquire", "object": "&mu", "lock_mode": "exclusive"},
    ]


@pytest.mark.parametrize("engine", ["clang", "regex"])
def test_realloc_rule_uses_mapped_old_object_and_size(engine):
    from zscope.core.candidates.clang_ast_cfg import ClangAstCfgCandidateGenerator
    from zscope.core.candidates.regex import RegexCandidateGenerator

    semantics = default_local_pattern_semantics()
    for raw in derive_contracts(
        {
            "func_name": "resize",
            "file_path": "x.c",
            "code": "void *resize(size_t n, void *p) { return realloc(p, n); }",
        },
        semantics.contracts,
    ):
        semantics.contracts.add(ApiContract.from_row({"contract": raw}))
        semantics.add_api(raw["role"], "resize", "inferred:semantic_modeling")
    generator = (ClangAstCfgCandidateGenerator if engine == "clang" else RegexCandidateGenerator)(
        semantics
    )

    def rules(size):
        return generator.generate_issues(
            "f", f"void f(void *p) {{\np = resize({size}, p);\n}}", "x.c"
        )

    assert any(i["defect_class"] == "realloc_misuse" for i in rules("32"))
    assert not any(i["defect_class"] == "realloc_misuse" for i in rules("0"))


def test_call_context_cannot_borrow_facts_from_another_occurrence():
    registry = default_local_pattern_semantics().contracts
    context = {"func_name": "f", "code": "void f(void *p) { if (p) free(p); free(p); }"}
    with bind_call_context(context, registry):
        assert registry.match_call("free", "deallocator", ["p"])[0].applicability == "unknown"
    arg = {"kind": "argument", "index": 0}
    assert (
        branch_values(
            {
                "op": "all",
                "items": [compare(arg, "==", 1), compare(arg, "==", 2), compare(arg, "==", 1)],
            },
            ["p"],
        )
        == {}
    )


def test_allocation_extent_mapping_and_no_suffix_role_guess():
    from zscope.core.candidates.clang_ast_cfg import ClangAstCfgCandidateGenerator

    registry = default_local_pattern_semantics().contracts
    raw = derive_contracts(
        {
            "func_name": "obtain",
            "file_path": "a.c",
            "code": "void *obtain(int unused, size_t count) { return malloc(count); }",
        },
        registry,
    )
    registry.add(ApiContract.from_row({"contract": raw[0]}))
    assert registry.allocation_extent("obtain", ["999", "packet_size"]) == "packet_size"
    assert registry.allocation_extent("unrelated_alloc", ["packet_size"]) == ""
    generator = ClangAstCfgCandidateGenerator()
    issues = generator.generate_issues(
        "f", "void f(size_t packet_size) { void *p = unrelated_alloc(packet_size); }", "a.c"
    )
    assert not any(i.get("rule") == "clang_cfg_unbounded_heap_allocation" for i in issues)
