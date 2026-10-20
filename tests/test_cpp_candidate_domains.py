from __future__ import annotations

from types import SimpleNamespace

from zscope.core.candidates.clang_ast_cfg import ClangAstCfgCandidateGenerator
from zscope.core.candidates.cpp_domains import detector_plan
from zscope.core.candidates.cpp_domains.concurrency_shared_state import (
    ClangConcurrencySharedStateRules,
    GraphConcurrencySharedStateRules,
    RegexConcurrencySharedStateRules,
)
from zscope.core.candidates.cpp_domains.memory_bounds_integer import (
    ClangMemoryBoundsIntegerRules,
    GraphMemoryBoundsIntegerRules,
    RegexMemoryBoundsIntegerRules,
)
from zscope.core.candidates.cpp_domains.models import (
    ClangCfgLine,
    CodeLine,
    FunctionView,
    GraphLine,
    LockOrderEdge,
    LockState,
    ResourceState,
)
from zscope.core.candidates.cpp_domains.protocol_ownership_logic import (
    ClangProtocolOwnershipLogicRules,
    GraphProtocolOwnershipLogicRules,
    RegexProtocolOwnershipLogicRules,
)
from zscope.core.candidates.cpp_domains.resource_lifecycle import (
    ClangResourceLifecycleRules,
    GraphResourceLifecycleRules,
    RegexResourceLifecycleRules,
)
from zscope.core.candidates.graph import GraphCandidateGenerator
from zscope.core.candidates.regex import RegexCandidateGenerator


_ALL_DOMAINS = {
    "resource_lifecycle",
    "memory_bounds_integer",
    "concurrency_shared_state",
    "protocol_ownership_logic",
}


def _covered_domains(engine: str) -> set[str]:
    stages = tuple(
        stage
        for phase in ("function", "view", "batch")
        for stage in detector_plan(engine, phase)  # type: ignore[arg-type]
    )
    return {domain for stage in stages for domain in (stage.domain, *stage.covers)}


def test_each_cpp_engine_plan_is_organized_across_all_domains() -> None:
    assert _covered_domains("regex") == _ALL_DOMAINS
    assert _covered_domains("clang_ast_cfg") == _ALL_DOMAINS
    assert _covered_domains("graph") == _ALL_DOMAINS


def test_facades_delegate_detector_business_methods_to_domain_mixins() -> None:
    """Prevent the mechanically split engines from growing back into facades."""

    facade_prefixes = ("_rule_", "_run_", "_maybe_emit_", "_track_", "_find_")
    expected_mixins = {
        RegexCandidateGenerator: (
            RegexResourceLifecycleRules,
            RegexMemoryBoundsIntegerRules,
            RegexConcurrencySharedStateRules,
            RegexProtocolOwnershipLogicRules,
        ),
        GraphCandidateGenerator: (
            GraphResourceLifecycleRules,
            GraphMemoryBoundsIntegerRules,
            GraphConcurrencySharedStateRules,
            GraphProtocolOwnershipLogicRules,
        ),
        ClangAstCfgCandidateGenerator: (
            ClangResourceLifecycleRules,
            ClangMemoryBoundsIntegerRules,
            ClangConcurrencySharedStateRules,
            ClangProtocolOwnershipLogicRules,
        ),
    }
    for facade, mixins in expected_mixins.items():
        assert not {name for name in facade.__dict__ if name.startswith(facade_prefixes)}
        assert facade.__mro__[1:5] == mixins

    helper_owners = {
        RegexCandidateGenerator._function_params: RegexMemoryBoundsIntegerRules,
        GraphCandidateGenerator._lock_arg: GraphConcurrencySharedStateRules,
        ClangAstCfgCandidateGenerator._match_null_reset: ClangResourceLifecycleRules,
        ClangAstCfgCandidateGenerator._has_overflow_guard: ClangMemoryBoundsIntegerRules,
        ClangAstCfgCandidateGenerator._macro_guard_names: ClangConcurrencySharedStateRules,
        ClangAstCfgCandidateGenerator._is_path_check: ClangProtocolOwnershipLogicRules,
    }
    for helper, owner in helper_owners.items():
        assert helper.__qualname__.startswith(f"{owner.__name__}.")


def test_registered_detector_stages_are_owned_by_domain_modules() -> None:
    facades_and_phases = (
        (RegexCandidateGenerator, "regex", ("function",)),
        (ClangAstCfgCandidateGenerator, "clang_ast_cfg", ("function",)),
        (GraphCandidateGenerator, "graph", ("view", "batch")),
    )
    for facade, engine, phases in facades_and_phases:
        for phase in phases:
            for stage in detector_plan(engine, phase):  # type: ignore[arg-type]
                method = getattr(facade, stage.method_name)
                assert method.__module__.startswith("zscope.core.candidates.cpp_domains.")
                assert stage.method_name not in facade.__dict__


def test_legacy_facades_reexport_shared_models() -> None:
    from zscope.core.candidates.clang_ast_cfg import (
        ClangCfgLine as LegacyClangCfgLine,
        LockState as LegacyLockState,
        ResourceState as LegacyResourceState,
    )
    from zscope.core.candidates.graph import (
        FunctionView as LegacyFunctionView,
        GraphLine as LegacyGraphLine,
        LockOrderEdge as LegacyLockOrderEdge,
    )
    from zscope.core.candidates.regex import CodeLine as LegacyCodeLine

    assert LegacyCodeLine is CodeLine
    assert LegacyClangCfgLine is ClangCfgLine
    assert LegacyResourceState is ResourceState
    assert LegacyLockState is LockState
    assert LegacyGraphLine is GraphLine
    assert LegacyFunctionView is FunctionView
    assert LegacyLockOrderEdge is LockOrderEdge


def test_regex_facade_runs_registered_stages_in_legacy_order(monkeypatch) -> None:
    generator = RegexCandidateGenerator()
    called: list[str] = []
    plan = detector_plan("regex", "function")
    monkeypatch.setattr(
        generator,
        "_parse_lines",
        lambda _code: [CodeLine(number=1, raw="1 | int f(void);", text="int f(void);", index=0)],
    )
    for stage in plan:
        monkeypatch.setattr(
            generator,
            stage.method_name,
            lambda *_args, name=stage.method_name: called.append(name),
        )

    generator.generate_issues("f", "ignored", "src/f.c")

    assert called == [stage.method_name for stage in plan]


def test_clang_facade_preserves_resource_lock_common_pass_order(monkeypatch) -> None:
    generator = ClangAstCfgCandidateGenerator()
    called: list[str] = []
    plan = detector_plan("clang_ast_cfg", "function")
    monkeypatch.setattr(generator, "_parse_lines", lambda _code: [SimpleNamespace()])
    for stage in plan:
        monkeypatch.setattr(
            generator,
            stage.method_name,
            lambda *_args, name=stage.method_name: called.append(name),
        )

    generator.generate_issues("f", "ignored", "src/f.c")

    assert called == [
        "_run_resource_state_machines",
        "_run_typed_resource_lifetimes",
        "_run_retained_slot_teardown",
        "_run_object_protocol_paths",
        "_run_lock_state_machine",
        "_run_common_sast_rules",
    ]


def test_graph_facade_runs_view_then_batch_plans_without_reordering(monkeypatch) -> None:
    generator = GraphCandidateGenerator(object())
    called: list[tuple[str, str]] = []
    view_plan = detector_plan("graph", "view")
    batch_plan = detector_plan("graph", "batch")
    for stage in (*view_plan, *batch_plan):
        monkeypatch.setattr(
            generator,
            stage.method_name,
            lambda *args, name=stage.method_name: called.append(
                (name, str(getattr(args[0], "name", "batch")))
            ),
        )
    views = [
        FunctionView("first", "a.c", "void first(void)", (), ()),
        FunctionView("second", "b.c", "void second(void)", (), ()),
    ]

    generator.generate_for_views(views)

    assert called == [
        *((stage.method_name, "first") for stage in view_plan),
        *((stage.method_name, "second") for stage in view_plan),
        *((stage.method_name, "batch") for stage in batch_plan),
    ]


class _UnknownEffective:
    @staticmethod
    def state_for(_rule_id: str) -> None:
        return None


class _StrictUnknownPolicy:
    effective = _UnknownEffective()

    @staticmethod
    def is_enabled(_rule_id: str) -> bool:
        return False

    @staticmethod
    def descriptor(_rule_id: str) -> object:
        raise AssertionError("unknown descriptors are owned by the central strict gate")


def test_generator_does_not_silently_drop_unregistered_rule() -> None:
    code = """
1 | int demo(size_t payload_len) {
2 |     void *response = malloc(payload_len * 2);
3 |     return response != NULL;
4 | }
"""

    issues = RegexCandidateGenerator(rule_policy=_StrictUnknownPolicy()).generate_issues(
        "demo", code, "src/demo.c"
    )

    assert any(issue["rule"] == "inline_allocation_size_overflow" for issue in issues)
