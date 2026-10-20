"""Shadow demand cannot narrow execution, publish proof, or create a blind spot."""

from copy import deepcopy
from dataclasses import replace
import json

import pytest

from test_global_modeler import FakeCodeIndex, RecordingAgent
from test_incremental_semantic_modeling import modeler_for
from zscope.config.function_entry import FunctionEntry
from zscope.core.candidates.clang_ast_cfg import ClangAstCfgCandidateGenerator
from zscope.orchestration.semantic_demand import (
    HINT_KINDS,
    SemanticDemandHint,
    plan_semantic_demand,
    source_hash,
)
from zscope.orchestration.semantic_modeling import IncrementalSemanticModeling
from zscope.semantics.contracts import SymbolIdentity
from zscope.semantics.defaults import default_local_pattern_semantics
from zscope.semantics.security_map import (
    AuditOccurrence,
    AuditUnit,
    CoverageKey,
    FunctionSecurityRecord,
    SecuritySemanticMap,
)


def context(name="entry", code=None):
    return {
        "func_name": name,
        "file_path": f"src/{name}.c",
        "signature": f"int {name}(void)",
        "code": code or f"int {name}(void) {{ return 0; }}",
    }


def identity(ctx):
    return SymbolIdentity.from_value(
        {"name": ctx["func_name"], "file_path": ctx["file_path"], "signature": ctx["signature"]}
    )


def plan(ctx=None, **kwargs):
    ctx = ctx or context()
    key = identity(ctx).key
    return plan_semantic_demand(
        contexts={key: ctx},
        children={},
        components=[[key]],
        registry=default_local_pattern_semantics().contracts,
        spec="existing-spec",
        **kwargs,
    )


@pytest.mark.parametrize("kind", sorted(HINT_KINDS))
def test_typed_gap_without_candidate_selects_bound_symbol(kind):
    ctx = context()
    hint = SemanticDemandHint(identity(ctx), source_hash(ctx), kind, ("missing fact",))
    result = plan(ctx, hints=[hint])
    assert result["selected"] == [identity(ctx).key]
    assert result["rows"][0]["reasons"] == [kind]
    assert result["rows"][0]["safety_status"] == "unknown"


@pytest.mark.parametrize(
    "code,reason",
    [
        ("int entry(void) { return arbitrary_endpoint(); }", "opaque_interface"),
        ("int entry(void) { return (*handler)(); }", "unknown_callback"),
        ("int entry(void) { int *p = source(); p++; return *p; }", "unknown_alias"),
        ("int entry(void) { while (1) {} return 0; }", "source_coverage_gap"),
    ],
)
def test_first_scan_source_gaps_do_not_require_map_or_candidates(code, reason):
    result = plan(context(code=code))
    assert reason in result["rows"][0]["reasons"]
    assert result["selected"]


@pytest.mark.parametrize(
    "extra",
    [
        {"source_truncated": True},
        {"referenced_types_truncation": {"truncated": True}},
        {"project_callees_truncation": {"truncated": True}},
    ],
)
def test_truncated_context_selects_and_stays_unknown(extra):
    result = plan({**context(), **extra})
    assert "coverage_gap" in result["rows"][0]["reasons"]
    assert "input_truncated" in result["rows"][0]["unknowns"]


def test_graph_truncation_selects_known_frontier_and_unavailable_remains_visible():
    result = plan(graph_truncated=True, unavailable=["unresolved-symbol"])
    assert result["selected"]
    assert "unresolved-symbol" in result["unknown"]
    assert result["unbound"] == [
        {"symbol": "unresolved-symbol", "reason": "model_input_unavailable"}
    ]


def test_stale_and_same_name_different_file_hints_do_not_rebind():
    ctx = context()
    other = replace(identity(ctx), file_path="src/other.c")
    result = plan(
        ctx,
        hints=[
            SemanticDemandHint(identity(ctx), "0" * 64, "document_conflict"),
            SemanticDemandHint(other, source_hash(ctx), "unknown_alias"),
        ],
    )
    assert not result["selected"]
    assert len(result["unbound"]) == 2
    assert result["deferred"] == [identity(ctx).key]
    assert result["rows"][0]["safety_status"] == "unknown"


def test_scc_and_dependency_closure_preserve_all_peers_without_mutating_inputs():
    values = [context(name) for name in ("a", "b", "c", "d")]
    contexts = {identity(ctx).key: ctx for ctx in values}
    a, b, c, d = contexts
    before = deepcopy(contexts)
    result = plan_semantic_demand(
        contexts=contexts,
        children={a: {b}, b: {a, c}},
        components=[[a, b], [c], [d]],
        registry=default_local_pattern_semantics().contracts,
        spec="v1",
        hints=[
            SemanticDemandHint(identity(values[0]), source_hash(values[0]), "document_conflict")
        ],
    )
    assert result["selected"] == sorted([a, b, c])
    assert result["deferred"] == [d]
    assert contexts == before
    assert {row["safety_status"] for row in result["rows"]} == {"unknown"}
    assert not result["changes_execution"]


def coverage_map(ctx, *, build=None, migration="current"):
    record = FunctionSecurityRecord(
        function_uid="function-uid",
        index_name="entry@src/entry.c:1-1",
        function_name="entry",
        file_path=ctx["file_path"],
        start_line=1,
        end_line=1,
        signature=ctx["signature"],
        code_hash=source_hash(ctx),
        entry_identities=("entry1", "entry2"),
        entry_paths=(("entry1", "entry"), ("entry2", "entry")),
        callees=(),
        unresolved_callees=(),
        events=(),
        backend_coverage={},
    )
    unit = AuditUnit(
        unit_id="unit",
        unit_kind="resource_protocol",
        fingerprint="fingerprint",
        risk_score=20,
        risk_reasons=(),
        root_entries=("entry1", "entry2"),
        member_functions=("function-uid",),
        event_refs=(),
        claim_refs=(),
        unknown_refs=("unknown",),
        skill_families=("resource_lifecycle",),
        backend_coverage={},
        candidate_desert=True,
        coverage_keys=tuple(
            CoverageKey("resource_lifecycle", "function-uid", obj, site, variant, "scope")
            for obj, site, variant in [
                ("p", "line1", build),
                ("q", "line2", build),
                ("p", "line1", "b" * 64),
            ]
        ),
        occurrences=(
            AuditOccurrence("entry1", ("entry1", "entry"), ("ev1",)),
            AuditOccurrence("entry2", ("entry2", "entry"), ("ev2",)),
        ),
        migration_status=migration,
    )
    return SecuritySemanticMap("project", "revision", "profile", (record,), (), (), (unit,), {}, {})


def test_d03_objects_variants_unknown_build_and_entry_occurrences_are_not_collapsed():
    result = plan(security_map=coverage_map(context()))
    rows = result["rows"][0]["coverage"]
    assert len(rows) == len({row["identity"] for row in rows}) == 3
    assert all(len(row["occurrences"]) == 2 for row in rows)
    assert all(row["current_project_revision_build"] == "unverified" for row in rows)
    assert "build_context_unknown" in result["rows"][0]["unknowns"]
    assert "audit_coverage_gap" in result["rows"][0]["reasons"]


@pytest.mark.parametrize("stale", [True, False])
def test_old_coverage_never_binds_or_marks_current(stale):
    ctx = context()
    value = coverage_map(ctx, migration="current" if stale else "legacy_unverifiable")
    if stale:
        value = replace(value, functions=(replace(value.functions[0], code_hash="old"),))
    result = plan(ctx, security_map=value)
    assert not result["selected"]
    assert len(result["unbound"]) == 3
    assert not result["rows"][0]["coverage"]


def test_off_never_invokes_planner_or_reads_hints_and_retains_hot_cache(tmp_path, monkeypatch):
    import zscope.orchestration.semantic_demand as module

    calls = []
    modeler = modeler_for(tmp_path, FakeCodeIndex(), calls)
    modeler.demand_hints = object()
    monkeypatch.setattr(module, "plan_semantic_demand", lambda **kwargs: pytest.fail("off planner"))
    before = IncrementalSemanticModeling(modeler).spec
    modeler.run([FunctionEntry("entry")])
    calls.clear()
    assert modeler.run([FunctionEntry("entry")]).cache_hit_functions == 4
    assert not calls and not modeler.result.demand_plan
    assert IncrementalSemanticModeling(modeler).spec == before
    audit = json.loads(
        (modeler.snapshot_store.snapshot_dir / ".semantic-modeling/publication.json").read_text()
    )
    assert "demand_plan" not in audit


def test_shadow_fixed_replay_has_identical_calls_snapshots_contracts_and_hot_reuse(tmp_path):
    results = []
    for mode in ("off", "shadow"):
        calls = []
        modeler = modeler_for(tmp_path / mode, FakeCodeIndex(), calls)
        modeler.config.analysis.semantic_model_demand_mode = mode
        cold = modeler.run([FunctionEntry("entry")])
        snapshot = deepcopy(modeler.result.snapshots)
        cold_calls = sorted(calls)
        calls.clear()
        hot = modeler.run([FunctionEntry("entry")])
        assert not calls and hot.cache_hit_functions == 4
        results.append(
            (
                cold_calls,
                snapshot,
                modeler.result.contract_version,
                modeler.result.overlay,
                cold.modeled_functions,
                cold.total_context_tokens,
            )
        )
        if mode == "shadow":
            assert modeler.result.demand_plan["passes"][0]["selected"]
            assert modeler.result.demand_plan["actual_execution"]["cache_hit_functions"] == 4
            assert not modeler.result.demand_plan["changes_execution"]
    assert results[0] == results[1]


def test_shadow_toggle_does_not_invalidate_existing_model_identity(tmp_path):
    calls = []
    modeler = modeler_for(tmp_path, FakeCodeIndex(), calls)
    spec = IncrementalSemanticModeling(modeler).spec
    modeler.run([FunctionEntry("entry")])
    calls.clear()
    modeler.config.analysis.semantic_model_demand_mode = "shadow"
    assert IncrementalSemanticModeling(modeler).spec == spec
    modeler.run([FunctionEntry("entry")])
    assert not calls
    assert modeler.result.demand_plan


def test_shadow_deferred_function_still_executes_and_is_not_labeled_safe(tmp_path):
    calls = []
    index = FakeCodeIndex()
    index.impls = {"entry": index._impl("entry", [])}
    index.impls["entry"]["code"] = "int entry(void) { return 0; }"
    modeler = modeler_for(tmp_path, index, calls)
    modeler.config.analysis.semantic_model_demand_mode = "shadow"
    stats = modeler.run([FunctionEntry("entry")])
    assert stats.modeled_functions == 1 and modeler.result.snapshots
    row = modeler.result.demand_plan["passes"][0]["rows"][0]
    assert row["decision"] == "deferred" and row["safety_status"] == "unknown"
    assert row["execution"] == "unchanged_full_schedule"


def test_unresolved_entry_is_audited_as_unknown_without_implementation(tmp_path):
    modeler = modeler_for(tmp_path, FakeCodeIndex(), [])
    modeler.config.analysis.semantic_model_demand_mode = "shadow"
    stats = modeler.run([FunctionEntry("missing")])
    assert not stats.stage_complete
    plan = modeler.result.demand_plan["passes"][0]
    assert not plan["rows"]
    assert any(json.loads(key)["name"] == "missing" for key in plan["unknown"])
    assert plan["unbound"][0]["reason"] == "model_input_unavailable"


def test_advisory_failure_does_not_change_real_model_calls_or_stage(tmp_path, monkeypatch):
    import zscope.orchestration.semantic_demand as module

    calls = []
    modeler = modeler_for(tmp_path, FakeCodeIndex(), calls)
    modeler.config.analysis.semantic_model_demand_mode = "shadow"

    def fail(**kwargs):
        raise ValueError("invalid advisory input")

    monkeypatch.setattr(module, "plan_semantic_demand", fail)
    assert modeler.run([FunctionEntry("entry")]).stage_complete
    assert sorted(calls) == ["entry", "leaf", "mid", "sibling"]
    assert modeler.result.demand_plan["passes"][0]["status"] == "unavailable"


def test_shadow_preparation_failure_does_not_interrupt_full_schedule(tmp_path, monkeypatch):
    calls = []
    modeler = modeler_for(tmp_path, FakeCodeIndex(), calls)
    modeler.config.analysis.semantic_model_demand_mode = "shadow"
    original = modeler._strongly_connected_components
    invocations = []

    def fail_once(graph):
        invocations.append(1)
        if len(invocations) == 1:
            raise ValueError("advisory preparation failed")
        return original(graph)

    monkeypatch.setattr(modeler, "_strongly_connected_components", fail_once)
    assert modeler.run([FunctionEntry("entry")]).stage_complete
    assert sorted(calls) == ["entry", "leaf", "mid", "sibling"]
    assert modeler.result.demand_plan["passes"][0]["status"] == "unavailable"


def test_real_publication_barrier_exposes_candidate_missing_before_modeling(tmp_path):
    calls = []
    index = FakeCodeIndex()
    index.impls = {"entry": index._impl("entry", ["alpha"]), "alpha": index._impl("alpha", [])}
    source = "void entry(void) {\nvoid *p = alpha(8);\nif (!p) return;\nuse(p);\nreturn;\n}"
    index.impls["entry"].update(code=source, signature="void entry(void)")
    index.impls["alpha"].update(
        code="void *alpha(size_t n) { return malloc(n); }", signature="void *alpha(size_t n)"
    )
    baseline = ClangAstCfgCandidateGenerator(default_local_pattern_semantics())
    assert not baseline.generate_issues("entry", source, "src/entry.c")
    modeler = modeler_for(tmp_path, index, calls)
    modeler.config.analysis.semantic_model_demand_mode = "shadow"
    modeler.run([FunctionEntry("entry")])
    result = modeler.result
    assert result.local_semantics.contracts.find("alpha")
    assert modeler.user_config.list_external_functions()
    engine = ClangAstCfgCandidateGenerator(result.local_semantics, result.overlay)
    issues = engine.generate_issues("entry", source, "src/entry.c")
    assert any(issue["defect_class"] == "memory_leak" for issue in issues)
    planned = result.demand_plan["passes"][0]
    assert any(json.loads(key)["name"] == "entry" for key in planned["selected"])
    assert any(json.loads(key)["name"] == "alpha" for key in planned["selected"])
    assert result.overlay["contract_version"] == result.contract_version


def test_shadow_callee_change_still_invalidates_parent(tmp_path):
    calls = []
    state = {"owns": False}

    class Agent(RecordingAgent):
        def run(self, context):
            response = super().run(context)
            if context["func_name"] == "leaf" and state["owns"]:
                response.data["return_values"]["ownership"] = "caller_owned"
            return response

    index = FakeCodeIndex()
    modeler = modeler_for(tmp_path, index, calls, lambda: Agent(calls))
    modeler.config.analysis.semantic_model_demand_mode = "shadow"
    modeler.run([FunctionEntry("entry")])
    calls.clear()
    state["owns"] = True
    index.impls["leaf"]["code"] += "4 | return 1;\n"
    assert modeler.run([FunctionEntry("entry")]).propagated_functions == 1
    assert calls == ["leaf", "mid"]


def test_shadow_recursive_failure_does_not_cache_safe_or_publish_partial_scc(tmp_path):
    calls = []
    index = FakeCodeIndex()
    index.impls = {"entry": index._impl("entry", ["entry"])}

    class Agent(RecordingAgent):
        def run(self, context):
            response = super().run(context)
            response.data["return_values"]["ownership"] = "owned" if len(calls) % 2 else "borrowed"
            return response

    modeler = modeler_for(tmp_path, index, calls, lambda: Agent(calls))
    modeler.config.analysis.semantic_model_demand_mode = "shadow"
    modeler.run([FunctionEntry("entry")])
    assert len(calls) == 3 and not modeler.result.snapshots
    assert modeler.result.partial
    assert all(
        row["safety_status"] == "unknown" for row in modeler.result.demand_plan["passes"][0]["rows"]
    )
    modeler.run([FunctionEntry("entry")])
    assert len(calls) == 6


@pytest.mark.parametrize("demand_mode", ["off", "shadow"])
def test_k01_off_retains_original_spec_digest_and_does_not_invoke_schema_helper(
    tmp_path, monkeypatch, demand_mode
):
    from pathlib import Path
    import zscope.orchestration.snapshot_observations as module
    from zscope.agents.semantic_modeler.schema import DEFAULT_FUNCTION_SNAPSHOT_SCHEMA
    from zscope.semantics.contracts import CONTRACT_COMPILER_VERSION, digest
    import zscope.orchestration.semantic_modeling as modeling

    modeler = modeler_for(tmp_path, FakeCodeIndex(), [])
    modeler.config.analysis.semantic_model_demand_mode = demand_mode
    monkeypatch.setattr(
        module, "observation_project_inputs", lambda *args, **kwargs: pytest.fail("off inventory")
    )
    monkeypatch.setattr(
        module, "conditional_snapshot_schema", lambda *args: pytest.fail("off schema")
    )
    monkeypatch.setattr(
        module, "bind_snapshot_observation", lambda *args, **kwargs: pytest.fail("off bind")
    )
    expected = digest(
        {
            "version": 2,
            "contract_compiler": CONTRACT_COMPILER_VERSION,
            "program_facts": "zscope.program-events.v5",
            "schema": DEFAULT_FUNCTION_SNAPSHOT_SCHEMA,
            "prompt": (
                Path(modeling.__file__).parents[1] / "agents/semantic_modeler/AGENT.md"
            ).read_text(),
            "model": modeler.config.llms["default"].models,
            "profile": "default",
            "builtins": default_local_pattern_semantics().contracts.version,
        }
    )
    assert IncrementalSemanticModeling(modeler).spec == expected
    modeler.run([FunctionEntry("entry")])
    assert not modeler.result.observation_bindings


def test_k01_shadow_schema_and_current_publication_binding_then_source_revocation(tmp_path):
    from zscope.agents.semantic_modeler.schema import DEFAULT_FUNCTION_SNAPSHOT_SCHEMA
    from zscope.orchestration.snapshot_observations import check_observation_binding

    calls, schemas = [], []
    index = FakeCodeIndex()
    for impl in index.impls.values():
        path = tmp_path / impl["file"]
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            "\n".join(line.split(" | ", 1)[1] for line in impl["code"].splitlines()) + "\n"
        )
    original = deepcopy(DEFAULT_FUNCTION_SNAPSHOT_SCHEMA)

    class Agent(RecordingAgent):
        def run(self, context):
            schemas.append(deepcopy(context["schema"]))
            response = super().run(context)
            response.data["conditional_observations"] = []
            return response

    modeler = modeler_for(tmp_path, index, calls, lambda: Agent(calls))
    old = IncrementalSemanticModeling(modeler).spec
    modeler.config.analysis.semantic_snapshot_candidate_mode = "shadow"
    assert IncrementalSemanticModeling(modeler).spec != old
    modeler.run([FunctionEntry("entry")])
    assert all("conditional_observations" in value["required"] for value in schemas)
    assert DEFAULT_FUNCTION_SNAPSHOT_SCHEMA == original
    result = modeler.result
    assert len(result.observation_bindings) == 4
    for key, binding in result.observation_bindings.items():
        assert (
            check_observation_binding(
                binding,
                result.snapshots[key],
                symbol=key,
                contract_version=result.contract_version,
                project_root=tmp_path,
            )
            == "current"
        )
    calls.clear()
    modeler.run([FunctionEntry("entry")])
    assert not calls and not modeler.result.observation_bindings
    key = next(key for key in result.snapshots if json.loads(key)["name"] == "leaf")
    (tmp_path / "src/leaf.c").write_text("int changed(void) { return 1; }\n")
    assert (
        check_observation_binding(
            result.observation_bindings[key],
            result.snapshots[key],
            symbol=key,
            contract_version=result.contract_version,
            project_root=tmp_path,
        )
        == "snapshot_source_changed"
    )


def test_k01_attached_custom_schema_is_copied_after_contract_hook(tmp_path):
    schema = {
        "type": "object",
        "properties": {"custom": {"type": "string"}},
        "required": ["custom"],
    }
    calls, schemas = [], []

    class Agent(RecordingAgent):
        def run(self, context):
            schemas.append(context["schema"])
            response = super().run(context)
            response.data["conditional_observations"] = []
            return response

    modeler = modeler_for(tmp_path, FakeCodeIndex(), calls, lambda: Agent(calls))
    modeler.attach_contract = lambda ctx, name: ctx.update(schema=schema)
    modeler.config.analysis.semantic_snapshot_candidate_mode = "shadow"
    modeler.run([FunctionEntry("entry")])
    assert schemas and all(
        value["required"] == ["custom", "conditional_observations"] for value in schemas
    )
    assert (
        schema["required"] == ["custom"] and "conditional_observations" not in schema["properties"]
    )
    assert not modeler.result.observation_bindings
    calls.clear()
    schema["properties"]["custom"]["maxLength"] = 7
    modeler.run([FunctionEntry("entry")])
    assert sorted(calls) == ["entry", "leaf", "mid", "sibling"]
    assert not modeler.result.observation_bindings


@pytest.mark.parametrize(
    "mutation", ["model", "header", "compile_database", "compile_config", "manual_contract"]
)
def test_k01_live_binding_rechecks_non_source_inputs(tmp_path, mutation):
    from zscope.orchestration.snapshot_observations import check_observation_binding

    calls = []
    index = FakeCodeIndex()
    index.impls = {"entry": index._impl("entry", [])}
    path = tmp_path / "src/entry.c"
    path.parent.mkdir(parents=True)
    path.write_text(
        "\n".join(line.split(" | ", 1)[1] for line in index.impls["entry"]["code"].splitlines())
        + "\n"
    )
    header = tmp_path / "limits.h"
    header.write_text("#define LIMIT 1\n")
    compile_database = tmp_path / "compile_commands.json"

    class Agent(RecordingAgent):
        def run(self, context):
            response = super().run(context)
            response.data["conditional_observations"] = []
            return response

    modeler = modeler_for(tmp_path, index, calls, lambda: Agent(calls))
    modeler.config.analysis.semantic_snapshot_candidate_mode = "shadow"
    modeler.run([FunctionEntry("entry")])
    result = modeler.result
    assert len(result.observation_bindings) == 1
    key, binding = next(iter(result.observation_bindings.items()))
    if mutation == "model":
        modeler.config.llms["default"].models = ["changed"]
    elif mutation == "header":
        header.write_text("#define LIMIT 2\n")
    elif mutation == "compile_database":
        compile_database.write_text(
            '[{"directory":"/elsewhere","file":"entry.c","arguments":["clang","-DOTHER"]}]'
        )
    elif mutation == "compile_config":
        modeler.config.project.compile_commands_path = tmp_path / "custom-compiler-input.json"
    else:
        modeler.user_config.workbook.write_rows(
            {"resource": [{"symbol_name": "new_api", "kind": "allocator", "source": "user"}]}
        )
    assert (
        check_observation_binding(
            binding,
            result.snapshots[key],
            symbol=key,
            contract_version=result.contract_version,
            project_root=tmp_path,
        )
        != "current"
    )
