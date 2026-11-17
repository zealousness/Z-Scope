"""Source-bound conditional observations stay shadow and carry no proof."""

from copy import deepcopy
from dataclasses import replace
import json
from types import SimpleNamespace

import pytest

from zscope.agents.semantic_modeler.schema import DEFAULT_FUNCTION_SNAPSHOT_SCHEMA
from zscope.orchestration.candidates import CandidateLedger, CandidateRegistrar
from zscope.orchestration.semantic_modeling import SessionSemanticResult
from zscope.orchestration.snapshot_candidates import register_conditional_snapshot_candidates
from zscope.orchestration.snapshot_observations import (
    OBSERVATION_SCHEMA_VERSION,
    bind_snapshot_observation,
    check_observation_binding,
    conditional_snapshot_schema,
    observation_project_inputs,
    observation_qualification,
)
from zscope.semantics.contracts import SymbolIdentity, digest
from test_investigation_evidence import case  # noqa: F401; shared real tool fixture

SOURCE = "int demo(void) {\n  void *p = alloc();\n  return -1;\n}\n"


def point(**updates):
    value = {
        "schema_version": OBSERVATION_SCHEMA_VERSION,
        "category": "resource_lifecycle",
        "lines": "3",
        "source_anchor": "  return -1;",
        "description": "Check p on error exit",
        "object": "p",
        "source": "",
        "sink": "",
        "violated_property": "error_path_cleanup_missing",
        "conditions": {"op": "true"},
        "missing_facts": ["cleanup_on_error_path"],
        "ownership": "unknown",
        "exit_kind": "error",
    }
    value.update(updates)
    return value


def setup_result(tmp_path, points=None, source=SOURCE):
    (tmp_path / "src").mkdir(exist_ok=True)
    (tmp_path / "src/demo.c").write_text(source)
    symbol = SymbolIdentity.from_value(
        {"name": "demo", "file_path": "src/demo.c", "signature": "int demo(void)"}
    ).key
    snapshot = {
        "func_name": "demo",
        "file_path": "src/demo.c",
        "signature": "int demo(void)",
        "start_line": 1,
        "end_line": len(source.splitlines()),
        "code": source,
        "conditional_observations": [point()] if points is None else points,
        "suspicious_points": [{"category": "other", "lines": "3", "description": "vague"}],
    }
    current = {"model": "fake", "schema": "v1", "build": "source_only", "contract": "v1"}

    def inputs():
        inventory = observation_project_inputs(tmp_path)
        return digest({"inventory": inventory, "current": current}) if inventory else None

    result = SessionSemanticResult(
        SimpleNamespace(stage_complete=True),
        snapshots={symbol: snapshot},
        contract_version="v1",
        entry_paths={symbol: [["demo"]]},
        symbol_paths={symbol: [[symbol]]},
    )

    def bind():
        binding = bind_snapshot_observation(
            snapshot,
            symbol=symbol,
            modeling_spec="spec1",
            source_context=snapshot,
            contract_version=result.contract_version,
            project_root=tmp_path,
            current_inputs=inputs,
            expected_inputs=inputs(),
        )
        assert binding is not None
        result.observation_bindings[symbol] = binding
        return binding

    bind()
    ledger = CandidateLedger(project_id="p", project_root=str(tmp_path), revision="r")
    return result, CandidateRegistrar(ledger), symbol, current, bind


def register(result, registrar, **kwargs):
    return register_conditional_snapshot_candidates(result, registrar, mode="shadow", **kwargs)


def reasons(result):
    return {
        item["reason"] for item in result.suspicious_metrics["conditional_observations"]["rejected"]
    }


def test_off_does_not_touch_inputs_and_default_schema_is_unchanged():
    class Forbidden:
        def __getattr__(self, key):
            pytest.fail(f"off accessed {key}")

    assert register_conditional_snapshot_candidates(Forbidden(), Forbidden()) == []
    before = deepcopy(DEFAULT_FUNCTION_SNAPSHOT_SCHEMA)
    schema = conditional_snapshot_schema(DEFAULT_FUNCTION_SNAPSHOT_SCHEMA)
    assert schema == before and schema is not DEFAULT_FUNCTION_SNAPSHOT_SCHEMA
    schema["required"].append("local")
    shadow = conditional_snapshot_schema(DEFAULT_FUNCTION_SNAPSHOT_SCHEMA, "shadow")
    assert "conditional_observations" in shadow["required"]
    assert DEFAULT_FUNCTION_SNAPSHOT_SCHEMA == before
    with pytest.raises(ValueError):
        conditional_snapshot_schema(before, "active")


def test_shadow_registration_retains_hypothesis_and_freeze(tmp_path):
    result, registrar, symbol, _, _ = setup_result(tmp_path)
    issues = register(result, registrar)
    assert len(issues) == 1
    issue = issues[0]
    assert issue["discovery_status"] == "hypothesis"
    assert issue["candidate_disposition"] == "needs_review"
    assert issue["rollout_visibility"] == "shadow"
    assert issue["candidate_promotion_eligible"] is False
    assert issue["evidence_pack"]["condition_proven"] is False
    assert issue["evidence_pack"]["proof_authority"] is False
    assert issue["attribution"]["discovered_by"] == ["semantic_modeling"]
    assert issue["evidence_pack"]["snapshot_symbol"] == symbol
    assert result.suspicious_metrics["conditional_observations"]["background_only"] == 1
    register(result, registrar)
    assert result.suspicious_metrics["conditional_observations"]["new_validation_groups"] == 0
    assert (
        len([r for r in registrar.ledger.records() if r.record_role == "validation_obligation"])
        == 1
    )
    registrar.ledger.freeze()
    with pytest.raises(RuntimeError, match="frozen"):
        register(result, registrar)


@pytest.mark.parametrize(
    "predicate,expected",
    [
        ({"op": "true"}, True),
        ({"op": "false"}, False),
        ({"op": "unknown"}, False),
        ({"op": "not", "item": {"op": "false"}}, True),
    ],
)
def test_condition_applicability_does_not_prove_feasibility(tmp_path, predicate, expected):
    result, registrar, _, _, _ = setup_result(tmp_path, [point(conditions=predicate)])
    issues = register(result, registrar)
    assert bool(issues) is expected
    if issues:
        assert issues[0]["evidence_pack"]["condition_proven"] is False


@pytest.mark.parametrize(
    "change,reason",
    [
        ({"missing_facts": []}, "invalid_observation_schema"),
        ({"effects_trusted": True}, "invalid_observation_schema"),
        ({"conditions": {"op": "true", "proof": True}}, "condition_unresolved"),
        ({"conditions": {"op": []}}, "condition_unresolved"),
        (
            {"conditions": {"op": "not", "item": {"op": "true", "proof": True}}},
            "condition_unresolved",
        ),
        ({"lines": "return -1"}, "observation_location_unresolved"),
        ({"lines": "2"}, "observation_anchor_mismatch"),
        ({"source_anchor": "free(p);"}, "observation_anchor_mismatch"),
        ({"object": "missing_object"}, "observation_object_unresolved"),
        ({"object": "", "source": "p", "sink": ""}, "observation_object_unresolved"),
    ],
)
def test_invalid_observation_is_explained_and_uncovered(tmp_path, change, reason):
    result, registrar, symbol, _, _ = setup_result(tmp_path, [point(**change)])
    assert register(result, registrar) == []
    assert reason in reasons(result)
    assert symbol in result.suspicious_metrics["conditional_observations"]["uncovered_symbols"]


def test_recursive_condition_budget_and_nonfinite_number(tmp_path):
    predicate = {"op": "true"}
    for _ in range(12):
        predicate = {"op": "not", "item": predicate}
    result, registrar, _, _, _ = setup_result(tmp_path, [point(conditions=predicate)])
    assert register(result, registrar) == []
    assert "condition_unresolved" in reasons(result)
    nonfinite = {
        "op": "compare",
        "left": {"kind": "literal", "value": float("inf")},
        "right": {"kind": "literal", "value": 0},
        "operator": ">",
    }
    result, registrar, _, _, _ = setup_result(tmp_path, [point(conditions=nonfinite)])
    assert register(result, registrar) == []
    assert "invalid_observation_schema" in reasons(result)


def test_symbolic_condition_is_kept_unknown_for_validator(tmp_path):
    condition = {
        "op": "compare",
        "left": {"kind": "call_result", "name": "p"},
        "right": {"kind": "literal", "value": None},
        "operator": "!=",
    }
    result, registrar, _, _, _ = setup_result(tmp_path, [point(conditions=condition)])
    issue = register(result, registrar)[0]
    assert issue["evidence_pack"]["condition_evaluation"] == "unknown"
    assert issue["evidence_pack"]["missing_facts"] == ["cleanup_on_error_path"]
    # A ruleless shadow observation has no governed obligation profile, so it
    # must not invent canonical fact kinds from its category. Its producer's
    # actual gaps and unproven condition must survive registration independently.
    assert issue["obligation_profile_status"] == "unsupported"
    assert issue["decision_fact_coverage"] == "partial"
    assert issue["candidate_promotion_eligible"] is False
    assert issue["candidate_disposition"] == "needs_review"
    evidence = registrar.ledger.records()[0].ticket.evidence
    assert evidence["conditions"] == condition
    assert evidence["condition_evaluation"] == "unknown"
    assert evidence["condition_proven"] is False
    assert evidence["proof_authority"] is False
    assert evidence["missing_facts"] == ["cleanup_on_error_path"]


@pytest.mark.parametrize(
    "argument",
    [
        "-I/opt/external",
        "@/opt/flags.rsp",
        "--sysroot=/opt/toolchain",
        "-include/opt/pre.h",
        "-imacros/opt/pre.h",
    ],
)
def test_inventory_rejects_unverifiable_build_search_scope(tmp_path, argument):
    (tmp_path / "x.c").write_text("int x;\n")
    (tmp_path / "compile_commands.json").write_text(
        json.dumps(
            [
                {
                    "file": "x.c",
                    "directory": str(tmp_path),
                    "arguments": ["clang", argument, "-c", "x.c"],
                }
            ]
        )
    )
    assert observation_project_inputs(tmp_path) is None


def test_even_empty_compile_database_needs_an_independent_tu_receipt(tmp_path):
    (tmp_path / "x.c").write_text("int x;\n")
    (tmp_path / "compile_commands.json").write_text("[]\n")
    assert observation_project_inputs(tmp_path) is None


def test_java_classpath_is_not_claimed_current_from_source_only_inventory(tmp_path):
    (tmp_path / "Demo.java").write_text("class Demo {}\n")
    assert observation_project_inputs(tmp_path) is None


def test_implicit_compiler_environment_needs_a_verified_receipt(tmp_path, monkeypatch):
    (tmp_path / "x.c").write_text("int x;\n")
    monkeypatch.setenv("CPATH", "/opt/headers")
    assert observation_project_inputs(tmp_path) is None


def test_returned_ownership_stays_background_but_error_exit_is_observation(tmp_path):
    source = SOURCE.replace("return -1;", "return p;")
    observation = point(
        source_anchor="return p;",
        violated_property="resource_not_released",
        ownership="returned_to_caller",
        exit_kind="return",
    )
    result, registrar, _, _, _ = setup_result(tmp_path, [observation], source)
    assert register(result, registrar) == []
    assert "return_ownership_requires_caller_scope" in reasons(result)
    result, registrar, _, _, _ = setup_result(tmp_path)
    assert len(register(result, registrar)) == 1


@pytest.mark.parametrize("change", ["model", "schema", "build", "contract"])
def test_old_live_result_is_revoked_when_non_source_inputs_change(tmp_path, change):
    result, registrar, _, current, _ = setup_result(tmp_path)
    current[change] = "changed"
    assert register(result, registrar) == []
    assert "snapshot_inputs_changed" in reasons(result)


@pytest.mark.parametrize(
    "path,content", [("src/helper.h", "#define FLAG 1\n"), ("compile_commands.json", "[]\n")]
)
def test_new_header_or_build_input_revokes_old_live_result(tmp_path, path, content):
    result, registrar, _, _, _ = setup_result(tmp_path)
    (tmp_path / path).write_text(content)
    assert register(result, registrar) == []
    assert reasons(result) & {"snapshot_inputs_changed", "snapshot_inputs_unverifiable"}


def test_changed_existing_header_revokes_without_changing_main_source(tmp_path):
    (tmp_path / "src").mkdir()
    header = tmp_path / "src/helper.h"
    header.write_text("#define FLAG 1\n")
    result, registrar, _, _, _ = setup_result(tmp_path, source='#include "helper.h"\n' + SOURCE)
    header.write_text("#define FLAG 0\n")
    assert register(result, registrar) == []
    assert "snapshot_inputs_changed" in reasons(result)


@pytest.mark.parametrize(
    "action,reason",
    [
        ("change", "snapshot_source_changed"),
        ("delete", "snapshot_source_unavailable"),
        ("json", "snapshot_binding_unavailable"),
        ("clone", "snapshot_binding_unavailable"),
        ("point", "snapshot_binding_changed"),
        ("missing", "snapshot_binding_unavailable"),
    ],
)
def test_stale_or_unissued_binding_cannot_register(tmp_path, action, reason):
    result, registrar, symbol, _, _ = setup_result(tmp_path)
    if action == "change":
        (tmp_path / "src/demo.c").write_text(SOURCE + "// changed\n")
    elif action == "delete":
        (tmp_path / "src/demo.c").unlink()
    elif action == "json":
        result.observation_bindings[symbol] = {"symbol": symbol, "proof": True}
    elif action == "clone":
        result.observation_bindings[symbol] = replace(result.observation_bindings[symbol])
    elif action == "missing":
        result.observation_bindings.clear()
    else:
        result.snapshots[symbol]["conditional_observations"][0]["description"] = "changed"
    assert register(result, registrar) == []
    assert reason in reasons(result)


@pytest.mark.parametrize(
    "action",
    ["missing", "wrong_overload", "wrong_file", "entry_filter", "signature_filter", "unaligned"],
)
def test_program_entry_path_must_match_full_symbol(tmp_path, action):
    result, registrar, symbol, _, _ = setup_result(tmp_path)
    kwargs = {}
    if action == "missing":
        result.entry_paths.clear()
    elif action in {"wrong_overload", "wrong_file"}:
        identity = json.loads(symbol)
        identity["signature" if action == "wrong_overload" else "file_path"] = (
            "int demo(int x)" if action == "wrong_overload" else "elsewhere.c"
        )
        result.symbol_paths[symbol] = [[SymbolIdentity.from_value(identity).key]]
    elif action == "entry_filter":
        kwargs["entry"] = "elsewhere"
    elif action == "signature_filter":
        kwargs["entry_signature"] = "int demo(int x)"
    else:
        result.entry_paths[symbol] = [["caller", "demo"]]
    assert register(result, registrar, **kwargs) == []
    assert "entry_path_unresolved" in reasons(result)


def test_old_vague_points_are_background_only(tmp_path):
    result, registrar, _, _, _ = setup_result(tmp_path, [])
    assert register(result, registrar) == []
    metrics = result.suspicious_metrics["conditional_observations"]
    assert metrics["background_only"] == 1 and metrics["total"] == 0


def test_project_inventory_rejects_external_missing_symlink_and_partial(tmp_path, monkeypatch):
    from zscope.tools.source_access import ProjectSourceAccess

    (tmp_path / "source.c").write_text("#include <external.h>\nint x;\n")
    assert observation_project_inputs(tmp_path) is None
    (tmp_path / "external.h").write_text("#define X 1\n")
    assert observation_project_inputs(tmp_path)
    assert (
        observation_project_inputs(tmp_path, required_paths=[tmp_path.parent / "outside.h"]) is None
    )
    (tmp_path / "alias.h").symlink_to(tmp_path / "external.h")
    assert observation_project_inputs(tmp_path) is None
    (tmp_path / "alias.h").unlink()
    original = ProjectSourceAccess._scan

    def partial(self, *args):
        view = original(self, *args)
        view["missing"].add("time_budget")
        return view

    monkeypatch.setattr(ProjectSourceAccess, "_scan", partial)
    assert observation_project_inputs(tmp_path) is None


def test_binding_requires_pre_model_guard_and_exact_source_symbol(tmp_path):
    result, _, symbol, _, _ = setup_result(tmp_path)
    snapshot = result.snapshots[symbol]
    assert (
        bind_snapshot_observation(
            snapshot,
            symbol=symbol,
            modeling_spec="s",
            source_context=snapshot,
            contract_version="v1",
            project_root=tmp_path,
        )
        is None
    )
    assert (
        bind_snapshot_observation(
            snapshot,
            symbol=symbol,
            modeling_spec="s",
            source_context=snapshot,
            contract_version="v1",
            project_root=tmp_path,
            current_inputs=lambda: "after",
            expected_inputs="before",
        )
        is None
    )


def test_final_registration_rechecks_input_guard(tmp_path, monkeypatch):
    import zscope.orchestration.snapshot_observations as module

    result, registrar, _, current, _ = setup_result(tmp_path)
    original = module.observation_qualification

    def change_after_qualification(*args):
        answer = original(*args)
        current["build"] = "changed"
        return answer

    monkeypatch.setattr(module, "observation_qualification", change_after_qualification)
    assert register(result, registrar) == []
    assert "snapshot_inputs_changed" in reasons(result)


@pytest.mark.parametrize("decision", ["disabled", "verified"])
def test_registered_payload_remains_shadow_through_real_validation_pipeline(tmp_path, decision):
    from zscope.core.validation.pipeline import ValidationPipeline
    from zscope.core.validation.runner import ValidationRunner
    from test_validation_pipeline import FakeUserConfig

    result, registrar, _, _, _ = setup_result(tmp_path)
    register(result, registrar)
    record = next(r for r in registrar.ledger.records() if r.record_role == "validation_obligation")
    issue = deepcopy(record.ticket.evidence["candidate_payload"])
    assert issue["candidate_kind"] == "conditional_snapshot_observation"
    assert ValidationRunner._is_shadow_only_candidate(issue)
    registrar.ledger.freeze()
    pipeline = ValidationPipeline(FakeUserConfig())
    if decision == "disabled":
        outcome = pipeline.apply_unvalidated(issue, {"final_score": 1.0})
    else:
        outcome = pipeline.apply_validator_result(
            issue,
            {"positive_evidence": ["path:1"], "blocking_negative_evidence": False},
            verdict="verified",
            score_data={"final_score": 1.0},
        )
    assert outcome.report_bucket is None
    assert issue["candidate_disposition"] == "shadow_observation"


def test_overlap_uses_canonical_obligation_but_separate_validation_group(tmp_path):
    result, registrar, _, _, _ = setup_result(tmp_path)
    first = register(result, registrar)[0]
    active = deepcopy(first)
    for field in (
        "validator_contract",
        "attribution",
        "candidate_uid",
        "candidate_id",
        "obligation_uid",
        "validation_group_uid",
        "validation_cluster_uid",
        "candidate_promotion_eligible",
        "candidate_promotion_reason",
        "candidate_promotion_terminal_status",
    ):
        active.pop(field, None)
    active.update(
        candidate_source="clang_ast_cfg",
        candidate_kind="deterministic",
        rollout_visibility="active",
    )
    registrar.register_issues([active], source="clang_ast_cfg")
    register(result, registrar)
    records = [r for r in registrar.ledger.records() if r.record_role == "validation_obligation"]
    assert len(records) == 2
    assert len({record.obligation_uid for record in records}) == 1
    assert len({record.validation_cluster_uid for record in records}) == 2
    metrics = result.suspicious_metrics["conditional_observations"]
    assert metrics["same_source_repeated_obligations"] == 1
    assert metrics["cross_source_overlap_obligations"] == 1
    assert metrics["exclusive_true_positives"] == "not_measured"


def test_blind_projection_drops_typed_observations_and_keeps_source_words(case):
    session = case.session()
    kind, data = session._project(
        "get_semantic_context",
        {
            "data": {
                "subject": {"symbol_id": case.scope.symbol_id},
                "snapshot": {
                    "status": "current",
                    "conditional_observations": [point()],
                    "data": {"conditional_observations": [point()], "proof": True},
                },
            }
        },
        case.scope,
        {},
    )
    assert kind == "semantic_advisory" and data == {"status": "unverifiable"}
    from test_investigation_evidence import read

    observation = session.query(read())
    assert "memcpy" in json.dumps(observation)


def test_actual_fake_model_observation_publishes_and_registers_before_freeze(tmp_path):
    from test_global_modeler import FakeCodeIndex, RecordingAgent
    from test_incremental_semantic_modeling import modeler_for
    from zscope.config.function_entry import FunctionEntry

    index = FakeCodeIndex()
    for impl in index.impls.values():
        path = tmp_path / impl["file"]
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            "\n".join(line.split(" | ", 1)[1] for line in impl["code"].splitlines()) + "\n"
        )
    calls = []

    class Agent(RecordingAgent):
        def run(self, context):
            response = super().run(context)
            assert "conditional_observations" in context["schema"]["required"]
            response.data["conditional_observations"] = (
                [
                    point(
                        category="ownership",
                        lines="2",
                        source_anchor="return external_leaf();",
                        object="external_leaf",
                        violated_property="ownership_not_established",
                        exit_kind="return",
                    )
                ]
                if context["func_name"] == "leaf"
                else []
            )
            return response

    modeler = modeler_for(tmp_path, index, calls, lambda: Agent(calls))
    modeler.config.analysis.semantic_snapshot_candidate_mode = "shadow"
    modeler.run([FunctionEntry("entry")])
    result = modeler.result
    symbol = next(key for key in result.snapshots if json.loads(key)["name"] == "leaf")
    assert symbol in result.observation_bindings
    assert result.snapshots[symbol]["conditional_observations"]
    ledger = CandidateLedger(project_id="p", project_root=str(tmp_path), revision="r")
    registrar = CandidateRegistrar(ledger)
    issues = register(result, registrar)
    assert len(issues) == 1 and issues[0]["function"] == "leaf"
    assert issues[0]["rollout_visibility"] == "shadow"
    assert issues[0]["call_paths"] == [["entry", "mid", "leaf"]]
    assert calls  # Fake agent executed through the normal modeling retry/commit path.
    ledger.freeze()
    with pytest.raises(RuntimeError, match="frozen"):
        register(result, registrar)
