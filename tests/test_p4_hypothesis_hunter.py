from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path
from threading import Barrier, Lock

import pytest

from zscope.core.validation.function_ir import FunctionIRGraph
from zscope.core.validation.proof_kernel import ProofKernelEngine
from zscope.framework.llm_usage import P6BalancedTokenAdmissionError
from zscope.orchestration.candidates import CandidateLedger, CandidateRegistrar
from zscope.orchestration.hypothesis_hunter import (
    AttackSurfacePlanner,
    CandidateBlindProjectionError,
    HypothesisArtifactStore,
    HypothesisHunterAgent,
    HypothesisHunterRuntime,
    HypothesisProofCatalog,
    build_candidate_blind_projection,
    load_hypothesis_manifest_identity,
)
from zscope.orchestration.hypothesis_hunter.blind import assert_candidate_blind
from zscope.orchestration.hypothesis_hunter.models import validate_hunt_report
from zscope.semantics.security_map import (
    FunctionSecurityRecord,
    SecurityEvent,
    SecuritySemanticMap,
)


def _graph(*, complete: bool = True) -> FunctionIRGraph:
    evidence = {
        "clang_path": "clang-21.1.8",
        "code_snapshot_sha256": "a" * 64,
        "unresolved_dynamic_edges": not complete,
        "cfg_dump": {
            "summary": {
                "parse_ok": True,
                "function": "neutral_gateway",
                "function_section_unique": True,
                "entry_blocks": ["B3"],
                "exit_blocks": ["B0"],
                "blocks": [
                    {
                        "id": "B3",
                        "label": "ENTRY",
                        "successors": ["B2"],
                        "predecessors": [],
                        "statements": ["buf = recv(fd)", "pthread_mutex_lock(&gate)"],
                    },
                    {
                        "id": "B2",
                        "label": "",
                        "successors": ["B1"],
                        "predecessors": ["B3"],
                        "statements": ["consume(buf)", "pthread_mutex_unlock(&gate)"],
                    },
                    {
                        "id": "B1",
                        "label": "",
                        "successors": ["B0"],
                        "predecessors": ["B2"],
                        "statements": [],
                    },
                    {
                        "id": "B0",
                        "label": "EXIT",
                        "successors": [],
                        "predecessors": ["B1"],
                        "statements": [],
                    },
                ],
            }
        },
        "ast_dump": {
            "summary": {
                "target_function": {
                    "call_exprs": [
                        {"callee": "recv", "line": 3},
                        {"callee": "pthread_mutex_lock", "line": 4},
                        {"callee": "consume", "line": 5},
                        {"callee": "pthread_mutex_unlock", "line": 6},
                    ]
                }
            }
        },
    }
    value = FunctionIRGraph.from_clang_evidence(
        evidence,
        function="neutral_gateway",
        file="src/neutral_gateway.c",
    )
    assert value is not None
    return value


def _resource_graph_from_blocks(
    blocks: list[dict[str, object]],
    *,
    calls: list[dict[str, object]],
    snapshot: str = "d",
) -> FunctionIRGraph:
    evidence = {
        "clang_path": "clang-21.1.8",
        "code_snapshot_sha256": snapshot * 64,
        "cfg_dump": {
            "summary": {
                "parse_ok": True,
                "function": "resource_gateway",
                "function_section_unique": True,
                "entry_blocks": ["B1"],
                "exit_blocks": ["B0"],
                "blocks": blocks,
            }
        },
        "ast_dump": {"summary": {"target_function": {"call_exprs": calls}}},
    }
    value = FunctionIRGraph.from_clang_evidence(
        evidence,
        function="resource_gateway",
        file="src/resource_gateway.c",
    )
    assert value is not None
    return value


def _resource_graph(*, cleanup: bool) -> FunctionIRGraph:
    statements = ["p = malloc(8)"]
    calls = [{"callee": "malloc", "line": 10}]
    if cleanup:
        statements.append("free(p)")
        calls.append({"callee": "free", "line": 11})
    return _resource_graph_from_blocks(
        [
            {
                "id": "B1",
                "label": "ENTRY",
                "successors": ["B0"],
                "predecessors": [],
                "statements": statements,
            },
            {
                "id": "B0",
                "label": "EXIT",
                "successors": [],
                "predecessors": ["B1"],
                "statements": [],
            },
        ],
        calls=calls,
    )


def _semantic_map() -> SecuritySemanticMap:
    record = FunctionSecurityRecord(
        function_uid="FUNC_NEUTRAL_GATEWAY",
        index_name="neutral_gateway",
        function_name="neutral_gateway",
        file_path="src/neutral_gateway.c",
        start_line=1,
        end_line=10,
        signature="neutral_gateway(int fd)",
        code_hash="a" * 64,
        entry_identities=("ENTRY_EXTERNAL",),
        entry_paths=(("ENTRY_EXTERNAL", "FUNC_NEUTRAL_GATEWAY"),),
        callees=("recv", "consume"),
        unresolved_callees=("dispatch_unknown",),
        events=(
            SecurityEvent(
                event_id="EVENT_INPUT",
                family="input_boundary",
                kind="external_input",
                function_uid="FUNC_NEUTRAL_GATEWAY",
                file="src/neutral_gateway.c",
                line=3,
                expression="recv(fd)",
                evidence_ref="evidence:input:neutral",
            ),
            SecurityEvent(
                event_id="EVENT_SINK",
                family="sensitive_sink",
                kind="security_sensitive_sink",
                function_uid="FUNC_NEUTRAL_GATEWAY",
                file="src/neutral_gateway.c",
                line=5,
                expression="consume(buf)",
                evidence_ref="evidence:sink:neutral",
            ),
        ),
        backend_coverage={"cfg": "complete"},
    )
    return SecuritySemanticMap(
        project_id="PROJECT_NEUTRAL",
        revision="b" * 40,
        profile="balanced",
        functions=(record,),
        claims=(),
        unknowns=(),
        audit_units=(),
        coverage={},
        fingerprints={"source": "c" * 64},
    )


def _resource_semantic_map(
    *,
    line: int = 10,
    expression: str = "p = malloc(8)",
) -> SecuritySemanticMap:
    baseline = _semantic_map()
    event = SecurityEvent(
        event_id="EVENT_RESOURCE",
        family="resource_lifecycle",
        kind="resource_transition",
        function_uid="FUNC_RESOURCE_GATEWAY",
        file="src/resource_gateway.c",
        line=line,
        expression=expression,
        evidence_ref="evidence:resource:neutral",
    )
    record = replace(
        baseline.functions[0],
        function_uid="FUNC_RESOURCE_GATEWAY",
        index_name="resource_gateway",
        function_name="resource_gateway",
        file_path="src/resource_gateway.c",
        signature="resource_gateway(void)",
        code_hash="d" * 64,
        entry_paths=(("ENTRY_EXTERNAL", "FUNC_RESOURCE_GATEWAY"),),
        callees=("malloc",),
        unresolved_callees=(),
        events=(event,),
    )
    return replace(baseline, functions=(record,))


def _semantic_map_with_function_count(count: int) -> SecuritySemanticMap:
    baseline = _semantic_map()
    template = baseline.functions[0]
    records = []
    for index in range(count):
        suffix = f"_{index:02d}"
        function_uid = template.function_uid + suffix
        file_path = f"src/neutral_gateway_{index:02d}.c"
        events = tuple(
            replace(
                event,
                event_id=event.event_id + suffix,
                function_uid=function_uid,
                file=file_path,
                evidence_ref=event.evidence_ref + suffix,
            )
            for event in template.events
        )
        records.append(
            replace(
                template,
                function_uid=function_uid,
                index_name=template.index_name + suffix,
                function_name=template.function_name + suffix,
                file_path=file_path,
                signature=f"neutral_gateway_{index:02d}(int fd)",
                code_hash=f"{index + 1:064x}",
                entry_paths=(("ENTRY_EXTERNAL", function_uid),),
                events=events,
            )
        )
    return replace(baseline, functions=tuple(records))


def _planned_bundle():
    semantic_map = _semantic_map()
    catalog = HypothesisProofCatalog(lambda record, event: _graph())
    from zscope.orchestration.hypothesis_hunter.planner import AttackSurfacePlanner

    planned = AttackSurfacePlanner(risk_threshold=35).plan(
        semantic_map,
        proof_bundle_provider=catalog.bundles,
    )
    assert planned
    assert planned[0].offers
    return semantic_map, planned[0]


def test_statementless_proof_graph_is_one_unexecutable_unit_not_stage_failure() -> None:
    original = _graph()
    graph = replace(
        original,
        blocks=tuple(replace(block, statements=()) for block in original.blocks),
        events=(),
        ir_sha256="f" * 64,
    )
    planner = AttackSurfacePlanner(risk_threshold=35)

    planned = planner.plan(
        _semantic_map(),
        proof_bundle_provider=HypothesisProofCatalog(lambda record, event: graph).bundles,
    )

    assert planned
    assert all(value.offers == () for value in planned)


def test_proof_bundle_failure_isolated_to_one_unit_without_error_body() -> None:
    planner = AttackSurfacePlanner(risk_threshold=35)

    planned = planner.plan(
        _semantic_map(),
        proof_bundle_provider=lambda record, event, identity: (_ for _ in ()).throw(
            ValueError("source-derived-private-body")
        ),
    )

    assert planned
    assert all(value.offers == () for value in planned)
    diagnostic = next(
        value
        for value in planner.diagnostics
        if value["reason_code"] == "PROOF_BUNDLE_PROVIDER_REJECTED"
    )
    assert diagnostic["failure_class"] == "ValueError"
    assert "source-derived-private-body" not in json.dumps(diagnostic)


def _select_report(unit, offers):
    offer = offers[0]
    return {
        "schema_version": "zscope.hypothesis-hunt-report.v2",
        "audit_unit_uid": unit["audit_unit_uid"],
        "unit_fingerprint_sha256": unit["unit_fingerprint_sha256"],
        "coverage_status": "complete",
        "selected_offers": [
            {
                "offer_uid": offer["offer_uid"],
                "evidence_action_uids": [offer["evidence_actions"][0]["action_uid"]],
                "supporting_fact_refs": [],
                "opposing_fact_refs": [],
                "unknown_fact_refs": [],
                "evidence_refs": [offer["evidence_refs"][0]],
            }
        ],
        "reviewed_evidence_refs": list(offer["evidence_refs"]),
        "unresolved_reasons": [],
    }


def test_candidate_blind_projection_checks_keys_scalars_and_unicode_variants() -> None:
    _, planned = _planned_bundle()
    projection = build_candidate_blind_projection(planned.audit_unit, planned.offers)
    assert "risk_score" not in json.dumps(projection, sort_keys=True)
    assert projection["audit_unit"]["risk_level"] > 0
    assert "localized_signal_desert" in projection["audit_unit"]["attack_signals"]
    assert "localized_candidate_desert" not in json.dumps(projection, sort_keys=True)
    with pytest.raises(CandidateBlindProjectionError):
        assert_candidate_blind({"verdict": "unknown"})
    with pytest.raises(CandidateBlindProjectionError):
        assert_candidate_blind({"note": "ＧＲＯＵＮＤ－ＴＲＵＴＨ"})
    with pytest.raises(CandidateBlindProjectionError):
        assert_candidate_blind({"note": "CaNdIdAtE_abcdef12"})


def test_selected_action_path_rejects_duplicates_and_foreign_ids() -> None:
    _, planned = _planned_bundle()
    offer = planned.offers[0]
    action_uid = offer["evidence_actions"][0]["action_uid"]
    engine = ProofKernelEngine()
    result = engine.evaluate_selected_actions(
        proof_ir=offer["proof_ir"],
        obligation=offer["proof_obligation"],
        selected_action_uids=(action_uid,),
    )
    assert len(result.actions) == 1
    # A source-to-sink CFG path is a useful investigation fact, but it is not
    # a sufficient proof of a memory/sensitive-operation vulnerability.
    assert result.decision == "needs_review"
    assert result.reason_code == "open_or_unknown_proof_clause"
    with pytest.raises(ValueError, match="duplicate_selected"):
        engine.evaluate_selected_actions(
            proof_ir=offer["proof_ir"],
            obligation=offer["proof_obligation"],
            selected_action_uids=(action_uid, action_uid),
        )
    with pytest.raises(ValueError, match="not_in_frozen_catalog"):
        engine.evaluate_selected_actions(
            proof_ir=offer["proof_ir"],
            obligation=offer["proof_obligation"],
            selected_action_uids=("EVACTION_" + "f" * 32,),
        )


def test_only_complete_uncovered_resource_path_has_terminal_hunter_proof() -> None:
    planner = AttackSurfacePlanner(risk_threshold=35)
    unsafe = planner.plan(
        _resource_semantic_map(),
        proof_bundle_provider=HypothesisProofCatalog(
            lambda record, event: _resource_graph(cleanup=False)
        ).bundles,
    )[0].offers[0]
    assert unsafe["defect_family"] == "resource_leak"
    assert unsafe["proof_obligation"]["open_clauses"] == []
    unsafe_result = ProofKernelEngine().evaluate_selected_actions(
        proof_ir=unsafe["proof_ir"],
        obligation=unsafe["proof_obligation"],
        selected_action_uids=(unsafe["evidence_actions"][0]["action_uid"],),
    )
    assert unsafe_result.decision == "confirmed"

    safe = (
        AttackSurfacePlanner(risk_threshold=35)
        .plan(
            _resource_semantic_map(),
            proof_bundle_provider=HypothesisProofCatalog(
                lambda record, event: _resource_graph(cleanup=True)
            ).bundles,
        )[0]
        .offers[0]
    )
    safe_result = ProofKernelEngine().evaluate_selected_actions(
        proof_ir=safe["proof_ir"],
        obligation=safe["proof_obligation"],
        selected_action_uids=(safe["evidence_actions"][0]["action_uid"],),
    )
    assert safe["proof_obligation"]["confirmation_clauses"] == []
    assert len(safe["proof_obligation"]["counterproof_clauses"]) == 1
    assert safe_result.decision == "rejected_with_proof"
    assert safe_result.reason_code == "verified_counterproof"


def test_resource_offer_binds_the_semantic_event_not_the_first_acquisition() -> None:
    graph = _resource_graph_from_blocks(
        [
            {
                "id": "B1",
                "label": "ENTRY",
                "successors": ["B0"],
                "predecessors": [],
                "statements": [
                    "p = malloc(8)",
                    "free(p)",
                    "q = calloc(1, 8)",
                ],
            },
            {
                "id": "B0",
                "label": "EXIT",
                "successors": [],
                "predecessors": ["B1"],
                "statements": [],
            },
        ],
        calls=[
            {"callee": "malloc", "line": 10},
            {"callee": "free", "line": 11},
            # Both acquisitions deliberately share a source line; the event
            # expression, not list order, must select the resource.
            {"callee": "calloc", "line": 10},
        ],
    )
    planner = AttackSurfacePlanner(risk_threshold=35)

    second = planner.plan(
        _resource_semantic_map(line=10, expression="q = calloc(1, 8)"),
        proof_bundle_provider=HypothesisProofCatalog(lambda record, event: graph).bundles,
    )[0].offers[0]
    second_clause = second["proof_obligation"]["confirmation_clauses"][0]
    assert second_clause["parameters"] == {"resource_uid": "q"}
    assert (
        ProofKernelEngine()
        .evaluate_selected_actions(
            proof_ir=second["proof_ir"],
            obligation=second["proof_obligation"],
            selected_action_uids=(second["evidence_actions"][0]["action_uid"],),
        )
        .decision
        == "confirmed"
    )

    first = planner.plan(
        _resource_semantic_map(line=10, expression="p = malloc(8)"),
        proof_bundle_provider=HypothesisProofCatalog(lambda record, event: graph).bundles,
    )[0].offers[0]
    first_clause = first["proof_obligation"]["counterproof_clauses"][0]
    assert first_clause["parameters"] == {"resource_uid": "p"}
    assert (
        ProofKernelEngine()
        .evaluate_selected_actions(
            proof_ir=first["proof_ir"],
            obligation=first["proof_obligation"],
            selected_action_uids=(first["evidence_actions"][0]["action_uid"],),
        )
        .decision
        == "rejected_with_proof"
    )
    assert first["subject_uid"] != second["subject_uid"]


@pytest.mark.parametrize(
    ("statement", "extra_calls"),
    [
        ("return p", []),
        ("g_owner = p", []),
        ("ctx->field = p", []),
        ("*out = p", []),
        ("items[index] = p", []),
        ("q = p", []),
        ("register_owner(p)", [{"callee": "register_owner", "line": 11}]),
        ("set_callback(p)", [{"callee": "set_callback", "line": 11}]),
        ("consume(p)", [{"callee": "consume", "line": 11}]),
    ],
)
def test_resource_alias_escape_transfer_and_unknown_callee_fail_closed(
    statement: str,
    extra_calls: list[dict[str, object]],
) -> None:
    graph = _resource_graph_from_blocks(
        [
            {
                "id": "B1",
                "label": "ENTRY",
                "successors": ["B0"],
                "predecessors": [],
                "statements": ["p = malloc(8)", statement],
            },
            {
                "id": "B0",
                "label": "EXIT",
                "successors": [],
                "predecessors": ["B1"],
                "statements": [],
            },
        ],
        calls=[{"callee": "malloc", "line": 10}, *extra_calls],
    )

    planned = AttackSurfacePlanner(risk_threshold=35).plan(
        _resource_semantic_map(),
        proof_bundle_provider=HypothesisProofCatalog(lambda record, event: graph).bundles,
    )

    assert planned
    assert planned[0].offers == ()


def test_field_resource_and_reacquired_identity_fail_closed() -> None:
    field_graph = _resource_graph_from_blocks(
        [
            {
                "id": "B1",
                "label": "ENTRY",
                "successors": ["B0"],
                "predecessors": [],
                "statements": ["owner->field = malloc(8)"],
            },
            {
                "id": "B0",
                "label": "EXIT",
                "successors": [],
                "predecessors": ["B1"],
                "statements": [],
            },
        ],
        calls=[{"callee": "malloc", "line": 10}],
    )
    reacquired_graph = _resource_graph_from_blocks(
        [
            {
                "id": "B1",
                "label": "ENTRY",
                "successors": ["B0"],
                "predecessors": [],
                "statements": ["p = malloc(8)", "free(p)", "p = calloc(1, 8)"],
            },
            {
                "id": "B0",
                "label": "EXIT",
                "successors": [],
                "predecessors": ["B1"],
                "statements": [],
            },
        ],
        calls=[
            {"callee": "malloc", "line": 10},
            {"callee": "free", "line": 11},
            {"callee": "calloc", "line": 12},
        ],
    )
    planner = AttackSurfacePlanner(risk_threshold=35)

    assert (
        planner.plan(
            _resource_semantic_map(expression="owner->field = malloc(8)"),
            proof_bundle_provider=HypothesisProofCatalog(lambda record, event: field_graph).bundles,
        )[0].offers
        == ()
    )
    assert (
        planner.plan(
            _resource_semantic_map(),
            proof_bundle_provider=HypothesisProofCatalog(
                lambda record, event: reacquired_graph
            ).bundles,
        )[0].offers
        == ()
    )


def test_unreachable_resource_acquisition_cannot_form_a_counterproof() -> None:
    graph = _resource_graph_from_blocks(
        [
            {
                "id": "B1",
                "label": "ENTRY",
                "successors": ["B0"],
                "predecessors": [],
                "statements": [],
            },
            {
                "id": "B9",
                "label": "UNREACHABLE",
                "successors": [],
                "predecessors": [],
                "statements": ["p = malloc(8)"],
            },
            {
                "id": "B0",
                "label": "EXIT",
                "successors": [],
                "predecessors": ["B1"],
                "statements": [],
            },
        ],
        calls=[{"callee": "malloc", "line": 10}],
    )
    assert graph.coverage_complete is True

    planned = AttackSurfacePlanner(risk_threshold=35).plan(
        _resource_semantic_map(),
        proof_bundle_provider=HypothesisProofCatalog(lambda record, event: graph).bundles,
    )

    assert planned[0].offers == ()


@pytest.mark.parametrize("cleanup_on_both_paths", [False, True])
def test_resource_branch_cleanup_metamorphic(cleanup_on_both_paths: bool) -> None:
    right_statements = ["free(p)"] if cleanup_on_both_paths else []
    graph = _resource_graph_from_blocks(
        [
            {
                "id": "B1",
                "label": "ENTRY",
                "successors": ["B2", "B3"],
                "predecessors": [],
                "statements": ["p = malloc(8)"],
            },
            {
                "id": "B2",
                "label": "",
                "successors": ["B0"],
                "predecessors": ["B1"],
                "statements": ["free(p)"],
            },
            {
                "id": "B3",
                "label": "",
                "successors": ["B0"],
                "predecessors": ["B1"],
                "statements": right_statements,
            },
            {
                "id": "B0",
                "label": "EXIT",
                "successors": [],
                "predecessors": ["B2", "B3"],
                "statements": [],
            },
        ],
        calls=[
            {"callee": "malloc", "line": 10},
            {"callee": "free", "line": 11},
            *([{"callee": "free", "line": 12}] if cleanup_on_both_paths else []),
        ],
        snapshot="e" if cleanup_on_both_paths else "f",
    )
    offer = (
        AttackSurfacePlanner(risk_threshold=35)
        .plan(
            _resource_semantic_map(),
            proof_bundle_provider=HypothesisProofCatalog(lambda record, event: graph).bundles,
        )[0]
        .offers[0]
    )
    result = ProofKernelEngine().evaluate_selected_actions(
        proof_ir=offer["proof_ir"],
        obligation=offer["proof_obligation"],
        selected_action_uids=(offer["evidence_actions"][0]["action_uid"],),
    )

    assert result.decision == ("rejected_with_proof" if cleanup_on_both_paths else "confirmed")


def test_hunt_report_rejects_free_parameters_and_cross_offer_actions() -> None:
    _, planned = _planned_bundle()
    report = _select_report(planned.audit_unit, planned.offers)
    report["selected_offers"][0]["parameters"] = {"path_exists": True}
    valid, reason = validate_hunt_report(
        report,
        audit_unit=planned.audit_unit,
        offers=planned.offers,
    )
    assert valid is False
    assert reason == "hunt_report_selection_schema_mismatch"

    report = _select_report(planned.audit_unit, planned.offers)
    report["selected_offers"][0]["evidence_action_uids"] = ["EVACTION_" + "f" * 32]
    valid, reason = validate_hunt_report(
        report,
        audit_unit=planned.audit_unit,
        offers=planned.offers,
    )
    assert valid is False
    assert reason == "hunt_report_action_not_offered"


def test_alias_cluster_schedules_only_one_representative_unit() -> None:
    semantic_map = _semantic_map()
    catalog = HypothesisProofCatalog(lambda record, event: _graph())
    baseline = AttackSurfacePlanner(risk_threshold=35).plan(
        semantic_map,
        proof_bundle_provider=catalog.bundles,
    )
    assert len(baseline) >= 2
    roots = {
        str(value.audit_unit["localized_coverage_key"]["key_uid"]): "ALIAS_NEUTRAL"
        for value in baseline
    }
    planner = AttackSurfacePlanner(risk_threshold=35)
    deduplicated = planner.plan(
        semantic_map,
        canonical_investigation_roots=roots,
        proof_bundle_provider=catalog.bundles,
    )
    assert len(deduplicated) == 1
    assert any(
        value["reason_code"] == "ALIAS_CLUSTER_ALREADY_SCHEDULED" for value in planner.diagnostics
    )


def test_non_candidate_structural_alias_root_schedules_one_observation() -> None:
    semantic_map = _semantic_map()
    baseline = AttackSurfacePlanner(risk_threshold=35).plan(semantic_map)
    assert len(baseline) >= 2
    roots = {
        str(value.audit_unit["localized_coverage_key"]["key_uid"]): "ALIAS_NO_CANDIDATE"
        for value in baseline
    }
    planner = AttackSurfacePlanner(risk_threshold=35)
    planned = planner.plan(
        semantic_map,
        canonical_investigation_roots=roots,
        proof_bundle_provider=None,
    )

    assert len(planned) == 1
    assert planned[0].offers == ()
    assert any(
        value["reason_code"] == "ALIAS_CLUSTER_ALREADY_SCHEDULED" for value in planner.diagnostics
    )


def test_active_runtime_registers_live_unconfirmed_candidates_and_reuses_exact_cache(
    tmp_path: Path,
) -> None:
    semantic_map = _semantic_map()
    catalog = HypothesisProofCatalog(lambda record, event: _graph())
    live = CandidateLedger(project_id="PROJECT_NEUTRAL", revision="b" * 40)
    registrar = CandidateRegistrar(live)
    calls = []

    def runner(projection, unit, offers):
        calls.append(unit["audit_unit_uid"])
        return _select_report(unit, offers)

    store = HypothesisArtifactStore(tmp_path / "hypothesis_hunter")
    runtime = HypothesisHunterRuntime(store, risk_threshold=35, model_profile="test")
    first = runtime.run(
        semantic_map,
        candidate_registrar=registrar,
        proof_bundle_provider=catalog.bundles,
        report_runner=runner,
    )
    assert first["mode"] == "active"
    assert first["active_product_effect"] == "candidate_registration_only"
    assert live.lifecycle_snapshot()["summary"]["total"] > 0
    assert first["coverage_summary"]["hypothesis_count"] > 0
    assert first["coverage_summary"]["registered_candidate_count"] > 0
    assert first["coverage_summary"]["coverage_status_counts"]["complete"] > 0
    assert isinstance(first["coverage_summary"]["reason_code_distribution"], dict)
    payload = live.records()[0].ticket.evidence["candidate_payload"]
    assert payload["function"] == "neutral_gateway"
    assert payload["location"]["function_uid"] == ("FUNC_NEUTRAL_GATEWAY")
    first_call_count = len(calls)

    second = HypothesisHunterRuntime(
        store,
        risk_threshold=35,
        model_profile="test",
    ).run(
        semantic_map,
        candidate_registrar=registrar,
        proof_bundle_provider=catalog.bundles,
        report_runner=runner,
    )
    assert len(calls) == first_call_count
    assert second["coverage_summary"]["cache_hit_count"] > 0
    identity = load_hypothesis_manifest_identity(
        tmp_path / "hypothesis_hunter",
        consumer="test",
    )
    assert identity["hypothesis_hunter_mode"] == "active"
    assert identity["hypothesis_hunter_decision"]["active_product_effect"] == (
        "candidate_registration_only"
    )


def test_runtime_counterproof_is_audited_without_registering_a_candidate(tmp_path: Path) -> None:
    ledger = CandidateLedger(project_id="PROJECT_NEUTRAL", revision="b" * 40)
    result = HypothesisHunterRuntime(
        HypothesisArtifactStore(tmp_path),
        risk_threshold=35,
        model_profile="test",
    ).run(
        _resource_semantic_map(),
        candidate_registrar=CandidateRegistrar(ledger),
        proof_bundle_provider=HypothesisProofCatalog(
            lambda record, event: _resource_graph(cleanup=True)
        ).bundles,
        report_runner=lambda projection, unit, offers: _select_report(unit, offers),
    )

    assert result["proof_decisions"][0]["decision"] == "rejected_with_proof"
    assert result["coverage_summary"]["registered_candidate_count"] == 0
    assert result["coverage_summary"]["reason_code_distribution"] == {
        "selected_hypothesis_counterproved": 1
    }
    assert ledger.lifecycle_snapshot()["summary"]["total"] == 0


def test_runtime_collects_eight_concurrent_calls_and_isolates_one_failure(
    tmp_path: Path,
) -> None:
    semantic_map = _semantic_map_with_function_count(4)
    catalog = HypothesisProofCatalog(lambda record, event: _graph())
    planned = AttackSurfacePlanner(risk_threshold=35).plan(
        semantic_map,
        proof_bundle_provider=catalog.bundles,
    )
    assert len(planned) == 8
    assert all(value.offers for value in planned)

    barrier = Barrier(8)
    lock = Lock()
    counters = {"active": 0, "maximum": 0, "calls": 0}

    def runner(projection, unit, offers):
        del projection
        with lock:
            counters["active"] += 1
            counters["calls"] += 1
            counters["maximum"] = max(counters["maximum"], counters["active"])
            call_number = counters["calls"]
        try:
            barrier.wait(timeout=10)
            if call_number == 1:
                raise RuntimeError("private-provider-error-body")
            return _select_report(unit, offers)
        finally:
            with lock:
                counters["active"] -= 1

    ledger = CandidateLedger(project_id="PROJECT_NEUTRAL", revision="b" * 40)
    result = HypothesisHunterRuntime(
        HypothesisArtifactStore(tmp_path),
        risk_threshold=35,
        max_concurrent_calls=8,
    ).run(
        semantic_map,
        candidate_registrar=CandidateRegistrar(ledger),
        proof_bundle_provider=catalog.bundles,
        report_runner=runner,
    )

    assert counters == {"active": 0, "maximum": 8, "calls": 8}
    assert result["coverage_summary"]["llm_call_count"] == 8
    assert result["coverage_summary"]["coverage_status_counts"] == {
        "complete": 7,
        "partial": 0,
        "failed": 1,
    }
    assert result["coverage_summary"]["hypothesis_count"] == 7
    assert "private-provider-error-body" not in json.dumps(result)


def test_runtime_propagates_p6_hard_token_admission(tmp_path: Path) -> None:
    catalog = HypothesisProofCatalog(lambda record, event: _graph())
    ledger = CandidateLedger(project_id="PROJECT_NEUTRAL", revision="b" * 40)

    def deny_before_provider(projection, unit, offers):
        del projection, unit, offers
        raise P6BalancedTokenAdmissionError("p6_token_hard_limit")

    with pytest.raises(P6BalancedTokenAdmissionError) as raised:
        HypothesisHunterRuntime(
            HypothesisArtifactStore(tmp_path),
            risk_threshold=35,
            max_units=1,
            max_concurrent_calls=8,
        ).run(
            _semantic_map(),
            candidate_registrar=CandidateRegistrar(ledger),
            proof_bundle_provider=catalog.bundles,
            report_runner=deny_before_provider,
        )

    assert raised.value.failure_class == "p6_token_hard_limit"
    assert ledger.lifecycle_snapshot()["summary"]["total"] == 0


def test_incomplete_unit_is_observation_not_candidate(tmp_path: Path) -> None:
    ledger = CandidateLedger(project_id="PROJECT_NEUTRAL", revision="b" * 40)
    runtime = HypothesisHunterRuntime(
        HypothesisArtifactStore(tmp_path),
        risk_threshold=35,
    )
    result = runtime.run(
        _semantic_map(),
        candidate_registrar=CandidateRegistrar(ledger),
        proof_bundle_provider=None,
        report_runner=None,
    )
    assert result["coverage_summary"]["hypothesis_count"] == 0
    assert result["coverage_summary"]["observation_count"] > 0
    assert ledger.lifecycle_snapshot()["summary"]["total"] == 0


def test_invalid_hunter_output_is_observation_not_candidate(tmp_path: Path) -> None:
    catalog = HypothesisProofCatalog(lambda record, event: _graph())
    ledger = CandidateLedger(project_id="PROJECT_NEUTRAL", revision="b" * 40)
    result = HypothesisHunterRuntime(
        HypothesisArtifactStore(tmp_path),
        risk_threshold=35,
    ).run(
        _semantic_map(),
        candidate_registrar=CandidateRegistrar(ledger),
        proof_bundle_provider=catalog.bundles,
        report_runner=lambda projection, unit, offers: {"selected_offers": []},
    )
    assert result["coverage_summary"]["observation_count"] > 0
    assert ledger.lifecycle_snapshot()["summary"]["total"] == 0


def test_fast_runtime_has_no_units_or_model_calls(tmp_path: Path) -> None:
    calls = []
    ledger = CandidateLedger(project_id="PROJECT_NEUTRAL", revision="b" * 40)
    result = HypothesisHunterRuntime(
        HypothesisArtifactStore(tmp_path),
        risk_threshold=101,
        max_units=0,
    ).run(
        _semantic_map(),
        candidate_registrar=CandidateRegistrar(ledger),
        report_runner=lambda projection, unit, offers: calls.append(unit),
    )
    assert result["coverage_summary"]["planned_unit_count"] == 0
    assert result["coverage_summary"]["llm_call_count"] == 0
    assert calls == []


def test_agent_has_no_repository_tools() -> None:
    class NeverCalled:
        pass

    agent = HypothesisHunterAgent(NeverCalled())
    assert agent.tools == []


def test_store_detects_content_tampering(tmp_path: Path) -> None:
    store = HypothesisArtifactStore(tmp_path)
    reference = store.put("neutral", {"value": 1})
    digest = reference.split(":", 1)[1]
    path = tmp_path / "hypothesis_objects" / f"{digest}.json"
    raw = json.loads(path.read_text(encoding="utf-8"))
    raw["payload"]["value"] = 2
    path.write_text(json.dumps(raw), encoding="utf-8")
    assert store.verify_ref(reference) is False


def test_manifest_loader_rejects_shadow_ledger_hash_tampering(tmp_path: Path) -> None:
    store = HypothesisArtifactStore(tmp_path)
    reference = store.put("neutral", {"value": 1})
    manifest = store.write_root_manifest(
        (reference,),
        registered_candidate_uids=(),
        coverage_summary={"planned_unit_count": 0},
    )
    manifest["candidate_registration_sha256"] = "not-a-hash"
    (tmp_path / "hypothesis_hunter_manifest.json").write_text(
        json.dumps(manifest),
        encoding="utf-8",
    )

    identity = load_hypothesis_manifest_identity(tmp_path, consumer="test")

    assert identity["hypothesis_hunter_root_manifest_sha256"] == ""
    assert identity["hypothesis_hunter_artifact_refs"] == []
