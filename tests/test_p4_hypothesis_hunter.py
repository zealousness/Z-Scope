from __future__ import annotations

import json
from pathlib import Path

import pytest

from zscope.core.validation.function_ir import FunctionIRGraph
from zscope.core.validation.proof_kernel import ProofKernelEngine
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
    assert first["coverage_summary"]["coverage_status_counts"]["complete"] > 0
    assert isinstance(first["coverage_summary"]["reason_code_distribution"], dict)
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
