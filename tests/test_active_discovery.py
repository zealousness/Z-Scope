import json
from dataclasses import replace
from types import SimpleNamespace

import pytest

from zscope.orchestration.active_discovery import (
    AUDIT_RISK_WEIGHTS,
    ActiveDiscoveryCoordinator,
    CoverageGapPlanner,
    SemanticMapEnricher,
    assert_candidate_blind_projection,
    audit_unit_risk_score,
    candidate_blind_prompt_projection,
    candidate_coverage_keys,
    fit_candidate_blind_prompt_projection,
    historical_variant_keys,
    resolve_discovery_profile,
)
from zscope.orchestration.candidates import CandidateLedger, CandidateRegistrar
from zscope.semantics.security_map import (
    DISCOVERY_REPORT_SCHEMA_VERSION,
    SEMANTIC_CLAIM_DELTA_SCHEMA_VERSION,
    DiscoveryReport,
    FunctionSecurityRecord,
    SecurityEvent,
    SecuritySemanticMap,
    SemanticClaim,
    SemanticClaimDelta,
    SemanticUnknown,
    SQLiteSecurityMapStore,
)


def _semantic_map(profile="balanced") -> SecuritySemanticMap:
    function_uid = "FUNC_copy"
    evidence_ref = "source:src/demo.c:12"
    event = SecurityEvent(
        event_id="EVT_copy",
        family="memory_bounds",
        kind="copy_or_length_sink",
        function_uid=function_uid,
        file="src/demo.c",
        line=12,
        expression="memcpy(dst, src, len);",
        evidence_ref=evidence_ref,
    )
    function = FunctionSecurityRecord(
        function_uid=function_uid,
        index_name="copy@src/demo.c:10-14",
        function_name="copy",
        file_path="src/demo.c",
        start_line=10,
        end_line=14,
        signature="void copy(char *dst, char *src, size_t len)",
        code_hash="a" * 64,
        entry_identities=("entry",),
        entry_paths=(("entry", "copy"),),
        callees=(),
        unresolved_callees=(),
        events=(event,),
        backend_coverage={
            "backend": "clang",
            "call_graph_observed": True,
            "framework_ir_observed": False,
        },
        diff_focus={"risk_score": 80},
    )
    claim = SemanticClaim(
        claim_id="CLAIM_copy",
        subject_uid=function_uid,
        kind="bounds_contract",
        value={"operation": "memcpy", "rule_id": "RULE_SECRET"},
        locations=({"file": "src/demo.c", "line": 12, "function": "copy"},),
        evidence_refs=(evidence_ref,),
        origin="program",
        confidence=0.9,
        status="known",
    )
    entry_claim = SemanticClaim(
        claim_id="CLAIM_external",
        subject_uid=function_uid,
        kind="trust_boundary",
        value={"entry_identity": "entry", "externally_exposed": True},
        locations=({"file": "src/demo.c", "line": 10, "function": "copy"},),
        evidence_refs=(evidence_ref,),
        origin="program",
        confidence=1.0,
        status="known",
    )
    return SecuritySemanticMap(
        project_id="demo",
        revision="rev",
        profile=profile,
        functions=(function,),
        claims=(claim, entry_claim),
        unknowns=(),
        audit_units=(),
        coverage={"llm_calls": 0},
        fingerprints={"builder": "test"},
    )


def _report_payload(unit, *, evidence_ref="source:src/demo.c:12"):
    return {
        "schema_version": DISCOVERY_REPORT_SCHEMA_VERSION,
        "unit_id": unit.unit_id,
        "unit_fingerprint": unit.fingerprint,
        "coverage_status": "complete",
        "reviewed_function_uids": ["FUNC_copy"],
        "reviewed_claim_ids": ["CLAIM_copy", "CLAIM_external"],
        "tool_evidence_refs": ["source:src/demo.c:12"],
        "hypotheses": [
            {
                "hypothesis_id": "HYP_1",
                "defect_class": "out_of_bounds_copy",
                "impact_level": "high",
                "confidence": 0.78,
                "function": "FUNC_copy",
                "location": "src/demo.c:12",
                "source": "src",
                "sink": "memcpy",
                "resource": "dst",
                "entry_paths": [["entry", "copy"]],
                "path_conditions": ["len may exceed destination capacity"],
                "positive_evidence_refs": [evidence_ref],
                "negative_evidence_refs": [],
                "missing_fact_kinds": ["destination_capacity"],
                "description": "Length may exceed the destination buffer.",
                "reasoning": "The copy has no visible capacity fact.",
                "root_cause": "Unproven caller-controlled length contract.",
            }
        ],
        "unresolved_facts": ["destination_capacity"],
    }


def test_planner_uses_coverage_gap_threshold_and_profile_budget() -> None:
    semantic_map = _semantic_map()
    balanced = resolve_discovery_profile(
        type("Config", (), {"scan": type("S", (), {"depth": "balanced"})()})()
    )
    deep = resolve_discovery_profile(
        type("Config", (), {"scan": type("S", (), {"depth": "deep"})()})()
    )

    uncovered = CoverageGapPlanner(balanced).plan(semantic_map)
    covered = CoverageGapPlanner(balanced).plan(semantic_map, covered_keys={"family:memory_bounds"})
    deep_covered = CoverageGapPlanner(deep).plan(
        semantic_map, covered_keys={"family:memory_bounds"}
    )

    assert len(uncovered) == 1
    assert uncovered[0].candidate_desert is True
    assert uncovered[0].risk_score >= balanced.risk_threshold
    assert covered == ()
    assert len(deep_covered) == 1
    assert balanced.max_units is None
    assert deep.max_units is None
    assert balanced.max_functions_per_unit == 16


def test_candidate_coverage_projection_contains_only_event_family_presence() -> None:
    ticket = SimpleNamespace(
        skill="memory_bounds_integer",
        origin="SECRET_ORIGIN",
        sink="SECRET_SINK",
        evidence={
            "function": "SECRET_FUNCTION",
            "location": "SECRET_FILE:99",
            "candidate_payload": {
                "category": "buffer_overflow",
                "source": "SECRET_SOURCE",
                "sink": "SECRET_SINK",
            },
        },
    )
    record = SimpleNamespace(
        ticket=ticket,
        candidate_uid="CAND_SECRET",
        defect_class="buffer_overflow",
    )
    ledger = SimpleNamespace(records=lambda: [record])

    keys = candidate_coverage_keys(ledger)

    assert keys == {"family:memory_bounds"}
    assert "secret" not in json.dumps(sorted(keys)).lower()


@pytest.mark.parametrize(
    "path,flag",
    [
        ("vendor/lib/unsafe.c", "is_vendor"),
        ("generated/api.c", "is_generated"),
        ("tests/unit/unsafe_test.c", "is_test_only"),
    ],
)
def test_planner_excludes_generated_vendor_and_test_only_units(path, flag) -> None:
    semantic_map = _semantic_map()
    function = semantic_map.functions[0]
    coverage = {**function.backend_coverage, "project_relative_path": path, flag: True}
    excluded_map = replace(
        semantic_map,
        functions=(replace(function, file_path=path, backend_coverage=coverage),),
    )
    balanced = resolve_discovery_profile(
        type("Config", (), {"scan": type("S", (), {"depth": "balanced"})()})()
    )

    assert CoverageGapPlanner(balanced).plan(excluded_map) == ()


def test_audit_unit_merge_requires_same_skill_and_jaccard_overlap() -> None:
    semantic_map = _semantic_map()
    balanced = resolve_discovery_profile(
        type("Config", (), {"scan": type("S", (), {"depth": "balanced"})()})()
    )
    planner = CoverageGapPlanner(balanced)
    base = planner.plan(semantic_map)[0]
    different_skill = replace(
        base,
        unit_id="AUDIT_other_skill",
        fingerprint="b" * 64,
        skill_families=("authorization",),
    )
    insufficient_overlap = replace(
        base,
        unit_id="AUDIT_low_overlap",
        fingerprint="c" * 64,
        member_functions=("FUNC_copy", "FUNC_a", "FUNC_b"),
    )
    expanded_base = replace(
        base,
        member_functions=("FUNC_copy", "FUNC_c", "FUNC_d", "FUNC_e"),
    )

    assert len(planner._merge_units((base, different_skill))) == 2
    # Intersection=1, union=6: this must not pass a 60% overlap gate.
    assert len(planner._merge_units((expanded_base, insufficient_overlap))) == 2


def test_historical_variant_keys_require_final_confirmation_and_extract_identities() -> None:
    keys = historical_variant_keys(
        [
            {
                "validation_status": "validated",
                "function": " Copy_Record ",
                "entry_function": "HTTP_Entry",
                "location": {"function": "Location_Func"},
                "evidence_pack": {
                    "canonical_sink": "MEMCPY",
                    "root_cause_key": "Bounds/Unchecked Length",
                    "canonical_flow": {"function_uid": "FUNC_42"},
                },
            },
            {
                "policy_disposition": "confirmed",
                "func_name": "Release_Item",
                "root_cause": "Missing ownership transfer",
            },
            {
                "policy_disposition": "needs_review",
                "model_verdict": "verified",
                "function": "Must_Not_Count",
            },
            {
                "validation_status": "rejected",
                "status": "confirmed",
                "function": "Conflicting_Status_Must_Not_Count",
            },
        ]
    )

    assert {
        "copy_record",
        "http_entry",
        "location_func",
        "memcpy",
        "bounds/unchecked length",
        "func_42",
        "release_item",
        "missing ownership transfer",
    }.issubset(keys)
    assert "must_not_count" not in keys
    assert "conflicting_status_must_not_count" not in keys


def test_coordinator_forwards_historical_variants_into_locked_risk_score(tmp_path) -> None:
    semantic_map = _semantic_map()
    profile = resolve_discovery_profile(
        type("Config", (), {"scan": type("S", (), {"depth": "balanced"})()})()
    )
    ledger = CandidateLedger(project_id="demo", revision="rev")
    planned_map, _state = ActiveDiscoveryCoordinator(
        profile=profile,
        store=SQLiteSecurityMapStore(tmp_path / "history.db"),
        registrar=CandidateRegistrar(ledger),
        report_runner=None,
    ).run(semantic_map, known_variant_keys={"copy"})

    assert len(planned_map.audit_units) == 1
    assert "known_variant_history=+35" in planned_map.audit_units[0].risk_reasons


def test_audit_unit_fingerprint_tracks_dependency_contract_fingerprint() -> None:
    semantic_map = _semantic_map()
    profile = resolve_discovery_profile(
        type("Config", (), {"scan": type("S", (), {"depth": "balanced"})()})()
    )
    record = semantic_map.functions[0]
    first_record = replace(
        record,
        backend_coverage={**record.backend_coverage, "dependency_fingerprint": "dep-a"},
    )
    second_record = replace(
        record,
        backend_coverage={**record.backend_coverage, "dependency_fingerprint": "dep-b"},
    )

    first = CoverageGapPlanner(profile).plan(replace(semantic_map, functions=(first_record,)))[0]
    second = CoverageGapPlanner(profile).plan(replace(semantic_map, functions=(second_record,)))[0]

    assert first.fingerprint != second.fingerprint


@pytest.mark.parametrize("signal,weight", list(AUDIT_RISK_WEIGHTS.items()))
def test_audit_risk_weights_are_exact_and_auditable(signal, weight) -> None:
    score, reasons = audit_unit_risk_score(**{signal: True})
    assert score == weight
    assert reasons == [f"{signal}=+{weight}"]


def test_prompt_projection_is_candidate_rule_and_verdict_blind() -> None:
    semantic_map = _semantic_map()
    profile = resolve_discovery_profile(
        type("Config", (), {"scan": type("S", (), {"depth": "balanced"})()})()
    )
    unit = CoverageGapPlanner(profile).plan(semantic_map)[0]
    projection = candidate_blind_prompt_projection(semantic_map, unit)
    serialized = json.dumps(projection, ensure_ascii=False, sort_keys=True).lower()

    assert "rule_secret" not in serialized
    assert "rule_id" not in serialized
    assert "candidate_desert" not in serialized
    assert "risk_score" not in serialized
    assert "coverage_gap" not in serialized
    assert projection["allowed_evidence_refs"] == ["source:src/demo.c:12"]


def test_prompt_projection_scrubs_outcome_payload_hidden_in_scalar_values() -> None:
    semantic_map = _semantic_map()
    record = replace(
        semantic_map.functions[0],
        backend_coverage={
            "notes": "RULE_SECRET candidate=CAND_123 benchmark ground_truth verdict=confirmed"
        },
    )
    semantic_map = replace(semantic_map, functions=(record,))
    profile = resolve_discovery_profile(
        type("Config", (), {"scan": type("S", (), {"depth": "balanced"})()})()
    )
    unit = CoverageGapPlanner(profile).plan(semantic_map)[0]

    projection = candidate_blind_prompt_projection(semantic_map, unit)
    serialized = json.dumps(projection, ensure_ascii=False, sort_keys=True).lower()

    assert "rule_secret" not in serialized
    assert "cand_123" not in serialized
    assert "ground_truth" not in serialized
    assert projection["functions"][0]["backend_coverage"]["notes"] == ("[redacted-sensitive-value]")
    with pytest.raises(ValueError, match="forbidden value"):
        assert_candidate_blind_projection(
            {"notes": "RULE_SECRET candidate=CAND_123 benchmark ground_truth verdict=confirmed"}
        )


def test_prompt_projection_hard_caps_initial_context() -> None:
    semantic_map = _semantic_map()
    profile = resolve_discovery_profile(
        type("Config", (), {"scan": type("S", (), {"depth": "balanced"})()})()
    )
    unit = CoverageGapPlanner(profile).plan(semantic_map)[0]
    projection = candidate_blind_prompt_projection(semantic_map, unit)
    projection["functions"][0]["callees"] = ["callee_" + ("x" * 500)] * 1000

    fitted = fit_candidate_blind_prompt_projection(projection, max_tokens=24_000)

    assert fitted["projection_truncated"] is True
    assert fitted["projection_estimated_tokens"] <= 24_000


def test_discovery_hypothesis_only_enters_ledger_as_open_obligation(tmp_path) -> None:
    semantic_map = _semantic_map()
    profile = resolve_discovery_profile(
        type("Config", (), {"scan": type("S", (), {"depth": "balanced"})()})()
    )
    ledger = CandidateLedger(project_id="demo", project_root=str(tmp_path), revision="rev")
    registrar = CandidateRegistrar(
        ledger,
        project_id="demo",
        project_root=str(tmp_path),
        revision="rev",
        run_id="run",
    )
    store = SQLiteSecurityMapStore(tmp_path / "security-map.db")

    def runner(projection, _profile):
        unit = CoverageGapPlanner(profile).plan(semantic_map)[0]
        assert projection["audit_unit"]["unit_id"] == unit.unit_id
        return _report_payload(unit)

    planned_map, state = ActiveDiscoveryCoordinator(
        profile=profile,
        store=store,
        registrar=registrar,
        report_runner=runner,
    ).run(semantic_map, export_path=tmp_path / "security-map.json")

    assert len(planned_map.audit_units) == 1
    assert state["status"] == "complete"
    assert state["security_map_coverage"] == planned_map.coverage
    assert state["hypothesis_count"] == 1
    assert state["new_validation_group_count"] == 1
    [record] = ledger.records()
    assert record.record_role == "validation_obligation"
    assert record.status == "queued"
    assert record.disposition == ""
    assert record.ticket.evidence["candidate_payload"]["discovery_status"] == "hypothesis"
    assert record.ticket.evidence["candidate_payload"]["rollout_visibility"] == "active"
    attribution = record.ticket.evidence["candidate_payload"]["attribution"]
    assert attribution["discovered_by"] == ["llm_active_discovery"]
    assert attribution["decided_by"] == "unresolved"
    assert attribution["decision_level"] == "none"
    assert attribution["discovery_details"][0]["unit_id"] == planned_map.audit_units[0].unit_id

    # The report is cached by the semantic unit fingerprint; a second run
    # must not call the model again.
    def should_not_run(*_args):
        raise AssertionError("cached discovery report should be reused")

    _map, cached_state = ActiveDiscoveryCoordinator(
        profile=profile,
        store=store,
        registrar=registrar,
        report_runner=should_not_run,
    ).run(semantic_map)
    assert cached_state["cached_report_count"] == 1
    assert cached_state["attempted_unit_count"] == 0


def test_discovery_shadow_marks_hypotheses_promotion_ineligible(tmp_path) -> None:
    semantic_map = _semantic_map()
    profile = resolve_discovery_profile(
        type("Config", (), {"scan": type("S", (), {"depth": "balanced"})()})()
    )
    unit = CoverageGapPlanner(profile).plan(semantic_map)[0]
    ledger = CandidateLedger(project_id="demo", revision="rev")

    _planned, state = ActiveDiscoveryCoordinator(
        profile=profile,
        store=SQLiteSecurityMapStore(tmp_path / "shadow-map.db"),
        registrar=CandidateRegistrar(ledger),
        report_runner=lambda *_args: _report_payload(unit),
        visibility_mode="shadow",
        rollout_stage="semantic_shadow",
    ).run(semantic_map)

    [record] = ledger.records()
    payload = record.ticket.evidence["candidate_payload"]
    assert state["visibility_mode"] == "shadow"
    assert state["rollout_stage"] == "semantic_shadow"
    assert payload["rollout_visibility"] == "shadow"
    assert payload["candidate_promotion_eligible"] is False
    assert payload["candidate_promotion_terminal_status"] == "shadow_observation"


def test_empty_discovery_cache_requires_complete_coverage_without_unknowns(tmp_path) -> None:
    semantic_map = _semantic_map()
    profile = resolve_discovery_profile(
        type("Config", (), {"scan": type("S", (), {"depth": "balanced"})()})()
    )
    unit = CoverageGapPlanner(profile).plan(semantic_map)[0]
    payload = _report_payload(unit)
    payload["coverage_status"] = "partial"
    payload["hypotheses"] = []
    payload["unresolved_facts"] = ["callee contract unknown"]
    store = SQLiteSecurityMapStore(tmp_path / "negative-cache.db")
    store.save_discovery_report(DiscoveryReport.from_dict(payload))
    calls = []

    def runner(_projection, _profile):
        calls.append(True)
        fresh = dict(payload)
        fresh["coverage_status"] = "complete"
        fresh["unresolved_facts"] = []
        return fresh

    _map, state = ActiveDiscoveryCoordinator(
        profile=profile,
        store=store,
        registrar=CandidateRegistrar(CandidateLedger(project_id="demo", revision="rev")),
        report_runner=runner,
    ).run(semantic_map)

    assert calls == [True]
    assert state["cached_report_count"] == 0
    assert state["completed_report_count"] == 1


def test_discovery_report_rejects_extra_fields_and_hallucinated_evidence(tmp_path) -> None:
    semantic_map = _semantic_map()
    profile = resolve_discovery_profile(
        type("Config", (), {"scan": type("S", (), {"depth": "balanced"})()})()
    )
    unit = CoverageGapPlanner(profile).plan(semantic_map)[0]
    extra = _report_payload(unit)
    extra["verdict"] = "confirmed"
    with pytest.raises(ValueError, match="unknown field"):
        DiscoveryReport.from_dict(extra)

    ledger = CandidateLedger(project_id="demo", revision="rev")
    coordinator = ActiveDiscoveryCoordinator(
        profile=profile,
        store=SQLiteSecurityMapStore(tmp_path / "invalid.db"),
        registrar=CandidateRegistrar(ledger),
        report_runner=lambda _projection, _profile: _report_payload(
            unit, evidence_ref="fabricated:evidence"
        ),
    )
    _map, state = coordinator.run(semantic_map)
    assert state["status"] == "failed"
    assert ledger.records() == []
    assert "unknown positive evidence" in state["failures"][0]["reason"]


def test_coordinator_defensively_rejects_hypothesis_without_flow_or_resource(tmp_path) -> None:
    semantic_map = _semantic_map()
    profile = resolve_discovery_profile(
        type("Config", (), {"scan": type("S", (), {"depth": "balanced"})()})()
    )
    unit = CoverageGapPlanner(profile).plan(semantic_map)[0]
    projection = candidate_blind_prompt_projection(semantic_map, unit)
    report = SimpleNamespace(
        unit_id=unit.unit_id,
        unit_fingerprint=unit.fingerprint,
        reviewed_function_uids=("FUNC_copy",),
        reviewed_claim_ids=("CLAIM_copy", "CLAIM_external"),
        tool_evidence_refs=(),
        hypotheses=(
            SimpleNamespace(
                function="FUNC_copy",
                source=" ",
                sink="",
                resource="\t",
                positive_evidence_refs=("source:src/demo.c:12",),
                negative_evidence_refs=(),
            ),
        ),
    )
    coordinator = ActiveDiscoveryCoordinator(
        profile=profile,
        store=SQLiteSecurityMapStore(tmp_path / "invalid-subject.db"),
        registrar=CandidateRegistrar(CandidateLedger(project_id="demo", revision="rev")),
        report_runner=None,
    )

    with pytest.raises(ValueError, match="requires source and sink or a resource"):
        coordinator._validate_report(report, unit, projection)


def test_shared_registrar_strips_spoofed_confirmed_status(tmp_path) -> None:
    ledger = CandidateLedger(project_id="demo", project_root=str(tmp_path), revision="rev")
    issue = {
        "id": "HYP_spoof",
        "defect_class": "bounds",
        "impact_level": "high",
        "confidence": 0.8,
        "function": "copy",
        "location": "src/demo.c:12",
        "source": "src",
        "sink": "memcpy",
        "description": "hypothesis",
        "status": "confirmed",
        "verdict": "confirmed",
        "confirmed": True,
        "positive_evidence": ["source:src/demo.c:12"],
        "entry_paths": [["entry", "copy"]],
    }
    CandidateRegistrar(ledger, project_root=str(tmp_path)).register_issues(
        [issue],
        source="active_discovery",
        force_unconfirmed=True,
    )
    [record] = ledger.records()
    assert record.disposition == ""
    assert record.status == "queued"
    payload = record.ticket.evidence["candidate_payload"]
    assert payload["candidate_disposition"] == "needs_review"
    assert "confirmed" not in payload
    assert "verdict" not in payload
    assert payload["attribution"] == {
        "schema_version": "zscope.finding-attribution.v1",
        "discovered_by": ["llm_active_discovery"],
        "discovery_details": [{"kind": "llm_active_discovery", "source_id": "HYP_spoof"}],
        "decided_by": "unresolved",
        "decision_level": "none",
        "decision_details": {},
    }


@pytest.mark.parametrize("schema_version", [None, "zscope.finding-attribution.v0"])
def test_shared_registrar_rejects_unversioned_or_wrong_explicit_attribution(
    tmp_path, schema_version
) -> None:
    ledger = CandidateLedger(project_id="demo", project_root=str(tmp_path), revision="rev")
    attribution = {
        "discovered_by": ["llm_active_discovery"],
        "discovery_details": [],
        "decided_by": "unresolved",
        "decision_level": "none",
    }
    if schema_version is not None:
        attribution["schema_version"] = schema_version
    issue = {
        "id": "HYP_invalid_attribution",
        "candidate_source": "active_discovery",
        "defect_class": "bounds",
        "function": "copy",
        "location": "src/demo.c:12",
        "description": "hypothesis",
        "entry_paths": [["entry", "copy"]],
        "attribution": attribution,
    }

    with pytest.raises(ValueError, match="invalid candidate attribution: schema_version"):
        CandidateRegistrar(ledger, project_root=str(tmp_path)).register_issues(
            [issue], source="active_discovery", force_unconfirmed=True
        )

    assert ledger.records() == []


def test_shared_registrar_merges_discovery_attribution_as_sets(tmp_path) -> None:
    ledger = CandidateLedger(project_id="demo", project_root=str(tmp_path), revision="rev")
    registrar = CandidateRegistrar(ledger, project_root=str(tmp_path))
    base = {
        "id": "HYP_same",
        "defect_class": "bounds",
        "function": "copy",
        "location": "src/demo.c:12",
        "source": "src",
        "sink": "memcpy",
        "description": "hypothesis",
        "entry_paths": [["entry", "copy"]],
        "attribution": {
            "schema_version": "zscope.finding-attribution.v1",
            "discovered_by": ["llm_active_discovery"],
            "discovery_details": [{"kind": "llm_active_discovery", "source_id": "AUDIT_A"}],
            "decided_by": "unresolved",
            "decision_level": "none",
        },
    }
    registrar.register_issues([dict(base)], source="active_discovery", force_unconfirmed=True)
    second = dict(base)
    second["attribution"] = {
        **base["attribution"],
        "discovered_by": ["llm_active_discovery", "backend_signal"],
        "discovery_details": [{"kind": "backend_signal", "source_id": "SVF_A"}],
    }
    registrar.register_issues([second], source="active_discovery", force_unconfirmed=True)

    [record] = ledger.records()
    attribution = record.ticket.evidence["candidate_payload"]["attribution"]
    assert attribution["discovered_by"] == ["llm_active_discovery", "backend_signal"]
    assert len(attribution["discovery_details"]) == 2


def test_semantic_enricher_validates_applies_and_caches_llm_delta(tmp_path) -> None:
    semantic_map = _semantic_map()
    profile = resolve_discovery_profile(
        type("Config", (), {"scan": type("S", (), {"depth": "balanced"})()})()
    )
    unit = CoverageGapPlanner(profile).plan(semantic_map)[0]
    store = SQLiteSecurityMapStore(tmp_path / "semantic-delta.db")
    calls = []

    def runner(projection, _profile):
        calls.append(projection["audit_unit"]["unit_id"])
        return {
            "schema_version": SEMANTIC_CLAIM_DELTA_SCHEMA_VERSION,
            "unit_id": unit.unit_id,
            "unit_fingerprint": unit.fingerprint,
            "claims": [
                {
                    "schema_version": "zscope.semantic_claim.v1",
                    "claim_id": "CLAIM_llm_capacity",
                    "subject_uid": "FUNC_copy",
                    "kind": "bounds_contract",
                    "value": {"capacity_relation": "not_proven"},
                    "locations": [{"file": "src/demo.c", "line": 12}],
                    "evidence_refs": ["source:src/demo.c:12"],
                    "origin": "llm",
                    "confidence": 0.55,
                    "status": "unknown",
                }
            ],
            "unknowns": [
                {
                    "unknown_id": "UNKNOWN_capacity",
                    "subject_uid": "FUNC_copy",
                    "kind": "destination_capacity",
                    "reason": "No capacity fact is present in the bounded projection.",
                    "evidence_refs": ["source:src/demo.c:12"],
                }
            ],
            "unresolved_facts": ["destination_capacity"],
        }

    enricher = SemanticMapEnricher(
        profile=profile,
        store=store,
        model_identity="glm-5.1",
        user_semantics_fingerprint="overlay-a",
        report_runner=runner,
        mode="active",
    )
    enriched, state, deltas = enricher.enrich(semantic_map, [unit])

    assert calls == [unit.unit_id]
    assert state["applied"] is True
    assert state["claim_count"] == 1
    assert len(deltas) == 1
    assert {claim.claim_id for claim in enriched.claims} >= {
        "CLAIM_copy",
        "CLAIM_llm_capacity",
    }
    assert {unknown.unknown_id for unknown in enriched.unknowns} == {"UNKNOWN_capacity"}

    cached, cached_state, _cached_deltas = SemanticMapEnricher(
        profile=profile,
        store=store,
        model_identity="glm-5.1",
        user_semantics_fingerprint="overlay-a",
        report_runner=lambda *_args: pytest.fail("semantic delta cache was not used"),
        mode="shadow",
    ).enrich(semantic_map, [unit])
    assert cached is semantic_map
    assert cached_state["cached_delta_count"] == 1
    assert cached_state["attempted_unit_count"] == 0

    key = SemanticMapEnricher.cache_key(
        unit,
        model_identity="glm-5.1",
        user_semantics_fingerprint="overlay-a",
    )
    assert store.load_semantic_delta(key) is not None
    assert "rule" not in key


def test_semantic_enricher_marks_units_without_client_or_cache_uncovered(tmp_path) -> None:
    semantic_map = _semantic_map()
    profile = resolve_discovery_profile(
        type("Config", (), {"scan": type("S", (), {"depth": "balanced"})()})()
    )
    unit = CoverageGapPlanner(profile).plan(semantic_map)[0]

    _result_map, state, deltas = SemanticMapEnricher(
        profile=profile,
        store=SQLiteSecurityMapStore(tmp_path / "semantic-no-client.db"),
        model_identity="glm-5.1",
        user_semantics_fingerprint="",
        report_runner=None,
        mode="active",
    ).enrich(semantic_map, [unit])

    assert deltas == ()
    assert state["status"] == "partial"
    assert state["uncovered_unit_ids"] == [unit.unit_id]


def test_semantic_claim_delta_rejects_non_llm_origin() -> None:
    semantic_map = _semantic_map()
    claim = semantic_map.claims[0].to_dict()
    payload = {
        "schema_version": SEMANTIC_CLAIM_DELTA_SCHEMA_VERSION,
        "unit_id": "AUDIT_1",
        "unit_fingerprint": "f" * 64,
        "claims": [claim],
        "unknowns": [],
        "unresolved_facts": [],
    }
    with pytest.raises(ValueError, match="origin=llm"):
        SemanticClaimDelta.from_dict(payload)
