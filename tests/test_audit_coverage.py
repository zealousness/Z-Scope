import hashlib
import json
from dataclasses import replace
from types import SimpleNamespace

import pytest

from zscope.config.function_entry import FunctionEntry
from zscope.orchestration.active_discovery import (
    ActiveDiscoveryCoordinator,
    CoverageGapPlanner,
    candidate_blind_prompt_projection,
    candidate_coverage_keys,
    resolve_discovery_profile,
)
from zscope.orchestration.candidates import CandidateLedger, CandidateRegistrar
from zscope.semantics.security_map import (
    AuditOccurrence,
    AuditUnit,
    CoverageKey,
    DiscoveryHypothesis,
    DiscoveryReport,
    FunctionSecurityRecord,
    SecurityEvent,
    SecuritySemanticMap,
    SemanticClaim,
    SemanticUnknown,
    SQLiteSecurityMapStore,
    ZeroLLMSecurityMapBuilder,
    event_coverage_key,
)


def profile(**kwargs):
    return replace(
        resolve_discovery_profile(SimpleNamespace(scan=SimpleNamespace(depth="balanced"))),
        risk_threshold=0,
        **kwargs,
    )


def sample(*, objects=("p", "q"), entries=("first",), build=None):
    events = tuple(
        SecurityEvent(
            f"EVT_{name}_{i}",
            "resource_lifecycle",
            "resource_transition",
            "FUNC_work",
            "src/demo.c",
            i + 2,
            f"free({name});",
            f"source:src/demo.c:{i + 2}",
            name,
            f"src/demo.c:{i + 2}:token-0",
            build,
        )
        for i, name in enumerate(objects)
    )
    record = FunctionSecurityRecord(
        "FUNC_work",
        "work@src/demo.c:1-9",
        "work",
        "src/demo.c",
        1,
        9,
        "void work(void)",
        "a" * 64,
        tuple(entries),
        tuple((entry, "work") for entry in entries),
        (),
        (),
        events,
        {"backend": "clang", "call_graph_observed": True},
        {"risk_score": 90},
        tuple(
            AuditOccurrence(entry, (entry, "work"), tuple(event.event_id for event in events))
            for entry in entries
        ),
    )
    return SecuritySemanticMap("demo", "rev", "balanced", (record,), (), (), (), {}, {})


def ledger_at(line, *, resource="p", location=None):
    payload = {
        "category": "resource_leak",
        "location": location or f"src/demo.c:{line}",
        "function": "FUNC_work",
        "resource": resource,
    }
    record = SimpleNamespace(
        ticket=SimpleNamespace(skill="resource_lifecycle", evidence={"candidate_payload": payload}),
        defect_class="resource_leak",
    )
    return SimpleNamespace(records=lambda: [record])


def test_two_objects_in_same_file_remain_distinct_with_candidate_at_one_site():
    semantic_map = sample()
    keys = candidate_coverage_keys(ledger_at(2), semantic_map=semantic_map)
    units = CoverageGapPlanner(profile()).plan(semantic_map, covered_keys=keys)
    assert len(units) == 2
    by_object = {unit.coverage_keys[0].object_ref: unit for unit in units}
    assert not by_object["p"].candidate_desert
    assert by_object["q"].candidate_desert
    prompt = json.dumps(candidate_blind_prompt_projection(semantic_map, by_object["q"]))
    assert '"candidate_desert"' not in prompt and '"risk_score"' not in prompt
    assert '"EVT_p_0"' not in prompt


def test_one_site_of_same_object_does_not_cover_other_operation():
    semantic_map = sample(objects=("p", "p"))
    keys = candidate_coverage_keys(ledger_at(2), semantic_map=semantic_map)
    units = CoverageGapPlanner(profile()).plan(semantic_map, covered_keys=keys)
    assert len(units) == 1 and len(units[0].coverage_keys) == 2
    assert units[0].candidate_desert


@pytest.mark.parametrize("location", ["src/demo.c:2:4", "src/demo.c:2"])
def test_location_column_does_not_change_line_match(location):
    semantic_map = sample(objects=("p",))
    keys = candidate_coverage_keys(ledger_at(2, location=location), semantic_map=semantic_map)
    assert len([key for key in keys if key.startswith("coverage:")]) == 1


def test_ambiguous_same_line_and_candidate_authored_build_key_are_not_accepted():
    semantic_map = sample()
    record = semantic_map.functions[0]
    events = tuple(replace(event, line=2) for event in record.events)
    semantic_map = replace(semantic_map, functions=(replace(record, events=events),))
    assert not any(
        key.startswith("coverage:")
        for key in candidate_coverage_keys(ledger_at(2, resource=""), semantic_map=semantic_map)
    )
    known = sample(objects=("p",), build="b" * 64)
    assert not any(
        key.startswith("coverage:")
        for key in candidate_coverage_keys(ledger_at(2), semantic_map=known)
    )


def test_coarse_file_family_presence_does_not_hide_fine_objects():
    units = CoverageGapPlanner(profile()).plan(
        sample(), covered_keys={"family:resource_lifecycle", "family:resource_lifecycle:src/demo.c"}
    )
    assert len(units) == 2 and all(unit.candidate_desert for unit in units)


def test_build_variants_and_unknown_records_do_not_merge():
    semantic_map = sample(objects=("p",), build="b" * 64)
    record = semantic_map.functions[0]
    other_event = replace(
        record.events[0], event_id="EVT_other", function_uid="FUNC_other", build_context="c" * 64
    )
    other = replace(
        record, function_uid="FUNC_other", index_name="work@other-tu", events=(other_event,)
    )
    variants = replace(semantic_map, functions=(record, other))
    units = CoverageGapPlanner(profile()).plan(variants)
    assert len(units) == 2 and len({unit.fingerprint for unit in units}) == 2
    unknown = replace(
        variants,
        functions=tuple(
            replace(item, events=tuple(replace(event, build_context=None) for event in item.events))
            for item in variants.functions
        ),
    )
    units = CoverageGapPlanner(profile()).plan(unknown)
    assert (
        len(units) == 2
        and len({key.scope_discriminator for unit in units for key in unit.coverage_keys}) == 2
    )


@pytest.mark.parametrize("build", ["unknown", "unavailable", "", True, "not-a-context"])
def test_placeholder_build_identities_are_rejected(build):
    with pytest.raises(ValueError):
        CoverageKey("resource_lifecycle", "uid", "p", "src/a.c:1", build, "stable")


def test_unknown_build_discriminator_includes_record_file_signature():
    semantic_map = sample(objects=("p",))
    record = semantic_map.functions[0]
    key = event_coverage_key(semantic_map, record, record.events[0])
    for changed in (
        replace(record, file_path="src/other.c"),
        replace(record, signature="void work(int)"),
    ):
        assert (
            event_coverage_key(semantic_map, changed, record.events[0]).identity() != key.identity()
        )


def test_entry_order_does_not_change_unit_or_occurrence_selection():
    semantic_map = sample(entries=("first", "second"))
    record = semantic_map.functions[0]
    reordered = replace(
        semantic_map,
        functions=(
            replace(
                record,
                entry_identities=tuple(reversed(record.entry_identities)),
                entry_paths=tuple(reversed(record.entry_paths)),
                entry_occurrences=tuple(reversed(record.entry_occurrences)),
            ),
        ),
    )
    assert CoverageGapPlanner(profile(max_units=1)).plan(semantic_map) == CoverageGapPlanner(
        profile(max_units=1)
    ).plan(reordered)


def test_occurrences_for_other_events_are_not_invented_for_this_unit():
    semantic_map = sample(entries=("first", "second"))
    record = semantic_map.functions[0]
    record = replace(
        record,
        entry_occurrences=(
            AuditOccurrence("first", ("first", "work"), (record.events[0].event_id,)),
            AuditOccurrence("second", ("second", "work"), (record.events[1].event_id,)),
        ),
    )
    units = CoverageGapPlanner(profile()).plan(replace(semantic_map, functions=(record,)))
    by_object = {unit.coverage_keys[0].object_ref: unit for unit in units}
    assert {item.entry_identity for item in by_object["p"].occurrences} == {"first"}
    assert {item.entry_identity for item in by_object["q"].occurrences} == {"second"}


def report_for(projection):
    unit = projection["audit_unit"]
    event = projection["functions"][0]["events"][0]
    hypothesis = DiscoveryHypothesis(
        "HYP_resource",
        "resource_leak",
        "high",
        0.7,
        event["function_uid"],
        f"{event['file']}:{event['line']}",
        "",
        "",
        event["object_ref"] or "unknown",
        (),
        (),
        (event["evidence_ref"],),
        (),
        (),
        "Resource obligation needs review.",
        "Source observation.",
        "Missing release fact.",
    )
    return DiscoveryReport(
        unit["unit_id"],
        unit["unit_fingerprint"],
        "partial",
        tuple(unit["member_functions"]),
        (),
        (event["evidence_ref"],),
        (hypothesis,),
        ("caller_precondition",),
    )


def test_shared_object_runs_one_task_preserving_two_ledger_occurrences(tmp_path):
    semantic_map = sample(objects=("p",), entries=("first", "second"))
    calls = []

    def run(projection, _profile):
        calls.append(projection)
        return report_for(projection)

    registrar = CandidateRegistrar(CandidateLedger(project_id="demo", revision="rev"))
    coord = ActiveDiscoveryCoordinator(
        profile=profile(),
        store=SQLiteSecurityMapStore(tmp_path / "map.db"),
        registrar=registrar,
        report_runner=run,
    )
    planned, state = coord.run(semantic_map)
    assert len(calls) == 1 and len(planned.audit_units) == 1
    records = registrar.ledger.records()
    assert len(records) == 1
    assert {item.entry_identity for item in records[0].occurrences} == {"first", "second"}
    assert state["registered_occurrence_count"] == 2
    assert state["coverage_completed_unit_count"] == 0
    assert state["uncovered_unit_ids"] == [planned.audit_units[0].unit_id]


def test_unit_budget_and_risk_exclusion_are_explicit_uncovered_accounts(tmp_path):
    semantic_map = sample()
    planner = CoverageGapPlanner(profile(max_units=1))
    selected = planner.plan(semantic_map)
    assert len(selected) == 1 and len(planner.last_plan["deferred_unit_ids"]) == 1
    assert planner.last_plan["eligible_unit_count"] == 2
    assert planner.last_plan["deferred"][0]["occurrences"]
    low_risk = replace(profile(), risk_threshold=100)
    coord = ActiveDiscoveryCoordinator(
        profile=low_risk,
        store=SQLiteSecurityMapStore(tmp_path / "map.db"),
        registrar=CandidateRegistrar(CandidateLedger(project_id="demo", revision="rev")),
    )
    planned, state = coord.run(semantic_map)
    assert not planned.audit_units and len(state["uncovered_unit_ids"]) == 2
    assert {item["reason"] for item in state["coverage_plan"]["not_selected"]} == {"risk_threshold"}


class Index:
    backend_name = "clang"

    def __init__(self, bodies, callees=None):
        self.bodies = bodies
        self.callees = callees or {}

    def get_function_impl(self, query, **_kwargs):
        name = str(query).split("@", 1)[0]
        code = self.bodies.get(name)
        return (
            None
            if code is None
            else {
                "func_name": name,
                "index_name": name + "@src/demo.c:1-20",
                "file": "src/demo.c",
                "start_line": 1,
                "end_line": 20,
                "signature": name,
                "code": code,
            }
        )

    def get_callees(self, query, limit=None):
        return self.callees.get(str(query).split("@", 1)[0], [])[:limit]


def build(index, entries=("entry",), **kwargs):
    return ZeroLLMSecurityMapBuilder(
        index, project_id="demo", revision="rev", profile="balanced", **kwargs
    ).build([FunctionEntry(name, file_path="src/demo.c") for name in entries])


def test_builder_resolves_lexical_objects_and_keeps_complex_alias_unknown():
    semantic_map = build(
        Index(
            {
                "entry": "void entry(void) {\nchar *p = malloc(8);\nchar *q = malloc(8);\nfree(p);\nfree(q);\nfree(pool[i]);\n}"
            }
        )
    )
    events = [
        event for event in semantic_map.functions[0].events if event.family == "resource_lifecycle"
    ]
    assert {event.object_ref for event in events} == {"p", "q", None}
    units = CoverageGapPlanner(profile()).plan(semantic_map)
    assert len([unit for unit in units if unit.unit_kind == "resource_protocol"]) == 3
    assert any(unknown.kind == "object_alias_unknown" for unknown in semantic_map.unknowns)
    assert all(event.build_context is None for event in events)


def test_member_assignment_is_not_rebound_to_bare_identifier():
    semantic_map = build(
        Index(
            {"entry": "void entry(void) {\nctx->p = malloc(8);\n*p = malloc(8);\nfree(pool[i]);\n}"}
        )
    )
    events = [
        event for event in semantic_map.functions[0].events if event.family == "resource_lifecycle"
    ]
    assert len(events) == 3 and all(event.object_ref is None for event in events)


def test_two_callbacks_on_one_line_retain_exact_targets():
    semantic_map = build(
        Index(
            {
                "entry": "void entry(void) {\nregister_callback(first); register_callback(second);\n}",
                "first": "void first(void) {}",
                "second": "void second(void) {}",
            }
        )
    )
    entry = next(record for record in semantic_map.functions if record.function_name == "entry")
    assert {
        event.callback_target for event in entry.events if event.family == "callback_concurrency"
    } == {"first", "second"}


def test_callback_registration_without_direct_caller_keeps_reachability_hint():
    semantic_map = build(
        Index(
            {
                "entry": "void entry(void) {\nregister_callback(on_ready);\n}",
                "on_ready": "void on_ready(void) {\nfree(p);\n}",
            }
        )
    )
    callback = next(item for item in semantic_map.functions if item.function_name == "on_ready")
    assert callback.entry_occurrences[0].reachability == "callback_registration"
    assert callback.entry_paths == (("entry", "on_ready"),)
    assert any(unknown.kind == "callback_dispatch_unproven" for unknown in semantic_map.unknowns)
    assert any(
        event.callback_target == "on_ready"
        for record in semantic_map.functions
        for event in record.events
    )


def test_unknown_callback_and_traversal_limits_are_not_silent():
    index = Index(
        {
            "entry": "void entry(void) { register_callback(missing); }",
            "worker": "void worker(void) { free(p); }",
        },
        {"entry": [{"name": "worker", "file": "src/demo.c"}]},
    )
    semantic_map = build(index, max_functions=1, callee_limit=1)
    assert semantic_map.coverage["truncated"]
    assert {unknown.kind for unknown in semantic_map.unknowns} >= {
        "unresolved_function",
        "function_budget_deferred",
        "callee_budget_partial",
        "callback_dispatch_unproven",
    }


def legacy_payload(semantic_map):
    raw = semantic_map.to_dict()
    raw["schema_version"] = "zscope.security_semantic_map.v1"
    for record in raw["functions"]:
        record.pop("entry_occurrences")
        for event in record["events"]:
            for key in ("object_ref", "operation_site", "build_context", "callback_target"):
                event.pop(key)
    for unit in raw["audit_units"]:
        unit["schema_version"] = "zscope.audit_unit.v1"
        for key in ("coverage_keys", "occurrences", "migration_status"):
            unit.pop(key)
    hashed = {
        key: raw[key]
        for key in (
            "schema_version",
            "project_id",
            "revision",
            "profile",
            "functions",
            "claims",
            "unknowns",
            "fingerprints",
        )
    }
    raw["map_fingerprint"] = hashlib.sha256(
        json.dumps(hashed, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    ).hexdigest()
    return raw


def test_v1_migration_invalidates_cached_reports_and_remains_unverifiable_on_replan(tmp_path):
    semantic_map = sample(objects=("p",))
    unit = CoverageGapPlanner(profile()).plan(semantic_map)[0]
    original = semantic_map.with_audit_units((unit,))
    legacy = legacy_payload(original)
    migrated = SecuritySemanticMap.from_dict(legacy)
    assert migrated.map_fingerprint != legacy["map_fingerprint"]
    assert migrated.audit_units[0].fingerprint != unit.fingerprint
    assert migrated.audit_units[0].coverage_keys[0].object_ref is None
    assert migrated.coverage["migration_status"] == "legacy_unverifiable"
    replanned = CoverageGapPlanner(profile()).plan(migrated)[0]
    assert replanned.migration_status == "legacy_unverifiable"
    coord = ActiveDiscoveryCoordinator(
        profile=profile(),
        store=SQLiteSecurityMapStore(tmp_path / "map.db"),
        registrar=CandidateRegistrar(CandidateLedger(project_id="demo", revision="rev")),
    )
    assert coord._load_cached(replanned) is None
    raw_report = replace(
        report_for(candidate_blind_prompt_projection(migrated, replanned)),
        coverage_status="complete",
    )
    with pytest.raises(ValueError, match="legacy"):
        coord._validate_report(
            raw_report, replanned, candidate_blind_prompt_projection(migrated, replanned)
        )
    assert SecuritySemanticMap.from_dict(migrated.to_dict()) == migrated


def test_v1_original_fingerprint_and_v2_extra_fields_are_strict():
    raw = legacy_payload(sample())
    raw["functions"][0]["file_path"] = "tampered.c"
    with pytest.raises(ValueError, match="fingerprint mismatch"):
        SecuritySemanticMap.from_dict(raw)
    unit = CoverageGapPlanner(profile()).plan(sample())[0].to_dict()
    unit["coverage_keys"][0]["self_proved"] = True
    with pytest.raises(ValueError, match="unknown field"):
        AuditUnit.from_dict(unit)


def test_mixed_nested_schema_cannot_hide_legacy_metadata():
    semantic_map = sample(objects=("p",))
    units = CoverageGapPlanner(profile()).plan(semantic_map)
    raw = semantic_map.with_audit_units(units).to_dict()
    raw["audit_units"][0]["schema_version"] = "zscope.audit_unit.v1"
    with pytest.raises(ValueError, match="mixed"):
        SecuritySemanticMap.from_dict(raw)


def test_legacy_marker_cannot_be_removed_from_unhashed_coverage():
    migrated = SecuritySemanticMap.from_dict(legacy_payload(sample()))
    raw = migrated.to_dict()
    raw["coverage"].pop("migration_status")
    with pytest.raises(ValueError, match="marker mismatch"):
        SecuritySemanticMap.from_dict(raw)
    in_memory = replace(migrated, coverage={})
    assert all(
        unit.migration_status == "legacy_unverifiable"
        for unit in CoverageGapPlanner(profile()).plan(in_memory)
    )


def test_same_record_same_object_same_site_different_builds_remain_distinct():
    semantic_map = sample(objects=("p",), build="b" * 64)
    record = semantic_map.functions[0]
    event = record.events[0]
    other = replace(event, event_id="EVT_other_build", build_context="c" * 64)
    semantic_map = replace(semantic_map, functions=(replace(record, events=(event, other)),))
    units = CoverageGapPlanner(profile()).plan(semantic_map)
    assert len(units) == 2
    assert {unit.coverage_keys[0].build_context for unit in units} == {"b" * 64, "c" * 64}
    assert len({unit.fingerprint for unit in units}) == 2


def test_builder_preserves_shared_function_routes_at_function_budget_boundary():
    index = Index(
        {
            "first": "void first(void) { work(); }",
            "second": "void second(void) { work(); }",
            "work": "void work(void) {\nfree(p);\n}",
        },
        {name: [{"name": "work", "file": "src/demo.c"}] for name in ("first", "second")},
    )
    before = build(index, entries=("first", "second"), max_functions=3)
    after = build(index, entries=("second", "first"), max_functions=3)
    assert before.map_fingerprint == after.map_fingerprint
    worker = next(record for record in before.functions if record.function_name == "work")
    assert {item.entry_path for item in worker.entry_occurrences} == {
        ("first", "work"),
        ("second", "work"),
    }
    units = [
        unit
        for unit in CoverageGapPlanner(profile()).plan(before)
        if unit.unit_kind == "resource_protocol"
    ]
    assert len(units) == 1 and len(units[0].occurrences) == 2


def test_deep_no_event_and_coarse_merge_preserve_legacy_status_and_occurrences():
    semantic_map = sample(objects=())
    uid = semantic_map.functions[0].function_uid
    claim = SemanticClaim(
        "CLAIM",
        uid,
        "resource_transition",
        {},
        (),
        ("source:src/demo.c:2",),
        "program",
        1.0,
        "unknown",
    )
    unknown = SemanticUnknown("UNKNOWN", uid, "alias", "Unknown object", ("source:src/demo.c:2",))
    migrated = SecuritySemanticMap.from_dict(
        legacy_payload(replace(semantic_map, claims=(claim,), unknowns=(unknown,)))
    )
    deep = replace(profile(), name="deep")
    planner = CoverageGapPlanner(deep)
    unit = planner.plan(migrated)[0]
    assert unit.migration_status == "legacy_unverifiable" and unit.claim_refs == ("CLAIM",)
    assert unit.occurrences
    second = replace(
        unit,
        unit_id="second",
        fingerprint="second",
        occurrences=(AuditOccurrence("other", ("other",), (), "legacy_unknown"),),
    )
    merged = planner._merge_units((unit, second))[0]
    assert merged.migration_status == "legacy_unverifiable"
    assert {item.entry_identity for item in merged.occurrences} == {"first", "other"}
