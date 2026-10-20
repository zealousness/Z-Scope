import json
from dataclasses import replace
from types import SimpleNamespace

import pytest

from zscope.orchestration.active_discovery import (
    ActiveDiscoveryCoordinator,
    CoverageGapPlanner,
    candidate_blind_prompt_projection,
    resolve_discovery_profile,
)
from zscope.orchestration.candidates import CandidateLedger, CandidateRegistrar
from zscope.orchestration.investigation import (
    InvestigationError,
    InvestigationIdentity,
    InvestigationRequest,
    InvestigationResult,
    InvestigationSession,
    SourceScope,
)
from zscope.semantics.security_map import (
    DiscoveryHypothesis,
    DiscoveryReport,
    FunctionSecurityRecord,
    SecurityEvent,
    SecuritySemanticMap,
    SQLiteSecurityMapStore,
)
from zscope.tools.runtime import ToolsRuntime
from zscope.tools.source_access import ProjectSourceAccess


@pytest.fixture
def case(tmp_path, monkeypatch):
    path = tmp_path / "src" / "demo.c"
    path.parent.mkdir()
    path.write_text(
        "void copy(char *src) {\n  char dst[2];\n  memcpy(dst, src, 8);\n}\n", encoding="utf-8"
    )
    access = ProjectSourceAccess(tmp_path)
    revision = access.read("src/demo.c")[1]
    identity = InvestigationIdentity(
        "demo", "rev", None, "tools-v1", "rules-v1", "prompt-v1", "fake", "blind-v1"
    )
    scope = SourceScope("FUNC_copy", "src/demo.c", 1, 4, revision)
    event = SecurityEvent(
        "EVT_copy",
        "memory_bounds",
        "copy_or_length_sink",
        "FUNC_copy",
        "src/demo.c",
        3,
        "memcpy(dst, src, 8)",
        "source:src/demo.c:3",
    )
    record = FunctionSecurityRecord(
        function_uid="FUNC_copy",
        index_name="copy@src/demo.c:1-4",
        function_name="copy",
        file_path="src/demo.c",
        start_line=1,
        end_line=4,
        signature="void copy(char *src)",
        code_hash=revision,
        entry_identities=("entry",),
        entry_paths=(("entry", "copy"),),
        callees=(),
        unresolved_callees=(),
        events=(event,),
        backend_coverage={"backend": "clang", "call_graph_observed": True},
        diff_focus={"risk_score": 100},
    )
    semantic_map = SecuritySemanticMap(
        "demo", "rev", "balanced", (record,), (), (), (), {}, {"builder": "test"}
    )
    profile = replace(
        resolve_discovery_profile(SimpleNamespace(scan=SimpleNamespace(depth="balanced"))),
        risk_threshold=0,
    )
    unit = CoverageGapPlanner(profile).plan(semantic_map)[0]
    projection = candidate_blind_prompt_projection(semantic_map, unit)
    runtime = ToolsRuntime(
        SimpleNamespace(project_root=tmp_path, exclude_paths=[], _index_epoch=0),
        SimpleNamespace(snapshot_dir=tmp_path / ".snapshots"),
        access_profile="candidate_blind",
    )
    monkeypatch.setattr(
        runtime._tools_by_name["search_code"].catalog,
        "snapshot",
        lambda: pytest.fail("index initialized"),
    )
    current = [identity]

    def session(**kwargs):
        options = dict(
            identity=current[0],
            current_identity=lambda: current[0],
            unit=unit,
            projection=projection,
            source_access=access,
            scopes=(scope,),
            execute_tool=runtime.execute_tool,
        )
        options.update(kwargs)
        return InvestigationSession(**options)

    return SimpleNamespace(
        root=tmp_path,
        path=path,
        access=access,
        identity=identity,
        scope=scope,
        semantic_map=semantic_map,
        profile=profile,
        unit=unit,
        projection=projection,
        runtime=runtime,
        current=current,
        session=session,
    )


def search(scope="text", query="memcpy"):
    return InvestigationRequest(
        "search_code", "FUNC_copy", {"scope": scope, "query": query, "path_prefix": "src/demo.c"}
    )


def read(line=3):
    return InvestigationRequest(
        "read_code", "FUNC_copy", {"file_path": "src/demo.c", "start_line": line, "end_line": line}
    )


def report(case, refs, *, function="FUNC_copy", coverage="partial", location="src/demo.c:3"):
    hypothesis = DiscoveryHypothesis(
        hypothesis_id="HYP_copy",
        defect_class="out_of_bounds_copy",
        impact_level="high",
        confidence=0.8,
        function=function,
        location=location,
        source="src",
        sink="memcpy",
        resource="dst",
        entry_paths=(("entry", "copy"),),
        path_conditions=(),
        positive_evidence_refs=tuple(refs),
        negative_evidence_refs=(),
        missing_fact_kinds=("caller_preconditions",),
        description="Copy requires bounds review.",
        reasoning="Source observations only.",
        root_cause="Unchecked copy.",
    )
    return DiscoveryReport(
        case.unit.unit_id,
        case.unit.fingerprint,
        coverage,
        (function,),
        (),
        tuple(refs),
        (hypothesis,),
        ("caller_preconditions",),
    )


def coordinator(case, **kwargs):
    return ActiveDiscoveryCoordinator(
        profile=case.profile,
        store=SQLiteSecurityMapStore(case.root / "map.db"),
        registrar=CandidateRegistrar(CandidateLedger(project_id="demo", revision="rev")),
        **kwargs,
    )


@pytest.mark.parametrize("search_scope,query", [("text", "memcpy"), ("files", "demo.c")])
def test_real_search_then_read_forms_hypothesis_without_index_or_llm(case, search_scope, query):
    session = case.session()
    first = session.query(search(search_scope, query))
    second = session.query(read())
    assert first["evidence_ref"] != second["evidence_ref"]
    assert first["kind"] == "text_location"
    assert second["kind"] == "source_text"
    assert second["data"]["code"] == "3 |   memcpy(dst, src, 8);\n"
    assert not second["proof_authority"]
    unit_before = case.unit.to_dict()
    coord = coordinator(case)
    result = report(case, [first["evidence_ref"], second["evidence_ref"]])
    coord._validate_report(result, case.unit, case.projection, session)
    issues = coord._hypothesis_issues(result, case.unit, case.semantic_map, session)
    assert issues[0]["candidate_disposition"] == "needs_review"
    assert issues[0]["evidence_pack"]["investigation"]["identity"]["build_context"] is None
    assert case.unit.to_dict() == unit_before


def test_coordinator_registers_live_refs_but_never_caches_them_as_legacy_report(case):
    def runner(projection, profile):
        session = case.session(projection=projection)
        refs = [session.query(search())["evidence_ref"], session.query(read())["evidence_ref"]]
        return InvestigationResult(report(case, refs), session)

    coord = coordinator(case, report_runner=runner)
    _planned, state = coord.run(case.semantic_map)
    assert state["hypothesis_count"] == 1
    assert state["registered_occurrence_count"] == 1
    assert state["failures"] == []
    assert coord.store.load_discovery_report(case.unit.unit_id, case.unit.fingerprint) is None
    records = coord.registrar.ledger.records()
    assert len(records) == 1
    assert records[0].disposition != "confirmed"


def test_serialized_report_or_manifest_cannot_restore_authority(case):
    session = case.session()
    ref = session.query(read())["evidence_ref"]
    restored = DiscoveryReport.from_dict(json.loads(json.dumps(report(case, [ref]).to_dict())))
    manifest = json.loads(json.dumps(session.manifest()))
    assert not manifest["proof_authority"]
    coord = coordinator(case)
    with pytest.raises(ValueError, match="outside the prompt projection"):
        coord._validate_report(restored, case.unit, case.projection)
    fresh = case.session()
    with pytest.raises(ValueError, match="outside the prompt projection"):
        coord._validate_report(restored, case.unit, case.projection, fresh)
    coord.store.save_discovery_report(restored)
    _planned, state = coord.run(case.semantic_map)
    assert state["registered_occurrence_count"] == 0
    assert state["failures"]


@pytest.mark.parametrize(
    "field,value",
    [
        ("revision", "later"),
        ("project_id", "other"),
        ("build_context", "another-tu"),
        ("rule_version", "new"),
        ("tool_version", "new"),
        ("prompt_version", "new"),
        ("model_identity", "new"),
        ("tool_policy", "new"),
    ],
)
def test_every_identity_component_invalidates_existing_registration(case, field, value):
    session = case.session()
    session.query(read())
    case.current[0] = replace(case.identity, **{field: value})
    with pytest.raises(InvestigationError, match="identity_changed"):
        session.manifest()


def test_source_change_after_first_read_rejects_mixed_version_report(case):
    session = case.session()
    ref = session.query(read())["evidence_ref"]
    case.path.write_text("void replacement(void) {}\n", encoding="utf-8")
    with pytest.raises(InvestigationError, match="source_changed"):
        session.query(read())
    with pytest.raises(InvestigationError, match="source_changed"):
        coordinator(case)._validate_report(report(case, [ref]), case.unit, case.projection, session)


def test_change_during_tool_execution_registers_nothing(case):
    def execute(name, args):
        raw = case.runtime.execute_tool(name, args)
        case.path.write_text("replacement\n", encoding="utf-8")
        return raw

    session = case.session(execute_tool=execute)
    with pytest.raises(InvestigationError, match="source_changed"):
        session.query(read())
    assert session._entries == {}


@pytest.mark.parametrize("query_request", [read(), search()])
def test_source_replaced_in_projection_read_cannot_register(case, monkeypatch, query_request):
    session = case.session()
    original = session._project

    def project(*args):
        result = original(*args)
        case.path.write_text("changed after projection\n", encoding="utf-8")
        return result

    monkeypatch.setattr(session, "_project", project)
    with pytest.raises(InvestigationError, match="source_changed"):
        session.query(query_request)
    assert session._entries == {}


@pytest.mark.parametrize(
    "query_request",
    [
        InvestigationRequest("query_static_findings", "FUNC_copy", {}),
        InvestigationRequest("scan.run", "FUNC_copy", {}),
        InvestigationRequest("shell", "FUNC_copy", {}),
        InvestigationRequest(
            "read_code", "OTHER", {"file_path": "src/demo.c", "start_line": 3, "end_line": 3}
        ),
        InvestigationRequest(
            "read_code", "FUNC_copy", {"file_path": "../secret.c", "start_line": 3, "end_line": 3}
        ),
        InvestigationRequest(
            "read_code", "FUNC_copy", {"file_path": "src/demo.c", "start_line": 1, "end_line": 100}
        ),
        InvestigationRequest(
            "search_code", "FUNC_copy", {"scope": "text", "query": "secret", "path_prefix": ""}
        ),
    ],
)
def test_unregistered_tools_paths_and_ranges_never_execute(case, query_request):
    session = case.session(execute_tool=lambda *_: pytest.fail("forbidden request executed"))
    with pytest.raises(InvestigationError):
        session.query(query_request)


def test_scope_expansion_is_program_owned_bounded_and_unit_remains_immutable(case):
    child_path = case.root / "src" / "helper.c"
    child_path.write_text("void helper(void) {}\n", encoding="utf-8")
    child = SourceScope("FUNC_helper", "src/helper.c", 1, 1, case.access.read("src/helper.c")[1])
    session = case.session(
        authorize_scope=lambda uid: child if uid == child.function_uid else None, max_extensions=1
    )
    with pytest.raises(InvestigationError, match="unregistered_scope"):
        session.query(
            InvestigationRequest(
                "read_code",
                child.function_uid,
                {"file_path": child.file_path, "start_line": 1, "end_line": 1},
            )
        )
    session.extend_scope(child.function_uid)
    item = session.query(
        InvestigationRequest(
            "read_code",
            child.function_uid,
            {"file_path": child.file_path, "start_line": 1, "end_line": 1},
        )
    )
    coordinator(case)._validate_report(
        report(
            case, [item["evidence_ref"]], function=child.function_uid, location="src/helper.c:1"
        ),
        case.unit,
        case.projection,
        session,
    )
    assert case.unit.member_functions == ("FUNC_copy",)
    for location in ("src/demo.c:3", "src/helper.c:2", "src/helper.c:1:0", "src/helper.c:0"):
        with pytest.raises(InvestigationError, match="hypothesis_scope_mismatch"):
            coordinator(case)._validate_report(
                report(
                    case, [item["evidence_ref"]], function=child.function_uid, location=location
                ),
                case.unit,
                case.projection,
                session,
            )
    with pytest.raises(InvestigationError, match="expansion_denied"):
        session.extend_scope("another")


@pytest.mark.parametrize(
    "file,build", [("../outside.c", None), ("GROUND_TRUTH.md", None), ("src/demo.c", "other-tu")]
)
def test_program_scope_still_must_obey_corpus_and_build_identity(case, file, build):
    child = replace(case.scope, function_uid="child", file_path=file, build_context=build)
    session = case.session(authorize_scope=lambda _: child)
    with pytest.raises(InvestigationError, match="scope_identity_mismatch"):
        session.extend_scope("child")


def test_forged_ref_and_partial_complete_report_rejected(case):
    session = case.session()
    item = session.query(read())
    coord = coordinator(case)
    with pytest.raises(ValueError, match="outside the prompt projection"):
        coord._validate_report(
            report(case, ["investigation:forged"]), case.unit, case.projection, session
        )
    with pytest.raises(ValueError, match="partial investigation"):
        coord._validate_report(
            report(case, [item["evidence_ref"]], coverage="complete"),
            case.unit,
            case.projection,
            session,
        )


def test_mutation_of_returned_copy_does_not_change_manifest_but_artifact_tampering_fails(case):
    session = case.session()
    item = session.query(read())
    item["data"]["code"] = "forged"
    manifest = session.manifest()
    assert manifest["entries"][0]["data"]["code"] != "forged"
    artifact = item["artifact_ref"]
    session._artifacts[artifact]["data"]["source"]["code"] = "tampered"
    with pytest.raises(InvestigationError, match="artifact_identity_mismatch"):
        session.manifest()


def test_nested_metadata_never_self_signs_or_leaks(case):
    def execute(name, args):
        raw = case.runtime.execute_tool(name, args)
        raw["metadata"] = {
            "verdict": "CONFIRMED_SECRET",
            "proof": {"source": "user", "verification": {"method": "source_composition"}},
        }
        raw["data"]["suspicious_points"] = ["CONCLUSION_SECRET"]
        return raw

    item = case.session(execute_tool=execute).query(read())
    assert "SECRET" not in json.dumps(item)
    assert item["strength"] == "observation"
    assert item["proof_authority"] is False


def test_fake_tool_cannot_inject_source_or_search_strings(case):
    def execute(name, args):
        raw = case.runtime.execute_tool(name, args)
        if name == "read_code":
            raw["data"]["source"]["code"] = "PRIVATE_CONCLUSION"
        else:
            raw["data"]["matches"][0]["text"] = "PRIVATE_CONCLUSION"
        return raw

    for request in (read(), search()):
        with pytest.raises(InvestigationError, match="content_mismatch"):
            case.session(execute_tool=execute).query(request)


def test_flow_preserves_may_and_rejects_other_tu_or_unknown_build(case):
    symbol = "zs1:function:" + "a" * 24
    scope = replace(case.scope, symbol_id=symbol, build_context="tu-a")
    identity = replace(case.identity, build_context="tu-a")
    case.current[0] = identity
    raw = {
        "status": "ok",
        "coverage": {"level": "complete"},
        "data": {
            "subject": {"symbol_id": symbol},
            "paths": [
                {
                    "classification": "must",
                    "proof": True,
                    "nodes": [
                        {
                            "location": {"file": "src/demo.c", "line": 3},
                            "evidence": {"verdict": "SECRET"},
                        }
                    ],
                }
            ],
        },
    }
    session = case.session(identity=identity, scopes=(scope,), execute_tool=lambda *_: raw)
    request = InvestigationRequest(
        "trace_data_flow",
        "FUNC_copy",
        {
            "symbol_id": symbol,
            "source": {"kind": "variable", "name": "src"},
            "sink": {"kind": "call", "query": "memcpy"},
        },
    )
    item = session.query(request)
    assert item["strength"] == "may" and item["coverage"] == "partial"
    assert item["data"]["paths"][0]["classification"] == "may"
    assert "SECRET" not in json.dumps(item)
    raw["data"]["subject"]["symbol_id"] = "zs1:function:" + "b" * 24
    with pytest.raises(InvestigationError, match="symbol_identity_mismatch"):
        session.query(request)
    case.current[0] = case.identity
    session = case.session(
        scopes=(replace(case.scope, symbol_id=symbol),),
        execute_tool=lambda *_: pytest.fail("no build identity"),
    )
    with pytest.raises(InvestigationError, match="build_identity_unavailable"):
        session.query(request)


@pytest.mark.parametrize("line", ["3", True, 0, 5])
def test_flow_location_requires_strict_in_scope_integer(case, line):
    identity = replace(case.identity, build_context="tu-a")
    case.current[0] = identity
    scope = replace(case.scope, build_context="tu-a", symbol_id="symbol-a")
    session = case.session(
        identity=identity,
        scopes=(scope,),
        execute_tool=lambda *_: pytest.fail("invalid flow executed"),
    )
    with pytest.raises(InvestigationError, match="query_scope_mismatch"):
        session.query(
            InvestigationRequest(
                "trace_data_flow",
                "FUNC_copy",
                {
                    "symbol_id": "symbol-a",
                    "source": {"kind": "location", "file_path": "src/demo.c", "line": line},
                    "sink": {"kind": "return"},
                },
            )
        )


def test_wrong_projection_denied_and_session_close_invalidates_refs(case):
    session = case.session()
    item = session.query(read())
    coord = coordinator(case)
    with pytest.raises(InvestigationError, match="unit_mismatch"):
        coord._validate_report(
            report(case, [item["evidence_ref"]]),
            case.unit,
            {**case.projection, "revision": "other"},
            session,
        )
    session.close()
    with pytest.raises(InvestigationError, match="closed"):
        session.manifest()


def test_evidence_budget_and_frozen_ledger_are_not_bypassed(case):
    session = case.session(max_evidence=1)
    ref = session.query(read())["evidence_ref"]
    with pytest.raises(InvestigationError, match="evidence_budget"):
        session.query(read())
    coord = coordinator(case)
    issues = coord._hypothesis_issues(report(case, [ref]), case.unit, case.semantic_map, session)
    coord.registrar.ledger.freeze()
    with pytest.raises(Exception, match="frozen"):
        coord.registrar.register_issues(issues, source="active_discovery", force_unconfirmed=True)
    assert coord.registrar.ledger.records() == []
