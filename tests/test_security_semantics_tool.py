from zscope.orchestration.active_discovery import CoverageGapPlanner, resolve_discovery_profile
from zscope.semantics.security_map import (
    FunctionSecurityRecord,
    SecurityEvent,
    SecuritySemanticMap,
    SemanticClaim,
    SQLiteSecurityMapStore,
)
from zscope.tools.registry import build_tool_registry
from zscope.tools.security_semantics import GetSecuritySemanticsTool


def _semantic_map():
    event = SecurityEvent(
        event_id="EVT_copy",
        family="memory_bounds",
        kind="copy_or_length_sink",
        function_uid="FUNC_copy",
        file="src/demo.c",
        line=12,
        expression="memcpy(dst, src, len);",
        evidence_ref="source:src/demo.c:12",
    )
    record = FunctionSecurityRecord(
        function_uid="FUNC_copy",
        index_name="copy@src/demo.c:10-14",
        function_name="copy",
        file_path="src/demo.c",
        start_line=10,
        end_line=14,
        signature="void copy(void)",
        code_hash="a" * 64,
        entry_identities=("entry",),
        entry_paths=(("entry", "copy"),),
        callees=(),
        unresolved_callees=(),
        events=(event,),
        backend_coverage={"backend": "clang", "call_graph_observed": True},
        diff_focus={"risk_score": 80},
    )
    claim = SemanticClaim(
        claim_id="CLAIM_external",
        subject_uid="FUNC_copy",
        kind="trust_boundary",
        value={"externally_exposed": True},
        locations=({"file": "src/demo.c", "line": 10},),
        evidence_refs=("source:src/demo.c:12",),
        origin="program",
        confidence=1.0,
        status="known",
    )
    return SecuritySemanticMap(
        project_id="demo",
        revision="rev",
        profile="balanced",
        functions=(record,),
        claims=(claim,),
        unknowns=(),
        audit_units=(),
        coverage={"reachable_function_count": 1, "llm_calls": 0},
        fingerprints={"builder": "test"},
    )


def test_security_semantics_tool_is_read_only_bounded_and_queryable(tmp_path) -> None:
    semantic_map = _semantic_map()
    profile = resolve_discovery_profile(
        type("Config", (), {"scan": type("S", (), {"depth": "balanced"})()})()
    )
    semantic_map = semantic_map.with_audit_units(CoverageGapPlanner(profile).plan(semantic_map))
    db_path = tmp_path / "security_map.db"
    SQLiteSecurityMapStore(db_path).save_map(semantic_map)
    tool = GetSecuritySemanticsTool(db_path)

    result = tool.execute({"kind": "function", "query": "copy", "limit": 1})
    assert result["success"] is True
    assert result["data"]["coverage"] == semantic_map.coverage
    assert result["data"]["total_matches"] == 1
    assert result["data"]["records"][0]["function_uid"] == "FUNC_copy"

    rejected = tool.execute({"kind": "claim", "limit": 51})
    assert rejected["success"] is False
    schema = tool.get_schema()["function"]["parameters"]
    assert schema["additionalProperties"] is False
    assert "edit" not in schema["properties"]


def test_builtin_registry_contains_security_semantics_read_tool(tmp_path) -> None:
    class SnapshotStoreStub:
        snapshot_dir = tmp_path

    registry = build_tool_registry(
        code_index=object(),
        snapshot_store=SnapshotStoreStub(),
        include_advanced=False,
    )

    assert isinstance(registry["get_security_semantics"], GetSecuritySemanticsTool)
