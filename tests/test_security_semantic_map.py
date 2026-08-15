import json
from dataclasses import replace

import pytest

from zscope.config.function_entry import FunctionEntry
from zscope.semantics.security_map import (
    AUDIT_UNIT_SCHEMA_VERSION,
    DISCOVERY_HYPOTHESIS_JSON_SCHEMA,
    AuditUnit,
    DiscoveryHypothesis,
    SQLiteSecurityMapStore,
    SecuritySemanticMap,
    SemanticClaim,
    ZeroLLMSecurityMapBuilder,
)


class FakeSecurityIndex:
    backend_name = "clang"

    def __init__(self):
        self.impls = {
            "entry": {
                "func_name": "entry",
                "index_name": "entry@src/demo.c:10-15",
                "file": "src/demo.c",
                "start_line": 10,
                "end_line": 15,
                "signature": "int entry(char *input)",
                "entry_exposure": "communication",
                "code": "int entry(char *input) {\nrecv(fd, input, 64, 0);\n(*callback)(input);\nreturn worker(input);\n}",
            },
            "worker": {
                "func_name": "worker",
                "index_name": "worker@src/demo.c:20-24",
                "file": "src/demo.c",
                "start_line": 20,
                "end_line": 24,
                "signature": "int worker(char *input)",
                "code": "int worker(char *input) {\nchar *p = malloc(8);\nstrcpy(p, input);\nfree(p);\nreturn 0;\n}",
            },
        }

    def get_function_impl(self, query, **kwargs):
        if str(query).startswith("int entry") or str(query).startswith("entry@"):
            query = "entry"
        if str(query).startswith("worker@"):
            query = "worker"
        return self.impls.get(str(query))

    def get_callees(self, query, limit=None):
        if str(query).startswith("entry"):
            return [{"name": "worker", "file": "src/demo.c"}]
        return []


def test_zero_llm_security_map_builds_evidence_graph_and_strict_claims() -> None:
    semantic_map = ZeroLLMSecurityMapBuilder(
        FakeSecurityIndex(),
        project_id="demo",
        revision="rev-1",
        profile="balanced",
        semantic_overlay={"resource_models": [{"name": "worker", "release": "free"}]},
    ).build([FunctionEntry("entry", file_path="src/demo.c")])

    assert semantic_map.coverage["llm_calls"] == 0
    assert semantic_map.coverage["reachable_function_count"] == 2
    assert {event.family for row in semantic_map.functions for event in row.events} >= {
        "input_boundary",
        "memory_bounds",
        "resource_lifecycle",
    }
    assert any(claim.origin == "user" for claim in semantic_map.claims)
    assert any(unknown.kind == "indirect_call_target" for unknown in semantic_map.unknowns)

    payload = semantic_map.claims[0].to_dict()
    payload["unexpected"] = True
    with pytest.raises(ValueError, match="unknown field"):
        SemanticClaim.from_dict(payload)


def test_security_map_sqlite_round_trip_and_json_export(tmp_path) -> None:
    semantic_map = ZeroLLMSecurityMapBuilder(
        FakeSecurityIndex(),
        project_id="demo",
        revision="rev-2",
        profile="deep",
    ).build([FunctionEntry("entry", file_path="src/demo.c")])
    store = SQLiteSecurityMapStore(tmp_path / "security-map.db")
    store.save_map(semantic_map)

    loaded = store.load_map("demo", "rev-2")
    assert loaded is not None
    assert loaded.map_fingerprint == semantic_map.map_fingerprint

    export_path = store.export_json(semantic_map, tmp_path / "security-map.json")
    exported = json.loads(export_path.read_text(encoding="utf-8"))
    assert exported["map_fingerprint"] == semantic_map.map_fingerprint
    assert exported["discovery_reports"] == []

    tampered = semantic_map.to_dict()
    tampered["map_fingerprint"] = "not-the-content-hash"
    with pytest.raises(ValueError, match="fingerprint mismatch"):
        SecuritySemanticMap.from_dict(tampered)

    updated = replace(semantic_map, profile="balanced")
    store.save_map(updated)
    reloaded = store.load_map("demo", "rev-2")
    assert reloaded is not None
    assert reloaded.profile == "balanced"


def test_callee_contract_change_invalidates_only_reverse_consumers() -> None:
    index = FakeSecurityIndex()
    before = ZeroLLMSecurityMapBuilder(
        index,
        project_id="demo",
        revision="rev",
        profile="balanced",
    ).build([FunctionEntry("entry", file_path="src/demo.c")])
    before_by_name = {item.function_name: item for item in before.functions}

    index.impls["worker"]["code"] = (
        "int worker(char *input) {\nchar *p = malloc(16);\n"
        "strcpy(p, input);\nfree(p);\nreturn 0;\n}"
    )
    after = ZeroLLMSecurityMapBuilder(
        index,
        project_id="demo",
        revision="rev",
        profile="balanced",
    ).build([FunctionEntry("entry", file_path="src/demo.c")])
    after_by_name = {item.function_name: item for item in after.functions}

    # The callee's exported contract changes its own identity and propagates
    # through the SCC DAG to its caller, without using any rule revision.
    assert (
        before_by_name["worker"].backend_coverage["dependency_fingerprint"]
        != after_by_name["worker"].backend_coverage["dependency_fingerprint"]
    )
    assert (
        before_by_name["entry"].backend_coverage["dependency_fingerprint"]
        != after_by_name["entry"].backend_coverage["dependency_fingerprint"]
    )


def test_security_map_invalidates_cycles_atomically() -> None:
    index = FakeSecurityIndex()
    index.impls["entry"]["code"] = "int entry(char *input) { return worker(input); }"
    index.impls["worker"]["code"] = "int worker(char *input) { return entry(input); }"

    def cyclic_callees(query, limit=None):
        return (
            [{"name": "worker", "file": "src/demo.c"}]
            if str(query).startswith("entry")
            else [{"name": "entry", "file": "src/demo.c"}]
        )

    index.get_callees = cyclic_callees
    semantic_map = ZeroLLMSecurityMapBuilder(
        index,
        project_id="cycle",
        revision="rev",
        profile="balanced",
    ).build([FunctionEntry("entry", file_path="src/demo.c")])

    assert len(semantic_map.functions) == 2
    assert {item.backend_coverage["scc_size"] for item in semantic_map.functions} == {2}
    assert len({item.backend_coverage["scc_id"] for item in semantic_map.functions}) == 1
    assert (
        len(
            {
                item.backend_coverage["semantic_contract_fingerprint"]
                for item in semantic_map.functions
            }
        )
        == 1
    )


def test_audit_unit_rejects_unknown_fields() -> None:
    unit = AuditUnit(
        schema_version=AUDIT_UNIT_SCHEMA_VERSION,
        unit_id="AUDIT_1",
        unit_kind="source_sink_path",
        fingerprint="f" * 64,
        risk_score=80,
        risk_reasons=("test",),
        root_entries=("entry",),
        member_functions=("FUNC_1",),
        event_refs=("EVT_1",),
        claim_refs=(),
        unknown_refs=(),
        skill_families=("bounds_and_integer",),
        backend_coverage={},
        candidate_desert=True,
    )
    payload = unit.to_dict()
    payload["legacy_hint"] = "not allowed"
    with pytest.raises(ValueError, match="unknown field"):
        AuditUnit.from_dict(payload)


def _discovery_hypothesis_payload(**overrides):
    payload = {
        "hypothesis_id": "HYP_1",
        "defect_class": "out_of_bounds_copy",
        "impact_level": "high",
        "confidence": 0.8,
        "function": "FUNC_copy",
        "location": "src/demo.c:12",
        "source": "src",
        "sink": "memcpy",
        "resource": "",
        "entry_paths": [["entry", "copy"]],
        "path_conditions": ["len may exceed capacity"],
        "positive_evidence_refs": ["source:src/demo.c:12"],
        "negative_evidence_refs": [],
        "missing_fact_kinds": ["destination_capacity"],
        "description": "Length may exceed the destination buffer.",
        "reasoning": "No destination capacity fact is available.",
        "root_cause": "Unproven caller-controlled length contract.",
    }
    payload.update(overrides)
    return payload


@pytest.mark.parametrize(
    "overrides",
    [
        {"source": "", "sink": "", "resource": ""},
        {"source": "src", "sink": "", "resource": ""},
        {"source": " ", "sink": "\t", "resource": "\n"},
    ],
)
def test_discovery_hypothesis_requires_flow_or_resource(overrides) -> None:
    with pytest.raises(ValueError, match="requires source and sink or a resource"):
        DiscoveryHypothesis.from_dict(_discovery_hypothesis_payload(**overrides))


def test_discovery_hypothesis_accepts_flow_or_resource_alternatives() -> None:
    flow = DiscoveryHypothesis.from_dict(_discovery_hypothesis_payload())
    resource = DiscoveryHypothesis.from_dict(
        _discovery_hypothesis_payload(source="", sink="", resource="allocation:dst")
    )

    assert (flow.source, flow.sink, flow.resource) == ("src", "memcpy", "")
    assert (resource.source, resource.sink, resource.resource) == (
        "",
        "",
        "allocation:dst",
    )


def test_discovery_hypothesis_schema_requires_nonempty_flow_or_resource() -> None:
    alternatives = DISCOVERY_HYPOTHESIS_JSON_SCHEMA["anyOf"]

    assert alternatives == [
        {
            "properties": {"resource": {"type": "string", "minLength": 1}},
            "required": ["resource"],
        },
        {
            "properties": {
                "source": {"type": "string", "minLength": 1},
                "sink": {"type": "string", "minLength": 1},
            },
            "required": ["source", "sink"],
        },
    ]
