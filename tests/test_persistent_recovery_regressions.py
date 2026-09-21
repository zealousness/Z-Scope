"""Regressions reproduced while recovering the persistent C/C++ trial."""

from copy import deepcopy
import json

import pytest

from test_global_modeler import FakeCodeIndex
from test_incremental_semantic_modeling import modeler_for
from test_json_output_agents import _semantic_model_input, _snapshot_payload
from test_security_semantic_map import FakeSecurityIndex
from zscope.agents.semantic_modeler.agent import SemanticModeler
from zscope.config.function_entry import FunctionEntry
from zscope.framework.llm_client import LLMClient
from zscope.semantics.security_map import ZeroLLMSecurityMapBuilder
from zscope.snapshots.modeling_input import build_semantic_model_input


@pytest.mark.parametrize(
    "exposure, external",
    [
        ("api", True),
        ("communication", True),
        ("other_user_input", True),
        ("thread+communication", True),
        ("thread", False),
        (None, False),
    ],
)
def test_entry_metadata_reaches_security_map_without_index_annotation(exposure, external):
    index = FakeSecurityIndex()
    index.impls["entry"].pop("entry_exposure")
    result = ZeroLLMSecurityMapBuilder(
        index,
        project_id="demo",
        revision="test",
        profile="balanced",
    ).build([FunctionEntry("entry", file_path="src/demo.c", exposure=exposure)])
    boundaries = [claim for claim in result.claims if claim.kind == "trust_boundary"]
    assert len(boundaries) == 1
    assert boundaries[0].value["externally_exposed"] is external
    origins = [
        claim for claim in result.claims if claim.kind == "input_origin" and "origin" in claim.value
    ]
    assert [claim.value["origin"] for claim in origins] == [
        "external" if external else "entry_unknown"
    ]
    assert result.coverage["llm_calls"] == 0


def test_program_callee_prose_refresh_preserves_ordinary_scan_cache(tmp_path):
    calls = []
    index = FakeCodeIndex()
    modeler = modeler_for(tmp_path, index, calls)
    modeler.run([FunctionEntry("entry")])
    store = modeler.snapshot_store
    target = index.impls["mid"]["index_name"]
    before = store.load_snapshot(target)
    context = build_semantic_model_input(index, "mid", include_context=False)
    context["project_callees"] = deepcopy(before["project_callees"])
    for callee in context["project_callees"]:
        callee["callee_summary"] = "Program-refreshed wording of the same callee behavior."
    assert store.reconcile_project_callee_summaries(target, context) == "refreshed"
    assert store.load_snapshot(target) != before
    calls.clear()
    # A fresh orchestrator must reuse the persisted record, not an in-memory copy.
    resumed = modeler_for(tmp_path, index, calls)
    stats = resumed.run([FunctionEntry("entry")])
    assert calls == []
    assert stats.cache_hit_functions == 4


def test_legacy_cache_fingerprint_upgrade_does_not_rewrite_snapshot(tmp_path):
    calls = []
    index = FakeCodeIndex()
    modeler = modeler_for(tmp_path, index, calls)
    modeler.run([FunctionEntry("entry")])
    store = modeler.snapshot_store
    generations = {
        impl["index_name"]: store.get_fingerprints(impl["index_name"])["snapshot_generation"]
        for impl in index.impls.values()
    }
    for path in (tmp_path / "snapshots/.semantic-modeling").glob("*.json"):
        record = json.loads(path.read_text())
        if "snapshot_content_hash" in record:
            record.pop("snapshot_content_hash")
            path.write_text(json.dumps(record), encoding="utf-8")
    calls.clear()
    resumed = modeler_for(tmp_path, index, calls)
    resumed.run([FunctionEntry("entry")])
    assert calls == []
    assert {
        key: resumed.snapshot_store.get_fingerprints(key)["snapshot_generation"]
        for key in generations
    } == generations


@pytest.mark.parametrize(
    "field, value",
    [
        ("return_values", {"return_type": "int", "ownership": "caller_owned"}),
        (
            "suspicious_points",
            [
                {
                    "category": "memory_safety",
                    "lines": "2",
                    "description": "A different unvalidated hypothesis.",
                }
            ],
        ),
    ],
)
def test_untracked_model_content_change_is_not_mistaken_for_prose_refresh(tmp_path, field, value):
    calls = []
    index = FakeCodeIndex()
    modeler = modeler_for(tmp_path, index, calls)
    modeler.run([FunctionEntry("entry")])
    store = modeler.snapshot_store
    target = index.impls["leaf"]["index_name"]
    snapshot = deepcopy(store.load_snapshot(target))
    snapshot[field] = value
    context = build_semantic_model_input(index, "leaf", include_context=False)
    store.save_snapshot(target, snapshot, context["code"], dependency_context=context)
    calls.clear()
    modeler_for(tmp_path, index, calls).run([FunctionEntry("entry")])
    assert calls == ["leaf"]


@pytest.mark.parametrize("nested", [False, True])
def test_terminal_schema_retry_reports_missing_contract_field(monkeypatch, nested):
    payload = _snapshot_payload()
    invalid = deepcopy(payload)
    invalid.pop("interface_contracts")
    calls = []
    client = LLMClient(api_key="test", base_url="http://example.invalid", models=["unit"])

    def respond(messages, **kwargs):
        calls.append(deepcopy(messages))
        value = invalid if len(calls) == 1 else payload
        if nested:
            value = {"function_snapshot": value}
        return {
            "choices": [
                {
                    "finish_reason": "tool_calls",
                    "message": {
                        "role": "assistant",
                        "content": "",
                        "tool_calls": [
                            {
                                "id": str(len(calls)),
                                "type": "function",
                                "function": {
                                    "name": "emit_function_snapshot",
                                    "arguments": json.dumps(value),
                                },
                            }
                        ],
                    },
                }
            ],
            "model": "unit",
            "usage": {"prompt_tokens": 10, "completion_tokens": 10},
        }

    monkeypatch.setattr(client, "chat_completion", respond)
    result = SemanticModeler(client, []).run(_semantic_model_input())
    assert result.success, result.error
    assert len(calls) == 2
    feedback = [message["content"] for message in calls[1] if message.get("role") == "tool"]
    assert any("interface_contracts: required" in str(message) for message in feedback)
