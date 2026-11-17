from copy import deepcopy
import json
from types import SimpleNamespace

import pytest

from zscope.framework.base import AgentResponse
from zscope.orchestration.hierarchical_context import unit_view
from zscope.orchestration.hierarchical_discovery import (
    ContractDiscoveryAgent,
    HierarchicalDiscovery,
    build_hierarchy,
    summary_validation_error,
)
from test_hierarchical_discovery import function, summary, EMPTY_LIFECYCLE, reusable_function


def large_unit():
    unit = function()
    unit["facts"].update(
        complete=False,
        cross_tu_complete=False,
        missing=["unresolved callback"],
        build_context={
            "build_context_id": "build-a",
            "dependencies_complete": False,
            "include_lookups": [{"path": f"header-{i}", "exists": False} for i in range(10000)],
        },
    )
    events = [
        {"id": i, "object_usr": "pointer", "generation": "allocation-1", "code": "x" * 500}
        for i in range(60)
    ]
    unit["facts"]["functions"][0]["events"] = events
    unit["facts"]["events"] = deepcopy(events)
    return unit


def test_projection_retains_full_inventory_identity_gaps_and_candidate_evidence():
    unit = large_unit()
    before = deepcopy(unit)
    shown = unit_view(unit)
    assert len(json.dumps(shown)) < len(json.dumps(unit)) / 10
    assert shown["build_context_id"] == unit["build_context_id"]
    assert shown["usr"] == unit["usr"]
    assert shown["source"] == unit["source"]
    assert shown["manifest"] == unit["manifest"]
    assert shown["citation_format"] == unit["id"] + ":<absolute source line>"
    assert shown["facts"]["complete"] is False
    assert shown["facts"]["missing"] == ["unresolved callback"]
    assert shown["facts"]["build_context"]["dependencies_complete"] is False
    assert unit == before
    h = summary(unit, hypothesis=True)["hypotheses"][0]
    candidate = HierarchicalDiscovery.candidate(h, {unit["id"]: unit}, unit, "input")
    assert candidate["evidence_pack"]["program_facts"] == before["facts"]


def test_exact_evidence_pages_recover_originals_and_reject_unadmitted_variants():
    unit = large_unit()
    current = []
    agent = ContractDiscoveryAgent(
        SimpleNamespace(), {unit["id"]: unit}, [], [unit["id"]], lambda: current.append(True), 120
    )
    collected = []
    for offset in (0, 32):
        page = agent._tool_executor(
            "read_semantic_evidence",
            {
                "unit_id": unit["id"],
                "pointer": "/facts/events",
                "offset": offset,
                "limit": 32,
            },
        )
        assert page["build_context_id"] == "build-a"
        assert page["usr"] == unit["usr"]
        # Large event nodes retain a pointer; smaller pages recover all fields.
        for item in page["data"]:
            row = agent._tool_executor(
                "read_semantic_evidence",
                {
                    "unit_id": unit["id"],
                    "pointer": item["pointer"],
                    "offset": 0,
                    "limit": 1,
                },
            )
            assert row["success"]
        collected += [p["pointer"] for p in page["data"]]
    assert collected == [f"/facts/events/{i}" for i in range(60)]
    receipt = agent._tool_executor(
        "read_semantic_evidence",
        {
            "unit_id": unit["id"],
            "pointer": "/facts/build_context/include_lookups",
            "offset": 9999,
            "limit": 1,
        },
    )
    assert receipt["data"][0]["value"] == {"path": "header-9999", "exists": False}
    assert receipt["page"]["has_more"] is False
    assert current  # Each read checks before and after, without trusting the ref.
    assert not agent._tool_executor(
        "read_semantic_evidence",
        {
            "unit_id": "FN_a_other-build",
            "pointer": "/facts",
            "offset": 0,
            "limit": 1,
        },
    )["success"]
    assert unit["id"] not in agent.visible  # Fact pages alone do not grant source citations.


def test_evidence_read_checks_currentness_after_projection():
    unit = large_unit()
    checks = []

    def current():
        checks.append(True)
        if len(checks) == 2:
            raise ValueError("source changed")

    agent = ContractDiscoveryAgent(
        SimpleNamespace(), {unit["id"]: unit}, [], [unit["id"]], current, 120
    )
    with pytest.raises(ValueError, match="source changed"):
        agent._tool_executor(
            "read_semantic_evidence",
            {
                "unit_id": unit["id"],
                "pointer": "/facts",
                "offset": 0,
                "limit": 2,
            },
        )


def test_leaf_offers_only_readable_evidence_while_composition_can_read_members(monkeypatch):
    a, b = function(), function("b")
    inventory = {u["id"]: u for u in (a, b)}
    captured = []

    def conversation(agent, *args, **kwargs):
        captured.append(deepcopy(agent.tools_schema))
        return AgentResponse(success=True, data={})

    monkeypatch.setattr(ContractDiscoveryAgent, "_run_json_conversation", conversation)
    leaf = ContractDiscoveryAgent(
        SimpleNamespace(), inventory, [[a["id"], b["id"]]], [a["id"]], lambda: None, 120
    )
    leaf.run({"initial_units": [a["id"]]})
    assert [t["function"]["name"] for t in captured[0]] == ["read_semantic_evidence"]
    assert captured[0][0]["function"]["parameters"]["properties"]["unit_id"]["enum"] == [a["id"]]
    assert not leaf._tool_executor("read_semantic_unit", {"unit_id": b["id"]})["success"]
    assert b["id"] not in leaf.visible

    parent = ContractDiscoveryAgent(
        SimpleNamespace(), inventory, [[a["id"], b["id"]]], list(inventory), lambda: None, 120
    )
    parent.run({"initial_units": []})
    read = next(t for t in captured[1] if t["function"]["name"] == "read_semantic_unit")
    assert set(read["function"]["parameters"]["properties"]["unit_id"]["enum"]) == set(inventory)
    assert parent._tool_executor("read_semantic_unit", {"unit_id": b["id"]})["success"]
    assert b["id"] in parent.visible


def test_page_capacity_uses_actual_items_not_requested_limit():
    from zscope.orchestration.hierarchical_context import read_evidence

    unit = function()
    unit["facts"]["one"] = [{"signature": "parameter " * 300}]
    page = read_evidence(unit, "/facts/one", 0, 32)
    assert page["data"][0]["value"] == unit["facts"]["one"][0]


def test_invalid_citations_and_enums_have_actionable_feedback_without_weakening_validation():
    unit = function()
    inventory = {unit["id"]: unit}
    valid = summary(unit, hypothesis=True)
    assert summary_validation_error(valid, inventory, set(inventory)) == ""
    wrong = deepcopy(valid)
    wrong["hypotheses"][0]["source_ref"] = "a.c:2"
    assert "not file names" in summary_validation_error(wrong, inventory, set(inventory))
    wrong = deepcopy(valid)
    wrong["hypotheses"][0]["defect_class"] = "invented_class"
    assert "enum" in summary_validation_error(wrong, inventory, set(inventory))


def test_unit_deadline_preserves_gap_and_continues_but_parent_cancel_propagates(
    tmp_path, monkeypatch
):
    from zscope.common.cancellation import (
        CancellationToken,
        CancellationError,
        current_cancellation_token,
    )
    import time

    a, b = function(), function("b")
    hierarchy = build_hierarchy([a, b], [], EMPTY_LIFECYCLE)
    calls = []

    def run(agent, data):
        calls.append(data["unit"]["id"])
        if len(calls) == 1:
            current_cancellation_token().tighten_deadline(time.monotonic() - 1)
            current_cancellation_token().raise_if_cancelled()
        agent.visible.update(agent.members)
        return AgentResponse(success=True, data=summary(b))

    monkeypatch.setattr(ContractDiscoveryAgent, "run", run)
    result = HierarchicalDiscovery(
        client=SimpleNamespace(), cache_dir=tmp_path / "local", require_current=lambda: None
    ).run(hierarchy, EMPTY_LIFECYCLE, compose=False)
    assert calls == [a["id"], b["id"]]
    assert result["gaps"][0]["reason"] == "unit_deadline_exceeded"
    assert a["id"] not in result["summaries"] and b["id"] in result["summaries"]
    parent = CancellationToken()

    def cancel(agent, data):
        parent.cancel("user_cancelled")
        current_cancellation_token().raise_if_cancelled()

    monkeypatch.setattr(ContractDiscoveryAgent, "run", cancel)
    with pytest.raises(CancellationError, match="user_cancelled"):
        HierarchicalDiscovery(
            client=SimpleNamespace(),
            cache_dir=tmp_path / "parent",
            require_current=lambda: None,
            cancellation_token=parent,
        ).run(hierarchy, EMPTY_LIFECYCLE)


def test_full_receipt_still_invalidates_leaf_cache_and_prompt_is_scoped(tmp_path, monkeypatch):
    unit, sibling = large_unit(), function("unrelated")
    captured = []

    def run(agent, data):
        captured.append(data)
        agent.visible.update(agent.members)
        return AgentResponse(success=True, data=summary(unit))

    monkeypatch.setattr(ContractDiscoveryAgent, "run", run)
    discovery = HierarchicalDiscovery(
        client=SimpleNamespace(), cache_dir=tmp_path, require_current=lambda: None
    )
    hierarchy = build_hierarchy([unit, sibling], [], EMPTY_LIFECYCLE)
    discovery.run(hierarchy, EMPTY_LIFECYCLE, compose=False)
    assert captured[0]["unit"] == unit_view(unit)
    assert discovery.run(hierarchy, EMPTY_LIFECYCLE, compose=False)["model_calls"] == 0
    hierarchy["functions"][unit["id"]]["facts"]["build_context"]["include_lookups"][0][
        "exists"
    ] = True
    assert discovery.run(hierarchy, EMPTY_LIFECYCLE, compose=False)["model_calls"] == 1


def test_cross_build_model_tools_read_the_same_stable_store_not_raw_receipts():
    from zscope.orchestration.hierarchical_reuse import SummaryReuseView

    old, new = reusable_function(), reusable_function(build="receipt-new")
    before = deepcopy(new)
    left = SummaryReuseView(build_hierarchy([old], [], EMPTY_LIFECYCLE), EMPTY_LIFECYCLE)
    right = SummaryReuseView(build_hierarchy([new], [], EMPTY_LIFECYCLE), EMPTY_LIFECYCLE)
    assert left.available and right.available
    assert left.hierarchy == right.hierarchy
    uid = next(iter(right.hierarchy["functions"]))
    model = right.hierarchy["functions"][uid]
    assert "dependencies" not in model["facts"]["build_context"]
    assert new == before  # Current program evidence has not been rewritten.
    agent = ContractDiscoveryAgent(
        SimpleNamespace(), right.hierarchy["functions"], [], [uid], lambda: None, 120
    )
    shown = agent._tool_executor("read_semantic_unit", {"unit_id": uid})
    assert shown["unit"] == unit_view(model)
    page = agent._tool_executor(
        "read_semantic_evidence",
        {
            "unit_id": uid,
            "pointer": "/facts/build_context",
            "offset": 0,
            "limit": 32,
        },
    )
    assert page["success"] and "bytes-receipt-new" not in str(page)
    refused = agent._tool_executor(
        "read_semantic_evidence",
        {
            "unit_id": uid,
            "pointer": "/facts/build_context/dependencies",
            "offset": 0,
            "limit": 1,
        },
    )
    assert not refused["success"] and not agent.reusable_reads


def test_cross_build_unread_paged_fact_hash_and_returned_content_change_together():
    from zscope.orchestration.hierarchical_reuse import SummaryReuseView
    from zscope.orchestration.hierarchical_context import read_evidence

    old = reusable_function()
    old["facts"]["payload"] = {"code": "x" * 20000}
    new = deepcopy(old)
    new["facts"]["payload"]["code"] += "changed"
    views = [
        SummaryReuseView(build_hierarchy([u], [], EMPTY_LIFECYCLE), EMPTY_LIFECYCLE)
        for u in (old, new)
    ]
    units = [next(iter(v.hierarchy["functions"].values())) for v in views]
    shown = [unit_view(u)["facts"]["payload"] for u in units]
    assert shown[0] != shown[1]
    pages = [read_evidence(u, "/facts/payload/code", 12000, 1) for u in units]
    assert pages[0]["sha256"] != pages[1]["sha256"]
    assert pages[0]["data"] != pages[1]["data"]
