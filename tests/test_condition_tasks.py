"""Condition progress through the real Validator tool session and cache entry."""

from copy import deepcopy
import json

import pytest

from zscope.agents.validator_agent.agent import ValidatorAgent
from zscope.agents.validator_agent.investigation import InvestigationSession
from zscope.core.validation import condition_tasks, investigation_reuse
from zscope.core.validation.runner import ValidationRunner
from zscope.core.validation.claims import replay_positive_claim
from test_validation_claims import _issue
from test_investigation_reuse import CurrentCallers, request, setup_runner
from test_validator_v3_protocol import _result


class ConditionTransport:
    def __init__(self):
        self.calls = 0

    def __call__(self, url, payload):
        self.calls += 1
        current, recorded, progress = None, None, {}
        names = {}
        evidence = None
        for message in payload["messages"]:
            for call in message.get("tool_calls") or []:
                names[call["id"]] = call["function"]["name"]
            content = message.get("content") or ""
            if message.get("role") == "user":
                if content.startswith("Investigate the candidate's unresolved conditions."):
                    evidence = json.loads(content.rsplit("\n\n", 1)[1])
                elif content.startswith("These read-only queries"):
                    current = json.loads(content.split("\n", 1)[1])[0]["current_result"]
                elif content.startswith("Current condition progress"):
                    progress = json.loads(content.split("\n", 1)[1])
            elif message.get("role") == "tool":
                value = json.loads(content)
                if names.get(message["tool_call_id"]) == "get_callers":
                    current = value
                elif names.get(message["tool_call_id"]) == "record_validator_investigation_fact":
                    recorded = value["fact"]
        recipes = progress.get("ready_recipes") or {}
        if current is None:
            name, args = "get_callers", {"func_name": "f"}
        elif not recipes and recorded is None:
            name, args = "record_validator_investigation_fact", {
                "fact_kind": "ownership_transfer",
                "evidence_refs": [current["evidence_ref"]],
                "summary": "当前调用者使用资源后未转交所有权。",
            }
            if any(
                "condition_ids" in t["function"].get("parameters", {}).get("properties", {})
                for t in payload["tools"]
            ):
                args.update(condition_ids=["resource_acquired"], condition_outcome="supported")
        else:
            name = "emit_validator_result_v3"
            args = _result(
                candidate_uid=evidence["obligation"]["candidate_uid"],
                validation_cluster_uid=evidence["obligation"]["validation_cluster_uid"],
                evidence_refs=(
                    [r["confirmation_ref"] for r in recipes.values()]
                    if recipes
                    else [recorded["fact_uid"]]
                ),
            )
            args["pass"] = "investigation_synthesis"
        return (
            {
                "role": "assistant",
                "content": "",
                "tool_calls": [
                    {
                        "id": f"step-{self.calls}",
                        "type": "function",
                        "function": {"name": name, "arguments": json.dumps(args)},
                    }
                ],
            },
            "tool_calls",
            {"prompt_tokens": 11, "completion_tokens": 7, "total_tokens": 18},
        )


def condition_request(build="build-a"):
    item, view = request(build)
    view["evidence_slice"]["obligation"].update(positive_conditions=["resource_acquired"])
    return item, view


def test_condition_reconfirmation_saves_model_turns_and_binds_current_facts(tmp_path, monkeypatch):
    tool, transport = CurrentCallers(), ConditionTransport()
    runner, agent, client = setup_runner(tmp_path, tool, transport)
    try:
        item, view = condition_request()
        cold = runner._investigate_with_query_reuse(item, agent, view)
        assert transport.calls == 3
        before = transport.calls
        item, view = condition_request("build-b")
        warm = runner._investigate_with_query_reuse(item, agent, deepcopy(view))
        assert transport.calls - before == 1
        assert warm.metadata["validator_query_reuse"]["reconfirmed_conditions"] == 1
        assert warm.metadata["validator_condition_table"]["remaining_tasks"] == []
        assert all(
            f["build_context_id"] == "build-b"
            for f in warm.metadata["validator_investigation_facts"]
        )
        assert not set(cold.data["evidence_refs"]) & set(warm.data["evidence_refs"])
        assert all(ref.startswith("FACT_V3_") for ref in warm.data["evidence_refs"])
        assert warm.metadata["cumulative_total_tokens"] == 18
        monkeypatch.setattr(condition_tasks, "ENABLED", False)
        before = transport.calls
        control = runner._investigate_with_query_reuse(item, agent, deepcopy(view))
        assert transport.calls - before == 2  # Query replay stays enabled.
        assert warm.data["verdict"] == control.data["verdict"] == "verified"
    finally:
        client.close()


def test_changed_evidence_reopens_conditions_at_the_model_entry(tmp_path):
    tool, transport = CurrentCallers(), ConditionTransport()
    runner, agent, client = setup_runner(tmp_path, tool, transport)
    try:
        item, view = condition_request()
        runner._investigate_with_query_reuse(item, agent, view)
        tool.members = ["new caller: ownership changed"]
        before = transport.calls
        item, view = condition_request("build-b")
        changed = runner._investigate_with_query_reuse(item, agent, view)
        assert transport.calls - before == 2
        counts = changed.metadata["validator_query_reuse"]
        assert counts["ready_conditions"] == counts["reconfirmed_conditions"] == 0
        assert (
            counts["reopened_conditions"] == counts["scope_added"] == counts["scope_removed"] == 1
        )
    finally:
        client.close()


def make_session(tool, plan=None, build="build-a", conditions=None):
    _, view = condition_request(build)
    if conditions is not None:
        view["evidence_slice"]["obligation"]["positive_conditions"] = conditions
    view["evidence_slice"]["obligation"]["counterfact_kinds"] = ["same_lock_covers_all_accesses"]
    view["evidence_slice"]["allowed_missing_fact_kinds"] = ["ownership_transfer", "lockset"]
    if plan:
        view["_investigation_query_plan"] = plan
    return InvestigationSession(
        view,
        execute_tool=lambda name, args: tool.execute(args),
        tools_schema=[tool.get_schema()],
        pass_kind="investigation_synthesis",
    )


def saved_plan(session):
    return {
        "schema_version": investigation_reuse.PROTOCOL,
        "queries": deepcopy(session.observed_queries),
        "condition_plan": session.conditions.export(session.observed_queries),
    }


def terminal(session, refs):
    result = _result(
        candidate_uid=session.candidate_uid,
        validation_cluster_uid=session.cluster_uid,
        evidence_refs=refs,
    )
    result["pass"] = "investigation_synthesis"
    return result


@pytest.mark.parametrize("before,after", [(["A", "B"], ["A", "C"]), ([], ["C"]), (["A"], [])])
def test_query_subscription_tracks_added_removed_and_empty_members(before, after):
    tool = CurrentCallers()
    tool.members = before
    seed = make_session(tool)
    observation = seed("get_callers", {"func_name": "f"})
    if before:
        seed.record_fact(
            {
                "fact_kind": "lockset",
                "summary": "当前访问集合均受锁保护。",
                "evidence_refs": [observation["evidence_ref"]],
                "condition_ids": ["same_lock_covers_all_accesses"],
                "condition_outcome": "supported",
            }
        )
    plan = saved_plan(seed)
    tool.members = after
    current = make_session(tool, plan, "build-b")
    current.replay_queries([])
    snapshot = current.conditions.snapshot()
    assert snapshot["metrics"]["scope_added"] == len(set(after) - set(before))
    assert snapshot["metrics"]["scope_removed"] == len(set(before) - set(after))
    assert len(
        [t for t in snapshot["remaining_tasks"] if t["action"] == "check_added_member"]
    ) == len(set(after) - set(before))
    assert not current.investigation_facts and not current.conditions.ready


def test_partial_scope_and_changed_task_cannot_confirm_historical_conditions():
    tool = CurrentCallers()
    seed = make_session(tool)
    observation = seed("get_callers", {"func_name": "f"})
    seed.record_fact(
        {
            "fact_kind": "lockset",
            "summary": "当前访问集合均受锁保护。",
            "evidence_refs": [observation["evidence_ref"]],
            "condition_ids": ["same_lock_covers_all_accesses"],
        }
    )
    plan = saved_plan(seed)
    current = make_session(tool, plan, "build-b")
    current.execute_tool = lambda name, args: {
        "success": True,
        "data": {"callers": tool.members, "truncated": True},
        "page": {"has_more": True, "next_offset": 1},
    }
    current.replay_queries([])
    assert any(task["action"] == "complete_query_scope" for task in current.conditions.remaining())
    assert not current.conditions.ready
    rejected = current.accept_result(terminal(current, ["CONDITION_R1"]))
    assert not rejected["valid"] and not current.investigation_facts
    # A business premise is part of the task input even when tool answers match.
    changed = make_session(tool, plan, "build-b")
    changed.conditions.context["workflow_context"] = "different business premise"
    changed.replay_queries([])
    assert not changed.conditions.ready


def test_failed_query_and_invalid_terminal_do_not_restore_condition_claims():
    tool = CurrentCallers()
    seed = make_session(tool)
    observation = seed("get_callers", {"func_name": "f"})
    seed.record_fact(
        {
            "fact_kind": "ownership_transfer",
            "summary": "当前调用者未转交所有权。",
            "evidence_refs": [observation["evidence_ref"]],
            "condition_ids": ["resource_acquired"],
        }
    )
    plan = saved_plan(seed)
    current = make_session(tool, plan, "build-b")
    current.replay_queries([])
    assert current.conditions.ready and not current.investigation_facts
    assert not current.accept_result({"verdict": "verified", "evidence_refs": ["CONDITION_R1"]})[
        "valid"
    ]
    assert not current.investigation_facts
    tool.failed = True
    failed = make_session(tool, plan, "build-b")
    failed.replay_queries([])
    assert not failed.conditions.ready and not failed.investigation_facts
    assert failed.conditions.snapshot()["metrics"]["scope_removed"] == 0


def test_source_and_search_handles_refresh_without_reopening_unchanged_evidence():
    tool = CurrentCallers()
    revision = ["file-v1"]
    text = ["int f(void) { return 1; }"]

    def execute(name, args):
        if args.get("scope") == "symbols":
            return {"success": True, "status": "unavailable", "data": None}
        if name == "read_code":
            data = {
                "source": {
                    "file": "unit.c",
                    "start_line": 1,
                    "end_line": 1,
                    "code": text[0],
                    "revision": revision[0],
                    "truncated": False,
                }
            }
        else:
            data = {
                "view_id": revision[0],
                "matches": [
                    {"file": "unit.c", "line": 1, "text": text[0], "revision": revision[0]}
                ],
            }
        return {
            "success": True,
            "status": "ok",
            "data": data,
            "coverage": {"level": "complete", "missing": []},
            "page": None,
        }

    def session(plan=None):
        value = make_session(tool, plan)
        value.execute_tool = execute
        value.tools_schema = [{"function": {"name": name}} for name in ("read_code", "search_code")]
        return value

    seed = session()
    read = seed("read_code", {"file_path": "unit.c", "start_line": 1, "end_line": 1})
    seed("search_code", {"query": "f", "scope": "text"})
    seed("search_code", {"query": "f", "scope": "symbols"})
    seed.record_fact(
        {
            "fact_kind": "ownership_transfer",
            "summary": "当前函数事实支持该条件。",
            "condition_ids": ["resource_acquired"],
            "evidence_refs": [read["evidence_ref"]],
        }
    )
    plan = saved_plan(seed)
    revision[0] = "file-v2"
    current = session(plan)
    current.replay_queries([])
    assert current.conditions.counts["ready_conditions"] == 1
    assert current.conditions.snapshot()["metrics"]["scope_added"] == 0
    assert not current.investigation_facts
    text[0] = "int f(void) { return 2; }"
    changed = session(plan)
    changed.replay_queries([])
    assert not changed.conditions.ready
    assert changed.conditions.counts["reopened_conditions"] == 1


def test_current_contradiction_replaces_a_ready_condition_and_its_terminal_ref():
    tool = CurrentCallers()
    seed = make_session(tool)
    read = seed("get_callers", {"func_name": "f"})
    seed.record_fact(
        {
            "fact_kind": "ownership_transfer",
            "summary": "历史候选条件成立。",
            "condition_ids": ["resource_acquired"],
            "evidence_refs": [read["evidence_ref"]],
        }
    )
    current = make_session(tool, saved_plan(seed), "build-b")
    current.replay_queries([])
    assert current.conditions.ready
    ref = next(iter(current.tool_fact_catalog))
    current.record_fact(
        {
            "fact_kind": "ownership_transfer",
            "summary": "当前审阅发现反例。",
            "condition_ids": ["resource_acquired"],
            "condition_outcome": "refuted",
            "evidence_refs": [ref],
        }
    )
    assert not current.conditions.ready
    current.terminal_schema = {"function": {"parameters": {"properties": {"evidence_refs": {}}}}}
    current._zscope_start_iteration(1)
    refs = current.terminal_schema["function"]["parameters"]["properties"]["evidence_refs"][
        "items"
    ]["enum"]
    assert "CONDITION_R1" not in refs
    assert current.investigation_facts[-1]["fact_uid"] in refs
    assert ref not in refs


def ready_batch(*, stale_second_build=False):
    tool = CurrentCallers()

    def execute(args):
        name = args["func_name"]
        data = {"callers": ["caller " + name], "truncated": False}
        if stale_second_build and name == "second":
            data["build_context_id"] = "build-a"
        return {"success": True, "data": data}

    tool.execute = execute
    seed = make_session(tool, conditions=["first", "second"])
    for condition in ("first", "second"):
        read = seed("get_callers", {"func_name": condition})
        assert seed.record_fact(
            {
                "fact_kind": "ownership_transfer",
                "summary": "当前证据支持条件 " + condition,
                "evidence_refs": [read["evidence_ref"]],
                "condition_ids": [condition],
            }
        )["success"]
    current = make_session(tool, saved_plan(seed), "build-b", conditions=["first", "second"])
    current.replay_queries([])
    assert list(current.conditions.ready) == ["R1", "R2"]
    return current


def fact_state(session):
    return deepcopy(
        (
            session.investigation_facts,
            session.fact_ids,
            session.allowed_refs,
            session.fact_progress,
            vars(session.conditions),
        )
    )


def test_terminal_confirmation_preflights_the_whole_batch_before_registering():
    current = ready_batch(stale_second_build=True)
    before = fact_state(current)
    result = current.accept_result(terminal(current, ["CONDITION_R1", "CONDITION_R2"]))
    assert result == {"valid": False, "error": "fact evidence belongs to a different build"}
    assert current.accepted_result is None
    assert fact_state(current) == before


def test_terminal_confirmation_preserves_citation_order_and_repeated_references():
    current = ready_batch()
    raw = terminal(current, ["CONDITION_R2", "CONDITION_R1", "CONDITION_R2"])
    result = current.accept_result(raw)
    assert result["valid"]
    second, first = current.investigation_facts
    assert second["condition_ids"] == ["second"]
    assert first["condition_ids"] == ["first"]
    assert result["payload"]["evidence_refs"] == [
        second["fact_uid"],
        first["fact_uid"],
        second["fact_uid"],
    ]
    assert current.accepted_result == result["payload"]
    assert current.fact_ids == {first["fact_uid"], second["fact_uid"]}
    assert all(fact["build_context_id"] == "build-b" for fact in (first, second))
    assert not current.conditions.ready
    assert current.conditions.counts["reconfirmed_conditions"] == 2
    assert current.terminal_output.payload["evidence_refs"] == raw["evidence_refs"]
    assert raw["evidence_refs"] == ["CONDITION_R2", "CONDITION_R1", "CONDITION_R2"]


def test_compatibility_terminal_confirmation_is_reflected_in_all_session_metadata():
    session = ready_batch()
    assert session.terminal_output is None  # This client has not invoked the handler.
    raw = terminal(session, ["CONDITION_R1", "CONDITION_R2"])
    agent = ValidatorAgent.__new__(ValidatorAgent)
    response = agent._finish_investigation(
        session,
        {
            "content": json.dumps(raw),
            "finish_reason": "stop",
            "iterations": 1,
            "api_call_count": 1,
        },
        agent._new_metadata(session.input_data),
    )

    assert response.success and response.data["verdict"] == "verified"
    metadata = response.metadata
    facts = metadata["validator_investigation_facts"]
    assert metadata["new_fact_count"] == len(facts) == 2
    assert set(response.data["evidence_refs"]) == {fact["fact_uid"] for fact in facts}
    assert metadata["validator_query_reuse"]["reconfirmed_conditions"] == 2
    table = metadata["validator_condition_table"]
    assert table == session.conditions.snapshot()
    assert not {"first", "second"} & {row["condition_id"] for row in table["remaining_tasks"]}
    plan = metadata["validator_condition_plan"]
    assert plan == session.conditions.export(session.observed_queries)
    assert {cid for recipe in plan["recipes"] for cid in recipe["condition_ids"]} == {
        "first",
        "second",
    }


def test_new_conditions_count_as_progress_but_rephrasing_existing_conditions_does_not():
    session = make_session(CurrentCallers(), conditions=["first", "second", "third"])
    assert not session._zscope_start_iteration(1)
    read = session("get_callers", {"func_name": "f"})

    def record(condition, summary):
        return session.record_fact(
            {
                "fact_kind": "ownership_transfer",
                "summary": summary,
                "evidence_refs": [read["evidence_ref"]],
                "condition_ids": [condition],
            }
        )

    for iteration, condition in enumerate(("first", "second", "third"), 1):
        if iteration > 1:
            assert not session._zscope_start_iteration(iteration)
            assert session.consecutive_no_evidence_fact_iterations == 0
        assert record(condition, "证据支持 " + condition)["success"]
    assert not session._zscope_start_iteration(4)
    assert session.consecutive_no_evidence_fact_iterations == 0
    progress = set(session.fact_progress)
    assert record("first", "对第一个条件的重新表述")["success"]
    assert not session._zscope_start_iteration(5)
    assert record("second", "对第二个条件的重新表述")["success"]
    assert session._zscope_start_iteration(6)
    assert session.fact_progress == progress
    assert len(session.investigation_facts) == 5


def test_new_condition_outcome_is_progress_and_repeated_outcomes_are_not():
    session = make_session(CurrentCallers())
    session._zscope_start_iteration(1)
    read = session("get_callers", {"func_name": "f"})
    for iteration, outcome in enumerate(("supported", "refuted", "supported", "refuted"), 1):
        if iteration > 1:
            assert not session._zscope_start_iteration(iteration)
            assert session.consecutive_no_evidence_fact_iterations == (1 if iteration == 4 else 0)
        assert session.record_fact(
            {
                "fact_kind": "ownership_transfer",
                "summary": f"当前解释 {iteration}",
                "evidence_refs": [read["evidence_ref"]],
                "condition_ids": ["resource_acquired"],
                "condition_outcome": outcome,
            }
        )["success"]
    assert session._zscope_start_iteration(5)
    assert len(session.fact_progress) == 2


def refute_condition(session, condition="resource_acquired", outcome="refuted"):
    read = next(iter(session.tool_fact_catalog), None)
    if read is None:
        read = session("get_callers", {"func_name": "f"})["evidence_ref"]
    result = session.record_fact(
        {
            "fact_kind": "ownership_transfer",
            "summary": "当前必要条件的证据结论。",
            "evidence_refs": [read],
            "condition_ids": [condition],
            "condition_outcome": outcome,
        }
    )
    assert result["success"]
    return result["fact"]


@pytest.mark.parametrize("replayed", [False, True])
def test_refuted_required_condition_cannot_admit_verified_or_publish_confirmations(replayed):
    tool = CurrentCallers()
    seed = make_session(tool)
    fact = refute_condition(seed)
    current = make_session(tool, saved_plan(seed), "build-b") if replayed else seed
    if replayed:
        current.replay_queries([])
        refs = [recipe["confirmation_ref"] for recipe in current.conditions.ready.values()]
        assert refs
    else:
        refs = [fact["fact_uid"]]
    before = fact_state(current)
    result = current.accept_result(terminal(current, refs))
    assert not result["valid"]
    assert "refuted" in result["error"]
    assert current.accepted_result is None
    assert fact_state(current) == before
    uncertain = terminal(current, refs)
    uncertain.update(verdict="uncertain", stop_reason="no_evidence_gain")
    assert current.accept_result(uncertain)["valid"]


def test_refuting_a_rejection_branch_does_not_refute_the_required_witness():
    current = make_session(CurrentCallers())
    fact = refute_condition(current, "same_lock_covers_all_accesses")
    assert current.accept_result(terminal(current, [fact["fact_uid"]]))["valid"]


def test_current_supported_condition_supersedes_an_earlier_refutation():
    current = make_session(CurrentCallers())
    refute_condition(current)
    fact = refute_condition(current, outcome="supported")
    assert current.accept_result(terminal(current, [fact["fact_uid"]]))["valid"]


@pytest.mark.parametrize("cited_refutation", [True, False])
def test_downstream_refuted_witness_never_closes_or_promotes_a_verified_claim(cited_refutation):
    current = make_session(CurrentCallers(), build="build-current")
    supported = refute_condition(current, outcome="supported")
    fact = refute_condition(current)
    # Exercise the independent runner guard, bypassing the session's terminal admission.
    data = terminal(
        current,
        [
            "FACT_SOURCE",
            "FACT_SINK",
            fact["fact_uid"] if cited_refutation else supported["fact_uid"],
        ],
    )
    issue = _issue()
    issue.update(
        candidate_uid=current.candidate_uid,
        validation_cluster_uid=current.cluster_uid,
        obligation_positive_conditions=["resource_acquired"],
        missing_fact_kinds=["ownership_transfer"],
        candidate_promotion_eligible=True,
    )
    metadata = {
        "validator_investigation_facts": current.investigation_facts,
        "validator_tool_fact_catalog": current.tool_fact_catalog,
    }
    control = deepcopy(issue)
    control_data = terminal(current, ["FACT_SOURCE", "FACT_SINK", supported["fact_uid"]])
    ValidationRunner._apply_v3_investigation_facts(
        control,
        control_data,
        {
            **metadata,
            # An orphaned history entry cannot supersede an identified fact.
            "validator_investigation_facts": [supported, {**fact, "fact_uid": ""}],
        },
    )
    assert replay_positive_claim(control, control_data).accepted
    ValidationRunner._apply_v3_investigation_facts(issue, data, metadata)
    assert issue["v3_evidence_closure"]["complete"] is False
    assert issue["missing_fact_kinds"] == ["ownership_transfer"]
    assert issue["decision_fact_coverage"] == "partial"
    assert issue["candidate_promotion_eligible"] is False
    assert issue["v3_evidence_closure"]["reason"] == "required_condition_refuted"
    replay = replay_positive_claim(issue, data)
    assert not replay.accepted
    assert "investigation_evidence_closure_incomplete" in replay.failures


@pytest.mark.parametrize("cite_old_refutation", [False, True])
def test_downstream_uses_current_direction_and_cannot_relabel_an_old_negative_fact(
    cite_old_refutation,
):
    current = make_session(CurrentCallers(), build="build-current")
    old = refute_condition(current)
    latest = refute_condition(current, outcome="supported")
    refs = [old["fact_uid"]] if cite_old_refutation else [latest["fact_uid"]]
    assert current.accept_result(terminal(current, refs))["valid"] is (not cite_old_refutation)
    issue = {
        "obligation_positive_conditions": ["resource_acquired"],
        "missing_fact_kinds": ["ownership_transfer"],
    }
    ValidationRunner._apply_v3_investigation_facts(
        issue,
        terminal(current, refs),
        {
            "validator_investigation_facts": current.investigation_facts,
            "validator_tool_fact_catalog": current.tool_fact_catalog,
        },
    )
    assert issue["v3_evidence_closure"]["complete"] is (not cite_old_refutation)
    assert issue["candidate_promotion_eligible"] is (not cite_old_refutation)


def test_unselected_refuted_replay_recipe_is_not_a_current_claim():
    tool = CurrentCallers()
    seed = make_session(tool)
    refute_condition(seed)
    current = make_session(tool, saved_plan(seed), "build-b")
    current.replay_queries([])
    assert current.conditions.ready
    result = current.accept_result(terminal(current, []))
    assert result["valid"]
    assert not current.investigation_facts
    assert current.conditions.ready  # The unselected claim was never confirmed.


def test_corrected_direction_is_consistent_when_both_historical_fact_refs_are_cited():
    current = make_session(CurrentCallers(), build="build-current")
    old = refute_condition(current)
    latest = refute_condition(current, outcome="supported")
    refs = [old["fact_uid"], latest["fact_uid"]]
    assert current.accept_result(terminal(current, refs))["valid"]
    issue = {
        "obligation_positive_conditions": ["resource_acquired"],
        "missing_fact_kinds": ["ownership_transfer"],
    }
    ValidationRunner._apply_v3_investigation_facts(
        issue,
        terminal(current, refs),
        {
            "validator_investigation_facts": current.investigation_facts,
            "validator_tool_fact_catalog": current.tool_fact_catalog,
        },
    )
    assert issue["v3_evidence_closure"]["complete"] is True


def test_refuted_witness_can_still_support_a_semantic_rejection():
    current = make_session(CurrentCallers())
    fact = refute_condition(current)
    rejected = terminal(current, [fact["fact_uid"]])
    rejected.update(verdict="rejected", blocking_negative_evidence=True)
    assert current.accept_result(rejected)["valid"]
    issue = {
        "obligation_positive_conditions": ["resource_acquired"],
        "missing_fact_kinds": ["ownership_transfer"],
    }
    ValidationRunner._apply_v3_investigation_facts(
        issue,
        rejected,
        {
            "validator_investigation_facts": current.investigation_facts,
            "validator_tool_fact_catalog": current.tool_fact_catalog,
        },
    )
    assert issue["v3_evidence_closure"]["complete"] is True
