import hashlib
import json
from dataclasses import replace
from types import SimpleNamespace

import pytest

from test_investigation_evidence import case, coordinator, read, report, search
from zscope.common.cancellation import CancellationError, CancellationToken, bind_cancellation_token
from zscope.framework.base import AgentResponse
from zscope.orchestration.bounded_investigation import (
    BoundedInvestigationWorker,
    InvestigationStepAgent,
    make_investigation_runner,
)
from zscope.orchestration.investigation import InvestigationError, InvestigationRequest, SourceScope


def query(request, question="Which source line contains the missing bounds fact?"):
    return {
        "action": "query",
        "question": question,
        "function_uid": request.function_uid,
        "tool": request.tool,
        "arguments_json": json.dumps(request.arguments),
        "report": None,
    }


def unknown():
    return {
        "action": "unknown",
        "question": "Missing external caller contract.",
        "function_uid": None,
        "tool": None,
        "arguments_json": None,
        "report": None,
    }


def finish(case, context, *, forged=False):
    refs = [item["evidence"]["evidence_ref"] for item in context["observations"]]
    payload = report(case, ["forged"] if forged else refs).to_dict()
    return {
        "action": "finish",
        "question": "Observed source requires review.",
        "function_uid": None,
        "tool": None,
        "arguments_json": None,
        "report": payload,
    }


class Steps:
    def __init__(self, actions):
        self.actions = list(actions)
        self.calls = 0
        self.contexts = []

    def __call__(self, context):
        self.contexts.append(json.loads(json.dumps(context)))
        action = self.actions[min(self.calls, len(self.actions) - 1)]
        self.calls += 1
        if isinstance(action, Exception):
            raise action
        value = action(context) if callable(action) else action
        return (
            value if isinstance(value, AgentResponse) else AgentResponse(success=True, data=value)
        )


def run(case, steps, **kwargs):
    session = kwargs.pop("session", None) or case.session()
    return BoundedInvestigationWorker(steps, **kwargs).run(case.projection, case.unit, session, [])


def test_second_query_supplies_needed_fact_and_final_hypothesis(case):
    steps = Steps([query(search()), query(read()), lambda context: finish(case, context)])
    outcome = run(case, steps)
    assert outcome.stop_reason == "report_ready"
    assert (outcome.rounds, outcome.attempts, outcome.evidence_count) == (3, 2, 2)
    assert outcome.report.hypotheses
    assert steps.contexts[0]["observations"] == []
    assert len(steps.contexts[2]["observations"]) == 2
    assert outcome.session is not None
    outcome.session.close()


def test_single_decision_unknown_finishes_without_tool(case):
    outcome = run(
        case,
        Steps([unknown()]),
        session=case.session(execute_tool=lambda *_: pytest.fail("tool executed")),
    )
    assert outcome.stop_reason == "model_unknown" and outcome.rounds == 1
    assert outcome.report.coverage_status == "partial"
    assert outcome.report.unresolved_facts == ("model_unknown",)


def test_one_round_final_uses_existing_evidence_without_query(case):
    payload = report(case, ["source:src/demo.c:3"]).to_dict()
    decision = {**unknown(), "action": "finish", "report": payload}
    outcome = run(case, Steps([decision]))
    assert outcome.stop_reason == "report_ready" and outcome.rounds == 1 and outcome.attempts == 0


def test_authorized_extension_refreshes_visible_program_scope(case):
    path = case.root / "src/helper.c"
    path.write_text("void helper(void) {}\n", encoding="utf-8")
    scope = SourceScope("FUNC_helper", "src/helper.c", 1, 1, case.access.read("src/helper.c")[1])
    steps = Steps(
        [
            query(
                InvestigationRequest(
                    "read_code",
                    "FUNC_helper",
                    {"file_path": "src/helper.c", "start_line": 1, "end_line": 1},
                )
            ),
            unknown(),
        ]
    )
    outcome = run(
        case,
        steps,
        session=case.session(
            authorize_scope=lambda uid: scope if uid == scope.function_uid else None,
            max_extensions=1,
        ),
    )
    assert outcome.evidence_count == 1
    assert {item["function_uid"] for item in steps.contexts[1]["granted_scopes"]} == {
        "FUNC_copy",
        "FUNC_helper",
    }


def test_repeated_query_stops_after_one_real_execution(case):
    calls = []

    def execute(name, args):
        calls.append((name, args))
        return case.runtime.execute_tool(name, args)

    outcome = run(case, Steps([query(read())]), session=case.session(execute_tool=execute))
    assert outcome.stop_reason == "repeated_query_no_gain"
    assert outcome.rounds == 2 and outcome.attempts == 2 and len(calls) == 1
    assert outcome.evidence_count == 1


def test_equivalent_queries_with_no_new_content_stop(case):
    second = search()
    second = replace(second, arguments={**second.arguments, "match_mode": "substring"})
    outcome = run(case, Steps([query(search()), query(second)]))
    assert outcome.stop_reason == "no_evidence_gain" and outcome.rounds == 2
    assert outcome.evidence_count == 1
    assert outcome.summary()["registered_ref_count"] == 2
    assert len(outcome.report.tool_evidence_refs) == 2
    assert outcome.trace[-2]["status"] == "registered_no_gain"
    assert outcome.trace[-2]["evidence_ref"] in outcome.report.tool_evidence_refs


def test_four_round_budget_preserves_all_collected_refs_without_extra_final_call(case):
    steps = Steps([query(read(i)) for i in range(1, 5)])
    outcome = run(case, steps)
    assert outcome.stop_reason == "round_budget"
    assert (steps.calls, outcome.rounds, outcome.attempts, outcome.evidence_count) == (4, 4, 4, 4)
    assert len(outcome.report.tool_evidence_refs) == 4
    assert not outcome.report.hypotheses and outcome.report.coverage_status == "partial"


def test_unavailable_attempts_are_bounded_and_error_text_is_not_echoed(case):
    session = case.session(
        execute_tool=lambda *_: {"status": "unavailable", "error": "PRIVATE_CONCLUSION"}
    )
    steps = Steps([query(read(i)) for i in range(1, 5)])
    outcome = run(case, steps, session=session)
    assert (outcome.rounds, outcome.attempts) == (4, 4)
    assert outcome.stop_reason == "round_budget"
    assert "PRIVATE_CONCLUSION" not in json.dumps(outcome.summary())


@pytest.mark.parametrize(
    "response",
    [
        AgentResponse(False, {}, error="SECRET_RAW_OUTPUT"),
        AgentResponse(True, {"bad": "SECRET_RAW_OUTPUT"}),
        AgentResponse(True, unknown(), metadata={"truncated": True}),
    ],
)
def test_invalid_failed_or_truncated_decisions_consume_rounds(case, response):
    outcome = run(case, Steps([response]))
    assert outcome.rounds == 4 and outcome.attempts == 0
    assert outcome.stop_reason == "round_budget"
    assert all(item["status"] == "invalid_response" for item in outcome.trace[:-1])
    assert "SECRET_RAW_OUTPUT" not in json.dumps(outcome.summary())


def test_invalid_report_refs_fail_closed_and_keep_observations(case):
    outcome = run(case, Steps([query(read()), lambda context: finish(case, context, forged=True)]))
    assert outcome.stop_reason == "invalid_report" and outcome.evidence_count == 1
    assert not outcome.report.hypotheses


@pytest.mark.parametrize(
    "query_request",
    [
        replace(read(), function_uid="outside"),
        replace(read(), arguments={"file_path": "../outside.c", "start_line": 1, "end_line": 1}),
    ],
)
def test_unauthorized_expansion_or_path_ends_attempt(case, query_request):
    outcome = run(case, Steps([query(query_request)]))
    assert outcome.stop_reason in {"scope_expansion_denied", "query_scope_mismatch"}
    assert outcome.rounds == 1 and outcome.attempts == 1


def test_worker_exception_keeps_collected_evidence(case):
    outcome = run(case, Steps([query(read()), RuntimeError("PRIVATE_EXCEPTION")]))
    assert outcome.stop_reason == "worker_error" and outcome.evidence_count == 1
    assert len(outcome.report.tool_evidence_refs) == 1
    assert "PRIVATE_EXCEPTION" not in json.dumps(outcome.summary())


def test_cancel_after_first_query_preserves_evidence_without_cancelling_other_owner(case):
    parent = CancellationToken()
    unrelated = CancellationToken()

    def stop(context):
        parent.cancel("user_cancelled")
        return unknown()

    outcome = run(case, Steps([query(read()), stop]), cancellation=parent)
    assert outcome.stop_reason == "cancelled" and outcome.evidence_count == 1
    assert outcome.owner_cancelled
    assert not unrelated.is_cancelled()


def test_cancel_during_tool_return_keeps_registered_manifest_and_trace(case):
    parent = CancellationToken()

    def execute(name, args):
        result = case.runtime.execute_tool(name, args)
        parent.cancel("user_cancelled")
        return result

    outcome = run(
        case,
        Steps([query(read())]),
        session=case.session(execute_tool=execute),
        cancellation=parent,
    )
    assert outcome.stop_reason == "cancelled" and outcome.owner_cancelled
    assert outcome.evidence_count == 1 and outcome.summary()["registered_ref_count"] == 1
    assert outcome.trace[0]["evidence_ref"] in outcome.report.tool_evidence_refs
    assert outcome.evidence["entries"][0]["evidence_ref"] in outcome.report.tool_evidence_refs


def test_local_deadline_does_not_cancel_parent(case, monkeypatch):
    import zscope.common.cancellation as cancellation_module

    now = [0.0]
    monkeypatch.setattr(cancellation_module.time, "monotonic", lambda: now[0])
    parent = CancellationToken()

    def expire(context):
        now[0] = 2.0
        return unknown()

    outcome = run(case, Steps([expire]), cancellation=parent, timeout_seconds=1)
    assert outcome.stop_reason == "deadline_exceeded"
    assert not outcome.owner_cancelled
    assert not parent.is_cancelled()


def test_source_change_during_investigation_revokes_report_but_keeps_audit(case):
    def change(context):
        case.path.write_text("changed\n", encoding="utf-8")
        return query(read(2))

    outcome = run(case, Steps([query(read()), change]))
    assert outcome.stop_reason == "scope_source_changed"
    assert outcome.report is None and outcome.session is None
    assert outcome.evidence_count == 1 and outcome.evidence["validity"] == "stale_or_unavailable"


class FakeClient:
    def __init__(self, steps):
        self.steps = steps
        self.calls = 0
        self.close_calls = 0

    def run_conversation_with_tools(self, **kwargs):
        self.calls += 1
        assert kwargs["max_iterations"] == 1
        assert [tool["function"]["name"] for tool in kwargs["tools_schema"]] == [
            "emit_investigation_step"
        ]
        context = json.loads(kwargs["messages"][-1]["content"])
        response = self.steps(context)
        result = kwargs["terminal_tool_handler"](response.data)
        return {
            "content": "",
            "conversation": [
                {
                    "role": "assistant",
                    "tool_calls": [
                        {
                            "id": "step",
                            "function": {
                                "name": "emit_investigation_step",
                                "arguments": json.dumps(response.data),
                            },
                        }
                    ],
                }
            ],
            "terminal_tool_payload": result.get("payload"),
            "terminal_tool_valid": result["valid"],
            "truncated": False,
        }

    def close(self):
        self.close_calls += 1


def config(case, mode="shadow"):
    return SimpleNamespace(
        analysis=SimpleNamespace(
            active_investigation_mode=mode,
            active_investigation_max_rounds=4,
            active_investigation_timeout_seconds=120,
            active_investigation_max_scope_extensions=1,
            snapshot_dir=str(case.root / ".snapshots"),
        ),
        project=SimpleNamespace(
            project_root=case.root, source_root=case.root, exclude_paths=[], language="c_cpp"
        ),
        indexing=SimpleNamespace(
            backend="unified", knowledge_db_path=str(case.root / ".knowledge" / "missing.db")
        ),
    )


def tree(root):
    return {
        str(p.relative_to(root)): (hashlib.sha256(p.read_bytes()).hexdigest(), p.stat().st_mtime_ns)
        for p in root.rglob("*")
        if p.is_file()
    }


def test_factory_uses_shared_json_agent_no_live_backend_no_project_writes(case, monkeypatch):
    import zscope.retrieval.code_index as code_index_module
    import zscope.snapshots.store as snapshot_module

    monkeypatch.setattr(
        code_index_module.CodeIndex,
        "__init__",
        lambda *_a, **_k: pytest.fail("live backend started"),
    )
    monkeypatch.setattr(
        snapshot_module.SnapshotStore,
        "__init__",
        lambda *_a, **_k: pytest.fail("writable store created"),
    )
    client = FakeClient(
        Steps([query(search()), query(read()), lambda context: finish(case, context)])
    )
    before = tree(case.root)
    runner = make_investigation_runner(config(case), case.semantic_map, client)
    outcome = runner(case.projection, case.profile, case.unit)
    assert outcome.stop_reason == "report_ready" and client.calls == 3
    assert outcome.evidence_count == 2
    outcome.session.close()
    assert tree(case.root) == before
    assert client.close_calls == 0


def test_off_factory_constructs_nothing(case, monkeypatch):
    import zscope.orchestration.bounded_investigation as module

    monkeypatch.setattr(
        module, "ProjectSourceAccess", lambda *_a, **_k: pytest.fail("off constructed reader")
    )
    assert make_investigation_runner(config(case, "off"), case.semantic_map, object()) is None


@pytest.mark.parametrize("kind", ["stale", "unknown", "bad_range"])
def test_factory_requires_map_code_hash_before_model_or_cached_index(case, monkeypatch, kind):
    import zscope.orchestration.bounded_investigation as module

    record = case.semantic_map.functions[0]
    record = (
        replace(record, end_line=100)
        if kind == "bad_range"
        else replace(record, code_hash="" if kind == "unknown" else "old-hash")
    )
    semantic_map = replace(case.semantic_map, functions=(record,))
    client = FakeClient(Steps([unknown()]))
    monkeypatch.setattr(
        module,
        "CachedCodeIndex",
        lambda *_: pytest.fail("unverified map initialized cached reader"),
    )
    runner = make_investigation_runner(config(case), semantic_map, client)
    outcome = runner(case.projection, case.profile, case.unit)
    assert outcome.stop_reason in {"map_source_hash_mismatch", "map_source_range_unverifiable"}
    assert client.calls == 0 and outcome.session is None


def test_factory_accepts_exact_numbered_universal_newline_map_hash(case):
    numbered = case.access.snippet("src/demo.c", 1, 4, 4)["code"]
    semantic_map = replace(
        case.semantic_map,
        functions=(
            replace(
                case.semantic_map.functions[0],
                code_hash=hashlib.sha256(numbered.encode()).hexdigest(),
            ),
        ),
    )
    client = FakeClient(Steps([unknown()]))
    outcome = make_investigation_runner(config(case), semantic_map, client)(
        case.projection, case.profile, case.unit
    )
    assert outcome.stop_reason == "model_unknown" and client.calls == 1


def test_factory_pre_cancelled_does_no_model_work(case):
    token = CancellationToken()
    token.cancel()
    client = FakeClient(Steps([unknown()]))
    outcome = make_investigation_runner(config(case), case.semantic_map, client, token)(
        case.projection, case.profile, case.unit
    )
    assert outcome.stop_reason == "cancelled" and client.calls == 0
    assert outcome.owner_cancelled


@pytest.mark.parametrize("exact", [False, True])
def test_factory_expansion_rejects_ambiguous_name_but_accepts_exact_identity(case, exact):
    original = case.semantic_map.functions[0]
    helpers = []
    for suffix in ("a", "b"):
        name = f"src/helper_{suffix}.c"
        (case.root / name).write_text("static void helper(void) {}\n", encoding="utf-8")
        helpers.append(
            replace(
                original,
                function_uid=f"FUNC_helper_{suffix}",
                index_name=f"helper@{name}:1-1",
                function_name="helper",
                file_path=name,
                start_line=1,
                end_line=1,
                code_hash=case.access.read(name)[1],
                events=(),
            )
        )
    target = helpers[1]
    semantic_map = replace(
        case.semantic_map,
        functions=(
            replace(original, callees=(target.index_name if exact else "helper",)),
            *helpers,
        ),
    )
    steps = Steps(
        [
            query(
                InvestigationRequest(
                    "read_code",
                    target.function_uid,
                    {"file_path": target.file_path, "start_line": 1, "end_line": 1},
                )
            ),
            unknown(),
        ]
    )
    outcome = make_investigation_runner(config(case), semantic_map, FakeClient(steps))(
        case.projection, case.profile, case.unit
    )
    offered = steps.contexts[0]["available_scope_requests"]
    assert [item["function_uid"] for item in offered] == ([target.function_uid] if exact else [])
    assert outcome.stop_reason == ("model_unknown" if exact else "scope_expansion_denied")
    assert outcome.evidence_count == int(exact)


def test_factory_local_deadline_is_not_owner_cancellation(case, monkeypatch):
    import zscope.common.cancellation as cancellation_module

    now = [0.0]
    monkeypatch.setattr(cancellation_module.time, "monotonic", lambda: now[0])
    parent = CancellationToken()

    def expire(_context):
        now[0] = 2.0
        return unknown()

    settings = config(case)
    settings.analysis.active_investigation_timeout_seconds = 1
    outcome = make_investigation_runner(
        settings, case.semantic_map, FakeClient(Steps([expire])), parent
    )(case.projection, case.profile, case.unit)
    assert outcome.stop_reason == "deadline_exceeded"
    assert not outcome.owner_cancelled and not parent.is_cancelled()


def test_coordinator_keeps_original_active_report_and_independent_shadow(case):
    once = report(case, ["source:src/demo.c:3"])

    def investigation(projection, profile, unit):
        session = case.session(projection=projection)
        steps = Steps([query(read()), lambda context: finish(case, context)])
        return BoundedInvestigationWorker(steps).run(projection, unit, session, [])

    coord = coordinator(
        case,
        report_runner=lambda *_: once,
        investigation_runner=investigation,
        visibility_mode="active",
    )
    _planned, state = coord.run(case.semantic_map)
    assert state["completed_report_count"] == 1 and state["hypothesis_count"] == 1
    assert state["investigation"]["hypothesis_count"] == 1
    records = coord.registrar.ledger.records()
    active = [record for record in records if "active_discovery" in record.sources]
    shadow = [record for record in records if "active_investigation" in record.sources]
    assert len(active) == len(shadow) == 1
    assert active[0] is not shadow[0]
    assert active[0].obligation_uid == shadow[0].obligation_uid
    assert active[0].validation_cluster_uid != shadow[0].validation_cluster_uid
    assert active[0].ticket.evidence["candidate_payload"]["rollout_visibility"] == "active"
    assert shadow[0].ticket.evidence["candidate_payload"]["rollout_visibility"] == "shadow"
    assert shadow[0].ticket.evidence["candidate_promotion_eligible"] is False
    assert coord.store.load_discovery_report(case.unit.unit_id, case.unit.fingerprint) == once


@pytest.mark.parametrize("timeout", [float("inf"), float("nan"), True, False, 0, -1, "120"])
def test_direct_worker_rejects_invalid_deadlines(timeout):
    with pytest.raises(ValueError, match="invalid bounded"):
        BoundedInvestigationWorker(lambda _: None, timeout_seconds=timeout)


def test_cost_counters_do_not_claim_physical_llm_attempts(case):
    outcome = run(case, Steps([query(read()), unknown()]))
    summary = outcome.summary()
    assert summary["tool_attempts"] == 1 and summary["decision_calls"] == 2
    assert summary["physical_llm_attempts"] == "unknown"


def test_model_identity_binds_models_and_provider_without_serializing_endpoint(case):
    from zscope.orchestration.bounded_investigation import _model_identity

    first = SimpleNamespace(
        models=["model-a"], base_urls=["https://private.invalid/v1"], api_key="SECRET"
    )
    second = SimpleNamespace(models=["model-b"], base_urls=first.base_urls, api_key="SECRET")
    third = SimpleNamespace(
        models=first.models, base_urls=["https://other.invalid/v1"], api_key="SECRET"
    )
    assert len({_model_identity(client) for client in (first, second, third)}) == 3
    assert "private" not in _model_identity(first) and "SECRET" not in _model_identity(first)


def test_factory_model_change_invalidates_already_collected_evidence(case):
    client = FakeClient(Steps([unknown()]))
    client.models = ["model-a"]

    def change(context):
        client.models = ["model-b"]
        return query(read(2))

    client.steps = Steps([query(read()), change])
    outcome = make_investigation_runner(config(case), case.semantic_map, client)(
        case.projection, case.profile, case.unit
    )
    assert outcome.stop_reason == "investigation_identity_changed"
    assert outcome.evidence_count == 1 and outcome.report is None


def test_coordinator_unit_budget_records_deferred_without_model_calls(case):
    once = report(case, ["source:src/demo.c:3"])

    def never(*_):
        pytest.fail("deferred worker invoked")

    never.max_units = 0
    coord = coordinator(case, report_runner=lambda *_: once, investigation_runner=never)
    _planned, state = coord.run(case.semantic_map)
    investigation = state["investigation"]
    assert investigation["deferred_unit_count"] == 1 and investigation["attempted_unit_count"] == 0
    assert investigation["outcomes"][0]["stop_reason"] == "unit_budget_deferred"
    assert investigation["uncovered_unit_ids"] == [case.unit.unit_id]


def test_coordinator_requires_gap_and_default_is_off(case):
    once = replace(report(case, ["source:src/demo.c:3"]), unresolved_facts=())
    coord = coordinator(
        case, report_runner=lambda *_: once, investigation_runner=lambda *_: pytest.fail("no gap")
    )
    _planned, state = coord.run(case.semantic_map)
    assert state["investigation"]["attempted_unit_count"] == 0
    _planned, default = coordinator(case, report_runner=lambda *_: once).run(case.semantic_map)
    assert default["investigation"]["mode"] == "off"


@pytest.mark.parametrize("cancel_mode", ["raised", "outcome", "pre_cancelled"])
def test_coordinator_parent_cancellation_defers_remaining_eligible_units(case, cancel_mode):
    from zscope.orchestration.bounded_investigation import BoundedInvestigationOutcome

    token = CancellationToken()
    calls = []

    def investigate(_projection, _profile, unit):
        calls.append(unit.unit_id)
        if cancel_mode == "raised":
            raise CancellationError("parent stopped")
        return BoundedInvestigationOutcome(stop_reason="deadline_exceeded", owner_cancelled=True)

    if cancel_mode == "pre_cancelled":
        token.cancel()
    coord = coordinator(case, investigation_runner=investigate)
    units = [case.unit, replace(case.unit, unit_id="second", fingerprint="second-fingerprint")]
    reports = [
        replace(report(case, ["source:src/demo.c:3"]), unit_id=unit.unit_id) for unit in units
    ]
    with bind_cancellation_token(token):
        state = coord._run_investigations(case.semantic_map, units, reports)
    expected_calls = [] if cancel_mode == "pre_cancelled" else [case.unit.unit_id]
    assert calls == expected_calls
    assert state["status"] == "interrupted"
    assert state["attempted_unit_count"] == len(expected_calls)
    assert state["deferred_unit_count"] == 2 - len(expected_calls)
    assert state["uncovered_unit_ids"] == [unit.unit_id for unit in units]
    assert state["completed_report_count"] == 0
    assert state["outcomes"][-1]["stop_reason"] == "cancelled_deferred"


def test_coordinator_local_deadline_does_not_defer_next_unit(case):
    from zscope.orchestration.bounded_investigation import BoundedInvestigationOutcome

    calls = []

    def investigate(_projection, _profile, unit):
        calls.append(unit.unit_id)
        return BoundedInvestigationOutcome(stop_reason="deadline_exceeded", owner_cancelled=False)

    coord = coordinator(case, investigation_runner=investigate)
    units = [case.unit, replace(case.unit, unit_id="second", fingerprint="second-fingerprint")]
    reports = [
        replace(report(case, ["source:src/demo.c:3"]), unit_id=unit.unit_id) for unit in units
    ]
    state = coord._run_investigations(case.semantic_map, units, reports)
    assert calls == [unit.unit_id for unit in units]
    assert state["status"] == "partial"
    assert state["attempted_unit_count"] == 2 and state["deferred_unit_count"] == 0
    assert state["uncovered_unit_ids"] == calls
