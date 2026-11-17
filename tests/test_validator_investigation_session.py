from types import SimpleNamespace

import pytest

from zscope.agents.validator_agent.investigation import InvestigationSession
from zscope.agents.validator_agent.output import DecisionOutput
from zscope.common.cancellation import CancellationError, CancellationToken, bind_cancellation_token
from zscope.common.validator_protocol import ValidatorResultV3
from zscope.tools.contracts import tool_result
from zscope.core.validation.review_protocol import REVIEW_VERSION


def _session(execute=None, **overrides):
    return InvestigationSession(
        {
            "candidate_subject_uid": "OBJECT_1",
            "candidate_build_context_id": "BUILD_1",
            "evidence_slice": {
                "obligation": {"candidate_uid": "CAND_1", "validation_cluster_uid": "VAL_1"},
                "allowed_missing_fact_kinds": ["value_range"],
                "evidence_ref_catalog": {},
            },
            **overrides,
        },
        execute_tool=execute or (lambda name, args: {"success": True, "data": {"code": "n < 8"}}),
        tools_schema=[],
        pass_kind="investigation_synthesis",
    )


def _fact(session):
    result = session("read_code", {"file_path": "demo.c"})
    return {
        "fact_kind": "value_range",
        "evidence_refs": [result["evidence_ref"]],
        "summary": "n is bounded by 8",
    }


def test_fact_registration_deduplicates_and_does_not_cross_sessions():
    first, second = _session(), _session(candidate_build_context_id="BUILD_2")
    args = _fact(first)
    result = first(first.fact_tool_name, args)
    assert result["success"]
    assert first(first.fact_tool_name, args) == result
    assert len(first.investigation_facts) == len(first.fact_ids) == 1
    assert result["fact"]["fact_uid"] in first.allowed_refs
    rejected = second(second.fact_tool_name, args)
    assert not rejected["success"]
    assert "prior TOOLFACT" in rejected["error"]
    assert not second.fact_ids


@pytest.mark.parametrize(
    "mutation",
    [
        {"extra": "not allowed"},
        {"summary": 123},
        {"summary": " "},
        {"fact_kind": "invented"},
        {"evidence_refs": [None]},
        {"evidence_refs": []},
    ],
)
def test_fact_recording_validates_arguments_before_mutating_evidence(mutation):
    session = _session()
    args = {**_fact(session), **mutation}
    assert not session(session.fact_tool_name, args)["success"]
    assert not session.investigation_facts
    assert not session.allowed_refs


def test_fact_reference_limit_is_enforced_locally():
    session = _session()
    args = _fact(session)
    args["evidence_refs"] *= 9
    assert not session(session.fact_tool_name, args)["success"]
    assert not session.investigation_facts


@pytest.mark.parametrize(
    "subject,build,scope,accepted",
    [
        ("OBJECT_1", "BUILD_1", "candidate_premise", True),
        ("OTHER_OBJECT", "BUILD_1", "candidate_premise", False),
        ("OBJECT_1", "", "candidate_premise", False),
        ("OBJECT_1", "BUILD_1", None, False),
        ("OBJECT_1", "BUILD_1", "invented_scope", False),
    ],
)
def test_counterexample_requires_exact_subject_build_and_claim_scope(
    subject, build, scope, accepted
):
    session = _session(autonomous_validation=True, candidate_build_context_id=build)
    args = {**_fact(session), "fact_kind": "counterexample", "subject_uid": subject}
    if scope is not None:
        args["claim_scope"] = scope
    assert session(session.fact_tool_name, args)["success"] == accepted
    assert bool(session.investigation_facts) == accepted


@pytest.mark.parametrize("subject,accepted", [("FALLBACK_OBJECT", True), ("OTHER", False)])
def test_counterexample_uses_the_resolved_obligation_subject(subject, accepted):
    session = _session(
        candidate_subject_uid="",
        autonomous_validation=True,
        evidence_slice={
            "obligation": {
                "candidate_uid": "CAND_1",
                "validation_cluster_uid": "VAL_1",
                "subject_uid": "FALLBACK_OBJECT",
            },
            "allowed_missing_fact_kinds": [],
            "evidence_ref_catalog": {},
        },
    )
    args = {
        **_fact(session),
        "fact_kind": "counterexample",
        "subject_uid": subject,
        "claim_scope": "candidate_premise",
    }
    assert session(session.fact_tool_name, args)["success"] is accepted
    assert bool(session.investigation_facts) is accepted


def test_failed_queries_cannot_be_registered_as_evidence():
    session = _session(lambda name, args: {"success": False, "error": "read failed"})
    result = session("read_code", {"file_path": "demo.c"})
    assert result["validator_new_evidence"] is False
    assert not session.tool_fact_catalog
    assert not session.observed_queries


@pytest.mark.parametrize("status", ["unavailable", "unsupported", "not_found"])
@pytest.mark.parametrize("data", [None, {"code": "misleading source"}])
def test_incomplete_tool_status_never_authorizes_evidence(status, data):
    session = _session(lambda name, args: tool_result(status=status, data=data))
    result = session("read_code", {"file_path": "demo.c"})
    assert result["validator_new_evidence"] is False
    assert "evidence_ref" not in result
    assert not session.tool_fact_catalog


@pytest.mark.parametrize("data", [None, {}, [], {"results": []}])
def test_envelope_diagnostics_are_not_evidence_or_progress(data):
    session = _session(
        lambda name, args: tool_result(
            data=data,
            providers=[args["file_path"]],
            warnings=["try another read"],
            next_actions=["search again"],
            coverage_details={"snapshot": args["file_path"]},
        )
    )
    for iteration in (1, 2):
        assert not session._zscope_start_iteration(iteration)
        result = session("read_code", {"file_path": f"query{iteration}.c"})
        assert result["validator_new_evidence"] is False
    assert session._zscope_start_iteration(3)
    assert not session.tool_fact_catalog


@pytest.mark.parametrize("status", ["ok", "partial"])
def test_partial_coverage_preserves_concrete_source_evidence(status):
    session = _session(
        lambda name, args: tool_result(
            status=status,
            data={"source": {"code": "n < 8", "status": "current"}},
        )
    )
    assert session(session.fact_tool_name, _fact(session))["success"]


def test_error_body_cannot_authorize_an_otherwise_successful_payload():
    session = _session(
        lambda name, args: tool_result(
            data={"code": "untrusted response"},
            error={"code": "failed"},
        )
    )
    assert session("read_code", {"file_path": "demo.c"})["validator_new_evidence"] is False


@pytest.mark.parametrize(
    "collection", ["records", "edges", "paths", "findings", "symbols", "matches", "files"]
)
@pytest.mark.parametrize("has_records", [False, True])
def test_collection_metadata_cannot_replace_missing_records(collection, has_records):
    session = _session(
        lambda name, args: tool_result(
            status="partial",
            data={
                collection: [{"file": "demo.c", "code": "n < 8"}] if has_records else [],
                "subject": {"file": "demo.c", "name": "f"},
                "kind": "program_facts",
                "relation": "call",
                "summary": {"build_context_id": "BUILD_1", "freshness": "stale"},
                "provenance": {"revision": "current"},
            },
        )
    )
    result = session("read_code", {"file_path": "demo.c"})
    assert result["validator_new_evidence"] is has_records
    assert bool(session.tool_fact_catalog) is has_records


def test_rephrasing_keeps_claims_but_does_not_reset_progress():
    session = _session()
    assert not session._zscope_start_iteration(1)
    fact = _fact(session)
    for iteration in (1, 2, 3):
        if iteration > 1:
            assert not session._zscope_start_iteration(iteration)
        assert session(
            session.fact_tool_name,
            {
                **fact,
                "summary": f"n is bounded by 8 (restatement {iteration})",
            },
        )["success"]
    assert session._zscope_start_iteration(4)
    assert len(session.investigation_facts) == 3


def test_new_fact_kind_and_source_each_advance_progress():
    session = _session(
        lambda name, args: tool_result(data={"code": args["file_path"]}),
        autonomous_validation=True,
    )
    session._zscope_start_iteration(1)
    first = _fact(session)
    session(session.fact_tool_name, first)
    assert not session._zscope_start_iteration(2)
    session(session.fact_tool_name, {**first, "fact_kind": "guard_dominance"})
    assert not session._zscope_start_iteration(3)
    assert session.consecutive_no_evidence_fact_iterations == 0
    second = session("read_code", {"file_path": "caller.c"})
    assert not session._zscope_start_iteration(4)
    assert session.consecutive_no_evidence_fact_iterations == 0
    second_fact = {**first, "evidence_refs": [second["evidence_ref"]]}
    session(session.fact_tool_name, second_fact)
    assert not session._zscope_start_iteration(5)
    for refs in (
        [*first["evidence_refs"], second["evidence_ref"]],
        [second["evidence_ref"], *first["evidence_refs"]],
    ):
        session(session.fact_tool_name, {**first, "evidence_refs": refs})
    assert not session._zscope_start_iteration(6)
    assert session._zscope_start_iteration(7)


def test_cancellation_during_query_cannot_publish_partial_evidence():
    token = CancellationToken()

    def execute(name, args):
        token.cancel("scan_cancelled")
        return {"success": True, "data": {"code": "partial evidence"}}

    session = _session(execute)
    with bind_cancellation_token(token), pytest.raises(CancellationError, match="scan_cancelled"):
        session("read_code", {"file_path": "demo.c"})
    assert not session.tool_fact_catalog
    assert not session.observed_queries


def test_review_receives_registered_fact_with_the_fact_tool_name():
    records = []
    review = SimpleNamespace(
        schemas=lambda: [],
        record_result=lambda name, args, result: records.append((name, result)),
    )
    session = _session(_review_session=review)
    session(session.fact_tool_name, _fact(session))
    name, result = records[-1]
    assert name == session.fact_tool_name
    assert result["fact"]["fact_uid"] in session.fact_ids


def _terminal(**changes):
    return {
        **ValidatorResultV3(
            candidate_uid="CAND_1",
            validation_cluster_uid="VAL_1",
            validation_pass="investigation_synthesis",
            verdict="uncertain",
            reasoning="The condition remains unknown",
            positive_evidence=(),
            negative_evidence=(),
            evidence_refs=(),
            blocking_negative_evidence=False,
            missing_fact_request=None,
            stop_reason="investigation_exhausted",
        ).to_dict(),
        **changes,
    }


@pytest.mark.parametrize(
    "changes",
    [
        {"evidence_refs": [{}]},
        {"verdict": {}},
        {"candidate_uid": "OTHER_CANDIDATE"},
        {"validation_cluster_uid": "OTHER_CLUSTER"},
        {"pass": "initial"},
    ],
)
def test_invalid_terminals_are_rejected_without_raising(changes):
    assert _session().accept_result(_terminal(**changes))["valid"] is False


def test_terminal_missing_fact_request_respects_candidate_policy():
    result = _session().accept_result(
        _terminal(
            stop_reason="missing_fact",
            missing_fact_request={"fact_kind": "caller_contract", "reason": "need callers"},
        )
    )
    assert not result["valid"]
    assert result["error"] == "unsupported investigation fact kind"


def _decision(**changes):
    result = _terminal(**changes)
    return {
        key: result[key]
        for key in (
            "verdict",
            "reasoning",
            "positive_evidence",
            "negative_evidence",
            "evidence_refs",
            "blocking_negative_evidence",
            "missing_fact_request",
        )
    }


@pytest.mark.parametrize("verdict", ["verified", "rejected", "uncertain"])
def test_compact_terminal_binds_public_identity_and_stop_reason(verdict):
    session = _session()
    raw = _decision(verdict=verdict)
    accepted = session.accept_result(raw)
    assert accepted["valid"]
    public = accepted["payload"]
    assert public["candidate_uid"] == "CAND_1"
    assert public["validation_cluster_uid"] == "VAL_1"
    assert public["pass"] == "investigation_synthesis"
    assert public["stop_reason"] == (
        "no_evidence_gain" if verdict == "uncertain" else "decision_complete"
    )
    assert session.accepted_result == public
    assert session.terminal_output.payload is raw
    assert "stop_reason" not in raw


def test_compact_missing_fact_request_binds_supplied_subject_and_function():
    session = _session(
        candidate_subject_uid="",
        evidence_slice={
            "obligation": {
                "candidate_uid": "CAND_1",
                "validation_cluster_uid": "VAL_1",
                "subject_uid": "OBJECT_FROM_OBLIGATION",
                "function_uid": "FUNCTION_1",
            },
            "allowed_missing_fact_kinds": ["value_range"],
        },
    )
    accepted = session.accept_result(
        _decision(missing_fact_request={"fact_kind": "value_range", "reason": "需要上界"})
    )
    assert accepted["valid"]
    assert accepted["payload"]["stop_reason"] == "missing_fact"
    assert accepted["payload"]["missing_fact_request"] == {
        "fact_kind": "value_range",
        "reason": "需要上界",
        "subject_uid": "OBJECT_FROM_OBLIGATION",
        "function_uid": "FUNCTION_1",
    }


@pytest.mark.parametrize(
    "changes",
    [
        {"candidate_uid": "OTHER"},
        {"stop_reason": "decision_complete"},
        {
            "missing_fact_request": {
                "fact_kind": "value_range",
                "reason": "上界",
                "subject_uid": "INVENTED",
            }
        },
        {
            "verdict": "verified",
            "missing_fact_request": {"fact_kind": "value_range", "reason": "上界"},
        },
    ],
)
def test_compact_terminal_rejects_mixed_scope_and_inconsistent_requests(changes):
    session = _session()
    assert not session.accept_result({**_decision(), **changes})["valid"]
    assert session.accepted_result is None


def test_terminal_reuses_decoded_output_and_clears_an_earlier_verdict(monkeypatch):
    session = _session()
    decoded = DecisionOutput.from_payload(_decision())
    monkeypatch.setattr(DecisionOutput, "from_payload", lambda value: pytest.fail("decoded twice"))
    assert session.accept_result(decoded)["valid"]
    assert session.terminal_output is decoded
    invalid = DecisionOutput({"verdict": "invalid"}, None)
    assert not session.accept_result(invalid)["valid"]
    assert session.terminal_output is invalid
    assert session.accepted_result is None


def _review(decision, *, version=True):
    result = {
        "decision": decision,
        "prior_rejection": {
            "assessment": "not_applicable",
            "reason": "无先前拒绝",
            "evidence_refs": [],
        },
        "defect_case": {
            "status": "incomplete",
            "subject": "对象",
            "source": "入口",
            "sink": "访问",
            "path": "入口到访问",
            "trigger": "上界未知",
            "guard_analysis": "待核实",
            "evidence_refs": [],
            "missing_conditions": ["上界"],
        },
    }
    if version:
        result["schema_version"] = REVIEW_VERSION
    return result


@pytest.mark.parametrize(
    "compact,version,accepted",
    [
        (True, False, True),
        (True, True, True),
        (False, True, True),
        (False, False, False),
    ],
)
def test_review_accepts_new_wire_and_preserves_historical_envelope_contract(
    compact, version, accepted
):
    session = _session(review_protocol_enabled=True)
    raw = _review(_decision() if compact else _terminal(), version=version)
    result = session.accept_result(raw)
    assert result["valid"] == accepted
    if accepted:
        assert session.accepted_result == result["payload"]
        assert session.accepted_review["envelope"]["schema_version"] == REVIEW_VERSION
        assert session.accepted_review["envelope"]["decision"]["candidate_uid"] == "CAND_1"
        assert session.terminal_output.payload is raw


@pytest.mark.parametrize("compact", [False, True])
def test_review_rejects_wrong_version_and_clears_old_review(compact):
    session = _session(review_protocol_enabled=True)
    decision = _decision() if compact else _terminal()
    assert session.accept_result(_review(decision))["valid"]
    invalid = {**_review(decision), "schema_version": "unsupported"}
    assert not session.accept_result(invalid)["valid"]
    assert session.accepted_result is None
    assert session.accepted_review == {}


def test_review_caches_adjudicated_decision_instead_of_the_proposed_verdict():
    session = _session(review_protocol_enabled=True)
    raw = _review(_decision(verdict="verified"), version=False)
    result = session.accept_result(raw)
    assert result["valid"]
    assert raw["decision"]["verdict"] == "verified"
    assert session.accepted_result["verdict"] == "uncertain"
    assert session.accepted_result["stop_reason"] == "unsupported_fact"


@pytest.mark.parametrize("value", [0, -1, False, 8, 0.5])
def test_numeric_and_boolean_program_values_are_evidence(value):
    session = _session(lambda name, args: tool_result(data={"records": [{"value": value}]}))
    assert session("get_semantic_context", {"query": "f"})["validator_new_evidence"]


def test_progress_preserves_record_associations_and_source_whitespace():
    bodies = iter(
        [
            {"records": [{"name": "a", "value": 0}, {"name": "b", "value": 1}]},
            {"records": [{"name": "a", "value": 1}, {"name": "b", "value": 0}]},
            {"code": 'puts("a b");'},
            {"code": 'puts("a  b");'},
        ]
    )
    session = _session(lambda name, args: tool_result(data=next(bodies)))
    for index in range(4):
        assert session("read_code", {"start_line": index + 1})["validator_new_evidence"]


def test_record_reordering_and_pagination_metadata_are_not_progress():
    session = _session(
        lambda name, args: tool_result(
            data={
                "records": (
                    [{"name": "a"}, {"name": "b"}]
                    if args["offset"] == 0
                    else [{"name": "b"}, {"name": "a"}]
                ),
                "summary": {"version": args["offset"]},
            }
        )
    )
    assert session("get_semantic_context", {"offset": 0})["validator_new_evidence"]
    assert not session("get_semantic_context", {"offset": 2})["validator_new_evidence"]


def test_semantic_cache_diagnostics_without_payload_are_not_evidence():
    session = _session(
        lambda name, args: tool_result(
            status="partial",
            data={
                "kind": "function",
                "subject": {"name": args["symbol_id"]},
                "snapshot": {"status": "stale", "data": {"value": 8}, "reason": "changed"},
                "contract": {},
                "security_semantics": {"status": "unavailable", "records": []},
            },
        )
    )
    assert not session("get_semantic_context", {"symbol_id": "f"})["validator_new_evidence"]


def test_semantic_record_reordering_is_not_progress():
    session = _session(
        lambda name, args: tool_result(
            data={
                "subject": {"name": "f"},
                "snapshot": {"status": "missing", "data": None},
                "security_semantics": {"status": "current", "records": args["records"]},
            }
        )
    )
    assert session("get_semantic_context", {"records": [{"id": "a"}, {"id": "b"}]})[
        "validator_new_evidence"
    ]
    assert not session("get_semantic_context", {"records": [{"id": "b"}, {"id": "a"}]})[
        "validator_new_evidence"
    ]


def test_review_fact_page_without_items_is_not_evidence():
    session = _session(
        lambda name, args: {
            "success": True,
            "data": {
                "items": [],
                "file_path": "demo.c",
                "function": "f",
                "complete": True,
                "fact_store_id": "STORE_1",
                "total": 0,
                "next_offset": None,
            },
        }
    )
    assert not session("query_validation_facts", {})["validator_new_evidence"]


@pytest.mark.parametrize(
    "data",
    [
        {"complete": False, "reason": "stale_fact_dependencies", "file_path": "demo.c"},
        {"rows": [], "complete": False, "known_call_site_count": 0, "file_path": "demo.c"},
        {
            "claim_kind": "auto",
            "status": "unknown",
            "reason": "incomplete_compiler_facts",
            "file_path": "demo.c",
        },
    ],
)
def test_review_diagnostics_cannot_authorize_facts(data):
    session = _session(lambda name, args: {"success": True, "data": data})
    assert not session("check_validation_claim", {})["validator_new_evidence"]


def test_symbol_read_uses_returned_location_and_actual_truncation():
    session = _session(
        lambda name, args: tool_result(
            data={
                "symbol": {
                    "name": "f",
                    "location": {"file": "demo.c", "start_line": 3, "end_line": 20},
                },
                "source": {"file": "demo.c", "start_line": 3, "end_line": 8, "code": "n < 8"},
            }
        )
    )
    result = session("read_code", {"symbol_id": "SYMBOL_1", "end_line": 20})
    record = session.tool_fact_catalog[result["evidence_ref"]]
    assert record["location"] == {"file": "demo.c", "function": "f", "start_line": 3, "end_line": 8}


def test_graph_evidence_retains_callsite_location():
    session = _session(
        lambda name, args: tool_result(
            data={
                "edges": [
                    {
                        "source": {"name": "f", "location": {"file": "demo.c", "start_line": 2}},
                        "target": {"name": "g"},
                        "site": {"file": "demo.c", "line": 9, "column": 2},
                    }
                ]
            }
        )
    )
    result = session("query_code_graph", {"symbol_id": "SYMBOL_1"})
    assert session.tool_fact_catalog[result["evidence_ref"]]["location"]["start_line"] == 9


def test_non_counterexample_cannot_invent_subjects_to_extend_progress():
    session = _session(autonomous_validation=True)
    args = _fact(session)
    result = session(session.fact_tool_name, {**args, "subject_uid": "OTHER_OBJECT"})
    assert not result["success"]
    assert not session.fact_progress


def test_redundant_fact_refs_do_not_create_a_second_claim():
    session = _session()
    args = _fact(session)
    first = session(session.fact_tool_name, args)
    second = session(session.fact_tool_name, {**args, "evidence_refs": args["evidence_refs"] * 2})
    assert first == second
    assert len(session.investigation_facts) == 1


def test_fact_cannot_relabel_evidence_from_another_build():
    session = _session(
        lambda name, args: tool_result(
            data={
                "records": [
                    {
                        "build_context_id": "BUILD_2",
                        "value": 8,
                    }
                ]
            }
        )
    )
    args = _fact(session)
    result = session(session.fact_tool_name, args)
    assert result == {"success": False, "error": "fact evidence belongs to a different build"}
    assert not session.fact_ids
    assert not session.fact_progress


def test_raw_evidence_identity_is_bound_to_the_current_candidate_build():
    first, second = _session(), _session(candidate_build_context_id="BUILD_2")
    assert _fact(first)["evidence_refs"] != _fact(second)["evidence_refs"]


def test_fact_can_use_current_build_evidence():
    session = _session(
        lambda name, args: tool_result(
            data={
                "records": [
                    {
                        "build_context_id": "BUILD_1",
                        "value": 8,
                    }
                ]
            }
        )
    )
    result = session(session.fact_tool_name, _fact(session))
    assert result["success"]
    assert result["fact"]["build_context_id"] == "BUILD_1"


def test_query_build_cannot_be_hidden_by_a_result_without_build_ids():
    session = _session()
    read = session("get_semantic_context", {"build_context_id": "BUILD_2"})
    result = session(
        session.fact_tool_name,
        {
            "fact_kind": "value_range",
            "evidence_refs": [read["evidence_ref"]],
            "summary": "n < 8",
        },
    )
    assert not result["success"]
    assert not session.fact_ids


def test_failed_query_can_retry_but_does_not_extend_no_gain_budget():
    calls = []

    def fail(name, args):
        calls.append(args)
        return {"success": False, "error": "temporarily unavailable"}

    session = _session(fail)
    for iteration in (1, 2):
        assert not session._zscope_start_iteration(iteration)
        result = session("read_code", {"file_path": "demo.c"})
        assert result["error"] == "temporarily unavailable"
    assert session._zscope_start_iteration(3)
    assert session("read_code", {"file_path": "demo.c"})["error"].startswith("validator_v3_no_new")
    assert len(calls) == 2


def test_exception_does_not_lock_query_or_publish_evidence():
    calls = []

    def execute(name, args):
        calls.append(args)
        if len(calls) == 1:
            raise RuntimeError("broken read")
        return tool_result(data={"code": "n < 8"})

    session = _session(execute)
    with pytest.raises(RuntimeError, match="broken read"):
        session("read_code", {"file_path": "demo.c"})
    assert not session.tool_fact_catalog
    assert not session.observed_queries
    assert session("read_code", {"file_path": "demo.c"})["validator_new_evidence"]
