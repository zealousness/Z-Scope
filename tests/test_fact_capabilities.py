import hashlib
import json
import threading
import time
from concurrent.futures import ThreadPoolExecutor

from zscope.agents.validator_agent.agent import ValidatorAgent
from zscope.core.validation.fact_capabilities import (
    ConcurrencyProofProvider,
    EvidenceAction,
    FactCapabilityRegistry,
    FunctionIRFactService,
    PathAndGuardProofProvider,
    ResourceProtocolProofProvider,
    verify_certificate_v2,
)
from zscope.core.validation.function_ir import FunctionIRGraph
from zscope.core.validation.proofs import deterministic_decision_proof


def _clang_graph(*, branch_release: bool = False) -> FunctionIRGraph:
    branch_statement = "free(p)" if branch_release else "pthread_mutex_lock(&mu)"
    evidence = {
        "clang_path": "clang",
        "code_snapshot_sha256": "a" * 64,
        "cfg_dump": {
            "summary": {
                "parse_ok": True,
                "function": "target",
                "function_section_unique": True,
                "entry_blocks": ["B4"],
                "exit_blocks": ["B0"],
                "blocks": [
                    {
                        "id": "B4",
                        "label": "(ENTRY)",
                        "successors": ["B3"],
                        "predecessors": [],
                        "statements": ["p = malloc(8)"],
                    },
                    {
                        "id": "B3",
                        "label": "",
                        "successors": ["B2", "B1"],
                        "predecessors": ["B4"],
                        "statements": ["if cond"],
                    },
                    {
                        "id": "B2",
                        "label": "",
                        "successors": ["B0"],
                        "predecessors": ["B3"],
                        "statements": [branch_statement],
                    },
                    {
                        "id": "B1",
                        "label": "",
                        "successors": ["B0"],
                        "predecessors": ["B3"],
                        "statements": ["sink(p)"],
                    },
                    {
                        "id": "B0",
                        "label": "(EXIT)",
                        "successors": [],
                        "predecessors": ["B2", "B1"],
                        "statements": [],
                    },
                ],
            }
        },
        "ast_dump": {
            "summary": {
                "target_function": {
                    "call_exprs": [
                        {"callee": "malloc", "line": 10},
                        {"callee": "sink", "line": 20},
                    ]
                }
            }
        },
    }
    graph = FunctionIRGraph.from_clang_evidence(
        evidence,
        function="target",
        file="src/anonymous.c",
    )
    assert graph is not None
    return graph


def _issue(**values):
    issue = {
        "function": "target",
        "file": "src/anonymous.c",
        "subject_uid": "p",
        "decision_region_uid": "REGION_1",
        "source": {"callee": "malloc", "line": 10},
        "sink": {"callee": "sink", "line": 20},
        "security_obligation": {
            "obligation_uid": "OBL_1",
            "subject_uid": "p",
            "decision_region_uid": "REGION_1",
            "required_fact_kinds": ["lockset"],
        },
    }
    issue.update(values)
    return issue


def _single_block_graph(statements, calls) -> FunctionIRGraph:
    evidence = {
        "code_snapshot_sha256": "c" * 64,
        "cfg_dump": {
            "summary": {
                "parse_ok": True,
                "function": "single_block",
                "function_section_unique": True,
                "entry_blocks": ["B1"],
                "exit_blocks": ["B0"],
                "blocks": [
                    {
                        "id": "B1",
                        "label": "(ENTRY)",
                        "successors": ["B0"],
                        "predecessors": [],
                        "statements": statements,
                    },
                    {
                        "id": "B0",
                        "label": "(EXIT)",
                        "successors": [],
                        "predecessors": ["B1"],
                        "statements": [],
                    },
                ],
            }
        },
        "ast_dump": {"summary": {"target_function": {"call_exprs": calls}}},
    }
    graph = FunctionIRGraph.from_clang_evidence(
        evidence,
        function="single_block",
        file="src/generic.c",
    )
    assert graph is not None
    return graph


def _minimal_clang_evidence(function: str = "target"):
    return {
        "clang_path": "clang",
        "code_snapshot_sha256": "d" * 64,
        "cfg_dump": {
            "ok": True,
            "summary": {
                "parse_ok": True,
                "function": function,
                "function_section_unique": True,
                "entry_blocks": ["B1"],
                "exit_blocks": ["B0"],
                "blocks": [
                    {
                        "id": "B1",
                        "label": "(ENTRY)",
                        "successors": ["B0"],
                        "predecessors": [],
                        "statements": ["consume(shared)"],
                    },
                    {
                        "id": "B0",
                        "label": "(EXIT)",
                        "successors": [],
                        "predecessors": ["B1"],
                        "statements": [],
                    },
                ],
            },
        },
        "ast_dump": {"summary": {"target_function": {"call_exprs": []}}},
    }


def test_function_ir_resolves_file_from_location_and_builds_single_flight(monkeypatch) -> None:
    service = FunctionIRFactService(None, enabled=True)
    calls = 0
    calls_lock = threading.Lock()

    def collect(**kwargs):
        nonlocal calls
        with calls_lock:
            calls += 1
        time.sleep(0.05)
        assert kwargs["file_path"] == "src/anonymous.c"
        assert kwargs["start_line"] == 17
        return _minimal_clang_evidence()

    monkeypatch.setattr(service._clang, "collect_for_function", collect)
    issue = {
        "function": "target",
        "location": "src/anonymous.c:17",
        "security_obligation": {
            "subject_uid": "shared",
            "decision_region_uid": "REGION_SHARED",
            "required_fact_kinds": ["lockset"],
        },
    }

    with ThreadPoolExecutor(max_workers=8) as executor:
        graphs = list(executor.map(lambda _: service.graph(dict(issue), {}), range(16)))

    assert calls == 1
    assert all(graph is not None for graph in graphs)
    assert len({graph.ir_sha256 for graph in graphs if graph is not None}) == 1


def test_function_ir_capability_reports_specific_build_failure(monkeypatch) -> None:
    service = FunctionIRFactService(None, enabled=True)
    monkeypatch.setattr(
        service._clang,
        "collect_for_function",
        lambda **_: {
            "status": "compile_command_not_found",
            "compile_command_found": False,
        },
    )
    issue = {
        "function": "target",
        "location": "src/anonymous.c:23",
        "security_obligation": {
            "subject_uid": "shared",
            "decision_region_uid": "REGION_SHARED",
        },
    }

    capabilities = service.capabilities(issue, {}, ["lockset"])

    assert capabilities[0].executable_for_subject_region is False
    assert capabilities[0].unavailable_reason == "function_ir_compile_command_not_found"


def test_cfg_join_uses_must_intersection_and_does_not_merge_branch_lock() -> None:
    graph = _clang_graph()

    locksets = graph.must_hold_locksets()
    sink_statement = next(
        event.statement_uid for event in graph.events if event.callee == "sink"
    )

    assert locksets["B0"] == frozenset()
    result = ConcurrencyProofProvider().prove(
        graph,
        _issue(),
        "lockset",
        {"access_statement_uid": sink_statement},
    )
    assert result.status == "verified_true"
    assert result.fact is not None
    assert result.fact["value"]["must_hold_locks"] == []
    assert verify_certificate_v2(result.certificate)


def test_statement_order_distinguishes_access_before_and_after_lock() -> None:
    graph = _clang_graph()
    sink_statement = next(
        event.statement_uid for event in graph.events if event.callee == "sink"
    )
    lock_statement = next(
        event.statement_uid for event in graph.events if event.kind == "lock_acquire"
    )

    locksets = graph.must_hold_locksets_at_statements()

    assert locksets[lock_statement] == frozenset()
    assert locksets[sink_statement] == frozenset()


def test_same_block_lockset_uses_statement_order() -> None:
    evidence = {
        "code_snapshot_sha256": "b" * 64,
        "cfg_dump": {
            "summary": {
                "parse_ok": True,
                "function": "anonymous_worker",
                "function_section_unique": True,
                "entry_blocks": ["B1"],
                "exit_blocks": ["B0"],
                "blocks": [
                    {
                        "id": "B1",
                        "label": "(ENTRY)",
                        "successors": ["B0"],
                        "predecessors": [],
                        "statements": ["pthread_mutex_lock(&gate)", "consume(shared)"],
                    },
                    {
                        "id": "B0",
                        "label": "(EXIT)",
                        "successors": [],
                        "predecessors": ["B1"],
                        "statements": [],
                    },
                ],
            }
        },
        "ast_dump": {
            "summary": {
                "target_function": {
                    "call_exprs": [
                        {"callee": "pthread_mutex_lock", "line": 3},
                        {"callee": "consume", "line": 4},
                    ]
                }
            }
        },
    }
    graph = FunctionIRGraph.from_clang_evidence(
        evidence,
        function="anonymous_worker",
        file="src/worker.c",
    )
    assert graph is not None
    sink_statement = next(
        event.statement_uid for event in graph.events if event.callee == "consume"
    )

    assert graph.must_hold_locksets_at_statements()[sink_statement] == frozenset({"gate"})


def test_same_block_path_rejects_source_after_sink() -> None:
    graph = _single_block_graph(
        ["consume(value)", "value = read_input()"],
        [
            {"callee": "consume", "line": 4},
            {"callee": "read_input", "line": 5},
        ],
    )
    source = next(event.statement_uid for event in graph.events if event.callee == "read_input")
    sink = next(event.statement_uid for event in graph.events if event.callee == "consume")

    assert graph.reachable("B1", "B1") == ("B1",)
    assert graph.statement_reachable(source, sink) == ()


def test_non_call_sink_is_resolved_by_structured_expression() -> None:
    graph = _single_block_graph(
        ["pthread_mutex_lock(&gate)", "shared_len = input_len"],
        [{"callee": "pthread_mutex_lock", "line": 3}],
    )
    issue = _issue(
        function="single_block",
        file="src/generic.c",
        sink={
            "file": "src/generic.c",
            "line": 4,
            "operation": "shared_len = input_len;",
        },
        function_ir_graph=graph.to_dict(),
    )
    service = FunctionIRFactService(None, enabled=False)

    actions = service.actions(issue, {}, ["lockset"])

    assert len(actions) == 1
    result = service.execute(actions[0], issue, {})
    assert result.status == "verified_true"
    assert result.fact is not None
    assert result.fact["value"]["must_hold_locks"] == ["gate"]


def test_same_block_guard_requires_guard_before_sink() -> None:
    graph = _single_block_graph(
        ["consume(value)", "if (value < limit)"],
        [{"callee": "consume", "line": 4}],
    )
    sink = next(event.statement_uid for event in graph.events if event.callee == "consume")
    guard = next(
        statement.statement_uid
        for block in graph.blocks
        for statement in block.statements
        if statement.text.startswith("if")
    )

    assert graph.statement_dominates(guard, sink) is False


def test_guard_dominance_certificate_is_not_a_safety_counterproof() -> None:
    graph = _single_block_graph(
        ["if (value < limit)", "consume(value)"],
        [{"callee": "consume", "line": 4}],
    )
    sink = next(event.statement_uid for event in graph.events if event.callee == "consume")
    guard = next(
        statement.statement_uid
        for block in graph.blocks
        for statement in block.statements
        if statement.text.startswith("if")
    )
    issue = _issue(
        function="single_block",
        file="src/generic.c",
        sink={"callee": "consume", "line": 4},
        function_ir_graph=graph.to_dict(),
    )

    result = PathAndGuardProofProvider().prove(
        graph,
        issue,
        "guard_dominance",
        {"guard_statement_uid": guard, "sink_statement_uid": sink},
    )
    service = FunctionIRFactService(None, enabled=False)
    action = next(iter(service.actions(issue, {}, ["guard_dominance"])))
    resolved = service.execute(action, issue, {})

    assert result.status == "verified_true"
    assert result.fact is not None
    assert result.fact["value"]["guard_dominates_sink"] is True
    assert resolved.fact is not None
    assert "deterministic_proof" not in resolved.fact


def test_same_block_happens_before_requires_event_order() -> None:
    graph = _single_block_graph(
        ["pthread_join(worker, 0)", "pthread_create(worker, 0, run, 0)"],
        [
            {"callee": "pthread_join", "line": 4},
            {"callee": "pthread_create", "line": 5},
        ],
    )
    create = next(event.event_uid for event in graph.events if event.kind == "thread_create")
    join = next(event.event_uid for event in graph.events if event.kind == "thread_join")

    assert graph.event_precedes(create, join) == ()


def test_certificate_backed_decision_proof_rejects_tampering() -> None:
    graph = _clang_graph(branch_release=False)
    # Remove the observation call so cleanup absence is not confused with an
    # unresolved external ownership-transfer contract.
    raw = graph.to_dict()
    for event in raw["events"]:
        if event["callee"] == "sink":
            event["kind"] = "return"
            event["callee"] = ""
            event["subject_symbols"] = []
    raw.pop("ir_sha256")
    raw["ir_sha256"] = hashlib.sha256(
        json.dumps(
            raw,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            default=str,
        ).encode("utf-8")
    ).hexdigest()
    service = FunctionIRFactService(None, enabled=False)
    issue = _issue(
        function_ir_graph=raw,
        security_obligation={
            "obligation_uid": "OBL_CLEANUP",
            "subject_uid": "p",
            "decision_region_uid": "REGION_1",
            "required_fact_kinds": ["cleanup_coverage"],
        },
    )

    fact = service.resolve_first("cleanup_coverage", issue, {})

    assert fact is not None
    proof = fact["deterministic_proof"]
    issue["deterministic_proofs"] = [proof]
    assert deterministic_decision_proof(issue, outcome="confirm") is not None
    proof["verification_certificate"]["coverage"] = "partial"
    assert deterministic_decision_proof(issue, outcome="confirm") is None


def test_cleanup_certificate_enumerates_all_exits_and_reports_uncovered_path() -> None:
    graph = _clang_graph(branch_release=True)

    result = ResourceProtocolProofProvider().prove(
        graph,
        _issue(),
        "cleanup_coverage",
        {"resource_symbol": "p"},
    )

    assert result.status == "verified_true"
    assert result.fact is not None
    assert result.fact["value"]["cleanup_complete"] is False
    assert result.fact["value"]["uncovered_exits"] == ["B0"]
    tampered = dict(result.certificate)
    tampered["coverage"] = "partial"
    assert verify_certificate_v2(tampered) is False


def test_capability_registry_requires_real_subject_region_action() -> None:
    service = FunctionIRFactService(None, enabled=False)
    issue = _issue(function_ir_graph=_clang_graph().to_dict())
    registry = FactCapabilityRegistry(service)

    actions = registry.executable_actions(issue, {}, ["lockset", "caller_contract"])
    capabilities = registry.inspect(issue, {}, ["lockset", "caller_contract"])

    assert {value.fact_kind for value in actions} == {"lockset"}
    by_kind = {value.fact_kind: value for value in capabilities}
    assert by_kind["lockset"].executable_for_subject_region is True
    assert by_kind["caller_contract"].executable_for_subject_region is False
    assert registry.executable_actions(issue, {}, []) == ()


class _ActionLLM:
    models = ["unit-model"]

    def __init__(self):
        self.schemas = []

    def run_conversation_with_tools(self, **kwargs):
        self.schemas = kwargs["tools_schema"]
        executor = kwargs["tool_executor"]
        assert executor._zscope_start_iteration(1) is False
        first = executor("execute_validator_evidence_action", {"action_id": "ACTION_1"})
        assert first["status"] == "unknown"
        assert executor._zscope_start_iteration(2) is False
        second = executor("execute_validator_evidence_action", {"action_id": "ACTION_2"})
        assert second["status"] == "unknown"
        assert executor._zscope_start_iteration(3) is True
        terminal = {
            "schema_version": "zscope.validator-result.v3",
            "candidate_uid": "CAND_1",
            "validation_cluster_uid": "VAL_1",
            "pass": "investigation_synthesis",
            "verdict": "uncertain",
            "reasoning": "finite actions did not close the clause",
            "positive_evidence": [],
            "negative_evidence": [],
            "evidence_refs": [],
            "blocking_negative_evidence": False,
            "missing_fact_request": None,
            "stop_reason": "investigation_exhausted",
        }
        accepted = kwargs["terminal_tool_handler"](terminal)
        return {
            "terminal_tool_payload": accepted["payload"],
            "terminal_tool_valid": True,
            "iterations": 2,
            "tool_call_count": 2,
            "cumulative_prompt_tokens": 10,
            "cumulative_completion_tokens": 5,
            "cumulative_total_tokens": 15,
        }


def test_v3_action_mode_exposes_no_generic_repository_tool_and_stops_after_two_rounds() -> None:
    llm = _ActionLLM()
    actions = [
        EvidenceAction(
            action_id=f"ACTION_{index}",
            fact_kind="lockset",
            provider_id="provider",
            verifier_id="verifier",
            subject_uid="p",
            decision_region_uid="REGION_1",
            fixed_parameters={"access_block_uid": f"B{index}"},
            description="fixed action",
        ).to_dict()
        for index in (1, 2)
    ]

    response = ValidatorAgent(llm, []).investigate(
        {
            "finding_uid": "CAND_1",
            "validation_cluster_uid": "VAL_1",
            "evidence_slice": {
                "obligation": {
                    "candidate_uid": "CAND_1",
                    "validation_cluster_uid": "VAL_1",
                    "subject_uid": "p",
                    "decision_region_uid": "REGION_1",
                },
                "decision_facts": {"missing_fact_kinds": ["lockset"]},
                "evidence_ref_catalog": {},
            },
        },
        evidence_actions=actions,
        evidence_action_executor=lambda action_id: {
            "status": "unknown",
            "reason_code": f"no_witness:{action_id}",
            "verified_fact": None,
        },
    )

    assert response.success is True
    names = {value["function"]["name"] for value in llm.schemas}
    assert names == {"execute_validator_evidence_action", "emit_validator_result_v3"}
    assert response.metadata["validator_no_new_evidence_fact_stop"] is True


def test_v3_action_terminal_authority_stops_when_no_executable_clause_remains() -> None:
    class TerminalAfterActionLLM:
        models = ["unit-model"]

        def run_conversation_with_tools(self, **kwargs):
            executor = kwargs["tool_executor"]
            outcome = executor(
                "execute_validator_evidence_action",
                {"action_id": "ACTION_1"},
            )
            assert outcome["status"] == "verified_true"
            terminal = executor._zscope_programmatic_terminal_payload()
            assert terminal["verdict"] == "uncertain"
            assert terminal["stop_reason"] == "investigation_exhausted"
            return {
                "terminal_tool_payload": terminal,
                "terminal_tool_valid": True,
                "iterations": 1,
                "tool_call_count": 1,
                "cumulative_prompt_tokens": 10,
                "cumulative_completion_tokens": 5,
                "cumulative_total_tokens": 15,
            }

    fact = {
        "fact_uid": "FACT_1",
        "fact_kind": "lockset",
        "satisfies_fact_kinds": ["lockset"],
    }
    response = ValidatorAgent(TerminalAfterActionLLM(), []).investigate(
        {
            "finding_uid": "CAND_1",
            "validation_cluster_uid": "VAL_1",
            "evidence_slice": {
                "obligation": {
                    "candidate_uid": "CAND_1",
                    "validation_cluster_uid": "VAL_1",
                    "subject_uid": "p",
                    "decision_region_uid": "REGION_1",
                },
                "decision_facts": {"missing_fact_kinds": ["lockset"]},
                "evidence_ref_catalog": {},
            },
        },
        evidence_actions=[
            EvidenceAction(
                action_id="ACTION_1",
                fact_kind="lockset",
                provider_id="provider",
                verifier_id="verifier",
                subject_uid="p",
                decision_region_uid="REGION_1",
                fixed_parameters={"access_statement_uid": "STMT_1"},
                description="fixed action",
            ).to_dict()
        ],
        evidence_action_executor=lambda _action_id: {
            "status": "verified_true",
            "reason_code": "certificate_complete",
            "verified_fact": fact,
            "terminal_authority": {
                "terminal": True,
                "disposition": "needs_review",
            },
        },
    )

    assert response.success is True
    assert response.data["verdict"] == "uncertain"
    assert response.metadata["iterations"] == 1
