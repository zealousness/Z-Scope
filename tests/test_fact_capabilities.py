import hashlib
import json
import threading
import time
from concurrent.futures import ThreadPoolExecutor

import pytest

from zscope.agents.proof_engine.agent import ProofEngineAgent
from zscope.core.candidates.decision_facts import security_obligation_for
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
from zscope.core.validation.proof_kernel import (
    ProofKernelEngine,
    build_cross_thread_function_ir,
)
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


def _governed_issue(issue, *, source, sink):
    source_identity = (
        json.dumps(source, sort_keys=True, separators=(",", ":"))
        if isinstance(source, dict)
        else str(source)
    )
    sink_identity = (
        json.dumps(sink, sort_keys=True, separators=(",", ":"))
        if isinstance(sink, dict)
        else str(sink)
    )
    issue.update(
        {
            "project_id": "PROJECT_TEST",
            "revision": "REV_TEST",
            "defect_class": str(issue.get("category") or issue.get("defect_class") or ""),
            "source_identity": source_identity,
            "sink_identity": sink_identity,
        }
    )
    subject_uid = str(
        issue.get("resource_identity")
        or issue.get("thread_object")
        or issue.get("subject_uid")
        or ""
    )
    issue["security_obligation"] = security_obligation_for(
        issue,
        project_id=issue["project_id"],
        revision=issue["revision"],
        defect_family=issue["defect_class"],
        source_uid=source_identity,
        sink_uid=sink_identity,
        subject_uid=subject_uid,
    ).to_dict()
    issue["security_obligation_v1"] = True
    return issue


def _single_block_graph(statements, calls, *, var_decls=()) -> FunctionIRGraph:
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
        "ast_dump": {
            "summary": {
                "parse_ok": True,
                "target_function": {
                    "call_exprs": calls,
                    "var_decls": list(var_decls),
                    "value_fact_coverage_complete": True,
                },
            }
        },
    }
    graph = FunctionIRGraph.from_clang_evidence(
        evidence,
        function="single_block",
        file="src/generic.c",
    )
    assert graph is not None
    return graph


def _named_single_block_graph(function, statements, calls, *, code_hash="9" * 64):
    evidence = {
        "clang_path": "clang",
        "code_snapshot_sha256": code_hash,
        "cfg_dump": {
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
        "ast_dump": {
            "summary": {
                "parse_ok": True,
                "target_function": {
                    "call_exprs": calls,
                    "value_fact_coverage_complete": True,
                },
            }
        },
    }
    graph = FunctionIRGraph.from_clang_evidence(
        evidence,
        function=function,
        file=f"src/{function}.c",
    )
    assert graph is not None
    return graph


class _CrossThreadProductIndex:
    def __init__(self, graphs):
        self._graphs = graphs

    def find_function_pointers(self, function):
        if function != "worker_left":
            return []
        return [{"caller": "start_workers", "file": "src/start_workers.c", "line": 4}]

    def find_function_identities(self, function, file_path=""):
        graph = self._graphs.get(function)
        if graph is None:
            return []
        if file_path and not str(graph.file).endswith(str(file_path)):
            return []
        return [
            {
                "function_name": function,
                "file_path": graph.file,
                "start_line": 1,
                "end_line": 20,
            }
        ]

    def find_function_infos(self, function, file_path=""):
        if function not in {"worker_left", "worker_right"}:
            return []
        return [
            {
                "function_name": function,
                "file_path": file_path,
                "referenced_globals": [
                    {
                        "name": "g_counter",
                        "type": "int",
                        "file_path": "src/shared.c",
                        "line": 2,
                        "storage_class": "static",
                        "qualifiers": [],
                        "access": "write" if function == "worker_left" else "read",
                    }
                ],
            }
        ]


def _cross_thread_race_fixture(*, locked=False, hidden_sync=False):
    creator = _named_single_block_graph(
        "start_workers",
        [
            "pthread_create(&left_thread, 0, worker_left, 0)",
            "pthread_create(&right_thread, 0, worker_right, 0)",
        ],
        [
            {"callee": "pthread_create", "line": 4},
            {"callee": "pthread_create", "line": 5},
        ],
        code_hash="1" * 64,
    )
    left_statements = (
        ["pthread_mutex_lock(&gate)", "g_counter++", "pthread_mutex_unlock(&gate)"]
        if locked
        else ["g_counter++"]
    )
    if hidden_sync:
        left_statements.insert(0, "while (!ready) {}")
    left_calls = (
        [
            {"callee": "pthread_mutex_lock", "line": 8},
            {"callee": "pthread_mutex_unlock", "line": 10},
        ]
        if locked
        else []
    )
    left = _named_single_block_graph(
        "worker_left",
        left_statements,
        left_calls,
        code_hash="2" * 64,
    )
    right = _named_single_block_graph(
        "worker_right",
        ["int snapshot = g_counter"],
        [],
        code_hash="3" * 64,
    )
    graphs = {value.function: value for value in (creator, left, right)}
    service = FunctionIRFactService(
        None,
        enabled=True,
        code_index=_CrossThreadProductIndex(graphs),
    )
    service._graph_for_identity = lambda identity: graphs.get(  # type: ignore[method-assign]
        str(identity.get("function_name") or "")
    )
    return left, service


def _signed_length_graph(*, guarded: bool = False, transformed: bool = False) -> FunctionIRGraph:
    target = {
        "parameters": [{"name": "fd", "type": "int", "line": 10}],
        "call_assignments": [
            {
                "target": "n",
                "callee": "recv",
                "line": 12,
                "result_type": "ssize_t",
            }
        ],
        "call_exprs": [
            {
                "callee": "recv",
                "line": 12,
                "result_type": "ssize_t",
                "argument_types": ["int"],
                "argument_refs": [["fd"]],
                "argument_ref_types": [{"fd": "int"}],
            },
            {
                "callee": "memcpy",
                "line": 14,
                "result_type": "void *",
                "argument_types": ["void *", "const void *", "size_t"],
                "argument_refs": [["dst"], ["src"], ["n"]],
                "argument_ref_types": [
                    {"dst": "void *"},
                    {"src": "const void *"},
                    {"n": "ssize_t"},
                ],
            },
        ],
        "conversions": [
            {
                "cast_kind": "ImplicitCastExpr",
                "line": 14,
                "source_type": "ssize_t",
                "target_type": "size_t",
                "refs": ["n"],
            }
        ],
        "terminating_guards": (
            [
                {
                    "line": 13,
                    "comparisons": [
                        {
                            "opcode": "<",
                            "lhs_refs": ["n"],
                            "rhs_refs": [],
                            "lhs_integer_literals": [],
                            "rhs_integer_literals": ["0"],
                        }
                    ],
                    "terminates_then_branch": True,
                }
            ]
            if guarded
            else []
        ),
        "binary_ops": [],
        "value_fact_coverage_complete": True,
    }
    evidence = {
        "code_snapshot_sha256": "e" * 64,
        "cfg_dump": {
            "summary": {
                "parse_ok": True,
                "function": "copy_received",
                "function_section_unique": True,
                "entry_blocks": ["B2"],
                "exit_blocks": ["B0"],
                "blocks": [
                    {
                        "id": "B2",
                        "label": "(ENTRY)",
                        "successors": ["B1"],
                        "predecessors": [],
                        "statements": [],
                    },
                    {
                        "id": "B1",
                        "label": "",
                        "successors": ["B0"],
                        "predecessors": ["B2"],
                        "statements": [
                            "n = recv(fd, src, cap, 0)",
                            *(["n = clamp_length(n)"] if transformed else []),
                            "memcpy(dst, src, n)",
                        ],
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
        "ast_dump": {"summary": {"parse_ok": True, "target_function": target}},
    }
    graph = FunctionIRGraph.from_clang_evidence(
        evidence,
        function="copy_received",
        file="src/copy_received.c",
    )
    assert graph is not None
    return graph


def _command_flow_graph(*, transformed: bool = False) -> FunctionIRGraph:
    statements = ["sanitize(cmd)", "system(cmd)"] if transformed else ["system(cmd)"]
    calls = (
        [
            {
                "callee": "sanitize",
                "line": 11,
                "argument_types": ["char *"],
                "argument_refs": [["cmd"]],
                "argument_ref_types": [{"cmd": "char *"}],
            }
        ]
        if transformed
        else []
    )
    calls.append(
        {
            "callee": "system",
            "line": 12,
            "argument_types": ["const char *"],
            "argument_refs": [["cmd"]],
            "argument_ref_types": [{"cmd": "char *"}],
        }
    )
    evidence = {
        "code_snapshot_sha256": "f" * 64,
        "cfg_dump": {
            "summary": {
                "parse_ok": True,
                "function": "run_command",
                "function_section_unique": True,
                "entry_blocks": ["B2"],
                "exit_blocks": ["B0"],
                "blocks": [
                    {
                        "id": "B2",
                        "label": "(ENTRY)",
                        "successors": ["B1"],
                        "predecessors": [],
                        "statements": [],
                    },
                    {
                        "id": "B1",
                        "label": "",
                        "successors": ["B0"],
                        "predecessors": ["B2"],
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
        "ast_dump": {
            "summary": {
                "parse_ok": True,
                "target_function": {
                    "parameters": [{"name": "cmd", "type": "char *", "line": 10}],
                    "call_exprs": calls,
                    "call_assignments": [],
                    "conversions": [],
                    "terminating_guards": [],
                    "binary_ops": [],
                    "value_fact_coverage_complete": True,
                },
            }
        },
    }
    graph = FunctionIRGraph.from_clang_evidence(
        evidence,
        function="run_command",
        file="src/run_command.c",
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


def _missing_exit_clang_graph() -> FunctionIRGraph:
    evidence = _minimal_clang_evidence()
    evidence["cfg_dump"]["summary"]["blocks"] = [
        {
            "id": "B1",
            "label": "(ENTRY)",
            "successors": [],
            "predecessors": [],
            "statements": ["consume(shared)"],
        }
    ]
    graph = FunctionIRGraph.from_clang_evidence(
        evidence,
        function="target",
        file="src/anonymous.c",
    )
    assert graph is not None
    return graph


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


def test_function_ir_serializes_distinct_clang_builds_across_services(monkeypatch) -> None:
    services = [FunctionIRFactService(None, enabled=True) for _ in range(2)]
    active = 0
    peak = 0
    calls = 0
    calls_lock = threading.Lock()

    def collect(**kwargs):
        nonlocal active, peak, calls
        with calls_lock:
            active += 1
            calls += 1
            peak = max(peak, active)
        time.sleep(0.03)
        with calls_lock:
            active -= 1
        return _minimal_clang_evidence(str(kwargs["func_name"]))

    for service in services:
        monkeypatch.setattr(service._clang, "collect_for_function", collect)

    issues = [
        {
            "function": f"target_{index}",
            "file": f"src/anonymous_{index}.c",
            "line": 17,
        }
        for index in range(8)
    ]

    with ThreadPoolExecutor(max_workers=8) as executor:
        graphs = list(
            executor.map(
                lambda indexed: services[indexed[0] % len(services)].graph(indexed[1], {}),
                enumerate(issues),
            )
        )

    assert calls == len(issues)
    assert peak == 1
    assert all(graph is not None and graph.coverage_complete for graph in graphs)


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


def test_function_ir_missing_exit_is_not_an_executable_proof_capability() -> None:
    graph = _missing_exit_clang_graph()
    issue = _issue(function_ir_graph=graph.to_dict())
    service = FunctionIRFactService(None, enabled=False)

    capabilities = service.capabilities(issue, {}, ["lockset"])

    assert graph.coverage_complete is False
    assert service.actions(issue, {}, ["lockset"]) == ()
    assert capabilities[0].executable_for_subject_region is False
    assert capabilities[0].unavailable_reason == "function_ir_cfg_incomplete"


def test_function_ir_incomplete_graph_rejects_stale_action_without_provider_call() -> None:
    complete_graph = _clang_graph()
    incomplete_graph = _missing_exit_clang_graph()
    complete_issue = _issue(function_ir_graph=complete_graph.to_dict())
    incomplete_issue = _issue(function_ir_graph=incomplete_graph.to_dict())
    service = FunctionIRFactService(None, enabled=False)
    action = service.actions(complete_issue, {}, ["lockset"])[0]

    result = service.execute(action, incomplete_issue, {})

    assert result.status == "unknown"
    assert result.reason_code == "function_ir_cfg_incomplete"
    assert result.proof_artifacts is None


def test_cfg_join_uses_must_intersection_and_does_not_merge_branch_lock() -> None:
    graph = _clang_graph()

    locksets = graph.must_hold_locksets()
    sink_statement = next(event.statement_uid for event in graph.events if event.callee == "sink")

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
    sink_statement = next(event.statement_uid for event in graph.events if event.callee == "sink")
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


def test_function_ir_path_existence_is_not_a_terminal_confirmation() -> None:
    graph = _clang_graph(branch_release=False)
    issue = _issue(function_ir_graph=graph.to_dict())
    service = FunctionIRFactService(None, enabled=False)
    action = service.actions(issue, {}, ["source_sink_reachability"])[0]

    result = service.execute(action, issue, {})

    assert result.fact is not None
    assert result.fact["value"]["path_exists"] is True
    assert "deterministic_proof" not in result.fact
    assert result.proof_artifacts is None


def test_function_ir_signed_length_flow_has_strict_confirmation_artifact() -> None:
    graph = _signed_length_graph()
    issue = _issue(
        function="copy_received",
        file="src/copy_received.c",
        function_ir_graph=graph.to_dict(),
        subject_uid="n",
        source={"callee": "recv", "line": 12},
        sink={"callee": "memcpy", "line": 14},
        security_obligation={
            "obligation_uid": "OBL_SIGNED_LENGTH",
            "subject_uid": "n",
            "decision_region_uid": "REGION_1",
            "required_fact_kinds": ["value_range"],
        },
    )
    service = FunctionIRFactService(None, enabled=False)

    actions = service.actions(issue, {}, ["value_range"])
    assert len(actions) == 1
    result = service.execute(actions[0], issue, {})

    assert result.status == "verified_true"
    assert result.fact is not None
    assert result.fact["value"]["range_violation"] is True
    assert result.fact["deterministic_proof"]["proof_kind"] == (
        "signed_value_reaches_unsigned_sink"
    )
    assert result.proof_artifacts is not None
    checked = result.proof_artifacts["proof_check_result"]
    assert checked["status"] == "accepted", checked
    assert checked["terminal_contribution"] == "confirmation"


def test_function_ir_signed_length_flow_with_terminating_guard_is_not_executable() -> None:
    graph = _signed_length_graph(guarded=True)
    issue = _issue(
        function="copy_received",
        file="src/copy_received.c",
        function_ir_graph=graph.to_dict(),
        subject_uid="n",
        source={"callee": "recv", "line": 12},
        sink={"callee": "memcpy", "line": 14},
        security_obligation={
            "obligation_uid": "OBL_GUARDED_LENGTH",
            "subject_uid": "n",
            "decision_region_uid": "REGION_1",
            "required_fact_kinds": ["value_range"],
        },
    )

    assert FunctionIRFactService(None, enabled=False).actions(issue, {}, ["value_range"]) == ()


def test_function_ir_missing_cleanup_has_strict_confirmation_artifact() -> None:
    graph = _clang_graph(branch_release=False)
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
    issue = _issue(
        function_ir_graph=raw,
        security_obligation={
            "obligation_uid": "OBL_CLEANUP_STRICT",
            "subject_uid": "p",
            "decision_region_uid": "REGION_1",
            "required_fact_kinds": ["cleanup_coverage"],
        },
    )
    service = FunctionIRFactService(None, enabled=False)
    action = service.actions(issue, {}, ["cleanup_coverage"])[0]

    result = service.execute(action, issue, {})

    assert result.fact is not None
    assert result.fact["deterministic_proof"]["proof_kind"] == "missing_cleanup_path"
    assert result.proof_artifacts is not None
    checked = result.proof_artifacts["proof_check_result"]
    assert checked["status"] == "accepted"
    assert checked["terminal_contribution"] == "confirmation"


def test_function_ir_complete_cleanup_has_strict_counterproof_artifact() -> None:
    graph = _single_block_graph(
        ["p = malloc(8)", "free(p)"],
        [
            {"callee": "malloc", "line": 4},
            {"callee": "free", "line": 5},
        ],
    )
    issue = _issue(
        function="single_block",
        file="src/generic.c",
        function_ir_graph=graph.to_dict(),
        security_obligation={
            "obligation_uid": "OBL_CLEANUP_COMPLETE",
            "subject_uid": "p",
            "decision_region_uid": "REGION_1",
            "required_fact_kinds": ["cleanup_coverage"],
        },
    )
    service = FunctionIRFactService(None, enabled=False)
    action = service.actions(issue, {}, ["cleanup_coverage"])[0]

    result = service.execute(action, issue, {})

    assert result.fact is not None
    assert result.fact["deterministic_proof"]["proof_kind"] == "ownership_cleanup_complete"
    assert result.proof_artifacts is not None
    checked = result.proof_artifacts["proof_check_result"]
    assert checked["status"] == "accepted"
    assert checked["terminal_contribution"] == "counterproof"


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


def test_composite_race_obligation_freezes_five_fail_closed_clauses() -> None:
    graph = _clang_graph(branch_release=False)
    issue = _issue(
        category="data_race",
        function_ir_graph=graph.to_dict(),
        security_obligation={
            "obligation_uid": "OBL_RACE_COMPOSITE",
            "defect_family": "data_race",
            "subject_uid": "p",
            "decision_region_uid": "REGION_1",
            "required_fact_kinds": [
                "object_identity",
                "lockset",
                "happens_before",
            ],
        },
    )
    service = FunctionIRFactService(None, enabled=False)

    frozen = service.build_composite_proof_input(issue, {})

    assert frozen is not None
    obligation = frozen["proof_obligation"]
    all_clauses = [
        *obligation["confirmation_clauses"],
        *obligation["open_clauses"],
    ]
    assert len(all_clauses) == 5
    assert {value["fact_kind"] for value in all_clauses} == {
        "object_identity",
        "conflicting_accesses",
        "cross_thread_reachability",
        "lockset",
        "happens_before",
    }
    evaluation = ProofKernelEngine().evaluate(
        proof_ir=frozen["proof_ir"],
        obligation=obligation,
    )
    assert evaluation.decision == "needs_review"
    assert evaluation.promotion_certificate is None
    assert evaluation.closure_evaluation.missing_clause_uids


def test_composite_qualified_cross_thread_race_mints_v4_promotion() -> None:
    graph, service = _cross_thread_race_fixture()
    issue = _issue(
        category="data_race",
        function="worker_left",
        file="src/worker_left.c",
        subject_uid="g_counter",
        function_ir_graph=graph.to_dict(),
        security_obligation={
            "obligation_uid": "OBL_QUALIFIED_RACE",
            "defect_family": "data_race",
            "subject_uid": "g_counter",
            "decision_region_uid": "REGION_1",
            "required_fact_kinds": [
                "object_identity",
                "lockset",
                "happens_before",
            ],
        },
    )
    frozen = service.build_composite_proof_input(issue, {})

    assert frozen is not None
    obligation = frozen["proof_obligation"]
    assert obligation["open_clauses"] == []
    assert obligation["counterproof_clauses"] == []
    assert {value["fact_kind"] for value in obligation["confirmation_clauses"]} == {
        "object_identity",
        "conflicting_accesses",
        "cross_thread_reachability",
        "lockset",
        "happens_before",
    }
    evaluation = ProofKernelEngine().evaluate(
        proof_ir=frozen["proof_ir"],
        obligation=obligation,
    )
    assert evaluation.decision == "confirmed"
    assert evaluation.promotion_certificate is not None
    assert len(evaluation.check_results) == 5
    assert {value["status"] for value in evaluation.check_results} == {"accepted"}


def test_governed_race_rejects_wrong_access_pair_anchor() -> None:
    graph, service = _cross_thread_race_fixture()
    issue = _governed_issue(
        _issue(
            category="data_race",
            function="worker_left",
            file="src/worker_left.c",
            subject_uid="g_counter",
            thread_object="g_counter",
            function_ir_graph=graph.to_dict(),
        ),
        source={"function": "worker_left", "expression": "different_object++"},
        sink={"function": "worker_right", "expression": "g_counter"},
    )

    frozen = service.build_composite_proof_input(issue, {})

    assert frozen is not None
    assert frozen["proof_obligation"]["open_clauses"]
    evaluation = ProofKernelEngine().evaluate(
        proof_ir=frozen["proof_ir"],
        obligation=frozen["proof_obligation"],
    )
    assert evaluation.decision == "needs_review"
    assert evaluation.promotion_certificate is None


def test_governed_race_accepts_exact_access_pair_and_region() -> None:
    graph, service = _cross_thread_race_fixture()
    issue = _governed_issue(
        _issue(
            category="data_race",
            function="worker_left",
            file="src/worker_left.c",
            subject_uid="g_counter",
            thread_object="g_counter",
            function_ir_graph=graph.to_dict(),
        ),
        source={"function": "worker_left", "expression": "g_counter++"},
        sink={"function": "worker_right", "expression": "g_counter"},
    )

    frozen = service.build_composite_proof_input(issue, {})

    assert frozen is not None
    assert frozen["proof_obligation"]["open_clauses"] == []
    evaluation = ProofKernelEngine().evaluate_selected_actions(
        proof_ir=frozen["proof_ir"],
        obligation=frozen["proof_obligation"],
        selected_action_uids=frozen["selected_action_uids"],
    )
    assert evaluation.decision == "confirmed"
    assert evaluation.promotion_certificate is not None


def test_composite_locked_cross_thread_access_stays_open() -> None:
    graph, service = _cross_thread_race_fixture(locked=True)
    issue = _issue(
        category="data_race",
        function="worker_left",
        file="src/worker_left.c",
        subject_uid="g_counter",
        function_ir_graph=graph.to_dict(),
        security_obligation={
            "obligation_uid": "OBL_LOCKED_RACE",
            "defect_family": "data_race",
            "subject_uid": "g_counter",
            "decision_region_uid": "REGION_1",
            "required_fact_kinds": ["object_identity", "lockset", "happens_before"],
        },
    )

    frozen = service.build_composite_proof_input(issue, {})

    assert frozen is not None
    evaluation = ProofKernelEngine().evaluate(
        proof_ir=frozen["proof_ir"],
        obligation=frozen["proof_obligation"],
    )
    assert evaluation.decision == "needs_review"
    assert evaluation.promotion_certificate is None


def test_composite_unmodeled_cross_thread_ordering_stays_open() -> None:
    graph, service = _cross_thread_race_fixture(hidden_sync=True)
    issue = _issue(
        category="data_race",
        function="worker_left",
        file="src/worker_left.c",
        subject_uid="g_counter",
        function_ir_graph=graph.to_dict(),
        security_obligation={
            "obligation_uid": "OBL_UNMODELED_ORDERING",
            "defect_family": "data_race",
            "subject_uid": "g_counter",
            "decision_region_uid": "REGION_1",
            "required_fact_kinds": ["object_identity", "lockset", "happens_before"],
        },
    )

    frozen = service.build_composite_proof_input(issue, {})

    assert frozen is not None
    assert frozen["proof_obligation"]["open_clauses"]
    evaluation = ProofKernelEngine().evaluate(
        proof_ir=frozen["proof_ir"],
        obligation=frozen["proof_obligation"],
    )
    assert evaluation.decision == "needs_review"
    assert evaluation.promotion_certificate is None


def test_composite_model_supplied_cross_thread_ir_is_ignored() -> None:
    graph, _service = _cross_thread_race_fixture()
    creator = _named_single_block_graph(
        "start_workers",
        [
            "pthread_create(&left_thread, 0, worker_left, 0)",
            "pthread_create(&right_thread, 0, worker_right, 0)",
        ],
        [
            {"callee": "pthread_create", "line": 4},
            {"callee": "pthread_create", "line": 5},
        ],
        code_hash="1" * 64,
    )
    right = _named_single_block_graph(
        "worker_right", ["int snapshot = g_counter"], [], code_hash="3" * 64
    )
    untrusted_envelope = build_cross_thread_function_ir(
        candidate_graph=graph,
        creator_graph=creator,
        worker_graphs=(graph, right),
        object_uid="g_counter",
        declaration_uid="GLOBAL:g_counter",
        declaration_file="src/shared.c",
        declaration_line=2,
        project_revision_sha256="4" * 64,
    )
    issue = _issue(
        category="data_race",
        function="worker_left",
        file="src/worker_left.c",
        subject_uid="g_counter",
        function_ir_graph=graph.to_dict(),
        security_obligation={
            "obligation_uid": "OBL_TAMPERED_RACE",
            "defect_family": "data_race",
            "subject_uid": "g_counter",
            "decision_region_uid": "REGION_1",
            "required_fact_kinds": ["object_identity", "lockset", "happens_before"],
        },
    )

    frozen = FunctionIRFactService(None, enabled=False).build_composite_proof_input(
        issue,
        {"_zscope_product_cross_thread_function_ir": untrusted_envelope},
    )

    assert frozen is not None
    assert frozen["proof_obligation"]["open_clauses"]
    evaluation = ProofKernelEngine().evaluate(
        proof_ir=frozen["proof_ir"],
        obligation=frozen["proof_obligation"],
    )
    assert evaluation.decision == "needs_review"
    assert evaluation.promotion_certificate is None


def test_composite_bounds_obligation_requires_all_four_semantic_classes() -> None:
    graph = _signed_length_graph()
    issue = _issue(
        category="integer_bounds",
        function="copy_received",
        file="src/copy_received.c",
        function_ir_graph=graph.to_dict(),
        subject_uid="n",
        source={"callee": "recv", "line": 12},
        sink={"callee": "memcpy", "line": 14},
        security_obligation={
            "obligation_uid": "OBL_BOUNDS_COMPOSITE",
            "defect_family": "integer_bounds",
            "subject_uid": "n",
            "decision_region_uid": "REGION_1",
            "required_fact_kinds": ["source", "sink", "value_range"],
        },
    )
    service = FunctionIRFactService(None, enabled=False)

    frozen = service.build_composite_proof_input(issue, {})

    assert frozen is not None
    obligation = frozen["proof_obligation"]
    clauses = [*obligation["confirmation_clauses"], *obligation["open_clauses"]]
    assert len(clauses) == 4
    assert {value["fact_kind"] for value in clauses} == {
        "source_controllability",
        "source_sink_reachability",
        "caller_contract",
        "value_range",
    }
    assert {value["fact_kind"] for value in obligation["confirmation_clauses"]} == {
        "source_controllability",
        "source_sink_reachability",
        "caller_contract",
        "value_range",
    }
    assert obligation["open_clauses"] == []
    evaluation = ProofKernelEngine().evaluate_selected_actions(
        proof_ir=frozen["proof_ir"],
        obligation=obligation,
        selected_action_uids=frozen["selected_action_uids"],
    )
    assert evaluation.decision == "confirmed"
    assert evaluation.promotion_certificate is not None
    assert len(evaluation.check_results) == 4
    assert {value["status"] for value in evaluation.check_results} == {"accepted"}


@pytest.mark.parametrize(
    ("subject_uid", "source", "sink"),
    [
        (
            "unrelated_length",
            {"function": "copy_received", "line": 12, "operation": "recv"},
            {"function": "copy_received", "line": 14, "operation": "memcpy"},
        ),
        (
            "n",
            {"function": "copy_received", "line": 99, "operation": "recv"},
            {"function": "copy_received", "line": 14, "operation": "memcpy"},
        ),
        (
            "n",
            {"function": "copy_received", "line": 12, "operation": "recv"},
            {"function": "copy_received", "line": 99, "operation": "memcpy"},
        ),
    ],
)
def test_governed_bounds_rejects_wrong_subject_or_source_sink_anchor(
    subject_uid, source, sink
) -> None:
    graph = _signed_length_graph()
    issue = _governed_issue(
        _issue(
            category="integer_bounds",
            function="copy_received",
            file="src/copy_received.c",
            function_ir_graph=graph.to_dict(),
            subject_uid=subject_uid,
        ),
        source=source,
        sink=sink,
    )

    frozen = FunctionIRFactService(None, enabled=False).build_composite_proof_input(issue, {})

    assert frozen is not None
    assert frozen["proof_obligation"]["open_clauses"]
    evaluation = ProofKernelEngine().evaluate(
        proof_ir=frozen["proof_ir"],
        obligation=frozen["proof_obligation"],
    )
    assert evaluation.decision == "needs_review"
    assert evaluation.promotion_certificate is None


def test_governed_obligation_rejects_rebound_decision_region() -> None:
    graph = _signed_length_graph()
    issue = _governed_issue(
        _issue(
            category="integer_bounds",
            function="copy_received",
            file="src/copy_received.c",
            function_ir_graph=graph.to_dict(),
            subject_uid="n",
        ),
        source={"function": "copy_received", "line": 12, "operation": "recv"},
        sink={"function": "copy_received", "line": 14, "operation": "memcpy"},
    )
    issue["security_obligation"]["decision_region_uid"] = "REGION_REBOUND"

    frozen = FunctionIRFactService(None, enabled=False).build_composite_proof_input(issue, {})

    assert frozen is None


def test_governed_bounds_accepts_exact_subject_source_and_sink() -> None:
    graph = _signed_length_graph()
    issue = _governed_issue(
        _issue(
            category="integer_bounds",
            function="copy_received",
            file="src/copy_received.c",
            function_ir_graph=graph.to_dict(),
            subject_uid="n",
        ),
        source={"function": "copy_received", "line": 12, "operation": "recv"},
        sink={"function": "copy_received", "line": 14, "operation": "memcpy"},
    )

    frozen = FunctionIRFactService(None, enabled=False).build_composite_proof_input(issue, {})

    assert frozen is not None
    assert frozen["proof_obligation"]["open_clauses"] == []
    evaluation = ProofKernelEngine().evaluate_selected_actions(
        proof_ir=frozen["proof_ir"],
        obligation=frozen["proof_obligation"],
        selected_action_uids=frozen["selected_action_uids"],
    )
    assert evaluation.decision == "confirmed"
    assert evaluation.promotion_certificate is not None


def test_composite_bounds_intervening_value_transform_stays_open() -> None:
    graph = _signed_length_graph(transformed=True)
    issue = _issue(
        category="integer_bounds",
        function="copy_received",
        file="src/copy_received.c",
        function_ir_graph=graph.to_dict(),
        subject_uid="n",
        source={"callee": "recv", "line": 12},
        sink={"callee": "memcpy", "line": 14},
        security_obligation={
            "obligation_uid": "OBL_BOUNDS_TRANSFORMED",
            "defect_family": "integer_bounds",
            "subject_uid": "n",
            "decision_region_uid": "REGION_1",
            "required_fact_kinds": ["source", "sink", "value_range"],
        },
    )

    frozen = FunctionIRFactService(None, enabled=False).build_composite_proof_input(issue, {})

    assert frozen is not None
    assert frozen["proof_obligation"]["open_clauses"]
    evaluation = ProofKernelEngine().evaluate(
        proof_ir=frozen["proof_ir"],
        obligation=frozen["proof_obligation"],
    )
    assert evaluation.decision == "needs_review"
    assert evaluation.promotion_certificate is None


def test_composite_leak_obligation_keeps_identity_and_transfer_open() -> None:
    graph = _clang_graph(branch_release=False)
    issue = _issue(
        category="memory_leak",
        function_ir_graph=graph.to_dict(),
        security_obligation={
            "obligation_uid": "OBL_LEAK_COMPOSITE",
            "defect_family": "memory_leak",
            "subject_uid": "p",
            "decision_region_uid": "REGION_1",
            "required_fact_kinds": ["event:acquire", "event:exit"],
        },
    )
    service = FunctionIRFactService(None, enabled=False)

    frozen = service.build_composite_proof_input(issue, {})

    assert frozen is not None
    obligation = frozen["proof_obligation"]
    clauses = [*obligation["confirmation_clauses"], *obligation["open_clauses"]]
    assert len(clauses) == 3
    assert {value["fact_kind"] for value in clauses} == {
        "object_identity",
        "cleanup_coverage",
        "ownership_transfer",
    }
    assert {value["fact_kind"] for value in obligation["open_clauses"]} == {
        "object_identity",
        "ownership_transfer",
    }
    evaluation = ProofKernelEngine().evaluate_selected_actions(
        proof_ir=frozen["proof_ir"],
        obligation=obligation,
        selected_action_uids=frozen["selected_action_uids"],
    )
    assert evaluation.decision == "needs_review"
    assert evaluation.promotion_certificate is None


def test_composite_direct_command_flow_stays_open_without_exact_caller_contract() -> None:
    graph = _command_flow_graph()
    issue = _issue(
        category="command_injection",
        function="run_command",
        file="src/run_command.c",
        function_ir_graph=graph.to_dict(),
        subject_uid="cmd",
        security_obligation={
            "obligation_uid": "OBL_COMMAND_COMPOSITE",
            "defect_family": "command_injection",
            "subject_uid": "cmd",
            "decision_region_uid": "REGION_1",
            "required_fact_kinds": ["source", "sink", "caller_contract"],
        },
    )

    frozen = FunctionIRFactService(None, enabled=False).build_composite_proof_input(issue, {})

    assert frozen is not None
    obligation = frozen["proof_obligation"]
    assert obligation["open_clauses"]
    evaluation = ProofKernelEngine().evaluate(
        proof_ir=frozen["proof_ir"],
        obligation=obligation,
    )
    assert evaluation.decision == "needs_review"
    assert evaluation.promotion_certificate is None


def test_composite_transformed_command_flow_remains_open() -> None:
    graph = _command_flow_graph(transformed=True)
    issue = _issue(
        category="command_injection",
        function="run_command",
        file="src/run_command.c",
        function_ir_graph=graph.to_dict(),
        subject_uid="cmd",
        security_obligation={
            "obligation_uid": "OBL_COMMAND_TRANSFORMED",
            "defect_family": "command_injection",
            "subject_uid": "cmd",
            "decision_region_uid": "REGION_1",
            "required_fact_kinds": ["source", "sink", "caller_contract"],
        },
    )

    frozen = FunctionIRFactService(None, enabled=False).build_composite_proof_input(issue, {})

    assert frozen is not None
    evaluation = ProofKernelEngine().evaluate(
        proof_ir=frozen["proof_ir"],
        obligation=frozen["proof_obligation"],
    )
    assert evaluation.decision == "needs_review"
    assert evaluation.promotion_certificate is None


def test_composite_exact_resource_leak_mints_v4_promotion() -> None:
    graph = _single_block_graph(
        ["p = malloc(8)"],
        [{"callee": "malloc", "line": 4}],
        var_decls=[{"name": "p", "type": "void *", "line": 4, "storage_class": ""}],
    )
    issue = _issue(
        category="memory_leak",
        function="single_block",
        file="src/generic.c",
        function_ir_graph=graph.to_dict(),
        security_obligation={
            "obligation_uid": "OBL_EXACT_LEAK",
            "defect_family": "memory_leak",
            "subject_uid": "p",
            "decision_region_uid": "REGION_1",
            "required_fact_kinds": ["event:acquire", "event:exit"],
        },
    )

    frozen = FunctionIRFactService(None, enabled=False).build_composite_proof_input(issue, {})

    assert frozen is not None
    obligation = frozen["proof_obligation"]
    assert obligation["open_clauses"] == []
    assert {value["fact_kind"] for value in obligation["confirmation_clauses"]} == {
        "object_identity",
        "cleanup_coverage",
        "ownership_transfer",
    }
    evaluation = ProofKernelEngine().evaluate_selected_actions(
        proof_ir=frozen["proof_ir"],
        obligation=obligation,
        selected_action_uids=frozen["selected_action_uids"],
    )
    assert evaluation.decision == "confirmed"
    assert evaluation.promotion_certificate is not None


def test_governed_leak_rejects_wrong_acquisition_anchor() -> None:
    graph = _single_block_graph(
        ["p = malloc(8)"],
        [{"callee": "malloc", "line": 4}],
        var_decls=[{"name": "p", "type": "void *", "line": 4, "storage_class": ""}],
    )
    issue = _governed_issue(
        _issue(
            category="memory_leak",
            function="single_block",
            file="src/generic.c",
            function_ir_graph=graph.to_dict(),
            subject_uid="p",
            resource_identity="p",
        ),
        source="single_block:99:resource_acquire:p",
        sink="single_block:99:sink:p",
    )

    frozen = FunctionIRFactService(None, enabled=False).build_composite_proof_input(issue, {})

    assert frozen is not None
    assert frozen["proof_obligation"]["open_clauses"]
    evaluation = ProofKernelEngine().evaluate(
        proof_ir=frozen["proof_ir"],
        obligation=frozen["proof_obligation"],
    )
    assert evaluation.decision == "needs_review"
    assert evaluation.promotion_certificate is None


def test_composite_complete_cleanup_is_alternative_counterproof_terminal() -> None:
    graph = _single_block_graph(
        ["p = malloc(8)", "free(p)"],
        [{"callee": "malloc", "line": 4}, {"callee": "free", "line": 5}],
        var_decls=[{"name": "p", "type": "void *", "line": 4, "storage_class": ""}],
    )
    issue = _issue(
        category="memory_leak",
        function="single_block",
        file="src/generic.c",
        function_ir_graph=graph.to_dict(),
        security_obligation={
            "obligation_uid": "OBL_EXACT_CLEANUP",
            "defect_family": "memory_leak",
            "subject_uid": "p",
            "decision_region_uid": "REGION_1",
            "required_fact_kinds": ["event:acquire", "event:exit"],
        },
    )

    frozen = FunctionIRFactService(None, enabled=False).build_composite_proof_input(issue, {})

    assert frozen is not None
    obligation = frozen["proof_obligation"]
    assert obligation["confirmation_clauses"] == []
    assert len(obligation["counterproof_clauses"]) == 1
    evaluation = ProofKernelEngine().evaluate_selected_actions(
        proof_ir=frozen["proof_ir"],
        obligation=obligation,
        selected_action_uids=frozen["selected_action_uids"],
    )
    assert evaluation.decision == "rejected_with_proof"
    assert evaluation.promotion_certificate is not None


@pytest.mark.parametrize(
    ("transfer_statement", "transfer_calls"),
    [
        ("return p", []),
        ("global_owner = p", []),
        ("ctx->field = p", []),
        ("*out = p", []),
        ("consume(p)", [{"callee": "consume", "line": 5}]),
        ("container_push(list, p)", [{"callee": "container_push", "line": 5}]),
        ("register_callback(p)", [{"callee": "register_callback", "line": 5}]),
    ],
)
def test_composite_resource_transfer_paths_stay_open(transfer_statement, transfer_calls) -> None:
    graph = _single_block_graph(
        ["p = malloc(8)", transfer_statement],
        [{"callee": "malloc", "line": 4}, *transfer_calls],
        var_decls=[{"name": "p", "type": "void *", "line": 4, "storage_class": ""}],
    )
    issue = _issue(
        category="memory_leak",
        function="single_block",
        file="src/generic.c",
        function_ir_graph=graph.to_dict(),
        security_obligation={
            "obligation_uid": "OBL_TRANSFER_UNKNOWN",
            "defect_family": "memory_leak",
            "subject_uid": "p",
            "decision_region_uid": "REGION_1",
            "required_fact_kinds": ["event:acquire", "event:exit"],
        },
    )

    frozen = FunctionIRFactService(None, enabled=False).build_composite_proof_input(issue, {})

    assert frozen is not None
    evaluation = ProofKernelEngine().evaluate_selected_actions(
        proof_ir=frozen["proof_ir"],
        obligation=frozen["proof_obligation"],
        selected_action_uids=frozen["selected_action_uids"],
    )
    assert evaluation.decision == "needs_review"
    assert evaluation.promotion_certificate is None


@pytest.mark.parametrize(
    "var_decls",
    [
        [],
        [{"name": "p", "type": "void *", "line": 4, "storage_class": "static"}],
    ],
)
def test_composite_non_automatic_acquisition_identity_stays_open(var_decls) -> None:
    graph = _single_block_graph(
        ["p = malloc(8)"],
        [{"callee": "malloc", "line": 4}],
        var_decls=var_decls,
    )
    issue = _issue(
        category="memory_leak",
        function="single_block",
        file="src/generic.c",
        function_ir_graph=graph.to_dict(),
        security_obligation={
            "obligation_uid": "OBL_NONLOCAL_RESOURCE",
            "defect_family": "memory_leak",
            "subject_uid": "p",
            "decision_region_uid": "REGION_1",
            "required_fact_kinds": ["event:acquire", "event:exit"],
        },
    )

    frozen = FunctionIRFactService(None, enabled=False).build_composite_proof_input(issue, {})

    assert frozen is not None
    evaluation = ProofKernelEngine().evaluate(
        proof_ir=frozen["proof_ir"],
        obligation=frozen["proof_obligation"],
    )
    assert evaluation.decision == "needs_review"
    assert evaluation.promotion_certificate is None


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
        first = executor("execute_proof_evidence_action", {"action_id": "ACTION_1"})
        assert first["status"] == "unknown"
        assert executor._zscope_start_iteration(2) is False
        second = executor("execute_proof_evidence_action", {"action_id": "ACTION_2"})
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

    response = ProofEngineAgent(llm, []).investigate(
        {
            "finding_uid": "CAND_1",
            "validation_cluster_uid": "VAL_1",
            "evidence_slice": {
                "protocol_version": "zscope.validator-protocol.v3",
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
    assert names == {"execute_proof_evidence_action", "emit_validator_result_v3"}
    assert response.metadata["validator_no_new_evidence_fact_stop"] is True


def test_v3_action_terminal_authority_stops_when_no_executable_clause_remains() -> None:
    class TerminalAfterActionLLM:
        models = ["unit-model"]

        def run_conversation_with_tools(self, **kwargs):
            executor = kwargs["tool_executor"]
            outcome = executor(
                "execute_proof_evidence_action",
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
    response = ProofEngineAgent(TerminalAfterActionLLM(), []).investigate(
        {
            "finding_uid": "CAND_1",
            "validation_cluster_uid": "VAL_1",
            "evidence_slice": {
                "protocol_version": "zscope.validator-protocol.v3",
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
