from zscope.orchestration.candidate_envelope import (
    DECISION_CONTEXT_VERSION,
    CandidateEnvelope,
)


def _issue(*, rule: str, category: str, sink_expression: str, sink_line: int, entry: str = "entry_a") -> dict:
    return {
        "rule": rule,
        "category": category,
        "function": "create_task",
        "location": f"src/task.c:{sink_line}",
        "source": {
            "expression": "task = safe_calloc(1, sizeof(*task))",
            "file": "src/task.c",
            "line": 10,
            "function": "create_task",
        },
        "sink": {
            "operation": sink_expression,
            "file": "src/task.c",
            "line": sink_line,
            "function": "create_task",
        },
        "code_hash": "task-body-v1",
        "entry_function": entry,
        "call_path": [entry, "create_task"],
    }


def test_source_centric_null_check_aliases_multiple_uses() -> None:
    first = CandidateEnvelope.from_issue(
        _issue(
            rule="clang_cfg_allocation_result_used_without_null_check",
            category="unchecked_allocation",
            sink_expression="task->state = READY",
            sink_line=20,
        ),
        project_id="demo",
        revision="rev1",
    )
    second = CandidateEnvelope.from_issue(
        _issue(
            rule="clang_cfg_allocation_result_used_without_null_check",
            category="unchecked_allocation",
            sink_expression="task->name = name",
            sink_line=21,
            entry="entry_b",
        ),
        project_id="demo",
        revision="rev1",
    )

    assert first.candidate_uid != second.candidate_uid
    assert first.obligation_uid == second.obligation_uid
    assert first.validation_cluster_uid == second.validation_cluster_uid
    assert first.decision_context_version == DECISION_CONTEXT_VERSION


def test_sink_sensitive_lifetime_obligations_do_not_merge() -> None:
    first = CandidateEnvelope.from_issue(
        _issue(
            rule="clang_cfg_use_after_release",
            category="use_after_free",
            sink_expression="task->state = READY",
            sink_line=20,
        ),
        project_id="demo",
        revision="rev1",
    )
    second = CandidateEnvelope.from_issue(
        _issue(
            rule="clang_cfg_use_after_release",
            category="use_after_free",
            sink_expression="task->name = name",
            sink_line=21,
        ),
        project_id="demo",
        revision="rev1",
    )

    assert first.obligation_uid != second.obligation_uid
    assert first.validation_cluster_uid != second.validation_cluster_uid
