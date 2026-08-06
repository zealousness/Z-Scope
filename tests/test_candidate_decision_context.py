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


def test_source_centric_obligation_ignores_entry_reachability_projection() -> None:
    direct = _issue(
        rule="clang_cfg_alloc_result_deref_without_null_guard",
        category="null_pointer_dereference",
        sink_expression="task->state = READY",
        sink_line=20,
        entry="wrapper_a",
    )
    through_wrapper = _issue(
        rule="clang_cfg_alloc_result_deref_without_null_guard",
        category="null_pointer_dereference",
        sink_expression="task->state = READY",
        sink_line=20,
        entry="wrapper_b",
    )
    direct["evidence_models"] = {
        "cross_procedure_contract": {"entry_function": "wrapper_a", "complete_to_entry": True}
    }
    through_wrapper["evidence_models"] = {
        "cross_procedure_contract": {"entry_function": "wrapper_b"}
    }

    first = CandidateEnvelope.from_issue(direct, project_id="demo", revision="rev1")
    second = CandidateEnvelope.from_issue(through_wrapper, project_id="demo", revision="rev1")

    assert first.occurrence_uid != second.occurrence_uid
    assert first.validation_cluster_uid == second.validation_cluster_uid


def test_complete_local_sink_obligation_ignores_wrapper_reachability() -> None:
    direct = _issue(
        rule="clang_cfg_path_check_before_open",
        category="toctou",
        sink_expression="open(path)",
        sink_line=20,
        entry="wrapper_a",
    )
    through_wrapper = _issue(
        rule="clang_cfg_path_check_before_open",
        category="toctou",
        sink_expression="open(path)",
        sink_line=20,
        entry="wrapper_b",
    )
    direct["evidence_pack"] = {
        "path": {"complete_in_function": True, "entry_function": "wrapper_a"},
        "ast_cfg": {"condition_guards": [{"line": 15, "condition": "path_ok"}], "events": []},
    }
    through_wrapper["evidence_pack"] = {
        "path": {"complete_in_function": True, "entry_function": "wrapper_b", "complete_to_entry": True},
        "ast_cfg": {"condition_guards": [{"line": 15, "condition": "path_ok"}], "events": []},
    }

    first = CandidateEnvelope.from_issue(direct, project_id="demo", revision="rev1")
    second = CandidateEnvelope.from_issue(through_wrapper, project_id="demo", revision="rev1")

    assert first.validation_cluster_uid == second.validation_cluster_uid
