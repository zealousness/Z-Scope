import json

import pytest

from zscope.framework.conversation_recorder import ConversationRecorder


@pytest.fixture(autouse=True)
def _clean_recorder_env(monkeypatch):
    for name in (
        "Z_SCOPE_CONVERSATION_REASONING",
        "Z_SCOPE_CONVERSATION_MAX_FIELD_BYTES",
        "Z_SCOPE_CONVERSATION_MD_TAIL_EXCHANGES",
        "Z_SCOPE_CONVERSATION_MD_REWRITE_EVENT_INTERVAL",
        "Z_SCOPE_CONVERSATION_FLUSH_INTERVAL_SECONDS",
    ):
        monkeypatch.delenv(name, raising=False)


def _jsonl_events(path):
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


def test_recorder_keeps_full_history_and_per_call_tool_events(tmp_path):
    recorder = ConversationRecorder(tmp_path)
    session = recorder.begin_session(
        "agent",
        "full",
        tools_schema_hash="schema-hash-1",
        attribution={"stage": "validation"},
    )

    recorder.record_exchange(
        session,
        iteration=1,
        request_messages=[{"role": "user", "content": "EARLY_REQUEST_BIG_PAYLOAD"}],
        response_message={"role": "assistant", "content": "EARLY_RESPONSE_BIG_PAYLOAD"},
        finish_reason="tool_calls",
        model="model-a",
        prompt_tokens=10,
        completion_tokens=20,
        duration_ms=1500,
        attempt_count=2,
        base_url="http://provider/v1",
    )
    recorder.record_tool_result(
        session,
        iteration=1,
        tool_name="lookup",
        tool_args={"query": "EARLY_TOOL_ARG_BIG_PAYLOAD"},
        result={"payload": "EARLY_TOOL_RESULT_BIG_PAYLOAD"},
        tool_call_id="call_1",
        duration_ms=12,
    )
    recorder.record_tool_result(
        session,
        iteration=2,
        tool_name="lookup",
        tool_args={"query": "LATEST_TOOL_ARG_BIG_PAYLOAD"},
        result={"payload": "LATEST_TOOL_RESULT_BIG_PAYLOAD"},
        tool_call_id="call_2",
    )
    recorder.record_exchange(
        session,
        iteration=3,
        request_messages=[{"role": "user", "content": "FINAL_REQUEST"}],
        response_message={"role": "assistant", "content": "FINAL_RESPONSE"},
        finish_reason="stop",
        model="model-b",
        prompt_tokens=30,
        completion_tokens=40,
    )
    recorder.record_session_end(
        session,
        iterations=3,
        context_tokens=70,
        truncated=True,
        cumulative_prompt_tokens=40,
        cumulative_completion_tokens=60,
        finish_reason="stop",
    )

    md_text = session.md_path.read_text(encoding="utf-8")
    events = _jsonl_events(session.jsonl_path)

    # The full trace keeps every iteration; the markdown tail shows the latest.
    assert "EARLY_REQUEST_BIG_PAYLOAD" in md_text
    assert "FINAL_RESPONSE" in md_text
    assert "Tool results observed: `2`" in md_text
    assert "### Session End" in md_text

    assert [event["event"] for event in events] == [
        "session_start",
        "exchange",
        "tool_result",
        "tool_result",
        "exchange",
        "session_end",
    ]
    assert [event["seq"] for event in events] == list(range(1, len(events) + 1))
    assert all(
        event["schema_version"] == "zscope.conversation-event.v2" for event in events
    )
    assert events[0]["tools_schema_hash"] == "schema-hash-1"
    assert events[0]["attribution"] == {"stage": "validation"}

    first_exchange = events[1]
    assert first_exchange["iteration"] == 1
    assert first_exchange["request_messages"][0]["content"] == "EARLY_REQUEST_BIG_PAYLOAD"
    assert first_exchange["response_message"]["content"] == "EARLY_RESPONSE_BIG_PAYLOAD"
    assert first_exchange["duration_ms"] == 1500
    assert first_exchange["attempt_count"] == 2
    assert first_exchange["base_url"] == "http://provider/v1"

    first_tool = events[2]
    assert first_tool["tool_name"] == "lookup"
    assert first_tool["tool_call_id"] == "call_1"
    assert first_tool["args"] == {"query": "EARLY_TOOL_ARG_BIG_PAYLOAD"}
    assert first_tool["result"] == {"payload": "EARLY_TOOL_RESULT_BIG_PAYLOAD"}
    assert first_tool["duration_ms"] == 12
    assert first_tool["status"] == "ok"

    last_exchange = events[4]
    assert last_exchange["iteration"] == 3
    assert last_exchange["request_messages"][0]["content"] == "FINAL_REQUEST"

    session_end = events[5]
    assert session_end["iterations"] == 3
    assert session_end["cumulative_prompt_tokens"] == 40
    assert session_end["cumulative_completion_tokens"] == 60
    assert session_end["cumulative_total_tokens"] == 100
    assert session_end["truncated"] is True


def test_recorder_writes_each_session_to_independent_files(tmp_path):
    recorder = ConversationRecorder(tmp_path)
    first = recorder.begin_session(agent_name="agent", label="first")
    second = recorder.begin_session(agent_name="agent", label="second")

    recorder.record_exchange(
        first,
        iteration=1,
        request_messages=[{"role": "user", "content": "FIRST_REQUEST"}],
        response_message={"role": "assistant", "content": "FIRST_RESPONSE"},
        finish_reason="stop",
        model="model-a",
        prompt_tokens=1,
        completion_tokens=2,
    )
    recorder.record_session_end(first, iterations=1, context_tokens=3)
    recorder.record_exchange(
        second,
        iteration=1,
        request_messages=[{"role": "user", "content": "SECOND_REQUEST"}],
        response_message={"role": "assistant", "content": "SECOND_RESPONSE"},
        finish_reason="stop",
        model="model-a",
        prompt_tokens=3,
        completion_tokens=4,
    )
    recorder.record_session_end(second, iterations=1, context_tokens=7)

    assert first.md_path != second.md_path
    assert first.jsonl_path != second.jsonl_path
    assert "FIRST_REQUEST" in first.md_path.read_text(encoding="utf-8")
    assert "SECOND_REQUEST" not in first.md_path.read_text(encoding="utf-8")
    assert "SECOND_REQUEST" in second.md_path.read_text(encoding="utf-8")


def test_recorder_never_persists_provider_reasoning_content(tmp_path):
    recorder = ConversationRecorder(tmp_path)
    session = recorder.begin_session(agent_name="validator_agent", label="v3")

    recorder.record_exchange(
        session,
        iteration=1,
        request_messages=[
            {"role": "assistant", "content": "prior", "reasoning_content": "SECRET_PRIOR"}
        ],
        response_message={
            "role": "assistant",
            "content": "structured result",
            "reasoning_content": "SECRET_CURRENT",
        },
        finish_reason="stop",
        model="unit-model",
        prompt_tokens=10,
        completion_tokens=5,
    )
    recorder.record_session_end(session, iterations=1, context_tokens=15)

    md_text = session.md_path.read_text(encoding="utf-8")
    jsonl_text = session.jsonl_path.read_text(encoding="utf-8")
    assert "structured result" in md_text
    assert "SECRET_PRIOR" not in md_text + jsonl_text
    assert "SECRET_CURRENT" not in md_text + jsonl_text
    assert "reasoning_content" not in jsonl_text


def test_recorder_reasoning_tail_and_full_policies(tmp_path, monkeypatch):
    monkeypatch.setenv("Z_SCOPE_CONVERSATION_REASONING", "tail:16")
    tail_recorder = ConversationRecorder(tmp_path / "tail")
    tail_session = tail_recorder.begin_session("agent", "tail")
    tail_recorder.record_exchange(
        tail_session,
        iteration=1,
        request_messages=[{"role": "user", "content": "q"}],
        response_message={
            "role": "assistant",
            "content": "a",
            "reasoning_content": "R" * 100,
        },
        finish_reason="stop",
        model="m",
        prompt_tokens=1,
        completion_tokens=1,
    )
    tail_events = _jsonl_events(tail_session.jsonl_path)
    tail_message = tail_events[1]["response_message"]
    assert tail_message["reasoning_content"] == "R" * 16
    assert tail_message["reasoning_content_truncated"] is True

    monkeypatch.setenv("Z_SCOPE_CONVERSATION_REASONING", "full")
    full_recorder = ConversationRecorder(tmp_path / "full")
    full_session = full_recorder.begin_session("agent", "full")
    full_recorder.record_exchange(
        full_session,
        iteration=1,
        request_messages=[{"role": "user", "content": "q"}],
        response_message={
            "role": "assistant",
            "content": "a",
            "reasoning_content": "S" * 100,
        },
        finish_reason="stop",
        model="m",
        prompt_tokens=1,
        completion_tokens=1,
    )
    full_events = _jsonl_events(full_session.jsonl_path)
    assert full_events[1]["response_message"]["reasoning_content"] == "S" * 100
    assert "reasoning_content_truncated" not in full_events[1]["response_message"]


def test_recorder_truncates_oversized_tool_fields(tmp_path, monkeypatch):
    monkeypatch.setenv("Z_SCOPE_CONVERSATION_MAX_FIELD_BYTES", "256")
    recorder = ConversationRecorder(tmp_path)
    session = recorder.begin_session("agent", "trunc")
    recorder.record_tool_result(
        session,
        iteration=1,
        tool_name="get_file_snippet",
        tool_args={"file_path": "src/a.c", "code": "A" * 5000},
        result={"data": "B" * 5000},
    )
    event = _jsonl_events(session.jsonl_path)[1]
    assert event["args"]["__truncated__"] is True
    assert len(event["args"]["preview"].encode("utf-8")) <= 256
    assert event["result"]["__truncated__"] is True
    assert event["result_size_bytes"] > 5000


def test_recorder_markdown_tail_is_bounded(tmp_path, monkeypatch):
    monkeypatch.setenv("Z_SCOPE_CONVERSATION_MD_TAIL_EXCHANGES", "2")
    recorder = ConversationRecorder(tmp_path)
    session = recorder.begin_session("agent", "tail-md")
    for iteration in range(1, 4):
        recorder.record_exchange(
            session,
            iteration=iteration,
            request_messages=[{"role": "user", "content": f"REQ_{iteration}"}],
            response_message={"role": "assistant", "content": f"RES_{iteration}"},
            finish_reason="stop",
            model="m",
            prompt_tokens=1,
            completion_tokens=1,
        )
    recorder.record_session_end(session, iterations=3, context_tokens=6)

    md_text = session.md_path.read_text(encoding="utf-8")
    assert md_text.count("#### Exchange") == 2
    assert "REQ_3" in md_text
    assert "REQ_1" not in md_text
    jsonl_events = _jsonl_events(session.jsonl_path)
    assert len([event for event in jsonl_events if event["event"] == "exchange"]) == 3
    assert "REQ_1" in session.jsonl_path.read_text(encoding="utf-8")


def test_recorder_records_attempt_control_and_guard_events(tmp_path):
    recorder = ConversationRecorder(tmp_path)
    session = recorder.begin_session("agent", "events")
    recorder.record_attempt_failure(
        session,
        1,
        model="model-a",
        base_url="http://provider/v1",
        attempt=1,
        outcome="timeout",
        error="read timed out",
        delay_ms=2000,
    )
    recorder.record_iteration_control(
        session, 2, "length_continuation", {"finish_reason": "length"}
    )
    recorder.record_loop_guard(
        session,
        3,
        tool="lookup",
        repeat_count=3,
        disabled_tools=["lookup"],
        scope="tool",
        recovered=False,
    )
    recorder.record_terminal_tool(
        session, 3, "emit_result", {"value": 7}, True, tool_call_id="call_t"
    )
    recorder.record_session_end(session, iterations=3, context_tokens=9)

    events = _jsonl_events(session.jsonl_path)
    by_type = {event["event"]: event for event in events}
    attempt = by_type["attempt"]
    assert attempt["outcome"] == "timeout"
    assert attempt["model"] == "model-a"
    assert attempt["base_url"] == "http://provider/v1"
    assert attempt["delay_ms"] == 2000
    control = by_type["iteration_control"]
    assert control["kind"] == "length_continuation"
    guard = by_type["loop_guard"]
    assert guard["tool"] == "lookup"
    assert guard["disabled_tools"] == ["lookup"]
    terminal = by_type["terminal_tool"]
    assert terminal["tool_call_id"] == "call_t"
    assert terminal["valid"] is True
    session_end = by_type["session_end"]
    assert session_end["loop_guard_triggered"] is True

    md_text = session.md_path.read_text(encoding="utf-8")
    assert "### Attempt Failures" in md_text
    assert "### Loop Guard" in md_text
    assert "### Terminal Tool Summary" in md_text


def test_recorder_writes_manifest_and_index(tmp_path):
    recorder = ConversationRecorder(
        tmp_path,
        metadata={"config_path": "zscope.yaml", "zscope_version": "test-1"},
    )
    session = recorder.begin_session("agent", "indexed")
    recorder.record_session_end(
        session,
        iterations=2,
        context_tokens=10,
        cumulative_prompt_tokens=5,
        cumulative_completion_tokens=7,
        finish_reason="stop",
    )
    # A duplicate session_end must not create a second index row.
    recorder.record_session_end(
        session,
        iterations=2,
        context_tokens=10,
        cumulative_prompt_tokens=5,
        cumulative_completion_tokens=7,
        finish_reason="stop",
    )

    manifest = json.loads((recorder.run_dir / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["schema_version"] == "zscope.conversation-run-manifest.v1"
    assert manifest["config_path"] == "zscope.yaml"
    assert manifest["zscope_version"] == "test-1"
    assert manifest["recorder"]["reasoning_policy"] == "off"

    index_rows = _jsonl_events(recorder.run_dir / "index.jsonl")
    assert len(index_rows) == 1
    row = index_rows[0]
    assert row["session_id"] == session.id
    assert row["agent"] == "agent"
    assert row["cumulative_total_tokens"] == 12
    assert row["jsonl_file"] == session.jsonl_path.name
    assert row["finish_reason"] == "stop"


def test_recorder_jsonl_is_append_only(tmp_path):
    recorder = ConversationRecorder(tmp_path)
    session = recorder.begin_session("agent", "append")
    baseline = session.jsonl_path.read_text(encoding="utf-8")
    recorder.record_exchange(
        session,
        iteration=1,
        request_messages=[{"role": "user", "content": "q"}],
        response_message={"role": "assistant", "content": "a"},
        finish_reason="stop",
        model="m",
        prompt_tokens=1,
        completion_tokens=1,
    )
    grown = session.jsonl_path.read_text(encoding="utf-8")
    assert grown.startswith(baseline)
    assert len(grown) > len(baseline)
