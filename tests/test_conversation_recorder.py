import json

from zscope.framework.conversation_recorder import ConversationRecorder


def _jsonl_events(path):
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


def test_recorder_keeps_only_latest_exchange_and_summarizes_tools(tmp_path):
    recorder = ConversationRecorder(tmp_path)
    session = recorder.begin_session(agent_name="agent", label="compact")

    recorder.record_exchange(
        session,
        iteration=1,
        request_messages=[{"role": "user", "content": "EARLY_REQUEST_BIG_PAYLOAD"}],
        response_message={"role": "assistant", "content": "EARLY_RESPONSE_BIG_PAYLOAD"},
        finish_reason="tool_calls",
        model="model-a",
        prompt_tokens=10,
        completion_tokens=20,
    )
    recorder.record_tool_result(
        session,
        iteration=1,
        tool_name="lookup",
        tool_args={"query": "EARLY_TOOL_ARG_BIG_PAYLOAD"},
        result={"payload": "EARLY_TOOL_RESULT_BIG_PAYLOAD"},
    )
    recorder.record_tool_result(
        session,
        iteration=2,
        tool_name="lookup",
        tool_args={"query": "LATEST_TOOL_ARG_BIG_PAYLOAD"},
        result={"payload": "LATEST_TOOL_RESULT_BIG_PAYLOAD"},
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
    recorder.record_session_end(session, iterations=3, context_tokens=70, truncated=True)

    md_text = session.md_path.read_text(encoding="utf-8")
    jsonl_text = session.jsonl_path.read_text(encoding="utf-8")
    events = _jsonl_events(session.jsonl_path)

    assert "FINAL_REQUEST" in md_text
    assert "FINAL_RESPONSE" in md_text
    assert "Final retained iteration: `3` / total iterations `3`" in md_text
    assert "Tool results observed: `2`" in md_text
    assert "Session End" in md_text
    assert "EARLY_REQUEST_BIG_PAYLOAD" not in md_text
    assert "EARLY_RESPONSE_BIG_PAYLOAD" not in md_text
    assert "EARLY_TOOL_ARG_BIG_PAYLOAD" not in md_text
    assert "EARLY_TOOL_RESULT_BIG_PAYLOAD" not in md_text
    assert "LATEST_TOOL_RESULT_BIG_PAYLOAD" not in md_text

    exchange_events = [event for event in events if event["event"] == "exchange"]
    assert [event["event"] for event in events] == [
        "session_start",
        "exchange",
        "tool_result_summary",
        "session_end",
    ]
    assert len(exchange_events) == 1
    assert exchange_events[0]["iteration"] == 3
    assert exchange_events[0]["total_iterations"] == 3
    assert exchange_events[0]["request_messages"][0]["content"] == "FINAL_REQUEST"
    assert exchange_events[0]["response_message"]["content"] == "FINAL_RESPONSE"

    tool_summary = next(event for event in events if event["event"] == "tool_result_summary")
    assert tool_summary["tool_result_count"] == 2
    assert tool_summary["last_tool_result"]["iteration"] == 2
    assert tool_summary["last_tool_result"]["result_keys"] == ["payload"]
    assert "EARLY_REQUEST_BIG_PAYLOAD" not in jsonl_text
    assert "EARLY_RESPONSE_BIG_PAYLOAD" not in jsonl_text
    assert "EARLY_TOOL_ARG_BIG_PAYLOAD" not in jsonl_text
    assert "EARLY_TOOL_RESULT_BIG_PAYLOAD" not in jsonl_text
    assert "LATEST_TOOL_RESULT_BIG_PAYLOAD" not in jsonl_text
