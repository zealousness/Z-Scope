#!/usr/bin/env python3
"""Extract baseline efficiency/cost metrics for a Z-SCOPE range benchmark run."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple


LOG_TS = "%Y-%m-%d %H:%M:%S"
STEP_START_RE = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}).*"
    r"\[T:(?P<thread>[^\]]+)\].*"
    r"\[workflow:default:entry\] step \d+ start: (?P<step>[a-z_]+)"
)
STEP_DONE_RE = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}).*"
    r"\[T:(?P<thread>[^\]]+)\].*"
    r"\[workflow:entry\] step (?P<step>[a-z_]+) completed"
)
LLM_TRACE_RE = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}).*"
    r"\[T:(?P<thread>[^\]]+)\].*"
    r"\[LLM API Trace\].*Prompt ≈ (?P<prompt>[\d,]+) tk \| "
    r"Completion ≈ (?P<completion>[\d,]+) tk \| Total ≈ (?P<total>[\d,]+) tk"
)
GLOBAL_MODEL_START_RE = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}).*"
    r"\[global-model\] start\b"
)
GLOBAL_MODEL_END_RE = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}).*"
    r"\[global-model\] end\b.*duration=(?P<duration>[\d.]+)s"
)


def _empty_token_bucket() -> Dict[str, int]:
    return {"calls": 0, "prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0}


def _empty_tool_bucket() -> Dict[str, int]:
    return {
        "calls": 0,
        "results": 0,
        "success": 0,
        "format_errors": 0,
        "parameter_errors": 0,
        "other_errors": 0,
        "empty_results": 0,
        "repeated_calls": 0,
        "loop_guard_warnings": 0,
        "loop_guard_blocked": 0,
        "evidence_hits": 0,
    }


def _read_json(path: Path) -> Dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _find_json(run_dir: Path, names: Iterable[str]) -> Path:
    for name in names:
        path = run_dir / name
        if path.exists():
            return path
    expected = ", ".join(names)
    raise FileNotFoundError(f"none of {expected} found under {run_dir}")


def _fmt_seconds(value: float) -> str:
    return f"{value:.2f}s"


def _parse_conversations(conv_dir: Path) -> Dict[str, Dict[str, int]]:
    by_agent: Dict[str, Dict[str, int]] = defaultdict(
        lambda: {
            "sessions": 0,
            "session_duration_seconds": 0,
            "retained_exchanges": 0,
            "retained_prompt_tokens": 0,
            "retained_completion_tokens": 0,
            "retained_total_tokens": 0,
            "final_context_tokens": 0,
        }
    )
    session_starts: Dict[str, Tuple[str, datetime]] = {}
    for path in sorted(conv_dir.glob("*.jsonl")):
        for line in path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            event = json.loads(line)
            session = event.get("session") or {}
            agent = str(session.get("agent_name") or "unknown")
            bucket = by_agent[agent]
            if event.get("event") == "session_start":
                bucket["sessions"] += 1
                timestamp = event.get("timestamp")
                session_id = str(session.get("id") or path.stem)
                if timestamp:
                    try:
                        session_starts[session_id] = (agent, datetime.strptime(str(timestamp), LOG_TS))
                    except ValueError:
                        pass
            elif event.get("event") == "exchange":
                prompt = int(event.get("prompt_tokens") or 0)
                completion = int(event.get("completion_tokens") or 0)
                bucket["retained_exchanges"] += 1
                bucket["retained_prompt_tokens"] += prompt
                bucket["retained_completion_tokens"] += completion
                bucket["retained_total_tokens"] += prompt + completion
            elif event.get("event") == "session_end":
                bucket["final_context_tokens"] += int(event.get("context_tokens") or 0)
                timestamp = event.get("timestamp")
                session_id = str(session.get("id") or path.stem)
                started = session_starts.get(session_id)
                if timestamp and started:
                    try:
                        ended = datetime.strptime(str(timestamp), LOG_TS)
                    except ValueError:
                        ended = None
                    if ended is not None:
                        start_agent, started_at = started
                        by_agent[start_agent]["session_duration_seconds"] += int(
                            max(0.0, (ended - started_at).total_seconds())
                        )
    return {agent: dict(values) for agent, values in sorted(by_agent.items())}


def _normalize_args(value: Any) -> str:
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except Exception:
            return value.strip()
    try:
        return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    except TypeError:
        return str(value)


def _result_success(result: Dict[str, Any]) -> Optional[bool]:
    if "success" in result:
        return bool(result.get("success"))
    summary = result.get("summary")
    if isinstance(summary, dict) and "success" in summary:
        return bool(summary.get("success"))
    if result.get("error"):
        return False
    return None


def _result_error(result: Dict[str, Any]) -> str:
    error = result.get("error")
    if error:
        return str(error)
    summary = result.get("summary")
    if isinstance(summary, dict) and summary.get("error"):
        return str(summary.get("error"))
    return ""


def _result_data(result: Dict[str, Any]) -> Any:
    if "data" in result:
        return result.get("data")
    summary = result.get("summary")
    if isinstance(summary, dict):
        return summary.get("data")
    return None


def _parse_tool_result_content(content: str) -> Dict[str, Any]:
    try:
        return json.loads(content or "{}")
    except Exception:
        pass

    if '"compacted_tool_result"' in content:
        if re.search(r'"success"\s*:\s*true', content):
            return {"success": True, "_partial_compacted_result": True}
        if re.search(r'"success"\s*:\s*false', content):
            error_match = re.search(r'"error"\s*:\s*"([^"]*)"', content)
            error = error_match.group(1) if error_match else "partial compacted tool result failed"
            return {
                "success": False,
                "error": error,
                "_partial_compacted_result": True,
            }

    return {"success": False, "error": "tool result is not parseable JSON"}


def _is_empty_result(tool_name: str, result: Dict[str, Any]) -> bool:
    if _result_success(result) is not True:
        return False
    if result.get("_partial_compacted_result"):
        return False
    data = _result_data(result)
    if data is None:
        return True
    if data == "" or data == [] or data == {}:
        return True
    if tool_name in {"get_function_impl", "get_function_snapshot"}:
        return False
    if isinstance(data, dict):
        if data.get("count") == 0:
            return True
        if "callers" in data and data.get("callers") == []:
            return True
        if "callees" in data and data.get("callees") == []:
            return True
        if "results" in data and data.get("results") == []:
            return True
    return False


def _classify_error(error: str) -> str:
    text = error.lower()
    if not text:
        return "other_errors"
    if "json" in text or "schema" in text or "required" in text or "type error" in text:
        return "format_errors"
    parameter_markers = (
        "not found",
        "not exist",
        "missing",
        "invalid",
        "line",
        "path",
        "file",
        "function",
        "type ",
        "no such",
        "out of range",
    )
    if any(marker in text for marker in parameter_markers):
        return "parameter_errors"
    return "other_errors"


def _normalize_error_type(error: str) -> str:
    text = str(error or "").strip()
    lower = text.lower()
    if not text:
        return "empty error message"
    if lower.startswith("tool result is not parseable json"):
        return "tool result is not parseable JSON"
    if re.fullmatch(r"Function '.+' not found", text):
        return "Function not found"
    if re.fullmatch(r"Type '.+' not found", text):
        return "Type not found"
    if text == "Failed to read file":
        return "Failed to read file"
    if lower.startswith("repeated identical tool call blocked by the loop guard"):
        return "Loop Guard blocked repeated call"
    if "blocked by policy" in lower and "sensitive path" in lower:
        return "Sensitive path denied by policy"
    return text


def _extract_anchor_strings(value: Any) -> List[str]:
    anchors: List[str] = []
    if isinstance(value, dict):
        file_value = value.get("file") or value.get("file_path") or value.get("filename")
        func_value = value.get("function") or value.get("func_name") or value.get("function_name")
        line_value = (
            value.get("line")
            or value.get("lineNumber")
            or value.get("start_line")
            or value.get("location")
        )
        for item in (file_value, func_value, line_value, value.get("candidate_id"), value.get("dedup_key")):
            if item is not None and str(item).strip():
                anchors.append(str(item).strip())
        if file_value and line_value:
            anchors.append(f"{file_value}:{line_value}")
        for child in value.values():
            anchors.extend(_extract_anchor_strings(child))
    elif isinstance(value, list):
        for item in value:
            anchors.extend(_extract_anchor_strings(item))
    return anchors


def _report_evidence_text(report: Dict[str, Any]) -> str:
    fields: List[str] = []
    for key in ("issues", "issues_with_needs_review"):
        fields.append(json.dumps(report.get(key, []), ensure_ascii=False))
    metadata = report.get("metadata") or {}
    fields.append(json.dumps(metadata.get("audit_observations", []), ensure_ascii=False))
    return "\n".join(fields).lower()


def _tool_evidence_hit(result: Dict[str, Any], evidence_text: str) -> bool:
    if _result_success(result) is not True:
        return False
    anchors = _extract_anchor_strings(_result_data(result))
    filtered = []
    for anchor in anchors:
        item = str(anchor).strip()
        if len(item) < 3:
            continue
        if item.isdigit() and len(item) < 2:
            continue
        filtered.append(item.lower())
    # Keep this intentionally conservative: require a file/function/symbol-like
    # anchor to appear literally in final report evidence.
    return any(anchor in evidence_text for anchor in set(filtered))


def _parse_tool_calls(conv_dir: Path, report: Dict[str, Any]) -> Dict[str, Any]:
    by_agent: Dict[str, Dict[str, int]] = defaultdict(_empty_tool_bucket)
    by_tool: Dict[str, Dict[str, int]] = defaultdict(_empty_tool_bucket)
    by_agent_tool: Dict[str, Dict[str, Dict[str, int]]] = defaultdict(
        lambda: defaultdict(_empty_tool_bucket)
    )
    error_types_by_tool: Dict[str, Counter[str]] = defaultdict(Counter)
    calls_by_signature: Counter[str] = Counter()
    call_meta: Dict[str, Tuple[str, str, str, str]] = {}
    evidence_text = _report_evidence_text(report)

    for path in sorted(conv_dir.glob("*.jsonl")):
        for line in path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            event = json.loads(line)
            if event.get("event") != "exchange":
                continue
            agent = str((event.get("session") or {}).get("agent_name") or "unknown")
            for message in event.get("request_messages") or []:
                if message.get("role") == "assistant":
                    for tool_call in message.get("tool_calls") or []:
                        call_id = str(tool_call.get("id") or "")
                        function = tool_call.get("function") or {}
                        tool_name = str(function.get("name") or "unknown")
                        args = _normalize_args(function.get("arguments"))
                        signature = f"{agent}|{tool_name}|{args}"
                        calls_by_signature[signature] += 1
                        call_meta[call_id] = (agent, tool_name, args, signature)
                        for bucket in (
                            by_agent[agent],
                            by_tool[tool_name],
                            by_agent_tool[agent][tool_name],
                        ):
                            bucket["calls"] += 1
                            if calls_by_signature[signature] > 1:
                                bucket["repeated_calls"] += 1
                elif message.get("role") == "tool":
                    call_id = str(message.get("tool_call_id") or "")
                    meta = call_meta.get(call_id)
                    if not meta:
                        continue
                    agent, tool_name, _args, _signature = meta
                    result = _parse_tool_result_content(str(message.get("content") or ""))
                    buckets = (by_agent[agent], by_tool[tool_name], by_agent_tool[agent][tool_name])
                    success = _result_success(result)
                    error = _result_error(result)
                    for bucket in buckets:
                        bucket["results"] += 1
                        if success is True:
                            bucket["success"] += 1
                        elif success is False:
                            bucket[_classify_error(error)] += 1
                    if success is False:
                        error_types_by_tool[tool_name][_normalize_error_type(error)] += 1
                    for bucket in buckets:
                        if _is_empty_result(tool_name, result):
                            bucket["empty_results"] += 1
                        if result.get("repeat_call_warning") or result.get("cached_tool_result"):
                            bucket["loop_guard_warnings"] += 1
                        if result.get("repeat_call_guard"):
                            bucket["loop_guard_blocked"] += 1
                        if _tool_evidence_hit(result, evidence_text):
                            bucket["evidence_hits"] += 1

    return {
        "by_agent": {key: dict(value) for key, value in sorted(by_agent.items())},
        "by_tool": {key: dict(value) for key, value in sorted(by_tool.items())},
        "by_agent_tool": {
            agent: {tool: dict(values) for tool, values in sorted(tools.items())}
            for agent, tools in sorted(by_agent_tool.items())
        },
        "error_types_by_tool": {
            tool: dict(counter.most_common())
            for tool, counter in sorted(error_types_by_tool.items())
        },
    }


def _parse_step_work_seconds(log_path: Path) -> Dict[str, float]:
    active: Dict[Tuple[str, str], datetime] = {}
    totals: Dict[str, float] = defaultdict(float)
    for line in log_path.read_text(encoding="utf-8", errors="replace").splitlines():
        global_end = GLOBAL_MODEL_END_RE.search(line)
        if global_end:
            totals["global_model"] += float(global_end.group("duration"))
            continue
        start = STEP_START_RE.search(line)
        if start:
            key = (start.group("thread"), start.group("step"))
            active[key] = datetime.strptime(start.group("ts"), LOG_TS)
            continue
        done = STEP_DONE_RE.search(line)
        if done:
            key = (done.group("thread"), done.group("step"))
            started = active.pop(key, None)
            if started is None:
                continue
            ended = datetime.strptime(done.group("ts"), LOG_TS)
            totals[done.group("step")] += max(0.0, (ended - started).total_seconds())
    return dict(sorted(totals.items()))


def _agent_for_trace_thread(thread: str, active_step: str) -> str:
    if thread.startswith("zscope-validator"):
        return "validator_agent"
    if thread.startswith("zscope-deep-worker"):
        return "deep_worker"
    if thread == "MainThread":
        return "issue_reconciler_agent"
    if active_step in {"model_entry", "premodel_reachable_callees"}:
        return "semantic_modeler"
    if active_step == "focused_subagent_planning":
        return "skill_selection_or_deep_worker"
    if active_step == "vulnerability_mining":
        return "vulnerability_analyzer"
    if active_step == "validate_findings":
        return "validator_agent"
    if active_step == "persist_report":
        return "issue_reconciler_agent"
    return "unknown"


def _parse_llm_trace_tokens(log_path: Path) -> Dict[str, Any]:
    active_by_thread: Dict[str, str] = {}
    global_model_active = False
    by_agent: Dict[str, Dict[str, int]] = defaultdict(_empty_token_bucket)
    by_step: Dict[str, Dict[str, int]] = defaultdict(_empty_token_bucket)
    for line in log_path.read_text(encoding="utf-8", errors="replace").splitlines():
        if GLOBAL_MODEL_START_RE.search(line):
            global_model_active = True
            continue
        if GLOBAL_MODEL_END_RE.search(line):
            global_model_active = False
            continue
        start = STEP_START_RE.search(line)
        if start:
            active_by_thread[start.group("thread")] = start.group("step")
            continue
        done = STEP_DONE_RE.search(line)
        if done:
            active_by_thread.pop(done.group("thread"), None)
            continue
        trace = LLM_TRACE_RE.search(line)
        if not trace:
            continue
        thread = trace.group("thread")
        if global_model_active:
            agent = "semantic_modeler"
            step = "global_model"
        else:
            active_step = active_by_thread.get(thread, "")
            agent = _agent_for_trace_thread(thread, active_step)
            step = active_step or ("validate_findings" if agent == "validator_agent" else "")
        if not step and agent == "deep_worker":
            step = "focused_subagent_planning"
        if not step and agent == "issue_reconciler_agent":
            step = "persist_report"
        prompt = int(trace.group("prompt").replace(",", ""))
        completion = int(trace.group("completion").replace(",", ""))
        total = int(trace.group("total").replace(",", ""))
        for bucket in (by_agent[agent], by_step[step or "unknown"]):
            bucket["calls"] += 1
            bucket["prompt_tokens"] += prompt
            bucket["completion_tokens"] += completion
            bucket["total_tokens"] += total
    return {
        "by_agent": {key: dict(value) for key, value in sorted(by_agent.items())},
        "by_step": {key: dict(value) for key, value in sorted(by_step.items())},
    }


def extract(run_dir: Path, conv_dir: Path) -> Dict[str, Any]:
    metrics_path = _find_json(run_dir, ("metrics.json", "global_model_metrics.json"))
    metrics = _read_json(metrics_path)
    report = _read_json(run_dir / "zscope_batch_report.json")
    summary = report.get("summary") or {}
    entry_count = int(metrics.get("entry_count") or summary.get("functions_analyzed") or 0)
    conversations = _parse_conversations(conv_dir)
    step_work_seconds = _parse_step_work_seconds(run_dir / "zscope_run.log")
    llm_trace_tokens = _parse_llm_trace_tokens(run_dir / "zscope_run.log")
    tool_calls = _parse_tool_calls(conv_dir, report)
    total = {
        "entry_count": entry_count,
        "scan_wall_seconds": int(metrics.get("scan_wall_seconds") or 0),
        "batch_wall_seconds": float(summary.get("batch_wall_seconds") or 0.0),
        "total_duration_seconds": float(summary.get("total_duration_seconds") or 0.0),
        "total_context_tokens": int(summary.get("total_context_tokens") or 0),
        "total_prompt_tokens": int(summary.get("total_cumulative_prompt_tokens") or 0),
        "total_completion_tokens": int(summary.get("total_cumulative_completion_tokens") or 0),
        "total_tokens": int(summary.get("total_cumulative_total_tokens") or 0),
    }
    averages = {
        key: (value / entry_count if entry_count else 0)
        for key, value in total.items()
        if key != "entry_count"
    }
    return {
        "run_dir": str(run_dir),
        "metrics_file": str(metrics_path),
        "conversation_dir": str(conv_dir),
        "total": total,
        "per_entry_average": averages,
        "conversation_by_agent": conversations,
        "llm_trace_tokens": llm_trace_tokens,
        "tool_calls": tool_calls,
        "workflow_step_work_seconds": step_work_seconds,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("run_dir", type=Path)
    parser.add_argument("conversation_dir", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    result = extract(args.run_dir, args.conversation_dir)
    text = json.dumps(result, ensure_ascii=False, indent=2)
    if args.output:
        args.output.write_text(text + "\n", encoding="utf-8")
    else:
        print(text)


if __name__ == "__main__":
    main()
