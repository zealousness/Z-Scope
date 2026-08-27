#!/usr/bin/env python3
"""Generate validation-stage efficiency, quality, and benchmark metrics."""

from __future__ import annotations

import argparse
import json
import re
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional


LOG_TS = "%Y-%m-%d %H:%M:%S"
LOG_TIME_RE = re.compile(r"^(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})")
VALIDATION_START_RE = re.compile(
    r"\[validation-queue\] start unique_groups=(?P<groups>\d+) "
    r"raw_occurrences=(?P<occurrences>\d+)"
)
VALIDATION_END_RE = re.compile(
    r"\[validation-queue\] end unique_groups=(?P<groups>\d+) "
    r"confirmed=(?P<confirmed>\d+) review=(?P<review>\d+) "
    r"duration=(?P<duration>[\d.]+)s"
)
CONVERSATION_DIR_RE = re.compile(r"LLM conversation recording enabled: (?P<path>.+)$")
VALIDATOR_LLM_TRACE_RE = re.compile(
    r"\[T:(?P<thread>zscope-validator-\d+)\].*\[LLM API Trace\].*"
    r"Prompt ≈ (?P<prompt>[\d,]+) tk \| "
    r"Completion ≈ (?P<completion>[\d,]+) tk \| "
    r"Total ≈ (?P<total>[\d,]+) tk"
)
DISCOVER_ENTRIES_START_RE = re.compile(
    r"\[workflow:[^]]+\] step \d+ start: discover_entries\b"
)
DISCOVER_ENTRIES_END_RE = re.compile(
    r"\[workflow:[^]]+\] step discover_entries completed\b"
)
RUN_STAMP_RE = re.compile(r"(?P<stamp>\d{8}_\d{6})")
CANDIDATE_RE = re.compile(r"\b(?P<candidate>CAND_[A-Za-z0-9]+)\b")
REPAIR_REASON_RE = re.compile(r"(?:^|;)\s*error=(?P<reason>[^;]+)")

REQUIRED_FILES = (
    "run_summary.json",
    "zscope_batch_report.json",
    "evaluation.json",
    "evaluation.with_needs_review.json",
    "zscope_run.log",
)

TOOL_BUCKET_KEYS = (
    "calls",
    "fallback_calls",
    "results",
    "success",
    "format_errors",
    "parameter_errors",
    "other_errors",
    "unknown_results",
    "empty_results",
    "repeated_calls",
    "loop_guard_warnings",
    "loop_guard_blocked",
    "unreturned_calls",
)

TERMINAL_OUTPUT_TOOL_NAMES = {"emit_validation_result"}
VALIDATION_RESULT_KEYS = {
    "confidence_score",
    "blocking_negative_evidence",
    "control_of_source",
    "exploit_scenario",
    "finding_kind",
    "guard_analysis",
    "negative_evidence",
    "positive_evidence",
    "reasoning",
    "sink",
    "source",
}
VALIDATION_WRAPPER_KEYS = {
    "answer",
    "data",
    "decision",
    "decisions",
    "output",
    "outputs",
    "payload",
    "response",
    "responses",
    "result",
    "results",
    "validation",
    "validationresult",
    "validationresults",
}
VALIDATION_VERDICT_ALIASES = {
    "valid": "verified",
    "true": "verified",
    "confirmed": "verified",
    "true_positive": "verified",
    "tp": "verified",
    "invalid": "rejected",
    "false": "rejected",
    "reject": "rejected",
    "rejected": "rejected",
    "false_positive": "rejected",
    "fp": "rejected",
    "needs_review": "uncertain",
    "need_review": "uncertain",
    "unknown": "uncertain",
    "inconclusive": "uncertain",
    "uncertain": "uncertain",
    "verified": "verified",
}


def read_json(path: Path) -> Dict[str, Any]:
    if not path.is_file():
        raise FileNotFoundError(f"required input not found: {path}")
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"expected a JSON object in {path}")
    return value


def line_time(line: str) -> str:
    match = LOG_TIME_RE.match(line)
    return match.group("ts") if match else ""


def elapsed_log_seconds(start: str, end: str) -> Optional[float]:
    if not start or not end:
        return None
    return (datetime.strptime(end, LOG_TS) - datetime.strptime(start, LOG_TS)).total_seconds()


def parse_build_cpg_timing(log_path: Path) -> Dict[str, Any]:
    if not log_path.is_file():
        return {
            "start_timestamp": "",
            "end_timestamp": "",
            "duration_seconds": None,
            "source": "missing build_cpg.log",
        }
    timestamps = [
        timestamp
        for line in log_path.read_text(encoding="utf-8", errors="replace").splitlines()
        if (timestamp := line_time(line))
    ]
    if not timestamps:
        return {
            "start_timestamp": "",
            "end_timestamp": "",
            "duration_seconds": None,
            "source": "build_cpg.log has no timestamped records",
        }
    return {
        "start_timestamp": timestamps[0],
        "end_timestamp": timestamps[-1],
        "duration_seconds": elapsed_log_seconds(timestamps[0], timestamps[-1]),
        "source": "build_cpg.log timestamp span",
    }


def parse_log(log_path: Path) -> Dict[str, Any]:
    if not log_path.is_file():
        raise FileNotFoundError(f"required input not found: {log_path}")
    counts = Counter()
    start: Dict[str, Any] = {}
    end: Dict[str, Any] = {}
    conversation_paths: List[str] = []
    validator_api_traces: Dict[str, List[Dict[str, int]]] = defaultdict(list)
    discover_entries_start = ""
    discover_entries_end = ""
    for line in log_path.read_text(encoding="utf-8", errors="replace").splitlines():
        if DISCOVER_ENTRIES_START_RE.search(line):
            discover_entries_start = line_time(line)
        if DISCOVER_ENTRIES_END_RE.search(line):
            discover_entries_end = line_time(line)
        recorded = CONVERSATION_DIR_RE.search(line)
        if recorded:
            conversation_paths.append(recorded.group("path").strip())
        start_match = VALIDATION_START_RE.search(line)
        if start_match:
            counts["validation_queue_start"] += 1
            start = {
                "timestamp": line_time(line),
                "unique_groups": int(start_match.group("groups")),
                "raw_occurrences": int(start_match.group("occurrences")),
            }
        end_match = VALIDATION_END_RE.search(line)
        if end_match:
            counts["validation_queue_end"] += 1
            end = {
                "timestamp": line_time(line),
                "unique_groups": int(end_match.group("groups")),
                "confirmed": int(end_match.group("confirmed")),
                "review": int(end_match.group("review")),
                "duration_seconds": float(end_match.group("duration")),
            }
        trace_match = VALIDATOR_LLM_TRACE_RE.search(line)
        if trace_match:
            validator_api_traces[trace_match.group("thread")].append(
                {
                    "prompt_tokens": int(trace_match.group("prompt").replace(",", "")),
                    "completion_tokens": int(
                        trace_match.group("completion").replace(",", "")
                    ),
                    "total_tokens": int(trace_match.group("total").replace(",", "")),
                }
            )
    return {
        "counts": dict(counts),
        "start": start,
        "end": end,
        "conversation_paths": conversation_paths,
        "validator_api_traces_by_thread": {
            thread: traces for thread, traces in sorted(validator_api_traces.items())
        },
        "discover_entries_timing": {
            "start_timestamp": discover_entries_start,
            "end_timestamp": discover_entries_end,
            "duration_seconds": elapsed_log_seconds(
                discover_entries_start, discover_entries_end
            ),
            "source": "zscope_run.log workflow markers",
        },
    }


def infer_conversation_dir(run_dir: Path, explicit: Optional[Path] = None) -> Path:
    if explicit is not None:
        path = explicit.resolve()
        if not path.is_dir():
            raise FileNotFoundError(f"conversation directory not found: {path}")
        return path

    log_path = run_dir / "zscope_run.log"
    log = parse_log(log_path)
    existing_log_paths = []
    for raw_path in log["conversation_paths"]:
        path = Path(raw_path).expanduser().resolve()
        if path.is_dir() and path not in existing_log_paths:
            existing_log_paths.append(path)
    if len(existing_log_paths) == 1:
        return existing_log_paths[0]
    if len(existing_log_paths) > 1:
        raise ValueError(
            "multiple existing conversation directories were recorded in zscope_run.log: "
            + ", ".join(str(path) for path in existing_log_paths)
        )

    stamp = RUN_STAMP_RE.search(run_dir.name)
    if stamp:
        root = run_dir.parents[1] / ".zscope_conversations"
        candidates = sorted(
            path for path in root.glob(f"run_{stamp.group('stamp')}_*") if path.is_dir()
        )
        if len(candidates) == 1:
            return candidates[0].resolve()
        if len(candidates) > 1:
            raise ValueError(
                f"multiple conversation directories match {stamp.group('stamp')}: "
                + ", ".join(str(path) for path in candidates)
            )
    raise ValueError(
        f"cannot uniquely infer the conversation directory for {run_dir}; "
        "pass --conversation-dir explicitly"
    )


def normalize_args(value: Any) -> str:
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except Exception:
            return value.strip()
    try:
        return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    except TypeError:
        return str(value)


def normalize_validation_verdict(verdict: Any, is_valid: Any = None) -> str:
    normalized = VALIDATION_VERDICT_ALIASES.get(
        str(verdict or "").strip().lower(), str(verdict or "").strip().lower()
    )
    if normalized in {"verified", "rejected", "uncertain"}:
        return normalized
    if isinstance(is_valid, bool):
        return "verified" if is_valid else "rejected"
    return ""


def normalized_wrapper_key(key: Any) -> str:
    return "".join(ch for ch in str(key or "").lower() if ch.isalnum())


def is_accepted_validation_payload(value: Any) -> bool:
    """Mirror the Validator's permissive validation-result coercion."""
    if not isinstance(value, dict):
        return False
    verdict = normalize_validation_verdict(value.get("verdict"), value.get("is_valid"))
    if verdict and (
        value.get("type") == "validation_result"
        or "is_valid" in value
        or any(key in value for key in VALIDATION_RESULT_KEYS)
    ):
        return True
    scalar_result = value.get("validation_result")
    if isinstance(scalar_result, str) and normalize_validation_verdict(
        scalar_result, value.get("is_valid")
    ):
        return True
    for key, nested in value.items():
        if normalized_wrapper_key(key) not in VALIDATION_WRAPPER_KEYS:
            continue
        if is_accepted_validation_payload(nested):
            return True
        if isinstance(nested, list) and any(
            is_accepted_validation_payload(item) for item in nested
        ):
            return True
    return False


def parse_json_object(value: Any) -> Optional[Dict[str, Any]]:
    if isinstance(value, dict):
        return value
    if not isinstance(value, str):
        return None
    try:
        parsed = json.loads(value)
    except (TypeError, ValueError):
        return None
    return parsed if isinstance(parsed, dict) else None


def text_has_accepted_validation_payload(content: Any) -> bool:
    text = str(content or "")
    decoder = json.JSONDecoder()
    for match in re.finditer(r"\{", text):
        try:
            value, _ = decoder.raw_decode(text[match.start() :])
        except ValueError:
            continue
        if is_accepted_validation_payload(value):
            return True
    return False


def parse_tool_result(content: str) -> Dict[str, Any]:
    try:
        value = json.loads(content or "{}")
        return value if isinstance(value, dict) else {"_unknown_result": True}
    except Exception:
        success = re.search(r'"success"\s*:\s*(true|false)', content, re.IGNORECASE)
        if success:
            value: Dict[str, Any] = {
                "success": success.group(1).lower() == "true",
                "_partial_result": True,
            }
            error = re.search(r'"error"\s*:\s*"([^"\\]*(?:\\.[^"\\]*)*)"', content)
            if error:
                try:
                    value["error"] = json.loads(f'"{error.group(1)}"')
                except Exception:
                    value["error"] = error.group(1)
            if re.search(r'"repeat_call_(?:warning|guard)"\s*:\s*true', content):
                value["repeat_call_warning"] = True
            return value
        return {"_unknown_result": True, "_partial_result": True}


def result_success(result: Dict[str, Any]) -> Optional[bool]:
    if "success" in result:
        return bool(result.get("success"))
    summary = result.get("summary")
    if isinstance(summary, dict) and "success" in summary:
        return bool(summary.get("success"))
    if result.get("error"):
        return False
    return None


def result_error(result: Dict[str, Any]) -> str:
    if result.get("error"):
        return str(result["error"])
    summary = result.get("summary")
    if isinstance(summary, dict) and summary.get("error"):
        return str(summary["error"])
    return ""


def result_data(result: Dict[str, Any]) -> Any:
    if "data" in result:
        return result.get("data")
    summary = result.get("summary")
    if isinstance(summary, dict):
        return summary.get("data")
    return None


def classify_error(error: str) -> str:
    text = error.lower()
    if any(marker in text for marker in ("json", "schema", "required", "type error")):
        return "format_errors"
    if any(
        marker in text
        for marker in (
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
    ):
        return "parameter_errors"
    return "other_errors"


def normalize_error(error: str) -> str:
    text = str(error or "").strip()
    if re.fullmatch(r"Function '.+' not found", text):
        return "Function not found"
    if re.fullmatch(r"Type '.+' not found", text):
        return "Type not found"
    return text or "empty error message"


def is_empty_result(tool_name: str, result: Dict[str, Any]) -> bool:
    if result_success(result) is not True or result.get("_partial_result"):
        return False
    if tool_name in {"get_function_impl", "get_function_info", "get_function_snapshot"}:
        return False
    data = result_data(result)
    if data in (None, "", [], {}):
        return True
    if isinstance(data, dict):
        if data.get("count") == 0:
            return True
        for key in ("callers", "callees", "results", "matches"):
            if key in data and data.get(key) == []:
                return True
    return False


def empty_tool_bucket() -> Dict[str, int]:
    return {key: 0 for key in TOOL_BUCKET_KEYS}


def session_stage(label: str) -> str:
    prefix = label.split(";", 1)[0].strip()
    if prefix in {
        "evidence_slice_v3_direct_full_tool",
        "legacy_direct_full_tool",
    }:
        return "full_tool_fallback"
    if prefix == "evidence_slice_v3_full_tool_fallback":
        return "full_tool_fallback"
    if prefix == "evidence_slice_v3":
        return "primary"
    if prefix.startswith("attempt=") or "json_repair=" in label:
        return "json_repair"
    return prefix or "unknown"


def label_candidate(label: str) -> str:
    match = CANDIDATE_RE.search(label)
    return match.group("candidate") if match else ""


def label_repair_reason(label: str) -> str:
    match = REPAIR_REASON_RE.search(label)
    return match.group("reason").strip() if match else "unknown"


def parse_conversations(conversation_dir: Path) -> Dict[str, Any]:
    files = sorted(conversation_dir.glob("*.jsonl"))
    if not files:
        raise FileNotFoundError(f"no conversation JSONL files found under {conversation_dir}")

    by_tool: Dict[str, Dict[str, int]] = defaultdict(empty_tool_bucket)
    error_types: Dict[str, Counter[str]] = defaultdict(Counter)
    failure_records: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    signatures: Counter[str] = Counter()
    call_meta: Dict[str, Dict[str, Any]] = {}
    seen_calls: set[str] = set()
    seen_results: set[str] = set()
    model_counts: Counter[str] = Counter()
    stage_counts: Counter[str] = Counter()
    finish_reason_counts: Counter[str] = Counter()
    repair_reason_counts: Counter[str] = Counter()
    repair_finish_reason_counts: Counter[str] = Counter()
    repair_outcome_counts: Counter[str] = Counter()
    totals = Counter()
    sessions: List[Dict[str, Any]] = []
    repair_records: List[Dict[str, Any]] = []
    finish_reason_records: List[Dict[str, Any]] = []
    terminal_output_records: List[Dict[str, Any]] = []
    seen_terminal_output_calls: set[str] = set()

    for path in files:
        record: Dict[str, Any] = {
            "conversation_file": path.name,
            "session_id": "",
            "thread_name": "",
            "thread_session_index": 0,
            "label": "",
            "candidate_id": "",
            "stage": "unknown",
            "start_timestamp": "",
            "end_timestamp": "",
            "iterations": 0,
            "context_tokens": 0,
            "retained_prompt_tokens": 0,
            "retained_completion_tokens": 0,
            "exchange_count": 0,
            "finish_reasons": [],
            "truncated": False,
            "repair_payload_sources": [],
        }
        for line_no, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if not line.strip():
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"invalid JSON in {path}:{line_no}: {exc}") from exc
            session = event.get("session") or {}
            if session:
                record["session_id"] = str(session.get("id") or record["session_id"])
                record["thread_name"] = str(
                    session.get("thread_name") or record["thread_name"]
                )
                record["thread_session_index"] = int(
                    session.get("thread_session_index")
                    or record["thread_session_index"]
                    or 0
                )
                record["label"] = str(session.get("label") or record["label"])
            event_type = event.get("event")
            if event_type == "session_start":
                record["start_timestamp"] = str(event.get("timestamp") or "")
                continue
            if event_type == "session_end":
                record["end_timestamp"] = str(event.get("timestamp") or "")
                record["iterations"] = int(event.get("iterations") or 0)
                record["context_tokens"] = int(event.get("context_tokens") or 0)
                record["truncated"] = bool(event.get("truncated"))
                continue
            if event_type != "exchange":
                continue

            record["exchange_count"] += 1
            prompt_tokens = int(event.get("prompt_tokens") or 0)
            completion_tokens = int(event.get("completion_tokens") or 0)
            record["retained_prompt_tokens"] += prompt_tokens
            record["retained_completion_tokens"] += completion_tokens
            model = str(event.get("model") or "unknown")
            model_counts[model] += 1
            finish_reason = str(event.get("finish_reason") or "unknown")
            finish_reason_counts[finish_reason] += 1
            record["finish_reasons"].append(finish_reason)

            messages = list(event.get("request_messages") or [])
            response = event.get("response_message")
            if isinstance(response, dict):
                messages.append(response)
                if session_stage(str(session.get("label") or record["label"])) == "json_repair":
                    if text_has_accepted_validation_payload(response.get("content")):
                        if "json_content" not in record["repair_payload_sources"]:
                            record["repair_payload_sources"].append("json_content")
            for position, message in enumerate(messages):
                role = message.get("role")
                if role == "assistant":
                    for call_position, tool_call in enumerate(message.get("tool_calls") or []):
                        call_id = str(tool_call.get("id") or "")
                        if not call_id:
                            call_id = f"{path.name}:{line_no}:{position}:{call_position}"
                        function = tool_call.get("function") or {}
                        tool_name = str(function.get("name") or "unknown")
                        raw_arguments = function.get("arguments")
                        normalized_arguments = normalize_args(raw_arguments)
                        current_label = str(session.get("label") or record["label"])
                        current_stage = session_stage(current_label)
                        if tool_name in TERMINAL_OUTPUT_TOOL_NAMES:
                            if call_id in seen_terminal_output_calls:
                                continue
                            seen_terminal_output_calls.add(call_id)
                            arguments = parse_json_object(raw_arguments)
                            payload_valid = is_accepted_validation_payload(arguments)
                            terminal_output_records.append(
                                {
                                    "call_id": call_id,
                                    "tool": tool_name,
                                    "arguments": arguments
                                    if arguments is not None
                                    else normalized_arguments,
                                    "payload_valid": payload_valid,
                                    "conversation_file": path.name,
                                    "session_id": str(
                                        session.get("id") or record["session_id"]
                                    ),
                                    "label": current_label,
                                    "candidate_id": label_candidate(current_label),
                                    "stage": current_stage,
                                    "finish_reason": finish_reason,
                                    "timestamp": str(event.get("timestamp") or ""),
                                    "iteration": int(event.get("iteration") or 0),
                                }
                            )
                            if (
                                current_stage == "json_repair"
                                and payload_valid
                                and "terminal_tool" not in record["repair_payload_sources"]
                            ):
                                record["repair_payload_sources"].append("terminal_tool")
                            continue
                        if call_id in seen_calls:
                            continue
                        seen_calls.add(call_id)
                        signature = f"{tool_name}|{normalized_arguments}"
                        signatures[signature] += 1
                        try:
                            arguments = (
                                json.loads(raw_arguments)
                                if isinstance(raw_arguments, str)
                                else raw_arguments
                            )
                        except Exception:
                            arguments = normalized_arguments
                        call_meta[call_id] = {
                            "call_id": call_id,
                            "tool": tool_name,
                            "signature": signature,
                            "arguments": arguments,
                            "conversation_file": path.name,
                            "session_id": str(session.get("id") or record["session_id"]),
                            "label": str(session.get("label") or record["label"]),
                            "candidate_id": label_candidate(
                                str(session.get("label") or record["label"])
                            ),
                            "timestamp": str(event.get("timestamp") or ""),
                            "iteration": int(event.get("iteration") or 0),
                        }
                        if session_stage(str(session.get("label") or record["label"])) == "full_tool_fallback":
                            totals["fallback_tool_calls"] += 1
                        bucket = by_tool[tool_name]
                        bucket["calls"] += 1
                        if session_stage(str(session.get("label") or record["label"])) == "full_tool_fallback":
                            bucket["fallback_calls"] += 1
                        if signatures[signature] > 1:
                            bucket["repeated_calls"] += 1
                elif role == "tool":
                    call_id = str(message.get("tool_call_id") or "")
                    if call_id in seen_results or call_id not in call_meta:
                        continue
                    seen_results.add(call_id)
                    meta = call_meta[call_id]
                    tool_name = str(meta["tool"])
                    result = parse_tool_result(str(message.get("content") or ""))
                    bucket = by_tool[tool_name]
                    bucket["results"] += 1
                    success = result_success(result)
                    error = result_error(result)
                    if success is True:
                        bucket["success"] += 1
                    elif success is False:
                        error_class = classify_error(error)
                        bucket[error_class] += 1
                        error_types[tool_name][normalize_error(error)] += 1
                        failure_records[tool_name].append(
                            {
                                **meta,
                                "error": error,
                                "error_class": error_class,
                            }
                        )
                    else:
                        bucket["unknown_results"] += 1
                    if is_empty_result(tool_name, result):
                        bucket["empty_results"] += 1
                    if result.get("repeat_call_warning") or result.get("cached_tool_result"):
                        bucket["loop_guard_warnings"] += 1
                    if result.get("repeat_call_guard") or "loop guard" in error.lower():
                        bucket["loop_guard_blocked"] += 1

        record["stage"] = session_stage(str(record["label"]))
        record["candidate_id"] = label_candidate(str(record["label"]))
        stage_counts[str(record["stage"])] += 1
        totals["sessions"] += 1
        totals["exchanges"] += int(record["exchange_count"])
        totals["context_tokens"] += int(record["context_tokens"])
        totals["retained_prompt_tokens"] += int(record["retained_prompt_tokens"])
        totals["retained_completion_tokens"] += int(record["retained_completion_tokens"])
        if record["truncated"]:
            totals["truncated_sessions"] += 1
        if record["stage"] == "json_repair":
            reason = label_repair_reason(str(record["label"]))
            repair_reason_counts[reason] += 1
            for finish_reason in record["finish_reasons"] or ["unknown"]:
                repair_finish_reason_counts[finish_reason] += 1
            repair_result = (
                "accepted" if record["repair_payload_sources"] else "failed"
            )
            repair_outcome_counts[repair_result] += 1
            repair_records.append(
                {**record, "repair_reason": reason, "repair_result": repair_result}
            )
        for finish_reason in record["finish_reasons"]:
            if finish_reason != "stop":
                finish_reason_records.append({**record, "finish_reason": finish_reason})
        sessions.append(record)

    main_sessions_by_thread_candidate: Dict[tuple[str, str], List[Dict[str, Any]]] = (
        defaultdict(list)
    )
    for record in sessions:
        if record["stage"] not in {"primary", "full_tool_fallback"}:
            continue
        key = (str(record["thread_name"]), str(record["candidate_id"]))
        main_sessions_by_thread_candidate[key].append(record)
    for candidates in main_sessions_by_thread_candidate.values():
        candidates.sort(key=lambda item: int(item["thread_session_index"]))

    for repair_record in repair_records:
        key = (
            str(repair_record["thread_name"]),
            str(repair_record["candidate_id"]),
        )
        repair_index = int(repair_record["thread_session_index"])
        preceding = [
            record
            for record in main_sessions_by_thread_candidate.get(key, [])
            if int(record["thread_session_index"]) < repair_index
        ]
        original = preceding[-1] if preceding else None
        repair_record["original_finish_reasons"] = (
            list(original.get("finish_reasons") or []) if original else []
        )

    unreturned_records: List[Dict[str, Any]] = []
    for call_id in sorted(seen_calls - seen_results):
        meta = dict(call_meta[call_id])
        by_tool[str(meta["tool"])]["unreturned_calls"] += 1
        unreturned_records.append(meta)

    totals["retained_total_tokens"] = (
        totals["retained_prompt_tokens"] + totals["retained_completion_tokens"]
    )
    totals["unique_tool_calls"] = len(seen_calls)
    totals["unique_tool_results"] = len(seen_results)
    totals["unreturned_tool_calls"] = len(unreturned_records)
    terminal_output = {
        "calls": len(terminal_output_records),
        "valid_payloads": sum(
            1 for record in terminal_output_records if record["payload_valid"]
        ),
        "invalid_payloads": sum(
            1 for record in terminal_output_records if not record["payload_valid"]
        ),
        "records": terminal_output_records,
    }
    repair_attempted = len(repair_records)
    repair_accepted = int(repair_outcome_counts.get("accepted") or 0)
    repair_failed = int(repair_outcome_counts.get("failed") or 0)
    repair_metrics = {
        "repair_attempted": repair_attempted,
        "repair_accepted": repair_accepted,
        "repair_failed": repair_failed,
        "repair_acceptance_rate": safe_div(repair_accepted, repair_attempted),
        "trigger_reason_counts": dict(repair_reason_counts),
        "finish_reason_counts": dict(repair_finish_reason_counts),
        "outcome_counts": dict(repair_outcome_counts),
    }
    main_sessions = [
        record
        for record in sessions
        if record["stage"] in {"primary", "full_tool_fallback"}
    ]
    outliers = sorted(
        (record for record in main_sessions if int(record["iterations"]) > 1),
        key=lambda item: (-int(item["iterations"]), str(item["conversation_file"])),
    )
    return {
        "conversation": dict(totals),
        "stage_counts": dict(stage_counts),
        "model_counts": dict(model_counts),
        "finish_reason_counts": dict(finish_reason_counts),
        "finish_reason_records": finish_reason_records,
        "repair_reason_counts": dict(repair_reason_counts),
        "repair_metrics": repair_metrics,
        "repair_records": repair_records,
        "terminal_output": terminal_output,
        "multi_turn_outlier_records": outliers,
        "sessions": sessions,
        "by_tool": {name: dict(values) for name, values in sorted(by_tool.items())},
        "error_types_by_tool": {
            name: dict(counter.most_common()) for name, counter in sorted(error_types.items())
        },
        "failure_records_by_tool": {
            name: list(failure_records.get(name) or []) for name in sorted(by_tool)
        },
        "unreturned_call_records": unreturned_records,
    }


def analyze_stage_usage(
    log: Dict[str, Any], conversations: Dict[str, Any]
) -> Dict[str, Dict[str, int]]:
    """Attribute Validator API traces to session stages in per-worker order."""
    sessions_by_thread: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for session in conversations.get("sessions") or []:
        stage = str(session.get("stage") or "")
        if stage not in {"primary", "full_tool_fallback", "json_repair"}:
            continue
        thread_name = str(session.get("thread_name") or "")
        if not thread_name:
            raise ValueError(
                f"Validator session {session.get('conversation_file')} has no thread_name"
            )
        sessions_by_thread[thread_name].append(session)

    traces_by_thread = log.get("validator_api_traces_by_thread") or {}
    usage: Dict[str, Counter[str]] = defaultdict(Counter)
    for thread_name, sessions in sorted(sessions_by_thread.items()):
        traces = list(traces_by_thread.get(thread_name) or [])
        position = 0
        for session in sorted(
            sessions,
            key=lambda item: (
                int(item.get("thread_session_index") or 0),
                str(item.get("conversation_file") or ""),
            ),
        ):
            api_calls = int(session.get("iterations") or 0)
            selected = traces[position : position + api_calls]
            if len(selected) != api_calls:
                raise ValueError(
                    f"not enough Validator API traces for {session.get('conversation_file')}: "
                    f"expected={api_calls}, found={len(selected)}"
                )
            stage = str(session["stage"])
            usage[stage]["sessions"] += 1
            usage[stage]["api_calls"] += api_calls
            for trace in selected:
                usage[stage]["prompt_tokens"] += int(trace.get("prompt_tokens") or 0)
                usage[stage]["completion_tokens"] += int(
                    trace.get("completion_tokens") or 0
                )
                usage[stage]["total_tokens"] += int(trace.get("total_tokens") or 0)
            position += api_calls
        if position != len(traces):
            raise ValueError(
                f"unattributed Validator API traces for {thread_name}: "
                f"attributed={position}, total={len(traces)}"
            )

    unknown_threads = sorted(set(traces_by_thread) - set(sessions_by_thread))
    if unknown_threads:
        raise ValueError(
            "Validator API traces have no matching conversations: "
            + ", ".join(unknown_threads)
        )
    return {stage: dict(values) for stage, values in sorted(usage.items())}


def is_rule_decision(item: Dict[str, Any]) -> bool:
    deterministic_decision = str(item.get("deterministic_prevalidation_decision") or "")
    rejection_source = str(item.get("rejection_source") or "")
    deterministic_rejection = bool(item.get("deterministic_rejection"))
    validator_avoided = bool(item.get("validator_avoided"))
    return bool(
        validator_avoided
        or deterministic_decision
        or deterministic_rejection
        or rejection_source.startswith("deterministic_")
        or rejection_source == "static_analysis"
    )


def candidate_decision_bucket(item: Dict[str, Any]) -> str:
    disposition = str(
        item.get("candidate_disposition") or item.get("terminal_disposition") or "other"
    )
    rule_decision = is_rule_decision(item)
    if disposition == "confirmed":
        return "rule_confirmed" if rule_decision else "llm_confirmed"
    if disposition == "rejected_with_proof":
        return "rule_rejected" if rule_decision else "llm_rejected"
    if disposition == "needs_review":
        return "rule_needs_review" if rule_decision else "llm_needs_review"
    if disposition == "deduplicated_alias":
        finding_kind = str(item.get("finding_kind") or "")
        aliases = {
            "verified_vulnerability": "confirmed_alias",
            "needs_review": "needs_review_alias",
            "audit_observation": "needs_review_alias",
        }
        if finding_kind in aliases:
            origin = "rule" if rule_decision else "llm"
            return f"{origin}_{aliases[finding_kind]}"
        raise ValueError(f"unknown deduplicated_alias finding_kind: {finding_kind!r}")
    raise ValueError(f"unknown candidate disposition: {disposition!r}")


def analyze_candidates(report: Dict[str, Any]) -> Dict[str, Any]:
    candidates = report.get("candidate_terminal_states")
    if not isinstance(candidates, list):
        raise ValueError("zscope_batch_report.json is missing candidate_terminal_states")
    terminal_counts: Counter[str] = Counter()
    evidence_completion: Counter[str] = Counter()
    by_source: Dict[str, Counter[str]] = defaultdict(Counter)
    decision_buckets: Counter[str] = Counter()
    validation_attempts: Counter[str] = Counter()
    for item in candidates:
        if not isinstance(item, dict):
            raise ValueError("candidate_terminal_states must contain JSON objects")
        terminal = str(item.get("terminal_disposition") or "")
        if terminal not in {"confirmed", "needs_review", "rejected_with_proof"}:
            raise ValueError(f"unknown or non-terminal candidate disposition: {terminal!r}")
        terminal_counts[terminal] += 1
        evidence_completion[str(item.get("evidence_completion_status") or "unknown")] += 1
        bucket = candidate_decision_bucket(item)
        source = str(item.get("candidate_source") or "unknown")
        by_source[source][bucket] += 1
        decision_buckets[bucket] += 1
        validation_attempts[str(int(item.get("validation_attempt_count") or 0))] += 1
    return {
        "candidate_count": len(candidates),
        "terminal_counts": dict(terminal_counts),
        "evidence_completion_status": dict(evidence_completion),
        "decision_buckets": dict(decision_buckets),
        "by_source": {name: dict(values) for name, values in sorted(by_source.items())},
        "validation_attempt_distribution": dict(validation_attempts),
    }


def benchmark_view(value: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "view": str(value.get("view") or ""),
        "report_issue_count": int(value.get("report_issue_count") or 0),
        "ground_truth_count": int(value.get("ground_truth_count") or 0),
        "true_positives": int(value.get("true_positives") or 0),
        "false_positives_raw": int(value.get("false_positives_raw") or 0),
        "false_positives_effective": int(
            value.get("false_positives_effective")
            if value.get("false_positives_effective") is not None
            else value.get("false_positives") or 0
        ),
        "duplicate_of_matched_count": int(value.get("duplicate_of_matched_count") or 0),
        "false_negatives": int(value.get("false_negatives") or 0),
        "recall": value.get("recall"),
        "actionable_precision": value.get("actionable_precision"),
        "actionable_f1": value.get("actionable_f1"),
        "root_cause_precision": value.get("root_cause_precision", value.get("precision")),
        "root_cause_f1": value.get("root_cause_f1", value.get("f1")),
        "root_cause_false_discovery_rate": value.get(
            "root_cause_false_discovery_rate", value.get("false_discovery_rate")
        ),
        "per_cwe_recall": dict(value.get("per_cwe_recall") or {}),
    }


def analyze_benchmark(
    default_evaluation: Dict[str, Any], needs_evaluation: Dict[str, Any]
) -> Dict[str, Any]:
    default = benchmark_view(default_evaluation)
    needs = benchmark_view(needs_evaluation)
    cwes = []
    all_cwes = sorted(
        set(default["per_cwe_recall"]) | set(needs["per_cwe_recall"]),
        key=lambda item: (int(item.split("-")[-1]) if item.split("-")[-1].isdigit() else 10**9, item),
    )
    for cwe in all_cwes:
        default_value = dict(default["per_cwe_recall"].get(cwe) or {})
        needs_value = dict(needs["per_cwe_recall"].get(cwe) or {})
        default_recall = default_value.get("recall")
        needs_recall = needs_value.get("recall")
        if (
            (default_recall is not None and float(default_recall) < 1.0)
            or (needs_recall is not None and float(needs_recall) < 1.0)
            or int(needs_value.get("true_positives") or 0)
            > int(default_value.get("true_positives") or 0)
        ):
            cwes.append(
                {
                    "cwe": cwe,
                    "sample_count": int(
                        needs_value.get("sample_count")
                        or default_value.get("sample_count")
                        or 0
                    ),
                    "default_true_positives": int(default_value.get("true_positives") or 0),
                    "default_recall": default_recall,
                    "needs_review_true_positives": int(needs_value.get("true_positives") or 0),
                    "needs_review_recall": needs_recall,
                }
            )
    gains = {
        "additional_true_positives": needs["true_positives"] - default["true_positives"],
        "additional_effective_false_positives": (
            needs["false_positives_effective"] - default["false_positives_effective"]
        ),
        "false_negatives_reduced": default["false_negatives"] - needs["false_negatives"],
    }
    for key in (
        "recall",
        "actionable_precision",
        "actionable_f1",
        "root_cause_precision",
        "root_cause_f1",
    ):
        default_value = default.get(key)
        needs_value = needs.get(key)
        gains[f"{key}_percentage_point_change"] = (
            (float(needs_value) - float(default_value)) * 100
            if default_value is not None and needs_value is not None
            else None
        )
    return {"default": default, "with_needs_review": needs, "gains": gains, "cwe_rows": cwes}


def validate_inputs(run: Dict[str, Any], report: Dict[str, Any], data: Dict[str, Any]) -> None:
    performance = data["validation_performance"]
    queue = data["validation_queue"]
    candidates = data["candidates"]
    conversations = data["conversations"]
    log = data["log"]
    groups = int(queue.get("unique_group_count") or performance.get("validation_group_count") or 0)
    terminal_total = sum(int(value) for value in candidates["terminal_counts"].values())
    if candidates["candidate_count"] != groups or terminal_total != groups:
        raise ValueError(
            "validation group terminal-state conservation failed: "
            f"groups={groups}, candidates={candidates['candidate_count']}, terminal={terminal_total}"
        )
    raw = int(queue.get("raw_occurrence_count") or 0)
    merged = int(performance.get("validation_group_merged_count") or 0)
    if raw and raw - groups != merged:
        raise ValueError(
            f"validation coalescing conservation failed: raw={raw}, groups={groups}, merged={merged}"
        )
    start = log.get("start") or {}
    end = log.get("end") or {}
    if int(log.get("counts", {}).get("validation_queue_start") or 0) != 1:
        raise ValueError("expected exactly one validation queue start log")
    if int(log.get("counts", {}).get("validation_queue_end") or 0) != 1:
        raise ValueError("expected exactly one validation queue end log")
    for label, value in (("start", start), ("end", end)):
        if value and int(value.get("unique_groups") or 0) != groups:
            raise ValueError(f"validation queue {label} group count disagrees with report")
    if start and int(start.get("raw_occurrences") or 0) != raw:
        raise ValueError("validation queue raw occurrence count disagrees with report")
    report_duration = float(queue.get("duration_seconds") or 0)
    log_duration = float(end.get("duration_seconds") or 0)
    if report_duration and log_duration and abs(report_duration - log_duration) > 0.02:
        raise ValueError("validation queue duration disagrees with the end log")
    terminal_counts = candidates["terminal_counts"]
    if end and int(end.get("confirmed") or 0) != int(terminal_counts.get("confirmed") or 0):
        raise ValueError("validation queue confirmed count disagrees with candidate terminals")
    if end and int(end.get("review") or 0) != int(terminal_counts.get("needs_review") or 0):
        raise ValueError("validation queue review count disagrees with candidate terminals")
    if not bool(queue.get("drained")):
        raise ValueError("validation queue was not drained")
    stage_counts = conversations["stage_counts"]
    conversation_main = int(stage_counts.get("primary") or 0) + int(
        stage_counts.get("full_tool_fallback") or 0
    )
    reported_main = int(queue.get("validator_session_count") or 0)
    if reported_main and conversation_main != reported_main:
        raise ValueError(
            f"validator main-session count mismatch: report={reported_main}, conversations={conversation_main}"
        )
    llm_groups = groups - int(performance.get("prevalidation_decision_count") or 0)
    decision_buckets = candidates.get("decision_buckets") or {}
    rule_terminal_count = sum(
        int(count or 0)
        for bucket, count in decision_buckets.items()
        if str(bucket).startswith("rule_")
    )
    llm_terminal_count = sum(
        int(count or 0)
        for bucket, count in decision_buckets.items()
        if str(bucket).startswith("llm_")
    )
    if rule_terminal_count != groups - llm_groups:
        raise ValueError(
            "Rule terminal-state conservation failed: "
            f"terminals={rule_terminal_count}, prevalidation={groups - llm_groups}"
        )
    if llm_terminal_count != llm_groups:
        raise ValueError(
            "LLM terminal-state conservation failed: "
            f"terminals={llm_terminal_count}, LLM groups={llm_groups}"
        )
    fast_attempted = int(performance.get("validator_fast_path_attempted") or 0)
    fast_accepted = int(performance.get("validator_fast_path_accepted") or 0)
    primary = int(stage_counts.get("primary") or 0)
    fallback = int(stage_counts.get("full_tool_fallback") or 0)
    if fast_attempted:
        if (
            primary != llm_groups
            or fast_attempted != primary
            or fallback != fast_attempted - fast_accepted
        ):
            raise ValueError("Validator fast-path/fallback conservation failed")
    elif primary != 0 or fallback != llm_groups or fast_accepted != 0:
        raise ValueError("Validator direct-full-tool conservation failed")
    turn_distribution = queue.get("validator_turn_distribution") or {}
    if sum(int(value or 0) for value in turn_distribution.values()) != llm_groups:
        raise ValueError("Validator turn distribution does not cover every LLM group")
    outlier_count = sum(
        int(count or 0)
        for turns, count in turn_distribution.items()
        if int(turns) > 2
    )
    if outlier_count != int(queue.get("multi_turn_outlier_count") or 0):
        raise ValueError("Validator multi-turn outlier count disagrees with turn distribution")
    llm_usage = data["llm_usage"]
    stage_usage = data["stage_usage"]
    reported_api_calls = int(queue.get("validator_api_call_count") or 0)
    successful_calls = int(llm_usage.get("successful_calls") or 0)
    if reported_api_calls and successful_calls and reported_api_calls != successful_calls:
        raise ValueError("Validator API call count disagrees with LLM usage")
    if int(llm_usage.get("prompt_tokens") or 0) + int(
        llm_usage.get("completion_tokens") or 0
    ) != int(llm_usage.get("total_tokens") or 0):
        raise ValueError("LLM token totals do not add up")
    for metric in ("api_calls", "prompt_tokens", "completion_tokens", "total_tokens"):
        stage_total = sum(int(values.get(metric) or 0) for values in stage_usage.values())
        expected = (
            reported_api_calls
            if metric == "api_calls"
            else int(llm_usage.get(metric) or 0)
        )
        if stage_total != expected:
            raise ValueError(
                f"Validator stage {metric} does not match the authoritative total: "
                f"stages={stage_total}, total={expected}"
            )
    tools = conversations["conversation"]
    if (
        int(tools.get("unique_tool_calls") or 0)
        != int(tools.get("unique_tool_results") or 0)
        + int(tools.get("unreturned_tool_calls") or 0)
    ):
        raise ValueError("tool call/result conservation failed")
    if not run.get("benchmark_valid"):
        raise ValueError("run_summary.json marks the benchmark invalid")
    if not run.get("run_manifest_valid"):
        raise ValueError("run_summary.json marks the run manifest invalid")
    if not run.get("model_trace_valid"):
        raise ValueError("run_summary.json marks the model trace invalid")
    if str(report.get("completeness") or "") != "complete":
        raise ValueError("zscope_batch_report.json is not complete")
    if data["benchmark"]["default"].get("view") != "default":
        raise ValueError("evaluation.json is not the default evaluation view")
    if data["benchmark"]["with_needs_review"].get("view") != "with_needs_review":
        raise ValueError(
            "evaluation.with_needs_review.json is not the with_needs_review evaluation view"
        )


def safe_div(numerator: Any, denominator: Any) -> float:
    return float(numerator or 0) / float(denominator or 0) if denominator else 0.0


def pct(numerator: Any, denominator: Any) -> str:
    return f"{safe_div(numerator, denominator) * 100:.2f}%" if denominator else "-"


def fmt_pct(value: Any) -> str:
    return f"{float(value) * 100:.2f}%" if value is not None else "-"


def fmt_pp(value: Any) -> str:
    return f"{float(value):+.2f} pp" if value is not None else "-"


def fmt_int(value: Any) -> str:
    return f"{int(value or 0):,}"


def fmt_float(value: Any, digits: int = 2) -> str:
    return f"{float(value or 0):,.{digits}f}"


def markdown_cell(value: Any) -> str:
    return str(value).replace("|", "\\|").replace("\n", "<br>")


def row(values: Iterable[Any]) -> str:
    return "| " + " | ".join(str(value) for value in values) + " |"


def source_row(name: str, counts: Dict[str, int]) -> List[str]:
    keys = (
        "rule_confirmed",
        "llm_confirmed",
        "rule_needs_review",
        "llm_needs_review",
        "rule_rejected",
        "llm_rejected",
        "rule_confirmed_alias",
        "llm_confirmed_alias",
        "rule_needs_review_alias",
        "llm_needs_review_alias",
    )
    return [name, fmt_int(sum(int(counts.get(key) or 0) for key in keys))] + [
        fmt_int(counts.get(key)) for key in keys
    ]


def render_markdown(data: Dict[str, Any], model: str) -> str:
    run = data["run"]
    performance = data["validation_performance"]
    queue = data["validation_queue"]
    llm = data["llm_usage"]
    candidates = data["candidates"]
    conversations = data["conversations"]
    benchmark = data["benchmark"]
    log = data["log"]
    groups = int(queue.get("unique_group_count") or 0)
    raw = int(queue.get("raw_occurrence_count") or 0)
    merged = int(performance.get("validation_group_merged_count") or 0)
    prevalidation = int(performance.get("prevalidation_decision_count") or 0)
    deterministic = int(performance.get("deterministic_prevalidation_decision_count") or 0)
    static_audit = int(performance.get("static_audit_observation_count") or 0)
    llm_groups = groups - prevalidation
    primary = int(conversations["stage_counts"].get("primary") or 0)
    fallback = int(conversations["stage_counts"].get("full_tool_fallback") or 0)
    repair = int(conversations["stage_counts"].get("json_repair") or 0)
    main_sessions = primary + fallback
    turn_distribution = queue.get("validator_turn_distribution") or {}
    logical_single_turn = int(turn_distribution.get("1") or 0)
    logical_multi_turn = llm_groups - logical_single_turn
    api_calls = int(queue.get("validator_api_call_count") or llm.get("successful_calls") or 0)
    validation_seconds = float(queue.get("duration_seconds") or 0)
    scan_seconds = float(run.get("scan_wall_seconds") or 0)
    build_cpg_seconds = run.get("build_cpg_timing", {}).get("duration_seconds")
    discover_entries_seconds = log.get("discover_entries_timing", {}).get(
        "duration_seconds"
    )
    terminal = candidates["terminal_counts"]
    stage_usage = data["stage_usage"]
    fast_path_usage = stage_usage.get("primary") or {}
    fallback_usage = stage_usage.get("full_tool_fallback") or {}
    repair_usage = stage_usage.get("json_repair") or {}
    repair_metrics = conversations.get("repair_metrics") or {}
    terminal_output = conversations.get("terminal_output") or {}

    lines = [
        "# Validation Metrics",
        "",
        f"> Run: `{run['run_id']}`  ",
        f"> Model: `{model}`  ",
        "",
        "## 一、验证总览",
        "",
    ]
    lines.extend(
            [
                "### 1.1 Benchmark 验证质量",
                "",
                "| 视图 | Report Issues | Ground Truth | TP | Raw FP | Effective FP | Matched Duplicate | FN | Recall | Actionable Precision | Actionable F1 | Root-cause Precision | Root-cause F1 | Root-cause FDR |",
                "|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|",
            ]
        )
    for label, key in (("默认视图", "default"), ("Needs Review 视图", "with_needs_review")):
        view = benchmark[key]
        lines.append(
            row(
                [
                    label,
                    fmt_int(view["report_issue_count"]),
                    fmt_int(view["ground_truth_count"]),
                    fmt_int(view["true_positives"]),
                    fmt_int(view["false_positives_raw"]),
                    fmt_int(view["false_positives_effective"]),
                    fmt_int(view["duplicate_of_matched_count"]),
                    fmt_int(view["false_negatives"]),
                    fmt_pct(view["recall"]),
                    fmt_pct(view["actionable_precision"]),
                    fmt_pct(view["actionable_f1"]),
                    fmt_pct(view["root_cause_precision"]),
                    fmt_pct(view["root_cause_f1"]),
                    fmt_pct(view["root_cause_false_discovery_rate"]),
                ]
            )
        )
    lines.extend(
            [
                "### 1.2 候选来源与决策方式",
                "",
                "| 候选来源 | 总数 | Rule Confirmed | LLM Confirmed | Rule Needs Review | LLM Needs Review | Rule Rejected | LLM Rejected | Rule Confirmed Alias | LLM Confirmed Alias | Rule Needs Review Alias | LLM Needs Review Alias |",
                "|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|",
            ]
    )
    total_source = Counter()
    for source, counts in sorted(
        candidates["by_source"].items(),
        key=lambda item: (-sum(int(value) for value in item[1].values()), item[0]),
    ):
        lines.append(row(source_row(source, counts)))
        total_source.update(counts)
    lines.append(row(source_row("Total", dict(total_source))))
    lines.extend(
        [
            "### 1.3 候选归并与验证路径",
            "",
            "| 指标 | 数值 | 比例 / 说明 |",
            "|---|---:|---:|",
            row(["原始 Candidate Occurrences", fmt_int(raw), "100.00%"]),
            row(["Validation Groups", fmt_int(groups), pct(groups, raw)]),
            row(["归并的重复 Occurrences", fmt_int(merged), pct(merged, raw)]),
            row(["不进入 LLM Validator", fmt_int(prevalidation), pct(prevalidation, groups)]),
            row(["其中 Deterministic Prevalidation", fmt_int(deterministic), pct(deterministic, groups)]),
            row(["其中 Static Audit", fmt_int(static_audit), pct(static_audit, groups)]),
            row(["进入 LLM Validator", fmt_int(llm_groups), pct(llm_groups, groups)]),
            row(["Fast Path 接受", fmt_int(performance.get("validator_fast_path_accepted")), pct(performance.get("validator_fast_path_accepted"), llm_groups)]),
            row(["Full-tool Fallback", fmt_int(fallback), pct(fallback, llm_groups)]),
            "",
            "### 1.4 最终终态",
            "",
            "| 终态 | Groups | 占比 |",
            "|---|---:|---:|",
            row(["Confirmed", fmt_int(terminal.get("confirmed")), pct(terminal.get("confirmed"), groups)]),
            row(["Needs Review", fmt_int(terminal.get("needs_review")), pct(terminal.get("needs_review"), groups)]),
            row(["Rejected with Proof", fmt_int(terminal.get("rejected_with_proof")), pct(terminal.get("rejected_with_proof"), groups)]),
            row(["Total", fmt_int(sum(int(value) for value in terminal.values())), "100.00%"]),
            "",
             "### 1.5 Evidence Completion",
            "",
            "| 状态 | Groups | 占比 |",
            "|---|---:|---:|",
        ]
    )
    for status, count in sorted(
        candidates["evidence_completion_status"].items(),
        key=lambda item: (-int(item[1]), item[0]),
    ):
        lines.append(row([f"`{status}`", fmt_int(count), pct(count, groups)]))
    lines.extend(
        [
            "",
            "## 二、验证效率与 Token 成本",
            "",
            "### 2.1 阶段耗时",
            "",
            "| 指标 | 数值 |",
            "|---|---:|",
            row(["Build CPG", f"{fmt_float(build_cpg_seconds)}s" if build_cpg_seconds is not None else "-"]),
            # row(["Discover Entries", f"{fmt_float(discover_entries_seconds)}s" if discover_entries_seconds is not None else "-"]),
            row(["Scan Wall Time", f"{fmt_float(scan_seconds)}s ({scan_seconds / 3600:.2f}h)"]),
            row(["Validation Queue Wall Time", f"{fmt_float(validation_seconds)}s ({validation_seconds / 3600:.2f}h)"]),
            "",
            # row(["Validation Groups 吞吐", f"{fmt_float(safe_div(groups, validation_seconds) * 60)} groups/min"]),
            # row(["LLM Groups 吞吐", f"{fmt_float(safe_div(llm_groups, validation_seconds) * 60)} groups/min"]),
            # row(["每个 Validation Group 的 wall-time 等价值", f"{fmt_float(safe_div(validation_seconds, groups))}s"]),
            # row(["每个 LLM Group 的 wall-time 等价值", f"{fmt_float(safe_div(validation_seconds, llm_groups))}s"]),
            # "",
            # "Wall-time 等价值用于成本归一化；Validator 并行运行，不能解释为每个 group 的实际独占耗时。",
            "",
            "### 2.2 Token 与 API 成本",
            "",
            "| 口径 | Sessions | API Calls | Prompt Tokens | Completion Tokens | Total Tokens |",
            "|---|---:|---:|---:|---:|---:|",
            row(["Validator 总计", fmt_int( conversations["conversation"].get("sessions")), fmt_int(api_calls), fmt_int(llm.get("prompt_tokens")), fmt_int(llm.get("completion_tokens")), fmt_int(llm.get("total_tokens"))]),
            row(["Fast Path Session 总计", fmt_int(fast_path_usage.get("sessions")), fmt_int(fast_path_usage.get("api_calls")), fmt_int(fast_path_usage.get("prompt_tokens")), fmt_int(fast_path_usage.get("completion_tokens")), fmt_int(fast_path_usage.get("total_tokens"))]),
            row(["Fallback Session 总计",  fmt_int(fallback_usage.get("sessions")), fmt_int(fallback_usage.get("api_calls")), fmt_int(fallback_usage.get("prompt_tokens")), fmt_int(fallback_usage.get("completion_tokens")), fmt_int(fallback_usage.get("total_tokens"))]),
            row(["JSON Repair Session 总计",  fmt_int(repair_usage.get("sessions")), fmt_int(repair_usage.get("api_calls")), fmt_int(repair_usage.get("prompt_tokens")), fmt_int(repair_usage.get("completion_tokens")), fmt_int(repair_usage.get("total_tokens"))]),        
            "",
            "### 2.3 Session 平均 Token 与 API 成本",
            "",
            "| 口径 | API Calls | Prompt Tokens | Completion Tokens | Total Tokens |",
            "|---|---:|---:|---:|---:|",
            row(["Fast Path Session 平均", fmt_float(safe_div(fast_path_usage.get("api_calls"), fast_path_usage.get("sessions"))), fmt_float(safe_div(fast_path_usage.get("prompt_tokens"), fast_path_usage.get("sessions"))), fmt_float(safe_div(fast_path_usage.get("completion_tokens"), fast_path_usage.get("sessions"))), fmt_float(safe_div(fast_path_usage.get("total_tokens"), fast_path_usage.get("sessions")))]),
            row(["Fallback Session 平均", fmt_float(safe_div(fallback_usage.get("api_calls"), fallback_usage.get("sessions"))), fmt_float(safe_div(fallback_usage.get("prompt_tokens"), fallback_usage.get("sessions"))), fmt_float(safe_div(fallback_usage.get("completion_tokens"), fallback_usage.get("sessions"))), fmt_float(safe_div(fallback_usage.get("total_tokens"), fallback_usage.get("sessions")))]),
            row(["JSON Repair Session 平均", fmt_float(safe_div(repair_usage.get("api_calls"), repair_usage.get("sessions"))), fmt_float(safe_div(repair_usage.get("prompt_tokens"), repair_usage.get("sessions"))), fmt_float(safe_div(repair_usage.get("completion_tokens"), repair_usage.get("sessions"))), fmt_float(safe_div(repair_usage.get("total_tokens"), repair_usage.get("sessions")))]),
            "",     
        ]
    )
    tools = conversations["by_tool"]
    lines.extend(
        [
            "",
            "## 三、Validator 工具质量",
            "",
            "### 3.1 工具调用总览",
            "",
            "| 工具 | Calls | Fallback Session 平均 Calls | Results | 成功率 | 参数错误率 | 格式错误率 | 其他错误率 | 未知结果率 | 空结果率 | 重复参数调用率 | Loop Guard 警告/拦截 | 未返回 |",
            "|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|",
        ]
    )
    for tool_name, bucket in sorted(
        tools.items(), key=lambda item: (-int(item[1].get("calls") or 0), item[0])
    ):
        results = int(bucket.get("results") or 0)
        calls = int(bucket.get("calls") or 0)
        lines.append(
            row(
                [
                    f"`{tool_name}`",
                    fmt_int(calls),
                    fmt_float(safe_div(bucket.get("fallback_calls"), fallback)),
                    fmt_int(results),
                    pct(bucket.get("success"), results),
                    pct(bucket.get("parameter_errors"), results),
                    pct(bucket.get("format_errors"), results),
                    pct(bucket.get("other_errors"), results),
                    pct(bucket.get("unknown_results"), results),
                    pct(bucket.get("empty_results"), results),
                    pct(bucket.get("repeated_calls"), calls),
                    f"{fmt_int(bucket.get('loop_guard_warnings'))}/{fmt_int(bucket.get('loop_guard_blocked'))}",
                    fmt_int(bucket.get("unreturned_calls")),
                ]
            )
        )
    total_tool_bucket = Counter()
    for bucket in tools.values():
        total_tool_bucket.update(
            {key: int(bucket.get(key) or 0) for key in TOOL_BUCKET_KEYS}
        )
    total_results = int(total_tool_bucket.get("results") or 0)
    total_calls = int(total_tool_bucket.get("calls") or 0)
    lines.append(
        row(
            [
                "Total",
                fmt_int(total_calls),
                fmt_float(safe_div(total_tool_bucket.get("fallback_calls"), fallback)),
                fmt_int(total_results),
                pct(total_tool_bucket.get("success"), total_results),
                pct(total_tool_bucket.get("parameter_errors"), total_results),
                pct(total_tool_bucket.get("format_errors"), total_results),
                pct(total_tool_bucket.get("other_errors"), total_results),
                pct(total_tool_bucket.get("unknown_results"), total_results),
                pct(total_tool_bucket.get("empty_results"), total_results),
                pct(total_tool_bucket.get("repeated_calls"), total_calls),
                f"{fmt_int(total_tool_bucket.get('loop_guard_warnings'))}/{fmt_int(total_tool_bucket.get('loop_guard_blocked'))}",
                fmt_int(total_tool_bucket.get("unreturned_calls")),
            ]
        )
    )
    tool_totals = conversations["conversation"]
    lines.extend(
        [
            "",
            "### 3.2 工具错误类型",
            "",
        ]
    )
    error_types = conversations.get("error_types_by_tool") or {}
    if error_types:
        lines.extend(["| 工具 | 错误类型 | 次数 |", "|---|---|---:|"])
        for tool_name, errors in sorted(error_types.items()):
            for error, count in errors.items():
                lines.append(row([f"`{tool_name}`", markdown_cell(error), fmt_int(count)]))
    else:
        lines.append("本次运行没有记录工具失败。")
    lines.extend(
        [
            "",
            "- 工具调用按唯一 `tool_call_id` 统计，同时解析历史 request messages 与最终 response message。",
            "",
        ]
    )

    lines.extend(
        [
            "",
            "## 四、异常与完整性附录",
            "",
            "### 4.1 JSON Repair 会话",
            "",
            "| # | Candidate | Repair 触发原因 | 原始 Session Finish Reason | Repair Session Finish Reason | Repair 解析结果 | Payload 来源 | Conversation 文件 |",
            "|---:|---|---|---|---|---|---|---|",
        ]
    )
    for index, record in enumerate(conversations["repair_records"], 1):
        lines.append(
            row(
                [
                    index,
                    f"`{record.get('candidate_id') or '-'}`",
                    f"`{record.get('repair_reason') or 'unknown'}`",
                    markdown_cell(
                        ", ".join(record.get("original_finish_reasons") or []) or "-"
                    ),
                    markdown_cell(", ".join(record.get("finish_reasons") or []) or "-"),
                    f"`{record.get('repair_result') or 'failed'}`",
                    markdown_cell(
                        ", ".join(record.get("repair_payload_sources") or []) or "-"
                    ),
                    f"`{record.get('conversation_file')}`",
                ]
            )
        )
    if not conversations["repair_records"]:
        lines.append(row(["-", "-", "无", "-", "-", "-", "-", "-"]))

    lines.extend(
        [
            "",
            "### 4.2  主 Validator 会话中的非 Stop Finish Reason",
            "",
            "| # | Candidate | Stage | Finish Reason | Iterations | Conversation 文件 |",
            "|---:|---|---|---|---:|---|",
        ]
    )
    main_finish_reason_records = [
        record
        for record in conversations["finish_reason_records"]
        if record.get("stage") in {"primary", "full_tool_fallback"}
    ]
    for index, record in enumerate(main_finish_reason_records, 1):
        lines.append(
            row(
                [
                    index,
                    f"`{record.get('candidate_id') or '-'}`",
                    f"`{record.get('stage')}`",
                    f"`{record.get('finish_reason')}`",
                    fmt_int(record.get("iterations")),
                    f"`{record.get('conversation_file')}`",
                ]
            )
        )
    if not main_finish_reason_records:
        lines.append(row(["-", "-", "-", "无", "-", "-"]))

    lines.extend(
        [
            "",
            "### 4.3 多轮离群主会话（Top 20）",
            "",
            "| # | Candidate | Stage | Iterations | Context Tokens | Conversation 文件 |",
            "|---:|---|---|---:|---:|---|",
        ]
    )
    for index, record in enumerate(conversations["multi_turn_outlier_records"][:20], 1):
        lines.append(
            row(
                [
                    index,
                    f"`{record.get('candidate_id') or '-'}`",
                    f"`{record.get('stage')}`",
                    fmt_int(record.get("iterations")),
                    fmt_int(record.get("context_tokens")),
                    f"`{record.get('conversation_file')}`",
                ]
            )
        )
    if not conversations["multi_turn_outlier_records"]:
        lines.append(row(["-", "-", "-", "-", "-", "无"]))

    lines.extend(["", "### 4.4 工具失败记录", ""])
    failure_records = conversations.get("failure_records_by_tool") or {}
    any_failure = False
    for tool_name in sorted(
        conversations["by_tool"],
        key=lambda name: (-int(conversations["by_tool"][name].get("calls") or 0), name),
    ):
        records = failure_records.get(tool_name) or []
        if not records:
            continue
        any_failure = True
        lines.extend(
            [
                f"#### `{tool_name}`（{len(records)} 条）",
                "",
                "| # | Candidate | Conversation 文件 | 调用参数 | 错误结果 |",
                "|---:|---|---|---|---|",
            ]
        )
        for index, record in enumerate(records, 1):
            arguments = json.dumps(record.get("arguments"), ensure_ascii=False, sort_keys=True)
            lines.append(
                row(
                    [
                        index,
                        f"`{record.get('candidate_id') or '-'}`",
                        f"`{record.get('conversation_file')}`",
                        f"`{markdown_cell(arguments)}`",
                        markdown_cell(record.get("error") or "-"),
                    ]
                )
            )
        lines.append("")
    if not any_failure:
        lines.append("本次运行没有工具失败记录。")

    # lines.extend(
    #     [
    #         "",
    #         "### 4.5 终态输出事件",
    #         "",
    #         "`emit_validation_result` 的 arguments 是最终结构化结果，不需要对应的 tool result。",
    #         "",
    #         "| # | 终态工具 | Candidate | Stage | Finish Reason | Payload 状态 | Conversation 文件 | 调用参数 |",
    #         "|---:|---|---|---|---|---|---|---|",
    #     ]
    # )
    # for index, record in enumerate(terminal_output.get("records") or [], 1):
    #     arguments = json.dumps(record.get("arguments"), ensure_ascii=False, sort_keys=True)
    #     lines.append(
    #         row(
    #             [
    #                 index,
    #                 f"`{record.get('tool')}`",
    #                 f"`{record.get('candidate_id') or '-'}`",
    #                 f"`{record.get('stage') or '-'}`",
    #                 f"`{record.get('finish_reason') or '-'}`",
    #                 "valid" if record.get("payload_valid") else "invalid",
    #                 f"`{record.get('conversation_file')}`",
    #                 f"`{markdown_cell(arguments)}`",
    #             ]
    #         )
    #     )
    # if not terminal_output.get("records"):
    #     lines.append(row(["-", "无", "-", "-", "-", "-", "-", "-"]))

    lines.extend(
        [
            "",
            "### 4.5 未完全召回或被 Needs Review 恢复的 CWE",
            "",
            "| CWE | Ground Truth | 默认 TP | 默认 Recall | Needs Review TP | Needs Review Recall | 恢复 TP |",
            "|---|---:|---:|---:|---:|---:|---:|",
        ]
    )
    for cwe in benchmark["cwe_rows"]:
        lines.append(
            row(
                [
                    cwe["cwe"],
                    fmt_int(cwe["sample_count"]),
                    fmt_int(cwe["default_true_positives"]),
                    fmt_pct(cwe["default_recall"]),
                    fmt_int(cwe["needs_review_true_positives"]),
                    fmt_pct(cwe["needs_review_recall"]),
                    fmt_int(
                        cwe["needs_review_true_positives"] - cwe["default_true_positives"]
                    ),
                ]
            )
        )

    # checks = data["integrity_checks"]
    # lines.extend(
    #     [
    #         "",
    #         "### 4.7 完整性检查",
    #         "",
    #         "| 检查项 | 结果 |",
    #         "|---|---:|",
    #     ]
    # )
    # for check, result in checks:
    #     lines.append(row([check, result]))
    # lines.extend(
    #     [
    #         "",
    #         "完整性结论：运行、validation queue、候选终态、conversation 会话和工具调用均已完成对账。",
    #     ]
    # )
    return "\n".join(lines) + "\n"


def generate(run_dir: Path, conversation_dir: Path) -> Dict[str, Any]:
    run_dir = run_dir.resolve()
    for name in REQUIRED_FILES:
        if not (run_dir / name).is_file():
            raise FileNotFoundError(f"required input not found: {run_dir / name}")
    run_summary = read_json(run_dir / "run_summary.json")
    report = read_json(run_dir / "zscope_batch_report.json")
    default_evaluation = read_json(run_dir / "evaluation.json")
    needs_evaluation = read_json(run_dir / "evaluation.with_needs_review.json")
    log = parse_log(run_dir / "zscope_run.log")
    build_cpg_timing = parse_build_cpg_timing(run_dir / "build_cpg.log")
    conversations = parse_conversations(conversation_dir)
    report_summary = report.get("summary") or {}
    performance = dict(report_summary.get("validation_performance") or {})
    queue = dict(report_summary.get("global_validation_queue") or {})
    llm_usage = dict(report_summary.get("llm_usage") or {})
    candidates = analyze_candidates(report)
    benchmark = analyze_benchmark(default_evaluation, needs_evaluation)
    stage_usage = analyze_stage_usage(log, conversations)
    main_sessions = int(conversations["stage_counts"].get("primary") or 0) + int(
        conversations["stage_counts"].get("full_tool_fallback") or 0
    )
    conversations["single_turn_main_session_count"] = main_sessions - len(
        conversations["multi_turn_outlier_records"]
    )
    models = [name for name, count in conversations["model_counts"].items() if count]
    inferred_model = models[0] if len(models) == 1 else ", ".join(sorted(models)) or "unknown"
    data: Dict[str, Any] = {
        "run": {
            "run_id": str(run_summary.get("run_id") or run_dir.name),
            "run_dir": str(run_dir),
            "conversation_dir": str(conversation_dir.resolve()),
            "scan_return_code": int(run_summary.get("scan_return_code") or 0),
            "scan_wall_seconds": float(run_summary.get("scan_wall_seconds") or 0),
            "build_cpg_timing": build_cpg_timing,
            "benchmark_valid": bool(run_summary.get("benchmark_valid")),
            "run_manifest_valid": bool(run_summary.get("run_manifest_valid")),
            "model_trace_valid": bool(run_summary.get("model_trace_valid")),
            "report_completeness": str(run_summary.get("report_completeness") or ""),
            "inferred_model": inferred_model,
        },
        "validation_performance": performance,
        "validation_queue": queue,
        "llm_usage": llm_usage,
        "candidates": candidates,
        "benchmark": benchmark,
        "log": log,
        "conversations": conversations,
        "stage_usage": stage_usage,
    }
    validate_inputs(run_summary, report, data)
    groups = int(queue.get("unique_group_count") or 0)
    terminal_total = sum(int(value) for value in candidates["terminal_counts"].values())
    tool_total = conversations["conversation"]
    data["integrity_checks"] = [
        ["Benchmark valid", "PASS" if run_summary.get("benchmark_valid") else "FAIL"],
        ["Run manifest valid", "PASS" if run_summary.get("run_manifest_valid") else "FAIL"],
        ["Model trace valid", "PASS" if run_summary.get("model_trace_valid") else "FAIL"],
        ["Report completeness", str(report.get("completeness") or "-")],
        [
            "Validation queue start/end",
            f"{fmt_int(log['counts'].get('validation_queue_start'))}/{fmt_int(log['counts'].get('validation_queue_end'))}",
        ],
        ["Validation queue drained", "PASS" if queue.get("drained") else "FAIL"],
        ["Group terminal-state conservation", f"{fmt_int(terminal_total)}/{fmt_int(groups)} PASS"],
        [
            "Validator main sessions",
            f"{fmt_int(main_sessions)}/{fmt_int(queue.get('validator_session_count'))} PASS",
        ],
        [
            "Tool call/result conservation",
            f"{fmt_int(tool_total.get('unique_tool_calls'))} = {fmt_int(tool_total.get('unique_tool_results'))} + {fmt_int(tool_total.get('unreturned_tool_calls'))} PASS",
        ],
        [
            "Terminal output events",
            f"{fmt_int(conversations['terminal_output'].get('valid_payloads'))}/{fmt_int(conversations['terminal_output'].get('calls'))} valid",
        ],
        [
            "Evaluation views",
            f"{default_evaluation.get('view') or '-'} / {needs_evaluation.get('view') or '-'}",
        ],
    ]
    return data


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("run_dir", type=Path)
    parser.add_argument("--conversation-dir", type=Path)
    parser.add_argument("--model")
    parser.add_argument("--json-output", type=Path)
    parser.add_argument("--markdown-output", type=Path)
    args = parser.parse_args()

    run_dir = args.run_dir.resolve()
    conversation_dir = infer_conversation_dir(run_dir, args.conversation_dir)
    data = generate(run_dir, conversation_dir)
    model = args.model or data["run"]["inferred_model"]
    json_output = args.json_output or (run_dir / "validation_efficiency_metrics.json")
    markdown_output = args.markdown_output or (run_dir / "validation_metrics.md")
    json_output.write_text(
        json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    markdown_output.write_text(render_markdown(data, model), encoding="utf-8")
    print(markdown_output)


if __name__ == "__main__":
    main()
