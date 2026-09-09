#!/usr/bin/env python3
"""Render a table-oriented Markdown summary for a completed Z-SCOPE trial."""

from __future__ import annotations

import argparse
import json
import os
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_ARTIFACT_ROOT = REPO_ROOT / "benchmark-artifacts"
REQUIRED_RUN_FILES = ("summary.json", "score.json", "report.json")


class TrialMetricsError(RuntimeError):
    """Raised when a trial cannot be rendered safely."""


@dataclass(frozen=True)
class TrialPaths:
    trial_dir: Path
    run_dir: Path


@dataclass
class ToolCallRecord:
    session_id: str
    tool_call_id: str
    tool_name: str
    normalized_args: str
    args_error: bool
    final_response: bool
    conversation_file: str


@dataclass
class ToolResultRecord:
    session_id: str
    tool_call_id: str
    content: Any


def _as_dict(value: Any) -> Dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _as_list(value: Any) -> List[Any]:
    return value if isinstance(value, list) else []


def _read_json(path: Path, *, required: bool = True) -> Dict[str, Any]:
    if not path.is_file():
        if required:
            raise TrialMetricsError(f"required JSON file does not exist: {path}")
        return {}
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise TrialMetricsError(f"failed to read JSON object {path}: {exc}") from exc
    if not isinstance(payload, dict):
        raise TrialMetricsError(f"JSON root must be an object: {path}")
    return payload


def _run_is_complete(run_dir: Path) -> bool:
    if not all((run_dir / name).is_file() for name in REQUIRED_RUN_FILES):
        return False
    try:
        summary = _read_json(run_dir / "summary.json")
    except TrialMetricsError:
        return False
    return summary.get("completed") is True


def _require_complete_run(run_dir: Path) -> None:
    missing = [name for name in REQUIRED_RUN_FILES if not (run_dir / name).is_file()]
    if missing:
        raise TrialMetricsError(
            f"trial run is missing required artifacts under {run_dir}: {', '.join(missing)}"
        )
    summary = _read_json(run_dir / "summary.json")
    if summary.get("completed") is not True:
        raise TrialMetricsError(f"trial run is incomplete: {run_dir}")


def resolve_trial_paths(
    trial_path: Optional[Path],
    *,
    language: str = "c_cpp",
    artifact_root: Path = DEFAULT_ARTIFACT_ROOT,
) -> TrialPaths:
    """Resolve an explicit trial/run path or select the newest completed trial."""

    if trial_path is not None:
        candidate = trial_path.expanduser().resolve()
        if candidate.name.startswith("run-"):
            run_dir = candidate
            trial_dir = candidate.parent
        elif (candidate / "summary.json").is_file():
            run_dir = candidate
            trial_dir = candidate.parent
        else:
            trial_dir = candidate
            run_dir = candidate / "run-01"
        if not trial_dir.is_dir():
            raise TrialMetricsError(f"trial directory does not exist: {trial_dir}")
        _require_complete_run(run_dir)
        return TrialPaths(trial_dir=trial_dir, run_dir=run_dir)

    trial_root = artifact_root / language / "trial"
    if not trial_root.is_dir():
        raise TrialMetricsError(f"trial artifact root does not exist: {trial_root}")
    candidates = sorted(
        (path for path in trial_root.iterdir() if path.is_dir()),
        key=lambda path: path.name,
        reverse=True,
    )
    for candidate in candidates:
        run_dir = candidate / "run-01"
        if _run_is_complete(run_dir):
            return TrialPaths(trial_dir=candidate, run_dir=run_dir)
    raise TrialMetricsError(f"no completed {language} trial found under {trial_root}")


def _read_jsonl(path: Path) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise TrialMetricsError(f"failed to read JSONL file {path}: {exc}") from exc
    for line_number, line in enumerate(lines, 1):
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError as exc:
            raise TrialMetricsError(
                f"invalid JSONL in {path} at line {line_number}: {exc}"
            ) from exc
        if not isinstance(row, dict):
            raise TrialMetricsError(f"JSONL row must be an object: {path}:{line_number}")
        rows.append(row)
    return rows


def _normalize_tool_args(value: Any) -> Tuple[str, bool]:
    if value is None or value == "":
        parsed: Any = {}
    elif isinstance(value, str):
        try:
            parsed = json.loads(value)
        except json.JSONDecodeError:
            return "!invalid:" + value.strip(), True
    else:
        parsed = value
    try:
        return json.dumps(parsed, ensure_ascii=False, sort_keys=True, separators=(",", ":")), False
    except (TypeError, ValueError):
        return "!invalid:" + str(value), True


def _session_id(event: Mapping[str, Any], path: Path) -> str:
    session = _as_dict(event.get("session"))
    return str(session.get("id") or path.stem)


def _tool_name(tool_call: Mapping[str, Any]) -> str:
    function = _as_dict(tool_call.get("function"))
    return str(function.get("name") or tool_call.get("name") or "unknown")


def _tool_arguments(tool_call: Mapping[str, Any]) -> Any:
    function = _as_dict(tool_call.get("function"))
    return function.get("arguments", tool_call.get("arguments"))


def _extract_calls_and_results(
    *,
    path: Path,
    session_id: str,
    exchange: Mapping[str, Any],
) -> Tuple[List[ToolCallRecord], List[ToolResultRecord]]:
    calls: List[ToolCallRecord] = []
    results: List[ToolResultRecord] = []
    message_sets: List[Tuple[Mapping[str, Any], bool]] = [
        (message, False)
        for message in _as_list(exchange.get("request_messages"))
        if isinstance(message, dict)
    ]
    response = exchange.get("response_message")
    if isinstance(response, dict):
        message_sets.append((response, True))
    for message, final_response in message_sets:
        for raw_call in _as_list(message.get("tool_calls")):
            if not isinstance(raw_call, dict):
                continue
            tool_call_id = str(raw_call.get("id") or "").strip()
            if not tool_call_id:
                continue
            normalized_args, args_error = _normalize_tool_args(_tool_arguments(raw_call))
            calls.append(
                ToolCallRecord(
                    session_id=session_id,
                    tool_call_id=tool_call_id,
                    tool_name=_tool_name(raw_call),
                    normalized_args=normalized_args,
                    args_error=args_error,
                    final_response=final_response,
                    conversation_file=path.name,
                )
            )
        tool_call_id = str(message.get("tool_call_id") or "").strip()
        if message.get("role") == "tool" or tool_call_id:
            if tool_call_id:
                results.append(
                    ToolResultRecord(
                        session_id=session_id,
                        tool_call_id=tool_call_id,
                        content=message.get("content"),
                    )
                )
    return calls, results


def _result_payload(content: Any) -> Tuple[Any, bool]:
    if isinstance(content, (dict, list)):
        return content, True
    if isinstance(content, str):
        try:
            return json.loads(content), True
        except json.JSONDecodeError:
            return content, False
    return content, False


def _result_error(payload: Any) -> str:
    if not isinstance(payload, dict):
        return ""
    if payload.get("error"):
        return str(payload["error"])
    summary = _as_dict(payload.get("summary"))
    return str(summary.get("error") or "")


def _result_status(payload: Any, parsed: bool) -> str:
    if not parsed or not isinstance(payload, dict):
        return "unknown"
    if isinstance(payload.get("success"), bool):
        return "success" if payload["success"] else "failure"
    summary = _as_dict(payload.get("summary"))
    if isinstance(summary.get("success"), bool):
        return "success" if summary["success"] else "failure"
    if _result_error(payload):
        return "failure"
    return "unknown"


def _result_is_empty(payload: Any, status: str) -> bool:
    if status != "success" or not isinstance(payload, dict):
        return False
    if "data" in payload:
        value = payload.get("data")
    else:
        summary = _as_dict(payload.get("summary"))
        if "data" not in summary:
            return False
        value = summary.get("data")
    return value is None or value == "" or value == [] or value == {}


def _error_class(error: str) -> str:
    text = error.strip().lower()
    if not text:
        return "other"
    if "loop guard" in text or "repeated identical tool call" in text:
        return "loop_guard"
    if "blocked by policy" in text or "sensitive path" in text or "policy denied" in text:
        return "policy"
    parameter_markers = (
        "not found",
        "does not exist",
        "no such file",
        "existing file path",
        "out of range",
        "invalid path",
        "unknown function",
        "unknown type",
    )
    if any(marker in text for marker in parameter_markers):
        return "parameter"
    format_markers = (
        "invalid json",
        "not parseable json",
        "schema",
        "missing required",
        "required field",
        "argument format",
        "type error",
    )
    if any(marker in text for marker in format_markers):
        return "format"
    return "other"


def analyze_conversations(conversations_dir: Path) -> Dict[str, Any]:
    """Extract session and per-tool metrics without retaining conversation bodies."""

    if not conversations_dir.is_dir():
        return {"present": False, "sessions": [], "by_agent": {}, "tools": {}, "coverage": {}}
    jsonl_files = sorted(conversations_dir.rglob("*.jsonl"))
    calls: Dict[Tuple[str, str], ToolCallRecord] = {}
    results: Dict[Tuple[str, str], ToolResultRecord] = {}
    sessions: List[Dict[str, Any]] = []
    duplicate_call_records = 0
    duplicate_result_records = 0
    for path in jsonl_files:
        events = _read_jsonl(path)
        start = next((row for row in events if row.get("event") == "session_start"), {})
        exchange = next((row for row in events if row.get("event") == "exchange"), {})
        end = next((row for row in events if row.get("event") == "session_end"), {})
        session_id = _session_id(start or exchange or end, path)
        relative_parent = path.parent.relative_to(conversations_dir).as_posix()
        session_scope = f"{relative_parent}/{session_id}"
        session_data = _as_dict((start or exchange or end).get("session"))
        sessions.append(
            {
                "session_id": session_id,
                "agent": str(session_data.get("agent_name") or "unknown"),
                "label": str(session_data.get("label") or ""),
                "iterations": int(end.get("iterations") or exchange.get("total_iterations") or 0),
                "context_tokens": int(end.get("context_tokens") or 0),
                "truncated": bool(end.get("truncated")),
                "finish_reason": str(exchange.get("finish_reason") or "unknown"),
                "ended": bool(end),
                "file": path.relative_to(conversations_dir).as_posix(),
            }
        )
        extracted_calls, extracted_results = _extract_calls_and_results(
            path=path,
            session_id=session_scope,
            exchange=exchange,
        )
        for call in extracted_calls:
            key = (call.session_id, call.tool_call_id)
            existing = calls.get(key)
            if existing is not None:
                duplicate_call_records += 1
                if call.final_response and not existing.final_response:
                    existing.final_response = True
                continue
            calls[key] = call
        for result in extracted_results:
            key = (result.session_id, result.tool_call_id)
            if key in results:
                duplicate_result_records += 1
                continue
            results[key] = result

    repeated_args: set[Tuple[str, str]] = set()
    seen_args: set[Tuple[str, str, str]] = set()
    for key, call in calls.items():
        identity = (call.session_id, call.tool_name, call.normalized_args)
        if identity in seen_args:
            repeated_args.add(key)
        else:
            seen_args.add(identity)

    tool_stats: Dict[str, Counter[str]] = defaultdict(Counter)
    for key, call in calls.items():
        bucket = tool_stats[call.tool_name]
        bucket["calls"] += 1
        bucket["argument_errors"] += int(call.args_error)
        bucket["repeated_arguments"] += int(key in repeated_args)
        bucket["final_response_calls"] += int(call.final_response)
        matched_result = results.get(key)
        if matched_result is None:
            bucket["unreturned"] += 1
            continue
        bucket["results"] += 1
        payload, parsed = _result_payload(matched_result.content)
        status = _result_status(payload, parsed)
        bucket[status] += 1
        bucket["non_json_results"] += int(not parsed)
        bucket["empty_results"] += int(_result_is_empty(payload, status))
        if status == "failure":
            bucket["error_" + _error_class(_result_error(payload))] += 1

    by_agent: Dict[str, Counter[str]] = defaultdict(Counter)
    finish_reasons: Counter[str] = Counter()
    for session in sessions:
        bucket = by_agent[session["agent"]]
        bucket["sessions"] += 1
        bucket["ended"] += int(session["ended"])
        bucket["truncated"] += int(session["truncated"])
        bucket["iterations"] += int(session["iterations"])
        bucket["context_tokens"] += int(session["context_tokens"])
        bucket["max_iterations"] = max(bucket["max_iterations"], int(session["iterations"]))
        bucket["max_context_tokens"] = max(
            bucket["max_context_tokens"], int(session["context_tokens"])
        )
        finish_reasons[session["finish_reason"]] += 1

    call_keys = set(calls)
    result_keys = set(results)
    return {
        "present": True,
        "file_count": len(jsonl_files),
        "sessions": sessions,
        "by_agent": {key: dict(value) for key, value in sorted(by_agent.items())},
        "finish_reasons": dict(sorted(finish_reasons.items())),
        "tools": {key: dict(value) for key, value in sorted(tool_stats.items())},
        "coverage": {
            "unique_calls": len(call_keys),
            "unique_results": len(result_keys),
            "paired": len(call_keys & result_keys),
            "calls_without_result": len(call_keys - result_keys),
            "results_without_call": len(result_keys - call_keys),
            "duplicate_call_records": duplicate_call_records,
            "duplicate_result_records": duplicate_result_records,
        },
    }


def analyze_usage_events(path: Path) -> Dict[str, Any]:
    if not path.is_file():
        return {"present": False, "by_model": {}, "by_outcome": {}}
    rows = _read_jsonl(path)
    by_model: Counter[str] = Counter()
    by_outcome: Counter[str] = Counter()
    for row in rows:
        by_model[str(row.get("model") or "unknown")] += 1
        by_outcome[str(row.get("outcome") or "unknown")] += 1
    return {
        "present": True,
        "call_count": len(rows),
        "by_model": dict(sorted(by_model.items())),
        "by_outcome": dict(sorted(by_outcome.items())),
    }


def _escape(value: Any, *, limit: int = 180) -> str:
    if value is None or value == "":
        return "不适用"
    if isinstance(value, bool):
        text = "是" if value else "否"
    elif isinstance(value, (dict, list)):
        text = json.dumps(value, ensure_ascii=False, sort_keys=True)
    else:
        text = str(value)
    text = text.replace("\r", " ").replace("\n", "<br>").replace("|", "\\|")
    return text if len(text) <= limit else text[: limit - 3] + "..."


def _integer(value: Any) -> str:
    if value is None or isinstance(value, bool):
        return "不适用"
    try:
        return f"{int(value):,}"
    except (TypeError, ValueError):
        return _escape(value)


def _count(value: Any) -> str:
    if isinstance(value, (list, tuple, set)):
        return _integer(len(value))
    if isinstance(value, dict) and isinstance(value.get("count"), (int, float)):
        return _integer(value["count"])
    return _integer(value)


def _decimal(value: Any, digits: int = 2) -> str:
    if value is None or isinstance(value, bool):
        return "不适用"
    try:
        return f"{float(value):,.{digits}f}"
    except (TypeError, ValueError):
        return _escape(value)


def _percent(value: Any) -> str:
    if value is None or isinstance(value, bool):
        return "不适用"
    try:
        return f"{float(value) * 100:.2f}%"
    except (TypeError, ValueError):
        return _escape(value)


def _duration(value: Any) -> str:
    if value is None or isinstance(value, bool):
        return "不适用"
    try:
        seconds = float(value)
    except (TypeError, ValueError):
        return _escape(value)
    if seconds >= 3600:
        return f"{seconds:,.2f}s ({seconds / 3600:.2f}h)"
    if seconds >= 60:
        return f"{seconds:,.2f}s ({seconds / 60:.2f}m)"
    return f"{seconds:,.2f}s"


def _table(
    headers: Sequence[str], rows: Iterable[Sequence[Any]], *, right: Iterable[int] = ()
) -> str:
    right_set = set(right)
    lines = ["| " + " | ".join(headers) + " |"]
    lines.append(
        "|"
        + "|".join("---:" if index in right_set else "---" for index in range(len(headers)))
        + "|"
    )
    observed = False
    for row in rows:
        observed = True
        values = list(row)
        if len(values) != len(headers):
            raise TrialMetricsError("Markdown table row does not match header width")
        lines.append("| " + " | ".join(_escape(value) for value in values) + " |")
    if not observed:
        lines.append("| " + " | ".join(["不适用"] + [""] * (len(headers) - 1)) + " |")
    return "\n".join(lines)


def _view(score: Mapping[str, Any], name: str) -> Dict[str, Any]:
    views = _as_dict(score.get("report_views"))
    aliases = [name]
    if name == "with_needs_review":
        aliases.append("with_review")
    for alias in aliases:
        value = views.get(alias)
        if isinstance(value, dict):
            return value
    if name == "default":
        return dict(score)
    return {}


def _quality_rows(score: Mapping[str, Any]) -> List[List[str]]:
    rows: List[List[str]] = []
    for label, name in (("默认视图", "default"), ("含复核视图", "with_needs_review")):
        view = _view(score, name)
        rows.append(
            [
                label,
                _integer(view.get("report_issue_count")),
                _integer(view.get("ground_truth_count")),
                _integer(view.get("true_positives")),
                _integer(view.get("false_positives_raw")),
                _integer(view.get("false_positives_effective")),
                _integer(view.get("duplicate_of_matched_count")),
                _integer(view.get("false_negatives")),
                _percent(view.get("recall")),
                _percent(view.get("actionable_precision")),
                _percent(view.get("actionable_f1")),
                _percent(view.get("actionable_false_discovery_rate")),
                _percent(view.get("root_cause_precision")),
            ]
        )
    return rows


def _severity_rows(report: Mapping[str, Any]) -> List[List[str]]:
    default = _as_dict(report.get("issues_by_severity"))
    review = _as_dict(report.get("issues_by_severity_with_needs_review"))
    labels = {"critical": "严重", "high": "高", "medium": "中", "low": "低"}
    return [
        [labels[severity], _count(default.get(severity)), _count(review.get(severity))]
        for severity in ("critical", "high", "medium", "low")
    ]


def _attribution_rows(attribution: Mapping[str, Any], key: str) -> List[List[str]]:
    rows = []
    for name, value in sorted(_as_dict(attribution.get(key)).items()):
        bucket = _as_dict(value)
        rows.append(
            [
                name,
                _integer(bucket.get("issues")),
                _integer(bucket.get("true_positives")),
                _integer(bucket.get("raw_false_positives")),
            ]
        )
    return rows


def _record_value(record: Mapping[str, Any], *names: str) -> Any:
    for name in names:
        value = record.get(name)
        if value not in (None, ""):
            return value
    return None


def _false_positive_rows(records: Sequence[Any], top: int) -> List[List[str]]:
    rows = []
    for raw in records[:top]:
        record = _as_dict(raw)
        rows.append(
            [
                _record_value(record, "candidate_id", "id", "stable_fingerprint"),
                _record_value(record, "category", "defect_class", "type"),
                _record_value(record, "file", "file_path"),
                _record_value(record, "function", "entry_function"),
                _record_value(record, "location", "line"),
            ]
        )
    return rows


def _cwe_rows(score: Mapping[str, Any]) -> List[Tuple[str, Dict[str, Any]]]:
    rows = [
        (name, _as_dict(value)) for name, value in _as_dict(score.get("per_cwe_recall")).items()
    ]
    return sorted(
        rows,
        key=lambda item: (
            float(item[1].get("recall") or 0),
            -int(item[1].get("sample_count") or 0),
            item[0],
        ),
    )


def _render_report(
    *,
    paths: TrialPaths,
    summary: Mapping[str, Any],
    score: Mapping[str, Any],
    report: Mapping[str, Any],
    aggregate: Mapping[str, Any],
    tool_health: Mapping[str, Any],
    usage_events: Mapping[str, Any],
    conversations: Mapping[str, Any],
    top: int,
) -> str:
    lines: List[str] = ["# 试运行验证指标", ""]
    provenance = _as_dict(summary.get("provenance"))
    models = ", ".join(_as_dict(usage_events.get("by_model"))) or "不适用"
    metadata_rows: List[List[Any]] = [
        ["试运行标识", paths.trial_dir.name],
        ["运行轮次", paths.run_dir.name],
        ["语言", aggregate.get("language") or summary.get("language")],
        ["模式", aggregate.get("mode") or summary.get("mode")],
        ["扫描深度", aggregate.get("scan_depth") or summary.get("scan_depth")],
        ["模型", models],
        ["Git 提交 SHA", aggregate.get("git_sha")],
        ["运行完成", summary.get("completed")],
        ["验证队列清空", summary.get("queue_empty")],
        ["具备发布资格", summary.get("release_eligible")],
        ["RuntimeSpec SHA-256", provenance.get("runtime_spec_sha256")],
        ["规则目录 SHA-256", provenance.get("rule_catalog_sha256")],
    ]
    lines.extend(["## 1. 运行概览", "", _table(["字段", "值"], metadata_rows), ""])

    lines.extend(
        [
            "## 2. 验证质量",
            "",
            _table(
                [
                    "视图",
                    "报告问题数",
                    "基准真值数",
                    "TP",
                    "原始 FP",
                    "有效 FP",
                    "已匹配重复项",
                    "FN",
                    "召回率",
                    "可处置精确率",
                    "可处置 F1",
                    "可处置 FDR",
                    "根因精确率",
                ],
                _quality_rows(score),
                right=range(1, 13),
            ),
            "",
        ]
    )
    high_rows = []
    for label, name in (("默认视图", "default"), ("含复核视图", "with_needs_review")):
        view = _view(score, name)
        high_rows.append(
            [
                label,
                _integer(view.get("high_critical_sample_count")),
                _integer(view.get("high_critical_true_positives")),
                _percent(view.get("high_critical_recall")),
            ]
        )
    lines.extend(
        [
            "### 严重度与高危问题覆盖",
            "",
            _table(
                ["严重度", "默认视图", "含复核视图"],
                _severity_rows(report),
                right=(1, 2),
            ),
            "",
            _table(
                ["视图", "高危/严重样本数", "TP", "召回率"],
                high_rows,
                right=(1, 2, 3),
            ),
            "",
        ]
    )

    funnel = _as_dict(score.get("candidate_funnel"))
    funnel_rows = [
        [
            name,
            _integer(_as_dict(value).get("count")),
            _as_dict(value).get("unit"),
            _as_dict(value).get("source"),
        ]
        for name, value in _as_dict(funnel.get("stages")).items()
    ]
    group_attr = _as_dict(funnel.get("canonical_group_attribution"))
    transition_rows = [
        [name, _integer(value)]
        for name, value in _as_dict(group_attr.get("transition_counts")).items()
    ]
    lines.extend(
        [
            "## 3. 候选漏斗与归因",
            "",
            "> 各阶段保留其声明的计数单位；occurrence、candidate、validation-group 与 finding 不能直接相除，因此不生成虚假的跨单位转化率。",
            "",
            _table(["阶段", "数量", "单位", "数据来源"], funnel_rows, right=(1,)),
            "",
            "### 验证状态转移",
            "",
            _table(["状态转移", "数量"], transition_rows, right=(1,)),
            "",
        ]
    )
    attribution = _as_dict(score.get("attribution"))
    for title, key in (
        ("按发现来源", "by_discovery"),
        ("按决策方式", "by_decision"),
        ("按决策层级", "by_decision_level"),
    ):
        lines.extend(
            [
                f"### {title}",
                "",
                _table(
                    ["来源 / 决策", "问题数", "TP", "原始 FP"],
                    _attribution_rows(attribution, key),
                    right=(1, 2, 3),
                ),
                "",
            ]
        )

    phase_rows = [
        [name, _duration(value)] for name, value in _as_dict(summary.get("phase_seconds")).items()
    ]
    telemetry = _as_dict(score.get("performance_telemetry"))
    telemetry_rows = [
        [name, _duration(value) if "seconds" in name else _integer(value)]
        for name, value in telemetry.items()
    ]
    lines.extend(
        [
            "## 4. 性能与 LLM 成本",
            "",
            "### 阶段耗时",
            "",
            _table(["阶段", "耗时"], phase_rows, right=(1,)),
            "",
            "### 运行时遥测",
            "",
            _table(["指标", "值"], telemetry_rows, right=(1,)),
            "",
        ]
    )
    usage = _as_dict(score.get("usage_accounting"))
    totals = _as_dict(usage.get("totals"))
    token_headers = [
        "统计范围",
        "Prompt Token",
        "缓存 Prompt Token",
        "Completion Token",
        "Reasoning Token",
        "总 Token",
        "工具调用数",
        "新增事实数",
    ]
    token_rows = [
        [
            "总计",
            _integer(totals.get("prompt_tokens")),
            _integer(totals.get("cached_prompt_tokens")),
            _integer(totals.get("completion_tokens")),
            _integer(totals.get("reasoning_tokens")),
            _integer(totals.get("total_tokens")),
            _integer(totals.get("tool_call_count")),
            _integer(totals.get("new_fact_count")),
        ]
    ]
    for prefix, key in (("智能体", "by_agent"), ("阶段", "by_stage")):
        for name, raw in sorted(_as_dict(usage.get(key)).items()):
            bucket = _as_dict(raw)
            token_rows.append(
                [
                    f"{prefix}: {name}",
                    _integer(bucket.get("prompt_tokens")),
                    _integer(bucket.get("cached_prompt_tokens")),
                    _integer(bucket.get("completion_tokens")),
                    _integer(bucket.get("reasoning_tokens")),
                    _integer(bucket.get("total_tokens")),
                    _integer(bucket.get("tool_call_count")),
                    _integer(bucket.get("new_fact_count")),
                ]
            )
    lines.extend(
        [
            "### Token 计量",
            "",
            _table(token_headers, token_rows, right=range(1, 8)),
            "",
            _table(
                ["结束原因", "调用次数"],
                [
                    [name, _integer(value)]
                    for name, value in _as_dict(usage.get("finish_reasons")).items()
                ],
                right=(1,),
            ),
            "",
            "### LLM 使用事件的模型与结果",
            "",
            _table(
                ["维度", "值", "调用次数"],
                [
                    ["模型", name, _integer(value)]
                    for name, value in _as_dict(usage_events.get("by_model")).items()
                ]
                + [
                    ["调用结果", name, _integer(value)]
                    for name, value in _as_dict(usage_events.get("by_outcome")).items()
                ],
                right=(2,),
            ),
            "",
        ]
    )

    lines.extend(["## 5. 会话与工具质量", ""])
    coverage = _as_dict(conversations.get("coverage"))
    coverage_rows = [[name, _integer(value)] for name, value in coverage.items()]
    lines.extend([_table(["会话覆盖指标", "数量"], coverage_rows, right=(1,)), ""])
    tool_rows = []
    for name, raw in sorted(_as_dict(conversations.get("tools")).items()):
        bucket = Counter(_as_dict(raw))
        tool_rows.append(
            [
                f"`{name}`",
                _integer(bucket["calls"]),
                _integer(bucket["results"]),
                _integer(bucket["success"]),
                _integer(bucket["failure"]),
                _integer(bucket["unknown"]),
                _integer(bucket["argument_errors"]),
                _integer(bucket["empty_results"]),
                _integer(bucket["repeated_arguments"]),
                _integer(bucket["error_loop_guard"]),
                _integer(bucket["final_response_calls"]),
                _integer(bucket["unreturned"]),
            ]
        )
    lines.extend(
        [
            _table(
                [
                    "工具",
                    "调用数",
                    "结果数",
                    "明确成功",
                    "明确失败",
                    "未知结果",
                    "参数 JSON 错误",
                    "空结果",
                    "重复参数",
                    "Loop Guard",
                    "最终响应调用",
                    "未返回",
                ],
                tool_rows,
                right=range(1, 12),
            ),
            "",
        ]
    )
    error_rows = []
    for name, raw in sorted(_as_dict(conversations.get("tools")).items()):
        bucket = Counter(_as_dict(raw))
        error_rows.append(
            [
                f"`{name}`",
                _integer(bucket["error_parameter"]),
                _integer(bucket["error_format"]),
                _integer(bucket["error_policy"]),
                _integer(bucket["error_loop_guard"]),
                _integer(bucket["error_other"]),
                _integer(bucket["non_json_results"]),
            ]
        )
    lines.extend(
        [
            "### 工具错误分类",
            "",
            _table(
                [
                    "工具",
                    "参数错误",
                    "格式错误",
                    "策略拒绝",
                    "Loop Guard",
                    "其他错误",
                    "非 JSON 结果",
                ],
                error_rows,
                right=range(1, 7),
            ),
            "",
        ]
    )
    agent_rows = []
    for agent, raw in sorted(_as_dict(conversations.get("by_agent")).items()):
        bucket = Counter(_as_dict(raw))
        sessions = bucket["sessions"]
        agent_rows.append(
            [
                agent,
                _integer(sessions),
                _integer(bucket["ended"]),
                _integer(bucket["truncated"]),
                _decimal(bucket["iterations"] / sessions if sessions else None),
                _integer(bucket["max_iterations"]),
                _decimal(bucket["context_tokens"] / sessions if sessions else None),
                _integer(bucket["max_context_tokens"]),
            ]
        )
    lines.extend(
        [
            "### 按智能体统计会话",
            "",
            _table(
                [
                    "智能体",
                    "会话数",
                    "正常结束",
                    "被截断",
                    "平均迭代数",
                    "最大迭代数",
                    "平均上下文 Token",
                    "最大上下文 Token",
                ],
                agent_rows,
                right=range(1, 8),
            ),
            "",
        ]
    )

    completeness_rows = [
        [name, value] for name, value in sorted(_as_dict(summary.get("completeness")).items())
    ]
    completeness_rows.extend(
        [
            ["usage_present", usage.get("present")],
            ["usage_complete", usage.get("complete")],
            ["token_conservation_passed", usage.get("conservation_passed")],
            ["provider_usage_coverage", _percent(usage.get("provider_usage_coverage"))],
            ["tool_health_ok", tool_health.get("ok")],
        ]
    )
    gate_failures = _as_list(summary.get("gate_failures"))
    sealed_failures = _as_list(summary.get("sealed_gate_failures"))
    lines.extend(
        [
            "## 6. 完整性与门禁",
            "",
            _table(["检查项", "值"], completeness_rows),
            "",
            _table(
                ["门禁", "失败原因"],
                [["Range 门禁", value] for value in gate_failures]
                + [["Sealed 门禁", value] for value in sealed_failures],
            ),
            "",
        ]
    )

    cwes = _cwe_rows(score)
    weak = [(name, data) for name, data in cwes if int(data.get("sample_count") or 0) >= 2][:top]
    lines.extend(
        [
            "## 7. 诊断附录",
            "",
            f"### 最低召回 CWE（前 {top} 项，样本数 >= 2）",
            "",
            _table(
                ["CWE", "样本数", "TP", "召回率"],
                [
                    [
                        name,
                        _integer(data.get("sample_count")),
                        _integer(data.get("true_positives")),
                        _percent(data.get("recall")),
                    ]
                    for name, data in weak
                ],
                right=(1, 2, 3),
            ),
            "",
            "### 全部 CWE 召回率",
            "",
            _table(
                ["CWE", "样本数", "TP", "召回率"],
                [
                    [
                        name,
                        _integer(data.get("sample_count")),
                        _integer(data.get("true_positives")),
                        _percent(data.get("recall")),
                    ]
                    for name, data in cwes
                ],
                right=(1, 2, 3),
            ),
            "",
        ]
    )
    function_results = sorted(
        (_as_dict(row) for row in _as_list(report.get("function_results"))),
        key=lambda row: float(row.get("duration_seconds") or 0),
        reverse=True,
    )[:top]
    lines.extend(
        [
            f"### 最慢入口（前 {top} 项）",
            "",
            _table(
                ["函数", "文件", "耗时", "终态", "问题数", "上下文 Token", "错误"],
                [
                    [
                        row.get("function"),
                        row.get("entry_file_path"),
                        _duration(row.get("duration_seconds")),
                        row.get("verdict"),
                        _integer(row.get("issue_count")),
                        _integer(row.get("context_tokens")),
                        row.get("error"),
                    ]
                    for row in function_results
                ],
                right=(2, 4, 5),
            ),
            "",
        ]
    )
    fp_audit = _as_dict(score.get("false_positive_audit"))
    for title, key in (
        ("有效误报", "effective_records"),
        ("已匹配问题的重复报告", "duplicate_of_matched_records"),
    ):
        lines.extend(
            [
                f"### {title}（前 {top} 项）",
                "",
                _table(
                    ["候选", "类别", "文件", "函数", "位置"],
                    _false_positive_rows(_as_list(fp_audit.get(key)), top),
                ),
                "",
            ]
        )
    missed = _as_list(score.get("missed"))
    lines.extend(
        [
            f"### 漏检真值 ID（共 {len(missed)} 条，显示前 {top} 条）",
            "",
            _table(
                ["序号", "Truth ID"],
                [[index, value] for index, value in enumerate(missed[:top], 1)],
                right=(0,),
            ),
            "",
        ]
    )
    diagnostics = _as_dict(score.get("match_diagnostics"))
    diagnostic_rows = [
        [name, value]
        for name, value in sorted(diagnostics.items())
        if not isinstance(value, (list, dict))
    ]
    lines.extend(
        [
            "### 匹配诊断",
            "",
            _table(["指标", "值"], diagnostic_rows),
            "",
        ]
    )
    outlier_sessions = sorted(
        (_as_dict(row) for row in _as_list(conversations.get("sessions"))),
        key=lambda row: (int(row.get("iterations") or 0), int(row.get("context_tokens") or 0)),
        reverse=True,
    )[:top]
    lines.extend(
        [
            f"### 会话离群项（前 {top} 项）",
            "",
            _table(
                ["智能体", "迭代数", "上下文 Token", "结束原因", "被截断", "文件"],
                [
                    [
                        row.get("agent"),
                        _integer(row.get("iterations")),
                        _integer(row.get("context_tokens")),
                        row.get("finish_reason"),
                        row.get("truncated"),
                        row.get("file"),
                    ]
                    for row in outlier_sessions
                ],
                right=(1, 2),
            ),
            "",
            "> 会话统计只使用 tool-call ID 和结构化元数据；本报告不会复制 Prompt、模型响应、reasoning 或工具结果正文。",
            "",
        ]
    )
    return "\n".join(lines).rstrip() + "\n"


def render_trial_metrics(
    trial_path: Optional[Path] = None,
    *,
    language: str = "c_cpp",
    top: int = 15,
    artifact_root: Path = DEFAULT_ARTIFACT_ROOT,
) -> Tuple[TrialPaths, str]:
    if top <= 0:
        raise TrialMetricsError("--top must be a positive integer")
    paths = resolve_trial_paths(trial_path, language=language, artifact_root=artifact_root)
    summary = _read_json(paths.run_dir / "summary.json")
    if summary.get("completed") is not True:
        raise TrialMetricsError(f"trial is not complete: {paths.run_dir}")
    score = _read_json(paths.run_dir / "score.json")
    report = _read_json(paths.run_dir / "report.json")
    aggregate = _read_json(paths.trial_dir / "aggregate.json", required=False)
    tool_health = _read_json(paths.run_dir / "tool-health.json", required=False)
    usage_events = analyze_usage_events(paths.run_dir / "llm_usage_events.jsonl")
    conversation_paths = (
        paths.run_dir / "conversations",
        paths.run_dir / "scan-extras" / ".zscope_conversations",
    )
    conversations = next(
        (analyze_conversations(path) for path in conversation_paths if path.is_dir()),
        analyze_conversations(paths.run_dir / "conversations"),
    )
    markdown = _render_report(
        paths=paths,
        summary=summary,
        score=score,
        report=report,
        aggregate=aggregate,
        tool_health=tool_health,
        usage_events=usage_events,
        conversations=conversations,
        top=top,
    )
    return paths, markdown


def _atomic_write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    try:
        temporary.write_text(text, encoding="utf-8")
        temporary.replace(path)
    finally:
        if temporary.exists():
            temporary.unlink()


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("trial_path", nargs="?", type=Path)
    parser.add_argument("--language", choices=("c_cpp", "java"), default="c_cpp")
    parser.add_argument("--top", type=int, default=15)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)
    try:
        paths, markdown = render_trial_metrics(
            args.trial_path,
            language=args.language,
            top=args.top,
        )
        output = (
            args.output.expanduser().resolve()
            if args.output
            else paths.run_dir / "validation_metrics.md"
        )
        _atomic_write(output, markdown)
    except TrialMetricsError as exc:
        parser.error(str(exc))
    print(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
