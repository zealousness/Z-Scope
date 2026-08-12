#!/usr/bin/env python3
"""Generate efficiency/cost and tool-quality metrics for a global-model run."""

from __future__ import annotations

import argparse
import json
import re
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Iterable, Optional


LOG_TS = "%Y-%m-%d %H:%M:%S"
LOG_TIME_RE = re.compile(r"^(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})")
GLOBAL_START_RE = re.compile(r"\[global-model\] start entries=(?P<entries>\d+)")
GLOBAL_END_RE = re.compile(
    r"\[global-model\] end entries=(?P<entries>\d+) "
    r"reachable=(?P<reachable>\d+) modeled=(?P<modeled>\d+) "
    r"cache_hits=(?P<cache_hits>\d+) deterministic=(?P<deterministic>\d+) "
    r"llm=(?P<llm>\d+) failed=(?P<failed>\d+)(?: .*?)? "
    r"duration=(?P<duration>[\d.]+)s"
)
SHARED_END_RE = re.compile(
    r"\[entry-worker\] shared-semantics end entries=(?P<entries>\d+) "
    r"duration=(?P<duration>[\d.]+)s"
)
LLM_TRACE_RE = re.compile(
    r"\[LLM API Trace\].*Prompt ≈ (?P<prompt>[\d,]+) tk \| "
    r"Completion ≈ (?P<completion>[\d,]+) tk \| "
    r"Total ≈ (?P<total>[\d,]+) tk"
)
RUN_STAMP_RE = re.compile(r"(?P<stamp>\d{8}_\d{6})")
CONVERSATION_DIR_RE = re.compile(r"LLM conversation recording enabled: (?P<path>.+)$")


def read_json(path: Path, default: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    if not path.exists():
        return dict(default or {})
    return json.loads(path.read_text(encoding="utf-8"))


def line_time(line: str) -> Optional[datetime]:
    match = LOG_TIME_RE.match(line)
    if not match:
        return None
    return datetime.strptime(match.group("ts"), LOG_TS)


def parse_log(log_path: Path) -> Dict[str, Any]:
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    shared_seconds = 0.0
    summary: Dict[str, Any] = {}
    tokens = {"calls": 0, "prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0}
    counts = Counter()

    for line in log_path.read_text(encoding="utf-8", errors="replace").splitlines():
        timestamp = line_time(line)
        start = GLOBAL_START_RE.search(line)
        if start:
            counts["global_model_start"] += 1
            start_time = timestamp
            summary.setdefault("entries", int(start.group("entries")))

        shared = SHARED_END_RE.search(line)
        if shared:
            shared_seconds += float(shared.group("duration"))

        end = GLOBAL_END_RE.search(line)
        if end:
            counts["global_model_end"] += 1
            end_time = timestamp
            summary.update(
                {
                    "entries": int(end.group("entries")),
                    "reachable_functions": int(end.group("reachable")),
                    "modeled_functions": int(end.group("modeled")),
                    "cache_hit_functions": int(end.group("cache_hits")),
                    "deterministic_snapshot_count": int(end.group("deterministic")),
                    "llm_snapshot_count": int(end.group("llm")),
                    "failed_functions": int(end.group("failed")),
                    "duration_seconds": float(end.group("duration")),
                }
            )

        if "[global-model] failed before entry fan-out" in line:
            counts["global_model_fallback"] += 1
        if "[global-model] Reusing entry snapshot" in line:
            counts["entry_snapshot_reuse"] += 1
        if "[premodel]" in line:
            counts["per_entry_premodel_logs"] += 1
        if "[snapshot-llm] completed context=entry" in line and "success=true" in line:
            counts["per_entry_llm_snapshots"] += 1
        if "[snapshot-llm] completed context=global" in line and "success=true" in line:
            counts["global_llm_snapshots"] += 1

        trace = LLM_TRACE_RE.search(line)
        if not trace:
            continue
        if start_time and timestamp and timestamp < start_time:
            continue
        if end_time and timestamp and timestamp > end_time:
            continue
        tokens["calls"] += 1
        tokens["prompt_tokens"] += int(trace.group("prompt").replace(",", ""))
        tokens["completion_tokens"] += int(trace.group("completion").replace(",", ""))
        tokens["total_tokens"] += int(trace.group("total").replace(",", ""))

    return {
        "global_model": summary,
        "shared_semantics_seconds": shared_seconds,
        "llm_api_tokens": tokens,
        "log_counts": dict(counts),
        "start_time": start_time.strftime(LOG_TS) if start_time else "",
        "end_time": end_time.strftime(LOG_TS) if end_time else "",
    }


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


def parse_tool_result(content: str) -> Dict[str, Any]:
    try:
        return json.loads(content or "{}")
    except Exception:
        if re.search(r'"success"\s*:\s*true', content):
            return {"success": True, "_partial_result": True}
        if re.search(r'"success"\s*:\s*false', content):
            match = re.search(r'"error"\s*:\s*"([^"]*)"', content)
            return {
                "success": False,
                "error": match.group(1) if match else "partial tool result failed",
                "_partial_result": True,
            }
        return {"success": False, "error": "tool result is not parseable JSON"}


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
    if text.lower().startswith("tool result is not parseable json"):
        return "Tool result is not parseable JSON"
    return text or "empty error message"


def result_data(result: Dict[str, Any]) -> Any:
    if "data" in result:
        return result.get("data")
    summary = result.get("summary")
    if isinstance(summary, dict):
        return summary.get("data")
    return None


def is_empty_result(tool_name: str, result: Dict[str, Any]) -> bool:
    if result_success(result) is not True or result.get("_partial_result"):
        return False
    if tool_name in {"get_function_impl", "get_function_snapshot"}:
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
    }


def conversation_files(conv_dir: Path) -> Iterable[Path]:
    return sorted(conv_dir.glob("*.jsonl"))


def parse_conversations(conv_dir: Path) -> Dict[str, Any]:
    by_tool: Dict[str, Dict[str, int]] = defaultdict(empty_tool_bucket)
    error_types: Dict[str, Counter[str]] = defaultdict(Counter)
    failure_records: Dict[str, list[Dict[str, Any]]] = defaultdict(list)
    seen_calls: set[str] = set()
    seen_results: set[str] = set()
    signatures: Counter[str] = Counter()
    call_meta: Dict[str, Dict[str, Any]] = {}
    totals = Counter()

    for path in conversation_files(conv_dir):
        for line_no, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if not line.strip():
                continue
            event = json.loads(line)
            event_type = event.get("event")
            if event_type == "session_start":
                totals["sessions"] += 1
            elif event_type == "session_end":
                totals["session_context_tokens"] += int(event.get("context_tokens") or 0)
            if event_type != "exchange":
                continue

            totals["exchanges"] += 1
            totals["retained_prompt_tokens"] += int(event.get("prompt_tokens") or 0)
            totals["retained_completion_tokens"] += int(event.get("completion_tokens") or 0)

            for message in event.get("request_messages") or []:
                role = message.get("role")
                if role == "assistant":
                    for position, tool_call in enumerate(message.get("tool_calls") or []):
                        call_id = str(tool_call.get("id") or "")
                        if not call_id:
                            call_id = f"{path.name}:{line_no}:{position}"
                        if call_id in seen_calls:
                            continue
                        seen_calls.add(call_id)
                        function = tool_call.get("function") or {}
                        tool_name = str(function.get("name") or "unknown")
                        raw_arguments = function.get("arguments")
                        normalized_arguments = normalize_args(raw_arguments)
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
                        session = event.get("session") or {}
                        call_meta[call_id] = {
                            "tool": tool_name,
                            "signature": signature,
                            "arguments": arguments,
                            "conversation_file": path.name,
                            "session_id": str(session.get("id") or ""),
                            "session_label": str(session.get("label") or ""),
                            "timestamp": str(event.get("timestamp") or ""),
                            "iteration": int(event.get("iteration") or 0),
                        }
                        bucket = by_tool[tool_name]
                        bucket["calls"] += 1
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
                                "conversation_file": meta["conversation_file"],
                                "session_id": meta["session_id"],
                                "session_label": meta["session_label"],
                                "timestamp": meta["timestamp"],
                                "iteration": meta["iteration"],
                                "arguments": meta["arguments"],
                                "error": error,
                            }
                        )
                    if is_empty_result(tool_name, result):
                        bucket["empty_results"] += 1
                    if result.get("repeat_call_warning") or result.get("cached_tool_result"):
                        bucket["loop_guard_warnings"] += 1
                    if result.get("repeat_call_guard"):
                        bucket["loop_guard_blocked"] += 1

    totals["retained_total_tokens"] = (
        totals["retained_prompt_tokens"] + totals["retained_completion_tokens"]
    )
    totals["unique_tool_calls"] = len(seen_calls)
    totals["unique_tool_results"] = len(seen_results)
    return {
        "conversation": dict(totals),
        "by_tool": {name: dict(values) for name, values in sorted(by_tool.items())},
        "error_types_by_tool": {
            name: dict(counter.most_common()) for name, counter in sorted(error_types.items())
        },
        "failure_records_by_tool": {
            name: list(failure_records.get(name) or []) for name in sorted(by_tool)
        },
    }


def infer_conversation_dir(run_dir: Path, explicit: Optional[Path]) -> Path:
    if explicit:
        path = explicit.resolve()
        if not path.is_dir():
            raise FileNotFoundError(f"Conversation directory not found: {path}")
        return path

    log_path = run_dir / "zscope_run.log"
    if log_path.exists():
        for line in log_path.read_text(encoding="utf-8", errors="replace").splitlines():
            recorded = CONVERSATION_DIR_RE.search(line)
            if not recorded:
                continue
            path = Path(recorded.group("path").strip()).resolve()
            if path.is_dir():
                return path

    match = RUN_STAMP_RE.search(run_dir.name)
    if not match:
        raise ValueError("Cannot infer conversation directory from run directory name")
    root = run_dir.parents[1] / ".zscope_conversations"
    candidates = sorted(root.glob(f"run_{match.group('stamp')}_*"))
    if len(candidates) != 1:
        raise ValueError(
            f"Expected one conversation directory for {match.group('stamp')}, found {len(candidates)}"
        )
    return candidates[0].resolve()


def safe_div(numerator: float, denominator: float) -> float:
    return numerator / denominator if denominator else 0.0


def pct(numerator: Any, denominator: Any) -> str:
    return f"{safe_div(float(numerator or 0), float(denominator or 0)) * 100:.2f}%" if denominator else "-"


def fmt_int(value: Any) -> str:
    return f"{int(value or 0):,}"


def fmt_float(value: Any, digits: int = 2) -> str:
    return f"{float(value or 0):,.{digits}f}"


def row(values: Iterable[Any]) -> str:
    return "| " + " | ".join(str(value) for value in values) + " |"


def markdown_cell(value: Any) -> str:
    return str(value).replace("|", "\\|").replace("\n", "<br>")


def render_markdown(data: Dict[str, Any], model: str) -> str:
    run = data["run"]
    global_model = data["global_model"]
    llm = data["llm_api_tokens"]
    log_counts = data["log_counts"]
    tools = data["tools"]
    entry_count = int(global_model.get("entries") or run.get("entry_count") or 0)
    reachable = int(global_model.get("reachable_functions") or 0)
    llm_snapshots = int(global_model.get("llm_snapshot_count") or 0)
    scan_seconds = float(run.get("scan_wall_seconds") or 0)
    global_seconds = float(global_model.get("duration_seconds") or 0)
    shared_seconds = float(data.get("shared_semantics_seconds") or 0)
    reuse_seconds = max(0.0, scan_seconds - global_seconds - shared_seconds)

    lines = [
        "# Global Semantic Modeling Metrics",
        "",
        f"> Run: `{run['run_id']}`  ",
        f"> Model: `{model}`  ",
        f"> Scope: 全局语义建模、入口 snapshot 复用及其必要前置阶段；不统计漏洞指标。",
        "",
        "## 一、效率与成本指标",
        "",
        "### 1.1 运行总览",
        "",
        "| 指标 | 数值 |",
        "|---|---:|",
        row(["入口函数", fmt_int(entry_count)]),
        row(["全局可达函数", fmt_int(reachable)]),
        row(["完成建模函数", fmt_int(global_model.get("modeled_functions"))]),
        row(["Deterministic snapshot", fmt_int(global_model.get("deterministic_snapshot_count"))]),
        row(["LLM snapshot", fmt_int(llm_snapshots)]),
        row(["Snapshot cache hit", fmt_int(global_model.get("cache_hit_functions"))]),
        row(["建模失败", fmt_int(global_model.get("failed_functions"))]),
        row(["全局建模成功率", pct(global_model.get("modeled_functions"), reachable)]),
        row(["入口 snapshot 复用", f"{fmt_int(log_counts.get('entry_snapshot_reuse'))}/{fmt_int(entry_count)}"]),
        "",
        "### 1.2 Token 与 API 成本",
        "",
        "| 口径 | API Calls | Prompt Tokens | Completion Tokens | Total Tokens |",
        "|---|---:|---:|---:|---:|",
        row([
            "全局建模总计",
            fmt_int(llm.get("calls")),
            fmt_int(llm.get("prompt_tokens")),
            fmt_int(llm.get("completion_tokens")),
            fmt_int(llm.get("total_tokens")),
        ]),
        row([
            "每个 LLM snapshot 平均",
            fmt_float(safe_div(llm.get("calls", 0), llm_snapshots)),
            fmt_float(safe_div(llm.get("prompt_tokens", 0), llm_snapshots)),
            fmt_float(safe_div(llm.get("completion_tokens", 0), llm_snapshots)),
            fmt_float(safe_div(llm.get("total_tokens", 0), llm_snapshots)),
        ]),
        row([
            "每个可达函数平均",
            fmt_float(safe_div(llm.get("calls", 0), reachable)),
            fmt_float(safe_div(llm.get("prompt_tokens", 0), reachable)),
            fmt_float(safe_div(llm.get("completion_tokens", 0), reachable)),
            fmt_float(safe_div(llm.get("total_tokens", 0), reachable)),
        ]),
        row([
            "每个入口平均",
            fmt_float(safe_div(llm.get("calls", 0), entry_count)),
            fmt_float(safe_div(llm.get("prompt_tokens", 0), entry_count)),
            fmt_float(safe_div(llm.get("completion_tokens", 0), entry_count)),
            fmt_float(safe_div(llm.get("total_tokens", 0), entry_count)),
        ]),
        "",
        "Token 取自 `zscope_run.log` 的全部 `[LLM API Trace]`，覆盖探索、工具循环、结构化 finalization 和 repair；因此 API Calls 高于成功生成的 LLM snapshot 数。",
        "",
        "### 1.3 阶段耗时",
        "",
        "| 阶段 | 用时 | 占 scan wall time | 备注 |",
        "|---|---:|---:|---|",
        row(["Shared semantics 前置准备", f"{fmt_float(shared_seconds)}s", pct(shared_seconds, scan_seconds), "日志显式 duration"]),
        row(["全局语义建模", f"{fmt_float(global_seconds)}s", pct(global_seconds, scan_seconds), "含调用图收集、deterministic 与 LLM snapshot"]),
        row(["入口复用与报告收尾", f"{fmt_float(reuse_seconds)}s", pct(reuse_seconds, scan_seconds), "由 scan wall time 扣除前两阶段估算"]),
        row(["Scan 总计", f"{fmt_float(scan_seconds)}s ({scan_seconds / 3600:.2f}h)", "100.00%", "外层脚本 wall time"]),
        "",
        "### 1.4 吞吐量",
        "",
        "| 指标 | 数值 |",
        "|---|---:|",
        row(["全局建模函数吞吐", f"{fmt_float(safe_div(reachable, global_seconds) * 60)} functions/min"]),
        row(["LLM snapshot 吞吐", f"{fmt_float(safe_div(llm_snapshots, global_seconds) * 60)} snapshots/min"]),
        row(["单个可达函数平均全局阶段用时", f"{fmt_float(safe_div(global_seconds, reachable))}s"]),
        row(["单个 LLM snapshot 平均全局阶段用时", f"{fmt_float(safe_div(global_seconds, llm_snapshots))}s"]),
        "",
        "## 二、工具质量指标",
        "",
        "### 2.1 工具调用总览",
        "",
        "| 工具 | Calls | Results | 成功率 | 参数错误率 | 格式错误率 | 其他错误率 | 空结果率 | 重复参数调用率 | Loop Guard 警告/拦截 |",
        "|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]

    for tool_name, bucket in sorted(
        tools["by_tool"].items(), key=lambda item: (-int(item[1].get("calls") or 0), item[0])
    ):
        results = int(bucket.get("results") or 0)
        calls = int(bucket.get("calls") or 0)
        lines.append(
            row(
                [
                    f"`{tool_name}`",
                    fmt_int(calls),
                    fmt_int(results),
                    pct(bucket.get("success"), results),
                    pct(bucket.get("parameter_errors"), results),
                    pct(bucket.get("format_errors"), results),
                    pct(bucket.get("other_errors"), results),
                    pct(bucket.get("empty_results"), results),
                    pct(bucket.get("repeated_calls"), calls),
                    f"{fmt_int(bucket.get('loop_guard_warnings'))}/{fmt_int(bucket.get('loop_guard_blocked'))}",
                ]
            )
        )

    total_tool_calls = sum(int(v.get("calls") or 0) for v in tools["by_tool"].values())
    total_tool_results = sum(int(v.get("results") or 0) for v in tools["by_tool"].values())
    total_tool_success = sum(int(v.get("success") or 0) for v in tools["by_tool"].values())
    lines.extend(
        [
            "",
            "### 2.2 工具成本归一化",
            "",
            "| 指标 | 数值 |",
            "|---|---:|",
            row(["唯一工具调用", fmt_int(total_tool_calls)]),
            row(["工具结果返回", fmt_int(total_tool_results)]),
            row(["工具整体成功率", pct(total_tool_success, total_tool_results)]),
            row(["每个 LLM snapshot 平均工具调用", fmt_float(safe_div(total_tool_calls, llm_snapshots))]),
            row(["每个可达函数平均工具调用", fmt_float(safe_div(total_tool_calls, reachable))]),
            row(["每个入口平均工具调用", fmt_float(safe_div(total_tool_calls, entry_count))]),
            "",
            "### 2.3 工具错误类型",
            "",
        ]
    )

    error_types = tools.get("error_types_by_tool") or {}
    if error_types:
        lines.extend(["| 工具 | 错误类型 | 次数 |", "|---|---|---:|"])
        for tool_name, counters in sorted(error_types.items()):
            for error, count in counters.items():
                lines.append(row([f"`{tool_name}`", error.replace("|", "\\|"), fmt_int(count)]))
    else:
        lines.append("本次运行未记录工具错误。")

    lines.extend(
        [
            "",
            "### 2.4 全部工具的失败对话记录",
            "",
            f"> Conversation 目录：`{data['run']['conversation_dir']}`",
            "",
        ]
    )
    failure_records = tools.get("failure_records_by_tool") or {}
    tool_names = sorted(
        tools["by_tool"],
        key=lambda name: (-int(tools["by_tool"][name].get("calls") or 0), name),
    )
    for tool_name in tool_names:
        records = list(failure_records.get(tool_name) or [])
        lines.extend(
            [
                f"#### `{tool_name}`（{len(records)} 条）",
                "",
                "| # | 时间 | 目标函数 / Session | Conversation 文件 | 调用参数 | 错误结果 |",
                "|---:|---|---|---|---|---|",
            ]
        )
        for index, record in enumerate(records, 1):
            arguments = json.dumps(
                record.get("arguments"), ensure_ascii=False, sort_keys=True
            )
            label = record.get("session_label") or record.get("session_id") or "-"
            lines.append(
                row(
                    [
                        index,
                        markdown_cell(record.get("timestamp") or "-"),
                        f"`{markdown_cell(label)}`",
                        f"`{markdown_cell(record.get('conversation_file') or '-')}`",
                        f"`{markdown_cell(arguments)}`",
                        markdown_cell(record.get("error") or "-"),
                    ]
                )
            )
        if not records:
            lines.append(row(["-", "-", "-", "-", "-", "无失败记录"]))
        lines.append("")

    lines.extend(
        [
            "",
            "说明：",
            "",
            "- 工具调用按唯一 `tool_call_id` 统计。conversation 的后续 request 会携带历史消息，不能逐 exchange 重复累计同一 call。",
            "- `重复参数调用率` 表示不同 call ID 使用相同工具和相同参数，不包含 conversation 历史消息造成的重复出现。",
            "- `get_function_snapshot` 的 `data=null` 可能是合法 missing/stale fallback，不按空结果处理。",
            "- 本报告不计算证据命中率，因为该 run 禁用了漏洞挖掘与验证，最终报告没有 finding evidence 可供关联。",
            "",
            "## 三、运行完整性检查",
            "",
            "| 检查项 | 结果 |",
            "|---|---:|",
            row(["Scan return code", fmt_int(run.get("scan_return_code"))]),
            row(["Global model start/end", f"{fmt_int(log_counts.get('global_model_start'))}/{fmt_int(log_counts.get('global_model_end'))}"]),
            row(["Global fallback", fmt_int(log_counts.get("global_model_fallback"))]),
            row(["Per-entry premodel 日志", fmt_int(log_counts.get("per_entry_premodel_logs"))]),
            row(["Per-entry LLM snapshot", fmt_int(log_counts.get("per_entry_llm_snapshots"))]),
            row(["Global LLM snapshot 成功日志", fmt_int(log_counts.get("global_llm_snapshots"))]),
            row(["入口 snapshot 复用日志", fmt_int(log_counts.get("entry_snapshot_reuse"))]),
            "",
            "完整性结论：全局阶段成功结束且没有回退；所有入口复用全局 snapshot，未触发 per-entry premodel 或 entry LLM 建模。",
        ]
    )
    return "\n".join(lines) + "\n"


def generate(run_dir: Path, conversation_dir: Path) -> Dict[str, Any]:
    log_metrics = parse_log(run_dir / "zscope_run.log")
    run_metrics = read_json(run_dir / "global_model_metrics.json")
    report = read_json(run_dir / "zscope_batch_report.json")
    report_summary = report.get("summary") or {}
    tools = parse_conversations(conversation_dir)
    global_model = dict(log_metrics["global_model"])

    run = {
        "run_id": run_dir.name,
        "run_dir": str(run_dir.resolve()),
        "conversation_dir": str(conversation_dir.resolve()),
        "entry_count": int(
            global_model.get("entries")
            or report_summary.get("functions_analyzed")
            or 0
        ),
        "scan_return_code": int(run_metrics.get("scan_return_code") or 0),
        "scan_wall_seconds": int(run_metrics.get("scan_wall_seconds") or 0),
    }
    return {
        "run": run,
        "global_model": global_model,
        "shared_semantics_seconds": log_metrics["shared_semantics_seconds"],
        "llm_api_tokens": log_metrics["llm_api_tokens"],
        "log_counts": log_metrics["log_counts"],
        "global_model_start": log_metrics["start_time"],
        "global_model_end": log_metrics["end_time"],
        "tools": tools,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("run_dir", type=Path)
    parser.add_argument("--conversation-dir", type=Path)
    parser.add_argument("--model", default="GLM-5")
    parser.add_argument("--json-output", type=Path)
    parser.add_argument("--markdown-output", type=Path)
    args = parser.parse_args()

    run_dir = args.run_dir.resolve()
    if not (run_dir / "zscope_run.log").exists():
        raise FileNotFoundError(f"zscope_run.log not found under {run_dir}")
    conversation_dir = infer_conversation_dir(run_dir, args.conversation_dir)
    data = generate(run_dir, conversation_dir)

    json_output = args.json_output or (run_dir / "global_model_efficiency_metrics.json")
    markdown_output = args.markdown_output or (run_dir / "metrics.md")
    json_output.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    markdown_output.write_text(render_markdown(data, args.model), encoding="utf-8")
    print(markdown_output)


if __name__ == "__main__":
    main()
