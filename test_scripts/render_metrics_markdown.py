#!/usr/bin/env python3
"""Render Z-SCOPE benchmark metrics markdown from extracted metric JSON files."""

from __future__ import annotations

import argparse
import json
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


TOOLS = [
    "get_function_impl",
    "get_function_snapshot",
    "get_file_snippet",
    "get_type_info",
    "get_callers",
    "get_call_graph",
    "get_data_flow",
    "get_deep_call_context",
    "list_known_functions",
    "find_function_pointers",
    "query_pointer_alias",
    "verify_taint_reachability",
]

AGENTS = [
    "semantic_modeler",
    "skill_selection",
    "deep_worker",
    "vulnerability_analyzer",
    "validator_agent",
    "issue_reconciler_agent",
]


def read_json(path: Path) -> Dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def fmt_int(value: Any) -> str:
    try:
        return f"{int(value):,}"
    except (TypeError, ValueError):
        return "0"


def fmt_float(value: float, digits: int = 2) -> str:
    return f"{value:,.{digits}f}"


def pct(numerator: Any, denominator: Any) -> str:
    try:
        denominator_f = float(denominator)
        numerator_f = float(numerator)
    except (TypeError, ValueError):
        return "-"
    if denominator_f == 0:
        return "-"
    return f"{numerator_f / denominator_f * 100:.2f}%"


def fmt_pct_value(value: Any) -> str:
    if value is None:
        return "-"
    return f"{float(value) * 100:.2f}%"


def build_cpg_seconds(log_path: Path) -> Optional[float]:
    if not log_path.exists():
        return None
    timestamps: List[datetime] = []
    for line in log_path.read_text(encoding="utf-8", errors="replace").splitlines():
        if len(line) < 19:
            continue
        try:
            timestamps.append(datetime.strptime(line[:19], "%Y-%m-%d %H:%M:%S"))
        except ValueError:
            continue
    if len(timestamps) < 2:
        return None
    return max(0.0, (timestamps[-1] - timestamps[0]).total_seconds())


def token_row(tokens: Dict[str, Any]) -> Tuple[int, int, int]:
    return (
        int(tokens.get("total_tokens") or 0),
        int(tokens.get("prompt_tokens") or 0),
        int(tokens.get("completion_tokens") or 0),
    )


def row_line(cells: List[str]) -> str:
    return "| " + " | ".join(cells) + " |"


def vulnerability_view(metrics: Dict[str, Any], name: str) -> Dict[str, Any]:
    views = metrics.get("benchmark_views") or {}
    view = dict(views.get(name) or {})
    if not view and name == "default":
        view = dict(metrics.get("evaluation") or {})
    tp = int(view.get("true_positives") or 0)
    fp = int(view.get("false_positives") or view.get("false_positives_effective") or 0)
    fn = int(view.get("false_negatives") or 0)
    issues = int(view.get("report_issue_count") or view.get("issues") or tp + fp)
    gt = int(view.get("ground_truth_count") or tp + fn)
    recall = view.get("recall")
    if recall is None:
        recall = view.get("detection_rate")
    if recall is None:
        recall = tp / gt if gt else 0
    precision = view.get("precision")
    if precision is None:
        precision = tp / (tp + fp) if (tp + fp) else 0
    f1 = view.get("f1")
    if f1 is None:
        f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0
    return {
        "issues": issues,
        "ground_truth": gt,
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "recall": recall,
        "precision": precision,
        "f1": f1,
        "false_positive_rate": view.get("false_positive_rate"),
    }


def render(run_dir: Path, model: str = "GLM-5") -> str:
    efficiency = read_json(run_dir / "efficiency_metrics.json")
    metrics = read_json(run_dir / "metrics.json")
    report = read_json(run_dir / "zscope_batch_report.json")

    entry_count = int(efficiency["total"].get("entry_count") or metrics.get("entry_count") or 0)
    trace_by_agent = efficiency["llm_trace_tokens"]["by_agent"]
    trace_by_step = efficiency["llm_trace_tokens"]["by_step"]
    step_seconds = efficiency["workflow_step_work_seconds"]
    conversation = efficiency["conversation_by_agent"]
    tool_calls = efficiency["tool_calls"]
    build_seconds = build_cpg_seconds(run_dir / "build_cpg.log")

    trace_total = {
        "prompt_tokens": sum(int(v.get("prompt_tokens") or 0) for v in trace_by_agent.values()),
        "completion_tokens": sum(int(v.get("completion_tokens") or 0) for v in trace_by_agent.values()),
        "total_tokens": sum(int(v.get("total_tokens") or 0) for v in trace_by_agent.values()),
    }

    def add_metric_row(
        lines: List[str],
        phase: str,
        agent: str,
        total_tokens: int,
        prompt_tokens: int,
        completion_tokens: int,
        seconds: float,
        note: str,
        *,
        per_entry: bool = False,
    ) -> None:
        divisor = entry_count if per_entry and entry_count else 1
        token_fmt = fmt_float(total_tokens / divisor) if per_entry else fmt_int(total_tokens)
        prompt_fmt = fmt_float(prompt_tokens / divisor) if per_entry else fmt_int(prompt_tokens)
        completion_fmt = fmt_float(completion_tokens / divisor) if per_entry else fmt_int(completion_tokens)
        seconds_fmt = fmt_float(seconds / divisor) + "s" if per_entry else fmt_float(seconds) + "s"
        lines.append(row_line([phase, agent, token_fmt, prompt_fmt, completion_fmt, seconds_fmt, note]))

    lines: List[str] = []
    lines.append("# Benchmark Metrics")
    lines.append("")
    lines.append(f">Model: {model}")
    lines.append("")
    lines.append("## 一、效率与成本指标")
    lines.append("")
    lines.append("### 1.1 单次运行总览")
    lines.append("")
    lines.append("| 阶段 | Agent | Total Tokens | Prompt Tokens | Completion Tokens | 用时 | 备注 |")
    lines.append("|---|---|---:|---:|---:|---:|---|")
    hours = int(efficiency["total"].get("scan_wall_seconds") or 0) / 3600
    total_note = "Token 使用 `zscope_run.log` 的 `[LLM API Trace]` 聚合；用时为外层 scan wall time"
    lines.append(
        row_line(
            [
                "Total",
                "-",
                fmt_int(trace_total["total_tokens"]),
                fmt_int(trace_total["prompt_tokens"]),
                fmt_int(trace_total["completion_tokens"]),
                f"{fmt_int(efficiency['total'].get('scan_wall_seconds'))}s ({hours:.1f}h)",
                total_note,
            ]
        )
    )
    add_metric_row(
        lines,
        "build_cpg / index warmup<br>(step0)",
        "-",
        0,
        0,
        0,
        build_seconds or 0,
        "工作流开始前的 CodeIndex/clangd/CPG 准备成本；无 LLM token",
    )
    add_metric_row(lines, "discover_entries<br>(step1)", "-", 0, 0, 0, 0, "直接使用配置的 entries；无 LLM token")
    pre = token_row(trace_by_step.get("premodel_reachable_callees", {}))
    add_metric_row(
        lines,
        "premodel_reachable_callees<br>(step1.5)",
        "semantic_modeler",
        *pre,
        float(step_seconds.get("premodel_reachable_callees") or 0),
        "workflow step 累计工作时长",
    )
    model_entry = token_row(trace_by_step.get("model_entry", {}))
    add_metric_row(
        lines,
        "model_entry<br>(step2)",
        "semantic_modeler",
        *model_entry,
        float(step_seconds.get("model_entry") or 0),
        "workflow step 累计工作时长",
    )
    skill = token_row(trace_by_agent.get("skill_selection_or_deep_worker", {}))
    add_metric_row(
        lines,
        "focused_subagent_planning<br>(step3)",
        "skill_selection",
        *skill,
        float(conversation.get("skill_selection", {}).get("session_duration_seconds") or step_seconds.get("focused_subagent_planning") or 0),
        "skill routing 的 Agent session 累计；该 step 内还会执行 deep_worker",
    )
    deep = token_row(trace_by_agent.get("deep_worker", {}))
    add_metric_row(
        lines,
        "focused_subagent_planning<br>(step3)",
        "deep_worker",
        *deep,
        float(conversation.get("deep_worker", {}).get("session_duration_seconds") or 0),
        "Agent session 累计；实际执行发生在 step3",
    )
    vuln = token_row(trace_by_step.get("vulnerability_mining", {}))
    add_metric_row(
        lines,
        "vulnerability_mining<br>(step4)",
        "vulnerability_analyzer",
        *vuln,
        float(step_seconds.get("vulnerability_mining") or 0),
        "workflow step 累计工作时长",
    )
    val = token_row(trace_by_step.get("validate_findings", {}))
    add_metric_row(
        lines,
        "validate_findings<br>(step5)",
        "validator_agent",
        *val,
        float(step_seconds.get("validate_findings") or 0),
        "workflow step 累计工作时长",
    )
    recon = token_row(trace_by_agent.get("issue_reconciler_agent", {}))
    add_metric_row(
        lines,
        "persist_report<br>(step6)",
        "issue_reconciler_agent",
        *recon,
        float(conversation.get("issue_reconciler_agent", {}).get("session_duration_seconds") or step_seconds.get("persist_report") or 0),
        "包含 batch 语义去重中的 issue_reconciler 调用",
    )

    lines.append("")
    lines.append("### 1.2 单入口平均")
    lines.append("")
    lines.append(f">入口数量：{entry_count}")
    lines.append("")
    lines.append("| 阶段 | Agent | Total Tokens | Prompt Tokens | Completion Tokens | 用时 | 备注 |")
    lines.append("|---|---|---:|---:|---:|---:|---|")
    add_metric_row(lines, "Total", "-", trace_total["total_tokens"], trace_total["prompt_tokens"], trace_total["completion_tokens"], float(efficiency["total"].get("scan_wall_seconds") or 0), "以入口数量均摊外层 scan wall time 与 API trace token", per_entry=True)
    add_metric_row(lines, "build_cpg / index warmup<br>(step0)", "-", 0, 0, 0, build_seconds or 0, "工作流开始前准备成本均摊", per_entry=True)
    add_metric_row(lines, "discover_entries<br>(step1)", "-", 0, 0, 0, 0, "直接使用配置的 entries", per_entry=True)
    add_metric_row(lines, "premodel_reachable_callees<br>(step1.5)", "semantic_modeler", *pre, float(step_seconds.get("premodel_reachable_callees") or 0), "", per_entry=True)
    add_metric_row(lines, "model_entry<br>(step2)", "semantic_modeler", *model_entry, float(step_seconds.get("model_entry") or 0), "", per_entry=True)
    add_metric_row(lines, "focused_subagent_planning<br>(step3)", "skill_selection", *skill, float(conversation.get("skill_selection", {}).get("session_duration_seconds") or step_seconds.get("focused_subagent_planning") or 0), "skill routing session 累计", per_entry=True)
    add_metric_row(lines, "focused_subagent_planning<br>(step3)", "deep_worker", *deep, float(conversation.get("deep_worker", {}).get("session_duration_seconds") or 0), "Agent session 累计；实际执行发生在 step3", per_entry=True)
    add_metric_row(lines, "vulnerability_mining<br>(step4)", "vulnerability_analyzer", *vuln, float(step_seconds.get("vulnerability_mining") or 0), "", per_entry=True)
    add_metric_row(lines, "validate_findings<br>(step5)", "validator_agent", *val, float(step_seconds.get("validate_findings") or 0), "", per_entry=True)
    add_metric_row(lines, "persist_report<br>(step6)", "issue_reconciler_agent", *recon, float(conversation.get("issue_reconciler_agent", {}).get("session_duration_seconds") or step_seconds.get("persist_report") or 0), "包含 batch 语义去重中的 issue_reconciler 调用", per_entry=True)
    lines.append("")
    lines.append("说明：")
    lines.append("- `build_cpg / index warmup（step0）` 不属于 `zscope/workflows/default.yaml` 的步骤，表示 CLI 创建 CodeIndex、clangd/CPG/KnowledgeDB 准备等工作流开始前成本。")
    lines.append("- 用时口径：`Total` 用时来自 `metrics.json.scan_wall_seconds`；workflow step 用时来自日志 step start/completed 的累计工作时长；`deep_worker` 与 `issue_reconciler_agent` 使用 conversation session 累计时长。")
    lines.append(f"- 报告归档口径 token：Prompt {fmt_int(efficiency['total'].get('total_prompt_tokens'))}，Completion {fmt_int(efficiency['total'].get('total_completion_tokens'))}，Total {fmt_int(efficiency['total'].get('total_tokens'))}。")

    by_tool = tool_calls["by_tool"]
    by_agent_tool = tool_calls["by_agent_tool"]
    lines.append("")
    lines.append("## 二、工具质量指标")
    lines.append("")
    lines.append("### 2.1 不同工具的单次运行总计调用次数")
    lines.append("")
    lines.append("| 工具名 | 不同 Agent 总计调用次数 | semantic_modeler | skill_selection | deep_worker | vulnerability_analyzer | validator_agent | issue_reconciler_agent |")
    lines.append("|---|---:|---:|---:|---:|---:|---:|---:|")
    for tool in TOOLS:
        row = [tool, fmt_int(by_tool.get(tool, {}).get("calls"))]
        for agent in AGENTS:
            row.append(fmt_int((by_agent_tool.get(agent) or {}).get(tool, {}).get("calls")))
        lines.append(row_line(row))

    lines.append("")
    lines.append("### 2.2 不同工具的单入口平均调用次数")
    lines.append("")
    lines.append(f">入口数量：{entry_count}")
    lines.append("")
    lines.append("| 工具名 | 不同 Agent 总计调用次数 | semantic_modeler | skill_selection | deep_worker | vulnerability_analyzer | validator_agent | issue_reconciler_agent |")
    lines.append("|---|---:|---:|---:|---:|---:|---:|---:|")
    for tool in TOOLS:
        row = [tool, fmt_float((by_tool.get(tool, {}).get("calls") or 0) / entry_count if entry_count else 0)]
        for agent in AGENTS:
            row.append(fmt_float(((by_agent_tool.get(agent) or {}).get(tool, {}).get("calls") or 0) / entry_count if entry_count else 0))
        lines.append(row_line(row))

    lines.append("")
    lines.append("### 2.3 不同工具的质量指标")
    lines.append("")
    lines.append("| 工具名 | 单次运行总计调用次数 | 成功率 | 格式错误率 | 参数错误率 | 其他错误率 | 空结果率 | Loop Guard 警告次数 | Loop Guard 拦截次数 | 证据命中率 |")
    lines.append("|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|")
    for tool in TOOLS:
        bucket = by_tool.get(tool, {})
        results = int(bucket.get("results") or 0)
        row = [
            tool,
            fmt_int(bucket.get("calls")),
            pct(bucket.get("success"), results),
            pct(bucket.get("format_errors"), results),
            pct(bucket.get("parameter_errors"), results),
            pct(bucket.get("other_errors"), results),
            pct(bucket.get("empty_results"), results),
            fmt_int(bucket.get("loop_guard_warnings")),
            fmt_int(bucket.get("loop_guard_blocked")),
            pct(bucket.get("evidence_hits"), results),
        ]
        lines.append(row_line(row))

    error_types_by_tool = tool_calls.get("error_types_by_tool") or {}
    error_types: List[str] = []
    for tool in TOOLS:
        for error_type in (error_types_by_tool.get(tool) or {}):
            if error_type not in error_types:
                error_types.append(error_type)
    lines.append("")
    lines.append("### 2.4 不同工具的错误情况统计")
    lines.append("")
    if error_types:
        lines.append("| 工具名 | 错误总次数 | " + " | ".join(error_types) + " |")
        lines.append("|---|---:|" + "|".join(["---:"] * len(error_types)) + "|")
        for tool in TOOLS:
            counter = error_types_by_tool.get(tool) or {}
            row = [tool, fmt_int(sum(int(v) for v in counter.values()))]
            row.extend(fmt_int(counter.get(error_type)) for error_type in error_types)
            lines.append(row_line(row))
    else:
        lines.append("| 工具名 | 错误总次数 |")
        lines.append("|---|---:|")
        for tool in TOOLS:
            lines.append(row_line([tool, "0"]))
    lines.append("")
    lines.append("说明：")
    lines.append("- `get_deep_call_context` 调用次数为 0 的原因是默认 workflow 下它对所有实际运行 Agent 都不可见：`vulnerability_analyzer` 的 Agent tools 声明了该工具，但当前 active vulnerability skills 未声明它；其他 Agent 本身也未声明该工具，因此运行时不会暴露给任何 Agent。")
    lines.append("- `get_function_impl` 和 `get_function_snapshot` 的 `callers/callees` 为空不代表工具结果为空；只有成功结果缺少 `data` 或 `data` 本身为空时，才计为空结果。")
    lines.append("- `参数错误` 包括：`Function not found`、`Failed to read file`、`Type not found`; `其他错误`包括：`Sensitive path denied by policy`、`Loop Guard blocked repeated call`。")
    lines.append("- `证据命中率` 指的是工具返回的结构化锚点（file/function/line/symbol/candidate_id/dedup_key 等）是否在后续 finding、validation result、audit observation 或 rejection evidence 中显式出现。仅用 Python 代码计算时，`证据命中率` 不能等价于完整语义层面的“有效调用率”。")

    default = vulnerability_view(metrics, "default")
    needs = vulnerability_view(metrics, "with_needs_review")
    needs_ratio = (needs["issues"] - default["issues"]) / needs["issues"] if needs["issues"] else 0
    lines.append("")
    lines.append("## 三、上下文质量指标（待分析）")
    lines.append("")
    lines.append("## 四、漏洞指标")
    lines.append("")
    lines.append("| 视图 | Report Issues | Ground Truth | TP | FP | FN | Recall | Precision | F1 | 误报率 | Needs Review 比例 |")
    lines.append("|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|")
    lines.append(row_line(["默认视图", fmt_int(default["issues"]), fmt_int(default["ground_truth"]), fmt_int(default["tp"]), fmt_int(default["fp"]), fmt_int(default["fn"]), fmt_pct_value(default["recall"]), fmt_pct_value(default["precision"]), fmt_pct_value(default["f1"]), fmt_pct_value(default["false_positive_rate"]), "-"]))
    lines.append(row_line(["Needs Review 视图", fmt_int(needs["issues"]), fmt_int(needs["ground_truth"]), fmt_int(needs["tp"]), fmt_int(needs["fp"]), fmt_int(needs["fn"]), fmt_pct_value(needs["recall"]), fmt_pct_value(needs["precision"]), fmt_pct_value(needs["f1"]), fmt_pct_value(needs["false_positive_rate"]), fmt_pct_value(needs_ratio)]))
    lines.append("")
    lines.append("说明：")
    lines.append("- `误报率` 使用 `metrics.json` 中的 `false_positive_rate` 字段。")
    lines.append(f"- `Needs Review 比例 = (Needs Review 视图 Report Issues - 默认视图 Report Issues) / Needs Review 视图 Report Issues = {needs['issues'] - default['issues']} / {needs['issues']} = {fmt_pct_value(needs_ratio)}`。")
    lines.append("")
    lines.append("## 五、后端质量指标")
    lines.append("")
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("run_dir", type=Path)
    parser.add_argument("--model", default="GLM-5")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    output = args.output or (args.run_dir / "metrics.md")
    output.write_text(render(args.run_dir, model=args.model) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
