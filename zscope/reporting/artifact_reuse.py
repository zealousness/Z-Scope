"""Report task reuse separately from the physical LLM usage ledger."""

from collections.abc import Iterable, Mapping
from typing import Any


def merge_initial_reuse(rows: Iterable[Mapping[str, Any]]) -> dict[str, Any]:
    counters = ("queries", "hits", "misses", "writes", "bypassed", "model_tasks", "tokens")
    reasons = ("miss_reasons", "bypass_reasons", "write_skip_reasons")
    result: dict[str, Any] = {key: 0 for key in counters}
    result.update({key: {} for key in reasons})
    for row in rows:
        for key in counters:
            result[key] += int(row.get(key, 0))
        for key in reasons:
            for reason, count in row.get(key, {}).items():
                result[key][reason] = result[key].get(reason, 0) + int(count)
    return result


def artifact_reuse_summary(
    discovery: Mapping[str, Any],
    initial: Mapping[str, Any],
    investigation: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    reuse = discovery.get("reuse", {})
    summaries = {
        "queries": int(reuse.get("lookups", 0)),
        "hits": int(reuse.get("hits", 0)),
        "cross_build_hits": int(reuse.get("cross_build_hits", 0)),
        "recomputed_units": int(reuse.get("recomputed_units", 0)),
        "miss_reasons": dict(reuse.get("miss_reasons", {})),
        "model_tasks": int(discovery.get("model_calls", 0)),
        "tokens": int(discovery.get("tokens", 0)),
        "tokens_complete": discovery.get("tokens_complete", True),
    }
    validation = merge_initial_reuse([initial])
    queries = merge_query_reuse([investigation or {}])
    for section in (summaries, validation):
        section["hit_rate"] = (
            round(section["hits"] / section["queries"], 4) if section["queries"] else None
        )
    return {
        "schema_version": "zscope.artifact-reuse.v1",
        "summaries": summaries,
        "initial_validation": validation,
        "investigation_queries": queries,
        "usage_scope": "current_run_only; physical requests are counted by llm_usage",
    }


def merge_query_reuse(rows: Iterable[Mapping[str, Any]]) -> dict[str, Any]:
    from ..core.validation.investigation_reuse import merge_metrics

    return merge_metrics(rows)


def artifact_reuse_markdown(metadata: Mapping[str, Any]) -> str:
    reuse = metadata.get("artifact_reuse")
    if not reuse:
        return ""
    rows = [
        "\n## 分析成果复用\n",
        "| 分析阶段 | 查询数 | 复用数 | 本轮模型任务 | 本轮 Token |",
        "| :--- | ---: | ---: | ---: | ---: |",
    ]
    for name, key in (("分层摘要", "summaries"), ("初始裁决", "initial_validation")):
        values = reuse[key]
        tokens = str(values["tokens"]) if values.get("tokens_complete", True) else "未完整计量"
        rows.append(
            f"| {name} | {values['queries']} | {values['hits']} | {values['model_tasks']} | {tokens} |"
        )
    rows.append("\n模型任务不等于物理请求次数；重试及后续调查计入扫描用量，历史用量不重复计入。\n")
    queries = reuse.get("investigation_queries", {})
    if queries.get("queries") or queries.get("replayed_queries"):
        rows.append(
            f"调查查询计划：查询 {queries['queries']}，命中 {queries['hits']}；"
            f"在当前代码上重放 {queries['replayed_queries']} 个查询，"
            f"返回结果变化 {queries['changed_results']} 个，失败 {queries['failed_queries']} 个。"
            "查询命中不等于结论复用；当前模型调查及证据裁决继续执行。\n"
        )
    if queries.get("condition_rows"):
        rows.append(
            f"成立条件：{queries['condition_rows']} 项，证据复核就绪 {queries['ready_conditions']} 项，"
            f"本轮确认复用 {queries['reconfirmed_conditions']} 项，重新调查 {queries['reopened_conditions']} 项；"
            f"查询范围新增成员 {queries['scope_added']} 个、删除成员 {queries['scope_removed']} 个，"
            f"剩余验证任务 {queries['remaining_tasks']} 项。\n"
        )
    return "\n".join(rows)
