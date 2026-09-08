"""Versioned, lossless human-review documents shared by the dashboard and export."""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any, Callable

import yaml

SCHEMA = "zscope.issue-markdown.v1"
REVIEW_START = "<!-- zscope-review:start -->"
REVIEW_END = "<!-- zscope-review:end -->"
MAX_DOCUMENT_BYTES = 16 * 1024 * 1024
VALIDATION_STATUSES = frozenset(
    {"pending", "needs_review", "validated", "rejected", "uncertain", "unvalidated"}
)
CONTEXT_FIELDS = (
    "validation_reasoning",
    "validator_verdict",
    "model_verdict",
    "policy_disposition",
    "evidence_hash",
    "decision_proof",
    "evidence_pack",
    "evidence_refs",
    "code_snippet",
    "positive_evidence",
    "negative_evidence",
    "source",
    "sink",
    "source_loc",
    "sink_loc",
    "description",
    "root_cause",
    "suggested_fix",
    "reasoning",
    "reasoning_process",
    "llm_explanation",
    "promotion_review_reason",
    "guard_analysis",
    "path_constraints",
    "call_path",
    "call_paths",
)


def digest(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(
            value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str
        ).encode("utf-8")
    ).hexdigest()


def issue_identity(issue: dict[str, Any]) -> str:
    # Scope even a legacy key to its exact occurrence; never use an array index or display text.
    stable = next(
        (
            issue.get(key)
            for key in (
                "finding_root_uid",
                "run_issue_uid",
                "validation_cluster_uid",
                "occurrence_uid",
                "candidate_uid",
                "dedup_key",
                "stable_fingerprint",
            )
            if issue.get(key)
        ),
        "",
    )
    return digest(
        [
            stable,
            *[
                issue.get(key)
                for key in ("id", "function", "location", "subcategory", "defect_class")
            ],
        ]
    )


def review_state(issue: dict[str, Any]) -> dict[str, str]:
    return {
        "validation_status": str(issue.get("validation_status") or "pending"),
        "user_rebuttal": str(issue.get("user_rebuttal") or ""),
    }


def context_revision(issue: dict[str, Any]) -> str:
    return digest({key: issue.get(key) for key in CONTEXT_FIELDS})


def review_revision(issue: dict[str, Any]) -> str:
    return digest({**review_state(issue), "context": context_revision(issue)})


class _ReviewLoader(yaml.SafeLoader):
    def compose_node(self, parent: Any, index: Any) -> Any:
        if self.check_event(yaml.AliasEvent):
            raise ValueError("Markdown metadata does not support YAML aliases")
        return super().compose_node(parent, index)

    def construct_mapping(self, node: Any, deep: bool = False) -> Any:
        result = {}
        for key_node, value_node in node.value:
            key = self.construct_object(key_node, deep=deep)
            if not isinstance(key, str) or key in result:
                raise ValueError("Duplicate or invalid Markdown metadata key")
            result[key] = self.construct_object(value_node, deep=deep)
        return result


def review_region(body: str) -> tuple[int, int] | None:
    """Recognize control comments only outside fenced code, never inside review examples."""
    markers: list[tuple[str, int, int]] = []
    fence = ""
    offset = 0
    for line in body.splitlines(keepends=True):
        stripped = line.rstrip("\n").rstrip("\r")
        match = re.match(r"^ {0,3}(`{3,}|~{3,})(.*)$", stripped)
        if match:
            run, rest = match.groups()
            if not fence:
                fence = run
            elif run[0] == fence[0] and len(run) >= len(fence) and not rest.strip():
                fence = ""
        elif not fence and stripped in {REVIEW_START, REVIEW_END}:
            markers.append((stripped, offset, offset + len(line)))
        offset += len(line)
    if not markers:
        return None
    if len(markers) != 2 or markers[0][0] != REVIEW_START or markers[1][0] != REVIEW_END:
        raise ValueError("人工说明边界损坏或重复")
    return markers[0][2], markers[1][1]


def parse_document(content: str) -> dict[str, Any]:
    if not isinstance(content, str) or len(content.encode("utf-8")) > MAX_DOCUMENT_BYTES:
        raise ValueError("Markdown 文件超过 16 MiB 或内容无效")
    content = content.removeprefix("\ufeff").replace("\r\n", "\n")
    match = re.match(r"\A---\n([\s\S]*?)\n---(?:\n|$)", content)
    if not match or len(match[1]) > 256 * 1024:
        raise ValueError("缺少有效的 Markdown 报告元数据；旧 HTML 请重新导出")
    try:
        meta = yaml.load(match[1], Loader=_ReviewLoader)
    except yaml.YAMLError as exc:
        raise ValueError("Markdown 报告元数据格式错误") from exc
    required = {
        "schema_version",
        "report_id",
        "issue_id",
        "base_revision",
        "base_context",
        "base_status",
        "base_user_rebuttal",
        "validation_status",
    }
    if not isinstance(meta, dict) or set(meta) != required:
        raise ValueError("Markdown 报告元数据字段不完整或包含未知字段")
    if any(not isinstance(value, str) for value in meta.values()):
        raise ValueError("Markdown 报告元数据必须为文本")
    if meta["schema_version"] != SCHEMA:
        raise ValueError("不支持此 Markdown 报告版本，请重新导出")
    if meta["validation_status"] not in VALIDATION_STATUSES:
        raise ValueError("非法验证状态")
    for key in ("report_id", "issue_id", "base_revision", "base_context"):
        if not re.fullmatch(r"[a-f0-9]{64}", meta[key]):
            raise ValueError(f"无效的 {key}")
    expected = digest(
        {
            "validation_status": meta["base_status"],
            "user_rebuttal": meta["base_user_rebuttal"],
            "context": meta["base_context"],
        }
    )
    if expected != meta["base_revision"]:
        raise ValueError("导出基线不一致，请重新导出")
    body = content[match.end() :]
    region = review_region(body)
    return {
        "metadata": meta,
        "body": body,
        "user_rebuttal": body[region[0] : region[1]].strip() if region else "",
    }


def parse_location(value: Any) -> dict[str, Any] | None:
    if isinstance(value, dict):
        path = next(
            (
                value.get(key)
                for key in ("path", "file", "file_path", "filename", "source_file", "sink_file")
                if value.get(key)
            ),
            None,
        )
        start = value.get("start_line", value.get("line", value.get("lineNumber")))
        end = value.get("end_line", start)
        try:
            if (
                path
                and start is not None
                and end is not None
                and int(start) > 0
                and int(end) >= int(start)
            ):
                return {"path": str(path).replace("\\", "/"), "start": int(start), "end": int(end)}
        except (ValueError, TypeError):
            pass
        return None
    if not isinstance(value, str):
        return None
    # A record reference like ir_path_slices:149 has no source extension.
    match = re.fullmatch(
        r"\s*(.+\.(?:c|h|cc|cpp|cxx|hh|hpp|hxx|java|py|go|rs|js|ts|ph)):(\d+)(?:-(\d+))?(?::\d+)?\s*",
        value,
    )
    if match and int(match[2]) > 0:
        return {
            "path": match[1].replace("\\", "/"),
            "start": int(match[2]),
            "end": max(int(match[2]), int(match[3] or match[2])),
        }
    return None


def parse_location_json(value: Any) -> dict[str, Any] | None:
    """Parse a location nested as a JSON string (e.g. security_obligation source/sink uid)."""
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except (ValueError, TypeError):
            return None
    return parse_location(value)


VERDICT_LABELS = {
    "verified": "已验证",
    "confirmed": "已确认",
    "rejected": "已否决",
    "uncertain": "证据不足",
    "pending": "待验证",
    "needs_review": "待人工复核",
    "unvalidated": "未启用验证",
    "valid": "有效",
    "true": "有效",
    "true_positive": "确认为真",
    "false": "无效",
    "false_positive": "确认为误报",
}


def verdict_label(value: Any) -> str:
    """Render a machine-readable verdict token as a readable label (fallback to raw text)."""
    text = str(value or "").strip()
    if not text:
        return ""
    return VERDICT_LABELS.get(text.lower(), text)


def endpoint_location(issue: dict[str, Any], kind: str) -> dict[str, Any] | None:
    """Resolve a Source/Sink coordinate from the explicit loc fields, evidence pack, or issue."""

    explicit = parse_location(issue.get(f"{kind}_loc"))
    if explicit:
        return explicit
    pack = issue.get("evidence_pack")
    if isinstance(pack, dict):
        for key in (f"{kind}_loc", f"{kind}_location"):
            located = parse_location(pack.get(key))
            if located:
                return located
        obligation = pack.get("security_obligation")
        if isinstance(obligation, dict):
            located = parse_location_json(obligation.get(f"{kind}_uid"))
            if located:
                return located
        path = pack.get("path")
        if isinstance(path, dict):
            line = path.get(f"{kind}_line")
            file_ref = path.get(f"{kind}_file") or path.get("file") or issue.get("file")
            if file_ref and line is not None:
                located = parse_location(file_ref)
                file_str = located["path"] if located else str(file_ref).replace("\\", "/")
                if file_str and not any(ch in file_str for ch in ("{", "}")):
                    try:
                        return {"path": file_str, "start": int(line), "end": int(line)}
                    except (ValueError, TypeError):
                        pass
    # Source and Sink both live in the finding's own function/file; the finding's reported
    # location is the strongest fallback when no per-endpoint coordinate was recorded.
    return parse_location(issue.get("location")) or parse_location(issue)


def endpoint_label(issue: dict[str, Any], kind: str) -> str:
    """Location suffix for a Source/Sink heading, or an empty string when unlocated."""
    loc = endpoint_location(issue, kind)
    if not loc:
        return ""
    start, end = loc["start"], loc["end"]
    span = f"{start}" if end == start else f"{start}-{end}"
    return f"（`{loc['path']}:{span}`）"


def _text(value: Any, fallback: str = "未提供") -> str:
    if value is None or value == "" or value == [] or value == {}:
        return fallback
    if not isinstance(value, str):
        value = json.dumps(value, ensure_ascii=False, indent=2)
    text = (
        str(value)
        .replace("\r\n", "\n")
        .replace(REVIEW_START, "\\" + REVIEW_START)
        .replace(REVIEW_END, "\\" + REVIEW_END)
    )
    # A model's unfinished fence must not consume later report sections or review markers.
    fence = ""
    for line in text.splitlines():
        match = re.match(r"^ {0,3}(`{3,}|~{3,})(.*)$", line)
        if match:
            run, rest = match.groups()
            if not fence:
                fence = run
            elif run[0] == fence[0] and len(run) >= len(fence) and not rest.strip():
                fence = ""
    return text + ("\n" + fence + "\n" if fence else "")


def _fenced(text: str, info: str) -> str:
    longest = max((len(m[0]) for m in re.finditer(r"`+", text)), default=0)
    fence = "`" * max(3, longest + 1)
    return f"{fence}{info}\n{text.rstrip(chr(10))}\n{fence}\n"


def build_document(
    issue: dict[str, Any],
    report_id: str,
    *,
    snippet_reader: Callable[[dict[str, Any]], dict[str, Any] | None] | None = None,
) -> str:
    state = review_state(issue)
    meta = {
        "schema_version": SCHEMA,
        "report_id": report_id,
        "issue_id": issue_identity(issue),
        "base_revision": review_revision(issue),
        "base_context": context_revision(issue),
        "base_status": state["validation_status"],
        "base_user_rebuttal": state["user_rebuttal"],
        "validation_status": state["validation_status"],
    }
    parts = [
        "---\n" + yaml.safe_dump(meta, allow_unicode=True, sort_keys=False) + "---\n",
        "# " + _text(issue.get("function"), "Issue").replace("\n", " ") + "\n",
        "## 问题概述\n",
        _text(issue.get("description")),
        f"\n- **位置**：{_text(issue.get('location'))}\n"
        f"- **类别 / 规则**：{_text(issue.get('defect_class') or issue.get('subcategory'))} / "
        f"{_text(issue.get('rule_id') or issue.get('rule'))}\n"
        f"- **风险 / 分数**：{_text(issue.get('impact_level'))} / "
        f"{_text(issue.get('final_score', issue.get('confidence')))}\n",
        "## 代码证据与路径\n",
        "**Source**" + endpoint_label(issue, "source") + "\n\n" + _text(issue.get("source")),
        "\n**Sink**" + endpoint_label(issue, "sink") + "\n\n" + _text(issue.get("sink")),
    ]
    pack = issue.get("evidence_pack")
    pack = pack if isinstance(pack, dict) else {}
    locations: list[dict[str, Any]] = []
    for raw in (
        issue.get("source_loc"),
        issue.get("sink_loc"),
        issue.get("location"),
        issue,
        pack.get("source_loc"),
        pack.get("sink_loc"),
        pack.get("source"),
        pack.get("sink"),
    ):
        loc = parse_location(raw)
        if loc and loc not in locations:
            locations.append(loc)
    refs = list(issue.get("evidence_refs") or pack.get("evidence_refs") or [])
    for ref in refs:
        loc = parse_location(ref)
        if loc and loc not in locations:
            locations.append(loc)
    anchors: dict[str, str] = {}
    block_number = 0

    def add_code(
        code: str, path: str, numbers: list[int], highlights: list[int], source: str
    ) -> str:
        nonlocal block_number
        block_number += 1
        anchor = f"code-{block_number}"
        language = (
            "java"
            if path.endswith(".java")
            else ("cpp" if path.endswith((".cpp", ".cc", ".cxx", ".hpp")) else "c")
        )
        metadata = {
            "id": anchor,
            "path": path,
            "numbers": numbers,
            "highlight": highlights,
            "source": source,
            "located": bool(numbers),
        }
        label = path + (f":{numbers[0]}-{numbers[-1]}" if numbers else "（片段内行号）")
        return f"\n**位置：{label}** · {source}\n\n" + _fenced(
            code,
            language + " zscope:" + json.dumps(metadata, ensure_ascii=False, separators=(",", ":")),
        )

    snippet = str(issue.get("code_snippet") or "").replace("\r\n", "\n").rstrip("\n")
    if snippet:
        numbered = [re.match(r"^\s*(\d+)\s*\| ?(.*)$", line) for line in snippet.split("\n")]
        has_numbers = all(numbered)
        nums = [int(m[1]) for m in numbered if m] if has_numbers else []
        code = "\n".join(m[2] for m in numbered if m) if has_numbers else snippet
        snippet_location = parse_location(issue.get("location")) or parse_location(issue)
        path = snippet_location["path"] if snippet_location else "未定位的报告片段"
        if not snippet_location:
            nums = []
            code = snippet
        parts.append(add_code(code, path, nums, [], "扫描报告原始片段"))
    for loc in locations:
        payload = snippet_reader(loc) if snippet_reader else None
        if payload and payload.get("lines"):
            lines = payload["lines"]
            numbers = [line["no"] for line in lines]
            parts.append(
                add_code(
                    "\n".join(line["text"] for line in lines),
                    loc["path"],
                    numbers,
                    [n for n in numbers if loc["start"] <= n <= loc["end"]],
                    "导出 / 查看时的当前源码摘录",
                )
            )
            anchors[digest(loc)] = f"code-{block_number}"
        else:
            parts.append(f"\n源码未能读取：`{loc['path']}:{loc['start']}`；保留位置供复核。\n")
    if not snippet and not locations:
        parts.append("\n未提供代码片段或可定位的源码坐标。\n")
    if issue.get("call_path") or issue.get("call_paths"):
        parts.extend(
            [
                "### 调用路径\n",
                _fenced(_text(issue.get("call_paths") or issue.get("call_path")), "text"),
            ]
        )
    parts.append("### 证据引用\n")
    for ref in refs:
        loc = parse_location(ref)
        anchor = anchors.get(digest(loc)) if loc else None
        label = str(ref).replace("[", "\\[").replace("]", "\\]")
        parts.append(f"- [{label}](#{anchor})" if anchor else f"- {_text(ref)}（未定位）")
    if not refs:
        parts.append("未提供证据引用")
    parts.append("\n## 正反证据\n")
    for heading, field in (
        ("正向证据", "positive_evidence"),
        ("反向证据 / 待复核点", "negative_evidence"),
    ):
        values = issue.get(field) or pack.get(field) or []
        parts.extend(
            [
                "### " + heading + "\n",
                (
                    "\n\n".join(_text(v) for v in values)
                    if isinstance(values, list) and values
                    else _text(values)
                ),
            ]
        )
    # Verdict tokens such as ``validator_verdict``/``model_verdict``/``policy_disposition``
    # carry machine-readable values ("verified", "confirmed", ...) instead of prose. Rendering
    # them verbatim produces orphan keywords under the section, so present them as one labelled,
    # human-readable judgment line while keeping the substantive reasoning fields as text.
    verdict_fields = (
        ("validator_verdict", "Validator 判定"),
        ("model_verdict", "模型判定"),
        ("policy_disposition", "策略处置"),
    )
    verdict_chunks = [
        f"{label}：{verdict_label(issue.get(field))}"
        for field, label in verdict_fields
        if issue.get(field)
    ]
    for heading, fields in (
        ("分析说明", ("reasoning", "reasoning_process", "guard_analysis", "path_constraints")),
        ("根因与影响", ("root_cause", "exploit_scenario")),
        ("修复建议", ("suggested_fix",)),
        (
            "Validator 验证结果",
            ("validation_reasoning", "llm_explanation", "promotion_review_reason"),
        ),
    ):
        parts.append("\n## " + heading + "\n")
        present = [_text(issue[field]) for field in fields if issue.get(field)]
        if heading == "Validator 验证结果" and verdict_chunks:
            present.append("**判定结论**：" + "；".join(verdict_chunks))
        parts.append("\n\n".join(present) if present else "未提供")
    if pack:
        parts.extend(["\n## 结构化证据\n", _fenced(_text(pack), "json")])
    parts.extend(
        [
            "\n## 历史人工说明（只读）\n",
            _text(state["user_rebuttal"], "暂无历史人工说明"),
            "\n## 本次人工反驳 / 复核说明\n",
            "填写本次复核依据；留空的条目在导入时不会更新。\n",
            REVIEW_START + "\n\n" + REVIEW_END + "\n",
        ]
    )
    return "\n\n".join(parts).rstrip() + "\n"