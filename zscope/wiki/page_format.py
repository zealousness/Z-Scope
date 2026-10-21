"""Program-owned Markdown page and index format contracts."""

from __future__ import annotations

import re
from typing import Sequence, Tuple


HEADINGS = (
    "摘要",
    "适用范围和模块边界",
    "已声明约束",
    "限定条件、例外和常见误报模式",
    "冲突与未决问题",
    "来源索引",
)

INDEX_HEADINGS = (
    "项目概览",
    "模块",
    "API 与协议",
    "资源与锁",
    "冲突与过期",
    "维护信息",
)

_WIKILINK_RE = re.compile(
    r"\[\[(page_[a-z0-9_:-]+)(?:\|[^\]\r\n]{1,240})?\]\]"
)
_H2_RE = re.compile(r"^##[ \t]+(.+?)[ \t]*$", flags=re.MULTILINE)
_CJK_RE = re.compile(r"[\u3400-\u4dbf\u4e00-\u9fff]")
_UNSAFE_CONTROL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_SLUG_RE = re.compile(r"^(?!/)(?!.*\.\.)(?:[a-z0-9-]+/)*[a-z0-9-]+$")


def body_from_markdown(markdown: str) -> str:
    text = str(markdown)
    if text.startswith("---\n") or text.startswith("---\r\n"):
        lines = text.splitlines(keepends=True)
        for index in range(1, len(lines)):
            if lines[index].strip() == "---":
                return "".join(lines[index + 1 :])
    return text


def wikilink_targets(markdown: str) -> Tuple[str, ...]:
    return tuple(dict.fromkeys(match.group(1) for match in _WIKILINK_RE.finditer(str(markdown))))


def page_markdown_errors(markdown: str) -> Tuple[str, ...]:
    body = body_from_markdown(markdown).strip()
    headings = tuple(match.group(1).strip() for match in _H2_RE.finditer(body))
    errors = []
    if _UNSAFE_CONTROL_RE.search(body):
        errors.append("control_character")
    if headings != HEADINGS:
        errors.append("fixed_heading_sequence")
    prose = _H2_RE.sub("", body)
    if not _CJK_RE.search(prose):
        errors.append("missing_chinese_content")
    malformed = re.findall(r"\[\[page_[^\]\r\n]*", body)
    valid_starts = [match.group(0) for match in _WIKILINK_RE.finditer(body)]
    if len(malformed) != len(valid_starts):
        errors.append("malformed_wikilink")
    return tuple(errors)


def markdown_links_for_pages(
    pages: Sequence[dict],
    *,
    kinds: Sequence[str] = (),
    statuses: Sequence[str] = (),
) -> str:
    selected = []
    kind_set = set(kinds)
    status_set = set(statuses)
    for page in pages:
        front = page.get("frontmatter", {})
        if kind_set and str(front.get("page_kind")) not in kind_set:
            continue
        if status_set and str(front.get("status")) not in status_set:
            continue
        title = str(front.get("title") or page.get("canonical_slug") or page.get("page_id"))
        slug = str(page.get("canonical_slug") or front.get("canonical_slug") or "")
        if slug and _SLUG_RE.fullmatch(slug):
            title = _UNSAFE_CONTROL_RE.sub("", title).replace("\r", " ").replace("\n", " ")[:240]
            title = title.replace("\\", "\\\\").replace("[", "\\[").replace("]", "\\]")
            selected.append(f"- [{title}](pages/{slug}.md)")
    return "\n".join(selected) or "- 暂无"


__all__ = [
    "HEADINGS",
    "INDEX_HEADINGS",
    "body_from_markdown",
    "markdown_links_for_pages",
    "page_markdown_errors",
    "wikilink_targets",
]
