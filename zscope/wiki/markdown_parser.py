"""Small, dependency-light Markdown section parser for source evidence."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple, Union

from .classification import parse_frontmatter
from .models import DiscoveredFile, DocumentSection


_ATX = re.compile(r"^\s{0,3}(#{1,6})\s+(.+?)\s*#*\s*$")
_SETEXT = re.compile(r"^\s{0,3}(=+|-+)\s*$")
_LINK = re.compile(r"!?(?:\[[^\]]*\])\(([^)]+)\)")
_MODULE = re.compile(r"\b(module:[a-z0-9_.:/-]+)\b", re.I)
_SYMBOL = re.compile(r"`([^`\n]+)`")
_NORMATIVE = (
    (re.compile(r"(?i)\bmust\s+not\b|\bshall\s+not\b"), "must_not"),
    (re.compile(r"(?i)\bmust\b"), "must"),
    (re.compile(r"(?i)\bshall\b"), "shall"),
    (re.compile(r"(?i)\brequired\b"), "required"),
    (re.compile(r"(?i)\bonly\b"), "only"),
    (re.compile(r"(?i)\bshould\b"), "should"),
    (re.compile(r"(?i)\brecommended\b"), "recommended"),
    (re.compile(r"(?i)\brange\b|\bbetween\b|\binclusive\b"), "range"),
    (re.compile(r"(?i)\bown(?:ership)?\b|\bborrow(?:s|ed)?\b"), "ownership"),
    (re.compile(r"(?i)\block(?:s|ed|ing)?\b"), "lock"),
    (re.compile(r"(?i)\berror\b|\bfail(?:s|ure)?\b"), "error"),
)


@dataclass(frozen=True)
class MarkdownDocument:
    source_id: str
    frontmatter: Dict[str, Any]
    sections: Tuple[DocumentSection, ...]
    input_language: str
    module_hints: Tuple[str, ...]

    def __iter__(self):
        return iter(self.sections)

    def __len__(self) -> int:
        return len(self.sections)


def _digest(value: str) -> str:
    return "sha256:" + hashlib.sha256(value.encode("utf-8")).hexdigest()


def _source_id(relative_path: str, source_id: Optional[str]) -> str:
    if source_id:
        return source_id
    return "docsrc_" + hashlib.sha256(relative_path.encode("utf-8")).hexdigest()[:32]


def _heading_lines(lines: Sequence[str]) -> List[Tuple[int, int, str]]:
    headings: List[Tuple[int, int, str]] = []
    in_fence = False
    fence = ""
    i = 0
    while i < len(lines):
        line = lines[i]
        match_fence = re.match(r"^\s*(`{3,}|~{3,})", line)
        if match_fence:
            marker = match_fence.group(1)[0]
            if not in_fence:
                in_fence, fence = True, marker
            elif marker == fence:
                in_fence = False
            i += 1
            continue
        if not in_fence:
            match = _ATX.match(line)
            if match:
                headings.append((i + 1, len(match.group(1)), match.group(2).strip()))
            elif i + 1 < len(lines) and line.strip() and _SETEXT.match(lines[i + 1]):
                level = 1 if lines[i + 1].lstrip().startswith("=") else 2
                headings.append((i + 1, level, line.strip()))
                i += 1
        i += 1
    return headings


def _section_features(text: str) -> Tuple[Tuple[str, ...], Tuple[str, ...], Tuple[str, ...], Tuple[str, ...]]:
    symbols = tuple(sorted(set(item.strip() for item in _SYMBOL.findall(text) if item.strip())))
    modules = tuple(sorted(set(item.lower() for item in _MODULE.findall(text))))
    normative = tuple(label for pattern, label in _NORMATIVE if pattern.search(text))
    links = tuple(sorted(set(match.group(1).strip() for match in _LINK.finditer(text) if match.group(1).strip())))
    return symbols, modules, normative, links


def _bounded_chunks(
    lines: Sequence[str], start: int, end: int, max_chars: int
) -> List[Tuple[int, int, str]]:
    """Split a section at paragraph/line boundaries while preserving locations."""

    if start > end:
        return [(start, start, "")]
    chunks: List[Tuple[int, int, str]] = []
    chunk_start = start
    chunk_lines: List[str] = []
    chunk_size = 0
    for line_no in range(start, end + 1):
        line = lines[line_no - 1]
        addition = len(line) + (1 if chunk_lines else 0)
        # Prefer a paragraph boundary, but hard split an unusually long line.
        if chunk_lines and chunk_size + addition > max_chars:
            chunks.append((chunk_start, line_no - 1, "\n".join(chunk_lines).strip()))
            chunk_start = line_no
            chunk_lines = []
            chunk_size = 0
        if len(line) > max_chars and not chunk_lines:
            # A single physical line cannot be split without overlapping the
            # line locator; retain a bounded excerpt for that exceptional case.
            chunks.append((line_no, line_no, line[:max_chars]))
            chunk_start = line_no + 1
            continue
        chunk_lines.append(line)
        chunk_size += len(line) + (1 if len(chunk_lines) > 1 else 0)
    if chunk_lines or not chunks:
        chunks.append((chunk_start, end, "\n".join(chunk_lines).strip()))
    return [(s, max(s, e), text) for s, e, text in chunks if text]


def _language(text: str) -> str:
    chinese = bool(re.search(r"[\u3400-\u9fff]", text))
    latin = bool(re.search(r"[A-Za-z]", text))
    if chinese and latin:
        return "mixed"
    if chinese:
        return "zh-CN"
    if latin:
        return "en"
    return "unknown"


def parse_markdown(
    document: Union[DiscoveredFile, str],
    source_id: Optional[str] = None,
    *,
    relative_path: str = "document.md",
    max_excerpt_chars: int = 8192,
) -> MarkdownDocument:
    if max_excerpt_chars <= 0:
        raise ValueError("max_excerpt_chars must be positive")
    if isinstance(document, str):
        raw = document.encode("utf-8")
        document = DiscoveredFile(
            relative_path=relative_path,
            absolute_path=Path(relative_path),
            size_bytes=len(raw),
            content_digest="sha256:" + hashlib.sha256(raw).hexdigest(),
            text=document,
        )
    sid = _source_id(document.relative_path, source_id)
    # splitlines keeps line coordinates stable for CRLF and LF alike
    lines = document.text.splitlines()
    if not lines:
        lines = [""]
    headings = _heading_lines(lines)
    boundaries: List[Tuple[int, int, str, int]] = []
    if not headings:
        boundaries = [(1, len(lines), "Document", 1)]
    else:
        first_line = headings[0][0]
        if any(line.strip() for line in lines[: first_line - 1]):
            boundaries.append((1, first_line - 1, "Document", 1))
        for index, (line_no, level, title) in enumerate(headings):
            end = headings[index + 1][0] - 1 if index + 1 < len(headings) else len(lines)
            boundaries.append((line_no, end, title, level))

    sections: List[DocumentSection] = []
    stack: List[Tuple[int, str]] = []
    all_text = "\n".join(lines)
    number = 0
    for start, end, title, level in boundaries:
        if title == "Document" and level == 1 and start == 1 and headings:
            path = ("Document",)
        else:
            while stack and stack[-1][0] >= level:
                stack.pop()
            stack.append((level, title))
            path = tuple(item[1] for item in stack)[-8:]
        for chunk_start, chunk_end, raw in _bounded_chunks(lines, start, end, max_excerpt_chars):
            number += 1
            symbols, modules, normative, links = _section_features(raw)
            sections.append(
                DocumentSection(
                    section_id=f"docsec_{hashlib.sha256(f'{sid}:{number}:{chunk_start}:{chunk_end}:{_digest(raw)}'.encode()).hexdigest()[:32]}",
                    source_id=sid,
                    heading_path=path,
                    heading_level=level,
                    start_line=chunk_start,
                    end_line=max(chunk_start, chunk_end),
                    text_digest=_digest(raw),
                    excerpt=raw[:max_excerpt_chars] or title,
                    symbols=symbols,
                    module_hints=modules,
                    normative_terms=normative,
                    link_targets=links,
                )
            )
    modules = tuple(sorted(set(item.lower() for item in _MODULE.findall(all_text))))
    return MarkdownDocument(sid, parse_frontmatter(document.text), tuple(sections), _language(all_text), modules)


parse_document = parse_markdown
MarkdownParser = parse_markdown

parse_sections = lambda document, source_id=None, **kwargs: parse_markdown(document, source_id, **kwargs).sections

__all__ = ["MarkdownDocument", "parse_markdown", "parse_document", "parse_sections", "MarkdownParser"]
