"""Deterministic SQLite index for accepted Markdown source documents.

The source index is deliberately independent from the compiled Wiki database.
It can be rebuilt from the YAML directory at any time and is therefore the last
resort used by the Validator when a Wiki revision or the Compiler is not
available.  Querying this module never calls an LLM and returns only bounded
excerpts of the original Markdown sections.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple, Union

from .classification import classify_document
from .context.obligation import (
    ConstraintObligation,
    _FACT_KIND_TERMS,
    canonical_obligation_kind,
)
from .discovery import DiscoveryResult, discover_markdown
from .markdown_parser import MarkdownDocument, parse_markdown
from .models import (
    DocumentSection,
    DiscoveredFile,
    SourceManifest,
    SourceRecord,
)
from .source_manifest import build_source_manifest

SCHEMA_VERSION = "zscope.source-index.v1"
DEFAULT_MAX_RESULTS = 5
DEFAULT_MAX_DOCUMENTS = 2
DEFAULT_MAX_TOKENS = None
HARD_MAX_TOKENS = None


SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS documents (
  source_id TEXT PRIMARY KEY,
  project_id TEXT NOT NULL,
  relative_path TEXT NOT NULL UNIQUE,
  content_digest TEXT NOT NULL,
  size_bytes INTEGER NOT NULL CHECK (size_bytes > 0),
  input_language TEXT NOT NULL CHECK (input_language IN ('zh-CN','en','mixed','unknown')),
  module_hints_json TEXT NOT NULL,
  frontmatter_json TEXT NOT NULL,
  observed_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS sections (
  section_id TEXT PRIMARY KEY,
  source_id TEXT NOT NULL REFERENCES documents(source_id) ON DELETE CASCADE,
  heading_path_json TEXT NOT NULL,
  heading_level INTEGER NOT NULL CHECK (heading_level BETWEEN 1 AND 6),
  start_line INTEGER NOT NULL CHECK (start_line > 0),
  end_line INTEGER NOT NULL CHECK (end_line >= start_line),
  text_digest TEXT NOT NULL,
  excerpt TEXT NOT NULL,
  symbols_json TEXT NOT NULL,
  module_hints_json TEXT NOT NULL,
  normative_terms_json TEXT NOT NULL,
  fragment_index INTEGER,
  fragment_count INTEGER,
  char_start INTEGER,
  char_end INTEGER
);

CREATE TABLE IF NOT EXISTS links (
  source_id TEXT NOT NULL REFERENCES documents(source_id) ON DELETE CASCADE,
  target TEXT NOT NULL,
  link_kind TEXT NOT NULL CHECK (link_kind IN ('relative_markdown','anchor','mailto','external_url')),
  PRIMARY KEY (source_id, target, link_kind)
);

CREATE TABLE IF NOT EXISTS classification_events (
  event_id INTEGER PRIMARY KEY AUTOINCREMENT,
  relative_path TEXT NOT NULL,
  classification TEXT NOT NULL CHECK (classification IN ('explanatory','generated_artifact','runtime_instruction','benchmark_truth','sensitive_rejected','unknown','unsupported')),
  reason TEXT NOT NULL,
  matched_rules_json TEXT NOT NULL,
  content_digest TEXT,
  observed_at TEXT NOT NULL
);
"""


def _json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _loads(value: str, default: Any) -> Any:
    try:
        return json.loads(value)
    except (TypeError, ValueError):
        return default


def _norm(value: Any) -> str:
    text = str(value or "").strip().casefold()
    text = text.strip("`'\"()[]{}<>")
    return text


def _contains(text: str, term: str) -> bool:
    """Case-insensitive token/phrase match, without requiring ASCII words."""

    needle = _norm(term)
    haystack = _norm(text)
    if not needle or not haystack:
        return False
    # Symbols such as ``foo_bar`` need an exact token boundary while Chinese
    # terms are most reliably found by substring.  Escape all user-provided
    # terms so this remains a pure deterministic search.
    if re.search(r"[A-Za-z0-9_]", needle):
        return (
            re.search(r"(?<![A-Za-z0-9_])" + re.escape(needle) + r"(?![A-Za-z0-9_])", haystack)
            is not None
        )
    return needle in haystack


def _flatten_frontmatter(value: Any) -> Iterable[str]:
    if isinstance(value, Mapping):
        for key, child in value.items():
            yield str(key)
            yield from _flatten_frontmatter(child)
    elif isinstance(value, (list, tuple, set)):
        for child in value:
            yield from _flatten_frontmatter(child)
    elif value is not None:
        yield str(value)


def _link_kind(target: str) -> str:
    lower = target.casefold()
    if lower.startswith("#"):
        return "anchor"
    if lower.startswith("mailto:"):
        return "mailto"
    if re.match(r"^[a-z][a-z0-9+.-]*://", lower):
        return "external_url"
    return "relative_markdown"


def _token_count(text: str) -> int:
    # A tokenizer is intentionally not a dependency of the fallback.  Four
    # UTF-8 characters is a conservative, stable approximation for context
    # budgeting and never affects ranking.
    return max(1, int(math.ceil(len(text) / 4.0)))


def _ref_id(source_id: str, section_id: str) -> str:
    return "docref_" + hashlib.sha256(f"{source_id}\0{section_id}".encode("utf-8")).hexdigest()[:32]


@dataclass(frozen=True)
class SourceIndexBuild:
    """Result of a rebuild, useful for audit logs without another DB table."""

    project_id: str
    source_manifest_digest: str
    document_count: int
    section_count: int
    link_count: int
    classification_event_count: int
    fts_enabled: bool


class SourceIndex:
    """SQLite-backed source index with a deterministic in-memory query path."""

    def __init__(self, path: Union[Path, str] = ":memory:") -> None:
        self.path = str(path)
        if self.path != ":memory:":
            Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        self.connection = sqlite3.connect(self.path)
        self.connection.row_factory = sqlite3.Row
        self.connection.execute("PRAGMA foreign_keys = ON")
        self._fts_enabled = False
        self._memory_rows: List[Dict[str, Any]] = []
        self._memory_rows_loaded = False
        self.project_id: Optional[str] = None
        self.source_manifest_digest: Optional[str] = None
        self._initialize()

    @property
    def fts_enabled(self) -> bool:
        return self._fts_enabled

    def _initialize(self) -> None:
        self.connection.executescript(SCHEMA_SQL)
        columns = {
            str(row["name"])
            for row in self.connection.execute("PRAGMA table_info(sections)").fetchall()
        }
        for name in ("fragment_index", "fragment_count", "char_start", "char_end"):
            if name not in columns:
                self.connection.execute(f"ALTER TABLE sections ADD COLUMN {name} INTEGER")
        # FTS5 is optional in system SQLite.  Its shadow tables are SQLite
        # internals and the only additional business object is sections_fts.
        try:
            self.connection.execute(
                "CREATE VIRTUAL TABLE IF NOT EXISTS sections_fts USING fts5(section_id UNINDEXED, heading_text, excerpt, symbols_text)"
            )
            self._fts_enabled = True
        except sqlite3.OperationalError:
            self._fts_enabled = False
        self.connection.commit()

    def close(self) -> None:
        self.connection.close()

    def __enter__(self) -> "SourceIndex":
        return self

    def __exit__(self, *_exc: Any) -> None:
        self.close()

    @staticmethod
    def _manifest(value: Any) -> SourceManifest:
        if isinstance(value, SourceManifest):
            return value
        if not isinstance(value, Mapping):
            raise TypeError("manifest must be a SourceManifest or mapping")
        accepted = []
        for item in value.get("accepted", ()):
            accepted.append(
                SourceRecord(
                    source_id=str(item["source_id"]),
                    project_id=str(item["project_id"]),
                    relative_path=str(item["relative_path"]),
                    content_digest=str(item["content_digest"]),
                    size_bytes=int(item["size_bytes"]),
                    classification_reason=str(item.get("classification_reason", "")),
                    input_language=str(item.get("input_language", "unknown")),
                    module_hints=tuple(item.get("module_hints", ())),
                    frontmatter=dict(item.get("frontmatter", {})),
                    observed_at=str(item.get("observed_at", value.get("created_at", ""))),
                )
            )
        excluded = []
        # Excluded records are not required to index accepted source, so keep a
        # tiny local representation only when a mapping is supplied.  Events
        # are generated from discovery below and do not depend on this tuple.
        from .models import ExcludedRecord

        for item in value.get("excluded", ()):
            excluded.append(
                ExcludedRecord(
                    descriptor_id=str(item["descriptor_id"]),
                    relative_path=str(item["relative_path"]),
                    classification=str(item["classification"]),
                    reason=str(item["reason"]),
                    content_digest=item.get("content_digest"),
                )
            )
        return SourceManifest(
            schema_version=str(value.get("schema_version", "zscope.document-source-manifest.v1")),
            project_id=str(value["project_id"]),
            project_root_digest=str(value["project_root_digest"]),
            scanner=dict(value.get("scanner", {})),
            accepted=tuple(accepted),
            excluded=tuple(excluded),
            unsupported_extensions={
                str(k): int(v) for k, v in dict(value.get("unsupported_extensions", {})).items()
            },
            override_digest=value.get("override_digest"),
            source_manifest_digest=str(value["source_manifest_digest"]),
            created_at=str(value.get("created_at", "")),
        )

    def rebuild(
        self,
        project_root: Union[Path, str, SourceManifest, Mapping[str, Any], None] = None,
        manifest: Optional[Union[SourceManifest, Mapping[str, Any]]] = None,
        *,
        discovered: Optional[DiscoveryResult] = None,
        project_id: Optional[str] = None,
        overrides: Optional[Mapping[str, Any]] = None,
        max_file_bytes: int = 10 * 1024 * 1024,
        max_files: int = 10_000,
        max_total_bytes: int = 100 * 1024 * 1024,
        prune_paths: Optional[Union[Path, str, Iterable[Union[Path, str]]]] = None,
        max_excerpt_chars: int = 8192,
    ) -> SourceIndexBuild:
        """Rebuild all index tables from the current explanatory Markdown.

        ``project_root`` is normally a path.  For convenience a manifest can
        be supplied as the first positional argument, but a root is still
        needed to read the source text unless ``discovered`` is provided.
        """

        if isinstance(project_root, (SourceManifest, Mapping)):
            if manifest is None:
                manifest = project_root
            project_root = None
        materialized_prune_paths: Tuple[Union[Path, str], ...]
        if prune_paths is None:
            materialized_prune_paths = ()
        elif isinstance(prune_paths, (str, Path)):
            materialized_prune_paths = (prune_paths,)
        else:
            materialized_prune_paths = tuple(prune_paths)
        if manifest is None:
            if project_root is None:
                raise ValueError("project_root or manifest is required")
            manifest_obj = build_source_manifest(
                project_root,
                project_id=project_id,
                overrides=overrides,
                max_file_bytes=max_file_bytes,
                max_files=max_files,
                max_total_bytes=max_total_bytes,
                prune_paths=materialized_prune_paths,
            )
        else:
            manifest_obj = self._manifest(manifest)
        if discovered is None:
            if project_root is None:
                raise ValueError("project_root is required when discovered is not supplied")
            discovered = discover_markdown(
                project_root,
                max_file_bytes=max_file_bytes,
                max_files=max_files,
                max_total_bytes=max_total_bytes,
                prune_paths=materialized_prune_paths,
            )

        accepted_by_path = {item.relative_path: item for item in manifest_obj.accepted}
        discovered_by_path = {item.relative_path: item for item in discovered.files}
        documents: List[Tuple[SourceRecord, DiscoveredFile, MarkdownDocument]] = []
        for relative_path in sorted(accepted_by_path):
            source = accepted_by_path[relative_path]
            document = discovered_by_path.get(relative_path)
            if document is None:
                raise ValueError(f"accepted source is absent from discovery: {relative_path}")
            if document.content_digest != source.content_digest:
                raise ValueError(f"source digest mismatch while indexing: {relative_path}")
            parsed = parse_markdown(
                document, source_id=source.source_id, max_excerpt_chars=max_excerpt_chars
            )
            documents.append((source, document, parsed))

        observed_at = manifest_obj.created_at or datetime.now(timezone.utc).replace(
            microsecond=0
        ).isoformat().replace("+00:00", "Z")
        self._memory_rows_loaded = False
        with self.connection:
            if self._fts_enabled:
                self.connection.execute("DELETE FROM sections_fts")
            self.connection.execute("DELETE FROM links")
            self.connection.execute("DELETE FROM sections")
            self.connection.execute("DELETE FROM documents")
            self.connection.execute("DELETE FROM classification_events")

            for source, _document, parsed in documents:
                self.connection.execute(
                    "INSERT INTO documents(source_id, project_id, relative_path, content_digest, size_bytes, input_language, module_hints_json, frontmatter_json, observed_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        source.source_id,
                        source.project_id,
                        source.relative_path,
                        source.content_digest,
                        source.size_bytes,
                        parsed.input_language,
                        _json(parsed.module_hints),
                        _json(parsed.frontmatter),
                        source.observed_at or observed_at,
                    ),
                )
                for section in parsed.sections:
                    self._insert_section(section)
                    for target in section.link_targets:
                        self.connection.execute(
                            "INSERT OR IGNORE INTO links(source_id, target, link_kind) VALUES (?, ?, ?)",
                            (source.source_id, target, _link_kind(target)),
                        )

            # Classification events are append-only within one rebuild and
            # include accepted documents, excluded files and discovery issues.
            for document in discovered.files:
                result = classify_document(document, overrides=overrides)
                self._insert_classification_event(
                    result.relative_path,
                    result.classification,
                    result.reason,
                    result.matched_rules,
                    result.content_digest,
                    observed_at,
                )
            for issue in discovered.issues:
                classification = (
                    issue.classification
                    if issue.classification
                    in {
                        "explanatory",
                        "generated_artifact",
                        "runtime_instruction",
                        "benchmark_truth",
                        "sensitive_rejected",
                        "unknown",
                        "unsupported",
                    }
                    else "unknown"
                )
                self._insert_classification_event(
                    issue.relative_path,
                    classification,
                    issue.reason,
                    (issue.reason,),
                    issue.content_digest,
                    observed_at,
                )

        self._load_memory_rows()
        self.project_id = manifest_obj.project_id
        self.source_manifest_digest = manifest_obj.source_manifest_digest
        section_count = sum(len(parsed.sections) for _source, _document, parsed in documents)
        link_count = int(self.connection.execute("SELECT COUNT(*) FROM links").fetchone()[0])
        event_count = int(
            self.connection.execute("SELECT COUNT(*) FROM classification_events").fetchone()[0]
        )
        return SourceIndexBuild(
            project_id=manifest_obj.project_id,
            source_manifest_digest=manifest_obj.source_manifest_digest,
            document_count=len(documents),
            section_count=section_count,
            link_count=link_count,
            classification_event_count=event_count,
            fts_enabled=self._fts_enabled,
        )

    build = rebuild
    rebuild_from_manifest = rebuild

    def _insert_section(self, section: DocumentSection) -> None:
        self.connection.execute(
            "INSERT INTO sections(section_id, source_id, heading_path_json, heading_level, start_line, end_line, text_digest, excerpt, symbols_json, module_hints_json, normative_terms_json, fragment_index, fragment_count, char_start, char_end) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                section.section_id,
                section.source_id,
                _json(section.heading_path),
                section.heading_level,
                section.start_line,
                section.end_line,
                section.text_digest,
                section.excerpt,
                _json(section.symbols),
                _json(section.module_hints),
                _json(section.normative_terms),
                section.fragment_index,
                section.fragment_count,
                section.char_start,
                section.char_end,
            ),
        )
        if self._fts_enabled:
            self.connection.execute(
                "INSERT INTO sections_fts(section_id, heading_text, excerpt, symbols_text) VALUES (?, ?, ?, ?)",
                (
                    section.section_id,
                    " / ".join(section.heading_path),
                    section.excerpt,
                    " ".join(section.symbols),
                ),
            )

    def _insert_classification_event(
        self,
        relative_path: str,
        classification: str,
        reason: str,
        matched_rules: Sequence[str],
        content_digest: Optional[str],
        observed_at: str,
    ) -> None:
        self.connection.execute(
            "INSERT INTO classification_events(relative_path, classification, reason, matched_rules_json, content_digest, observed_at) VALUES (?, ?, ?, ?, ?, ?)",
            (
                relative_path,
                classification,
                reason,
                _json(tuple(matched_rules)),
                content_digest,
                observed_at,
            ),
        )

    def _load_memory_rows(self) -> None:
        self._memory_rows = []
        query = """
        SELECT s.section_id, s.source_id, d.project_id, d.relative_path,
               d.content_digest, d.module_hints_json AS document_module_hints_json,
               d.frontmatter_json, s.heading_path_json, s.heading_level,
               s.start_line, s.end_line, s.text_digest, s.excerpt,
               s.symbols_json, s.module_hints_json AS section_module_hints_json,
               s.normative_terms_json, s.fragment_index, s.fragment_count,
               s.char_start, s.char_end
        FROM sections AS s JOIN documents AS d ON d.source_id = s.source_id
        ORDER BY d.relative_path, s.start_line, s.section_id
        """
        for row in self.connection.execute(query):
            self._memory_rows.append(dict(row))
        self._memory_rows_loaded = True

    def _rows(self) -> Iterable[Dict[str, Any]]:
        if not self._memory_rows_loaded:
            self._load_memory_rows()
        return self._memory_rows

    @staticmethod
    def _coerce_obligation(
        value: Union[ConstraintObligation, Mapping[str, Any]],
    ) -> ConstraintObligation:
        if isinstance(value, ConstraintObligation):
            return value
        if isinstance(value, Mapping):
            return ConstraintObligation.from_mapping(value)
        raise TypeError("obligation must be a ConstraintObligation or mapping")

    def _rank_row(
        self, row: Mapping[str, Any], obligation: ConstraintObligation
    ) -> Optional[Dict[str, Any]]:
        if obligation.project_id and str(row.get("project_id", "")) != obligation.project_id:
            return None
        heading_path = tuple(_loads(row["heading_path_json"], ()))
        symbols = tuple(_loads(row["symbols_json"], ()))
        section_modules = tuple(
            _loads(row.get("section_module_hints_json", row.get("module_hints_json", "[]")), ())
        )
        document_modules = tuple(_loads(row.get("document_module_hints_json", "[]"), ()))
        frontmatter = _loads(row.get("frontmatter_json", "{}"), {})
        excerpt = str(row.get("excerpt", ""))
        heading_text = " / ".join(heading_path)
        subject_terms = tuple(
            item
            for item in (
                *obligation.subject_ids,
                obligation.function_id,
                obligation.entry_function,
            )
            if item
        )
        query_terms = obligation.query_terms()
        reasons: List[str] = []
        score = 0.0

        exact_heading = any(_contains(heading_text, term) for term in subject_terms)
        exact_frontmatter = any(
            _contains(" ".join(_flatten_frontmatter(frontmatter)), term) for term in subject_terms
        )
        exact_symbol = any(_contains(" ".join(symbols), term) for term in subject_terms)
        exact_text_symbol = any(_contains(excerpt, term) for term in subject_terms)
        if exact_heading or exact_frontmatter or exact_symbol or exact_text_symbol:
            reasons.append("exact_symbol")
            # Heading/frontmatter exact references are the strongest signal;
            # code symbols and prose references follow them deterministically.
            score += (
                120.0
                if exact_heading
                else 115.0 if exact_frontmatter else 105.0 if exact_symbol else 90.0
            )

        module_terms = tuple(_norm(item) for item in obligation.module_ids if item)
        available_modules = tuple(_norm(item) for item in section_modules + document_modules)
        if module_terms and any(term in available_modules for term in module_terms):
            reasons.append("module_scope")
            score += 65.0

        if obligation.path_matches(str(row.get("relative_path", ""))):
            reasons.append("path_scope")
            score += 55.0

        fact_terms = tuple(
            _FACT_KIND_TERMS.get(canonical_obligation_kind(obligation.obligation_kind), ())
        )
        normative = tuple(_loads(row["normative_terms_json"], ()))
        fact_hit = bool(fact_terms and any(_contains(excerpt, term) for term in fact_terms))
        if fact_hit or (obligation.obligation_kind and obligation.obligation_kind in normative):
            reasons.append("fact_kind")
            score += 38.0

        # Resource/lock terms have their own schema reason.  They are still
        # deterministic lexical matches and never become proof by themselves.
        if obligation.resource_ids and any(
            _contains(excerpt, term) for term in obligation.resource_ids
        ):
            reasons.append("resource_identity")
            score += 34.0
        if obligation.lock_ids and any(_contains(excerpt, term) for term in obligation.lock_ids):
            reasons.append("lock_identity")
            score += 34.0

        # A generic fact-kind word (for example, ``range``) is not enough to
        # select a document: otherwise every API-range paragraph would be
        # returned for an unrelated candidate.  Require one stable identity or
        # scope anchor before applying lexical/fact-kind boosts.
        anchor_hit = bool(
            exact_heading
            or exact_frontmatter
            or exact_symbol
            or exact_text_symbol
            or module_terms
            and any(term in available_modules for term in module_terms)
            or obligation.path_matches(str(row.get("relative_path", "")))
            or obligation.resource_ids
            and any(_contains(excerpt, term) for term in obligation.resource_ids)
            or obligation.lock_ids
            and any(_contains(excerpt, term) for term in obligation.lock_ids)
        )
        if not anchor_hit:
            return None

        lexical_hits = sum(
            1 for term in query_terms if _contains(heading_text + "\n" + excerpt, term)
        )
        if lexical_hits:
            reasons.append("bm25")
            score += min(24.0, lexical_hits * 4.0)

        if score <= 0.0:
            return None
        return {
            "ref_id": _ref_id(str(row["source_id"]), str(row["section_id"])),
            "relative_path": str(row["relative_path"]),
            "heading_path": list(heading_path),
            "start_line": int(row["start_line"]),
            "end_line": int(row["end_line"]),
            "text": excerpt,
            "match_reasons": reasons,
            "score": round(score, 6),
            "_section_id": str(row["section_id"]),
            "_tokens": _token_count(excerpt),
        }

    def search(
        self,
        obligation: Union[ConstraintObligation, Mapping[str, Any]],
        *,
        max_results: Optional[int] = DEFAULT_MAX_RESULTS,
        max_documents: Optional[int] = DEFAULT_MAX_DOCUMENTS,
        max_tokens: Optional[int] = DEFAULT_MAX_TOKENS,
        hard_max_tokens: Optional[int] = HARD_MAX_TOKENS,
    ) -> List[Dict[str, Any]]:
        """Return ranked, bounded source excerpts for one obligation.

        Results are sorted by descending deterministic score, then relative
        path, line range and section ID.  No low-relevance sections are added
        merely to fill a budget.
        """

        if (max_results is not None and max_results <= 0) or (max_documents is not None and max_documents <= 0) or (max_tokens is not None and max_tokens <= 0):
            return []
        budgets = [int(value) for value in (max_tokens, hard_max_tokens, HARD_MAX_TOKENS) if value is not None]
        budget = min(budgets) if budgets else None
        query = self._coerce_obligation(obligation)
        ranked = []
        for row in self._rows():
            hit = self._rank_row(row_with_document_alias(row), query)
            if hit is not None:
                ranked.append(hit)
        ranked.sort(
            key=lambda item: (
                -float(item["score"]),
                item["relative_path"],
                int(item["start_line"]),
                item["_section_id"],
            )
        )

        selected: List[Dict[str, Any]] = []
        selected_documents: set[str] = set()
        used_tokens = 0
        for item in ranked:
            path = item["relative_path"]
            if max_documents is not None and path not in selected_documents and len(selected_documents) >= int(max_documents):
                continue
            text = item["text"]
            tokens = int(item["_tokens"])
            if budget is not None and used_tokens + tokens > budget:
                remaining = budget - used_tokens
                if not selected or remaining <= 0:
                    continue
                # Keep line provenance intact while bounding the returned
                # excerpt.  The source digest remains in the index, not in the
                # truncated display text.
                text = text[: max(4, remaining * 4)].rstrip()
                tokens = _token_count(text)
                if not text or tokens <= 0:
                    continue
            item = dict(item)
            item["text"] = text
            item.pop("_section_id", None)
            item.pop("_tokens", None)
            selected.append(item)
            selected_documents.add(path)
            used_tokens += tokens
            if max_results is not None and len(selected) >= int(max_results):
                break
        return selected


def row_with_document_alias(row: Mapping[str, Any]) -> Dict[str, Any]:
    """Normalize sqlite rows for ranking (section/document keys are distinct)."""

    result = dict(row)
    # Hand-built rows from small callers may use the historical single key.
    if "section_module_hints_json" not in result:
        result["section_module_hints_json"] = result.get("module_hints_json", "[]")
    if "document_module_hints_json" not in result:
        result["document_module_hints_json"] = "[]"
    return result


def build_source_index(
    project_root: Union[Path, str],
    path: Union[Path, str],
    *,
    manifest: Optional[Union[SourceManifest, Mapping[str, Any]]] = None,
    **kwargs: Any,
) -> SourceIndexBuild:
    """Convenience function used by orchestration and fixture tests."""

    with SourceIndex(path) as index:
        return index.rebuild(project_root, manifest, **kwargs)


__all__ = ["SourceIndex", "SourceIndexBuild", "build_source_index", "SCHEMA_SQL"]
