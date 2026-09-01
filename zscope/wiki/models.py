"""Small, serialization-friendly models shared by Wiki ingestion stages."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


Classification = str


@dataclass(frozen=True)
class DiscoveredFile:
    relative_path: str
    absolute_path: Path
    size_bytes: int
    content_digest: str
    text: str
    is_symlink: bool = False


@dataclass(frozen=True)
class DiscoveryIssue:
    relative_path: str
    reason: str
    classification: str = "unknown"
    content_digest: Optional[str] = None


@dataclass(frozen=True)
class ClassificationResult:
    relative_path: str
    classification: Classification
    reason: str
    matched_rules: Tuple[str, ...] = ()
    content_digest: Optional[str] = None
    override_id: Optional[str] = None


@dataclass(frozen=True)
class DocumentSection:
    section_id: str
    source_id: str
    heading_path: Tuple[str, ...]
    heading_level: int
    start_line: int
    end_line: int
    text_digest: str
    excerpt: str
    symbols: Tuple[str, ...] = ()
    module_hints: Tuple[str, ...] = ()
    normative_terms: Tuple[str, ...] = ()
    link_targets: Tuple[str, ...] = ()
    fragment_index: Optional[int] = None
    fragment_count: Optional[int] = None
    char_start: Optional[int] = None
    char_end: Optional[int] = None


@dataclass(frozen=True)
class SourceRecord:
    source_id: str
    project_id: str
    relative_path: str
    content_digest: str
    size_bytes: int
    classification_reason: str
    input_language: str
    module_hints: Tuple[str, ...]
    frontmatter: Dict[str, Any]
    observed_at: str

    def to_schema_dict(self) -> Dict[str, Any]:
        value: Dict[str, Any] = {
            "schema_version": "zscope.document-source.v1",
            "source_id": self.source_id,
            "project_id": self.project_id,
            "source_kind": "markdown_document",
            "relative_path": self.relative_path,
            "content_digest": self.content_digest,
            "size_bytes": self.size_bytes,
            "classification": "explanatory",
            "classification_reason": self.classification_reason,
            "input_language": self.input_language,
            "module_hints": list(self.module_hints),
            "observed_at": self.observed_at,
        }
        if self.frontmatter:
            value["frontmatter"] = self.frontmatter
        return value


@dataclass(frozen=True)
class ExcludedRecord:
    descriptor_id: str
    relative_path: str
    classification: str
    reason: str
    content_digest: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        value: Dict[str, Any] = {
            "descriptor_id": self.descriptor_id,
            "relative_path": self.relative_path,
            "classification": self.classification,
            "reason": self.reason,
        }
        if self.content_digest is not None:
            value["content_digest"] = self.content_digest
        return value


@dataclass(frozen=True)
class SourceManifest:
    schema_version: str
    project_id: str
    project_root_digest: str
    scanner: Dict[str, str]
    accepted: Tuple[SourceRecord, ...]
    excluded: Tuple[ExcludedRecord, ...]
    unsupported_extensions: Dict[str, int]
    override_digest: Optional[str]
    source_manifest_digest: str
    created_at: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "project_id": self.project_id,
            "project_root_digest": self.project_root_digest,
            "scanner": dict(self.scanner),
            "accepted": [item.to_schema_dict() for item in self.accepted],
            "excluded": [item.to_dict() for item in self.excluded],
            "unsupported_extensions": dict(self.unsupported_extensions),
            "override_digest": self.override_digest,
            "source_manifest_digest": self.source_manifest_digest,
            "created_at": self.created_at,
        }


@dataclass(frozen=True)
class SourceExcerpt:
    ref_id: str
    relative_path: str
    heading_path: Tuple[str, ...]
    start_line: int
    end_line: int
    text: str
    match_reasons: Tuple[str, ...]
    score: float

    def to_dict(self) -> Dict[str, Any]:
        return {
            "ref_id": self.ref_id,
            "relative_path": self.relative_path,
            "heading_path": list(self.heading_path),
            "start_line": self.start_line,
            "end_line": self.end_line,
            "text": self.text,
            "match_reasons": list(self.match_reasons),
            "score": self.score,
        }


@dataclass(frozen=True)
class DirectResolution:
    source_excerpts: Tuple[SourceExcerpt, ...]
    fallback_reason: Optional[str]

    @property
    def resolution_mode(self) -> str:
        return "source_fallback" if self.source_excerpts else "none"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "resolution_mode": self.resolution_mode,
            "source_excerpts": [item.to_dict() for item in self.source_excerpts],
            "fallback_reason": self.fallback_reason,
        }
