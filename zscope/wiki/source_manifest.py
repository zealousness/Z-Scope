"""Build and persist the deterministic explanatory-document manifest."""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, Mapping, Optional, Union

from .classification import classify_document, override_digest
from .discovery import DiscoveryResult, discover_markdown
from .markdown_parser import parse_markdown
from .models import ExcludedRecord, SourceManifest, SourceRecord


DISCOVERY_VERSION = "zscope-wiki-discovery.v1"
CLASSIFIER_VERSION = "zscope-wiki-classifier.v1"
PARSER_VERSION = "zscope-wiki-markdown-parser.v1"
_CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f]")


def _sha(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _root(value: Union[Path, str, object]) -> Path:
    return Path(getattr(value, "project_root", value)).expanduser().resolve()


def _source_id(project_id: str, relative_path: str) -> str:
    return "docsrc_" + hashlib.sha256(f"{project_id}\0markdown_document\0{relative_path}".encode()).hexdigest()[:32]


def _descriptor_id(relative_path: str, reason: str) -> str:
    return "docdesc_" + hashlib.sha256(f"{relative_path}\0{reason}".encode()).hexdigest()[:32]


def _manifest_payload(manifest: SourceManifest) -> Dict[str, Any]:
    value = manifest.to_dict()
    value.pop("source_manifest_digest", None)
    value.pop("created_at", None)
    for item in value.get("accepted", []):
        item.pop("observed_at", None)
    return value


def build_source_manifest(
    project_root: Union[Path, str, object],
    *,
    project_id: Optional[str] = None,
    overrides: Optional[Mapping[str, Any]] = None,
    max_file_bytes: int = 10 * 1024 * 1024,
    max_files: int = 10_000,
    max_total_bytes: int = 100 * 1024 * 1024,
    prune_paths: Optional[Iterable[Union[Path, str]]] = None,
    created_at: Optional[str] = None,
) -> SourceManifest:
    root = _root(project_root)
    pid = str(project_id or root.name or "project").strip()
    if not pid or len(pid) > 160 or _CONTROL_CHARS.search(pid):
        raise ValueError("project_id must be 1-160 characters without control text")
    discovered = discover_markdown(
        root,
        max_file_bytes=max_file_bytes,
        max_files=max_files,
        max_total_bytes=max_total_bytes,
        prune_paths=prune_paths,
    )
    accepted = []
    excluded = []
    for issue in discovered.issues:
        excluded.append(
            ExcludedRecord(
                descriptor_id=_descriptor_id(issue.relative_path, issue.reason),
                relative_path=issue.relative_path,
                classification=issue.classification if issue.classification in {"generated_artifact", "runtime_instruction", "benchmark_truth", "sensitive_rejected", "unknown"} else "unknown",
                reason=issue.reason,
                content_digest=issue.content_digest,
            )
        )
    observed = created_at or datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    for document in discovered.files:
        result = classify_document(document, overrides=overrides)
        if result.classification != "explanatory":
            excluded.append(
                ExcludedRecord(
                    descriptor_id="docdesc_" + hashlib.sha256(f"{result.relative_path}\0{result.reason}".encode()).hexdigest()[:32],
                    relative_path=result.relative_path,
                    classification=result.classification,
                    reason=result.reason,
                    content_digest=result.content_digest,
                )
            )
            continue
        sid = _source_id(pid, document.relative_path)
        parsed = parse_markdown(document, source_id=sid)
        accepted.append(
            SourceRecord(
                source_id=sid,
                project_id=pid,
                relative_path=document.relative_path,
                content_digest=document.content_digest,
                size_bytes=document.size_bytes,
                classification_reason=result.reason,
                input_language=parsed.input_language,
                module_hints=parsed.module_hints,
                frontmatter=parsed.frontmatter,
                observed_at=observed,
            )
        )
    accepted.sort(key=lambda item: item.relative_path)
    excluded.sort(key=lambda item: item.relative_path)
    root_facts = [
        (item.relative_path, item.size_bytes, item.content_digest)
        for item in discovered.files
    ]
    root_facts.extend(
        (item.relative_path, item.reason, item.content_digest or "")
        for item in discovered.issues
    )
    root_facts.append(("<unsupported>", discovered.unsupported_extensions))
    root_digest = _sha(json.dumps(sorted(root_facts, key=lambda item: repr(item)), sort_keys=True, separators=(",", ":")).encode("utf-8"))
    manifest = SourceManifest(
        schema_version="zscope.document-source-manifest.v1",
        project_id=pid,
        project_root_digest=root_digest,
        scanner={"discovery_version": DISCOVERY_VERSION, "classifier_version": CLASSIFIER_VERSION, "parser_version": PARSER_VERSION},
        accepted=tuple(accepted),
        excluded=tuple(excluded),
        unsupported_extensions=discovered.unsupported_extensions,
        override_digest=override_digest(overrides),
        source_manifest_digest="",
        created_at=observed,
    )
    digest = _sha(json.dumps(_manifest_payload(manifest), sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8"))
    return SourceManifest(
        schema_version=manifest.schema_version,
        project_id=manifest.project_id,
        project_root_digest=manifest.project_root_digest,
        scanner=manifest.scanner,
        accepted=manifest.accepted,
        excluded=manifest.excluded,
        unsupported_extensions=manifest.unsupported_extensions,
        override_digest=manifest.override_digest,
        source_manifest_digest=digest,
        created_at=manifest.created_at,
    )


def write_source_manifest(manifest: SourceManifest, path: Union[Path, str]) -> Path:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    if target.is_symlink():
        raise ValueError("source manifest path must not be a symlink")
    payload = (json.dumps(manifest.to_dict(), ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode("utf-8")
    fd, temp_name = tempfile.mkstemp(prefix=f".{target.name}.", suffix=".tmp", dir=str(target.parent))
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_name, target)
    finally:
        if os.path.exists(temp_name):
            os.unlink(temp_name)
    return target


build_manifest = build_source_manifest

__all__ = ["build_source_manifest", "build_manifest", "write_source_manifest"]
