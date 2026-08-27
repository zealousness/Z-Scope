"""Shared read-only Wiki status/query control surface for Web and MCP."""

from __future__ import annotations

import re
from pathlib import Path, PurePosixPath
from typing import Any, Dict, Mapping, Optional, Sequence, Union

from .service import ProjectKnowledgeService, validate_project_knowledge
from .source_index import SourceIndex
from .source_manifest import build_source_manifest
from .store.revision_store import (
    WikiStore,
    read_active_pointer,
    read_revision_metadata,
    resolve_project_state_root,
)


_CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f]")
_WINDOWS_ABSOLUTE = re.compile(r"^[A-Za-z]:/")
_STATUS_ERROR_MESSAGES = {
    "invalid_active_pointer": "Wiki active pointer is invalid or unavailable.",
    "invalid_revision": "Wiki active revision is invalid or unavailable.",
    "stale_revision": "Wiki active revision does not match its source manifest.",
}


def _state_root(project_root: Path, state_dir: str) -> Path:
    return resolve_project_state_root(project_root, state_dir)


def _status_base(state_dir: str) -> Dict[str, Any]:
    return {
        "schema_version": "zscope.wiki-status.v1",
        "available": False,
        "state_dir": PurePosixPath(str(state_dir).replace("\\", "/")).as_posix(),
        "active": None,
        "revision": None,
        "error": None,
    }


def _status_error(payload: Dict[str, Any], code: str) -> Dict[str, Any]:
    payload["error"] = {
        "code": code,
        "message": _STATUS_ERROR_MESSAGES[code],
    }
    return payload


def _bounded_text(value: Any, max_length: int = 300) -> Optional[str]:
    if value is None:
        return None
    return str(value)[:max_length]


def wiki_status(project_root: Union[Path, str], *, state_dir: str = ".zscope_knowledge/wiki") -> Dict[str, Any]:
    root = Path(project_root).resolve()
    state = _state_root(root, state_dir)
    payload = _status_base(state_dir)
    try:
        active = read_active_pointer(state)
    except ValueError:
        return _status_error(payload, "invalid_active_pointer")
    if active is None:
        return payload
    revision_id = str(active["revision_id"])
    try:
        revision = read_revision_metadata(state, revision_id)
    except ValueError:
        return _status_error(payload, "invalid_revision")
    if revision.get("source_manifest_digest") != active.get("source_manifest_digest"):
        return _status_error(payload, "stale_revision")
    compiler = revision.get("compiler") if isinstance(revision.get("compiler"), Mapping) else {}
    lint = revision.get("lint") if isinstance(revision.get("lint"), Mapping) else {}
    if lint.get("status") != "passed":
        return _status_error(payload, "invalid_revision")
    payload.update(
        {
            "available": True,
            "active": {
                "revision_id": revision_id,
                "source_manifest_digest": str(active["source_manifest_digest"]),
                "updated_at": _bounded_text(active.get("updated_at"), 80),
            },
            "revision": {
                "schema_version": "zscope.wiki-revision.v1",
                "revision_id": revision_id,
                "parent_revision_id": _bounded_text(revision.get("parent_revision_id")),
                "source_manifest_digest": str(revision["source_manifest_digest"]),
                "compiler": {
                    "kind": _bounded_text(compiler.get("kind"), 40),
                    "identity": _bounded_text(compiler.get("identity")),
                    "prompt_version": _bounded_text(compiler.get("prompt_version")),
                    "model": _bounded_text(compiler.get("model")),
                },
                "lint": {
                    "status": "passed",
                    "errors": int(lint.get("errors", 0) or 0),
                    "warnings": int(lint.get("warnings", 0) or 0),
                },
                "created_at": _bounded_text(revision.get("created_at"), 80),
            },
        }
    )
    return payload


def _normalize_query_inputs(
    subjects: Sequence[str],
    fact_kind: str,
    candidate_file: str,
    max_tokens: Optional[int],
) -> tuple[list[str], str, str, Optional[int]]:
    if isinstance(subjects, (str, bytes)):
        raise ValueError("subjects must be an array")
    normalized_subjects = [str(value).strip() for value in subjects]
    if (
        not normalized_subjects
        or len(normalized_subjects) > 32
        or any(
            not value or len(value) > 300 or _CONTROL_CHARS.search(value)
            for value in normalized_subjects
        )
    ):
        raise ValueError("subjects must contain 1-32 bounded text values")
    normalized_fact_kind = str(fact_kind or "unknown").strip() or "unknown"
    if len(normalized_fact_kind) > 80 or _CONTROL_CHARS.search(normalized_fact_kind):
        raise ValueError("fact_kind must be bounded text")
    normalized_file = str(candidate_file or "").replace("\\", "/").strip()
    path = PurePosixPath(normalized_file)
    if (
        len(normalized_file) > 500
        or normalized_file.startswith("/")
        or _WINDOWS_ABSOLUTE.match(normalized_file)
        or ".." in path.parts
        or _CONTROL_CHARS.search(normalized_file)
    ):
        raise ValueError("candidate_file must be project-root relative")
    if max_tokens is None:
        return normalized_subjects, normalized_fact_kind, normalized_file, None
    if isinstance(max_tokens, bool):
        raise ValueError("max_tokens must be an integer")
    try:
        normalized_tokens = int(max_tokens)
    except (TypeError, ValueError) as exc:
        raise ValueError("max_tokens must be an integer") from exc
    if normalized_tokens < 256:
        raise ValueError("max_tokens must be at least 256")
    return normalized_subjects, normalized_fact_kind, normalized_file, normalized_tokens


def wiki_query(
    project_root: Union[Path, str],
    *,
    subjects: Sequence[str],
    fact_kind: str = "unknown",
    candidate_file: str = "",
    max_tokens: Optional[int] = None,
    project_id: Optional[str] = None,
    state_dir: str = ".zscope_knowledge/wiki",
    overrides: Optional[Mapping[str, Any]] = None,
    max_file_bytes: int = 10 * 1024 * 1024,
    max_files: int = 10_000,
    max_total_bytes: int = 100 * 1024 * 1024,
) -> Dict[str, Any]:
    subjects, fact_kind, candidate_file, max_tokens = _normalize_query_inputs(
        subjects,
        fact_kind,
        candidate_file,
        max_tokens,
    )
    root = Path(project_root).resolve()
    state = _state_root(root, state_dir)
    manifest = build_source_manifest(
        root,
        project_id=project_id or root.name,
        overrides=overrides,
        max_file_bytes=max_file_bytes,
        max_files=max_files,
        max_total_bytes=max_total_bytes,
        prune_paths=(state.relative_to(root),),
    )
    index = SourceIndex(":memory:")
    index.rebuild(
        root,
        manifest=manifest,
        overrides=overrides,
        prune_paths=(state.relative_to(root),),
    )
    store = None
    fallback_reason = "no_active_revision"
    try:
        active = read_active_pointer(state)
        if active is not None:
            revision = read_revision_metadata(state, str(active["revision_id"]))
            if active.get("source_manifest_digest") != manifest.source_manifest_digest:
                fallback_reason = "stale_revision"
            elif revision.get("source_manifest_digest") != manifest.source_manifest_digest:
                fallback_reason = "stale_revision"
            else:
                compiler = revision.get("compiler") if isinstance(revision.get("compiler"), Mapping) else {}
                fallback_reason = (
                    "no_wiki_match"
                    if compiler.get("kind") in {"llm", "mixed"}
                    else "compiler_unavailable"
                )
                # Query is a read-only control-plane operation.  Opening a
                # missing/corrupt state must not create directories, a DB, or
                # run schema initialization as a side effect.
                store = WikiStore(state, read_only=True)
    except (OSError, ValueError):
        fallback_reason = "invalid_revision"
        if store is not None:
            store.close()
            store = None
    try:
        try:
            service = ProjectKnowledgeService(
                source_index=index,
                wiki_store=store,
                source_manifest_digest=manifest.source_manifest_digest,
                mode="active",
            )
        except Exception:
            if store is not None:
                store.close()
                store = None
            fallback_reason = "invalid_revision"
            service = ProjectKnowledgeService(
                source_index=index,
                wiki_store=None,
                source_manifest_digest=manifest.source_manifest_digest,
                mode="active",
            )
        context = service.resolve_for_candidate(
            {
                "project_id": manifest.project_id,
                "subject_ids": subjects,
                "fact_kind": fact_kind,
                "candidate_file": candidate_file,
            },
            max_tokens=max_tokens,
            fallback_reason=fallback_reason,
        )
        return validate_project_knowledge(context)
    finally:
        if store is not None:
            store.close()
        index.close()


__all__ = ["wiki_status", "wiki_query"]
