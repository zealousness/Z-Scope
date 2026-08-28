"""Read-only Wiki/source ProjectKnowledgeService for Validator shadow runs."""

from __future__ import annotations

import hashlib
import json
import fnmatch
import threading
from collections import Counter
from pathlib import Path
from typing import Any, Dict, Mapping, Optional, Sequence, Tuple

from .context.direct_documents import DirectDocumentResolver
from .context.obligation import ConstraintObligation
from .identity import digest_json
from .models import DirectResolution
from .source_index import SourceIndex
from .schema import SchemaValidationError, validate_instance


ZERO_DIGEST = "sha256:" + "0" * 64
RUNTIME_PROJECTION_MAX_ROWS = 10_000
RUNTIME_PROJECTION_MAX_JSON_CHARS = 1024 * 1024
RUNTIME_PROJECTION_MAX_MARKDOWN_CHARS = 2 * 1024 * 1024


def validate_project_knowledge(value: Mapping[str, Any]) -> Dict[str, Any]:
    """Validate the public context envelope and its cross-field invariants."""

    try:
        validate_instance(value, "zscope.validator-project-knowledge.v1")
    except SchemaValidationError:
        raise
    mode = str(value.get("resolution_mode"))
    constraints = list(value.get("constraints") or ())
    pages = list(value.get("page_excerpts") or ())
    sources = list(value.get("source_excerpts") or ())
    if mode == "wiki" and not value.get("wiki_revision_id"):
        raise ValueError("wiki project knowledge requires wiki_revision_id")
    if mode == "source_fallback" and (value.get("wiki_revision_id") is not None or constraints or pages):
        raise ValueError("source_fallback cannot carry Wiki revision, constraints, or pages")
    if mode == "none" and (value.get("wiki_revision_id") is not None or constraints or pages or sources or value.get("conflicts") or value.get("unknowns")):
        raise ValueError("none project knowledge must be empty")
    selection = value.get("selection") if isinstance(value.get("selection"), Mapping) else {}
    max_tokens = selection.get("max_tokens")
    if max_tokens is not None and int(selection.get("estimated_tokens", 0) or 0) > int(max_tokens):
        raise ValueError("project knowledge exceeds max_tokens")
    constraint_ids = {str(item.get("constraint_id")) for item in constraints if isinstance(item, Mapping)}
    page_ids = {str(item.get("page_id")) for item in pages if isinstance(item, Mapping)}
    source_ids = {str(item.get("ref_id")) for item in sources if isinstance(item, Mapping)}
    if not set(selection.get("selected_constraint_ids", ())) <= constraint_ids:
        raise ValueError("selected constraint is absent from context")
    if not set(selection.get("selected_page_ids", ())) <= page_ids:
        raise ValueError("selected page is absent from context")
    if not set(selection.get("selected_source_ref_ids", ())) <= source_ids | {str(ref) for item in constraints for ref in item.get("source_refs", ())} | {str(ref) for item in pages for ref in item.get("source_refs", ())}:
        raise ValueError("selected source ref is absent from context")
    for item in constraints:
        if item.get("status") != "active" or item.get("authority") != "documented_contract" or not item.get("source_refs"):
            raise ValueError("only active documented constraints with source refs may enter context")
    return dict(value)


def _tokens(text: str) -> int:
    return max(1, (len(text) + 3) // 4)


class ProjectKnowledgeService:
    """Select bounded documented context without changing Validator verdicts."""

    def __init__(
        self,
        *,
        source_index: SourceIndex,
        wiki_store: Optional[Any] = None,
        source_manifest_digest: Optional[str] = None,
        mode: str = "shadow",
        compiler_available: Optional[bool] = None,
        max_context_tokens: Optional[int] = None,
    ) -> None:
        if mode not in {"shadow", "active"}:
            raise ValueError("Wiki context mode must be shadow or active")
        self.source_index = source_index
        self.wiki_store = wiki_store
        self.source_manifest_digest = source_manifest_digest or getattr(source_index, "source_manifest_digest", None) or ZERO_DIGEST
        self.mode = mode
        self.compiler_available = compiler_available
        self.max_context_tokens = max_context_tokens
        self._telemetry_lock = threading.RLock()
        self._pinned_revision_id: Optional[str] = None
        self._pinned_constraints: Tuple[Dict[str, Any], ...] = ()
        self._pinned_refs: Dict[str, Dict[str, Any]] = {}
        self._pinned_pages: Tuple[Dict[str, Any], ...] = ()
        self._pinned_compiler_kind: Optional[str] = None
        self._pin_active_revision()
        self._telemetry = {
            "resolution_count": 0,
            "wiki_resolution_count": 0,
            "source_fallback_count": 0,
            "none_count": 0,
            "knowledge_context_tokens": 0,
            "incremental_fact_count": 0,
            "selected_constraint_ids": Counter(),
            "selected_page_ids": Counter(),
            "selected_source_ref_ids": Counter(),
            "fallback_reasons": Counter(),
        }

    def _pin_active_revision(self) -> None:
        """Snapshot one immutable revision before Validator workers start."""

        if self.wiki_store is None:
            return
        active = self.wiki_store.active_revision()
        if not active or active.get("source_manifest_digest") != self.source_manifest_digest:
            return
        revision_id = str(active.get("revision_id") or "")
        if not revision_id:
            return
        from .lint import lint_revision

        linted = lint_revision(self.wiki_store, revision_id)
        if not linted.passed:
            raise ValueError(
                "Wiki revision failed runtime lint: " + ", ".join(linted.errors[:8])
            )

        def rows(query: str):
            values = self.wiki_store.connection.execute(
                query + f" LIMIT {RUNTIME_PROJECTION_MAX_ROWS + 1}",
                (revision_id,),
            ).fetchall()
            if len(values) > RUNTIME_PROJECTION_MAX_ROWS:
                raise ValueError("Wiki runtime projection exceeds row limit")
            return values

        constraints = []
        for row in rows(
            "SELECT constraint_json FROM constraints WHERE revision_id=? ORDER BY constraint_id",
        ):
            raw_json = str(row["constraint_json"])
            if len(raw_json) > RUNTIME_PROJECTION_MAX_JSON_CHARS:
                raise ValueError("Wiki constraint projection exceeds size limit")
            try:
                value = json.loads(raw_json)
            except Exception:
                continue
            if isinstance(value, dict):
                constraints.append(value)

        refs: Dict[str, Dict[str, Any]] = {}
        for row in rows(
            "SELECT ref_id, ref_json FROM document_refs WHERE revision_id=? ORDER BY ref_id",
        ):
            raw_json = str(row["ref_json"])
            if len(raw_json) > RUNTIME_PROJECTION_MAX_JSON_CHARS:
                raise ValueError("Wiki ref projection exceeds size limit")
            try:
                value = json.loads(raw_json)
            except Exception:
                continue
            if isinstance(value, dict):
                refs[str(row["ref_id"])] = value

        pages = []
        for row in rows(
            "SELECT page_id, canonical_slug, frontmatter_json, markdown FROM pages WHERE revision_id=? ORDER BY canonical_slug, page_id",
        ):
            raw_frontmatter = str(row["frontmatter_json"])
            markdown = str(row["markdown"])
            if len(raw_frontmatter) > RUNTIME_PROJECTION_MAX_JSON_CHARS:
                raise ValueError("Wiki page frontmatter exceeds size limit")
            if len(markdown) > RUNTIME_PROJECTION_MAX_MARKDOWN_CHARS:
                raise ValueError("Wiki page Markdown exceeds size limit")
            try:
                frontmatter = json.loads(raw_frontmatter)
            except Exception:
                continue
            if not isinstance(frontmatter, dict):
                continue
            # Only current Wiki pages may enter the Validator runtime
            # projection.  Historical/stale pages remain available in the
            # revision for audit and maintenance, but are not queryable.
            if frontmatter.get("status") != "active":
                continue
            pages.append(
                {
                    "page_id": str(row["page_id"]),
                    "canonical_slug": str(row["canonical_slug"]),
                    "frontmatter": frontmatter,
                    "markdown": markdown,
                }
            )

        compiler_kind = None
        try:
            revision = self.wiki_store.revision_metadata(revision_id)
            compiler = revision.get("compiler") if isinstance(revision, Mapping) else None
            if isinstance(compiler, Mapping):
                compiler_kind = str(compiler.get("kind") or "") or None
        except (AttributeError, OSError, ValueError):
            pass

        self._pinned_revision_id = revision_id
        self._pinned_constraints = tuple(constraints)
        self._pinned_refs = refs
        self._pinned_pages = tuple(pages)
        self._pinned_compiler_kind = compiler_kind

    def _record_context(self, context: Mapping[str, Any]) -> Dict[str, Any]:
        with self._telemetry_lock:
            mode = str(context.get("resolution_mode", "none"))
            self._telemetry["resolution_count"] += 1
            if mode == "wiki":
                self._telemetry["wiki_resolution_count"] += 1
            elif mode == "source_fallback":
                self._telemetry["source_fallback_count"] += 1
            else:
                self._telemetry["none_count"] += 1
            selection = context.get("selection") if isinstance(context.get("selection"), Mapping) else {}
            self._telemetry["knowledge_context_tokens"] += int(selection.get("estimated_tokens", 0) or 0)
            # Background pages alone are not proof of Wiki injection.  Count only
            # structured constraints or page excerpts that carry constraint IDs;
            # this prevents a deterministic skeleton from being reported as an
            # injected knowledge signal.
            page_facts = sum(len(item.get("constraint_ids") or ()) for item in (context.get("page_excerpts") or ()) if isinstance(item, Mapping))
            facts = len(context.get("constraints") or ()) + page_facts
            self._telemetry["incremental_fact_count"] += facts
            for key, counter_name in (("selected_constraint_ids", "selected_constraint_ids"), ("selected_page_ids", "selected_page_ids"), ("selected_source_ref_ids", "selected_source_ref_ids")):
                counter = self._telemetry[counter_name]
                for value in selection.get(key, ()):
                    counter[str(value)] += 1
            reason = selection.get("fallback_reason")
            if reason:
                self._telemetry["fallback_reasons"][str(reason)] += 1
        return dict(context)

    def telemetry_snapshot(self) -> Dict[str, Any]:
        with self._telemetry_lock:
            return {
                "effective_mode": self.mode,
                "active_effective_mode": self.mode == "active",
                "resolution_count": int(self._telemetry["resolution_count"]),
                "wiki_resolution_count": int(self._telemetry["wiki_resolution_count"]),
                "source_fallback_count": int(self._telemetry["source_fallback_count"]),
                "none_count": int(self._telemetry["none_count"]),
                "knowledge_context_tokens": int(self._telemetry["knowledge_context_tokens"]),
                "incremental_fact_count": int(self._telemetry["incremental_fact_count"]),
                "wiki_context_injected": bool(self.mode == "active" and self._telemetry["wiki_resolution_count"] > 0 and self._telemetry["incremental_fact_count"] > 0 and self._telemetry["knowledge_context_tokens"] > 0),
                "selected_constraint_ids": dict(sorted(self._telemetry["selected_constraint_ids"].items())),
                "selected_page_ids": dict(sorted(self._telemetry["selected_page_ids"].items())),
                "selected_source_ref_ids": dict(sorted(self._telemetry["selected_source_ref_ids"].items())),
                "fallback_reasons": dict(sorted(self._telemetry["fallback_reasons"].items())),
            }

    @staticmethod
    def _obligation(candidate: Mapping[str, Any], evidence_pack: Optional[Mapping[str, Any]]) -> ConstraintObligation:
        evidence = evidence_pack or {}
        merged: Dict[str, Any] = dict(candidate)
        if isinstance(evidence.get("obligation"), Mapping):
            merged.update(evidence["obligation"])
        if "target" not in merged:
            merged["target"] = dict(merged)
        return ConstraintObligation.from_mapping(merged)

    def _active_projection(self) -> Tuple[Optional[str], Tuple[Dict[str, Any], ...], Mapping[str, Dict[str, Any]]]:
        return self._pinned_revision_id, self._pinned_constraints, self._pinned_refs

    @staticmethod
    def _constraint_matches(item: Mapping[str, Any], obligation: ConstraintObligation) -> bool:
        if item.get("status") != "active" or item.get("authority") != "documented_contract":
            return False
        kind = str(item.get("kind", ""))
        if obligation.obligation_kind not in {"", "unknown"} and kind != obligation.obligation_kind:
            return False
        subject = item.get("subject") if isinstance(item.get("subject"), Mapping) else {}
        canonical = str(subject.get("canonical_id", "")).casefold()
        targets = {str(value).casefold() for value in (obligation.subject_ids + ((obligation.function_id,) if obligation.function_id else ()))}
        if targets and canonical and not any(target == canonical or target.rsplit(":", 1)[-1] == canonical.rsplit(":", 1)[-1] for target in targets):
            return False
        scope = item.get("scope") if isinstance(item.get("scope"), Mapping) else {}
        scoped_modules = {str(value) for value in scope.get("module_ids", ())}
        if obligation.module_ids and scoped_modules and not scoped_modules.intersection(obligation.module_ids):
            return False
        globs = [str(value) for value in scope.get("path_globs", ())]
        if globs and obligation.candidate_file and not any(fnmatch.fnmatch(obligation.candidate_file, pattern) for pattern in globs):
            return False
        return True

    def _wiki_constraints(self, obligation: ConstraintObligation, max_constraints: int = 8) -> Tuple[Dict[str, Any], ...]:
        rid, constraints, refs = self._active_projection()
        if rid is None:
            return ()
        selected = []
        for item in constraints:
            source_refs = [str(ref) for ref in item.get("source_refs", ())]
            if not source_refs or any(ref not in refs or not bool(refs[ref].get("resolvable")) for ref in source_refs):
                continue
            if self._constraint_matches(item, obligation):
                selected.append(dict(item))
        selected.sort(key=lambda item: (str(item.get("kind", "")), str(item.get("subject", {}).get("canonical_id", "")), str(item.get("constraint_id", ""))))
        return tuple(selected[:max_constraints])

    def _wiki_pages(self, obligation: ConstraintObligation, constraint_ids: Sequence[str] = (), max_pages: int = 3) -> Tuple[Dict[str, Any], ...]:
        if self._pinned_revision_id is None:
            return ()
        selected = []
        for row in self._pinned_pages:
            front = row["frontmatter"]
            # Keep this guard even though _pin_active_revision filters the
            # snapshot, so manually supplied or future projections cannot
            # re-introduce non-active pages into Validator context.
            if front.get("status") != "active":
                continue
            subject = " ".join(str(item) for item in front.get("subject_ids", []))
            modules = " ".join(str(item) for item in front.get("module_ids", []))
            slug = str(row["canonical_slug"])
            if obligation.module_ids and not any(module in modules or module.removeprefix("module:") in slug for module in obligation.module_ids):
                if front.get("page_kind") != "project_overview":
                    continue
            text = row["markdown"]
            if obligation.subject_ids and not any(str(term).casefold() in (text + " " + subject).casefold() for term in obligation.subject_ids):
                if front.get("page_kind") not in {"project_overview", "source"}:
                    continue
            refs = []
            for line in text.splitlines():
                if "[docref_" in line:
                    start = line.find("[docref_") + 1
                    end = line.find("]", start)
                    if end > start:
                        refs.append(line[start:end])
            page_constraint_ids = [str(value) for value in front.get("constraint_ids", ()) if str(value) in set(constraint_ids)]
            if constraint_ids and not page_constraint_ids and front.get("page_kind") not in {"project_overview", "source"}:
                continue
            selected.append({"page_id": front["page_id"], "page_kind": front["page_kind"], "canonical_slug": slug, "heading_path": [front.get("title", slug)], "text": text[:12000], "constraint_ids": page_constraint_ids, "source_refs": refs})
            if len(selected) >= max_pages:
                break
        return tuple(selected)

    def resolve_for_candidate(
        self,
        candidate: Mapping[str, Any],
        evidence_pack: Optional[Mapping[str, Any]] = None,
        *,
        max_tokens: Optional[int] = None,
        compiler_available: Optional[bool] = None,
        fallback_reason: str = "compiler_unavailable",
    ) -> Dict[str, Any]:
        if max_tokens is None:
            max_tokens = self.max_context_tokens
        if max_tokens is not None and max_tokens < 256:
            raise ValueError("max_tokens must be at least 256")
        obligation = self._obligation(candidate, evidence_pack)
        candidate_file = obligation.candidate_file or "unknown.md"
        target = {
            "module_ids": list(obligation.module_ids),
            "subject_ids": list(obligation.subject_ids),
            "obligation_kind": obligation.obligation_kind,
            "candidate_file": candidate_file,
        }
        if obligation.function_id:
            target["function_id"] = obligation.function_id
        if obligation.entry_function:
            target["entry_function"] = obligation.entry_function
        constraints = self._wiki_constraints(obligation)
        constraint_ids = [str(item["constraint_id"]) for item in constraints]
        pages = self._wiki_pages(obligation, constraint_ids)
        effective_compiler = self.compiler_available if compiler_available is None else compiler_available
        if effective_compiler is None:
            effective_compiler = self._pinned_compiler_kind in {"llm", "mixed"}
        if (pages or constraints) and effective_compiler:
            constraint_items = []
            for item in constraints:
                constraint_items.append({key: item.get(key) for key in ("constraint_id", "kind", "statement", "normalized_value", "authority", "normativity", "status", "source_refs", "page_refs") if key in item} | {"subject_id": str(item.get("subject", {}).get("canonical_id", ""))})
            selected_source_refs = list(dict.fromkeys(
                [ref for p in pages for ref in p["source_refs"]]
                + [ref for item in constraint_items for ref in item.get("source_refs", ())]
            ))
            context: Dict[str, Any] = {
                "schema_version": "zscope.validator-project-knowledge.v1",
                "resolution_mode": "wiki",
                "project_id": obligation.project_id or getattr(self.source_index, "project_id", "project"),
                "wiki_revision_id": self._pinned_revision_id,
                "source_manifest_digest": self.source_manifest_digest,
                "context_digest": ZERO_DIGEST,
                "target": target,
                "constraints": constraint_items,
                "page_excerpts": list(pages),
                "source_excerpts": [],
                "conflicts": [],
                "unknowns": [],
                "selection": {"max_tokens": max_tokens, "estimated_tokens": sum(_tokens(p["text"]) for p in pages) + sum(_tokens(str(item["statement"])) for item in constraint_items), "selected_constraint_ids": [item["constraint_id"] for item in constraint_items], "omitted_constraint_count": 0, "selected_page_ids": [p["page_id"] for p in pages], "selected_source_ref_ids": selected_source_refs, "ranking_version": "wiki-constraint-rank.v1", "fallback_reason": None},
            }
            if max_tokens is not None:
                context["selection"]["estimated_tokens"] = min(context["selection"]["estimated_tokens"], max_tokens)
            context["context_digest"] = digest_json({key: value for key, value in context.items() if key != "context_digest"})
            return self._record_context(context)
        resolution = DirectDocumentResolver(self.source_index).resolve(obligation, max_results=4, max_tokens=max_tokens, fallback_reason=fallback_reason)
        mode = resolution.resolution_mode
        excerpts = [item.to_dict() for item in resolution.source_excerpts]
        estimate = sum(_tokens(item["text"]) for item in excerpts)
        if max_tokens is not None:
            estimate = min(max_tokens, estimate)
        context = {
            "schema_version": "zscope.validator-project-knowledge.v1",
            "resolution_mode": mode,
            "project_id": obligation.project_id or getattr(self.source_index, "project_id", "project"),
            "wiki_revision_id": None,
            "source_manifest_digest": self.source_manifest_digest,
            "context_digest": ZERO_DIGEST,
            "target": target,
            "constraints": [],
            "page_excerpts": [],
            "source_excerpts": excerpts,
            "conflicts": [],
            "unknowns": [],
            "selection": {"max_tokens": max_tokens, "estimated_tokens": estimate, "selected_constraint_ids": [], "omitted_constraint_count": 0, "selected_page_ids": [], "selected_source_ref_ids": [item["ref_id"] for item in excerpts], "ranking_version": "source-index.v1", "fallback_reason": resolution.fallback_reason},
        }
        context["context_digest"] = digest_json({key: value for key, value in context.items() if key != "context_digest"})
        return self._record_context(context)

    resolve = resolve_for_candidate


__all__ = ["ProjectKnowledgeService", "validate_project_knowledge"]
