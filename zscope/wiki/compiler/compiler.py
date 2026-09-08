"""Wiki Compiler adapter with deterministic no-LLM degradation."""

from __future__ import annotations

import json
import re
import unicodedata
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Callable, Dict, List, Mapping, Optional, Sequence

from .chunker import CompilerChunk, build_chunk_workset, plan_compiler_chunks
from .changeset import validate_changeset
from .workset import split_workset_by_document


def program_summary(
    outcome: str,
    proposal_count: int = 0,
    source_results: Sequence[Mapping[str, Any]] = (),
) -> str:
    """Return a deterministic, non-semantic compiler summary.

    The summary is a ChangeSet/report convenience field owned by the program;
    it is intentionally not accepted from the LLM and must not affect
    revision identity or Validator matching.
    """

    if outcome == "changed":
        source_count = sum(
            1
            for item in source_results
            if str(item.get("source_ref", "")).startswith("docsrc_")
        )
        noun = "source" if source_count == 1 else "sources"
        constraint_noun = "constraint" if proposal_count == 1 else "constraints"
        return (
            f"Compiled {proposal_count} documented {constraint_noun} from "
            f"{source_count} Markdown {noun}."
        )
    if outcome == "background_only":
        return "No documented constraints found."
    if outcome == "extraction_failed":
        return "Constraint compilation failed; no new content was published."
    if outcome == "source_rejected":
        return "Source was rejected; no new content was published."
    return "Constraint compilation completed."


class WikiCompiler:
    """Compile a bounded workset with document-local concurrent chunks."""

    def __init__(
        self,
        provider: Optional[Callable[[Mapping[str, Any]], Any]] = None,
        *,
        max_workers: int = 4,
    ) -> None:
        self.provider = provider
        if isinstance(max_workers, bool) or int(max_workers) <= 0:
            raise ValueError("wiki_compiler_workers must be a positive integer")
        self.max_workers = int(max_workers)

    def compile(self, workset: Mapping[str, Any]) -> Dict[str, Any]:
        added_source_ids = list(workset.get("added_source_ids", []))
        changed_source_ids = list(workset.get("changed_source_ids", []))
        removed_source_ids = list(workset.get("removed_source_ids", []))
        source_ids = added_source_ids + changed_source_ids + removed_source_ids

        # A model invocation is scoped to exactly one Markdown document.  Keep
        # publication atomic by compiling children first and combining their
        # semantic proposals into the parent ChangeSet before returning.
        active_source_ids = tuple(dict.fromkeys((*added_source_ids, *changed_source_ids)))
        if active_source_ids and self.provider is not None:
            if len(active_source_ids) == 1 and not removed_source_ids:
                try:
                    chunks = plan_compiler_chunks(
                        workset,
                        completion_tokens=getattr(self.provider, "max_tokens", None),
                    )
                except Exception:
                    chunks = ()
                if len(chunks) <= 1:
                    return self._compile_one(workset, source_ids)
            return self._compile_documents(workset, active_source_ids)

        # A removed-only delta has no current source text and must not ask the
        # LLM to reconstruct the deleted document.
        # RevisionStore performs deterministic ref/constraint stale
        # propagation while publishing the current manifest revision.
        if removed_source_ids and not added_source_ids and not changed_source_ids:
            result = {
                "schema_version": "zscope.wiki-changeset.v1",
                "workset_id": workset["workset_id"],
                "base_revision_id": workset.get("base_revision_id"),
                "outcome": "background_only",
                "source_results": [
                    {
                        "source_ref": source_id,
                        "extraction_status": "no_constraints_found",
                        "source_refs_used": [],
                        "reason": "removed_source_invalidated_deterministically",
                    }
                    for source_id in removed_source_ids
                ],
                "constraint_proposals": [],
                "summary": "Removed-only sources were handled deterministically; no content was regenerated.",
                "compiler": {
                    "kind": "deterministic",
                    "identity": "zscope.wiki.removal.v1",
                    "prompt_version": None,
                    "model": None,
                },
            }
            return validate_changeset(result, workset)

        # A noop has no document payload and must never invoke the LLM.  It is
        # represented by the same deterministic background result as the
        # no-provider degradation path.
        if self.provider is None or not source_ids:
            results = [
                {
                    "source_ref": source_id,
                    "extraction_status": "no_constraints_found",
                    "source_refs_used": [],
                    "reason": "deterministic_compiler_does_not_infer_constraints",
                }
                for source_id in source_ids
            ] or [
                {
                    "source_ref": "docsrc_none",
                    "extraction_status": "no_constraints_found",
                    "source_refs_used": [],
                    "reason": "empty_workset",
                }
            ]
            result = {
                "schema_version": "zscope.wiki-changeset.v1",
                "workset_id": workset["workset_id"],
                "base_revision_id": workset.get("base_revision_id"),
                "outcome": "background_only",
                "source_results": results,
                "constraint_proposals": [],
                "summary": program_summary("background_only", source_results=results),
                "compiler": {
                    "kind": "deterministic",
                    "identity": "zscope.wiki.deterministic.v1",
                    "prompt_version": None,
                    "model": None,
                },
            }
            return validate_changeset(result, workset)
        return self._compile_one(workset, source_ids)

    def _compile_one(self, workset: Mapping[str, Any], source_ids: Sequence[str]) -> Dict[str, Any]:
        try:
            raw = self.provider(workset) if self.provider is not None else None
            if self.provider is None:
                raise ValueError("deterministic compiler does not invoke provider")
            if isinstance(raw, str):
                raw = json.loads(raw)
            if not isinstance(raw, Mapping):
                raise ValueError("provider output is not an object")
            enriched = dict(raw)
            # Summary is program-owned.  Ignore any legacy/provider-supplied
            # value and replace it after deriving the result outcome.
            enriched.pop("summary", None)
            enriched.setdefault(
                "compiler",
                {
                    "kind": "llm",
                    "identity": "zscope.wiki.provider.v1",
                    "prompt_version": None,
                    "model": None,
                },
            )
            enriched["summary"] = program_summary(
                str(enriched.get("outcome", "")),
                len(enriched.get("constraint_proposals", ()))
                if isinstance(enriched.get("constraint_proposals"), list)
                else 0,
                enriched.get("source_results", ())
                if isinstance(enriched.get("source_results"), list)
                else (),
            )
            return validate_changeset(enriched, workset)
        except Exception as exc:
            return {
                "schema_version": "zscope.wiki-changeset.v1",
                "workset_id": workset["workset_id"],
                "base_revision_id": workset.get("base_revision_id"),
                "outcome": "extraction_failed",
                "source_results": [
                    {
                        "source_ref": source_ids[0] if source_ids else "docsrc_none",
                        "extraction_status": "extraction_failed",
                        "source_refs_used": [],
                        "reason": str(exc)[:1000],
                    }
                ],
                "constraint_proposals": [],
                "summary": program_summary("extraction_failed"),
            }

    compile_workset = compile

    def _compile_documents(
        self, workset: Mapping[str, Any], source_ids: Sequence[str]
    ) -> Dict[str, Any]:
        """Compile each active source in concurrent chunks, then merge atomically."""

        completion_tokens = getattr(self.provider, "max_tokens", None)
        if completion_tokens is None and self.provider is not None:
            completion_tokens = getattr(getattr(self.provider, "llm_client", None), "max_tokens", None)

        children = split_workset_by_document(workset)
        child_by_source = {
            str(
                (child.get("added_source_ids") or child.get("changed_source_ids") or [""])[0]
            ): child
            for child in children
        }
        source_results: List[Dict[str, Any]] = []
        proposals: List[Mapping[str, Any]] = []
        compiler_metadata: List[Mapping[str, Any]] = []
        failed = False
        for source_id in sorted(dict.fromkeys(str(item) for item in source_ids)):
            child = child_by_source.get(str(source_id))
            if child is None:
                failed = True
                source_results.append(
                    {
                        "source_ref": str(source_id),
                        "extraction_status": "extraction_failed",
                        "source_refs_used": [],
                        "reason": "document Workset was not created",
                    }
                )
                continue
            try:
                chunks = plan_compiler_chunks(
                    child,
                    completion_tokens=completion_tokens,
                )
            except Exception as exc:
                failed = True
                source_results.append(
                    {
                        "source_ref": str(source_id),
                        "extraction_status": "extraction_failed",
                        "source_refs_used": [],
                        "reason": str(exc)[:1000],
                    }
                )
                continue
            if not chunks:
                source_results.append(
                    {
                        "source_ref": str(source_id),
                        "extraction_status": "no_constraints_found",
                        "source_refs_used": [],
                        "reason": "no_source_sections",
                    }
                )
                continue
            chunk_results: Dict[int, Dict[str, Any]] = {}
            with ThreadPoolExecutor(
                max_workers=min(self.max_workers, len(chunks)),
                thread_name_prefix="zscope-wiki-chunk",
            ) as executor:
                def _run_chunk(chunk: CompilerChunk) -> Dict[str, Any]:
                    # Preserve the historical one-document Workset identity
                    # when no split is needed; this keeps custom providers and
                    # replay fixtures backwards compatible.
                    target = child if len(chunks) == 1 else build_chunk_workset(child, chunk)
                    return self._compile_one(target, [source_id])

                futures = {
                    executor.submit(_run_chunk, chunk): chunk
                    for chunk in chunks
                }
                for future in as_completed(futures):
                    chunk = futures[future]
                    try:
                        chunk_results[chunk.ordinal] = future.result()
                    except Exception as exc:
                        chunk_results[chunk.ordinal] = {
                            "schema_version": "zscope.wiki-changeset.v1",
                            "workset_id": build_chunk_workset(child, chunk)["workset_id"],
                            "base_revision_id": child.get("base_revision_id"),
                            "outcome": "extraction_failed",
                            "source_results": [{
                                "source_ref": str(source_id),
                                "extraction_status": "extraction_failed",
                                "source_refs_used": [],
                                "reason": str(exc)[:1000],
                            }],
                            "constraint_proposals": [],
                            "summary": program_summary("extraction_failed"),
                        }
            for ordinal in sorted(chunk_results):
                result = chunk_results[ordinal]
                if str(result.get("outcome", "")) in {"extraction_failed", "source_rejected"}:
                    failed = True
                child_results = result.get("source_results", ())
                if isinstance(child_results, list):
                    source_results.extend(
                        dict(item) for item in child_results if isinstance(item, Mapping)
                    )
                child_proposals = result.get("constraint_proposals", ())
                if isinstance(child_proposals, list):
                    proposals.extend(item for item in child_proposals if isinstance(item, Mapping))
                metadata = result.get("compiler")
                if isinstance(metadata, Mapping):
                    compiler_metadata.append(metadata)

        # Mixed deltas retain deterministic stale propagation for removed
        # sources, but removed documents never receive a model call.
        for source_id in sorted(
            dict.fromkeys(str(item) for item in workset.get("removed_source_ids", ()))
        ):
            source_results.append(
                {
                    "source_ref": str(source_id),
                    "extraction_status": "no_constraints_found",
                    "source_refs_used": [],
                    "reason": "removed_source_invalidated_deterministically",
                }
            )

        # Collapse chunk-local source results back to the parent contract. A
        # source remains one logical ingestion unit even when it required many
        # model requests.
        aggregated_results: List[Dict[str, Any]] = []
        result_source_ids = tuple(
            sorted(
                set(str(item) for item in source_ids)
                | set(str(item) for item in workset.get("removed_source_ids", ()))
            )
        )
        for source_id in result_source_ids:
            items = [
                item for item in source_results
                if str(item.get("source_ref", "")) == source_id
            ]
            if not items:
                continue
            used = sorted({
                str(ref)
                for item in items
                for ref in item.get("source_refs_used", ())
            })
            statuses = {str(item.get("extraction_status", "")) for item in items}
            status = (
                "extraction_failed"
                if "extraction_failed" in statuses
                else "constraints_found"
                if "constraints_found" in statuses
                else "no_constraints_found"
            )
            aggregated_results.append({
                "source_ref": source_id,
                "extraction_status": status,
                "source_refs_used": used,
                "reason": f"compiled {len(items)} compiler chunk(s)",
            })
        source_results = aggregated_results

        outcome: str
        if failed:
            outcome = "extraction_failed"
            proposals = []
        elif proposals:
            outcome = "changed"
        else:
            outcome = "background_only"
        proposals = self._dedupe_proposals(proposals)
        summary = program_summary(outcome, len(proposals), source_results)

        result = {
            "schema_version": "zscope.wiki-changeset.v1",
            "workset_id": workset["workset_id"],
            "base_revision_id": workset.get("base_revision_id"),
            "outcome": outcome,
            "source_results": source_results
            or [
                {
                    "source_ref": "docsrc_none",
                    "extraction_status": "no_constraints_found",
                    "source_refs_used": [],
                    "reason": "empty_workset",
                }
            ],
            "constraint_proposals": proposals,
            "summary": summary,
        }
        if compiler_metadata and not failed:
            identities = {str(item.get("identity", "")) for item in compiler_metadata}
            kinds = {str(item.get("kind", "")) for item in compiler_metadata}
            first = dict(compiler_metadata[0])
            if len(identities) > 1 or len(kinds) > 1:
                first["kind"] = "mixed"
            result["compiler"] = first
        return validate_changeset(result, workset)

    @staticmethod
    def _dedupe_proposals(proposals: Sequence[Mapping[str, Any]]) -> List[Mapping[str, Any]]:
        """Merge semantically identical proposals emitted by multiple chunks."""
        result: List[Mapping[str, Any]] = []
        positions: Dict[tuple[str, ...], int] = {}
        for proposal in proposals:
            statement = unicodedata.normalize("NFKC", str(proposal.get("statement", "")))
            statement = re.sub(r"\s+", " ", statement).strip()
            key = (
                str(proposal.get("subject_kind", "")),
                str(proposal.get("subject_id", "")),
                str(proposal.get("kind", "")),
                str(proposal.get("normativity", "")),
                statement,
            )
            index = positions.get(key)
            if index is None:
                item = dict(proposal)
                item["source_refs"] = sorted(set(str(ref) for ref in item.get("source_refs", ())))
                positions[key] = len(result)
                result.append(item)
                continue
            item = dict(result[index])
            item["source_refs"] = sorted(
                set(str(ref) for ref in item.get("source_refs", ()))
                | set(str(ref) for ref in proposal.get("source_refs", ()))
            )
            result[index] = item
        return result
