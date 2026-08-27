#!/usr/bin/env python3
"""Replay five LLM Wiki context modes without running a scan or benchmark."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Dict, Mapping, Optional, Sequence

from zscope.wiki.identity import digest_json
from zscope.wiki.service import ProjectKnowledgeService, validate_project_knowledge
from zscope.wiki.source_index import SourceIndex
from zscope.wiki.source_manifest import build_source_manifest
from zscope.wiki.store.revision_store import WikiStore


SCHEMA_VERSION = "zscope.wiki-context-replay.v1"


def _candidate_id(value: Mapping[str, Any], ordinal: int) -> str:
    return str(value.get("candidate_uid") or value.get("id") or f"candidate:{ordinal}")


def _compact_context(context: Mapping[str, Any]) -> Dict[str, Any]:
    selection = context.get("selection") if isinstance(context.get("selection"), Mapping) else {}
    return {
        "resolution_mode": context.get("resolution_mode"),
        "wiki_revision_id": context.get("wiki_revision_id"),
        "source_manifest_digest": context.get("source_manifest_digest"),
        "context_digest": context.get("context_digest"),
        "constraint_count": len(context.get("constraints") or ()),
        "page_excerpt_count": len(context.get("page_excerpts") or ()),
        "source_excerpt_count": len(context.get("source_excerpts") or ()),
        "estimated_tokens": int(selection.get("estimated_tokens", 0) or 0),
        "selected_constraint_ids": list(selection.get("selected_constraint_ids", ())),
        "selected_page_ids": list(selection.get("selected_page_ids", ())),
        "selected_source_ref_ids": list(selection.get("selected_source_ref_ids", ())),
        "fallback_reason": selection.get("fallback_reason"),
    }


def replay_context_modes(
    project_root: Path,
    candidates: Sequence[Mapping[str, Any]],
    *,
    state_root: Optional[Path] = None,
    max_tokens: int = 2000,
) -> Dict[str, Any]:
    root = Path(project_root).resolve()
    manifest = build_source_manifest(root, project_id=root.name)
    index = SourceIndex(":memory:")
    index.rebuild(root, manifest=manifest)
    wiki_state = Path(state_root or root / ".zscope_knowledge" / "wiki")
    store = WikiStore(wiki_state) if (wiki_state / "active.json").is_file() else None
    modes: Dict[str, Dict[str, Any]] = {
        name: {"context_injected_to_validator": name == "active", "candidates": []}
        for name in ("control", "direct", "shadow", "active", "unavailable")
    }
    services = {
        "direct": ProjectKnowledgeService(source_index=index, source_manifest_digest=manifest.source_manifest_digest, mode="active", compiler_available=False),
        "shadow": ProjectKnowledgeService(source_index=index, wiki_store=store, source_manifest_digest=manifest.source_manifest_digest, mode="shadow") if store else ProjectKnowledgeService(source_index=index, source_manifest_digest=manifest.source_manifest_digest, mode="shadow", compiler_available=False),
        "active": ProjectKnowledgeService(source_index=index, wiki_store=store, source_manifest_digest=manifest.source_manifest_digest, mode="active") if store else ProjectKnowledgeService(source_index=index, source_manifest_digest=manifest.source_manifest_digest, mode="active", compiler_available=False),
        "unavailable": ProjectKnowledgeService(source_index=index, source_manifest_digest=manifest.source_manifest_digest, mode="active", compiler_available=False),
    }
    try:
        for ordinal, candidate in enumerate(candidates):
            candidate_id = _candidate_id(candidate, ordinal)
            modes["control"]["candidates"].append({"candidate_id": candidate_id, "resolution_mode": "off", "context_digest": None, "estimated_tokens": 0})
            for name, service in services.items():
                reason = "compiler_disabled" if name == "direct" else "compiler_unavailable"
                context = service.resolve_for_candidate(candidate, max_tokens=max_tokens, fallback_reason=reason)
                validate_project_knowledge(context)
                modes[name]["candidates"].append({"candidate_id": candidate_id, **_compact_context(context)})
        for name, service in services.items():
            modes[name]["telemetry"] = service.telemetry_snapshot()
        modes["control"]["telemetry"] = {
            "effective_mode": "off",
            "wiki_context_injected": False,
            "resolution_count": 0,
            "knowledge_context_tokens": 0,
            "incremental_fact_count": 0,
        }
        return {
            "schema_version": SCHEMA_VERSION,
            "project_root": str(root),
            "project_id": manifest.project_id,
            "source_manifest_digest": manifest.source_manifest_digest,
            "candidate_input_digest": digest_json(list(candidates)),
            "candidate_count": len(candidates),
            "modes": modes,
            "benchmark_executed": False,
            "llm_called": False,
        }
    finally:
        if store is not None:
            store.close()
        index.close()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", required=True, type=Path)
    parser.add_argument("--candidates", required=True, type=Path)
    parser.add_argument("--state-root", type=Path)
    parser.add_argument("--max-tokens", type=int, default=2000)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    value = json.loads(args.candidates.read_text(encoding="utf-8"))
    if not isinstance(value, list) or not all(isinstance(item, dict) for item in value):
        raise SystemExit("candidates must be a JSON array of objects")
    result = replay_context_modes(args.root, value, state_root=args.state_root, max_tokens=args.max_tokens)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
