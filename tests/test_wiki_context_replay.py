from __future__ import annotations

import shutil
from pathlib import Path

from scripts.replay_llm_wiki_context import replay_context_modes
from zscope.wiki.source_manifest import build_source_manifest
from zscope.wiki.store.revision_store import WikiStore


FIXTURE = Path(__file__).parent / "fixtures" / "wiki_project"


def test_context_replay_compares_five_modes_without_llm_or_benchmark(tmp_path: Path) -> None:
    root = tmp_path / "project"
    shutil.copytree(FIXTURE, root, symlinks=True)
    state = root / ".zscope_knowledge" / "wiki"
    manifest = build_source_manifest(root, project_id=root.name, created_at="2026-01-01T00:00:00Z")
    with WikiStore(state) as store:
        store.build_skeleton(root, manifest)
    result = replay_context_modes(
        root,
        [{"candidate_uid": "candidate-1", "project_id": root.name, "subject_id": "parse_byte", "fact_kind": "value_range", "relative_file": "src/parser.c"}],
        state_root=state,
    )
    assert result["benchmark_executed"] is False
    assert result["llm_called"] is False
    assert set(result["modes"]) == {"control", "direct", "shadow", "active", "unavailable"}
    assert result["modes"]["control"]["candidates"][0]["resolution_mode"] == "off"
    assert result["modes"]["direct"]["candidates"][0]["resolution_mode"] == "source_fallback"
    assert result["modes"]["shadow"]["context_injected_to_validator"] is False
    assert result["modes"]["active"]["context_injected_to_validator"] is True
    assert result["modes"]["unavailable"]["candidates"][0]["fallback_reason"] == "compiler_unavailable"

