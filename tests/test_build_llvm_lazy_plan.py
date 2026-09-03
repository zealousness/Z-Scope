"""Lazy scope-first bitcode build tests (P1-M4)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set

import pytest

from zscope.retrieval import build_llvm as build_llvm_module
from zscope.retrieval.build_llvm import BitcodeBuilder
from zscope.retrieval.bitcode_scope import (
    BitcodeScopeConfig,
    BitcodeScopePlan,
    EntryBitcodeCluster,
)
from zscope.retrieval.knowledge_db import KnowledgeDB
from zscope.retrieval.svf_analyzer import SvfAnalyzer


class FakeSelector:
    """Records planning inputs; returns a deterministic selected subset."""

    instances: List["FakeSelector"] = []

    def __init__(self, *, db, source_root, project_root, config):
        self.db = db
        self.source_root = source_root
        self.project_root = project_root
        self.config = config
        self.select_calls: List[Dict[str, Any]] = []
        self.cluster_calls: List[str] = []
        FakeSelector.instances.append(self)

    def _plan(self, group_name: str, candidate_bcs: Sequence[Path]) -> BitcodeScopePlan:
        chosen = [Path(bc).resolve() for bc in list(candidate_bcs)[:2]]
        return BitcodeScopePlan(
            group_name=group_name,
            mode="entry",
            entries=[],
            selected_sources=[],
            selected_bcs=[str(bc) for bc in chosen],
            reachable_functions=[],
            unresolved_entries=[],
            symbol_closure_added=[],
            fallback_reason="",
        )

    def select(self, *, group_name, candidate_bcs, bc_to_src, entries):
        self.select_calls.append(
            {"group": group_name, "bcs": [Path(bc) for bc in candidate_bcs]}
        )
        plan = self._plan(group_name, candidate_bcs)
        return [Path(bc).resolve() for bc in plan.selected_bcs], plan

    def cluster_entries(self, *, group_prefix, candidate_bcs, bc_to_src, entries, min_overlap=0.6):
        self.cluster_calls.append(group_prefix)
        plan = self._plan(group_prefix, candidate_bcs)
        return [
            EntryBitcodeCluster(
                group_name=f"{group_prefix}_1",
                entries=[],
                selected_bcs=[Path(bc).resolve() for bc in plan.selected_bcs],
                plan=plan,
            )
        ]

    def _always_include_sources(self, sources: Iterable[Path]) -> Set[Path]:
        return set()


def make_builder(tmp_path: Path, sources: Sequence[str]) -> BitcodeBuilder:
    src_dir = tmp_path / "src"
    src_dir.mkdir(parents=True, exist_ok=True)
    commands = []
    for name in sources:
        (src_dir / name).write_text(f"int fn_{name.replace('.', '_')}(void) {{ return 0; }}\n", encoding="utf-8")
        commands.append(
            {
                "directory": str(src_dir),
                "file": name,
                "command": f"gcc -c {name}",
            }
        )
    cc_path = tmp_path / "compile_commands.json"
    cc_path.write_text(json.dumps(commands), encoding="utf-8")
    return BitcodeBuilder(
        source_root=tmp_path,
        compile_commands_path=cc_path,
        output_dir=tmp_path / ".zscope_bc",
    )


def resolved_src(tmp_path: Path, name: str) -> str:
    return str((tmp_path / "src" / name).resolve())


def test_filter_commands_for_scope_plan(tmp_path: Path) -> None:
    builder = make_builder(tmp_path, ["a.c", "b.c", "c.c"])
    commands = builder._load_compile_commands()
    filtered = builder._filter_commands_for_scope_plan(
        commands, {resolved_src(tmp_path, "a.c"), resolved_src(tmp_path, "c.c")}
    )
    assert [cmd["file"] for cmd in filtered] == ["a.c", "c.c"]


def test_plan_none_cases(tmp_path: Path, monkeypatch) -> None:
    builder = make_builder(tmp_path, ["a.c", "b.c"])
    db = KnowledgeDB(str(tmp_path / "code_knowledge.db"))
    entries = ["main"]

    full_config = BitcodeScopeConfig(mode="full", entry_depth=4, max_selected_tus=200)
    assert (
        builder.plan_required_sources(
            scope_config=full_config,
            entry_functions=entries,
            knowledge_db=db,
        )
        is None
    )

    entry_config = BitcodeScopeConfig(mode="entry", entry_depth=4, max_selected_tus=200)
    assert (
        builder.plan_required_sources(
            scope_config=entry_config,
            entry_functions=[],
            knowledge_db=db,
        )
        is None
    )
    assert (
        builder.plan_required_sources(
            scope_config=entry_config,
            entry_functions=entries,
            knowledge_db=None,
        )
        is None
    )


def test_plan_maps_selected_bcs_back_to_sources(tmp_path: Path, monkeypatch) -> None:
    FakeSelector.instances = []
    monkeypatch.setattr(build_llvm_module, "EntryBitcodeSelector", FakeSelector)
    builder = make_builder(tmp_path, ["a.c", "b.c", "c.c"])
    db = KnowledgeDB(str(tmp_path / "code_knowledge.db"))
    config = BitcodeScopeConfig(mode="entry", entry_depth=4, max_selected_tus=200)

    plan = builder.plan_required_sources(
        groups={"default": []},
        scope_config=config,
        entry_functions=["main"],
        knowledge_db=db,
        project_root=tmp_path,
        auto_entry_clusters=False,
    )

    assert plan is not None
    # FakeSelector picks the first two prospective bcs -> a.c and b.c
    assert plan == {resolved_src(tmp_path, "a.c"), resolved_src(tmp_path, "b.c")}
    selector = FakeSelector.instances[0]
    assert selector.select_calls, "planning must consult the selector"
    passed_bcs = selector.select_calls[0]["bcs"]
    assert len(passed_bcs) == 3
    # prospective bc paths share the real naming scheme
    assert Path(passed_bcs[0]).name == "tu_0_a.o.bc"


def test_plan_respects_group_exclusions(tmp_path: Path, monkeypatch) -> None:
    FakeSelector.instances = []
    monkeypatch.setattr(build_llvm_module, "EntryBitcodeSelector", FakeSelector)
    builder = make_builder(tmp_path, ["a.c", "skipme.c"])
    db = KnowledgeDB(str(tmp_path / "code_knowledge.db"))
    config = BitcodeScopeConfig(mode="entry", entry_depth=4, max_selected_tus=200)

    builder.plan_required_sources(
        groups={"default": ["skipme"]},
        scope_config=config,
        entry_functions=["main"],
        knowledge_db=db,
        project_root=tmp_path,
        auto_entry_clusters=False,
    )

    selector = FakeSelector.instances[0]
    passed = [Path(bc).name for bc in selector.select_calls[0]["bcs"]]
    assert passed == ["tu_0_a.o.bc"]


def test_plan_uses_clusters_when_auto(tmp_path: Path, monkeypatch) -> None:
    FakeSelector.instances = []
    monkeypatch.setattr(build_llvm_module, "EntryBitcodeSelector", FakeSelector)
    builder = make_builder(tmp_path, ["a.c", "b.c", "c.c"])
    db = KnowledgeDB(str(tmp_path / "code_knowledge.db"))
    config = BitcodeScopeConfig(mode="auto", entry_depth=4, max_selected_tus=200)

    plan = builder.plan_required_sources(
        groups={"default": []},
        scope_config=config,
        entry_functions=["main"],
        knowledge_db=db,
        project_root=tmp_path,
        auto_entry_clusters=True,
    )

    selector = FakeSelector.instances[0]
    assert selector.cluster_calls == ["plan_default"]
    assert plan == {resolved_src(tmp_path, "a.c"), resolved_src(tmp_path, "b.c")}


def test_lazy_env_gate(monkeypatch) -> None:
    monkeypatch.delenv("Z_SCOPE_SVF_LAZY_BITCODE", raising=False)
    assert SvfAnalyzer._lazy_bitcode_enabled() is False
    monkeypatch.setenv("Z_SCOPE_SVF_LAZY_BITCODE", "1")
    assert SvfAnalyzer._lazy_bitcode_enabled() is True
    monkeypatch.setenv("Z_SCOPE_SVF_LAZY_BITCODE", "0")
    assert SvfAnalyzer._lazy_bitcode_enabled() is False


def test_build_bitcode_passes_only_sources_to_capable_builders(tmp_path: Path) -> None:
    db = KnowledgeDB(str(tmp_path / "code_knowledge.db"))
    analyzer = SvfAnalyzer(db=db)
    captured: Dict[str, Any] = {}

    class CapableBuilder:
        def build(self, **kwargs):
            captured.update(kwargs)
            return {}

    analyzer._build_bitcode(
        CapableBuilder(),
        groups={"default": []},
        scope_entries=["main"],
        project_root=tmp_path,
        explicit_groups_config=False,
        only_sources={resolved_src(tmp_path, "a.c")},
    )
    assert captured["only_sources"] == {resolved_src(tmp_path, "a.c")}
    assert captured["saber_groups"] is True

    captured.clear()

    class LegacyBuilder:
        def build(self, groups):
            captured["groups"] = groups
            return {}

    analyzer._build_bitcode(
        LegacyBuilder(),
        groups={"default": []},
        scope_entries=["main"],
        project_root=tmp_path,
        explicit_groups_config=False,
        only_sources={resolved_src(tmp_path, "a.c")},
    )
    assert captured == {"groups": {"default": []}}
