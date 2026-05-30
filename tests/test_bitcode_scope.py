from pathlib import Path

from zscope.config.function_entry import FunctionEntry
from zscope.retrieval.bitcode_scope import (
    BitcodeScopeConfig,
    BitcodeSymbols,
    EntryBitcodeSelector,
)
from zscope.retrieval.knowledge_db import KnowledgeDB


def _touch(path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("int x;\n", encoding="utf-8")
    return path


def test_entry_scope_selects_reachable_translation_units(tmp_path: Path) -> None:
    project = tmp_path / "project"
    source_root = project
    db = KnowledgeDB(str(tmp_path / "knowledge.db"))
    db.insert_function("entry", "src/entry.c", 1, 5)
    db.insert_function("helper", "src/helper.c", 1, 5)
    db.insert_function("unused", "src/unused.c", 1, 5)
    db.insert_call_edge("entry", "src/entry.c", "helper", "src/helper.c", 3)

    entry_bc = _touch(tmp_path / "bc" / "entry.bc")
    helper_bc = _touch(tmp_path / "bc" / "helper.bc")
    unused_bc = _touch(tmp_path / "bc" / "unused.bc")
    bc_to_src = {
        entry_bc: source_root / "src" / "entry.c",
        helper_bc: source_root / "src" / "helper.c",
        unused_bc: source_root / "src" / "unused.c",
    }

    selector = EntryBitcodeSelector(
        db=db,
        source_root=source_root,
        project_root=project,
        config=BitcodeScopeConfig(mode="entry", entry_depth=2, symbol_closure=False),
    )

    selected, plan = selector.select(
        group_name="default",
        candidate_bcs=[entry_bc, helper_bc, unused_bc],
        bc_to_src=bc_to_src,
        entries=["entry"],
    )

    assert selected == [entry_bc.resolve(), helper_bc.resolve()]
    assert "entry" in plan.reachable_functions
    assert "helper" in plan.reachable_functions
    assert all("unused" not in path for path in plan.selected_bcs)
    db.close()


def test_symbol_closure_adds_provider_bitcode(tmp_path: Path) -> None:
    project = tmp_path / "project"
    source_root = project
    db = KnowledgeDB(str(tmp_path / "knowledge.db"))
    db.insert_function("entry", "src/entry.c", 1, 5)

    entry_bc = _touch(tmp_path / "bc" / "entry.bc")
    provider_bc = _touch(tmp_path / "bc" / "provider.bc")
    bc_to_src = {
        entry_bc: source_root / "src" / "entry.c",
        provider_bc: source_root / "src" / "provider.c",
    }

    class FakeSymbolReader:
        def read_symbols(self, bc_path: Path) -> BitcodeSymbols:
            if bc_path.name == "entry.bc":
                return BitcodeSymbols(defined={"entry"}, undefined={"helper_global"})
            if bc_path.name == "provider.bc":
                return BitcodeSymbols(defined={"helper_global"}, undefined=set())
            return BitcodeSymbols()

    selector = EntryBitcodeSelector(
        db=db,
        source_root=source_root,
        project_root=project,
        config=BitcodeScopeConfig(mode="entry", entry_depth=1, symbol_closure=True),
        symbol_reader=FakeSymbolReader(),
    )

    selected, plan = selector.select(
        group_name="default",
        candidate_bcs=[entry_bc, provider_bc],
        bc_to_src=bc_to_src,
        entries=["entry"],
    )

    assert selected == [entry_bc.resolve(), provider_bc.resolve()]
    assert len(plan.symbol_closure_added) == 1
    assert plan.symbol_closure_added[0].endswith("/provider.bc")
    db.close()


def test_entry_file_path_hint_selects_matching_bitcode(tmp_path: Path) -> None:
    project = tmp_path / "project"
    source_root = project
    db = KnowledgeDB(str(tmp_path / "knowledge.db"))
    hinted_bc = _touch(tmp_path / "bc" / "hinted.bc")
    other_bc = _touch(tmp_path / "bc" / "other.bc")
    bc_to_src = {
        hinted_bc: source_root / "src" / "hinted.c",
        other_bc: source_root / "src" / "other.c",
    }

    selector = EntryBitcodeSelector(
        db=db,
        source_root=source_root,
        project_root=project,
        config=BitcodeScopeConfig(mode="entry", entry_depth=1, symbol_closure=False),
    )

    selected, plan = selector.select(
        group_name="default",
        candidate_bcs=[hinted_bc, other_bc],
        bc_to_src=bc_to_src,
        entries=[FunctionEntry("entry", file_path="src/hinted.c")],
    )

    assert selected == [hinted_bc.resolve()]
    assert plan.unresolved_entries == ["entry"]
    db.close()


def test_entry_file_path_hint_disambiguates_duplicate_function_names(tmp_path: Path) -> None:
    project = tmp_path / "project"
    source_root = project
    db = KnowledgeDB(str(tmp_path / "knowledge.db"))
    db.insert_function("A", "src/pool/normal/A.c", 1, 5)
    db.insert_function("A", "src/pool/compat/A.c", 1, 5)

    normal_bc = _touch(tmp_path / "bc" / "normal_A.bc")
    compat_bc = _touch(tmp_path / "bc" / "compat_A.bc")
    bc_to_src = {
        normal_bc: source_root / "src" / "pool" / "normal" / "A.c",
        compat_bc: source_root / "src" / "pool" / "compat" / "A.c",
    }

    selector = EntryBitcodeSelector(
        db=db,
        source_root=source_root,
        project_root=project,
        config=BitcodeScopeConfig(mode="entry", entry_depth=1, symbol_closure=False),
    )

    selected, plan = selector.select(
        group_name="default",
        candidate_bcs=[normal_bc, compat_bc],
        bc_to_src=bc_to_src,
        entries=[FunctionEntry("A", file_path="src/pool/compat/A.c")],
    )

    assert selected == [compat_bc.resolve()]
    selected_sources = [path.replace("\\", "/") for path in plan.selected_sources]
    assert any(path.endswith("src/pool/compat/A.c") for path in selected_sources)
    assert not any(path.endswith("src/pool/normal/A.c") for path in selected_sources)
    db.close()
