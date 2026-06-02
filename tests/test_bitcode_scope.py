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


def test_symbol_closure_reuses_selector_symbol_cache(tmp_path: Path) -> None:
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
    read_counts = {"entry.bc": 0, "provider.bc": 0}

    class FakeSymbolReader:
        def read_symbols(self, bc_path: Path) -> BitcodeSymbols:
            read_counts[bc_path.name] += 1
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

    for _ in range(2):
        selected, _plan = selector.select(
            group_name="default",
            candidate_bcs=[entry_bc, provider_bc],
            bc_to_src=bc_to_src,
            entries=["entry"],
        )
        assert selected == [entry_bc.resolve(), provider_bc.resolve()]

    assert read_counts == {"entry.bc": 1, "provider.bc": 1}
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


def test_entry_clustering_merges_overlapping_entry_scopes(tmp_path: Path) -> None:
    project = tmp_path / "project"
    source_root = project
    db = KnowledgeDB(str(tmp_path / "knowledge.db"))
    db.insert_function("api_a", "src/api.c", 1, 10)
    db.insert_function("api_b", "src/api.c", 12, 20)
    db.insert_function("helper", "src/helper.c", 1, 5)
    db.insert_function("api_c", "src/other.c", 1, 10)
    db.insert_call_edge("api_a", "src/api.c", "helper", "src/helper.c", 3)
    db.insert_call_edge("api_b", "src/api.c", "helper", "src/helper.c", 14)

    api_bc = _touch(tmp_path / "bc" / "api.bc")
    helper_bc = _touch(tmp_path / "bc" / "helper.bc")
    other_bc = _touch(tmp_path / "bc" / "other.bc")
    bc_to_src = {
        api_bc: source_root / "src" / "api.c",
        helper_bc: source_root / "src" / "helper.c",
        other_bc: source_root / "src" / "other.c",
    }

    selector = EntryBitcodeSelector(
        db=db,
        source_root=source_root,
        project_root=project,
        config=BitcodeScopeConfig(mode="entry", entry_depth=1, symbol_closure=False),
    )

    clusters = selector.cluster_entries(
        group_prefix="entry_cluster",
        candidate_bcs=[api_bc, helper_bc, other_bc],
        bc_to_src=bc_to_src,
        entries=["api_a", "api_b", "api_c"],
    )

    assert len(clusters) == 2
    by_entries = {tuple(cluster.plan.entries): cluster for cluster in clusters}
    assert ("api_a", "api_b") in by_entries
    assert ("api_c",) in by_entries
    assert {path.name for path in by_entries[("api_a", "api_b")].selected_bcs} == {
        "api.bc",
        "helper.bc",
    }
    db.close()


def test_entry_clustering_seed_selection_skips_symbol_closure(tmp_path: Path) -> None:
    project = tmp_path / "project"
    source_root = project
    db = KnowledgeDB(str(tmp_path / "knowledge.db"))
    db.insert_function("api_a", "src/api.c", 1, 10)
    db.insert_function("api_b", "src/api.c", 12, 20)
    db.insert_function("helper", "src/helper.c", 1, 5)
    db.insert_call_edge("api_a", "src/api.c", "helper", "src/helper.c", 3)
    db.insert_call_edge("api_b", "src/api.c", "helper", "src/helper.c", 14)

    api_bc = _touch(tmp_path / "bc" / "api.bc")
    helper_bc = _touch(tmp_path / "bc" / "helper.bc")
    provider_bc = _touch(tmp_path / "bc" / "provider.bc")
    bc_to_src = {
        api_bc: source_root / "src" / "api.c",
        helper_bc: source_root / "src" / "helper.c",
        provider_bc: source_root / "src" / "provider.c",
    }

    selector = EntryBitcodeSelector(
        db=db,
        source_root=source_root,
        project_root=project,
        config=BitcodeScopeConfig(mode="entry", entry_depth=1, symbol_closure=True),
    )
    closure_calls = []

    def record_symbol_closure(selected_bcs, all_bcs, bc_to_src):
        closure_calls.append({path.name for path in selected_bcs})
        return set()

    selector._expand_symbol_closure = record_symbol_closure

    clusters = selector.cluster_entries(
        group_prefix="entry_cluster",
        candidate_bcs=[api_bc, helper_bc, provider_bc],
        bc_to_src=bc_to_src,
        entries=["api_a", "api_b"],
    )

    assert len(clusters) == 1
    assert closure_calls == [{"api.bc", "helper.bc"}]
    db.close()


def test_entry_seed_dependency_cache_reuses_bc_dependency_result(tmp_path: Path) -> None:
    project = tmp_path / "project"
    source_root = project
    db = KnowledgeDB(str(tmp_path / "knowledge.db"))
    db.insert_function("entry", "src/entry.c", 1, 5)
    db.insert_function("helper", "src/helper.c", 1, 5)
    db.insert_call_edge("entry", "src/entry.c", "helper", "src/helper.c", 3)

    entry_bc = _touch(tmp_path / "bc" / "entry.bc")
    helper_bc = _touch(tmp_path / "bc" / "helper.bc")
    bc_to_src = {
        entry_bc: source_root / "src" / "entry.c",
        helper_bc: source_root / "src" / "helper.c",
    }
    original_get_callees = db.get_callees
    call_count = {"entry": 0}

    def counting_get_callees(func_name, *args, **kwargs):
        if func_name == "entry":
            call_count["entry"] += 1
        return original_get_callees(func_name, *args, **kwargs)

    db.get_callees = counting_get_callees

    selector = EntryBitcodeSelector(
        db=db,
        source_root=source_root,
        project_root=project,
        config=BitcodeScopeConfig(mode="entry", entry_depth=1, symbol_closure=False),
    )

    for _ in range(2):
        clusters = selector.cluster_entries(
            group_prefix="entry_cluster",
            candidate_bcs=[entry_bc, helper_bc],
            bc_to_src=bc_to_src,
            entries=["entry"],
        )
        assert len(clusters) == 1
        assert {path.name for path in clusters[0].selected_bcs} == {"entry.bc", "helper.bc"}

    assert call_count["entry"] == 1
    db.close()


def test_entry_seed_dependency_respects_exclusive_pool(tmp_path: Path) -> None:
    project = tmp_path / "project"
    source_root = project
    db = KnowledgeDB(str(tmp_path / "knowledge.db"))
    db.insert_function("entry", "src/pool/normal/entry.c", 1, 5)
    db.insert_function("normal_helper", "src/pool/normal/helper.c", 1, 5)
    db.insert_function("compat_helper", "src/pool/compat/helper.c", 1, 5)
    db.insert_call_edge("entry", "src/pool/normal/entry.c", "normal_helper", "src/pool/normal/helper.c", 3)
    db.insert_call_edge("entry", "src/pool/normal/entry.c", "compat_helper", "src/pool/compat/helper.c", 4)

    entry_bc = _touch(tmp_path / "bc" / "entry.bc")
    normal_bc = _touch(tmp_path / "bc" / "normal_helper.bc")
    compat_bc = _touch(tmp_path / "bc" / "compat_helper.bc")
    bc_to_src = {
        entry_bc: source_root / "src" / "pool" / "normal" / "entry.c",
        normal_bc: source_root / "src" / "pool" / "normal" / "helper.c",
        compat_bc: source_root / "src" / "pool" / "compat" / "helper.c",
    }

    selector = EntryBitcodeSelector(
        db=db,
        source_root=source_root,
        project_root=project,
        config=BitcodeScopeConfig(
            mode="entry",
            entry_depth=1,
            symbol_closure=False,
            exclusive_pools=[
                {"name": "normal", "paths": ["src/pool/normal/**"]},
                {"name": "compat", "paths": ["src/pool/compat/**"]},
            ],
        ),
    )

    clusters = selector.cluster_entries(
        group_prefix="entry_cluster",
        candidate_bcs=[entry_bc, normal_bc, compat_bc],
        bc_to_src=bc_to_src,
        entries=["entry"],
    )

    assert len(clusters) == 1
    assert {path.name for path in clusters[0].selected_bcs} == {"entry.bc", "normal_helper.bc"}
    assert clusters[0].plan.exclusive_pool == "normal"
    db.close()


def test_symbol_closure_does_not_cross_exclusive_pool(tmp_path: Path) -> None:
    project = tmp_path / "project"
    source_root = project
    db = KnowledgeDB(str(tmp_path / "knowledge.db"))
    db.insert_function("entry", "src/pool/normal/entry.c", 1, 5)

    entry_bc = _touch(tmp_path / "bc" / "entry.bc")
    compat_bc = _touch(tmp_path / "bc" / "compat_provider.bc")
    bc_to_src = {
        entry_bc: source_root / "src" / "pool" / "normal" / "entry.c",
        compat_bc: source_root / "src" / "pool" / "compat" / "provider.c",
    }

    class FakeSymbolReader:
        def read_symbols(self, bc_path: Path) -> BitcodeSymbols:
            if bc_path.name == "entry.bc":
                return BitcodeSymbols(defined={"entry"}, undefined={"shared_symbol"})
            if bc_path.name == "compat_provider.bc":
                return BitcodeSymbols(defined={"shared_symbol"}, undefined=set())
            return BitcodeSymbols()

    selector = EntryBitcodeSelector(
        db=db,
        source_root=source_root,
        project_root=project,
        config=BitcodeScopeConfig(
            mode="entry",
            entry_depth=1,
            symbol_closure=True,
            exclusive_pools=[
                {"name": "normal", "paths": ["src/pool/normal/**"]},
                {"name": "compat", "paths": ["src/pool/compat/**"]},
            ],
        ),
        symbol_reader=FakeSymbolReader(),
    )

    clusters = selector.cluster_entries(
        group_prefix="entry_cluster",
        candidate_bcs=[entry_bc, compat_bc],
        bc_to_src=bc_to_src,
        entries=["entry"],
    )

    assert len(clusters) == 1
    assert clusters[0].selected_bcs == [entry_bc.resolve()]
    assert clusters[0].plan.symbol_closure_added == []
    db.close()


def test_unresolved_external_callee_does_not_expand_scope(tmp_path: Path) -> None:
    project = tmp_path / "project"
    source_root = project
    db = KnowledgeDB(str(tmp_path / "knowledge.db"))
    db.insert_function("entry", "src/entry.c", 1, 5)
    db.insert_call_edge("entry", "src/entry.c", "external_api", "", 3)

    entry_bc = _touch(tmp_path / "bc" / "entry.bc")
    decoy_bc = _touch(tmp_path / "bc" / "decoy.bc")
    bc_to_src = {
        entry_bc: source_root / "src" / "entry.c",
        decoy_bc: source_root / "src" / "decoy.c",
    }

    selector = EntryBitcodeSelector(
        db=db,
        source_root=source_root,
        project_root=project,
        config=BitcodeScopeConfig(mode="entry", entry_depth=2, symbol_closure=False),
    )

    selected, plan = selector.select(
        group_name="default",
        candidate_bcs=[entry_bc, decoy_bc],
        bc_to_src=bc_to_src,
        entries=["entry"],
    )

    assert selected == [entry_bc.resolve()]
    assert plan.reachable_functions == ["entry"]
    db.close()


def test_ambiguous_callee_without_file_hint_prefers_nearby_implementation(tmp_path: Path) -> None:
    project = tmp_path / "project"
    source_root = project
    db = KnowledgeDB(str(tmp_path / "knowledge.db"))
    db.insert_function("entry", "src/feature/entry.c", 1, 5)
    db.insert_function("helper", "src/feature/helper.c", 1, 5)
    db.insert_function("helper", "src/other/helper.c", 1, 5)
    db.insert_call_edge("entry", "src/feature/entry.c", "helper", "", 3)

    entry_bc = _touch(tmp_path / "bc" / "entry.bc")
    feature_helper_bc = _touch(tmp_path / "bc" / "feature_helper.bc")
    other_helper_bc = _touch(tmp_path / "bc" / "other_helper.bc")
    bc_to_src = {
        entry_bc: source_root / "src" / "feature" / "entry.c",
        feature_helper_bc: source_root / "src" / "feature" / "helper.c",
        other_helper_bc: source_root / "src" / "other" / "helper.c",
    }

    selector = EntryBitcodeSelector(
        db=db,
        source_root=source_root,
        project_root=project,
        config=BitcodeScopeConfig(mode="entry", entry_depth=1, symbol_closure=False),
    )

    selected, _plan = selector.select(
        group_name="default",
        candidate_bcs=[entry_bc, feature_helper_bc, other_helper_bc],
        bc_to_src=bc_to_src,
        entries=["entry"],
    )

    assert selected == [entry_bc.resolve(), feature_helper_bc.resolve()]
    db.close()
