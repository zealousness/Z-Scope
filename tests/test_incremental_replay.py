"""P01 command coverage and loss-sensitive incremental fact comparisons."""

import json
import os
from pathlib import Path
import sqlite3

from click.testing import CliRunner
import pytest

from zscope.cli.index_audit import main
from zscope.retrieval.incremental_replay import (
    MUTATIONS,
    canonical_database,
    compare_facts,
    input_manifest,
    mutate_fixture,
    run_fixture_replay,
    _preserve_preparation,
    write_fixture,
)
from zscope.retrieval.indexing_identity import command_identity, digest_json
from zscope.retrieval.indexing_inventory import compilation_contexts, inventory
from zscope.retrieval.knowledge_db import KnowledgeDB


def test_all_commands_keep_macro_include_abi_and_response_context(tmp_path):
    root = tmp_path / "source"
    write_fixture(root)
    cdb = root / "compile_commands.json"
    commands = json.loads(cdb.read_text())
    for flag in ("-m32", "-Iother", "@args.rsp"):
        row = dict(commands[0], arguments=[*commands[0]["arguments"], flag])
        commands.append(row)
    (root / "args.rsp").write_text("-DOTHER=1")
    cdb.write_text(json.dumps(commands))
    selected = digest_json(command_identity(commands[0], root))
    result = compilation_contexts(cdb, selected_contexts=[selected])
    assert result["command_entries"] == 8
    assert result["compile_contexts"] == 7
    assert [row["selection_status"] for row in result["command_records"][:3]] == [
        "selected",
        "equivalent",
        "uncovered",
    ]
    assert result["command_records"][1]["equivalent_to_command"] == 0
    variants = next(row for row in result["source_variants"] if row["source"].endswith("a.c"))
    assert len(variants["uncovered_contexts"]) == 4
    before = [row["context"] for row in result["contexts"]]
    (root / "args.rsp").write_text("-DOTHER=2")
    after = compilation_contexts(cdb, selected_contexts=[selected])
    assert [row["context"] for row in after["contexts"]] != before


def test_inventory_reports_selection_without_claiming_artifact_coverage(tmp_path):
    root = tmp_path / "source"
    write_fixture(root)
    cdb = root / "compile_commands.json"
    key = compilation_contexts(cdb)["contexts"][0]["context"]
    unknown = inventory(cdb, tmp_path)
    assert unknown["selection_verified"] is False
    assert {row["selection_status"] for row in unknown["command_records"]} == {"unverified"}
    result = inventory(cdb, tmp_path, {"attempts": {key: {"status": "compiled"}}})
    assert result["selection_verified"] is True
    assert result["coverage_verified"] is False
    assert result["command_records"][1]["selection_status"] == "equivalent"
    assert result["contexts"][0]["reason"] == "artifact_not_recorded"


def test_invalid_commands_are_not_silently_covered(tmp_path):
    cdb = tmp_path / "compile_commands.json"
    cdb.write_text(json.dumps([{}, {"file": "a.c"}]))
    result = compilation_contexts(cdb, selected_contexts=["nonexistent"])
    assert len(result["invalid_commands"]) == 2
    assert result["selection_verified"] is False
    assert result["unrecognized_selected_contexts"] == ["nonexistent"]


def database(tmp_path, name, offset):
    db = KnowledgeDB(str(tmp_path / name))
    db._conn.execute(
        "INSERT INTO translation_units(id,file_path,last_modified,index_time,status,file_hash) VALUES (?,?,?,?,?,?)",
        (offset + 1, "a.c", offset * 2, offset * 3, "indexed", "source-digest"),
    )
    db._conn.execute(
        "INSERT INTO functions(id,name,file_path,start_line,end_line,tu_id) VALUES (?,?,?,?,?,?)",
        (offset + 2, "entry", "a.c", 1, 10, offset + 1),
    )
    db._conn.execute(
        "INSERT INTO macro_definitions(id,name,file_path,line,macro_index_name) VALUES (?,?,?,?,?)",
        (offset + 3, "VALUE", "a.c", 1, "VALUE@a.c:1"),
    )
    db._conn.execute(
        "INSERT INTO function_macro_refs(function_id,macro_id,reference_line) VALUES (?,?,?)",
        (offset + 2, offset + 3, 3),
    )
    db._conn.execute(
        "INSERT INTO function_program_facts VALUES (?,?,?,?,?,?)",
        (
            "entry",
            "a.c",
            1,
            "program_function",
            "identity",
            json.dumps({"events": [{"resource": "heap", "timestamp": 4}], "complete": True}),
        ),
    )
    db.commit()
    return db


def test_database_ignores_storage_ids_and_times_but_keeps_fact_payload(tmp_path):
    a, b = database(tmp_path, "a.db", 0), database(tmp_path, "b.db", 20)
    try:
        assert compare_facts(canonical_database(a._conn), canonical_database(b._conn))["equal"]
        b._conn.execute(
            "UPDATE function_program_facts SET data=?",
            (json.dumps({"events": [{"resource": "heap", "timestamp": 5}], "complete": True}),),
        )
        delta = compare_facts(canonical_database(a._conn), canonical_database(b._conn))
        assert delta["difference_count"] == 2
        assert delta["differences"][0]["section"] == "function_program_facts"
    finally:
        a.close()
        b.close()


@pytest.mark.parametrize(
    "table", ["functions", "function_macro_refs", "function_program_facts", "translation_units"]
)
def test_missing_fact_category_cannot_pass(tmp_path, table):
    a = database(tmp_path, "a.db", 0)
    try:
        before = canonical_database(a._conn)
        a._conn.execute(f'DELETE FROM "{table}"')
        try:
            after = canonical_database(a._conn)
        except ValueError as exc:
            assert "dangling fact reference" in str(exc)
        else:
            assert not compare_facts(before, after)["equal"]
    finally:
        a.close()


def test_comparator_preserves_duplicates_build_context_and_coverage():
    a = {"native_tus": [{"context": "variant-a", "symbol": "f"}], "coverage": {"complete": True}}
    b = {"native_tus": [*a["native_tus"], *a["native_tus"]], "coverage": {"complete": False}}
    result = compare_facts(a, b)
    assert result["difference_count"] == 2
    assert not compare_facts(a, {**a, "native_tus": [{"context": "variant-b", "symbol": "f"}]})[
        "equal"
    ]


def test_unknown_semantic_tables_are_not_dropped():
    db = sqlite3.connect(":memory:")
    try:
        db.execute("CREATE TABLE future_fact(id TEXT PRIMARY KEY, data TEXT)")
        db.execute("INSERT INTO future_fact VALUES ('source-id','v1')")
        assert canonical_database(db)["future_fact"] == [{"id": "source-id", "data": "v1"}]
    finally:
        db.close()


@pytest.mark.parametrize("mutation", MUTATIONS)
def test_each_mutation_starts_from_same_fixed_input(tmp_path, mutation):
    source = tmp_path / "fixture"
    write_fixture(source)
    before = input_manifest(source)
    mutate_fixture(source, mutation)
    assert input_manifest(source) != before
    if mutation == "delete":
        assert "unused.c" not in input_manifest(source)
    if mutation == "rename":
        assert "b.c" not in input_manifest(source)
        assert "renamed.c" in input_manifest(source)


def test_replay_refuses_existing_work_before_writing(tmp_path, monkeypatch):
    monkeypatch.setattr("zscope.retrieval.clang_batch.find_indexer", lambda _path: ("fake", {}))
    sentinel = tmp_path / "user.txt"
    sentinel.write_text("preserve")
    with pytest.raises(ValueError, match="must not already exist"):
        run_fixture_replay(tmp_path, clang_indexer="fake")
    assert sentinel.read_text() == "preserve"


def test_replay_fails_closed_without_native_tool(tmp_path, monkeypatch):
    monkeypatch.setattr("zscope.retrieval.clang_batch.find_indexer", lambda _path: None)
    work = tmp_path / "work"
    with pytest.raises(ValueError, match="never falls back"):
        run_fixture_replay(work, clang_indexer="missing")
    assert not work.exists()


def test_clean_branch_gets_fresh_preparation_without_deleting_evidence(tmp_path):
    root = tmp_path / "source"
    root.mkdir()
    prepared = root / ".zscope-compile-commands"
    prepared.mkdir()
    (prepared / "evidence.json").write_text("retained")
    archived = Path(_preserve_preparation(root))
    assert not prepared.exists()
    assert (archived / "evidence.json").read_text() == "retained"


def test_preparation_archive_rejects_symlink(tmp_path):
    root = tmp_path / "source"
    root.mkdir()
    other = tmp_path / "outside"
    other.mkdir()
    (root / ".zscope-compile-commands").symlink_to(other, target_is_directory=True)
    with pytest.raises(ValueError, match="unsafe replay"):
        _preserve_preparation(root)
    assert other.is_dir()


def test_replay_cli_does_not_load_config(tmp_path, monkeypatch):
    monkeypatch.setattr(
        "zscope.cli.index_audit.ConfigLoader.load",
        lambda *args: pytest.fail("project config loaded"),
    )
    seen = []
    monkeypatch.setattr(
        "zscope.retrieval.incremental_replay.run_fixture_replay",
        lambda work, **kwargs: seen.append((work, kwargs)) or {"complete": True},
    )
    output = tmp_path / "report.json"
    result = CliRunner().invoke(
        main,
        [
            "--replay-fixture",
            "--work-directory",
            str(tmp_path / "work"),
            "--clang-indexer",
            "/tool with spaces/indexer",
            "--output",
            str(output),
        ],
    )
    assert result.exit_code == 0, result.output
    assert seen[0][1] == {"clang_indexer": "/tool with spaces/indexer"}
    assert json.loads(output.read_text())["complete"]


@pytest.mark.parametrize(
    "args",
    [
        [],
        ["--replay-fixture"],
        ["--work-directory", "new"],
        ["--replay-fixture", "--measure-svf", "--work-directory", "new"],
    ],
)
def test_audit_cli_rejects_ambiguous_inputs(args):
    result = CliRunner().invoke(main, args)
    assert result.exit_code == 2


def test_real_mutation_replay(tmp_path):
    executable = os.environ.get("Z_SCOPE_TEST_CLANG_INDEXER")
    if not executable:
        pytest.skip("native replay requires Z_SCOPE_TEST_CLANG_INDEXER")
    result = run_fixture_replay(tmp_path / "real replay", clang_indexer=executable)
    assert result["complete"], [
        (row["mutation"], row.get("reason"), row.get("difference_count"))
        for row in result["mutations"]
    ]
    assert result["unexplained_semantic_differences"] == 0
    assert len(result["mutations"]) == len(MUTATIONS)
    assert all(row["stages"]["baseline_hot"]["rebuilt_tus"] == 0 for row in result["mutations"])
    assert all(
        row["stages"]["baseline_hot"]["reused_tus"] == row["stages"]["baseline_cold"]["planned_tus"]
        for row in result["mutations"]
    )
    assert all(row["stages"]["clean"]["reused_tus"] == 0 for row in result["mutations"])
