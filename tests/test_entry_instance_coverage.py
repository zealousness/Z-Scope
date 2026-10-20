"""Command-level coverage reconciliation against the exact-context store.

Synthetic manifests mirror what ``BatchIndexer._publish_compilation_instances``
stores, so the receipt checks exercised here are the real
``context_input_status`` path. The native fixtures repeat the real two-macro
indexing used by ``tests/test_build_context.py`` and must not be skipped when
``Z_SCOPE_TEST_CLANG_INDEXER`` is available.
"""

import json
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from zscope.orchestration.entry_instance_coverage import (
    ENTRY_INSTANCE_COVERAGE_SCHEMA,
    reconcile_entry_instance_coverage,
)
from zscope.retrieval.build_context import BuildContext
from zscope.retrieval.indexing_identity import (
    command_identity,
    file_digest,
    search_directories_snapshot,
)

TOOL_RECEIPT = {
    "binary": {"path": "/opt/zscope-clang-indexer", "sha256": "0" * 64},
    "capability": {"batch": True},
}


def _row(root: Path, name: str, flags=()) -> dict:
    source = root / name
    return {
        "directory": str(root),
        "file": str(source),
        "arguments": ["clang", "-c", str(source), *flags],
    }


def _write_project(root: Path) -> tuple[list[dict], Path]:
    (root / "flags.h").write_text("#define FLAG 1\n")
    (root / "unit.c").write_text('#include "flags.h"\nint f(void) { return FLAG; }\n')
    rows = [_row(root, "unit.c"), _row(root, "unit.c", flags=("-DALT=1",))]
    cdb = root / "compile_commands.json"
    cdb.write_text(json.dumps(rows))
    return rows, cdb


def _stored_context(
    row: dict,
    cdb: Path,
    *,
    status: str = "indexed",
    tool: dict | None = None,
    cdb_sha: str | None = None,
    extra_dependency: Path | None = None,
    include_lookups: dict | None = None,
) -> dict:
    """Build a manifest shaped like the real publisher's stored context."""

    identity = command_identity(row, cdb.parent)
    dependencies = {identity["source"]: file_digest(Path(identity["source"]))}
    for header in sorted(cdb.parent.glob("*.h")):
        dependencies[str(header)] = file_digest(header)
    if extra_dependency is not None:
        dependencies[str(extra_dependency)] = file_digest(extra_dependency)
    context = BuildContext.create(
        identity,
        tool=tool if tool is not None else TOOL_RECEIPT,
        dependencies=dependencies,
        dependencies_complete=status == "indexed",
        target={},
        include_lookups=include_lookups,
    )
    manifest = context.to_dict()
    manifest.update(
        source=Path(identity["source"]).name,
        status=status,
        failure=None,
        search_directories=search_directories_snapshot([cdb.parent]),
        search_excludes=[],
        compilation_database={
            "path": str(cdb.resolve()),
            "sha256": cdb_sha if cdb_sha is not None else file_digest(cdb),
        },
    )
    if status == "failed":
        manifest["failure"] = {"code": "clang_batch_exit", "exception": "BatchExtractionError"}
    return manifest


def _fake_index(contexts, *, language: str = "c_cpp", backend_name: str = "clang"):
    return SimpleNamespace(
        language=language,
        backend_name=backend_name,
        get_build_contexts=lambda file_path="": [dict(context) for context in contexts],
    )


def test_stored_include_lookups_are_part_of_the_identity(tmp_path):
    # The publisher stores the native include-lookups receipt and
    # BuildContext.create makes it identity-bearing; a reconciler that drops
    # the field rejects every native context with a bogus identity gap.
    lookups = {
        "schema": "zscope.include-lookups.v1",
        "mode": "native",
        "lookups": [{"path": "flags.h", "resolution": "quoted", "found": True}],
    }
    rows, cdb = _write_project(tmp_path)
    stored = [
        _stored_context(rows[0], cdb, include_lookups=lookups),
        _stored_context(rows[1], cdb, include_lookups=lookups),
    ]
    result = reconcile_entry_instance_coverage(
        _fake_index(stored), compile_commands_path=cdb, source_root=tmp_path
    )
    assert result["status"] == "reconciled"
    assert result["gaps"] == []
    assert len(result["current_commands"]) == 2
    assert result["command_coverage_complete"]


def test_single_tu_two_macros_missing_one_context(tmp_path):
    rows, cdb = _write_project(tmp_path)
    stored = [_stored_context(rows[0], cdb)]
    result = reconcile_entry_instance_coverage(
        _fake_index(stored), compile_commands_path=cdb, source_root=tmp_path
    )
    assert result["schema"] == ENTRY_INSTANCE_COVERAGE_SCHEMA
    assert result["status"] == "reconciled"
    assert len(result["expected_commands"]) == 2
    assert len({entry["command_id"] for entry in result["expected_commands"]}) == 2
    assert len(result["current_commands"]) == 1
    missing_ids = {entry["command_id"] for entry in result["missing_commands"]}
    assert missing_ids == {result["expected_commands"][1]["command_id"]}
    assert [gap["reason"] for gap in result["gaps"]] == ["command_not_indexed"]
    assert result["gaps"][0]["source"].endswith("unit.c")
    assert not result["command_coverage_complete"]
    assert result["scan_coverage_complete"] is False


def test_empty_store_reports_every_expected_command_missing(tmp_path):
    rows, cdb = _write_project(tmp_path)
    result = reconcile_entry_instance_coverage(
        _fake_index([]), compile_commands_path=cdb, source_root=tmp_path
    )
    assert result["status"] == "reconciled"
    assert len(result["missing_commands"]) == 2
    assert not result["current_commands"]
    assert {gap["reason"] for gap in result["gaps"]} == {"command_not_indexed"}
    assert not result["command_coverage_complete"]


def test_equal_command_count_with_wrong_commands_stays_incomplete(tmp_path):
    rows, cdb = _write_project(tmp_path)
    wrong_rows = [
        _row(tmp_path, "unit.c", flags=("-DOTHER=1",)),
        _row(tmp_path, "unit.c", flags=("-DEXTRA=1",)),
    ]
    stored = [_stored_context(row, cdb) for row in wrong_rows]
    result = reconcile_entry_instance_coverage(
        _fake_index(stored), compile_commands_path=cdb, source_root=tmp_path
    )
    assert len(result["expected_commands"]) == len(stored) == 2
    assert not result["current_commands"]
    assert len(result["missing_commands"]) == 2
    assert len(result["unexpected_contexts"]) == 2
    assert {gap["reason"] for gap in result["gaps"]} == {
        "command_not_indexed",
        "unexpected_stored_context",
    }
    assert not result["command_coverage_complete"]


def test_duplicate_identical_commands_dedup_explicitly(tmp_path):
    rows, cdb = _write_project(tmp_path)
    cdb.write_text(json.dumps([rows[0], rows[0], rows[0], rows[1]]))
    stored = [_stored_context(row, cdb) for row in rows]
    result = reconcile_entry_instance_coverage(
        _fake_index(stored), compile_commands_path=cdb, source_root=tmp_path
    )
    assert result["command_entries"] == 4
    assert result["duplicate_command_entries"] == 2
    assert len(result["expected_commands"]) == 2
    assert len(result["current_commands"]) == 2
    assert not result["gaps"]
    assert result["command_coverage_complete"]
    assert result["scan_coverage_complete"] is False


def test_stale_dependencies_break_currency_without_rerun(tmp_path):
    rows, cdb = _write_project(tmp_path)
    stored = [_stored_context(row, cdb) for row in rows]
    (tmp_path / "flags.h").write_text("#define FLAG 2\n")
    result = reconcile_entry_instance_coverage(
        _fake_index(stored), compile_commands_path=cdb, source_root=tmp_path
    )
    assert not result["current_commands"]
    assert len(result["stale_contexts"]) == 2
    assert {entry["reason"] for entry in result["stale_contexts"]} == {"stale_build_dependencies"}
    assert not result["command_coverage_complete"]


def test_stale_compilation_database_breaks_currency(tmp_path):
    rows, cdb = _write_project(tmp_path)
    stored = [_stored_context(row, cdb) for row in rows]
    cdb.write_text(json.dumps(rows, indent=1))
    result = reconcile_entry_instance_coverage(
        _fake_index(stored), compile_commands_path=cdb, source_root=tmp_path
    )
    assert not result["current_commands"]
    assert {entry["reason"] for entry in result["stale_contexts"]} == {"stale_compilation_database"}
    assert not result["command_coverage_complete"]


def test_response_file_change_invalidates_command_identity(tmp_path):
    (tmp_path / "flags.h").write_text("#define FLAG 1\n")
    (tmp_path / "unit.c").write_text('#include "flags.h"\nint f(void) { return FLAG; }\n')
    response = tmp_path / "args.rsp"
    response.write_text("-DALT=1\n")
    plain = _row(tmp_path, "unit.c")
    with_response = {
        "directory": str(tmp_path),
        "file": str(tmp_path / "unit.c"),
        "arguments": ["clang", "-c", str(tmp_path / "unit.c"), "@args.rsp"],
    }
    cdb = tmp_path / "compile_commands.json"
    cdb.write_text(json.dumps([plain, with_response]))
    stored = [_stored_context(plain, cdb), _stored_context(with_response, cdb)]
    result = reconcile_entry_instance_coverage(
        _fake_index(stored), compile_commands_path=cdb, source_root=tmp_path
    )
    assert result["command_coverage_complete"]
    response.write_text("-DOTHER=1\n")
    result = reconcile_entry_instance_coverage(
        _fake_index(stored), compile_commands_path=cdb, source_root=tmp_path
    )
    assert len(result["current_commands"]) == 1
    assert len(result["missing_commands"]) == 1
    assert len(result["unexpected_contexts"]) == 1
    assert not result["command_coverage_complete"]


def test_missing_tool_receipt_is_a_conservative_gap(tmp_path):
    rows, cdb = _write_project(tmp_path)
    # The receipts-less tools are part of the manifest from creation, so the
    # declared identity stays self-consistent and the gap is the tool receipt.
    stored = [
        _stored_context(rows[0], cdb, tool={"binary": {"path": "/opt/tool"}, "capability": {}}),
        _stored_context(rows[1], cdb, tool={"capability": {}}),
    ]
    result = reconcile_entry_instance_coverage(
        _fake_index(stored), compile_commands_path=cdb, source_root=tmp_path
    )
    assert len(result["current_commands"]) == 0
    assert {entry["reason"] for entry in result["stale_contexts"]} == {"tool_receipt_missing"}
    assert not result["command_coverage_complete"]


def test_failed_extraction_context_is_an_indexing_failure_gap(tmp_path):
    rows, cdb = _write_project(tmp_path)
    stored = [_stored_context(rows[0], cdb), _stored_context(rows[1], cdb, status="failed")]
    result = reconcile_entry_instance_coverage(
        _fake_index(stored), compile_commands_path=cdb, source_root=tmp_path
    )
    assert len(result["current_commands"]) == 1
    assert len(result["stale_contexts"]) == 1
    failed = result["stale_contexts"][0]
    assert failed["reason"] == "incomplete_compilation_instance"
    gap = next(
        gap for gap in result["gaps"] if gap["build_context_id"] == failed["build_context_id"]
    )
    assert "clang_batch_exit" in gap["detail"]
    assert not result["command_coverage_complete"]


def test_path_selection_filters_commands_and_report_surprises(tmp_path):
    (tmp_path / "flags.h").write_text("#define FLAG 1\n")
    (tmp_path / "src").mkdir()
    (tmp_path / "vendor").mkdir()
    (tmp_path / "excluded").mkdir()
    (tmp_path / "src" / "unit.c").write_text('#include "../flags.h"\nint f(void);\n')
    (tmp_path / "vendor" / "b.c").write_text("int b(void) { return 0; }\n")
    (tmp_path / "excluded" / "hidden.c").write_text("int h(void) { return 0; }\n")
    rows = [
        _row(tmp_path / "src", "unit.c"),
        _row(tmp_path / "src", "unit.c", flags=("-DALT=1",)),
        _row(tmp_path / "vendor", "b.c"),
        _row(tmp_path / "excluded", "hidden.c"),
        _row(tmp_path, "flags.h"),
    ]
    cdb = tmp_path / "compile_commands.json"
    cdb.write_text(json.dumps(rows))
    stored = [_stored_context(row, cdb) for row in rows[:2]]

    # include_paths replace the source root as the selection scope.
    result = reconcile_entry_instance_coverage(
        _fake_index(stored),
        compile_commands_path=cdb,
        source_root=tmp_path,
        include_paths=[tmp_path / "src"],
    )
    assert result["command_entries"] == 5
    assert result["filtered_command_entries"] == 3  # vendor, excluded, header row
    assert len(result["expected_commands"]) == 2
    assert result["command_coverage_complete"]
    assert result["scan_coverage_complete"] is False

    # exclude_paths remove a subtree while the source root stays the base.
    result = reconcile_entry_instance_coverage(
        _fake_index(stored),
        compile_commands_path=cdb,
        source_root=tmp_path,
        exclude_paths=[tmp_path / "excluded"],
    )
    assert len(result["expected_commands"]) == 3
    assert result["command_coverage_complete"] is False
    assert {gap["reason"] for gap in result["gaps"]} == {"command_not_indexed"}

    # A stored context for an out-of-scope command cannot fill the denominator.
    surprised = [*stored, _stored_context(rows[2], cdb)]
    result = reconcile_entry_instance_coverage(
        _fake_index(surprised),
        compile_commands_path=cdb,
        source_root=tmp_path,
        include_paths=[tmp_path / "src"],
    )
    assert len(result["unexpected_contexts"]) == 1
    assert result["unexpected_contexts"][0]["source"].endswith("b.c")
    assert not result["command_coverage_complete"]


def test_duplicate_current_context_for_one_command_is_reported(tmp_path):
    rows, cdb = _write_project(tmp_path)
    # Outside the helper's root-level *.h glob, so only the duplicate build
    # records it as a dependency.
    (tmp_path / "deps").mkdir()
    (tmp_path / "deps" / "extra.h").write_text("#define EXTRA 1\n")
    first = _stored_context(rows[0], cdb)
    # A genuinely different build of the same command: its own valid identity,
    # same command identity, current inputs.
    duplicate = _stored_context(rows[0], cdb, extra_dependency=tmp_path / "deps" / "extra.h")
    assert duplicate["build_context_id"] != first["build_context_id"]
    assert duplicate["command_id"] == first["command_id"]
    stored = [_stored_context(rows[1], cdb), first, duplicate]
    result = reconcile_entry_instance_coverage(
        _fake_index(stored), compile_commands_path=cdb, source_root=tmp_path
    )
    assert len(result["current_commands"]) == 2
    assert {gap["reason"] for gap in result["gaps"]} == {"duplicate_stored_context"}
    assert not result["command_coverage_complete"]


def test_missing_or_foreign_build_context_identity_cannot_fill_coverage(tmp_path):
    rows, cdb = _write_project(tmp_path)
    stored = [_stored_context(row, cdb) for row in rows]
    result = reconcile_entry_instance_coverage(
        _fake_index([dict(context) for context in stored]),
        compile_commands_path=cdb,
        source_root=tmp_path,
    )
    assert result["command_coverage_complete"]
    assert len(result["current_commands"]) == 2

    # Cleared identity: the manifest no longer names a build context.
    cleared = [dict(context) for context in stored]
    cleared[1]["build_context_id"] = ""
    result = reconcile_entry_instance_coverage(
        _fake_index(cleared), compile_commands_path=cdb, source_root=tmp_path
    )
    assert len(result["current_commands"]) == 1
    assert {entry["reason"] for entry in result["stale_contexts"]} == {
        "build_context_identity_mismatch"
    }
    assert not result["command_coverage_complete"]

    # Foreign arbitrary identity attached to an otherwise valid receipt.
    foreign = [dict(context) for context in stored]
    foreign[1]["build_context_id"] = "foreign-arbitrary-identity"
    result = reconcile_entry_instance_coverage(
        _fake_index(foreign), compile_commands_path=cdb, source_root=tmp_path
    )
    assert len(result["current_commands"]) == 1
    assert {entry["reason"] for entry in result["stale_contexts"]} == {
        "build_context_identity_mismatch"
    }
    gap = next(g for g in result["gaps"] if g["reason"] == "build_context_identity_mismatch")
    assert "foreign-arbitrary-identity" in gap["detail"]
    assert not result["command_coverage_complete"]

    # Swapped identities: each declared id names the other macro's manifest.
    swapped = [dict(context) for context in stored]
    swapped[0]["build_context_id"], swapped[1]["build_context_id"] = (
        swapped[1]["build_context_id"],
        swapped[0]["build_context_id"],
    )
    result = reconcile_entry_instance_coverage(
        _fake_index(swapped), compile_commands_path=cdb, source_root=tmp_path
    )
    assert not result["current_commands"]
    assert len(result["stale_contexts"]) == 2
    assert {entry["reason"] for entry in result["stale_contexts"]} == {
        "build_context_identity_mismatch"
    }
    assert not result["command_coverage_complete"]

    # A command_id copied from the expected command onto another command's
    # manifest: the stored command_id must name the stored command identity.
    borrowed = [dict(context) for context in stored]
    baseline = reconcile_entry_instance_coverage(
        _fake_index([dict(context) for context in stored]),
        compile_commands_path=cdb,
        source_root=tmp_path,
    )
    borrowed[1]["command_id"] = baseline["expected_commands"][0]["command_id"]
    result = reconcile_entry_instance_coverage(
        _fake_index(borrowed), compile_commands_path=cdb, source_root=tmp_path
    )
    assert len(result["current_commands"]) == 1
    assert {gap["reason"] for gap in result["gaps"]} == {
        "build_context_identity_mismatch",
        "command_not_indexed",
    }
    assert not result["command_coverage_complete"]


def test_java_and_non_cdb_backends_are_not_applicable():
    java = SimpleNamespace(language="java", backend_name="java_unified")
    result = reconcile_entry_instance_coverage(
        java, compile_commands_path=Path("unused.json"), source_root=Path(".")
    )
    assert result["status"] == "not_applicable"
    assert result["expected_commands"] is None
    assert not result["gaps"]
    assert not result["command_coverage_complete"]
    regex = SimpleNamespace(language="c_cpp", backend_name="regex")
    result = reconcile_entry_instance_coverage(
        regex, compile_commands_path=Path("unused.json"), source_root=Path(".")
    )
    assert result["status"] == "not_applicable"
    assert result["reasons"] == ["regex_backend_has_no_compilation_instances"]


def test_missing_query_surface_is_unavailable(tmp_path):
    rows, cdb = _write_project(tmp_path)
    result = reconcile_entry_instance_coverage(
        SimpleNamespace(language="c_cpp", backend_name="clang"),
        compile_commands_path=cdb,
        source_root=tmp_path,
    )
    assert result["status"] == "unknown"
    assert result["expected_commands"] is None
    assert [gap["reason"] for gap in result["gaps"]] == ["stored_contexts_unavailable"]
    assert not result["command_coverage_complete"]


def test_unusable_database_or_selection_root_keeps_denominator_null(tmp_path):
    rows, cdb = _write_project(tmp_path)
    index = _fake_index([])

    missing = reconcile_entry_instance_coverage(
        index, compile_commands_path=tmp_path / "absent.json", source_root=tmp_path
    )
    assert missing["status"] == "unknown"
    assert missing["expected_commands"] is None
    assert [gap["reason"] for gap in missing["gaps"]] == ["compile_database_missing"]

    cdb.write_text("{ not json")
    corrupt = reconcile_entry_instance_coverage(
        index, compile_commands_path=cdb, source_root=tmp_path
    )
    assert corrupt["status"] == "unknown"
    assert [gap["reason"] for gap in corrupt["gaps"]] == ["compile_database_invalid"]

    cdb.write_text('{"entries": []}')
    shaped = reconcile_entry_instance_coverage(
        index, compile_commands_path=cdb, source_root=tmp_path
    )
    assert [gap["reason"] for gap in shaped["gaps"]] == ["compile_database_invalid"]

    cdb.write_text("[]")
    empty = reconcile_entry_instance_coverage(
        index, compile_commands_path=cdb, source_root=tmp_path
    )
    assert empty["status"] == "reconciled"
    assert empty["expected_commands"] == []
    assert [gap["reason"] for gap in empty["gaps"]] == ["compile_database_empty"]
    assert not empty["command_coverage_complete"]

    _write_project(tmp_path)
    vanished = reconcile_entry_instance_coverage(
        index, compile_commands_path=cdb, source_root=tmp_path / "vanished"
    )
    assert vanished["status"] == "unknown"
    assert vanished["expected_commands"] is None
    assert [gap["reason"] for gap in vanished["gaps"]] == ["selection_root_unavailable"]


@pytest.fixture
def native_two_macro(tmp_path, monkeypatch):
    from zscope.retrieval.clang_backend import ClangBackend

    executable = os.environ.get("Z_SCOPE_TEST_CLANG_INDEXER")
    if not executable:
        pytest.skip("native variant tests require Z_SCOPE_TEST_CLANG_INDEXER")
    monkeypatch.setenv("Z_SCOPE_CLANG_BATCH_MEMORY_MB", "512")
    monkeypatch.setattr(
        ClangBackend, "_ensure_extractor", lambda self: pytest.fail("unexpected LSP")
    )
    (tmp_path / "flags.h").write_text("#define FLAG 1\n")
    (tmp_path / "unit.c").write_text(
        '#include "flags.h"\n'
        "void consume(int*);\n"
        "int f(int *p) {\n"
        "#ifdef ALT\n"
        "  consume(p);\n"
        "#endif\n"
        "  return FLAG;\n}\n"
    )
    rows = [
        dict(
            directory=str(tmp_path),
            file=str(tmp_path / "unit.c"),
            arguments=["clang", "-c", str(tmp_path / "unit.c"), *flags],
        )
        for flags in ([], ["-DALT=1"])
    ]
    cdb = tmp_path / "compile_commands.json"
    cdb.write_text(json.dumps(rows))
    backend = ClangBackend(frontend="batch", clang_indexer_path=executable, max_threads=2)
    try:
        assert backend.initialize(str(tmp_path), compile_commands_path=str(cdb))
        yield backend, tmp_path, cdb, rows
    finally:
        backend.close()


def _native_index(backend, root, cdb):
    from zscope.retrieval.code_index import CodeIndex

    return CodeIndex(root, cdb, backend=backend, indexing_config=SimpleNamespace(backend="clang"))


def test_native_two_macro_commands_reconcile_current(native_two_macro):
    backend, root, cdb, rows = native_two_macro
    index = _native_index(backend, root, cdb)
    # The publisher stores the root-relative source expression; the reconcile
    # must accept it as-is, not reject correct native contexts.
    assert {context["source"] for context in index.get_build_contexts("")} == {"unit.c"}
    result = reconcile_entry_instance_coverage(index, compile_commands_path=cdb, source_root=root)
    assert result["status"] == "reconciled"
    assert result["stored_contexts"] == 2
    assert len(result["expected_commands"]) == 2
    assert len({entry["command_id"] for entry in result["expected_commands"]}) == 2
    assert len(result["current_commands"]) == 2
    assert not result["gaps"]
    assert result["command_coverage_complete"]
    assert result["scan_coverage_complete"] is False
    assert result["scan_coverage_reasons"] == ["command_reconciliation_only"]


def test_native_dependency_change_breaks_currency_without_rerun(native_two_macro):
    backend, root, cdb, rows = native_two_macro
    index = _native_index(backend, root, cdb)
    (root / "flags.h").write_text("#define FLAG 2\n")
    result = reconcile_entry_instance_coverage(index, compile_commands_path=cdb, source_root=root)
    assert len(result["expected_commands"]) == 2
    assert not result["current_commands"]
    assert len(result["stale_contexts"]) == 2
    assert {entry["reason"] for entry in result["stale_contexts"]} == {"stale_build_dependencies"}
    assert not result["command_coverage_complete"]


def test_native_cdb_growth_after_indexing_leaves_command_missing(native_two_macro):
    backend, root, cdb, rows = native_two_macro
    index = _native_index(backend, root, cdb)
    grown = [*rows, {**rows[1], "arguments": [*rows[1]["arguments"], "-DEXTRA=1"]}]
    cdb.write_text(json.dumps(grown))
    result = reconcile_entry_instance_coverage(index, compile_commands_path=cdb, source_root=root)
    assert len(result["expected_commands"]) == 3
    assert not result["current_commands"]
    assert len(result["missing_commands"]) == 1
    assert {entry["reason"] for entry in result["stale_contexts"]} == {"stale_compilation_database"}
    assert {gap["reason"] for gap in result["gaps"]} == {
        "stale_compilation_database",
        "command_not_indexed",
    }
    assert not result["command_coverage_complete"]
