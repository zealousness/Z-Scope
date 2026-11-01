"""Compilation variants must not share proof facts or content identities."""

import json
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from zscope.retrieval.build_context import BuildContext
from zscope.retrieval.clang_backend import ClangBackend
from zscope.retrieval.clang_batch import BatchIndexer
from zscope.retrieval.indexing_identity import command_identity


def test_report_separates_extraction_from_scan_and_link_coverage():
    from zscope.retrieval.build_context import scan_build_coverage

    contexts = [
        {
            "source": "unit.c",
            "build_context_id": build,
            "status": "indexed",
            "dependencies_complete": True,
            "link_target": None,
        }
        for build in ("a", "b")
    ]
    result = scan_build_coverage(SimpleNamespace(get_build_contexts=lambda: contexts))
    assert result["extraction_complete"]
    assert not result["scan_complete"]
    assert result["variant_sources"] == {"unit.c": 2}
    assert result["reasons"] == [
        "scan_consumers_use_navigation_projection",
        "link_targets_unverified",
    ]
    contexts[1]["status"] = "failed"
    result = scan_build_coverage(SimpleNamespace(get_build_contexts=lambda: contexts))
    assert result["failed_instances"] == ["b"]
    assert not result["extraction_complete"]


def test_identity_binds_dependencies_tool_target_and_link_but_not_mapping_order(tmp_path):
    source = tmp_path / "unit.c"
    source.write_text("int f(void) { return 0; }\n")
    command = command_identity(
        {
            "file": str(source),
            "directory": str(tmp_path),
            "arguments": ["clang", "-c", str(source)],
        },
        tmp_path,
    )
    inputs = dict(
        tool={"sha256": "tool1"},
        dependencies={str(source): "a", "header.h": "b"},
        dependencies_complete=True,
        target={"triple": "x86_64"},
    )
    base = BuildContext.create(command, **inputs)
    reordered = {**inputs, "dependencies": {"header.h": "b", str(source): "a"}}
    assert BuildContext.create(command, **reordered) == base
    for change in (
        {"dependencies": {str(source): "a", "header.h": "changed"}},
        {"tool": {"sha256": "tool2"}},
        {"target": {"triple": "aarch64"}},
        {"dependencies_complete": False},
        {"link_target": {"binary": "server"}},
        {"include_probes": {"version": "zscope.include-probes.v1", "queries": []}},
    ):
        other = BuildContext.create(command, **{**inputs, **change})
        assert other.command_id == base.command_id
        assert other.context_id != base.context_id
    exported = base.to_dict()
    exported["dependencies"]["header.h"] = "edited"
    assert base.to_dict()["dependencies"]["header.h"] == "b"
    assert base.to_dict()["link_target"] is None


def test_native_include_probes_bind_missing_absolute_and_relative_files(tmp_path):
    from zscope.retrieval.indexing_identity import include_probes_current

    source = tmp_path / "f.cpp"
    source.write_text("// source")
    target = tmp_path / "optional.inc"
    for name, angled in ((str(target), True), ("optional.inc", False), ("optional.inc", True)):
        query = {
            "name": name,
            "angled": angled,
            "found": False,
            "including_file": str(source),
            "target_file": "",
        }
        receipt = {
            "version": "zscope.include-probes.v1",
            "search_directories": [str(tmp_path)],
            "queries": [query],
        }
        assert include_probes_current(receipt)
        target.write_text("// existence only")
        assert not include_probes_current(receipt)
        query.update(found=True, target_file=str(target))
        assert include_probes_current(receipt)
        target.unlink()
        assert not include_probes_current(receipt)
    assert not include_probes_current({"version": "unrecognized"})
    assert not include_probes_current(
        {"version": "zscope.include-probes.v1", "search_directories": [1], "queries": []}
    )


def test_include_next_negative_probe_skips_the_origin_search_directory(tmp_path):
    from zscope.retrieval.indexing_identity import include_probes_current

    high = tmp_path / "high"
    low = tmp_path / "low"
    high.mkdir()
    low.mkdir()
    including = high / "wrapper.h"
    including.write_text("/* wrapper */\n", encoding="utf-8")
    # This candidate precedes the include-next starting point and therefore
    # cannot invalidate the observed negative result.
    (high / "probe.h").write_text("/* shadowed before next */\n", encoding="utf-8")
    query = {
        "name": "probe.h",
        "angled": True,
        "including_file": str(including),
        "found": False,
        "target_file": "",
    }
    probes = {
        "version": "zscope.include-probes.v1",
        "search_directories": [str(high), str(low)],
        "queries": [query],
    }
    lookups = {
        "version": "zscope.include-lookups.v1",
        "search_directories": [{"path": str(high)}, {"path": str(low)}],
        "probe_lookups": [{**query, "operator": "__has_include_next"}],
    }
    assert include_probes_current(probes, lookups)
    (low / "probe.h").write_text("/* now visible to include-next */\n", encoding="utf-8")
    assert not include_probes_current(probes, lookups)


def test_jobs_select_every_variant_deduplicate_only_identical_commands(tmp_path):
    source = tmp_path / "unit.c"
    source.write_text("int f(void);\n")
    row = {
        "file": str(source),
        "directory": str(tmp_path),
        "arguments": ["clang", "-c", str(source)],
    }
    cdb = tmp_path / "compile_commands.json"
    cdb.write_text(json.dumps([row, row, {**row, "arguments": [*row["arguments"], "-DALT=1"]}]))
    indexer = BatchIndexer.__new__(BatchIndexer)
    indexer.root, indexer.tool, indexer.stats = tmp_path, {}, {}
    indexer.backend = SimpleNamespace(
        _compile_commands_path=cdb,
        _include_paths=[],
        _exclude_paths=[],
        _collect_source_files=lambda: [source],
    )
    jobs = indexer._jobs()
    assert len(jobs) == 2
    assert len({job["context"] for job in jobs}) == 2
    assert not indexer.stats["projection_complete"]
    assert indexer.stats["variant_sources"] == {str(source): 2}


@pytest.fixture
def native_variants(tmp_path, monkeypatch):
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


def test_native_variants_are_queryable_without_mixing_program_events(native_variants):
    backend, root, cdb, rows = native_variants
    from zscope.retrieval.code_index import CodeIndex

    index = CodeIndex(root, cdb, backend=backend, indexing_config=SimpleNamespace(backend="clang"))
    contexts = index.get_build_contexts("unit.c")
    assert len(contexts) == 2
    assert len({c["build_context_id"] for c in contexts}) == 2
    ambiguous = index.get_function_program_facts("f", "unit.c")
    assert not ambiguous["complete"] and not ambiguous["events"]
    assert ambiguous["reason"] == "ambiguous_build_context"
    for context in contexts:
        facts = index.get_function_program_facts(
            "f", "unit.c", build_context_id=context["build_context_id"]
        )
        assert facts["complete"]
        assert facts["build_context_id"] == context["build_context_id"]
        assert not facts["cross_tu_complete"]
        calls = [
            event
            for event in facts["events"]
            if (event.get("callee") or {}).get("name") == "consume"
        ]
        assert bool(calls) == ("-DALT=1" in context["command"]["arguments"])
    missing = index.get_function_program_facts("f", "unit.c", build_context_id="not-a-real-context")
    assert missing["reason"] == "build_context_not_found" and not missing["events"]


def test_native_variants_hot_reuse_dependency_change_and_variant_removal(native_variants):
    backend, root, cdb, rows = native_variants
    original = backend.get_build_contexts()
    ids = {c["build_context_id"] for c in original}
    assert backend._run_full_extraction()
    assert {c["build_context_id"] for c in backend.get_build_contexts()} == ids
    stats = json.loads(backend.db.get_metadata("clang_batch_stats"))
    assert stats["reused_tus"] == 2 and stats["compiled_tus"] == 0
    (root / "flags.h").write_text("#define FLAG 2\n")
    assert backend._run_full_extraction()
    assert not ids & {c["build_context_id"] for c in backend.get_build_contexts()}
    for stale in ids:
        assert (
            backend.get_function_program_facts("f", "unit.c", build_context_id=stale)["reason"]
            == "build_context_not_found"
        )
    cdb.write_text(json.dumps(rows[:1]))
    assert backend._run_full_extraction()
    assert len(backend.get_build_contexts()) == 1
    assert backend.get_function_program_facts("f", "unit.c")["complete"]


def test_native_variant_reorder_does_not_change_context_identity(native_variants):
    backend, _, cdb, rows = native_variants
    before = {c["build_context_id"] for c in backend.get_build_contexts()}
    cdb.write_text(json.dumps(list(reversed(rows))))
    assert backend._run_full_extraction()
    assert {c["build_context_id"] for c in backend.get_build_contexts()} == before


def test_semantic_tool_reads_exact_context_without_modeling(native_variants):
    from zscope.tools.semantic_context import SemanticContextTool
    from zscope.retrieval.code_index import CodeIndex
    from zscope.tools.symbols import SymbolCatalog
    from zscope.framework.base import validate_function_arguments

    backend, root, cdb, _ = native_variants
    index = CodeIndex(root, cdb, backend=backend, indexing_config=SimpleNamespace(backend="clang"))
    tool = SemanticContextTool(
        SimpleNamespace(snapshot_dir=root / "snapshots"),
        index,
        SymbolCatalog(index),
        resolver=lambda *_: pytest.fail("compilation queries must not call the LLM"),
        cache_only=True,
    )
    listed = tool.execute({"kind": "build_contexts", "limit": 1})
    assert validate_function_arguments(tool.contract.output_schema, listed) is None
    assert listed["page"]["total"] == 2 and listed["page"]["has_more"]
    identity = listed["data"]["records"][0]["build_context_id"]
    result = tool.execute({"kind": "program_facts", "query": "f", "build_context_id": identity})
    assert validate_function_arguments(tool.contract.output_schema, result) is None
    assert result["data"]["summary"]["build_context_id"] == identity
    assert result["data"]["summary"]["complete"]
    invalid = tool.execute({"kind": "program_facts", "query": "f"})
    assert invalid["status"] == "invalid_request"
    assert (
        tool.execute({"kind": "program_facts", "query": "f", "build_context_id": "0" * 64})[
            "status"
        ]
        == "not_found"
    )
    (root / "flags.h").write_text("#define FLAG 99\n")
    stale = tool.execute({"kind": "program_facts", "query": "f", "build_context_id": identity})
    assert stale["status"] == "partial" and stale["data"]["records"] == []
    assert "stale_build_dependencies" in stale["coverage"]["missing"]


def test_semantic_reuse_separates_build_receipts_from_compiler_meaning():
    from copy import deepcopy
    from zscope.semantics.compiler_fingerprint import compiler_structure

    original = {
        "build_context_id": "old",
        "build_context": {
            "build_context_id": "old",
            "dependencies": {"a.c": "old"},
            "command_id": "command",
            "tool": {"sha256": "tool"},
            "target": {"target.pointer_bits": 64},
            "link_target": None,
        },
        "events": [{"operation": "read"}],
    }
    relocated = deepcopy(original)
    relocated["build_context_id"] = "new"
    relocated["build_context"]["build_context_id"] = "new"
    relocated["build_context"]["dependencies"]["a.c"] = "comment-only"
    assert compiler_structure(original) == compiler_structure(relocated)
    relocated["build_context"]["command_id"] = "different-macros"
    assert compiler_structure(original) != compiler_structure(relocated)
    assert compiler_structure({"object": {"build_context_id": "a"}}) != compiler_structure(
        {"object": {"build_context_id": "b"}}
    )


def test_compilation_receipts_reject_changed_response_files_and_environment(tmp_path, monkeypatch):
    from zscope.retrieval.build_context import context_input_status
    from zscope.retrieval.indexing_identity import file_digest, search_directories_snapshot

    source, response, cdb = (
        tmp_path / name for name in ("unit.c", "flags.rsp", "compile_commands.json")
    )
    source.write_text("int value;\n")
    response.write_text("-DALT=1\n")
    row = dict(
        file=str(source),
        directory=str(tmp_path),
        arguments=["clang", "@flags.rsp", "-c", str(source)],
    )
    cdb.write_text(json.dumps([row]))
    context = BuildContext.create(
        command_identity(row, tmp_path),
        tool={},
        dependencies={str(source): file_digest(source)},
        dependencies_complete=True,
    ).to_dict()
    context.update(
        status="indexed",
        compilation_database={"path": str(cdb), "sha256": file_digest(cdb)},
        search_directories=search_directories_snapshot([tmp_path]),
    )
    assert context_input_status(context) == "current"
    with monkeypatch.context() as env:
        env.setenv("CPATH", str(tmp_path / "new-headers"))
        assert context_input_status(context) == "stale_build_command"
    response.write_text("-DALT=2\n")
    assert context_input_status(context) == "stale_build_command"
    response.write_text("-DALT=1\n")
    (tmp_path / "new_header.h").write_text("#define ALT 2\n")
    assert context_input_status(context) == "stale_include_search"
    cdb.write_text("[]\n")
    assert context_input_status(context) == "stale_compilation_database"


def test_deleting_tu_removes_all_compilation_variants(native_variants):
    backend, _, _, _ = native_variants
    contexts = backend.get_build_contexts("unit.c")
    assert len(contexts) == 2
    tu = next(row for row in backend.db.get_all_tus() if row["file_path"] == "unit.c")
    backend.db.delete_tu(tu["id"])
    assert backend.get_build_contexts("unit.c") == []
    for context in contexts:
        assert backend.db.get_compilation_facts(context["build_context_id"]) == []


def _coverage_context(build_id: str, *, status: str = "indexed") -> dict:
    return {
        "source": "unit.c",
        "build_context_id": build_id,
        "status": status,
        "dependencies_complete": status == "indexed",
        "link_target": None,
    }


class _CoverageIndex:
    """Minimal index double: every stored context, no pinned enumeration."""

    def __init__(self, contexts):
        self.contexts = list(contexts)
        self.asked: list[str] = []

    def get_build_contexts(self, file_path: str = "") -> list:
        self.asked.append(file_path)
        return [dict(context) for context in self.contexts]


class _ScopedCoverageIndex:
    """Pinned enumeration plus the coverage accessor a real facade exposes."""

    def __init__(self, base, pinned: str, source: str = "unit.c"):
        self.base = base
        self.pinned_build_context_id = pinned
        self.pinned_source = source

    def coverage_index(self):
        return self.base

    def get_build_contexts(self, file_path: str = "") -> list:
        return [
            dict(context)
            for context in self.base.get_build_contexts(file_path)
            if context["build_context_id"] == self.pinned_build_context_id
        ]


def test_coverage_view_reads_stored_instances_not_the_pinned_subset():
    """A scoped facade must not collapse the coverage counts to one instance."""

    from zscope.retrieval.build_context import scan_build_coverage

    plain = _CoverageIndex([_coverage_context("a"), _coverage_context("b")])
    scoped = _ScopedCoverageIndex(plain, "b")

    # The facade itself still reports one instance: instance semantics depend
    # on exactly one current context, so the fix adds a second accessor.
    assert len(scoped.get_build_contexts("unit.c")) == 1

    scan_view = scan_build_coverage(plain)
    instance_view = scan_build_coverage(scoped)
    assert scan_view["view"] == "scan"
    assert instance_view["view"] == "instance"
    assert instance_view["pinned_build_context_id"] == "b"
    assert instance_view["instances"] == 2
    assert instance_view["variant_sources"] == {"unit.c": 2}
    assert instance_view["scan_complete"] is False

    stripped = {
        key: value
        for key, value in instance_view.items()
        if key not in {"view", "pinned_build_context_id"}
    }
    scan_stripped = {key: value for key, value in scan_view.items() if key != "view"}
    assert stripped == scan_stripped


def test_coverage_view_ignores_instances_of_other_sources():
    from zscope.retrieval.build_context import scan_build_coverage

    other = dict(_coverage_context("c"))
    other["source"] = "other.c"
    plain = _CoverageIndex([_coverage_context("a"), _coverage_context("b"), other])
    instance_view = scan_build_coverage(_ScopedCoverageIndex(plain, "a"))
    assert instance_view["instances"] == 2
    assert instance_view["sources"] == 1
    assert instance_view["variant_sources"] == {"unit.c": 2}


def test_coverage_view_reports_a_failed_sibling_variant():
    from zscope.retrieval.build_context import scan_build_coverage

    plain = _CoverageIndex([_coverage_context("a", status="failed"), _coverage_context("b")])
    instance_view = scan_build_coverage(_ScopedCoverageIndex(plain, "b"))
    assert instance_view["failed_instances"] == ["a"]
    assert instance_view["extraction_complete"] is False
    assert "incomplete_compilation_instances" in instance_view["reasons"]
    assert instance_view["scan_complete"] is False


def test_coverage_view_marks_receipt_less_instances_unmeasured():
    """A summary without receipts is never promoted to a current instance."""

    from zscope.retrieval.build_context import scan_build_coverage

    plain = _CoverageIndex([_coverage_context("a"), _coverage_context("b")])
    coverage = scan_build_coverage(plain)
    assert coverage["instance_input_status"] == {"a": "unmeasured", "b": "unmeasured"}
    assert coverage["uncurrent_instances"] == []
    assert coverage["extraction_complete"] is True
    assert "stale_compilation_instance_inputs" not in coverage["reasons"]


def _measured_coverage_context(tmp_path, build_id: str, header: Path) -> dict:
    """A stored context that really carries the receipts currency re-checks."""

    from zscope.retrieval.indexing_identity import (
        digest_json,
        file_digest,
        search_directories_snapshot,
    )

    source = tmp_path / "unit.c"
    database = tmp_path / "compile_commands.json"
    command = command_identity(
        {
            "file": str(source),
            "directory": str(tmp_path),
            "arguments": ["clang", "-c", str(source)],
        },
        tmp_path,
    )
    return {
        "source": str(source),
        "build_context_id": build_id,
        "status": "indexed",
        "dependencies_complete": True,
        "command": command,
        "command_id": digest_json(command),
        "dependencies": {
            str(source): file_digest(source),
            str(header): file_digest(header),
            str(database): file_digest(database),
        },
        "compilation_database": {
            "path": str(database),
            "sha256": file_digest(database),
        },
        "search_directories": search_directories_snapshot([tmp_path]),
        "search_excludes": [],
        "include_probes": {
            "version": "zscope.include-probes.v1",
            "search_directories": [str(tmp_path)],
            "queries": [],
        },
    }


def test_coverage_view_names_a_stale_stored_instance_instead_of_counting_it(tmp_path):
    from zscope.retrieval.build_context import scan_build_coverage

    (tmp_path / "unit.c").write_text("int f(void) { return 0; }\n", encoding="utf-8")
    (tmp_path / "compile_commands.json").write_text("[]\n", encoding="utf-8")
    header_a = tmp_path / "a.h"
    header_b = tmp_path / "b.h"
    header_a.write_text("#define A 1\n", encoding="utf-8")
    header_b.write_text("#define B 1\n", encoding="utf-8")
    a = _measured_coverage_context(tmp_path, "a", header_a)
    b = _measured_coverage_context(tmp_path, "b", header_b)
    plain = SimpleNamespace(get_build_contexts=lambda: [dict(a), dict(b)])

    covered = scan_build_coverage(plain)
    assert covered["instance_input_status"] == {"a": "current", "b": "current"}
    assert covered["uncurrent_instances"] == []
    assert covered["reasons"] == [
        "scan_consumers_use_navigation_projection",
        "link_targets_unverified",
    ]

    # A dependency edit invalidates only the instance that read this header.
    header_b.write_text("#define B 2\n", encoding="utf-8")
    stale = scan_build_coverage(plain)
    assert stale["instance_input_status"]["a"] == "current"
    assert stale["instance_input_status"]["b"] == "stale_build_dependencies"
    assert stale["uncurrent_instances"] == ["b"]
    # Extraction still succeeded; the inputs behind it did not survive.
    assert stale["extraction_complete"] is True
    assert stale["status"] == "partial"
    assert "stale_compilation_instance_inputs" in stale["reasons"]


def test_coverage_currentness_honors_each_context_search_excludes(tmp_path):
    from zscope.retrieval.build_context import scan_build_coverage
    from zscope.retrieval.indexing_identity import search_directories_snapshot

    (tmp_path / "unit.c").write_text("int f(void) { return 0; }\n", encoding="utf-8")
    (tmp_path / "compile_commands.json").write_text("[]\n", encoding="utf-8")
    header = tmp_path / "unit.h"
    header.write_text("#define VALUE 1\n", encoding="utf-8")
    generated = tmp_path / ".cache" / "clangd"
    context = _measured_coverage_context(tmp_path, "a", header)
    context["search_excludes"] = [str(generated)]
    context["search_directories"] = search_directories_snapshot(
        [tmp_path], exclude_paths=[generated]
    )
    plain = SimpleNamespace(get_build_contexts=lambda: [dict(context)])

    generated.mkdir(parents=True)
    (generated / "unit.idx").write_text("generated", encoding="utf-8")

    coverage = scan_build_coverage(plain)

    assert coverage["instance_input_status"] == {"a": "current"}
    assert coverage["uncurrent_instances"] == []
