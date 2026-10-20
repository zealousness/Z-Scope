"""Entry compile-instance enumeration is the scan scheduling boundary.

Every scheduled instance is an exact ``(build_context_id, usr)`` pair queried
through scoped program facts; same-source macro variants are enumerated
separately, unknown is never a wildcard, and a failed or absent variant stays
a precise coverage gap instead of borrowing another variant's evidence.

The ``_VariantCodeIndex`` double stands in for the native/DB extraction layer
only; it does not fake native extraction results as a full scan. The
native-gated test at the bottom exercises the real ClangBackend, real
CodeIndex facade, and the real planner end to end.
"""

import json
import os
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import pytest

from zscope.config.function_entry import FunctionEntry
from zscope.orchestration.entry_instances import (
    ENTRY_INSTANCE_SCHEMA,
    plan_entry_instances,
)
from zscope.orchestration.scan_session import ScanSessionRunner
from zscope.retrieval.build_context import program_facts_result

# ── Test double: stands in for the native/DB layer only ──


def _make_context(context_id: str, source: str, *, indexed: bool = True, complete: bool = True):
    return {
        "build_context_id": context_id,
        "source": source,
        "status": "indexed" if indexed else "failed",
        "dependencies_complete": complete,
        "command": {"source": source, "directory": "/proj", "arguments": ["clang", "-c", source]},
    }


def _facts_row(usr: str, name: str, file_path: str, events: Optional[List[str]] = None):
    return {
        "kind": "program_function",
        "complete": True,
        "owner": {"usr": usr, "name": name, "file": file_path},
        "events": list(events or []),
    }


class _VariantCodeIndex:
    """In-memory stand-in for CodeIndex over a multi-variant instance store."""

    language = "c_cpp"
    backend_name = "clang"

    def __init__(
        self,
        contexts: List[Dict[str, Any]],
        facts: Dict[str, List[Dict[str, Any]]],
    ):
        self.contexts = list(contexts)
        self.facts = dict(facts)
        self.queries: List[Tuple[str, str, str]] = []
        self.function_context_calls: List[Tuple[str, str]] = []

    def get_build_contexts(self, file_path: str = "") -> List[Dict[str, Any]]:
        if not file_path:
            return list(self.contexts)
        return [dict(c) for c in self.contexts if c["source"] == file_path]

    def get_function_build_contexts(self, func_name: str, file_path: str = ""):
        self.function_context_calls.append((func_name, file_path))
        rows = [
            dict(c)
            for c in self.contexts
            if any(
                row["owner"]["name"] == func_name or row["owner"]["usr"] == func_name
                for row in self.facts.get(c["build_context_id"], [])
            )
        ]
        if file_path:
            rows = [
                c
                for c in rows
                if any(
                    row["owner"]["name"] == func_name and row["owner"]["file"] == file_path
                    for row in self.facts.get(c["build_context_id"], [])
                )
            ]
        return rows

    def get_function_program_facts(
        self, func_name: str, file_path: str = "", *, build_context_id: str = ""
    ) -> Dict[str, Any]:
        self.queries.append((func_name, file_path, build_context_id))
        if not build_context_id:
            return {"complete": False, "events": [], "reason": "unscoped_query"}
        matching = list(self.facts.get(build_context_id, []))
        if func_name.startswith("c:"):
            matching = [row for row in matching if row["owner"]["usr"] == func_name]
        else:
            matching = [row for row in matching if row["owner"]["name"] == func_name]
            if file_path:
                file_matching = [row for row in matching if row["owner"]["file"] == file_path]
                if not file_matching:
                    return {
                        "complete": False,
                        "events": [],
                        "reason": "function_identity_not_found",
                    }
                matching = file_matching
        if not matching:
            return {
                "complete": False,
                "events": [],
                "reason": "function_identity_not_found",
            }
        context = next((c for c in self.contexts if c["build_context_id"] == build_context_id), {})
        return program_facts_result(matching, context=context)


# ── Positive: same source, two macro variants ──


def _two_variant_index() -> _VariantCodeIndex:
    contexts = [
        _make_context("ctx-base", "unit.c"),
        _make_context("ctx-alt", "unit.c"),
    ]
    facts = {
        "ctx-base": [_facts_row("c:@F@f", "f", "unit.c", events=["return"])],
        "ctx-alt": [_facts_row("c:@F@f", "f", "unit.c", events=["call:consume", "return"])],
    }
    return _VariantCodeIndex(contexts, facts)


def test_two_macro_variants_enumerated_separately_with_exact_queries():
    index = _two_variant_index()
    plan = plan_entry_instances(index, [FunctionEntry("f", file_path="unit.c")])

    assert plan.status == "planned"
    assert plan.entry_count == 1
    assert plan.variant_entry_count == 1
    assert len(plan.instances) == 2
    assert not plan.gaps
    assert plan.boundary_coverage_complete
    # Each variant is queried exactly once, with its own build_context_id.
    assert index.queries == [("f", "unit.c", "ctx-base"), ("f", "unit.c", "ctx-alt")]
    payloads = [instance.to_payload() for instance in plan.instances]
    assert {p["build_context_id"] for p in payloads} == {"ctx-base", "ctx-alt"}
    assert all(p["usr"] == "c:@F@f" for p in payloads)
    assert len({p["identity"] for p in payloads}) == 2


def test_identical_instances_deduplicate_only_exact_pairs():
    index = _two_variant_index()
    entries = [FunctionEntry("f", file_path="unit.c")] * 3
    plan = plan_entry_instances(index, entries)

    assert plan.entry_count == 1  # duplicate entries collapse
    assert len(plan.instances) == 2  # ctx-base/ctx-alt stay separate instances
    assert not plan.gaps
    assert len(index.queries) == 2


def test_payload_reports_boundary_only_scan_coverage_incomplete():
    plan = plan_entry_instances(_two_variant_index(), [FunctionEntry("f", file_path="unit.c")])
    payload = plan.to_payload()

    assert payload["schema"] == ENTRY_INSTANCE_SCHEMA
    assert payload["boundary_coverage_complete"] is True
    assert payload["scan_coverage_complete"] is False
    assert payload["scan_coverage_reasons"] == ["entry_analysis_not_instance_scoped"]
    assert payload["fact_queries"] == 2
    assert payload["variant_entries"] == 1
    assert len(payload["instances"]) == 2
    assert all(record["coverage_complete"] for record in payload["entry_records"])


# ── Negative: single-variant failure stays a precise gap ──


def test_failed_variant_keeps_precise_gap_without_borrowing():
    contexts = [
        _make_context("ctx-ok", "unit.c"),
        _make_context("ctx-failed", "unit.c", indexed=False, complete=False),
    ]
    facts = {"ctx-ok": [_facts_row("c:@F@f", "f", "unit.c")]}
    index = _VariantCodeIndex(contexts, facts)

    plan = plan_entry_instances(index, [FunctionEntry("f", file_path="unit.c")])

    assert plan.status == "planned"
    assert [i.build_context_id for i in plan.instances] == ["ctx-ok"]
    assert len(plan.gaps) == 1
    gap = plan.gaps[0]
    assert gap.build_context_id == "ctx-failed"
    assert gap.reason == "incomplete_compilation_instance"
    assert not plan.boundary_coverage_complete
    assert plan.to_payload()["gaps"][0]["build_context_id"] == "ctx-failed"
    # The failed variant is never queried; only the healthy one is.
    assert index.queries == [("f", "unit.c", "ctx-ok")]


def test_entry_absent_in_one_variant_is_a_gap_not_borrowed():
    contexts = [
        _make_context("ctx-base", "unit.c"),
        _make_context("ctx-alt", "unit.c"),
    ]
    facts = {
        "ctx-base": [_facts_row("c:@F@f", "f", "unit.c")],
        "ctx-alt": [_facts_row("c:@F@g", "g", "unit.c")],
    }
    index = _VariantCodeIndex(contexts, facts)

    plan = plan_entry_instances(index, [FunctionEntry("f", file_path="unit.c")])

    assert [i.build_context_id for i in plan.instances] == ["ctx-base"]
    gaps = [g for g in plan.gaps if g.function_name == "f"]
    assert len(gaps) == 1
    assert gaps[0].build_context_id == "ctx-alt"
    assert gaps[0].reason == "entry_absent_in_variant"
    assert not plan.boundary_coverage_complete
    # The absence retry stays scoped to the exact variant context.
    assert ("f", "", "ctx-alt") in index.queries


def test_entry_missing_everywhere_keeps_entry_level_gap():
    index = _two_variant_index()
    plan = plan_entry_instances(index, [FunctionEntry("missing_fn")])

    assert plan.status == "planned"
    assert not plan.instances
    assert all(g.reason == "no_compilation_instance" for g in plan.gaps)
    record = plan.entry_records[0]
    assert record["coverage_complete"] is False
    assert record["note"] == "entry_source_unresolved"


def test_function_absent_from_only_context_is_proven_absence():
    index = _VariantCodeIndex([_make_context("ctx-base", "unit.c")], {})
    plan = plan_entry_instances(index, [FunctionEntry("f", file_path="unit.c")])

    assert not plan.instances
    assert plan.gaps and plan.gaps[0].reason == "entry_absent_in_variant"
    assert plan.gaps[0].build_context_id == "ctx-base"


# ── Unknown is not a wildcard; no first-context fallback ──


def test_no_instance_store_yields_unavailable_not_coverage():
    class _NoInstanceIndex:
        language = "c_cpp"
        backend_name = "clang"

        def get_build_contexts(self, file_path: str = ""):
            return []

        def get_function_program_facts(self, *args, **kwargs):
            raise AssertionError("must not be reached when no instance store exists")

    plan = plan_entry_instances(_NoInstanceIndex(), [FunctionEntry("f", file_path="unit.c")])

    assert plan.status == "unavailable"
    assert plan.reasons == ["compilation_instances_unavailable"]
    assert not plan.instances
    assert [g.reason for g in plan.gaps] == ["compilation_instances_unavailable"]
    assert not plan.boundary_coverage_complete


def test_lsp_cleared_instances_reported_with_inventory_summary(tmp_path):
    cdb = tmp_path / "compile_commands.json"
    cdb.write_text(
        json.dumps(
            [
                {
                    "directory": str(tmp_path),
                    "file": str(tmp_path / "unit.c"),
                    "arguments": ["clang", "-c", str(tmp_path / "unit.c")],
                },
                {
                    "directory": str(tmp_path),
                    "file": str(tmp_path / "unit.c"),
                    "arguments": ["clang", "-c", str(tmp_path / "unit.c"), "-DALT=1"],
                },
            ]
        )
    )

    class _LspIndex:
        language = "c_cpp"
        backend_name = "clang"

        def get_build_contexts(self, file_path: str = ""):
            return []  # LSP transition deletes the exact-context store

        def get_function_program_facts(self, *args, **kwargs):
            raise AssertionError("no query may run without instances")

    plan = plan_entry_instances(
        _LspIndex(), [FunctionEntry("f", file_path="unit.c")], compile_commands_path=cdb
    )

    assert plan.status == "unavailable"
    payload = plan.to_payload()
    database = payload["compile_database"]
    assert database["command_entries"] == 2
    assert database["compile_contexts"] == 2
    assert database["variant_sources"] == {str(tmp_path / "unit.c"): 2}
    # The database shows expected variants, but coverage must stay unknown.
    assert payload["gaps"][0]["reason"] == "compilation_instances_unavailable"
    assert payload["scan_coverage_complete"] is False


def test_unscoped_query_never_used_by_boundary():
    class _UnscopedTrapIndex(_VariantCodeIndex):
        def get_function_program_facts(self, func_name, file_path="", *, build_context_id=""):
            if not build_context_id:
                raise AssertionError("boundary must always pass build_context_id")
            return super().get_function_program_facts(
                func_name, file_path, build_context_id=build_context_id
            )

    index = _UnscopedTrapIndex(
        [_make_context("ctx-base", "unit.c")],
        {"ctx-base": [_facts_row("c:@F@f", "f", "unit.c")]},
    )
    plan = plan_entry_instances(index, [FunctionEntry("f", file_path="unit.c")])

    assert plan.status == "planned"
    assert [i.build_context_id for i in plan.instances] == ["ctx-base"]


def test_java_and_regex_backends_stay_not_applicable():
    java_like = type("JavaIndex", (), {"language": "java", "backend_name": "java_unified"})()
    plan = plan_entry_instances(java_like, [FunctionEntry("f")])
    assert plan.status == "not_applicable"
    assert plan.reasons == ["java_scan_has_no_compilation_instances"]
    assert not plan.instances and not plan.gaps

    regex_like = type("RegexIndex", (), {"language": "c_cpp", "backend_name": "regex"})()
    plan = plan_entry_instances(regex_like, [FunctionEntry("f", file_path="unit.c")])
    assert plan.status == "not_applicable"
    assert "regex_backend_has_no_compilation_instances" in plan.reasons


# ── Overload ambiguity stays per-context, never cross-variant ──


def test_overload_in_one_variant_resolved_by_usr_within_context():
    contexts = [_make_context("ctx-base", "unit.c")]
    facts = {
        "ctx-base": [
            _facts_row("c:@F@f#I#", "f", "unit.c"),
            _facts_row("c:@F@f#S#", "f", "unit.c"),
        ]
    }
    index = _VariantCodeIndex(contexts, facts)

    plan = plan_entry_instances(index, [FunctionEntry("f", file_path="unit.c")])

    assert len(plan.instances) == 2
    assert {i.usr for i in plan.instances} == {"c:@F@f#I#", "c:@F@f#S#"}
    assert all(i.build_context_id == "ctx-base" for i in plan.instances)
    assert not plan.gaps


# ── Returned-identity verification: never mix contexts, never wildcard ──


class _CannedFactsIndex:
    """Serves scoped program-facts responses built by the real result builder."""

    language = "c_cpp"
    backend_name = "clang"

    def __init__(self, contexts, responses):
        # responses: {(build_context_id, func_name, file_path): facts dict}
        self.contexts = list(contexts)
        self.responses = dict(responses)
        self.queries: List[Tuple[str, str, str]] = []

    def get_build_contexts(self, file_path: str = ""):
        if not file_path:
            return list(self.contexts)
        return [dict(c) for c in self.contexts if c["source"] == file_path]

    def get_function_build_contexts(self, func_name: str, file_path: str = ""):
        return [
            dict(c)
            for c in self.contexts
            if any(
                key[0] == c["build_context_id"] and key[1] == func_name and key[2] == ""
                for key in self.responses
            )
        ]

    def get_function_program_facts(
        self, func_name: str, file_path: str = "", *, build_context_id: str = ""
    ) -> Dict[str, Any]:
        self.queries.append((func_name, file_path, build_context_id))
        return self.responses.get(
            (build_context_id, func_name, file_path),
            {"complete": False, "events": [], "reason": "function_identity_not_found"},
        )


def test_foreign_build_identity_in_returned_facts_is_gap():
    """A complete answer naming another context must not enter this scope."""
    bc_a = _make_context("bc-a", "unit.c")
    bc_b = _make_context("bc-b", "unit.c")
    # The getter answers the bc-a query with bc-b's identity, exactly as the
    # coordinator probe observed.
    foreign = program_facts_result([_facts_row("usr-main", "f", "unit.c")], context=bc_b)
    index = _CannedFactsIndex([bc_a], {("bc-a", "f", "unit.c"): foreign})

    plan = plan_entry_instances(index, [FunctionEntry("f", file_path="unit.c")])

    assert plan.status == "planned"
    assert not plan.instances
    assert len(plan.gaps) == 1
    gap = plan.gaps[0]
    assert gap.build_context_id == "bc-a"
    assert gap.reason == "identity_context_mismatch"
    assert "bc-a" in gap.detail and "bc-b" in gap.detail
    assert not plan.boundary_coverage_complete


def test_identity_without_build_context_is_not_wildcard():
    bc_a = _make_context("bc-a", "unit.c")
    unverified = {
        "complete": True,
        "build_context_id": "bc-a",
        "function_identity": {"usr": "usr-main", "key": "opaque-key"},
        "functions": [
            {
                "kind": "program_function",
                "complete": True,
                "owner": {"usr": "usr-main", "name": "f", "file": "unit.c"},
                "events": [],
            }
        ],
        "events": [],
        "accesses": [],
    }
    index = _CannedFactsIndex([bc_a], {("bc-a", "f", "unit.c"): unverified})

    plan = plan_entry_instances(index, [FunctionEntry("f", file_path="unit.c")])

    assert not plan.instances
    assert plan.gaps[0].reason == "identity_context_unverified"
    assert not plan.boundary_coverage_complete


def test_explicit_entry_file_not_bypassed_by_fileless_retry():
    """A same-name definition in another file never satisfies the entry file."""
    bc_a = _make_context("bc-a", "unit.c")
    # Direct file-scoped query misses; the file-less retry in the same context
    # finds only other.c's same-name definition.
    other_file = program_facts_result([_facts_row("usr-other", "f", "other.c")], context=bc_a)
    index = _CannedFactsIndex([bc_a], {("bc-a", "f", ""): other_file})

    plan = plan_entry_instances(index, [FunctionEntry("f", file_path="unit.c")])

    assert plan.status == "planned"
    assert not plan.instances
    gap = plan.gaps[0]
    assert gap.build_context_id == "bc-a"
    assert gap.reason == "entry_absent_in_variant"
    assert "other.c" in gap.detail and "unit.c" in gap.detail
    assert index.queries == [("f", "unit.c", "bc-a"), ("f", "", "bc-a")]
    assert not plan.boundary_coverage_complete


@pytest.mark.parametrize(
    "entry_file", ["../unit.c", "../../unit.c", "sub/../../unit.c", "..\\unit.c"]
)
def test_parent_relative_entry_file_is_not_an_inside_project_definition(entry_file):
    context = _make_context("bc-a", "unit.c")
    facts = program_facts_result([_facts_row("c:@F@f", "f", "unit.c")], context=context)
    index = _CannedFactsIndex(
        [context], {("bc-a", "f", entry_file): facts, ("bc-a", "f", ""): facts}
    )
    plan = plan_entry_instances(index, [FunctionEntry("f", file_path=entry_file)])
    assert not plan.instances
    assert not plan.boundary_coverage_complete


def test_retry_authorized_only_by_exact_definition_file_mapping():
    bc_a = _make_context("bc-a", "unit.c")
    same_file = program_facts_result([_facts_row("c:@F@f", "f", "unit.c")], context=bc_a)
    index = _CannedFactsIndex([bc_a], {("bc-a", "f", ""): same_file})

    plan = plan_entry_instances(index, [FunctionEntry("f", file_path="unit.c")])

    assert len(plan.instances) == 1
    instance = plan.instances[0]
    assert instance.build_context_id == "bc-a"
    assert instance.usr == "c:@F@f"
    # The selection basis is the precise definition-file mapping, not the
    # entry-file query that actually missed.
    assert instance.selected_by == "definition_file_match"
    assert not plan.gaps


def test_retry_choice_authorization_requires_exact_file_no_suffix():
    bc_a = _make_context("bc-a", "unit.c")
    ambiguous_across_files = program_facts_result(
        [
            _facts_row("c:@F@f#1", "f", "src/unit.c"),
            _facts_row("c:@F@f#2", "f", "other.c"),
        ],
        context=bc_a,
    )
    index = _CannedFactsIndex([bc_a], {("bc-a", "f", ""): ambiguous_across_files})

    plan = plan_entry_instances(index, [FunctionEntry("f", file_path="unit.c")])

    assert not plan.instances
    gap = plan.gaps[0]
    assert gap.reason == "entry_absent_in_variant"
    # A suffix-matching path and a foreign file are both named as unselected.
    assert "src/unit.c" in gap.detail and "other.c" in gap.detail
    assert not plan.boundary_coverage_complete


def test_direct_overload_ambiguity_keeps_per_usr_instances_in_context():
    """Overloads behind a file-scoped query stay constrained by that query."""
    bc_a = _make_context("bc-a", "unit.c")
    responses = {
        ("bc-a", "f", "unit.c"): program_facts_result(
            [
                _facts_row("c:@F@f#I#", "f", "unit.c"),
                _facts_row("c:@F@f#S#", "f", "unit.c"),
            ],
            context=bc_a,
        ),
        ("bc-a", "c:@F@f#I#", ""): program_facts_result(
            [_facts_row("c:@F@f#I#", "f", "unit.c")], context=bc_a
        ),
        ("bc-a", "c:@F@f#S#", ""): program_facts_result(
            [_facts_row("c:@F@f#S#", "f", "unit.c")], context=bc_a
        ),
    }
    index = _CannedFactsIndex([bc_a], responses)

    plan = plan_entry_instances(index, [FunctionEntry("f", file_path="unit.c")])

    assert len(plan.instances) == 2
    assert {i.usr for i in plan.instances} == {"c:@F@f#I#", "c:@F@f#S#"}
    assert all(i.selected_by == "function_choice" for i in plan.instances)
    assert not plan.gaps


# ── Session wiring: plan is built once and attached to reports ──


def _session_config(tmp_path: Path):
    from zscope.config.config import (
        AnalysisConfig,
        IndexingConfig,
        LLMConfig,
        ProjectConfig,
        ZScopeConfig,
    )
    from zscope.rules.extensions import preflight_rules

    config = ZScopeConfig(
        llm=LLMConfig(),
        llms={"default": LLMConfig()},
        indexing=IndexingConfig(backend="clang"),
        analysis=AnalysisConfig(snapshot_dir=str(tmp_path / ".zscope_snapshots")),
        project=ProjectConfig(
            project_root=tmp_path,
            source_root=tmp_path,
            compile_commands_path=tmp_path / "compile_commands.json",
        ),
    )
    preflight_rules(config)
    return config


def _planned_state(tmp_path: Path, index, functions) -> Dict[str, Any]:
    runner = ScanSessionRunner(_session_config(tmp_path), emit=lambda message: None)
    entry_list = tmp_path / "entries.json"
    entry_list.write_text(json.dumps({"functions": functions}))
    runner.config.project.entry_functions_list = entry_list
    state = runner._create_state()
    state["code_index"] = index
    runner._ensure_batch_entries(state)
    runner._plan_entry_instances(state)
    return state


def test_session_builds_plan_and_attaches_coverage_to_state(tmp_path: Path):
    state = _planned_state(
        tmp_path,
        _two_variant_index(),
        [{"function_name": "f", "file_path": "unit.c"}],
    )

    plan = state["entry_instance_plan"]
    assert plan.status == "planned"
    assert len(plan.instances) == 2

    report: Dict[str, Any] = {}
    ScanSessionRunner._attach_entry_instance_coverage(report, state)
    entry_instances = report["metadata"]["entry_instances"]
    assert entry_instances["schema"] == ENTRY_INSTANCE_SCHEMA
    assert entry_instances["boundary_coverage_complete"] is True
    assert entry_instances["scan_coverage_complete"] is False


def test_session_unavailable_plan_still_attached_as_unknown(tmp_path: Path):
    class _EmptyIndex:
        language = "c_cpp"
        backend_name = "clang"

        def get_build_contexts(self, file_path: str = ""):
            return []

    state = _planned_state(tmp_path, _EmptyIndex(), [{"function_name": "f"}])

    payload = state["entry_instance_plan"].to_payload()
    assert payload["status"] == "unavailable"
    assert payload["scan_coverage_complete"] is False
    report: Dict[str, Any] = {}
    ScanSessionRunner._attach_entry_instance_coverage(report, state)
    assert report["metadata"]["entry_instances"]["status"] == "unavailable"


# ── Native-gated: real indexer, real backend, real CodeIndex facade ──


@pytest.fixture
def native_variants(tmp_path, monkeypatch):
    executable = os.environ.get("Z_SCOPE_TEST_CLANG_INDEXER")
    if not executable:
        pytest.skip("native variant tests require Z_SCOPE_TEST_CLANG_INDEXER")
    from zscope.retrieval.clang_backend import ClangBackend

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
        yield backend, tmp_path, cdb
    finally:
        backend.close()


def test_native_two_variant_planning_through_real_index(native_variants):
    from types import SimpleNamespace

    from zscope.retrieval.code_index import CodeIndex

    backend, root, cdb = native_variants
    index = CodeIndex(root, cdb, backend=backend, indexing_config=SimpleNamespace(backend="clang"))
    contexts = index.get_build_contexts("unit.c")
    assert len(contexts) == 2

    plan = plan_entry_instances(index, [FunctionEntry("f", file_path="unit.c")])

    assert plan.status == "planned"
    assert plan.fact_queries == 2
    assert len(plan.instances) == 2
    assert not plan.gaps
    assert plan.boundary_coverage_complete
    assert {i.build_context_id for i in plan.instances} == {c["build_context_id"] for c in contexts}

    # Each scheduled instance reads back its own variant's facts; the ALT
    # variant alone contains the consume call edge.
    for instance in plan.instances:
        facts = index.get_function_program_facts(
            "f", "unit.c", build_context_id=instance.build_context_id
        )
        assert facts["complete"]
        assert facts["function_identity"]["usr"] == instance.usr
        has_consume = any(
            (event.get("callee") or {}).get("name") == "consume"
            for event in facts.get("events", [])
        )
        context = next(c for c in contexts if c["build_context_id"] == instance.build_context_id)
        assert has_consume == ("-DALT=1" in context["command"]["arguments"])

    # Facade membership query lists exactly the contexts containing the symbol.
    function_contexts = index.get_function_build_contexts("f", "unit.c")
    assert {c["build_context_id"] for c in function_contexts} == {
        c["build_context_id"] for c in contexts
    }
    assert index.get_function_build_contexts("no_such_function", "unit.c") == []
