"""Producer-side build identity for SVF/Saber signals (schema v18).

The SVF producer is one project-wide run whose artifacts are linked per group, so
a signal is usable as instance evidence only when the producer can name the
compile command that produced it. These tests pin the three pieces of that
contract:

* ``SvfOutputMapper`` turns a reported location into an attribution verdict
  (``exact`` / ``ambiguous`` / ``unattributed``) instead of guessing;
* the storage layer keeps ``command_id`` inside the UNIQUE key so a second
  variant is not silently dropped, and a legacy row without an identity is never
  instance evidence;
* ``ScopedCodeIndex.get_instance_backend_signals`` serves only the pinned
  context's own command and refuses foreign or shared identities.
"""

from __future__ import annotations

import sqlite3
import json
from pathlib import Path

from zscope.retrieval.build_context import BuildContext
from zscope.retrieval.indexing_identity import digest_json, file_digest
from zscope.retrieval.instance_index import InstanceScope, ScopedCodeIndex
from zscope.retrieval.knowledge_db import KnowledgeDB
from zscope.retrieval.svf_parser import SvfOutputMapper


def _identities(source: str, command_ids: list[str]) -> dict:
    return {
        "tus": [
            {"source": source, "command_id": command, "dependencies_complete": True}
            for command in command_ids
        ],
        "command_ids": sorted(set(command_ids)),
        "variant_sources": {source: len(command_ids)} if len(command_ids) > 1 else {},
    }


def _store_instance(
    db: KnowledgeDB,
    *,
    context_id: str,
    command_id: str,
    source: str,
    dependencies: dict[str, str],
) -> dict:
    context = BuildContext.create(
        {"source": source, "directory": ".", "arguments": ["clang", "-c", source]},
        tool={"path": "zscope-clang-indexer", "version": "test"},
        dependencies=dependencies,
        dependencies_complete=True,
    )
    manifest = context.to_dict()
    manifest.update(
        source=source,
        status="indexed",
        failure=None,
        search_directories={},
        search_excludes=[],
        compilation_database={"path": str(Path(source).name), "sha256": "0" * 64},
    )
    manifest["build_context_id"] = context_id
    manifest["command_id"] = command_id
    db._conn.execute(
        "INSERT INTO compilation_instances VALUES (?,?,?,?)",
        (context_id, command_id, source, json.dumps(manifest)),
    )
    return manifest


def _saber_row(db: KnowledgeDB, *, command_id: str, attribution: str, line: int = 12) -> None:
    db.insert_taint_signature(
        source_func="",
        sink_func="",
        bug_type="NeverFree",
        file_path="src/unit.c",
        line=line,
        tool="saber",
        svf_group="saber:default",
        command_id=command_id,
        attribution=attribution,
    )


class _BaseIndex:
    """Minimal base index exposing exactly what the scoped accessor reads."""

    def __init__(self, db: KnowledgeDB, manifests: list[dict]) -> None:
        self.db = db
        self._manifests = manifests

    def get_build_contexts(self, file_path: str = "") -> list[dict]:
        return [
            dict(manifest)
            for manifest in self._manifests
            if not file_path or str(manifest.get("source") or "") == file_path
        ]


class _ProductionShapedBaseIndex:
    """Production CodeIndex keeps the database behind its backend."""

    def __init__(self, db: KnowledgeDB, manifests: list[dict]) -> None:
        self._backend = type("Backend", (), {"db": db})()
        self._manifests = manifests

    def get_build_contexts(self, file_path: str = "") -> list[dict]:
        return [
            dict(manifest)
            for manifest in self._manifests
            if not file_path or str(manifest.get("source") or "") == file_path
        ]


def _scoped(
    db: KnowledgeDB, manifests: list[dict], context_id: str, source: str
) -> ScopedCodeIndex:
    scope = InstanceScope(
        build_context_id=context_id,
        usr="c:@F@main",
        identity=f"{context_id}|c:@F@main",
        source=source,
        function_names=("main",),
    )
    return ScopedCodeIndex(_BaseIndex(db, manifests), scope)


def test_single_command_source_is_attributed_exactly(tmp_path: Path) -> None:
    db = KnowledgeDB(str(tmp_path / "knowledge.db"))
    mapper = SvfOutputMapper(
        db,
        svf_group="saber:default",
        project_root=tmp_path,
        tu_identities=_identities("src/unit.c", ["command-base"]),
    )

    assert mapper.attribution("src/unit.c") == ("command-base", "exact")
    assert mapper.attribution(str(tmp_path / "src" / "unit.c")) == ("command-base", "exact")


def test_two_variants_of_one_source_are_ambiguous(tmp_path: Path) -> None:
    db = KnowledgeDB(str(tmp_path / "knowledge.db"))
    mapper = SvfOutputMapper(
        db,
        svf_group="saber:default",
        project_root=tmp_path,
        tu_identities=_identities("src/unit.c", ["command-base", "command-alt"]),
    )

    # Picking either variant would invent evidence the producer never proved.
    assert mapper.attribution("src/unit.c") == ("", "ambiguous")


def test_header_and_unknown_locations_are_never_exact(tmp_path: Path) -> None:
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "unit.c").write_text("int main(void) { return 0; }\n", encoding="utf-8")
    (tmp_path / "src" / "unit.h").write_text("#define UNIT 1\n", encoding="utf-8")
    db = KnowledgeDB(str(tmp_path / "knowledge.db"))
    mapper = SvfOutputMapper(
        db,
        svf_group="saber:default",
        project_root=tmp_path,
        tu_identities=_identities("src/unit.c", ["command-base"]),
    )

    # An existing header belongs to every TU that includes it.
    assert mapper.attribution("src/unit.h") == ("", "ambiguous")
    # A path the group never linked is not evidence at all.
    assert mapper.attribution("src/elsewhere.c") == ("", "unattributed")
    assert mapper.attribution("") == ("", "unattributed")


def test_mapper_without_identities_attributes_nothing(tmp_path: Path) -> None:
    db = KnowledgeDB(str(tmp_path / "knowledge.db"))
    mapper = SvfOutputMapper(db, svf_group="saber:default", project_root=tmp_path)

    assert mapper.attribution("src/unit.c") == ("", "unattributed")


def test_saber_import_records_the_compile_command(tmp_path: Path) -> None:
    db = KnowledgeDB(str(tmp_path / "knowledge.db"))
    mapper = SvfOutputMapper(
        db,
        svf_group="saber:default",
        project_root=tmp_path,
        tu_identities=_identities("src/unit.c", ["command-base"]),
    )
    mapper.import_saber_bugs([{"type": "NeverFree", "file": "src/unit.c", "line": 12}], commit=True)

    stored = db._conn.execute(
        "SELECT bug_type, command_id, attribution FROM taint_signatures"
    ).fetchall()
    assert [(row["bug_type"], row["command_id"], row["attribution"]) for row in stored] == [
        ("NeverFree", "command-base", "exact")
    ]


def test_two_variants_of_one_bug_are_both_retained(tmp_path: Path) -> None:
    """Without the widened UNIQUE key INSERT OR IGNORE drops the second variant."""

    db = KnowledgeDB(str(tmp_path / "knowledge.db"))
    _saber_row(db, command_id="command-base", attribution="exact")
    _saber_row(db, command_id="command-alt", attribution="exact")
    db.commit()

    count = db._conn.execute("SELECT COUNT(*) AS count FROM taint_signatures").fetchone()["count"]
    assert count == 2
    base = db.get_instance_taint_signals(command_id="command-base")
    alt = db.get_instance_taint_signals(command_id="command-alt")
    assert [row["command_id"] for row in base] == ["command-base"]
    assert [row["command_id"] for row in alt] == ["command-alt"]


def test_legacy_rows_without_identity_are_not_instance_evidence(tmp_path: Path) -> None:
    db = KnowledgeDB(str(tmp_path / "knowledge.db"))
    _saber_row(db, command_id="", attribution="unattributed")
    db.commit()

    assert db.get_instance_taint_signals(command_id="command-base") == []
    counts = db.count_taint_signal_attribution("command-base")
    assert counts["unattributed"] == 1
    assert counts["exact_for_command"] == 0


def test_ambiguous_rows_are_not_returned_for_an_instance(tmp_path: Path) -> None:
    db = KnowledgeDB(str(tmp_path / "knowledge.db"))
    _saber_row(db, command_id="", attribution="ambiguous")
    db.commit()

    assert db.get_instance_taint_signals(command_id="") == []
    counts = db.count_taint_signal_attribution()
    assert counts["ambiguous"] == 1
    assert counts["exact"] == 0


def test_command_context_map_reports_every_owner(tmp_path: Path) -> None:
    db = KnowledgeDB(str(tmp_path / "knowledge.db"))
    unit = tmp_path / "src" / "unit.c"
    other = tmp_path / "src" / "other.c"
    for path in (unit, other):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("int main(void) { return 0; }\n", encoding="utf-8")
    _store_instance(
        db,
        context_id="ctx-a",
        command_id="command-shared",
        source="src/unit.c",
        dependencies={str(unit): file_digest(unit)},
    )
    _store_instance(
        db,
        context_id="ctx-b",
        command_id="command-shared",
        source="src/unit.c",
        dependencies={str(unit): file_digest(unit)},
    )
    _store_instance(
        db,
        context_id="ctx-c",
        command_id="command-sole",
        source="src/other.c",
        dependencies={str(other): file_digest(other)},
    )
    db.commit()

    db._conn.setlimit(sqlite3.SQLITE_LIMIT_VARIABLE_NUMBER, 999)
    db._conn.execute("PRAGMA query_only=ON")
    mapping = db.get_command_context_map(
        [f"absent-{index}" for index in range(1200)] + ["command-shared", "command-sole"]
    )
    assert mapping["command-shared"] == ["ctx-a", "ctx-b"]
    assert mapping["command-sole"] == ["ctx-c"]


def _current_instance(tmp_path: Path, db: KnowledgeDB, *, context_id: str, command_id: str):
    unit = tmp_path / "src" / "unit.c"
    unit.parent.mkdir(parents=True, exist_ok=True)
    unit.write_text("int main(void) { return 0; }\n", encoding="utf-8")
    manifest = _store_instance(
        db,
        context_id=context_id,
        command_id=command_id,
        source="src/unit.c",
        dependencies={str(unit): file_digest(unit)},
    )
    return manifest


def test_scoped_accessor_serves_only_the_pinned_command(tmp_path: Path) -> None:
    db = KnowledgeDB(str(tmp_path / "knowledge.db"))
    manifest_a = _current_instance(tmp_path, db, context_id="ctx-a", command_id="command-base")
    manifest_b = dict(manifest_a)
    manifest_b["build_context_id"] = "ctx-b"
    manifest_b["command_id"] = "command-alt"
    _saber_row(db, command_id="command-base", attribution="exact")
    _saber_row(db, command_id="command-alt", attribution="exact")
    db.commit()

    scoped = _scoped(db, [manifest_a, manifest_b], "ctx-a", "src/unit.c")
    payload = scoped.get_instance_backend_signals(func_names=[])

    assert payload["status"] == "complete", payload
    assert payload["command_id"] == "command-base"
    assert [row["command_id"] for row in payload["rows"]] == ["command-base"]
    assert payload["status"] != "ambiguous_command"


def test_scoped_accessor_resolves_production_backend_signal_store(tmp_path: Path) -> None:
    db = KnowledgeDB(str(tmp_path / "knowledge.db"))
    manifest = _current_instance(tmp_path, db, context_id="ctx-a", command_id="command-base")
    _saber_row(db, command_id="command-base", attribution="exact")
    db.commit()
    scope = InstanceScope(
        build_context_id="ctx-a",
        usr="c:@F@main",
        identity="ctx-a|c:@F@main",
        source="src/unit.c",
        function_names=("main",),
    )
    scoped = ScopedCodeIndex(_ProductionShapedBaseIndex(db, [manifest]), scope)

    payload = scoped.get_instance_backend_signals(func_names=[])

    assert payload["status"] == "complete", payload
    assert payload["command_id"] == "command-base"
    assert [row["command_id"] for row in payload["rows"]] == ["command-base"]


def test_scoped_accessor_refuses_a_foreign_build_context(tmp_path: Path) -> None:
    db = KnowledgeDB(str(tmp_path / "knowledge.db"))
    manifest = _current_instance(tmp_path, db, context_id="ctx-a", command_id="command-base")
    db.commit()

    scoped = _scoped(db, [manifest], "ctx-a", "src/unit.c")
    payload = scoped.get_instance_backend_signals(build_context_id="ctx-b")

    assert payload["status"] == "foreign_build_context"
    assert payload["rows"] == []
    assert payload["exact_rows"] == 0


def test_scoped_accessor_refuses_a_shared_command_identity(tmp_path: Path) -> None:
    db = KnowledgeDB(str(tmp_path / "knowledge.db"))
    manifest_a = _current_instance(tmp_path, db, context_id="ctx-a", command_id="command-shared")
    # The same compile command produced a second stored context.
    manifest_b = _store_instance(
        db,
        context_id="ctx-b",
        command_id="command-shared",
        source="src/unit.c",
        dependencies={str(tmp_path / "src" / "unit.c"): file_digest(tmp_path / "src" / "unit.c")},
    )
    _saber_row(db, command_id="command-shared", attribution="exact")
    db.commit()

    scoped = _scoped(db, [manifest_a, manifest_b], "ctx-a", "src/unit.c")
    payload = scoped.get_instance_backend_signals(func_names=[])

    # Two contexts were built with the same command: the row cannot be pinned.
    assert payload["status"] == "ambiguous_command"
    assert payload["rows"] == []


def test_scoped_accessor_never_publishes_a_stale_instance(tmp_path: Path) -> None:
    db = KnowledgeDB(str(tmp_path / "knowledge.db"))
    unit = tmp_path / "src" / "unit.c"
    unit.parent.mkdir(parents=True, exist_ok=True)
    unit.write_text("int main(void) { return 0; }\n", encoding="utf-8")
    manifest = _store_instance(
        db,
        context_id="ctx-a",
        command_id="command-base",
        source="src/unit.c",
        dependencies={"src/unit.c": file_digest(unit)},
    )
    _saber_row(db, command_id="command-base", attribution="exact")
    db.commit()
    # A source edit after indexing invalidates the stored instance.
    unit.write_text("int main(void) { return 1; }\n", encoding="utf-8")

    scoped = _scoped(db, [manifest], "ctx-a", "src/unit.c")
    payload = scoped.get_instance_backend_signals(func_names=[])

    assert payload["status"] == "stale"
    assert payload["rows"] == []


def test_scoped_accessor_reports_attribution_counts(tmp_path: Path) -> None:
    db = KnowledgeDB(str(tmp_path / "knowledge.db"))
    manifest = _current_instance(tmp_path, db, context_id="ctx-a", command_id="command-base")
    _saber_row(db, command_id="command-base", attribution="exact", line=12)
    _saber_row(db, command_id="", attribution="ambiguous", line=13)
    _saber_row(db, command_id="", attribution="unattributed", line=14)
    db.commit()

    scoped = _scoped(db, [manifest], "ctx-a", "src/unit.c")
    payload = scoped.get_instance_backend_signals(func_names=[])

    assert payload["status"] == "complete", payload
    assert payload["exact_rows"] == 1
    assert payload["ambiguous_rows"] == 1
    assert payload["unattributed_rows"] == 1
    assert len(payload["rows"]) == 1


def test_candidate_identity_differs_between_variants(tmp_path: Path) -> None:
    """Two variants of one Saber row must survive candidate deduplication."""

    from zscope.core.candidates.svf_value_flow import SvfValueFlowCandidateGenerator

    bug = {
        "bug_type": "NeverFree",
        "file_path": "src/unit.c",
        "line": 12,
        "tool": "saber",
        "svf_group": "saber:default",
    }
    generator = SvfValueFlowCandidateGenerator()
    base = generator.bug_to_issue(dict(bug), entry_func="main")
    alt = generator.bug_to_issue({**bug, "build_context_id": "ctx-b"}, entry_func="main")

    assert "build_context_id" not in base
    assert base["candidate_id"] != alt["candidate_id"]
    assert alt["build_context_id"] == "ctx-b"
    assert alt["evidence_pack"]["build_context_id"] == "ctx-b"
    assert alt["evidence_pack"]["value_flow"]["build_context_id"] == "ctx-b"
    assert base["dedup_key"] != alt["dedup_key"]


def test_variant_group_publishes_ambiguous_sources(tmp_path: Path) -> None:
    """A group that links one source twice reports it instead of picking one."""

    from zscope.retrieval.build_llvm import BitcodeBuilder

    builder = BitcodeBuilder(source_root=tmp_path, compile_commands_path=tmp_path / "c.json")
    first = tmp_path / "a.o.bc"
    second = tmp_path / "b.o.bc"
    command = {"source": "src/unit.c", "directory": str(tmp_path), "arguments": ["clang"]}
    alt_command = {**command, "arguments": ["clang", "-DALT=1"]}
    builder._bc_to_src[first.resolve()] = tmp_path / "src" / "unit.c"
    builder._bc_to_src[second.resolve()] = tmp_path / "src" / "unit.c"
    builder._manifest["bitcode"] = {
        str(first.resolve()): {"command": command, "dependencies_complete": True},
        str(second.resolve()): {"command": alt_command, "dependencies_complete": True},
    }
    builder._group_inputs["saber:default"] = [first, second]

    identities = builder.group_tu_identities("saber:default")

    assert len(identities["command_ids"]) == 2
    assert list(identities["variant_sources"].values()) == [2]
    assert len(identities["variant_sources"]) == 1
    assert digest_json(command) in identities["command_ids"]
