"""Deterministic incremental/full comparison on owned, fixed compiler fixtures.

This is an indexing audit, not a vulnerability benchmark. It never accepts a
project build script, executes a fixture binary, starts SVF or calls a model.
Both branches consume the same final source paths with independent databases.
"""

from __future__ import annotations

from collections import Counter
import json
import os
import platform
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, Optional

from .indexing_identity import atomic_json, digest_json, file_digest
from .indexing_inventory import compilation_contexts


REPLAY_SCHEMA = "zscope.incremental-replay.v1"
MUTATIONS = (
    "function_body",
    "shared_header",
    "macro",
    "compile_command",
    "delete",
    "rename",
    "callback_target",
    "negative_include",
)
# These are storage/lifecycle fields, not compiler facts. No global name-based
# filtering is applied to nested facts: a source property named 'timestamp' is
# still a semantic input and must compare equal.
IGNORED_COLUMNS = {
    "translation_units": {"id", "last_modified", "index_time"},
    "function_type_ref_state": {"generation", "attempt", "retry_count", "retry_after"},
    "function_contracts": {"id", "updated_at"},
}
FOREIGN_KEYS = {
    "functions": {"tu_id": "translation_units"},
    "type_definitions": {"tu_id": "translation_units"},
    "type_members": {"type_id": "type_definitions"},
    "function_macro_refs": {"function_id": "functions", "macro_id": "macro_definitions"},
    "function_type_refs": {"function_id": "functions", "type_id": "type_definitions"},
    "function_type_ref_state": {"function_id": "functions"},
    "ir_cfg_edges": {"from_stmt": "ir_statements", "to_stmt": "ir_statements"},
    "ir_def_use_edges": {"def_stmt": "ir_statements", "use_stmt": "ir_statements"},
    "ir_path_slices": {"source_stmt": "ir_statements", "sink_stmt": "ir_statements"},
}
IDENTITY_COLUMNS = {
    "translation_units": ("file_path",),
    "functions": ("name", "file_path", "start_line"),
    "type_definitions": ("name", "kind", "file_path"),
    "macro_definitions": ("name", "file_path", "line"),
    "ir_statements": (
        "file_path",
        "line",
        "function",
        "normalized_code",
        "column_number",
        "event_ordinal",
    ),
}


def canonical_database(connection: sqlite3.Connection) -> Dict[str, Any]:
    """Retain all published fact tables and map storage IDs to logical keys.

    The database is owned by the replay. No migrations or writes occur here.
    Metadata contains transient counters and caches; semantic coverage is read
    from the actual TU/type state rows and recorded separately by the runner.
    Unknown tables/columns are retained, so schema growth cannot hide facts.
    """
    names = sorted(
        str(row[0])
        for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")
        if row[0] != "metadata" and not str(row[0]).startswith("sqlite_")
    )
    raw: Dict[str, list[dict[str, Any]]] = {}
    storage_ids = set()
    for name in names:
        quoted = '"' + name.replace('"', '""') + '"'
        if any(
            row[1] == "id" and row[2].upper() == "INTEGER" and row[5]
            for row in connection.execute("PRAGMA table_info(" + quoted + ")")
        ):
            storage_ids.add(name)
        cursor = connection.execute("SELECT * FROM " + quoted)
        columns = [str(column[0]) for column in cursor.description or []]
        raw[name] = [dict(zip(columns, row)) for row in cursor]
    identities = {
        name: {row["id"]: [row[column] for column in columns] for row in raw.get(name, [])}
        for name, columns in IDENTITY_COLUMNS.items()
    }
    result = {}
    for table, rows in raw.items():
        canonical = []
        for row in rows:
            item = {}
            ignored = IGNORED_COLUMNS.get(table, set()) | (
                {"id"} if table in storage_ids else set()
            )
            for key, value in row.items():
                if key in ignored:
                    continue
                target = FOREIGN_KEYS.get(table, {}).get(key)
                if target and value is not None:
                    if value not in identities[target]:
                        raise ValueError(f"dangling fact reference: {table}.{key}")
                    value = {"table": target, "key": identities[target][value]}
                # Canonicalize JSON formatting only, never delete nested fields
                # or reorder arrays whose sequence may be semantically relevant.
                if isinstance(value, str) and value[:1] in {"[", "{"}:
                    try:
                        value = json.loads(value)
                    except ValueError:
                        pass
                if table == "compilation_facts" and key == "data" and isinstance(value, dict):
                    if value.get("kind") == "complete":
                        # Same operational timing excluded in native_tus below;
                        # preserve every compiler fact and adjustment decision.
                        for attempt in value.get("argument_adjustments", {}).get("attempts", []):
                            attempt.pop("wall_seconds", None)
                if (
                    table == "compilation_instances"
                    and key == "manifest"
                    and isinstance(value, dict)
                ):
                    # Branches own different cache paths excluded from include
                    # scans. Keep the actual search roots/membership digests.
                    value.pop("search_excludes", None)
                item[key] = value
            canonical.append(item)
        result[table] = sorted(canonical, key=_json)
    return result


def _json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(",", ":"))


def compare_facts(left: Dict[str, Any], right: Dict[str, Any]) -> Dict[str, Any]:
    """Compare complete multisets, preserving duplicate fact counts."""
    differences = []
    for section in sorted(set(left) | set(right)):
        a, b = left.get(section), right.get(section)
        if a == b:
            continue
        if isinstance(a, list) and isinstance(b, list):
            aa, bb = Counter(map(_json, a)), Counter(map(_json, b))
            missing, extra = bb - aa, aa - bb
            differences.append(
                {
                    "section": section,
                    "missing": [json.loads(item) for item in missing.elements()],
                    "extra": [json.loads(item) for item in extra.elements()],
                    "difference_count": sum(missing.values()) + sum(extra.values()),
                }
            )
        else:
            differences.append(
                {"section": section, "incremental": a, "clean": b, "difference_count": 1}
            )
    return {
        "equal": not differences,
        "difference_count": sum(item["difference_count"] for item in differences),
        "differences": differences,
    }


def write_fixture(root: Path) -> None:
    """Create an inert C fixture; all executable work is compiler indexing."""
    root.mkdir(parents=True, exist_ok=False)
    (root / "shared.h").write_text(
        "#pragma once\n#define HEADER_VALUE 1\n"
        "typedef struct Item { int value; } Item;\n"
        "typedef int (*Callback)(Item *);\n"
        "int target_a(Item *);\nint target_b(Item *);\n"
        "void *malloc(unsigned long);\nvoid free(void *);\n",
        encoding="utf-8",
    )
    (root / "a.c").write_text(
        '#include "shared.h"\n#define LOCAL_VALUE 2\n'
        '#ifdef NEGATIVE_TEST\n#if __has_include("late.h")\n#include "late.h"\n'
        "#else\n#define LATE_VALUE 0\n#endif\n#else\n#define LATE_VALUE 0\n#endif\n"
        "int global_count;\nint entry(Item *item) {\n"
        "  void *memory = malloc(16);\n"
        "  item->value += HEADER_VALUE + LOCAL_VALUE + MODE + LATE_VALUE;\n"
        "  free(memory);\n  return target_a(item);\n}\n"
        "int invoke(Item *item) { Callback callback = target_a; return callback(item); }\n",
        encoding="utf-8",
    )
    (root / "b.c").write_text(
        '#include "shared.h"\nint target_a(Item *item) { return item->value; }\n'
        "int target_b(Item *item) { return item->value + 1; }\n",
        encoding="utf-8",
    )
    (root / "unused.c").write_text("int obsolete(void) { return 7; }\n", encoding="utf-8")
    commands = []
    for name, mode in (("a.c", 0), ("a.c", 0), ("a.c", 1), ("b.c", 0), ("unused.c", 0)):
        commands.append(
            {
                "directory": str(root),
                "file": str(root / name),
                "arguments": [
                    "clang",
                    "-std=c11",
                    f"-DMODE={mode}",
                    "-I",
                    str(root),
                    "-c",
                    str(root / name),
                ],
            }
        )
    atomic_json(root / "compile_commands.json", commands)


def mutate_fixture(root: Path, mutation: str) -> None:
    if mutation not in MUTATIONS:
        raise ValueError("unknown replay mutation")
    replacements = {
        "function_body": ("a.c", "malloc(16)", "malloc(32)"),
        "shared_header": ("shared.h", "int value;", "int value; long extra;"),
        "macro": ("a.c", "LOCAL_VALUE 2", "LOCAL_VALUE 9"),
        "callback_target": ("a.c", "callback = target_a", "callback = target_b"),
    }
    if mutation in replacements:
        name, before, after = replacements[mutation]
        path = root / name
        source = path.read_text(encoding="utf-8")
        if source.count(before) != 1:
            raise ValueError("fixture baseline was changed")
        path.write_text(source.replace(before, after), encoding="utf-8")
    elif mutation == "negative_include":
        (root / "late.h").write_text("#define LATE_VALUE 13\n", encoding="utf-8")
    else:
        path = root / "compile_commands.json"
        commands = json.loads(path.read_text(encoding="utf-8"))
        if mutation == "compile_command":
            commands[0]["arguments"][2] = "-DMODE=3"
        elif mutation == "delete":
            (root / "unused.c").unlink()
            commands = [row for row in commands if Path(row["file"]).name != "unused.c"]
        elif mutation == "rename":
            (root / "b.c").rename(root / "renamed.c")
            for row in commands:
                if Path(row["file"]).name == "b.c":
                    row["file"] = str(root / "renamed.c")
                    row["arguments"][-1] = row["file"]
        atomic_json(path, commands)


def input_manifest(root: Path) -> Dict[str, str]:
    # The fixed fixture contains only direct sources and its CDB. Backend-owned
    # preparation/cache products are outside this declared source corpus.
    return {
        path.name: file_digest(path)
        for path in sorted(root.iterdir())
        if path.is_file() and (path.suffix in {".c", ".h"} or path.name == "compile_commands.json")
    }


def _preserve_preparation(root: Path) -> str:
    """Keep the owned A-side preflight state and give B a fresh preflight cache."""
    from .compile_commands_prepare import MANAGED_DIRECTORY

    source = root / MANAGED_DIRECTORY
    destination = root.parent / "incremental-preparation"
    if (
        source.is_symlink()
        or source.resolve().parent != root.resolve()
        or destination.is_symlink()
        or destination.resolve().parent != root.parent.resolve()
        or destination.exists()
    ):
        raise ValueError("unsafe replay preparation archive")
    if not source.is_dir():
        raise ValueError("replay preparation state missing")
    source.rename(destination)
    return str(destination)


def _capture(backend: Any, root: Path, native: tuple[str, Dict[str, Any]]) -> Dict[str, Any]:
    from .clang_batch import BatchIndexer, records

    indexer = BatchIndexer(backend, *native)
    jobs = indexer._jobs()
    raw_tus = []
    for job in jobs:
        package = json.loads((indexer.cache / (job["key"] + ".json")).read_text(encoding="utf-8"))
        if (
            package.get("key") != job["key"]
            or not indexer.validator.dependencies(package.get("dependencies"))
            or not indexer.validator.searches(package.get("search_directories"))
            or file_digest(Path(package["artifact"])) != package.get("artifact_sha256")
        ):
            raise ValueError("successful TU package unavailable or stale")
        # Capture is not cache authorization. A missing include is deliberately
        # non-reusable; preserve that fact while comparing this run's output.
        native_rows = list(records(Path(package["artifact"])))
        for native_row in native_rows:
            if native_row.get("kind") == "complete":
                for attempt in native_row.get("argument_adjustments", {}).get("attempts", []):
                    attempt.pop("wall_seconds", None)
        raw_tus.append(
            {
                "context": job["context"],
                "source": job["source"],
                "dependencies": package["dependencies"],
                "dependencies_complete": package["dependencies_complete"],
                "records": sorted(native_rows, key=_json),
            }
        )
    stats = json.loads(backend.db.get_metadata("clang_batch_stats") or "{}")
    return {
        "published": canonical_database(backend.db._conn),
        "native_tus": sorted(raw_tus, key=lambda row: row["context"]),
        "compilation": compilation_contexts(
            root / "compile_commands.json", selected_contexts=[job["context"] for job in jobs]
        ),
        "coverage": {
            key: stats.get(key)
            for key in (
                "complete",
                "extraction_complete",
                "projection_complete",
                "variant_sources",
                "ready_for_queries",
                "type_refs_complete",
                "type_refs_functions",
                "fallback_files",
                "failed_tus",
            )
        },
    }


def _build(backend: Any, root: Path, *, initial: bool) -> Dict[str, Any]:
    import resource

    from .indexing_runtime import process_tree_rss

    usage = resource.getrusage(resource.RUSAGE_SELF)
    children = resource.getrusage(resource.RUSAGE_CHILDREN)
    cpu_before = usage.ru_utime + usage.ru_stime + children.ru_utime + children.ru_stime
    stop = threading.Event()
    peak = [process_tree_rss(os.getpid()) or 0]

    def sample() -> None:
        while not stop.wait(0.02):
            peak[0] = max(peak[0], process_tree_rss(os.getpid()) or 0)

    sampler = threading.Thread(target=sample, name="ReplayMemorySample", daemon=True)
    sampler.start()
    started = time.monotonic()
    try:
        success = (
            backend.initialize(str(root), compile_commands_path=str(root / "compile_commands.json"))
            if initial
            else backend._run_full_extraction()
        )
    finally:
        stop.set()
        sampler.join()
    wall = time.monotonic() - started
    usage = resource.getrusage(resource.RUSAGE_SELF)
    children = resource.getrusage(resource.RUSAGE_CHILDREN)
    cpu = usage.ru_utime + usage.ru_stime + children.ru_utime + children.ru_stime - cpu_before
    stats = json.loads(backend.db.get_metadata("clang_batch_stats") or "{}") if backend.db else {}
    if (
        not success
        or not stats.get("extraction_complete")
        or not stats.get("type_refs_complete")
        or stats.get("failed_tus")
        or stats.get("fallback_files")
    ):
        raise RuntimeError("replay requires complete strict-batch facts: " + _json(stats))
    return {
        "wall_seconds": wall,
        "import_seconds": stats.get("import_seconds"),
        "cpu_seconds": cpu,
        "sampled_process_tree_peak_rss_bytes": peak[0],
        "rss_scope": "20ms sampled Python process plus current child processes; not an exact peak",
        "planned_tus": stats.get("selected_compile_contexts"),
        "rebuilt_tus": stats.get("compiled_tus"),
        "reused_tus": stats.get("reused_tus"),
        "failed_tus": len(stats.get("failed_tus", [])),
        "coverage_complete": bool(stats.get("complete")),
        "compilation_instances_complete": bool(stats.get("extraction_complete")),
        "projection_complete": bool(stats.get("projection_complete")),
        "rpc_requests_native": stats.get("rpc_requests_native"),
    }


def run_fixture_replay(
    work: Path,
    *,
    clang_indexer: str,
    mutations: Iterable[str] = MUTATIONS,
    on_progress: Optional[Callable[[Dict[str, Any]], None]] = None,
) -> Dict[str, Any]:
    """Run only built-in fixtures in a newly created directory, preserving evidence.

    Refuse existing work roots. No rm/rmtree, shared project cache, external
    build scripts, LLM configuration or arbitrary mutation commands are used.
    """
    from .clang_backend import ClangBackend
    from .clang_batch import find_indexer
    from .indexing_identity import executable_identity
    from .indexing_runtime import resource_limits

    if platform.system() != "Linux":
        raise ValueError("incremental replay requires Linux/WSL")
    chosen = tuple(mutations)
    if (
        not chosen
        or len(set(chosen)) != len(chosen)
        or any(item not in MUTATIONS for item in chosen)
    ):
        raise ValueError("select distinct supported replay mutations")
    native = find_indexer(clang_indexer)
    if not native:
        raise ValueError("compatible native indexer unavailable; replay never falls back to LSP")
    work = work.absolute()
    if work.exists() or work.is_symlink():
        raise ValueError("replay work directory must not already exist")
    work.mkdir(parents=True, exist_ok=False)
    report: Dict[str, Any] = {
        "schema": REPLAY_SCHEMA,
        "fixture": "clang-c-mutations.v1",
        "scope": "all eligible strict-batch compilation instances and the published navigation projection",
        "not_covered": [
            "whole-scan consumers of compilation variants and verified link targets",
            "SVF/Saber",
            "LLM semantics",
            "arbitrary C/C++ projects",
        ],
        "normalization": {
            "storage_ids": "logical foreign-key targets",
            "ignored_columns": {key: sorted(value) for key, value in IGNORED_COLUMNS.items()},
            "metadata": "excluded; actual fact tables and explicit coverage retained",
            "raw_tu_records": "record order normalized; only complete.argument_adjustments.attempts[*].wall_seconds omitted",
        },
        "tool": {"identity": executable_identity(native[0]), "capability": native[1]},
        "resources": resource_limits(),
        "workers": 1,
        "llm": "disabled",
        "performance_status": "observational_only_not_isolated_benchmark",
        "mutations": [],
        "complete": False,
    }
    producer = Path(__file__).parent
    report["producer_inputs"] = {
        path.name: file_digest(path) for path in sorted(producer.glob("*.py"))
    }
    atomic_json(work / "report.json", report)
    for mutation in chosen:
        area = work / mutation
        root = area / "source"
        write_fixture(root)
        if mutation == "negative_include":
            commands_path = root / "compile_commands.json"
            commands = json.loads(commands_path.read_text(encoding="utf-8"))
            for command in commands:
                if Path(command["file"]).name == "a.c":
                    command["arguments"].insert(1, "-DNEGATIVE_TEST=1")
            atomic_json(commands_path, commands)
        incremental = ClangBackend(
            frontend="batch",
            clang_indexer_path=native[0],
            db_path=str(area / "incremental" / "facts.db"),
            max_threads=1,
        )
        clean = ClangBackend(
            frontend="batch",
            clang_indexer_path=native[0],
            db_path=str(area / "clean" / "facts.db"),
            max_threads=1,
        )
        row: Dict[str, Any] = {"mutation": mutation, "status": "running", "stages": {}}
        report["mutations"].append(row)
        try:
            row["baseline_inputs"] = input_manifest(root)
            row["stages"]["baseline_cold"] = _build(incremental, root, initial=True)
            baseline = _capture(incremental, root, native)
            row["stages"]["baseline_hot"] = _build(incremental, root, initial=False)
            hot = _capture(incremental, root, native)
            hot_diff = compare_facts(baseline, hot)
            if not hot_diff["equal"]:
                row["baseline_hot_difference"] = hot_diff
                raise RuntimeError("warm baseline changed compiler facts")
            mutate_fixture(root, mutation)
            final_inputs = input_manifest(root)
            row["final_inputs"] = final_inputs
            row["stages"]["incremental"] = _build(incremental, root, initial=False)
            a = _capture(incremental, root, native)
            if input_manifest(root) != final_inputs:
                raise RuntimeError("incremental build changed declared fixture inputs")
            incremental.close()
            row["incremental_preparation_artifact"] = _preserve_preparation(root)
            row["clean_cache_scope"] = (
                "fresh database, native/derived facts, and compile-argument preflight"
            )
            row["stages"]["clean"] = _build(clean, root, initial=True)
            b = _capture(clean, root, native)
            if input_manifest(root) != final_inputs:
                raise RuntimeError("clean build changed declared fixture inputs")
            atomic_json(area / "incremental-facts.json", a)
            atomic_json(area / "clean-facts.json", b)
            difference = compare_facts(a, b)
            atomic_json(area / "differences.json", difference)
            row.update(
                status="passed" if difference["equal"] else "failed",
                difference_count=difference["difference_count"],
                incremental_digest=digest_json(a),
                clean_digest=digest_json(b),
                mutation_changed_facts=not compare_facts(baseline, b)["equal"],
                artifacts={
                    name: str(area / name)
                    for name in ("incremental-facts.json", "clean-facts.json", "differences.json")
                },
            )
            if not row["mutation_changed_facts"]:
                row.update(status="failed", reason="mutation did not change observed facts")
        except Exception as exc:
            row.update(status="failed", reason=f"{type(exc).__name__}: {exc}")
        finally:
            incremental.close()
            clean.close()
            atomic_json(work / "report.json", report)
            if on_progress:
                on_progress(dict(row))
    report["complete"] = all(row["status"] == "passed" for row in report["mutations"])
    report["producer_inputs_stable"] = report["producer_inputs"] == {
        path.name: file_digest(path) for path in sorted(producer.glob("*.py"))
    }
    report["complete"] = report["complete"] and report["producer_inputs_stable"]
    report["unexplained_semantic_differences"] = sum(
        row.get("difference_count", 0) for row in report["mutations"]
    )
    report["execution_failures"] = sum("reason" in row for row in report["mutations"])
    atomic_json(work / "report.json", report)
    return report
