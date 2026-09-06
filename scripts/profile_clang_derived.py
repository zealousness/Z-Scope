"""Profile derived indexing on isolated database copies, without invoking an LLM.

Example: python -m scripts.profile_clang_derived --project-root /src/project
  --knowledge-db /src/project/.zscope_knowledge/code_knowledge.db
  --compile-commands-dir /src/project/build --workers 1 2 4 8 --output timings.json

This is an indexing performance harness, not a vulnerability benchmark. It never
deletes clangd's cache. Report its cold/warm state separately when comparing runs.
"""

from __future__ import annotations

import argparse
import hashlib
import inspect
import json
import logging
import platform
import sqlite3
import tempfile
import time
from contextlib import closing
from pathlib import Path
from typing import Any

from zscope.retrieval.clang_backend import ClangBackend
from zscope.retrieval.clang_extractor import ClangExtractor
from zscope.retrieval.knowledge_db import KnowledgeDB


def fact_digest(db: KnowledgeDB) -> str:
    digest = hashlib.sha256()
    queries = (
        "SELECT function_name,function_file,symbol_name,symbol_kind,symbol_file,reference_line,access_kind "
        "FROM function_symbol_refs ORDER BY 1,2,3,4,5,6,7",
        "SELECT f.name,f.file_path,f.start_line,f.signature,m.macro_index_name,r.reference_line FROM function_macro_refs r "
        "JOIN functions f ON f.id=r.function_id JOIN macro_definitions m ON m.id=r.macro_id ORDER BY 1,2,3,4,5,6",
        "SELECT f.name,f.file_path,f.start_line,f.signature,r.referenced_name,r.type_index_name,r.reference_file,"
        "r.reference_line,r.reference_kind,r.resolution_reason FROM function_type_refs r "
        "JOIN functions f ON f.id=r.function_id ORDER BY 1,2,3,4,5,6,7,8,9,10",
    )
    for query in queries:
        for row in db._conn.execute(query):
            digest.update(json.dumps(list(row), ensure_ascii=True, separators=(",", ":")).encode())
            digest.update(b"\n")
    return digest.hexdigest()


def select_files(db: KnowledgeDB, limit: int) -> list[str]:
    # Stratify by function count. The selected list is saved verbatim for replay.
    rows = db._conn.execute(
        "SELECT file_path,COUNT(*) AS n FROM functions "
        "WHERE is_declaration=0 GROUP BY file_path ORDER BY n DESC,file_path"
    ).fetchall()
    files = [str(row[0]) for row in rows]
    if limit <= 0 or limit >= len(files):
        return sorted(files)
    return sorted({files[i * len(files) // limit] for i in range(limit)})


def profile(args: argparse.Namespace) -> dict[str, Any]:
    root = Path(args.project_root).resolve()
    source_db = Path(args.knowledge_db).resolve()
    output = Path(args.output).resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    report: dict[str, Any] = {
        "schema": "zscope.clang-derived-profile.v1",
        "platform": platform.platform(),
        "implementation": inspect.getfile(ClangExtractor),
        "project_root": str(root),
        "knowledge_db": str(source_db),
        "clangd_cache": "retained; state not inferred",
        "runs": [],
    }
    with tempfile.TemporaryDirectory(
        prefix="clang-derived-profile-", dir=output.parent
    ) as temporary:
        Path(temporary).resolve().relative_to(output.parent)
        for workers in args.workers:
            run_dir = Path(temporary) / str(workers)
            run_dir.mkdir()
            copy = run_dir / "knowledge.db"
            # SQLite backup also captures a source database's WAL consistently.
            with closing(sqlite3.connect(source_db.as_uri() + "?mode=ro", uri=True)) as original:
                with closing(sqlite3.connect(copy)) as target:
                    original.backup(target)
            db = KnowledgeDB(str(copy))
            try:
                files = select_files(db, args.file_limit)
                if args.files:
                    files = json.loads(Path(args.files).read_text(encoding="utf-8"))
                if not isinstance(files, list) or not all(isinstance(file, str) for file in files):
                    raise ValueError(
                        "--files must contain a JSON array of project-relative file names"
                    )
                if "files" not in report:
                    report["files"] = files
                elif report["files"] != files:
                    raise RuntimeError("Selected file set changed between worker runs")
                for repeat in range(args.repeats):
                    extractor = ClangExtractor(
                        root,
                        clangd_path=args.clangd,
                        compile_commands_dir=Path(args.compile_commands_dir).resolve(),
                        max_threads=workers,
                    )
                    start = time.monotonic()
                    try:
                        if not extractor.start():
                            raise RuntimeError("clangd failed to start")
                        if files:
                            first_file = extractor._resolve_indexed_source_path(files[0])
                            if not extractor.open_document(first_file):
                                raise RuntimeError("Cannot open first selected file")
                            try:
                                extractor.get_semantic_tokens(first_file)
                            finally:
                                extractor.close_document(first_file)
                        if not extractor.wait_for_indexing(timeout=120):
                            raise RuntimeError("clangd did not become ready; this run is invalid")
                        ready_seconds = time.monotonic() - start
                        specs = (
                            (
                                "function_symbol_context",
                                ClangBackend.SYMBOL_CONTEXT_EXTRACTOR_VERSION,
                            ),
                            (
                                "function_type_refs",
                                ClangBackend.FUNCTION_TYPE_REF_EXTRACTOR_VERSION,
                            ),
                        )
                        for name, version in specs:
                            db.begin_derived_index_rebuild(name, version)
                            db.prepare_derived_index_staging(name)
                        derived_start = time.monotonic()
                        result = extractor.rebuild_function_derived_refs(
                            db, use_staging=True, only_files=set(files)
                        )
                        if result["errors"]:
                            raise RuntimeError(str(result["errors"]))
                        for name, version in specs:
                            db.finalize_derived_index_rebuild(
                                name, version, extractor.get_last_derived_stats(name)
                            )
                        row = {
                            "workers": workers,
                            "repeat": repeat,
                            "clangd": extractor._server_info,
                            "derived_cache_state": "fresh" if repeat == 0 else "resume_requested",
                            "startup_seconds": ready_seconds,
                            "derived_seconds": time.monotonic() - derived_start,
                            "elapsed_seconds": time.monotonic() - start,
                            "facts_sha256": fact_digest(db),
                            "layers": {
                                name: extractor.get_last_derived_stats(name) for name, _ in specs
                            },
                        }
                        report["runs"].append(row)
                        output.write_text(
                            json.dumps(report, indent=2, ensure_ascii=False) + "\n",
                            encoding="utf-8",
                        )
                    finally:
                        extractor.stop()
            finally:
                db.close()
    if len({run["facts_sha256"] for run in report["runs"]}) != 1:
        raise RuntimeError("Derived facts differ between runs; inspect the saved report")
    return report


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project-root", required=True)
    parser.add_argument("--knowledge-db", required=True)
    parser.add_argument("--compile-commands-dir", required=True)
    parser.add_argument("--clangd", default="clangd")
    parser.add_argument(
        "--workers", nargs="+", type=int, choices=(1, 2, 4, 8), default=[1, 2, 4, 8]
    )
    parser.add_argument("--repeats", type=int, default=3)
    parser.add_argument("--file-limit", type=int, default=200, help="0 selects all function files")
    parser.add_argument("--files", help="Replay a saved JSON array of file names")
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    if args.repeats < 1:
        parser.error("--repeats must be positive")
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s")
    report = profile(args)
    print(json.dumps({"runs": len(report["runs"]), "output": str(Path(args.output).resolve())}))


if __name__ == "__main__":
    main()
