"""Measure a fixed TU sample and checkpoint reuse without touching published facts.

This measures extraction, not end-to-end indexing or a vulnerability benchmark.
Use a full configured scan for publication/total-time acceptance.
"""

from __future__ import annotations

import argparse
import json
import logging
import platform
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from types import SimpleNamespace

from zscope.config.config import ConfigLoader
from zscope.retrieval.clang_backend import ClangBackend
from zscope.retrieval.clang_batch import BatchIndexer, find_indexer
from zscope.retrieval.indexing_identity import InputValidator, atomic_json, digest_json
from zscope.retrieval.indexing_runtime import admitted_workers, heartbeat, resource_limits


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("-c", "--config", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--sample-tus", type=int, default=200, help="0 means all selected TUs")
    parser.add_argument("--workers", type=int, nargs="+", default=[1, 2, 4, 8])
    parser.add_argument("--repeats", type=int, default=2)
    parser.add_argument(
        "--sources", type=Path, help="Replay a saved JSON array of absolute source paths"
    )
    args = parser.parse_args()
    if platform.system() != "Linux":
        parser.error("run this harness in Linux/WSL with the native tool installed")
    if args.sample_tus != 0 and not 100 <= args.sample_tus <= 300:
        parser.error("--sample-tus must be 100..300, or 0 for the complete selected scope")
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    config = ConfigLoader.load(str(args.config.resolve()))
    native = find_indexer(config.indexing.clang_indexer_path)
    if not native or not config.project.compile_commands_path:
        parser.error("a compatible batch tool and compile_commands.json are required")
    output = args.output.resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    backend = ClangBackend(frontend="batch")
    backend._source_path = Path(config.project.source_root).resolve()
    backend._compile_commands_path = str(config.project.compile_commands_path)
    backend._include_paths = list(getattr(config.project, "include_paths", []))
    backend._exclude_paths = list(getattr(config.project, "exclude_paths", []))
    report = {
        "schema": "zscope.batch-profile.v1",
        "scope": "TU extraction and validation only",
        "resources": resource_limits(),
        "runs": [],
    }
    # Persistent subdirectories allow interrupted runs to be inspected/resumed.
    cache_root = output.parent / (output.stem + "-artifacts")
    for requested in args.workers:
        backend._db = SimpleNamespace(_db_path=cache_root / str(requested) / "unused.db")
        indexer = BatchIndexer(backend, *native)
        jobs = sorted(
            indexer._jobs(), key=lambda job: (Path(job["source"]).stat().st_size, job["source"])
        )
        if args.sources:
            selected = set(json.loads(args.sources.read_text()))
            jobs = [job for job in jobs if job["source"] in selected]
        elif 0 < args.sample_tus < len(jobs):
            jobs = [jobs[index * len(jobs) // args.sample_tus] for index in range(args.sample_tus)]
        report["sources"] = [job["source"] for job in jobs]
        workers = admitted_workers(requested, len(jobs), indexer.memory_mb)
        if not workers:
            raise RuntimeError("no TU worker fits the available memory budget")
        for repeat in range(max(1, args.repeats)):
            indexer.validator = InputValidator([indexer.cache.parent])
            started = time.monotonic()
            row = {
                "requested_workers": requested,
                "admitted_workers": workers,
                "repeat": repeat,
                "successful": [],
                "failed": [],
                "reused": 0,
                "planned_tus": len(jobs),
            }
            with heartbeat("clang-timing", row), ThreadPoolExecutor(max_workers=workers) as pool:
                pending = {pool.submit(indexer._extract, job): job for job in jobs}
                try:
                    for future in as_completed(pending):
                        job = pending[future]
                        try:
                            package = future.result()
                            atomic_json(indexer.cache / (job["key"] + ".json"), package)
                            row["reused"] += int(package["reused"])
                            row["successful"].append(
                                {
                                    "source": job["source"],
                                    "facts_sha256": package["artifact_sha256"],
                                    "metrics": package["metrics"],
                                }
                            )
                        except Exception as exc:
                            row["failed"].append({"source": job["source"], "reason": str(exc)})
                except BaseException:
                    indexer.cancel.set()
                    for future in pending:
                        future.cancel()
                    row.update(
                        interrupted=True, complete=False, wall_seconds=time.monotonic() - started
                    )
                    report["runs"].append(row)
                    atomic_json(output, report)
                    raise
            row["wall_seconds"] = time.monotonic() - started
            row["complete"] = not row["failed"] and len(row["successful"]) == len(jobs)
            row["stable_facts_digest"] = digest_json(
                sorted((value["source"], value["facts_sha256"]) for value in row["successful"])
            )
            report["runs"].append(row)
            atomic_json(output, report)


if __name__ == "__main__":
    main()
