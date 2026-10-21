"""Replay derived cache pressure without clangd or customer source code.

Run this same script with PYTHONPATH pointing to each source revision. It measures
coordinate conversion, simulated RPC cache traffic and file validation, not full
indexing throughput. Output identities must agree across revisions and workers.
"""

from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor
import hashlib
import inspect
import json
import os
from pathlib import Path
import tempfile
import time

from zscope.retrieval.clang_derived_cache import DerivedCache
from zscope.retrieval.clang_extractor import ClangExtractor
from zscope.retrieval.clang_resolution import DerivedResolver, process_rss


def measure(root, files, references, workers, budget):
    ex = ClangExtractor(root)
    cache = DerivedCache(max_bytes=budget)
    resolver = ex._derived_resolver = DerivedResolver(ex, cache)
    selects = 0

    def trace(sql):
        nonlocal selects
        if sql.startswith("SELECT"):
            selects += 1

    cache.db.set_trace_callback(trace)

    def run(source):
        digest = hashlib.sha256()
        with resolver.file(source) as state:
            # Shared headers and per-TU coordinates exceed a small hot budget.
            for path in files:
                locations = [
                    {"uri": path.as_uri(), "range": {"start": {"line": line, "character": 7}}}
                    for line in range(references)
                ]
                for location in resolver.locations(locations):
                    digest.update(json.dumps(location).encode())
            for line in range(references):
                key = source.name + ":" + str(line)
                value = cache.compute("symbolInfo", key, lambda: {"items": [{"usr": key}]})
                digest.update(json.dumps(value, sort_keys=True).encode())
            for line in range(references):
                key = source.name + ":" + str(line)
                value = cache.get("symbolInfo", key)
                assert value == {"items": [{"usr": key}]}
        receipts = resolver.sources.receipts(state)
        assert receipts
        return digest.hexdigest()

    started = time.monotonic()
    try:
        with ThreadPoolExecutor(workers) as pool:
            futures = [pool.submit(run, path) for path in files]
            while not all(future.done() for future in futures):
                cache.wakeup.clear()
                cache.pump()
                cache.wakeup.wait(0.001)
            identities = [future.result() for future in futures]
        resolver.sources.validate_all()
        cache.checkpoint()
        return dict(
            cache_implementation=inspect.getfile(DerivedCache),
            workers=workers,
            files=len(files),
            coordinates=len(files) ** 2 * references,
            cache_budget=budget,
            wall_seconds=time.monotonic() - started,
            sqlite_selects=selects,
            result_digest=hashlib.sha256(json.dumps(identities).encode()).hexdigest(),
            python_rss_bytes=process_rss(os.getpid()),
            actual_rpc=0,
            cache=cache.snapshot(),
            sources=resolver.sources.snapshot(),
        )
    finally:
        cache.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--files", type=int, default=16)
    parser.add_argument("--references", type=int, default=1000)
    parser.add_argument("--workers", type=int, nargs="+", default=[1, 8])
    parser.add_argument("--budget-kib", type=int, default=256)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="zscope-cache-pressure-") as directory:
        root = Path(directory)
        files = [root / f"file_{number}.cpp" for number in range(args.files)]
        for path in files:
            path.write_text("/*😀*/ value;\n" * args.references, encoding="utf-8")
        results = [
            measure(root, files, args.references, workers, args.budget_kib << 10)
            for workers in args.workers
        ]
        assert len({result["result_digest"] for result in results}) == 1
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps({"kind": "synthetic_cache_pressure_replay", "results": results}, indent=2)
        + "\n",
        encoding="utf-8",
    )
    for result in results:
        print(
            json.dumps(
                {
                    k: result[k]
                    for k in ("workers", "wall_seconds", "sqlite_selects", "result_digest")
                }
            )
        )


if __name__ == "__main__":
    main()
