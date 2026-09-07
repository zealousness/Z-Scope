"""Compare the previous location conversion with session snapshots (no RPC).

Synthetic references isolate Python path/source overhead; this is not a full
clangd index benchmark or an estimate for a customer's repository.
"""

from __future__ import annotations

import argparse
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import os
from pathlib import Path
import tempfile
import threading
import time
from unittest.mock import patch

from zscope.retrieval.clang_derived_cache import DerivedCache
from zscope.retrieval.clang_extractor import ClangExtractor
from zscope.retrieval.clang_resolution import DerivedResolver, process_rss


def measure(root, files, references, workers, snapshots):
    ex = ClangExtractor(root)
    cache = DerivedCache()
    resolver = DerivedResolver(ex, cache) if snapshots else None
    ex._derived_resolver = resolver
    counters, lock = Counter(), threading.Lock()
    original_resolve, original_stat = Path.resolve, Path.stat

    def counted(method, name):
        def invoke(path, *args, **kwargs):
            with lock:
                counters[name] += 1
            return method(path, *args, **kwargs)

        return invoke

    def run(path):
        rows = []
        for line in range(references):
            raw = {"uri": path.as_uri(), "range": {"start": {"line": line, "character": 7}}}
            if resolver:
                rows.append(resolver.location(raw))
            else:
                # The exact pre-snapshot conversion, including its warm-cache checks.
                file = ex._uri_to_project_path(raw["uri"])
                lines = ex._read_source_lines(ex._resolve_indexed_source_path(file))
                column = ex._lsp_offset_to_python_in_text(lines[line], 7)
                rows.append((file, line + 1, column))
        return rows

    started = time.monotonic()
    try:
        with (
            patch.object(Path, "resolve", counted(original_resolve, "resolve")),
            patch.object(Path, "stat", counted(original_stat, "stat")),
            ThreadPoolExecutor(workers) as pool,
        ):
            futures = [pool.submit(run, path) for path in files]
            while not all(f.done() for f in futures):
                cache.wakeup.clear()
                cache.pump()
                cache.wakeup.wait(0.001)
            rows = [f.result() for f in futures]
            if resolver:
                resolver.sources.validate_all()
        return dict(
            mode="snapshots" if snapshots else "previous",
            workers=workers,
            files=len(files),
            coordinates=len(files) * references,
            wall_seconds=time.monotonic() - started,
            filesystem_calls=dict(counters),
            python_rss_bytes=process_rss(os.getpid()),
            clangd_rpc=0,
            result_digest=hashlib.sha256(json.dumps(rows).encode()).hexdigest(),
            sources=resolver.sources.snapshot() if resolver else {},
            cache=cache.snapshot(),
        )
    finally:
        cache.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--files", type=int, default=150)
    parser.add_argument("--references", type=int, default=100)
    parser.add_argument("--workers", type=int, nargs="+", default=[1, 8])
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="zscope-location-profile-") as directory:
        root = Path(directory)
        files = [root / f"file_{number}.cpp" for number in range(args.files)]
        for path in files:
            path.write_text("/*😀*/ value;\n" * args.references, encoding="utf-8")
        results = [
            measure(root, files, args.references, workers, snapshots)
            for workers in args.workers
            for snapshots in (False, True)
        ]
        assert len({result["result_digest"] for result in results}) == 1
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps({"kind": "synthetic_reference_coordinate_replay", "results": results}, indent=2)
        + "\n",
        encoding="utf-8",
    )
    for result in results:
        print(
            json.dumps(
                {
                    key: result[key]
                    for key in ("mode", "workers", "wall_seconds", "filesystem_calls")
                }
            )
        )


if __name__ == "__main__":
    main()
