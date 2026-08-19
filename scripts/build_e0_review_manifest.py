#!/usr/bin/env python3
"""Create a deterministic hash manifest for protected E0 review artifacts."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Sequence

from e0_review_governance import sha256_file, sha256_value


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--review-root", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)
    root = args.review_root.resolve(strict=True)
    output = args.output.resolve()
    files = []
    for path in sorted((item for item in root.rglob("*") if item.is_file()), key=str):
        if path.resolve() == output:
            continue
        relative = path.relative_to(root).as_posix()
        files.append({"path": relative, "size": path.stat().st_size, "sha256": sha256_file(path)})
    payload = {
        "schema_version": "zscope.range-v16-review-bundle.v1",
        "files": files,
        "file_count": len(files),
        "bundle_sha256": sha256_value(files),
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
