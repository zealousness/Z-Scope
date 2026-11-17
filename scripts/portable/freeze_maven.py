#!/usr/bin/env python3
"""Freeze a prepared Maven repository; normal fetch never resolves Maven versions."""

import argparse
import base64
import hashlib
import json
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    files = {}
    for path in sorted(args.repository.rglob("*")):
        if not path.is_file() or (
            path.suffix not in {".jar", ".pom", ".xml"} and path.name != "_remote.repositories"
        ):
            continue
        relative = path.relative_to(args.repository).as_posix()
        content = path.read_bytes()
        item = {"sha256": hashlib.sha256(content).hexdigest(), "size": len(content)}
        if path.suffix in {".jar", ".pom"}:
            item["url"] = "https://repo.maven.apache.org/maven2/" + relative
        else:
            item["inline_base64"] = base64.b64encode(content).decode("ascii")
        files[relative] = item
    if not files:
        raise ValueError("Cannot freeze an empty Maven repository")
    args.output.write_text(
        json.dumps({"schema_version": "zscope.portable-maven.v1", "files": files}, indent=2) + "\n"
    )


if __name__ == "__main__":
    main()
