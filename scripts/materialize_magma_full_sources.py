#!/usr/bin/env python3
"""Materialize full Magma target source trees with target fetch scripts."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import Any


def _safe_rmtree(path: Path, allowed_root: Path) -> None:
    path = path.resolve()
    allowed_root = allowed_root.resolve()
    if not path.exists():
        return
    if path != allowed_root and allowed_root not in path.parents:
        raise SystemExit(f"Refusing to delete outside output root: {path}")
    shutil.rmtree(path)


def _copy_src(target_dir: Path, dst_root: Path) -> None:
    src = target_dir / "src"
    if src.exists():
        shutil.copytree(src, dst_root / "src", dirs_exist_ok=True)


def _run_fetch(target_dir: Path, dst_root: Path, downloads: Path) -> dict[str, Any]:
    dst_root.mkdir(parents=True, exist_ok=True)
    downloads.mkdir(parents=True, exist_ok=True)
    _copy_src(target_dir, dst_root)
    env = os.environ.copy()
    env["TARGET"] = dst_root.as_posix()
    env["OUT"] = downloads.as_posix()
    result = subprocess.run(
        ["bash", str(target_dir / "fetch.sh")],
        cwd=str(target_dir),
        env=env,
        text=True,
        capture_output=True,
    )
    repo = dst_root / "repo"
    files = 0
    bytes_total = 0
    if repo.exists():
        for item in repo.rglob("*"):
            if item.is_file() and ".git" not in item.parts:
                files += 1
                try:
                    bytes_total += item.stat().st_size
                except OSError:
                    pass
    return {
        "returncode": result.returncode,
        "stdout": result.stdout[-4000:],
        "stderr": result.stderr[-4000:],
        "source_root": repo.as_posix(),
        "files": files,
        "bytes": bytes_total,
    }


def materialize(args: argparse.Namespace) -> dict[str, Any]:
    magma_root = Path(args.magma_root).resolve()
    output_root = Path(args.output_root).resolve()
    downloads = output_root / "_downloads"
    targets_root = magma_root / "targets"
    targets = args.targets or [p.name for p in sorted(targets_root.iterdir()) if p.is_dir()]
    output_root.mkdir(parents=True, exist_ok=True)
    summary: dict[str, Any] = {"output_root": output_root.as_posix(), "targets": {}}
    for target in targets:
        target_dir = targets_root / target
        if not (target_dir / "fetch.sh").exists():
            raise SystemExit(f"Missing fetch.sh for target: {target}")
        dst_root = output_root / target
        if args.force:
            _safe_rmtree(dst_root, output_root)
        if (dst_root / "repo").exists() and not args.force:
            files = 0
            bytes_total = 0
            for p in (dst_root / "repo").rglob("*"):
                if p.is_file() and ".git" not in p.parts:
                    files += 1
                    try:
                        bytes_total += p.stat().st_size
                    except OSError:
                        pass
            result = {
                "returncode": 0,
                "stdout": "",
                "stderr": "already exists; use --force to refresh",
                "source_root": (dst_root / "repo").as_posix(),
                "files": files,
                "bytes": bytes_total,
            }
        else:
            result = _run_fetch(target_dir, dst_root, downloads)
        summary["targets"][target] = result
        if result["returncode"] != 0 and args.fail_fast:
            break
    (output_root / "materialize_full_summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    return summary


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--magma-root", default="/mnt/c/tmp/zscope_external_sources/magma")
    parser.add_argument("--output-root", default="/mnt/c/tmp/zscope_external_sources/magma_full")
    parser.add_argument("--targets", nargs="*", default=[])
    parser.add_argument("--force", action="store_true")
    parser.add_argument("--fail-fast", action="store_true")
    return parser


def main() -> None:
    args = build_parser().parse_args()
    print(json.dumps(materialize(args), ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
