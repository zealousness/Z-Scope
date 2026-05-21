#!/usr/bin/env python3
"""Materialize only Magma bug-touched source files.

The full Magma targets are large and some fetch scripts require full builds.
For static-analysis benchmarking we first need the files touched by Magma bug
patches. This helper downloads those files at the exact upstream commit pinned
by each target's fetch script.
"""

from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import tarfile
import urllib.request
from pathlib import Path
from typing import Any


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="ignore")


def _patch_changed_files(patch: Path) -> list[str]:
    files: list[str] = []
    for line in _read(patch).splitlines():
        if line.startswith("diff --git "):
            parts = line.split()
            if len(parts) >= 4:
                path = parts[2][2:] if parts[2].startswith("a/") else parts[2]
                if path not in files:
                    files.append(path)
    return files


def _target_fetch_info(target_dir: Path) -> dict[str, Any]:
    fetch = _read(target_dir / "fetch.sh")
    clones = re.findall(
        r"git clone(?: --no-checkout)?\s+([^\s]+)\s+(?:\\\s*[\r\n]+\s*)?\"\$TARGET/([^\"]+)\"",
        fetch,
    )
    checkouts = re.findall(r"git -C \"\$TARGET/([^\"]+)\" checkout ([0-9a-f]+)", fetch)
    checkout_by_dir = {name: commit for name, commit in checkouts}
    repos = []
    for url, directory in clones:
        repos.append({"url": url, "directory": directory, "commit": checkout_by_dir.get(directory, "")})
    sqlite = re.search(r"curl \"([^\"]*sqlite[^\"]*)\"", fetch)
    return {"repos": repos, "sqlite_tarball": sqlite.group(1) if sqlite else ""}


def _raw_url(repo_url: str, commit: str, rel: str) -> str:
    repo_url = repo_url.removesuffix(".git")
    if "github.com/" in repo_url:
        owner_repo = repo_url.split("github.com/", 1)[1]
        return f"https://raw.githubusercontent.com/{owner_repo}/{commit}/{rel}"
    if "gitlab.com/" in repo_url:
        owner_repo = repo_url.split("gitlab.com/", 1)[1]
        return f"https://gitlab.com/{owner_repo}/-/raw/{commit}/{rel}"
    if "gitlab.gnome.org/" in repo_url:
        owner_repo = repo_url.split("gitlab.gnome.org/", 1)[1]
        return f"https://gitlab.gnome.org/{owner_repo}/-/raw/{commit}/{rel}"
    if "gitlab.freedesktop.org/" in repo_url:
        owner_repo = repo_url.split("gitlab.freedesktop.org/", 1)[1]
        return f"https://gitlab.freedesktop.org/{owner_repo}/-/raw/{commit}/{rel}"
    raise ValueError(f"Unsupported repo URL: {repo_url}")


def _download(url: str, dst: Path) -> tuple[bool, str]:
    dst.parent.mkdir(parents=True, exist_ok=True)
    last_error = ""
    for _ in range(3):
        try:
            request = urllib.request.Request(url, headers={"User-Agent": "zscope-magma-materializer"})
            with urllib.request.urlopen(request, timeout=90) as response:
                dst.write_bytes(response.read())
            return True, ""
        except Exception as exc:  # pragma: no cover - network dependent
            last_error = str(exc)
    curl = shutil.which("curl") or shutil.which("curl.exe")
    if curl:
        try:
            subprocess.run([curl, "-L", "--fail", "--retry", "3", "-o", str(dst), url], check=True)
            return True, ""
        except Exception as exc:  # pragma: no cover - network dependent
            last_error = str(exc)
    return False, last_error


def _download_sqlite_files(tarball_url: str, rels: list[str], target_root: Path) -> dict[str, str]:
    result: dict[str, str] = {}
    archive = target_root.parent / "_downloads" / "sqlite.tar.gz"
    ok, err = _download(tarball_url, archive)
    if not ok:
        return {rel: err for rel in rels}
    wanted = set(rels)
    with tarfile.open(archive, "r:gz") as tar:
        for member in tar.getmembers():
            rel = "/".join(Path(member.name).parts[1:])
            if rel not in wanted or not member.isfile():
                continue
            extracted = tar.extractfile(member)
            if extracted is None:
                continue
            dst = target_root / "repo" / rel
            dst.parent.mkdir(parents=True, exist_ok=True)
            dst.write_bytes(extracted.read())
            result[rel] = "ok"
    for rel in wanted:
        result.setdefault(rel, "not found in sqlite tarball")
    return result


def materialize(args: argparse.Namespace) -> dict[str, Any]:
    magma_root = Path(args.magma_root).resolve()
    output_root = Path(args.output_root).resolve()
    targets_root = magma_root / "targets"
    targets = args.targets or [p.name for p in sorted(targets_root.iterdir()) if p.is_dir()]
    summary: dict[str, Any] = {"output_root": output_root.as_posix(), "targets": {}}

    for target in targets:
        target_dir = targets_root / target
        bug_dir = target_dir / "patches" / "bugs"
        patches = sorted(bug_dir.glob("*.patch"))
        changed: list[str] = []
        for patch in patches:
            for rel in _patch_changed_files(patch):
                if rel not in changed:
                    changed.append(rel)
        info = _target_fetch_info(target_dir)
        target_root = output_root / target
        target_summary = {
            "bugs": len(patches),
            "changed_files": len(changed),
            "downloaded": 0,
            "failed": {},
            "source_root": (target_root / "repo").as_posix(),
        }

        if info["sqlite_tarball"]:
            sqlite_result = _download_sqlite_files(info["sqlite_tarball"], changed, target_root)
            for rel, status in sqlite_result.items():
                if status == "ok":
                    target_summary["downloaded"] += 1
                else:
                    target_summary["failed"][rel] = status
        elif info["repos"]:
            main_repo = next((repo for repo in info["repos"] if repo["directory"] == "repo"), info["repos"][0])
            for rel in changed:
                if rel.startswith("oniguruma/"):
                    repo = next((item for item in info["repos"] if item["directory"] == "repo/oniguruma"), main_repo)
                    raw_rel = rel[len("oniguruma/") :]
                else:
                    repo = main_repo
                    raw_rel = rel
                if not repo.get("commit"):
                    target_summary["failed"][rel] = "missing commit"
                    continue
                url = _raw_url(repo["url"], repo["commit"], raw_rel)
                ok, err = _download(url, target_root / "repo" / rel)
                if ok:
                    target_summary["downloaded"] += 1
                else:
                    target_summary["failed"][rel] = err
        else:
            target_summary["failed"]["<target>"] = "no fetch source parsed"

        summary["targets"][target] = target_summary

    (output_root / "materialize_summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    return summary


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--magma-root", default="/mnt/c/tmp/zscope_external_sources/magma")
    parser.add_argument("--output-root", default="/mnt/c/tmp/zscope_external_sources/magma_raw")
    parser.add_argument("--targets", nargs="*", default=[])
    return parser


def main() -> None:
    args = build_parser().parse_args()
    print(json.dumps(materialize(args), ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
