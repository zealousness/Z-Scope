"""Preserve committed semantic evidence before a trial removes its workspace."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sqlite3
import zipfile


def archive_workbook(publication: Path, target: Path, manifest: dict) -> None:
    if any(row["path"] == "user_config.xlsx" for row in manifest["files"]):
        return
    path = Path(json.loads(publication.read_text(encoding="utf-8"))["workbook"]).resolve()
    if not path.is_relative_to(publication.parents[2].resolve()):
        raise ValueError("Workbook is outside the isolated scan input")
    with zipfile.ZipFile(path) as book:
        if book.testzip() is not None:
            raise ValueError("Publication workbook is not a valid complete archive")
    contents = path.read_bytes()
    (target / "user_config.xlsx").write_bytes(contents)
    manifest["files"].append(
        {
            "path": "user_config.xlsx",
            "bytes": len(contents),
            "sha256": hashlib.sha256(contents).hexdigest(),
        }
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", type=Path, required=True)
    parser.add_argument("--run", type=Path, required=True)
    args = parser.parse_args()
    root = args.workspace / "scan-input/.zscope_snapshots"
    publication = root / ".semantic-modeling/publication.json"
    if not publication.exists():
        print("Modeling has not published yet; no archive was written.")
        return
    target = args.run / "semantic-evidence"
    manifest_path = target / "manifest.json"
    if manifest_path.exists():
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        if not any(row["path"] == "user_config.xlsx" for row in manifest["files"]):
            archive_workbook(publication, target, manifest)
            manifest_path.write_text(
                json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
            )
        print("Committed evidence already archived: " + str(manifest_path))
        return
    paths = list((root / ".semantic-modeling").rglob("*.json"))
    paths.extend((root / ".modeling-tasks").glob("*.json"))
    for path in root.glob("*.json"):
        data = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(data, dict) and data.get("func_name"):
            paths.append(path)
    manifest = {
        "source_workspace": str(args.workspace),
        "contract_version": json.loads(publication.read_text(encoding="utf-8"))["contract_version"],
        "files": [],
    }
    for path in sorted(paths):
        contents = path.read_bytes()
        json.loads(contents)  # A partial concurrent write must never be archived.
        relative = path.relative_to(root)
        destination = target / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(contents)
        manifest["files"].append(
            {
                "path": relative.as_posix(),
                "bytes": len(contents),
                "sha256": hashlib.sha256(contents).hexdigest(),
            }
        )
    # SQLite backup gives a committed index even if Validator has opened the
    # source database. Copying the main file alone could miss its WAL contents.
    database = root / "snapshots.db"
    if database.exists():
        destination = target / "snapshots.db"
        with sqlite3.connect(database.as_uri() + "?mode=ro", uri=True) as source:
            with sqlite3.connect(destination) as backup:
                source.backup(backup)
        contents = destination.read_bytes()
        manifest["files"].append(
            {
                "path": "snapshots.db",
                "bytes": len(contents),
                "sha256": hashlib.sha256(contents).hexdigest(),
            }
        )
    archive_workbook(publication, target, manifest)
    manifest_path.write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    print(json.dumps({"archive": str(target), "files": len(manifest["files"])}, ensure_ascii=False))


if __name__ == "__main__":
    main()
