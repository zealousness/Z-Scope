"""Prepare and verify customer Maven dependency caches for isolated networks."""

from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
from pathlib import Path
from typing import Dict

import click

MANIFEST = "zscope-maven-cache-manifest.json"


def _hashes(root: Path) -> Dict[str, str]:
    result: Dict[str, str] = {}
    for path in sorted(
        item for item in root.rglob("*") if item.is_file() and item.name != MANIFEST
    ):
        if path.is_symlink():
            raise click.ClickException(f"symbolic links are not allowed in Maven cache: {path}")
        result[path.relative_to(root).as_posix()] = hashlib.sha256(path.read_bytes()).hexdigest()
    return result


@click.group()
def main() -> None:
    """Move customer Maven dependencies from a connected host to an offline host."""


@main.command("prepare")
@click.option(
    "--project",
    type=click.Path(exists=True, file_okay=False, path_type=Path),
    default=Path("."),
    show_default=True,
)
@click.option("--output", type=click.Path(file_okay=False, path_type=Path), required=True)
def prepare(project: Path, output: Path) -> None:
    """Resolve a project's Maven dependencies into a portable directory."""

    mvn = shutil.which("mvn")
    if not mvn:
        raise click.ClickException("mvn is required on the connected preparation host")
    pom = project.resolve() / "pom.xml"
    if not pom.is_file():
        raise click.ClickException(f"pom.xml not found: {pom}")
    destination = output.expanduser().resolve()
    destination.mkdir(parents=True, exist_ok=True)
    proc = subprocess.run(
        [mvn, "-B", "-f", str(pom), f"-Dmaven.repo.local={destination}", "dependency:go-offline"],
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        raise click.ClickException(
            f"Maven dependency resolution failed with exit code {proc.returncode}"
        )
    files = _hashes(destination)
    manifest = {"format": 1, "project": str(pom), "files": files}
    (destination / MANIFEST).write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    click.echo(f"Prepared {len(files)} files in {destination}")


@main.command("install")
@click.option(
    "--source", type=click.Path(exists=True, file_okay=False, path_type=Path), required=True
)
@click.option(
    "--destination",
    type=click.Path(file_okay=False, path_type=Path),
    default=Path("~/.cache/zscope/maven"),
    show_default=True,
)
def install(source: Path, destination: Path) -> None:
    """Verify and import a prepared cache without contacting the network."""

    source = source.resolve()
    manifest_path = source / MANIFEST
    if not manifest_path.is_file():
        raise click.ClickException(f"missing cache manifest: {manifest_path}")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    expected = manifest.get("files") if isinstance(manifest, dict) else None
    actual = _hashes(source)
    if not isinstance(expected, dict) or actual != expected:
        raise click.ClickException("Maven cache hash verification failed")
    destination = destination.expanduser().resolve()
    destination.mkdir(parents=True, exist_ok=True)
    shutil.copytree(source, destination, dirs_exist_ok=True)
    click.echo(f"Installed {len(actual)} verified files into {destination}")


if __name__ == "__main__":
    main()
