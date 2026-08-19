"""Validate public config v2 and explicitly persist compat migrations."""

from __future__ import annotations

from pathlib import Path

import click
import yaml

from ..compat.config import migrate_legacy_document
from ..config.config import ConfigLoader
from ..config.v2 import load_yaml_unique


@click.group()
def main() -> None:
    """Manage strict Z-Scope public configuration v2."""


@main.command("validate")
@click.option(
    "--config",
    "config_path",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    required=True,
)
def validate_command(config_path: Path) -> None:
    """Validate a v2 YAML file and its internal runtime-spec composition."""

    try:
        config = ConfigLoader.load(str(config_path))
    except Exception as exc:
        raise click.ClickException(str(exc)) from exc
    click.echo(
        "Valid config v2: "
        f"language={config.project.language} backend={config.indexing.backend} "
        f"runtime_spec={config.runtime_provenance.sha256[:12]} "
        f"effective_rules={getattr(config.rule_catalog_provenance, 'effective_sha256', '')[:12]}"
    )
    for warning in config.rule_validation_warnings:
        click.echo(f"Warning: {warning}", err=True)


@main.command("migrate")
@click.option(
    "--input",
    "input_path",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    required=True,
)
@click.option(
    "--output",
    "output_path",
    type=click.Path(dir_okay=False, path_type=Path),
    required=True,
)
@click.option("--force", is_flag=True, help="Replace an existing output file.")
def migrate_command(input_path: Path, output_path: Path, force: bool) -> None:
    """Create a v2 file from legacy YAML without changing the source file."""

    destination = output_path.expanduser()
    if destination.resolve() == input_path.resolve():
        raise click.ClickException(
            "--output must differ from --input; migration never overwrites source"
        )
    if destination.exists() and not force:
        raise click.ClickException(f"refusing to overwrite existing file: {destination}")
    try:
        migrated, warnings = migrate_legacy_document(load_yaml_unique(input_path.resolve()))
    except Exception as exc:
        raise click.ClickException(str(exc)) from exc
    destination.parent.mkdir(parents=True, exist_ok=True)
    text = yaml.safe_dump(
        migrated,
        allow_unicode=True,
        sort_keys=False,
        default_flow_style=False,
    )
    with destination.open("w", encoding="utf-8", newline="\n") as handle:
        handle.write(text)
    click.echo(f"Created config v2: {destination}")
    for warning in warnings:
        click.echo(f"Warning: {warning}", err=True)


if __name__ == "__main__":
    main()
