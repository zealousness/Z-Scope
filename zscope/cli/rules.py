"""Command-line interface for the effective rule catalog and extensions."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

import click

from ..config.config import ConfigLoader
from ..orchestration.specs import SpecRegistry
from ..rules.catalog import EffectiveRuleSet
from ..rules.extensions import RulePackError, RuleRegistry, run_pack_tests
from ..rules.query import query_effective_rules


def _configured_effective(config_path: Path) -> EffectiveRuleSet:
    config = ConfigLoader.load(str(config_path))
    effective = config.effective_rules
    if not isinstance(effective, EffectiveRuleSet):
        raise RulePackError("rule preflight did not produce an EffectiveRuleSet")
    return effective


def _filtered_payload(
    effective: EffectiveRuleSet,
    *,
    language: Optional[str] = None,
    engine: Optional[str] = None,
    skill: Optional[str] = None,
    status: Optional[str] = None,
    query: Optional[str] = None,
) -> Dict[str, Any]:
    return query_effective_rules(
        effective,
        language=language,
        engine=engine,
        skill=skill,
        status=status,
        query=query,
    )


@click.group()
def main() -> None:
    """Inspect the effective catalog and validate Z-SCOPE rule extensions."""


@main.command("list")
@click.option(
    "--config",
    "config_path",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    default=Path("zscope.yaml"),
    show_default=True,
)
@click.option("--language", type=click.Choice(["c_cpp", "java"]))
@click.option("--engine", help="Filter by deterministic engine.")
@click.option(
    "--status",
    type=click.Choice(
        ["stable", "experimental", "deprecated", "enabled", "disabled", "unavailable"]
    ),
)
@click.option("--json", "json_output", is_flag=True, help="Emit the shared JSON schema.")
def list_rules(
    config_path: Path,
    language: Optional[str],
    engine: Optional[str],
    status: Optional[str],
    json_output: bool,
) -> None:
    """List built-in and configured extension rules for one config."""

    try:
        effective = _configured_effective(config_path)
        payload = _filtered_payload(
            effective,
            language=language,
            engine=engine,
            status=status,
        )
    except (OSError, RulePackError, ValueError) as exc:
        raise click.ClickException(str(exc)) from exc
    if json_output:
        click.echo(json.dumps(payload, ensure_ascii=False, indent=2))
        return
    click.echo("ID\tLANGUAGE\tENGINE\tCWE\tSKILL\tREV\tSOURCE\tSTATUS\tREASON")
    for row in payload["rules"]:
        click.echo(
            "\t".join(
                str(row.get(key) or "")
                for key in (
                    "id",
                    "language",
                    "engine",
                    "cwe",
                    "skill",
                    "revision",
                    "source",
                    "effective_status",
                    "effective_reason",
                )
            )
        )


@main.command("show")
@click.argument("rule_id")
@click.option(
    "--config",
    "config_path",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    default=Path("zscope.yaml"),
    show_default=True,
)
@click.option("--json", "json_output", is_flag=True, help="Emit machine-readable JSON.")
def show_rule(rule_id: str, config_path: Path, json_output: bool) -> None:
    """Show a canonical descriptor and its effective status."""

    try:
        effective = _configured_effective(config_path)
        state = effective.state_for(rule_id)
        if state is None:
            raise RulePackError(f"unknown rule id {rule_id!r}")
        payload: Dict[str, Any] = {
            "schema_version": effective.provenance.schema_version,
            "catalog_sha256": effective.provenance.catalog_sha256,
            "effective_sha256": effective.provenance.effective_sha256,
            "language": effective.language,
            "backend": effective.backend,
            "config_valid": True,
            "rule": state.as_dict(),
        }
    except (OSError, RulePackError, ValueError) as exc:
        raise click.ClickException(str(exc)) from exc
    if json_output:
        click.echo(json.dumps(payload, ensure_ascii=False, indent=2))
        return
    row = dict(payload["rule"])
    for key in (
        "id",
        "language",
        "engine",
        "defect_class",
        "cwe",
        "skill",
        "default_severity",
        "revision",
        "status",
        "title",
        "summary",
        "required_capabilities",
        "aliases",
        "source",
        "effective_status",
        "effective_reason",
    ):
        value = row.get(key)
        click.echo(
            f"{key}: {json.dumps(value, ensure_ascii=False) if isinstance(value, (list, dict)) else value}"
        )


@main.command("validate")
@click.argument(
    "packs", nargs=-1, required=True, type=click.Path(exists=True, dir_okay=False, path_type=Path)
)
def validate_rules(packs: Tuple[Path, ...]) -> None:
    """Validate one or more versioned YAML rule packs."""

    specs = SpecRegistry()
    registry = RuleRegistry()
    skill_languages = {name: tuple(skill.languages) for name, skill in specs.skills.items()}
    try:
        for path in packs:
            pack = registry.load_pack(path, skill_languages=skill_languages)
            click.echo(f"OK {pack.path} ({len(pack.rules)} rules)")
    except (OSError, RulePackError, ValueError) as exc:
        raise click.ClickException(str(exc)) from exc


@main.command("test")
@click.argument(
    "packs", nargs=-1, required=True, type=click.Path(exists=True, dir_okay=False, path_type=Path)
)
def test_rules(packs: Tuple[Path, ...]) -> None:
    """Run each pack's positive, negative, and candidate snapshot fixtures."""

    specs = SpecRegistry()
    registry = RuleRegistry()
    skill_languages = {name: tuple(skill.languages) for name, skill in specs.skills.items()}
    failures: list[str] = []
    try:
        loaded = [registry.load_pack(path, skill_languages=skill_languages) for path in packs]
        for pack in loaded:
            pack_failures = run_pack_tests(pack, registry)
            if pack_failures:
                failures.extend(f"{pack.path}: {item}" for item in pack_failures)
            else:
                click.echo(f"PASS {pack.path} ({len(pack.tests)} fixtures)")
    except (OSError, RulePackError, ValueError) as exc:
        raise click.ClickException(str(exc)) from exc
    if failures:
        raise click.ClickException("\n".join(failures))


if __name__ == "__main__":
    main()
