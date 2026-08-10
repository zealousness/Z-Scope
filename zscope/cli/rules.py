"""Command-line interface for rule-pack discovery, validation, and fixtures."""

from __future__ import annotations

from pathlib import Path
from typing import Optional, Tuple

import click

from ..config.config import ConfigLoader
from ..core.candidates.java_rules import JavaRuleCandidateGenerator
from ..orchestration.specs import SpecRegistry
from ..rules.extensions import RulePackError, RuleRegistry, run_pack_tests


def _configured_registry(config_path: Path) -> Tuple[RuleRegistry, SpecRegistry]:
    config = ConfigLoader.load(str(config_path))
    specs = SpecRegistry(project_root=config.project.project_root)
    registry = RuleRegistry(disabled_ids=config.rules.disabled_ids)
    known_skills = sorted(specs.skills)
    for value in config.rules.packs:
        path = Path(value).expanduser()
        if not path.is_absolute():
            path = config.project.project_root / path
        registry.load_pack(path, known_skills=known_skills)
    registry.load_providers(config.rules.providers)
    return registry, specs


@click.group()
def main() -> None:
    """Inspect and validate Z-SCOPE rule extensions."""


@main.command("list")
@click.option(
    "--config",
    "config_path",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    default=Path("zscope.yaml"),
    show_default=True,
)
def list_rules(config_path: Path) -> None:
    """List enabled and disabled configured extension rules."""

    try:
        registry, _ = _configured_registry(config_path)
    except (OSError, RulePackError, ValueError) as exc:
        raise click.ClickException(str(exc)) from exc
    for builtin_rule in sorted(JavaRuleCandidateGenerator._RULES, key=lambda item: item.rule_id):
        state = "disabled" if builtin_rule.rule_id in registry.disabled_ids else "enabled"
        click.echo(f"{builtin_rule.rule_id}\tjava\t{state}\tbuiltin")
    for rule_id, extension_rule in sorted(registry.all_rules.items()):
        state = "disabled" if rule_id in registry.disabled_ids else "enabled"
        click.echo(f"{rule_id}\t{extension_rule.language}\t{state}\textension")


@main.command("validate")
@click.argument(
    "packs", nargs=-1, required=True, type=click.Path(exists=True, dir_okay=False, path_type=Path)
)
def validate_rules(packs: Tuple[Path, ...]) -> None:
    """Validate one or more versioned YAML rule packs."""

    specs = SpecRegistry()
    registry = RuleRegistry()
    try:
        for path in packs:
            pack = registry.load_pack(path, known_skills=sorted(specs.skills))
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
    failures = []
    try:
        loaded = [registry.load_pack(path, known_skills=sorted(specs.skills)) for path in packs]
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
