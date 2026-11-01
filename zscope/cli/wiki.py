"""Config-aware Wiki CLI with explicit read/write boundaries."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, Optional

import click

from ..config.config import ConfigLoader
from ..wiki.control import wiki_query, wiki_status
from ..wiki.maintenance import WikiWriterLock
from ..wiki.source_index import SourceIndex
from ..wiki.source_manifest import build_source_manifest, write_source_manifest
from ..wiki.store.revision_store import WikiStore, resolve_project_state_root
from ..wiki.lint import lint_revision


def _settings(ctx: click.Context) -> Dict[str, Any]:
    """Resolve one project/config closure for every subcommand."""

    cached = ctx.ensure_object(dict).get("wiki_settings")
    if isinstance(cached, dict):
        return cached
    explicit_root: Optional[Path] = ctx.obj.get("root")
    config_path: Optional[Path] = ctx.obj.get("config_path")
    config = None
    if config_path is not None:
        try:
            config = ConfigLoader.load(str(config_path))
        except Exception as exc:
            raise click.UsageError(f"unable to load config: {exc}") from exc
        root = Path(config.project.project_root).resolve()
        if explicit_root is not None and explicit_root.resolve() != root:
            raise click.UsageError("--root conflicts with the YAML directory from --config")
    elif explicit_root is not None:
        root = explicit_root.resolve()
    else:
        raise click.UsageError("provide --root or --config/-c")
    if not root.is_dir():
        raise click.UsageError(f"project root is not a directory: {root}")
    wiki = getattr(getattr(config, "project", None), "wiki", None)
    values: Dict[str, Any] = {
        "root": root,
        "project_id": str(getattr(getattr(config, "project", None), "project_id", "") or root.name),
        "state_dir": str(getattr(wiki, "state_dir", ".zscope_knowledge/wiki")),
        "overrides": {
            "exclude": list(getattr(wiki, "document_exclude", []) or []),
            "explanatory": list(getattr(wiki, "explanatory_overrides", []) or []),
            "generated": list(getattr(wiki, "generated_overrides", []) or []),
        },
        "max_file_bytes": int(getattr(wiki, "max_file_bytes", 10 * 1024 * 1024)),
        "max_files": int(getattr(wiki, "max_files", 10_000)),
        "max_total_bytes": int(getattr(wiki, "max_total_bytes", 100 * 1024 * 1024)),
    }
    values["state"] = resolve_project_state_root(values["root"], values["state_dir"])
    ctx.obj["wiki_settings"] = values
    return values


def _lock(settings: Dict[str, Any]) -> WikiWriterLock:
    return WikiWriterLock(settings["state"] / "locks" / "compiler.lock", timeout_seconds=0.0)


def _manifest(settings: Dict[str, Any]):
    return build_source_manifest(
        settings["root"],
        project_id=settings["project_id"],
        overrides=settings["overrides"],
        max_file_bytes=settings["max_file_bytes"],
        max_files=settings["max_files"],
        max_total_bytes=settings["max_total_bytes"],
        prune_paths=(settings["state"].relative_to(settings["root"]),),
    )


@click.group()
@click.option("--root", type=click.Path(file_okay=False, path_type=Path), required=False)
@click.option("--config", "config_path", "-c", type=click.Path(dir_okay=False, path_type=Path), required=False)
@click.pass_context
def main(ctx: click.Context, root: Optional[Path], config_path: Optional[Path]) -> None:
    """Discover, build, query and rollback a project Wiki."""

    ctx.ensure_object(dict)
    ctx.obj["root"] = root
    ctx.obj["config_path"] = config_path


@main.command("discover")
@click.pass_context
def discover(ctx: click.Context) -> None:
    settings = _settings(ctx)
    with _lock(settings):
        manifest = _manifest(settings)
        path = write_source_manifest(manifest, settings["state"] / "source-manifest.json")
    click.echo(json.dumps({"path": str(path), "accepted": len(manifest.accepted), "excluded": len(manifest.excluded), "digest": manifest.source_manifest_digest}, ensure_ascii=False, sort_keys=True))


@main.command("build")
@click.pass_context
def build(ctx: click.Context) -> None:
    settings = _settings(ctx)
    with _lock(settings):
        manifest = _manifest(settings)
        index = SourceIndex(settings["state"] / "source-index.db")
        try:
            index.rebuild(
                settings["root"],
                manifest=manifest,
                overrides=settings["overrides"],
                prune_paths=(settings["state"].relative_to(settings["root"]),),
            )
            with WikiStore(settings["state"]) as store:
                result = store.build_skeleton(settings["root"], manifest)
        finally:
            index.close()
    click.echo(json.dumps({"revision_id": result.revision_id, "pages": result.page_count, "refs": result.document_ref_count, "outcome": result.outcome}, ensure_ascii=False, sort_keys=True))


@main.command("rebuild-index")
@click.pass_context
def rebuild_index(ctx: click.Context) -> None:
    """Rebuild only the deterministic accepted-source index."""

    settings = _settings(ctx)
    with _lock(settings):
        manifest = _manifest(settings)
        index = SourceIndex(settings["state"] / "source-index.db")
        try:
            result = index.rebuild(
                settings["root"],
                manifest=manifest,
                overrides=settings["overrides"],
                prune_paths=(settings["state"].relative_to(settings["root"]),),
            )
            path = write_source_manifest(manifest, settings["state"] / "source-manifest.json")
        finally:
            index.close()
    click.echo(json.dumps({"path": str(path), "documents": result.document_count, "sections": result.section_count, "digest": result.source_manifest_digest}, ensure_ascii=False, sort_keys=True))


@main.command("status")
@click.pass_context
def status(ctx: click.Context) -> None:
    settings = _settings(ctx)
    click.echo(json.dumps(wiki_status(settings["root"], state_dir=settings["state_dir"]), ensure_ascii=False, sort_keys=True))


@main.command("lint")
@click.pass_context
def lint(ctx: click.Context) -> None:
    settings = _settings(ctx)
    try:
        with WikiStore(settings["state"], read_only=True) as store:
            result = lint_revision(store)
    except (OSError, ValueError) as exc:
        raise click.ClickException(f"Wiki state unavailable: {exc}") from exc
    click.echo(json.dumps(result.to_dict(), ensure_ascii=False, sort_keys=True))
    if not result.passed:
        raise click.exceptions.Exit(1)


@main.command("query")
@click.option("--subject", multiple=True, required=True)
@click.option("--file", "candidate_file", default="")
@click.option("--fact-kind", default="unknown")
@click.option("--max-tokens", type=int, default=None)
@click.pass_context
def query(ctx: click.Context, subject: tuple[str, ...], candidate_file: str, fact_kind: str, max_tokens: Optional[int]) -> None:
    settings = _settings(ctx)
    selected_limit = max_tokens
    if selected_limit is not None and selected_limit < 256:
        raise click.UsageError("--max-tokens must be at least 256")
    result = wiki_query(
        settings["root"],
        subjects=list(subject),
        fact_kind=fact_kind,
        candidate_file=candidate_file,
        max_tokens=selected_limit,
        project_id=settings["project_id"],
        state_dir=settings["state_dir"],
        overrides=settings["overrides"],
        max_file_bytes=settings["max_file_bytes"],
        max_files=settings["max_files"],
        max_total_bytes=settings["max_total_bytes"],
    )
    click.echo(json.dumps(result, ensure_ascii=False, sort_keys=True))


@main.command("rollback")
@click.argument("revision_id")
@click.pass_context
def rollback(ctx: click.Context, revision_id: str) -> None:
    settings = _settings(ctx)
    with _lock(settings):
        with WikiStore(settings["state"]) as store:
            result = store.rollback(revision_id)
    click.echo(json.dumps(result, ensure_ascii=False, sort_keys=True))


if __name__ == "__main__":  # pragma: no cover
    main()
