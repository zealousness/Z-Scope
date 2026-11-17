"""Validate the single public configuration and explicitly migrate older YAML."""

from __future__ import annotations

from pathlib import Path
from copy import deepcopy
import json
import os
import tempfile
from typing import Any, Dict, List, Mapping, Tuple

import click
import yaml

from ..config.config import ConfigLoader
from ..config.support import (
    PUBLIC_CONFIG_VERSION,
    load_yaml_unique,
    _expand_env,
)
from ..config.v3 import DECLARED_ONLY, compose_effective_config, parse_user_config_v3
from ..config.semantics_migration import write_migrated_semantics


def _mapping(value: Any, path: str) -> Dict[str, Any]:
    if value is None:
        return {}
    if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
        raise ValueError(f"{path} must be a mapping with string keys")
    return dict(value)


def migrate_document(raw: Mapping[str, Any]) -> Tuple[Dict[str, Any], List[str]]:
    """One-way conversion; this function is never part of runtime loading."""
    version = raw.get("config_version")
    if type(version) is not int or version not in (2, 3):
        raise ValueError(
            "migration supports config_version: 2 or 3 only; for unversioned/older YAML "
            "generate a new file with zscope-init and review settings manually"
        )
    document = deepcopy(dict(raw))
    project = _mapping(document.get("project"), "project")
    project.pop("root", None)
    project.pop("source_root", None)
    warnings = ["YAML directory is the only project root; review the output before scanning"]
    scan = _mapping(document.get("scan"), "scan")
    if version == 3:
        # Historical v3 omitted preset meant deep for C/C++; materialize it
        # before the new shared fast default can change the existing intent.
        preset = scan.get("preset", "fast" if project.get("language") == "java" else "deep")
        scan["preset"] = {"quick": "fast", "overnight": "deep"}.get(preset, preset)
        document["project"], document["scan"] = project, scan
        warnings.append(
            "made the previous scan preset explicit (including the old omitted default)"
        )
        return document, warnings

    # Old structural names are rewritten only by this explicit command.
    # All other fields survive and are checked by the single v3 parser.
    if "targets" in project or "preset" in scan:
        raise ValueError(
            "v2 input mixes v3 targets/preset fields; review the document before migration"
        )
    target: Dict[str, Any] = {"id": "main"}
    if "compile_commands_path" in project:
        target["compile_commands"] = project.pop("compile_commands_path")
    elif project.get("language") == "c_cpp":
        target["compile_commands"] = "compile_commands.json"
        warnings.append(
            "project.compile_commands_path was omitted; retained the old automatic lookup location compile_commands.json; verify it before scanning"
        )
    project["targets"] = [target]
    project.setdefault("platform", "linux_user")
    # v2 discovery default was false; make it explicit so migration does not
    # silently expand an entry-restricted workload.
    discovery = _mapping(project.get("entry_discovery"), "project.entry_discovery")
    discovery.setdefault("enabled", False)
    project["entry_discovery"] = discovery
    scan["preset"] = scan.pop("depth", "fast")
    indexing = _mapping(document.get("indexing"), "indexing")
    if project.get("language") == "c_cpp":
        svf = _mapping(indexing.get("svf"), "indexing.svf")
        svf.setdefault("heap_limit_mb", 32768)
        indexing["svf"] = svf
    document.update(
        config_version=PUBLIC_CONFIG_VERSION, project=project, scan=scan, indexing=indexing
    )
    warnings.append(
        "converted depth to preset and compile_commands_path to targets; preserved v2 entry discovery and SVF defaults explicitly"
    )
    if project.get("language") == "c_cpp" and not project.get("semantics_file"):
        warnings.append(
            "C/C++ scanning requires project.semantics_file and primitive preparation; see README.md"
        )
    return document, warnings


@click.group()
def main() -> None:
    """Manage strict Z-SCOPE public configuration v3."""


@main.command("validate")
@click.option(
    "--config",
    "config_path",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    required=True,
)
def validate_command(config_path: Path) -> None:
    """Validate a v3 YAML file; document validity is distinct from execution."""
    _validate_v3_document(config_path)


def _validate_v3_document(config_path: Path) -> None:
    """Validate a v3 document through the formal model, then report execution separately.

    Parsing checks every declared target without composing the single-target
    execution chain, so a multi-target document is reported as a valid
    document whose execution is currently refused, never as silently first-target.
    """

    try:
        model = parse_user_config_v3(str(config_path))
    except Exception as exc:
        raise click.ClickException(str(exc)) from exc
    click.echo(
        "Valid config v3: "
        f"language={model.project.language} platform={model.project.platform} "
        f"targets={len(model.project.targets)} preset={model.scan.preset}"
    )
    click.echo(f"  preset mapping: {model.scan.mapping_note}")
    for target in model.project.targets:
        if target.compile_commands is not None:
            click.echo(f"  target {target.id}: {target.compile_commands}")
        else:
            click.echo(f"  target {target.id}: no compile database (Java)")
    declared_only = [note.field for note in model.wiring if note.state == DECLARED_ONLY]
    if declared_only:
        click.echo("Declared, not yet consumed: " + ", ".join(declared_only))
    try:
        effective = compose_effective_config(model)
    except ValueError as exc:
        click.echo(f"Execution: not startable — {exc}")
    else:
        click.echo(
            "Execution: composes into the current single-target chain "
            f"(depth={effective.scan.depth})."
        )
    click.echo(
        "Validation checks the document only; run 'zscope-config prepare' for "
        "read-only readiness without scanning."
    )


@main.command("prepare")
@click.option(
    "--config",
    "config_path",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    default=Path("zscope.yaml"),
    show_default=True,
)
@click.option(
    "--json", "as_json", is_flag=True, help="Return the same preparation data as the local WebUI."
)
def prepare_command(config_path: Path, as_json: bool) -> None:
    """Inspect project paths, build variants and local prerequisites without scanning."""
    import json
    from ..config.v3_preparation import prepare_saved_config

    try:
        payload = prepare_saved_config(str(config_path))
    except (OSError, ValueError, TypeError) as exc:
        raise click.ClickException(str(exc)) from exc
    if as_json:
        click.echo(json.dumps(payload, ensure_ascii=False, indent=2))
        return
    _echo_preparation(payload)


def _echo_preparation(payload: Dict[str, Any]) -> None:
    version3 = payload.get("version3")
    click.echo(f"配置：{payload['config_path']}")
    if version3 is not None:
        _echo_v3_preparation(payload, version3)
    else:
        click.echo(f"工程：{payload['project']['root']}")
        click.echo(f"语言/后端：{payload['project']['language']} / {payload['project']['backend']}")
        click.echo(f"编译数据库：{payload['build']['status']}；链接目标归属尚未核验")
        if "compilation_instances" in payload["build"]:
            click.echo(
                f"编译实例：{payload['build']['compilation_instances']}；"
                f"源文件：{payload['build']['sources']}"
            )
        click.echo(
            f"扫描深度：{payload['scan']['depth']}；自动复现：{payload['scan']['reproduction']}"
        )
        click.echo(f"产物：{payload['scan']['artifact_directory']}")
    for tool in payload["tools"]:
        click.echo(f"工具 {tool['name']}：{'已找到' if tool['available_on_path'] else '未找到'}")
    if version3 is not None:
        capability = version3["start_capability"]
        if capability["startable"]:
            click.echo("启动：当前配置可启动扫描")
        else:
            click.echo("启动：不可用")
            for reason in capability["reasons"]:
                click.echo(f"  - {reason['code']}：{reason['message']}")
    click.echo("仅检查本地配置和文件；模型连接、工具运行及扫描完整性尚未验证。")
    for message in payload["messages"]:
        click.echo(message["message"])


def _echo_v3_preparation(payload: Dict[str, Any], version3: Mapping[str, Any]) -> None:
    click.echo(
        f"工程（v3）：{version3['project_root']}"
        f"（语言/后端：{payload['project']['language']} / {payload['project']['backend']}；"
        f"平台：{version3['platform']}）"
    )
    targets = version3["targets"]
    for index, target in enumerate(targets, start=1):
        database = target["compile_commands"]
        if database is None:
            state = "不适用"
        else:
            state = "存在" if target["database_exists"] else "缺失"
        click.echo(
            f"目标 {index}/{len(targets)} {target['id']}："
            f"数据库 {database or '—'}（{state}）；构建：{target['build']['status']}"
        )
        for message in target["messages"]:
            click.echo(f"  - {message['message']}")
    semantics = version3.get("project_semantics") or {}
    if semantics.get("applicable"):
        click.echo(
            f"项目原语：{semantics.get('path') or '未配置'}；"
            f"{'已就绪' if semantics.get('ready') else '未就绪'}"
        )
        for reason in semantics.get("reasons", [])[:20]:
            message = reason.get("message") if isinstance(reason, Mapping) else str(reason)
            click.echo(f"  - {message}")
    preset = version3["preset"]
    click.echo(
        f"预设：{preset['preset']}（临时映射到内部深度 {preset['mapped_depth']}；"
        f"来源 {preset['depth_source']}）"
    )
    declared = version3["declared_not_consumed"]
    if declared:
        click.echo("已声明未消费（仅解析与展示）：" + "、".join(declared))
    execution = version3["execution"]
    if execution["resolved_stop_time"] is not None:
        click.echo(
            f"停止边界：{execution['timezone']} {execution['stop_at_local']} -> "
            f"{execution['resolved_stop_time']}（本轮一次；调度消费未接线）"
        )
    else:
        click.echo("停止边界：未配置")
    click.echo(f"产物：{payload['scan']['artifact_directory']}")


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
@click.option(
    "--legacy-working-directory",
    type=click.Path(exists=True, file_okay=False, path_type=Path),
    help="Original execution directory, required for a relative v2/legacy project.root.",
)
def migrate_command(
    input_path: Path, output_path: Path, force: bool, legacy_working_directory: Path | None
) -> None:
    """Convert a legacy YAML file without changing the source file."""

    destination = output_path.expanduser()
    if destination.resolve() == input_path.resolve():
        raise click.ClickException(
            "--output must differ from --input; migration never overwrites source"
        )
    if destination.exists() and not force:
        raise click.ClickException(f"refusing to overwrite existing file: {destination}")
    try:
        raw = load_yaml_unique(input_path.resolve())
        old_project = _mapping(raw.get("project"), "project")
        has_old_roots = any(key in old_project for key in ("root", "source_root"))
        version = raw.get("config_version")
        if has_old_roots or version not in (2, 3):
            root_value = old_project.get("root", ".")
            if not isinstance(root_value, str) or not root_value.strip():
                raise ValueError("legacy project.root must be a nonempty string")
            old_root = Path(_expand_env(root_value))
            if not old_root.is_absolute():
                if version == 3:
                    old_root = input_path.resolve().parent / old_root
                elif legacy_working_directory is not None:
                    old_root = legacy_working_directory.resolve() / old_root
                else:
                    raise ValueError(
                        "relative legacy/v2 project.root needs --legacy-working-directory ORIGINAL_CWD; its original root cannot be inferred safely"
                    )
            old_root = old_root.resolve()
            source_value = old_project.get("source_root", ".")
            if not isinstance(source_value, str) or not source_value.strip():
                raise ValueError("legacy project.source_root must be a nonempty string")
            old_source = Path(_expand_env(source_value))
            if not old_source.is_absolute():
                old_source = old_root / old_source
            if old_source.resolve() != old_root:
                raise ValueError(
                    "split project.root/source_root cannot migrate automatically; explicitly rebase include/exclude and discovery paths to one project directory first"
                )
        else:
            old_root = input_path.resolve().parent
        if destination.resolve().parent != old_root:
            raise ValueError(
                f"--output must be directly inside the original project directory: {old_root}; moving it elsewhere would change scan scope"
            )
        migrated, warnings = migrate_document(raw)
        text = yaml.safe_dump(migrated, allow_unicode=True, sort_keys=False)
        # Same formal schema as editor/init, preserving ${ENV} references.
        # Validate before touching an existing --force output.
        from ..config.editor import validate_document_text

        validate_document_text(text, config_dir=old_root, expand_environment=False)
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
    click.echo(f"Created config v{migrated['config_version']}: {destination}")
    for warning in warnings:
        click.echo(f"Warning: {warning}", err=True)


@main.command("review-semantics")
@click.option(
    "--config", "config_path", type=click.Path(path_type=Path, exists=True), default="zscope.yaml"
)
@click.option(
    "--complete",
    is_flag=True,
    help="Verify current discovery and record explicit human completion.",
)
@click.option(
    "--declare-none",
    is_flag=True,
    help="Explicitly declare no known custom primitives; discovery is still required.",
)
@click.option("--json", "as_json", is_flag=True)
def review_semantics_command(
    config_path: Path, complete: bool, declare_none: bool, as_json: bool
) -> None:
    from ..config.project_semantics import ProjectSemanticsStore
    from ..config.semantics_workflow import (
        workflow_status,
        complete_review,
        revision,
        save_document,
    )

    try:
        config = ConfigLoader.load(str(config_path), read_only=True)
        if config.project.language == "java":
            click.echo(
                '{"applicable": false, "ready": true}' if as_json else "Java：项目原语不适用。"
            )
            return
        path = config.project.semantics_file
        if path is None:
            raise ValueError("请先设置 project.semantics_file。")
        version = revision(path)
        document = ProjectSemanticsStore(path).read(allow_unbound_primitive_proposals=True)
        if declare_none:
            if any(
                row.get("primitive") and row.get("status") != "rejected"
                for row in document["interfaces"]
            ):
                raise ValueError("已有项目原语；请先审视这些声明，不能同时声明没有自定义原语。")
            document["discovery_receipt"]["declaration"] = "none_known"
            version = save_document(
                path, document, root=config.project.project_root, expected_revision=version
            )
        if complete:
            complete_review(
                path,
                root=config.project.project_root,
                config_path=config_path.resolve(),
                expected_revision=version,
            )
            document = ProjectSemanticsStore(path).read()
        status = workflow_status(document, config.project.project_root, config_path.resolve())
        click.echo(
            json.dumps(status, ensure_ascii=False, indent=2)
            if as_json
            else f"项目原语：{status['stage']}\n" + "\n".join(status["reasons"])
        )
    except (ValueError, OSError) as exc:
        raise click.ClickException(str(exc)) from exc


@main.command("migrate-semantics")
@click.option(
    "--config",
    "config_path",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    required=True,
)
@click.option(
    "--from-xlsx",
    "xlsx_path",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    required=True,
)
@click.option(
    "--output",
    "output_path",
    type=click.Path(dir_okay=False, path_type=Path),
    required=True,
)
def migrate_semantics_command(
    config_path: Path,
    xlsx_path: Path,
    output_path: Path,
) -> None:
    """Migrate XLSX semantics once, preserve it, and bind a v3 config to YAML."""

    config_path = config_path.resolve()
    project_root = config_path.parent
    destination = output_path if output_path.is_absolute() else project_root / output_path
    destination = destination.resolve()
    report_path = destination.with_suffix(".migration-report.json")
    try:
        destination.relative_to(project_root)
    except ValueError as exc:
        raise click.ClickException("--output must stay inside the project directory") from exc
    if destination.exists():
        raise click.ClickException(f"refusing to overwrite existing file: {destination}")
    if report_path.exists():
        raise click.ClickException(f"refusing to overwrite existing report: {report_path}")
    try:
        raw = load_yaml_unique(config_path)
        if raw.get("config_version") != PUBLIC_CONFIG_VERSION:
            raise ValueError("migrate-semantics requires a public config v3 document")
        project = _mapping(raw.get("project"), "project")
        if project.get("language") not in {"cpp", "c", "c_cpp"}:
            raise ValueError("migrate-semantics is available only for C/C++ projects")
        if project.get("semantics_file"):
            raise ValueError("project.semantics_file is already configured")
        report = write_migrated_semantics(xlsx_path.resolve(), destination)
        report_path.write_text(
            json.dumps(report, ensure_ascii=False, indent=2, default=str) + "\n",
            encoding="utf-8",
        )

        # Preserve comments and ordering while changing the only public config
        # field owned by this migration.
        from ruamel.yaml import YAML  # type: ignore[import-untyped]

        yaml_rt = YAML()
        yaml_rt.preserve_quotes = True
        with config_path.open("r", encoding="utf-8") as handle:
            editable = yaml_rt.load(handle)
        editable["project"]["semantics_file"] = destination.relative_to(project_root).as_posix()
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".{config_path.name}.", suffix=".tmp", dir=str(project_root)
        )
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
                yaml_rt.dump(editable, handle)
                handle.flush()
                os.fsync(handle.fileno())
            # Validate the exact bytes before publishing them.
            parse_user_config_v3(temporary_name)
            os.replace(temporary_name, config_path)
        finally:
            if os.path.exists(temporary_name):
                os.unlink(temporary_name)
    except Exception as exc:
        # The destination did not exist before this command, so this removes
        # only a partially-created migration output.  The XLSX is never touched.
        if destination.exists():
            destination.unlink()
        if report_path.exists():
            report_path.unlink()
        raise click.ClickException(str(exc)) from exc
    click.echo(f"Created project semantics: {destination}")
    click.echo(f"Updated config reference: {config_path}")
    click.echo(f"Migration report: {report_path}")
    click.echo(
        "Run --discover-primitives to resolve current native identities, then review every pending row."
    )


if __name__ == "__main__":
    main()
