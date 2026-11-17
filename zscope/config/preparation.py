"""Read-only project preparation shared by CLI and the local dashboard."""

from __future__ import annotations

from collections import Counter
import json
from pathlib import Path
import shutil
import sys
from typing import Any

from ..common.portable import default_tool
from ..retrieval.indexing_identity import command_arguments, digest_json, source_path


def prepare_project(config: Any, config_path: Path) -> dict[str, Any]:
    root = Path(config.project.project_root).resolve()
    messages: list[dict[str, str]] = []
    if not root.is_dir():
        messages.append(
            {"code": "project_missing", "message": "工程目录不存在，请检查所选 YAML 的所在目录。"}
        )
    build: dict[str, Any] = {"status": "not_applicable", "link_targets": "unverified"}
    if config.project.language == "c_cpp":
        database = config.project.compile_commands_path
        path = Path(database) if database else root / "compile_commands.json"
        path = (path if path.is_absolute() else root / path).resolve()
        build = {"status": "missing", "path": str(path), "link_targets": "unverified"}
        if path.is_file():
            try:
                if path.stat().st_size > 128 * 1024 * 1024:
                    raise ValueError("编译数据库超过准备视图的 128 MiB 读取范围")
                rows = json.loads(path.read_text(encoding="utf-8"))
                if not isinstance(rows, list):
                    raise ValueError("编译数据库必须是 JSON 数组")
                commands: set[str] = set()
                sources: Counter[str] = Counter()
                invalid = 0
                for row in rows:
                    if (
                        not isinstance(row, dict)
                        or not row.get("file")
                        or not command_arguments(row)
                    ):
                        invalid += 1
                        continue
                    source = str(source_path(row, path.parent))
                    directory = Path(str(row.get("directory") or path.parent))
                    directory = (
                        directory if directory.is_absolute() else path.parent / directory
                    ).resolve()
                    identity = digest_json(
                        {
                            "source": source,
                            "directory": str(directory),
                            "arguments": command_arguments(row),
                        }
                    )
                    if identity not in commands:
                        commands.add(identity)
                        sources[source] += 1
                variants = {source: count for source, count in sources.items() if count > 1}
                build.update(
                    status="available" if commands and not invalid else "partial",
                    rows=len(rows),
                    compilation_instances=len(commands),
                    sources=len(sources),
                    invalid_rows=invalid,
                    variant_sources=variants,
                )
                if variants:
                    messages.append(
                        {
                            "code": "multiple_compile_variants",
                            "message": "发现同源多个编译变体；当前扫描覆盖仍需按实例核对。",
                        }
                    )
                if invalid or not commands:
                    messages.append(
                        {
                            "code": "compile_commands_incomplete",
                            "message": "编译数据库存在无效记录或没有有效命令，请检查生成结果。",
                        }
                    )
            except (OSError, ValueError, TypeError, KeyError) as exc:
                build.update(status="invalid", reason=str(exc))
                messages.append(
                    {
                        "code": "compile_commands_invalid",
                        "message": "无法读取编译数据库，请重新导出有效 JSON。",
                    }
                )
        else:
            messages.append(
                {
                    "code": "compile_commands_missing",
                    "message": "尚无编译数据库；CMake 工程可配置 -DCMAKE_EXPORT_COMPILE_COMMANDS=ON，并核对 project.targets[].compile_commands。",
                }
            )
    backend = str(config.indexing.backend)
    tools = []
    names = []
    if config.project.language == "c_cpp" and backend in {"clang", "unified"}:
        names = [("clangd", "clangd_path"), ("zscope-clang-indexer", "clang_indexer_path")]
        if backend == "unified":
            names.extend(
                [
                    ("gclang", "gclang_path"),
                    ("get-bc", "get_bc_path"),
                    ("llvm-link", "llvm_link_path"),
                    ("wpa", ""),
                    ("saber", ""),
                ]
            )
    for name, attribute in names:
        explicit = str(getattr(config.indexing, attribute, "") or "") if attribute else ""
        if name in {"wpa", "saber"} and getattr(config.indexing, "svf_bin_dir", None):
            explicit = str(Path(config.indexing.svf_bin_dir) / name)
        configured = explicit or default_tool(name)
        tools.append({"name": name, "available_on_path": bool(shutil.which(configured))})
    if sys.platform != "linux" and config.project.language == "c_cpp":
        messages.append(
            {
                "code": "linux_execution_required",
                "message": "C/C++ 扫描和运行验证应在 Linux/WSL 执行；当前工具检查仅反映此服务所在环境。",
            }
        )
    semantics: dict[str, Any] = {"applicable": False, "ready": True}
    if config.project.language == "c_cpp":
        from .project_semantics import ProjectSemanticsStore
        from .semantics_workflow import workflow_status

        try:
            if not config.project.semantics_file:
                raise ValueError("请设置 project.semantics_file 并完成原语引导。")
            semantics = {"applicable": True, **workflow_status(
                ProjectSemanticsStore(config.project.semantics_file).read(allow_unbound_primitive_proposals=True), root, config_path
            )}
        except (OSError, ValueError) as exc:
            semantics = {"applicable": True, "ready": False, "stage": "needs_discovery", "reasons": [str(exc)]}
        if not semantics["ready"]:
            messages.append({"code": "project_semantics_not_ready", "message": "项目原语未就绪：" + "; ".join(semantics.get("reasons", []) or ["请完成发现与人工审阅。"] )})
    return {
        "schema": "zscope.project-preparation.v1",
        "config_path": str(config_path.resolve()),
        "working_directory": str(Path.cwd()),
        "project": {
            "root": str(root),
            "language": config.project.language,
            "backend": backend,
        },
        "build": build,
        "tools": tools,
        "tool_check": "executable_presence_only",
        "models": [
            {
                "profile": name,
                "configured": bool(profile.models and profile.base_urls),
                "connection_checked": False,
            }
            for name, profile in sorted(config.llms.items())
        ],
        "scan": {
            "depth": config.scan.depth,
            "focus": config.scan.task or "全部适用检查（含内存、资源与并发）",
            "entry": str(config.project.entry_function or ""),
            "entry_discovery": bool(config.project.entry_discovery.enabled),
            "reproduction": str(config.analysis.dynamic_reproduction_mode),
            "artifact_directory": str(Path(config.analysis.snapshot_dir).resolve()),
        },
        "messages": messages,
        "read_only": True,
        "project_semantics": semantics,
    }
