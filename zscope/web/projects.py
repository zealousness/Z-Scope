"""Machine-local project picker; each HTTP request stays bound to one YAML."""

from __future__ import annotations

import hashlib
import json
import os
import sys
import threading
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

import yaml

from ..config.config import ConfigLoader, ProjectConfig
from ..config.editor import validate_document_file
from ..config.v2 import load_yaml_unique
from . import services
from .acceptance_service import AcceptanceReviewService
from .scan_jobs_service import ScanJobsHttpService
from ..orchestration.scan_request import ScanRequestService


class ProjectContext:
    """A captured bundle, never rebound while another request is using it."""

    def __init__(self, path: Path, scan_depth: str | None = None):
        from ..config.user_config_store import UserConfigStore
        from ..snapshots.store import SnapshotStore

        # An already registered project's controls must remain reachable even
        # after a bad edit; start/resume still pass the full execution parser.
        try:
            validate_document_file(path, expand_environment=False)
            raw = load_yaml_unique(path)
        except (ValueError, TypeError, KeyError):
            raw = {}
        project = ProjectConfig(
            project_root=path.parent, language=raw.get("project", {}).get("language", "c_cpp")
        )
        store = snapshots = config = None
        # Multi-target documents remain editable without choosing the first target.
        multi = raw.get("config_version") == 3 and len(raw["project"].get("targets", [])) != 1
        if raw and not multi:
            try:
                config = ConfigLoader.load(str(path), read_only=True, scan_depth=scan_depth)
            except (ValueError, TypeError, KeyError):
                config = None
            if config is not None:
                project = config.project
                store = UserConfigStore(
                    Path(config.analysis.user_config_db or config.analysis.snapshot_dir)
                )
                snapshots = SnapshotStore.from_config(config)
        feedback = services.ReportFeedbackService(
            store,
            snapshots,
            project_config=project,
            report_filename=str(path.parent / "zscope_batch_report.json"),
        )
        self._config_service = services.ConfigService(path, scan_depth=scan_depth)
        self._rule_service = services.RuleService(path)
        self._wiki_control_service = services.WikiControlService(path)
        self._workbook_service = services.WorkbookService(store)
        self._user_config_service = services.UserConfigService(store)

        def create_index():
            from ..retrieval.code_index import CodeIndex

            # Constructing an index can launch tools. Only the explicit build
            # action may do this; selecting a project and status reads may not.
            current = ConfigLoader.load(str(path), read_only=True, scan_depth=scan_depth)
            return CodeIndex(
                current.project.project_root,
                current.project.compile_commands_path,
                source_root=current.project.project_root,
                indexing_config=current.indexing,
                include_paths=current.project.include_paths,
                exclude_paths=current.project.exclude_paths,
                wait_for_cpg=False,
                svf_parallel_workers=current.concurrency.svf_workers
                or current.concurrency.index_workers,
            )

        self._cpg_service = services.CpgService(project_config=project, index_factory=create_index)
        self._source_snippet_service = services.SourceSnippetService(project)
        self._report_feedback_service = feedback
        self._scan_request_service = ScanRequestService(path, default_scan_depth=scan_depth)
        self._acceptance_review_service = AcceptanceReviewService(feedback, path)
        self._scan_jobs_http_service = ScanJobsHttpService(path, feedback)
        from .semantics_service import SemanticsService

        self._semantics_service = SemanticsService(path)
        self._worker: Any = None
        self._worker_config = config

    def activate(self) -> None:
        config = self._worker_config
        review = getattr(self._report_feedback_service.project_config, "review_memory", None)
        store = self._report_feedback_service.review_memory_store
        if (
            config is not None
            and review is not None
            and review.mode in {"extract", "active"}
            and review.extraction == "auto_extract"
            and store is not None
        ):
            from ..review_memory.worker import ReviewMemoryWorker
            from ..cli.review_memory import _llm_client

            self._worker = ReviewMemoryWorker(
                store,
                llm_client_factory=lambda: _llm_client(config),
                llm_enabled=review.llm_enabled,
            )
            self._worker.start()

    def close(self) -> None:
        if self._worker is not None:
            self._worker.stop()
        self._cpg_service.close()


class ProjectLibrary:
    """Remember paths only; credentials and report authority stay in each project."""

    def __init__(self, registry: Path | None = None, *, scan_depth: str | None = None):
        self.registry = registry or Path.home() / ".zscope" / "web" / "projects.json"
        self.scan_depth = scan_depth
        self.initial_project_id = ""
        self._lock = threading.RLock()
        self._contexts: dict[str, tuple[str, ProjectContext]] = {}

    @staticmethod
    def project_id(path: Path) -> str:
        return hashlib.sha256(os.path.normcase(str(path.resolve())).encode()).hexdigest()[:24]

    def _read(self) -> list[dict[str, str]]:
        if not self.registry.exists():
            return []
        data = json.loads(self.registry.read_text(encoding="utf-8"))
        if (
            not isinstance(data, dict)
            or data.get("schema") != "zscope.web-projects.v1"
            or not isinstance(data.get("projects"), list)
        ):
            raise ValueError("项目列表格式无效，请检查用户目录中的 projects.json")
        rows = []
        for row in data["projects"]:
            if isinstance(row, dict) and isinstance(row.get("config_path"), str):
                path = Path(row["config_path"])
                if path.is_absolute():
                    rows.append(
                        {
                            "project_id": self.project_id(path),
                            "config_path": str(path),
                            "last_opened": str(row.get("last_opened", "")),
                        }
                    )
        return rows[:100]

    def _remember(self, path: Path) -> dict[str, str]:
        row = {
            "project_id": self.project_id(path),
            "config_path": str(path),
            "last_opened": datetime.now(timezone.utc).isoformat(),
        }
        with self._lock, self._registry_lock():
            rows = [row] + [r for r in self._read() if r["project_id"] != row["project_id"]]
            self.registry.parent.mkdir(parents=True, exist_ok=True)
            temporary = self.registry.with_name(
                f".projects-{os.getpid()}-{threading.get_ident()}.tmp"
            )
            try:
                temporary.write_text(
                    json.dumps(
                        {"schema": "zscope.web-projects.v1", "projects": rows[:100]},
                        ensure_ascii=False,
                        indent=2,
                    ),
                    encoding="utf-8",
                )
                temporary.chmod(0o600)
                os.replace(temporary, self.registry)
            finally:
                temporary.unlink(missing_ok=True)
        return row

    @contextmanager
    def _registry_lock(self) -> Iterator[None]:
        """Serialize read/modify/replace across independent --web processes."""
        self.registry.parent.mkdir(parents=True, exist_ok=True)
        with self.registry.with_suffix(".lock").open("a+b") as handle:
            if sys.platform == "win32":
                import msvcrt

                if handle.tell() == 0:
                    handle.write(b"\0")
                    handle.flush()
                handle.seek(0)
                msvcrt.locking(handle.fileno(), msvcrt.LK_LOCK, 1)
                try:
                    yield
                finally:
                    handle.seek(0)
                    msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                import fcntl

                fcntl.flock(handle, fcntl.LOCK_EX)
                try:
                    yield
                finally:
                    fcntl.flock(handle, fcntl.LOCK_UN)

    def list(self) -> dict[str, Any]:
        with self._lock:
            rows = self._read()
        return {
            "schema": "zscope.web-projects.v1",
            "enabled": True,
            "initial_project_id": self.initial_project_id,
            "home": str(Path.home()),
            "registry_path": str(self.registry),
            "projects": [
                {
                    **r,
                    "name": Path(r["config_path"]).parent.name,
                    "root": str(Path(r["config_path"]).parent),
                    "available": Path(r["config_path"]).is_file(),
                }
                for r in rows
            ],
        }

    def browse(self, raw: str = "") -> dict[str, Any]:
        path = Path(raw).expanduser() if raw else Path.home()
        if not path.is_absolute():
            raise ValueError("请输入执行机器上的绝对路径")
        path = path.resolve(strict=True)
        if not path.is_dir():
            raise ValueError("请选择目录；已有 YAML 可直接通过路径打开")
        entries = []
        for child in path.iterdir():
            try:
                if child.is_dir() or (
                    child.is_file() and child.suffix.lower() in {".yaml", ".yml"}
                ):
                    entries.append(
                        {
                            "name": child.name,
                            "path": str(child),
                            "kind": "directory" if child.is_dir() else "yaml",
                        }
                    )
            except OSError:
                continue
        entries.sort(key=lambda item: (item["kind"] != "directory", item["name"].casefold()))
        return {
            "path": str(path),
            "parent": str(path.parent),
            "entries": entries[:300],
            "truncated": len(entries) > 300,
            "has_yaml": any(item["kind"] == "yaml" for item in entries),
        }

    def open(self, raw: str) -> dict[str, Any]:
        if not isinstance(raw, str) or not raw.strip():
            raise ValueError("请选择 YAML 文件")
        path = Path(raw).expanduser()
        if not path.is_absolute():
            raise ValueError("配置路径必须是执行机器上的绝对路径")
        path = path.resolve(strict=True)
        if path.is_dir():
            path = (path / "zscope.yaml").resolve(strict=True)
        if not path.is_file() or path.suffix.lower() not in {".yaml", ".yml"}:
            raise ValueError("未找到 YAML 配置；请选择工程目录并使用创建向导")
        validate_document_file(path, expand_environment=False)
        row = self._remember(path)
        return {
            "success": True,
            "project": {**row, "root": str(path.parent), "name": path.parent.name},
        }

    def context(self, project_id: str) -> ProjectContext:
        with self._lock:
            row = next((r for r in self._read() if r["project_id"] == project_id), None)
            if row is None:
                raise ValueError("请先选择项目；请求不会自动绑定另一工程")
            path = Path(row["config_path"])
            # A symlink retarget cannot silently switch an existing project ID.
            if self.project_id(path) != project_id:
                raise ValueError("配置路径目标已变化，请重新选择项目")
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            cached = self._contexts.get(project_id)
            if cached is None or cached[0] != digest:
                replacement = ProjectContext(path, self.scan_depth)
                if (
                    path.resolve() != path
                    or hashlib.sha256(path.read_bytes()).hexdigest() != digest
                ):
                    replacement.close()
                    raise ValueError("配置在加载期间变化，请重新打开项目")
                if cached is not None:
                    cached[1].close()
                replacement.activate()
                cached = (digest, replacement)
                self._contexts[project_id] = cached
            return cached[1]

    def close(self) -> None:
        with self._lock:
            for _, context in self._contexts.values():
                context.close()
            self._contexts.clear()

    def create(self, payload: dict[str, Any]) -> dict[str, Any]:
        from ..cli.init import render_project_config

        allowed = {
            "directory",
            "filename",
            "language",
            "target_id",
            "compile_commands",
            "preset",
            "base_url",
            "model",
            "api_key",
        }
        if set(payload) - allowed:
            raise ValueError("创建请求包含不支持的字段")
        directory = Path(str(payload.get("directory", ""))).expanduser()
        if not directory.is_absolute() or not directory.is_dir():
            raise ValueError("请选择执行机器上已存在的工程目录")
        directory = directory.resolve()
        directory_identity = directory.stat()
        name = str(payload.get("filename", "zscope.yaml"))
        if (
            Path(name).name != name
            or "/" in name
            or "\\" in name
            or Path(name).suffix.lower() not in {".yaml", ".yml"}
        ):
            raise ValueError("配置文件名必须是当前目录中的 .yaml 或 .yml 文件")
        path = directory / name
        if path.exists():
            raise ValueError("配置文件已存在，请打开它；创建向导不会覆盖已有文件")
        language = str(payload.get("language", "c_cpp"))
        compile_commands = str(payload.get("compile_commands", "")).strip()
        if compile_commands and (
            Path(compile_commands).is_absolute() or ".." in Path(compile_commands).parts
        ):
            raise ValueError("编译数据库请填写相对 YAML 目录的工程内路径")
        content = render_project_config(
            directory,
            language=language,
            target_id=str(payload.get("target_id", "main")),
            compile_commands=compile_commands or None,
            preset=payload.get("preset"),
        )
        document = yaml.safe_load(content)
        profile = document["llms"]["default"]
        for field_name, target in (
            ("base_url", "base_urls"),
            ("model", "models"),
            ("api_key", "api_key"),
        ):
            value = payload.get(field_name)
            if value is not None and not isinstance(value, str):
                raise ValueError(f"{field_name} 必须是文本")
            if value and value.strip():
                profile[target] = [value.strip()] if target != "api_key" else value.strip()
        content = "# 本 YAML 所在目录就是工程根；项目内路径请使用相对路径。\n" + yaml.safe_dump(
            document, allow_unicode=True, sort_keys=False
        )
        from ..config.v3 import parse_user_config_v3_document

        parse_user_config_v3_document(path, document)
        from ..config.project_semantics import render_empty_project_semantics

        payloads = [(name, content)]
        if language == "c_cpp":
            if name == "zscope.semantics.yaml" or (directory / "zscope.semantics.yaml").exists():
                raise ValueError("语义文档已存在；创建向导不会覆盖它，请打开已有工程或选择其他目录。")
            payloads.append(("zscope.semantics.yaml", render_empty_project_semantics()))
        current_identity = directory.stat()
        if directory.resolve() != directory or (
            current_identity.st_dev,
            current_identity.st_ino,
        ) != (directory_identity.st_dev, directory_identity.st_ino):
            raise ValueError("工程目录在创建期间变化，请重新选择目录")
        # Exclusive creation prevents two tabs from replacing one another's config.
        directory_fd = (
            os.open(directory, os.O_RDONLY | os.O_DIRECTORY) if hasattr(os, "O_DIRECTORY") else None
        )
        published = []
        try:
            if directory_fd is not None:
                pinned = os.fstat(directory_fd)
                if (pinned.st_dev, pinned.st_ino) != (
                    directory_identity.st_dev,
                    directory_identity.st_ino,
                ):
                    raise ValueError("工程目录在创建期间变化，请重新选择目录")
            for filename, text in payloads:
                descriptor = os.open(
                    filename if directory_fd is not None else directory / filename,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600, dir_fd=directory_fd,
                )
                published.append(filename)
                with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
                    handle.write(text)
                    handle.flush()
                    os.fsync(handle.fileno())
        except Exception:
            for filename in reversed(published):
                os.unlink(filename if directory_fd is not None else directory / filename, dir_fd=directory_fd)
            raise
        finally:
            if directory_fd is not None:
                os.close(directory_fd)
        return self.open(str(path))
