"""Shared project-semantics onboarding, currentness and atomic human edits.

The YAML remains the sole human authority. Task databases never authorize a
contract; even an empty discovery needs a current receipt and explicit review.
"""

from __future__ import annotations

from contextlib import contextmanager
from copy import deepcopy
import json
import os
from pathlib import Path
import shutil
import sys
import threading
import time
from typing import Any, Iterator, Mapping

from .project_semantics import (
    ProjectSemanticsError,
    ProjectSemanticsStore,
    canonical_digest,
    file_sha256,
    semantics_readiness,
    validate_project_semantics,
    _yaml_round_trip_dump,
)

WORKFLOW_SCHEMA = "zscope.semantics-workflow.v1"
COLLECTIONS = ("interfaces", "dispatchers", "function_pointer_bindings")
_locks: dict[str, threading.RLock] = {}
_local = threading.local()


class SemanticsConflict(ProjectSemanticsError):
    pass


def revision(path: Path) -> str:
    return file_sha256(path) if path.is_file() else "missing"


@contextmanager
def project_activity(root: Path, *, wait_seconds: float = 0) -> Iterator[None]:
    """One project writer/scanner across CLI, HTTP and detached processes."""
    key = str(Path(root).resolve())
    held: set[str] = getattr(_local, "held", set())
    if key in held:
        yield
        return
    lock = _locks.setdefault(key, threading.RLock())
    if not lock.acquire(timeout=max(0, wait_seconds)):
        raise SemanticsConflict("工程正在执行扫描或原语任务，请完成或停止该任务后再发布修改。")
    try:
        directory = Path(root) / ".zscope_snapshots" / "semantics"
        if not directory.resolve().is_relative_to(Path(root).resolve()):
            raise SemanticsConflict("工程状态目录不能通过符号链接指向工程外。")
        directory.mkdir(parents=True, exist_ok=True)
        with (directory / "activity.lock").open("a+b") as handle:
            if sys.platform != "linux":
                raise SemanticsConflict("项目原语任务需要 Linux/WSL 后台。")
            import fcntl

            deadline = time.monotonic() + wait_seconds
            while True:
                try:
                    fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except BlockingIOError as exc:
                    if time.monotonic() >= deadline:
                        raise SemanticsConflict("工程正在执行扫描或原语任务，请稍后重试。") from exc
                    time.sleep(0.01)
            _local.held = held | {key}
            try:
                yield
            finally:
                _local.held = held
                fcntl.flock(handle, fcntl.LOCK_UN)
    finally:
        lock.release()


def roots_digest(document: Mapping[str, Any]) -> str:
    """Reviewing a rebound root must not require discovery forever."""
    rows = []
    for row in document.get("interfaces", []):
        if row.get("primitive") and row.get("status") != "rejected":
            rows.append(
                {
                    key: deepcopy(row.get(key))
                    for key in (
                        "id",
                        "selector",
                        "basis",
                        "effects",
                        "cases",
                        "otherwise",
                        "pairs",
                        "derived_from",
                    )
                }
            )
    return canonical_digest(sorted(rows, key=lambda row: row["id"]))


def decisions_digest(document: Mapping[str, Any]) -> str:
    return canonical_digest({key: document.get(key, []) for key in COLLECTIONS})


def project_inputs(root: Path, config_path: Path | None = None) -> dict[str, Any]:
    """Content hashes, not mtime, include newly added source/header files."""
    from ..semantics.contracts import CONTRACT_COMPILER_VERSION
    from ..semantics.c_linux_catalog import CATALOG_VERSION

    files = {}
    for directory, names, filenames in os.walk(root, followlinks=False):
        names[:] = sorted(
            name
            for name in names
            if not name.startswith(".") and name not in {"__pycache__", "node_modules"}
        )
        for name in sorted(filenames):
            path = Path(directory) / name
            if (
                path.suffix.lower()
                in {".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp", ".hxx", ".inc"}
                or name == "compile_commands.json"
            ):
                files[path.relative_to(root).as_posix()] = revision(path)
    config = {}
    if config_path is not None:
        from .v2 import load_yaml_unique

        raw = load_yaml_unique(config_path)
        config = {
            "project": raw.get("project"),
            "indexing": raw.get("indexing"),
            "rules": raw.get("rules"),
        }
        for target in (raw.get("project") or {}).get("targets", []):
            if target.get("compile_commands"):
                database = (root / target["compile_commands"]).resolve()
                files[str(database)] = revision(database)
    return {
        "files": files,
        "configuration": config,
        "compiler": CONTRACT_COMPILER_VERSION,
        "catalog": CATALOG_VERSION,
    }


def discovery_snapshot(config: Any, index: Any, document: Mapping[str, Any]) -> dict[str, Any]:
    root = Path(config.project.project_root)
    configured_path = getattr(config, "config_path", None)
    path = Path(configured_path) if configured_path else None
    contexts = list(index.get_build_contexts() or [])
    from ..retrieval.build_context import context_input_status
    from ..orchestration.instance_semantics_context import _native_inputs_current

    if not contexts or any(
        context_input_status(context) != "current" or not _native_inputs_current(context)
        for context in contexts
    ):
        raise ProjectSemanticsError("native 编译实例尚未完整或已失效，请重新准备接口目录。")
    tool = getattr(config.indexing, "clang_indexer_path", "")
    from ..common.portable import default_tool

    executable = shutil.which(str(tool or default_tool("zscope-clang-indexer")))
    return {
        "schema": WORKFLOW_SCHEMA,
        "inputs": project_inputs(root, path),
        "contexts": contexts,
        "lookup_inputs": {
            str(context.get("build_context_id")): _lookup_inputs_digest(context)
            for context in contexts
        },
        "roots_digest": roots_digest(document),
        "native_tool": {
            "path": executable,
            "sha256": revision(Path(executable)) if executable else None,
        },
    }


def _lookup_inputs_digest(context: Mapping[str, Any]) -> str | None:
    """Bind all possible native lookup names, including absent candidates.

    A report or queue added after discovery is not a compiler input. Only a
    complete ordinary-lookup receipt can narrow the full directory census;
    unsupported lookup modes retain the original conservative invalidation.
    Reuse the scanner's strict lookup verifier, never a suffix/output allowlist.
    """
    from ..retrieval.indexing_identity import _lookup_path_state, _runtime_lookup_candidates

    try:
        candidates = _runtime_lookup_candidates(context)
        return canonical_digest(
            {str(path): _lookup_path_state(path) for path in sorted(candidates)}
        )
    except (OSError, ValueError, KeyError, TypeError):
        return None


def _discovery_context_current(context: Mapping[str, Any], lookups: Mapping[str, Any]) -> bool:
    from ..retrieval.build_context import context_input_status
    from ..retrieval.indexing_identity import include_probes_current
    from ..orchestration.instance_semantics_context import _native_inputs_current

    if not _native_inputs_current(context):
        return False
    status = context_input_status(context)
    if status == "current":
        return True
    expected = lookups.get(str(context.get("build_context_id")))
    return bool(
        status == "stale_include_search"
        and expected
        and expected == _lookup_inputs_digest(context)
        and include_probes_current(context.get("include_probes"), context.get("include_lookups"))
    )


def evidence_payload(root: Path, reference: str) -> dict[str, Any]:
    name = reference.split("#", 1)[0]
    path = (root / name).resolve()
    directory = (root / ".zscope_snapshots" / "semantics").resolve()
    if (
        not directory.is_relative_to(root.resolve())
        or not name
        or not path.is_relative_to(directory)
        or path.suffix != ".json"
    ):
        raise ProjectSemanticsError("证据引用不属于当前工程。")
    payload = json.loads(path.read_text(encoding="utf-8"))
    if path.name.startswith("discovery-") and path.stem != "discovery-" + canonical_digest(payload):
        raise ProjectSemanticsError("发现证据摘要不匹配，请重新发现。")
    if not isinstance(payload, dict):
        raise ProjectSemanticsError("发现证据必须是对象。")
    return dict(payload)


def discovery_current(
    document: Mapping[str, Any], root: Path, config_path: Path | None = None
) -> tuple[bool, str]:
    receipt = document.get("discovery_receipt") or {}
    try:
        evidence = evidence_payload(root, str(receipt.get("evidence_ref") or ""))
        snapshot = evidence.get("receipt", {}).get("workflow")
        # Legacy receipts can be adopted only when they actually contain the
        # same verifiable inputs, never on timestamp or confirmed count alone.
        if not isinstance(snapshot, dict) or snapshot.get("schema") != WORKFLOW_SCHEMA:
            return False, "缺少可核验的发现输入收据，请重新发现。"
        if receipt.get("workflow_digest") != canonical_digest(snapshot):
            return False, "发现收据与机器证据版本不一致，请重新发现。"
        if (receipt.get("blocking_coverage_gaps") or []) != (
            evidence.get("receipt", {}).get("blocking_coverage_gaps") or []
        ):
            return False, "阻塞性缺口与发现证据不一致，请重新发现。"
        if snapshot.get("inputs") != project_inputs(root, config_path):
            return False, "源码、构建配置或契约版本已变化，请重新发现。"
        if snapshot.get("roots_digest") != roots_digest(document):
            return False, "项目原语规格已变化，请重新发现。"
        contexts = snapshot.get("contexts", [])
        if not contexts or any(
            not _discovery_context_current(context, snapshot.get("lookup_inputs") or {})
            for context in contexts
        ):
            return False, "native 依赖或编译实例已失效，请重新发现。"
        tool = snapshot.get("native_tool") or {}
        if tool.get("path") and revision(Path(tool["path"])) != tool.get("sha256"):
            return False, "native 工具已变化，请重新发现。"
        return True, ""
    except (OSError, ValueError, KeyError, TypeError) as exc:
        return False, f"发现证据不可核验：{exc}"


def workflow_status(
    document: Mapping[str, Any], root: Path, config_path: Path | None = None
) -> dict[str, Any]:
    receipt = document.get("discovery_receipt") or {}
    declared = bool(receipt.get("declaration")) or any(
        row.get("primitive") for row in document.get("interfaces", [])
    )
    current, reason = discovery_current(document, root, config_path)
    try:
        checks = semantics_readiness(document, project_root=root)
        row_ready, reasons = checks.ready, list(checks.reasons)
    except ValueError as exc:
        row_ready, reasons = False, [str(exc)]
    review = receipt.get("human_review") or {}
    reviewed = review.get("decisions_digest") == decisions_digest(document) and review.get(
        "evidence_ref"
    ) == receipt.get("evidence_ref")
    stage = (
        "undeclared"
        if not declared
        else (
            "needs_discovery"
            if not current
            else "ready" if row_ready and reviewed else "needs_review"
        )
    )
    if declared and not current and receipt.get("evidence_ref"):
        stage = "needs_rediscovery"
    active = False
    if config_path is not None:
        from ..orchestration.primitive_tasks import PrimitiveTasks

        active = PrimitiveTasks(config_path).has_active()
        if active:
            stage = "discovering"
            reasons.insert(0, "原语准备任务正在执行，请等待完成或取消后再发布语义或启动扫描。")
    return {
        "schema": WORKFLOW_SCHEMA,
        "stage": stage,
        "ready": stage == "ready",
        "discovery_current": current,
        "review_complete": reviewed and current,
        "reasons": ([reason] if reason else []) + reasons,
        "coverage_gap_count": receipt.get("coverage_gap_count"),
        "can_complete": declared and current and row_ready and not active,
        "declaration": receipt.get("declaration") or ("custom" if declared else None),
    }


def require_workflow(config: Any) -> None:
    if config.project.language == "java":
        return
    path = config.project.semantics_file
    if not path:
        raise ProjectSemanticsError("请先配置 project.semantics_file 并完成项目原语引导。")
    document = ProjectSemanticsStore(path).read(allow_unbound_primitive_proposals=True)
    config_path = getattr(config, "config_path", None)
    status = workflow_status(
        document, config.project.project_root, Path(config_path) if config_path else None
    )
    if not status["ready"]:
        raise ProjectSemanticsError(
            "项目原语尚未就绪（"
            + status["stage"]
            + "）："
            + "; ".join(status["reasons"][:8])
            + "；请运行 --discover-primitives 并完成 review-semantics。"
        )


def save_document(
    path: Path,
    document: Mapping[str, Any],
    *,
    expected_revision: str,
    root: Path,
    allow_proposals: bool = True,
) -> str:
    with project_activity(root):
        if revision(path) != expected_revision:
            raise SemanticsConflict("语义文档已被其他操作更新。草稿已保留，请重新载入并比较。")
        validated = validate_project_semantics(
            document, allow_unbound_primitive_proposals=allow_proposals
        )
        _yaml_round_trip_dump(path, validated)
        return revision(path)


def complete_review(
    path: Path, *, root: Path, config_path: Path | None, expected_revision: str
) -> str:
    with project_activity(root):
        document = ProjectSemanticsStore(path).read()
        status = workflow_status(document, root, config_path)
        if not status["can_complete"]:
            raise ProjectSemanticsError("尚不能完成审阅：" + "; ".join(status["reasons"]))
        document["discovery_receipt"]["human_review"] = {
            "schema": WORKFLOW_SCHEMA,
            "completed_at_epoch": int(time.time()),
            "decisions_digest": decisions_digest(document),
            "evidence_ref": document["discovery_receipt"]["evidence_ref"],
        }
        return save_document(
            path, document, expected_revision=expected_revision, root=root, allow_proposals=False
        )
