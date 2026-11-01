"""Project-bound primitive authoring, evidence and human review HTTP service."""

from __future__ import annotations

from copy import deepcopy
import hashlib
import io
import json
import os
from pathlib import Path
import tempfile
import time
from typing import Any
from urllib.parse import parse_qs

import yaml
from ruamel.yaml.error import YAMLError

from ..config.project_semantics import (
    ProjectSemanticsStore,
    ProjectSemanticsError,
    canonical_digest,
    empty_project_semantics,
    validate_project_semantics,
)
from ..config.semantics_workflow import (
    COLLECTIONS,
    SemanticsConflict,
    complete_review,
    discovery_current,
    evidence_payload,
    project_activity,
    project_inputs,
    revision,
    save_document,
    workflow_status,
)
from ..config.v2 import load_yaml_unique, _UniqueKeyLoader
from ..orchestration.primitive_tasks import PrimitiveTasks


class SemanticsService:
    def __init__(self, config_path: Path):
        self.config_path = Path(config_path).resolve()
        self.root = self.config_path.parent
        self.tasks = PrimitiveTasks(self.config_path)

    def location(self):
        raw = load_yaml_unique(self.config_path)
        project = raw.get("project") or {}
        if project.get("language") == "java":
            return None
        name = project.get("semantics_file")
        if not name:
            raise ValueError(
                "请在项目设置的 YAML 中添加 project.semantics_file: zscope.semantics.yaml。"
            )
        path = (self.root / name).resolve()
        if (
            not path.is_relative_to(self.root)
            or path == self.config_path
            or path.suffix not in {".yaml", ".yml"}
        ):
            raise ValueError("语义文档必须是当前工程内独立的 YAML 文件。")
        return path

    def read(self):
        path, document, _, _ = self.snapshot()
        return path, document

    def snapshot(self):
        """Bind displayed content and version even when an external editor writes."""
        path = self.location()
        if path is None:
            raise ValueError("Java 项目不适用项目原语。")
        raw = path.read_bytes()
        version = hashlib.sha256(raw).hexdigest()
        content = raw.decode("utf-8")
        try:
            document = validate_project_semantics(
                yaml.load(content, Loader=_UniqueKeyLoader), allow_unbound_primitive_proposals=True
            )
        except yaml.YAMLError as exc:
            raise ProjectSemanticsError(f"语义 YAML 无法解析：{exc}") from exc
        if revision(path) != version:
            raise SemanticsConflict("读取期间语义文档发生变化，请重新载入；本地草稿不会被覆盖。")
        return path, document, version, content

    def status(self):
        path = self.location()
        if path is None:
            return {"applicable": False, "ready": True, "stage": "not_applicable", "reasons": []}
        if not path.exists():
            return {
                "applicable": True,
                "ready": False,
                "stage": "missing",
                "version": "missing",
                "path": str(path.relative_to(self.root)),
                "reasons": ["请创建项目语义文档。"],
                "tasks": self.tasks.list(),
            }
        path, document, version, _ = self.snapshot()
        status = workflow_status(document, self.root, self.config_path)
        from ..config.config import ConfigLoader

        configuration_ready = True
        try:
            config = ConfigLoader.load(str(self.config_path), read_only=True)
            if (
                not config.project.compile_commands_path
                or not config.project.compile_commands_path.is_file()
            ):
                raise ValueError("请在工程设置中指定当前执行机上存在的编译数据库。")
        except (ValueError, OSError) as exc:
            configuration_ready = False
            status["reasons"] = ["工程与模型配置：" + str(exc), *status["reasons"]]
        tasks = self.tasks.list()
        active = next(
            (
                task
                for task in tasks
                if task["status"] in {"queued", "running", "publishing", "cancelling"}
            ),
            None,
        )
        return {
            **status,
            "applicable": True,
            "configuration_ready": configuration_ready,
            "version": version,
            "path": str(path.relative_to(self.root)),
            "evidence_version": document["discovery_receipt"].get("evidence_ref", ""),
            "receipt": document["discovery_receipt"],
            "tasks": tasks,
            "active_task": active,
            "counts": {
                state: sum(
                    row.get("status") == state for key in COLLECTIONS for row in document[key]
                )
                for state in ("pending", "stale", "confirmed", "rejected")
            },
        }

    @staticmethod
    def row(document, collection, identifier):
        if collection not in COLLECTIONS:
            raise ValueError("未知的语义条目类型。")
        row = next((row for row in document[collection] if row["id"] == identifier), None)
        if row is None:
            raise SemanticsConflict("条目已变化或不属于当前文档。")
        return row

    def _current_evidence(self, document):
        current, reason = discovery_current(document, self.root, self.config_path)
        if not current:
            raise SemanticsConflict(reason)
        return evidence_payload(self.root, document["discovery_receipt"]["evidence_ref"])

    def _inventory(self):
        from ..config.semantics_workflow import _discovery_context_current

        task = next(
            (
                task
                for task in self.tasks.list()
                if task["mode"] == "inventory" and task["status"] == "completed"
            ),
            None,
        )
        if task is None:
            return {"symbols": [], "current": False, "reason": "请先准备 native 接口目录。"}
        payload = evidence_payload(self.root, task["result_ref"])
        snapshot = payload["snapshot"]
        tool = snapshot.get("native_tool") or {}
        current = (
            snapshot.get("inputs") == project_inputs(self.root, self.config_path)
            and bool(snapshot.get("contexts"))
            and all(
                _discovery_context_current(context, snapshot.get("lookup_inputs") or {})
                for context in snapshot["contexts"]
            )
            and (not tool.get("path") or revision(Path(tool["path"])) == tool["sha256"])
        )
        return {
            "current": current,
            "version": canonical_digest(snapshot),
            "symbols": payload["symbols"] if current else [],
            "reason": "" if current else "接口目录已失效，请重新准备。",
        }

    def get(self, endpoint: str, query: str = ""):
        try:
            params = {key: values[0] for key, values in parse_qs(query).items()}
            if endpoint == "/api/semantics":
                return 200, self.status()
            if endpoint == "/api/semantics/task":
                return 200, self.tasks.get(
                    params.get("id", ""), max(0, int(params.get("cursor", "0")))
                )
            if endpoint == "/api/semantics/symbols":
                inventory = self._inventory()
                search = params.get("q", "").casefold()
                rows = [
                    row
                    for row in inventory["symbols"]
                    if search
                    in " ".join(
                        str(row.get(key, ""))
                        for key in ("name", "file", "signature", "build_context_id")
                    ).casefold()
                ]
                page = max(1, int(params.get("page", "1")))
                return 200, {
                    **inventory,
                    "total": len(rows),
                    "page": page,
                    "symbols": rows[(page - 1) * 30 : page * 30],
                }
            path, document, version, content = self.snapshot()
            if endpoint == "/api/semantics/document":
                return 200, {
                    "content": content,
                    "version": version,
                    "evidence_version": document["discovery_receipt"].get("evidence_ref", ""),
                }
            if endpoint == "/api/semantics/entries":
                state, search = params.get("state", "todo"), params.get("q", "").casefold()
                rows = []
                for collection in COLLECTIONS:
                    for row in document[collection]:
                        if state != "all" and (
                            row["status"] not in {"pending", "stale"}
                            if state == "todo"
                            else row["status"] != state
                        ):
                            continue
                        if search and search not in json.dumps(row, ensure_ascii=False).casefold():
                            continue
                        rows.append(
                            {
                                "collection": collection,
                                "id": row["id"],
                                "selector": row.get("selector", {}),
                                "status": row["status"],
                                "primitive": row.get("primitive", False),
                                "variants": row.get("variants", []),
                                "row_version": canonical_digest(row),
                                "evidence_digest": row.get("evidence_digest", ""),
                            }
                        )
                page = max(1, int(params.get("page", "1")))
                return 200, {
                    "rows": rows[(page - 1) * 30 : page * 30],
                    "total": len(rows),
                    "page": page,
                    "version": version,
                    "evidence_version": document["discovery_receipt"].get("evidence_ref", ""),
                }
            if endpoint == "/api/semantics/entry":
                collection = params.get("collection", "interfaces")
                row = self.row(document, collection, params.get("id", ""))
                reference = str(
                    row.get("evidence_ref")
                    or document["discovery_receipt"].get("evidence_ref")
                    or ""
                )
                evidence: dict[str, Any] = {}
                source, diagnostics = "", []
                if reference:
                    try:
                        payload = evidence_payload(self.root, reference)
                        evidence = next(
                            (
                                item
                                for item in payload.get(collection, [])
                                if item["id"] == row["id"]
                            ),
                            {},
                        )
                    except (ValueError, OSError) as exc:
                        diagnostics.append(str(exc))
                relative = row.get("selector", {}).get("file") or row.get("file")
                if relative:
                    target = (self.root / relative).resolve()
                    if (
                        target.is_relative_to(self.root)
                        and target.is_file()
                        and target.suffix.lower()
                        in {".c", ".cpp", ".cc", ".h", ".hpp", ".hh", ".cxx", ".hxx", ".inc"}
                    ):
                        # The source path comes exclusively from the saved row;
                        # request parameters can never select an arbitrary file.
                        with target.open(encoding="utf-8", errors="replace") as handle:
                            source = handle.read(128000)
                return 200, {
                    "row": row,
                    "collection": collection,
                    "row_version": canonical_digest(row),
                    "content": yaml.safe_dump(row, allow_unicode=True, sort_keys=False),
                    "version": version,
                    "evidence_version": document["discovery_receipt"].get("evidence_ref", ""),
                    "source": source,
                    "evidence": evidence,
                    "diagnostics": diagnostics,
                }
            if endpoint == "/api/semantics/evidence":
                # No caller-supplied file path. Only current registered evidence.
                payload = evidence_payload(
                    self.root, document["discovery_receipt"].get("evidence_ref", "")
                )
                return 200, {
                    "receipt": payload.get("receipt", {}),
                    "llm_audit": payload.get("llm_audit", {}),
                }
            return 404, {"error": "未知的项目原语接口。"}
        except SemanticsConflict as exc:
            return 409, {"error": str(exc), "code": "semantics_conflict"}
        except (ValueError, OSError, TypeError, KeyError, YAMLError) as exc:
            return 400, {"error": str(exc), "code": "semantics_invalid"}

    def _guard(self, path, document, payload):
        if payload.get("version") != revision(path):
            raise SemanticsConflict("文档已更新，草稿保留在浏览器；请载入最新版本进行比较。")
        if payload.get("evidence_version", "") != document["discovery_receipt"].get(
            "evidence_ref", ""
        ):
            raise SemanticsConflict("发现证据版本已变化，请重新审视当前证据。")

    def _review(self, path, document, payload):
        evidence = self._current_evidence(document)
        items = payload.get("items")
        if not isinstance(items, list) or not 1 <= len(items) <= 100:
            raise ValueError("请显式选择 1–100 个条目。")
        seen = set()
        for item in items:
            collection, identifier = item.get("collection"), item.get("id")
            if (collection, identifier) in seen:
                raise ValueError("批次包含重复条目。")
            seen.add((collection, identifier))
            row = self.row(document, collection, identifier)
            if item.get("row_version") != canonical_digest(row):
                raise SemanticsConflict(f"条目 {identifier} 已变化。")
            machine = next(
                (entry for entry in evidence.get(collection, []) if entry["id"] == identifier), None
            )
            if machine is None or machine.get("evidence_digest") != row.get("evidence_digest"):
                raise SemanticsConflict(f"条目 {identifier} 没有本轮可核验的发现证据。")
            for field in (
                "selector",
                "variants",
                "build_context_id",
                "usr",
                "handler_usr",
                "callsite_id",
                "slot_usr",
                "target_usrs",
                "attribution",
            ):
                if machine.get(field) != row.get(field):
                    raise SemanticsConflict(f"条目 {identifier} 的 {field} 与本轮发现证据不一致。")
            decision = item.get("decision")
            if decision not in {"confirmed", "rejected", "pending"}:
                raise ValueError("未知审阅操作。")
            if decision == "rejected" and not str(item.get("reason", "")).strip():
                raise ValueError("拒绝条目需要填写原因。")
            row["status"] = decision
            row["review_note"] = str(item.get("reason", ""))[:8000]
            row["reviewed_at_epoch"] = int(time.time())
        validate_project_semantics(document)
        # Preflight validates the entire transaction, including unselected rows.
        if payload.get("preview"):
            return {
                "valid": True,
                "count": len(items),
                "scope": [f"{key}:{value}" for key, value in seen],
            }
        save_document(
            path,
            document,
            root=self.root,
            expected_revision=payload["version"],
            allow_proposals=False,
        )
        return self.status()

    def _save_text(self, path, document, payload):
        from ruamel.yaml import YAML

        content = payload.get("content")
        if not isinstance(content, str) or len(content.encode()) > 2 * 1024 * 1024:
            raise ValueError("YAML 文档需要是小于 2 MiB 的文本。")
        parser = YAML()
        parser.preserve_quotes = True
        candidate = parser.load(content)
        validate_project_semantics(
            json.loads(json.dumps(candidate)), allow_unbound_primitive_proposals=True
        )
        if candidate["discovery_receipt"] != document["discovery_receipt"]:
            raise ValueError("发现收据由后台维护；请只编辑条目。")
        for key in COLLECTIONS:
            old = {row["id"]: row for row in document[key]}
            for row in candidate[key]:
                previous = old.get(row["id"])
                if previous is None:
                    if not (
                        key == "interfaces"
                        and row.get("primitive")
                        and row["status"] == "pending"
                        and not row.get("variants")
                    ):
                        raise ValueError(
                            "新条目必须是尚未绑定的 pending 原语声明；派生条目由发现任务生成。"
                        )
                elif row != previous:
                    if row["status"] not in {previous["status"], "pending"}:
                        raise ValueError("请使用确认／拒绝操作提交审阅决定。")
                    for field in ("variants", "evidence_ref", "evidence_digest", "llm_review"):
                        if row.get(field) != previous.get(field):
                            raise ValueError(f"{row['id']}.{field} 是只读发现证据。")
                    if not row.get("primitive") and row.get("selector") != previous.get("selector"):
                        raise ValueError("派生条目身份不可手工替换，请重新发现。")
                    row["status"] = "pending"
            if key != "interfaces" and set(old) != {row["id"] for row in candidate[key]}:
                raise ValueError("派生条目请拒绝并记录原因，不可直接删除。")
            if key == "interfaces" and any(
                not row.get("primitive") and row["id"] not in {new["id"] for new in candidate[key]}
                for row in document[key]
            ):
                raise ValueError("派生条目请拒绝并记录原因，不可直接删除。")
        validate_project_semantics(
            json.loads(json.dumps(candidate)), allow_unbound_primitive_proposals=True
        )
        if payload.get("preview"):
            return {"valid": True}
        stream = io.StringIO()
        parser.dump(candidate, stream)
        fd, name = tempfile.mkstemp(prefix=".semantics-", suffix=".tmp", dir=path.parent)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                handle.write(stream.getvalue())
                handle.flush()
                os.fsync(handle.fileno())
            if revision(path) != payload["version"]:
                raise SemanticsConflict("保存期间语义文档已变化。")
            os.replace(name, path)
        finally:
            if os.path.exists(name):
                os.unlink(name)
        return self.status()

    def _primitive(self, document, payload):
        inventory = self._inventory()
        if not inventory["current"] or payload.get("inventory_version") != inventory["version"]:
            raise SemanticsConflict("接口目录版本已变化，请重新选择函数。")
        symbol = next(
            (row for row in inventory["symbols"] if row["id"] == payload.get("symbol_id")), None
        )
        if symbol is None:
            raise ValueError("请选择目录中精确的函数实例。")
        role = payload.get("role")
        if role not in {"allocator", "deallocator", "reallocator", "lock", "unlock", "copy"}:
            raise ValueError("请选择受支持的原语模板。")
        carrier = {
            "root": payload.get("carrier", "return"),
            "phase": "post" if payload.get("carrier", "return") == "return" else "pre",
            "dereference": int(payload.get("dereference", 0)),
            "members": [x.strip() for x in str(payload.get("members", "")).split(".") if x.strip()],
        }
        if carrier["root"] == "argument":
            carrier["index"] = int(payload.get("argument", 0))
            if not 0 <= carrier["index"] < symbol.get("parameter_count", 0):
                raise ValueError("参数索引超出所选 native 函数的参数范围。")
        if carrier["root"] not in {"return", "argument"}:
            raise ValueError("请选择返回值或参数载体。")
        condition = payload.get("condition", "always")
        conditions = {
            "always": {"op": "true"},
            "return_nonnull": {
                "op": "compare",
                "left": {"kind": "return"},
                "operator": "!=",
                "right": {"kind": "literal", "value": None},
            },
            "return_zero": {
                "op": "compare",
                "left": {"kind": "return"},
                "operator": "==",
                "right": {"kind": "literal", "value": 0},
            },
        }
        if condition not in conditions:
            raise ValueError("未知生效条件，复杂条件请使用高级 YAML。")
        row = {
            "id": "project:primitive:"
            + canonical_digest(
                [symbol["file"], symbol["usr"], symbol["signature"], symbol["build_context_id"]]
            )[:24],
            "primitive": True,
            "status": "pending",
            "basis": "expected_contract",
            "selector": {
                "kind": "function",
                **{
                    key: symbol[key]
                    for key in ("name", "file", "signature", "usr", "build_context_id")
                },
            },
            "effects": [
                {
                    "domain": (
                        "lock"
                        if role in {"lock", "unlock"}
                        else "copy" if role == "copy" else "resource"
                    ),
                    "role": role,
                    "operation": role,
                    "carrier": carrier,
                    "strength": "must_under_guard",
                    "resource_family": str(payload.get("resource_family", "malloc")),
                }
            ],
            "cases": [{"when": conditions[condition], "effect": "applies"}],
            "otherwise": "unknown",
            "pairs": [
                value.strip() for value in str(payload.get("pairs", "")).split(",") if value.strip()
            ],
            "variants": [],
            "derived_from": [],
            "evidence_summary": "人工声明，等待 native 绑定与发现后的审阅。",
        }
        if any(item["id"] == row["id"] for item in document["interfaces"]):
            raise ValueError("该接口已有声明，请使用高级 YAML 编辑现有条目。")
        document["interfaces"].append(row)
        document["discovery_receipt"]["declaration"] = "custom"

    def post(self, endpoint: str, payload: dict[str, Any]):
        try:
            if endpoint == "/api/semantics/tasks":
                return 202, {
                    "task": self.tasks.create(
                        mode=payload.get("mode", ""),
                        request_id=payload.get("request_id", ""),
                        expected_revision=payload.get("version", ""),
                    )
                }
            if endpoint == "/api/semantics/cancel":
                return 200, {"task": self.tasks.cancel(payload.get("id", ""))}
            with project_activity(self.root):
                path = self.location()
                if path is None:
                    raise ValueError("Java 项目不适用项目原语。")
                if endpoint == "/api/semantics/initialize":
                    if path.exists():
                        raise SemanticsConflict("语义文档已存在，不会覆盖。")
                    save_document(
                        path, empty_project_semantics(), root=self.root, expected_revision="missing"
                    )
                    return 200, self.status()
                path, document = self.read()
                self._guard(path, document, payload)
                if endpoint == "/api/semantics/review":
                    return 200, self._review(path, document, payload)
                if endpoint == "/api/semantics/draft":
                    from ruamel.yaml import YAML

                    parser = YAML()
                    parser.preserve_quotes = True
                    edited = parser.load(str(payload.get("content", "")))
                    collection, identifier = payload.get("collection"), payload.get("id")
                    previous = self.row(document, collection, identifier)
                    if (
                        payload.get("row_version") != canonical_digest(previous)
                        or not isinstance(edited, dict)
                        or edited.get("id") != identifier
                    ):
                        raise SemanticsConflict("条目身份或版本已变化，草稿未发布。")
                    candidate = parser.load(path.read_text(encoding="utf-8"))
                    for index, row in enumerate(candidate[collection]):
                        if row["id"] == identifier:
                            candidate[collection][index] = edited
                    stream = io.StringIO()
                    parser.dump(candidate, stream)
                    return 200, self._save_text(
                        path, document, {**payload, "content": stream.getvalue()}
                    )
                if endpoint == "/api/semantics/complete":
                    complete_review(
                        path,
                        root=self.root,
                        config_path=self.config_path,
                        expected_revision=payload["version"],
                    )
                elif endpoint in {"/api/semantics/save", "/api/semantics/validate"}:
                    return 200, self._save_text(
                        path, document, {**payload, "preview": endpoint.endswith("validate")}
                    )
                elif endpoint == "/api/semantics/declare":
                    if payload.get("declaration") != "none_known" or any(
                        row.get("primitive") and row["status"] != "rejected"
                        for row in document["interfaces"]
                    ):
                        raise ValueError("已有有效原语声明时不能选择没有已知自定义原语。")
                    document["discovery_receipt"]["declaration"] = "none_known"
                    save_document(
                        path, document, root=self.root, expected_revision=payload["version"]
                    )
                elif endpoint == "/api/semantics/primitive":
                    self._primitive(document, payload)
                    save_document(
                        path, document, root=self.root, expected_revision=payload["version"]
                    )
                elif endpoint == "/api/semantics/migrate":
                    from ..config.semantics_migration import migrate_workbook_document

                    if any(document[key] for key in COLLECTIONS) or document[
                        "discovery_receipt"
                    ].get("evidence_ref"):
                        raise ValueError("迁移仅写入尚未发现的空语义文档，避免覆盖已有决定。")
                    relative = Path(str(payload.get("workbook", "user_config.xlsx")))
                    source = (self.root / relative).resolve()
                    if (
                        relative.is_absolute()
                        or not source.is_relative_to(self.root)
                        or source.suffix != ".xlsx"
                    ):
                        raise ValueError("请选择工程内的旧 XLSX 工作簿。")
                    migrated, report = migrate_workbook_document(source)
                    save_document(
                        path, migrated, root=self.root, expected_revision=payload["version"]
                    )
                    return 200, {**self.status(), "migration_report": report}
                else:
                    return 404, {"error": "未知的项目原语操作。"}
                return 200, self.status()
        except SemanticsConflict as exc:
            return 409, {"error": str(exc), "code": "semantics_conflict"}
        except (ValueError, OSError, TypeError, KeyError, YAMLError) as exc:
            return 400, {"error": str(exc), "code": "semantics_invalid"}
