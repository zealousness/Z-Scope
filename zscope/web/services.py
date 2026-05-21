"""Service layer used by the Z-SCOPE dashboard HTTP handlers."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, Optional
from urllib.parse import parse_qs

from ..config.config import yaml
from ..config.user_config_workbook import SHEET_HEADERS
from ..reporting.views import (
    DEFAULT_REPORT_VIEW,
    WITH_NEEDS_REVIEW_REPORT_VIEW,
    build_report_views,
    findings_for_view,
    report_view_summary,
)


ALLOWED_VALIDATION_STATUSES = {
    "validated",
    "needs_review",
    "uncertain",
    "unvalidated",
    "pending",
    "rejected",
}


def empty_report() -> Dict[str, Any]:
    return {
        "issues": [],
        "issues_by_severity": {"critical": [], "high": [], "medium": [], "low": []},
    }


class ConfigService:
    """Read and write the structured dashboard config document."""

    def __init__(self, config_path: Optional[Path] = None, *, default_name: str = "zscope.yaml"):
        self.config_path = Path(config_path).resolve() if config_path else None
        self.default_name = default_name

    @property
    def path(self) -> Path:
        return self.config_path or Path(self.default_name)

    def load_document(self) -> Dict[str, Any]:
        path = self.path
        if not path.exists():
            return {}
        if yaml is None:
            raise RuntimeError("PyYAML is required for structured config editing")
        content = path.read_text(encoding="utf-8")
        data = yaml.safe_load(content) if content.strip() else {}
        return data if isinstance(data, dict) else {}

    def save_document(self, data: Dict[str, Any]) -> None:
        if yaml is None:
            raise RuntimeError("PyYAML is required for structured config editing")
        header = (
            "# Z-SCOPE 配置文件\n"
            "# 本文件由 Web UI 结构化配置编辑器生成。\n"
            "# 字段说明请参考仓库根目录 zscope.yaml 模板中的注释。\n\n"
        )
        text = yaml.safe_dump(data, allow_unicode=True, sort_keys=False)
        self.path.write_text(header + text, encoding="utf-8")

    def structured_payload(self) -> Dict[str, Any]:
        return {"config": self.load_document()}

    def read_text(self) -> Dict[str, str]:
        path = self.path
        if not path.exists():
            return {"content": ""}
        return {"content": path.read_text(encoding="utf-8")}

    def write_text(self, content: str) -> Dict[str, Any]:
        path = self.path
        path.write_text(content, encoding="utf-8")
        return {"success": True, "path": str(path)}


class WorkbookService:
    """Normalize workbook payloads for dashboard editing."""

    def __init__(self, user_config_store: Any = None):
        self.user_config_store = user_config_store

    def path(self) -> Optional[Path]:
        store = self.user_config_store
        if not store:
            return None
        workbook = getattr(store, "workbook", None)
        path = getattr(workbook, "path", None)
        return Path(path) if path else None

    def payload(self) -> Dict[str, Any]:
        store = self.user_config_store
        if not store:
            return self.empty_payload()
        rows = store.workbook.read_rows()
        normalized_rows = {name: list(rows.get(name, [])) for name in SHEET_HEADERS}
        return {
            "headers": SHEET_HEADERS,
            "rows": normalized_rows,
            "sheets": [
                {
                    "name": name,
                    "headers": headers,
                    "rows": normalized_rows.get(name, []),
                }
                for name, headers in SHEET_HEADERS.items()
            ],
        }

    def write_payload(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        if not self.user_config_store:
            raise RuntimeError("Config store not available")
        rows = self.rows_from_payload(payload)
        self.user_config_store.workbook.write_rows(rows)
        return self.payload()

    def import_bytes(self, data: bytes) -> Dict[str, Any]:
        store = self.user_config_store
        if not store:
            raise RuntimeError("Config store not available")
        if not data:
            raise ValueError("Uploaded workbook is empty")
        path = self.path()
        if path is None:
            raise RuntimeError("Workbook path not available")
        tmp_path = path.with_suffix(".upload.tmp.xlsx")
        try:
            tmp_path.parent.mkdir(parents=True, exist_ok=True)
            tmp_path.write_bytes(data)
            rows = type(store.workbook)(tmp_path).read_rows()
            store.workbook.write_rows(rows)
        finally:
            try:
                tmp_path.unlink(missing_ok=True)
            except OSError:
                pass
        return self.payload()

    def download_bytes(self) -> bytes:
        store = self.user_config_store
        if not store:
            raise RuntimeError("Config store not available")
        path = self.path()
        if path is None:
            raise RuntimeError("Workbook path not available")
        if not path.exists():
            store.workbook.write_rows({name: [] for name in SHEET_HEADERS})
        return path.read_bytes()

    @staticmethod
    def empty_payload() -> Dict[str, Any]:
        return {
            "headers": SHEET_HEADERS,
            "rows": {name: [] for name in SHEET_HEADERS},
            "sheets": [
                {"name": name, "headers": headers, "rows": []}
                for name, headers in SHEET_HEADERS.items()
            ],
        }

    @staticmethod
    def rows_from_payload(payload: Dict[str, Any]) -> Dict[str, Any]:
        rows = payload.get("rows")
        if isinstance(rows, dict):
            return {name: list(rows.get(name, [])) for name in SHEET_HEADERS}
        sheets = payload.get("sheets")
        if isinstance(sheets, list):
            by_name = {}
            for sheet in sheets:
                if isinstance(sheet, dict) and sheet.get("name") in SHEET_HEADERS:
                    by_name[sheet["name"]] = sheet.get("rows", [])
            return {name: list(by_name.get(name, [])) for name in SHEET_HEADERS}
        raise ValueError("Expected workbook rows or sheets")


class UserConfigService:
    """CRUD helpers for dashboard-editable user configuration resources."""

    def __init__(self, user_config_store: Any = None):
        self.user_config_store = user_config_store

    def warnings_payload(self) -> Dict[str, Any]:
        store = self.user_config_store
        if not store:
            return {"items": []}
        return {"items": store.list_config_warnings()}

    def clear_warnings(self) -> tuple[int, Dict[str, Any]]:
        store = self.user_config_store
        if not store:
            return 400, {"success": False, "error": "Config store not available"}
        store.clear_config_warnings()
        return 200, {"success": True}

    def list_resource(self, resource: str) -> tuple[int, Dict[str, Any]]:
        store = self.user_config_store
        if not store:
            return 200, {"items": []}
        dispatch = {
            "external_functions": store.list_external_functions,
            "paired_functions": store.list_paired_functions,
            "pointer_targets": store.get_pointer_targets,
            "function_intents": store.list_function_intents,
        }
        fn = dispatch.get(resource)
        if not fn:
            return 404, {"success": False, "error": f"Unknown user config resource: {resource}"}
        return 200, {"items": fn()}

    def upsert_resource(self, resource: str, payload: Dict[str, Any]) -> tuple[int, Dict[str, Any]]:
        store = self.user_config_store
        if not store:
            return 400, {"success": False, "error": "Config store not available"}
        try:
            if resource == "external_functions":
                store.upsert_external_function(
                    payload["func_name"],
                    payload.get("description", ""),
                    library=payload.get("library", ""),
                    memory_behavior=payload.get("memory_behavior"),
                    concurrency_behavior=payload.get("concurrency_behavior"),
                    return_semantics=payload.get("return_semantics", ""),
                )
            elif resource == "paired_functions":
                store.upsert_paired_function(
                    payload["category"],
                    payload["acquire_func"],
                    payload["release_func"],
                    payload.get("description", ""),
                )
            elif resource == "pointer_targets":
                store.upsert_pointer_target(
                    payload["pointer_location"],
                    payload.get("scope", "local"),
                    payload.get("target_functions", []),
                    payload.get("context", ""),
                )
            elif resource == "function_intents":
                store.upsert_function_intent(
                    payload["func_name"],
                    payload.get("file_path", ""),
                    caller_constraints=payload.get("caller_constraints"),
                    concurrency_group=payload.get("concurrency_group", ""),
                    concurrent_with=payload.get("concurrent_with"),
                    notes=payload.get("notes", ""),
                )
            else:
                return 404, {"success": False, "error": f"Unknown user config resource: {resource}"}
        except KeyError as exc:
            return 400, {"success": False, "error": f"Missing field: {exc}"}
        return 200, {"success": True}

    def delete_resource(self, resource: str, payload: Dict[str, Any]) -> tuple[int, Dict[str, Any]]:
        store = self.user_config_store
        if not store:
            return 400, {"success": False, "error": "Config store not available"}
        try:
            if resource == "external_functions":
                store.delete_external_function(payload["func_name"])
            elif resource == "paired_functions":
                store.delete_paired_function(payload["id"])
            elif resource == "pointer_targets":
                store.delete_pointer_target(payload["id"])
            elif resource == "function_intents":
                store.delete_function_intent(
                    payload["func_name"],
                    payload.get("file_path", ""),
                )
            else:
                return 404, {"success": False, "error": f"Unknown user config resource: {resource}"}
        except KeyError as exc:
            return 400, {"success": False, "error": f"Missing field: {exc}"}
        return 200, {"success": True}


class CpgService:
    """Dashboard-facing CPG backend status and build operations."""

    def __init__(self, code_index: Any = None, project_config: Any = None):
        self.code_index = code_index
        self.project_config = project_config

    @property
    def backend(self) -> Any:
        return getattr(self.code_index, "backend", None) if self.code_index else None

    def status_payload(self) -> Dict[str, Any]:
        backend = self.backend
        if not backend:
            return {"status": "unavailable", "error": None}
        error = None
        joern_client = getattr(backend, "joern_client", None)
        if joern_client is not None:
            error = getattr(joern_client, "cpg_error", None)
        return {"status": backend.status(), "error": error}

    def build(self) -> tuple[int, Dict[str, Any]]:
        backend = self.backend
        if not backend:
            return 400, {"success": False, "error": "Backend not available"}
        if not self.project_config:
            return 400, {"success": False, "error": "Project config not available"}

        joern_client = getattr(backend, "joern_client", None)
        importer = getattr(joern_client, "import_cpg_async", None)
        if not callable(importer):
            return 400, {"success": False, "error": "Current backend does not support async CPG build"}

        source_path = str(getattr(self.project_config, "source_root", ""))
        project_root = str(getattr(self.project_config, "project_root", ""))
        compile_commands = getattr(self.project_config, "compile_commands_path", None)
        cc_path = str(compile_commands) if compile_commands else None
        importer(source_path, project_root, cc_path)
        return 200, {"success": True, "status": "building"}


class SourceSnippetService:
    """Resolve and slice source files visible to the dashboard."""

    def __init__(self, project_config: Any = None):
        self.project_config = project_config

    def search_roots(self) -> list[Path]:
        roots: list[Path] = []
        if self.project_config:
            for attr in ("project_root", "source_root"):
                value = getattr(self.project_config, attr, None)
                if value:
                    roots.append(Path(value))
            for value in getattr(self.project_config, "include_paths", []) or []:
                roots.append(Path(value))
        if not roots:
            roots.extend([Path.cwd(), repo_root()])

        unique: list[Path] = []
        seen: set[str] = set()
        for root in roots:
            try:
                resolved = root.resolve()
            except OSError:
                continue
            key = str(resolved).lower()
            if key not in seen and resolved.exists():
                unique.append(resolved)
                seen.add(key)
        return unique

    def resolve_source_file(self, raw_path: str) -> Optional[Path]:
        if not raw_path:
            return None
        normalized = raw_path.replace("\\", "/").strip().lstrip("/")
        requested = Path(normalized)
        roots = self.search_roots()
        candidates: list[Path] = []
        if requested.is_absolute() and any(is_within(requested, root) for root in roots):
            candidates.append(requested)
        for root in roots:
            candidates.append(root / normalized)
        if normalized.endswith(".ph"):
            fallback = normalized[:-3] + ".h"
            for root in roots:
                candidates.append(root / fallback)

        for candidate in candidates:
            try:
                resolved = candidate.resolve()
            except OSError:
                continue
            if not resolved.is_file():
                continue
            if any(is_within(resolved, root) for root in roots):
                return resolved
        return None

    def snippet_payload(self, query: str) -> tuple[int, Dict[str, Any]]:
        parsed_query = parse_qs(query)
        raw_path = str((parsed_query.get("path") or [""])[0] or "")
        source_path = self.resolve_source_file(raw_path)
        if not source_path:
            return 404, {"success": False, "error": f"source file not found: {raw_path}"}
        try:
            start = int((parsed_query.get("start") or ["1"])[0] or "1")
            end = int((parsed_query.get("end") or [str(start)])[0] or start)
            context = int((parsed_query.get("context") or ["6"])[0] or "6")
        except ValueError:
            return 400, {"success": False, "error": "invalid line range"}
        try:
            raw_lines = source_path.read_text(encoding="utf-8", errors="ignore").splitlines()
        except OSError as exc:
            return 500, {"success": False, "error": str(exc)}
        if not raw_lines:
            return 200, {"success": True, "path": raw_path, "resolved_path": str(source_path), "lines": []}
        start = max(1, start)
        end = max(start, end)
        snippet_start = max(1, start - max(context, 0))
        snippet_end = min(len(raw_lines), end + max(context, 0))
        lines = [
            {"no": number, "text": raw_lines[number - 1]}
            for number in range(snippet_start, snippet_end + 1)
        ]
        return 200, {
            "success": True,
            "path": raw_path,
            "resolved_path": str(source_path),
            "start": start,
            "end": end,
            "snippet_start": snippet_start,
            "snippet_end": snippet_end,
            "lines": lines,
            "code_snippet": "\n".join(line["text"] for line in lines),
        }


class ReportFeedbackService:
    """Persist dashboard validation feedback into reports, snapshots, and user DB."""

    def __init__(
        self,
        user_config_store: Any = None,
        snapshot_store: Any = None,
        *,
        report_filename: str = "zscope_batch_report.json",
    ):
        self.user_config_store = user_config_store
        self.snapshot_store = snapshot_store
        self.report_filename = report_filename

    def load_report(self) -> Dict[str, Any]:
        report_path = Path(self.report_filename)
        if not report_path.exists():
            return empty_report()
        raw_content = report_path.read_text(encoding="utf-8", errors="ignore")
        sanitized = strip_json_code_fence(raw_content)
        if not sanitized:
            return empty_report()
        try:
            return json.loads(sanitized)
        except json.JSONDecodeError as exc:
            print(f"Warning: failed to parse report JSON: {exc}")
            return empty_report()

    def save_report(self, report: Dict[str, Any]) -> None:
        with Path(self.report_filename).open("w", encoding="utf-8") as f:
            json.dump(report, f, ensure_ascii=False, indent=2)

    def selected_view_payload(self, path: str) -> Dict[str, Any]:
        report = self.load_report()
        view = selected_report_view(path)
        return {
            "report": report,
            "findings": findings_for_view(report, view),
            "view": view,
            "views": report_view_summary(report),
        }

    def persist_validation_feedback(self, updates: list[Any]) -> Dict[str, Any]:
        store = self.user_config_store
        if not store:
            return {
                "db_available": False,
                "db_path": "",
                "baseline_upserts": 0,
                "suppression_upserts": 0,
            }
        result = {
            "db_available": True,
            "db_path": str(getattr(store, "db_path", "")),
            "baseline_upserts": 0,
            "suppression_upserts": 0,
        }
        for issue in updates:
            if not isinstance(issue, dict):
                continue
            status, reasoning = normalize_validation(issue)
            dedup_key = feedback_dedup_key(issue)
            if dedup_key:
                baseline_status = {
                    "validated": "true_positive",
                    "needs_review": "needs_review",
                    "uncertain": "uncertain",
                    "rejected": "false_positive",
                }.get(status)
                if baseline_status:
                    store.upsert_finding_baseline(dedup_key, baseline_status, issue)
                    result["baseline_upserts"] += 1
            if status == "rejected":
                store.add_false_positive_suppression(
                    func_name=str(issue.get("function") or ""),
                    location=str(issue.get("location") or ""),
                    category=feedback_category(issue),
                    reason=str(reasoning or "user rejected finding"),
                    scope="finding",
                    rule=str(issue.get("rule") or issue.get("candidate_source") or ""),
                    note=str(issue.get("description") or ""),
                )
                result["suppression_upserts"] += 1
        return result

    def apply_validation_updates(self, report: Dict[str, Any], updates: list[Any]) -> None:
        update_map = {issue_key(issue): normalize_validation(issue) for issue in updates}

        def update_issue(issue: Dict[str, Any]) -> None:
            key = issue_key(issue)
            if key in update_map:
                status, reasoning = update_map[key]
                issue["validation_status"] = status
                issue["validation_reasoning"] = reasoning

        for issue in report.get("issues", []):
            update_issue(issue)
        for issues in report.get("issues_by_severity", {}).values():
            for issue in issues:
                update_issue(issue)
        for issue in report.get("findings", []):
            update_issue(issue)
        metadata = report.get("metadata")
        if isinstance(metadata, dict):
            for issue in metadata.get("audit_observations", []):
                update_issue(issue)
        for issue in report.get("issues_with_needs_review", []):
            update_issue(issue)

        report_views = report.get("report_views")
        if isinstance(report_views, dict):
            for view in report_views.values():
                if isinstance(view, dict):
                    for issue in view.get("issues", []):
                        update_issue(issue)

            metadata = report.get("metadata") if isinstance(report.get("metadata"), dict) else {}
            rebuilt_views = build_report_views(
                report.get("issues", []),
                metadata.get("audit_observations", []),
            )
            report["report_views"] = rebuilt_views
            with_review = rebuilt_views.get(WITH_NEEDS_REVIEW_REPORT_VIEW, {})
            report["issues_with_needs_review"] = with_review.get("issues", [])
            report["issues_by_severity_with_needs_review"] = with_review.get(
                "issues_by_severity",
                {},
            )
            report.setdefault("metadata", {})["report_view_summary"] = report_view_summary(report)

    def apply_validation_to_snapshots(self, updates: list[Any]) -> Dict[str, Any]:
        snapshot_store = self.snapshot_store
        if not snapshot_store:
            return {
                "snapshot_available": False,
                "final_reports_scanned": 0,
                "final_reports_updated": 0,
                "issues_updated": 0,
            }

        key_updates = {
            issue_key(issue): normalize_validation(issue)
            for issue in updates
            if isinstance(issue, dict)
        }
        dedup_updates = {
            str(issue.get("dedup_key")): normalize_validation(issue)
            for issue in updates
            if isinstance(issue, dict) and issue.get("dedup_key")
        }

        def apply_to_issue(target: Any) -> bool:
            if not isinstance(target, dict):
                return False
            update = None
            key = issue_key(target)
            if key in key_updates:
                update = key_updates[key]
            else:
                dedup_key = target.get("dedup_key")
                if dedup_key and str(dedup_key) in dedup_updates:
                    update = dedup_updates[str(dedup_key)]
            if not update:
                return False
            status, reasoning = update
            target["validation_status"] = status
            target["validation_reasoning"] = reasoning
            if status == "rejected":
                target["rejection_source"] = "user"
            return True

        def apply_to_issue_list(items: Any) -> int:
            changed = 0
            if isinstance(items, list):
                for item in items:
                    if apply_to_issue(item):
                        changed += 1
            return changed

        def apply_to_report(report: Dict[str, Any]) -> int:
            changed = apply_to_issue_list(report.get("issues"))
            for bucket in report.get("issues_by_severity", {}).values():
                changed += apply_to_issue_list(bucket)
            report_views = report.get("report_views")
            if isinstance(report_views, dict):
                for view in report_views.values():
                    if not isinstance(view, dict):
                        continue
                    changed += apply_to_issue_list(view.get("issues"))
                    for bucket in view.get("issues_by_severity", {}).values():
                        changed += apply_to_issue_list(bucket)
            return changed

        result = {
            "snapshot_available": True,
            "snapshot_dir": str(getattr(snapshot_store, "snapshot_dir", "")),
            "final_reports_scanned": 0,
            "final_reports_updated": 0,
            "issues_updated": 0,
        }
        snapshot_dir = getattr(snapshot_store, "snapshot_dir", None)
        if not snapshot_dir:
            return result
        for final_path in Path(snapshot_dir).glob("*_final.json"):
            result["final_reports_scanned"] += 1
            try:
                report = json.loads(final_path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            changed_count = apply_to_report(report)
            if not changed_count:
                continue
            final_path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
            result["final_reports_updated"] += 1
            result["issues_updated"] += changed_count
        return result

    def save_validation_feedback(self, updates: list[Any]) -> Dict[str, Any]:
        report = self.load_report()
        self.apply_validation_updates(report, updates)
        snapshot_result = self.apply_validation_to_snapshots(updates)
        feedback_result = self.persist_validation_feedback(updates)
        self.save_report(report)
        return {
            "success": True,
            "saved_to_report": True,
            "db_persisted": bool(feedback_result.get("db_available")),
            "state_db_persisted": bool(feedback_result.get("db_available")),
            "feedback_persistence": feedback_result,
            "snapshot_persistence": snapshot_result,
        }


def strip_json_code_fence(content: str) -> str:
    stripped = content.strip()
    if not stripped.startswith("```"):
        return stripped
    lines = stripped.splitlines()
    if lines and lines[0].startswith("```"):
        lines = lines[1:]
    if lines and lines[-1].strip() == "```":
        lines = lines[:-1]
    return "\n".join(lines).strip()


def selected_report_view(path: str) -> str:
    from urllib.parse import urlparse

    parsed = urlparse(path)
    query = parse_qs(parsed.query)
    view = str((query.get("view") or [DEFAULT_REPORT_VIEW])[0] or DEFAULT_REPORT_VIEW)
    if view not in {DEFAULT_REPORT_VIEW, WITH_NEEDS_REVIEW_REPORT_VIEW}:
        view = DEFAULT_REPORT_VIEW
    return view


def issue_key(issue: Dict[str, Any]) -> tuple[Any, Any, Any, Any]:
    return (
        issue.get("id"),
        issue.get("function"),
        issue.get("location"),
        issue.get("subcategory"),
    )


def normalize_validation(issue: Dict[str, Any]) -> tuple[str, Any]:
    status = issue.get("validation_status")
    if status not in ALLOWED_VALIDATION_STATUSES:
        status = "pending"
    reasoning = issue.get("validation_reasoning")
    return status, reasoning


def feedback_category(issue: Dict[str, Any]) -> str:
    return str(
        issue.get("defect_class")
        or issue.get("subcategory")
        or issue.get("category")
        or ""
    )


def feedback_dedup_key(issue: Dict[str, Any]) -> str:
    explicit = issue.get("dedup_key")
    if explicit:
        return str(explicit)
    parts = [
        issue.get("defect_class") or issue.get("subcategory") or issue.get("category") or "",
        issue.get("function") or "",
        issue.get("location") or "",
        issue.get("sink") or "",
        issue.get("source") or "",
    ]
    return "|".join(str(part) for part in parts)


def repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def is_within(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
        return True
    except ValueError:
        return False
    except OSError:
        return False
