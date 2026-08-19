"""Service layer used by the Z-SCOPE dashboard HTTP handlers."""

from __future__ import annotations

import json
import hashlib
import os
import tempfile
from pathlib import Path
from typing import Any, Dict, Optional
from urllib.parse import parse_qs

from ..config.config import ConfigLoader, yaml
from ..config.user_config_workbook import SHEET_HEADERS
from ..framework.llm_usage import scan_token_usage_snapshot
from ..orchestration.rollout import rollout_runtime_policy
from ..reporting.views import (
    DEFAULT_REPORT_VIEW,
    WITH_NEEDS_REVIEW_REPORT_VIEW,
    findings_for_view,
    group_by_severity,
    report_view_summary,
)
from ..rules.query import query_effective_rules, validate_rule_filters
from ..semantics.security_specs.archive import (
    archive_from_json_bytes,
    archive_from_xlsx,
    archive_to_json_bytes,
    archive_to_xlsx,
    build_archive,
)
from ..semantics.security_specs.compiler import SecuritySpecCompiler
from ..semantics.security_specs.lifecycle import REVIEWER_IDENTITY_MODE, SECURITY_SPEC_MODE
from ..semantics.security_specs.store import SecuritySpecStore


ALLOWED_VALIDATION_STATUSES = {
    "validated",
    "needs_review",
    "uncertain",
    "unvalidated",
    "pending",
    "rejected",
}

DASHBOARD_TEXT_LIMITS = {
    "dedup_key": 240,
    "category": 80,
    "normalized_category": 80,
    "subcategory": 80,
    "defect_class": 80,
    "code_snippet": 12000,
    "reasoning": 10000,
    "reasoning_process": 10000,
    "validation_reasoning": 10000,
    "description": 5000,
    "root_cause": 5000,
    "suggested_fix": 5000,
    "guard_analysis": 4000,
    "exploit_scenario": 4000,
}

DASHBOARD_ISSUE_FIELDS = (
    "id",
    "candidate_id",
    "candidate_source",
    "finding_kind",
    "function",
    "location",
    "category",
    "subcategory",
    "description",
    "root_cause",
    "suggested_fix",
    "reasoning",
    "reasoning_process",
    "code_snippet",
    "validation_status",
    "validation_reasoning",
    "confidence",
    "impact_level",
    "dedup_key",
    "stable_fingerprint",
    "defect_class",
    "rule",
    "rule_id",
    "rule_engine",
    "rule_revision",
    "rule_source",
    "rule_status",
    "rule_catalog_version",
    "rule_catalog_sha256",
    "skill",
    "candidate_kind",
    "signal_source",
    "native_rule_id",
    "cwe",
    "source",
    "sink",
    "guard_analysis",
    "exploit_scenario",
    "final_score",
    "file",
    "line",
    "start_line",
    "end_line",
    "entry_function",
    "sink_function",
    "target_function",
    "analyzed_from",
    "reachable_from_entry",
    "internal_sink_lifted",
    "normalized_category",
    "source_loc",
    "sink_loc",
)

DASHBOARD_ARRAY_FIELDS = (
    "positive_evidence",
    "negative_evidence",
    "evidence_refs",
    "call_path",
    "path_constraints",
    "call_paths",
)

DASHBOARD_EVIDENCE_PACK_FIELDS = (
    "checker",
    "candidate_source",
    "candidate_is_conclusion",
    "validation_required",
    "final_score",
    "score",
    "entry_function",
    "sink_function",
    "target_function",
    "resource",
    "resource_kind",
    "path",
    "source_path",
    "value_flow",
    "lifecycle_pair",
    "ast_cfg",
    "clang_matcher_fact",
    "semantic_overlay_evidence",
)


def empty_report() -> Dict[str, Any]:
    return {
        "issues": [],
        "issues_by_severity": {"critical": [], "high": [], "medium": [], "low": []},
    }


class SecuritySpecReviewService:
    """Read-only P3 Security Spec review and strict dry-run import service."""

    def __init__(self, root: Optional[Path] = None) -> None:
        self.root = Path(root) if root else None
        self.store = SecuritySpecStore(self.root) if self.root else None

    def _archive(self) -> Dict[str, Any]:
        if self.store is None:
            return build_archive(specs=[])
        return build_archive(
            specs=self.store.list_specs(latest_only=False),
            reviews=self.store.list_review_events(),
            qualifications=self.store.list_artifacts("qualification"),
        )

    def list_payload(self, query: str = "") -> Dict[str, Any]:
        parsed = parse_qs(query)
        requested_status = str((parsed.get("status") or [""])[0])
        specs = self.store.list_specs(status=requested_status) if self.store else []
        return {
            "schema_version": "zscope.security-spec-review-center.v2",
            "security_spec_mode": SECURITY_SPEC_MODE,
            "reviewer_identity_mode": REVIEWER_IDENTITY_MODE,
            "read_only": True,
            "specs": specs,
            "summary": {
                "spec_count": len(specs),
                "by_status": {
                    status: sum(1 for value in specs if value.get("status") == status)
                    for status in sorted({str(value.get("status")) for value in specs})
                },
            },
        }

    def detail_payload(self, spec_uid: str) -> tuple[int, Dict[str, Any]]:
        spec = self.store.get_spec(spec_uid) if self.store else None
        if spec is None:
            return 404, {"success": False, "error": "security_spec_not_found"}
        qualifications = self.store.list_artifacts("qualification") if self.store else []
        qualification_hashes = [str(value["content_sha256"]) for value in qualifications]
        compilation = SecuritySpecCompiler().compile(
            [spec],
            qualification_hashes=qualification_hashes,
            resolvable_evidence_refs=spec["evidence_refs"],
            current_dependency_hashes=spec["dependency_hashes"],
        )
        events = [
            value
            for value in (self.store.list_review_events() if self.store else [])
            if value.get("spec_uid") == spec_uid
        ]
        return 200, {
            "schema_version": "zscope.security-spec-detail.v2",
            "read_only": True,
            "spec": spec,
            "review_events": events,
            "compilation_preview": compilation,
            "impact_preview": list(spec.get("impact_preview") or []),
        }

    def export_bytes(self, export_format: str) -> tuple[bytes, str, str]:
        archive = self._archive()
        if export_format == "json":
            return archive_to_json_bytes(archive), "application/json", "security-specs.json"
        if export_format != "xlsx":
            raise ValueError("security_spec_export_format_must_be_json_or_xlsx")
        with tempfile.TemporaryDirectory(prefix="zscope-security-spec-export-") as temporary:
            path = Path(temporary) / "security-specs.xlsx"
            archive_to_xlsx(path, archive)
            return (
                path.read_bytes(),
                "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                "security-specs.xlsx",
            )

    def dry_run_import(self, data: bytes, import_format: str) -> Dict[str, Any]:
        current_archive = self._archive()
        current = current_archive["store_revision"]
        if import_format == "json":
            archive = archive_from_json_bytes(data, expected_store_revision=current)
        elif import_format == "xlsx":
            with tempfile.TemporaryDirectory(prefix="zscope-security-spec-import-") as temporary:
                path = Path(temporary) / "security-specs.xlsx"
                path.write_bytes(data)
                archive = archive_from_xlsx(path, expected_store_revision=current)
        else:
            raise ValueError("security_spec_import_format_must_be_json_or_xlsx")
        current_specs = {
            (str(value["spec_uid"]), int(value["revision"])): str(value["content_sha256"])
            for value in current_archive["specs"]
        }
        proposed_specs = {
            (str(value["spec_uid"]), int(value["revision"])): str(value["content_sha256"])
            for value in archive["specs"]
        }
        added = sorted(
            f"{uid}@{revision}" for uid, revision in proposed_specs.keys() - current_specs.keys()
        )
        removed = sorted(
            f"{uid}@{revision}" for uid, revision in current_specs.keys() - proposed_specs.keys()
        )
        changed = sorted(
            f"{uid}@{revision}"
            for uid, revision in proposed_specs.keys() & current_specs.keys()
            if proposed_specs[(uid, revision)] != current_specs[(uid, revision)]
        )
        return {
            "success": True,
            "dry_run": True,
            "applied": False,
            "read_only": True,
            "store_revision": current,
            "bundle_sha256": archive["bundle_sha256"],
            "summary": {
                "spec_count": len(archive["specs"]),
                "review_count": len(archive["reviews"]),
                "qualification_count": len(archive["qualifications"]),
            },
            "impact_preview": {
                "added_spec_revisions": added,
                "removed_spec_revisions": removed,
                "changed_spec_revisions": changed,
            },
        }

    @staticmethod
    def write_rejected_payload() -> tuple[int, Dict[str, Any]]:
        return 403, {
            "success": False,
            "error": "reviewer_identity_unavailable",
            "read_only": True,
        }


class ConfigService:
    """Read and write the structured dashboard config document."""

    def __init__(
        self,
        config_path: Optional[Path] = None,
        *,
        default_name: str = "zscope.yaml",
        scan_depth: Optional[str] = None,
    ):
        self.config_path = Path(config_path).resolve() if config_path else None
        self.default_name = default_name
        self.scan_depth = scan_depth

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
            "# 字段说明请参考仓库根目录 zscope.c_cpp.yaml 或 zscope.java.yaml 中的注释。\n\n"
        )
        text = yaml.safe_dump(data, allow_unicode=True, sort_keys=False)
        self._validate_and_replace(header + text)

    def structured_payload(self) -> Dict[str, Any]:
        effective = None
        if self.path.exists():
            overrides: Dict[str, Any] = {}
            if self.scan_depth is not None:
                overrides["scan_depth"] = self.scan_depth
            effective = ConfigLoader.load(str(self.path), **overrides)
        document = self.load_document()
        payload: Dict[str, Any] = {
            "config": document,
            "config_version": document.get("config_version"),
            "language": (document.get("project") or {}).get("language"),
        }
        if effective is not None:
            payload["effective_scan"] = {
                "depth": effective.scan.depth,
                "depth_source": effective.scan.depth_source,
                "rollout": rollout_runtime_policy(effective),
            }
            payload["llm_usage"] = scan_token_usage_snapshot(effective)
        return payload

    def read_text(self) -> Dict[str, str]:
        path = self.path
        if not path.exists():
            return {"content": ""}
        return {"content": path.read_text(encoding="utf-8")}

    def write_text(self, content: str) -> Dict[str, Any]:
        self._validate_and_replace(content)
        return {"success": True, "path": str(self.path)}

    def _validate_and_replace(self, content: str) -> None:
        path = self.path
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary = path.with_name(f".{path.name}.tmp-{os.getpid()}")
        try:
            with temporary.open("w", encoding="utf-8", newline="\n") as handle:
                handle.write(content)
            ConfigLoader.load(str(temporary))
            os.replace(temporary, path)
        finally:
            if temporary.exists():
                temporary.unlink()


class RuleService:
    """Return the immutable effective rule catalog used by the current config."""

    def __init__(self, config_path: Optional[Path] = None, *, default_name: str = "zscope.yaml"):
        self.config_path = Path(config_path).resolve() if config_path else None
        self.default_name = default_name

    @property
    def path(self) -> Path:
        return self.config_path or Path(self.default_name)

    def payload(self, query: str = "") -> Dict[str, Any]:
        """Load the current config and apply read-only catalog query filters."""

        params = parse_qs(query, keep_blank_values=True)
        filters = {
            name: str((params.get(name) or [""])[0]).strip()
            for name in ("language", "engine", "skill", "status", "q")
        }
        validate_rule_filters(filters)

        config = ConfigLoader.load(str(self.path))
        effective = getattr(config, "effective_rules", None)
        if effective is None:
            raise RuntimeError("rule preflight did not produce an EffectiveRuleSet")
        return query_effective_rules(
            effective,
            language=filters["language"],
            engine=filters["engine"],
            skill=filters["skill"],
            status=filters["status"],
            query=filters["q"],
        )


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
            return 400, {
                "success": False,
                "error": "Current backend does not support async CPG build",
            }

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
            return 200, {
                "success": True,
                "path": raw_path,
                "resolved_path": str(source_path),
                "lines": [],
            }
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
            "code_snippet": "\n".join(str(line["text"]) for line in lines),
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
        self._report_cache_key: Optional[tuple[str, int, int]] = None
        self._report_cache: Optional[Dict[str, Any]] = None

    def load_report(self) -> Dict[str, Any]:
        report_path = Path(self.report_filename)
        if not report_path.exists():
            return empty_report()
        stat = report_path.stat()
        cache_key = (str(report_path.resolve()), stat.st_mtime_ns, stat.st_size)
        if self._report_cache_key == cache_key and self._report_cache is not None:
            return self._report_cache
        raw_content = report_path.read_text(encoding="utf-8", errors="ignore")
        sanitized = strip_json_code_fence(raw_content)
        if not sanitized:
            return empty_report()
        try:
            raw_report = json.loads(sanitized)
        except json.JSONDecodeError as exc:
            print(f"Warning: failed to parse report JSON: {exc}")
            return empty_report()
        report = raw_report if isinstance(raw_report, dict) else empty_report()
        self._report_cache_key = cache_key
        self._report_cache = report
        return report

    def save_report(self, report: Dict[str, Any]) -> None:
        with Path(self.report_filename).open("w", encoding="utf-8") as f:
            json.dump(report, f, ensure_ascii=False, indent=2)
        self._report_cache_key = None
        self._report_cache = None

    @staticmethod
    def _lightweight_report(report: Dict[str, Any]) -> Dict[str, Any]:
        report_views = report.get("report_views")
        compact_views: Dict[str, Any] = {}
        if isinstance(report_views, dict):
            for name, view in report_views.items():
                if not isinstance(view, dict):
                    continue
                compact_views[name] = {
                    key: value
                    for key, value in view.items()
                    if key not in {"issues", "issues_by_severity"}
                }

        raw_metadata = report.get("metadata")
        metadata: Dict[str, Any] = raw_metadata if isinstance(raw_metadata, dict) else {}
        return {
            "entry_function": report.get("entry_function"),
            "overall_verdict": report.get("overall_verdict"),
            "finding_status": report.get("finding_status"),
            "completeness": report.get("completeness"),
            "scan_outcome": report.get("scan_outcome"),
            "summary": report.get("summary"),
            "report_views": compact_views,
            "run_manifest": report.get("run_manifest"),
            "needs_review_governance": report.get("needs_review_governance"),
            "metadata": {
                "report_view_summary": metadata.get("report_view_summary"),
            },
        }

    def selected_view_payload(self, path: str) -> Dict[str, Any]:
        from urllib.parse import urlparse

        report = self.load_report()
        view = selected_report_view(path)
        query = parse_qs(urlparse(path).query)
        full_report = str((query.get("full_report") or [""])[0]).lower() in {
            "1",
            "true",
            "yes",
        }
        findings = findings_for_view(report, view)
        return {
            "report": report if full_report else self._lightweight_report(report),
            "findings": findings if full_report else self._compact_findings(findings),
            "view": view,
            "views": report_view_summary(report),
        }

    @classmethod
    def _compact_findings(cls, findings: list[Any]) -> list[Dict[str, Any]]:
        return [cls._compact_issue(issue) for issue in findings if isinstance(issue, dict)]

    @classmethod
    def _compact_issue(cls, issue: Dict[str, Any], depth: int = 0) -> Dict[str, Any]:
        compact: Dict[str, Any] = {}
        truncated_fields: list[str] = []

        for key in DASHBOARD_ISSUE_FIELDS:
            if key not in issue:
                continue
            value = issue[key]
            if isinstance(value, str):
                compact_value = cls._compact_issue_text(key, value, issue)
                if compact_value != value:
                    truncated_fields.append(key)
                compact[key] = compact_value
            else:
                compact[key] = cls._compact_value(value, depth=1)

        for key in DASHBOARD_ARRAY_FIELDS:
            value = issue.get(key)
            if isinstance(value, list):
                compact[key] = cls._compact_value(value, depth=1)

        evidence_pack = issue.get("evidence_pack")
        if isinstance(evidence_pack, dict):
            compact_pack = {
                key: cls._compact_value(evidence_pack[key], depth=1)
                for key in DASHBOARD_EVIDENCE_PACK_FIELDS
                if key in evidence_pack
            }
            if compact_pack:
                compact["evidence_pack"] = compact_pack

        related = issue.get("related_needs_review_observations")
        if isinstance(related, list) and depth < 1:
            compact["related_needs_review_observations"] = [
                cls._compact_issue(item, depth=depth + 1)
                for item in related[:6]
                if isinstance(item, dict)
            ]
            if len(related) > 6:
                compact["related_needs_review_omitted"] = len(related) - 6

        if truncated_fields:
            compact["_truncated_fields"] = truncated_fields
        return compact

    @classmethod
    def _compact_issue_text(cls, key: str, value: str, issue: Dict[str, Any]) -> str:
        if key == "dedup_key" and len(value) > DASHBOARD_TEXT_LIMITS["dedup_key"]:
            digest = hashlib.sha256(value.encode("utf-8")).hexdigest()[:24]
            return f"sha256:{digest}"
        if key in {"category", "normalized_category"} and len(value) > DASHBOARD_TEXT_LIMITS[key]:
            fallback = issue.get("subcategory") or issue.get("defect_class") or "unknown"
            return cls._compact_text(str(fallback), DASHBOARD_TEXT_LIMITS[key])
        return cls._compact_text(value, DASHBOARD_TEXT_LIMITS.get(key, 2000))

    @classmethod
    def _compact_value(cls, value: Any, depth: int = 0) -> Any:
        if isinstance(value, str):
            return cls._compact_text(value, 1200 if depth else 4000)
        if isinstance(value, (int, float, bool)) or value is None:
            return value
        if isinstance(value, list):
            max_items = 8 if depth > 0 else 16
            list_result = [cls._compact_value(item, depth + 1) for item in value[:max_items]]
            if len(value) > max_items:
                list_result.append(f"... [truncated {len(value) - max_items} items]")
            return list_result
        if isinstance(value, dict):
            if depth >= 3:
                return cls._compact_text(json.dumps(value, ensure_ascii=False, default=str), 1200)
            entries = list(value.items())[:40]
            dict_result = {str(key): cls._compact_value(item, depth + 1) for key, item in entries}
            omitted = len(value) - len(entries)
            if omitted > 0:
                dict_result["_truncated_keys"] = omitted
            return dict_result
        return cls._compact_text(str(value), 1200)

    @staticmethod
    def _compact_text(value: str, limit: int) -> str:
        if len(value) <= limit:
            return value
        digest = hashlib.sha256(value.encode("utf-8")).hexdigest()[:12]
        return (
            f"{value[:limit].rstrip()}... [truncated {len(value) - limit} chars, sha256:{digest}]"
        )

    def persist_validation_feedback(self, updates: list[Any]) -> Dict[str, Any]:
        store = self.user_config_store
        if not store:
            return {
                "db_available": False,
                "db_path": "",
                "baseline_upserts": 0,
                "suppression_upserts": 0,
            }
        result: Dict[str, Any] = {
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
        update_map = {
            issue_key(issue): normalize_validation(issue)
            for issue in updates
            if isinstance(issue, dict)
        }

        def update_issue(issue: Dict[str, Any]) -> None:
            if not isinstance(issue, dict):
                return
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
                    for issues in view.get("issues_by_severity", {}).values():
                        for issue in issues:
                            update_issue(issue)
                    view_issues = [
                        issue for issue in view.get("issues", []) if isinstance(issue, dict)
                    ]
                    view["issue_count"] = len(view_issues)
                    view["issues_by_severity"] = group_by_severity(view_issues)

            with_review = report_views.get(WITH_NEEDS_REVIEW_REPORT_VIEW)
            if isinstance(with_review, dict):
                with_review_issues = [
                    issue for issue in with_review.get("issues", []) if isinstance(issue, dict)
                ]
                report["issues_with_needs_review"] = with_review_issues
                report["issues_by_severity_with_needs_review"] = group_by_severity(
                    with_review_issues
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

        result: Dict[str, Any] = {
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
            final_path.write_text(
                json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8"
            )
            result["final_reports_updated"] += 1
            result["issues_updated"] += changed_count
        return result

    def save_validation_feedback(
        self,
        updates: list[Any],
        *,
        persist_snapshots: bool = True,
        save_scope: str = "full",
    ) -> Dict[str, Any]:
        report = self.load_report()
        self.apply_validation_updates(report, updates)
        if persist_snapshots:
            snapshot_result = self.apply_validation_to_snapshots(updates)
        else:
            snapshot_result = {
                "snapshot_available": bool(self.snapshot_store),
                "snapshot_dir": str(getattr(self.snapshot_store, "snapshot_dir", "")),
                "final_reports_scanned": 0,
                "final_reports_updated": 0,
                "issues_updated": 0,
                "skipped": True,
                "skip_reason": "persist_snapshots=false",
            }
        feedback_result = self.persist_validation_feedback(updates)
        self.save_report(report)
        return {
            "success": True,
            "save_scope": save_scope,
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
        issue_key_part(issue.get("id")),
        issue_key_part(issue.get("function")),
        issue_key_part(issue.get("location")),
        issue_key_part(issue.get("subcategory")),
    )


def issue_key_part(value: Any) -> Any:
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    try:
        return json.dumps(value, ensure_ascii=False, sort_keys=True, default=str)
    except TypeError:
        return str(value)


def normalize_validation(issue: Dict[str, Any]) -> tuple[str, Any]:
    status = issue.get("validation_status")
    if status not in ALLOWED_VALIDATION_STATUSES:
        status = "pending"
    reasoning = issue.get("validation_reasoning")
    return status, reasoning


def feedback_category(issue: Dict[str, Any]) -> str:
    return str(issue.get("defect_class") or issue.get("subcategory") or issue.get("category") or "")


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
