import http.server
import socketserver
import json
from pathlib import Path
from typing import Any, Dict
from urllib.parse import parse_qs, urlparse

from .._version import __version__
from ..config.config import yaml
from ..core.report_views import (
    DEFAULT_REPORT_VIEW,
    WITH_NEEDS_REVIEW_REPORT_VIEW,
    build_report_views,
    findings_for_view,
    report_view_summary,
)
from ..config.user_config_workbook import SHEET_HEADERS

PORT = 8000
WEB_DIR = Path(__file__).parent / "static"
REPORT_FILENAME = "zscope_batch_report.json"
CONFIG_FILENAME = "zscope.yaml"
USER_CONFIG_WORKBOOK_NAME = "user_config.xlsx"
ALLOWED_VALIDATION_STATUSES = {
    "validated",
    "needs_review",
    "uncertain",
    "unvalidated",
    "pending",
    "rejected",
}

# Shared state set by run_server()
_user_config_store = None
_code_index = None
_project_config = None
_snapshot_store = None


def _empty_report() -> Dict[str, Any]:
    return {
        "issues": [],
        "issues_by_severity": {"critical": [], "high": [], "medium": [], "low": []},
    }


def _strip_json_code_fence(content: str) -> str:
    """Allow loading reports accidentally wrapped by markdown code fences."""
    stripped = content.strip()
    if not stripped.startswith("```"):
        return stripped

    lines = stripped.splitlines()
    if not lines:
        return stripped

    if lines[0].startswith("```"):
        lines = lines[1:]
    if lines and lines[-1].strip() == "```":
        lines = lines[:-1]
    return "\n".join(lines).strip()


def load_report():
    report_path = Path(REPORT_FILENAME)
    if not report_path.exists():
        return _empty_report()

    raw_content = report_path.read_text(encoding="utf-8", errors="ignore")
    sanitized = _strip_json_code_fence(raw_content)
    if not sanitized:
        return _empty_report()

    try:
        return json.loads(sanitized)
    except json.JSONDecodeError as exc:
        print(f"Warning: failed to parse report JSON: {exc}")
        return _empty_report()


def save_report(report):
    report_path = Path(REPORT_FILENAME)
    with report_path.open("w", encoding="utf-8") as f:
        json.dump(report, f, ensure_ascii=False, indent=2)


def _config_path() -> Path:
    return Path(CONFIG_FILENAME)


def load_config_document() -> Dict[str, Any]:
    path = _config_path()
    if not path.exists():
        return {}
    if yaml is None:
        raise RuntimeError("PyYAML is required for structured config editing")
    content = path.read_text(encoding="utf-8")
    data = yaml.safe_load(content) if content.strip() else {}
    return data if isinstance(data, dict) else {}


def save_config_document(data: Dict[str, Any]) -> None:
    if yaml is None:
        raise RuntimeError("PyYAML is required for structured config editing")
    header = (
        "# Z-SCOPE 配置文件\n"
        "# 本文件由 Web UI 结构化配置编辑器生成。\n"
        "# 字段说明请参考仓库根目录 zscope.yaml 模板中的注释。\n\n"
    )
    text = yaml.safe_dump(data, allow_unicode=True, sort_keys=False)
    _config_path().write_text(header + text, encoding="utf-8")


def structured_config_payload() -> Dict[str, Any]:
    data = load_config_document()
    return {"config": data}


def _workbook_path(user_config_store) -> Path | None:
    if not user_config_store:
        return None
    workbook = getattr(user_config_store, "workbook", None)
    path = getattr(workbook, "path", None)
    return Path(path) if path else None


def workbook_payload(user_config_store) -> Dict[str, Any]:
    if not user_config_store:
        return {
            "headers": SHEET_HEADERS,
            "rows": {name: [] for name in SHEET_HEADERS},
            "sheets": [
                {"name": name, "headers": headers, "rows": []}
                for name, headers in SHEET_HEADERS.items()
            ],
        }
    rows = user_config_store.workbook.read_rows()
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


def workbook_rows_from_payload(payload: Dict[str, Any]) -> Dict[str, Any]:
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


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _source_search_roots() -> list[Path]:
    roots: list[Path] = []
    for candidate in [Path.cwd(), _repo_root(), _repo_root() / "test" / "range"]:
        roots.append(candidate)
    if _project_config:
        for attr in ("project_root", "source_root"):
            value = getattr(_project_config, attr, None)
            if value:
                roots.append(Path(value))
    for parent in list(Path.cwd().parents)[:5]:
        roots.append(parent)
        if parent.name == "benchmark_runs":
            roots.append(parent.parent)

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


def _is_within(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
        return True
    except ValueError:
        return False
    except OSError:
        return False


def resolve_source_file(raw_path: str) -> Path | None:
    if not raw_path:
        return None
    normalized = raw_path.replace("\\", "/").strip().lstrip("/")
    requested = Path(normalized)
    roots = _source_search_roots()
    candidates: list[Path] = []
    if requested.is_absolute():
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
        if any(_is_within(resolved, root) for root in roots):
            return resolved
    return None


def selected_report_view(path: str) -> str:
    parsed = urlparse(path)
    query = parse_qs(parsed.query)
    view = str((query.get("view") or [DEFAULT_REPORT_VIEW])[0] or DEFAULT_REPORT_VIEW)
    if view not in {DEFAULT_REPORT_VIEW, WITH_NEEDS_REVIEW_REPORT_VIEW}:
        view = DEFAULT_REPORT_VIEW
    return view


def issue_key(issue):
    return (
        issue.get("id"),
        issue.get("function"),
        issue.get("location"),
        issue.get("subcategory"),
    )


def normalize_validation(issue):
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


def persist_validation_feedback(updates):
    global _user_config_store
    if not _user_config_store:
        return {
            "db_available": False,
            "db_path": "",
            "baseline_upserts": 0,
            "suppression_upserts": 0,
        }
    result = {
        "db_available": True,
        "db_path": str(getattr(_user_config_store, "db_path", "")),
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
                _user_config_store.upsert_finding_baseline(
                    dedup_key,
                    baseline_status,
                    issue,
                )
                result["baseline_upserts"] += 1
        if status == "rejected":
            _user_config_store.add_false_positive_suppression(
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


def apply_validation_updates(report, updates):
    update_map = {issue_key(issue): normalize_validation(issue) for issue in updates}

    def update_issue(issue):
        key = issue_key(issue)
        if key in update_map:
            status, reasoning = update_map[key]
            issue["validation_status"] = status
            issue["validation_reasoning"] = reasoning

    # Legacy report shape
    for issue in report.get("issues", []):
        update_issue(issue)

    for issues in report.get("issues_by_severity", {}).values():
        for issue in issues:
            update_issue(issue)

    # Current report shape
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

    if isinstance(report_views, dict):
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

def apply_validation_to_snapshots(updates):
    global _snapshot_store
    if not _snapshot_store:
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

    def apply_to_issue(target):
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

    def apply_to_issue_list(items):
        changed = 0
        if isinstance(items, list):
            for item in items:
                if apply_to_issue(item):
                    changed += 1
        return changed

    def apply_to_report(report):
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
        "snapshot_dir": str(getattr(_snapshot_store, "snapshot_dir", "")),
        "final_reports_scanned": 0,
        "final_reports_updated": 0,
        "issues_updated": 0,
    }
    snapshot_dir = getattr(_snapshot_store, "snapshot_dir", None)
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
            json.dumps(report, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        result["final_reports_updated"] += 1
        result["issues_updated"] += changed_count
    return result


class ZScopeHandler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(WEB_DIR), **kwargs)

    def _send_json(self, payload, status=200):
        self.send_response(status)
        self.send_header("Content-type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(payload).encode("utf-8"))

    def end_headers(self):
        # Avoid stale dashboard cache causing old broken JS to persist in browser.
        self.send_header("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
        self.send_header("Pragma", "no-cache")
        self.send_header("Expires", "0")
        super().end_headers()

    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path == "/api/findings":
            report = load_report()
            view = selected_report_view(self.path)
            findings = findings_for_view(report, view)
            self._send_json(
                {
                    "report": report,
                    "findings": findings,
                    "view": view,
                    "views": report_view_summary(report),
                }
            )
        elif parsed.path == "/api/version":
            self._send_json({"version": __version__, "display": f"v{__version__}"})
        elif parsed.path == "/api/config/structured":
            try:
                self._send_json(structured_config_payload())
            except Exception as exc:
                self._send_json({"error": str(exc), "config": {}}, status=500)
        elif parsed.path == "/api/config":
            config_path = Path(CONFIG_FILENAME)
            if config_path.exists():
                try:
                    content = config_path.read_text(encoding="utf-8")
                except OSError as exc:
                    self._send_json({"content": "", "error": str(exc)}, status=500)
                    return
                self._send_json({"content": content})
            else:
                self._send_json({"content": ""})
        elif parsed.path == "/api/cpg_status":
            self._handle_cpg_status()
        elif parsed.path == "/api/source_snippet":
            self._handle_source_snippet(parsed)
        elif parsed.path == "/api/user_config/warnings":
            self._handle_get_warnings()
        elif parsed.path == "/api/user_config/workbook/download":
            self._handle_user_config_workbook_download()
        elif parsed.path == "/api/user_config/workbook":
            self._handle_user_config_workbook_get()
        elif parsed.path.startswith("/api/user_config/"):
            self._handle_user_config_get()
        else:
            super().do_GET()

    def do_POST(self):
        content_length = int(self.headers.get("Content-Length", 0))
        post_data = self.rfile.read(content_length)
        if self.path == "/api/user_config/workbook/import":
            self._handle_user_config_workbook_import(post_data)
            return
        try:
            payload = json.loads(post_data or b"{}")
        except json.JSONDecodeError:
            self._send_json({"success": False, "error": "Invalid JSON"}, status=400)
            return

        if self.path == "/api/config":
            content = payload.get("content", "")
            config_path = Path(CONFIG_FILENAME)
            config_path.write_text(content, encoding="utf-8")
            self._send_json({"success": True, "path": str(config_path)})
        elif self.path == "/api/config/structured":
            data = payload.get("config")
            if not isinstance(data, dict):
                self._send_json({"success": False, "error": "config must be an object"}, status=400)
                return
            try:
                save_config_document(data)
            except Exception as exc:
                self._send_json({"success": False, "error": str(exc)}, status=500)
                return
            self._send_json({"success": True, **structured_config_payload()})
        elif self.path == "/api/save_findings":
            try:
                report = load_report()
                updates = payload.get("issues", [])
                if not isinstance(updates, list):
                    self._send_json({"success": False, "error": "Issues must be a list"}, status=400)
                    return
                apply_validation_updates(report, updates)
                snapshot_result = apply_validation_to_snapshots(updates)
                feedback_result = persist_validation_feedback(updates)
                save_report(report)
            except Exception as exc:
                self._send_json({"success": False, "error": str(exc)}, status=500)
                return
            self._send_json(
                {
                    "success": True,
                    "saved_to_report": True,
                    "db_persisted": bool(feedback_result.get("db_available")),
                    "state_db_persisted": bool(feedback_result.get("db_available")),
                    "feedback_persistence": feedback_result,
                    "snapshot_persistence": snapshot_result,
                }
            )
        elif self.path == "/api/build_cpg":
            self._handle_build_cpg(payload)
        elif self.path == "/api/clear_warnings":
            self._handle_clear_warnings()
        elif self.path == "/api/user_config/workbook":
            self._handle_user_config_workbook_post(payload)
        elif self.path.startswith("/api/user_config/"):
            self._handle_user_config_post(payload)
        else:
            self.send_error(404)

    def do_DELETE(self):
        content_length = int(self.headers.get("Content-Length", 0))
        post_data = self.rfile.read(content_length) if content_length else b"{}"
        try:
            payload = json.loads(post_data or b"{}")
        except json.JSONDecodeError:
            payload = {}
        if self.path.startswith("/api/user_config/"):
            self._handle_user_config_delete(payload)
        else:
            self.send_error(404)

    # ── CPG handlers ──

    def _handle_cpg_status(self):
        global _code_index
        if not _code_index or not _code_index.backend:
            self._send_json({"status": "unavailable", "error": None})
            return
        backend = _code_index.backend
        status = backend.status()
        error = None
        # Joern 后端特有的 error 属性
        if hasattr(backend, 'joern_client'):
            error = backend.joern_client.cpg_error
        self._send_json({"status": status, "error": error})

    def _handle_build_cpg(self, payload):
        global _code_index, _project_config
        if not _code_index or not _code_index.backend:
            self._send_json({"success": False, "error": "Backend not available"}, status=400)
            return
        if not _project_config:
            self._send_json({"success": False, "error": "Project config not available"}, status=400)
            return
        backend = _code_index.backend
        source_path = str(_project_config.source_root)
        project_root = str(_project_config.project_root)
        cc_path = str(_project_config.compile_commands_path) if _project_config.compile_commands_path else None
        # Joern 后端支持异步构建
        from ..retrieval.joern_backend import JoernBackend
        if isinstance(backend, JoernBackend):
            backend.joern_client.import_cpg_async(source_path, project_root, cc_path)
            self._send_json({"success": True, "status": "building"})
        else:
            self._send_json({"success": False, "error": "Current backend does not support async CPG build"}, status=400)

    def _handle_clear_warnings(self):
        global _user_config_store
        if not _user_config_store:
            self._send_json({"success": False, "error": "Config store not available"}, status=400)
            return
        _user_config_store.clear_config_warnings()
        self._send_json({"success": True})

    def _handle_get_warnings(self):
        global _user_config_store
        if not _user_config_store:
            self._send_json({"items": []})
            return
        self._send_json({"items": _user_config_store.list_config_warnings()})

    def _handle_source_snippet(self, parsed):
        query = parse_qs(parsed.query)
        raw_path = str((query.get("path") or [""])[0] or "")
        source_path = resolve_source_file(raw_path)
        if not source_path:
            self._send_json(
                {"success": False, "error": f"source file not found: {raw_path}"},
                status=404,
            )
            return
        try:
            start = int((query.get("start") or ["1"])[0] or "1")
            end = int((query.get("end") or [str(start)])[0] or start)
            context = int((query.get("context") or ["6"])[0] or "6")
        except ValueError:
            self._send_json({"success": False, "error": "invalid line range"}, status=400)
            return
        try:
            raw_lines = source_path.read_text(encoding="utf-8", errors="ignore").splitlines()
        except OSError as exc:
            self._send_json({"success": False, "error": str(exc)}, status=500)
            return
        if not raw_lines:
            self._send_json(
                {"success": True, "path": raw_path, "resolved_path": str(source_path), "lines": []}
            )
            return
        start = max(1, start)
        end = max(start, end)
        snippet_start = max(1, start - max(context, 0))
        snippet_end = min(len(raw_lines), end + max(context, 0))
        lines = [
            {"no": number, "text": raw_lines[number - 1]}
            for number in range(snippet_start, snippet_end + 1)
        ]
        self._send_json(
            {
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
        )

    # ── User config CRUD handlers ──

    def _handle_user_config_workbook_get(self):
        global _user_config_store
        self._send_json(workbook_payload(_user_config_store))

    def _handle_user_config_workbook_download(self):
        global _user_config_store
        path = _workbook_path(_user_config_store)
        if path is None:
            self._send_json({"success": False, "error": "Config store not available"}, status=400)
            return
        if not path.exists():
            _user_config_store.workbook.write_rows({name: [] for name in SHEET_HEADERS})
        try:
            data = path.read_bytes()
        except OSError as exc:
            self._send_json({"success": False, "error": str(exc)}, status=500)
            return
        self.send_response(200)
        self.send_header(
            "Content-type",
            "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        )
        self.send_header("Content-Disposition", f'attachment; filename="{USER_CONFIG_WORKBOOK_NAME}"')
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _handle_user_config_workbook_import(self, data: bytes):
        global _user_config_store
        if not _user_config_store:
            self._send_json({"success": False, "error": "Config store not available"}, status=400)
            return
        if not data:
            self._send_json({"success": False, "error": "Uploaded workbook is empty"}, status=400)
            return
        path = _workbook_path(_user_config_store)
        if path is None:
            self._send_json({"success": False, "error": "Workbook path not available"}, status=400)
            return
        tmp_path = path.with_suffix(".upload.tmp.xlsx")
        try:
            tmp_path.parent.mkdir(parents=True, exist_ok=True)
            tmp_path.write_bytes(data)
            rows = type(_user_config_store.workbook)(tmp_path).read_rows()
            _user_config_store.workbook.write_rows(rows)
            tmp_path.unlink(missing_ok=True)
        except Exception as exc:
            try:
                tmp_path.unlink(missing_ok=True)
            except OSError:
                pass
            self._send_json({"success": False, "error": str(exc)}, status=400)
            return
        self._send_json({"success": True, **workbook_payload(_user_config_store)})

    def _handle_user_config_workbook_post(self, payload):
        global _user_config_store
        if not _user_config_store:
            self._send_json({"success": False, "error": "Config store not available"}, status=400)
            return
        try:
            rows = workbook_rows_from_payload(payload)
            _user_config_store.workbook.write_rows(rows)
        except ValueError as exc:
            self._send_json({"success": False, "error": str(exc)}, status=400)
            return
        except OSError as exc:
            self._send_json({"success": False, "error": str(exc)}, status=500)
            return
        self._send_json({"success": True, **workbook_payload(_user_config_store)})

    def _get_config_resource(self):
        """Extract resource name from /api/user_config/<resource>."""
        parts = self.path.strip("/").split("/")
        return parts[2] if len(parts) >= 3 else ""

    def _handle_user_config_get(self):
        global _user_config_store
        if not _user_config_store:
            self._send_json({"items": []})
            return
        resource = self._get_config_resource()
        dispatch = {
            "external_functions": _user_config_store.list_external_functions,
            "paired_functions": _user_config_store.list_paired_functions,
            "pointer_targets": _user_config_store.get_pointer_targets,
            "function_intents": _user_config_store.list_function_intents,
        }
        fn = dispatch.get(resource)
        if fn:
            self._send_json({"items": fn()})
        else:
            self.send_error(404)

    def _handle_user_config_post(self, payload):
        global _user_config_store
        if not _user_config_store:
            self._send_json({"success": False, "error": "Config store not available"}, status=400)
            return
        resource = self._get_config_resource()
        try:
            if resource == "external_functions":
                _user_config_store.upsert_external_function(
                    payload["func_name"], payload.get("description", ""),
                    library=payload.get("library", ""),
                    memory_behavior=payload.get("memory_behavior"),
                    concurrency_behavior=payload.get("concurrency_behavior"),
                    return_semantics=payload.get("return_semantics", ""),
                )
            elif resource == "paired_functions":
                _user_config_store.upsert_paired_function(
                    payload["category"], payload["acquire_func"],
                    payload["release_func"], payload.get("description", ""),
                )
            elif resource == "pointer_targets":
                _user_config_store.upsert_pointer_target(
                    payload["pointer_location"], payload.get("scope", "local"),
                    payload.get("target_functions", []), payload.get("context", ""),
                )
            elif resource == "function_intents":
                _user_config_store.upsert_function_intent(
                    payload["func_name"], payload.get("file_path", ""),
                    caller_constraints=payload.get("caller_constraints"),
                    concurrency_group=payload.get("concurrency_group", ""),
                    concurrent_with=payload.get("concurrent_with"),
                    notes=payload.get("notes", ""),
                )
            else:
                self.send_error(404)
                return
            self._send_json({"success": True})
        except KeyError as e:
            self._send_json({"success": False, "error": f"Missing field: {e}"}, status=400)

    def _handle_user_config_delete(self, payload):
        global _user_config_store
        if not _user_config_store:
            self._send_json({"success": False, "error": "Config store not available"}, status=400)
            return
        resource = self._get_config_resource()
        try:
            if resource == "external_functions":
                _user_config_store.delete_external_function(payload["func_name"])
            elif resource == "paired_functions":
                _user_config_store.delete_paired_function(payload["id"])
            elif resource == "pointer_targets":
                _user_config_store.delete_pointer_target(payload["id"])
            elif resource == "function_intents":
                _user_config_store.delete_function_intent(
                    payload["func_name"], payload.get("file_path", ""),
                )
            else:
                self.send_error(404)
                return
            self._send_json({"success": True})
        except KeyError as e:
            self._send_json({"success": False, "error": f"Missing field: {e}"}, status=400)


def run_server(code_index=None, user_config_store=None, project_config=None, snapshot_store=None):
    global _user_config_store, _code_index, _project_config, _snapshot_store
    _user_config_store = user_config_store
    _code_index = code_index
    _project_config = project_config
    _snapshot_store = snapshot_store
    WEB_DIR.mkdir(parents=True, exist_ok=True)

    with socketserver.TCPServer(("", PORT), ZScopeHandler) as httpd:
        print(f"Z-SCOPE Dashboard available at http://localhost:{PORT}")
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\nShutting down server...")
            httpd.server_close()


if __name__ == "__main__":
    run_server()
