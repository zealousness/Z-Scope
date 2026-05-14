import http.server
import socketserver
import json
from pathlib import Path
from typing import Any, Dict

PORT = 8000
WEB_DIR = Path(__file__).parent / "static"
REPORT_FILENAME = "zscope_batch_report.json"
CONFIG_FILENAME = "zscope.yaml"
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
        return
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

def apply_validation_to_snapshots(updates):
    global _snapshot_store
    if not _snapshot_store:
        return
        
    func_updates = {}
    for issue in updates:
        func = issue.get("function")
        if func:
            func_updates.setdefault(func, []).append(issue)
            
    for func, issues_to_update in func_updates.items():
        file_path = None
        for issue in issues_to_update:
            loc = issue.get("location", "")
            if ":" in loc:
                file_path = loc.split(":")[0]
                break
                
        old_report = _snapshot_store.load_final_report(func, file_path)
        if old_report:
            update_map = {issue_key(iss): normalize_validation(iss) for iss in issues_to_update}
            changed = False
            for old_issue in old_report.get("issues", []):
                key = (old_issue.get("id"), old_issue.get("function"), old_issue.get("location"), old_issue.get("subcategory"))
                if key in update_map:
                    status, reasoning = update_map[key]
                    old_issue["validation_status"] = status
                    old_issue["validation_reasoning"] = reasoning
                    # Tag user-rejected issues so the reconciler can auto-suppress them in future scans
                    if status == "rejected":
                        old_issue["rejection_source"] = "user"
                    changed = True
            
            if changed:
                fake_location = f"{file_path}:0" if file_path else "unknown:0"
                _snapshot_store.save_final_report(func, old_report, fake_location)


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
        if self.path == "/api/findings":
            report = load_report()
            findings = report.get("issues")
            if findings is None or (isinstance(findings, list) and not findings and isinstance(report.get("findings"), list) and report.get("findings")):
                findings = report.get("findings", [])
            self._send_json({"report": report, "findings": findings})
        elif self.path == "/api/config":
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
        elif self.path == "/api/cpg_status":
            self._handle_cpg_status()
        elif self.path == "/api/user_config/warnings":
            self._handle_get_warnings()
        elif self.path.startswith("/api/user_config/"):
            self._handle_user_config_get()
        else:
            super().do_GET()

    def do_POST(self):
        content_length = int(self.headers.get("Content-Length", 0))
        post_data = self.rfile.read(content_length)
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
        elif self.path == "/api/save_findings":
            report = load_report()
            updates = payload.get("issues", [])
            if not isinstance(updates, list):
                self._send_json({"success": False, "error": "Issues must be a list"}, status=400)
                return
            apply_validation_updates(report, updates)
            apply_validation_to_snapshots(updates)
            persist_validation_feedback(updates)
            save_report(report)
            self._send_json({"success": True})
        elif self.path == "/api/build_cpg":
            self._handle_build_cpg(payload)
        elif self.path == "/api/clear_warnings":
            self._handle_clear_warnings()
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

    # ── User config CRUD handlers ──

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
