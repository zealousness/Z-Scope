import http.server
import json
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from .._version import __version__
from .dashboard_server import DashboardHttpServer
from . import services as web_services
from ..orchestration.scan_request import ScanRequestError, ScanRequestService

PORT = 8000
WEB_DIR = Path(__file__).parent / "static"
REPORT_FILENAME = "zscope_batch_report.json"
CONFIG_FILENAME = "zscope.yaml"
USER_CONFIG_WORKBOOK_NAME = "user_config.xlsx"

_config_service = web_services.ConfigService()
_rule_service = web_services.RuleService()
_workbook_service = web_services.WorkbookService()
_user_config_service = web_services.UserConfigService()
_cpg_service = web_services.CpgService()
_source_snippet_service = web_services.SourceSnippetService()
_report_feedback_service = web_services.ReportFeedbackService()
_scan_request_service = None


def persist_validation_feedback(updates):
    return _report_feedback_service.persist_validation_feedback(updates)


class ZScopeHandler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(WEB_DIR), **kwargs)

    def _send_json(self, payload, status=200):
        body = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            return

    def end_headers(self):
        # Avoid stale dashboard cache causing old broken JS to persist in browser.
        self.send_header("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
        self.send_header("Pragma", "no-cache")
        self.send_header("Expires", "0")
        super().end_headers()

    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path == "/api/findings":
            self._send_json(_report_feedback_service.selected_view_payload(self.path))
        elif parsed.path == "/api/version":
            self._send_json({"version": __version__, "display": f"v{__version__}"})
        elif parsed.path == "/api/config/structured":
            try:
                self._send_json(_config_service.structured_payload())
            except Exception as exc:
                self._send_json({"error": str(exc), "config": {}}, status=400)
        elif parsed.path == "/api/config":
            try:
                self._send_json(_config_service.read_text())
            except OSError as exc:
                self._send_json({"content": "", "error": str(exc)}, status=500)
        elif parsed.path == "/api/scan/status":
            if _scan_request_service is None:
                self._send_json({"error": "scan service is unavailable"}, status=503)
                return
            try:
                scan_id = (parse_qs(parsed.query).get("scan_id") or [""])[0]
                self._send_json(_scan_request_service.status(scan_id))
            except ScanRequestError as exc:
                self._send_json({"error": str(exc)}, status=404)
        elif parsed.path == "/api/rules":
            try:
                self._send_json(_rule_service.payload(parsed.query))
            except Exception as exc:
                self._send_json({"error": str(exc), "rules": []}, status=400)
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
            try:
                response = _config_service.write_text(content)
            except Exception as exc:
                self._send_json({"success": False, "error": str(exc)}, status=400)
                return
            self._send_json(response)
        elif self.path == "/api/config/structured":
            data = payload.get("config")
            if not isinstance(data, dict):
                self._send_json({"success": False, "error": "config must be an object"}, status=400)
                return
            try:
                _config_service.save_document(data)
            except Exception as exc:
                self._send_json({"success": False, "error": str(exc)}, status=400)
                return
            self._send_json({"success": True, **_config_service.structured_payload()})
        elif self.path == "/api/save_findings":
            try:
                updates = payload.get("issues", [])
                if not isinstance(updates, list):
                    self._send_json(
                        {"success": False, "error": "Issues must be a list"}, status=400
                    )
                    return
                response_payload = _report_feedback_service.save_validation_feedback(
                    updates,
                    persist_snapshots=payload.get("persist_snapshots", True) is not False,
                    save_scope=str(payload.get("save_scope") or "full"),
                )
            except Exception as exc:
                self._send_json({"success": False, "error": str(exc)}, status=500)
                return
            self._send_json(response_payload)
        elif self.path == "/api/scan":
            if _scan_request_service is None:
                self._send_json(
                    {"success": False, "error": "scan service is unavailable"}, status=503
                )
                return
            if not isinstance(payload, dict):
                self._send_json(
                    {"success": False, "error": "request must be an object"}, status=400
                )
                return
            unknown = sorted(set(payload) - {"scan_depth"})
            if unknown:
                self._send_json(
                    {"success": False, "error": f"unsupported scan request fields: {unknown}"},
                    status=400,
                )
                return
            try:
                response = _scan_request_service.start(
                    scan_depth=payload.get("scan_depth"),
                )
            except (ScanRequestError, ValueError) as exc:
                self._send_json({"success": False, "error": str(exc)}, status=400)
                return
            self._send_json({"success": True, **response}, status=202)
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
        self._send_json(_cpg_service.status_payload())

    def _handle_build_cpg(self, payload):
        status, response_payload = _cpg_service.build()
        self._send_json(response_payload, status=status)

    def _handle_clear_warnings(self):
        status, payload = _user_config_service.clear_warnings()
        self._send_json(payload, status=status)

    def _handle_get_warnings(self):
        self._send_json(_user_config_service.warnings_payload())

    def _handle_source_snippet(self, parsed):
        status, payload = _source_snippet_service.snippet_payload(parsed.query)
        self._send_json(payload, status=status)
        return

    # ── User config CRUD handlers ──

    def _handle_user_config_workbook_get(self):
        self._send_json(_workbook_service.payload())

    def _handle_user_config_workbook_download(self):
        try:
            data = _workbook_service.download_bytes()
        except RuntimeError as exc:
            self._send_json({"success": False, "error": str(exc)}, status=400)
            return
        except OSError as exc:
            self._send_json({"success": False, "error": str(exc)}, status=500)
            return
        self.send_response(200)
        self.send_header(
            "Content-type",
            "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        )
        self.send_header(
            "Content-Disposition", f'attachment; filename="{USER_CONFIG_WORKBOOK_NAME}"'
        )
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _handle_user_config_workbook_import(self, data: bytes):
        try:
            payload = _workbook_service.import_bytes(data)
        except ValueError as exc:
            self._send_json({"success": False, "error": str(exc)}, status=400)
            return
        except Exception as exc:
            self._send_json({"success": False, "error": str(exc)}, status=400)
            return
        self._send_json({"success": True, **payload})
        return

    def _handle_user_config_workbook_post(self, payload):
        try:
            workbook_payload_data = _workbook_service.write_payload(payload)
        except ValueError as exc:
            self._send_json({"success": False, "error": str(exc)}, status=400)
            return
        except OSError as exc:
            self._send_json({"success": False, "error": str(exc)}, status=500)
            return
        except RuntimeError as exc:
            self._send_json({"success": False, "error": str(exc)}, status=400)
            return
        self._send_json({"success": True, **workbook_payload_data})
        return

    def _get_config_resource(self):
        """Extract resource name from /api/user_config/<resource>."""
        parts = self.path.strip("/").split("/")
        return parts[2] if len(parts) >= 3 else ""

    def _handle_user_config_get(self):
        status, payload = _user_config_service.list_resource(self._get_config_resource())
        if status == 404:
            self.send_error(404)
            return
        self._send_json(payload, status=status)

    def _handle_user_config_post(self, payload):
        status, response_payload = _user_config_service.upsert_resource(
            self._get_config_resource(),
            payload,
        )
        if status == 404:
            self.send_error(404)
            return
        self._send_json(response_payload, status=status)

    def _handle_user_config_delete(self, payload):
        status, response_payload = _user_config_service.delete_resource(
            self._get_config_resource(),
            payload,
        )
        if status == 404:
            self.send_error(404)
            return
        self._send_json(response_payload, status=status)


def run_server(
    code_index=None,
    user_config_store=None,
    project_config=None,
    snapshot_store=None,
    config_path=None,
    scan_depth=None,
    host="0.0.0.0",
    port=PORT,
):
    global _config_service, _rule_service, _workbook_service, _user_config_service, _cpg_service, _source_snippet_service, _report_feedback_service, _scan_request_service
    config_file_path = (
        Path(config_path).resolve() if config_path else Path(CONFIG_FILENAME).resolve()
    )
    _config_service = web_services.ConfigService(
        config_file_path,
        default_name=CONFIG_FILENAME,
        scan_depth=scan_depth,
    )
    _rule_service = web_services.RuleService(config_file_path, default_name=CONFIG_FILENAME)
    _workbook_service = web_services.WorkbookService(user_config_store)
    _user_config_service = web_services.UserConfigService(user_config_store)
    _cpg_service = web_services.CpgService(code_index, project_config)
    _source_snippet_service = web_services.SourceSnippetService(project_config)
    _report_feedback_service = web_services.ReportFeedbackService(
        user_config_store,
        snapshot_store,
        report_filename=REPORT_FILENAME,
    )
    _scan_request_service = ScanRequestService(
        config_file_path,
        default_scan_depth=scan_depth,
    )
    DashboardHttpServer(
        handler_class=ZScopeHandler,
        web_dir=WEB_DIR,
        host=host,
        port=port,
    ).serve_forever()


if __name__ == "__main__":
    run_server()
