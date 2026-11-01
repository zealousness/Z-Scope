import http.server
import json
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from .._version import __version__
from .dashboard_server import DashboardHttpServer
from . import services as web_services
from .review_reports import MAX_IMPORT_BYTES, ReportReviewService
from .acceptance_service import AcceptanceReviewService
from .scan_jobs_service import ScanJobsHttpService
from .semantics_service import SemanticsService
from ..orchestration.scan_request import ScanRequestError, ScanRequestService

PORT = 8000
WEB_DIR = Path(__file__).parent / "static"
REPORT_FILENAME = "zscope_batch_report.json"
CONFIG_FILENAME = "zscope.yaml"
USER_CONFIG_WORKBOOK_NAME = "user_config.xlsx"

_config_service = web_services.ConfigService()
_rule_service = web_services.RuleService()
_wiki_control_service = web_services.WikiControlService()
_workbook_service = web_services.WorkbookService()
_user_config_service = web_services.UserConfigService()
_cpg_service = web_services.CpgService()
_source_snippet_service = web_services.SourceSnippetService()
_report_feedback_service = web_services.ReportFeedbackService()
_scan_request_service = None
_acceptance_review_service = None
_scan_jobs_http_service = None
_project_library = None
_semantics_service = SemanticsService(Path(CONFIG_FILENAME))


def persist_validation_feedback(updates):
    return _report_feedback_service.persist_validation_feedback(updates)


class ZScopeHandler(http.server.SimpleHTTPRequestHandler):
    def __getattr__(self, name):
        if name in {
            "_config_service", "_rule_service", "_wiki_control_service", "_workbook_service",
            "_user_config_service", "_cpg_service", "_source_snippet_service",
            "_report_feedback_service", "_scan_request_service", "_acceptance_review_service",
            "_scan_jobs_http_service",
            "_semantics_service",
        }:
            context = self.__dict__.get("_project_context")
            return getattr(context, name) if context is not None else globals()[name]
        raise AttributeError(name)

    def _bind_project(self):
        self._project_context = None
        if _project_library is None:
            return True
        parsed = urlparse(self.path)
        if not parsed.path.startswith("/api/") or parsed.path == "/api/version" or parsed.path.startswith("/api/projects"):
            return True
        identity = self.headers.get("X-ZScope-Project", "")
        if parsed.path in {"/api/user_config/workbook/download", "/api/offline_report"}:
            identity = identity or (parse_qs(parsed.query).get("project") or [""])[0]
        if not identity:
            self._send_json({"code": "project_required", "error": "请先选择工程 YAML"}, status=409)
            return False
        try:
            self._project_context = _project_library.context(identity)
        except (OSError, ValueError, TypeError, KeyError) as exc:
            self._send_json({"code": "project_unavailable", "error": str(exc)}, status=409)
            return False
        return True

    def _same_origin_write(self):
        if _project_library is None:
            return True
        origin = self.headers.get("Origin")
        if origin and (urlparse(origin).scheme != "http" or urlparse(origin).netloc != self.headers.get("Host")):
            self._send_json({"error": "跨站项目操作被拒绝", "code": "invalid_origin"}, status=403)
            return False
        return True

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
        if parsed.path == "/api/projects":
            try:
                self._send_json(_project_library.list() if _project_library else {"enabled": False})
            except (OSError, ValueError) as exc:
                self._send_json({"error": str(exc)}, status=400)
            return
        if parsed.path == "/api/projects/browse" and _project_library:
            try:
                self._send_json(_project_library.browse((parse_qs(parsed.query).get("path") or [""])[0]))
            except (OSError, ValueError) as exc:
                self._send_json({"error": str(exc)}, status=400)
            return
        if not self._bind_project():
            return
        if parsed.path == "/api/semantics" or parsed.path.startswith("/api/semantics/"):
            status, response = self._semantics_service.get(parsed.path, parsed.query)
            self._send_json(response, status=status)
            return
        if self._legacy_semantics_blocked(parsed.path):
            return
        if parsed.path == "/api/findings":
            self._send_json(self._report_feedback_service.selected_view_payload(self.path))
        elif parsed.path in {"/api/jobs", "/api/schedules"} or parsed.path.startswith(("/api/jobs/", "/api/schedules/")):
            if self._scan_jobs_http_service is None:
                self._send_json({"error": "持久作业服务不可用", "code": "unavailable"}, status=503)
                return
            status, response = self._scan_jobs_http_service.get(parsed.path, parsed.query)
            self._send_json(response, status=status)
        elif parsed.path == "/api/acceptance/dispositions":
            if self._acceptance_review_service is None:
                self._send_json({"error": "项目处置服务不可用", "code": "unavailable"}, status=503)
                return
            status, response = self._acceptance_review_service.get(parsed.query)
            self._send_json(response, status=status)
        elif parsed.path in {"/api/issue_report", "/api/offline_report"}:
            service = ReportReviewService(self._report_feedback_service, self._source_snippet_service)
            try:
                if parsed.path == "/api/issue_report":
                    key = (parse_qs(parsed.query).get("issue_id") or [""])[0]
                    self._send_json(service.issue_report(key))
                else:
                    body = service.offline_report()
                    self.send_response(200)
                    self.send_header("Content-Type", "application/zip")
                    self.send_header(
                        "Content-Disposition", 'attachment; filename="zscope-report.zip"'
                    )
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
            except KeyError as exc:
                self._send_json({"error": str(exc)}, status=404)
            except ValueError as exc:
                self._send_json({"error": str(exc)}, status=400)
            except (BrokenPipeError, ConnectionResetError):
                return
            except OSError as exc:
                self._send_json({"error": f"报告读取或导出失败：{exc}"}, status=500)
        elif parsed.path == "/api/version":
            self._send_json({"version": __version__, "display": f"v{__version__}"})
        elif parsed.path == "/api/config/structured":
            try:
                self._send_json(self._config_service.structured_payload())
            except Exception as exc:
                self._send_json({"error": str(exc), "config": {}}, status=400)
        elif parsed.path == "/api/config":
            try:
                self._send_json(self._config_service.read_text())
            except OSError as exc:
                self._send_json({"content": "", "error": str(exc)}, status=500)
        elif parsed.path == "/api/scan/prepare":
            try:
                self._send_json(self._config_service.prepare_project())
            except (OSError, ValueError, TypeError) as exc:
                self._send_json({"error": str(exc)}, status=400)
        elif parsed.path == "/api/scan/status":
            if self._scan_request_service is None:
                self._send_json({"error": "scan service is unavailable"}, status=503)
                return
            try:
                scan_id = (parse_qs(parsed.query).get("scan_id") or [""])[0]
                self._send_json(self._scan_request_service.status(scan_id))
            except ScanRequestError as exc:
                self._send_json({"error": str(exc)}, status=404)
        elif parsed.path == "/api/rules":
            try:
                self._send_json(self._rule_service.payload(parsed.query))
            except Exception as exc:
                self._send_json({"error": str(exc), "rules": []}, status=400)
        elif parsed.path == "/api/wiki/status":
            try:
                self._send_json(self._wiki_control_service.status_payload())
            except Exception:
                self._send_json(
                    {"error": "Wiki status is unavailable.", "available": False},
                    status=400,
                )
        elif parsed.path == "/api/wiki/query":
            try:
                self._send_json(self._wiki_control_service.query_payload(parsed.query))
            except ValueError as exc:
                message = str(exc)
                safe_prefixes = (
                    "unsupported Wiki query fields",
                    "subject",
                    "fact_kind",
                    "candidate_file",
                    "max_tokens",
                )
                self._send_json(
                    {
                        "error": (
                            message[:500]
                            if message.startswith(safe_prefixes)
                            else "Wiki query is unavailable."
                        )
                    },
                    status=400,
                )
            except Exception:
                self._send_json({"error": "Wiki query is unavailable."}, status=400)
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
        if not self._same_origin_write() or not self._bind_project():
            return
        try:
            content_length = int(self.headers.get("Content-Length", 0))
            if content_length < 0:
                raise ValueError("negative Content-Length")
        except ValueError:
            self.close_connection = True
            self._send_json({"success": False, "error": "Invalid Content-Length"}, status=400)
            return
        if self.path.startswith(("/api/jobs", "/api/schedules", "/api/projects")) and content_length > 64 * 1024:
            self._send_json({"error": "作业请求过大", "code": "invalid_request"}, status=413)
            self.close_connection = True
            return
        if self.path.startswith("/api/semantics") and content_length > 2 * 1024 * 1024:
            self._send_json({"error": "项目原语请求超过 2 MiB。"}, status=413)
            self.close_connection = True
            return
        if self.path.startswith("/api/import_reviews") and content_length > MAX_IMPORT_BYTES * 2:
            self._send_json({"error": "导入请求过大"}, status=413)
            self.close_connection = True
            return
        post_data = self.rfile.read(content_length)
        if self._legacy_semantics_blocked(urlparse(self.path).path):
            return
        if self.path == "/api/user_config/workbook/import":
            self._handle_user_config_workbook_import(post_data)
            return
        try:
            payload = json.loads(post_data or b"{}")
        except (json.JSONDecodeError, UnicodeError):
            self._send_json({"success": False, "error": "Invalid JSON"}, status=400)
            return

        if not isinstance(payload, dict):
            self._send_json(
                {"success": False, "error": "request must be an object", "code": "invalid_request"},
                status=400,
            )
            return

        if self.path.startswith("/api/semantics/"):
            if self.headers.get_content_type() != "application/json":
                self._send_json({"error": "项目原语操作需要 application/json 请求。"}, status=400)
                return
            status, response = self._semantics_service.post(self.path, payload)
            self._send_json(response, status=status)
            return

        if self.path.startswith("/api/projects/") and _project_library:
            try:
                if self.headers.get_content_type() != "application/json":
                    raise ValueError("项目操作需要 application/json 请求")
                if self.path == "/api/projects/open":
                    result = _project_library.open(payload.get("path", ""))
                elif self.path == "/api/projects/create":
                    result = _project_library.create(payload)
                else:
                    self.send_error(404)
                    return
                self._send_json(result)
            except (OSError, ValueError, TypeError, KeyError) as exc:
                self._send_json({"error": str(exc)}, status=400)
            return

        if self.path in {"/api/jobs", "/api/schedules"} or self.path.startswith(("/api/jobs/", "/api/schedules/")):
            if self._scan_jobs_http_service is None:
                self._send_json({"error": "持久作业服务不可用", "code": "unavailable"}, status=503)
                return
            status, response = self._scan_jobs_http_service.post(self.path, payload)
            self._send_json(response, status=status)
            return

        if self.path == "/api/business_review":
            from ..config.protocol_feedback import ProtocolAnswerConflict

            try:
                result = ReportReviewService(self._report_feedback_service).save_business_review(payload)
                self._send_json(result)
            except ProtocolAnswerConflict as exc:
                self._send_json({"success": False, "error": str(exc)}, status=409)
            except (ValueError, KeyError, TypeError) as exc:
                self._send_json({"success": False, "error": str(exc)}, status=400)
            except Exception as exc:
                self._send_json({"success": False, "error": f"业务前提保存失败：{exc}"}, status=500)
            return
        if self.path == "/api/acceptance/dispositions":
            if self._acceptance_review_service is None:
                self._send_json({"error": "项目处置服务不可用", "code": "unavailable"}, status=503)
                return
            status, response = self._acceptance_review_service.post(payload)
            self._send_json(response, status=status)
            return
        if self.path in {"/api/import_reviews", "/api/import_reviews/resolve"}:
            try:
                result = ReportReviewService(self._report_feedback_service).import_reviews(
                    payload, resolve=self.path.endswith("/resolve")
                )
                self._send_json(result)
            except ValueError as exc:
                self._send_json({"error": str(exc)}, status=400)
            except Exception as exc:
                self._send_json({"success": False, "error": f"复核保存失败：{exc}"}, status=500)
            return
        if self.path == "/api/config":
            content = payload.get("content", "")
            try:
                response = self._config_service.write_text(content)
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
                self._config_service.save_document(data)
            except Exception as exc:
                self._send_json({"success": False, "error": str(exc)}, status=400)
                return
            self._send_json({"success": True, **self._config_service.structured_payload()})
        elif self.path == "/api/save_findings":
            try:
                updates = payload.get("issues", [])
                if not isinstance(updates, list):
                    self._send_json(
                        {"success": False, "error": "Issues must be a list"}, status=400
                    )
                    return
                response_payload = self._report_feedback_service.save_validation_feedback(
                    updates,
                    persist_snapshots=payload.get("persist_snapshots", True) is not False,
                    save_scope=str(payload.get("save_scope") or "full"),
                )
            except Exception as exc:
                self._send_json({"success": False, "error": str(exc)}, status=500)
                return
            self._send_json(response_payload)
        elif self.path == "/api/scan":
            if self._scan_request_service is None:
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
                response = self._scan_request_service.start(
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
        if not self._same_origin_write() or not self._bind_project():
            return
        if self._legacy_semantics_blocked(urlparse(self.path).path):
            self.close_connection = True
            return
        try:
            content_length = int(self.headers.get("Content-Length", 0))
            if content_length < 0:
                raise ValueError("negative Content-Length")
        except ValueError:
            self.close_connection = True
            self._send_json({"success": False, "error": "Invalid Content-Length"}, status=400)
            return
        post_data = self.rfile.read(content_length) if content_length else b"{}"
        try:
            payload = json.loads(post_data or b"{}")
        except (json.JSONDecodeError, UnicodeError):
            self._send_json({"success": False, "error": "Invalid JSON"}, status=400)
            return
        if not isinstance(payload, dict):
            self._send_json({"success": False, "error": "request must be an object"}, status=400)
            return
        if self.path.startswith("/api/user_config/"):
            self._handle_user_config_delete(payload)
        else:
            self.send_error(404)

    # ── CPG handlers ──

    def _handle_cpg_status(self):
        self._send_json(self._cpg_service.status_payload())

    def _handle_build_cpg(self, payload):
        status, response_payload = self._cpg_service.build()
        self._send_json(response_payload, status=status)

    def _handle_clear_warnings(self):
        status, payload = self._user_config_service.clear_warnings()
        self._send_json(payload, status=status)

    def _handle_get_warnings(self):
        self._send_json(self._user_config_service.warnings_payload())

    def _handle_source_snippet(self, parsed):
        status, payload = self._source_snippet_service.snippet_payload(parsed.query)
        self._send_json(payload, status=status)
        return

    # ── User config CRUD handlers ──

    def _handle_user_config_workbook_get(self):
        self._send_json(self._workbook_service.payload())

    def _handle_user_config_workbook_download(self):
        try:
            data = self._workbook_service.download_bytes()
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
            payload = self._workbook_service.import_bytes(data)
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
            workbook_payload_data = self._workbook_service.write_payload(payload)
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
        status, payload = self._user_config_service.list_resource(self._get_config_resource())
        if status == 404:
            self.send_error(404)
            return
        self._send_json(payload, status=status)

    def _legacy_semantics_blocked(self, path):
        if not path.startswith("/api/user_config/") or path == "/api/user_config/warnings":
            return False
        try:
            applicable = self._semantics_service.location() is not None
        except (ValueError, OSError):
            applicable = False
        if applicable:
            self._send_json({"error": "C/C++ 执行语义已迁移至项目原语，请使用原语引导；旧工作簿可单向导入。", "code": "semantics_moved", "url": "/#tab=semantics"}, status=410)
        return applicable

    def _handle_user_config_post(self, payload):
        status, response_payload = self._user_config_service.upsert_resource(
            self._get_config_resource(),
            payload,
        )
        if status == 404:
            self.send_error(404)
            return
        self._send_json(response_payload, status=status)

    def _handle_user_config_delete(self, payload):
        status, response_payload = self._user_config_service.delete_resource(
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
    project_picker=False,
):
    global _config_service, _rule_service, _wiki_control_service, _workbook_service, _user_config_service, _cpg_service, _source_snippet_service, _report_feedback_service, _scan_request_service, _acceptance_review_service, _scan_jobs_http_service
    global _project_library, _semantics_service
    _project_library = None
    if project_picker:
        from .projects import ProjectLibrary

        _project_library = ProjectLibrary(scan_depth=scan_depth)
        if config_path:
            opened = _project_library.open(str(Path(config_path).resolve()))
            _project_library.initial_project_id = opened["project"]["project_id"]
        try:
            DashboardHttpServer(handler_class=ZScopeHandler, web_dir=WEB_DIR, host=host, port=port).serve_forever()
        finally:
            _project_library.close()
        return
    config_file_path = (
        Path(config_path).resolve() if config_path else Path(CONFIG_FILENAME).resolve()
    )
    _semantics_service = SemanticsService(config_file_path)
    _config_service = web_services.ConfigService(
        config_file_path,
        default_name=CONFIG_FILENAME,
        scan_depth=scan_depth,
    )
    _rule_service = web_services.RuleService(config_file_path, default_name=CONFIG_FILENAME)
    _wiki_control_service = web_services.WikiControlService(
        config_file_path, default_name=CONFIG_FILENAME
    )
    _workbook_service = web_services.WorkbookService(user_config_store)
    _user_config_service = web_services.UserConfigService(user_config_store)
    _cpg_service = web_services.CpgService(code_index, project_config)
    _source_snippet_service = web_services.SourceSnippetService(project_config)
    _report_feedback_service = web_services.ReportFeedbackService(
        user_config_store,
        snapshot_store,
        report_filename=REPORT_FILENAME,
        project_config=project_config,
    )
    worker = None
    review_config = getattr(project_config, "review_memory", None)
    if (review_config is not None and review_config.mode in {"extract", "active"}
            and review_config.extraction == "auto_extract"
            and _report_feedback_service.review_memory_store is not None):
        from ..review_memory.worker import ReviewMemoryWorker
        from ..cli.review_memory import _llm_client
        from ..config.config import ConfigLoader
        worker_config = ConfigLoader.load(str(config_file_path))
        worker = ReviewMemoryWorker(
            _report_feedback_service.review_memory_store,
            llm_client_factory=lambda: _llm_client(worker_config),
            llm_enabled=review_config.llm_enabled,
        )
        worker.start()
    _scan_request_service = ScanRequestService(
        config_file_path,
        default_scan_depth=scan_depth,
    )
    _acceptance_review_service = AcceptanceReviewService(_report_feedback_service, config_file_path)
    _scan_jobs_http_service = ScanJobsHttpService(config_file_path, _report_feedback_service)
    try:
        DashboardHttpServer(handler_class=ZScopeHandler, web_dir=WEB_DIR, host=host, port=port).serve_forever()
    finally:
        if worker is not None:
            worker.stop()


if __name__ == "__main__":
    run_server()
