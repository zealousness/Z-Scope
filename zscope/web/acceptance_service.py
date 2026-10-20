"""HTTP integration for independent, server-bound acceptance dispositions."""

from __future__ import annotations

from pathlib import Path
import sqlite3
import threading
from typing import Any
from urllib.parse import parse_qs


class AcceptanceReviewService:
    """Bind each command to the full current report before accessing the store.

    Numeric disposition revisions are scoped to evidence. The separate context
    digest prevents a never-saved draft at revision zero from binding to changed
    evidence or another resource at the same issue id.
    """

    def __init__(self, feedback: Any, config_path: Path | None = None, *, store: Any = None):
        self.feedback = feedback
        self.config_path = Path(config_path) if config_path is not None else None
        self._injected_store = store
        self._stores: dict[Path, Any] = {}
        self._lock = threading.Lock()

    def _service(self) -> Any:
        from ..config.acceptance_feedback import (
            AcceptanceDispositionService,
            AcceptanceFeedbackStore,
        )
        from ..config.config import ConfigLoader

        if self._injected_store is not None:
            return AcceptanceDispositionService(self._injected_store)
        if self.config_path is None:
            raise ValueError("saved project configuration is unavailable")
        config = ConfigLoader.load(str(self.config_path), read_only=True)
        path = config.project.project_root / ".zscope_acceptance" / "dispositions.sqlite3"
        with self._lock:
            if path not in self._stores:
                self._stores[path] = AcceptanceFeedbackStore(path)
            return AcceptanceDispositionService(self._stores[path])

    def _resolver(self) -> Any:
        from ..config.acceptance_feedback import resolver_from_report
        from .review_reports import report_identity

        # Do not resolve identities from a stale lightweight client payload.
        self.feedback._report_cache_key = None
        report = self.feedback.load_report()
        return resolver_from_report(
            report, report_id=report_identity(report, self.feedback.report_filename)
        )

    @staticmethod
    def _error(code: str, message: str, status: int) -> tuple[int, dict[str, Any]]:
        return status, {"error": message, "code": code}

    def get(self, query: str) -> tuple[int, dict[str, Any]]:
        values = parse_qs(query, keep_blank_values=True)
        if set(values) != {"report_id", "issue_id"} or any(
            len(items) != 1 for items in values.values()
        ):
            return self._error("invalid_request", "处置查询参数无效", 400)
        try:
            service = self._service()
            resolve = self._resolver()
            params = {key: items[0] for key, items in values.items()}
            status, payload = service.get_dispositions(params, resolve)
            if status == 200:
                scope = resolve(params["report_id"], params["issue_id"])
                if scope is None:
                    return self._error("stale_scope", "报告已变化，请重新载入", 409)
                payload["context_revision"] = scope.scope.scope_key
            return status, payload
        except (OSError, ValueError, ImportError, sqlite3.Error):
            return self._error("unavailable", "项目处置状态库不可用", 503)

    def post(self, payload: Any) -> tuple[int, dict[str, Any]]:
        if not isinstance(payload, dict):
            return self._error("invalid_request", "处置请求必须是 JSON 对象", 400)
        context = payload.get("base_context_revision")
        if not isinstance(context, str) or not context:
            return self._error("invalid_request", "缺少当前证据范围版本，请重新载入", 400)
        try:
            service = self._service()
            if not service.writable:
                return self._error("unavailable", "处置状态库只读", 503)
            resolve = self._resolver()
            report_id, issue_id = payload.get("report_id"), payload.get("issue_id")
            if not isinstance(report_id, str) or not isinstance(issue_id, str):
                return self._error("invalid_request", "报告与问题身份无效", 400)
            resolution = resolve(report_id, issue_id)
            if resolution is None or context != resolution.scope.scope_key:
                return self._error("stale_scope", "报告证据或对象已变化，保留草稿并重新载入", 409)
            command = {
                key: value for key, value in payload.items() if key != "base_context_revision"
            }
            status, result = service.post_disposition(command, resolve)
            if status == 200:
                result["context_revision"] = resolution.scope.scope_key
            return status, result
        except (OSError, ValueError, ImportError, sqlite3.Error):
            return self._error("unavailable", "项目处置状态库不可用", 503)
