"""Strict HTTP binding for the saved-config persistent job service."""

from __future__ import annotations

import importlib
from pathlib import Path
import sys
from typing import Any
from urllib.parse import parse_qs

from ..reporting.job_result_projection import project_job_result


class ScanJobsHttpService:
    """Keep request validation and report projection at the HTTP boundary.

    Job execution remains owned by the orchestration service. Its report id is
    the artifact hash; findings use the existing report review scope identity.
    A historical snapshot may use the current scope only when its full content
    is still equal to the current report. Otherwise it stays independently bound.
    """

    def __init__(self, config_path: Path, feedback: Any, *, engine: Any = None):
        self.config_path = Path(config_path)
        self.feedback = feedback
        self._engine = engine

    @staticmethod
    def _error(code: str, message: str, status: int) -> tuple[int, dict[str, Any]]:
        return status, {"error": message, "code": code}

    def _service(self) -> Any:
        if self._engine is None:
            if sys.platform != "linux":
                raise RuntimeError("persistent jobs require Linux")
            module = importlib.import_module("zscope.orchestration.jobs.service")
            self._engine = module.ScanJobService(self.config_path)
        return self._engine

    @staticmethod
    def _query(query: str, keys: set[str]) -> dict[str, str] | None:
        values = parse_qs(query, keep_blank_values=True)
        if set(values) != keys or any(len(items) != 1 or not items[0] for items in values.values()):
            return None
        return {key: items[0] for key, items in values.items()}

    def _result(self, engine: Any, job_id: str) -> tuple[int, dict[str, Any]]:
        return project_job_result(
            engine,
            job_id,
            config_path=self.config_path,
            current_report_path=self.feedback.report_filename,
        )

    def get(self, path: str, query: str) -> tuple[int, dict[str, Any]]:
        if path == "/api/jobs":
            params = self._query(query, set())
        elif path in {"/api/jobs/detail", "/api/jobs/result"}:
            params = self._query(query, {"job_id"})
        elif path == "/api/jobs/events":
            params = self._query(query, {"job_id", "after_seq"})
        else:
            return self._error("not_found", "作业接口不存在", 404)
        if params is None or len(params.get("job_id", "")) > 128:
            return self._error("invalid_request", "作业查询参数无效", 400)
        if "after_seq" in params and (
            not params["after_seq"].isascii()
            or not params["after_seq"].isdigit()
            or len(params["after_seq"]) > 18
        ):
            return self._error("invalid_request", "事件游标必须是非负整数", 400)
        try:
            engine = self._service()
            if path == "/api/jobs/result":
                return self._result(engine, params["job_id"])
            if path == "/api/jobs":
                response = engine.list()
            elif path == "/api/jobs/detail":
                response = engine.detail(params["job_id"])
            else:
                response = engine.events(params["job_id"], int(params["after_seq"]))
            return response.status_code, response.payload
        except (ImportError, OSError, ValueError, RuntimeError):
            return self._error(
                "unavailable", "持久作业服务不可用，需要已连接的 Linux 作业后台", 503
            )

    def post(self, path: str, payload: Any) -> tuple[int, dict[str, Any]]:
        if path == "/api/jobs":
            required, allowed = {"request_id"}, {"request_id", "scan_depth", "stop_at"}
        elif path in {"/api/jobs/cancel", "/api/jobs/resume"}:
            required = allowed = {"job_id", "base_revision", "request_id"}
        else:
            return self._error("not_found", "作业接口不存在", 404)
        if not isinstance(payload, dict) or not required <= set(payload) <= allowed:
            return self._error("invalid_request", "作业请求字段无效", 400)
        if not isinstance(payload["request_id"], str) or not payload["request_id"]:
            return self._error("invalid_request", "缺少作业请求身份", 400)
        if path != "/api/jobs" and (
            not isinstance(payload["job_id"], str)
            or not payload["job_id"]
            or len(payload["job_id"]) > 128
            or type(payload["base_revision"]) is not int
            or payload["base_revision"] < 0
        ):
            return self._error("invalid_request", "作业身份或版本无效", 400)
        if "scan_depth" in payload and (
            not isinstance(payload["scan_depth"], str)
            or payload["scan_depth"] not in {"fast", "balanced", "deep"}
        ):
            return self._error("invalid_request", "扫描深度无效", 400)
        if "stop_at" in payload and not isinstance(payload["stop_at"], str):
            return self._error("invalid_request", "作业窗口必须是带时区的绝对时间", 400)
        try:
            engine = self._service()
            if path == "/api/jobs":
                response = engine.start(**payload)
            elif path == "/api/jobs/cancel":
                response = engine.cancel(**payload)
            else:
                response = engine.resume(**payload)
            return response.status_code, response.payload
        except (ImportError, OSError, ValueError, RuntimeError):
            return self._error(
                "unavailable", "持久作业服务不可用，需要已连接的 Linux 作业后台", 503
            )
