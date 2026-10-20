"""MCP tool surface over the shared persistent scan job service.

The MCP job tools call the same
:class:`~zscope.orchestration.jobs.service.ScanJobService` the Web jobs API
uses: one project store located from the saved config (real SQLite under
``<project>/.zscope_jobs``), detached owner processes, and identical
``request_id`` / ``base_revision`` replay-conflict semantics.  This adapter
adds no second job database, no worker threads, and no HTTP self-calls; it
validates strict MCP tool arguments at the boundary and translates service
envelopes to the MCP result shape.  Read-only MCP profiles never construct
it, and a v3 multi-target document fails exactly where the shared parser and
service refuse it — the adapter has no approximate schema of its own.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

SCAN_DEPTH_CHOICES = ("fast", "balanced", "deep")
JOB_ID_MAX_CHARS = 128
REQUEST_ID_MAX_CHARS = 128
STOP_AT_MAX_CHARS = 64

_UNAVAILABLE_LINUX = "persistent scan jobs require the Linux job backend"
_UNAVAILABLE_CONFIG = "persistent scan jobs require a saved config path"


class McpJobsAdapter:
    """Translate strict MCP job tool calls onto :class:`ScanJobService`."""

    def __init__(
        self,
        config_path: Optional[Path | str] = None,
        *,
        service: Optional[Any] = None,
    ) -> None:
        self.config_path = Path(config_path) if config_path is not None else None
        self._service = service

    def _engine(self) -> Optional[Any]:
        """Lazily bind the shared service; no engine, no side effects."""

        if self._service is None:
            if self.config_path is None:
                return None
            if sys.platform != "linux":
                return None
            from ..orchestration.jobs.service import ScanJobService

            self._service = ScanJobService(self.config_path)
        return self._service

    # ------------------------------------------------------------------ boundary

    @staticmethod
    def _invalid(message: str) -> Dict[str, Any]:
        return {"success": False, "error": message, "code": "invalid_request", "status_code": 400}

    @staticmethod
    def _unavailable(reason: str) -> Dict[str, Any]:
        return {"success": False, "error": reason, "code": "unavailable", "status_code": 503}

    def _check(
        self,
        arguments: Any,
        *,
        required: Tuple[str, ...],
        allowed: Tuple[str, ...],
        strings: Tuple[Tuple[str, int], ...] = (),
        non_negative_ints: Tuple[str, ...] = (),
        enums: Tuple[Tuple[str, Tuple[str, ...]], ...] = (),
    ) -> Optional[Dict[str, Any]]:
        """Strict boundary validation mirroring the Web jobs request checks.

        A field that is *present* is validated for its full declared type —
        an explicit ``null`` is never treated as an omitted optional field,
        matching the published tool schema (none of these fields is nullable)
        and the Web boundary.  Everything here must reject before
        :meth:`_engine` locates the store, so an invalid request never
        creates ``.zscope_jobs`` or spawns an owner.  Semantic validation
        (request-id bounds, revision positivity, stop_at parsing) stays in
        the shared service so both surfaces cannot drift.
        """

        if not isinstance(arguments, dict):
            return self._invalid("tool arguments must be a JSON object")
        unknown = sorted(set(arguments) - set(allowed))
        if unknown:
            return self._invalid("unknown argument(s): " + ", ".join(unknown))
        missing = sorted(set(required) - set(arguments))
        if missing:
            return self._invalid("missing required argument(s): " + ", ".join(missing))
        for name, max_chars in strings:
            if name not in arguments:
                continue
            value = arguments[name]
            if not isinstance(value, str) or not value.strip() or len(value) > max_chars:
                return self._invalid(
                    f"{name} must be a non-empty string of at most {max_chars} characters"
                )
        for name in non_negative_ints:
            if name not in arguments:
                continue
            value = arguments[name]
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                return self._invalid(f"{name} must be a non-negative integer")
        for name, choices in enums:
            if name not in arguments:
                continue
            if arguments[name] not in choices:
                return self._invalid(f"{name} must be one of: " + ", ".join(choices))
        return None

    def _call(self, method_name: str, **kwargs: Any) -> Dict[str, Any]:
        engine = self._engine()
        if engine is None:
            reason = _UNAVAILABLE_CONFIG if self.config_path is None else _UNAVAILABLE_LINUX
            return self._unavailable(reason)
        response = getattr(engine, method_name)(**kwargs)
        status_code = int(getattr(response, "status_code", 500))
        payload = dict(getattr(response, "payload", {}))
        if 200 <= status_code < 300:
            return {"success": True, "data": payload}
        return {
            "success": False,
            "error": str(payload.get("error") or "job request failed"),
            "code": str(payload.get("code") or "job_error"),
            "status_code": status_code,
        }

    # ------------------------------------------------------------------ tools

    def start(self, arguments: Any) -> Dict[str, Any]:
        """``zscope.scan.run``: create one persistent job and spawn its owner."""

        error = self._check(
            arguments,
            required=("request_id",),
            allowed=("request_id", "scan_depth", "stop_at"),
            strings=(("request_id", REQUEST_ID_MAX_CHARS), ("stop_at", STOP_AT_MAX_CHARS)),
            enums=(("scan_depth", SCAN_DEPTH_CHOICES),),
        )
        if error is not None:
            return error
        assert isinstance(arguments, dict)
        return self._call(
            "start",
            scan_depth=arguments.get("scan_depth"),
            stop_at=arguments.get("stop_at"),
            request_id=arguments["request_id"],
        )

    def status(self, arguments: Any) -> Dict[str, Any]:
        """``zscope.scan.status``: one job's durable state by ``job_id``."""

        error = self._check(
            arguments,
            required=("job_id",),
            allowed=("job_id",),
            strings=(("job_id", JOB_ID_MAX_CHARS),),
        )
        if error is not None:
            return error
        assert isinstance(arguments, dict)
        return self._call("detail", job_id=arguments["job_id"])

    def list(self, arguments: Any) -> Dict[str, Any]:
        """``zscope.jobs.list``: this project's jobs and start capability."""

        error = self._check(arguments, required=(), allowed=())
        if error is not None:
            return error
        return self._call("list")

    def events(self, arguments: Any) -> Dict[str, Any]:
        """``zscope.jobs.events``: page job events after a cursor."""

        error = self._check(
            arguments,
            required=("job_id",),
            allowed=("job_id", "after_seq"),
            strings=(("job_id", JOB_ID_MAX_CHARS),),
            non_negative_ints=("after_seq",),
        )
        if error is not None:
            return error
        assert isinstance(arguments, dict)
        return self._call(
            "events", job_id=arguments["job_id"], after_seq=int(arguments.get("after_seq", 0))
        )

    def result(self, arguments: Any) -> Dict[str, Any]:
        """``zscope.jobs.result``: the current attempt's report binding + findings.

        The shared projection reads only the current attempt's immutable
        bound snapshot (outer ``report_id`` stays the artifact byte hash) and
        reuses the existing lightweight findings/acceptance projection; the
        review scope is shared with the current report only when the logical
        content still matches, and a moved attempt is never served as
        another's result.
        """

        error = self._check(
            arguments,
            required=("job_id",),
            allowed=("job_id",),
            strings=(("job_id", JOB_ID_MAX_CHARS),),
        )
        if error is not None:
            return error
        assert isinstance(arguments, dict)
        engine = self._engine()
        if engine is None:
            reason = _UNAVAILABLE_CONFIG if self.config_path is None else _UNAVAILABLE_LINUX
            return self._unavailable(reason)
        from ..reporting.job_result_projection import project_job_result

        status_code, payload = project_job_result(
            engine, arguments["job_id"], config_path=self.config_path
        )
        if 200 <= status_code < 300:
            return {"success": True, "data": payload}
        return {
            "success": False,
            "error": str(payload.get("error") or "job request failed"),
            "code": str(payload.get("code") or "job_error"),
            "status_code": status_code,
        }

    def cancel(self, arguments: Any) -> Dict[str, Any]:
        """``zscope.jobs.cancel``: request cancellation of one job."""

        error = self._check(
            arguments,
            required=("job_id", "base_revision", "request_id"),
            allowed=("job_id", "base_revision", "request_id"),
            strings=(("job_id", JOB_ID_MAX_CHARS), ("request_id", REQUEST_ID_MAX_CHARS)),
            non_negative_ints=("base_revision",),
        )
        if error is not None:
            return error
        assert isinstance(arguments, dict)
        return self._call(
            "cancel",
            job_id=arguments["job_id"],
            base_revision=arguments["base_revision"],
            request_id=arguments["request_id"],
        )

    def resume(self, arguments: Any) -> Dict[str, Any]:
        """``zscope.jobs.resume``: arm a new attempt of a resumable job."""

        error = self._check(
            arguments,
            required=("job_id", "base_revision", "request_id"),
            allowed=("job_id", "base_revision", "request_id"),
            strings=(("job_id", JOB_ID_MAX_CHARS), ("request_id", REQUEST_ID_MAX_CHARS)),
            non_negative_ints=("base_revision",),
        )
        if error is not None:
            return error
        assert isinstance(arguments, dict)
        return self._call(
            "resume",
            job_id=arguments["job_id"],
            base_revision=arguments["base_revision"],
            request_id=arguments["request_id"],
        )
