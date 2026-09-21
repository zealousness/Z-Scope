"""Bounded asynchronous scan requests for Web and MCP interfaces."""

from __future__ import annotations

import datetime as dt
import json
import os
import subprocess
import sys
import threading
import uuid
from pathlib import Path
from typing import Any, Callable, Dict, Mapping, Optional

from ..config.config import ConfigLoader
from ..framework.llm_usage import scan_token_usage_snapshot
from .rollout import rollout_runtime_policy


SCAN_REQUEST_SCHEMA_VERSION = "zscope.scan-request.v1"
SCAN_DEPTHS = frozenset({"fast", "balanced", "deep"})


class ScanRequestError(ValueError):
    """Raised before process launch for an invalid or conflicting request."""


class ScanRequestService:
    """Start a scan using only a server-owned config and a depth override.

    The service deliberately exposes no arbitrary argv, cwd, environment, or
    path fields.  It is therefore suitable for both the local dashboard and a
    policy-protected MCP tool.  One active process is allowed per service.
    """

    def __init__(
        self,
        config_path: Path,
        *,
        default_scan_depth: Optional[str] = None,
        process_factory: Callable[..., Any] = subprocess.Popen,
        python_executable: str = sys.executable,
    ) -> None:
        self.config_path = Path(config_path).expanduser().resolve()
        self.default_scan_depth = default_scan_depth
        self._process_factory = process_factory
        self._python_executable = str(python_executable)
        self._lock = threading.Lock()
        self._runs: Dict[str, Dict[str, Any]] = {}
        self._latest_scan_id = ""

    def start(
        self,
        *,
        scan_depth: Optional[str] = None,
    ) -> Dict[str, Any]:
        if not self.config_path.is_file():
            raise ScanRequestError(f"configuration does not exist: {self.config_path}")
        depth = scan_depth if scan_depth is not None else self.default_scan_depth
        if depth is not None and (not isinstance(depth, str) or depth not in SCAN_DEPTHS):
            raise ScanRequestError("scan_depth must be fast, balanced, or deep")
        effective = ConfigLoader.load(str(self.config_path), scan_depth=depth)
        with self._lock:
            self._refresh_locked()
            if any(run["status"] == "running" for run in self._runs.values()):
                raise ScanRequestError("a scan is already running for this interface")
            scan_id = uuid.uuid4().hex
            artifact_dir = effective.project.project_root / ".zscope_interface_scans"
            artifact_dir.mkdir(parents=True, exist_ok=True)
            log_path = artifact_dir / f"{scan_id}.log"
            log_handle = log_path.open("wb")
            argv = [
                self._python_executable,
                "-m",
                "zscope.cli.cli",
                "-c",
                str(self.config_path),
            ]
            # Pass request intent, not the already-routed effective result.
            # The child loads the same persisted rollout state and must retain
            # default enrollment versus explicit opt-in provenance.  Passing
            # an enrolled balanced depth back as a CLI override would turn it
            # into a fabricated explicit opt-in on the second load.
            if depth is not None:
                argv.extend(("--scan-depth", str(depth)))
            creationflags = (
                int(getattr(subprocess, "CREATE_NO_WINDOW", 0)) if os.name == "nt" else 0
            )
            try:
                process = self._process_factory(
                    argv,
                    cwd=str(Path.cwd()),
                    stdin=subprocess.DEVNULL,
                    stdout=log_handle,
                    stderr=subprocess.STDOUT,
                    shell=False,
                    creationflags=creationflags,
                )
            except Exception:
                log_handle.close()
                raise
            now = dt.datetime.now(dt.timezone.utc).isoformat()
            report_candidates = (
                effective.project.project_root / "zscope_batch_report.json",
                effective.project.project_root / "report.json",
            )
            run: Dict[str, Any] = {
                "schema_version": SCAN_REQUEST_SCHEMA_VERSION,
                "scan_id": scan_id,
                "status": "running",
                "started_at": now,
                "completed_at": "",
                "return_code": None,
                "effective_scan": {
                    "depth": effective.scan.depth,
                    "depth_source": (
                        effective.scan.depth_source
                        if effective.scan.depth_source == "rollout"
                        else (
                            "interface_request"
                            if scan_depth is not None
                            else effective.scan.depth_source
                        )
                    ),
                    "rollout": rollout_runtime_policy(effective),
                },
                "llm_usage": scan_token_usage_snapshot(effective),
                "log_path": str(log_path),
                "report_path": "",
                "scan_response": {},
                "_process": process,
                "_log_handle": log_handle,
                "_project_root": effective.project.project_root,
                "_report_baselines": {
                    str(path): self._file_signature(path) for path in report_candidates
                },
            }
            self._runs[scan_id] = run
            self._latest_scan_id = scan_id
            return self._public(run)

    def status(self, scan_id: str = "") -> Dict[str, Any]:
        with self._lock:
            identity = str(scan_id or self._latest_scan_id)
            if not identity or identity not in self._runs:
                raise ScanRequestError("unknown scan_id")
            self._refresh_run_locked(self._runs[identity])
            return self._public(self._runs[identity])

    def _refresh_locked(self) -> None:
        for run in self._runs.values():
            self._refresh_run_locked(run)

    def _refresh_run_locked(self, run: Dict[str, Any]) -> None:
        if run.get("status") != "running":
            return
        process = run["_process"]
        return_code = process.poll()
        if return_code is None:
            return
        log_handle = run.get("_log_handle")
        if log_handle is not None and not log_handle.closed:
            log_handle.close()
        run["return_code"] = int(return_code)
        run["completed_at"] = dt.datetime.now(dt.timezone.utc).isoformat()
        project_root = Path(run["_project_root"])
        report_path = next(
            (
                path
                for path in (
                    project_root / "zscope_batch_report.json",
                    project_root / "report.json",
                )
                if path.is_file()
                and self._file_signature(path) != run.get("_report_baselines", {}).get(str(path))
            ),
            None,
        )
        report: Dict[str, Any] = {}
        if report_path is not None:
            try:
                from ..reporting.json_io import read_report
                parsed = read_report(report_path)
                report = parsed if isinstance(parsed, dict) else {}
            except (OSError, json.JSONDecodeError):
                report = {}
        run["report_path"] = str(report_path or "")
        usage = self._report_usage(report)
        if usage:
            run["llm_usage"] = usage
        run["scan_response"] = {
            "finding_status": report.get("finding_status"),
            "completeness": report.get("completeness"),
            "scan_outcome": report.get("scan_outcome"),
            "effective_scan": dict(run["effective_scan"]),
            "llm_usage": dict(run["llm_usage"]),
        }
        run["status"] = "completed" if return_code in {0, 1, 2} else "failed"

    @staticmethod
    def _file_signature(path: Path) -> Optional[tuple[int, int]]:
        try:
            stat = path.stat()
        except OSError:
            return None
        return stat.st_mtime_ns, stat.st_size

    @staticmethod
    def _report_usage(report: Mapping[str, Any]) -> Dict[str, Any]:
        for owner in (
            report,
            report.get("metadata"),
            report.get("summary"),
            report.get("run_manifest"),
        ):
            if not isinstance(owner, Mapping):
                continue
            value = owner.get("llm_usage")
            if isinstance(value, dict):
                return dict(value)
        return {}

    @staticmethod
    def _public(run: Mapping[str, Any]) -> Dict[str, Any]:
        return {key: value for key, value in run.items() if not str(key).startswith("_")}
