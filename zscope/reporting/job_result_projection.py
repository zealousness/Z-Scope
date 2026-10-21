"""Pure findings projection for a persistent job's bound report snapshot.

This module wires the existing lightweight report projection onto the
per-attempt report binding that :class:`~zscope.orchestration.jobs.service.ScanJobService`
maintains, without owning any HTTP surface.  The MCP ``zscope.jobs.result``
tool uses it today; the shared Web jobs route can adopt the same call.

Contract (mirrors the Web ``ScanJobsHttpService._result`` behaviour exactly,
so both surfaces serve the same values):

* The outer ``report_id`` stays the byte hash of the bound snapshot artifact.
  The inner ``report_id`` produced by the review projection is the review
  scope identity — the bound snapshot's own scope, shared with the current
  report only when the decoded logical report is still fully equal to the
  current project report; otherwise it stays independently bound.
* Findings come only from the *current* attempt's immutable snapshot loaded
  through the formal reader (``load_bound_report`` re-verifies the byte hash
  and decodes through ``read_report``/``decode_storage``): never from the
  live project report replacing a bound one.  A missing/damaged current
  report therefore never revokes an intact bound historical result.
* Identity binding: ``job_id``/``run_id``/``revision``/``input_revision``
  and the attempt's ``report_id`` are read from the job row before AND
  after the envelope read and again after the snapshot load — the envelope
  (coverage/questions/artifacts included), the bound snapshot and the
  published ``binding``/``findings`` all belong to one and the same round.
  A job that was resumed across any of those reads is retried a bounded
  number of times and, if it keeps moving, answered with an honest
  ``attempt_changed`` refusal.  Identical report bytes do not make two
  attempts the same round.
* Unknown stays unknown: when the attempt is still active, no report was
  bound or the artifact is damaged, ``findings`` stays ``None`` with the
  real reason; nothing is invented.

This module is pure: it constructs no databases, threads or HTTP calls,
never runs the Validator, and never writes anything.  The projection helpers
(``project_report`` / ``findings_for_view`` / acceptance) are the existing
shared ones; no near-copy of their logic lives here.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

#: The report filename the product scanner writes into the project root.
CURRENT_REPORT_FILENAME = "zscope_batch_report.json"

#: How often the attempt binding may be re-read before an honest refusal.
_MAX_BINDING_ATTEMPTS = 3

_BINDING_FIELDS = ("job_id", "run_id", "report_id", "input_revision")


def _attempt_binding(service: Any, job_id: str) -> Optional[Dict[str, Any]]:
    """Read the current attempt's identity binding from the job row."""

    response = service.detail(job_id)
    if getattr(response, "status_code", 500) != 200:
        return None
    job = dict(getattr(response, "payload", {}) or {}).get("job") or {}
    report = job.get("report") or {}
    return {
        "job_id": job.get("job_id"),
        "run_id": job.get("run_id"),
        "revision": job.get("revision"),
        "input_revision": job.get("input_revision"),
        "status": job.get("status"),
        "report_id": report.get("report_id"),
        "report_path": report.get("path"),
    }


def _binding_matches(left: Optional[Dict[str, Any]], right: Optional[Dict[str, Any]]) -> bool:
    if left is None or right is None:
        return False
    return all(left.get(field) == right.get(field) for field in _BINDING_FIELDS)


def _project_root_for(config_path: Optional[Path | str]) -> Optional[Path]:
    """Locate the saved config's ``project.root``; no Bridge cwd, no guesses."""

    if config_path is None:
        return None
    try:
        from ..config.config import ConfigLoader

        config = ConfigLoader.load(str(config_path), read_only=True)
        root = getattr(config.project, "project_root", None)
        return Path(root) if root else None
    except Exception:
        return None


def _review_scope(
    report: Dict[str, Any],
    snapshot: Path,
    project_root: Optional[Path],
    current_report_path: Optional[Path | str] = None,
) -> Tuple[str, bool]:
    """The review scope for this snapshot.

    The snapshot's own scope is the default; the current report's scope is
    shared only when the current report file exists and its decoded logical
    content is still fully equal to the bound snapshot.
    """

    scope_filename = str(snapshot)
    shared = False
    current_path = (
        Path(current_report_path)
        if current_report_path is not None
        else project_root / CURRENT_REPORT_FILENAME if project_root is not None else None
    )
    if current_path is not None:
        if current_path.is_file():
            from ..web.services import ReportFeedbackService

            feedback = ReportFeedbackService(report_filename=str(current_path))
            current = feedback.load_report()
            if isinstance(current, dict) and report == current:
                scope_filename = str(current_path)
                shared = True
    return scope_filename, shared


def project_job_result(
    service: Any,
    job_id: str,
    *,
    config_path: Optional[Path | str] = None,
    current_report_path: Optional[Path | str] = None,
) -> Tuple[int, Dict[str, Any]]:
    """Serve one job's result envelope with the real findings projection.

    Returns ``(status_code, payload)``.  On success the payload carries the
    service result envelope (``report_id`` = bound snapshot byte hash,
    ``coverage``, ``questions``, ``artifacts``, ...) plus:

    * ``findings`` — the existing lightweight projection (report, findings
      with per-issue identity and acceptance, review ``report_id``,
      coverage, view, views) or ``None`` with the honest reason;
    * ``binding`` — the attempt identity the projection was bound to
      (job/run/revision/input_revision/status/report fields);
    * ``review_scope`` — the scope filename used for the review identity and
      whether it is shared with the current report.
    """

    if config_path is None:
        # No explicit path: fall back to the service's own saved config, so
        # the current-report comparison never depends on a process cwd.
        config_path = getattr(service, "config_path", None)
    project_root = _project_root_for(config_path)
    payload: Dict[str, Any] = {}
    for _ in range(_MAX_BINDING_ATTEMPTS):
        # Full attempt fence around the envelope: the binding is read before
        # AND after ``service.result`` — a resume that lands while the
        # envelope is being served makes the two reads disagree, so the
        # envelope is stale and the whole round is retried.  Identical report
        # bytes never make two attempts the same round, and the envelope's
        # coverage/questions/artifacts are only ever published together with
        # a binding of the very same round.
        before = _attempt_binding(service, job_id)
        response = service.result(job_id)
        status_code = int(getattr(response, "status_code", 500))
        payload = dict(getattr(response, "payload", {}) or {})
        if status_code != 200:
            return status_code, payload
        mid = _attempt_binding(service, job_id)
        if before is None or not _binding_matches(before, mid):
            continue
        if not payload.get("report_available"):
            # Honest boundary: no bound report, nothing to project.  The
            # reason (job_status/report_not_produced/...) already says why,
            # and the attached binding is the same round as this envelope.
            payload["binding"] = mid
            return 200, payload
        bound = service.load_bound_report(job_id)
        if bound is None:
            payload.update(
                report_available=False, findings=None, reason="report_artifact_unavailable"
            )
            return 200, payload
        report, snapshot = bound
        try:
            raw = Path(snapshot).read_bytes()
        except OSError:
            payload.update(report_available=False, findings=None, reason="report_artifact_missing")
            return 200, payload
        # Re-hash the exact bytes parsed below, never trusting a prior read.
        if hashlib.sha256(raw).hexdigest() != payload.get("report_id"):
            payload.update(report_available=False, findings=None, reason="report_artifact_mismatch")
            return 200, payload
        try:
            decoded = json.loads(raw)
            from ..reporting.shared_objects import decode_storage

            decoded = decode_storage(decoded)
        except (ValueError, UnicodeError):
            decoded = None
        if not isinstance(decoded, dict):
            payload.update(report_available=False, findings=None, reason="report_artifact_invalid")
            return 200, payload
        after = _attempt_binding(service, job_id)
        if not _binding_matches(mid, after):
            # The attempt moved between the reads (even with identical
            # report bytes); retry against the fresh envelope instead of
            # publishing one attempt's envelope with another's binding.
            continue
        scope_filename, shared = _review_scope(
            decoded, Path(snapshot), project_root, current_report_path
        )
        from ..web.services import ReportFeedbackService

        findings = ReportFeedbackService.project_report(decoded, scope_filename)
        payload["findings"] = findings
        payload["binding"] = mid
        payload["review_scope"] = {
            "filename": scope_filename,
            "shared_with_current": shared,
        }
        return 200, payload
    # The binding keeps moving under us: refuse honestly rather than guess.
    return 200, {
        "schema": payload.get("schema"),
        "job_id": job_id,
        "report_available": False,
        "report_id": None,
        "reason": "attempt_changed",
        "findings": None,
    }
