"""Consumption tests for the public config v3 ``execution.stop_at`` boundary.

Fixed-clock unit tests cover the boundary bridge (remaining time, expiry
refusal, one-read config resolution, DST rejection, capability disclosure);
real-state tests cover the actual consumers: the SQLite job store through
``ScanJobService``, the HTTP and MCP bindings on top of it, a real detached
owner enforcing a config-derived window on a real scanner process, and the
real CLI entry with only the model endpoint and waits controlled.  v2
documents and window-less v3 documents keep the window-less behaviour
everywhere.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
import time
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Dict, Optional, Tuple

import pytest
from click.testing import CliRunner

from zscope.cli import cli as cli_module
from zscope.cli.cli import main as cli_main
from zscope.common import cancellation as cancellation_module
from zscope.common.cancellation import CancellationToken, bind_cancellation_token
from zscope.config.config import ConfigLoader
from zscope.config.v3 import StopWindow
from zscope.config.v3_preparation import prepare_saved_config
from zscope.framework.llm_client import LLMClient
from zscope.orchestration.execution_profile import (
    CONFIG_STOP_WINDOW_SOURCE,
    ExpiredStopWindowError,
    PersistedStopWindow,
    SessionDeadlineGuard,
    arm_session_deadline,
    persisted_window_closed,
    remaining_seconds,
    resolve_saved_config_stop_window,
    session_cancellation_token,
    stop_window_from_config,
)
from zscope.orchestration.jobs import identity
from zscope.orchestration.jobs.service import (
    STORE_DB_NAME,
    STORE_DIR_NAME,
    ScanJobService,
)
from zscope.orchestration.jobs.store import JobStore
from zscope.orchestration.scan_session import ScanSessionResult, ScanSessionRunner

# 2026-10-15T20:00Z == 2026-10-16T04:00+08:00 in Taipei, so the next local
# 08:00 boundary is 2026-10-16T08:00+08:00 == 2026-10-16T00:00Z.
FIXED_NOW = datetime(2026, 10, 15, 20, 0, 0, tzinfo=timezone.utc)
FIXED_WINDOW = StopWindow(
    timezone="Asia/Taipei",
    stop_at="08:00",
    resolved_stop_time=datetime(2026, 10, 16, 0, 0, 0, tzinfo=timezone.utc),
)

needs_proc = pytest.mark.skipif(
    not identity.proc_available(), reason="detached owner tests require Linux /proc"
)


# --- fixtures ---------------------------------------------------------------------


def _v3_document(*, execution: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    document: Dict[str, Any] = {
        "config_version": 3,
        "llms": {
            "default": {
                "base_urls": ["http://127.0.0.1:9/v1"],
                "models": ["unit-model"],
                "api_key": "unit-key",
            }
        },
        "project": {
            "root": ".",
            "language": "c_cpp",
            "platform": "linux_user",
            "targets": [{"id": "main", "compile_commands": "build/compile_commands.json"}],
        },
        "scan": {"preset": "quick"},
    }
    if execution is not None:
        document["execution"] = execution
    return document


def _v2_document(root: str = ".") -> Dict[str, Any]:
    return {
        "config_version": 2,
        "llms": {
            "default": {
                "base_urls": ["http://127.0.0.1:9/v1"],
                "models": ["unit-model"],
                "api_key": "unit-key",
            }
        },
        "project": {"root": root, "source_root": ".", "language": "c_cpp"},
        "scan": {"task": ""},
        "indexing": {"backend": "regex"},
        "concurrency": {
            "entry_workers": 1,
            "validator_workers": 1,
            "investigator_workers": 1,
            "evidence_completion_workers": 1,
            "index_workers": 1,
            "svf_workers": 1,
            "llm_max_inflight": 1,
        },
    }


def _materialize_cpp_project(root: Path) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    (root / "src").mkdir(exist_ok=True)
    (root / "src" / "lib.h").write_text(
        "#ifndef LIB_H\n#define LIB_H\nint process_data(const char *input, int len);\n#endif\n",
        encoding="utf-8",
    )
    (root / "src" / "lib.c").write_text(
        '#include "lib.h"\n'
        "int process_data(const char *input, int len) {\n"
        "    if (len > 4) {\n"
        "        return input[0];\n"
        "    }\n"
        "    return 0;\n"
        "}\n",
        encoding="utf-8",
    )
    (root / "build").mkdir(exist_ok=True)
    (root / "build" / "compile_commands.json").write_text(
        json.dumps(
            [
                {
                    "directory": str(root),
                    "file": "src/lib.c",
                    "arguments": ["cc", "-I", "src", "-c", "src/lib.c"],
                }
            ]
        ),
        encoding="utf-8",
    )
    return root


def _make_project(
    tmp_path: Path,
    *,
    document: Optional[Dict[str, Any]] = None,
    execution: Optional[Dict[str, Any]] = None,
    name: str = "project",
) -> Path:
    project = _materialize_cpp_project(tmp_path / name)
    data = document if document is not None else _v3_document(execution=execution)
    (project / "zscope.yaml").write_text(json.dumps(data, indent=2), encoding="utf-8")
    return project


def _minute_ahead_utc(offset_seconds: int = 91) -> Tuple[str, datetime, datetime]:
    """Local UTC ``HH:MM`` whose next occurrence is the upcoming minute.

    Adding ``offset_seconds`` guarantees the named minute has not started
    yet, so the strict next-occurrence resolution lands exactly at the start
    of that minute: between ``offset_seconds - 60`` and ``offset_seconds``
    from ``now``.  The expected boundary is returned so consumers can assert
    the resolved instant exactly.
    """

    now = datetime.now(timezone.utc)
    target = now + timedelta(seconds=offset_seconds)
    expected = target.replace(second=0, microsecond=0)
    return target.strftime("%H:%M"), now, expected


def _store_for(project: Path) -> JobStore:
    return JobStore(project / STORE_DIR_NAME / STORE_DB_NAME)


def _service(project: Path, **kwargs: Any) -> ScanJobService:
    kwargs.setdefault("spawn_owner", False)
    return ScanJobService(project / "zscope.yaml", **kwargs)


def _events(store: JobStore, job_id: str) -> list:
    items, _ = store.list_events(job_id, after_seq=0, limit=500)
    return items


# --- fixed-clock unit tests: the boundary bridge ----------------------------------


def test_stop_window_from_config_only_sees_v3_windows(tmp_path: Path) -> None:
    project = _make_project(tmp_path, execution={"timezone": "Asia/Taipei", "stop_at": "08:00"})
    window = stop_window_from_config(ConfigLoader.load(str(project / "zscope.yaml")))
    assert window is not None
    assert window.timezone == "Asia/Taipei"
    assert window.stop_at == "08:00"
    assert window.resolved_stop_time.tzinfo is not None

    bare = _make_project(tmp_path, name="bare", execution=None)
    assert stop_window_from_config(ConfigLoader.load(str(bare / "zscope.yaml"))) is None

    v2 = _make_project(
        tmp_path, name="legacy", document=_v2_document(root=str(tmp_path / "legacy"))
    )
    assert stop_window_from_config(ConfigLoader.load(str(v2 / "zscope.yaml"))) is None


def test_remaining_seconds_is_exact_then_expired_without_rolling(tmp_path: Path) -> None:
    now = FIXED_NOW
    assert remaining_seconds(FIXED_WINDOW, now=now) == 4 * 3600
    # One hour past the boundary: zero remaining, never negative, and the
    # boundary itself is never re-resolved to tomorrow's occurrence.
    past = FIXED_WINDOW.resolved_stop_time + timedelta(hours=1)
    assert remaining_seconds(FIXED_WINDOW, now=past) == 0.0


def test_arm_session_deadline_refuses_an_expired_window() -> None:
    token = CancellationToken()
    runner = SimpleNamespace(session_executor=SimpleNamespace(cancellation_token=token))
    past = FIXED_NOW - timedelta(hours=1)
    with pytest.raises(ExpiredStopWindowError, match="never silently rolled"):
        arm_session_deadline(runner, StopWindow("Asia/Taipei", "08:00", past), now=FIXED_NOW)
    assert not token.is_cancelled()


def test_arm_session_deadline_cancels_the_shared_token_at_the_boundary() -> None:
    token = CancellationToken()
    runner = SimpleNamespace(session_executor=SimpleNamespace(cancellation_token=token))
    window = StopWindow(
        timezone="Asia/Taipei",
        stop_at="08:00",
        resolved_stop_time=datetime.now(timezone.utc) + timedelta(seconds=0.4),
    )
    guard = arm_session_deadline(runner, window)
    try:
        assert not token.is_cancelled()
        deadline = time.monotonic() + 5.0
        while not token.is_cancelled() and time.monotonic() < deadline:
            time.sleep(0.02)
        assert token.is_cancelled()
        assert "stop window reached" in token.reason
        assert "08:00" in token.reason and "Asia/Taipei" in token.reason
    finally:
        guard.release()


def test_arm_session_deadline_release_stops_the_watcher() -> None:
    token = CancellationToken()
    runner = SimpleNamespace(session_executor=SimpleNamespace(cancellation_token=token))
    window = StopWindow(
        timezone="UTC",
        stop_at="08:00",
        resolved_stop_time=datetime.now(timezone.utc) + timedelta(seconds=0.6),
    )
    guard = SessionDeadlineGuard(runner, window).start()
    guard.release()
    time.sleep(0.2)
    # The watcher stopped on its own before the boundary: the thread is gone
    # and nothing has cancelled the token yet (~0.4s of budget left).
    assert not guard._thread.is_alive()
    assert not token.is_cancelled()
    # The tightened budget itself stays on the real token: deadlines only
    # tighten, and the boundary keeps passing in wall-clock time even after
    # the session that armed it has ended.
    time.sleep(0.6)
    assert token.remaining_seconds() == 0.0
    assert token.is_cancelled()
    assert "stop window reached" in token.reason


def test_session_cancellation_token_resolves_both_real_surfaces() -> None:
    token = CancellationToken()
    public_runner = SimpleNamespace(session_executor=SimpleNamespace(cancellation_token=token))
    assert session_cancellation_token(public_runner) is token
    private_runner = SimpleNamespace(_cancellation_token=token)
    assert session_cancellation_token(private_runner) is token
    with pytest.raises(RuntimeError, match="fake flag"):
        session_cancellation_token(SimpleNamespace())


# --- the stop budget on the real shared token and its children -------------------


def test_tighten_deadline_bounds_existing_and_future_children() -> None:
    token = CancellationToken(timeout_seconds=30)
    earlier_child = token.child(timeout_seconds=120)
    token.tighten_deadline(time.monotonic() + 5.0, reason="stop window reached: unit")

    # The shared token itself carries the budget...
    assert 0 < token.remaining_seconds() <= 5.0
    # ...a child created before the tighten is bounded through the parent
    # chain, a child created after inherits the tightened deadline at
    # creation, and a child with a tighter local budget keeps the tighter
    # one (pre-existing shorter budgets are never relaxed).
    assert 0 < earlier_child.remaining_seconds() <= 5.0
    assert 0 < token.child(timeout_seconds=120).remaining_seconds() <= 5.0
    assert 0 < token.child(timeout_seconds=1.0).remaining_seconds() <= 1.0


def test_tighten_deadline_never_extends_an_earlier_deadline() -> None:
    token = CancellationToken(timeout_seconds=2)
    token.tighten_deadline(time.monotonic() + 60, reason="later window")
    assert token.remaining_seconds() <= 2.0
    token.tighten_deadline(time.monotonic() + 1, reason="earlier window")
    assert token.remaining_seconds() <= 1.0


def test_tighten_deadline_preserves_cancelled_state_and_reason() -> None:
    token = CancellationToken()
    token.cancel("job_cancel_requested")
    token.tighten_deadline(time.monotonic() + 60, reason="stop window reached")
    assert token.is_cancelled()
    assert token.reason == "job_cancel_requested"


def test_tightened_deadline_follows_the_monotonic_clock(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    token = CancellationToken()
    clock = {"now": 1000.0}
    # Only the cancellation module's clock is replaced; the deadline must be
    # derived from it alone, so wall-clock changes can neither extend nor
    # shorten the budget.
    monkeypatch.setattr(
        cancellation_module, "time", SimpleNamespace(monotonic=lambda: clock["now"])
    )
    token.tighten_deadline(clock["now"] + 10, reason="stop window reached: unit")
    assert token.remaining_seconds() == 10.0
    clock["now"] += 5.0
    assert token.remaining_seconds() == 5.0
    assert not token.is_cancelled()
    clock["now"] += 5.5
    assert token.remaining_seconds() == 0.0
    assert token.is_cancelled()
    assert token.reason == "stop window reached: unit"


def test_arm_session_deadline_puts_the_budget_on_the_real_runner_token(
    tmp_path: Path,
) -> None:
    project = _make_project(tmp_path, document=_v2_document(root=str(tmp_path / "project")))
    config = ConfigLoader.load(str(project / "zscope.yaml"))
    runner = ScanSessionRunner(config, task_id="stop-budget")
    token = session_cancellation_token(runner)
    window = StopWindow(
        timezone="UTC",
        stop_at="08:00",
        resolved_stop_time=datetime.now(timezone.utc) + timedelta(seconds=10),
    )
    guard = arm_session_deadline(runner, window)
    try:
        # The real shared token the executors/analyzer/LLM client read must
        # carry the configured budget, and a child with a much looser local
        # budget stays bounded by it.
        remaining = token.remaining_seconds()
        assert remaining is not None and 0 < remaining <= 10
        child_remaining = token.child(timeout_seconds=90).remaining_seconds()
        assert child_remaining is not None and 0 < child_remaining <= 10
    finally:
        guard.release()


def test_earlier_window_is_not_extended_by_a_later_window() -> None:
    token = CancellationToken()
    runner = SimpleNamespace(session_executor=SimpleNamespace(cancellation_token=token))
    first = StopWindow(
        timezone="UTC",
        stop_at="08:00",
        resolved_stop_time=datetime.now(timezone.utc) + timedelta(seconds=2),
    )
    second = StopWindow(
        timezone="UTC",
        stop_at="09:00",
        resolved_stop_time=datetime.now(timezone.utc) + timedelta(seconds=30),
    )
    guard_first = arm_session_deadline(runner, first)
    guard_second = arm_session_deadline(runner, second)
    try:
        assert 0 < token.remaining_seconds() <= 2.0
    finally:
        guard_first.release()
        guard_second.release()


def test_external_cancel_reason_survives_the_window() -> None:
    token = CancellationToken()
    runner = SimpleNamespace(session_executor=SimpleNamespace(cancellation_token=token))
    window = StopWindow(
        timezone="UTC",
        stop_at="08:00",
        resolved_stop_time=datetime.now(timezone.utc) + timedelta(seconds=0.4),
    )
    guard = arm_session_deadline(runner, window)
    try:
        token.cancel("job_cancel_requested")
        deadline = time.monotonic() + 5.0
        while guard._thread.is_alive() and time.monotonic() < deadline:
            time.sleep(0.02)
        # The watcher observed the external cancel, stood down without
        # overriding it, and the original reason survives the window.
        assert not guard._thread.is_alive()
        time.sleep(0.6)
        assert token.reason == "job_cancel_requested"
    finally:
        guard.release()


def test_guard_release_recovers_after_a_runner_exception() -> None:
    token = CancellationToken()
    runner = SimpleNamespace(session_executor=SimpleNamespace(cancellation_token=token))
    window = StopWindow(
        timezone="UTC",
        stop_at="08:00",
        resolved_stop_time=datetime.now(timezone.utc) + timedelta(seconds=30),
    )
    guard = arm_session_deadline(runner, window)
    try:
        raise RuntimeError("scan failed mid-window")
    except RuntimeError:
        pass
    finally:
        guard.release()
    time.sleep(0.2)
    assert not guard._thread.is_alive()
    # The budget is still real for the token's remaining lifetime; only the
    # watcher is gone.
    assert 20 < token.remaining_seconds() <= 30


def test_real_http_wait_is_bounded_by_the_config_stop_window(tmp_path: Path) -> None:
    class SlowHeaders(BaseHTTPRequestHandler):
        def do_POST(self) -> None:
            self.rfile.read(int(self.headers.get("Content-Length", "0")))
            time.sleep(2.0)
            body = json.dumps(
                {
                    "choices": [
                        {
                            "message": {"role": "assistant", "content": "done"},
                            "finish_reason": "stop",
                        }
                    ],
                    "model": "controlled",
                    "usage": {},
                }
            ).encode()
            try:
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            except (BrokenPipeError, ConnectionResetError):
                pass

        def log_message(self, *args: Any) -> None:
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), SlowHeaders)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    project = _make_project(tmp_path, document=_v2_document(root=str(tmp_path / "project")))
    config = ConfigLoader.load(str(project / "zscope.yaml"))
    runner = ScanSessionRunner(config, task_id="stop-http-budget")
    token = session_cancellation_token(runner)
    client = LLMClient(
        api_key="unit-key",
        base_url=f"http://127.0.0.1:{server.server_port}/v1",
        models=["controlled"],
        timeout=4,
        max_retries=0,
    )
    window = StopWindow(
        timezone="UTC",
        stop_at="08:00",
        resolved_stop_time=datetime.now(timezone.utc) + timedelta(seconds=0.3),
    )
    guard = arm_session_deadline(runner, window)
    started = time.monotonic()
    try:
        with bind_cancellation_token(token):
            with pytest.raises(Exception):
                client.chat_completion([{"role": "user", "content": "budget probe"}])
        elapsed = time.monotonic() - started
        assert (
            elapsed < 1.5
        ), f"0.3s configured budget was hidden from a real HTTP header wait: {elapsed:.3f}s"
    finally:
        guard.release()
        client.close()
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


# --- reason precedence: earlier causes survive the config watcher ----------------


def test_cancel_if_deadline_distinguishes_first_causes() -> None:
    # A different, earlier binding deadline is not relabelled by a later one.
    token = CancellationToken()
    token.tighten_deadline(time.monotonic() + 0.05)
    assert token.cancel_if_deadline(time.monotonic() + 10, "stop window reached: unit") is False
    time.sleep(0.12)
    assert token.is_cancelled()
    assert token.reason == "deadline_exceeded"

    # A cancelled parent keeps its reason even when the child's own deadline
    # has also passed.
    parent = CancellationToken()
    child = parent.child()
    child_deadline = time.monotonic() + 0.05
    child.tighten_deadline(child_deadline, reason="child window")
    parent.cancel("caller_cancel_requested")
    time.sleep(0.1)
    assert child.cancel_if_deadline(child_deadline, "stop window reached: unit") is False
    assert child.reason == "caller_cancel_requested"

    # The token's own first-cause deadline does convert into its cancel.
    solo = CancellationToken()
    own_deadline = time.monotonic() + 0.05
    solo.tighten_deadline(own_deadline)
    time.sleep(0.1)
    assert solo.cancel_if_deadline(own_deadline, "stop window reached: unit") is True
    assert solo.reason == "stop window reached: unit"


def test_earlier_deadline_reason_survives_the_config_watcher(tmp_path: Path) -> None:
    project = _make_project(tmp_path, document=_v2_document(root=str(tmp_path / "project")))
    config = ConfigLoader.load(str(project / "zscope.yaml"))
    runner = ScanSessionRunner(config, task_id="stop-reason-earlier")
    token = session_cancellation_token(runner)
    # A pre-existing session budget tighter than the config window.
    token.tighten_deadline(time.monotonic() + 0.05)
    window = StopWindow(
        timezone="UTC",
        stop_at="08:00",
        resolved_stop_time=datetime.now(timezone.utc) + timedelta(seconds=10),
    )
    guard = arm_session_deadline(runner, window)
    try:
        guard._thread.join(timeout=2.0)
        assert not guard._thread.is_alive(), "watcher must observe the earlier cancellation"
        assert token.is_cancelled()
        # The earlier deadline keeps its true reason; the later window never
        # relabels it while its own boundary is still seconds away.
        assert token.reason == "deadline_exceeded"
        assert "stop window reached" not in token.reason
    finally:
        guard.release()


def test_parent_cancellation_reason_survives_the_config_watcher() -> None:
    parent = CancellationToken()
    child = parent.child()
    runner = SimpleNamespace(session_executor=SimpleNamespace(cancellation_token=child))
    window = StopWindow(
        timezone="UTC",
        stop_at="08:00",
        resolved_stop_time=datetime.now(timezone.utc) + timedelta(seconds=10),
    )
    guard = arm_session_deadline(runner, window)
    try:
        parent.cancel("caller_cancel_requested")
        guard._thread.join(timeout=2.0)
        assert not guard._thread.is_alive(), "watcher must observe the parent cancellation"
        assert child.is_cancelled()
        assert child.reason == "caller_cancel_requested"
        assert "stop window reached" not in child.reason
    finally:
        guard.release()


def test_own_window_reason_is_reported_when_it_fires_first() -> None:
    parent = CancellationToken()
    child = parent.child()
    runner = SimpleNamespace(session_executor=SimpleNamespace(cancellation_token=child))
    window = StopWindow(
        timezone="UTC",
        stop_at="08:00",
        resolved_stop_time=datetime.now(timezone.utc) + timedelta(seconds=0.3),
    )
    guard = arm_session_deadline(runner, window)
    try:
        deadline = time.monotonic() + 5.0
        while not child.is_cancelled() and time.monotonic() < deadline:
            time.sleep(0.02)
        assert child.is_cancelled()
        assert "stop window reached" in child.reason
        # A later parent cancel cannot relabel the first cause either.
        parent.cancel("caller_cancel_requested")
        assert "stop window reached" in child.reason
    finally:
        guard.release()


def test_resolve_saved_config_stop_window_one_read_fixed_clock(tmp_path: Path) -> None:
    project = _make_project(tmp_path, execution={"timezone": "Asia/Taipei", "stop_at": "08:00"})
    window = resolve_saved_config_stop_window(str(project / "zscope.yaml"), now=FIXED_NOW)
    assert window == PersistedStopWindow(
        source=CONFIG_STOP_WINDOW_SOURCE,
        timezone="Asia/Taipei",
        stop_at="08:00",
        resolved_stop_time="2026-10-16T00:00:00+00:00",
        stop_at_epoch=datetime(2026, 10, 16, 0, 0, tzinfo=timezone.utc).timestamp(),
        requested_stop_at="08:00 Asia/Taipei",
        resolved_local="2026-10-16T08:00:00+08:00",
    )


def test_resolve_saved_config_stop_window_returns_none_outside_v3(tmp_path: Path) -> None:
    v2 = _make_project(tmp_path / "legacy", document=_v2_document())
    assert resolve_saved_config_stop_window(str(v2 / "zscope.yaml"), now=FIXED_NOW) is None
    bare = _make_project(tmp_path / "bare", execution=None)
    assert resolve_saved_config_stop_window(str(bare / "zscope.yaml"), now=FIXED_NOW) is None
    # A v3 document with only a timezone (no stop_at) declares no window.
    tz_only = _make_project(
        tmp_path / "tzonly", execution={"timezone": "Asia/Taipei", "max_workers": 2}
    )
    assert resolve_saved_config_stop_window(str(tz_only / "zscope.yaml"), now=FIXED_NOW) is None


def test_resolve_saved_config_stop_window_keeps_dst_rejection(tmp_path: Path) -> None:
    # 02:30 does not exist in America/New_York on 2027-03-14 (spring gap).
    gap = _make_project(
        tmp_path / "gap", execution={"timezone": "America/New_York", "stop_at": "02:30"}
    )
    now_gap = datetime(2027, 3, 13, 15, 0, tzinfo=timezone(-timedelta(hours=5)))
    with pytest.raises(ValueError, match="daylight-saving gap"):
        resolve_saved_config_stop_window(str(gap / "zscope.yaml"), now=now_gap)
    # 01:30 occurs twice in America/New_York on 2027-11-07 (fall fold).
    fold = _make_project(
        tmp_path / "fold", execution={"timezone": "America/New_York", "stop_at": "01:30"}
    )
    now_fold = datetime(2027, 11, 6, 15, 0, tzinfo=timezone(-timedelta(hours=4)))
    with pytest.raises(ValueError, match="occurs twice"):
        resolve_saved_config_stop_window(str(fold / "zscope.yaml"), now=now_fold)


def test_v3_preparation_discloses_the_stop_window_consumers(tmp_path: Path) -> None:
    project = _make_project(
        tmp_path,
        execution={"timezone": "Asia/Taipei", "stop_at": "08:00", "max_workers": 4},
    )
    result = prepare_saved_config(str(project / "zscope.yaml"), now=FIXED_NOW)
    version3 = result["version3"]
    assert version3["execution"]["scheduler_consumer_wired"] is True
    assert version3["machine_flags"]["stop_window_scheduler_wired"] is True
    # Only the stop window is newly wired; the other declared-only fields
    # must not be swept along into a completion claim.
    assert version3["machine_flags"]["focus_wired"] is False
    assert version3["machine_flags"]["reproduction_wired"] is False
    assert version3["machine_flags"]["max_workers_wired"] is False
    assert version3["machine_flags"]["platform_wired"] is False
    assert set(version3["declared_not_consumed"]) == {
        "project.platform",
        "scan.focus",
        "scan.reproduction",
        "execution.max_workers",
    }
    stop_note = next(note for note in version3["wiring"] if note["field"] == "execution.stop_at")
    assert stop_note["state"] == "wired"
    assert "not wired yet" not in stop_note["detail"]
    assert "CLI" in stop_note["detail"] and "job" in stop_note["detail"]


# --- real SQLite job store through ScanJobService.start ---------------------------


def test_start_applies_the_config_stop_window_by_default(tmp_path: Path) -> None:
    stop_at, _, expected = _minute_ahead_utc()
    project = _make_project(tmp_path, execution={"timezone": "UTC", "stop_at": stop_at})
    service = _service(project)
    response = service.start(request_id="req-config-window")
    assert response.status_code == 202, response.payload
    job = response.payload["job"]
    resolved = datetime.fromisoformat(job["resolved_stop_time"])
    assert resolved == expected

    store = _store_for(project)
    row = store.get_job(job["job_id"])
    assert row is not None
    assert row["stop_at_epoch"] == pytest.approx(resolved.timestamp())
    assert row["requested_stop_at"] == f"{stop_at} UTC"
    # The creation event records the actual date/timezone/UTC of this run.
    created = next(e for e in _events(store, job["job_id"]) if e["kind"] == "job_created")
    assert created["data"]["stop_at_source"] == "config"
    assert created["data"]["stop_at_local"] == stop_at
    assert created["data"]["stop_at_timezone"] == "UTC"
    assert created["data"]["resolved_stop_time_local"] == resolved.isoformat()
    # The launch file the owner consumes carries the config-derived epoch.
    launch = json.loads((Path(row["run_dir"]) / "launch.json").read_text(encoding="utf-8"))
    assert launch["stop_at_epoch"] == pytest.approx(resolved.timestamp())


def test_start_explicit_stop_at_overrides_the_config_window(tmp_path: Path) -> None:
    config_stop_at, _, _ = _minute_ahead_utc()
    project = _make_project(tmp_path, execution={"timezone": "UTC", "stop_at": config_stop_at})
    explicit = (datetime.now(timezone.utc) + timedelta(seconds=1800)).isoformat()
    service = _service(project)
    response = service.start(stop_at=explicit, request_id="req-explicit")
    assert response.status_code == 202, response.payload
    job = response.payload["job"]
    resolved = datetime.fromisoformat(job["resolved_stop_time"])
    assert resolved == datetime.fromisoformat(explicit).astimezone(timezone.utc)

    store = _store_for(project)
    row = store.get_job(job["job_id"])
    assert row is not None
    assert row["requested_stop_at"] == explicit
    created = next(e for e in _events(store, job["job_id"]) if e["kind"] == "job_created")
    assert created["data"]["stop_at_source"] == "request"


def test_start_without_a_config_window_keeps_windowless_behaviour(tmp_path: Path) -> None:
    # v2 resolves project.root against the process CWD, so the fixture pins
    # the absolute project root to keep the store inside the test project.
    v2 = _make_project(
        tmp_path, name="legacy", document=_v2_document(root=str(tmp_path / "legacy"))
    )
    service = _service(v2)
    job = service.start(request_id="req-v2").payload["job"]
    assert job["resolved_stop_time"] is None
    store = _store_for(v2)
    row = store.get_job(job["job_id"])
    assert row is not None and row["stop_at_epoch"] is None

    bare = _make_project(tmp_path, name="bare", execution=None)
    job = _service(bare).start(request_id="req-bare-v3").payload["job"]
    store = _store_for(bare)
    row = store.get_job(job["job_id"])
    assert row is not None and row["stop_at_epoch"] is None


def test_start_duplicate_request_replays_the_original_window(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    stop_at, _, _ = _minute_ahead_utc()
    project = _make_project(tmp_path, execution={"timezone": "UTC", "stop_at": stop_at})
    service = _service(project)
    first = service.start(request_id="req-replay").payload["job"]
    original = first["resolved_stop_time"]

    # A replay must serve the registered marker without resolving the config
    # boundary again — a cross-date retry can never start a second job from
    # a re-resolved window.
    from zscope.orchestration.jobs import service as service_module

    def _must_not_resolve(*args: Any, **kwargs: Any) -> None:
        raise AssertionError("a replayed start must not re-resolve the config window")

    monkeypatch.setattr(service_module, "resolve_saved_config_stop_window", _must_not_resolve)
    replay = service.start(request_id="req-replay")
    assert replay.status_code == 202, replay.payload
    second = replay.payload["job"]
    assert second["job_id"] == first["job_id"]
    assert second["resolved_stop_time"] == original

    store = _store_for(project)
    row = store.get_job(first["job_id"])
    assert row is not None
    assert row["stop_at_epoch"] == pytest.approx(datetime.fromisoformat(original).timestamp())
    kinds = [event["kind"] for event in _events(store, first["job_id"])]
    assert kinds.count("request_replayed") == 1
    assert len(store.list_jobs()) == 1


def test_start_request_id_conflict_is_still_rejected(tmp_path: Path) -> None:
    project = _make_project(
        tmp_path, execution={"timezone": "UTC", "stop_at": _minute_ahead_utc()[0]}
    )
    service = _service(project)
    assert service.start(request_id="req-conflict").status_code == 202
    explicit = (datetime.now(timezone.utc) + timedelta(seconds=900)).isoformat()
    response = service.start(stop_at=explicit, request_id="req-conflict")
    assert response.status_code == 409
    assert response.payload["code"] == "request_id_conflict"


# --- a saved config whose boundary already passed is refused at creation ----------


def _closed_boundary(monkeypatch: pytest.MonkeyPatch) -> datetime:
    """Make the strict v3 resolver land on an instant that already passed."""

    from zscope.config import v3 as v3_module

    past = datetime.now(timezone.utc) - timedelta(hours=1)
    monkeypatch.setattr(v3_module, "resolve_stop_boundary", lambda stop_at, zone, *, now=None: past)
    return past


def test_persisted_window_closed_is_exact_and_never_rolls() -> None:
    window = PersistedStopWindow(
        source=CONFIG_STOP_WINDOW_SOURCE,
        timezone="Asia/Taipei",
        stop_at="08:00",
        resolved_stop_time=FIXED_WINDOW.resolved_stop_time.isoformat(),
        stop_at_epoch=FIXED_WINDOW.resolved_stop_time.timestamp(),
        requested_stop_at="08:00 Asia/Taipei",
        resolved_local=FIXED_WINDOW.resolved_stop_time.isoformat(),
    )
    assert persisted_window_closed(window, now=FIXED_NOW) is False
    # The boundary instant itself is closed: it is never re-resolved forward.
    assert persisted_window_closed(window, now=FIXED_WINDOW.resolved_stop_time) is True
    assert persisted_window_closed(window, now=FIXED_NOW + timedelta(days=3)) is True
    with pytest.raises(ValueError):
        persisted_window_closed(window, now=datetime(2026, 10, 15, 20, 0))


def test_start_refuses_an_already_closed_config_window(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    project = _make_project(
        tmp_path, execution={"timezone": "UTC", "stop_at": _minute_ahead_utc()[0]}
    )
    _closed_boundary(monkeypatch)
    service = _service(project)
    response = service.start(request_id="req-closed-window")
    assert response.status_code == 400, response.payload
    assert response.payload["code"] == "stop_window_closed"
    message = str(response.payload["error"])
    assert "already passed" in message
    assert "never silently rolled to tomorrow" in message
    details = response.payload["details"]
    assert details["requested_stop_at"].endswith("UTC")
    assert details["resolved_stop_time_local"]

    # Nothing was created: no job row, no attempt, no launch.
    store = _store_for(project)
    assert store.list_jobs() == []


def test_http_and_mcp_bindings_refuse_the_closed_config_window(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from zscope.mcp.jobs_adapter import McpJobsAdapter
    from zscope.web.scan_jobs_service import ScanJobsHttpService

    project = _make_project(
        tmp_path, execution={"timezone": "UTC", "stop_at": _minute_ahead_utc()[0]}
    )
    _closed_boundary(monkeypatch)
    service = _service(project)
    http_service = ScanJobsHttpService(project / "zscope.yaml", feedback=None, engine=service)
    status, payload = http_service.post("/api/jobs", {"request_id": "req-http-closed"})
    assert status == 400, payload
    assert payload["code"] == "stop_window_closed"

    adapter = McpJobsAdapter(project / "zscope.yaml", service=service)
    result = adapter.start({"request_id": "req-mcp-closed"})
    assert result.get("success") is False, result
    assert result["code"] == "stop_window_closed"
    assert result["status_code"] == 400
    assert _store_for(project).list_jobs() == []


def test_explicit_request_window_is_unaffected_by_a_closed_config(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    project = _make_project(
        tmp_path, execution={"timezone": "UTC", "stop_at": _minute_ahead_utc()[0]}
    )
    _closed_boundary(monkeypatch)
    explicit = (datetime.now(timezone.utc) + timedelta(seconds=1800)).isoformat()
    service = _service(project)
    response = service.start(stop_at=explicit, request_id="req-explicit-closed-config")
    assert response.status_code == 202, response.payload
    job = response.payload["job"]
    assert datetime.fromisoformat(job["resolved_stop_time"]) == datetime.fromisoformat(
        explicit
    ).astimezone(timezone.utc)
    created = next(
        event
        for event in _events(_store_for(project), job["job_id"])
        if event["kind"] == "job_created"
    )
    assert created["data"]["stop_at_source"] == "request"


def test_replay_of_an_accepted_window_survives_a_now_closed_config(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    project = _make_project(
        tmp_path, execution={"timezone": "UTC", "stop_at": _minute_ahead_utc()[0]}
    )
    service = _service(project)
    first = service.start(request_id="req-closed-replay").payload["job"]
    _closed_boundary(monkeypatch)
    replay = service.start(request_id="req-closed-replay")
    assert replay.status_code == 202, replay.payload
    assert replay.payload["job"]["job_id"] == first["job_id"]
    assert len(_store_for(project).list_jobs()) == 1


def test_resume_stays_windowless_when_the_config_window_is_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from test_scan_jobs import force_status

    project = _make_project(
        tmp_path, execution={"timezone": "UTC", "stop_at": _minute_ahead_utc()[0]}
    )
    service = _service(project)
    job = service.start(request_id="req-closed-resume").payload["job"]
    cancelled = force_status(_store_for(project), job["job_id"], "cancelled")
    _closed_boundary(monkeypatch)
    response = service.resume(
        job["job_id"],
        base_revision=int(cancelled["revision"]),
        request_id="req-closed-resume-2",
    )
    assert response.status_code == 202, response.payload
    resumed = response.payload["job"]
    assert resumed["job_id"] == job["job_id"]
    # A resumed attempt never re-applies the config window, closed or not.
    assert resumed["resolved_stop_time"] is None


# --- HTTP and MCP bindings on the same service ------------------------------------


def test_http_binding_start_uses_the_config_window(tmp_path: Path) -> None:
    from zscope.web.scan_jobs_service import ScanJobsHttpService

    stop_at, _, expected = _minute_ahead_utc()
    project = _make_project(tmp_path, execution={"timezone": "UTC", "stop_at": stop_at})
    http_service = ScanJobsHttpService(
        project / "zscope.yaml", feedback=None, engine=_service(project)
    )
    status, payload = http_service.post("/api/jobs", {"request_id": "req-http"})
    assert status == 202, payload
    resolved = datetime.fromisoformat(payload["job"]["resolved_stop_time"])
    assert resolved == expected


def test_mcp_adapter_start_uses_the_config_window(tmp_path: Path) -> None:
    from zscope.mcp.jobs_adapter import McpJobsAdapter

    stop_at, _, expected = _minute_ahead_utc()
    project = _make_project(tmp_path, execution={"timezone": "UTC", "stop_at": stop_at})
    adapter = McpJobsAdapter(project / "zscope.yaml", service=_service(project))
    result = adapter.start({"request_id": "req-mcp"})
    assert result.get("success") is True, result
    job = result["data"]["job"]
    resolved = datetime.fromisoformat(job["resolved_stop_time"])
    assert resolved == expected


# --- real detached owner enforcing a config-derived window ------------------------

OWNER_SCANNER_SCRIPT = """\
import sys
import time

time.sleep(300)
sys.exit(0)
"""


def _wait_terminal(service: ScanJobService, job_id: str, *, timeout: float) -> Dict[str, Any]:
    deadline = time.monotonic() + timeout
    last: Any = None
    while time.monotonic() < deadline:
        response = service.detail(job_id)
        assert response.status_code == 200, response.payload
        last = response.payload["job"]
        if last["status"] in {"completed", "partial", "cancelled", "failed", "lost"}:
            return last
        time.sleep(0.5)
    raise AssertionError(f"job did not reach a terminal state; last={last!r}")


@needs_proc
def test_config_stop_window_is_enforced_by_the_real_owner(tmp_path: Path) -> None:
    stop_at, _, expected = _minute_ahead_utc()
    project = _make_project(tmp_path, execution={"timezone": "UTC", "stop_at": stop_at})
    scanner = tmp_path / "scanner.py"
    scanner.write_text(OWNER_SCANNER_SCRIPT, encoding="utf-8")

    def builder(config_path: Path, scan_depth: Optional[str], python_executable: str):
        return [python_executable, str(scanner)]

    service = ScanJobService(
        project / "zscope.yaml",
        scan_command_builder=builder,
        terminate_grace=2.0,
    )
    response = service.start(request_id="req-owner-window")
    assert response.status_code == 202, response.payload
    job = response.payload["job"]
    resolved = datetime.fromisoformat(job["resolved_stop_time"])
    assert resolved == expected

    terminal = _wait_terminal(service, job["job_id"], timeout=160.0)
    assert terminal["status"] == "partial"
    assert terminal["error"]["code"] == "stop_window_reached"

    store = _store_for(project)
    events = _events(store, job["job_id"])
    reached = next(e for e in events if e["kind"] == "stop_window_reached")
    assert reached["data"]["resolved_stop_time"] == job["resolved_stop_time"]
    launch = json.loads(
        (Path(store.db_path.parent) / job["job_id"] / job["run_id"] / "launch.json").read_text(
            encoding="utf-8"
        )
    )
    assert launch["stop_at_epoch"] == pytest.approx(resolved.timestamp())


# --- real CLI entry (only the model endpoint and waits are controlled) ------------


def test_real_cli_entry_arms_the_config_stop_window(tmp_path: Path) -> None:
    stop_at, _, expected = _minute_ahead_utc()
    project = _make_project(tmp_path, execution={"timezone": "UTC", "stop_at": stop_at})
    config = project / "zscope.yaml"

    env = dict(os.environ)
    workspace = Path(__file__).resolve().parents[1]
    env["PYTHONPATH"] = str(workspace) + os.pathsep + env.get("PYTHONPATH", "")
    process = subprocess.Popen(
        [sys.executable, "-u", "-m", "zscope.cli.cli", "-c", str(config), "--discover-entries"],
        cwd=str(project),
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        env=env,
    )
    try:
        output, _ = process.communicate(timeout=120)
    except subprocess.TimeoutExpired:
        process.kill()
        output, _ = process.communicate()
        pytest.fail(f"real CLI did not finish within the bound; output tail: {output[-2000:]}")

    assert "Stop window armed:" in output
    armed_line = next(line for line in output.splitlines() if "Stop window armed" in line)
    assert f"{stop_at} UTC" in armed_line
    # The resolved boundary names the actual upcoming minute, and the real
    # remaining time at arming is inside the configured window.
    resolved = datetime.fromisoformat(armed_line.split("->", 1)[1].split("(")[0].strip())
    assert resolved == expected
    remaining = int(armed_line.rsplit("(", 1)[1].split("s", 1)[0])
    assert 20 <= remaining <= 91
    # The real scan started (index build, entry discovery, batch mode) under
    # the armed window, and the boundary did not fire prematurely: the scan
    # ended inside its window either way.  Whether the batch itself can
    # complete in this environment is the pre-existing unified-backend
    # question, not this slice's.
    assert "Batch mode activated" in output
    assert "stop window reached" not in output


def test_cli_refuses_an_expired_window_instead_of_rolling(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    project = _make_project(tmp_path, execution={"timezone": "Asia/Taipei", "stop_at": "08:00"})
    past = datetime.now(timezone.utc) - timedelta(hours=1)

    from zscope.config import v3 as v3_module

    monkeypatch.setattr(
        v3_module,
        "resolve_stop_boundary",
        lambda stop_at, zone, *, now=None: past,
    )

    captured: Dict[str, Any] = {}

    class FakeRunner:
        def __init__(self, config: Any, **kwargs: Any) -> None:
            captured["constructed"] = True
            self._cancellation_token = CancellationToken()

        def run(self) -> ScanSessionResult:
            captured["ran"] = True
            return ScanSessionResult(is_batch=True, exit_code=0)

    monkeypatch.setattr(cli_module, "ScanSessionRunner", FakeRunner)
    result = CliRunner().invoke(cli_main, ["-c", str(project / "zscope.yaml")])
    assert result.exit_code == 1
    assert "already passed" in result.output
    assert "never silently rolled to tomorrow" in result.output
    # The refusal happens before any scan work starts.
    assert captured.get("constructed") is True
    assert captured.get("ran") is not True


def test_cli_arms_and_releases_the_deadline_around_the_real_runner(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    project = _make_project(tmp_path, execution={"timezone": "Asia/Taipei", "stop_at": "08:00"})
    # Generous margin: the CLI loads the config from the workspace before it
    # arms, and that read is slower than the sub-second boundary itself.
    soon = datetime.now(timezone.utc) + timedelta(seconds=3.0)

    from zscope.config import v3 as v3_module

    monkeypatch.setattr(
        v3_module,
        "resolve_stop_boundary",
        lambda stop_at, zone, *, now=None: soon,
    )

    token = CancellationToken()

    class SlowRunner:
        def __init__(self, config: Any, **kwargs: Any) -> None:
            self.session_executor = SimpleNamespace(cancellation_token=token)

        def run(self) -> ScanSessionResult:
            # The controlled wait stands in for scan work that outlives the
            # boundary; the LLM client bounds its own waits by this token.
            time.sleep(4.5)
            return ScanSessionResult(is_batch=True, exit_code=0)

    monkeypatch.setattr(cli_module, "ScanSessionRunner", SlowRunner)
    result = CliRunner().invoke(cli_main, ["-c", str(project / "zscope.yaml")])
    assert result.exit_code == 0, result.output
    assert "Stop window armed:" in result.output
    # The boundary passed mid-run: the shared token was cooperatively
    # cancelled with the stop-window reason before the session ended.
    assert token.is_cancelled()
    assert "stop window reached" in token.reason
    assert "Interrupted entries: none." in result.output


def test_cli_keeps_current_behaviour_without_a_config_window(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bare = _make_project(tmp_path, name="bare", execution=None)
    v2 = _make_project(
        tmp_path, name="legacy", document=_v2_document(root=str(tmp_path / "legacy"))
    )

    captured: Dict[str, Any] = {}

    class FakeRunner:
        def __init__(self, config: Any, **kwargs: Any) -> None:
            captured.setdefault("tokens", []).append(CancellationToken())

        def run(self) -> ScanSessionResult:
            return ScanSessionResult(is_batch=True, exit_code=0)

    monkeypatch.setattr(cli_module, "ScanSessionRunner", FakeRunner)
    for project in (bare, v2):
        result = CliRunner().invoke(cli_main, ["-c", str(project / "zscope.yaml")])
        assert result.exit_code == 0, result.output
        assert "Stop window armed:" not in result.output
    # Two runs, no deadline watchers armed.
    assert len(captured["tokens"]) == 2
