"""The real session token and HTTP consumer must receive the configured budget."""
import os
import sys
from pathlib import Path
sys.path.insert(0, str(Path(os.environ["PYTHONPATH"]) / "tests"))

from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import threading
import time

import pytest
from test_config_stop_at_consumers import _make_project, _v2_document
from zscope.common.cancellation import bind_cancellation_token
from zscope.config.config import ConfigLoader
from zscope.config.v3 import StopWindow
from zscope.framework.llm_client import LLMClient
from zscope.orchestration.execution_profile import arm_session_deadline, session_cancellation_token
from zscope.orchestration.scan_session import ScanSessionRunner


def real_runner(tmp_path):
    project = _make_project(tmp_path, document=_v2_document(str(tmp_path / "project")))
    config = ConfigLoader.load(str(project / "zscope.yaml"))
    return ScanSessionRunner(config, task_id="stop-budget-probe")


def test_config_budget_is_visible_on_real_shared_session_token(tmp_path):
    runner = real_runner(tmp_path)
    token = session_cancellation_token(runner)
    window = StopWindow(timezone="UTC", stop_at="08:00", resolved_stop_time=datetime.now(timezone.utc) + timedelta(seconds=10))
    guard = arm_session_deadline(runner, window)
    try:
        remaining = token.remaining_seconds()
        assert remaining is not None and 0 < remaining <= 10, (
            "the actual shared token read by LLM/process consumers must carry the budget, not only the watcher's separate token"
        )
        child_remaining = token.child(timeout_seconds=90).remaining_seconds()
        assert child_remaining is not None and 0 < child_remaining <= 10
    finally:
        guard.release()


def test_real_http_wait_is_bounded_by_the_config_stop_window(tmp_path):
    class SlowHeaders(BaseHTTPRequestHandler):
        def do_POST(self):
            self.rfile.read(int(self.headers.get("Content-Length", "0")))
            time.sleep(2.0)
            body = json.dumps({"choices": [{"message": {"role": "assistant", "content": "done"}, "finish_reason": "stop"}], "model": "controlled", "usage": {}}).encode()
            try:
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            except (BrokenPipeError, ConnectionResetError):
                pass
        def log_message(self, *args):
            pass
    server = ThreadingHTTPServer(("127.0.0.1", 0), SlowHeaders)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    runner = real_runner(tmp_path)
    token = session_cancellation_token(runner)
    client = LLMClient(api_key="unit-key", base_url=f"http://127.0.0.1:{server.server_port}/v1", models=["controlled"], timeout=4, max_retries=0)
    window = StopWindow(timezone="UTC", stop_at="08:00", resolved_stop_time=datetime.now(timezone.utc) + timedelta(seconds=0.3))
    guard = arm_session_deadline(runner, window)
    started = time.monotonic()
    try:
        with bind_cancellation_token(token):
            with pytest.raises(Exception):
                client.chat_completion([{"role": "user", "content": "budget probe"}])
        elapsed = time.monotonic() - started
        assert elapsed < 1.5, (
            f"0.3s configured budget was hidden from a real HTTP header wait: {elapsed:.3f}s"
        )
    finally:
        guard.release()
        client.close()
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
