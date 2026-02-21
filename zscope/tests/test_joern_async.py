"""Tests for Joern async CPG build and CodeIndex non-blocking mode."""

import threading
import time
from unittest.mock import MagicMock, patch

import pytest

from zscope.common.joern_client import JoernClient


class TestJoernAsyncBuild:
    def test_initial_status_idle(self):
        client = JoernClient()
        assert client.cpg_status == "idle"
        assert client.cpg_error is None

    def test_import_cpg_sync_sets_ready(self):
        client = JoernClient()
        client.query = MagicMock(return_value={"ok": True})
        assert client.import_cpg("/src") is True
        assert client.cpg_status == "ready"

    def test_import_cpg_sync_sets_error(self):
        client = JoernClient()
        client.query = MagicMock(return_value=None)
        assert client.import_cpg("/src") is False
        assert client.cpg_status == "error"
        assert client.cpg_error == "CPG import returned None"

    def test_import_cpg_async_transitions(self):
        event = threading.Event()

        def slow_query(cpgql):
            event.wait(timeout=5)
            return {"ok": True}

        client = JoernClient()
        client.query = slow_query
        client.import_cpg_async("/src")
        assert client.cpg_status == "building"

        event.set()
        client.wait_for_cpg(timeout=5)
        assert client.cpg_status == "ready"

    def test_import_cpg_async_error(self):
        def fail_query(cpgql):
            raise RuntimeError("boom")

        client = JoernClient()
        client.query = fail_query
        client.import_cpg_async("/src")
        client.wait_for_cpg(timeout=5)
        assert client.cpg_status == "error"
        assert "boom" in client.cpg_error

    def test_import_cpg_async_skip_if_building(self):
        event = threading.Event()

        def slow_query(cpgql):
            event.wait(timeout=5)
            return {"ok": True}

        client = JoernClient()
        client.query = slow_query
        client.import_cpg_async("/src")
        # Second call should be ignored
        client.import_cpg_async("/src2")
        assert client.cpg_status == "building"
        event.set()
        client.wait_for_cpg(timeout=5)
        assert client.cpg_status == "ready"

    def test_wait_for_cpg_timeout(self):
        event = threading.Event()

        def slow_query(cpgql):
            event.wait(timeout=10)
            return {"ok": True}

        client = JoernClient()
        client.query = slow_query
        client.import_cpg_async("/src")
        result = client.wait_for_cpg(timeout=0.1)
        assert result is False
        event.set()  # cleanup

    def test_wait_for_cpg_no_thread(self):
        client = JoernClient()
        # No build started, should return False (status is idle)
        assert client.wait_for_cpg(timeout=1) is False
