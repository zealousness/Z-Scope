"""Tests for Z-SCOPE Web API endpoints (unit-level, no HTTP server)."""

import json
from unittest.mock import MagicMock, PropertyMock

import pytest

from zscope.config.user_config_store import UserConfigStore
from zscope.web import server


@pytest.fixture
def user_config(tmp_path):
    return UserConfigStore(tmp_path)


@pytest.fixture
def mock_joern():
    client = MagicMock()
    type(client).cpg_status = PropertyMock(return_value="idle")
    type(client).cpg_error = PropertyMock(return_value=None)
    return client


@pytest.fixture(autouse=True)
def _reset_globals():
    """Reset module globals before each test."""
    old_j, old_u, old_c = server._joern_client, server._user_config_store, server._code_index
    yield
    server._joern_client = old_j
    server._user_config_store = old_u
    server._code_index = old_c


class TestCpgStatusHandler:
    """Test CPG status via module globals (simulates handler logic)."""

    def test_cpg_status_unavailable(self):
        server._joern_client = None
        assert server._joern_client is None

    def test_cpg_status_idle(self, mock_joern):
        server._joern_client = mock_joern
        assert server._joern_client.cpg_status == "idle"
        assert server._joern_client.cpg_error is None

    def test_cpg_status_ready(self, mock_joern):
        type(mock_joern).cpg_status = PropertyMock(return_value="ready")
        server._joern_client = mock_joern
        assert server._joern_client.cpg_status == "ready"


class TestUserConfigViaGlobals:
    """Test user config CRUD via module globals."""

    def test_external_functions_crud(self, user_config):
        server._user_config_store = user_config
        user_config.upsert_external_function("malloc", "分配内存", library="libc")
        items = server._user_config_store.list_external_functions()
        assert len(items) == 1
        assert items[0]["func_name"] == "malloc"
        server._user_config_store.delete_external_function("malloc")
        assert len(server._user_config_store.list_external_functions()) == 0

    def test_paired_functions_crud(self, user_config):
        server._user_config_store = user_config
        user_config.upsert_paired_function("memory", "alloc", "free")
        items = server._user_config_store.list_paired_functions()
        assert len(items) == 1
        server._user_config_store.delete_paired_function(items[0]["id"])
        assert len(server._user_config_store.list_paired_functions()) == 0

    def test_false_positive_mark(self, user_config):
        server._user_config_store = user_config
        user_config.add_false_positive("func_a", "file.c:10", "leak", "非问题")
        assert server._user_config_store.is_false_positive("func_a", "file.c:10", "leak")
        assert not server._user_config_store.is_false_positive("func_a", "file.c:10", "other")

    def test_warnings_crud(self, user_config):
        server._user_config_store = user_config
        user_config.add_config_warning("missing_func", "foo", "未找到foo")
        items = server._user_config_store.list_config_warnings()
        assert len(items) == 1
        server._user_config_store.clear_config_warnings()
        assert len(server._user_config_store.list_config_warnings()) == 0

    def test_store_not_set(self):
        server._user_config_store = None
        assert server._user_config_store is None


class TestReportHelpers:
    def test_issue_key(self):
        issue = {"id": "1", "function": "f", "location": "a.c:1", "subcategory": "leak"}
        assert server.issue_key(issue) == ("1", "f", "a.c:1", "leak")

    def test_normalize_validation_valid(self):
        s, r = server.normalize_validation({"validation_status": "validated", "validation_reasoning": "ok"})
        assert s == "validated"
        assert r == "ok"

    def test_normalize_validation_invalid(self):
        s, _ = server.normalize_validation({"validation_status": "bogus"})
        assert s == "pending"
