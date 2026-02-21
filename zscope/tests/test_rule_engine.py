"""Tests for RuleEngine and RuleMatch."""

import json
from unittest.mock import MagicMock, patch

import pytest

from zscope.core.rule_engine import RuleEngine, RuleMatch


@pytest.fixture
def mock_joern():
    client = MagicMock()
    client.joern_path = "joern"
    return client


@pytest.fixture
def mock_user_config(tmp_path):
    from zscope.config.user_config_store import UserConfigStore
    return UserConfigStore(tmp_path)


class TestRuleMatch:
    def test_to_dict(self):
        m = RuleMatch(
            rule_id="r1", rule_name="Test", category="memory",
            score=7.0, func_name="foo", file_path="a.c", line_number=10,
        )
        d = m.to_dict()
        assert d["rule_id"] == "r1"
        assert d["function"] == "foo"
        assert d["score"] == 7.0


class TestBuiltinScan:
    def test_parse_list(self, mock_joern):
        mock_joern.query.return_value = [
            {
                "name": "buffer-overflow",
                "title": "Buffer Overflow",
                "tags": ["memory"],
                "score": 8.0,
                "methodFullName": "copy_data",
                "filename": "util.c",
                "lineNumber": 42,
                "code": "memcpy(dst, src, len);",
            }
        ]
        engine = RuleEngine(mock_joern)
        matches = engine.run_builtin_scan()
        assert len(matches) == 1
        assert matches[0].rule_id == "buffer-overflow"
        assert matches[0].func_name == "copy_data"

    def test_parse_empty(self, mock_joern):
        mock_joern.query.return_value = []
        engine = RuleEngine(mock_joern)
        assert engine.run_builtin_scan() == []

    def test_parse_string_json(self, mock_joern):
        mock_joern.query.return_value = json.dumps([
            {"name": "r1", "title": "R1", "score": 5, "methodName": "f", "filename": "x.c", "lineNumber": 1}
        ])
        engine = RuleEngine(mock_joern)
        matches = engine.run_builtin_scan()
        assert len(matches) == 1

    def test_parse_non_list(self, mock_joern):
        mock_joern.query.return_value = None
        engine = RuleEngine(mock_joern)
        assert engine.run_builtin_scan() == []


class TestPairedFunctionChecks:
    def test_finds_missing_release(self, mock_joern, mock_user_config):
        mock_user_config.upsert_paired_function("memory", "my_alloc", "my_free")
        mock_joern.query.return_value = [
            {"name": "leaky_func", "filename": "leak.c", "lineNumber": 5}
        ]
        engine = RuleEngine(mock_joern, mock_user_config)
        matches = engine.run_paired_function_checks()
        assert len(matches) == 1
        assert matches[0].func_name == "leaky_func"
        assert "my_free" in matches[0].rule_name

    def test_no_pairs_configured(self, mock_joern, mock_user_config):
        engine = RuleEngine(mock_joern, mock_user_config)
        assert engine.run_paired_function_checks() == []

    def test_no_user_config(self, mock_joern):
        engine = RuleEngine(mock_joern, None)
        assert engine.run_paired_function_checks() == []

    def test_skips_internal_names(self, mock_joern, mock_user_config):
        mock_user_config.upsert_paired_function("lock", "lock", "unlock")
        mock_joern.query.return_value = [
            {"name": "<global>", "filename": "", "lineNumber": -1},
            {"name": "real_func", "filename": "a.c", "lineNumber": 1},
        ]
        engine = RuleEngine(mock_joern, mock_user_config)
        matches = engine.run_paired_function_checks()
        assert len(matches) == 1
        assert matches[0].func_name == "real_func"


class TestCustomScripts:
    def test_run_scripts(self, mock_joern, tmp_path):
        script = tmp_path / "check.sc"
        script.write_text("// dummy")
        engine = RuleEngine(mock_joern)
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0,
                stdout=json.dumps([{"rule_id": "custom1", "function": "bar", "file_path": "b.c", "line_number": 3}]),
            )
            matches = engine.run_custom_scripts(str(tmp_path))
        assert len(matches) == 1
        assert matches[0].rule_id == "custom1"

    def test_empty_dir(self, mock_joern, tmp_path):
        engine = RuleEngine(mock_joern)
        assert engine.run_custom_scripts(str(tmp_path)) == []
