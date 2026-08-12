from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from click.testing import CliRunner

import zscope.cli.cli as cli_module
import zscope.core.analysis.analyzer as analyzer_module
from zscope.cli.cli import main as zscope_main
from zscope.config.config import ConfigLoader
from zscope.core.analysis.analyzer import Analyzer
from zscope.core.validation.runner import ValidationRunner
from zscope.reporting.report import FinalReport
from zscope.reporting.schema import build_run_manifest
from zscope.rules.catalog import EffectiveRuleSet, RuleCatalog, RuleCatalogError
from zscope.rules.analyzer import RuleDrivenAnalyzer


def _config(root: Path, *, disabled_ids: list[str] | None = None) -> dict[str, Any]:
    data: dict[str, Any] = {
        "config_version": 2,
        "llms": {
            "default": {
                "base_urls": ["http://localhost/v1"],
                "models": ["unit-model"],
                "api_key": "unit-key",
            }
        },
        "project": {
            "root": str(root),
            "source_root": ".",
            "language": "c_cpp",
            "entry_discovery": {
                "enabled": True,
                "search_root": ".",
                "interface_files": ["include/**/*.h"],
                "max_entries": 20,
                "max_functions": 100,
            },
        },
        "scan": {"task": ""},
        "indexing": {"backend": "regex"},
        "concurrency": {
            "entry_workers": 2,
            "validator_workers": 2,
            "investigator_workers": 1,
            "evidence_completion_workers": 2,
            "index_workers": 2,
            "svf_workers": 1,
            "llm_max_inflight": 2,
        },
    }
    if disabled_ids is not None:
        data["rules"] = {"disabled_ids": disabled_ids}
    return data


def _write_config(
    root: Path, *, disabled_ids: list[str] | None = None, name: str = "zscope.yaml"
) -> Path:
    path = root / name
    path.write_text(
        json.dumps(_config(root, disabled_ids=disabled_ids), ensure_ascii=False),
        encoding="utf-8",
    )
    return path


@pytest.mark.parametrize(
    ("disabled_ids", "message"),
    [
        (["same_pointer_freed_twce"], r"rules\.disabled_ids\[0\].*did you mean"),
        (
            ["same_pointer_freed_twice", "same_pointer_freed_twice"],
            r"rules\.disabled_ids\[1\].*duplicate rule id",
        ),
        (["java_command_execution"], r"rules\.disabled_ids\[0\].*is for java"),
    ],
)
def test_config_loader_runs_strict_rule_preflight(
    tmp_path: Path, disabled_ids: list[str], message: str
) -> None:
    path = _write_config(tmp_path, disabled_ids=disabled_ids)

    with pytest.raises(RuleCatalogError, match=message):
        ConfigLoader.load(str(path))


def test_cli_rule_preflight_fails_before_code_index_is_constructed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = _write_config(tmp_path, disabled_ids=["same_pointer_freed_twce"])
    constructed = False

    class UnexpectedCodeIndex:
        def __init__(self, *_args: Any, **_kwargs: Any) -> None:
            nonlocal constructed
            constructed = True
            raise AssertionError("CodeIndex must not be created before rule preflight")

    monkeypatch.setattr(cli_module, "CodeIndex", UnexpectedCodeIndex)
    result = CliRunner().invoke(
        zscope_main,
        ["--config", str(path), "--plan-entries"],
    )

    assert result.exit_code == 2
    assert constructed is False


def test_config_loader_reports_disabled_rule_unavailable_for_backend(
    tmp_path: Path,
) -> None:
    config = ConfigLoader.load(
        str(
            _write_config(
                tmp_path,
                disabled_ids=["clang_cfg_use_after_release"],
            )
        )
    )

    assert config.effective_rules.disabled_ids == {"clang_cfg_use_after_release"}
    assert config.rule_validation_warnings
    assert "not applicable to backend 'regex'" in config.rule_validation_warnings[0]
    assert "clang_structure" in config.rule_validation_warnings[0]


def _governed_analyzer(effective: EffectiveRuleSet, tmp_path: Path) -> Analyzer:
    analyzer = Analyzer.__new__(Analyzer)
    analyzer.config = SimpleNamespace(project=None)
    analyzer.code_index = SimpleNamespace(project_root=tmp_path)
    analyzer.effective_rules = effective
    analyzer.rule_policy = effective.policy
    analyzer._semantic_overlay = {}
    analyzer.candidate_ledger = SimpleNamespace(revision="unit-revision")
    analyzer.decision_fact_cache = None
    analyzer._candidate_backend_profile = lambda: {}  # type: ignore[method-assign]
    return analyzer


def _identity_envelope() -> SimpleNamespace:
    return SimpleNamespace(
        schema_version="zscope.candidate.v3.3",
        candidate_uid="candidate",
        occurrence_uid="occurrence",
        history_key="history",
        evidence_hash="evidence",
        decision_evidence_hash="decision",
        provenance_hash="provenance",
        validation_cluster_uid="cluster",
        context_signature="context",
    )


def test_analyzer_second_gate_rejects_disabled_unknown_and_conflicting_candidates(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    catalog = RuleCatalog.builtin()
    effective = EffectiveRuleSet.build(
        catalog,
        language="c_cpp",
        backend="unified",
        disabled_ids=["same_pointer_freed_twice"],
    )
    analyzer = _governed_analyzer(effective, tmp_path)
    monkeypatch.setattr(analyzer_module, "annotate_candidate_evidence", lambda *_a, **_k: None)
    monkeypatch.setattr(
        analyzer_module,
        "annotate_issue_identity",
        lambda *_a, **_k: _identity_envelope(),
    )

    disabled = analyzer._annotate_candidate_issues(
        [{"rule_id": "same_pointer_freed_twice"}],
        checker="unit",
        path_kind="local",
    )
    assert disabled == []

    with pytest.raises(RuleCatalogError, match="unknown c_cpp rule id"):
        analyzer._annotate_candidate_issues(
            [{"rule_id": "not_registered"}],
            checker="unit",
            path_kind="local",
        )

    with pytest.raises(RuleCatalogError, match="does not match catalog"):
        analyzer._annotate_candidate_issues(
            [
                {
                    "rule_id": "unchecked_strchr_result",
                    "defect_class": "memory_leak",
                }
            ],
            checker="unit",
            path_kind="local",
        )


def test_analyzer_enriches_deterministic_candidate_but_never_disables_backend_signal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    catalog = RuleCatalog.builtin()
    effective = EffectiveRuleSet.build(
        catalog,
        language="c_cpp",
        backend="unified",
        disabled_ids=["same_pointer_freed_twice"],
    )
    analyzer = _governed_analyzer(effective, tmp_path)
    monkeypatch.setattr(analyzer_module, "annotate_candidate_evidence", lambda *_a, **_k: None)
    monkeypatch.setattr(
        analyzer_module,
        "annotate_issue_identity",
        lambda *_a, **_k: _identity_envelope(),
    )

    deterministic = analyzer._annotate_candidate_issues(
        [{"rule_id": "unchecked_strchr_result"}],
        checker="unit",
        path_kind="local",
    )
    assert deterministic[0]["candidate_kind"] == "deterministic_rule"
    assert deterministic[0]["rule"] == "unchecked_strchr_result"
    assert deterministic[0]["rule_engine"] == "cpp_regex"
    assert deterministic[0]["skill"] == "null_and_failure"
    assert deterministic[0]["evidence_pack"]["rule_revision"] == 1

    signal = analyzer._annotate_candidate_issues(
        [
            {
                "rule_id": "same_pointer_freed_twice",
                "candidate_source": "svf_value_flow",
            }
        ],
        checker="svf",
        path_kind="backend_signal",
    )
    assert len(signal) == 1
    assert signal[0]["candidate_kind"] == "backend_signal"
    assert signal[0]["signal_source"] == "svf_value_flow"
    assert signal[0]["native_rule_id"] == "same_pointer_freed_twice"


def test_effective_rule_hash_changes_config_and_validator_cache_identity(
    tmp_path: Path,
) -> None:
    config = ConfigLoader.load(str(_write_config(tmp_path)))
    analyzer = Analyzer.__new__(Analyzer)
    analyzer.config = config

    runner = ValidationRunner.__new__(ValidationRunner)
    runner.config = config
    runner.llm_clients = {}
    runner.code_index = SimpleNamespace(backend=None, backend_name="regex")
    runner.tool_policy_for_agent = lambda _name: None

    config_hash_before = analyzer._config_hash()
    validator_hash_before = runner._build_validation_environment_fingerprint()
    config.rule_catalog_provenance = SimpleNamespace(effective_sha256="changed-effective-hash")

    assert analyzer._config_hash() != config_hash_before
    assert runner._build_validation_environment_fingerprint() != validator_hash_before


def test_report_contract_exposes_catalog_and_deduplicated_candidate_counts() -> None:
    state = {
        "_candidate_signal_cache": {
            "local": [
                {
                    "rule_id": "same_pointer_freed_twice",
                    "rule_engine": "cpp_regex",
                    "candidate_kind": "deterministic_rule",
                    "occurrence_uid": "one",
                },
                {
                    "rule_id": "unchecked_strchr_result",
                    "rule_engine": "cpp_regex",
                    "candidate_kind": "deterministic_rule",
                    "occurrence_uid": "two",
                },
            ],
            "graph": [
                {
                    "rule_id": "same_pointer_freed_twice",
                    "rule_engine": "cpp_regex",
                    "candidate_kind": "deterministic_rule",
                    "occurrence_uid": "one",
                }
            ],
            "backend": [
                {
                    "rule_id": "svf_value_flow_uaf",
                    "candidate_kind": "backend_signal",
                    "occurrence_uid": "signal",
                }
            ],
        }
    }
    counts = Analyzer._rule_candidate_counts(state)
    catalog = {"schema_version": "zscope.rule-catalog.v1", "effective_sha256": "rules"}
    metadata = {
        "run_id": "run",
        "effective_rules_sha256": "rules",
        "rule_catalog": catalog,
        "rule_candidate_counts": counts,
    }

    assert counts == {
        "by_engine": {"cpp_regex": 2},
        "by_rule": {
            "unchecked_strchr_result": 1,
            "same_pointer_freed_twice": 1,
        },
        "total": 2,
    }
    report = FinalReport(
        entry_function="entry", overall_verdict="no_issue_found", metadata=metadata
    )
    serialized = report.to_dict()
    assert serialized["rule_catalog"] == catalog
    assert serialized["rule_candidate_counts"] == counts
    manifest = build_run_manifest(
        metadata,
        entry_function="entry",
        finding="clean",
        completeness="complete",
        issue_count=0,
        needs_review_count=0,
    )
    assert manifest["effective_rules_sha256"] == "rules"
    assert manifest["rule_catalog"] == catalog
    assert manifest["rule_candidate_counts"] == counts


def test_rule_driven_report_keeps_catalog_provenance_and_backend_signal_boundary() -> None:
    analyzer = RuleDrivenAnalyzer.__new__(RuleDrivenAnalyzer)
    analyzer.effective_rules = EffectiveRuleSet.build(
        RuleCatalog.builtin(), language="java", backend="joern"
    )
    analyzer.report_generator = SimpleNamespace(
        save_json_report=lambda _report: None,
        save_markdown_report=lambda _report: None,
    )

    report = analyzer._build_report(
        [
            {
                "rule_id": "joern.native.query",
                "native_rule_id": "joern.native.query",
                "candidate_kind": "backend_signal",
                "function": "entry",
                "file_path": "src/demo.c",
                "line_number": 7,
                "description": "native signal",
                "category": "backend_signal",
            }
        ],
        [],
    )

    assert report["rule_catalog"]["schema_version"] == "zscope.rule-catalog.v1"
    assert len(report["metadata"]["effective_rules_sha256"]) == 64
    assert report["rule_candidate_counts"] == {
        "total": 0,
        "by_engine": {},
        "by_rule": {},
    }
    assert report["metadata"]["backend_signal_counts"] == {"joern.native.query": 1}
