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
from zscope.core.validation.pipeline import ValidationPipeline
from zscope.core.validation.runner import ValidationRunner
from zscope.framework.base import AgentResponse
from zscope.reporting.report import FinalReport
from zscope.reporting.schema import build_run_manifest, exit_code_for_report
from zscope.rules.catalog import EffectiveRuleSet, RuleCatalog, RuleCatalogError
from zscope.rules.analyzer import RuleDrivenAnalyzer


class _RuleValidationMemory:
    def __init__(self) -> None:
        self.rows: list[tuple[str, str]] = []

    def is_false_positive(self, _func: str, _location: str, _category: str) -> bool:
        return False

    def get_finding_baseline_for_issue(self, _issue: dict[str, Any], _dedup_key: str) -> None:
        return None

    def get_finding_baseline(self, _dedup_key: str) -> None:
        return None

    def upsert_finding_baseline(
        self, dedup_key: str, status: str, _issue: dict[str, Any] | None = None
    ) -> None:
        self.rows.append((dedup_key, status))


class _RuleValidationCodeIndex:
    backend = None
    backend_name = "joern"

    def get_function_impl(self, _func: str, warn_missing: bool = False) -> dict[str, str]:
        del warn_missing
        return {"code": "void entry(void) { sink(); }"}

    def get_file_snippet(self, _path: str, _start: int, _end: int) -> str:
        return "sink();"

    def get_callers(self, _func: str, limit: int = 8) -> list[Any]:
        del limit
        return []

    def get_callees(self, _func: str, limit: int = 12) -> list[Any]:
        del limit
        return []


def _rule_validation_analyzer(
    tmp_path: Path,
    validator: Any,
    *,
    depth: str = "fast",
) -> RuleDrivenAnalyzer:
    analyzer = RuleDrivenAnalyzer.__new__(RuleDrivenAnalyzer)
    analyzer.config = SimpleNamespace(
        project=SimpleNamespace(
            project_root=tmp_path,
            entry_function="",
            agents=[
                SimpleNamespace(
                    name="validator_agent",
                    enabled=True,
                    llm_ref="default",
                )
            ],
        ),
        analysis=SimpleNamespace(
            snapshot_dir=tmp_path / "snapshots",
            validation_deadline_seconds=30,
            validation_cache_entries=0,
        ),
        concurrency=SimpleNamespace(
            validator_workers=1,
            evidence_completion_workers=1,
        ),
        scan=SimpleNamespace(
            depth=depth,
            llm_profiles=SimpleNamespace(validation="default"),
        ),
    )
    analyzer.code_index = _RuleValidationCodeIndex()
    analyzer.snapshot_store = SimpleNamespace(load_snapshot=lambda _name: None)
    analyzer.user_config = _RuleValidationMemory()
    analyzer.validation_pipeline = ValidationPipeline(analyzer.user_config)
    analyzer.llm_clients = {"default": object()}
    analyzer._validator_agent_factory = lambda *_args, **_kwargs: validator
    analyzer._get_tools = lambda _agent=None: []
    analyzer._tool_policy_for_agent = lambda _agent=None: None
    analyzer._attach_agent_contract = lambda _context, _agent: None
    analyzer._last_validation_state = {}
    analyzer.validation_runner = analyzer._make_validation_runner()
    return analyzer


def _rule_validator_result(
    input_data: dict[str, Any],
    *,
    verdict: str,
    validation_pass: str,
    missing_fact_request: dict[str, str] | None = None,
) -> dict[str, Any]:
    return {
        "schema_version": "zscope.validator-result.v3",
        "candidate_uid": input_data["finding_uid"],
        "validation_cluster_uid": input_data["validation_cluster_uid"],
        "pass": validation_pass,
        "verdict": verdict,
        "reasoning": "bounded rule-driven validation",
        "positive_evidence": ["backend signal and code context"],
        "negative_evidence": [],
        "evidence_refs": [],
        "blocking_negative_evidence": False,
        "missing_fact_request": missing_fact_request,
        "stop_reason": "missing_fact" if missing_fact_request else "decision_complete",
    }


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

    assert "clang_cfg_use_after_release" in config.effective_rules.disabled_ids
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
    descriptor = catalog.get("unchecked_strchr_result")
    assert descriptor is not None
    assert deterministic[0]["evidence_pack"]["rule_revision"] == descriptor.revision

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


def test_validator_stage_profile_overrides_legacy_agent_llm_ref(tmp_path: Path) -> None:
    config = ConfigLoader.load(str(_write_config(tmp_path)))
    config.llms["validation-stage"] = config.llms["default"]
    config.scan.llm_profiles.validation = "validation-stage"
    validator_cfg = next(
        agent for agent in config.project.agents if agent.name == "validator_agent"
    )
    validator_cfg.llm_ref = "default"

    selected: list[Any] = []
    runner = ValidationRunner.__new__(ValidationRunner)
    runner.config = config
    runner.llm_clients = {
        "default": object(),
        "validation-stage": object(),
    }
    runner.get_tools = lambda _name: []
    runner.tool_policy_for_agent = lambda _name: None
    runner.validator_agent_factory = lambda client, _tools, **_kwargs: selected.append(client)

    runner._build_validator_agent()

    assert selected == [runner.llm_clients["validation-stage"]]


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

    assert report["rule_catalog"]["schema_version"] == "zscope.rule-catalog.v2"
    assert len(report["metadata"]["effective_rules_sha256"]) == 64
    assert report["rule_candidate_counts"] == {
        "total": 0,
        "by_engine": {},
        "by_rule": {},
    }
    assert report["metadata"]["backend_signal_counts"] == {"joern.native.query": 1}
    assert report["metadata"]["candidate_funnel"]["schema_version"] == (
        "zscope.candidate-funnel.v1"
    )


def test_rule_driven_validator_rejection_is_explicit_needs_review(tmp_path: Path) -> None:
    class RejectingValidator:
        def run(self, input_data: dict[str, Any]) -> AgentResponse:
            return AgentResponse(
                success=True,
                data=_rule_validator_result(
                    input_data,
                    verdict="rejected",
                    validation_pass="initial",
                ),
            )

    analyzer = _rule_validation_analyzer(tmp_path, RejectingValidator())
    issues = analyzer._validate_matches(
        "entry",
        [
            {
                "rule_id": "joern.native.query",
                "function": "entry",
                "file_path": "src/demo.c",
                "line_number": 7,
                "description": "native signal",
                "category": "backend_signal",
            }
        ],
    )

    assert len(issues) == 1
    issue = issues[0]
    assert issue["model_verdict"] == "rejected"
    assert issue["candidate_disposition"] == "needs_review"
    assert issue["validation_status"] == "needs_review"
    assert issue["attribution"]["discovered_by"] == ["backend_signal"]
    assert issue["attribution"]["decided_by"] == "unresolved"
    assert issue["attribution"]["decision_level"] == "V1"


def test_rule_driven_deduplicates_equivalent_cross_rule_backend_signals(
    tmp_path: Path,
) -> None:
    class CountingValidator:
        def __init__(self) -> None:
            self.calls = 0

        def run(self, input_data: dict[str, Any]) -> AgentResponse:
            self.calls += 1
            return AgentResponse(
                success=True,
                data=_rule_validator_result(
                    input_data,
                    verdict="verified",
                    validation_pass="initial",
                ),
            )

    validator = CountingValidator()
    analyzer = _rule_validation_analyzer(tmp_path, validator)
    issues = analyzer._validate_matches(
        "entry",
        [
            {
                "rule_id": "joern.native.query.a",
                "rule_name": "native query A",
                "function": "entry",
                "file_path": "src/demo.c",
                "line_number": 7,
                "description": "first detector provenance",
                "category": "use_after_free",
                "candidate_uid": "CAND_PRODUCER_A",
                "validation_cluster_uid": "VCL_PRODUCER_A",
            },
            {
                "rule_id": "joern.native.query.b",
                "rule_name": "native query B",
                "function": "entry",
                "file_path": "src/demo.c",
                "line_number": 7,
                "description": "second detector provenance",
                "category": "use_after_free",
                "candidate_uid": "CAND_PRODUCER_B",
                "validation_cluster_uid": "VCL_PRODUCER_B",
            },
        ],
    )

    assert validator.calls == 1
    assert len(issues) == 1
    issue = issues[0]
    aliases = issue["backend_signal_provenance_aliases"]
    assert {item["native_rule_id"] for item in aliases} == {
        "joern.native.query.a",
        "joern.native.query.b",
    }
    assert issue["grouped_candidate_count"] == 2
    assert issue["validation_group_alias_count"] == 1
    assert issue["validator_invocation_count"] == 1
    assert issue["attribution"]["discovered_by"] == ["backend_signal"]
    assert {item["native_rule_id"] for item in issue["attribution"]["discovery_details"]} == {
        "joern.native.query.a",
        "joern.native.query.b",
    }

    state = analyzer._last_validation_state
    assert state["candidate_discovery_frozen"] is True
    assert state["scan_level_raw_occurrence_count"] == 2
    assert state["validation_group_count"] == 1
    assert state["validation_group_merged_count"] == 1
    assert state["candidate_ledger_summary"]["validation_group_count"] == 1
    assert state["candidate_ledger_summary"]["duplicates_merged"] == 1
    assert len(state["candidate_terminal_states"]) == 1
    terminal_issue = state["candidate_terminal_states"][0]["issue"]
    assert {
        item["native_rule_id"] for item in terminal_issue["backend_signal_provenance_aliases"]
    } == {"joern.native.query.a", "joern.native.query.b"}

    analyzer.effective_rules = EffectiveRuleSet.build(
        RuleCatalog.builtin(), language="java", backend="joern"
    )
    analyzer.report_generator = SimpleNamespace(
        save_json_report=lambda _report: None,
        save_markdown_report=lambda _report: None,
    )
    report = analyzer._build_report(issues, [])
    funnel = report["metadata"]["candidate_funnel"]["stages"]
    assert funnel["raw_occurrences"]["count"] == 2
    assert funnel["canonical_validation_groups"]["count"] == 1
    assert funnel["validator_invoked_groups"]["count"] == 1
    assert report["metadata"]["backend_signal_counts"] == {
        "joern.native.query.a": 1,
        "joern.native.query.b": 1,
    }


def test_rule_driven_uses_shared_v0_without_calling_validator(tmp_path: Path) -> None:
    class UnexpectedValidator:
        def run(self, _input_data: dict[str, Any]) -> AgentResponse:
            raise AssertionError("V0 proof must avoid the Validator")

    analyzer = _rule_validation_analyzer(tmp_path, UnexpectedValidator())
    issues = analyzer._validate_matches(
        "entry",
        [
            {
                "rule_id": "joern.native.query",
                "function": "entry",
                "file_path": "src/demo.c",
                "line_number": 7,
                "description": "native signal",
                "category": "backend_signal",
                "deterministic_proofs": [
                    {
                        "outcome": "confirm",
                        "proof_kind": "deterministic_cfg_obligation_path",
                        "producer_engine": "joern_fact_prover",
                        "fact_ids": ["fact:source", "fact:sink"],
                        "code_hash": "body-v1",
                        "facts": ["source_to_sink_complete", "event_path_complete"],
                        "completeness": "complete",
                    }
                ],
            }
        ],
    )

    assert issues[0]["candidate_disposition"] == "confirmed"
    assert issues[0]["validator_invocation_count"] == 0
    assert issues[0]["attribution"]["discovered_by"] == ["backend_signal"]
    assert issues[0]["attribution"]["decided_by"] == "deterministic_proof"
    assert issues[0]["attribution"]["decision_level"] == "V0"
    assert analyzer._last_validation_state["validator_avoided_count"] == 1


def test_rule_driven_uses_fact_resolution_v2_and_eligible_v3(tmp_path: Path) -> None:
    class LayeredValidator:
        def __init__(self) -> None:
            self.passes: list[str] = []
            self.investigations = 0

        def run(self, input_data: dict[str, Any]) -> AgentResponse:
            validation_pass = str(input_data["validation_pass"])
            self.passes.append(validation_pass)
            request = (
                {
                    "fact_kind": "caller_contract",
                    "subject_uid": "entry",
                    "function_uid": "entry",
                    "reason": "caller contract is missing",
                }
                if validation_pass == "initial"
                else None
            )
            return AgentResponse(
                success=True,
                data=_rule_validator_result(
                    input_data,
                    verdict="uncertain",
                    validation_pass=validation_pass,
                    missing_fact_request=request,
                ),
            )

        def investigate(
            self,
            input_data: dict[str, Any],
            *,
            max_iterations: int,
        ) -> AgentResponse:
            self.investigations += 1
            assert max_iterations == 50
            return AgentResponse(
                success=True,
                data=_rule_validator_result(
                    input_data,
                    verdict="verified",
                    validation_pass="investigation_synthesis",
                ),
            )

    validator = LayeredValidator()
    analyzer = _rule_validation_analyzer(tmp_path, validator, depth="balanced")
    issues = analyzer._validate_matches(
        "entry",
        [
            {
                "rule_id": "joern.native.query",
                "function": "entry",
                "file_path": "src/demo.c",
                "line_number": 7,
                "description": "native signal",
                "category": "backend_signal",
                "impact_level": "critical",
                "externally_reachable": True,
                "fact_completion_by_kind": {
                    "caller_contract": [
                        {
                            "kind": "caller_contract",
                            "value": "entry is externally reachable",
                        }
                    ]
                },
            }
        ],
    )

    assert validator.passes == ["initial", "evidence_recheck"]
    assert validator.investigations == 1
    issue = issues[0]
    assert issue["validator_fact_resolution"]["status"] == "completed_partial"
    assert issue["validator_result_pass"] == "investigation_synthesis"
    assert issue["validator_invocation_count"] == 3
    assert issue["attribution"]["discovered_by"] == ["backend_signal"]
    assert issue["attribution"]["decision_level"] == "V3"
