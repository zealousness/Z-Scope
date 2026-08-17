from pathlib import Path
from types import SimpleNamespace

from zscope.core.analysis import analyzer as analyzer_module
from zscope.core.analysis.analyzer import Analyzer
from zscope.orchestration.candidates import CandidateLedger
from zscope.orchestration.parallel_analyzer import ParallelAnalyzer


class SingleEntryIndex:
    backend_name = "clang"

    def get_function_impl(self, query, **kwargs):
        return {
            "func_name": "entry",
            "index_name": "entry@src/demo.c:1-3",
            "file": "src/demo.c",
            "start_line": 1,
            "end_line": 3,
            "entry_exposure": "communication",
            "code": "int entry(char *src) { char dst[4]; memcpy(dst, src, 8); }",
        }

    def get_callees(self, query, limit=None):
        return []


def _analyzer(tmp_path: Path, depth: str) -> Analyzer:
    value = object.__new__(Analyzer)
    value.config = SimpleNamespace(
        analysis=SimpleNamespace(snapshot_dir=str(tmp_path / "snapshots")),
        project=SimpleNamespace(
            project_id="demo",
            project_root=tmp_path,
            entry_function="entry",
            agents=[],
        ),
        scan=SimpleNamespace(
            depth=depth,
            llm_profiles=SimpleNamespace(analysis="default", modeling="default"),
            rollout={},
        ),
    )
    value.code_index = SingleEntryIndex()
    value.llm_clients = {}
    value.defer_validation_to_scan = False
    value.decision_fact_cache = None
    value._get_semantic_overlay = lambda: {}
    return value


def _state(tmp_path: Path):
    ledger = CandidateLedger(project_id="demo", project_root=str(tmp_path), revision="rev")
    return {
        "entry_func": "entry",
        "entry_file_path": "src/demo.c",
        "entry_signature": "",
        "entry_identity": "src/demo.c::entry",
        "run_id": "run",
        "diff_focus": {"risk_score": 80},
        "candidate_ledger": ledger,
        "pending_new_issues": [],
        "total_context_tokens": 0,
        "total_cumulative_prompt_tokens": 0,
        "total_cumulative_completion_tokens": 0,
        "total_cumulative_total_tokens": 0,
    }


def test_single_entry_active_discovery_registers_before_validation(monkeypatch, tmp_path) -> None:
    class FakeCoordinator:
        def __init__(self, *, registrar, **kwargs):
            self.registrar = registrar

        def run(self, semantic_map, **kwargs):
            self.registrar.register_issues(
                [
                    {
                        "id": "HYP_single",
                        "candidate_source": "active_discovery",
                        "candidate_kind": "llm_active_discovery_hypothesis",
                        "defect_class": "bounds",
                        "impact_level": "high",
                        "confidence": 0.8,
                        "function": "entry",
                        "location": "src/demo.c:1",
                        "source": "src",
                        "sink": "memcpy",
                        "description": "single-entry hypothesis",
                        "entry_paths": [["src/demo.c::entry"]],
                        "attribution": {
                            "schema_version": "zscope.finding-attribution.v1",
                            "discovered_by": ["llm_active_discovery"],
                            "discovery_details": [
                                {"kind": "llm_active_discovery", "source_id": "AUDIT_single"}
                            ],
                            "decided_by": "unresolved",
                            "decision_level": "none",
                        },
                    }
                ],
                source="active_discovery",
                force_unconfirmed=True,
            )
            return semantic_map, {
                "enabled": True,
                "profile": "balanced",
                "status": "complete",
                "context_tokens": 0,
                "cumulative_prompt_tokens": 0,
                "cumulative_completion_tokens": 0,
                "cumulative_total_tokens": 0,
            }

    monkeypatch.setattr(analyzer_module, "ActiveDiscoveryCoordinator", FakeCoordinator)
    analyzer = _analyzer(tmp_path, "balanced")
    state = _state(tmp_path)

    analyzer._run_single_entry_active_discovery(state)

    assert len(state["pending_new_issues"]) == 1
    [record] = state["candidate_ledger"].records()
    assert record.record_role == "validation_obligation"
    assert record.status == "queued"
    assert record.disposition == ""
    assert state["active_discovery"]["json_export_path"].endswith("security_semantic_map.json")
    assert state["candidate_ledger"]._frozen is False


def test_single_entry_fast_profile_does_zero_security_map_work(monkeypatch, tmp_path) -> None:
    class ForbiddenBuilder:
        def __init__(self, *args, **kwargs):
            raise AssertionError("fast profile must not construct the semantic map")

    monkeypatch.setattr(analyzer_module, "ZeroLLMSecurityMapBuilder", ForbiddenBuilder)
    analyzer = _analyzer(tmp_path, "fast")
    state = _state(tmp_path)

    analyzer._run_single_entry_active_discovery(state)

    assert state["active_discovery"]["status"] == "disabled_by_profile"
    assert not (tmp_path / "snapshots" / "security_map.db").exists()


def test_single_entry_rollout_can_disable_discovery_at_balanced_depth(
    monkeypatch, tmp_path
) -> None:
    class ForbiddenBuilder:
        def __init__(self, *args, **kwargs):
            raise AssertionError("validator-only rollout must not construct the semantic map")

    monkeypatch.setattr(analyzer_module, "ZeroLLMSecurityMapBuilder", ForbiddenBuilder)
    analyzer = _analyzer(tmp_path, "balanced")
    analyzer.config.scan.rollout = {
        "stage": "validator_opt_in",
        "active_discovery_mode": "disabled",
    }
    state = _state(tmp_path)

    analyzer._run_single_entry_active_discovery(state)

    assert state["active_discovery"]["status"] == "disabled_by_rollout"
    assert state["active_discovery"]["rollout"]["stage"] == "validator_opt_in"


def test_single_entry_uses_public_modeling_and_analysis_profiles_separately(tmp_path) -> None:
    analyzer = _analyzer(tmp_path, "balanced")
    modeling_client = object()
    analysis_client = object()
    legacy_client = object()
    analyzer.llm_clients = {
        "modeling-profile": modeling_client,
        "analysis-profile": analysis_client,
        "legacy-profile": legacy_client,
        "default": legacy_client,
    }
    analyzer.config.scan.llm_profiles = SimpleNamespace(
        modeling="modeling-profile",
        analysis="analysis-profile",
    )
    analyzer.config.project.agents = [
        SimpleNamespace(
            name="active_discovery",
            enabled=True,
            llm_ref="legacy-profile",
        )
    ]

    assert analyzer._scan_role_llm_client("modeling") is modeling_client
    assert analyzer._scan_role_llm_client("analysis") is analysis_client
    assert analyzer._security_discovery_llm_client() is analysis_client

    parallel = object.__new__(ParallelAnalyzer)
    parallel.base_config = analyzer.config
    parallel._shared_llm_clients = analyzer.llm_clients
    assert parallel._scan_role_llm_client("modeling") is modeling_client
    assert parallel._scan_role_llm_client("analysis") is analysis_client
    assert parallel._active_discovery_llm_client() is analysis_client

    analyzer.config.scan.llm_profiles = SimpleNamespace()
    assert analyzer._scan_role_llm_client("analysis") is legacy_client
    parallel.base_config = analyzer.config
    assert parallel._scan_role_llm_client("analysis") is legacy_client
