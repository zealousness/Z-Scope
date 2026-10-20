from pathlib import Path
from types import SimpleNamespace

import pytest

from zscope.core.analysis import analyzer as analyzer_module
from zscope.core.analysis.analyzer import Analyzer
from zscope.common.cancellation import CancellationToken
from zscope.orchestration import parallel_analyzer as parallel_module
from zscope.orchestration.active_discovery import resolve_discovery_profile
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


@pytest.mark.parametrize("mode", ["off", "shadow"])
def test_snapshot_shadow_runs_after_blind_discovery_before_local_freeze(
    monkeypatch, tmp_path, mode
) -> None:
    from zscope.orchestration import snapshot_candidates

    analyzer = _analyzer(tmp_path, "balanced")
    analyzer.config.analysis.semantic_snapshot_candidate_mode = mode
    analyzer.semantic_result = object()
    state = _state(tmp_path)
    state.update(agent_context={}, notes=[])
    events = []

    def blind(current):
        assert not current["candidate_ledger"].records()
        assert not current["pending_new_issues"]
        events.append("blind")

    def register(result, registrar, **kwargs):
        assert events == ["blind"]
        assert not registrar.ledger._frozen
        assert result is analyzer.semantic_result
        assert kwargs["entry"] == "entry"
        assert kwargs["entry_file"] == "src/demo.c"
        events.append("snapshot")
        return [{"id": "shadow-1"}]

    def validate(current):
        assert current["candidate_ledger"]._frozen
        assert bool(current["pending_new_issues"]) == (mode == "shadow")
        events.append("validate")

    monkeypatch.setattr(analyzer, "_run_single_entry_active_discovery", blind)
    monkeypatch.setattr(snapshot_candidates, "register_conditional_snapshot_candidates", register)
    analyzer.validation_runner = SimpleNamespace(run=validate)
    analyzer._step_vulnerability_mining(state)
    analyzer._step_validate_findings(state)
    assert events == (
        ["blind", "snapshot", "validate"] if mode == "shadow" else ["blind", "validate"]
    )


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
            name="vulnerability_analyzer",
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


@pytest.mark.parametrize("entry_mode", ["single", "parallel"])
def test_both_entry_modes_pass_owned_context_to_investigation_factory(
    monkeypatch, tmp_path, entry_mode
) -> None:
    """An opt-in worker is wired before registration/freeze on both entry paths."""
    analyzer = _analyzer(tmp_path, "balanced")
    state = _state(tmp_path)
    cancellation = CancellationToken()
    analyzer.cancellation_token = cancellation
    semantic_map = SimpleNamespace(audit_units=(), functions=(), fingerprints={})
    marker_runner = object()
    calls = []
    coverage_calls = []
    target = analyzer_module if entry_mode == "single" else parallel_module

    class Builder:
        def __init__(self, *args, **kwargs):
            pass

        def build(self, entries):
            return semantic_map

    def factory(config, current_map, client, *, cancellation):
        calls.append((config, current_map, client, cancellation))
        return marker_runner

    def coverage(ledger, *, semantic_map):
        coverage_calls.append((ledger, semantic_map))
        return {"program-coverage-key"}

    class Coordinator:
        def __init__(self, *, investigation_runner, registrar, **kwargs):
            assert investigation_runner is marker_runner
            assert state["candidate_ledger"]._frozen is False

        def run(self, current_map, **kwargs):
            assert current_map is semantic_map
            assert kwargs["covered_keys"] == {"program-coverage-key"}
            return current_map, {"status": "complete", "enabled": True}

    monkeypatch.setattr(target, "ZeroLLMSecurityMapBuilder", Builder)
    monkeypatch.setattr(target, "make_investigation_runner", factory)
    monkeypatch.setattr(target, "candidate_coverage_keys", coverage)
    monkeypatch.setattr(target, "ActiveDiscoveryCoordinator", Coordinator)
    if entry_mode == "single":
        analyzer._run_single_entry_active_discovery(state)
        result = state["active_discovery"]
    else:
        parallel = object.__new__(ParallelAnalyzer)
        parallel.base_config = analyzer.config
        parallel.code_index = analyzer.code_index
        parallel._candidate_ledger = state["candidate_ledger"]
        parallel._cancellation_token = cancellation
        parallel._benchmark_ablation_override = None
        parallel._decision_fact_cache = None
        parallel._get_shared_semantic_overlay = lambda: {}
        parallel._scan_role_llm_client = lambda role: None
        parallel._historical_variant_keys_for_map = lambda current_map: set()
        parallel.run_id = "run"
        parallel._run_active_discovery([], resolve_discovery_profile(analyzer.config))
        result = parallel._active_discovery_state
    assert result["status"] == "complete"
    assert calls == [(analyzer.config, semantic_map, None, cancellation)]
    assert coverage_calls == [(state["candidate_ledger"], semantic_map)]
    assert state["candidate_ledger"]._frozen is False
