from __future__ import annotations

import time
from pathlib import Path

from zscope.config.config import (
    AgentConfig,
    AnalysisConfig,
    ConcurrencyConfig,
    IndexingConfig,
    LLMConfig,
    ProjectConfig,
    ZScopeConfig,
)
from zscope.config.function_entry import FunctionEntry
from zscope.orchestration import parallel_analyzer as parallel_module
from zscope.orchestration.parallel_analyzer import ParallelAnalyzer


class FakeCodeIndex:
    pass


def _config(
    tmp_path: Path,
    *,
    entry_budget_seconds: float,
    budget_exhaustion_policy: str,
    scan_budget_seconds: float | None = None,
) -> ZScopeConfig:
    llm = LLMConfig(
        api_key="test",
        base_url="http://localhost",
        models=["test"],
    )
    return ZScopeConfig(
        llm=llm,
        llms={"default": llm},
        indexing=IndexingConfig(),
        analysis=AnalysisConfig(
            snapshot_dir=str(tmp_path / "snapshots"),
            user_config_db=str(tmp_path / "user-config"),
            entry_deadline_seconds=entry_budget_seconds,
            scan_deadline_seconds=scan_budget_seconds,
            budget_exhaustion_policy=budget_exhaustion_policy,
        ),
        project=ProjectConfig(
            project_root=tmp_path,
            source_root=tmp_path,
            agents=[AgentConfig(name="active_discovery", task="audit")],
        ),
        concurrency=ConcurrencyConfig(entry_workers=1),
    )


def _install_slow_analyzer(monkeypatch, observed_remaining):
    class SlowAnalyzer:
        _git_commit_sha = staticmethod(lambda _project_root: "")

        def __init__(self, *args, cancellation_token=None, **kwargs):
            self.cancellation_token = cancellation_token

        def run(self):
            observed_remaining.append(self.cancellation_token.remaining_seconds())
            time.sleep(0.03)
            self.cancellation_token.raise_if_cancelled()
            return {
                "overall_verdict": "no_issue_found",
                "issues": [],
                "candidate_terminal_states": [],
                "metadata": {
                    "audit_observations": [],
                    "context_tokens": 1,
                    "budget_observations": [
                        {
                            "kind": "llm_iteration_budget",
                            "budget_reached": True,
                            "hard_failure": False,
                        }
                    ],
                },
            }

    monkeypatch.setattr(parallel_module, "Analyzer", SlowAnalyzer)


def test_entry_budget_is_observe_only_and_reported(monkeypatch, tmp_path) -> None:
    parallel = ParallelAnalyzer(
        _config(
            tmp_path,
            entry_budget_seconds=0.005,
            budget_exhaustion_policy="observe",
        ),
        code_index=FakeCodeIndex(),
        maintain_mode=True,
    )
    observed_remaining = []
    _install_slow_analyzer(monkeypatch, observed_remaining)

    result = parallel._analyze_single_entry(FunctionEntry("slow_entry"))

    assert result.verdict == "no_issue_found"
    assert result.error is None
    assert observed_remaining == [None]
    assert result.entry_budget_seconds == 0.005
    assert result.entry_budget_exceeded is True
    assert result.entry_budget_overrun_seconds > 0
    assert result.metadata["entry_budget_exceeded"] is True
    assert result.metadata["entry_budget"]["policy"] == "observe"

    report = parallel.generate_combined_report({"slow_entry": result})
    function_summary = report["function_results"][0]
    assert function_summary["entry_budget_exceeded"] is True
    assert function_summary["entry_budget_overrun_seconds"] > 0
    assert report["summary"]["entry_budget"]["exceeded_entry_count"] == 1
    assert report["metadata"]["entry_budget"]["exceeded_entry_count"] == 1
    assert report["summary"]["llm_iteration_budget"]["budget_reached_count"] == 1
    assert report["summary"]["llm_iteration_budget"]["hard_failure_count"] == 0


def test_legacy_hard_policy_is_normalized_to_observe(monkeypatch, tmp_path) -> None:
    parallel = ParallelAnalyzer(
        _config(
            tmp_path,
            entry_budget_seconds=0.005,
            budget_exhaustion_policy="cancel",
        ),
        code_index=FakeCodeIndex(),
        maintain_mode=True,
    )
    observed_remaining = []
    _install_slow_analyzer(monkeypatch, observed_remaining)

    result = parallel._analyze_single_entry(FunctionEntry("slow_entry"))

    assert result.verdict == "no_issue_found"
    assert result.error is None
    assert observed_remaining == [None]
    assert result.entry_budget_exceeded is True
    assert result.metadata["budget_exhaustion_policy"] == "observe"


def test_scan_budget_is_observed_and_all_entries_complete(
    monkeypatch,
    tmp_path,
) -> None:
    parallel = ParallelAnalyzer(
        _config(
            tmp_path,
            entry_budget_seconds=1.0,
            scan_budget_seconds=0.005,
            budget_exhaustion_policy="observe",
        ),
        code_index=FakeCodeIndex(),
        maintain_mode=True,
    )
    observed_remaining = []
    _install_slow_analyzer(monkeypatch, observed_remaining)

    results = parallel.analyze_function_entries([FunctionEntry("first"), FunctionEntry("second")])

    assert set(results) == {"first", "second"}
    assert all(result.verdict == "no_issue_found" for result in results.values())
    assert observed_remaining == [None, None]
    assert parallel._last_scan_budget_metadata["scan_budget_exceeded"] is True
    assert parallel._last_scan_budget_metadata["scan_budget_overrun_seconds"] > 0
