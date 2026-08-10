"""Candidate signal orchestration for the analyzer workflow."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List


CandidateDetector = Callable[[Dict[str, Any]], List[Dict[str, Any]]]
CandidateMerger = Callable[[List[Dict[str, Any]]], List[Dict[str, Any]]]
BudgetRefresher = Callable[..., Any]
CandidatePersister = Callable[[List[Dict[str, Any]]], None]


@dataclass
class CandidateSignalBatch:
    """Candidate sets produced before LLM validation."""

    local_candidates: List[Dict[str, Any]] = field(default_factory=list)
    graph_candidates: List[Dict[str, Any]] = field(default_factory=list)
    backend_candidates: List[Dict[str, Any]] = field(default_factory=list)
    merged_candidates: List[Dict[str, Any]] = field(default_factory=list)

    def summary_increment(self) -> Dict[str, int]:
        return {
            "regex": sum(
                1
                for item in self.local_candidates
                if item.get("candidate_source") == "regex_local_rule"
            ),
            "clang_ast_cfg": sum(
                1
                for item in self.local_candidates
                if item.get("candidate_source") == "clang_ast_cfg"
            ),
            "graph": len(self.graph_candidates),
            "svf_value_flow": sum(
                1
                for item in self.backend_candidates
                if item.get("candidate_source") == "svf_value_flow"
            ),
            "backend": len(self.backend_candidates),
            "total": len(self.merged_candidates),
        }

    def note(self) -> str:
        return (
            f"Added {len(self.local_candidates)} local backend candidate(s), "
            f"{len(self.graph_candidates)} graph/protocol candidate(s), "
            f"and {len(self.backend_candidates)} backend signal candidate(s)."
        )


class CandidatePipeline:
    """Collect, merge, summarize, and persist evidence-only candidates."""

    SUMMARY_KEYS = ("regex", "clang_ast_cfg", "svf_value_flow", "graph", "backend", "total")

    def __init__(
        self,
        *,
        local_detector: CandidateDetector,
        graph_detector: CandidateDetector,
        backend_detector: CandidateDetector,
        unified_merger: CandidateMerger,
        budget_refresher: BudgetRefresher,
        candidate_persister: CandidatePersister,
    ) -> None:
        self._local_detector = local_detector
        self._graph_detector = graph_detector
        self._backend_detector = backend_detector
        self._unified_merger = unified_merger
        self._budget_refresher = budget_refresher
        self._candidate_persister = candidate_persister

    def collect_signal_candidates(self, state: Dict[str, Any]) -> CandidateSignalBatch:
        # Focused planning and vulnerability mining historically executed the
        # same deterministic detectors twice.  Reuse the per-entry immutable
        # signal batch so expensive AST/CFG/graph/backend queries run once.
        cache = state.setdefault("_candidate_signal_cache", {})
        local_candidates = cache.get("local")
        if local_candidates is None:
            local_candidates = self._local_detector(state)
            cache["local"] = local_candidates
        graph_candidates = cache.get("graph")
        if graph_candidates is None:
            graph_candidates = self._graph_detector(state)
            cache["graph"] = graph_candidates
        backend_candidates = cache.get("backend")
        if backend_candidates is None:
            backend_candidates = self._backend_detector(state)
            cache["backend"] = backend_candidates
        merged_candidates = self._unified_merger(
            local_candidates + graph_candidates + backend_candidates
        )
        cache["merged"] = merged_candidates
        self._budget_refresher(
            state,
            "candidate_signals",
            rule_candidates=local_candidates,
            graph_candidates=graph_candidates,
            backend_candidates=backend_candidates,
        )
        return CandidateSignalBatch(
            local_candidates=local_candidates,
            graph_candidates=graph_candidates,
            backend_candidates=backend_candidates,
            merged_candidates=merged_candidates,
        )

    def accumulate_summary(
        self,
        state: Dict[str, Any],
        batch: CandidateSignalBatch,
    ) -> Dict[str, int]:
        summary = state.setdefault(
            "candidate_signal_summary",
            {key: 0 for key in self.SUMMARY_KEYS},
        )
        for key in self.SUMMARY_KEYS:
            summary.setdefault(key, 0)
        for key, value in batch.summary_increment().items():
            summary[key] += value
        return summary

    def persist(self, batch: CandidateSignalBatch) -> None:
        self._candidate_persister(batch.merged_candidates)
