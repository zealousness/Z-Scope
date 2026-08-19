"""Risk-adaptive runtime budgets for analysis orchestration."""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence

from ..config.config import AnalysisConfig


CONTROL_FLOW_RE = re.compile(
    r"\b(switch|case|goto|state|status|opcode|cmd|message|event|handler|dispatch)\b",
    re.IGNORECASE,
)
INDIRECT_CALL_RE = re.compile(
    r"(\(\s*\*\s*[A-Za-z_]\w*\s*\)|[A-Za-z_]\w*\s*->\s*[A-Za-z_]\w*)\s*\("
)
CALLBACK_RE = re.compile(
    r"\b(callback|register|unregister|notify|timer|workqueue|pthread_create|thread|irq|tasklet)\b",
    re.IGNORECASE,
)
PROTOCOL_FLOW_RE = re.compile(
    r"(?:runtime|event|callback|timer|rcu|qrcu|crcu|shared|shm|memzone|"
    r"proc|slot|signal|pool|cache|arena|worker|publish|schedule|configure|"
    r"apply|refresh|maintenance)",
    re.IGNORECASE,
)
CALL_TOKEN_RE = re.compile(r"\b([A-Za-z_]\w*)\s*\(")
KEYWORD_CALLS = {
    "if",
    "for",
    "while",
    "switch",
    "return",
    "sizeof",
    "case",
    "do",
}


@dataclass
class EffectiveBudget:
    """Effective runtime budget after risk adaptation."""

    recursion_depth: int
    graph_depth: int
    graph_functions: int
    hard_caps: Dict[str, int] = field(default_factory=dict)
    risk_scores: Dict[str, int] = field(default_factory=dict)
    risk_reasons: Dict[str, List[str]] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "recursion_depth": self.recursion_depth,
            "graph_depth": self.graph_depth,
            "graph_functions": self.graph_functions,
            "hard_caps": dict(self.hard_caps),
            "risk_scores": dict(self.risk_scores),
            "risk_reasons": {key: list(value) for key, value in self.risk_reasons.items()},
        }


class RiskBudgetPlanner:
    """Turn configured hard caps into per-run effective analysis budgets.

    The user-facing ``max_*`` settings remain hard upper bounds. The planner
    allocates less than those caps for low-risk functions and approaches the
    caps only when the relevant risk dimension has evidence for doing so.
    """

    def __init__(self, analysis_config: AnalysisConfig):
        self.analysis_config = analysis_config

    def hard_caps(self) -> Dict[str, int]:
        recursion_depth = self._non_negative(self.analysis_config.max_recursion_depth)
        graph_breadth = 20
        return {
            "max_recursion_depth": recursion_depth,
            "max_graph_functions": (graph_breadth * recursion_depth if recursion_depth > 0 else 0),
        }

    def plan(
        self,
        state: Mapping[str, Any],
        *,
        rule_candidates: Optional[Sequence[Any]] = None,
        graph_candidates: Optional[Sequence[Any]] = None,
        backend_candidates: Optional[Sequence[Any]] = None,
    ) -> EffectiveBudget:
        impl = self._mapping(state.get("impl_result"))
        agent_context = self._mapping(state.get("agent_context"))
        code = str(impl.get("code") or agent_context.get("code") or "")
        call_tokens = self._call_tokens(code)
        candidates = (
            list(rule_candidates or [])
            + list(graph_candidates or [])
            + list(backend_candidates or [])
        )

        scores: Dict[str, int] = {}
        reasons: Dict[str, List[str]] = {}

        scores["recursion_depth"], reasons["recursion_depth"] = self._score_recursion(
            code,
            call_tokens,
            candidates,
            self._historical_issues(state),
        )
        caps = self.hard_caps()
        recursion_depth = self._depth_budget(scores["recursion_depth"], caps["max_recursion_depth"])
        graph_depth = (
            min(caps["max_recursion_depth"], max(1, recursion_depth))
            if caps["max_recursion_depth"] > 0
            else 0
        )
        graph_functions = (
            min(
                caps["max_graph_functions"],
                max(8, self._breadth_budget(scores["recursion_depth"], 20) * max(1, graph_depth)),
            )
            if caps["max_graph_functions"] > 0
            else 0
        )

        return EffectiveBudget(
            recursion_depth=recursion_depth,
            graph_depth=graph_depth,
            graph_functions=graph_functions,
            hard_caps=caps,
            risk_scores=scores,
            risk_reasons=reasons,
        )

    def _score_recursion(
        self,
        code: str,
        call_tokens: Sequence[str],
        candidates: Sequence[Any],
        historical_issues: Sequence[Any],
    ) -> tuple[int, List[str]]:
        score = 10
        reasons = ["baseline_entry_context"]
        if len(set(call_tokens)) >= 8:
            score += 15
            reasons.append("many_distinct_call_sites")
        if CONTROL_FLOW_RE.search(code):
            score += 15
            reasons.append("dispatcher_or_protocol_control_flow")
        if INDIRECT_CALL_RE.search(code):
            score += 20
            reasons.append("indirect_call_or_function_pointer")
        if CALLBACK_RE.search(code):
            score += 15
            reasons.append("callback_or_threading_signal")
        if any(PROTOCOL_FLOW_RE.search(name) for name in call_tokens):
            score += 15
            reasons.append("protocol_or_runtime_callee")
        return_call = re.search(r"\breturn\s+(?P<callee>[A-Za-z_]\w+)\s*\(", code)
        if return_call and PROTOCOL_FLOW_RE.search(return_call.group("callee")):
            score += 10
            reasons.append("thin_public_facade_requires_callee_trace")
        if any(self._candidate_source(item, "graph") for item in candidates):
            score += 25
            reasons.append("graph_candidate_requires_cross_function_trace")
        if any(self._candidate_source(item, "backend") for item in candidates):
            score += 15
            reasons.append("backend_signal_requires_followup_trace")
        if historical_issues:
            score += 10
            reasons.append("historical_issue_context")
        return min(score, 100), reasons

    @staticmethod
    def _depth_budget(score: int, cap: int) -> int:
        if cap <= 0:
            return 0
        if score >= 80:
            return cap
        if score >= 55:
            return min(cap, max(3, (cap * 3 + 3) // 4))
        if score >= 30:
            return min(cap, max(2, (cap + 1) // 2))
        return min(cap, 1)

    @staticmethod
    def _breadth_budget(score: int, cap: int) -> int:
        if cap <= 0:
            return 0
        if score >= 80:
            return cap
        if score >= 55:
            return min(cap, max(24, (cap * 3 + 3) // 4))
        if score >= 30:
            return min(cap, max(12, (cap + 1) // 2))
        return min(cap, min(8, cap))

    @staticmethod
    def _non_negative(value: Any) -> int:
        try:
            return max(0, int(value))
        except (TypeError, ValueError):
            return 0

    @staticmethod
    def _mapping(value: Any) -> Mapping[str, Any]:
        return value if isinstance(value, Mapping) else {}

    @staticmethod
    def _call_tokens(code: str) -> List[str]:
        tokens = []
        for token in CALL_TOKEN_RE.findall(code or ""):
            if token in KEYWORD_CALLS:
                continue
            tokens.append(token)
        return tokens

    @staticmethod
    def _historical_issues(state: Mapping[str, Any]) -> List[Any]:
        issues: List[Any] = []
        for key in ("verified_hist_issues", "valid_hist_issues", "user_rejected_hist_issues"):
            value = state.get(key)
            if isinstance(value, list):
                issues.extend(value)
        return issues

    @classmethod
    def _candidate_source(cls, item: Any, needle: str) -> bool:
        return any(needle in source for source in cls._candidate_sources(item))

    @classmethod
    def _candidate_sources(cls, item: Any) -> List[str]:
        sources: List[str] = []
        raw_sources = cls._candidate_field(item, "sources")
        if isinstance(raw_sources, list):
            sources.extend(str(source).lower() for source in raw_sources)
        raw_source = cls._candidate_field(item, "source")
        if raw_source:
            sources.append(str(raw_source).lower())
        kind = cls._candidate_field(item, "candidate_kind")
        if kind:
            sources.append(str(kind).lower())
        candidate_source = cls._candidate_field(item, "candidate_source")
        if candidate_source:
            sources.append(str(candidate_source).lower())
        issue_type = cls._candidate_field(item, "issue_type")
        if issue_type:
            sources.append(str(issue_type).lower())
        return sources

    @staticmethod
    def _candidate_field(item: Any, field_name: str) -> Any:
        if isinstance(item, Mapping):
            ticket = item.get("ticket")
            if field_name in item:
                return item.get(field_name)
            if isinstance(ticket, Mapping) and field_name in ticket:
                return ticket.get(field_name)
            evidence = item.get("evidence")
            if isinstance(evidence, Mapping) and field_name in evidence:
                return evidence.get(field_name)
            return None
        if hasattr(item, field_name):
            return getattr(item, field_name)
        return None
