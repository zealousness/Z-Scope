"""Domain-organized implementations for C/C++ deterministic candidates."""

from .models import (
    ClangRuleContext,
    DetectorDomain,
    DetectorStage,
    GraphBatchRuleContext,
    GraphViewRuleContext,
    RegexRuleContext,
)
from .registry import detector_plan, run_detector_plan
from .policy import (
    ResolvedRuleDescriptor,
    resolve_emitter_descriptor,
    resolve_emitter_skill,
    resolve_rule_descriptor,
    rule_policy_allows_emit,
)

__all__ = [
    "ClangRuleContext",
    "DetectorDomain",
    "DetectorStage",
    "GraphBatchRuleContext",
    "GraphViewRuleContext",
    "RegexRuleContext",
    "ResolvedRuleDescriptor",
    "detector_plan",
    "resolve_emitter_descriptor",
    "resolve_emitter_skill",
    "resolve_rule_descriptor",
    "rule_policy_allows_emit",
    "run_detector_plan",
]
