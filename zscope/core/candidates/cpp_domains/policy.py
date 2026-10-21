"""Early detector policy helpers.

These helpers intentionally distinguish an unknown ID from a disabled ID.
Unknown deterministic candidates must reach the central strict gate so the
scan fails loudly; generator-level policy is only an execution shortcut for a
known disabled or unavailable rule.
"""

from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache
from typing import Any, Optional, Tuple


@dataclass(frozen=True)
class ResolvedRuleDescriptor:
    """Small immutable projection used by deterministic candidate emitters.

    The projection is deliberately resolved by canonical rule ID.  It is not a
    second metadata registry: values come from the injected ``RulePolicy`` or,
    for standalone generator use, from the packaged ``RuleCatalog``.
    """

    rule_id: str
    cwe: str
    skill: str


@lru_cache(maxsize=2)
def _packaged_policy(language: str) -> Any:
    from zscope.rules.catalog import EffectiveRuleSet, RuleCatalog

    backend = "java_unified" if language == "java" else "unified"
    catalog = RuleCatalog.builtin()
    return EffectiveRuleSet.build(
        catalog,
        language=language,
        backend=backend,
        # This policy resolves metadata for standalone detector experiments.
        # Actual scan admission is controlled by the injected runtime policy.
        enabled_ids=[rule.id for rule in catalog.descriptors if rule.language == language],
    ).policy


def _resolved_from_packaged_catalog(
    rule_id: str,
    *,
    defect_class: str,
    language: str,
) -> Optional[ResolvedRuleDescriptor]:
    from zscope.rules.catalog import RuleCatalogError

    policy = _packaged_policy(language)
    try:
        issue = policy.enrich_issue(
            {
                "rule_id": rule_id,
                **({"defect_class": defect_class} if defect_class else {}),
            }
        )
    except RuleCatalogError as exc:
        if "unknown" in str(exc):
            return None
        raise
    return ResolvedRuleDescriptor(
        rule_id=str(issue["rule_id"]),
        cwe=str(issue["cwe"]),
        skill=str(issue["skill"]),
    )


def resolve_rule_descriptor(
    policy: Any,
    rule_id: str,
    *,
    defect_class: str = "",
    language: str = "c_cpp",
) -> Optional[ResolvedRuleDescriptor]:
    """Resolve authoritative CWE/Skill metadata for one canonical rule ID."""

    if not str(rule_id or ""):
        return None
    packaged = _resolved_from_packaged_catalog(
        rule_id,
        defect_class=defect_class,
        language=language,
    )
    if policy is None:
        return packaged

    has_strict_state, state = _effective_state(policy, rule_id)
    if has_strict_state and state is None:
        # Preserve an unknown implementation ID for the central strict gate and
        # do not call a policy descriptor method that is required to reject it.
        return packaged

    enrich_issue = getattr(policy, "enrich_issue", None)
    if callable(enrich_issue):
        enriched = enrich_issue(
            {
                "rule_id": rule_id,
                **({"defect_class": defect_class} if defect_class else {}),
            }
        )
        return ResolvedRuleDescriptor(
            rule_id=str(enriched["rule_id"]),
            cwe=str(enriched["cwe"]),
            skill=str(enriched["skill"]),
        )

    descriptor_method = getattr(policy, "descriptor", None)
    if not callable(descriptor_method):
        return packaged
    descriptor = descriptor_method(rule_id)
    if packaged is None:
        descriptor_id = str(getattr(descriptor, "id", rule_id) or rule_id)
        cwe = str(getattr(descriptor, "cwe", "") or "")
        skill = str(getattr(descriptor, "skill", "") or "")
        if not cwe or not skill:
            return None
        return ResolvedRuleDescriptor(descriptor_id, cwe, skill)
    return ResolvedRuleDescriptor(
        rule_id=str(getattr(descriptor, "id", packaged.rule_id) or packaged.rule_id),
        cwe=str(getattr(descriptor, "cwe", packaged.cwe) or packaged.cwe),
        skill=str(getattr(descriptor, "skill", packaged.skill) or packaged.skill),
    )


def _effective_state(policy: Any, rule_id: str) -> tuple[bool, Any]:
    effective = getattr(policy, "effective", None)
    state_for = getattr(effective, "state_for", None)
    if not callable(state_for):
        return False, None
    return True, state_for(rule_id)


def rule_policy_allows_emit(policy: Any, rule_id: str) -> bool:
    if policy is None:
        return True
    has_strict_state, state = _effective_state(policy, rule_id)
    if has_strict_state:
        # An unregistered ID must be emitted so the central candidate gate can
        # reject it instead of turning a catalog defect into a silent miss.
        return state is None or str(getattr(state, "state", "")) == "enabled"
    return bool(policy.is_enabled(rule_id))


def resolve_emitter_descriptor(
    policy: Any,
    rule_id: str,
    *,
    defect_class: str = "",
    language: str = "c_cpp",
) -> Tuple[bool, Optional[ResolvedRuleDescriptor]]:
    """Return early-emission status and authoritative descriptor projection."""

    if not rule_policy_allows_emit(policy, rule_id):
        return False, None
    return True, resolve_rule_descriptor(
        policy,
        rule_id,
        defect_class=defect_class,
        language=language,
    )


def resolve_emitter_skill(policy: Any, rule_id: str, fallback: str) -> Tuple[bool, str]:
    """Compatibility wrapper around the descriptor resolver."""

    should_emit, descriptor = resolve_emitter_descriptor(policy, rule_id)
    if not should_emit:
        return False, fallback
    return True, descriptor.skill if descriptor is not None else fallback
