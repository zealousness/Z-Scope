"""Typed validation obligations for deterministic C/C++ rules.

The rule catalog describes discovery governance.  This companion catalog
describes the evidence contract used after discovery.  Bindings are resolved
by canonical rule id and current revision; candidate descriptions and rule
name substrings never select an obligation profile.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, replace
from functools import lru_cache
import hashlib
import json
from typing import Any, Dict, Mapping, Optional, Sequence, Tuple

from .catalog import RuleCatalog, RuleDescriptor


VALIDATION_OBLIGATION_CATALOG_VERSION = "zscope.validation-obligation-catalog.v2"


@dataclass(frozen=True)
class ValidationObligationProfile:
    profile_id: str
    revision: int
    mechanism_family: str
    obligation_shape: str
    required_roles: Tuple[str, ...]
    required_fact_kinds: Tuple[str, ...]
    allowed_missing_fact_kinds: Tuple[str, ...]
    positive_conditions: Tuple[str, ...]
    counterfact_kinds: Tuple[str, ...]
    positive_checker: str
    rejection_checker: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class ValidationObligationBinding:
    rule_id: str
    rule_revision: int
    profile: ValidationObligationProfile
    binding_uid: str
    origin: str = "deterministic_rule"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "catalog_version": VALIDATION_OBLIGATION_CATALOG_VERSION,
            "binding_uid": self.binding_uid,
            "rule_id": self.rule_id,
            "rule_revision": self.rule_revision,
            "origin": self.origin,
            **self.profile.to_dict(),
        }


def _profile(
    profile_id: str,
    *,
    family: str,
    roles: Sequence[str],
    facts: Sequence[str] = (),
    allowed: Optional[Sequence[str]] = None,
    positive: Sequence[str] = ("current_source", "current_sink", "feasible_order"),
    counterfacts: Sequence[str] = (
        "source_or_sink_identity_disproved",
        "dominating_guard",
        "path_unreachable",
    ),
    shape: str = "sink_sensitive",
    positive_checker: str = "cited_positive_path",
    rejection_checker: str = "typed_counterfact",
) -> ValidationObligationProfile:
    return ValidationObligationProfile(
        profile_id=profile_id,
        revision=1,
        mechanism_family=family,
        obligation_shape=shape,
        required_roles=tuple(roles),
        required_fact_kinds=tuple(facts),
        allowed_missing_fact_kinds=tuple(allowed if allowed is not None else facts),
        positive_conditions=tuple(positive),
        counterfact_kinds=tuple(counterfacts),
        positive_checker=positive_checker,
        rejection_checker=rejection_checker,
    )


PROFILES: Mapping[str, ValidationObligationProfile] = {
    "local_source_sink": _profile(
        "local_source_sink",
        family="local",
        roles=("source", "sink"),
    ),
    "local_path": _profile(
        "local_path",
        family="local_path",
        roles=("source", "sink", "path"),
        shape="path_sensitive",
    ),
    "local_source_centric": _profile(
        "local_source_centric",
        family="local_source_centric",
        roles=("source", "sink", "path"),
        shape="source_centric",
    ),
    "bounds_range": _profile(
        "bounds_range",
        family="bounds_range",
        roles=("source", "sink", "guard"),
        facts=("value_range", "guard_dominance", "type_layout", "source_sink_reachability"),
        positive=("source_value_reaches_sink", "unsafe_range", "guard_insufficient"),
        counterfacts=("safe_value_range", "dominating_guard", "sink_identity_disproved"),
    ),
    "resource_lifecycle": _profile(
        "resource_lifecycle",
        family="resource_lifecycle",
        roles=("source", "sink", "ownership", "exit"),
        facts=("cleanup_coverage", "ownership_transfer", "caller_contract"),
        shape="source_centric",
        positive=("resource_acquired", "exit_without_release_or_transfer"),
        counterfacts=("acquisition_failed", "all_paths_release", "ownership_transfer"),
    ),
    "temporal_memory": _profile(
        "temporal_memory",
        family="temporal_memory",
        roles=("source", "release", "sink", "path"),
        facts=("object_identity", "source_sink_reachability"),
        shape="path_sensitive",
        positive=("same_object_generation", "release_precedes_access", "feasible_path"),
        counterfacts=("different_object_generation", "access_precedes_release", "path_unreachable"),
    ),
    "invalid_release": _profile(
        "invalid_release",
        family="invalid_release",
        roles=("source", "sink", "object_identity"),
        facts=("object_identity",),
        positive=("release_sink", "released_value_is_not_owner_base"),
        counterfacts=("released_value_is_owner_base", "release_is_noop", "sink_identity_disproved"),
    ),
    "concurrency": _profile(
        "concurrency",
        family="concurrency",
        roles=("source", "sink", "access", "synchronization"),
        facts=("lockset", "happens_before", "source_sink_reachability"),
        shape="path_sensitive",
        positive=("conflicting_shared_accesses", "no_happens_before"),
        counterfacts=(
            "same_lock_covers_all_accesses",
            "atomic_or_happens_before",
            "object_not_shared",
        ),
    ),
    "lock_path": _profile(
        "lock_path",
        family="lock_path",
        roles=("source", "sink", "path"),
        facts=("lockset",),
        shape="path_sensitive",
        positive=("lock_state_transition", "invalid_exit_or_reentry_path"),
        counterfacts=(
            "balanced_lock_state_all_paths",
            "recursive_lock_contract",
            "path_unreachable",
        ),
    ),
    "taint_sink": _profile(
        "taint_sink",
        family="taint_sink",
        roles=("source", "sink", "path", "guard"),
        facts=("source_controllability", "source_sink_reachability", "guard_dominance"),
        shape="path_sensitive",
        positive=("controllable_source", "source_reaches_sink", "sanitizer_insufficient"),
        counterfacts=("source_not_controllable", "sanitizer_dominates_sink", "path_unreachable"),
    ),
    "protocol": _profile(
        "protocol",
        family="protocol",
        roles=("source", "sink", "state"),
        facts=("caller_contract", "source_sink_reachability"),
        shape="path_sensitive",
        positive=("current_protocol_state", "invalid_transition_or_unit", "feasible_path"),
        counterfacts=("valid_transition", "compatible_unit_or_identity", "path_unreachable"),
    ),
    "availability": _profile(
        "availability",
        family="availability",
        roles=("source", "sink", "guard"),
        facts=("source_controllability", "guard_dominance"),
        positive=(
            "externally_influenced_work",
            "unbounded_or_nonterminating_sink",
            "guard_insufficient",
        ),
        counterfacts=("hard_resource_bound", "terminating_guard", "source_not_controllable"),
    ),
    "unchecked_result": _profile(
        "unchecked_result",
        family="unchecked_result",
        roles=("source", "sink", "contract"),
        facts=("caller_contract",),
        shape="source_centric",
        positive=("fallible_operation", "result_not_checked", "dependent_sink"),
        counterfacts=("success_check_dominates_sink", "operation_infallible", "sink_independent"),
    ),
    "state_transition": _profile(
        "state_transition",
        family="state_transition",
        roles=("source", "sink", "state", "path"),
        facts=("caller_contract", "source_sink_reachability"),
        shape="path_sensitive",
        positive=("current_state", "invalid_transition", "feasible_path"),
        counterfacts=("valid_transition", "state_restored_all_paths", "path_unreachable"),
    ),
    "native_object_protocol": _profile(
        "native_object_protocol",
        family="state_transition",
        roles=("source", "sink", "state", "path"),
        facts=(
            "event:protocol_acquisition",
            "event:object_generation",
            "event:feasible_lifecycle_path",
            "event:protocol_observation",
            "event:business_release_requirement",
        ),
        allowed=(),
        shape="path_sensitive",
        positive=("current_native_replay", "same_object_generation", "scoped_business_acceptance"),
        # A changed/unreproduced witness is pending, not a rejection proof.
        counterfacts=(),
    ),
}


_DEFECT_PROFILE: Mapping[str, str] = {
    # Numeric, layout and copy-range obligations.
    **{
        name: "bounds_range"
        for name in (
            "bounds",
            "buffer_overread",
            "buffer_underflow",
            "heap_overflow",
            "integer_overflow",
            "off_by_one",
            "out_of_bounds_write",
            "out_of_range_pointer_offset",
            "signed_unsigned",
            "size_limit_mismatch",
        )
    },
    # Resource ownership and cleanup.
    **{
        name: "resource_lifecycle"
        for name in (
            "fd_leak",
            "incomplete_cleanup",
            "memory_leak",
            "realloc_misuse",
            "stale_fd",
        )
    },
    # Object generation and lifetime ordering.
    **{
        name: "temporal_memory"
        for name in (
            "double_free",
            "missing_refcount",
            "premature_destroy",
            "use_after_free",
        )
    },
    "alloc_free_mismatch": "invalid_release",
    "invalid_free": "invalid_release",
    # Shared-state and scheduling obligations.
    **{
        name: "concurrency"
        for name in (
            "callback_self_destroy_race",
            "double_checked_locking",
            "dynamic_array_race",
            "global_mode_race",
            "key_generation_race",
            "lost_wakeup",
            "object_publication",
            "race",
            "reader_state_race",
            "refcount_race",
            "registration_race",
            "shared_memory_race",
            "signal_race",
            "slot_race",
            "unsynchronized_shared_state",
        )
    },
    **{
        name: "lock_path"
        for name in (
            "held_lock_callback",
            "lock_protocol_violation",
            "missing_unlock",
            "deadlock",
            "signal_deadlock",
        )
    },
    "command_injection": "taint_sink",
    "format_string": "taint_sink",
    # Protocol and cross-function state contracts.
    **{
        name: "protocol"
        for name in (
            "byte_order_logic",
            "fd_encoding_mismatch",
            "fd_type_mismatch",
            "file_type_validation",
            "key_truncation",
            "permission",
            "protocol_mixup",
            "protocol_validation",
            "semantic_mismatch",
            "state_machine",
            "toctou",
            "version_filtering",
        )
    },
    **{
        name: "availability"
        for name in (
            "busy_loop",
            "infinite_loop",
            "log_amplification",
            "resource_allocation_without_limits",
            "sigpipe_unhandled",
            "stack_overflow",
        )
    },
    "unchecked_allocation": "unchecked_result",
    "unchecked_return": "unchecked_result",
    **{
        name: "state_transition"
        for name in (
            "logic_error",
            "state_inconsistency",
        )
    },
    # These rules encode a local language-level violation and need no broad
    # interprocedural fact request beyond their cited source/sink/path.
    **{
        name: "local_source_sink"
        for name in (
            "alignment",
            "null_pointer_dereference",
            "stack_escape",
            "type_confusion",
            "uninitialized_output",
            "uninitialized_pointer",
            "uninitialized_read",
            "untrusted_pointer",
        )
    },
}

_DEFECT_PROFILE_ALIASES: Mapping[str, str] = {
    "buffer_overflow": "bounds_range",
    "buffer_underread": "bounds_range",
    "buffer_underwrite": "bounds_range",
    "expired_pointer": "temporal_memory",
    "partial_resource_leak": "resource_lifecycle",
    "thread_cache_leak": "resource_lifecycle",
    "optimization_resource_lifecycle": "resource_lifecycle",
    "missing_fd_release": "resource_lifecycle",
    "resource_leak": "resource_lifecycle",
    "check_then_act_race": "concurrency",
    "excessive_allocation": "availability",
    "fd_allocation_without_limits": "availability",
    "unlock_without_lock": "lock_path",
    "lock_leak": "lock_path",
    "potential_deadlock": "lock_path",
}


# Explicit evidence contracts for local detectors and dedicated native replay.
# The exact canonical ids are deliberate: a new rule never inherits this
# authority merely by using a similar name.
_RULE_PROFILE_OVERRIDES: Mapping[str, str] = {
    # The dedicated checker replays the concrete native path and separately
    # checks scoped business declarations. Generic caller/reachability facts
    # cannot discharge this contract or replace its process-local receipt.
    "zscope.c_cpp.cpp_clang_cfg.object_protocol_path": "native_object_protocol",
    "clang_cfg_refcount_update_after_unlock": "local_path",
    "clang_cfg_free_non_owner_pointer_expression": "local_path",
    "clang_cfg_free_derived_pointer_alias": "local_path",
    "clang_cfg_global_mapping_unmapped_without_invalidation": "local_path",
    "clang_cfg_log_error_path_allocation_not_released": "local_source_centric",
    "clang_cfg_parent_release_without_owned_member_cleanup": "local_source_centric",
    "global_state_not_restored_on_error": "local_path",
    "clang_cfg_shared_resource_freed_without_refcount_protocol": "local_path",
    "clang_cfg_active_owner_destroy_without_quiescence": "local_path",
    "clang_cfg_fd_open_return_without_close": "local_source_centric",
    "clang_cfg_heap_thread_argument_owner_not_released": "local_source_centric",
    "heap_thread_argument_not_released": "local_source_centric",
    "error_path_allocation_not_released": "local_source_centric",
    "same_function_allocation_not_released": "local_source_centric",
    "member_allocation_not_released_with_parent": "local_source_centric",
    "child_list_cleanup_omitted": "local_source_centric",
    "paired_free_wrapper_omits_dynamic_member": "local_source_centric",
    "clang_cfg_return_with_lock_held": "local_path",
    "return_while_lock_held": "local_path",
}


_CUSTOM_FACT_EXTENSION_RULES = frozenset(
    {
        "zscope.c_cpp.cpp_clang_cfg.object_protocol_path",
        "zscope.c_cpp.cpp_clang_cfg.retained_slot_release",
    }
)


@lru_cache(maxsize=1)
def _builtin_catalog() -> RuleCatalog:
    return RuleCatalog.builtin()


def _binding(descriptor: RuleDescriptor) -> Optional[ValidationObligationBinding]:
    overridden = descriptor.id in _RULE_PROFILE_OVERRIDES
    profile_id = _RULE_PROFILE_OVERRIDES.get(descriptor.id) or _DEFECT_PROFILE.get(
        descriptor.defect_class
    )
    profile = PROFILES.get(str(profile_id or ""))
    if profile is None:
        return None
    # A precise local detector may close the fact obligation without broad
    # provider requests, but its vulnerability mechanism remains the rule's
    # governed defect family.  Preserve that family for mechanism-level
    # benchmark auditing instead of relabelling it as merely "local".
    if overridden:
        governed = profile_for_defect_class(descriptor.defect_class)
        if governed is not None:
            profile = replace(profile, mechanism_family=governed.mechanism_family)
    payload = {
        "catalog": VALIDATION_OBLIGATION_CATALOG_VERSION,
        "rule_id": descriptor.id,
        "rule_revision": descriptor.revision,
        "profile": profile.to_dict(),
    }
    digest = hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    return ValidationObligationBinding(
        rule_id=descriptor.id,
        rule_revision=descriptor.revision,
        profile=profile,
        binding_uid="VOB_" + digest[:32],
    )


def binding_for_rule(rule_id: str) -> Optional[ValidationObligationBinding]:
    descriptor = _builtin_catalog().get(str(rule_id or ""))
    return _binding(descriptor) if descriptor is not None else None


def profile_for_defect_class(defect_class: str) -> Optional[ValidationObligationProfile]:
    normalized = str(defect_class or "").strip().lower().replace("-", "_")
    profile_id = _DEFECT_PROFILE.get(normalized) or _DEFECT_PROFILE_ALIASES.get(normalized)
    return PROFILES.get(str(profile_id or ""))


def supported_defect_classes() -> Tuple[str, ...]:
    """Public discovery vocabulary; verification families remain governed."""
    return tuple(sorted(set(_DEFECT_PROFILE) | set(_DEFECT_PROFILE_ALIASES)))


def binding_for_issue(issue: Mapping[str, Any]) -> Optional[ValidationObligationBinding]:
    pack = issue.get("evidence_pack")
    pack = pack if isinstance(pack, Mapping) else {}
    rule_id = str(
        issue.get("rule_id") or issue.get("rule") or pack.get("rule_id") or pack.get("rule") or ""
    )
    binding = binding_for_rule(rule_id)
    if binding is None:
        # Never let an unknown/obsolete detector masquerade as LLM discovery.
        # The producer declares a mechanism, not a checker or a relaxed set of
        # required roles. The governed catalog chooses the verification policy.
        if rule_id or issue.get("candidate_source") != "hierarchical_discovery":
            return None
        if issue.get("candidate_kind") != "llm_contract_hypothesis":
            return None
        obligation = issue.get("security_obligation")
        if not isinstance(obligation, Mapping):
            return None
        profile = profile_for_defect_class(str(issue.get("defect_class") or ""))
        mechanism = issue.get("hypothesis_mechanism_family") or obligation.get("mechanism_family")
        if profile is None or mechanism != profile.mechanism_family:
            return None
        material = [VALIDATION_OBLIGATION_CATALOG_VERSION, "llm_contract_hypothesis", profile.to_dict()]
        return ValidationObligationBinding(
            rule_id="", rule_revision=0, profile=profile,
            binding_uid=hashlib.sha256(json.dumps(material, sort_keys=True).encode()).hexdigest(),
            origin="llm_contract_hypothesis",
        )
    declared_revision = issue.get("rule_revision")
    if declared_revision is None:
        declared_revision = pack.get("rule_revision")
    if declared_revision is not None:
        try:
            if int(declared_revision) != binding.rule_revision:
                return None
        except (TypeError, ValueError):
            return None
    return binding


def issue_fact_extensions(issue: Mapping[str, Any]) -> Tuple[str, ...]:
    """Return exact producer-declared extensions for the two protocol rules."""

    binding = binding_for_issue(issue)
    if binding is None or binding.rule_id not in _CUSTOM_FACT_EXTENSION_RULES:
        return ()
    pack = issue.get("evidence_pack")
    pack = pack if isinstance(pack, Mapping) else {}
    raw = issue.get("obligation_required_fact_kinds") or pack.get("obligation_required_fact_kinds")
    if not isinstance(raw, Sequence) or isinstance(raw, str):
        return ()
    return tuple(sorted({str(value) for value in raw if str(value).startswith("event:")}))


def attach_obligation_binding(issue: Dict[str, Any]) -> Optional[ValidationObligationBinding]:
    binding = binding_for_issue(issue)
    if binding is None:
        issue["obligation_profile_status"] = "unsupported"
        issue["obligation_catalog_version"] = VALIDATION_OBLIGATION_CATALOG_VERSION
        return None
    profile = binding.profile
    issue.update(
        {
            "obligation_catalog_version": VALIDATION_OBLIGATION_CATALOG_VERSION,
            "obligation_profile_status": "bound",
            "obligation_profile_id": profile.profile_id,
            "obligation_profile_revision": profile.revision,
            "obligation_binding_uid": binding.binding_uid,
            "obligation_origin": binding.origin,
            "obligation_rule_id": binding.rule_id,
            "obligation_rule_revision": binding.rule_revision,
            "obligation_mechanism_family": profile.mechanism_family,
            "obligation_required_roles": list(profile.required_roles),
            "allowed_missing_fact_kinds": list(profile.allowed_missing_fact_kinds),
            "obligation_positive_conditions": list(profile.positive_conditions),
            "obligation_counterfact_kinds": list(profile.counterfact_kinds),
            "positive_claim_checker": profile.positive_checker,
            "rejection_claim_checker": profile.rejection_checker,
        }
    )
    return binding


def builtin_obligation_coverage() -> Dict[str, Any]:
    descriptors = [
        descriptor
        for descriptor in _builtin_catalog()
        if descriptor.language == "c_cpp" and descriptor.default_enabled
    ]
    missing = [descriptor.id for descriptor in descriptors if _binding(descriptor) is None]
    return {
        "schema_version": VALIDATION_OBLIGATION_CATALOG_VERSION,
        "default_enabled_cpp_rules": len(descriptors),
        "bound_rules": len(descriptors) - len(missing),
        "missing_rules": sorted(missing),
        "complete": not missing,
    }
