from __future__ import annotations

import pytest

from zscope.rules.validation_obligations import (
    attach_obligation_binding,
    binding_for_rule,
    builtin_obligation_coverage,
    profile_for_defect_class,
)


def test_every_default_cpp_rule_has_current_typed_obligation() -> None:
    coverage = builtin_obligation_coverage()

    assert coverage["default_enabled_cpp_rules"] == 166
    assert coverage["bound_rules"] == 166
    assert coverage["missing_rules"] == []
    assert coverage["complete"] is True


def test_exact_local_rule_override_keeps_governed_mechanism_family() -> None:
    binding = binding_for_rule("clang_cfg_refcount_update_after_unlock")

    assert binding is not None
    assert binding.profile.profile_id == "local_path"
    assert binding.profile.mechanism_family == "concurrency"
    assert binding.profile.required_fact_kinds == ()


def test_unknown_rule_does_not_inherit_profile_from_its_name() -> None:
    issue = {
        "rule": "third_party_thread_free_lock_rule",
        "category": "race",
    }

    assert attach_obligation_binding(issue) is None
    assert issue["obligation_profile_status"] == "unsupported"


def test_native_protocol_requires_its_own_path_and_business_evidence() -> None:
    from zscope.core.candidates.decision_facts import required_fact_kinds_for_issue
    from zscope.core.validation.evidence_completion import EvidenceCompletionQueue

    issue = {
        "rule": "zscope.c_cpp.cpp_clang_cfg.object_protocol_path",
        # A producer cannot remove the governed minimum by omitting extensions.
        "obligation_required_fact_kinds": [],
    }
    binding = attach_obligation_binding(issue)
    assert binding is not None
    assert binding.profile.profile_id == "native_object_protocol"
    assert binding.profile.mechanism_family == "state_transition"
    assert set(required_fact_kinds_for_issue(issue)) == {
        "event:protocol_acquisition",
        "event:object_generation",
        "event:feasible_lifecycle_path",
        "event:protocol_observation",
        "event:business_release_requirement",
    }
    issue["obligation_required_fact_kinds"] = ["event:responsibility_endpoint"]
    assert "event:responsibility_endpoint" in required_fact_kinds_for_issue(issue)
    assert EvidenceCompletionQueue.required_resolution_fact_kinds(
        issue, {"missing_fact_request": {"fact_kind": "caller_contract"}}
    ) == ()
    # Ordinary state-transition candidates still need their generic evidence.
    generic = profile_for_defect_class("state_inconsistency")
    assert generic is not None
    assert generic.required_fact_kinds == ("caller_contract", "source_sink_reachability")


def test_binding_is_serialized_for_validator_cache_and_report() -> None:
    issue = {"rule": "clang_cfg_sizeof_index_write", "category": "off_by_one"}

    binding = attach_obligation_binding(issue)

    assert binding is not None
    assert issue["obligation_profile_id"] == "bounds_range"
    assert issue["obligation_binding_uid"] == binding.binding_uid
    assert issue["obligation_rule_revision"] == binding.rule_revision
    assert issue["allowed_missing_fact_kinds"] == [
        "value_range",
        "guard_dominance",
        "type_layout",
        "source_sink_reachability",
    ]
    assert issue["obligation_positive_conditions"] == [
        "source_value_reaches_sink",
        "unsafe_range",
        "guard_insufficient",
    ]
    assert "dominating_guard" in issue["obligation_counterfact_kinds"]


def test_stale_rule_revision_cannot_bind_current_obligation() -> None:
    issue = {
        "rule": "clang_cfg_sizeof_index_write",
        "rule_revision": 1,
        "category": "off_by_one",
    }

    assert attach_obligation_binding(issue) is None
    assert issue["obligation_profile_status"] == "unsupported"


@pytest.mark.parametrize(
    ("rule_id", "expected_profile"),
    [
        ("clang_cfg_refcount_update_after_unlock", "local_path"),
        ("clang_cfg_free_non_owner_pointer_expression", "local_path"),
        ("clang_cfg_global_mapping_unmapped_without_invalidation", "local_path"),
        ("clang_cfg_log_error_path_allocation_not_released", "local_source_centric"),
        ("clang_cfg_parent_release_without_owned_member_cleanup", "local_source_centric"),
        ("global_state_not_restored_on_error", "local_path"),
        ("clang_cfg_shared_resource_freed_without_refcount_protocol", "local_path"),
        ("clang_cfg_active_owner_destroy_without_quiescence", "local_path"),
        ("clang_cfg_free_derived_pointer_alias", "local_path"),
        ("clang_cfg_fd_open_return_without_close", "local_source_centric"),
        ("clang_cfg_heap_thread_argument_owner_not_released", "local_source_centric"),
        ("paired_free_wrapper_omits_dynamic_member", "local_source_centric"),
        ("clang_cfg_return_with_lock_held", "local_path"),
    ],
)
def test_audited_local_path_rules_do_not_request_unrelated_generic_facts(
    rule_id: str,
    expected_profile: str,
) -> None:
    binding = binding_for_rule(rule_id)

    assert binding is not None
    assert binding.profile.profile_id == expected_profile
    assert binding.profile.required_fact_kinds == ()
    assert binding.profile.allowed_missing_fact_kinds == ()


@pytest.mark.parametrize(
    ("rule_id", "expected_profile"),
    [
        ("partial_resource_leak", "resource_lifecycle"),
        ("thread_cache_leak", "resource_lifecycle"),
        ("optimization_resource_lifecycle", "resource_lifecycle"),
        ("check_then_act_race", "concurrency"),
        ("excessive_allocation", "availability"),
        ("fd_allocation_without_limits", "availability"),
        ("unlock_without_lock", "lock_path"),
        ("potential_deadlock", "lock_path"),
    ],
)
def test_rule_families_bind_to_their_actual_mechanism(rule_id: str, expected_profile: str) -> None:
    profile = profile_for_defect_class(rule_id)

    assert profile is not None
    assert profile.profile_id == expected_profile
