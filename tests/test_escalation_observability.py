"""Tests for escalation-ladder rung observability (balanced_confirmed_tp_plan.md).

Covers the M1 contract surface: the three ``runtime.analysis`` rung flags,
the ``uncertain`` high-confidence confirmation rung, ``confirmed_via``
tagging on finding attribution, and the ``escalation_rung`` usage-event
dimension (including the benchmark archive validator).
"""

from __future__ import annotations

import json

from pathlib import Path

import pytest

from zscope.benchmarking.protocol import attribution_summary, finding_attribution
from zscope.benchmarking.runner import _validate_usage_event_v1
from zscope.config.v2 import _runtime_analysis, load_runtime_spec
from zscope.framework.llm_usage import (
    LLMUsageAttribution,
    LLMUsageEvent,
    escalation_rung_for_call_kind,
)
from zscope.core.validation.pipeline import ValidationPipeline


class FakeUserConfig:
    def __init__(self):
        self.false_positive = False
        self.baseline = None

    def is_false_positive(self, func_name, location, category):
        return self.false_positive

    def get_finding_baseline_for_issue(self, issue, dedup_key):
        return self.baseline

    def get_finding_baseline(self, dedup_key):
        return self.baseline


def _score(final_score: float) -> dict:
    return {
        "rule_confidence": final_score,
        "path_completeness": final_score,
        "contract_consistency": final_score,
        "validation_confidence": final_score,
        "history_feedback": 0.5,
        "final_score": final_score,
    }


# --------------------------------------------------------------------------
# runtime.analysis rung flags (runtime spec)
# --------------------------------------------------------------------------


def test_v3_reattempt_switch_gates_investigation_budget() -> None:
    """Plan Phase 4 R2: the V3 reattempt only participates when the switch is on."""
    from dataclasses import replace as dc_replace
    from unittest import mock

    from zscope.core.validation.runner import ValidationRunner, _PreparedValidation

    def _item():
        return _PreparedValidation(
            index=0,
            raw_issue={"id": "X"},
            issue_func="f",
            issue_code="C",
            evidence_pack={},
        )

    runner = mock.create_autospec(ValidationRunner, instance=True)
    runner._scan_depth.return_value = "balanced"
    # getattr(config.analysis, ...) path used by the implementation.
    analysis = mock.MagicMock()
    analysis.validation_v3_reattempt = False
    runner.config = mock.MagicMock()
    runner.config.analysis = analysis
    # Bind the real method onto the autospec instance's class pathway.
    result = ValidationRunner._assign_v3_investigation_budget(runner, [_item()])
    assert result and all(item.allow_v3 is False for item in result)
    assert all(item.v3_max_iterations == 0 for item in result)

    analysis.validation_v3_reattempt = True
    # The autospec instance shadows class methods; drive eligibility through
    # the instance mocks directly.
    runner._is_shadow_only_candidate.return_value = False
    runner._v3_is_high_or_critical.return_value = True
    runner._externally_reachable.return_value = True
    runner._has_valid_security_obligation.return_value = True
    runner._has_readonly_closable_gap.return_value = True
    runner._v3_risk_score.return_value = 1.0
    result = ValidationRunner._assign_v3_investigation_budget(runner, [_item()])
    assert result and result[0].allow_v3 is True
    assert result[0].v3_max_iterations == 50


def test_runtime_spec_rung_flags_default_off() -> None:
    analysis = load_runtime_spec().analysis
    assert analysis.validation_uncertain_confirm_threshold is None
    # v3_reattempt defaults to True: the balanced pipeline has always run the
    # V3 reattempt; the switch exists so reference runs can turn it off.
    assert analysis.validation_v3_reattempt is True
    assert analysis.validation_v2b_adjudication is False


def test_runtime_spec_override_accepts_rung_flags(tmp_path: Path, monkeypatch) -> None:
    override = tmp_path / "runtime_override.yaml"
    override.write_text(
        "analysis:\n"
        "  validation_uncertain_confirm_threshold: 0.9\n"
        "  validation_v3_reattempt: true\n"
        "  validation_v2b_adjudication: false\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("Z_SCOPE_DEVELOPER_MODE", "1")
    monkeypatch.setenv("Z_SCOPE_RUNTIME_SPEC", str(override))
    analysis = load_runtime_spec().analysis
    assert analysis.validation_uncertain_confirm_threshold == 0.9
    assert analysis.validation_v3_reattempt is True
    assert analysis.validation_v2b_adjudication is False


@pytest.mark.parametrize("threshold", [0.5, 0.0, 1.2, -0.1])
def test_runtime_analysis_rejects_threshold_outside_band(threshold) -> None:
    with pytest.raises(ValueError, match="\\(0.5, 1.0\\]"):
        _runtime_analysis({"validation_uncertain_confirm_threshold": threshold})


def test_runtime_analysis_accepts_null_threshold() -> None:
    analysis = _runtime_analysis({"validation_uncertain_confirm_threshold": None})
    assert analysis.validation_uncertain_confirm_threshold is None


def test_runtime_analysis_rejects_non_boolean_rung_flag() -> None:
    with pytest.raises(ValueError, match="true or false"):
        _runtime_analysis({"validation_v3_reattempt": "yes"})


def test_analysis_config_dataclass_rejects_threshold_outside_band() -> None:
    from zscope.config.config import AnalysisConfig

    with pytest.raises(ValueError, match="\\(0.5, 1.0\\]"):
        AnalysisConfig(validation_uncertain_confirm_threshold=0.5)
    assert AnalysisConfig().validation_uncertain_confirm_threshold is None
    assert (
        AnalysisConfig(
            validation_uncertain_confirm_threshold=1.0
        ).validation_uncertain_confirm_threshold
        == 1.0
    )


# --------------------------------------------------------------------------
# uncertain -> high_confidence_band confirmation rung
# --------------------------------------------------------------------------


def _uncertain_issue(**overrides) -> dict:
    issue = {"id": "ISSUE_UNCERTAIN_TP"}
    issue.update(overrides)
    return issue


def test_uncertain_verdict_never_confirms_from_high_confidence_or_score() -> None:
    pipeline = ValidationPipeline(FakeUserConfig(), uncertain_confirm_threshold=0.9)
    issue = _uncertain_issue()

    outcome = pipeline.apply_validator_result(
        issue,
        {"finding_kind": "heap_double_free", "reasoning": "likely", "confidence_score": 0.92},
        verdict="uncertain",
        score_data=_score(0.8),
    )

    assert outcome.report_bucket == "observations"
    assert outcome.memory_status == "needs_review"
    assert issue["candidate_disposition"] == "needs_review"
    assert issue["score_role"] == "ranking_only"
    assert "promotion_reason" not in issue
    assert "confirmed_via" not in issue


def test_uncertain_verdict_stays_needs_review_when_rung_disabled() -> None:
    pipeline = ValidationPipeline(FakeUserConfig())
    issue = _uncertain_issue()

    outcome = pipeline.apply_validator_result(
        issue,
        {"finding_kind": "needs_manual_review", "reasoning": "ambiguous", "confidence_score": 0.95},
        verdict="uncertain",
        score_data=_score(0.8),
    )

    assert outcome.report_bucket == "observations"
    assert outcome.memory_status == "needs_review"
    assert issue["candidate_disposition"] == "needs_review"
    assert "confirmed_via" not in issue


def test_uncertain_verdict_with_missing_facts_stays_needs_review() -> None:
    pipeline = ValidationPipeline(FakeUserConfig(), uncertain_confirm_threshold=0.9)
    issue = _uncertain_issue(missing_fact_kinds=["svf_lock_pairing"])

    outcome = pipeline.apply_validator_result(
        issue,
        {"reasoning": "likely but incomplete", "confidence_score": 0.95},
        verdict="uncertain",
        score_data=_score(0.8),
    )

    assert outcome.report_bucket == "observations"
    assert issue["candidate_disposition"] == "needs_review"
    assert "confirmed_via" not in issue


def test_uncertain_verdict_with_negative_evidence_stays_needs_review() -> None:
    pipeline = ValidationPipeline(FakeUserConfig(), uncertain_confirm_threshold=0.9)
    issue = _uncertain_issue(negative_evidence=["release path guarded by quiescence flag"])

    outcome = pipeline.apply_validator_result(
        issue,
        {"reasoning": "conflicting signals", "confidence_score": 0.95},
        verdict="uncertain",
        score_data=_score(0.8),
    )

    assert issue["candidate_disposition"] == "needs_review"


def test_uncertain_verdict_below_threshold_stays_needs_review() -> None:
    pipeline = ValidationPipeline(FakeUserConfig(), uncertain_confirm_threshold=0.9)
    issue = _uncertain_issue()

    outcome = pipeline.apply_validator_result(
        issue,
        {"reasoning": "unclear", "confidence_score": 0.7},
        verdict="uncertain",
        score_data=_score(0.8),
    )

    assert issue["candidate_disposition"] == "needs_review"


# --------------------------------------------------------------------------
# escalation_rung on usage events + archive validation
# --------------------------------------------------------------------------


def _usage_event(call_kind: str, *, escalation_rung: str | None = None) -> dict:
    kwargs = {}
    if escalation_rung is not None:
        kwargs["escalation_rung"] = escalation_rung
    return LLMUsageEvent(
        sequence=1,
        reservation_id="call-1",
        outcome="success",
        prompt_tokens=10,
        completion_tokens=5,
        total_tokens=15,
        reserved_total_tokens=20,
        provider_reported=True,
        conservative_charge=False,
        budget_violation=False,
        attribution=LLMUsageAttribution(
            stage="validation",
            agent="validator_agent",
            candidate_uid="candidate-1",
            validation_cluster_uid="cluster-1",
            llm_ref="validation",
            call_kind=call_kind,
        ),
        budget_stage="validation",
        model="unit-model",
        finish_reason="stop",
        **kwargs,
    ).to_dict()


@pytest.mark.parametrize(
    ("call_kind", "expected"),
    [
        ("initial", "R1_validator_v1"),
        ("targeted_investigation", "R2_v3_reattempt"),
        ("investigation_synthesis", "R2_v3_reattempt"),
        ("v2b_adjudication", "R3_v2b_adjudication"),
        ("json_repair", ""),
        ("", ""),
        (None, ""),
    ],
)
def test_escalation_rung_derives_from_call_kind(call_kind, expected) -> None:
    assert escalation_rung_for_call_kind(call_kind) == expected


def test_usage_event_carries_derived_escalation_rung() -> None:
    event = _usage_event("targeted_investigation")
    assert event["escalation_rung"] == "R2_v3_reattempt"
    _validate_usage_event_v1(event, line_number=1)


def test_usage_event_escalation_rung_override_wins() -> None:
    event = _usage_event("targeted_investigation", escalation_rung="replay_arm_x")
    assert event["escalation_rung"] == "replay_arm_x"
    _validate_usage_event_v1(event, line_number=1)


def test_usage_event_without_escalation_rung_fails_archive_validation() -> None:
    event = _usage_event("initial")
    del event["escalation_rung"]
    with pytest.raises(Exception, match="missing=escalation_rung"):
        _validate_usage_event_v1(event, line_number=1)


def test_usage_reader_backfills_escalation_rung_for_pre_field_archives(tmp_path: Path) -> None:
    from zscope.benchmarking.runner import _read_usage_events_jsonl

    legacy_rows = [_usage_event("initial"), _usage_event("targeted_investigation")]
    for index, row in enumerate(legacy_rows, 1):
        del row["escalation_rung"]
        row["sequence"] = index
        row["reservation_id"] = f"call-{index}"
        row["call_id"] = row["reservation_id"]
    sidecar = tmp_path / "llm_usage_events.jsonl"
    sidecar.write_text(
        "".join(json.dumps(row, ensure_ascii=False) + "\n" for row in legacy_rows),
        encoding="utf-8",
    )

    rows = _read_usage_events_jsonl(sidecar)

    assert [row["escalation_rung"] for row in rows] == [
        "R1_validator_v1",
        "R2_v3_reattempt",
    ]


# --------------------------------------------------------------------------
# confirmed_via in finding attribution
# --------------------------------------------------------------------------


def test_finding_attribution_surfaces_confirmed_via() -> None:
    issue = {
        "id": "I1",
        "candidate_disposition": "confirmed",
        "confirmed_via": "high_confidence_band",
    }
    value = finding_attribution(issue)
    assert value["confirmed_via"] == "high_confidence_band"


def test_finding_attribution_confirmed_via_defaults_empty() -> None:
    value = finding_attribution({"id": "I2", "candidate_disposition": "needs_review"})
    assert value["confirmed_via"] == ""


def test_attribution_summary_counts_by_confirmed_via() -> None:
    issues = [
        {"id": "A", "candidate_disposition": "confirmed", "confirmed_via": "deterministic_proof"},
        {"id": "B", "candidate_disposition": "confirmed", "confirmed_via": "high_confidence_band"},
        {"id": "C", "candidate_disposition": "needs_review"},
    ]
    summary = attribution_summary(
        issues,
        matched_issue_indices=[0, 1],
        raw_false_positive_indices=[],
    )
    by_via = summary["by_confirmed_via"]
    assert by_via["deterministic_proof"]["issues"] == 1
    assert by_via["deterministic_proof"]["true_positives"] == 1
    assert by_via["high_confidence_band"]["issues"] == 1
    assert by_via["high_confidence_band"]["true_positives"] == 1
