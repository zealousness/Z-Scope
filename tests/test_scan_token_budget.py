"""Regression tests for scan-wide token usage and P6 balanced admission.

Ordinary product scans retain observability-only budgets.  A P6 cold balanced
attempt explicitly enables the frozen 10.5M soft / 11,999,999 hard admission
contract so concurrent reservations cannot overshoot its formal evidence cap.
"""

from concurrent.futures import ThreadPoolExecutor
import json
from pathlib import Path

import pytest

from zscope.framework.llm_usage import (
    LLMUsageAttribution,
    P6_BALANCED_MAX_TOKENS,
    P6_BALANCED_SOFT_TOKEN_WATERMARK,
    P6BalancedTokenAdmissionError,
    ScanTokenUsageLedger,
    TOKEN_USAGE_STAGES,
    llm_usage_attribution_scope,
)
from zscope.framework.llm_client import LLMClient


def test_usage_ledger_never_reduces_or_rejects_completion_allowance() -> None:
    ledger = ScanTokenUsageLedger(depth="balanced")
    first = ledger.reserve(1_000_000, 2_000_000, model="glm")
    second = ledger.reserve(9_000_000, 7_000_000, model="glm")

    assert first.completion_token_limit == 2_000_000
    assert second.completion_token_limit == 7_000_000


def test_p6_balanced_hard_boundary_uses_consumed_plus_inflight_reservations() -> None:
    ledger = ScanTokenUsageLedger(depth="balanced")
    ledger.enable_p6_balanced_admission()
    consumed = ledger.reserve(
        P6_BALANCED_MAX_TOKENS - 10_000,
        1,
        attribution=LLMUsageAttribution(stage="validation"),
    )
    ledger.settle(
        consumed,
        prompt_tokens=P6_BALANCED_MAX_TOKENS - 10_000,
        completion_tokens=1,
        provider_reported=True,
    )
    exact = ledger.reserve(
        9_998,
        1,
        attribution=LLMUsageAttribution(stage="validation"),
    )
    assert ledger.snapshot()["consumed_tokens"] + exact.reserved_total_tokens == (
        P6_BALANCED_MAX_TOKENS
    )
    before = ledger.snapshot(include_events=True)
    with pytest.raises(P6BalancedTokenAdmissionError) as raised:
        ledger.reserve(0, 1, attribution=LLMUsageAttribution(stage="validation"))
    assert raised.value.failure_class == "p6_token_hard_limit"
    after = ledger.snapshot(include_events=True)
    assert after["events"] == before["events"]
    assert after["usage_attribution"] == before["usage_attribution"]
    assert after["event_count"] == before["event_count"] == 1
    assert after["p6_balanced_admission"] == {
        "enabled": True,
        "soft_token_watermark": P6_BALANCED_SOFT_TOKEN_WATERMARK,
        "maximum_tokens": P6_BALANCED_MAX_TOKENS,
        "request_count": 3,
        "admitted_request_count": 2,
        "denied_request_count": 1,
        "denied_reasons": {"p6_token_hard_limit": 1},
        "request_conservation_passed": True,
    }


def test_p6_balanced_soft_watermark_stops_low_value_but_allows_closure_work() -> None:
    ledger = ScanTokenUsageLedger(depth="balanced")
    ledger.enable_p6_balanced_admission()
    reservation = ledger.reserve(
        P6_BALANCED_SOFT_TOKEN_WATERMARK - 101,
        1,
        attribution=LLMUsageAttribution(stage="validation"),
    )
    ledger.settle(
        reservation,
        prompt_tokens=P6_BALANCED_SOFT_TOKEN_WATERMARK - 101,
        completion_tokens=1,
        provider_reported=True,
    )
    before_denial = ledger.snapshot(include_events=True)
    with pytest.raises(P6BalancedTokenAdmissionError) as raised:
        ledger.reserve(
            100,
            100,
            attribution=LLMUsageAttribution(
                stage="active_discovery",
                call_kind="p6_low_value_audit",
            ),
        )
    assert raised.value.failure_class == "p6_token_soft_watermark"
    after_denial = ledger.snapshot(include_events=True)
    assert after_denial["events"] == before_denial["events"]
    assert after_denial["usage_attribution"] == before_denial["usage_attribution"]
    assert after_denial["p6_balanced_admission"]["denied_request_count"] == 1
    assert after_denial["p6_balanced_admission"]["request_conservation_passed"] is True
    security_spec = ledger.reserve(
        100,
        100,
        attribution=LLMUsageAttribution(
            stage="semantic_modeling",
            call_kind="security_spec_mining",
        ),
    )
    hunter = ledger.reserve(
        100,
        100,
        attribution=LLMUsageAttribution(
            stage="active_discovery",
            call_kind="hypothesis_hunter",
        ),
    )
    assert security_spec.completion_token_limit == 100
    assert hunter.completion_token_limit == 100
    closure = ledger.reserve(
        100,
        100,
        attribution=LLMUsageAttribution(stage="validation", call_kind="evidence_recheck"),
    )
    assert closure.completion_token_limit == 100


def test_p6_balanced_atomic_reservations_never_exceed_limit_with_eight_workers() -> None:
    ledger = ScanTokenUsageLedger(depth="balanced")
    ledger.enable_p6_balanced_admission()
    initial = ledger.reserve(
        P6_BALANCED_MAX_TOKENS - 800,
        1,
        attribution=LLMUsageAttribution(stage="validation"),
    )
    ledger.settle(
        initial,
        prompt_tokens=P6_BALANCED_MAX_TOKENS - 800,
        completion_tokens=1,
        provider_reported=True,
    )

    def attempt(_index: int) -> bool:
        try:
            ledger.reserve(49, 50, attribution=LLMUsageAttribution(stage="validation"))
        except P6BalancedTokenAdmissionError:
            return False
        return True

    with ThreadPoolExecutor(max_workers=9) as pool:
        accepted = list(pool.map(attempt, range(9)))
    assert sum(accepted) == 8
    snapshot = ledger.snapshot()
    assert snapshot["consumed_tokens"] + snapshot["reserved_tokens"] <= P6_BALANCED_MAX_TOKENS
    admission = snapshot["p6_balanced_admission"]
    assert admission["request_count"] == 10
    assert admission["admitted_request_count"] == 9
    assert admission["denied_request_count"] == 1
    assert admission["request_conservation_passed"] is True
    assert snapshot["usage_attribution"]["totals"]["request_count"] == 1
    assert snapshot["usage_attribution"]["totals"]["provider_reported_calls"] == 1
    assert snapshot["usage_attribution"]["totals"]["estimated_or_conservative_calls"] == 0


def test_usage_ledger_conserves_tokens_by_agent_and_stage() -> None:
    ledger = ScanTokenUsageLedger(depth="deep")

    def record(index: int) -> None:
        stage = TOKEN_USAGE_STAGES[index % len(TOKEN_USAGE_STAGES)]
        reservation = ledger.reserve(
            100,
            200,
            attribution=LLMUsageAttribution(agent=f"agent-{index % 2}", stage=stage),
        )
        ledger.settle(
            reservation,
            prompt_tokens=80,
            completion_tokens=20,
            provider_reported=True,
        )

    with ThreadPoolExecutor(max_workers=8) as pool:
        list(pool.map(record, range(40)))

    snapshot = ledger.snapshot()
    assert snapshot["consumed_tokens"] == 4_000
    assert snapshot["reserved_tokens"] == 0
    assert snapshot["usage_attribution"]["totals"]["total_tokens"] == 4_000
    assert (
        sum(row["total_tokens"] for row in snapshot["usage_attribution"]["by_agent"].values())
        == 4_000
    )
    assert (
        sum(row["total_tokens"] for row in snapshot["usage_attribution"]["by_stage"].values())
        == 4_000
    )


def test_unknown_provider_usage_is_conservatively_measured_not_denied() -> None:
    ledger = ScanTokenUsageLedger(depth="fast")
    reservation = ledger.reserve(100, 300)
    event = ledger.forfeit(reservation, reason="connection_reset")

    assert event.conservative_charge is True
    assert event.total_tokens == 400
    assert ledger.snapshot()["consumed_tokens"] == 400

    following = ledger.reserve(1_000_000, 2_000_000)
    assert following.completion_token_limit == 2_000_000


def test_explicit_pre_model_rejection_releases_without_fabricating_usage() -> None:
    ledger = ScanTokenUsageLedger(depth="balanced")
    reservation = ledger.reserve(100, 300)

    ledger.reject_before_model(reservation, reason="provider_http_client_error")

    snapshot = ledger.snapshot(include_events=True)
    assert snapshot["consumed_tokens"] == 0
    assert snapshot["reserved_tokens"] == 0
    assert snapshot["active_reservation_count"] == 0
    assert snapshot["event_count"] == 0
    assert snapshot["events"] == []
    assert snapshot["rejected_before_model_count"] == 1
    assert snapshot["rejected_before_model_reasons"] == {"provider_http_client_error": 1}


def test_usage_jsonl_contains_no_prompt_or_response_bodies() -> None:
    ledger = ScanTokenUsageLedger(depth="balanced")
    reservation = ledger.reserve(
        10,
        20,
        attribution=LLMUsageAttribution(agent="validator_agent", stage="validation"),
    )
    ledger.settle(
        reservation,
        prompt_tokens=7,
        completion_tokens=3,
        provider_reported=True,
        finish_reason="stop",
    )

    row = json.loads(ledger.events_jsonl())
    assert row["prompt_tokens"] == 7
    assert row["completion_tokens"] == 3
    assert "prompt" not in row
    assert "response" not in row
    assert "reasoning_content" not in row


def test_usage_ledger_aggregates_validator_passes_by_call_kind() -> None:
    ledger = ScanTokenUsageLedger(depth="balanced")
    for call_kind in ("initial", "evidence_recheck", "targeted_investigation"):
        reservation = ledger.reserve(
            10,
            20,
            attribution=LLMUsageAttribution(
                agent="validator_agent",
                stage="validation",
                call_kind=call_kind,
            ),
        )
        ledger.settle(
            reservation,
            prompt_tokens=7,
            completion_tokens=3,
            provider_reported=True,
        )

    by_call_kind = ledger.snapshot()["usage_attribution"]["by_call_kind"]
    assert by_call_kind["initial"]["total_tokens"] == 10
    assert by_call_kind["evidence_recheck"]["total_tokens"] == 10
    assert by_call_kind["targeted_investigation"]["total_tokens"] == 10


def test_usage_ledger_attributes_only_system_accepted_v3_facts(tmp_path) -> None:
    sidecar = tmp_path / "usage.jsonl"
    ledger = ScanTokenUsageLedger(depth="balanced", event_sink_path=sidecar)
    reservation = ledger.reserve(
        100,
        200,
        attribution=LLMUsageAttribution(
            agent="validator_agent",
            stage="validation",
            call_kind="targeted_investigation",
            validation_cluster_uid="VAL_FACTS",
        ),
    )
    ledger.settle(
        reservation,
        prompt_tokens=80,
        completion_tokens=20,
        provider_reported=True,
        # A provider/model supplied value is not authoritative until the
        # validation runner accepts the structured facts into the slice.
        new_fact_count=0,
    )

    assert ledger.attribute_accepted_facts(validation_cluster_uid="VAL_FACTS", new_fact_count=3)

    snapshot = ledger.snapshot(include_events=True)
    assert snapshot["consumed_tokens"] == 100
    assert snapshot["usage_attribution"]["totals"]["new_fact_count"] == 3
    assert snapshot["events"][0]["new_fact_count"] == 3
    persisted = json.loads(sidecar.read_text(encoding="utf-8"))
    assert persisted["new_fact_count"] == 3
    assert persisted["total_tokens"] == 100


def test_usage_event_sink_failure_is_answer_safe(monkeypatch, tmp_path) -> None:
    secret = "PRIVATE_SOURCE_PATH_AND_API_KEY_MUST_NOT_LEAK"

    def fail_mkdir(*_args, **_kwargs):
        raise OSError(secret)

    monkeypatch.setattr(Path, "mkdir", fail_mkdir)
    ledger = ScanTokenUsageLedger(
        depth="balanced",
        event_sink_path=tmp_path / "usage.jsonl",
    )
    reservation = ledger.reserve(10, 20)
    ledger.settle(
        reservation,
        prompt_tokens=7,
        completion_tokens=3,
        provider_reported=True,
    )

    snapshot = ledger.snapshot()
    assert snapshot["telemetry_complete"] is False
    assert snapshot["telemetry_error"] == "llm_usage_event_sink_write_failed"
    assert snapshot["telemetry_error_count"] == 1
    assert secret not in json.dumps(snapshot, ensure_ascii=False, sort_keys=True)


def test_nested_llm_call_inherits_validation_cluster_for_proof_engine() -> None:
    ledger = ScanTokenUsageLedger(depth="balanced")
    client = LLMClient(
        api_key="test",
        base_url="http://example.invalid",
        models=["unit-model"],
        token_usage_ledger=ledger,
        llm_ref="modeling",
    )

    with llm_usage_attribution_scope(
        validation_cluster_uid="VAL_NESTED",
        candidate_uid="CAND_NESTED",
        call_kind="v3_tool_dependency",
    ):
        reservation = client._reserve_scan_usage(
            [{"role": "user", "content": "frozen snapshot request"}],
            tools=None,
            response_format=None,
            max_completion_tokens=50,
            model="unit-model",
            trace_agent="proof_engine",
            trace_label="function=callee",
            usage_attribution=None,
        )

    assert reservation is not None
    assert reservation.attribution.agent == "proof_engine"
    assert reservation.attribution.stage == "validation"
    assert reservation.attribution.validation_cluster_uid == "VAL_NESTED"
    assert reservation.attribution.candidate_uid == "CAND_NESTED"
    assert reservation.attribution.call_kind == "v3_tool_dependency"
