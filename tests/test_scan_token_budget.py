"""Regression tests for scan-wide token usage telemetry.

The product deliberately has no scan-wide token admission budget.  Depth cost
expectations are benchmark gates evaluated after a run.
"""

from concurrent.futures import ThreadPoolExecutor
import json

from zscope.framework.llm_usage import (
    LLMUsageAttribution,
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
