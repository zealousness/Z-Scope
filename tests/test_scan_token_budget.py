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
)


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
