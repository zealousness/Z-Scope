"""Plan Phase 2.3: the uncertain-error-analysis bucketing helpers."""

from __future__ import annotations

from scripts.uncertain_error_analysis import _confidence_band, _missing_bucket


def test_missing_bucket() -> None:
    assert _missing_bucket([]) == "obligation_complete"
    assert _missing_bucket(["event:acquire", "event:exit"]) == "event_lifecycle"
    assert _missing_bucket(["event:shared_state_access", "lockset"]) == "lockset_pair"
    assert _missing_bucket(["lockset"]) == "lockset"
    assert _missing_bucket(["happens_before", "lockset"]) == "happens_before"
    assert _missing_bucket(["value_range"]) == "other"


def test_confidence_band() -> None:
    assert _confidence_band(0.82) == ">=0.80"
    assert _confidence_band(0.75) == "0.70-0.79"
    assert _confidence_band(0.65) == "0.60-0.69"
    assert _confidence_band(0.4) == "<0.60"
    assert _confidence_band(None) == "unknown"
    assert _confidence_band("not-a-number") == "unknown"
