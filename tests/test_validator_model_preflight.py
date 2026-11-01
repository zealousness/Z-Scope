from scripts.compare_validator_models import _recommended_model, _run_metrics


def test_model_preflight_counts_only_complete_protocol_valid_groups() -> None:
    metrics = _run_metrics(
        "primary/model",
        {
            "complete": False,
            "run_sha256": "a" * 64,
            "usage": {"total_tokens": 123},
            "groups": [
                {"execution_status": "complete", "protocol_valid": True},
                {"execution_status": "complete", "protocol_valid": False},
                {"execution_status": "invalid", "protocol_valid": True},
            ],
        },
        30.0,
    )

    assert metrics["successful_group_count"] == 1
    assert metrics["protocol_error_group_count"] == 1
    assert metrics["successful_packs_per_minute"] == 2.0


def test_model_preflight_switches_only_at_twenty_percent_without_more_errors() -> None:
    primary = {
        "model": "volcengine/deepseek-v4.1-flash",
        "successful_packs_per_minute": 10.0,
        "protocol_error_rate": 0.05,
    }
    secondary = {
        "model": "deepseek-v4.1-flash",
        "successful_packs_per_minute": 12.0,
        "protocol_error_rate": 0.05,
    }

    selected, reason = _recommended_model(
        [primary, secondary],
        speedup_threshold=1.2,
    )

    assert selected == "deepseek-v4.1-flash"
    assert reason == "secondary_meets_speed_and_protocol_gate"

    secondary["protocol_error_rate"] = 0.1
    selected, reason = _recommended_model(
        [primary, secondary],
        speedup_threshold=1.2,
    )
    assert selected == "volcengine/deepseek-v4.1-flash"
    assert reason == "keep_primary_model"

    primary["successful_packs_per_minute"] = 0.0
    secondary["successful_packs_per_minute"] = 0.0
    secondary["protocol_error_rate"] = 0.05
    selected, reason = _recommended_model(
        [primary, secondary],
        speedup_threshold=1.2,
    )
    assert selected == "volcengine/deepseek-v4.1-flash"
    assert reason == "keep_primary_model"
