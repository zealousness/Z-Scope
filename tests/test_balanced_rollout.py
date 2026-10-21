from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest

from zscope.orchestration.rollout import (
    ROLLOUT_STAGES,
    BalancedRolloutController,
    ObservationWindow,
    RolloutDecision,
    RolloutState,
    RolloutStateError,
    RolloutThresholds,
    apply_persisted_rollout_policy,
    deterministic_rollout_bucket,
    _build_signed_rollout_envelope,
    _rollout_release_identity,
)


TEST_MANAGEMENT_KEY = b"runtime-test-management-key-32-bytes"


class FakeClock:
    def __init__(self) -> None:
        self.current = datetime(2026, 1, 1, tzinfo=timezone.utc)

    def __call__(self) -> datetime:
        return self.current

    def advance(self, *, days: int = 0, hours: int = 0) -> None:
        self.current += timedelta(days=days, hours=hours)


def _timestamp(value: datetime) -> str:
    return value.isoformat(timespec="microseconds").replace("+00:00", "Z")


def _window(
    clock: FakeClock,
    *,
    window_id: str,
    started_at: datetime,
    project_ids: tuple[str, ...] | None = None,
    precision_at_25: float = 0.75,
    high_critical_precision: float = 0.85,
    incomplete_scan_rate: float = 0.01,
    p95_wall_time_vs_approved_ratio: float = 1.20,
    token_conservation: bool = True,
    attribution_complete: bool = True,
    silent_rejection_without_proof: bool = False,
) -> ObservationWindow:
    return ObservationWindow(
        window_id=window_id,
        started_at=_timestamp(started_at),
        ended_at=_timestamp(clock.current),
        project_ids=project_ids or (f"{window_id}-project",),
        precision_at_25=precision_at_25,
        high_critical_precision=high_critical_precision,
        incomplete_scan_rate=incomplete_scan_rate,
        p95_wall_time_vs_approved_ratio=p95_wall_time_vs_approved_ratio,
        token_conservation=token_conservation,
        attribution_complete=attribution_complete,
        silent_rejection_without_proof=silent_rejection_without_proof,
    )


def _twenty_projects(prefix: str) -> tuple[str, ...]:
    return tuple(f"{prefix}-{index:02d}" for index in range(20))


def test_full_rollout_ladder_requires_stage_time_projects_and_two_100_windows(
    tmp_path: Path,
) -> None:
    clock = FakeClock()
    state_path = tmp_path / "rollout-state.json"
    controller = BalancedRolloutController(state_path, clock=clock)
    state = controller.initialize(owner="release-team", reason="start telemetry")
    assert state.stage == "telemetry_only"
    assert state.effective_depth == "fast"

    expected_promotions = [
        "validator_opt_in",
        "semantic_shadow",
        "10",
        "50",
        "100",
    ]
    for index, target_stage in enumerate(expected_promotions):
        entered_at = clock.current
        clock.advance(days=7)
        decision = controller.record_window(
            _window(
                clock,
                window_id=f"promotion-{index}",
                started_at=entered_at,
                project_ids=_twenty_projects(f"stage-{index}"),
            ),
            owner="release-team",
            reason=f"promote to {target_stage}",
        )
        assert decision.action == "promote"
        assert decision.to_stage == target_stage

    entered_100 = clock.current
    clock.advance(days=3)
    first = controller.record_window(
        _window(
            clock,
            window_id="100-stable-1",
            started_at=entered_100,
            project_ids=tuple(f"100-a-{index}" for index in range(10)),
        ),
        owner="release-team",
        reason="first stable 100 percent window",
    )
    assert first.action == "hold"
    assert controller.load().stable_windows_at_100 == 1

    second_start = clock.current
    clock.advance(days=4)
    second = controller.record_window(
        _window(
            clock,
            window_id="100-stable-2",
            started_at=second_start,
            project_ids=tuple(f"100-b-{index}" for index in range(10)),
        ),
        owner="release-team",
        reason="second stable 100 percent window",
    )
    assert second.action == "promote"
    assert second.to_stage == "balanced_default"
    assert second.effective_depth == "balanced"

    reloaded = BalancedRolloutController(state_path, clock=clock).load()
    assert reloaded.stage == "balanced_default"
    assert reloaded.recommended_balanced_percent == 100
    assert reloaded.owner == "release-team"
    assert reloaded.reason == "second stable 100 percent window"
    assert [item.to_stage for item in reloaded.decisions if item.action == "promote"] == [
        *ROLLOUT_STAGES[1:],
    ]


def test_promotion_accumulates_distinct_projects_but_waits_seven_days(
    tmp_path: Path,
) -> None:
    clock = FakeClock()
    controller = BalancedRolloutController(tmp_path / "state.json", clock=clock)
    controller.initialize(owner="operator", reason="start")
    entered_at = clock.current

    clock.advance(days=6)
    first = controller.record_window(
        _window(
            clock,
            window_id="under-seven-days",
            started_at=entered_at,
            project_ids=_twenty_projects("project"),
        ),
        owner="operator",
        reason="duration gate check",
    )
    assert first.action == "hold"
    assert "minimum_7_days" in first.rationale

    second_start = clock.current
    clock.advance(days=1)
    second = controller.record_window(
        _window(
            clock,
            window_id="seven-days",
            started_at=second_start,
        ),
        owner="operator",
        reason="duration gate satisfied",
    )
    assert second.action == "promote"
    assert second.to_stage == "validator_opt_in"


@pytest.mark.parametrize(
    "overrides, expected_failure",
    [
        ({"token_conservation": False}, "token_conservation"),
        ({"attribution_complete": False}, "attribution_complete"),
        (
            {"silent_rejection_without_proof": True},
            "silent_rejection_without_proof",
        ),
    ],
)
def test_hard_invariant_immediately_rolls_back_and_restarts_telemetry_period(
    tmp_path: Path,
    overrides: dict[str, bool],
    expected_failure: str,
) -> None:
    clock = FakeClock()
    controller = BalancedRolloutController(tmp_path / "state.json", clock=clock)
    initial = controller.initialize(owner="operator", reason="start")
    clock.advance(days=1)
    decision = controller.record_window(
        _window(
            clock,
            window_id="hard-failure",
            started_at=datetime.fromisoformat(initial.stage_entered_at.replace("Z", "+00:00")),
            **overrides,
        ),
        owner="safety-owner",
        reason="hard invariant failed",
    )

    assert decision.action == "rollback_fast"
    assert decision.to_stage == "telemetry_only"
    assert decision.hard_failures == (expected_failure,)
    state = controller.load()
    assert state.effective_depth == "fast"
    assert state.stage_entered_at == decision.timestamp
    assert state.stage_project_ids == ()
    assert state.consecutive_threshold_breaches == 0
    assert state.owner == "safety-owner"
    assert state.reason == "hard invariant failed"


def test_two_consecutive_user_threshold_breaches_roll_back_but_healthy_resets(
    tmp_path: Path,
) -> None:
    clock = FakeClock()
    controller = BalancedRolloutController(
        tmp_path / "state.json",
        thresholds=RolloutThresholds(precision_at_25_min=0.90),
        clock=clock,
    )
    controller.initialize(owner="operator", reason="start")

    start = clock.current
    clock.advance(hours=1)
    first = controller.record_window(
        _window(clock, window_id="bad-1", started_at=start, precision_at_25=0.80),
        owner="operator",
        reason="first breach",
    )
    assert first.action == "hold"
    assert controller.load().consecutive_threshold_breaches == 1

    start = clock.current
    clock.advance(hours=1)
    healthy = controller.record_window(
        _window(clock, window_id="healthy", started_at=start, precision_at_25=0.95),
        owner="operator",
        reason="healthy reset",
    )
    assert healthy.action == "hold"
    assert controller.load().consecutive_threshold_breaches == 0

    start = clock.current
    clock.advance(hours=1)
    controller.record_window(
        _window(clock, window_id="bad-2", started_at=start, precision_at_25=0.80),
        owner="operator",
        reason="new first breach",
    )
    start = clock.current
    clock.advance(hours=1)
    rollback = controller.record_window(
        _window(
            clock,
            window_id="bad-3",
            started_at=start,
            precision_at_25=0.95,
            high_critical_precision=0.70,
        ),
        owner="operator",
        reason="second consecutive breach",
    )
    assert rollback.action == "rollback_fast"
    assert rollback.threshold_breaches == ("high_critical_precision",)
    assert controller.load().consecutive_threshold_breaches == 0


def test_strict_json_rejects_unknown_fields_and_invalid_decision_transitions(
    tmp_path: Path,
) -> None:
    clock = FakeClock()
    path = tmp_path / "state.json"
    controller = BalancedRolloutController(path, clock=clock)
    controller.initialize(owner="operator", reason="start")
    raw = json.loads(path.read_text(encoding="utf-8"))
    raw["unexpected"] = True
    path.write_text(json.dumps(raw), encoding="utf-8")
    with pytest.raises(RolloutStateError, match="fields mismatch"):
        controller.load()

    valid = RolloutDecision(
        action="hold",
        from_stage="telemetry_only",
        to_stage="telemetry_only",
        effective_depth="fast",
        recommended_balanced_percent=0,
        owner="operator",
        reason="test",
        rationale="test hold",
        timestamp=_timestamp(clock.current),
    ).to_dict()
    valid["to_stage"] = "semantic_shadow"
    with pytest.raises(RolloutStateError, match="hold decision cannot change stage"):
        RolloutDecision.from_dict(valid)


def test_atomic_replace_failure_leaves_previous_state_intact(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    clock = FakeClock()
    path = tmp_path / "state.json"
    controller = BalancedRolloutController(path, clock=clock)
    controller.initialize(owner="operator", reason="start")
    original = path.read_bytes()
    start = clock.current
    clock.advance(hours=1)

    def fail_replace(_source: object, _target: object) -> None:
        raise OSError("simulated replace failure")

    monkeypatch.setattr("zscope.orchestration.rollout.os.replace", fail_replace)
    with pytest.raises(OSError, match="simulated replace failure"):
        controller.record_window(
            _window(clock, window_id="atomic", started_at=start),
            owner="operator",
            reason="atomic write test",
        )

    assert path.read_bytes() == original
    assert list(tmp_path.glob(".state.json.*.tmp")) == []


def test_signed_state_binds_release_sequence_and_expiry(tmp_path: Path) -> None:
    clock = FakeClock()
    path = tmp_path / "signed-state.json"
    controller = BalancedRolloutController(
        path,
        clock=clock,
        management_key=TEST_MANAGEMENT_KEY,
        release_identity="release-2026.08",
    )
    state = controller.initialize(owner="release-control", reason="signed rollout")
    envelope = json.loads(path.read_text(encoding="utf-8"))

    assert envelope["sequence"] == len(state.decisions) == 1
    assert envelope["release_identity"] == "release-2026.08"
    assert controller.load().stage == "telemetry_only"
    with pytest.raises(RolloutStateError, match="release identity mismatch"):
        BalancedRolloutController(
            path,
            clock=clock,
            management_key=TEST_MANAGEMENT_KEY,
            release_identity="different-release",
        ).load()

    clock.advance(days=91)
    with pytest.raises(RolloutStateError, match="has expired"):
        controller.load()


def test_observation_schema_requires_exact_types() -> None:
    clock = FakeClock()
    clock.advance(hours=1)
    raw = _window(
        clock,
        window_id="strict-window",
        started_at=clock.current - timedelta(hours=1),
    ).to_dict()
    raw["token_conservation"] = 1
    with pytest.raises(RolloutStateError, match="must be boolean"):
        ObservationWindow.from_dict(raw)

    raw = _window(
        clock,
        window_id="strict-extra",
        started_at=clock.current - timedelta(hours=1),
    ).to_dict()
    raw["extra"] = "not allowed"
    with pytest.raises(RolloutStateError, match="fields mismatch"):
        ObservationWindow.from_dict(raw)


def _persist_rollout_stage(path: Path, stage: str, *, signed: bool = True) -> None:
    # Runtime policy tests need a currently valid envelope. Expiry itself is
    # covered separately with the controller's injected deterministic clock.
    entered = _timestamp(datetime.now(timezone.utc))
    if stage == "telemetry_only":
        action = "initialize"
        from_stage = "telemetry_only"
    else:
        action = "promote"
        from_stage = ROLLOUT_STAGES[ROLLOUT_STAGES.index(stage) - 1]
    percentage = {"10": 10, "50": 50, "100": 100, "balanced_default": 100}.get(stage, 0)
    decision = RolloutDecision(
        action=action,
        from_stage=from_stage,
        to_stage=stage,
        effective_depth="balanced" if stage == "balanced_default" else "fast",
        recommended_balanced_percent=percentage,
        owner="release-team",
        reason="runtime policy test",
        rationale="persisted release decision",
        timestamp=entered,
    )
    state = RolloutState(
        stage=stage,
        effective_depth="balanced" if stage == "balanced_default" else "fast",
        recommended_balanced_percent=percentage,
        stage_entered_at=entered,
        updated_at=entered,
        owner="release-team",
        reason="runtime policy test",
        thresholds=RolloutThresholds(),
        stage_project_ids=(),
        consecutive_threshold_breaches=0,
        stable_windows_at_100=0,
        observations=(),
        decisions=(decision,),
    )
    payload = (
        _build_signed_rollout_envelope(
            state,
            key=TEST_MANAGEMENT_KEY,
            release_identity=_rollout_release_identity(),
        )
        if signed
        else state.to_dict()
    )
    path.write_text(json.dumps(payload), encoding="utf-8")


def _runtime_config(
    tmp_path: Path,
    *,
    depth: str,
    source: str,
    project_id: str = "project-a",
):
    return SimpleNamespace(
        scan=SimpleNamespace(
            depth=depth,
            depth_source=source,
        ),
        analysis=SimpleNamespace(
            snapshot_dir=str(tmp_path),
            security_semantic_enrichment_mode="shadow",
        ),
        project=SimpleNamespace(
            language="c_cpp",
            project_id=project_id,
            project_root=tmp_path,
        ),
    )


def test_runtime_telemetry_state_forces_fast_and_preserves_requested_audit(
    tmp_path: Path,
) -> None:
    state_path = tmp_path / "state.json"
    _persist_rollout_stage(state_path, "telemetry_only")
    config = _runtime_config(tmp_path, depth="deep", source="cli")

    policy = apply_persisted_rollout_policy(
        config, state_path=state_path, management_key=TEST_MANAGEMENT_KEY
    )

    assert config.scan.depth == "fast"
    assert config.scan.depth_source == "rollout"
    assert policy["requested_depth"] == "deep"
    assert policy["effective_depth"] == "fast"
    assert policy["forced_fast"] is True
    assert policy["active_discovery_mode"] == "disabled"


def test_runtime_semantic_shadow_honors_explicit_opt_in_without_promotion(
    tmp_path: Path,
) -> None:
    state_path = tmp_path / "state.json"
    _persist_rollout_stage(state_path, "semantic_shadow")
    config = _runtime_config(tmp_path, depth="balanced", source="config")

    policy = apply_persisted_rollout_policy(
        config, state_path=state_path, management_key=TEST_MANAGEMENT_KEY
    )

    assert config.scan.depth == "balanced"
    assert policy["semantic_enrichment_mode"] == "shadow"
    assert policy["active_discovery_mode"] == "shadow"
    assert policy["shadow_findings_visible_in_default"] is False


def test_runtime_percentage_stage_uses_stable_project_enrollment(tmp_path: Path) -> None:
    state_path = tmp_path / "state.json"
    _persist_rollout_stage(state_path, "10")
    enrolled_id = next(
        f"project-{index}"
        for index in range(1000)
        if deterministic_rollout_bucket(f"project-{index}") < 10
    )
    held_id = next(
        f"held-{index}"
        for index in range(1000)
        if deterministic_rollout_bucket(f"held-{index}") >= 10
    )

    enrolled = _runtime_config(tmp_path, depth="fast", source="default", project_id=enrolled_id)
    held = _runtime_config(tmp_path, depth="fast", source="default", project_id=held_id)

    enrolled_policy = apply_persisted_rollout_policy(
        enrolled, state_path=state_path, management_key=TEST_MANAGEMENT_KEY
    )
    held_policy = apply_persisted_rollout_policy(
        held, state_path=state_path, management_key=TEST_MANAGEMENT_KEY
    )

    assert enrolled.scan.depth == "balanced"
    assert enrolled_policy["enrolled"] is True
    assert enrolled_policy["active_discovery_mode"] == "active"
    assert held.scan.depth == "fast"
    assert held_policy["enrolled"] is False
    assert held_policy["active_discovery_mode"] == "disabled"


def test_invalid_persisted_runtime_state_is_unmanaged_and_preserves_explicit_opt_in(
    tmp_path: Path,
) -> None:
    state_path = tmp_path / "state.json"
    state_path.write_text('{"schema_version":"invalid"}', encoding="utf-8")
    config = _runtime_config(tmp_path, depth="balanced", source="cli")

    policy = apply_persisted_rollout_policy(
        config, state_path=state_path, management_key=TEST_MANAGEMENT_KEY
    )

    assert config.scan.depth == "balanced"
    assert policy["stage"] == "unmanaged"
    assert policy["managed"] is False
    assert policy["state_error"]


def test_unsigned_project_local_state_cannot_auto_promote_default_depth(tmp_path: Path) -> None:
    state_path = tmp_path / "state.json"
    _persist_rollout_stage(state_path, "balanced_default", signed=False)
    config = _runtime_config(tmp_path, depth="fast", source="default")

    policy = apply_persisted_rollout_policy(
        config, state_path=state_path, management_key=TEST_MANAGEMENT_KEY
    )

    assert config.scan.depth == "fast"
    assert policy["managed"] is False
    assert policy["state_authenticated"] is False
    assert policy["enrollment_reason"] == "rollout_state_authentication_failed"


def test_missing_management_key_ignores_state_but_preserves_explicit_cli_depth(
    tmp_path: Path,
) -> None:
    state_path = tmp_path / "state.json"
    _persist_rollout_stage(state_path, "balanced_default")
    default_config = _runtime_config(tmp_path, depth="fast", source="default")
    explicit_config = _runtime_config(tmp_path, depth="balanced", source="cli")

    default_policy = apply_persisted_rollout_policy(default_config, state_path=state_path)
    explicit_policy = apply_persisted_rollout_policy(explicit_config, state_path=state_path)

    assert default_config.scan.depth == "fast"
    assert explicit_config.scan.depth == "balanced"
    assert default_policy["managed"] is False
    assert explicit_policy["managed"] is False
    assert default_policy["enrollment_reason"] == "rollout_management_key_unavailable"


def test_tampered_signed_state_is_unmanaged_and_cannot_enroll(tmp_path: Path) -> None:
    state_path = tmp_path / "state.json"
    _persist_rollout_stage(state_path, "balanced_default")
    envelope = json.loads(state_path.read_text(encoding="utf-8"))
    envelope["state"]["recommended_balanced_percent"] = 0
    state_path.write_text(json.dumps(envelope), encoding="utf-8")
    config = _runtime_config(tmp_path, depth="fast", source="default")

    policy = apply_persisted_rollout_policy(
        config, state_path=state_path, management_key=TEST_MANAGEMENT_KEY
    )

    assert config.scan.depth == "fast"
    assert policy["managed"] is False
    assert "authentication failed" in policy["state_error"]
