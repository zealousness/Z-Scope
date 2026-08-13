from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional


REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT = REPO_ROOT / "scripts" / "balanced_rollout_operator.py"
MANAGEMENT_KEY_ENV = "Z_SCOPE_BALANCED_ROLLOUT_HMAC_KEY"
TEST_MANAGEMENT_KEY = "operator-test-management-key-32-bytes"


def _run(
    *arguments: object, env: Optional[Dict[str, str]] = None
) -> subprocess.CompletedProcess[str]:
    effective_env = dict(os.environ if env is None else env)
    if env is None:
        effective_env[MANAGEMENT_KEY_ENV] = TEST_MANAGEMENT_KEY
    return subprocess.run(
        [sys.executable, str(SCRIPT), *(str(item) for item in arguments)],
        cwd=REPO_ROOT,
        env=effective_env,
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=False,
    )


def _window(*, started_at: str, ended_at: str) -> Dict[str, Any]:
    return {
        "schema_version": "zscope.rollout-observation-window.v1",
        "window_id": "operator-window-1",
        "started_at": started_at,
        "ended_at": ended_at,
        "project_ids": ["project-a", "project-b"],
        "precision@25": 0.75,
        "high_critical_precision": 0.85,
        "incomplete_scan_rate": 0.01,
        "p95_wall_time_vs_approved_ratio": 1.2,
        "token_conservation": True,
        "attribution_complete": True,
        "silent_rejection_without_proof": False,
    }


def test_operator_initializes_then_records_one_window_and_hashes_state(
    tmp_path: Path,
) -> None:
    state_path = tmp_path / "balanced_rollout_state.json"
    initialized = _run(
        "initialize",
        "--state-file",
        state_path,
        "--owner",
        "release-control",
        "--reason",
        "begin telemetry",
    )
    assert initialized.returncode == 0, initialized.stderr
    initial_result = json.loads(initialized.stdout)
    assert initial_result["schema_version"] == "zscope.rollout-operator-result.v1"
    assert initial_result["operation"] == "initialize"
    assert initial_result["decision"]["action"] == "initialize"
    assert initial_result["stage"] == "telemetry_only"
    assert initial_result["state_sha256"] == hashlib.sha256(state_path.read_bytes()).hexdigest()

    envelope = json.loads(state_path.read_text(encoding="utf-8"))
    assert envelope["schema_version"] == "zscope.balanced-rollout-signed-envelope.v1"
    assert envelope["algorithm"] == "HMAC-SHA256"
    assert envelope["language"] == "c_cpp"
    assert len(envelope["signature"]) == 64
    initial_state = envelope["state"]
    started_at = initial_state["stage_entered_at"]
    ended_at = datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")
    window_path = tmp_path / "window.json"
    window_path.write_text(
        json.dumps(_window(started_at=started_at, ended_at=ended_at)),
        encoding="utf-8",
    )

    recorded = _run(
        "record",
        "--state-file",
        state_path,
        "--window-file",
        window_path,
        "--expected-state-sha256",
        initial_result["state_sha256"],
        "--owner",
        "release-control",
        "--reason",
        "completed observation",
    )
    assert recorded.returncode == 0, recorded.stderr
    result = json.loads(recorded.stdout)
    assert result["operation"] == "record"
    assert result["decision"]["action"] == "hold"
    assert result["decision"]["from_stage"] == "telemetry_only"
    assert result["decision"]["to_stage"] == "telemetry_only"
    assert result["state_sha256"] == hashlib.sha256(state_path.read_bytes()).hexdigest()
    assert result["previous_state_sha256"] == initial_result["state_sha256"]
    assert result["window_file_sha256"] == hashlib.sha256(window_path.read_bytes()).hexdigest()
    state = json.loads(state_path.read_text(encoding="utf-8"))["state"]
    assert len(state["observations"]) == 1
    assert state["observations"][0]["window"]["window_id"] == "operator-window-1"


def test_operator_rejects_duplicate_json_keys_without_mutating_state(
    tmp_path: Path,
) -> None:
    state_path = tmp_path / "state.json"
    initialized = _run(
        "initialize",
        "--state-file",
        state_path,
        "--owner",
        "operator",
        "--reason",
        "start",
    )
    assert initialized.returncode == 0, initialized.stderr
    original = state_path.read_bytes()
    state = json.loads(original)["state"]
    ended_at = datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")
    payload = json.dumps(_window(started_at=state["stage_entered_at"], ended_at=ended_at)).replace(
        '"window_id": "operator-window-1"',
        '"window_id": "operator-window-1", "window_id": "duplicate"',
        1,
    )
    window_path = tmp_path / "duplicate.json"
    window_path.write_text(payload, encoding="utf-8")

    completed = _run(
        "record",
        "--state-file",
        state_path,
        "--window-file",
        window_path,
        "--expected-state-sha256",
        hashlib.sha256(original).hexdigest(),
        "--owner",
        "operator",
        "--reason",
        "must reject",
    )
    assert completed.returncode == 1
    assert completed.stdout == ""
    assert "duplicate key: window_id" in completed.stderr
    assert state_path.read_bytes() == original


def test_operator_requires_explicit_files_and_ignores_environment_defaults(
    tmp_path: Path,
) -> None:
    explicit_state = tmp_path / "explicit.json"
    poisoned_state = tmp_path / "from-environment.json"
    environment = dict(os.environ)
    environment[MANAGEMENT_KEY_ENV] = TEST_MANAGEMENT_KEY
    environment["Z_SCOPE_BALANCED_ROLLOUT_STATE"] = str(poisoned_state)
    completed = _run(
        "initialize",
        "--state-file",
        explicit_state,
        "--owner",
        "literal;owner",
        "--reason",
        "explicit input only",
        env=environment,
    )
    assert completed.returncode == 0, completed.stderr
    assert explicit_state.is_file()
    assert not poisoned_state.exists()

    missing_state = tmp_path / "missing.json"
    missing_window = tmp_path / "missing-window.json"
    rejected = _run(
        "record",
        "--state-file",
        missing_state,
        "--window-file",
        missing_window,
        "--expected-state-sha256",
        "0" * 64,
        "--owner",
        "operator",
        "--reason",
        "no implicit initialization",
    )
    assert rejected.returncode == 1
    assert "run the initialize operation" in rejected.stderr
    assert not missing_state.exists()

    unknown = _run(
        "initialize",
        "--state-file",
        explicit_state,
        "--owner",
        "operator",
        "--reason",
        "strict flags",
        "--command",
        "anything",
    )
    assert unknown.returncode == 2
    assert "unrecognized arguments" in unknown.stderr


def test_operator_cas_rejects_stale_state_and_serializes_competing_processes(
    tmp_path: Path,
) -> None:
    state_path = tmp_path / "state.json"
    initialized = _run(
        "initialize",
        "--state-file",
        state_path,
        "--owner",
        "operator",
        "--reason",
        "start",
    )
    assert initialized.returncode == 0, initialized.stderr
    expected = json.loads(initialized.stdout)["state_sha256"]
    state = json.loads(state_path.read_text(encoding="utf-8"))["state"]
    ended_at = datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")
    window_path = tmp_path / "window.json"
    window_path.write_text(
        json.dumps(_window(started_at=state["stage_entered_at"], ended_at=ended_at)),
        encoding="utf-8",
    )
    arguments = (
        "record",
        "--state-file",
        state_path,
        "--window-file",
        window_path,
        "--expected-state-sha256",
        expected,
        "--owner",
        "operator",
        "--reason",
        "competing update",
    )
    with ThreadPoolExecutor(max_workers=2) as pool:
        completed = list(pool.map(lambda _index: _run(*arguments), range(2)))

    assert sorted(item.returncode for item in completed) == [0, 1]
    rejected = next(item for item in completed if item.returncode == 1)
    assert "state changed since the operator read it" in rejected.stderr
    persisted = json.loads(state_path.read_text(encoding="utf-8"))["state"]
    assert len(persisted["observations"]) == 1

    stale = _run(*arguments)
    assert stale.returncode == 1
    assert "state changed since the operator read it" in stale.stderr
    assert len(json.loads(state_path.read_text(encoding="utf-8"))["state"]["observations"]) == 1


def test_operator_requires_env_only_management_key_and_never_echoes_it(tmp_path: Path) -> None:
    state_path = tmp_path / "state.json"
    environment = dict(os.environ)
    environment.pop(MANAGEMENT_KEY_ENV, None)
    completed = _run(
        "initialize",
        "--state-file",
        state_path,
        "--owner",
        "operator",
        "--reason",
        "must authenticate",
        env=environment,
    )

    assert completed.returncode == 1
    assert not state_path.exists()
    assert MANAGEMENT_KEY_ENV in completed.stderr
    assert TEST_MANAGEMENT_KEY not in completed.stderr
    assert "management-key" not in completed.stdout
