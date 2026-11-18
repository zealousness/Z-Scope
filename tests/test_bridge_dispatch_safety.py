"""Reliability checks for project-local development coordination, not scanner policy."""

import importlib.util
from pathlib import Path

import pytest

PATH = Path(__file__).parents[1] / "tests/fixtures/dispatch_safety.py"
SPEC = importlib.util.spec_from_file_location("local_dispatch_safety", PATH)
assert SPEC and SPEC.loader
SAFE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SAFE)

EXPECTED = {
    "agent": "dsh",
    "command": [r"C:\Program Files\DSH\dsh.cmd", "--profile", "acp"],
    "version": "0.2.0-rc.2",
    "provider": "deepseek",
    "model": "deepseek/deepseek-v4.1-flash",
    "base_url": "https://example.test/v1",
    "entry_sha256": "1" * 64,
}


def observed():
    return dict(
        EXPECTED,
        dispatch_enabled=True,
        provider_route_current=True,
        advertised_models=[EXPECTED["model"]],
    )


def test_exact_current_entry_version_provider_model_can_proceed_without_secret_fields():
    assert SAFE.validate_route(EXPECTED, observed(), connection_state="ready") == EXPECTED


@pytest.mark.parametrize(
    "field,value",
    [
        ("command", ["dsh", "--profile", "acp"]),
        ("version", "0.1.2-rc.1"),
        ("provider", "deepseek-official"),
        ("model", "deepseek-official/deepseek-v4-flash"),
        ("base_url", "https://other.test/v1"),
        ("entry_sha256", "2" * 64),
    ],
)
def test_old_path_version_provider_model_and_endpoint_never_fall_back(field, value):
    current = observed()
    current[field] = value
    with pytest.raises(SAFE.DispatchStopped, match="route_mismatch"):
        SAFE.validate_route(EXPECTED, current, connection_state="ready")


def test_static_desktop_route_does_not_authorize_unadvertised_acp_model():
    current = observed()
    current["advertised_models"] = ["deepseek-official/deepseek-v4-flash"]
    with pytest.raises(SAFE.DispatchStopped, match="model_not_advertised"):
        SAFE.validate_route(EXPECTED, current, connection_state="ready")


@pytest.mark.parametrize("state", ["starting", "disconnected", "unknown", "closed"])
def test_connection_loss_blocks_new_send(state):
    with pytest.raises(SAFE.DispatchStopped, match="connection_not_ready"):
        SAFE.validate_route(EXPECTED, observed(), connection_state=state)


def test_secret_fields_are_not_in_diagnostics_and_secret_urls_are_not_echoed():
    current = dict(
        EXPECTED, api_key="SECRET_DO_NOT_PRINT", headers={"Authorization": "SECRET_DO_NOT_PRINT"}
    )
    result = SAFE.public_route(current)
    assert "SECRET_DO_NOT_PRINT" not in str(result)
    current["base_url"] = (
        "https://user:SECRET_DO_NOT_PRINT@example.test/v1?token=SECRET_DO_NOT_PRINT"
    )
    with pytest.raises(SAFE.DispatchStopped) as error:
        SAFE.public_route(current)
    assert "SECRET_DO_NOT_PRINT" not in str(error.value)


def test_missing_or_upgraded_entry_does_not_lookup_path(tmp_path, monkeypatch):
    import shutil

    monkeypatch.setattr(
        shutil, "which", lambda _: (_ for _ in ()).throw(AssertionError("must not fall back"))
    )
    with pytest.raises(SAFE.DispatchStopped, match="pinned_entry_missing"):
        SAFE.verify_entry(tmp_path / "missing.cmd", "1" * 64)
    entry = tmp_path / "entry.cmd"
    entry.write_text("upgraded")
    with pytest.raises(SAFE.DispatchStopped, match="pinned_entry_changed"):
        SAFE.verify_entry(entry, "1" * 64)


def test_unknown_result_survives_client_restart_and_blocks_new_request_id(tmp_path):
    path = tmp_path / "dispatch.sqlite"
    first = SAFE.DispatchJournal(path)
    assert first.claim("r1", "s08", {"model": "kimi-k3"}, connection_state="ready")["send"]
    first.uncertain("r1")
    first.close()
    second = SAFE.DispatchJournal(path)
    assert second.claim("r1", "s08", {"model": "kimi-k3"}, connection_state="ready") == {
        "send": False,
        "state": "uncertain",
        "task_id": None,
    }
    with pytest.raises(SAFE.DispatchStopped, match="branch_occupied"):
        second.claim("r2", "s08", {"model": "kimi-k3"}, connection_state="ready")
    second.close()


def test_receipt_reuse_conflicting_arguments_and_terminal_scope(tmp_path):
    journal = SAFE.DispatchJournal(tmp_path / "dispatch.sqlite")
    journal.claim("r1", "u02", {"model": "kimi-k3"}, connection_state="ready")
    journal.accepted("r1", "task_real")
    assert (
        journal.claim("r1", "u02", {"model": "kimi-k3"}, connection_state="ready")["task_id"]
        == "task_real"
    )
    with pytest.raises(SAFE.DispatchStopped, match="arguments_changed"):
        journal.claim("r1", "u02", {"model": "another"}, connection_state="ready")
    with pytest.raises(SAFE.DispatchStopped, match="branch_changed"):
        journal.claim("r1", "other-branch", {"model": "kimi-k3"}, connection_state="ready")
    with pytest.raises(SAFE.DispatchStopped, match="non_terminal"):
        journal.terminal("task_real", "running")
    with pytest.raises(SAFE.DispatchStopped, match="not_owned"):
        journal.terminal("other_task", "completed")
    journal.terminal("task_real", "failed")
    assert journal.claim("r2", "u02", {"model": "kimi-k3"}, connection_state="ready")["send"]
    journal.close()


def test_nested_worker_and_unverified_provider_cannot_dispatch():
    current = observed()
    current["dispatch_enabled"] = False
    with pytest.raises(SAFE.DispatchStopped, match="dispatch_disabled"):
        SAFE.validate_route(EXPECTED, current, connection_state="ready")
    current = observed()
    current["provider_route_current"] = False
    with pytest.raises(SAFE.DispatchStopped, match="current_provider_route_unverified"):
        SAFE.validate_route(EXPECTED, current, connection_state="ready")


def test_accepted_then_prompt_error_is_still_occupied_after_restart(tmp_path):
    path = tmp_path / "journal.sqlite"
    first = SAFE.DispatchJournal(path)
    first.claim("r1", "zcode-eval", {"model": "hw/glm-5.3"}, connection_state="ready")
    first.accepted("r1", "task_acknowledged")
    first.uncertain("r1")
    first.close()
    second = SAFE.DispatchJournal(path)
    assert second.claim("r1", "zcode-eval", {"model": "hw/glm-5.3"}, connection_state="ready") == {
        "send": False,
        "state": "uncertain",
        "task_id": "task_acknowledged",
    }
    with pytest.raises(SAFE.DispatchStopped, match="branch_occupied"):
        second.claim("r2", "zcode-eval", {"model": "hw/glm-5.3"}, connection_state="ready")
    second.close()


def test_checked_queue_transfers_send_ownership_once_and_blocks_new_uuid(tmp_path):
    path = tmp_path / "queue.sqlite"
    writer = SAFE.DispatchJournal(path)
    writer.claim("r1", "s08", {"model": "kimi-k3"}, connection_state="ready")
    writer.queued("r1")
    driver = SAFE.DispatchJournal(path)
    assert (
        driver.claim("r1", "s08", {"model": "kimi-k3"}, connection_state="ready")["state"]
        == "queued"
    )
    with pytest.raises(SAFE.DispatchStopped, match="branch_occupied"):
        driver.claim("other", "s08", {"model": "kimi-k3"}, connection_state="ready")
    assert driver.begin_send("r1") is True
    assert writer.begin_send("r1") is False
    driver.accepted("r1", "task_once")
    assert (
        writer.claim("r1", "s08", {"model": "kimi-k3"}, connection_state="ready")["send"] is False
    )
    writer.close()
    driver.close()
