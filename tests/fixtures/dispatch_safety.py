"""Small local dispatch checks and durable duplicate protection, outside product code."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path, PureWindowsPath
import sqlite3
from urllib.parse import urlsplit


class DispatchStopped(ValueError):
    """A dispatch was stopped before invoking the public Bridge tool."""


def public_route(value: dict) -> dict:
    """Only non-secret routing fields may enter diagnostic output."""
    allowed = (
        "agent",
        "command",
        "version",
        "provider",
        "model",
        "base_url",
        "entry_sha256",
        "adapter_sha256",
    )
    result = {key: value[key] for key in allowed if key in value}
    if "base_url" in result:
        parts = urlsplit(str(result["base_url"]))
        if parts.username or parts.password or parts.query or parts.fragment:
            raise DispatchStopped("endpoint_contains_non_public_components")
    return result


def validate_route(expected: dict, actual: dict, *, connection_state: str) -> dict:
    """No PATH lookup, fallback, model alias guess, or default-provider substitution."""
    if connection_state != "ready":
        raise DispatchStopped("bridge_connection_not_ready")
    if actual.get("dispatch_enabled") is not True:
        raise DispatchStopped("bridge_dispatch_disabled")
    for key in ("agent", "command", "version", "provider", "model", "base_url", "entry_sha256"):
        if not expected.get(key) or not actual.get(key):
            raise DispatchStopped(f"route_unverified:{key}")
        if key == "command":
            wanted = [str(PureWindowsPath(p)).casefold() for p in expected[key]]
            observed = [str(PureWindowsPath(p)).casefold() for p in actual[key]]
            if wanted != observed:
                raise DispatchStopped("route_mismatch:command")
        elif expected[key] != actual[key]:
            raise DispatchStopped(f"route_mismatch:{key}")
    if expected.get("adapter_sha256") and expected["adapter_sha256"] != actual.get(
        "adapter_sha256"
    ):
        raise DispatchStopped("route_mismatch:adapter_sha256")
    if expected["model"] not in actual.get("advertised_models", []):
        raise DispatchStopped("model_not_advertised_by_current_session")
    # Read from the current official config, then bind its selected provider to
    # the ACP session. An old desktop selection alone is insufficient.
    if actual.get("provider_route_current") is not True:
        raise DispatchStopped("current_provider_route_unverified")
    return public_route(expected)


def verify_entry(path: Path, expected_sha256: str) -> str:
    """A missing or changed pinned entry requires normal inspection/update."""
    if not path.is_file():
        raise DispatchStopped("pinned_entry_missing; inspect_installed_official_entry")
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    if digest != expected_sha256:
        raise DispatchStopped("pinned_entry_changed; inspect_upgrade_and_update_binding")
    return digest


class DispatchJournal:
    """Persist before send; uncertain outcomes remain occupied, even after restart."""

    def __init__(self, path: Path):
        path.parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(path, timeout=10)
        self.db.execute(
            "CREATE TABLE IF NOT EXISTS requests (id TEXT PRIMARY KEY, branch TEXT NOT NULL, digest TEXT NOT NULL, state TEXT NOT NULL, task_id TEXT)"
        )
        self.db.commit()

    def close(self):
        self.db.close()

    def claim(
        self, request_id: str, branch: str, arguments: dict, *, connection_state: str
    ) -> dict:
        if connection_state != "ready":
            raise DispatchStopped("bridge_connection_not_ready")
        digest = hashlib.sha256(
            json.dumps(
                arguments, sort_keys=True, ensure_ascii=False, separators=(",", ":")
            ).encode()
        ).hexdigest()
        self.db.execute("BEGIN IMMEDIATE")
        try:
            row = self.db.execute(
                "SELECT digest,state,task_id,branch FROM requests WHERE id=?", (request_id,)
            ).fetchone()
            if row:
                if row[0] != digest:
                    raise DispatchStopped("request_id_arguments_changed")
                if row[3] != branch:
                    raise DispatchStopped("request_id_branch_changed")
                # Never invoke again just because another client was created.
                result = {"send": False, "state": row[1], "task_id": row[2]}
            else:
                occupied = self.db.execute(
                    "SELECT id,state,task_id FROM requests WHERE branch=? AND state IN ('queued','pending','uncertain','accepted')",
                    (branch,),
                ).fetchone()
                if occupied:
                    raise DispatchStopped(
                        "branch_occupied; inspect_public_task_and_execution_before_retry"
                    )
                self.db.execute(
                    "INSERT INTO requests VALUES (?,?,?,'pending',NULL)",
                    (request_id, branch, digest),
                )
                result = {"send": True, "state": "pending", "task_id": None}
            self.db.commit()
            return result
        except BaseException:
            self.db.rollback()
            raise

    def accepted(self, request_id: str, task_id: str):
        if not task_id:
            raise DispatchStopped("missing_public_task_receipt")
        with self.db:
            cursor = self.db.execute(
                "UPDATE requests SET state='accepted',task_id=? WHERE id=? AND state IN ('queued','pending')",
                (task_id, request_id),
            )
            if cursor.rowcount != 1:
                raise DispatchStopped("receipt_does_not_match_pending_request")

    def queued(self, request_id: str):
        with self.db:
            self.db.execute(
                "UPDATE requests SET state='queued' WHERE id=? AND state='pending'", (request_id,)
            )

    def begin_send(self, request_id: str) -> bool:
        with self.db:
            cursor = self.db.execute(
                "UPDATE requests SET state='pending' WHERE id=? AND state='queued'", (request_id,)
            )
            return cursor.rowcount == 1

    def uncertain(self, request_id: str):
        with self.db:
            self.db.execute(
                "UPDATE requests SET state='uncertain' WHERE id=? AND state IN ('queued','pending','accepted')",
                (request_id,),
            )

    def terminal(self, task_id: str, state: str):
        if state not in {"completed", "failed", "cancelled"}:
            raise DispatchStopped("non_terminal_status_cannot_release_branch")
        with self.db:
            cursor = self.db.execute(
                "UPDATE requests SET state=? WHERE task_id=? AND state='accepted'", (state, task_id)
            )
            if cursor.rowcount != 1:
                raise DispatchStopped("terminal_receipt_task_not_owned")
