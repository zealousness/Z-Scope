"""Business answer history in the existing project user-config state database."""

from __future__ import annotations

import json
from typing import Any

from ..semantics.business_assumptions import assumption_key, assumption_subject


class ProtocolAnswerConflict(ValueError):
    pass


def initialize(conn: Any) -> None:
    conn.execute(
        """CREATE TABLE IF NOT EXISTS protocol_assumption_answers (
        subject_key TEXT NOT NULL,
        revision INTEGER NOT NULL,
        subject_json TEXT NOT NULL,
        answer TEXT NOT NULL,
        source_note TEXT NOT NULL,
        origin TEXT NOT NULL,
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY(subject_key, revision)
    )"""
    )


def latest(conn: Any, keys: list[str]) -> dict[str, dict[str, Any]]:
    result = {}
    # Avoid SQLite's parameter limit for reports with many objects.
    for start in range(0, len(keys), 400):
        chunk = keys[start : start + 400]
        if not chunk:
            continue
        rows = conn.execute(
            "SELECT answer.* FROM protocol_assumption_answers AS answer JOIN "
            "(SELECT subject_key, MAX(revision) AS revision FROM protocol_assumption_answers WHERE subject_key IN ("
            + ",".join("?" for _ in chunk)
            + ") GROUP BY subject_key) AS current USING (subject_key, revision)",
            chunk,
        ).fetchall()
        for row in rows:
            key = str(row["subject_key"])
            if key not in result:
                result[key] = dict(row)
    return result


def save(conn: Any, updates: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    """One atomic batch; an optimistic conflict never loses an earlier answer."""
    if not updates or len(updates) > 1000:
        raise ValueError("一次可保存 1–1000 条业务前提")
    prepared: dict[str, dict[str, Any]] = {}
    for update in updates:
        assumption = update.get("assumption")
        if not isinstance(assumption, dict):
            raise ValueError("缺少业务前提")
        key = assumption_key(assumption)
        answer, note = update.get("answer"), update.get("source_note")
        revision = update.get("expected_revision")
        if key in prepared or not isinstance(answer, str) or answer not in {"yes", "no", "unknown"}:
            raise ValueError("业务前提重复或回答无效")
        if not isinstance(note, str) or not note.strip() or len(note) > 4000:
            raise ValueError("请填写业务约定来源或说明（1–4000 字）")
        if type(revision) is not int or revision < 0:
            raise ValueError("缺少业务回答版本，请刷新后重试")
        prepared[key] = {
            "subject_json": json.dumps(
                assumption_subject(assumption), ensure_ascii=False, sort_keys=True
            ),
            "answer": answer,
            "source_note": note.strip(),
            "expected_revision": revision,
        }
    conn.execute("BEGIN IMMEDIATE")
    try:
        current = latest(conn, list(prepared))
        for key, value in prepared.items():
            old = current.get(key, {})
            if (
                old.get("answer") == value["answer"]
                and old.get("source_note") == value["source_note"]
            ):
                continue  # Retrying the exact accepted write is harmless.
            revision = int(old.get("revision", 0))
            if revision != value["expected_revision"]:
                raise ProtocolAnswerConflict("业务回答已变化，保留本次草稿；刷新后核对再保存")
            conn.execute(
                "INSERT INTO protocol_assumption_answers "
                "(subject_key, revision, subject_json, answer, source_note, origin) VALUES (?, ?, ?, ?, ?, ?)",
                (
                    key,
                    revision + 1,
                    value["subject_json"],
                    value["answer"],
                    value["source_note"],
                    "user_acceptance",
                ),
            )
        result = latest(conn, list(prepared))
        conn.commit()
        return result
    except Exception:
        conn.rollback()
        raise
