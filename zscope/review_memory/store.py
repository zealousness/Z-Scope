from __future__ import annotations

import json
import os
import sqlite3
import hashlib
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

from .identity import utc_now
from .schema import validate_pattern, validate_pattern_match, validate_review_record


class ReviewMemoryStore:
    """Project-local store; Review Memory is intentionally separate from Wiki state."""

    def __init__(self, project_root: Path, state_dir: str = ".zscope/review-memory") -> None:
        root = Path(project_root).resolve()
        relative = Path(state_dir)
        if relative.is_absolute() or ".." in relative.parts:
            raise ValueError("review memory state_dir must be project-root relative")
        self.root = root
        self.state = (root / relative).resolve()
        try:
            self.state.relative_to(root)
        except ValueError as exc:
            raise ValueError("review memory state_dir escapes project root") from exc
        self.records_dir = self.state / "records"
        self.proposals_dir = self.state / "proposals"
        self.audit_dir = self.state / "audits"
        self.replays_dir = self.state / "replays"
        self.exports_dir = self.state / "exports"
        for directory in (self.records_dir, self.proposals_dir, self.audit_dir, self.replays_dir, self.exports_dir):
            directory.mkdir(parents=True, exist_ok=True)
        self.db_path = self.state / "review-memory.db"
        with sqlite3.connect(self.db_path) as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS review_records (
                    review_id TEXT PRIMARY KEY, project_id TEXT NOT NULL,
                    status TEXT NOT NULL, record_json TEXT NOT NULL, created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS pattern_proposals (
                    pattern_id TEXT PRIMARY KEY, project_id TEXT NOT NULL,
                    status TEXT NOT NULL, pattern_json TEXT NOT NULL, updated_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS pattern_matches (
                    pattern_id TEXT NOT NULL,
                    scan_id TEXT NOT NULL,
                    issue_identity_json TEXT NOT NULL,
                    match_json TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    PRIMARY KEY (pattern_id, scan_id, issue_identity_json)
                );
                CREATE TABLE IF NOT EXISTS extraction_jobs (
                    job_id TEXT PRIMARY KEY,
                    status TEXT NOT NULL,
                    review_ids_json TEXT NOT NULL,
                    attempts INTEGER NOT NULL DEFAULT 0,
                    error TEXT NOT NULL DEFAULT '',
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_review_project ON review_records(project_id);
                CREATE INDEX IF NOT EXISTS idx_pattern_scope ON pattern_proposals(project_id, status);
                CREATE INDEX IF NOT EXISTS idx_pattern_matches_scan ON pattern_matches(scan_id);
            """)

    def _atomic_json(self, path: Path, value: Dict[str, Any]) -> None:
        temporary = path.with_suffix(path.suffix + ".tmp")
        temporary.write_text(json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        os.replace(temporary, path)

    def append_audit(self, event: str, payload: Dict[str, Any]) -> None:
        path = self.audit_dir / "events.jsonl"
        previous_hash = ""
        if path.exists():
            with path.open("rb") as handle:
                for line in handle:
                    if line.strip():
                        try:
                            previous_hash = str(json.loads(line).get("event_hash") or "")
                        except json.JSONDecodeError:
                            previous_hash = ""
        entry = {"schema_version": "zscope.review-memory-event.v1", "event": event, "at": utc_now(), "prev_hash": previous_hash, **payload}
        canonical = json.dumps(entry, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        entry["event_hash"] = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
        with path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(entry, ensure_ascii=False, sort_keys=True) + "\n")

    def verify_audit_integrity(self) -> Dict[str, Any]:
        path = self.audit_dir / "events.jsonl"
        previous_hash = ""
        count = 0
        if not path.exists():
            return {"valid": True, "events": 0, "last_hash": ""}
        with path.open("r", encoding="utf-8") as handle:
            for line_number, line in enumerate(handle, 1):
                if not line.strip():
                    continue
                entry = json.loads(line)
                event_hash = entry.pop("event_hash", None)
                if event_hash is None or entry.get("prev_hash", "") != previous_hash:
                    return {"valid": False, "events": count, "line": line_number, "last_hash": previous_hash}
                canonical = json.dumps(entry, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
                expected = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
                if event_hash != expected:
                    return {"valid": False, "events": count, "line": line_number, "last_hash": previous_hash}
                previous_hash = event_hash
                count += 1
        return {"valid": True, "events": count, "last_hash": previous_hash}

    def save_record(self, record: Dict[str, Any]) -> Dict[str, Any]:
        validate_review_record(record)
        record_path = self.records_dir / f"{record['review_id']}.json"
        existing = self.get_record(str(record["review_id"]))
        # SQLite is an index/cache of the JSON archive, not the archive's
        # authority.  If the JSON event was removed or lost, allow the next
        # Web feedback submission to recreate it instead of treating the
        # stale database row as an existing immutable event.
        record_file_missing = not record_path.is_file()
        if record_file_missing:
            existing = None
        if existing is not None:
            immutable = ("project_id", "finding", "user_rebuttal", "source_context", "evidence_refs", "repository_identity", "created_at")
            if any(existing.get(key) != record.get(key) for key in immutable):
                raise ValueError("review record identity is immutable; create a new review event")
        # Re-submitting the same rebuttal is idempotent; retain the original
        # event timestamp while allowing mutable extraction fields to update.
        now = str((existing or {}).get("created_at") or record.get("created_at") or utc_now())
        record = dict(record, created_at=now)
        self._atomic_json(record_path, record)
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("INSERT OR REPLACE INTO review_records VALUES (?, ?, ?, ?, ?)", (record["review_id"], record["project_id"], record["status"], json.dumps(record, ensure_ascii=False), now))
        self.append_audit("review_record_updated" if existing is not None else "review_record_created", {"review_id": record["review_id"], "project_id": record["project_id"], "recreated_missing_file": record_file_missing})
        return record

    def list_records(self, status: Optional[str] = None) -> List[Dict[str, Any]]:
        query = "SELECT record_json FROM review_records"
        args: tuple[str, ...] = ()
        if status:
            query += " WHERE status = ?"
            args = (status,)
        query += " ORDER BY created_at DESC"
        with sqlite3.connect(self.db_path) as conn:
            return [json.loads(row[0]) for row in conn.execute(query, args)]

    def save_proposal(self, proposal: Dict[str, Any]) -> Dict[str, Any]:
        validate_pattern(proposal)
        now = str(proposal.get("updated_at") or utc_now())
        proposal = dict(proposal, updated_at=now, created_at=proposal.get("created_at") or now)
        self._atomic_json(self.proposals_dir / f"{proposal['pattern_id']}.json", proposal)
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("INSERT OR REPLACE INTO pattern_proposals VALUES (?, ?, ?, ?, ?)", (proposal["pattern_id"], proposal["project_id"], proposal["status"], json.dumps(proposal, ensure_ascii=False), now))
        self.append_audit("proposal_saved", {"pattern_id": proposal["pattern_id"], "status": proposal["status"]})
        self._publish_active()
        return proposal

    def _publish_active(self) -> Dict[str, Any]:
        active = [item for item in self.list_proposals() if item.get("status") == "advisory"]
        digest = hashlib.sha256(
            json.dumps(active, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()
        pointer_path = self.state / "active.json"
        revision = 0
        if pointer_path.exists():
            try:
                revision = int(json.loads(pointer_path.read_text(encoding="utf-8")).get("revision", 0))
            except (OSError, TypeError, ValueError, json.JSONDecodeError):
                revision = 0
        pointer = {
            "schema_version": "zscope.review-memory-active.v1",
            "revision": revision + 1,
            "digest": digest,
            "pattern_ids": [str(item["pattern_id"]) for item in active],
            "updated_at": utc_now(),
        }
        self._atomic_json(pointer_path, pointer)
        return pointer

    def active_pointer(self) -> Dict[str, Any]:
        path = self.state / "active.json"
        if not path.exists():
            return self._publish_active()
        return json.loads(path.read_text(encoding="utf-8"))

    def list_proposals(self, project_id: Optional[str] = None, status: Optional[str] = None) -> List[Dict[str, Any]]:
        clauses, args = [], []
        if project_id:
            clauses.append("project_id = ?"); args.append(project_id)
        if status:
            clauses.append("status = ?"); args.append(status)
        query = "SELECT pattern_json FROM pattern_proposals" + ((" WHERE " + " AND ".join(clauses)) if clauses else "") + " ORDER BY updated_at DESC"
        with sqlite3.connect(self.db_path) as conn:
            return [json.loads(row[0]) for row in conn.execute(query, args)]

    def get_record(self, review_id: str) -> Optional[Dict[str, Any]]:
        rows = [item for item in self.list_records() if item.get("review_id") == review_id]
        return rows[0] if rows else None

    def update_record(self, record: Dict[str, Any]) -> Dict[str, Any]:
        return self.save_record(record)

    @staticmethod
    def _finding_matches(record_finding: Dict[str, Any], finding: Dict[str, Any]) -> bool:
        """Match a feedback update to the immutable finding snapshot."""
        for key in ("candidate_id", "issue_id", "id", "stable_fingerprint", "dedup_key"):
            left = record_finding.get(key)
            right = finding.get(key)
            if left and right and str(left) == str(right):
                return True
        return False

    def supersede_for_finding(self, finding: Dict[str, Any], *, reason: str = "validated") -> Dict[str, Any]:
        """Expire rejected-memory artifacts after a later validation reversal.

        Review records remain immutable audit history; they are marked
        superseded and their derived proposals are deprecated so they cannot
        be projected as current advisory context.
        """
        changed_records: List[str] = []
        changed_patterns: List[str] = []
        for record in self.list_records():
            snapshot = record.get("finding")
            if not isinstance(snapshot, dict) or not self._finding_matches(snapshot, finding):
                continue
            if record.get("status") != "superseded":
                updated = dict(record, status="superseded", superseded_at=utc_now(), superseded_reason=reason)
                self.save_record(updated)
                changed_records.append(str(record["review_id"]))
            subject = str(record.get("review_subject_id") or "")
            for proposal in self.list_proposals():
                origins = {str(item) for item in proposal.get("origin_review_ids", [])}
                if str(record.get("review_id")) in origins or (subject and proposal.get("review_subject_id") == subject):
                    if proposal.get("status") not in {"deprecated", "disabled"}:
                        self.save_proposal(dict(proposal, status="deprecated", deprecated_at=utc_now(), deprecated_reason=reason))
                        changed_patterns.append(str(proposal["pattern_id"]))
        if changed_records or changed_patterns:
            self.append_audit("review_memory_superseded", {
                "reason": reason,
                "review_ids": changed_records,
                "pattern_ids": changed_patterns,
            })
        return {"review_ids": changed_records, "pattern_ids": changed_patterns}

    def get_proposal(self, pattern_id: str) -> Optional[Dict[str, Any]]:
        rows = [item for item in self.list_proposals() if item.get("pattern_id") == pattern_id]
        return rows[0] if rows else None

    def proposal_digest(self, project_id: Optional[str] = None) -> str:
        payload = json.dumps(self.list_proposals(project_id=project_id), ensure_ascii=False, sort_keys=True)
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    def export_json(self) -> Dict[str, Any]:
        return {
            "schema_version": "zscope.review-memory-export.v1",
            "records": self.list_records(),
            "proposals": self.list_proposals(),
            "matches": self.list_matches(),
            "jobs": self.list_extraction_jobs(),
            "active": self.active_pointer(),
            "audit_integrity": self.verify_audit_integrity(),
        }

    def set_proposal_status(self, pattern_id: str, status: str) -> Dict[str, Any]:
        proposal = self.get_proposal(pattern_id)
        if proposal is None:
            raise KeyError(pattern_id)
        proposal = dict(proposal, status=status, updated_at=utc_now())
        return self.save_proposal(proposal)

    def save_match(self, match: Dict[str, Any]) -> Dict[str, Any]:
        validate_pattern_match(match)
        saved = dict(match, created_at=match.get("created_at") or utc_now())
        identity_json = json.dumps(saved["issue_identity"], ensure_ascii=False, sort_keys=True)
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                "INSERT OR REPLACE INTO pattern_matches VALUES (?, ?, ?, ?, ?)",
                (
                    saved["pattern_id"],
                    saved["scan_id"],
                    identity_json,
                    json.dumps(saved, ensure_ascii=False),
                    saved["created_at"],
                ),
            )
        replay_path = self.replays_dir / f"{saved['scan_id']}.jsonl"
        with replay_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(saved, ensure_ascii=False, sort_keys=True) + "\n")
        self.append_audit(
            "pattern_match_recorded",
            {"pattern_id": saved["pattern_id"], "scan_id": saved["scan_id"]},
        )
        return saved

    def list_matches(
        self, *, scan_id: Optional[str] = None, pattern_id: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        clauses, args = [], []
        if scan_id:
            clauses.append("scan_id = ?")
            args.append(scan_id)
        if pattern_id:
            clauses.append("pattern_id = ?")
            args.append(pattern_id)
        query = "SELECT match_json FROM pattern_matches"
        if clauses:
            query += " WHERE " + " AND ".join(clauses)
        query += " ORDER BY created_at"
        with sqlite3.connect(self.db_path) as conn:
            return [json.loads(row[0]) for row in conn.execute(query, args)]

    def create_extraction_job(self, review_ids: List[str]) -> Dict[str, Any]:
        job_id = hashlib.sha256(
            json.dumps({"reviews": review_ids, "at": utc_now()}, sort_keys=True).encode("utf-8")
        ).hexdigest()[:24]
        now = utc_now()
        job = {
            "schema_version": "zscope.review-memory-operation.v1",
            "operation": "extraction_job",
            "job_id": f"job_{job_id}",
            "status": "pending",
            "review_ids": list(review_ids),
            "attempts": 0,
            "error": "",
            "created_at": now,
            "updated_at": now,
        }
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                "INSERT INTO extraction_jobs VALUES (?, ?, ?, ?, ?, ?, ?)",
                (job["job_id"], job["status"], json.dumps(job["review_ids"]), 0, "", now, now),
            )
        self.append_audit("extraction_job_created", {"job_id": job["job_id"], "review_count": len(review_ids)})
        return job

    def update_extraction_job(self, job: Dict[str, Any], *, status: str, error: str = "") -> Dict[str, Any]:
        updated = dict(job, status=status, error=error, attempts=int(job.get("attempts", 0)) + (1 if status == "running" else 0), updated_at=utc_now())
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                "UPDATE extraction_jobs SET status=?, attempts=?, error=?, updated_at=? WHERE job_id=?",
                (updated["status"], updated["attempts"], updated["error"], updated["updated_at"], updated["job_id"]),
            )
        self.append_audit("extraction_job_updated", {"job_id": updated["job_id"], "status": status, "error": error})
        return updated

    def list_extraction_jobs(self) -> List[Dict[str, Any]]:
        with sqlite3.connect(self.db_path) as conn:
            rows = conn.execute(
                "SELECT job_id, status, review_ids_json, attempts, error, created_at, updated_at FROM extraction_jobs ORDER BY created_at DESC"
            )
        return [
            {
                "schema_version": "zscope.review-memory-operation.v1",
                "operation": "extraction_job",
                "job_id": row[0], "status": row[1], "review_ids": json.loads(row[2]),
                "attempts": row[3], "error": row[4], "created_at": row[5], "updated_at": row[6],
            }
            for row in rows
        ]

    def mark_source_drift(self, current_fingerprints: set[str]) -> List[str]:
        stale: List[str] = []
        for proposal in self.list_proposals():
            fingerprints = {str(item) for item in proposal.get("source_fingerprints", []) if item}
            if fingerprints and not fingerprints.intersection(current_fingerprints):
                if proposal.get("status") == "advisory":
                    self.set_proposal_status(str(proposal["pattern_id"]), "stale")
                    self.append_audit("proposal_staled", {"pattern_id": proposal["pattern_id"]})
                    stale.append(str(proposal["pattern_id"]))
        return stale
