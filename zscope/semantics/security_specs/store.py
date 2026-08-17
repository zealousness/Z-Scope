"""Immutable CAS and SQLite index for SecuritySpec artifacts."""

from __future__ import annotations

import json
import os
import re
import sqlite3
import tempfile
from pathlib import Path
from typing import Any, Iterable, Mapping, Optional, Sequence

from .canonical import canonical_json, content_sha256
from .models import (
    transition_allowed,
    validate_qualification,
    validate_review_event,
    validate_security_spec,
)


_REF_RE = re.compile(r"^sha256:([0-9a-f]{64})$")


class SecuritySpecObjectStore:
    """Write immutable SecuritySpec objects with verified dependency refs."""

    def __init__(self, root: Path) -> None:
        self.root = Path(root)
        self.objects = self.root / "spec_objects"

    def put(
        self,
        kind: str,
        payload: Mapping[str, Any],
        *,
        dependency_refs: Sequence[str] = (),
    ) -> str:
        dependencies = sorted({self._digest(value) for value in dependency_refs})
        for digest in dependencies:
            if not self.verify_ref("sha256:" + digest):
                raise ValueError("security_spec_dependency_ref_invalid")
        body = {
            "schema_version": "zscope.security-spec-object.v1",
            "kind": str(kind),
            "payload": dict(payload),
            "dependency_refs": dependencies,
        }
        digest = content_sha256(body)
        envelope = {**body, "content_sha256": digest}
        encoded = (canonical_json(envelope) + "\n").encode("utf-8")
        self.objects.mkdir(parents=True, exist_ok=True)
        path = self.objects / f"{digest}.json"
        if path.exists():
            if path.read_bytes() != encoded:
                raise ValueError("security_spec_object_hash_collision")
        else:
            descriptor, temporary = tempfile.mkstemp(
                prefix=".security-spec-", suffix=".tmp", dir=self.objects
            )
            try:
                with os.fdopen(descriptor, "wb") as handle:
                    handle.write(encoded)
                    handle.flush()
                    os.fsync(handle.fileno())
                os.replace(temporary, path)
            finally:
                Path(temporary).unlink(missing_ok=True)
        return "sha256:" + digest

    def load(self, reference: str) -> dict[str, Any]:
        return self._load(reference, seen=set())

    def _load(self, reference: str, *, seen: set[str]) -> dict[str, Any]:
        digest = self._digest(reference)
        if digest in seen:
            raise ValueError("security_spec_dependency_cycle")
        path = self.objects / f"{digest}.json"
        raw = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(raw, dict):
            raise ValueError("security_spec_object_not_mapping")
        supplied = str(raw.pop("content_sha256", ""))
        if supplied != digest or content_sha256(raw) != digest:
            raise ValueError("security_spec_object_content_hash_mismatch")
        dependencies = raw.get("dependency_refs")
        if not isinstance(dependencies, list):
            raise ValueError("security_spec_object_dependencies_not_array")
        for value in dependencies:
            dependency = str(value)
            if re.fullmatch(r"[0-9a-f]{64}", dependency) is None:
                dependency = self._digest(dependency)
            self._load("sha256:" + dependency, seen=seen | {digest})
        return {**raw, "content_sha256": supplied}

    def verify_ref(self, reference: str) -> bool:
        try:
            self.load(reference)
            return True
        except (OSError, ValueError, json.JSONDecodeError):
            return False

    def write_root_manifest(self, references: Sequence[str]) -> dict[str, Any]:
        refs = sorted({"sha256:" + self._digest(value) for value in references})
        if any(not self.verify_ref(value) for value in refs):
            raise ValueError("security_spec_manifest_reference_invalid")
        body = {
            "schema_version": "zscope.security-spec-root-manifest.v1",
            "mode": "shadow",
            "artifact_refs": refs,
        }
        manifest = {**body, "content_sha256": content_sha256(body)}
        self.root.mkdir(parents=True, exist_ok=True)
        encoded = (canonical_json(manifest) + "\n").encode("utf-8")
        descriptor, temporary = tempfile.mkstemp(
            prefix=".security-spec-manifest-", suffix=".tmp", dir=self.root
        )
        try:
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(encoded)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, self.root / "security_spec_manifest.json")
        finally:
            Path(temporary).unlink(missing_ok=True)
        return manifest

    @staticmethod
    def _digest(reference: str) -> str:
        match = _REF_RE.fullmatch(str(reference))
        if match is None:
            raise ValueError("invalid_security_spec_reference")
        return match.group(1)


class SecuritySpecStore:
    """Transactional metadata index over immutable SecuritySpec CAS objects."""

    def __init__(self, root: Path) -> None:
        self.root = Path(root)
        self.cas = SecuritySpecObjectStore(self.root)
        self.db_path = self.root / "security_specs.db"
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(str(self.db_path))
        connection.row_factory = sqlite3.Row
        return connection

    def _initialize(self) -> None:
        self.root.mkdir(parents=True, exist_ok=True)
        connection = self._connect()
        try:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS spec_revisions (
                    spec_uid TEXT NOT NULL,
                    revision INTEGER NOT NULL,
                    status TEXT NOT NULL,
                    predicate_id TEXT NOT NULL,
                    scope_kind TEXT NOT NULL,
                    scope_target TEXT NOT NULL,
                    content_sha256 TEXT NOT NULL,
                    object_ref TEXT NOT NULL,
                    PRIMARY KEY(spec_uid, revision),
                    UNIQUE(content_sha256)
                );
                CREATE TABLE IF NOT EXISTS artifact_index (
                    artifact_kind TEXT NOT NULL,
                    artifact_uid TEXT NOT NULL,
                    content_sha256 TEXT NOT NULL,
                    object_ref TEXT NOT NULL,
                    PRIMARY KEY(artifact_kind, artifact_uid),
                    UNIQUE(content_sha256)
                );
                CREATE TABLE IF NOT EXISTS spec_dependencies (
                    spec_uid TEXT NOT NULL,
                    revision INTEGER NOT NULL,
                    dependency_sha256 TEXT NOT NULL,
                    PRIMARY KEY(spec_uid, revision, dependency_sha256)
                );
                CREATE INDEX IF NOT EXISTS idx_spec_dependencies_hash
                    ON spec_dependencies(dependency_sha256);
                CREATE TABLE IF NOT EXISTS spec_footprints (
                    spec_uid TEXT NOT NULL,
                    revision INTEGER NOT NULL,
                    footprint_kind TEXT NOT NULL,
                    footprint_uid TEXT NOT NULL,
                    PRIMARY KEY(spec_uid, revision, footprint_kind, footprint_uid)
                );
                CREATE INDEX IF NOT EXISTS idx_spec_footprints_uid
                    ON spec_footprints(footprint_kind, footprint_uid);
                CREATE TABLE IF NOT EXISTS spec_call_dependents (
                    spec_uid TEXT NOT NULL,
                    revision INTEGER NOT NULL,
                    function_uid TEXT NOT NULL,
                    dependent_function_uid TEXT NOT NULL,
                    PRIMARY KEY(
                        spec_uid, revision, function_uid, dependent_function_uid
                    )
                );
                CREATE INDEX IF NOT EXISTS idx_spec_call_dependents_function
                    ON spec_call_dependents(function_uid);
                CREATE TABLE IF NOT EXISTS review_chain (
                    spec_uid TEXT NOT NULL,
                    event_uid TEXT NOT NULL PRIMARY KEY,
                    previous_event_sha256 TEXT NOT NULL,
                    content_sha256 TEXT NOT NULL UNIQUE,
                    object_ref TEXT NOT NULL
                );
                """
            )
            connection.commit()
        finally:
            connection.close()

    def put_spec(
        self,
        spec: Mapping[str, Any],
        *,
        call_dependents: Sequence[tuple[str, str]] = (),
    ) -> str:
        valid, reason = validate_security_spec(spec)
        if not valid:
            raise ValueError(reason)
        dependency_hashes = [
            str(value)
            for value in (
                spec.get("qualification_ref"),
                spec.get("review_ref"),
                *(spec.get("supersedes") or []),
            )
            if str(value or "")
        ]
        dependency_refs = self._references_for_content_hashes(dependency_hashes)
        reference = self.cas.put("security_spec", spec, dependency_refs=dependency_refs)
        connection = self._connect()
        try:
            current = connection.execute(
                "SELECT content_sha256 FROM spec_revisions WHERE spec_uid = ? AND revision = ?",
                (str(spec["spec_uid"]), int(spec["revision"])),
            ).fetchone()
            if current is not None and str(current[0]) != str(spec["content_sha256"]):
                raise ValueError("security_spec_revision_is_immutable")
            latest = connection.execute(
                "SELECT revision, status FROM spec_revisions WHERE spec_uid = ? "
                "ORDER BY revision DESC LIMIT 1",
                (str(spec["spec_uid"]),),
            ).fetchone()
            if current is None and latest is not None:
                if int(spec["revision"]) != int(latest[0]) + 1:
                    raise ValueError("security_spec_revision_must_be_contiguous")
                if not transition_allowed(str(latest[1]), str(spec["status"])):
                    raise ValueError("security_spec_state_transition_not_allowed")
            connection.execute(
                """
                INSERT OR IGNORE INTO spec_revisions(
                    spec_uid, revision, status, predicate_id, scope_kind, scope_target,
                    content_sha256, object_ref
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    str(spec["spec_uid"]),
                    int(spec["revision"]),
                    str(spec["status"]),
                    str(spec["predicate"]),
                    str(spec["scope"]["kind"]),
                    str(spec["scope"]["target"]),
                    str(spec["content_sha256"]),
                    reference,
                ),
            )
            for dependency in spec["dependency_hashes"]:
                connection.execute(
                    "INSERT OR IGNORE INTO spec_dependencies VALUES (?, ?, ?)",
                    (str(spec["spec_uid"]), int(spec["revision"]), str(dependency)),
                )
            connection.execute(
                "INSERT OR IGNORE INTO spec_footprints VALUES (?, ?, ?, ?)",
                (
                    str(spec["spec_uid"]),
                    int(spec["revision"]),
                    str(spec["scope"]["kind"]),
                    str(spec["scope"]["target"]),
                ),
            )
            for function_uid in spec.get("impact_preview") or []:
                connection.execute(
                    "INSERT OR IGNORE INTO spec_footprints VALUES (?, ?, 'function', ?)",
                    (str(spec["spec_uid"]), int(spec["revision"]), str(function_uid)),
                )
            for function_uid, dependent_uid in sorted(set(call_dependents)):
                if not str(function_uid) or not str(dependent_uid):
                    raise ValueError("security_spec_call_dependency_identity_empty")
                connection.execute(
                    "INSERT OR IGNORE INTO spec_call_dependents VALUES (?, ?, ?, ?)",
                    (
                        str(spec["spec_uid"]),
                        int(spec["revision"]),
                        str(function_uid),
                        str(dependent_uid),
                    ),
                )
            connection.commit()
        finally:
            connection.close()
        return reference

    def put_qualification(self, qualification: Mapping[str, Any]) -> str:
        valid, reason = validate_qualification(qualification)
        if not valid:
            raise ValueError(reason)
        return self._put_artifact(
            "qualification", str(qualification["qualification_uid"]), qualification
        )

    def put_review_event(self, event: Mapping[str, Any]) -> str:
        valid, reason = validate_review_event(event)
        if not valid:
            raise ValueError(reason)
        spec = self.get_spec(str(event["spec_uid"]), int(event["spec_revision"]))
        if spec is None or spec["content_sha256"] != event["before_spec_sha256"]:
            raise ValueError("review_event_spec_binding_mismatch")
        connection = self._connect()
        try:
            previous = connection.execute(
                "SELECT content_sha256 FROM review_chain WHERE spec_uid = ? ORDER BY rowid DESC LIMIT 1",
                (str(event["spec_uid"]),),
            ).fetchone()
            expected_previous = str(previous[0]) if previous else "0" * 64
            if str(event["previous_event_sha256"]) != expected_previous:
                raise ValueError("review_event_chain_mismatch")
            dependency_hashes = [str(event["before_spec_sha256"])]
            if str(event["previous_event_sha256"]) != "0" * 64:
                dependency_hashes.append(str(event["previous_event_sha256"]))
            reference = self.cas.put(
                "review_event",
                event,
                dependency_refs=self._references_for_content_hashes(dependency_hashes),
            )
            connection.execute(
                "INSERT INTO review_chain VALUES (?, ?, ?, ?, ?)",
                (
                    str(event["spec_uid"]),
                    str(event["event_uid"]),
                    str(event["previous_event_sha256"]),
                    str(event["content_sha256"]),
                    reference,
                ),
            )
            connection.commit()
            return reference
        finally:
            connection.close()

    def put_compilation(self, uid: str, artifact: Mapping[str, Any]) -> str:
        dependency_hashes = [
            *map(str, artifact.get("input_spec_sha256s") or []),
            *(
                str(value.get("qualification_ref") or "")
                for value in artifact.get("compiled_specs") or []
                if isinstance(value, Mapping)
            ),
        ]
        return self._put_artifact(
            "compilation",
            uid,
            artifact,
            dependency_refs=self._references_for_content_hashes(dependency_hashes),
        )

    def _put_artifact(
        self,
        kind: str,
        uid: str,
        artifact: Mapping[str, Any],
        *,
        dependency_refs: Sequence[str] = (),
    ) -> str:
        reference = self.cas.put(kind, artifact, dependency_refs=dependency_refs)
        digest = str(artifact.get("content_sha256") or content_sha256(artifact))
        connection = self._connect()
        try:
            existing = connection.execute(
                "SELECT content_sha256 FROM artifact_index WHERE artifact_kind = ? AND artifact_uid = ?",
                (kind, uid),
            ).fetchone()
            if existing is not None and str(existing[0]) != digest:
                raise ValueError("security_spec_artifact_uid_is_immutable")
            connection.execute(
                "INSERT OR IGNORE INTO artifact_index VALUES (?, ?, ?, ?)",
                (kind, uid, digest, reference),
            )
            connection.commit()
        finally:
            connection.close()
        return reference

    def _references_for_content_hashes(self, hashes: Iterable[str]) -> list[str]:
        values = sorted({str(value) for value in hashes if str(value)})
        if not values:
            return []
        connection = self._connect()
        try:
            references = []
            for digest in values:
                row = connection.execute(
                    "SELECT object_ref FROM spec_revisions WHERE content_sha256 = ? "
                    "UNION SELECT object_ref FROM artifact_index WHERE content_sha256 = ? "
                    "UNION SELECT object_ref FROM review_chain WHERE content_sha256 = ?",
                    (digest, digest, digest),
                ).fetchone()
                if row is None:
                    raise ValueError("security_spec_content_dependency_unresolved")
                references.append(str(row[0]))
            return sorted(set(references))
        finally:
            connection.close()

    def get_spec(self, spec_uid: str, revision: Optional[int] = None) -> Optional[dict[str, Any]]:
        connection = self._connect()
        try:
            if revision is None:
                row = connection.execute(
                    "SELECT object_ref FROM spec_revisions WHERE spec_uid = ? ORDER BY revision DESC LIMIT 1",
                    (spec_uid,),
                ).fetchone()
            else:
                row = connection.execute(
                    "SELECT object_ref FROM spec_revisions WHERE spec_uid = ? AND revision = ?",
                    (spec_uid, int(revision)),
                ).fetchone()
        finally:
            connection.close()
        if row is None:
            return None
        return dict(self.cas.load(str(row[0]))["payload"])

    def list_specs(self, *, latest_only: bool = True, status: str = "") -> list[dict[str, Any]]:
        connection = self._connect()
        try:
            if latest_only:
                query = """
                    SELECT r.object_ref FROM spec_revisions r
                    JOIN (
                        SELECT spec_uid, MAX(revision) revision FROM spec_revisions GROUP BY spec_uid
                    ) latest ON latest.spec_uid = r.spec_uid AND latest.revision = r.revision
                """
            else:
                query = "SELECT object_ref FROM spec_revisions"
            params: tuple[Any, ...] = ()
            if status:
                query += " WHERE r.status = ?" if latest_only else " WHERE status = ?"
                params = (status,)
            query += " ORDER BY spec_uid" if not latest_only else " ORDER BY r.spec_uid"
            rows = connection.execute(query, params).fetchall()
        finally:
            connection.close()
        return [dict(self.cas.load(str(row[0]))["payload"]) for row in rows]

    def has_qualification_hash(self, digest: str) -> bool:
        connection = self._connect()
        try:
            row = connection.execute(
                "SELECT 1 FROM artifact_index WHERE artifact_kind = 'qualification' AND content_sha256 = ?",
                (digest,),
            ).fetchone()
            return row is not None
        finally:
            connection.close()

    def list_artifacts(self, kind: str) -> list[dict[str, Any]]:
        connection = self._connect()
        try:
            rows = connection.execute(
                "SELECT object_ref FROM artifact_index WHERE artifact_kind = ? ORDER BY artifact_uid",
                (str(kind),),
            ).fetchall()
        finally:
            connection.close()
        return [dict(self.cas.load(str(row[0]))["payload"]) for row in rows]

    def list_review_events(self) -> list[dict[str, Any]]:
        connection = self._connect()
        try:
            rows = connection.execute(
                "SELECT object_ref FROM review_chain ORDER BY spec_uid, rowid"
            ).fetchall()
        finally:
            connection.close()
        return [dict(self.cas.load(str(row[0]))["payload"]) for row in rows]

    def affected_spec_uids(self, changed_hashes: Iterable[str]) -> set[str]:
        values = sorted(set(map(str, changed_hashes)))
        if not values:
            return set()
        placeholders = ",".join("?" for _ in values)
        connection = self._connect()
        try:
            rows = connection.execute(
                f"SELECT DISTINCT spec_uid FROM spec_dependencies WHERE dependency_sha256 IN ({placeholders})",
                values,
            ).fetchall()
            return {str(row[0]) for row in rows}
        finally:
            connection.close()

    def affected_spec_uids_for_footprints(self, footprints: Iterable[tuple[str, str]]) -> set[str]:
        values = sorted({(str(kind), str(uid)) for kind, uid in footprints if kind and uid})
        if not values:
            return set()
        clauses = " OR ".join("(footprint_kind = ? AND footprint_uid = ?)" for _ in values)
        parameters = [part for value in values for part in value]
        connection = self._connect()
        try:
            rows = connection.execute(
                f"SELECT DISTINCT spec_uid FROM spec_footprints WHERE {clauses}",
                parameters,
            ).fetchall()
            return {str(row[0]) for row in rows}
        finally:
            connection.close()

    def invalidation_impact(self, changed_hashes: Iterable[str]) -> dict[str, list[str]]:
        spec_uids = self.affected_spec_uids(changed_hashes)
        if not spec_uids:
            return {"spec_uids": [], "function_uids": [], "dependent_function_uids": []}
        placeholders = ",".join("?" for _ in spec_uids)
        parameters = sorted(spec_uids)
        connection = self._connect()
        try:
            functions = connection.execute(
                f"SELECT DISTINCT footprint_uid FROM spec_footprints "
                f"WHERE spec_uid IN ({placeholders}) AND footprint_kind = 'function'",
                parameters,
            ).fetchall()
            dependents = connection.execute(
                f"SELECT DISTINCT dependent_function_uid FROM spec_call_dependents "
                f"WHERE spec_uid IN ({placeholders})",
                parameters,
            ).fetchall()
        finally:
            connection.close()
        return {
            "spec_uids": parameters,
            "function_uids": sorted(str(row[0]) for row in functions),
            "dependent_function_uids": sorted(str(row[0]) for row in dependents),
        }

    def artifact_refs(self) -> list[str]:
        connection = self._connect()
        try:
            rows = connection.execute(
                "SELECT object_ref FROM spec_revisions UNION SELECT object_ref FROM artifact_index "
                "UNION SELECT object_ref FROM review_chain"
            ).fetchall()
            return sorted({str(row[0]) for row in rows})
        finally:
            connection.close()
