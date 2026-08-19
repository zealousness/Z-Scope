"""Immutable content-addressed storage for proof artifacts."""

from __future__ import annotations

import json
import os
import re
import tempfile
from pathlib import Path
from typing import Any, Dict, Mapping, Sequence

from .canonical import canonical_json, content_sha256


_REF = re.compile(r"^sha256:([0-9a-f]{64})$")


class ProofArtifactStore:
    """Store proof objects by content hash with verified, atomic writes."""

    def __init__(self, root: Path | str) -> None:
        self.root = Path(root)
        self.objects = self.root / "proof_objects"

    def put(
        self,
        kind: str,
        payload: Mapping[str, Any],
        *,
        dependency_refs: Sequence[str] = (),
    ) -> str:
        refs = sorted({self._validated_ref(value) for value in dependency_refs})
        for digest in refs:
            if not self.verify_ref(f"sha256:{digest}"):
                raise ValueError("proof_object_dependency_invalid")
        body = {
            "schema_version": "zscope.proof-artifact-object.v1",
            "kind": str(kind),
            "payload": dict(payload),
            "dependency_refs": refs,
        }
        digest = content_sha256(body)
        envelope = {**body, "content_sha256": digest}
        data = (canonical_json(envelope) + "\n").encode("utf-8")
        self.objects.mkdir(parents=True, exist_ok=True)
        path = self.objects / f"{digest}.json"
        if path.exists():
            if path.read_bytes() != data:
                raise ValueError("proof_object_hash_collision")
        else:
            fd, temporary = tempfile.mkstemp(prefix=".proof-", suffix=".tmp", dir=self.objects)
            try:
                with os.fdopen(fd, "wb") as handle:
                    handle.write(data)
                    handle.flush()
                    os.fsync(handle.fileno())
                os.replace(temporary, path)
            finally:
                try:
                    Path(temporary).unlink()
                except FileNotFoundError:
                    pass
        return f"sha256:{digest}"

    def load(self, reference: str) -> Dict[str, Any]:
        return self._load(reference, seen=set())

    def _load(self, reference: str, *, seen: set[str]) -> Dict[str, Any]:
        digest = self._validated_ref(reference)
        if digest in seen:
            raise ValueError("proof_object_dependency_cycle")
        seen.add(digest)
        path = self.objects / f"{digest}.json"
        raw = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(raw, dict):
            raise ValueError("proof_object_not_mapping")
        supplied = str(raw.pop("content_sha256", ""))
        if supplied != digest or content_sha256(raw) != digest:
            raise ValueError("proof_object_content_hash_mismatch")
        refs = raw.get("dependency_refs")
        if not isinstance(refs, list):
            raise ValueError("proof_object_dependencies_not_array")
        for value in refs:
            self._load(f"sha256:{self._validated_ref(str(value))}", seen=set(seen))
        raw["content_sha256"] = supplied
        return raw

    def verify_ref(self, reference: str) -> bool:
        try:
            self.load(reference)
            return True
        except (OSError, ValueError, json.JSONDecodeError):
            return False

    def write_root_manifest(self, references: Sequence[str]) -> Dict[str, Any]:
        refs = sorted({f"sha256:{self._validated_ref(value)}" for value in references})
        for value in refs:
            if not self.verify_ref(value):
                raise ValueError("root_manifest_reference_invalid")
        body = {
            "schema_version": "zscope.proof-root-manifest.v1",
            "artifact_refs": refs,
        }
        manifest = {**body, "content_sha256": content_sha256(body)}
        self.root.mkdir(parents=True, exist_ok=True)
        target = self.root / "proof_manifest.json"
        data = (canonical_json(manifest) + "\n").encode("utf-8")
        fd, temporary = tempfile.mkstemp(prefix=".proof-manifest-", suffix=".tmp", dir=self.root)
        try:
            with os.fdopen(fd, "wb") as handle:
                handle.write(data)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, target)
        finally:
            try:
                Path(temporary).unlink()
            except FileNotFoundError:
                pass
        return manifest

    @staticmethod
    def _validated_ref(reference: str) -> str:
        match = _REF.fullmatch(str(reference))
        if match is None:
            raise ValueError("invalid_proof_artifact_reference")
        return match.group(1)
