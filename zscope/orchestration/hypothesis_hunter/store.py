"""Immutable P5 hypothesis artifacts and exact-fingerprint report cache."""

from __future__ import annotations

import json
import os
import re
import tempfile
from pathlib import Path
from typing import Any, Mapping, Sequence

from ...core.validation.proof_kernel.canonical import canonical_json, content_sha256
from .lifecycle import ACTIVE_PRODUCT_EFFECT, HYPOTHESIS_HUNTER_MODE


_REF = re.compile(r"^sha256:([0-9a-f]{64})$")


class HypothesisArtifactStore:
    """Separate CAS for offers, selections, proof replay, and registration refs."""

    def __init__(self, root: Path | str) -> None:
        self.root = Path(root)
        self.objects = self.root / "hypothesis_objects"
        self.cache = self.root / "report_cache"

    @staticmethod
    def _digest(reference: str) -> str:
        match = _REF.fullmatch(str(reference))
        if match is None:
            raise ValueError("invalid_hypothesis_artifact_reference")
        return match.group(1)

    @staticmethod
    def _atomic_write(path: Path, payload: bytes, *, prefix: str) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        descriptor, temporary = tempfile.mkstemp(prefix=prefix, suffix=".tmp", dir=path.parent)
        try:
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, path)
        finally:
            Path(temporary).unlink(missing_ok=True)

    def put(
        self,
        kind: str,
        payload: Mapping[str, Any],
        *,
        dependency_refs: Sequence[str] = (),
    ) -> str:
        dependencies = sorted({self._digest(value) for value in dependency_refs})
        if any(not self.verify_ref("sha256:" + value) for value in dependencies):
            raise ValueError("hypothesis_artifact_dependency_invalid")
        body = {
            "schema_version": "zscope.hypothesis-artifact-object.v1",
            "kind": str(kind),
            "payload": dict(payload),
            "dependency_refs": dependencies,
        }
        digest = content_sha256(body)
        envelope = {**body, "content_sha256": digest}
        data = (canonical_json(envelope) + "\n").encode("utf-8")
        path = self.objects / f"{digest}.json"
        if path.exists():
            if path.read_bytes() != data:
                raise ValueError("hypothesis_artifact_hash_collision")
        else:
            self._atomic_write(path, data, prefix=".hypothesis-")
        return "sha256:" + digest

    def load(self, reference: str) -> dict[str, Any]:
        return self._load(reference, seen=set())

    def _load(self, reference: str, *, seen: set[str]) -> dict[str, Any]:
        digest = self._digest(reference)
        if digest in seen:
            raise ValueError("hypothesis_artifact_dependency_cycle")
        path = self.objects / f"{digest}.json"
        raw = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(raw, dict):
            raise ValueError("hypothesis_artifact_not_mapping")
        supplied = str(raw.pop("content_sha256", ""))
        if supplied != digest or content_sha256(raw) != digest:
            raise ValueError("hypothesis_artifact_content_hash_mismatch")
        dependencies = raw.get("dependency_refs")
        if not isinstance(dependencies, list):
            raise ValueError("hypothesis_artifact_dependencies_not_array")
        for value in dependencies:
            dependency = str(value)
            if _REF.fullmatch(dependency) is None:
                dependency = "sha256:" + dependency
            self._load(dependency, seen=seen | {digest})
        return {**raw, "content_sha256": supplied}

    def verify_ref(self, reference: str) -> bool:
        try:
            self.load(reference)
            return True
        except (OSError, ValueError, json.JSONDecodeError):
            return False

    def write_root_manifest(
        self,
        references: Sequence[str],
        *,
        registered_candidate_uids: Sequence[str],
        coverage_summary: Mapping[str, Any],
    ) -> dict[str, Any]:
        refs = sorted({"sha256:" + self._digest(value) for value in references})
        if any(not self.verify_ref(value) for value in refs):
            raise ValueError("hypothesis_root_manifest_reference_invalid")
        candidate_uids = sorted({str(value) for value in registered_candidate_uids if str(value)})
        body = {
            "schema_version": "zscope.hypothesis-hunter-root-manifest.v2",
            "mode": HYPOTHESIS_HUNTER_MODE,
            "active_product_effect": ACTIVE_PRODUCT_EFFECT,
            "artifact_refs": refs,
            "registered_candidate_uids": candidate_uids,
            "candidate_registration_sha256": content_sha256(candidate_uids),
            "coverage_summary": dict(coverage_summary),
        }
        manifest = {**body, "content_sha256": content_sha256(body)}
        self._atomic_write(
            self.root / "hypothesis_hunter_manifest.json",
            (canonical_json(manifest) + "\n").encode("utf-8"),
            prefix=".hypothesis-manifest-",
        )
        return manifest

    def save_cached_report(self, cache_key: str, report: Mapping[str, Any]) -> None:
        if re.fullmatch(r"[0-9a-f]{64}", cache_key) is None:
            raise ValueError("hypothesis_report_cache_key_invalid")
        body = {
            "schema_version": "zscope.hypothesis-hunter-report-cache.v1",
            "cache_key": cache_key,
            "report": dict(report),
        }
        envelope = {**body, "content_sha256": content_sha256(body)}
        self._atomic_write(
            self.cache / f"{cache_key}.json",
            (canonical_json(envelope) + "\n").encode("utf-8"),
            prefix=".hypothesis-cache-",
        )

    def load_cached_report(self, cache_key: str) -> dict[str, Any] | None:
        if re.fullmatch(r"[0-9a-f]{64}", cache_key) is None:
            return None
        try:
            raw = json.loads((self.cache / f"{cache_key}.json").read_text(encoding="utf-8"))
            if not isinstance(raw, dict) or set(raw) != {
                "schema_version",
                "cache_key",
                "report",
                "content_sha256",
            }:
                return None
            body = {key: value for key, value in raw.items() if key != "content_sha256"}
            if (
                raw.get("schema_version") != "zscope.hypothesis-hunter-report-cache.v1"
                or raw.get("cache_key") != cache_key
                or content_sha256(body) != raw.get("content_sha256")
                or not isinstance(raw.get("report"), dict)
            ):
                return None
            return dict(raw["report"])
        except (OSError, ValueError, json.JSONDecodeError):
            return None


def load_hypothesis_manifest_identity(root: Path | str, *, consumer: str) -> dict[str, Any]:
    """Load a frozen P5 manifest without granting terminal authority."""

    root = Path(root)
    fallback = {
        "hypothesis_hunter_mode": HYPOTHESIS_HUNTER_MODE,
        "hypothesis_hunter_root_manifest_sha256": "",
        "hypothesis_hunter_artifact_refs": [],
        "hypothesis_hunter_decision": {
            "active_product_effect": ACTIVE_PRODUCT_EFFECT,
            "reason_code": f"{consumer}_hypothesis_manifest_unavailable",
        },
    }
    try:
        raw = json.loads((root / "hypothesis_hunter_manifest.json").read_text(encoding="utf-8"))
        expected = {
            "schema_version",
            "mode",
            "active_product_effect",
            "artifact_refs",
            "registered_candidate_uids",
            "candidate_registration_sha256",
            "coverage_summary",
            "content_sha256",
        }
        if not isinstance(raw, dict) or set(raw) != expected:
            raise ValueError("hypothesis_manifest_schema_mismatch")
        body = {key: value for key, value in raw.items() if key != "content_sha256"}
        refs = raw.get("artifact_refs")
        store = HypothesisArtifactStore(root)
        if (
            raw.get("schema_version") != "zscope.hypothesis-hunter-root-manifest.v2"
            or raw.get("mode") != HYPOTHESIS_HUNTER_MODE
            or raw.get("active_product_effect") != ACTIVE_PRODUCT_EFFECT
            or content_sha256(body) != raw.get("content_sha256")
            or not isinstance(raw.get("registered_candidate_uids"), list)
            or raw.get("candidate_registration_sha256")
            != content_sha256(raw.get("registered_candidate_uids") or [])
            or not isinstance(refs, list)
            or any(not store.verify_ref(str(value)) for value in refs)
        ):
            raise ValueError("hypothesis_manifest_invalid")
        return {
            "hypothesis_hunter_mode": HYPOTHESIS_HUNTER_MODE,
            "hypothesis_hunter_root_manifest_sha256": str(raw["content_sha256"]),
            "hypothesis_hunter_artifact_refs": list(refs),
            "hypothesis_hunter_decision": {
                "active_product_effect": ACTIVE_PRODUCT_EFFECT,
                "reason_code": f"{consumer}_hypothesis_manifest_loaded",
                "coverage_summary": dict(raw.get("coverage_summary") or {}),
            },
        }
    except (OSError, ValueError, json.JSONDecodeError):
        return fallback
