"""Immutable, answer-free review checkpoints and one-generation proposals."""

from __future__ import annotations

import json
import threading
import uuid
from copy import deepcopy
from pathlib import Path
from typing import Any, Dict

from ...retrieval.validation_facts import digest

CHECKPOINT_VERSION = "zscope.review-checkpoint.v2"
LEGACY_CHECKPOINT_VERSION = "zscope.review-checkpoint.v1"
_FORBIDDEN = {
    "audit_labels",
    "audit_label",
    "score",
    "scorecard",
    "scoring",
    "matched_truth",
    "matched_truth_id",
    "is_tp",
    "is_fp",
    "cls",
    "offline_label",
}


def assert_answer_free(value: Any) -> None:
    from ...reporting.shared_objects import SharedDict, SharedList
    if isinstance(value, (SharedDict, SharedList)) and not value._dirty:
        decoder = value._decoder
        checked = getattr(decoder, "_answer_free_nodes", None)
        if checked is None:
            checked = set()
            decoder._answer_free_nodes = checked
        def inspect(node: Any) -> None:
            kind, body = node
            if kind == "ref":
                if body not in checked:
                    inspect(decoder.objects[body])
                    checked.add(body)
            elif kind == "map":
                for key, child in body:
                    normalized = str(key).lower()
                    if normalized in _FORBIDDEN or "truth" in normalized.split("_"):
                        raise ValueError(f"offline evaluation field in checkpoint: {key}")
                    inspect(child)
            elif kind == "list":
                for child in body:
                    inspect(child)
        inspect(["map" if isinstance(value, SharedDict) else "list", value._body])
        return
    if isinstance(value, dict):
        for key, child in value.items():
            normalized = str(key).lower()
            if normalized in _FORBIDDEN or "truth" in normalized.split("_"):
                raise ValueError(f"offline evaluation field in checkpoint: {key}")
            assert_answer_free(child)
    elif isinstance(value, list):
        for child in value:
            assert_answer_free(child)


class ReviewCheckpointStore:
    def __init__(self, directory: Path):
        self.directory = directory
        self._lock = threading.RLock()

    def save(
        self, issue: Dict[str, Any], *, stage: str, facts: Dict[str, Any], runtime: Dict[str, Any]
    ) -> str:
        candidate = deepcopy(issue)
        # In-process proof authority is never restored from disk.
        candidate.pop("review_checked_proof", None)
        candidate.pop("review_checkpoint_id", None)
        payload = {
            "schema_version": CHECKPOINT_VERSION,
            "stage": stage,
            "candidate": candidate,
            "facts": facts,
            "runtime": runtime,
        }
        assert_answer_free(payload)
        from ...reporting.evidence_objects import EvidenceObjectStore

        reference = EvidenceObjectStore(self.directory / "evidence").put(payload)
        uid = "RC_" + str(reference["root"][1])
        with self._lock:
            self.directory.mkdir(parents=True, exist_ok=True)
            target = self.directory / f"{uid}.json"
            from ...reporting.json_io import write_json_atomic
            write_json_atomic(target, reference, compact=True)
        issue["review_checkpoint_id"] = uid
        return uid

    def load(self, uid: str) -> Dict[str, Any]:
        import re

        if not re.fullmatch(r"RC_[0-9a-f]{64}", uid):
            raise ValueError("invalid review checkpoint identity")
        data = json.loads((self.directory / f"{uid}.json").read_text(encoding="utf-8"))
        from ...reporting.evidence_objects import EvidenceObjectStore
        from ...reporting.shared_objects import STORAGE_SCHEMA

        if data.get("storage_schema") == STORAGE_SCHEMA:
            if set(data) != {"storage_schema", "root"}:
                raise ValueError("review checkpoint integrity failure: unexpected envelope fields")
            if "RC_" + str(data.get("root", ["", ""])[1]) != uid:
                raise ValueError("review checkpoint integrity failure")
            data = EvidenceObjectStore(self.directory / "evidence").get(data)
            if data.get("schema_version") != CHECKPOINT_VERSION:
                raise ValueError("unsupported review checkpoint version")
        elif data.get("schema_version") != LEGACY_CHECKPOINT_VERSION or "RC_" + digest(data) != uid:
            raise ValueError("review checkpoint integrity failure")
        assert_answer_free(data)
        data["candidate"].pop("review_checked_proof", None)
        return dict(data)


class RelatedCandidateRegistry:
    """Append-only proposals; main CandidateLedger is never mutated here."""

    def __init__(self, parents: list[Dict[str, Any]]):
        self.parents = parents

    def freeze(self) -> list[Dict[str, Any]]:
        children: Dict[str, Dict[str, Any]] = {}
        # Deduplication includes subject and build scope, not just line/category.
        for parent in self.parents:
            if int(parent.get("related_generation") or 0) != 0:
                continue
            for raw in parent.get("review_related_proposals") or []:
                child = deepcopy(raw)
                key = digest(
                    {
                        k: child.get(k)
                        for k in (
                            "file",
                            "line",
                            "function",
                            "category",
                            "source",
                            "sink",
                            "analysis_scope",
                            "trigger_condition",
                        )
                    }
                )
                if key in children:
                    children[key]["parent_candidate_uids"] = sorted(
                        set(
                            children[key]["parent_candidate_uids"]
                            + [str(parent.get("candidate_uid") or parent.get("id"))]
                        )
                    )
                    continue
                child.update(
                    id="RELATED_" + key[:24],
                    related_generation=1,
                    parent_candidate_uid=str(parent.get("candidate_uid") or parent.get("id")),
                    parent_candidate_uids=[str(parent.get("candidate_uid") or parent.get("id"))],
                    candidate_source="validator_related_discovery",
                    candidate_kind="llm_observation",
                    validation_status="needs_review",
                    candidate_disposition="needs_review",
                    finding_kind="needs_review",
                    confirmed=False,
                )
                child.pop("candidate_uid", None)
                child.pop("validation_cluster_uid", None)
                if child.get("analysis_scope") == "conditional_source_branch":
                    child["validator_contract"] = {
                        "build_scope": "conditional_source_branch",
                        "condition": child.get("trigger_condition"),
                    }
                child["path_constraints"] = {
                    "scope": child.get("analysis_scope"),
                    "trigger": child.get("trigger_condition"),
                }
                children[key] = child
        return list(children.values())
