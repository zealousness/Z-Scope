"""Versioned candidate identity and lifecycle helpers.

The LLM-facing ``id`` field is intentionally treated as display-only.  Every
candidate and occurrence receives a content-derived internal identity before it
can enter validation, de-duplication, persistence, or reporting.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, Iterable, List, Mapping, MutableMapping, Optional

from ..core.candidates.evidence_models import build_evidence_models

CANDIDATE_SCHEMA_VERSION = "zscope.candidate.v3"
CANDIDATE_DISPOSITIONS = {
    "confirmed",
    "rejected_with_proof",
    "needs_review",
    "deferred_budget",
    "engine_failed",
    "interrupted",
    "deduplicated_alias",
}

_DETERMINISTIC_REJECTION_SOURCES = {
    "clang_ast_cfg",
    "deterministic_prevalidation",
    "programmatic",
    "rule_proof",
    "user_suppression",
}


def _stable_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, default=str, separators=(",", ":"))


def _digest(value: Any, length: int = 24) -> str:
    return hashlib.sha256(_stable_json(value).encode("utf-8")).hexdigest()[:length]


def occurrence_uid_for(
    candidate_uid: str,
    *,
    entry: str = "",
    entry_paths: Iterable[Iterable[Any]] = (),
) -> str:
    normalized_paths = [
        [str(item) for item in path if str(item)]
        for path in entry_paths
    ]
    payload = {
        "candidate": candidate_uid,
        "entry": str(entry or ""),
        "paths": normalized_paths,
    }
    return f"OCC_{_digest(payload)}"


def context_signature_for(
    *,
    entry: str = "",
    entry_paths: Iterable[Iterable[Any]] = (),
    constraints: Any = None,
) -> str:
    normalized_paths = [
        [str(item) for item in path if str(item)]
        for path in entry_paths
    ]
    return _digest(
        {
            "entry": str(entry or ""),
            "paths": normalized_paths,
            "constraints": constraints,
        },
        length=32,
    )


def validation_cluster_uid_for(
    candidate_uid: str,
    *,
    decision_evidence_hash: str,
    validator_contract: Any = None,
) -> str:
    """Return the identity of one semantic validation obligation.

    Entry wrappers and full call paths intentionally do not participate.  The
    decision evidence already contains the guards, sanitizers, ownership,
    reachability, and concurrency facts that can change the verdict.
    """

    return "VAL_" + _digest(
        {
            "candidate": candidate_uid,
            "decision_evidence": decision_evidence_hash,
            "validator_contract": validator_contract,
        },
        length=32,
    )


def _normalize_text(value: Any) -> str:
    if isinstance(value, Mapping):
        value = {
            str(key): _normalize_text(item)
            for key, item in sorted(value.items(), key=lambda pair: str(pair[0]))
        }
        return _stable_json(value)
    if isinstance(value, (list, tuple, set)):
        return _stable_json([_normalize_text(item) for item in value])
    return re.sub(r"\s+", " ", str(value or "").strip().lower())


def _normalize_path(value: Any) -> str:
    text = str(value or "").strip().replace("\\", "/")
    text = re.sub(r"/+", "/", text)
    return text


def _normalize_project_id(value: Any) -> str:
    text = _normalize_path(value).rstrip("/")
    if not text:
        return "project"
    if re.match(r"^[A-Za-z]:/", text) or text.startswith("/"):
        text = text.rsplit("/", 1)[-1]
    return _normalize_text(text) or "project"


def _project_relative_path(value: Any, project_root: Any = "") -> str:
    path = _normalize_path(value)
    root = _normalize_path(project_root).rstrip("/")
    if not path:
        return ""
    if root:
        path_folded = path.casefold()
        root_folded = root.casefold()
        if path_folded == root_folded:
            return "."
        prefix = root_folded + "/"
        if path_folded.startswith(prefix):
            return path[len(root) + 1 :].lstrip("./")
        # The same repository may be checked out below unrelated Windows and
        # POSIX roots.  Recover the suffix below the project directory.
        project_name = root.rsplit("/", 1)[-1]
        marker = f"/{project_name.casefold()}/"
        marked = f"/{path_folded.lstrip('/')}"
        marker_index = marked.rfind(marker)
        if marker_index >= 0:
            original_marked = f"/{path.lstrip('/')}"
            return original_marked[
                marker_index + len(marker) :
            ].lstrip("./")
    return path.lstrip("./")


def _structured_identity(value: Any, project_root: Any = "") -> str:
    if isinstance(value, Mapping):
        normalized: Dict[str, Any] = {}
        semantic_keys = (
            "expression",
            "operation",
            "object",
            "object_id",
            "resource",
            "symbol",
            "function",
            "kind",
            "field",
            "line",
            "file",
            "file_path",
        )
        for key in semantic_keys:
            if key not in value or value.get(key) in (None, "", [], {}):
                continue
            item = value.get(key)
            if key in {"file", "file_path"}:
                normalized[key] = _project_relative_path(item, project_root)
            else:
                normalized[key] = _normalize_text(item)
        return _stable_json(normalized) if normalized else _normalize_text(value)
    return _normalize_text(value)


def _location_parts(
    issue: Mapping[str, Any],
    project_root: Any = "",
) -> tuple[str, Optional[int]]:
    location = _normalize_path(issue.get("location") or issue.get("file") or "")
    match = re.match(r"^(.*?):(\d+)(?:[-:]\d+)?$", location)
    if match:
        return _project_relative_path(match.group(1), project_root), int(match.group(2))
    return _project_relative_path(location, project_root), None


def _evidence_pack(issue: Mapping[str, Any]) -> Dict[str, Any]:
    value = issue.get("evidence_pack")
    if not isinstance(value, Mapping):
        return {}
    # Identity fields are projections of the evidence, not evidence themselves.
    # Excluding them keeps re-annotation idempotent and prevents recursive hash
    # churn when a candidate moves through the ledger and report assembler.
    identity_fields = {
        "candidate_schema_version",
        "candidate_id",
        "id",
        "candidate_uid",
        "occurrence_uid",
        "history_key",
        "evidence_hash",
        "decision_evidence_hash",
        "provenance_hash",
        "validation_cluster_uid",
        "context_signature",
        "run_issue_uid",
        "candidate_disposition",
        "entry_identity",
        "reported_from_entry",
    }
    return {
        str(key): item
        for key, item in value.items()
        if str(key) not in identity_fields
    }


def infer_candidate_disposition(
    issue: Mapping[str, Any],
    *,
    default: str = "needs_review",
) -> str:
    explicit = str(
        issue.get("candidate_disposition")
        or issue.get("disposition")
        or ""
    ).strip().lower()
    if explicit in CANDIDATE_DISPOSITIONS:
        return explicit

    status = str(issue.get("validation_status") or issue.get("status") or "").strip().lower()
    if status in {"validated", "verified", "confirmed"}:
        return "confirmed"
    if status in {"deferred", "deferred_budget"}:
        return "deferred_budget"
    if status in {"engine_failed", "failed"}:
        return "engine_failed"
    if status in {"interrupted", "cancelled", "canceled"}:
        return "interrupted"
    if status in {"duplicate", "deduplicated", "deduplicated_alias"}:
        return "deduplicated_alias"
    if status == "rejected":
        source = str(issue.get("rejection_source") or "").strip().lower()
        if bool(issue.get("deterministic_rejection")) or source in _DETERMINISTIC_REJECTION_SOURCES:
            return "rejected_with_proof"
        # A contextual LLM rejection is not proof of absence.  Preserve it for
        # human review instead of silently turning it into a clean scan.
        return "needs_review"
    return default if default in CANDIDATE_DISPOSITIONS else "needs_review"


@dataclass(frozen=True)
class CandidateEnvelope:
    """Stable v3 representation shared by discovery, validation, and reports."""

    candidate_uid: str
    occurrence_uid: str
    history_key: str
    evidence_hash: str
    decision_evidence_hash: str
    provenance_hash: str
    validation_cluster_uid: str
    run_issue_uid: str
    project_id: str
    revision: str
    defect_class: str
    source_identity: str
    sink_identity: str
    resource_identity: str
    severity: str
    evidence_completeness: str
    disposition: str
    context_signature: str
    record_role: str = "validation_obligation"
    evidence_models: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    evidence_sources: List[str] = field(default_factory=list)
    entry_paths: List[List[str]] = field(default_factory=list)
    schema_version: str = CANDIDATE_SCHEMA_VERSION

    @classmethod
    def from_issue(
        cls,
        issue: Mapping[str, Any],
        *,
        project_id: str = "",
        project_root: str = "",
        revision: str = "",
        entry_function: str = "",
        run_id: str = "",
        ordinal: int = 0,
        default_disposition: str = "needs_review",
    ) -> "CandidateEnvelope":
        existing_schema = str(issue.get("candidate_schema_version") or "")
        if (
            existing_schema == CANDIDATE_SCHEMA_VERSION
            and issue.get("candidate_uid")
            and issue.get("occurrence_uid")
            and issue.get("decision_evidence_hash")
            and issue.get("validation_cluster_uid")
        ):
            raw_paths = issue.get("entry_paths") or issue.get("call_paths") or []
            existing_paths = [
                [str(item) for item in path if str(item)]
                for path in raw_paths
                if isinstance(path, list)
            ] if isinstance(raw_paths, list) else []
            return cls(
                candidate_uid=str(issue["candidate_uid"]),
                occurrence_uid=str(issue["occurrence_uid"]),
                history_key=str(issue.get("history_key") or ""),
                evidence_hash=str(issue.get("evidence_hash") or ""),
                decision_evidence_hash=str(issue["decision_evidence_hash"]),
                provenance_hash=str(issue.get("provenance_hash") or ""),
                validation_cluster_uid=str(issue["validation_cluster_uid"]),
                run_issue_uid=str(issue.get("run_issue_uid") or ""),
                project_id=str(issue.get("project_id") or _normalize_project_id(project_id)),
                revision=str(issue.get("revision") or revision or ""),
                defect_class=str(issue.get("defect_class") or issue.get("category") or ""),
                source_identity=str(issue.get("source_identity") or ""),
                sink_identity=str(issue.get("sink_identity") or ""),
                resource_identity=str(
                    issue.get("resource_identity")
                    or issue.get("resource_signature")
                    or ""
                ),
                severity=str(issue.get("impact_level") or "medium").lower(),
                evidence_completeness=str(issue.get("evidence_completeness") or "unknown"),
                disposition=infer_candidate_disposition(
                    issue,
                    default=default_disposition,
                ),
                context_signature=str(issue.get("context_signature") or ""),
                record_role=str(issue.get("record_role") or "validation_obligation"),
                evidence_models=dict(issue.get("evidence_models") or {}),
                evidence_sources=[
                    str(value) for value in (issue.get("evidence_sources") or [])
                ],
                entry_paths=existing_paths,
            )

        pack = _evidence_pack(issue)
        normalized_project_id = _normalize_project_id(project_id)
        file_path, line = _location_parts(issue, project_root)
        defect_class = _normalize_text(
            issue.get("defect_class")
            or issue.get("normalized_category")
            or issue.get("subcategory")
            or issue.get("category")
            or pack.get("defect_class")
        )
        function = _normalize_text(
            issue.get("function")
            or issue.get("sink_function")
            or issue.get("target_function")
        )
        raw_source = (
            pack.get("source")
            if isinstance(pack.get("source"), Mapping)
            else issue.get("source") or pack.get("source")
        )
        raw_sink = (
            pack.get("sink")
            if isinstance(pack.get("sink"), Mapping)
            else issue.get("sink")
            or issue.get("sink_function")
            or pack.get("sink")
        )
        if raw_source and not isinstance(raw_source, Mapping):
            raw_source = {
                "expression": raw_source,
                "file": file_path,
                "line": line,
                "function": function,
            }
        if raw_sink and not isinstance(raw_sink, Mapping):
            raw_sink = {
                "operation": raw_sink,
                "file": file_path,
                "line": line,
                "function": function,
            }
        if not raw_source:
            raw_source = {
                "kind": "source",
                "file": file_path,
                "line": line,
                "function": function,
            }
        if not raw_sink:
            raw_sink = {
                "kind": "sink",
                "file": file_path,
                "line": line,
                "function": function,
            }
        source = _structured_identity(raw_source, project_root)
        sink = _structured_identity(raw_sink, project_root)
        resource = _structured_identity(
            issue.get("resource_signature")
            or issue.get("resource")
            or issue.get("owner_object")
            or issue.get("thread_object")
            or pack.get("resource_signature")
            or pack.get("resource"),
            project_root,
        )
        structural = {
            "schema": CANDIDATE_SCHEMA_VERSION,
            "project": normalized_project_id,
            "defect_class": defect_class,
            "source": source,
            "sink": sink,
            "resource": resource,
        }
        history_key = f"HIST_{_digest(structural)}"
        candidate_uid = f"CAND_{_digest({**structural, 'revision': revision})}"

        raw_call_paths = issue.get("call_paths")
        if isinstance(raw_call_paths, list) and raw_call_paths and isinstance(raw_call_paths[0], list):
            entry_paths = [
                [str(item) for item in path if str(item)]
                for path in raw_call_paths
                if isinstance(path, list)
            ]
        else:
            raw_path = issue.get("call_path") or pack.get("call_path") or []
            path = [str(item) for item in raw_path if str(item)] if isinstance(raw_path, list) else []
            entry_paths = [path] if path else []

        entry = str(
            issue.get("entry_identity")
            or entry_function
            or issue.get("entry_function")
            or issue.get("analyzed_from")
            or pack.get("entry_function")
            or ""
        )
        occurrence_uid = occurrence_uid_for(
            candidate_uid,
            entry=entry,
            entry_paths=entry_paths,
        )
        evidence_models = build_evidence_models(issue)
        evidence = {
            "pack": pack,
            "positive": issue.get("positive_evidence") or [],
            "negative": issue.get("negative_evidence") or [],
            "constraints": issue.get("path_constraints") or [],
            "source_loc": issue.get("source_loc"),
            "sink_loc": issue.get("sink_loc"),
            "code_snippet": issue.get("code_snippet"),
            "models": evidence_models,
        }
        evidence_hash = _digest(evidence, length=64)
        decision_evidence = {
            "candidate": candidate_uid,
            "negative": issue.get("negative_evidence")
            or pack.get("negative_evidence")
            or [],
            "constraints": issue.get("path_constraints")
            or pack.get("path_constraints")
            or (
                pack.get("path", {}).get("path_constraints")
                if isinstance(pack.get("path"), Mapping)
                else []
            ),
            "guards": issue.get("guards")
            or issue.get("guard")
            or pack.get("guards")
            or pack.get("guard"),
            "sanitizers": issue.get("sanitizers")
            or issue.get("sanitizer")
            or pack.get("sanitizers")
            or pack.get("sanitizer"),
            "ownership": issue.get("ownership_facts")
            or pack.get("ownership_facts")
            or evidence_models.get("ownership"),
            "reachability": issue.get("reachability_facts")
            or pack.get("reachability_facts")
            or evidence_models.get("contract"),
            "concurrency": issue.get("concurrency_facts")
            or pack.get("concurrency_facts")
            or evidence_models.get("concurrency"),
            "value_domain": issue.get("value_domain_facts")
            or pack.get("value_domain_facts")
            or evidence_models.get("value_domain"),
            "dependency_code_hash": issue.get("dependency_code_hash")
            or issue.get("code_hash")
            or issue.get("source_fingerprint")
            or pack.get("dependency_code_hash")
            or pack.get("code_hash")
            or pack.get("source_fingerprint"),
        }
        decision_evidence_hash = _digest(decision_evidence, length=64)
        provenance_hash = _digest(
            {
                "display_id": issue.get("id") or issue.get("candidate_id"),
                "detector": issue.get("candidate_source")
                or issue.get("finding_kind")
                or issue.get("evidence_checker"),
                "rule": issue.get("rule") or pack.get("rule"),
                "description": issue.get("description"),
                "root_cause": issue.get("root_cause"),
                "positive": issue.get("positive_evidence") or [],
                "evidence_sources": issue.get("evidence_sources") or [],
            },
            length=64,
        )
        validator_contract = (
            issue.get("validator_contract")
            or pack.get("validator_contract")
            or issue.get("validation_requirements")
            or pack.get("validation_requirements")
        )
        validation_cluster_uid = validation_cluster_uid_for(
            candidate_uid,
            decision_evidence_hash=decision_evidence_hash,
            validator_contract=validator_contract,
        )
        context_signature = context_signature_for(
            entry=entry,
            entry_paths=entry_paths,
            constraints=(
                issue.get("path_constraints")
                or pack.get("path_constraints")
                or pack.get("path")
            ),
        )
        run_issue_uid = f"RUNISSUE_{_digest({'run': run_id, 'occurrence': occurrence_uid, 'evidence': evidence_hash, 'ordinal': ordinal})}"
        evidence_sources = sorted(
            {
                str(value)
                for value in (
                    issue.get("candidate_source"),
                    issue.get("finding_kind"),
                    issue.get("evidence_checker"),
                    pack.get("candidate_source"),
                )
                if value
            }
        )
        complete = pack.get("path", {}).get("complete") if isinstance(pack.get("path"), Mapping) else None
        evidence_completeness = "complete" if complete is True else "partial" if complete is False else "unknown"
        return cls(
            candidate_uid=candidate_uid,
            occurrence_uid=occurrence_uid,
            history_key=history_key,
            evidence_hash=evidence_hash,
            decision_evidence_hash=decision_evidence_hash,
            provenance_hash=provenance_hash,
            validation_cluster_uid=validation_cluster_uid,
            run_issue_uid=run_issue_uid,
            project_id=normalized_project_id,
            revision=str(revision or ""),
            defect_class=defect_class,
            source_identity=source,
            sink_identity=sink,
            resource_identity=resource,
            severity=str(issue.get("impact_level") or "medium").lower(),
            evidence_completeness=evidence_completeness,
            disposition=infer_candidate_disposition(issue, default=default_disposition),
            context_signature=context_signature,
            record_role=str(issue.get("record_role") or "validation_obligation"),
            evidence_models=evidence_models,
            evidence_sources=evidence_sources,
            entry_paths=entry_paths,
        )

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def annotate_issue_identity(
    issue: MutableMapping[str, Any],
    *,
    project_id: str = "",
    project_root: str = "",
    revision: str = "",
    entry_function: str = "",
    run_id: str = "",
    ordinal: int = 0,
    default_disposition: str = "needs_review",
) -> CandidateEnvelope:
    envelope = CandidateEnvelope.from_issue(
        issue,
        project_id=project_id,
        project_root=project_root,
        revision=revision,
        entry_function=entry_function,
        run_id=run_id,
        ordinal=ordinal,
        default_disposition=default_disposition,
    )
    issue.update(
        {
            "candidate_schema_version": envelope.schema_version,
            "candidate_uid": envelope.candidate_uid,
            "occurrence_uid": envelope.occurrence_uid,
            "history_key": envelope.history_key,
            "project_id": envelope.project_id,
            "revision": envelope.revision,
            "defect_class": envelope.defect_class,
            "source_identity": envelope.source_identity,
            "sink_identity": envelope.sink_identity,
            "resource_identity": envelope.resource_identity,
            "evidence_hash": envelope.evidence_hash,
            "decision_evidence_hash": envelope.decision_evidence_hash,
            "provenance_hash": envelope.provenance_hash,
            "validation_cluster_uid": envelope.validation_cluster_uid,
            "context_signature": envelope.context_signature,
            "evidence_models": dict(envelope.evidence_models),
            "run_issue_uid": envelope.run_issue_uid,
            "candidate_disposition": envelope.disposition,
            "evidence_completeness": envelope.evidence_completeness,
            "evidence_sources": list(envelope.evidence_sources),
            "entry_paths": [list(path) for path in envelope.entry_paths],
            "record_role": envelope.record_role,
        }
    )
    return envelope


def annotate_issue_collection(
    issues: Iterable[MutableMapping[str, Any]],
    *,
    project_id: str = "",
    project_root: str = "",
    revision: str = "",
    entry_function: str = "",
    run_id: str = "",
    default_disposition: str = "needs_review",
) -> List[CandidateEnvelope]:
    envelopes: List[CandidateEnvelope] = []
    for ordinal, issue in enumerate(issues):
        if not isinstance(issue, MutableMapping):
            continue
        envelopes.append(
            annotate_issue_identity(
                issue,
                project_id=project_id,
                project_root=project_root,
                revision=revision,
                entry_function=entry_function,
                run_id=run_id,
                ordinal=ordinal,
                default_disposition=default_disposition,
            )
        )
    return envelopes
