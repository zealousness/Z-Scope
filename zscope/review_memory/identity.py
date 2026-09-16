from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone
from typing import Any, Dict
from typing import Mapping, Optional


CANDIDATE_STABLE_FIELDS_SCHEMA = "zscope.candidate-stable-fields.v1"

# These are fields already emitted by zscope.candidate.v3.x/report findings.
# The registry is deliberately program-owned: an LLM may select from it, but
# it cannot introduce a new path or promote an audit-only value.
CANDIDATE_MATCHABLE_FIELDS = (
    "function", "history_key", "candidate_uid", "stable_fingerprint", "candidate_kind",
    "candidate_source", "finding_kind", "root_cause_key",
    "source_identity", "sink_identity", "resource_identity",
    "obligation_shape", "canonical_source", "canonical_sink",
    "skill", "cwe", "cwes", "category", "defect_class",
    "subcategory",
)
CANDIDATE_SCOPE_FIELDS = (
    "project_id", "rule", "rule_id", "rule_revision",
    "rule_catalog_version", "rule_catalog_sha256",
    "category", "defect_class", "subcategory",
    "candidate_schema_version",
)
CANDIDATE_AUDIT_ONLY_FIELDS = (
    "candidate_id", "issue_id", "id", "dedup_key", "file",
    "file_path", "line", "location", "code_snippet",
    "call_path", "call_paths", "entry_function", "occurrence_uid",
    "run_issue_uid", "evidence_hash", "decision_evidence_hash",
    "description", "reasoning",
)


def normalize_candidate_value(value: Any) -> Any:
    if isinstance(value, (list, tuple, set)):
        return [normalize_candidate_value(item) for item in value]
    if isinstance(value, Mapping):
        return {str(k): normalize_candidate_value(v) for k, v in sorted(value.items(), key=lambda p: str(p[0]))}
    if isinstance(value, str):
        return re.sub(r"\s+", " ", value.strip().lower())
    return value


def candidate_projection(finding: Optional[Mapping[str, Any]]) -> Dict[str, Any]:
    """Return the stable, program-owned Candidate field projection."""
    issue = finding if isinstance(finding, Mapping) else {}
    fields: Dict[str, Any] = {}
    for key in (*CANDIDATE_SCOPE_FIELDS, *CANDIDATE_MATCHABLE_FIELDS):
        value = issue.get(key)
        if value not in (None, "", [], {}):
            fields[key] = normalize_candidate_value(value)
    # Rule identity is serialized under both names in historical reports.
    if "rule" not in fields and "rule_id" in fields:
        fields["rule"] = fields["rule_id"]
    if "rule_id" not in fields and "rule" in fields:
        fields["rule_id"] = fields["rule"]
    return {
        "schema_version": CANDIDATE_STABLE_FIELDS_SCHEMA,
        "candidate_schema_version": str(issue.get("candidate_schema_version") or ""),
        "fields": fields,
    }


def candidate_scope(finding: Optional[Mapping[str, Any]]) -> Dict[str, Any]:
    projection = candidate_projection(finding)
    return {key: projection["fields"][key] for key in CANDIDATE_SCOPE_FIELDS if key in projection["fields"]}


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def stable_id(prefix: str, value: Dict[str, Any]) -> str:
    encoded = json.dumps(value, ensure_ascii=False, sort_keys=True, default=str).encode()
    return f"{prefix}_{hashlib.sha256(encoded).hexdigest()[:24]}"


def project_id(project: Any) -> str:
    return str(getattr(project, "project_id", "") or getattr(project, "project_root", "project"))


def review_subject_id(record: Dict[str, Any]) -> str:
    """Stable identity of a finding review subject, excluding rebuttal text."""
    finding = record.get("finding") or {}
    if not isinstance(finding, dict):
        finding = {}
    identity = {
        "project_id": record.get("project_id", ""),
        "issue_id": finding.get("issue_id") or finding.get("id"),
        "dedup_key": finding.get("dedup_key"),
        "stable_fingerprint": finding.get("stable_fingerprint"),
    }
    return stable_id("subject", identity)
