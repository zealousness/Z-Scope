from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List

REVIEW_RECORD_SCHEMA = "zscope.review-record.v1"
PATTERN_SCHEMA = "zscope.false-positive-pattern-proposal.v1"
PATTERN_MATCH_SCHEMA = "zscope.review-pattern-match.v1"


@dataclass
class ReviewRecord:
    review_id: str
    project_id: str
    finding: Dict[str, Any]
    candidate_snapshot: Dict[str, Any] = field(default_factory=dict)
    candidate_projection: Dict[str, Any] = field(default_factory=dict)
    review_subject_id: str = ""
    user_rebuttal: str = ""
    source_context: Dict[str, Any] = field(default_factory=dict)
    evidence_refs: List[str] = field(default_factory=list)
    repository_identity: Dict[str, Any] = field(default_factory=dict)
    status: str = "pending_extraction"
    created_at: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {"schema_version": REVIEW_RECORD_SCHEMA, **self.__dict__}


@dataclass
class PatternProposal:
    pattern_id: str
    project_id: str
    scope: Dict[str, Any]
    trigger_features: List[Dict[str, Any]] = field(default_factory=list)
    match_contract: Dict[str, Any] = field(default_factory=dict)
    contract_digest: str = ""
    false_positive_reason: str = ""
    required_checks: List[str] = field(default_factory=list)
    counter_conditions: List[str] = field(default_factory=list)
    evidence_refs: List[str] = field(default_factory=list)
    source_fingerprints: List[str] = field(default_factory=list)
    origin_review_ids: List[str] = field(default_factory=list)
    status: str = "proposed"
    generator: Dict[str, Any] = field(default_factory=dict)
    created_at: str = ""
    updated_at: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {"schema_version": PATTERN_SCHEMA, **self.__dict__}


@dataclass
class PatternMatch:
    """Program-owned receipt for one advisory match during a scan or replay."""

    pattern_id: str
    scan_id: str
    issue_identity: Dict[str, Any]
    project_id: str = ""
    match_basis: List[str] = field(default_factory=list)
    source_compatible: bool = False
    injected: bool = False
    validator_status: str = ""
    token_cost: int = 0
    tool_cost: int = 0
    overturned: bool = False
    created_at: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {"schema_version": PATTERN_MATCH_SCHEMA, **self.__dict__}
