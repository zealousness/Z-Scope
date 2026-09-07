"""Coverage-gap discovery over a candidate-blind semantic projection.

This module deliberately separates four concerns:

* zero-LLM semantic facts are built and persisted by ``security_map``;
* the planner may use ledger coverage to choose work, but never projects that
  coverage into an LLM prompt;
* a discovery model may emit hypotheses only through a strict report schema;
* hypotheses enter the shared CandidateRegistrar as open validation
  obligations and therefore cannot become confirmed findings directly.
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
from copy import deepcopy
from dataclasses import dataclass
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Sequence, Set, Tuple

from ..agents.base import JsonOutputSpec, JsonToolAgent
from ..framework.base import AgentResponse
from ..framework.llm_client import LLMClient
from ..orchestration.candidates import (
    CandidateLedger,
    CandidateRegistrar,
    CandidateRegistrationResult,
)
from ..semantics.security_map import (
    DISCOVERY_REPORT_JSON_SCHEMA,
    SEMANTIC_CLAIM_DELTA_JSON_SCHEMA,
    AuditUnit,
    DiscoveryHypothesis,
    DiscoveryReport,
    FunctionSecurityRecord,
    SecurityMapStore,
    SecuritySemanticMap,
    SemanticClaimDelta,
)

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class DiscoveryProfile:
    name: str
    risk_threshold: int
    max_units: Optional[int]
    max_functions_per_unit: int
    max_hypotheses_per_unit: int
    max_agent_iterations: int
    max_initial_context_tokens: int = 24_000


DISCOVERY_PROFILES: Dict[str, DiscoveryProfile] = {
    # ``fast`` is a hard off switch: no map build and no discovery LLM call in
    # the parallel orchestration path.
    "fast": DiscoveryProfile("fast", 101, 0, 0, 0, 0),
    "balanced": DiscoveryProfile("balanced", 60, None, 16, 4, 1),
    "deep": DiscoveryProfile("deep", 35, None, 16, 8, 1),
}

_PROFILE_ALIASES = {
    "": "fast",
    "off": "fast",
    "disabled": "fast",
    "none": "fast",
    "quick": "fast",
    "standard": "balanced",
    "default": "balanced",
    "thorough": "deep",
    "full": "deep",
}

_FAMILY_POLICY: Dict[str, Tuple[str, Tuple[str, ...]]] = {
    "memory_bounds": ("source_sink_path", ("bounds_and_integer",)),
    "resource_lifecycle": (
        "resource_protocol",
        ("resource_lifecycle", "ownership_contract", "temporal_memory"),
    ),
    "callback_concurrency": (
        "callback_concurrency",
        ("shared_state_race", "concurrency_lock_order", "stack_escape"),
    ),
    "state_protocol": ("state_machine", ("ownership_contract",)),
    "input_boundary": ("source_sink_path", ("security_review",)),
    "auth_boundary": ("auth_boundary", ("authorization",)),
    "sensitive_sink": ("source_sink_path", ("security_review",)),
}

AUDIT_RISK_WEIGHTS: Dict[str, int] = {
    "known_variant_history": 35,
    "high_risk_diff": 25,
    "external_reachable_sensitive": 20,
    "same_event_family_candidate_desert": 20,
    "callback_dynamic_alias_unresolved": 15,
    "backend_unavailable_degraded": 15,
    "cross_module_path": 10,
    "semantic_unknown_conflict": 10,
}

_SENSITIVE_EVENT_FAMILIES = frozenset(
    {
        "memory_bounds",
        "resource_lifecycle",
        "callback_concurrency",
        "auth_boundary",
        "sensitive_sink",
    }
)

_DEFAULT_EXCLUDED_AUDIT_DIRECTORIES = frozenset(
    {
        "generated",
        "generated-sources",
        "third_party",
        "third-party",
        "vendor",
        "vendors",
        "node_modules",
    }
)
_DEFAULT_TEST_ONLY_DIRECTORIES = frozenset(
    {"test", "tests", "testing", "fixtures", "testdata", "test-data"}
)

_FORBIDDEN_PROMPT_KEY_PARTS = frozenset(
    {
        "candidate",
        "ledger",
        "rule",
        "benchmark",
        "ground_truth",
        "groundtruth",
        "verdict",
        "validation",
        "confirmed",
        "finding",
    }
)

# Values from backend/user metadata are untrusted too: a producer could hide
# outcome-bearing fields below an innocuous key such as ``notes``.  These
# patterns intentionally target serialized identities and decision payloads,
# not ordinary source words such as a local variable named ``candidate``.
_FORBIDDEN_PROMPT_VALUE_PATTERNS = tuple(
    re.compile(pattern, re.IGNORECASE)
    for pattern in (
        r"\bcandidate\s*[:=]",
        r"\bcandidate_(?:id|uid)\b",
        r"\bvalidation_cluster_uid\b",
        r"\bobligation_uid\b",
        r"\bcand(?:idate)?[-_:][a-z0-9]",
        r"\brule\s*[:=]",
        r"\brule_(?:id|name)\b",
        r"\brule[-_:][a-z0-9]",
        r"\bdeterministic_rule\b",
        r"\bbenchmark\b",
        r"\bground[ _-]?truth\b",
        r"\btruth_id\b",
        r"\bscorer?\s*[:=]",
        r"\bverdict\s*[:=]",
        r"\b(?:confirmed|rejected|verified)[ _-]?finding\b",
    )
)
_FORBIDDEN_PROMPT_EXACT_VALUES = frozenset(
    {
        "confirmed",
        "rejected",
        "verified",
        "true_positive",
        "false_positive",
        "needs_review",
    }
)

ACTIVE_DISCOVERY_CONTRACT = """You are Z-Scope's bounded active-discovery worker.
You receive one candidate-blind audit unit containing only program/user semantic facts.
Independently look for a concrete security hypothesis within that unit. Do not infer
that a rule, candidate, benchmark answer, or prior verdict exists. Every hypothesis
must cite only evidence_ref values present in the projection. Treat missing facts as
unknown, record them in missing_fact_kinds/unresolved_facts, and never claim a final
or confirmed vulnerability. Use function_uid values exactly as supplied. Return one
strict discovery_report object for the supplied unit_id and unit_fingerprint.
"""

SEMANTIC_ENRICHMENT_PROMPT_VERSION = "security-semantic-enricher.v1"
SEMANTIC_ENRICHMENT_CONTRACT = """You enrich one immutable security audit unit with
structured semantic claims only. Use only the candidate-blind program/user facts in
the prompt. Every claim must set origin=llm, cite only supplied evidence_ref values,
and use a supplied function_uid as subject_uid. Preserve uncertainty: status must be
unknown or conflicting whenever the evidence does not establish one interpretation.
Do not report vulnerabilities, verdicts, candidates, rules, or benchmark outcomes.
Emit exactly one strict semantic_claim_delta for the supplied unit identity.
"""


def resolve_discovery_profile(config_or_analysis: Any) -> DiscoveryProfile:
    """Resolve new or compatibility profile attributes without changing config schema."""

    analysis = getattr(config_or_analysis, "analysis", config_or_analysis)
    raw: Any = None
    for name in (
        "security_discovery_profile",
        "active_discovery_profile",
        "discovery_profile",
        "scan_profile",
        "analysis_profile",
    ):
        value = getattr(analysis, name, None)
        if value not in (None, ""):
            raw = value
            break
    if raw in (None, ""):
        # The public v2 surface calls this ``scan.depth``.  Keep the getattr
        # fallbacks above so this module can also run against older effective
        # config objects during a staged rollout.
        scan = getattr(config_or_analysis, "scan", None)
        raw = getattr(scan, "depth", None)
    normalized = str(raw or "fast").strip().lower().replace("-", "_")
    normalized = _PROFILE_ALIASES.get(normalized, normalized)
    return DISCOVERY_PROFILES.get(normalized, DISCOVERY_PROFILES["fast"])


def candidate_coverage_keys(ledger: CandidateLedger) -> Set[str]:
    """Project the ledger to event-family presence for planning only.

    The planner is intentionally not allowed to inspect candidate identities,
    sources, sinks, locations, or rule conclusions.  Those values are neither
    prompt material nor trigger inputs; a family-level coverage count/presence
    bit is the only information that crosses this boundary.
    """

    keys: Set[str] = set()
    for record in ledger.records():
        ticket = record.ticket
        evidence = ticket.evidence if isinstance(ticket.evidence, dict) else {}
        payload = evidence.get("candidate_payload")
        if not isinstance(payload, dict):
            payload = {}
        family = _candidate_event_family(record, payload)
        if family:
            keys.add(_normalize_key(f"family:{family}"))
    return keys


def historical_variant_keys(issues: Iterable[Any]) -> Set[str]:
    """Extract normalized planner identities from confirmed history only.

    ``model_verdict`` is deliberately ignored.  A historical issue becomes a
    variant signal only after its persisted policy/result status is confirmed
    or validated.
    """

    keys: Set[str] = set()
    identity_fields = (
        "function_uid",
        "function",
        "func_name",
        "entry_function",
        "canonical_sink",
        "sink_identity",
        "root_cause_key",
        "canonical_root_cause",
        "root_cause_identity",
        "root_cause",
    )

    def add_mapping(value: Any) -> None:
        if not isinstance(value, Mapping):
            return
        for field_name in identity_fields:
            normalized = _normalize_key(value.get(field_name))
            if normalized:
                keys.add(normalized)
        location = value.get("location")
        if isinstance(location, Mapping):
            for field_name in ("function_uid", "function", "func_name"):
                normalized = _normalize_key(location.get(field_name))
                if normalized:
                    keys.add(normalized)

    for raw_issue in issues:
        issue = raw_issue
        if not isinstance(issue, Mapping):
            serializer = getattr(raw_issue, "to_dict", None)
            issue = serializer() if callable(serializer) else None
        if not isinstance(issue, Mapping) or not _is_confirmed_historical_issue(issue):
            continue
        add_mapping(issue)
        add_mapping(issue.get("evidence_pack"))
        add_mapping(issue.get("candidate_payload"))
        evidence_pack = issue.get("evidence_pack")
        if isinstance(evidence_pack, Mapping):
            add_mapping(evidence_pack.get("canonical_flow"))
    return keys


def _is_confirmed_historical_issue(issue: Mapping[str, Any]) -> bool:
    # Prefer the first available final status field.  This prevents a stale
    # top-level status or a raw model verdict from overriding policy.
    for field_name, accepted in (
        ("policy_disposition", {"confirmed", "validated"}),
        ("candidate_disposition", {"confirmed", "validated"}),
        ("validation_status", {"validated", "confirmed"}),
        ("status", {"validated", "confirmed"}),
        ("disposition", {"validated", "confirmed"}),
    ):
        if field_name not in issue or issue.get(field_name) in (None, ""):
            continue
        return _normalize_key(issue.get(field_name)) in accepted
    return issue.get("confirmed") is True


def audit_unit_risk_score(**signals: bool) -> Tuple[int, List[str]]:
    """Return the locked, additive and fully auditable audit-unit score."""

    unknown = sorted(set(signals) - set(AUDIT_RISK_WEIGHTS))
    if unknown:
        raise ValueError(f"unknown audit risk signal(s): {', '.join(unknown)}")
    score = 0
    reasons: List[str] = []
    for name, weight in AUDIT_RISK_WEIGHTS.items():
        if bool(signals.get(name, False)):
            score += weight
            reasons.append(f"{name}=+{weight}")
    return min(100, score), reasons


class CoverageGapPlanner:
    """Create bounded audit units from risky semantic facts and coverage gaps."""

    def __init__(self, profile: DiscoveryProfile, *, merge_overlap: float = 0.60):
        self.profile = profile
        self.merge_overlap = max(0.0, min(1.0, float(merge_overlap)))

    def plan(
        self,
        semantic_map: SecuritySemanticMap,
        *,
        covered_keys: Iterable[str] = (),
        known_variant_keys: Iterable[str] = (),
    ) -> Tuple[AuditUnit, ...]:
        if self.profile.max_units == 0:
            return ()
        covered = {_normalize_key(value) for value in covered_keys if _normalize_key(value)}
        known_variants = {
            _normalize_key(value) for value in known_variant_keys if _normalize_key(value)
        }
        functions = {item.function_uid: item for item in semantic_map.functions}
        by_name: Dict[str, List[str]] = {}
        for record in semantic_map.functions:
            by_name.setdefault(_normalize_key(record.function_name), []).append(record.function_uid)
        claims_by_subject: Dict[str, List[Any]] = {}
        for claim in semantic_map.claims:
            claims_by_subject.setdefault(claim.subject_uid, []).append(claim)
        unknowns_by_subject: Dict[str, List[Any]] = {}
        for unknown in semantic_map.unknowns:
            unknowns_by_subject.setdefault(unknown.subject_uid, []).append(unknown)
        external_entry_identities: Set[str] = set()
        for subject_uid, subject_claims in claims_by_subject.items():
            is_external = any(
                claim.kind == "input_origin"
                and str(claim.value.get("origin") or "").lower() == "external"
                or claim.kind == "trust_boundary"
                and bool(claim.value.get("externally_exposed"))
                for claim in subject_claims
            )
            entry_record = functions.get(subject_uid)
            if is_external and entry_record is not None:
                external_entry_identities.update(entry_record.entry_identities)

        seeds: List[AuditUnit] = []
        for record in semantic_map.functions:
            if self._record_is_default_excluded(record):
                continue
            by_family: Dict[str, List[Any]] = {}
            for event in record.events:
                by_family.setdefault(event.family, []).append(event)
            for family, events in by_family.items():
                policy = _FAMILY_POLICY.get(family)
                if policy is None:
                    continue
                unit_kind, skill_families = policy
                members = tuple(
                    uid
                    for uid in self._member_uids(record, by_name)
                    if uid in functions and not self._record_is_default_excluded(functions[uid])
                )
                member_records = [functions[uid] for uid in members if uid in functions]
                desert = not self._same_family_is_covered(
                    family,
                    member_records,
                    covered,
                )
                subject_claims = [
                    claim for uid in members for claim in claims_by_subject.get(uid, ())
                ]
                subject_unknowns = [
                    unknown for uid in members for unknown in unknowns_by_subject.get(uid, ())
                ]
                score, reasons = audit_unit_risk_score(
                    known_variant_history=self._is_known_variant(record, known_variants),
                    high_risk_diff=self._is_high_risk_diff(record),
                    external_reachable_sensitive=(
                        family in _SENSITIVE_EVENT_FAMILIES
                        and bool(set(record.entry_identities) & external_entry_identities)
                    ),
                    same_event_family_candidate_desert=desert,
                    callback_dynamic_alias_unresolved=self._has_dynamic_unknown(
                        member_records, subject_unknowns
                    ),
                    backend_unavailable_degraded=self._backend_is_degraded(member_records),
                    cross_module_path=self._is_cross_module(member_records),
                    semantic_unknown_conflict=(
                        bool(subject_unknowns)
                        or any(
                            claim.status in {"unknown", "conflicting"} for claim in subject_claims
                        )
                    ),
                )
                if score < self.profile.risk_threshold:
                    continue
                event_refs = tuple(sorted(event.event_id for event in events))
                claim_refs = tuple(
                    sorted(
                        {
                            claim_id
                            for uid in members
                            for claim_id in (
                                claim.claim_id for claim in claims_by_subject.get(uid, ())
                            )
                        }
                    )
                )
                unknown_refs = tuple(
                    sorted(
                        {
                            unknown_id
                            for uid in members
                            for unknown_id in (
                                unknown.unknown_id for unknown in unknowns_by_subject.get(uid, ())
                            )
                        }
                    )
                )
                fingerprint = self._unit_fingerprint(
                    unit_kind=unit_kind,
                    records=member_records,
                    event_refs=event_refs,
                    claim_refs=claim_refs,
                    unknown_refs=unknown_refs,
                )
                seeds.append(
                    AuditUnit(
                        unit_id=f"AUDIT_{fingerprint[:20]}",
                        unit_kind=unit_kind,
                        fingerprint=fingerprint,
                        risk_score=score,
                        risk_reasons=tuple(reasons),
                        root_entries=tuple(sorted(record.entry_identities)),
                        member_functions=tuple(members),
                        event_refs=event_refs,
                        claim_refs=claim_refs,
                        unknown_refs=unknown_refs,
                        skill_families=tuple(skill_families),
                        backend_coverage=self._aggregate_backend_coverage(member_records),
                        candidate_desert=desert,
                    )
                )

        # Deep mode also investigates structurally unresolved regions that do
        # not contain a regex-recognized event.  Their lower base score keeps
        # them outside the balanced threshold unless other risk signals exist.
        if self.profile.name == "deep":
            for record in semantic_map.functions:
                if self._record_is_default_excluded(record):
                    continue
                unknown_refs = tuple(
                    sorted(
                        unknown.unknown_id
                        for unknown in unknowns_by_subject.get(record.function_uid, ())
                    )
                )
                if not unknown_refs or record.events:
                    continue
                desert = not self._same_family_is_covered("known_variant", [record], covered)
                score, reasons = audit_unit_risk_score(
                    known_variant_history=self._is_known_variant(record, known_variants),
                    high_risk_diff=self._is_high_risk_diff(record),
                    external_reachable_sensitive=False,
                    same_event_family_candidate_desert=desert,
                    callback_dynamic_alias_unresolved=self._has_dynamic_unknown(
                        [record], unknowns_by_subject.get(record.function_uid, ())
                    ),
                    backend_unavailable_degraded=self._backend_is_degraded([record]),
                    cross_module_path=False,
                    semantic_unknown_conflict=True,
                )
                if score < self.profile.risk_threshold:
                    continue
                fingerprint = self._unit_fingerprint(
                    unit_kind="known_variant",
                    records=[record],
                    event_refs=(),
                    claim_refs=tuple(
                        sorted(
                            claim.claim_id
                            for claim in claims_by_subject.get(record.function_uid, ())
                        )
                    ),
                    unknown_refs=unknown_refs,
                )
                seeds.append(
                    AuditUnit(
                        unit_id=f"AUDIT_{fingerprint[:20]}",
                        unit_kind="known_variant",
                        fingerprint=fingerprint,
                        risk_score=score,
                        risk_reasons=tuple(reasons),
                        root_entries=tuple(sorted(record.entry_identities)),
                        member_functions=(record.function_uid,),
                        event_refs=(),
                        claim_refs=tuple(sorted(claims_by_subject.get(record.function_uid, ()))),
                        unknown_refs=unknown_refs,
                        skill_families=("security_review",),
                        backend_coverage=self._aggregate_backend_coverage([record]),
                        candidate_desert=desert,
                    )
                )

        merged = self._merge_units(seeds)
        merged.sort(key=lambda item: (-item.risk_score, item.fingerprint))
        if self.profile.max_units is None:
            return tuple(merged)
        return tuple(merged[: self.profile.max_units])

    def _member_uids(
        self,
        record: FunctionSecurityRecord,
        by_name: Mapping[str, List[str]],
    ) -> Tuple[str, ...]:
        members: List[str] = []
        # The shortest entry path provides enough context while preventing a
        # dispatcher graph from exploding each audit unit.
        paths = sorted(record.entry_paths, key=lambda path: (len(path), path))
        if paths:
            for name in paths[0][-self.profile.max_functions_per_unit :]:
                matches = by_name.get(_normalize_key(name), ())
                if len(matches) == 1 and matches[0] not in members:
                    members.append(matches[0])
        if record.function_uid not in members:
            members.append(record.function_uid)
        return tuple(members[-self.profile.max_functions_per_unit :])

    @staticmethod
    def _record_is_covered(record: FunctionSecurityRecord, covered: Set[str]) -> bool:
        if not covered:
            return False
        identities = {
            _normalize_key(record.function_uid),
            _normalize_key(record.index_name),
            _normalize_key(record.function_name),
            _normalize_key(record.file_path),
        }
        identities.update(_normalize_key(event.evidence_ref) for event in record.events)
        for identity in identities:
            if not identity:
                continue
            if identity in covered or any(identity in key or key in identity for key in covered):
                return True
        return False

    @staticmethod
    def _record_is_default_excluded(record: FunctionSecurityRecord) -> bool:
        coverage = record.backend_coverage if isinstance(record.backend_coverage, dict) else {}
        if any(bool(coverage.get(key)) for key in ("is_generated", "is_vendor", "is_test_only")):
            return True
        path = str(coverage.get("project_relative_path") or record.file_path or "")
        normalized = path.replace("\\", "/").strip("/").lower()
        if not normalized:
            return False
        parts = tuple(part for part in normalized.split("/") if part)
        directories = parts[:-1]
        if any(part in _DEFAULT_EXCLUDED_AUDIT_DIRECTORIES for part in directories):
            return True
        if any(part in _DEFAULT_TEST_ONLY_DIRECTORIES for part in directories):
            return True
        filename = parts[-1]
        stem = filename.rsplit(".", 1)[0]
        return stem.startswith("test_") or stem.endswith("_test") or ".test." in filename

    @staticmethod
    def _same_family_is_covered(
        family: str,
        records: Sequence[FunctionSecurityRecord],
        covered: Set[str],
    ) -> bool:
        del records
        return _normalize_key(f"family:{family}") in covered

    @staticmethod
    def _is_known_variant(record: FunctionSecurityRecord, known_variants: Set[str]) -> bool:
        focus = record.diff_focus if isinstance(record.diff_focus, dict) else {}
        explicit = any(
            bool(focus.get(key))
            for key in (
                "known_variant",
                "history_match",
                "historical_finding",
                "previously_confirmed",
            )
        )
        return explicit or any(
            _normalize_key(value) in known_variants
            for value in (record.function_uid, record.index_name, record.function_name)
        )

    @staticmethod
    def _is_high_risk_diff(record: FunctionSecurityRecord) -> bool:
        focus = record.diff_focus if isinstance(record.diff_focus, dict) else {}
        try:
            score = int(float(focus.get("risk_score") or 0))
        except (TypeError, ValueError):
            score = 0
        label = str(
            focus.get("risk") or focus.get("risk_level") or focus.get("severity") or ""
        ).lower()
        return score >= 70 or label in {"high", "critical"}

    @staticmethod
    def _has_dynamic_unknown(
        records: Sequence[FunctionSecurityRecord], unknowns: Sequence[Any]
    ) -> bool:
        if any(record.unresolved_callees for record in records):
            return True
        return any(
            any(
                token in str(getattr(unknown, "kind", "") or "").lower()
                for token in (
                    "callback",
                    "dynamic",
                    "indirect",
                    "alias",
                )
            )
            for unknown in unknowns
        )

    @staticmethod
    def _backend_is_degraded(records: Sequence[FunctionSecurityRecord]) -> bool:
        for record in records:
            coverage = record.backend_coverage
            backend = str(coverage.get("backend") or "unknown").lower()
            precision = str(coverage.get("structure_precision") or "unknown").lower()
            status = str(coverage.get("status") or "").lower()
            if backend in {"", "unknown", "regex", "none", "unavailable"}:
                return True
            if status in {"failed", "degraded", "unavailable"}:
                return True
            if precision in {"degraded", "low", "unavailable"}:
                return True
        return False

    @staticmethod
    def _is_cross_module(records: Sequence[FunctionSecurityRecord]) -> bool:
        modules = {
            "/".join(str(record.file_path or "").replace("\\", "/").split("/")[:-1])
            for record in records
            if str(record.file_path or "")
        }
        return len(modules) > 1

    @staticmethod
    def _aggregate_backend_coverage(
        records: Sequence[FunctionSecurityRecord],
    ) -> Dict[str, Any]:
        backends = sorted(
            {str(item.backend_coverage.get("backend") or "unknown") for item in records}
        )
        return {
            "backends": backends,
            "function_count": len(records),
            "call_graph_observed_for_all": bool(records)
            and all(bool(item.backend_coverage.get("call_graph_observed")) for item in records),
            "framework_ir_observed": any(
                bool(item.backend_coverage.get("framework_ir_observed")) for item in records
            ),
        }

    @staticmethod
    def _unit_fingerprint(
        *,
        unit_kind: str,
        records: Sequence[FunctionSecurityRecord],
        event_refs: Sequence[str],
        claim_refs: Sequence[str],
        unknown_refs: Sequence[str],
    ) -> str:
        payload = {
            "unit_kind": unit_kind,
            "functions": sorted((item.function_uid, item.code_hash) for item in records),
            "dependency_fingerprints": sorted(
                (
                    item.function_uid,
                    str(item.backend_coverage.get("dependency_fingerprint") or ""),
                )
                for item in records
            ),
            "events": sorted(event_refs),
            "claims": sorted(claim_refs),
            "unknowns": sorted(unknown_refs),
        }
        return hashlib.sha256(_stable_json(payload).encode("utf-8")).hexdigest()

    def _merge_units(self, units: Sequence[AuditUnit]) -> List[AuditUnit]:
        result: List[AuditUnit] = []
        for unit in sorted(units, key=lambda item: (-item.risk_score, item.fingerprint)):
            merged = False
            for index, existing in enumerate(result):
                if existing.unit_kind != unit.unit_kind:
                    continue
                if set(existing.skill_families) != set(unit.skill_families):
                    continue
                left = set(existing.member_functions)
                right = set(unit.member_functions)
                overlap = len(left & right) / max(1, len(left | right))
                combined_members = tuple(sorted(left | right))
                if overlap < self.merge_overlap:
                    continue
                if len(combined_members) > self.profile.max_functions_per_unit:
                    continue
                payload = {
                    "unit_kind": unit.unit_kind,
                    "source_fingerprints": sorted({existing.fingerprint, unit.fingerprint}),
                    "members": combined_members,
                    "events": sorted(set(existing.event_refs) | set(unit.event_refs)),
                    "claims": sorted(set(existing.claim_refs) | set(unit.claim_refs)),
                    "unknowns": sorted(set(existing.unknown_refs) | set(unit.unknown_refs)),
                }
                fingerprint = hashlib.sha256(_stable_json(payload).encode("utf-8")).hexdigest()
                result[index] = AuditUnit(
                    unit_id=f"AUDIT_{fingerprint[:20]}",
                    unit_kind=unit.unit_kind,
                    fingerprint=fingerprint,
                    risk_score=min(100, max(existing.risk_score, unit.risk_score) + 3),
                    risk_reasons=tuple(sorted(set(existing.risk_reasons) | set(unit.risk_reasons))),
                    root_entries=tuple(sorted(set(existing.root_entries) | set(unit.root_entries))),
                    member_functions=combined_members,
                    event_refs=tuple(payload["events"]),
                    claim_refs=tuple(payload["claims"]),
                    unknown_refs=tuple(payload["unknowns"]),
                    skill_families=tuple(
                        sorted(set(existing.skill_families) | set(unit.skill_families))
                    ),
                    backend_coverage={
                        "merged": True,
                        "parts": [existing.backend_coverage, unit.backend_coverage],
                    },
                    candidate_desert=existing.candidate_desert or unit.candidate_desert,
                )
                merged = True
                break
            if not merged:
                result.append(unit)
        return result


def candidate_blind_prompt_projection(
    semantic_map: SecuritySemanticMap,
    unit: AuditUnit,
) -> Dict[str, Any]:
    """Project program facts only; ledger/candidate/rule state is impossible to include."""

    member_ids = set(unit.member_functions)
    event_ids = set(unit.event_refs)
    claim_ids = set(unit.claim_refs)
    unknown_ids = set(unit.unknown_refs)
    functions = []
    allowed_evidence_refs: Set[str] = set()
    for record in semantic_map.functions:
        if record.function_uid not in member_ids:
            continue
        events = []
        for event in record.events:
            if event.event_id not in event_ids:
                continue
            events.append(_strip_forbidden_prompt_keys(event.to_dict()))
            allowed_evidence_refs.add(event.evidence_ref)
        functions.append(
            {
                "function_uid": record.function_uid,
                "index_name": record.index_name,
                "function_name": record.function_name,
                "file_path": record.file_path,
                "start_line": record.start_line,
                "end_line": record.end_line,
                "signature": record.signature,
                "entry_identities": list(record.entry_identities),
                "entry_paths": [list(path) for path in record.entry_paths],
                "callees": list(record.callees),
                "unresolved_callees": list(record.unresolved_callees),
                "events": events,
                "backend_coverage": _strip_forbidden_prompt_keys(record.backend_coverage),
                "diff_focus": _strip_forbidden_prompt_keys(record.diff_focus),
            }
        )
    claims = []
    for claim in semantic_map.claims:
        # LLM-derived claims would make the supposedly independent prompt
        # self-referential.  Only program/user evidence is projected.
        if claim.claim_id not in claim_ids or claim.origin not in {"program", "user"}:
            continue
        value = claim.to_dict()
        value["value"] = _strip_forbidden_prompt_keys(value.get("value") or {})
        claims.append(value)
        allowed_evidence_refs.update(claim.evidence_refs)
    unknowns = []
    for unknown in semantic_map.unknowns:
        if unknown.unknown_id not in unknown_ids:
            continue
        unknowns.append(_strip_forbidden_prompt_keys(unknown.to_dict()))
        allowed_evidence_refs.update(unknown.evidence_refs)

    projection = {
        "schema_version": "zscope.discovery_prompt_projection.v1",
        "project_id": semantic_map.project_id,
        "revision": semantic_map.revision,
        "audit_unit": {
            "schema_version": unit.schema_version,
            "unit_id": unit.unit_id,
            "unit_kind": unit.unit_kind,
            "unit_fingerprint": unit.fingerprint,
            "root_entries": list(unit.root_entries),
            "member_functions": list(unit.member_functions),
            "event_refs": list(unit.event_refs),
            "claim_refs": list(unit.claim_refs),
            "unknown_refs": list(unit.unknown_refs),
            "skill_families": list(unit.skill_families),
            "backend_coverage": _strip_forbidden_prompt_keys(unit.backend_coverage),
        },
        "functions": functions,
        "semantic_claims": claims,
        "semantic_unknowns": unknowns,
        "allowed_evidence_refs": sorted(allowed_evidence_refs),
    }
    assert_candidate_blind_projection(projection)
    return projection


def assert_candidate_blind_projection(value: Any) -> None:
    """Fail closed if a future projection adds an outcome-bearing field."""

    if isinstance(value, Mapping):
        for key, nested in value.items():
            normalized = str(key).strip().lower().replace("-", "_")
            if any(part in normalized for part in _FORBIDDEN_PROMPT_KEY_PARTS):
                raise ValueError(f"candidate-blind projection contains forbidden key: {key}")
            assert_candidate_blind_projection(nested)
    elif isinstance(value, list):
        for nested in value:
            assert_candidate_blind_projection(nested)
    elif isinstance(value, str) and _contains_forbidden_prompt_value(value):
        raise ValueError("candidate-blind projection contains forbidden value")


def discovery_projection_tokens(projection: Mapping[str, Any]) -> int:
    serialized = json.dumps(projection, ensure_ascii=False, sort_keys=True)
    return LLMClient.estimate_tokens(
        [
            {"role": "system", "content": ACTIVE_DISCOVERY_CONTRACT},
            {"role": "user", "content": serialized},
        ]
    )


def fit_candidate_blind_prompt_projection(
    projection: Mapping[str, Any],
    *,
    max_tokens: int = 24_000,
) -> Dict[str, Any]:
    """Deterministically fit one initial unit projection or fail closed."""

    fitted = deepcopy(dict(projection))
    if discovery_projection_tokens(fitted) <= max_tokens:
        fitted["projection_estimated_tokens"] = discovery_projection_tokens(fitted)
        if fitted["projection_estimated_tokens"] > max_tokens:
            # Fall through to the deterministic trimming path if the audit
            # metadata itself crosses the hard boundary.
            fitted.pop("projection_estimated_tokens", None)
        else:
            assert_candidate_blind_projection(fitted)
            return fitted

    fitted["projection_truncated"] = True
    fitted["projection_truncated_sections"] = []
    for function in fitted.get("functions", []):
        if not isinstance(function, dict):
            continue
        for key, limit in (("callees", 32), ("unresolved_callees", 16), ("entry_paths", 4)):
            values = function.get(key)
            if isinstance(values, list) and len(values) > limit:
                function[key] = values[:limit]
                fitted["projection_truncated_sections"].append(f"functions.{key}")
        events = function.get("events")
        if isinstance(events, list):
            if len(events) > 48:
                function["events"] = events[:48]
                events = function["events"]
                fitted["projection_truncated_sections"].append("functions.events")
            for event in events:
                if isinstance(event, dict):
                    event["expression"] = str(event.get("expression") or "")[:240]
        function["diff_focus"] = _compact_json_value(function.get("diff_focus"), 400)

    claims = fitted.get("semantic_claims")
    if isinstance(claims, list):
        if len(claims) > 96:
            fitted["semantic_claims"] = claims[:96]
            claims = fitted["semantic_claims"]
            fitted["projection_truncated_sections"].append("semantic_claims")
        for claim in claims:
            if isinstance(claim, dict):
                claim["value"] = _compact_json_value(claim.get("value"), 800)
                locations = claim.get("locations")
                if isinstance(locations, list):
                    claim["locations"] = locations[:4]
    unknowns = fitted.get("semantic_unknowns")
    if isinstance(unknowns, list) and len(unknowns) > 64:
        fitted["semantic_unknowns"] = unknowns[:64]
        fitted["projection_truncated_sections"].append("semantic_unknowns")

    if discovery_projection_tokens(fitted) > max_tokens:
        # Preserve identities and evidence references, but discard verbose
        # semantic values before sacrificing any evidence-bearing event.
        for claim in fitted.get("semantic_claims", []):
            if isinstance(claim, dict):
                claim["value"] = {}
                claim["locations"] = list(claim.get("locations") or [])[:1]
        for function in fitted.get("functions", []):
            if isinstance(function, dict):
                function["callees"] = []
                function["unresolved_callees"] = list(function.get("unresolved_callees") or [])[:4]
                function["entry_paths"] = list(function.get("entry_paths") or [])[:1]
                function["backend_coverage"] = _compact_json_value(
                    function.get("backend_coverage"), 300
                )
                function["diff_focus"] = {}
                for event in function.get("events", []):
                    if isinstance(event, dict):
                        event["expression"] = str(event.get("expression") or "")[:120]
        fitted["projection_truncated_sections"].append("minimal_semantic_projection")

    # Reconcile reference catalogs after deterministic array caps.
    included_event_refs = {
        str(event.get("event_id") or "")
        for function in fitted.get("functions", [])
        if isinstance(function, dict)
        for event in function.get("events", [])
        if isinstance(event, dict) and event.get("event_id")
    }
    included_claim_refs = {
        str(claim.get("claim_id") or "")
        for claim in fitted.get("semantic_claims", [])
        if isinstance(claim, dict) and claim.get("claim_id")
    }
    included_unknown_refs = {
        str(unknown.get("unknown_id") or "")
        for unknown in fitted.get("semantic_unknowns", [])
        if isinstance(unknown, dict) and unknown.get("unknown_id")
    }
    unit = fitted.get("audit_unit")
    if isinstance(unit, dict):
        unit["event_refs"] = [
            value for value in unit.get("event_refs", []) if value in included_event_refs
        ]
        unit["claim_refs"] = [
            value for value in unit.get("claim_refs", []) if value in included_claim_refs
        ]
        unit["unknown_refs"] = [
            value for value in unit.get("unknown_refs", []) if value in included_unknown_refs
        ]
    allowed_evidence: Set[str] = set()
    for function in fitted.get("functions", []):
        if not isinstance(function, dict):
            continue
        for event in function.get("events", []):
            if isinstance(event, dict) and event.get("evidence_ref"):
                allowed_evidence.add(str(event["evidence_ref"]))
    for collection in (fitted.get("semantic_claims", []), fitted.get("semantic_unknowns", [])):
        for item in collection if isinstance(collection, list) else []:
            if isinstance(item, dict):
                allowed_evidence.update(
                    str(value) for value in item.get("evidence_refs", []) if str(value)
                )
    fitted["allowed_evidence_refs"] = sorted(allowed_evidence)
    estimated = discovery_projection_tokens(fitted)
    fitted["projection_estimated_tokens"] = estimated
    estimated = discovery_projection_tokens(fitted)
    fitted["projection_estimated_tokens"] = estimated
    if estimated > max_tokens:
        raise ValueError(
            f"candidate-blind audit unit exceeds {max_tokens}-token initial context limit"
        )
    assert_candidate_blind_projection(fitted)
    return fitted


class SemanticEnrichmentAgent(JsonToolAgent):
    """Strict one-pass semantic-claim delta producer for a selected unit."""

    def __init__(self, llm_client: Any):
        super().__init__(
            name="security_semantic_enricher",
            description="Adds evidence-referenced semantic claims to one risky audit unit.",
            llm_client=llm_client,
            tools=[],
        )

    def run(self, input_data: Dict[str, Any]) -> AgentResponse:
        projection = input_data.get("projection")
        if not isinstance(projection, Mapping):
            return AgentResponse(
                success=False,
                data={},
                error="security semantic enrichment requires a projection object",
            )
        return self.run_projection(
            projection,
            max_iterations=int(input_data.get("max_iterations") or 1),
        )

    def run_projection(
        self,
        projection: Mapping[str, Any],
        *,
        max_iterations: int = 1,
    ) -> AgentResponse:
        projection = fit_candidate_blind_prompt_projection(projection, max_tokens=24_000)
        unit = projection.get("audit_unit") or {}
        prompt = "Produce a strict semantic_claim_delta for this unit.\n" + json.dumps(
            projection, ensure_ascii=False, sort_keys=True
        )
        return self._run_json_conversation(
            self._messages({"agent_contract": SEMANTIC_ENRICHMENT_CONTRACT}, prompt),
            extractor=lambda content, result, conversation: self._extract_valid_payload(
                content,
                result,
                conversation,
                validator=self._is_delta,
            ),
            trace_label=f"unit={unit.get('unit_id') or ''}; skill=semantic_enrichment",
            parse_label="semantic_claim_delta JSON",
            retry_prompt="Emit exactly one strict semantic_claim_delta object.",
            max_iterations=max(1, int(max_iterations)),
            max_json_retries=0,
            fail_on_truncated=True,
            json_output_spec=JsonOutputSpec(
                type_name="semantic_claim_delta",
                schema=SEMANTIC_CLAIM_DELTA_JSON_SCHEMA,
                final_tool_name="emit_semantic_claim_delta",
                final_tool_description="Emit the strict evidence-backed semantic claim delta.",
                validator=self._is_delta,
                metadata_prefix="semantic_enrichment",
            ),
            require_structured_finalization=True,
            single_pass_final_tool=True,
        )

    @staticmethod
    def _is_delta(value: Any) -> bool:
        try:
            SemanticClaimDelta.from_dict(value)
            return True
        except (TypeError, ValueError):
            return False


SemanticDeltaRunner = Callable[[Mapping[str, Any], DiscoveryProfile], Any]


class SemanticMapEnricher:
    """Cacheable selective LLM enrichment over already selected risky units."""

    def __init__(
        self,
        *,
        profile: DiscoveryProfile,
        store: SecurityMapStore,
        model_identity: str,
        user_semantics_fingerprint: str,
        report_runner: Optional[SemanticDeltaRunner],
        mode: str = "shadow",
    ) -> None:
        self.profile = profile
        self.store = store
        self.model_identity = str(model_identity or "unknown")
        self.user_semantics_fingerprint = str(user_semantics_fingerprint or "")
        normalized_mode = str(mode or "shadow").strip().lower()
        self.mode = normalized_mode if normalized_mode in {"shadow", "active"} else "shadow"
        self.report_runner = report_runner

    @staticmethod
    def cache_key(
        unit: AuditUnit,
        *,
        model_identity: str,
        user_semantics_fingerprint: str,
        prompt_version: str = SEMANTIC_ENRICHMENT_PROMPT_VERSION,
    ) -> str:
        # Intentionally excludes deterministic rule catalogs/revisions.  A
        # semantic claim is invalidated by code/unit, model/prompt, selected
        # skills, or user semantic facts—not benchmark-oriented rule changes.
        payload = {
            "unit_fingerprint": unit.fingerprint,
            "model_identity": str(model_identity or "unknown"),
            "prompt_version": str(prompt_version),
            "skill_families": sorted(unit.skill_families),
            "user_semantics_fingerprint": str(user_semantics_fingerprint or ""),
        }
        return hashlib.sha256(_stable_json(payload).encode("utf-8")).hexdigest()

    def enrich(
        self,
        semantic_map: SecuritySemanticMap,
        units: Sequence[AuditUnit],
    ) -> Tuple[SecuritySemanticMap, Dict[str, Any], Tuple[SemanticClaimDelta, ...]]:
        deltas: List[SemanticClaimDelta] = []
        attempted = 0
        cache_hits = 0
        failures: List[Dict[str, str]] = []
        prompt_tokens = 0
        completion_tokens = 0
        total_tokens = 0
        uncovered_unit_ids: List[str] = []
        for unit_index, unit in enumerate(units):
            key = self.cache_key(
                unit,
                model_identity=self.model_identity,
                user_semantics_fingerprint=self.user_semantics_fingerprint,
            )
            delta = self.store.load_semantic_delta(key)
            if delta is not None:
                cache_hits += 1
            elif self.report_runner is None:
                uncovered_unit_ids.append(unit.unit_id)
                continue
            else:
                attempted += 1
                try:
                    projection = fit_candidate_blind_prompt_projection(
                        candidate_blind_prompt_projection(semantic_map, unit),
                        max_tokens=self.profile.max_initial_context_tokens,
                    )
                    raw = self.report_runner(projection, self.profile)
                    usage = ActiveDiscoveryCoordinator._response_usage(raw)
                    prompt_tokens += usage["prompt_tokens"]
                    completion_tokens += usage["completion_tokens"]
                    total_tokens += usage["total_tokens"]
                    delta = self._coerce_delta(raw)
                    self._validate_delta(delta, unit, projection)
                    self.store.save_semantic_delta(key, delta)
                except Exception as exc:
                    uncovered_unit_ids.append(unit.unit_id)
                    failures.append(
                        {
                            "unit_id": unit.unit_id,
                            "reason": f"{type(exc).__name__}: {exc}",
                        }
                    )
                    continue
            try:
                projection = fit_candidate_blind_prompt_projection(
                    candidate_blind_prompt_projection(semantic_map, unit),
                    max_tokens=self.profile.max_initial_context_tokens,
                )
                self._validate_delta(delta, unit, projection)
            except Exception as exc:
                uncovered_unit_ids.append(unit.unit_id)
                failures.append(
                    {
                        "unit_id": unit.unit_id,
                        "reason": f"cached_{type(exc).__name__}: {exc}",
                    }
                )
                continue
            deltas.append(delta)

        result_map = (
            semantic_map.with_semantic_deltas(deltas) if self.mode == "active" else semantic_map
        )
        state = {
            "mode": self.mode,
            "selected_unit_count": len(units),
            "attempted_unit_count": attempted,
            "cached_delta_count": cache_hits,
            "completed_delta_count": len(deltas),
            "claim_count": sum(len(delta.claims) for delta in deltas),
            "unknown_count": sum(len(delta.unknowns) for delta in deltas),
            "applied": self.mode == "active",
            "status": "partial" if failures or uncovered_unit_ids else "complete",
            "uncovered_unit_ids": list(dict.fromkeys(uncovered_unit_ids)),
            "failures": failures,
            "cumulative_prompt_tokens": prompt_tokens,
            "cumulative_completion_tokens": completion_tokens,
            "cumulative_total_tokens": total_tokens,
        }
        return result_map, state, tuple(deltas)

    @staticmethod
    def _coerce_delta(raw: Any) -> SemanticClaimDelta:
        if isinstance(raw, SemanticClaimDelta):
            return raw
        if isinstance(raw, AgentResponse):
            if not raw.success:
                raise ValueError(raw.error or "semantic enrichment agent failed")
            raw = raw.data
        if not isinstance(raw, Mapping):
            raise ValueError("semantic enrichment runner returned a non-object delta")
        return SemanticClaimDelta.from_dict(raw)

    @staticmethod
    def _validate_delta(
        delta: SemanticClaimDelta,
        unit: AuditUnit,
        projection: Mapping[str, Any],
    ) -> None:
        if delta.unit_id != unit.unit_id or delta.unit_fingerprint != unit.fingerprint:
            raise ValueError("semantic claim delta unit identity mismatch")
        allowed_subjects = set(unit.member_functions)
        allowed_evidence = set(projection.get("allowed_evidence_refs") or [])
        for claim in delta.claims:
            if claim.subject_uid not in allowed_subjects:
                raise ValueError("semantic claim delta references a function outside its unit")
            if claim.origin != "llm":
                raise ValueError("semantic claim delta must use origin=llm")
            if not set(claim.evidence_refs).issubset(allowed_evidence):
                raise ValueError("semantic claim delta cites unknown evidence")
        for unknown in delta.unknowns:
            if unknown.subject_uid not in allowed_subjects:
                raise ValueError("semantic unknown references a function outside its unit")
            if not set(unknown.evidence_refs).issubset(allowed_evidence):
                raise ValueError("semantic unknown cites unknown evidence")


def make_semantic_enrichment_runner(agent: SemanticEnrichmentAgent) -> SemanticDeltaRunner:
    def run(projection: Mapping[str, Any], profile: DiscoveryProfile) -> AgentResponse:
        return agent.run_projection(
            projection,
            max_iterations=max(1, profile.max_agent_iterations),
        )

    return run


class ActiveDiscoveryAgent(JsonToolAgent):
    """One strict, tool-free LLM pass for one pre-bounded audit unit."""

    def __init__(self, llm_client: Any):
        super().__init__(
            name="active_discovery",
            description="Independently audits one candidate-blind security semantic unit.",
            llm_client=llm_client,
            tools=[],
        )

    def run(self, input_data: Dict[str, Any]) -> AgentResponse:
        projection = input_data.get("projection")
        if not isinstance(projection, Mapping):
            return AgentResponse(
                success=False,
                data={},
                error="active discovery requires a projection object",
            )
        return self.run_projection(
            projection,
            max_iterations=int(input_data.get("max_iterations") or 1),
        )

    def run_projection(
        self,
        projection: Mapping[str, Any],
        *,
        max_iterations: int = 1,
    ) -> AgentResponse:
        projection = fit_candidate_blind_prompt_projection(
            projection,
            max_tokens=24_000,
        )
        audit_unit = projection.get("audit_unit") or {}
        prompt = (
            "Audit exactly this bounded semantic unit and emit a strict discovery_report.\n"
            + json.dumps(projection, ensure_ascii=False, sort_keys=True)
        )
        input_data = {"agent_contract": ACTIVE_DISCOVERY_CONTRACT}
        return self._run_json_conversation(
            self._messages(input_data, prompt),
            extractor=lambda content, result, conversation: self._extract_valid_payload(
                content,
                result,
                conversation,
                validator=self._is_discovery_report,
            ),
            trace_label=f"unit={audit_unit.get('unit_id') or ''}",
            parse_label="discovery_report JSON",
            retry_prompt="Emit exactly one strict discovery_report object for this audit unit.",
            max_iterations=max(1, int(max_iterations)),
            max_json_retries=0,
            fail_on_truncated=True,
            json_output_spec=JsonOutputSpec(
                type_name="discovery_report",
                schema=DISCOVERY_REPORT_JSON_SCHEMA,
                final_tool_name="emit_discovery_report",
                final_tool_description="Emit the strict candidate-blind discovery report.",
                validator=self._is_discovery_report,
                metadata_prefix="active_discovery",
            ),
            require_structured_finalization=True,
            single_pass_final_tool=True,
        )

    @staticmethod
    def _is_discovery_report(value: Any) -> bool:
        try:
            DiscoveryReport.from_dict(value)
            return True
        except (TypeError, ValueError):
            return False


ReportRunner = Callable[[Mapping[str, Any], DiscoveryProfile], Any]


class ActiveDiscoveryCoordinator:
    """Plan, cache, validate, persist, and register discovery hypotheses."""

    def __init__(
        self,
        *,
        profile: DiscoveryProfile,
        store: SecurityMapStore,
        registrar: CandidateRegistrar,
        report_runner: Optional[ReportRunner] = None,
        semantic_enricher: Optional[SemanticMapEnricher] = None,
        discovery_enabled: bool = True,
        visibility_mode: str = "active",
        rollout_stage: str = "unmanaged",
    ) -> None:
        self.profile = profile
        self.store = store
        self.registrar = registrar
        self.report_runner = report_runner
        self.semantic_enricher = semantic_enricher
        self.discovery_enabled = bool(discovery_enabled)
        normalized_visibility = str(visibility_mode or "active").strip().lower()
        self.visibility_mode = (
            normalized_visibility if normalized_visibility in {"active", "shadow"} else "shadow"
        )
        self.rollout_stage = str(rollout_stage or "unmanaged")

    def run(
        self,
        semantic_map: SecuritySemanticMap,
        *,
        covered_keys: Iterable[str] = (),
        known_variant_keys: Iterable[str] = (),
        export_path: Optional[Any] = None,
    ) -> Tuple[SecuritySemanticMap, Dict[str, Any]]:
        planner = CoverageGapPlanner(self.profile)
        covered_key_values = tuple(covered_keys)
        known_variant_key_values = tuple(known_variant_keys)
        units = planner.plan(
            semantic_map,
            covered_keys=covered_key_values,
            known_variant_keys=known_variant_key_values,
        )
        enrichment_state: Dict[str, Any] = {
            "mode": "disabled",
            "selected_unit_count": 0,
            "attempted_unit_count": 0,
            "completed_delta_count": 0,
            "claim_count": 0,
            "unknown_count": 0,
            "applied": False,
            "failures": [],
        }
        if self.semantic_enricher is not None and units:
            semantic_map, enrichment_state, _deltas = self.semantic_enricher.enrich(
                semantic_map,
                units,
            )
            # Active enrichment may introduce an unknown/conflict signal and
            # therefore change selection. Shadow mode intentionally leaves the
            # original plan and map untouched while still producing metrics.
            if enrichment_state.get("applied"):
                units = planner.plan(
                    semantic_map,
                    covered_keys=covered_key_values,
                    known_variant_keys=known_variant_key_values,
                )
        planned_map = semantic_map.with_audit_units(units)
        self.store.save_map(planned_map)
        reports: List[DiscoveryReport] = []
        cache_hits = 0
        attempted = 0
        failed: List[Dict[str, str]] = []
        registration = CandidateRegistrationResult(0, 0, 0, ())
        prompt_tokens = int(enrichment_state.get("cumulative_prompt_tokens", 0) or 0)
        completion_tokens = int(enrichment_state.get("cumulative_completion_tokens", 0) or 0)
        total_tokens = int(enrichment_state.get("cumulative_total_tokens", 0) or 0)
        context_tokens = 0

        discovery_units = units if self.discovery_enabled else []
        for unit_index, unit in enumerate(discovery_units):
            report = self._load_cached(unit)
            if report is not None:
                cache_hits += 1
            elif self.report_runner is None:
                continue
            else:
                attempted += 1
                projection = fit_candidate_blind_prompt_projection(
                    candidate_blind_prompt_projection(planned_map, unit),
                    max_tokens=self.profile.max_initial_context_tokens,
                )
                try:
                    raw = self.report_runner(projection, self.profile)
                    usage = self._response_usage(raw)
                    prompt_tokens += usage["prompt_tokens"]
                    completion_tokens += usage["completion_tokens"]
                    total_tokens += usage["total_tokens"]
                    context_tokens += usage["context_tokens"]
                    report = self._coerce_report(raw)
                    self._validate_report(report, unit, projection)
                    self.store.save_discovery_report(report)
                except Exception as exc:
                    failed.append(
                        {
                            "unit_id": unit.unit_id,
                            "reason": f"{type(exc).__name__}: {exc}",
                        }
                    )
                    logger.warning(
                        "[active-discovery] unit=%s failed: %s",
                        unit.unit_id,
                        exc,
                    )
                    continue
            # Cache rows predate this process and must pass the same current
            # contract before they are allowed to register obligations.
            projection = fit_candidate_blind_prompt_projection(
                candidate_blind_prompt_projection(planned_map, unit),
                max_tokens=self.profile.max_initial_context_tokens,
            )
            try:
                self._validate_report(report, unit, projection)
            except Exception as exc:
                failed.append(
                    {
                        "unit_id": unit.unit_id,
                        "reason": f"cached_{type(exc).__name__}: {exc}",
                    }
                )
                continue
            reports.append(report)
            result = self.registrar.register_issues(
                self._hypothesis_issues(report, unit, planned_map),
                source="active_discovery",
                default_entry_identity=(
                    unit.root_entries[0] if unit.root_entries else "__project__"
                ),
                force_unconfirmed=True,
            )
            registration = CandidateRegistrationResult(
                registration.submitted_issue_count + result.submitted_issue_count,
                registration.registered_occurrence_count + result.registered_occurrence_count,
                registration.new_validation_group_count + result.new_validation_group_count,
                tuple(dict.fromkeys((*registration.candidate_ids, *result.candidate_ids))),
            )

        if export_path is not None:
            self.store.export_json(planned_map, export_path, reports)
        state = {
            "enabled": self.profile.name != "fast",
            "profile": self.profile.name,
            "visibility_mode": self.visibility_mode,
            "discovery_enabled": self.discovery_enabled,
            "rollout_stage": self.rollout_stage,
            "status": (
                "partial"
                if (str(enrichment_state.get("status") or "").lower() == "partial")
                else (
                    "failed"
                    if failed and not reports and attempted
                    else (
                        "partial"
                        if failed
                        else (
                            "semantic_only"
                            if not self.discovery_enabled
                            else "planned" if self.report_runner is None else "complete"
                        )
                    )
                )
            ),
            "map_fingerprint": planned_map.map_fingerprint,
            "security_map_coverage": dict(planned_map.coverage),
            "reachable_function_count": len(planned_map.functions),
            "semantic_claim_count": len(planned_map.claims),
            "semantic_unknown_count": len(planned_map.unknowns),
            "planned_unit_count": len(units),
            "attempted_unit_count": attempted,
            "cached_report_count": cache_hits,
            "completed_report_count": len(reports),
            "hypothesis_count": sum(len(report.hypotheses) for report in reports),
            "registered_occurrence_count": registration.registered_occurrence_count,
            "new_validation_group_count": registration.new_validation_group_count,
            "uncovered_unit_ids": list(
                dict.fromkeys(
                    [
                        *list(enrichment_state.get("uncovered_unit_ids") or []),
                    ]
                )
            ),
            "failures": failed,
            "semantic_enrichment": enrichment_state,
            "llm_semantic_model_calls": int(enrichment_state.get("attempted_unit_count", 0) or 0),
            "llm_discovery_call_count": attempted,
            "cumulative_prompt_tokens": prompt_tokens,
            "cumulative_completion_tokens": completion_tokens,
            "cumulative_total_tokens": total_tokens,
            "context_tokens": context_tokens,
        }
        return planned_map, state

    def _load_cached(self, unit: AuditUnit) -> Optional[DiscoveryReport]:
        loader = getattr(self.store, "load_discovery_report", None)
        if not callable(loader):
            return None
        report = loader(unit.unit_id, unit.fingerprint)
        if not isinstance(report, DiscoveryReport):
            return None
        # A positive, evidence-backed hypothesis can be reused under the exact
        # immutable unit fingerprint.  Absence is weaker: cache it only when
        # the worker covered the whole unit and neither the map nor report
        # retained an unknown that could change the conclusion.
        if not report.hypotheses and (
            report.coverage_status != "complete"
            or bool(report.unresolved_facts)
            or bool(unit.unknown_refs)
        ):
            return None
        return report

    @staticmethod
    def _coerce_report(raw: Any) -> DiscoveryReport:
        if isinstance(raw, DiscoveryReport):
            return raw
        if isinstance(raw, AgentResponse):
            if not raw.success:
                raise ValueError(raw.error or "active discovery agent failed")
            raw = raw.data
        if not isinstance(raw, Mapping):
            raise ValueError("active discovery runner returned a non-object report")
        return DiscoveryReport.from_dict(raw)

    @staticmethod
    def _response_usage(raw: Any) -> Dict[str, int]:
        metadata = raw.metadata if isinstance(raw, AgentResponse) else {}
        metadata = metadata if isinstance(metadata, Mapping) else {}

        def number(*names: str) -> int:
            for name in names:
                value = metadata.get(name)
                if value not in (None, ""):
                    try:
                        return max(0, int(str(value)))
                    except (TypeError, ValueError):
                        continue
            return 0

        prompt = number("cumulative_prompt_tokens", "prompt_tokens")
        completion = number("cumulative_completion_tokens", "completion_tokens")
        total = number("cumulative_total_tokens", "total_tokens") or prompt + completion
        return {
            "prompt_tokens": prompt,
            "completion_tokens": completion,
            "total_tokens": total,
            "context_tokens": number("context_tokens", "estimated_context_tokens"),
        }

    def _validate_report(
        self,
        report: DiscoveryReport,
        unit: AuditUnit,
        projection: Mapping[str, Any],
    ) -> None:
        if report.unit_id != unit.unit_id or report.unit_fingerprint != unit.fingerprint:
            raise ValueError("discovery report unit identity mismatch")
        member_ids = set(unit.member_functions)
        if not set(report.reviewed_function_uids).issubset(member_ids):
            raise ValueError("discovery report references a function outside its audit unit")
        if not set(report.reviewed_claim_ids).issubset(set(unit.claim_refs)):
            raise ValueError("discovery report references a claim outside its audit unit")
        allowed = set(projection.get("allowed_evidence_refs") or [])
        if not set(report.tool_evidence_refs).issubset(allowed):
            raise ValueError("discovery report contains evidence outside the prompt projection")
        if len(report.hypotheses) > self.profile.max_hypotheses_per_unit:
            raise ValueError("discovery report exceeded hypothesis budget")
        for hypothesis in report.hypotheses:
            if hypothesis.function not in member_ids:
                raise ValueError("discovery hypothesis references a function outside its unit")
            source = str(hypothesis.source or "").strip()
            sink = str(hypothesis.sink or "").strip()
            resource = str(hypothesis.resource or "").strip()
            if not resource and not (source and sink):
                raise ValueError("discovery hypothesis requires source and sink or a resource")
            if not set(hypothesis.positive_evidence_refs).issubset(allowed):
                raise ValueError("discovery hypothesis cites unknown positive evidence")
            if not set(hypothesis.negative_evidence_refs).issubset(allowed):
                raise ValueError("discovery hypothesis cites unknown negative evidence")

    def _hypothesis_issues(
        self,
        report: DiscoveryReport,
        unit: AuditUnit,
        semantic_map: SecuritySemanticMap,
    ) -> List[Dict[str, Any]]:
        records = {item.function_uid: item for item in semantic_map.functions}
        issues: List[Dict[str, Any]] = []
        for hypothesis in report.hypotheses:
            record = records.get(hypothesis.function)
            entry_paths = [list(path) for path in hypothesis.entry_paths]
            if not entry_paths and record is not None:
                entry_paths = [list(path) for path in record.entry_paths]
            entry_identity = (
                unit.root_entries[0]
                if unit.root_entries
                else (
                    record.entry_identities[0]
                    if record and record.entry_identities
                    else "__project__"
                )
            )
            issues.append(
                {
                    "id": hypothesis.hypothesis_id,
                    "candidate_id": hypothesis.hypothesis_id,
                    "candidate_kind": "llm_active_discovery_hypothesis",
                    "candidate_source": "active_discovery",
                    "category": hypothesis.defect_class,
                    "subcategory": hypothesis.defect_class,
                    "defect_class": hypothesis.defect_class,
                    "impact_level": hypothesis.impact_level,
                    "confidence": hypothesis.confidence,
                    "rule_confidence": hypothesis.confidence,
                    "function": hypothesis.function,
                    "location": hypothesis.location,
                    "source": hypothesis.source,
                    "sink": hypothesis.sink,
                    "resource": hypothesis.resource,
                    "description": hypothesis.description,
                    "reasoning": hypothesis.reasoning,
                    "root_cause": hypothesis.root_cause,
                    "path_conditions": list(hypothesis.path_conditions),
                    "positive_evidence": list(hypothesis.positive_evidence_refs),
                    "negative_evidence": list(hypothesis.negative_evidence_refs),
                    "missing_fact_kinds": list(hypothesis.missing_fact_kinds),
                    "entry_paths": entry_paths,
                    "call_paths": entry_paths,
                    "entry_identity": entry_identity,
                    "discovery_status": "hypothesis",
                    "candidate_disposition": "needs_review",
                    "rollout_visibility": self.visibility_mode,
                    "rollout_stage": self.rollout_stage,
                    "candidate_promotion_eligible": self.visibility_mode == "active",
                    "candidate_promotion_reason": (
                        "active_discovery_rollout_active"
                        if self.visibility_mode == "active"
                        else "active_discovery_rollout_shadow"
                    ),
                    "candidate_promotion_terminal_status": (
                        "candidate" if self.visibility_mode == "active" else "shadow_observation"
                    ),
                    "security_obligation": {
                        "kind": "active_discovery_hypothesis",
                        "unit_id": unit.unit_id,
                        "unit_fingerprint": unit.fingerprint,
                        "requires_validator": True,
                    },
                    "attribution": {
                        "schema_version": "zscope.finding-attribution.v1",
                        "discovered_by": ["llm_active_discovery"],
                        "discovery_details": [
                            {
                                "kind": "llm_active_discovery",
                                "source_id": unit.unit_id,
                                "unit_id": unit.unit_id,
                                "unit_fingerprint": unit.fingerprint,
                                "report_schema": report.schema_version,
                                "coverage_status": report.coverage_status,
                            }
                        ],
                        "decided_by": "unresolved",
                        "decision_level": "none",
                    },
                    "evidence_pack": {
                        "producer": "active_discovery",
                        "discovery_report_schema": report.schema_version,
                        "audit_unit_id": unit.unit_id,
                        "audit_unit_fingerprint": unit.fingerprint,
                        "function_uid": hypothesis.function,
                        "positive_evidence": list(hypothesis.positive_evidence_refs),
                        "negative_evidence": list(hypothesis.negative_evidence_refs),
                        "missing_fact_kinds": list(hypothesis.missing_fact_kinds),
                        "coverage_status": report.coverage_status,
                        "candidate_blind_projection": True,
                    },
                }
            )
        return issues


def make_agent_report_runner(agent: ActiveDiscoveryAgent) -> ReportRunner:
    def run(projection: Mapping[str, Any], profile: DiscoveryProfile) -> AgentResponse:
        return agent.run_projection(
            projection,
            max_iterations=max(1, profile.max_agent_iterations),
        )

    return run


def _strip_forbidden_prompt_keys(value: Any) -> Any:
    if isinstance(value, Mapping):
        result: Dict[str, Any] = {}
        for key, nested in value.items():
            normalized = str(key).strip().lower().replace("-", "_")
            if any(part in normalized for part in _FORBIDDEN_PROMPT_KEY_PARTS):
                continue
            if normalized in {
                "risk",
                "risk_score",
                "risk_level",
                "severity",
                "priority_score",
                "priority_reasons",
            }:
                continue
            result[str(key)] = _strip_forbidden_prompt_keys(nested)
        return result
    if isinstance(value, (list, tuple)):
        return [_strip_forbidden_prompt_keys(item) for item in value]
    if isinstance(value, str) and _contains_forbidden_prompt_value(value):
        return "[redacted-sensitive-value]"
    return value


def _contains_forbidden_prompt_value(value: str) -> bool:
    normalized = str(value or "").strip().lower().replace("-", "_").replace(" ", "_")
    if normalized in _FORBIDDEN_PROMPT_EXACT_VALUES:
        return True
    return any(pattern.search(value) is not None for pattern in _FORBIDDEN_PROMPT_VALUE_PATTERNS)


def _compact_json_value(value: Any, max_chars: int) -> Any:
    if isinstance(value, Mapping):
        compact: Dict[str, Any] = {}
        for key in sorted(value, key=str):
            compact[str(key)] = _compact_json_value(value[key], max(80, max_chars // 2))
            if len(_stable_json(compact)) >= max_chars:
                break
        return compact
    if isinstance(value, (list, tuple)):
        compact_list: List[Any] = []
        for item in value:
            compact_list.append(_compact_json_value(item, max(80, max_chars // 2)))
            if len(_stable_json(compact_list)) >= max_chars:
                break
        return compact_list
    if isinstance(value, str):
        return value[:max_chars]
    return value


def _normalize_key(value: Any) -> str:
    return " ".join(str(value or "").strip().lower().replace("\\", "/").split())


def _candidate_event_family(record: Any, payload: Mapping[str, Any]) -> str:
    text = " ".join(
        str(value or "").lower()
        for value in (
            getattr(getattr(record, "ticket", None), "skill", ""),
            getattr(record, "defect_class", ""),
            payload.get("category"),
            payload.get("subcategory"),
            payload.get("defect_class"),
        )
    )
    policies = (
        ("memory_bounds", ("bound", "overflow", "buffer", "integer", "copy")),
        ("resource_lifecycle", ("resource", "ownership", "leak", "free", "uaf")),
        ("callback_concurrency", ("callback", "concurr", "race", "lock", "thread")),
        ("auth_boundary", ("auth", "permission", "tenant", "role")),
        ("sensitive_sink", ("inject", "command", "sql", "path", "ssrf", "deserial")),
        ("state_protocol", ("state", "protocol", "lifecycle")),
    )
    for family, markers in policies:
        if any(marker in text for marker in markers):
            return family
    return ""


def _stable_json(value: Any) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    )


__all__ = [
    "ACTIVE_DISCOVERY_CONTRACT",
    "ActiveDiscoveryAgent",
    "ActiveDiscoveryCoordinator",
    "AUDIT_RISK_WEIGHTS",
    "CoverageGapPlanner",
    "DISCOVERY_PROFILES",
    "DiscoveryProfile",
    "assert_candidate_blind_projection",
    "audit_unit_risk_score",
    "candidate_blind_prompt_projection",
    "candidate_coverage_keys",
    "historical_variant_keys",
    "discovery_projection_tokens",
    "fit_candidate_blind_prompt_projection",
    "make_agent_report_runner",
    "resolve_discovery_profile",
]
