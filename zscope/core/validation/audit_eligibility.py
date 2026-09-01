"""Answer-free classification of unresolved security obligations.

``needs_review`` is a user-actionable security view, not a catch-all bucket for
every broad hint or failed proof attempt.  This module separates an unresolved
but falsifiable obligation from an audit-only observation before reporting and
before any downstream quality evaluation can run.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import asdict, dataclass
from functools import lru_cache
from typing import Any, Mapping, Sequence

from ...rules.catalog import RuleCatalog
from ...rules.qualification import QualificationRegistry


AUDIT_ELIGIBILITY_VERSION = "zscope.audit-eligibility.v1"
AUDIT_ONLY_DISPOSITION = "shadow_observation"

_HUNTER_HYPOTHESIS_FIELDS = frozenset(
    {
        "schema_version",
        "protocol_revision",
        "hypothesis_uid",
        "audit_unit_uid",
        "offer_uid",
        "defect_family",
        "subject_uid",
        "decision_region_uid",
        "location",
        "source_ref",
        "sink_ref",
        "resource_ref",
        "confirmation_clauses",
        "counterproof_clauses",
        "open_clauses",
        "supporting_fact_refs",
        "opposing_fact_refs",
        "unknown_fact_refs",
        "evidence_action_uids",
        "evidence_refs",
        "dependency_hashes",
        "origin",
        "content_sha256",
    }
)
_HUNTER_LOCATION_FIELDS = frozenset(
    {"file", "function_uid", "start_line", "end_line", "statement_uid"}
)
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


def _mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _sequence(value: Any) -> Sequence[Any]:
    return value if isinstance(value, (list, tuple)) else ()


def _canonical(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str)


def _sha256(value: Any) -> str:
    return hashlib.sha256(_canonical(value).encode("utf-8")).hexdigest()


def _nonempty(value: Any) -> bool:
    return bool(str(value or "").strip())


def _source_file(issue: Mapping[str, Any]) -> str:
    for key in ("file", "file_path", "module_path"):
        if _nonempty(issue.get(key)):
            return str(issue[key]).strip()
    location = issue.get("location")
    if isinstance(location, Mapping):
        return str(location.get("file") or location.get("path") or "").strip()
    if isinstance(location, str):
        match = re.match(r"^(?P<file>.+?):\d+(?::\d+)?$", location.strip())
        return match.group("file") if match else ""
    return ""


def _source_line(issue: Mapping[str, Any]) -> int:
    for key in ("line", "start_line"):
        try:
            value = int(issue.get(key) or 0)
        except (TypeError, ValueError):
            value = 0
        if value > 0:
            return value
    location = issue.get("location")
    if isinstance(location, Mapping):
        try:
            return max(0, int(location.get("line") or location.get("start_line") or 0))
        except (TypeError, ValueError):
            return 0
    if isinstance(location, str):
        match = re.match(r"^.+?:(?P<line>\d+)(?::\d+)?$", location.strip())
        return int(match.group("line")) if match else 0
    return 0


def _subject(issue: Mapping[str, Any]) -> str:
    obligation = _mapping(issue.get("security_obligation"))
    for owner, keys in (
        (
            obligation,
            ("subject_uid", "source_uid", "sink_uid"),
        ),
        (
            issue,
            (
                "subject_uid",
                "resource_identity",
                "resource_signature",
                "source_identity",
                "sink_identity",
            ),
        ),
    ):
        for key in keys:
            if _nonempty(owner.get(key)):
                return str(owner[key]).strip()
    return ""


def _rule_identity(issue: Mapping[str, Any]) -> tuple[str, int]:
    evidence = _mapping(issue.get("evidence_pack"))
    rule_id = str(
        issue.get("native_rule_id")
        or issue.get("rule_id")
        or issue.get("rule")
        or evidence.get("native_rule_id")
        or evidence.get("rule_id")
        or ""
    ).strip()
    try:
        revision = int(issue.get("rule_revision") or evidence.get("rule_revision") or 0)
    except (TypeError, ValueError):
        revision = 0
    return rule_id, max(0, revision)


@lru_cache(maxsize=1)
def _qualified_rule_bindings() -> Mapping[tuple[str, int], str]:
    catalog = RuleCatalog.builtin()
    registry = QualificationRegistry.builtin(catalog=catalog)
    return {
        key: _sha256(
            {
                "qualification_registry_sha256": registry.source_sha256,
                "rule_id": record.rule_id,
                "revision": record.revision,
                "evidence_sha256": record.evidence_sha256,
            }
        )
        for key, record in registry.records.items()
        if record.state == "qualified"
        and record.evidence_verified
        and _nonempty(record.evidence_sha256)
    }


@lru_cache(maxsize=1)
def _successor_runtime_binding() -> tuple[str, str, str]:
    """Load the exact fresh local successor without granting phase authority.

    The loader revalidates all source and dependency hashes.  Keeping this a
    lazy import avoids making the reporting classifier part of the validation
    package's import graph.
    """

    from ...orchestration.proof_promotion_qualification import (
        load_successor_qualification,
    )

    raw = load_successor_qualification()
    protocol = _mapping(raw.get("protocol_identity"))
    dependencies = _mapping(raw.get("qualification_dependencies"))
    if (
        raw.get("status") != "local_candidate_qualified"
        or raw.get("requires_independent_review") is not True
        or raw.get("authorizes_phase_completion") is not False
        or protocol.get("terminal_authority_decision_schema")
        != "zscope.terminal-authority-decision.v4"
        or protocol.get("hypothesis_hunter_effect") != "candidate_registration_only"
    ):
        raise ValueError("successor_runtime_qualification_boundary_invalid")
    return (
        str(raw["content_sha256"]),
        str(dependencies["p4_hypothesis_qualification_sha256"]),
        str(protocol["hypothesis_hunter_effect"]),
    )


def _strict_hunter_hypothesis(raw: Mapping[str, Any]) -> bool:
    """Validate the sealed P4 envelope without importing the shadow package.

    P5's lifecycle contract deliberately prevents live validation/reporting
    modules from importing P4 implementation code.  The v4 successor hashes
    that implementation and its schema; this local parser only verifies the
    immutable, source-independent envelope before binding it to the current
    obligation below.
    """

    from .proof_kernel.canonical import verify_sealed_mapping

    valid, _ = verify_sealed_mapping(
        raw,
        uid_field="hypothesis_uid",
        prefix="HYP_",
        expected_keys=_HUNTER_HYPOTHESIS_FIELDS,
    )
    if not valid:
        return False
    if (
        raw.get("schema_version") != "zscope.security-hypothesis.v2"
        or raw.get("protocol_revision") != 2
        or raw.get("origin") != "hypothesis_hunter"
    ):
        return False
    if any(
        not _nonempty(raw.get(name))
        for name in (
            "audit_unit_uid",
            "offer_uid",
            "defect_family",
            "subject_uid",
            "decision_region_uid",
        )
    ):
        return False
    location = _mapping(raw.get("location"))
    if set(location) != _HUNTER_LOCATION_FIELDS or any(
        not _nonempty(location.get(name)) for name in ("file", "function_uid", "statement_uid")
    ):
        return False
    try:
        start_line = int(location.get("start_line") or 0)
        end_line = int(location.get("end_line") or 0)
    except (TypeError, ValueError):
        return False
    if start_line <= 0 or end_line < start_line:
        return False
    if not raw.get("resource_ref") and not (raw.get("source_ref") and raw.get("sink_ref")):
        return False
    for name, required in (
        ("supporting_fact_refs", False),
        ("opposing_fact_refs", False),
        ("unknown_fact_refs", False),
        ("evidence_action_uids", True),
        ("evidence_refs", True),
    ):
        values = raw.get(name)
        if (
            not isinstance(values, list)
            or (required and not values)
            or len(values) != len(set(values))
            or any(not isinstance(value, str) or not value for value in values)
        ):
            return False
    dependencies = raw.get("dependency_hashes")
    if (
        not isinstance(dependencies, list)
        or not dependencies
        or len(dependencies) != len(set(dependencies))
        or any(_SHA256_RE.fullmatch(str(value)) is None for value in dependencies)
    ):
        return False
    return all(
        isinstance(raw.get(name), list)
        and all(isinstance(value, Mapping) for value in raw.get(name) or [])
        for name in ("confirmation_clauses", "counterproof_clauses", "open_clauses")
    )


def _v4_qualification_binding(issue: Mapping[str, Any]) -> str:
    """Return an exact candidate binding for a reducer-verified v4 envelope.

    Candidate source names, model attribution, and Validator history are not
    qualification evidence.  The current local successor plus a byte-sealed
    FrozenProofState/closure replay is the system-generated qualification for
    ordinary Validator, semantic, backend, LLM, and Hunter candidates.
    """

    try:
        from .proof_kernel import PROOF_KERNEL_AUTHORITY_INPUT_VERSION, ProofKernelEngine
        from .proof_kernel.closure import (
            FrozenProofState,
            ProofClosureEvaluation,
            reduce_proof_closure,
        )
        from .proof_kernel.models import validate_obligation, validate_program_ir

        successor_sha256, p4_sha256, hunter_effect = _successor_runtime_binding()
        raw_input = _mapping(issue.get("proof_kernel_input"))
        if (
            set(raw_input)
            != {
                "schema_version",
                "proof_ir",
                "proof_obligation",
                "selected_action_uids",
            }
            or raw_input.get("schema_version") != PROOF_KERNEL_AUTHORITY_INPUT_VERSION
        ):
            return ""
        proof_ir = _mapping(raw_input.get("proof_ir"))
        obligation = _mapping(raw_input.get("proof_obligation"))
        valid_ir, _ = validate_program_ir(proof_ir)
        valid_obligation, _ = validate_obligation(obligation)
        if not (valid_ir and valid_obligation):
            return ""
        state = FrozenProofState.from_mapping(_mapping(issue.get("proof_kernel_frozen_state")))
        closure = ProofClosureEvaluation.from_mapping(
            _mapping(issue.get("proof_kernel_closure_evaluation"))
        )
        if (
            closure.complete is not False
            or closure.disposition != "needs_review"
            or closure.integrity_status != "verified"
            or closure.failure_codes
            or closure.conflicting_clause_uids
            or closure.proof_state_sha256 != state.content_sha256
            or closure.obligation_uid != state.obligation_uid
            or closure.obligation_sha256 != state.obligation_sha256
            or closure.proof_ir_uid != state.proof_ir_uid
            or closure.proof_ir_sha256 != state.proof_ir_sha256
            or state.obligation_uid != obligation.get("obligation_uid")
            or state.obligation_sha256 != obligation.get("content_sha256")
            or state.proof_ir_uid != proof_ir.get("proof_ir_uid")
            or state.proof_ir_sha256 != proof_ir.get("content_sha256")
        ):
            return ""
        initial_selection = tuple(
            sorted({str(value) for value in _sequence(raw_input.get("selected_action_uids"))})
        )
        if not set(initial_selection) <= set(state.selected_action_uids):
            return ""
        catalog = ProofKernelEngine().action_catalog(
            proof_ir=proof_ir,
            obligation=obligation,
        )
        if tuple(sorted(str(value["action_uid"]) for value in catalog)) != (
            state.catalog_action_uids
        ) or tuple(sorted(str(value["clause_uid"]) for value in catalog)) != (
            state.catalog_clause_uids
        ):
            return ""
        checker_results = tuple(
            dict(value)
            for value in _sequence(issue.get("proof_kernel_checker_results"))
            if isinstance(value, Mapping)
        )
        replayed = reduce_proof_closure(
            frozen_state=state,
            proof_ir=proof_ir,
            obligation=obligation,
            action_catalog=catalog,
            check_results=checker_results,
        )
        if replayed.to_dict() != closure.to_dict():
            return ""
        source = str(issue.get("candidate_source") or issue.get("origin") or "").lower()
        if source == "hypothesis_hunter":
            hypothesis = _mapping(issue.get("security_hypothesis"))
            if (
                not _strict_hunter_hypothesis(hypothesis)
                or not p4_sha256
                or hunter_effect != "candidate_registration_only"
                or hypothesis.get("subject_uid") != obligation.get("subject_uid")
                or hypothesis.get("decision_region_uid") != obligation.get("decision_region_uid")
                or hypothesis.get("defect_family") != obligation.get("defect_family")
                or hypothesis.get("confirmation_clauses") != obligation.get("confirmation_clauses")
                or hypothesis.get("counterproof_clauses") != obligation.get("counterproof_clauses")
                or hypothesis.get("open_clauses") != obligation.get("open_clauses")
                or tuple(sorted(map(str, hypothesis.get("evidence_action_uids") or [])))
                != initial_selection
            ):
                return ""
        return _sha256(
            {
                "successor_qualification_sha256": successor_sha256,
                "proof_state_sha256": state.content_sha256,
                "closure_evaluation_sha256": closure.content_sha256,
                "obligation_sha256": state.obligation_sha256,
                "proof_ir_sha256": state.proof_ir_sha256,
                "p4_hypothesis_qualification_sha256": (
                    p4_sha256 if source == "hypothesis_hunter" else ""
                ),
            }
        )
    except (ImportError, KeyError, OSError, RuntimeError, TypeError, ValueError):
        return ""


def _qualification_binding(issue: Mapping[str, Any]) -> str:
    rule_id, revision = _rule_identity(issue)
    if rule_id:
        if revision <= 0:
            return ""
        try:
            return str(_qualified_rule_bindings().get((rule_id, revision)) or "")
        except (OSError, TypeError, ValueError):
            return ""
    return _v4_qualification_binding(issue)


def _qualification_backed(issue: Mapping[str, Any]) -> bool:
    return bool(_qualification_binding(issue))


def _required_clauses(issue: Mapping[str, Any]) -> tuple[str, ...]:
    frozen = _mapping(issue.get("proof_kernel_frozen_state") or issue.get("frozen_proof_state"))
    obligation = _mapping(issue.get("security_obligation"))
    closure = _mapping(issue.get("proof_closure_evaluation"))
    for raw in (
        [
            *_sequence(frozen.get("required_confirmation_clause_uids")),
            *_sequence(frozen.get("required_counterproof_clause_uids")),
        ],
        frozen.get("required_clauses"),
        closure.get("required_clauses"),
        obligation.get("required_fact_kinds"),
        issue.get("obligation_required_fact_kinds"),
    ):
        values = tuple(sorted({str(value).strip() for value in _sequence(raw) if _nonempty(value)}))
        if values:
            return values
    return ()


def _open_clauses(issue: Mapping[str, Any]) -> tuple[str, ...]:
    frozen = _mapping(issue.get("proof_kernel_frozen_state") or issue.get("frozen_proof_state"))
    closure = _mapping(
        issue.get("proof_kernel_closure_evaluation") or issue.get("proof_closure_evaluation")
    )
    evidence_closure = _mapping(issue.get("evidence_closure_state"))
    for raw in (
        closure.get("missing_clause_uids"),
        closure.get("missing_clauses"),
        frozen.get("open_clause_uids"),
        frozen.get("open_clauses"),
        evidence_closure.get("missing_fact_kinds"),
        issue.get("missing_fact_kinds"),
    ):
        values = tuple(sorted({str(value).strip() for value in _sequence(raw) if _nonempty(value)}))
        if values:
            return values
    return ()


def _executable_open_clauses(issue: Mapping[str, Any], open_clauses: Sequence[str]) -> set[str]:
    actions = _sequence(issue.get("validator_evidence_actions"))
    action_kinds = {
        str(_mapping(action).get("fact_kind") or "").strip()
        for action in actions
        if _nonempty(_mapping(action).get("action_id"))
        and _nonempty(_mapping(action).get("provider_id"))
        and _nonempty(_mapping(action).get("verifier_id"))
    }
    capabilities = _sequence(issue.get("fact_capabilities"))
    action_kinds.update(
        str(_mapping(capability).get("fact_kind") or "").strip()
        for capability in capabilities
        if _mapping(capability).get("supported") is True
        and _mapping(capability).get("executable_for_subject_region") is True
    )
    # A v4 frozen state may use clause IDs while actions remain fact-kind
    # keyed.  The optional mapping is produced by the reducer for this purpose.
    clause_plan = _mapping(issue.get("proof_clause_action_plan"))
    planned = {
        str(clause).strip()
        for clause, descriptor in clause_plan.items()
        if _mapping(descriptor).get("executable") is True
    }
    frozen = _mapping(issue.get("proof_kernel_frozen_state") or issue.get("frozen_proof_state"))
    catalog_actions = tuple(
        str(value) for value in _sequence(frozen.get("catalog_action_uids")) if _nonempty(value)
    )
    catalog_clauses = tuple(
        str(value) for value in _sequence(frozen.get("catalog_clause_uids")) if _nonempty(value)
    )
    # FrozenProofState guarantees one system-generated action per parallel
    # clause entry.  Presence in that catalog is the v4 executable-plan proof;
    # no model-authored action descriptor is trusted here.
    frozen_executable = {
        clause for action, clause in zip(catalog_actions, catalog_clauses) if action and clause
    }
    return (action_kinds | planned | frozen_executable).intersection(set(open_clauses))


def _is_refuted(issue: Mapping[str, Any]) -> bool:
    closure = _mapping(
        issue.get("proof_kernel_closure_evaluation") or issue.get("proof_closure_evaluation")
    )
    status = (
        str(
            closure.get("status")
            or closure.get("proof_closure_status")
            or closure.get("disposition")
            or issue.get("proof_closure_status")
            or ""
        )
        .strip()
        .lower()
    )
    if status in {"refuted", "contradicted", "conflicting", "invalid"}:
        return True
    return bool(
        closure.get("counterexample_present") is True
        or closure.get("accepted_counterproof_clause_uids")
        or closure.get("conflicting_clause_uids")
        or closure.get("conflicting_clauses")
        or issue.get("blocking_negative_evidence")
    )


@dataclass(frozen=True)
class AuditEligibilityEvaluation:
    needs_review_eligible: bool
    concrete_anchor: bool
    stable_defect_family: bool
    falsifiable_obligation: bool
    executable_proof_plan: bool
    qualification_backed: bool
    qualification_binding_sha256: str
    unrefuted: bool
    reason_codes: tuple[str, ...]
    input_sha256: str
    schema_version: str = AUDIT_ELIGIBILITY_VERSION

    @property
    def disposition(self) -> str:
        return "needs_review" if self.needs_review_eligible else AUDIT_ONLY_DISPOSITION

    def to_dict(self) -> dict[str, Any]:
        value = asdict(self)
        value["reason_codes"] = list(self.reason_codes)
        value["disposition"] = self.disposition
        return value


def evaluate_audit_eligibility(issue: Mapping[str, Any]) -> AuditEligibilityEvaluation:
    """Classify one unresolved candidate without Truth, score, or model prose."""

    obligation = _mapping(issue.get("security_obligation"))
    required = _required_clauses(issue)
    open_clauses = _open_clauses(issue)
    concrete_anchor = bool(
        _source_file(issue)
        and (_source_line(issue) > 0 or _nonempty(issue.get("function")))
        and _subject(issue)
    )
    family = (
        str(
            obligation.get("defect_family")
            or issue.get("defect_family")
            or issue.get("defect_class")
            or issue.get("category")
            or issue.get("cwe")
            or ""
        )
        .strip()
        .lower()
    )
    stable_family = bool(family and family not in {"unknown", "generic", "potential_issue"})
    obligation_uid = str(
        obligation.get("obligation_uid") or issue.get("obligation_uid") or ""
    ).strip()
    falsifiable = bool(obligation_uid and required and open_clauses)
    executable = bool(_executable_open_clauses(issue, open_clauses))
    qualification_binding = _qualification_binding(issue)
    qualified = bool(qualification_binding)
    unrefuted = not _is_refuted(issue)
    checks = {
        "concrete_anchor": concrete_anchor,
        "stable_defect_family": stable_family,
        "falsifiable_obligation": falsifiable,
        "executable_proof_plan": executable,
        "qualification_backed": qualified,
        "unrefuted": unrefuted,
    }
    reason_codes = tuple(
        f"AUDIT_{name.upper()}_MISSING" for name, passed in checks.items() if not passed
    )
    input_projection = {
        "file": _source_file(issue),
        "line": _source_line(issue),
        "function": str(issue.get("function") or ""),
        "subject": _subject(issue),
        "family": family,
        "obligation_uid": obligation_uid,
        "required_clauses": list(required),
        "open_clauses": list(open_clauses),
        "executable_open_clauses": sorted(_executable_open_clauses(issue, open_clauses)),
        "rule": list(_rule_identity(issue)),
        "qualification_binding_sha256": qualification_binding,
        "refuted": not unrefuted,
    }
    return AuditEligibilityEvaluation(
        needs_review_eligible=all(checks.values()),
        concrete_anchor=concrete_anchor,
        stable_defect_family=stable_family,
        falsifiable_obligation=falsifiable,
        executable_proof_plan=executable,
        qualification_backed=qualified,
        qualification_binding_sha256=qualification_binding,
        unrefuted=unrefuted,
        reason_codes=reason_codes,
        input_sha256=_sha256(input_projection),
    )
