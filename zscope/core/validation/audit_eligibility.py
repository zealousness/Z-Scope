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
from dataclasses import asdict, dataclass, replace
from functools import lru_cache
from types import MappingProxyType
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
_HUNTER_OFFER_FIELDS = frozenset(
    {
        "schema_version",
        "protocol_revision",
        "offer_uid",
        "audit_unit_uid",
        "defect_family",
        "subject_uid",
        "decision_region_uid",
        "location",
        "source_ref",
        "sink_ref",
        "resource_ref",
        "proof_ir",
        "proof_obligation",
        "evidence_actions",
        "supporting_fact_refs",
        "opposing_fact_refs",
        "unknown_fact_refs",
        "evidence_refs",
        "dependency_hashes",
        "content_sha256",
    }
)
_HUNTER_LOCATION_FIELDS = frozenset(
    {"file", "function_uid", "start_line", "end_line", "statement_uid"}
)
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_DETERMINISTIC_RULE_SOURCES = {
    "cpp_regex": "regex_local_rule",
    "cpp_clang_cfg": "clang_ast_cfg",
    "cpp_clang_matcher": "clang_ast_matcher",
    "cpp_graph": "graph_rule",
    "java_local": "java_local_rule",
}


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


def _deterministic_rule_producer_binding(
    issue: Mapping[str, Any],
    *,
    rule_id: str,
    revision: int,
) -> str:
    """Bind a qualified rule to the detector that actually emitted it.

    A model or backend signal may repeat a catalogued ``rule_id`` in its
    output.  The qualification belongs to the deterministic implementation,
    not to that label, so the live candidate must carry the exact producer
    source and Registrar attribution for the canonical rule.
    """

    try:
        descriptor = RuleCatalog.builtin().get(rule_id)
    except (OSError, TypeError, ValueError):
        return ""
    if descriptor is None or descriptor.id != rule_id or descriptor.revision != revision:
        return ""
    expected_source = _DETERMINISTIC_RULE_SOURCES.get(descriptor.engine, "")
    source = str(issue.get("candidate_source") or issue.get("origin") or "").strip().lower()
    if not expected_source or source != expected_source:
        return ""

    evidence = _mapping(issue.get("evidence_pack"))
    identity_values = {
        str(value).strip()
        for value in (
            issue.get("native_rule_id"),
            issue.get("rule_id"),
            evidence.get("native_rule_id"),
            evidence.get("rule_id"),
        )
        if _nonempty(value)
    }
    if identity_values != {rule_id}:
        return ""
    revision_values: set[int] = set()
    for raw in (issue.get("rule_revision"), evidence.get("rule_revision")):
        if raw in (None, ""):
            continue
        if isinstance(raw, bool) or not isinstance(raw, (int, str)):
            return ""
        if isinstance(raw, str) and not raw.isdecimal():
            return ""
        revision_values.add(int(raw))
    if revision_values != {revision}:
        return ""

    attribution = _mapping(issue.get("attribution"))
    discovered_by = attribution.get("discovered_by")
    details = attribution.get("discovery_details")
    if (
        not isinstance(discovered_by, list)
        or "deterministic_rule" not in discovered_by
        or not isinstance(details, list)
    ):
        return ""
    matching_details = [
        value
        for value in details
        if isinstance(value, Mapping)
        and value.get("kind") == "deterministic_rule"
        and value.get("source_id") == rule_id
    ]
    if len(matching_details) != 1:
        return ""
    return _sha256(
        {
            "rule_id": rule_id,
            "revision": revision,
            "engine": descriptor.engine,
            "candidate_source": source,
            "attribution": matching_details[0],
        }
    )


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
        load_runtime_successor_qualification,
    )

    raw = load_runtime_successor_qualification()
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


def _hunter_offer_binding(
    issue: Mapping[str, Any],
    *,
    offer: Mapping[str, Any],
    hypothesis: Mapping[str, Any],
    proof_ir: Mapping[str, Any],
    obligation: Mapping[str, Any],
    action_catalog: Sequence[Mapping[str, Any]],
    selected_action_uids: Sequence[str],
) -> str:
    """Rebuild the exact P4 producer offer and selected hypothesis.

    ``hypothesis_offer`` is copied from the system-owned planner before the
    strict Hunter selection is registered.  The model-facing report contract
    can select only identifiers from that object and cannot replace proof
    artifacts.  This verifier treats the copied offer as the immutable
    producer domain, but still rebuilds both seals from the current Proof IR,
    obligation, catalog, and selected hypothesis instead of accepting either
    content hash as a receipt.

    The surrounding candidate artifact/root supplies the persistence trust
    boundary.  This check is intentionally not described as protection from
    an actor able to rewrite and re-root the entire sealed artifact.
    """

    from .proof_kernel.canonical import seal_mapping, verify_sealed_mapping

    valid, _ = verify_sealed_mapping(
        offer,
        uid_field="offer_uid",
        prefix="HOFFER_",
        expected_keys=_HUNTER_OFFER_FIELDS,
    )
    if (
        not valid
        or offer.get("schema_version") != "zscope.hypothesis-offer.v2"
        or offer.get("protocol_revision") != 2
        or offer.get("proof_ir") != proof_ir
        or offer.get("proof_obligation") != obligation
        or offer.get("evidence_actions") != [dict(value) for value in action_catalog]
        or set(map(str, offer.get("dependency_hashes") or []))
        != set(map(str, proof_ir.get("dependency_hashes") or []))
    ):
        return ""

    location = _mapping(offer.get("location"))
    if set(location) != _HUNTER_LOCATION_FIELDS or any(
        not _nonempty(location.get(name)) for name in ("file", "function_uid", "statement_uid")
    ):
        return ""
    if not offer.get("resource_ref") and not (offer.get("source_ref") and offer.get("sink_ref")):
        return ""

    def strict_strings(name: str, *, required: bool = False) -> list[str] | None:
        raw = offer.get(name)
        if (
            not isinstance(raw, list)
            or (required and not raw)
            or any(not isinstance(value, str) or not value for value in raw)
            or raw != sorted(set(raw))
        ):
            return None
        return list(raw)

    supporting = strict_strings("supporting_fact_refs")
    opposing = strict_strings("opposing_fact_refs")
    unknown = strict_strings("unknown_fact_refs")
    evidence = strict_strings("evidence_refs", required=True)
    dependencies = strict_strings("dependency_hashes", required=True)
    if None in (supporting, opposing, unknown, evidence, dependencies):
        return ""
    if any(
        not _nonempty(offer.get(name))
        for name in (
            "audit_unit_uid",
            "defect_family",
            "subject_uid",
            "decision_region_uid",
        )
    ):
        return ""

    rebuilt_offer = seal_mapping(
        {
            "schema_version": "zscope.hypothesis-offer.v2",
            "protocol_revision": 2,
            "audit_unit_uid": str(offer["audit_unit_uid"]),
            "defect_family": str(offer["defect_family"]),
            "subject_uid": str(offer["subject_uid"]),
            "decision_region_uid": str(offer["decision_region_uid"]),
            "location": dict(location),
            "source_ref": offer.get("source_ref"),
            "sink_ref": offer.get("sink_ref"),
            "resource_ref": offer.get("resource_ref"),
            "proof_ir": dict(proof_ir),
            "proof_obligation": dict(obligation),
            "evidence_actions": [dict(value) for value in action_catalog],
            "supporting_fact_refs": supporting,
            "opposing_fact_refs": opposing,
            "unknown_fact_refs": unknown,
            "evidence_refs": evidence,
            "dependency_hashes": dependencies,
        },
        uid_field="offer_uid",
        prefix="HOFFER_",
    )
    if rebuilt_offer != dict(offer):
        return ""

    selected = sorted(set(map(str, selected_action_uids)))
    hypothesis_lists: dict[str, list[str]] = {}
    for name, allowed in (
        ("supporting_fact_refs", supporting),
        ("opposing_fact_refs", opposing),
        ("unknown_fact_refs", unknown),
        ("evidence_refs", evidence),
    ):
        raw = hypothesis.get(name)
        if (
            not isinstance(raw, list)
            or any(not isinstance(value, str) or not value for value in raw)
            or raw != sorted(set(raw))
            or not set(raw) <= set(allowed or [])
        ):
            return ""
        hypothesis_lists[name] = list(raw)
    if not hypothesis_lists["evidence_refs"]:
        return ""

    rebuilt_hypothesis = seal_mapping(
        {
            "schema_version": "zscope.security-hypothesis.v2",
            "protocol_revision": 2,
            "audit_unit_uid": str(offer["audit_unit_uid"]),
            "offer_uid": str(offer["offer_uid"]),
            "defect_family": str(offer["defect_family"]),
            "subject_uid": str(offer["subject_uid"]),
            "decision_region_uid": str(offer["decision_region_uid"]),
            "location": dict(location),
            "source_ref": offer.get("source_ref"),
            "sink_ref": offer.get("sink_ref"),
            "resource_ref": offer.get("resource_ref"),
            "confirmation_clauses": [
                dict(value) for value in obligation.get("confirmation_clauses") or []
            ],
            "counterproof_clauses": [
                dict(value) for value in obligation.get("counterproof_clauses") or []
            ],
            "open_clauses": [dict(value) for value in obligation.get("open_clauses") or []],
            **hypothesis_lists,
            "evidence_action_uids": selected,
            "dependency_hashes": dependencies,
            "origin": "hypothesis_hunter",
        },
        uid_field="hypothesis_uid",
        prefix="HYP_",
    )
    if rebuilt_hypothesis != dict(hypothesis):
        return ""

    attribution = _mapping(issue.get("attribution"))
    discovered_by = attribution.get("discovered_by")
    details = attribution.get("discovery_details")
    matching = [
        value
        for value in details or []
        if isinstance(value, Mapping)
        and value.get("kind") == "hypothesis_hunter"
        and value.get("source_id") == offer.get("offer_uid")
    ]
    if (
        not isinstance(discovered_by, list)
        or "hypothesis_hunter" not in discovered_by
        or not isinstance(details, list)
        or len(matching) != 1
    ):
        return ""
    return _sha256(
        {
            "offer_uid": str(offer["offer_uid"]),
            "offer_sha256": str(offer["content_sha256"]),
            "hypothesis_uid": str(hypothesis["hypothesis_uid"]),
            "hypothesis_sha256": str(hypothesis["content_sha256"]),
            "selected_action_uids": selected,
            "attribution": dict(matching[0]),
        }
    )


def _v4_occurrence_binding(
    issue: Mapping[str, Any],
    *,
    proof_ir: Mapping[str, Any],
    obligation: Mapping[str, Any],
    action_catalog: Sequence[Mapping[str, Any]],
    hunter_hypothesis: Mapping[str, Any] | None = None,
) -> str:
    """Bind the live candidate occurrence to one sealed FunctionIR statement.

    Proof hashes are not occurrence provenance by themselves: the same valid
    Proof IR could otherwise be attached to a candidate at another file,
    function, or line.  The ordinary candidate anchor is required to resolve
    to exactly one statement in the sealed summary's event domain.  Hunter
    candidates additionally carry a sealed statement identity and must match
    it byte-for-byte.
    """

    from ...orchestration.candidate_envelope import (
        concrete_candidate_occurrence_anchor,
    )

    anchor = concrete_candidate_occurrence_anchor(issue)
    functions = proof_ir.get("functions")
    if anchor is None or not isinstance(functions, list) or len(functions) != 1:
        return ""
    summary = functions[0]
    if not isinstance(summary, Mapping):
        return ""
    file_path, function_uid, line = anchor
    if file_path != summary.get("file") or function_uid != summary.get("function_uid"):
        return ""

    events = tuple(event for event in summary.get("events") or [] if isinstance(event, Mapping))
    line_events = tuple(
        event
        for event in events
        if isinstance(event.get("attributes"), Mapping)
        and not isinstance(event["attributes"].get("source_line"), bool)
        and int(event["attributes"].get("source_line") or 0) == line
        and str(event.get("statement_uid") or "")
    )
    statement_uids = {str(event.get("statement_uid") or "") for event in line_events}
    if len(statement_uids) != 1:
        return ""
    statement_uid = next(iter(statement_uids))
    statement_occurrences = sum(
        list(node.get("statement_uids") or []).count(statement_uid)
        for node in summary.get("cfg_nodes") or []
        if isinstance(node, Mapping) and isinstance(node.get("statement_uids"), list)
    )
    if statement_occurrences != 1:
        return ""

    hunter_location: Mapping[str, Any] = {}
    if hunter_hypothesis is not None:
        hunter_location = _mapping(hunter_hypothesis.get("location"))
        if (
            dict(_mapping(issue.get("location"))) != dict(hunter_location)
            or hunter_location.get("file") != file_path
            or int(hunter_location.get("start_line") or 0) != line
            or int(hunter_location.get("end_line") or 0) != line
            or hunter_location.get("statement_uid") != statement_uid
        ):
            return ""
    else:
        # Product candidates must bind the top-level occurrence to the
        # structured source/sink obligation and then to a concrete witness
        # referenced by the frozen EvidenceAction catalog.  A unique but
        # unrelated event on the same line is not provenance for this
        # candidate.
        source = _mapping(issue.get("source"))
        sink = _mapping(issue.get("sink"))
        if not source or not sink:
            return ""

        def endpoint_line(endpoint: Mapping[str, Any]) -> int:
            raw = endpoint.get("line") or endpoint.get("start_line") or 0
            if isinstance(raw, bool):
                return 0
            try:
                return int(raw)
            except (TypeError, ValueError):
                return 0

        endpoint_lines: list[int] = []
        subject_uid = str(obligation.get("subject_uid") or "")
        if not subject_uid:
            return ""
        for endpoint in (source, sink):
            endpoint_file = str(endpoint.get("file") or endpoint.get("path") or "")
            endpoint_function = str(endpoint.get("function") or endpoint.get("function_uid") or "")
            if endpoint_file and endpoint_file != file_path:
                return ""
            if endpoint_function and endpoint_function != function_uid:
                return ""
            current_line = endpoint_line(endpoint)
            if current_line > 0:
                endpoint_lines.append(current_line)
            endpoint_subjects = {
                str(endpoint.get(key) or "")
                for key in (
                    "resource",
                    "resource_uid",
                    "subject_uid",
                    "value_uid",
                    "object_uid",
                    "thread_object",
                )
                if _nonempty(endpoint.get(key))
            }
            if endpoint_subjects and subject_uid not in endpoint_subjects:
                return ""
        if line not in endpoint_lines:
            return ""

        explicit_subjects = {
            str(issue.get(key) or "")
            for key in ("resource_identity", "thread_object", "subject_uid", "resource")
            if _nonempty(issue.get(key))
        }
        if explicit_subjects and subject_uid not in explicit_subjects:
            return ""

        def frozen_strings(value: Any) -> set[str]:
            if isinstance(value, Mapping):
                values: set[str] = set()
                for child in value.values():
                    values.update(frozen_strings(child))
                return values
            if isinstance(value, (list, tuple)):
                values = set()
                for child in value:
                    values.update(frozen_strings(child))
                return values
            return {value} if isinstance(value, str) and value else set()

        subject_actions = tuple(
            action
            for action in action_catalog
            if isinstance(action, Mapping) and str(action.get("subject_uid") or "") == subject_uid
        )
        if not subject_actions:
            return ""
        action_witness_refs = set().union(
            *(frozen_strings(action.get("fixed_parameters")) for action in subject_actions)
        )
        line_witness_uids = {
            str(value)
            for event in line_events
            for value in (
                event.get("event_uid"),
                event.get("statement_uid"),
                event.get("node_uid"),
            )
            if _nonempty(value)
        }
        referenced_line_events = tuple(
            event
            for event in line_events
            if str(event.get("event_uid") or "") in action_witness_refs
            or str(event.get("statement_uid") or "") in action_witness_refs
            or str(event.get("node_uid") or "") in action_witness_refs
        )
        if not referenced_line_events or any(
            str(event.get("statement_uid") or "") != statement_uid
            for event in referenced_line_events
        ):
            return ""
        relevant_action_uids = sorted(
            str(action.get("action_uid") or "")
            for action in subject_actions
            if frozen_strings(action.get("fixed_parameters")) & line_witness_uids
        )
        if not relevant_action_uids:
            return ""
    return _sha256(
        {
            "proof_ir_sha256": str(proof_ir.get("content_sha256") or ""),
            "summary_sha256": str(summary.get("content_sha256") or ""),
            "file": file_path,
            "function": function_uid,
            "line": line,
            "statement_uid": statement_uid,
            "obligation_uid": str(obligation.get("obligation_uid") or ""),
            "subject_uid": str(obligation.get("subject_uid") or ""),
            "relevant_action_uids": (relevant_action_uids if hunter_hypothesis is None else []),
            "hunter_location_sha256": (
                _sha256(hunter_location) if hunter_hypothesis is not None else ""
            ),
        }
    )


def _product_candidate_binding(
    issue: Mapping[str, Any],
    *,
    proof_ir: Mapping[str, Any],
    proof_obligation: Mapping[str, Any],
    selected_action_uids: Sequence[str] | None,
) -> str:
    """Rebuild the live product identity that authorized one v4 obligation.

    P2 qualification proves that the reducer is sound; it does not allow an
    arbitrary candidate to attach a qualified ProofIR.  Product candidates
    therefore have to carry the Registrar envelope plus the independently
    rebuildable SecurityObligation used by ``FunctionIRFactService``.
    """

    try:
        from ..candidates.decision_facts import (
            DecisionFactGraph,
            SECURITY_OBLIGATION_VERSION,
            security_obligation_for,
        )
        from .fact_capabilities import FunctionIRFactService
        from .proof_kernel import ProofKernelEngine
        from ...orchestration.candidate_envelope import (
            CANDIDATE_SCHEMA_VERSION,
            CandidateEnvelope,
        )
    except ImportError:
        return ""
    if (
        issue.get("proof_kernel_input_origin") != "product_composite_obligation_v4"
        or issue.get("security_obligation_v1") is not True
        or issue.get("candidate_schema_version") != CANDIDATE_SCHEMA_VERSION
    ):
        return ""
    project_id = str(issue.get("project_id") or "")
    revision = str(issue.get("revision") or "")
    if not project_id or not revision:
        return ""

    # Every field below is a projection produced by CandidateEnvelope or the
    # decision-fact attachment step.  Keeping even one of them on the input
    # would let CandidateEnvelope.from_issue take its trusted-identity fast
    # path, or let a coordinated re-seal feed its own digest back into the
    # rebuild.  MappingProxyType also makes the absence of mutation authority
    # explicit at this reporting boundary.
    projected_fields = {
        "candidate_schema_version",
        "candidate_uid",
        "occurrence_uid",
        "history_key",
        "evidence_hash",
        "decision_evidence_hash",
        "provenance_hash",
        "validation_cluster_uid",
        "run_issue_uid",
        "context_signature",
        "obligation_uid",
        "obligation_shape",
        "decision_fact_version",
        "decision_context_version",
        "project_id",
        "revision",
        "defect_class",
        "source_identity",
        "sink_identity",
        "resource_identity",
        "evidence_models",
        "evidence_sources",
        "entry_paths",
        "record_role",
        "candidate_disposition",
        "evidence_completeness",
        "security_obligation",
        "decision_fact_slice",
        "decision_fact_coverage",
        "obligation_required_fact_kinds",
        "missing_fact_kinds",
        "candidate_promotion_eligible",
        "candidate_promotion_reason",
        "candidate_promotion_terminal_status",
    }
    raw_candidate = {
        str(key): value for key, value in issue.items() if str(key) not in projected_fields
    }
    entry_function = str(
        issue.get("entry_identity")
        or issue.get("entry_function")
        or issue.get("analyzed_from")
        or ""
    )
    project_root = str(issue.get("project_root") or "")
    try:
        base_envelope = CandidateEnvelope.from_issue(
            MappingProxyType(raw_candidate),
            project_id=project_id,
            project_root=project_root,
            revision=revision,
            entry_function=entry_function,
            default_disposition="needs_review",
        )
    except (KeyError, TypeError, ValueError):
        return ""

    source_uid = base_envelope.source_identity
    sink_uid = base_envelope.sink_identity
    subject_uid = base_envelope.resource_identity or base_envelope.source_identity
    defect_family = base_envelope.defect_class
    if not source_uid or not sink_uid or not subject_uid or not defect_family:
        return ""

    governed_candidate = dict(raw_candidate)
    governed_candidate.update(
        {
            "project_id": base_envelope.project_id,
            "revision": base_envelope.revision,
            "defect_class": defect_family,
            "source_identity": source_uid,
            "sink_identity": sink_uid,
            "resource_identity": base_envelope.resource_identity,
        }
    )
    raw_security = _mapping(issue.get("security_obligation"))
    try:
        expected_security_object = security_obligation_for(
            MappingProxyType(governed_candidate),
            project_id=base_envelope.project_id,
            revision=base_envelope.revision,
            defect_family=defect_family,
            source_uid=source_uid,
            sink_uid=sink_uid,
            subject_uid=subject_uid,
        )
    except (KeyError, TypeError, ValueError):
        return ""

    raw_fact_slice = issue.get("decision_fact_slice")
    raw_security_fact_slice = raw_security.get("decision_fact_slice")
    if issue.get("decision_fact_graph_v1") is True:
        try:
            fact_slice = DecisionFactGraph.from_issue(
                MappingProxyType(governed_candidate)
            ).slice_for(expected_security_object)
        except (KeyError, TypeError, ValueError):
            return ""
        expected_security_object = replace(
            expected_security_object,
            decision_fact_slice=fact_slice,
        )
        expected_fact_slice: Any = fact_slice.to_dict()
        if _canonical(raw_fact_slice) != _canonical(expected_fact_slice) or _canonical(
            raw_security_fact_slice
        ) != _canonical(expected_fact_slice):
            return ""
        governed_candidate["decision_fact_slice"] = expected_fact_slice
        governed_candidate["decision_fact_coverage"] = fact_slice.coverage
        governed_candidate["missing_fact_kinds"] = list(fact_slice.missing_fact_kinds)
    elif raw_fact_slice not in (None, {}) or raw_security_fact_slice is not None:
        # A fact slice without the governed producer flag is an untrusted
        # projection.  It cannot become decision identity merely by being
        # hashed together with a coordinated CandidateEnvelope re-seal.
        return ""

    expected_security = expected_security_object.to_dict()
    if expected_security.get("version") != SECURITY_OBLIGATION_VERSION or _canonical(
        raw_security
    ) != _canonical(expected_security):
        return ""
    governed_candidate.update(
        {
            "security_obligation": expected_security,
            "security_obligation_v1": True,
            "obligation_shape": expected_security_object.obligation_shape,
            "obligation_required_fact_kinds": list(expected_security_object.required_fact_kinds),
        }
    )

    # Recompute the complete envelope a second time using only the
    # independently rebuilt decision-fact slice.  This is what prevents an
    # attacker from changing a slice and coherently re-sealing every dependent
    # candidate ID.
    try:
        expected_envelope = CandidateEnvelope.from_issue(
            MappingProxyType(governed_candidate),
            project_id=project_id,
            project_root=project_root,
            revision=revision,
            entry_function=entry_function,
            default_disposition="needs_review",
        )
    except (KeyError, TypeError, ValueError):
        return ""
    claimed_identity = {
        "schema_version": issue.get("candidate_schema_version"),
        "candidate_uid": issue.get("candidate_uid"),
        "occurrence_uid": issue.get("occurrence_uid"),
        "history_key": issue.get("history_key"),
        "evidence_hash": issue.get("evidence_hash"),
        "decision_evidence_hash": issue.get("decision_evidence_hash"),
        "provenance_hash": issue.get("provenance_hash"),
        "validation_cluster_uid": issue.get("validation_cluster_uid"),
        "project_id": issue.get("project_id"),
        "revision": issue.get("revision"),
        "defect_class": issue.get("defect_class"),
        "source_identity": issue.get("source_identity"),
        "sink_identity": issue.get("sink_identity"),
        "resource_identity": issue.get("resource_identity"),
        "context_signature": issue.get("context_signature"),
        "obligation_uid": issue.get("obligation_uid"),
        "obligation_shape": issue.get("obligation_shape"),
        "decision_fact_version": issue.get("decision_fact_version"),
        "decision_context_version": issue.get("decision_context_version"),
    }
    expected_identity = {key: expected_envelope.to_dict()[key] for key in claimed_identity}
    if _canonical(claimed_identity) != _canonical(expected_identity):
        return ""

    # The envelope and SecurityObligation are only the candidate side of the
    # authority.  Rebuild the entire composite obligation from the current
    # FunctionIR, then require the attached IR and full clause set to be exact.
    # A live partial state may choose a subset of those confirmation actions;
    # it may not shrink the underlying obligation and re-seal the smaller set.
    proof_free_candidate = {
        key: value
        for key, value in governed_candidate.items()
        if not key.startswith("proof_kernel_")
        and not key.startswith("terminal_authority")
        and not key.startswith("promotion_certificate")
    }
    proof_free_candidate.update(
        {
            "candidate_schema_version": expected_envelope.schema_version,
            "candidate_uid": expected_envelope.candidate_uid,
            "occurrence_uid": expected_envelope.occurrence_uid,
            "history_key": expected_envelope.history_key,
            "evidence_hash": expected_envelope.evidence_hash,
            "decision_evidence_hash": expected_envelope.decision_evidence_hash,
            "provenance_hash": expected_envelope.provenance_hash,
            "validation_cluster_uid": expected_envelope.validation_cluster_uid,
            "context_signature": expected_envelope.context_signature,
            "obligation_uid": expected_envelope.obligation_uid,
            "obligation_shape": expected_envelope.obligation_shape,
            "decision_fact_version": expected_envelope.decision_fact_version,
            "decision_context_version": expected_envelope.decision_context_version,
        }
    )
    rebuilt = FunctionIRFactService(None, enabled=False).build_composite_proof_input(
        MappingProxyType(proof_free_candidate),
        _mapping(proof_free_candidate.get("evidence_pack")),
    )
    if (
        rebuilt is None
        or _canonical(proof_ir) != _canonical(rebuilt.get("proof_ir"))
        or _canonical(proof_obligation) != _canonical(rebuilt.get("proof_obligation"))
    ):
        return ""

    rebuilt_obligation = _mapping(rebuilt.get("proof_obligation"))
    rebuilt_selection = tuple(str(value) for value in rebuilt.get("selected_action_uids") or [])
    rebuild_binding = _sha256(
        {
            "candidate_schema_version": CANDIDATE_SCHEMA_VERSION,
            "candidate_identity": expected_identity,
            "source_uid": source_uid,
            "sink_uid": sink_uid,
            "subject_uid": subject_uid,
            "defect_family": defect_family,
            "security_obligation": expected_security,
            "proof_ir_sha256": str(proof_ir.get("content_sha256") or ""),
            "proof_obligation_uid": str(proof_obligation.get("obligation_uid") or ""),
            "full_selected_action_uids": sorted(
                str(value) for value in rebuilt.get("selected_action_uids") or []
            ),
        }
    )
    if selected_action_uids is None:
        return rebuild_binding

    confirmation_clause_uids = {
        str(_mapping(value).get("clause_uid") or "")
        for value in _sequence(rebuilt_obligation.get("confirmation_clauses"))
        if _nonempty(_mapping(value).get("clause_uid"))
    }
    try:
        rebuilt_catalog = ProofKernelEngine().action_catalog(
            proof_ir=_mapping(rebuilt.get("proof_ir")),
            obligation=rebuilt_obligation,
        )
    except (KeyError, TypeError, ValueError):
        return ""
    allowed_confirmation_actions = {
        str(value.get("action_uid") or "")
        for value in rebuilt_catalog
        if str(value.get("clause_uid") or "") in confirmation_clause_uids
        and _nonempty(value.get("action_uid"))
    }
    counterproof_clause_uids = {
        str(_mapping(value).get("clause_uid") or "")
        for value in _sequence(rebuilt_obligation.get("counterproof_clauses"))
        if _nonempty(_mapping(value).get("clause_uid"))
    }
    required_counterproof_actions = {
        str(value.get("action_uid") or "")
        for value in rebuilt_catalog
        if str(value.get("clause_uid") or "") in counterproof_clause_uids
        and _nonempty(value.get("action_uid"))
    }
    raw_selection = tuple(str(value) for value in selected_action_uids)
    raw_action_uids = set(raw_selection)
    if (
        len(raw_selection) != len(raw_action_uids)
        or not required_counterproof_actions <= raw_action_uids
        or not raw_action_uids <= allowed_confirmation_actions | required_counterproof_actions
    ):
        return ""
    return _sha256(
        {
            "product_rebuild_binding_sha256": rebuild_binding,
            "live_selected_action_uids": sorted(raw_selection),
        }
    )


def _product_candidate_rebuild_binding(
    issue: Mapping[str, Any],
    *,
    proof_ir: Mapping[str, Any],
    proof_obligation: Mapping[str, Any],
) -> str:
    """Verify product identity and the full rebuilt obligation, not a live subset."""

    return _product_candidate_binding(
        issue,
        proof_ir=proof_ir,
        proof_obligation=proof_obligation,
        selected_action_uids=None,
    )


def revalidate_v4_producer_occurrence_binding(
    issue: Mapping[str, Any],
) -> tuple[str, str]:
    """Rebuild the producer and concrete occurrence behind one v4 input.

    Proof Kernel objects are intentionally self-sealing, so their hashes prove
    internal consistency rather than candidate provenance.  Every live or
    reporting authority boundary must independently rebuild these two hashes
    from the system-owned product/Hunter producer objects and the concrete
    FunctionIR occurrence.  Callers must compare both returned values to the
    two values stored on ``issue``; an empty value is always fail closed.

    Hunter V2/V3 re-entry may extend the live action selection.  Its producer
    identity remains the selection frozen in the sealed hypothesis, while the
    current input must retain that selection and stay inside the same catalog.
    """

    try:
        from .proof_kernel import PROOF_KERNEL_AUTHORITY_INPUT_VERSION, ProofKernelEngine
        from .proof_kernel.models import validate_obligation, validate_program_ir

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
            return "", ""
        proof_ir = _mapping(raw_input.get("proof_ir"))
        obligation = _mapping(raw_input.get("proof_obligation"))
        valid_ir, _ = validate_program_ir(proof_ir)
        valid_obligation, _ = validate_obligation(obligation)
        raw_selection = raw_input.get("selected_action_uids")
        if (
            not valid_ir
            or not valid_obligation
            or not isinstance(raw_selection, list)
            or any(not isinstance(value, str) or not value for value in raw_selection)
            or len(raw_selection) != len(set(raw_selection))
        ):
            return "", ""
        selected_action_uids = tuple(raw_selection)
        catalog = ProofKernelEngine().action_catalog(
            proof_ir=proof_ir,
            obligation=obligation,
        )
        catalog_action_uids = {
            str(value.get("action_uid") or "")
            for value in catalog
            if _nonempty(value.get("action_uid"))
        }
        if not set(selected_action_uids) <= catalog_action_uids:
            return "", ""

        source = str(issue.get("candidate_source") or issue.get("origin") or "").lower()
        hunter_hypothesis: Mapping[str, Any] | None = None
        if source == "hypothesis_hunter":
            hunter_hypothesis = _mapping(issue.get("security_hypothesis"))
            offer = _mapping(issue.get("hypothesis_offer"))
            hypothesis_selection = hunter_hypothesis.get("evidence_action_uids")
            if (
                not _strict_hunter_hypothesis(hunter_hypothesis)
                or not isinstance(hypothesis_selection, list)
                or any(not isinstance(value, str) or not value for value in hypothesis_selection)
                or len(hypothesis_selection) != len(set(hypothesis_selection))
                or not set(hypothesis_selection) <= set(selected_action_uids)
            ):
                return "", ""
            producer_binding = _hunter_offer_binding(
                issue,
                offer=offer,
                hypothesis=hunter_hypothesis,
                proof_ir=proof_ir,
                obligation=obligation,
                action_catalog=catalog,
                selected_action_uids=tuple(hypothesis_selection),
            )
        else:
            producer_binding = _product_candidate_rebuild_binding(
                issue,
                proof_ir=proof_ir,
                proof_obligation=obligation,
            )
        if not producer_binding:
            return "", ""
        occurrence_binding = _v4_occurrence_binding(
            issue,
            proof_ir=proof_ir,
            obligation=obligation,
            action_catalog=catalog,
            hunter_hypothesis=hunter_hypothesis,
        )
        if not occurrence_binding:
            return "", ""
        return producer_binding, occurrence_binding
    except (ImportError, KeyError, OSError, RuntimeError, TypeError, ValueError):
        return "", ""


def has_exact_v4_producer_occurrence_binding(issue: Mapping[str, Any]) -> bool:
    """Return whether both stored provenance hashes exactly rebuild now."""

    producer_binding, occurrence_binding = revalidate_v4_producer_occurrence_binding(issue)
    return bool(
        producer_binding
        and occurrence_binding
        and issue.get("proof_kernel_producer_binding_sha256") == producer_binding
        and issue.get("proof_kernel_occurrence_binding_sha256") == occurrence_binding
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
            freeze_proof_state,
            reduce_proof_closure,
        )
        from .proof_kernel.models import (
            validate_check_result,
            validate_obligation,
            validate_program_ir,
        )

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
        raw_selection = raw_input.get("selected_action_uids")
        if (
            not isinstance(raw_selection, list)
            or any(not isinstance(value, str) or not value for value in raw_selection)
            or len(raw_selection) != len(set(raw_selection))
        ):
            return ""
        initial_selection = tuple(sorted(raw_selection))
        if initial_selection != state.selected_action_uids:
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
        raw_checker_results = issue.get("proof_kernel_checker_results")
        if not isinstance(raw_checker_results, list) or any(
            not isinstance(value, Mapping) for value in raw_checker_results
        ):
            return ""
        checker_results = tuple(dict(value) for value in raw_checker_results)
        check_uids: list[str] = []
        for result in checker_results:
            valid, _ = validate_check_result(result)
            check_uid = str(result.get("check_uid") or "")
            if not valid or not check_uid:
                return ""
            check_uids.append(check_uid)
        if len(check_uids) != len(set(check_uids)):
            return ""
        recomputed = ProofKernelEngine().reevaluate_authority_input(raw_input)
        if (
            recomputed.frozen_state.to_dict() != state.to_dict()
            or recomputed.closure_evaluation.to_dict() != closure.to_dict()
            or tuple(recomputed.check_results) != checker_results
            or tuple(sorted(recomputed.selected_action_uids)) != initial_selection
        ):
            return ""
        counterproof_clause_uids = {
            str(value.get("clause_uid") or "")
            for value in obligation.get("counterproof_clauses") or []
            if isinstance(value, Mapping) and _nonempty(value.get("clause_uid"))
        }
        executable_counterproof_actions = {
            str(action.get("action_uid") or ""): str(action.get("clause_uid") or "")
            for action in catalog
            if isinstance(action, Mapping)
            and str(action.get("clause_uid") or "") in counterproof_clause_uids
            and _nonempty(action.get("action_uid"))
        }
        checked_counterproof_actions = {
            str(result.get("action_uid") or ""): str(result.get("clause_uid") or "")
            for result in checker_results
            if str(result.get("clause_uid") or "") in counterproof_clause_uids
            and _nonempty(result.get("action_uid"))
        }
        if (
            not set(executable_counterproof_actions) <= set(initial_selection)
            or executable_counterproof_actions != checked_counterproof_actions
        ):
            return ""
        rebuilt_state = freeze_proof_state(
            proof_ir=proof_ir,
            obligation=obligation,
            action_catalog=catalog,
            selected_action_uids=initial_selection,
            check_results=checker_results,
            checker_result_refs=state.checker_result_refs,
            root_manifest_sha256=state.root_manifest_sha256,
        )
        if rebuilt_state.to_dict() != state.to_dict():
            return ""
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
        hypothesis: Mapping[str, Any] | None = None
        producer_binding = ""
        if source == "hypothesis_hunter":
            hypothesis = _mapping(issue.get("security_hypothesis"))
            offer = _mapping(issue.get("hypothesis_offer"))
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
            offer_binding = _hunter_offer_binding(
                issue,
                offer=offer,
                hypothesis=hypothesis,
                proof_ir=proof_ir,
                obligation=obligation,
                action_catalog=catalog,
                selected_action_uids=initial_selection,
            )
            if not offer_binding:
                return ""
            producer_binding = _sha256(
                {
                    "producer": "hypothesis_hunter",
                    "offer_binding_sha256": offer_binding,
                    "p4_hypothesis_qualification_sha256": p4_sha256,
                }
            )
        else:
            producer_binding = _product_candidate_binding(
                issue,
                proof_ir=proof_ir,
                proof_obligation=obligation,
                selected_action_uids=initial_selection,
            )
            if not producer_binding:
                return ""
        occurrence_binding = _v4_occurrence_binding(
            issue,
            proof_ir=proof_ir,
            obligation=obligation,
            action_catalog=catalog,
            hunter_hypothesis=hypothesis,
        )
        if not occurrence_binding:
            return ""
        return _sha256(
            {
                "successor_qualification_sha256": successor_sha256,
                "proof_state_sha256": state.content_sha256,
                "closure_evaluation_sha256": closure.content_sha256,
                "obligation_sha256": state.obligation_sha256,
                "proof_ir_sha256": state.proof_ir_sha256,
                "candidate_occurrence_binding_sha256": occurrence_binding,
                "candidate_producer_binding_sha256": producer_binding,
                "p4_hypothesis_qualification_sha256": (
                    p4_sha256 if source == "hypothesis_hunter" else ""
                ),
            }
        )
    except (ImportError, KeyError, OSError, RuntimeError, TypeError, ValueError):
        return ""


def _qualification_binding(issue: Mapping[str, Any]) -> str:
    """Bind a reducer-verified v4 producer path and optional rule identity.

    A deterministic rule identity is evidence provenance, not proof authority.
    It may strengthen an already reducer-verified v4 envelope, but can never
    authorize an actionable record by itself.  This keeps rule-backed and
    model-backed candidates on the same fail-closed Promotion/Proof path.
    """

    rule_id, revision = _rule_identity(issue)
    rule_binding = ""
    if rule_id and revision > 0:
        try:
            qualification = str(_qualified_rule_bindings().get((rule_id, revision)) or "")
            producer = _deterministic_rule_producer_binding(
                issue,
                rule_id=rule_id,
                revision=revision,
            )
            if qualification and producer:
                rule_binding = _sha256(
                    {
                        "rule_qualification_sha256": qualification,
                        "deterministic_producer_binding_sha256": producer,
                    }
                )
        except (OSError, TypeError, ValueError):
            rule_binding = ""
    v4_binding = _v4_qualification_binding(issue)
    if not v4_binding:
        return ""
    if rule_binding and v4_binding:
        return _sha256(
            {
                "rule_qualification_sha256": rule_binding,
                "v4_successor_qualification_sha256": v4_binding,
            }
        )
    return v4_binding


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


def _recomputed_executable_fact_kinds(
    issue: Mapping[str, Any],
    open_clauses: Sequence[str],
) -> set[str]:
    """Recompute local executable capabilities from sealed FunctionIR.

    Candidate/model fields such as ``validator_evidence_actions``,
    ``fact_capabilities`` and ``proof_clause_action_plan`` are projections for
    reporting.  They are not eligibility authority and can be stale or
    model-authored.  The audit boundary therefore rebuilds capabilities from
    the current subject/region and FunctionIR graph.
    """

    try:
        from .fact_capabilities import FactCapabilityRegistry, FunctionIRFactService
    except ImportError:
        return set()
    clause_to_fact: dict[str, str] = {}
    raw_input = _mapping(issue.get("proof_kernel_input"))
    obligation = _mapping(raw_input.get("proof_obligation"))
    for role in ("confirmation_clauses", "counterproof_clauses", "open_clauses"):
        for raw_clause in _sequence(obligation.get(role)):
            clause = _mapping(raw_clause)
            clause_uid = str(clause.get("clause_uid") or "").strip()
            fact_kind = str(clause.get("fact_kind") or "").strip()
            if clause_uid and fact_kind:
                clause_to_fact[clause_uid] = fact_kind
    requested = {
        clause_to_fact.get(str(value).strip(), str(value).strip())
        for value in open_clauses
        if str(value).strip()
    }
    if not requested:
        return set()
    try:
        registry = FactCapabilityRegistry(FunctionIRFactService(None, enabled=False))
        capabilities = registry.inspect(
            issue,
            _mapping(issue.get("evidence_pack")),
            requested,
        )
    except (KeyError, OSError, RuntimeError, TypeError, ValueError):
        return set()
    return {
        str(value.fact_kind)
        for value in capabilities
        if value.supported is True and value.executable_for_subject_region is True
    }


def _executable_open_clauses(issue: Mapping[str, Any], open_clauses: Sequence[str]) -> set[str]:
    raw_input = _mapping(issue.get("proof_kernel_input"))
    obligation = _mapping(raw_input.get("proof_obligation"))
    clause_to_fact = {
        str(clause.get("clause_uid") or "").strip(): str(clause.get("fact_kind") or "").strip()
        for role in ("confirmation_clauses", "counterproof_clauses", "open_clauses")
        for clause in (_mapping(value) for value in _sequence(obligation.get(role)))
        if _nonempty(clause.get("clause_uid")) and _nonempty(clause.get("fact_kind"))
    }
    recomputed_fact_kinds = _recomputed_executable_fact_kinds(issue, open_clauses)
    recomputed = {
        clause
        for clause in open_clauses
        if clause in recomputed_fact_kinds or clause_to_fact.get(clause) in recomputed_fact_kinds
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
    return (recomputed | frozen_executable).intersection(set(open_clauses))


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
