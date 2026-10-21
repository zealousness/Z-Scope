"""Declarative offline boundary for an external investigation provider.

No provider code, SDK, command, environment, or credential is accepted here.
Only the program-owned D01 session can execute tools. Real providers stay
unsupported until an independent launcher can enforce the same restrictions.
The caller owns and closes the borrowed session; this adapter owns no process.
"""

from __future__ import annotations

import contextvars
import hashlib
import json
import math
import secrets
from dataclasses import dataclass, field
from typing import Any, Mapping

from ..common.cancellation import (
    CancellationError,
    CancellationToken,
    bind_cancellation_token,
    current_cancellation_token,
)
from ..semantics.security_map import AuditUnit, DiscoveryReport
from .active_discovery import assert_candidate_blind_projection
from .investigation import InvestigationError, InvestigationRequest, InvestigationSession

SCHEMA = "zscope.external-investigation.offline.v1"
TOOLS = frozenset(
    {"search_code", "read_code", "get_semantic_context", "query_code_graph", "trace_data_flow"}
)
MAX_BYTES = 2 * 1024 * 1024
_ACTIVE = contextvars.ContextVar("zscope_external_investigation_active", default=False)


class OfflineImportError(ValueError):
    """Source-free boundary failure; never include rejected provider content."""


def _json(value: Any) -> str:
    try:
        text = json.dumps(value, sort_keys=True, ensure_ascii=False, allow_nan=False)
        if len(text.encode("utf-8")) > MAX_BYTES:
            raise ValueError
        return text
    except (TypeError, ValueError, RecursionError):
        raise OfflineImportError("invalid_offline_object") from None


def _digest(value: Any) -> str:
    return hashlib.sha256(_json(value).encode("utf-8")).hexdigest()


def _object(value: Any, fields: set[str]) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        raise OfflineImportError("invalid_offline_shape")
    return value


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise OfflineImportError("duplicate_offline_key")
        value[key] = item
    return value


def _load(text: str) -> dict[str, Any]:
    if type(text) is not str or len(text.encode("utf-8")) > MAX_BYTES:
        raise OfflineImportError("invalid_offline_document")
    try:
        value = json.loads(text, object_pairs_hook=_pairs)
        _json(value)  # Reject non-finite numbers and bound canonical size too.
    except (ValueError, TypeError, RecursionError):
        raise OfflineImportError("invalid_offline_document") from None
    return _object(
        value, {"schema_version", "provider", "task_id", "task_fingerprint", "decisions"}
    )


def _binding(session: InvestigationSession) -> dict[str, Any]:
    manifest = session.manifest()
    return {
        name: manifest[name]
        for name in (
            "identity",
            "unit_id",
            "unit_fingerprint",
            "projection_hash",
            "effective_policy",
            "scopes",
        )
    }


@dataclass(frozen=True)
class ExternalInvestigationTask:
    """Program-created task capability; exported hashes alone grant no rights."""

    task_id: str
    binding_json: str
    unit_json: str
    projection_json: str
    proposition: str
    missing_facts: tuple[str, ...]
    allowed_tools: tuple[str, ...]
    max_steps: int = 4
    timeout_seconds: float = 120.0
    parent_depth: int = 0

    def __post_init__(self) -> None:
        if (
            not self.task_id
            or not isinstance(self.proposition, str)
            or not self.proposition.strip()
            or len(self.proposition) > 512
            or not self.missing_facts
            or len(self.missing_facts) > 16
            or any(
                type(value) is not str or not value or len(value) > 128
                for value in self.missing_facts
            )
            or not set(self.allowed_tools) <= TOOLS
            or type(self.max_steps) is not int
            or not 1 <= self.max_steps <= 4
            or type(self.timeout_seconds) not in {int, float}
            or not math.isfinite(self.timeout_seconds)
            or not 0 < self.timeout_seconds <= 120
            or type(self.parent_depth) is not int
            or self.parent_depth != 0
        ):
            raise OfflineImportError("invalid_external_task_policy")

    @classmethod
    def from_session(
        cls,
        session: InvestigationSession,
        unit: AuditUnit,
        projection: Mapping[str, Any],
        *,
        proposition: str,
        missing_facts: tuple[str, ...],
        allowed_tools: frozenset[str] = TOOLS,
        max_steps: int = 4,
        timeout_seconds: float = 120,
    ) -> ExternalInvestigationTask:
        session.validate_report_binding(unit, projection)
        assert_candidate_blind_projection(projection)
        binding = _binding(session)
        if not allowed_tools <= set(binding["effective_policy"]["allowed_tools"]):
            raise OfflineImportError("task_tool_policy_expansion")
        return cls(
            secrets.token_hex(16),
            _json(binding),
            _json(unit.to_dict()),
            _json(dict(projection)),
            proposition,
            tuple(missing_facts),
            tuple(sorted(allowed_tools)),
            max_steps,
            timeout_seconds,
        )

    @property
    def fingerprint(self) -> str:
        return _digest(
            {
                "schema": SCHEMA,
                "task_id": self.task_id,
                "binding": self.binding_json,
                "unit": self.unit_json,
                "projection": self.projection_json,
                "proposition": self.proposition,
                "missing_facts": self.missing_facts,
                "tools": self.allowed_tools,
                "max_steps": self.max_steps,
                "timeout_seconds": self.timeout_seconds,
                "parent_depth": self.parent_depth,
            }
        )

    def to_dict(self) -> dict[str, Any]:
        binding = json.loads(self.binding_json)
        return {
            "schema_version": SCHEMA,
            "task_id": self.task_id,
            "task_fingerprint": self.fingerprint,
            "identity": binding["identity"],
            "unit_id": binding["unit_id"],
            "unit_fingerprint": binding["unit_fingerprint"],
            "proposition": self.proposition,
            "missing_facts": list(self.missing_facts),
            "allowed_scopes": binding["scopes"],
            "allowed_tools": list(self.allowed_tools),
            "write_paths": [],
            "network": "none",
            "shell": False,
            "scan": False,
            "max_steps": self.max_steps,
            "timeout_seconds": self.timeout_seconds,
            "parent_depth": self.parent_depth,
            "max_child_depth": 0,
        }

    def validate(self, session: InvestigationSession) -> None:
        self.__post_init__()
        unit = AuditUnit.from_dict(json.loads(self.unit_json))
        projection = json.loads(self.projection_json)
        assert_candidate_blind_projection(projection)
        session.validate_report_binding(unit, projection)
        if _json(_binding(session)) != self.binding_json:
            raise OfflineImportError("external_task_binding_changed")
        if not set(self.allowed_tools) <= set(
            json.loads(self.binding_json)["effective_policy"]["allowed_tools"]
        ):
            raise OfflineImportError("task_tool_policy_expansion")


@dataclass
class ExternalInvestigationOutcome:
    status: str
    stop_reason: str
    report: DiscoveryReport | None = None
    evidence: list[dict[str, Any]] = field(default_factory=list)
    trace: list[dict[str, Any]] = field(default_factory=list)
    provenance: dict[str, Any] = field(default_factory=dict)
    usage: dict[str, Any] = field(
        default_factory=lambda: {"status": "unknown", "physical_attempts": None, "tokens": None}
    )
    proof_authority: bool = False


def _report(
    raw: Any,
    task: ExternalInvestigationTask,
    session: InvestigationSession,
    refs: list[str],
) -> DiscoveryReport:
    # Only these reference fields support local slots. Never substitute prose,
    # paths, identities, or an imported artifact/manifest into capabilities.
    value = json.loads(_json(raw))
    projection = json.loads(task.projection_json)
    allowed = set(projection.get("allowed_evidence_refs") or []) | set(refs)

    def bind(items: Any) -> list[str]:
        if not isinstance(items, list) or any(type(item) is not str for item in items):
            raise OfflineImportError("invalid_report_reference")
        result = []
        for item in items:
            if item.startswith("@evidence:"):
                ordinal = item[len("@evidence:") :]
                if not ordinal.isdecimal() or not 1 <= int(ordinal) <= len(refs):
                    raise OfflineImportError("invalid_report_reference")
                item = refs[int(ordinal) - 1]
            if item not in allowed:
                raise OfflineImportError("unregistered_report_reference")
            result.append(item)
        return result

    if not isinstance(value, dict):
        raise OfflineImportError("invalid_external_report")
    value["tool_evidence_refs"] = bind(value.get("tool_evidence_refs"))
    hypotheses = value.get("hypotheses")
    if not isinstance(hypotheses, list) or len(hypotheses) > 8:
        raise OfflineImportError("invalid_external_report")
    for hypothesis in hypotheses:
        if not isinstance(hypothesis, dict):
            raise OfflineImportError("invalid_external_report")
        for name in ("positive_evidence_refs", "negative_evidence_refs"):
            hypothesis[name] = bind(hypothesis.get(name))
    report = DiscoveryReport.from_dict(value)
    binding = json.loads(task.binding_json)
    members = {scope["function_uid"] for scope in binding["scopes"]}
    claims = {claim["claim_id"] for claim in projection.get("semantic_claims", [])}
    if (
        report.unit_id != binding["unit_id"]
        or report.unit_fingerprint != binding["unit_fingerprint"]
        or report.coverage_status != "partial"
        or not set(report.reviewed_function_uids) <= members
        or not set(report.reviewed_claim_ids) <= claims
    ):
        raise OfflineImportError("external_report_scope_mismatch")
    for hypothesis in report.hypotheses:
        if hypothesis.function not in members:
            raise OfflineImportError("external_report_scope_mismatch")
        session.validate_hypothesis_location(hypothesis.function, hypothesis.location)
    return report


def run_external_investigation(
    task: ExternalInvestigationTask,
    document: str,
    session: InvestigationSession,
    *,
    cancellation: CancellationToken | None = None,
) -> ExternalInvestigationOutcome:
    """Import offline intentions and execute them through a borrowed session.

    ``document`` is JSON data, never a callback. All provider kinds except the
    built-in offline fixture return unsupported without starting work. No task
    expansion, credential forwarding, executable loading or recursion exists.
    """
    outcome = ExternalInvestigationOutcome("partial", "step_budget")
    if _ACTIVE.get():
        outcome.status, outcome.stop_reason = "rejected", "recursive_adapter_denied"
        return outcome
    marker = _ACTIVE.set(True)
    refs: list[str] = []
    bound = False
    try:
        payload = _load(document)
        provider = _object(payload["provider"], {"kind", "name", "version"})
        if any(
            type(value) is not str or not value or len(value) > 128 for value in provider.values()
        ):
            raise OfflineImportError("invalid_provider_identity")
        outcome.provenance = {
            "origin": "external_offline_investigation",
            "execution": "simulated_provider_program_executed_tools",
            "provider": dict(provider),
            "task_id": task.task_id,
            "task_fingerprint": task.fingerprint,
            "document_sha256": hashlib.sha256(document.encode("utf-8")).hexdigest(),
            "independent_blind_discovery": False,
            "real_provider_executed": False,
        }
        if provider["kind"] != "offline" or provider["version"] != "1":
            outcome.status, outcome.stop_reason = "unsupported", "provider_permissions_unenforced"
            outcome.provenance["execution"] = "not_run"
            return outcome
        if (
            payload["schema_version"] != SCHEMA
            or payload["task_id"] != task.task_id
            or payload["task_fingerprint"] != task.fingerprint
        ):
            raise OfflineImportError("offline_task_version_mismatch")
        decisions = payload["decisions"]
        if not isinstance(decisions, list) or not 1 <= len(decisions) <= 32:
            raise OfflineImportError("invalid_offline_decisions")
        parent = cancellation or current_cancellation_token() or CancellationToken()
        token = parent.child(timeout_seconds=task.timeout_seconds)
        with bind_cancellation_token(token):
            token.raise_if_cancelled()
            task.validate(session)
            bound = True
            scopes = {item["function_uid"] for item in json.loads(task.binding_json)["scopes"]}
            seen: set[str] = set()
            for index, decision in enumerate(decisions[: task.max_steps], 1):
                token.raise_if_cancelled()
                task.validate(session)
                if not isinstance(decision, dict):
                    raise OfflineImportError("invalid_offline_decision")
                action = decision.get("action")
                if action == "query":
                    _object(decision, {"action", "tool", "function_uid", "arguments"})
                    if decision["tool"] not in task.allowed_tools:
                        raise OfflineImportError("external_tool_denied")
                    if decision["function_uid"] not in scopes:
                        raise OfflineImportError("external_scope_expansion_denied")
                    if not isinstance(decision["arguments"], dict):
                        raise OfflineImportError("invalid_offline_arguments")
                    key = _digest(decision)
                    if key in seen:
                        outcome.stop_reason = "repeated_query_no_gain"
                        break
                    seen.add(key)
                    try:
                        item = session.query(
                            InvestigationRequest(
                                decision["tool"], decision["function_uid"], decision["arguments"]
                            )
                        )
                    except InvestigationError:
                        task.validate(session)
                        outcome.trace.append(
                            {"step": index, "status": "query_rejected_or_unavailable"}
                        )
                        continue
                    refs.append(item["evidence_ref"])
                    outcome.evidence.append(item)
                    outcome.trace.append(
                        {
                            "step": index,
                            "status": "registered",
                            "evidence_ref": item["evidence_ref"],
                        }
                    )
                    token.raise_if_cancelled()
                elif action == "finish":
                    _object(decision, {"action", "report"})
                    outcome.report = _report(decision["report"], task, session, refs)
                    outcome.status, outcome.stop_reason = "completed", "report_imported"
                    break
                elif action == "unknown":
                    _object(decision, {"action"})
                    outcome.stop_reason = "provider_unknown"
                    break
                else:
                    raise OfflineImportError("external_action_denied")
            task.validate(session)
            token.raise_if_cancelled()
    except CancellationError:
        outcome.status, outcome.stop_reason = "interrupted", "cancelled_or_deadline"
    except (OfflineImportError, InvestigationError):
        outcome.status, outcome.stop_reason = "rejected", "invalid_or_unauthorized_offline_intent"
    except (ValueError, TypeError, KeyError, AttributeError, RecursionError):
        outcome.status, outcome.stop_reason = "rejected", "invalid_offline_document"
    finally:
        if bound:
            try:
                task.validate(session)
                if outcome.report is None:
                    binding = json.loads(task.binding_json)
                    outcome.report = DiscoveryReport(
                        binding["unit_id"],
                        binding["unit_fingerprint"],
                        "partial",
                        (),
                        (),
                        tuple(refs),
                        (),
                        (outcome.stop_reason,),
                    )
            except (ValueError, TypeError, KeyError, AttributeError):
                outcome.status, outcome.stop_reason = "rejected", "external_task_became_stale"
                outcome.provenance["evidence_validity"] = "stale_or_unavailable"
                outcome.report = None
        _ACTIVE.reset(marker)
    return outcome
