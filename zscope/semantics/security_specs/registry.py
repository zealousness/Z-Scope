"""Finite SecuritySpec DSL registry and strict parameter validation."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Mapping


SLOT_RE = re.compile(r"^(?:parameter:[0-9]+|return|receiver|field:[A-Za-z_][A-Za-z0-9_.:]*)$")
IDENTITY_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_.:/@-]*$")
SCOPE_KINDS = frozenset({"project", "module", "file", "function", "callsite"})
LABELS = frozenset(
    {"untrusted", "secret", "path", "command", "query", "memory", "format", "network"}
)
RESOURCE_KINDS = frozenset(
    {"memory", "file", "socket", "handle", "mapping", "transaction", "custom"}
)
OWNERS = frozenset({"caller", "callee", "return", "receiver", "global", "callback"})
LOCK_MODES = frozenset({"exclusive", "shared", "read", "write"})
LIFETIMES = frozenset({"call", "async", "object", "global"})
SENTINEL_MEANINGS = frozenset({"success", "failure", "absent", "retry", "terminal"})
CALLER_REQUIREMENTS = frozenset(
    {"non_null", "bounds", "ownership", "lock_held", "initialized", "valid_state"}
)


@dataclass(frozen=True)
class PredicateContract:
    predicate_id: str
    required: frozenset[str]
    optional: frozenset[str] = frozenset()

    @property
    def allowed(self) -> frozenset[str]:
        return self.required | self.optional


PREDICATE_REGISTRY: dict[str, PredicateContract] = {
    "source": PredicateContract("source", frozenset({"source_slot", "label"})),
    "sink": PredicateContract("sink", frozenset({"sink_slot", "label"})),
    "propagate": PredicateContract("propagate", frozenset({"from_slots", "to_slot", "label"})),
    "sanitize": PredicateContract("sanitize", frozenset({"from_slots", "to_slot", "label"})),
    "acquire": PredicateContract("acquire", frozenset({"resource_slot", "resource_kind"})),
    "release": PredicateContract("release", frozenset({"resource_slot", "resource_kind"})),
    "transfer": PredicateContract(
        "transfer", frozenset({"resource_slot", "from_owner", "to_owner"})
    ),
    "lock": PredicateContract("lock", frozenset({"lock_slot", "mode"})),
    "unlock": PredicateContract("unlock", frozenset({"lock_slot", "mode"})),
    "state_transition": PredicateContract(
        "state_transition", frozenset({"state_slot", "from_value", "to_value"})
    ),
    "sentinel": PredicateContract(
        "sentinel", frozenset({"value_slot", "sentinel_value", "meaning"})
    ),
    "callback_retains": PredicateContract(
        "callback_retains", frozenset({"callback_slot", "retained_slots", "lifetime"})
    ),
    "caller_contract": PredicateContract(
        "caller_contract", frozenset({"target_slots", "requirement"})
    ),
}


def validate_scope(scope: Any) -> tuple[bool, str]:
    if not isinstance(scope, Mapping) or set(scope) != {"kind", "target"}:
        return False, "invalid_scope_shape"
    kind = str(scope.get("kind") or "")
    target = str(scope.get("target") or "")
    if kind not in SCOPE_KINDS or not target:
        return False, "invalid_scope"
    if kind == "project" and target != "project":
        return False, "project_scope_target_must_be_project"
    return True, "ok"


def validate_subject(subject: Any) -> tuple[bool, str]:
    expected = {"language", "function_uid", "signature", "slot_uids"}
    if not isinstance(subject, Mapping) or set(subject) != expected:
        return False, "invalid_subject_shape"
    if str(subject.get("language") or "") not in {"c_cpp", "java"}:
        return False, "invalid_subject_language"
    if not str(subject.get("function_uid") or "") or not str(subject.get("signature") or ""):
        return False, "incomplete_subject_identity"
    slots = subject.get("slot_uids")
    if not isinstance(slots, list) or len(slots) != len(set(map(str, slots))):
        return False, "invalid_subject_slots"
    if any(SLOT_RE.fullmatch(str(value)) is None for value in slots):
        return False, "invalid_subject_slot"
    return True, "ok"


def validate_parameters(predicate_id: str, parameters: Any) -> tuple[bool, str]:
    contract = PREDICATE_REGISTRY.get(str(predicate_id))
    if contract is None:
        return False, "predicate_not_registered"
    if not isinstance(parameters, Mapping):
        return False, "parameters_not_object"
    keys = set(parameters)
    if keys != set(contract.required):
        return False, "parameter_schema_mismatch"

    def slot(name: str) -> bool:
        return SLOT_RE.fullmatch(str(parameters.get(name) or "")) is not None

    def slots(name: str) -> bool:
        value = parameters.get(name)
        return bool(
            isinstance(value, list)
            and value
            and len(value) == len(set(map(str, value)))
            and all(SLOT_RE.fullmatch(str(item)) for item in value)
        )

    if predicate_id in {"source", "sink"}:
        name = "source_slot" if predicate_id == "source" else "sink_slot"
        if not slot(name) or parameters.get("label") not in LABELS:
            return False, "invalid_dataflow_parameters"
    elif predicate_id in {"propagate", "sanitize"}:
        if not slots("from_slots") or not slot("to_slot") or parameters.get("label") not in LABELS:
            return False, "invalid_dataflow_parameters"
    elif predicate_id in {"acquire", "release"}:
        if not slot("resource_slot") or parameters.get("resource_kind") not in RESOURCE_KINDS:
            return False, "invalid_resource_parameters"
    elif predicate_id == "transfer":
        if (
            not slot("resource_slot")
            or parameters.get("from_owner") not in OWNERS
            or parameters.get("to_owner") not in OWNERS
            or parameters.get("from_owner") == parameters.get("to_owner")
        ):
            return False, "invalid_transfer_parameters"
    elif predicate_id in {"lock", "unlock"}:
        if not slot("lock_slot") or parameters.get("mode") not in LOCK_MODES:
            return False, "invalid_lock_parameters"
    elif predicate_id == "state_transition":
        if not slot("state_slot") or parameters.get("from_value") == parameters.get("to_value"):
            return False, "invalid_state_parameters"
    elif predicate_id == "sentinel":
        if not slot("value_slot") or parameters.get("meaning") not in SENTINEL_MEANINGS:
            return False, "invalid_sentinel_parameters"
    elif predicate_id == "callback_retains":
        if (
            not slot("callback_slot")
            or not slots("retained_slots")
            or parameters.get("lifetime") not in LIFETIMES
        ):
            return False, "invalid_callback_parameters"
    elif predicate_id == "caller_contract":
        if not slots("target_slots") or parameters.get("requirement") not in CALLER_REQUIREMENTS:
            return False, "invalid_caller_contract_parameters"
    return True, "ok"


def registry_manifest() -> dict[str, Any]:
    return {
        "schema_version": "zscope.security-spec-registry.v2",
        "predicates": [
            {
                "predicate_id": value.predicate_id,
                "required_parameters": sorted(value.required),
                "optional_parameters": sorted(value.optional),
            }
            for value in PREDICATE_REGISTRY.values()
        ],
        "scope_kinds": sorted(SCOPE_KINDS),
    }
