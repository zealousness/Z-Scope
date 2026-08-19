"""Stable finding discovery and decision attribution contract."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Mapping, Tuple


FINDING_ATTRIBUTION_SCHEMA_VERSION = "zscope.finding-attribution.v2"
FINDING_DISCOVERY_SOURCES = frozenset(
    {
        "deterministic_rule",
        "backend_signal",
        "hypothesis_hunter",
    }
)
FINDING_DECISION_SOURCES = frozenset(
    {
        "deterministic_proof",
        "proof_engine",
        "dynamic_reproduction",
        "human",
        "unresolved",
    }
)
FINDING_DECISION_LEVELS = frozenset({"none", "V0", "V1", "V2", "V3", "V4"})


def _ordered_strings(values: Iterable[Any]) -> Tuple[str, ...]:
    return tuple(sorted({str(value).strip() for value in values if str(value).strip()}))


def finding_attribution_mapping_errors(value: Mapping[str, Any]) -> List[str]:
    """Validate an explicit attribution mapping without silently upgrading it.

    Historical reports may be inferred by benchmark compatibility code, but an
    object presented as *explicit* attribution must identify the exact public
    schema and retain the JSON field shapes used by that schema.  Keeping this
    check beside :class:`FindingAttribution` prevents formal scoring and the
    Candidate Ledger boundary from drifting to different definitions of
    "explicit".
    """

    errors: List[str] = []
    schema_version = value.get("schema_version")
    if schema_version != FINDING_ATTRIBUTION_SCHEMA_VERSION:
        errors.append(
            "schema_version must be "
            f"{FINDING_ATTRIBUTION_SCHEMA_VERSION!r}, got {schema_version!r}"
        )

    discovered = value.get("discovered_by")
    if not isinstance(discovered, (list, tuple, set, frozenset)):
        errors.append("discovered_by must be an array")
    elif not discovered:
        errors.append("discovered_by has no recognized source")
    elif len({str(item).strip() for item in discovered}) != len(discovered):
        errors.append("discovered_by contains duplicate sources")

    details = value.get("discovery_details")
    if not isinstance(details, (list, tuple)) or any(
        not isinstance(item, Mapping) for item in details
    ):
        errors.append("discovery_details must be an array of objects")

    decided_by = value.get("decided_by")
    if not isinstance(decided_by, str) or not decided_by.strip():
        errors.append("decided_by must be a non-empty string")
    decision_level = value.get("decision_level")
    if not isinstance(decision_level, str) or not decision_level.strip():
        errors.append("decision_level must be a non-empty string")

    parsed = FindingAttribution.from_mapping(value)
    errors.extend(parsed.validation_errors())
    if not parsed.discovered_by and "discovered_by has no recognized source" not in errors:
        errors.append("discovered_by has no recognized source")
    return list(dict.fromkeys(errors))


@dataclass(frozen=True)
class FindingAttribution:
    """Independent discovery and terminal-decision provenance for one finding.

    A finding may have multiple discovery sources, but exactly one current
    decision source and assurance level.  Details contain identifiers and
    evidence metadata only; prompt and chain-of-thought text do not belong in
    this contract.
    """

    discovered_by: Tuple[str, ...] = ()
    decided_by: str = "unresolved"
    decision_level: str = "none"
    discovery_details: Tuple[Mapping[str, Any], ...] = ()
    decision_details: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "discovered_by", _ordered_strings(self.discovered_by))
        object.__setattr__(
            self,
            "discovery_details",
            tuple(dict(item) for item in self.discovery_details if isinstance(item, Mapping)),
        )
        object.__setattr__(self, "decided_by", str(self.decided_by or "unresolved").strip())
        object.__setattr__(
            self,
            "decision_level",
            str(self.decision_level or "none").strip(),
        )
        object.__setattr__(self, "decision_details", dict(self.decision_details))

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "FindingAttribution":
        discovered = value.get("discovered_by")
        if isinstance(discovered, str):
            discovered_values: Iterable[Any] = (discovered,)
        elif isinstance(discovered, (list, tuple, set, frozenset)):
            discovered_values = discovered
        else:
            discovered_values = ()
        raw_details = value.get("discovery_details")
        details = (
            tuple(dict(item) for item in raw_details if isinstance(item, Mapping))
            if isinstance(raw_details, (list, tuple))
            else ()
        )
        decision_details = value.get("decision_details")
        return cls(
            discovered_by=_ordered_strings(discovered_values),
            decided_by=str(value.get("decided_by") or "unresolved").strip(),
            decision_level=str(value.get("decision_level") or "none").strip(),
            discovery_details=details,
            decision_details=(
                dict(decision_details) if isinstance(decision_details, Mapping) else {}
            ),
        )

    def validation_errors(self) -> List[str]:
        errors: List[str] = []
        invalid_discovery = sorted(set(self.discovered_by) - FINDING_DISCOVERY_SOURCES)
        if invalid_discovery:
            errors.append("invalid discovered_by: " + ", ".join(invalid_discovery))
        if self.decided_by not in FINDING_DECISION_SOURCES:
            errors.append(f"invalid decided_by: {self.decided_by}")
        if self.decision_level not in FINDING_DECISION_LEVELS:
            errors.append(f"invalid decision_level: {self.decision_level}")
        return errors

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema_version": FINDING_ATTRIBUTION_SCHEMA_VERSION,
            "discovered_by": list(self.discovered_by),
            "discovery_details": [dict(item) for item in self.discovery_details],
            "decided_by": self.decided_by,
            "decision_level": self.decision_level,
            "decision_details": dict(self.decision_details),
        }


def serialize_finding_attribution(value: Any) -> Dict[str, Any]:
    """Serialize either the common type or an existing mapping canonically."""

    if isinstance(value, FindingAttribution):
        return value.to_dict()
    if isinstance(value, Mapping):
        return FindingAttribution.from_mapping(value).to_dict()
    raise TypeError("finding attribution must be a FindingAttribution or mapping")
