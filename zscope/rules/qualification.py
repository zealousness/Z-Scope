"""Versioned, auditable qualification evidence for deterministic rules."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Any, Dict, Iterable, Mapping, Optional, Tuple

import yaml

from .catalog import RuleCatalog, RuleCatalogError, _UniqueKeyLoader
from .qualification_evidence import (
    QualificationEvidenceSummary,
    load_qualification_evidence,
    qualification_evidence_filename,
)


QUALIFICATION_SCHEMA_VERSION = "zscope.rule-qualification.v1"
QUALIFICATION_STATES = frozenset({"qualified", "pending", "failed"})
LEGACY_POLICIES = frozenset({"legacy_stable_pending", "require_explicit"})
_SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
_TOP_LEVEL_FIELDS = frozenset({"schema_version", "legacy_stable_policy", "qualifications"})
_RECORD_FIELDS = frozenset(
    {
        "rule_id",
        "revision",
        "state",
        "evidence_sha256",
        "external_projects",
        "positive_cases",
        "near_miss_negative_cases",
        "metamorphic_variants",
        "vulnerable_fixed_pair",
        "external_precision",
        "notes",
    }
)


@dataclass(frozen=True)
class RuleQualification:
    rule_id: str
    revision: int
    state: str
    evidence_sha256: str = ""
    external_projects: int = 0
    positive_cases: int = 0
    near_miss_negative_cases: int = 0
    metamorphic_variants: int = 0
    vulnerable_fixed_pair: bool = False
    external_precision: float = 0.0
    notes: str = ""
    inherited_legacy_pending: bool = False
    evidence_verified: bool = False

    def as_dict(self) -> Dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "revision": self.revision,
            "state": self.state,
            "evidence_sha256": self.evidence_sha256,
            "external_projects": self.external_projects,
            "positive_cases": self.positive_cases,
            "near_miss_negative_cases": self.near_miss_negative_cases,
            "metamorphic_variants": self.metamorphic_variants,
            "vulnerable_fixed_pair": self.vulnerable_fixed_pair,
            "external_precision": self.external_precision,
            "notes": self.notes,
            "inherited_legacy_pending": self.inherited_legacy_pending,
            "evidence_verified": self.evidence_verified,
        }


@dataclass(frozen=True)
class QualificationRegistry:
    source_path: str
    source_sha256: str
    legacy_stable_policy: str
    records: Mapping[Tuple[str, int], RuleQualification]
    evidence: Mapping[Tuple[str, int], QualificationEvidenceSummary]

    @classmethod
    def from_path(
        cls,
        path: Path,
        *,
        catalog: RuleCatalog,
        evidence_root: Optional[Path] = None,
    ) -> "QualificationRegistry":
        resolved = Path(path).expanduser().resolve()
        if not resolved.is_file():
            raise RuleCatalogError(f"qualification registry does not exist: {resolved}")
        raw_bytes = resolved.read_bytes()
        try:
            decoded = raw_bytes.decode("utf-8")
            payload = (
                json.loads(decoded)
                if resolved.suffix.lower() == ".json"
                else yaml.load(decoded, Loader=_UniqueKeyLoader)
            )
        except (UnicodeDecodeError, json.JSONDecodeError, yaml.YAMLError) as exc:
            raise RuleCatalogError(
                f"{resolved}: qualification registry must be UTF-8 YAML or JSON"
            ) from exc
        if not isinstance(payload, dict):
            raise RuleCatalogError(f"{resolved}: qualification registry must be an object")
        unknown = sorted(set(payload) - _TOP_LEVEL_FIELDS)
        missing = sorted(_TOP_LEVEL_FIELDS - set(payload))
        if unknown or missing:
            detail = []
            if unknown:
                detail.append("unknown fields: " + ", ".join(unknown))
            if missing:
                detail.append("missing fields: " + ", ".join(missing))
            raise RuleCatalogError(f"{resolved}: " + "; ".join(detail))
        if payload["schema_version"] != QUALIFICATION_SCHEMA_VERSION:
            raise RuleCatalogError(
                f"{resolved}: schema_version must be {QUALIFICATION_SCHEMA_VERSION}"
            )
        policy = payload["legacy_stable_policy"]
        if policy not in LEGACY_POLICIES:
            raise RuleCatalogError(f"{resolved}: invalid legacy_stable_policy {policy!r}")
        rows = payload["qualifications"]
        if not isinstance(rows, list):
            raise RuleCatalogError(f"{resolved}: qualifications must be a list")

        records: Dict[Tuple[str, int], RuleQualification] = {}
        evidence: Dict[Tuple[str, int], QualificationEvidenceSummary] = {}
        resolved_evidence_root = (
            Path(evidence_root).expanduser()
            if evidence_root is not None
            else resolved.parent / "qualification_evidence"
        )
        if not resolved_evidence_root.is_absolute():
            resolved_evidence_root = Path.cwd() / resolved_evidence_root
        for index, row in enumerate(rows):
            record = _parse_record(row, path=f"{resolved}:qualifications[{index}]")
            descriptor = catalog.get(record.rule_id)
            if descriptor is None:
                raise RuleCatalogError(
                    f"{resolved}:qualifications[{index}].rule_id: unknown rule "
                    f"{record.rule_id!r}"
                )
            if descriptor.id != record.rule_id:
                raise RuleCatalogError(
                    f"{resolved}:qualifications[{index}].rule_id: aliases are not allowed"
                )
            if record.revision > descriptor.revision:
                raise RuleCatalogError(
                    f"{resolved}:qualifications[{index}]: revision {record.revision} does not "
                    f"exist in catalog revision {descriptor.revision}"
                )
            key = (record.rule_id, record.revision)
            if key in records:
                raise RuleCatalogError(f"{resolved}: duplicate qualification {key!r}")
            if record.state == "qualified" and record.revision == descriptor.revision:
                evidence_path = resolved_evidence_root / qualification_evidence_filename(
                    record.rule_id,
                    record.revision,
                )
                evidence_summary = load_qualification_evidence(
                    evidence_path,
                    descriptor=descriptor,
                    expected_sha256=record.evidence_sha256,
                    evidence_root=resolved_evidence_root,
                )
                _verify_derived_evidence(
                    record,
                    evidence_summary,
                    path=f"{resolved}:qualifications[{index}]",
                )
                evidence[key] = evidence_summary
                record = RuleQualification(
                    **{
                        **record.__dict__,
                        "evidence_verified": True,
                    }
                )
            records[key] = record

        for descriptor in catalog:
            key = (descriptor.id, descriptor.revision)
            if descriptor.status != "stable":
                continue
            if key in records:
                if not descriptor.legacy_id and (
                    records[key].state != "qualified" or not records[key].evidence_verified
                ):
                    raise RuleCatalogError(
                        f"stable rule {descriptor.id!r} revision {descriptor.revision} "
                        "must have a qualified promotion record with verified evidence"
                    )
                continue
            if policy == "legacy_stable_pending" and descriptor.legacy_id:
                records[key] = RuleQualification(
                    rule_id=descriptor.id,
                    revision=descriptor.revision,
                    state="pending",
                    notes="Inherited catalog-v1 stable status; external qualification pending.",
                    inherited_legacy_pending=True,
                )
                continue
            raise RuleCatalogError(
                f"stable rule {descriptor.id!r} revision {descriptor.revision} has no "
                "qualification record"
            )

        return cls(
            source_path=str(resolved),
            source_sha256=hashlib.sha256(raw_bytes).hexdigest(),
            legacy_stable_policy=policy,
            records=MappingProxyType(records),
            evidence=MappingProxyType(evidence),
        )

    @classmethod
    def builtin(cls, *, catalog: Optional[RuleCatalog] = None) -> "QualificationRegistry":
        effective_catalog = catalog or RuleCatalog.builtin()
        return cls.from_path(
            Path(__file__).with_name("qualification_registry.yaml"),
            catalog=effective_catalog,
        )

    def state_for(self, rule_id: str, revision: int) -> Optional[RuleQualification]:
        return self.records.get((str(rule_id), int(revision)))

    def summary(self) -> Dict[str, Any]:
        counts = {state: 0 for state in sorted(QUALIFICATION_STATES)}
        inherited = 0
        for record in self.records.values():
            counts[record.state] += 1
            inherited += int(record.inherited_legacy_pending)
        return {
            "schema_version": QUALIFICATION_SCHEMA_VERSION,
            "source_path": self.source_path,
            "source_sha256": self.source_sha256,
            "legacy_stable_policy": self.legacy_stable_policy,
            "counts": counts,
            "inherited_legacy_pending": inherited,
            "evidence_verified": sum(record.evidence_verified for record in self.records.values()),
            "total": len(self.records),
            "rules": [
                {
                    "rule_id": rule_id,
                    "revision": revision,
                    "state": record.state,
                    "inherited_legacy_pending": record.inherited_legacy_pending,
                    "evidence_sha256": record.evidence_sha256,
                    "evidence_verified": record.evidence_verified,
                }
                for (rule_id, revision), record in sorted(self.records.items())
            ],
        }


def _parse_record(raw: Any, *, path: str) -> RuleQualification:
    if not isinstance(raw, dict):
        raise RuleCatalogError(f"{path}: qualification must be an object")
    unknown = sorted(set(raw) - _RECORD_FIELDS)
    required = {"rule_id", "revision", "state"}
    missing = sorted(required - set(raw))
    if unknown or missing:
        raise RuleCatalogError(f"{path}: invalid fields; unknown={unknown!r}, missing={missing!r}")
    rule_id = raw["rule_id"]
    revision = raw["revision"]
    state = raw["state"]
    if not isinstance(rule_id, str) or not rule_id:
        raise RuleCatalogError(f"{path}.rule_id: must be a non-empty string")
    if isinstance(revision, bool) or not isinstance(revision, int) or revision < 1:
        raise RuleCatalogError(f"{path}.revision: must be a positive integer")
    if state not in QUALIFICATION_STATES:
        raise RuleCatalogError(f"{path}.state: invalid qualification state {state!r}")

    integer_fields = (
        "external_projects",
        "positive_cases",
        "near_miss_negative_cases",
        "metamorphic_variants",
    )
    integers: Dict[str, int] = {}
    for field in integer_fields:
        value = raw.get(field, 0)
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise RuleCatalogError(f"{path}.{field}: must be a non-negative integer")
        integers[field] = value
    paired = raw.get("vulnerable_fixed_pair", False)
    if not isinstance(paired, bool):
        raise RuleCatalogError(f"{path}.vulnerable_fixed_pair: must be a boolean")
    precision = raw.get("external_precision", 0.0)
    if isinstance(precision, bool) or not isinstance(precision, (int, float)):
        raise RuleCatalogError(f"{path}.external_precision: must be numeric")
    precision = float(precision)
    if not 0.0 <= precision <= 1.0:
        raise RuleCatalogError(f"{path}.external_precision: must be between 0 and 1")
    evidence_sha = raw.get("evidence_sha256", "")
    notes = raw.get("notes", "")
    if not isinstance(evidence_sha, str) or not isinstance(notes, str):
        raise RuleCatalogError(f"{path}: evidence_sha256 and notes must be strings")

    if state == "qualified":
        failures = []
        if not _SHA256_RE.fullmatch(evidence_sha):
            failures.append("evidence_sha256")
        if integers["external_projects"] < 3:
            failures.append("external_projects>=3")
        if integers["positive_cases"] < 10:
            failures.append("positive_cases>=10")
        if integers["near_miss_negative_cases"] < 20:
            failures.append("near_miss_negative_cases>=20")
        if integers["metamorphic_variants"] < 3:
            failures.append("metamorphic_variants>=3")
        if not paired:
            failures.append("vulnerable_fixed_pair")
        if precision < 0.90:
            failures.append("external_precision>=0.90")
        if failures:
            raise RuleCatalogError(
                f"{path}: qualified record fails promotion gates: {', '.join(failures)}"
            )

    return RuleQualification(
        rule_id=rule_id,
        revision=revision,
        state=state,
        evidence_sha256=evidence_sha,
        external_projects=integers["external_projects"],
        positive_cases=integers["positive_cases"],
        near_miss_negative_cases=integers["near_miss_negative_cases"],
        metamorphic_variants=integers["metamorphic_variants"],
        vulnerable_fixed_pair=paired,
        external_precision=precision,
        notes=notes,
    )


def _verify_derived_evidence(
    record: RuleQualification,
    evidence: QualificationEvidenceSummary,
    *,
    path: str,
) -> None:
    """Reject registry counters that are not derived from the bound manifest."""

    comparisons = {
        "external_projects": (record.external_projects, evidence.external_projects),
        "positive_cases": (record.positive_cases, evidence.positive_cases),
        "near_miss_negative_cases": (
            record.near_miss_negative_cases,
            evidence.near_miss_negative_cases,
        ),
        "metamorphic_variants": (
            record.metamorphic_variants,
            evidence.metamorphic_variants,
        ),
        "vulnerable_fixed_pair": (
            record.vulnerable_fixed_pair,
            evidence.vulnerable_fixed_pair,
        ),
    }
    mismatches = [
        f"{field} registry={actual!r} evidence={derived!r}"
        for field, (actual, derived) in comparisons.items()
        if actual != derived
    ]
    if abs(record.external_precision - evidence.external_precision) > 1e-9:
        mismatches.append(
            "external_precision "
            f"registry={record.external_precision!r} evidence={evidence.external_precision!r}"
        )
    if len(evidence.metamorphic_transformations) < 3:
        mismatches.append(
            "metamorphic_transformations requires at least three distinct transformation kinds"
        )
    if not evidence.leakage_lint_passed:
        mismatches.append("leakage_lint_passed")
    if mismatches:
        raise RuleCatalogError(f"{path}: qualification evidence mismatch: " + "; ".join(mismatches))


def qualification_rows(
    catalog: RuleCatalog,
    registry: QualificationRegistry,
) -> Iterable[Dict[str, Any]]:
    for descriptor in catalog:
        record = registry.state_for(descriptor.id, descriptor.revision)
        yield {
            "rule_id": descriptor.id,
            "revision": descriptor.revision,
            "catalog_status": descriptor.status,
            "default_enabled": descriptor.default_enabled,
            "qualification_state": record.state if record else "not_required",
            "inherited_legacy_pending": bool(record and record.inherited_legacy_pending),
            "evidence_verified": bool(record and record.evidence_verified),
        }
