"""Strict, content-addressed evidence for deterministic-rule qualification.

The registry intentionally stores only a SHA-256 commitment.  A rule cannot be
promoted from that commitment alone: this module resolves the corresponding
manifest and derives every promotion metric from immutable case records.
"""

from __future__ import annotations

import hashlib
import json
import math
import stat
from dataclasses import dataclass
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Any, Dict, Mapping, Optional, Sequence, Tuple

from .catalog import RuleCatalogError, RuleDescriptor


QUALIFICATION_EVIDENCE_SCHEMA_VERSION = "zscope.rule-qualification-evidence.v1"
METAMORPHIC_TRANSFORMATIONS = frozenset(
    {"identifier_rename", "wrapper_rewrite", "macro_rewrite", "branch_reorder"}
)
EXTERNAL_EXPECTATIONS = frozenset({"vulnerable", "near_miss_safe"})
_SHA_FIELDS = frozenset(
    {
        "catalog_descriptor_sha256",
        "scanned_product_sha256",
        "range_token_set_sha256",
    }
)


def _canonical_sha256(value: Any) -> str:
    rendered = json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )
    return hashlib.sha256(rendered.encode("utf-8")).hexdigest()


def _is_sha256(value: Any) -> bool:
    text = value if isinstance(value, str) else ""
    return len(text) == 64 and all(char in "0123456789abcdef" for char in text)


def _exact_mapping(value: Any, fields: set[str], *, path: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise RuleCatalogError(f"{path}: must be an object")
    actual = set(value)
    if actual != fields:
        raise RuleCatalogError(
            f"{path}: fields mismatch; missing={sorted(fields - actual)!r}, "
            f"unknown={sorted(actual - fields)!r}"
        )
    return value


def _text(value: Any, *, path: str, max_length: int = 512) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > max_length:
        raise RuleCatalogError(f"{path}: must be a non-empty string <= {max_length} chars")
    return value.strip()


def _boolean(value: Any, *, path: str) -> bool:
    if not isinstance(value, bool):
        raise RuleCatalogError(f"{path}: must be a boolean")
    return value


def _sha(value: Any, *, path: str) -> str:
    if not _is_sha256(value):
        raise RuleCatalogError(f"{path}: must be a lowercase SHA-256")
    return str(value)


def _absolute_without_resolving(path: Path) -> Path:
    expanded = Path(path).expanduser()
    return expanded if expanded.is_absolute() else Path.cwd() / expanded


def _is_link_like(path: Path) -> bool:
    """Treat symlinks and Windows reparse points as untrusted indirection."""

    if path.is_symlink():
        return True
    try:
        metadata = path.lstat()
    except OSError:
        return False
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    return bool(reparse_flag and getattr(metadata, "st_file_attributes", 0) & reparse_flag)


def _canonical_artifact_path(value: Any, *, path: str) -> PurePosixPath:
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or len(value) > 1024
        or "\\" in value
        or "\x00" in value
    ):
        raise RuleCatalogError(
            f"{path}: must be a canonical relative POSIX path under the evidence root"
        )
    relative = PurePosixPath(value)
    windows_view = PureWindowsPath(value)
    if (
        relative.is_absolute()
        or windows_view.is_absolute()
        or bool(windows_view.drive)
        or not relative.parts
        or any(part in {".", "..", ""} for part in relative.parts)
        or relative.as_posix() != value
    ):
        raise RuleCatalogError(
            f"{path}: must be a canonical relative POSIX path under the evidence root"
        )
    return relative


def _prepare_evidence_root(root: Path, *, manifest_path: Path) -> Tuple[Path, Path]:
    lexical_root = _absolute_without_resolving(root)
    lexical_manifest = _absolute_without_resolving(manifest_path)
    if _is_link_like(lexical_root):
        raise RuleCatalogError(
            f"{lexical_root}: qualification evidence root cannot be a symbolic link "
            "or reparse point"
        )
    if not lexical_root.is_dir():
        raise RuleCatalogError(f"qualification evidence cannot be loaded: {lexical_manifest}")
    try:
        resolved_root = lexical_root.resolve(strict=True)
    except OSError as exc:
        raise RuleCatalogError(
            f"qualification evidence root cannot be resolved: {lexical_root}"
        ) from exc

    if _is_link_like(lexical_manifest):
        raise RuleCatalogError(
            f"{lexical_manifest}: qualification evidence manifest cannot be a symbolic link "
            "or reparse point"
        )
    if not lexical_manifest.is_file():
        raise RuleCatalogError(f"qualification evidence cannot be loaded: {lexical_manifest}")
    try:
        resolved_manifest = lexical_manifest.resolve(strict=True)
        resolved_manifest.relative_to(resolved_root)
    except (OSError, ValueError) as exc:
        raise RuleCatalogError(
            f"{lexical_manifest}: qualification evidence manifest is outside the evidence root"
        ) from exc
    if not resolved_manifest.is_file():
        raise RuleCatalogError(f"qualification evidence cannot be loaded: {resolved_manifest}")
    return lexical_root, resolved_manifest


def _verify_artifact(
    *,
    evidence_root: Path,
    artifact_path: Any,
    artifact_sha256: Any,
    path: str,
) -> None:
    relative = _canonical_artifact_path(artifact_path, path=f"{path}.artifact_path")
    expected_sha = _sha(artifact_sha256, path=f"{path}.artifact_sha256")
    target = evidence_root.joinpath(*relative.parts)

    current = evidence_root
    for component in relative.parts:
        current = current / component
        if _is_link_like(current):
            raise RuleCatalogError(
                f"{path}.artifact_path: symbolic links or reparse points are not allowed"
            )
    if not target.is_file():
        raise RuleCatalogError(
            f"{path}.artifact_path: qualification artifact does not exist or is not a "
            f"regular file: {relative.as_posix()}"
        )

    try:
        resolved_root = evidence_root.resolve(strict=True)
        resolved_target = target.resolve(strict=True)
        resolved_target.relative_to(resolved_root)
        raw = resolved_target.read_bytes()
    except (OSError, ValueError) as exc:
        raise RuleCatalogError(
            f"{path}.artifact_path: qualification artifact escapes the evidence root"
        ) from exc
    observed_sha = hashlib.sha256(raw).hexdigest()
    if observed_sha != expected_sha:
        raise RuleCatalogError(
            f"{path}.artifact_sha256: artifact SHA-256 mismatch; expected {expected_sha}, "
            f"observed {observed_sha}"
        )


def _strict_json(path: Path) -> Tuple[Dict[str, Any], bytes]:
    def reject_duplicates(pairs: Sequence[tuple[str, Any]]) -> Dict[str, Any]:
        result: Dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise RuleCatalogError(f"{path}: duplicate JSON key {key!r}")
            result[key] = value
        return result

    def reject_non_finite(value: str) -> None:
        raise RuleCatalogError(f"{path}: non-finite JSON number {value}")

    try:
        raw = path.read_bytes()
        decoded = raw.decode("utf-8")
        payload = json.loads(
            decoded,
            object_pairs_hook=reject_duplicates,
            parse_constant=reject_non_finite,
        )
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RuleCatalogError(f"qualification evidence cannot be loaded: {path}") from exc
    if not isinstance(payload, dict):
        raise RuleCatalogError(f"{path}: qualification evidence must be an object")
    return payload, raw


@dataclass(frozen=True)
class QualificationEvidenceSummary:
    source_path: str
    source_sha256: str
    rule_id: str
    revision: int
    external_projects: int
    positive_cases: int
    near_miss_negative_cases: int
    metamorphic_variants: int
    metamorphic_transformations: Tuple[str, ...]
    vulnerable_fixed_pair: bool
    external_precision: float
    leakage_lint_passed: bool

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema_version": QUALIFICATION_EVIDENCE_SCHEMA_VERSION,
            "source_path": self.source_path,
            "source_sha256": self.source_sha256,
            "rule_id": self.rule_id,
            "revision": self.revision,
            "external_projects": self.external_projects,
            "positive_cases": self.positive_cases,
            "near_miss_negative_cases": self.near_miss_negative_cases,
            "metamorphic_variants": self.metamorphic_variants,
            "metamorphic_transformations": list(self.metamorphic_transformations),
            "vulnerable_fixed_pair": self.vulnerable_fixed_pair,
            "external_precision": self.external_precision,
            "leakage_lint_passed": self.leakage_lint_passed,
        }


def load_qualification_evidence(
    path: Path,
    *,
    descriptor: RuleDescriptor,
    expected_sha256: str,
    evidence_root: Optional[Path] = None,
) -> QualificationEvidenceSummary:
    """Load one evidence manifest and derive, rather than trust, gate metrics."""

    lexical_root, resolved = _prepare_evidence_root(
        Path(evidence_root) if evidence_root is not None else Path(path).parent,
        manifest_path=Path(path),
    )
    payload, raw = _strict_json(resolved)
    observed_sha = hashlib.sha256(raw).hexdigest()
    if observed_sha != expected_sha256:
        raise RuleCatalogError(
            f"{resolved}: evidence SHA-256 mismatch; expected {expected_sha256}, "
            f"observed {observed_sha}"
        )
    data = _exact_mapping(
        payload,
        {
            "schema_version",
            "rule_id",
            "revision",
            "catalog_descriptor_sha256",
            "leakage_lint",
            "metamorphic_cases",
            "external_cases",
            "vulnerable_fixed_pairs",
        },
        path=str(resolved),
    )
    if data["schema_version"] != QUALIFICATION_EVIDENCE_SCHEMA_VERSION:
        raise RuleCatalogError(f"{resolved}: unsupported qualification evidence schema")
    if data["rule_id"] != descriptor.id or data["revision"] != descriptor.revision:
        raise RuleCatalogError(f"{resolved}: evidence rule_id/revision does not match catalog")
    expected_descriptor_sha = _canonical_sha256(descriptor.as_dict())
    if (
        _sha(
            data["catalog_descriptor_sha256"],
            path=f"{resolved}:catalog_descriptor_sha256",
        )
        != expected_descriptor_sha
    ):
        raise RuleCatalogError(f"{resolved}: catalog descriptor commitment mismatch")

    leakage = _exact_mapping(
        data["leakage_lint"],
        {
            "passed",
            "scanned_product_sha256",
            "range_token_set_sha256",
            "artifact_path",
            "artifact_sha256",
        },
        path=f"{resolved}:leakage_lint",
    )
    for field in _SHA_FIELDS - {"catalog_descriptor_sha256"}:
        _sha(leakage[field], path=f"{resolved}:leakage_lint.{field}")
    _verify_artifact(
        evidence_root=lexical_root,
        artifact_path=leakage["artifact_path"],
        artifact_sha256=leakage["artifact_sha256"],
        path=f"{resolved}:leakage_lint",
    )
    leakage_passed = _boolean(leakage["passed"], path=f"{resolved}:leakage_lint.passed")
    if not leakage_passed:
        raise RuleCatalogError(f"{resolved}: structural leakage lint did not pass")

    metamorphic_rows = data["metamorphic_cases"]
    if not isinstance(metamorphic_rows, list):
        raise RuleCatalogError(f"{resolved}:metamorphic_cases must be an array")
    metamorphic_ids: set[str] = set()
    transformations: set[str] = set()
    metamorphic_passed = 0
    for index, raw_case in enumerate(metamorphic_rows):
        case = _exact_mapping(
            raw_case,
            {
                "case_id",
                "transformation",
                "unsafe_detected",
                "fixed_not_detected",
                "artifact_path",
                "artifact_sha256",
            },
            path=f"{resolved}:metamorphic_cases[{index}]",
        )
        case_id = _text(case["case_id"], path=f"{resolved}:metamorphic_cases[{index}].case_id")
        if case_id in metamorphic_ids:
            raise RuleCatalogError(f"{resolved}: duplicate metamorphic case_id {case_id!r}")
        metamorphic_ids.add(case_id)
        transformation = _text(
            case["transformation"],
            path=f"{resolved}:metamorphic_cases[{index}].transformation",
        )
        if transformation not in METAMORPHIC_TRANSFORMATIONS:
            raise RuleCatalogError(f"{resolved}: unsupported metamorphic transformation")
        transformations.add(transformation)
        _verify_artifact(
            evidence_root=lexical_root,
            artifact_path=case["artifact_path"],
            artifact_sha256=case["artifact_sha256"],
            path=f"{resolved}:metamorphic_cases[{index}]",
        )
        unsafe_detected = _boolean(
            case["unsafe_detected"],
            path=f"{resolved}:metamorphic_cases[{index}].unsafe_detected",
        )
        fixed_not_detected = _boolean(
            case["fixed_not_detected"],
            path=f"{resolved}:metamorphic_cases[{index}].fixed_not_detected",
        )
        metamorphic_passed += int(unsafe_detected and fixed_not_detected)

    external_rows = data["external_cases"]
    if not isinstance(external_rows, list):
        raise RuleCatalogError(f"{resolved}:external_cases must be an array")
    external_ids: set[str] = set()
    project_ids: set[str] = set()
    positive_cases = 0
    near_miss_cases = 0
    true_positives = 0
    false_positives = 0
    for index, raw_case in enumerate(external_rows):
        case = _exact_mapping(
            raw_case,
            {
                "case_id",
                "project_id",
                "family_id",
                "expectation",
                "detected",
                "artifact_path",
                "artifact_sha256",
            },
            path=f"{resolved}:external_cases[{index}]",
        )
        case_id = _text(case["case_id"], path=f"{resolved}:external_cases[{index}].case_id")
        if case_id in external_ids:
            raise RuleCatalogError(f"{resolved}: duplicate external case_id {case_id!r}")
        external_ids.add(case_id)
        project_ids.add(
            _text(case["project_id"], path=f"{resolved}:external_cases[{index}].project_id")
        )
        _text(case["family_id"], path=f"{resolved}:external_cases[{index}].family_id")
        expectation = _text(
            case["expectation"], path=f"{resolved}:external_cases[{index}].expectation"
        )
        if expectation not in EXTERNAL_EXPECTATIONS:
            raise RuleCatalogError(f"{resolved}: unsupported external expectation")
        _verify_artifact(
            evidence_root=lexical_root,
            artifact_path=case["artifact_path"],
            artifact_sha256=case["artifact_sha256"],
            path=f"{resolved}:external_cases[{index}]",
        )
        detected = _boolean(case["detected"], path=f"{resolved}:external_cases[{index}].detected")
        if expectation == "vulnerable":
            positive_cases += 1
            true_positives += int(detected)
        else:
            near_miss_cases += 1
            false_positives += int(detected)

    pair_rows = data["vulnerable_fixed_pairs"]
    if not isinstance(pair_rows, list):
        raise RuleCatalogError(f"{resolved}:vulnerable_fixed_pairs must be an array")
    pair_ids: set[str] = set()
    passing_pair = False
    for index, raw_pair in enumerate(pair_rows):
        pair = _exact_mapping(
            raw_pair,
            {
                "pair_id",
                "project_id",
                "vulnerable_detected",
                "fixed_detected",
                "artifact_path",
                "artifact_sha256",
            },
            path=f"{resolved}:vulnerable_fixed_pairs[{index}]",
        )
        pair_id = _text(pair["pair_id"], path=f"{resolved}:vulnerable_fixed_pairs[{index}].pair_id")
        if pair_id in pair_ids:
            raise RuleCatalogError(f"{resolved}: duplicate vulnerable/fixed pair_id {pair_id!r}")
        pair_ids.add(pair_id)
        project_ids.add(
            _text(pair["project_id"], path=f"{resolved}:vulnerable_fixed_pairs[{index}].project_id")
        )
        _verify_artifact(
            evidence_root=lexical_root,
            artifact_path=pair["artifact_path"],
            artifact_sha256=pair["artifact_sha256"],
            path=f"{resolved}:vulnerable_fixed_pairs[{index}]",
        )
        vulnerable_detected = _boolean(
            pair["vulnerable_detected"],
            path=f"{resolved}:vulnerable_fixed_pairs[{index}].vulnerable_detected",
        )
        fixed_detected = _boolean(
            pair["fixed_detected"],
            path=f"{resolved}:vulnerable_fixed_pairs[{index}].fixed_detected",
        )
        passing_pair = passing_pair or (vulnerable_detected and not fixed_detected)

    denominator = true_positives + false_positives
    precision = true_positives / denominator if denominator else 0.0
    if not math.isfinite(precision):
        raise RuleCatalogError(f"{resolved}: derived external precision is non-finite")
    return QualificationEvidenceSummary(
        source_path=str(resolved),
        source_sha256=observed_sha,
        rule_id=descriptor.id,
        revision=descriptor.revision,
        external_projects=len(project_ids),
        positive_cases=positive_cases,
        near_miss_negative_cases=near_miss_cases,
        metamorphic_variants=metamorphic_passed,
        metamorphic_transformations=tuple(sorted(transformations)),
        vulnerable_fixed_pair=passing_pair,
        external_precision=round(precision, 12),
        leakage_lint_passed=leakage_passed,
    )


def qualification_evidence_filename(rule_id: str, revision: int) -> str:
    if not isinstance(rule_id, str) or not rule_id or "/" in rule_id or "\\" in rule_id:
        raise RuleCatalogError("qualification evidence rule_id is not path-safe")
    if isinstance(revision, bool) or not isinstance(revision, int) or revision < 1:
        raise RuleCatalogError("qualification evidence revision must be positive")
    return f"{rule_id}.r{revision}.json"
