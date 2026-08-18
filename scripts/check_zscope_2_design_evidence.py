#!/usr/bin/env python3
"""Validate the Z-SCOPE 2.0 design archive and acceptance evidence bindings."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any, Mapping, Sequence


DESIGN_RELATIVE_ROOT = PurePosixPath("docs/design/zscope-2.0-security-architecture")
DESIGN_MANIFEST = DESIGN_RELATIVE_ROOT / "design-manifest.json"
EXTERNAL_ARTIFACT_PREFIXES = ("benchmark-artifacts/",)
PHASES = ("P0", "P1", "P2", "P3", "P4", "P5", "E0", "P6", "P7")
P0_REVIEW_ROLES = ("product_architecture", "proof_security", "independent_benchmark")
DESIGN_STATUSES = (
    "draft",
    "reviewed",
    "approved",
    "implementing",
    "validated",
    "superseded",
)
ACTIVE_AFTER_REVIEW = {"approved", "implementing", "validated"}
HEX_40 = re.compile(r"^[0-9a-f]{40}$")
HEX_64 = re.compile(r"^[0-9a-f]{64}$")


class DuplicateJsonKeyError(ValueError):
    """Raised when governance JSON contains a duplicate object key."""


@dataclass
class ValidationReport:
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    checked_files: set[str] = field(default_factory=set)

    @property
    def valid(self) -> bool:
        return not self.errors

    def error(self, message: str) -> None:
        self.errors.append(message)

    def warning(self, message: str) -> None:
        self.warnings.append(message)


def _object_without_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise DuplicateJsonKeyError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def load_json(path: Path) -> Any:
    return json.loads(
        path.read_text(encoding="utf-8"), object_pairs_hook=_object_without_duplicates
    )


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _inside(root: Path, candidate: Path) -> bool:
    try:
        candidate.relative_to(root)
    except ValueError:
        return False
    return True


def resolve_repository_path(
    repo_root: Path,
    raw_path: str,
    *,
    relative_root: PurePosixPath | None = None,
) -> Path:
    normalized = raw_path.strip().replace("\\", "/")
    relative = PurePosixPath(normalized)
    if not normalized or relative.is_absolute() or ".." in relative.parts:
        raise ValueError(f"unsafe repository-relative path: {raw_path!r}")
    base = repo_root if relative_root is None else repo_root / Path(*relative_root.parts)
    candidate = (base / Path(*relative.parts)).resolve()
    resolved_root = repo_root.resolve()
    if not _inside(resolved_root, candidate):
        raise ValueError(f"path escapes repository root: {raw_path!r}")
    return candidate


def _schema_type_matches(instance: Any, expected: str) -> bool:
    if expected == "object":
        return isinstance(instance, dict)
    if expected == "array":
        return isinstance(instance, list)
    if expected == "string":
        return isinstance(instance, str)
    if expected == "boolean":
        return isinstance(instance, bool)
    if expected == "integer":
        return isinstance(instance, int) and not isinstance(instance, bool)
    if expected == "number":
        return isinstance(instance, (int, float)) and not isinstance(instance, bool)
    if expected == "null":
        return instance is None
    raise ValueError(f"unsupported JSON schema type: {expected}")


def validate_json_schema(instance: Any, schema: Mapping[str, Any], path: str = "$") -> list[str]:
    """Validate the deliberately small JSON Schema subset used by the evidence index."""

    errors: list[str] = []
    supported = {
        "$schema",
        "$id",
        "title",
        "description",
        "type",
        "additionalProperties",
        "required",
        "properties",
        "const",
        "enum",
        "pattern",
        "minLength",
        "minItems",
        "minProperties",
        "items",
    }
    unknown_keywords = sorted(set(schema) - supported)
    if unknown_keywords:
        return [f"{path}: unsupported schema keyword(s): {', '.join(unknown_keywords)}"]

    expected_type = schema.get("type")
    if isinstance(expected_type, str) and not _schema_type_matches(instance, expected_type):
        return [f"{path}: expected {expected_type}, got {type(instance).__name__}"]
    if "const" in schema and instance != schema["const"]:
        errors.append(f"{path}: expected constant {schema['const']!r}")
    enum = schema.get("enum")
    if isinstance(enum, list) and instance not in enum:
        errors.append(f"{path}: value {instance!r} is not in {enum!r}")

    if isinstance(instance, str):
        min_length = schema.get("minLength")
        if isinstance(min_length, int) and len(instance) < min_length:
            errors.append(f"{path}: string is shorter than {min_length}")
        pattern = schema.get("pattern")
        if isinstance(pattern, str) and re.search(pattern, instance) is None:
            errors.append(f"{path}: string does not match {pattern!r}")

    if isinstance(instance, list):
        min_items = schema.get("minItems")
        if isinstance(min_items, int) and len(instance) < min_items:
            errors.append(f"{path}: array has fewer than {min_items} items")
        item_schema = schema.get("items")
        if isinstance(item_schema, dict):
            for index, item in enumerate(instance):
                errors.extend(validate_json_schema(item, item_schema, f"{path}[{index}]"))

    if isinstance(instance, dict):
        min_properties = schema.get("minProperties")
        if isinstance(min_properties, int) and len(instance) < min_properties:
            errors.append(f"{path}: object has fewer than {min_properties} properties")
        required = schema.get("required", [])
        if isinstance(required, list):
            for key in required:
                if key not in instance:
                    errors.append(f"{path}: missing required property {key!r}")
        properties = schema.get("properties", {})
        if not isinstance(properties, dict):
            errors.append(f"{path}: schema properties must be an object")
            properties = {}
        additional = schema.get("additionalProperties", True)
        for key, value in instance.items():
            if key in properties:
                property_schema = properties[key]
                if isinstance(property_schema, dict):
                    errors.extend(validate_json_schema(value, property_schema, f"{path}.{key}"))
            elif additional is False:
                errors.append(f"{path}: unexpected property {key!r}")
            elif isinstance(additional, dict):
                errors.extend(validate_json_schema(value, additional, f"{path}.{key}"))
    return errors


def _read_governance_json(path: Path, report: ValidationReport) -> Any | None:
    try:
        value = load_json(path)
    except (OSError, UnicodeError, json.JSONDecodeError, DuplicateJsonKeyError) as exc:
        report.error(f"cannot read governance JSON {path}: {exc}")
        return None
    report.checked_files.add(path.as_posix())
    return value


def _verify_file_hash(
    path: Path,
    expected: str,
    label: str,
    report: ValidationReport,
    *,
    allow_missing_external: bool = False,
) -> None:
    if HEX_64.fullmatch(expected) is None:
        report.error(f"{label}: invalid SHA-256 {expected!r}")
        return
    if not path.is_file():
        if allow_missing_external:
            report.warning(f"{label}: external hash-bound artifact is unavailable locally: {path}")
        else:
            report.error(f"{label}: bound artifact does not exist: {path}")
        return
    report.checked_files.add(path.as_posix())
    actual = sha256_file(path)
    if actual != expected:
        report.error(f"{label}: SHA-256 mismatch; expected {expected}, got {actual}")


def _git_tree(repo_root: Path, commit: str) -> str | None:
    completed = subprocess.run(
        ["git", "rev-parse", f"{commit}^{{tree}}"],
        cwd=repo_root,
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
    if completed.returncode != 0:
        return None
    return completed.stdout.strip()


def _git_text(repo_root: Path, *args: str) -> str | None:
    completed = subprocess.run(
        ["git", *args],
        cwd=repo_root,
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
    if completed.returncode != 0:
        return None
    return completed.stdout


def _git_blob(repo_root: Path, commit: str, raw_path: str) -> bytes | None:
    completed = subprocess.run(
        ["git", "show", f"{commit}:{raw_path}"],
        cwd=repo_root,
        check=False,
        capture_output=True,
    )
    if completed.returncode != 0:
        return None
    return completed.stdout


def _git_blob_sha256(repo_root: Path, commit: str, raw_path: str) -> str | None:
    blob = _git_blob(repo_root, commit, raw_path)
    return hashlib.sha256(blob).hexdigest() if blob is not None else None


def validate_formal_review_documents(
    manifest: Mapping[str, Any],
    reviews: Mapping[str, Any],
    review_schema: Mapping[str, Any],
    *,
    require_approval: bool,
) -> list[str]:
    """Validate the three role-separated P0 review decisions without file I/O."""

    errors: list[str] = []
    formal = manifest.get("formal_reviews")
    review_roles = manifest.get("review_roles")
    if not isinstance(formal, dict) or not isinstance(review_roles, dict):
        return ["formal_reviews or review_roles structure is missing"]
    artifacts = formal.get("artifacts")
    if not isinstance(artifacts, dict) or set(artifacts) != set(P0_REVIEW_ROLES):
        return ["formal_reviews artifacts must contain the three P0 review roles exactly once"]
    reviewed_commit = formal.get("reviewed_commit")
    reviewed_tree = formal.get("reviewed_tree")
    if HEX_40.fullmatch(str(reviewed_commit)) is None:
        errors.append("formal_reviews reviewed_commit must be a full Git commit")
    if HEX_40.fullmatch(str(reviewed_tree)) is None:
        errors.append("formal_reviews reviewed_tree must be a full Git tree")

    for role in P0_REVIEW_ROLES:
        spec = artifacts.get(role)
        review = reviews.get(role)
        if not isinstance(spec, dict) or not isinstance(review, dict):
            errors.append(f"{role}: review specification or document is missing")
            continue
        errors.extend(f"{role}: {row}" for row in validate_json_schema(review, review_schema))
        expected_model = spec.get("reviewer_model")
        expected_harness = spec.get("harness")
        if review.get("role") != role:
            errors.append(f"{role}: review document names role {review.get('role')!r}")
        if review.get("reviewer_model") != expected_model:
            errors.append(f"{role}: reviewer model differs from the formal assignment")
        if review.get("harness") != expected_harness:
            errors.append(f"{role}: harness configuration differs from the formal assignment")
        if review_roles.get(role) != expected_model:
            errors.append(f"{role}: review_roles identity differs from the formal assignment")
        if review.get("reviewed_commit") != reviewed_commit:
            errors.append(f"{role}: reviewed commit differs from the common review target")
        if review.get("reviewed_tree") != reviewed_tree:
            errors.append(f"{role}: reviewed tree differs from the common review target")
        if require_approval and review.get("decision") != "approved":
            errors.append(f"{role}: P0 completion requires an approved review decision")
        if require_approval and review.get("blocking_findings") != []:
            errors.append(f"{role}: P0 completion requires zero blocking findings")
    return errors


def _validate_approval_tag(
    repo_root: Path, manifest: Mapping[str, Any], report: ValidationReport
) -> None:
    approval = manifest.get("approval")
    if not isinstance(approval, dict) or approval.get("tag_created") is not True:
        return
    tag = approval.get("tag")
    bindings = approval.get("tag_hash_bindings")
    if not isinstance(tag, str) or not tag:
        report.error("approval tag is missing")
        return
    if not isinstance(bindings, dict) or not bindings:
        report.error("approved design requires non-empty tag_hash_bindings")
        return
    ref = f"refs/tags/{tag}"
    object_type = _git_text(repo_root, "cat-file", "-t", ref)
    if object_type is None or object_type.strip() != "tag":
        report.error(f"approval tag must exist as an annotated tag: {tag}")
        return
    tagged_commit = _git_text(repo_root, "rev-parse", f"{ref}^{{commit}}")
    tag_object = _git_text(repo_root, "cat-file", "-p", ref)
    if tagged_commit is None or tag_object is None:
        report.error(f"cannot read approval tag: {tag}")
        return
    tagged_commit = tagged_commit.strip()
    message = tag_object.split("\n\n", 1)[1] if "\n\n" in tag_object else ""
    message_fields: dict[str, str] = {}
    for line in message.splitlines():
        if ": " in line:
            key, value = line.split(": ", 1)
            message_fields[key.strip()] = value.strip()
    if message_fields.get("reviewed-commit") != approval.get("approved_commit"):
        report.error("approval tag reviewed-commit does not match approval.approved_commit")
    formal = manifest.get("formal_reviews")
    if not isinstance(formal, dict) or message_fields.get("reviewed-tree") != formal.get(
        "reviewed_tree"
    ):
        report.error("approval tag reviewed-tree does not match formal_reviews.reviewed_tree")

    tagged_manifest_blob = _git_blob(repo_root, tagged_commit, DESIGN_MANIFEST.as_posix())
    try:
        tagged_manifest = (
            json.loads(
                tagged_manifest_blob.decode("utf-8"),
                object_pairs_hook=_object_without_duplicates,
            )
            if tagged_manifest_blob is not None
            else None
        )
    except (UnicodeError, json.JSONDecodeError, DuplicateJsonKeyError) as exc:
        report.error(f"approval tag contains an unreadable design manifest: {exc}")
        tagged_manifest = None
    if not isinstance(tagged_manifest, dict):
        report.error("approval tag does not contain a design manifest object")
    else:
        tagged_phases = tagged_manifest.get("phase_status")
        tagged_approval = tagged_manifest.get("approval")
        if tagged_manifest.get("status") != "approved":
            report.error("approval tag design manifest must have status approved")
        if not isinstance(tagged_phases, dict) or tagged_phases.get("P0") != "complete":
            report.error("approval tag design manifest must record P0 complete")
        if not isinstance(tagged_approval, dict):
            report.error("approval tag design manifest is missing approval metadata")
        else:
            if tagged_approval.get("tag") != tag or tagged_approval.get("tag_created") is not True:
                report.error("approval tag design manifest does not name its created tag")
            if tagged_approval.get("approved_commit") != approval.get("approved_commit"):
                report.error("approval tag design manifest changes the reviewed commit")

    required_paths = {
        DESIGN_MANIFEST.as_posix(),
        (DESIGN_RELATIVE_ROOT / "acceptance/evidence-index.json").as_posix(),
    }
    raw_artifacts = formal.get("artifacts") if isinstance(formal, dict) else None
    if isinstance(raw_artifacts, dict):
        for spec in raw_artifacts.values():
            if isinstance(spec, dict) and isinstance(spec.get("path"), str):
                required_paths.add((DESIGN_RELATIVE_ROOT / PurePosixPath(spec["path"])).as_posix())
    if set(bindings.values()) != required_paths:
        report.error("approval tag_hash_bindings must cover manifest, evidence index, and reviews")

    for key, raw_path in bindings.items():
        if not isinstance(key, str) or not isinstance(raw_path, str):
            report.error("approval tag hash bindings must be string pairs")
            continue
        expected = message_fields.get(key)
        if expected is None or HEX_64.fullmatch(expected) is None:
            report.error(f"approval tag is missing a valid {key} binding")
            continue
        actual = _git_blob_sha256(repo_root, tagged_commit, raw_path)
        if actual is None:
            report.error(f"approval tag does not contain bound path: {raw_path}")
        elif actual != expected:
            report.error(
                f"approval tag {key} mismatch for {raw_path}: expected {expected}, got {actual}"
            )

    ancestry = subprocess.run(
        ["git", "merge-base", "--is-ancestor", tagged_commit, "HEAD"],
        cwd=repo_root,
        check=False,
        capture_output=True,
    )
    if ancestry.returncode != 0:
        report.error("approval tag target is not an ancestor of the current HEAD")


def validate_phase_gates(
    manifest: Mapping[str, Any], evidence_index: Mapping[str, Any]
) -> list[str]:
    errors: list[str] = []
    design_status = manifest.get("status")
    if design_status not in DESIGN_STATUSES:
        errors.append(f"design manifest has invalid status {design_status!r}")

    raw_manifest_phases = manifest.get("phase_status")
    raw_evidence_phases = evidence_index.get("phases")
    if not isinstance(raw_manifest_phases, dict) or not isinstance(raw_evidence_phases, list):
        return errors + ["phase status structures are missing"]
    if set(raw_manifest_phases) != set(PHASES):
        errors.append("design manifest phase_status must contain P0-P7 and E0 exactly once")

    indexed_phases: dict[str, Any] = {}
    for row in raw_evidence_phases:
        if not isinstance(row, dict):
            continue
        phase = row.get("phase")
        if isinstance(phase, str):
            if phase in indexed_phases:
                errors.append(f"evidence index repeats phase {phase}")
            indexed_phases[phase] = row.get("status")
    if set(indexed_phases) != set(PHASES):
        errors.append("evidence index phases must contain P0-P7 and E0 exactly once")
    for phase in PHASES:
        if raw_manifest_phases.get(phase) != indexed_phases.get(phase):
            errors.append(f"phase {phase} status differs between manifest and evidence index")

    p0_status = raw_manifest_phases.get("P0")
    later_started = [
        phase for phase in PHASES if phase != "P0" and raw_manifest_phases.get(phase) != "pending"
    ]
    if later_started and p0_status != "complete":
        errors.append(f"phases started before P0 completion: {', '.join(later_started)}")
    if later_started and design_status not in ACTIVE_AFTER_REVIEW:
        errors.append("post-P0 work requires an approved or later design status")

    approval = manifest.get("approval")
    review_roles = manifest.get("review_roles")
    if not isinstance(approval, dict) or not isinstance(review_roles, dict):
        return errors + ["approval or review_roles structure is missing"]
    reviews_complete = bool(review_roles) and all(
        isinstance(value, str) and value and value != "pending_assignment"
        for value in review_roles.values()
    )
    approval_complete = (
        isinstance(approval.get("approved_at"), str)
        and bool(approval.get("approved_at"))
        and isinstance(approval.get("approved_commit"), str)
        and HEX_40.fullmatch(str(approval.get("approved_commit"))) is not None
        and approval.get("tag_created") is True
        and approval.get("blocked_reasons") == []
    )
    if p0_status == "complete" or design_status in ACTIVE_AFTER_REVIEW:
        if not reviews_complete:
            errors.append("P0/design approval requires all formal review roles")
        if not approval_complete:
            errors.append("P0/design approval requires timestamp, commit, and created tag")
    if design_status == "reviewed" and approval.get("tag_created") is True:
        errors.append("reviewed design must not claim that its approval tag was created")
    if design_status in ACTIVE_AFTER_REVIEW and p0_status != "complete":
        errors.append("approved or later design status requires P0 completion")
    if p0_status == "complete" and design_status not in ACTIVE_AFTER_REVIEW:
        errors.append("P0 completion requires an approved or later design status")
    return errors


def validate_design_evidence(
    repo_root: Path,
    *,
    verify_git: bool = True,
    strict_external_artifacts: bool = False,
) -> ValidationReport:
    report = ValidationReport()
    repo_root = repo_root.resolve()
    manifest_path = resolve_repository_path(repo_root, DESIGN_MANIFEST.as_posix())
    manifest = _read_governance_json(manifest_path, report)
    if not isinstance(manifest, dict):
        if manifest is not None:
            report.error("design manifest root must be an object")
        return report
    if manifest.get("schema_version") != "zscope.design-manifest.v1":
        report.error("unexpected design manifest schema_version")

    design_root = DESIGN_RELATIVE_ROOT
    document_hashes = manifest.get("document_hashes")
    if not isinstance(document_hashes, dict) or not document_hashes:
        report.error("design manifest document_hashes must be a non-empty object")
    else:
        for raw_path, expected in document_hashes.items():
            if not isinstance(raw_path, str) or not isinstance(expected, str):
                report.error("design manifest document hash bindings must be string pairs")
                continue
            try:
                path = resolve_repository_path(
                    repo_root,
                    raw_path,
                    relative_root=None if raw_path.startswith("docs/") else design_root,
                )
            except ValueError as exc:
                report.error(str(exc))
                continue
            _verify_file_hash(path, expected, f"document {raw_path}", report)

    evidence_binding = manifest.get("evidence_index")
    if not isinstance(evidence_binding, dict):
        report.error("design manifest evidence_index binding is missing")
        return report
    try:
        evidence_path = resolve_repository_path(
            repo_root, str(evidence_binding.get("path", "")), relative_root=design_root
        )
        schema_path = resolve_repository_path(
            repo_root, str(evidence_binding.get("schema", "")), relative_root=design_root
        )
    except ValueError as exc:
        report.error(str(exc))
        return report
    evidence_index = _read_governance_json(evidence_path, report)
    schema = _read_governance_json(schema_path, report)
    if not isinstance(evidence_index, dict) or not isinstance(schema, dict):
        return report

    report.errors.extend(validate_json_schema(evidence_index, schema))
    if evidence_index.get("design_version") != manifest.get("design_version"):
        report.error("design version differs between manifest and evidence index")
    if evidence_index.get("design_status") != manifest.get("status"):
        report.error("design status differs between manifest and evidence index")
    report.errors.extend(validate_phase_gates(manifest, evidence_index))

    formal = manifest.get("formal_reviews")
    require_formal_approval = manifest.get("status") in ACTIVE_AFTER_REVIEW or (
        isinstance(manifest.get("phase_status"), dict)
        and manifest["phase_status"].get("P0") == "complete"
    )
    if formal is not None:
        if not isinstance(formal, dict):
            report.error("formal_reviews must be an object")
        else:
            try:
                review_schema_path = resolve_repository_path(
                    repo_root,
                    str(formal.get("schema", "")),
                    relative_root=design_root,
                )
            except ValueError as exc:
                report.error(str(exc))
                review_schema_path = None
            review_schema = (
                _read_governance_json(review_schema_path, report)
                if review_schema_path is not None
                else None
            )
            reviews: dict[str, Any] = {}
            artifacts = formal.get("artifacts")
            if isinstance(artifacts, dict):
                for role, spec in artifacts.items():
                    if not isinstance(role, str) or not isinstance(spec, dict):
                        report.error("formal review artifact entries must be objects")
                        continue
                    try:
                        review_path = resolve_repository_path(
                            repo_root,
                            str(spec.get("path", "")),
                            relative_root=design_root,
                        )
                    except ValueError as exc:
                        report.error(f"{role}: {exc}")
                        continue
                    reviews[role] = _read_governance_json(review_path, report)
            if isinstance(review_schema, dict):
                report.errors.extend(
                    validate_formal_review_documents(
                        manifest,
                        reviews,
                        review_schema,
                        require_approval=require_formal_approval,
                    )
                )
            reviewed_commit = str(formal.get("reviewed_commit", ""))
            reviewed_tree = str(formal.get("reviewed_tree", ""))
            if verify_git and HEX_40.fullmatch(reviewed_commit) and HEX_40.fullmatch(reviewed_tree):
                actual_tree = _git_tree(repo_root, reviewed_commit)
                if actual_tree is None:
                    report.error(f"formal review commit is unavailable in Git: {reviewed_commit}")
                elif actual_tree != reviewed_tree:
                    report.error(
                        "formal review tree mismatch; "
                        f"expected {reviewed_tree}, got {actual_tree}"
                    )
    elif require_formal_approval:
        report.error("P0/design approval requires formal_reviews")

    if verify_git:
        _validate_approval_tag(repo_root, manifest, report)

    manifest_baseline = manifest.get("baseline")
    evidence_baseline = evidence_index.get("baseline")
    if not isinstance(manifest_baseline, dict) or not isinstance(evidence_baseline, dict):
        report.error("baseline structures are missing")
    else:
        for key in ("git_commit", "git_tree"):
            if manifest_baseline.get(key) != evidence_baseline.get(key):
                report.error(f"baseline {key} differs between manifest and evidence index")
        if manifest_baseline.get("worktree_clean") != evidence_baseline.get("clean"):
            report.error("baseline clean state differs between manifest and evidence index")
        if manifest_baseline.get("worktree_patch_sha256") != evidence_baseline.get(
            "worktree_patch_sha256"
        ):
            report.error("baseline patch hash differs between manifest and evidence index")
        if verify_git:
            commit = str(manifest_baseline.get("git_commit", ""))
            expected_tree = str(manifest_baseline.get("git_tree", ""))
            tree = _git_tree(repo_root, commit) if HEX_40.fullmatch(commit) else None
            if tree is None:
                report.error(f"baseline commit is unavailable in Git: {commit}")
            elif tree != expected_tree:
                report.error(
                    f"baseline tree mismatch for {commit}: expected {expected_tree}, got {tree}"
                )

    seen_evidence: set[str] = set()
    raw_evidence = evidence_index.get("evidence")
    if isinstance(raw_evidence, list):
        for row in raw_evidence:
            if not isinstance(row, dict):
                continue
            uid = str(row.get("evidence_uid", "<missing>"))
            if uid in seen_evidence:
                report.error(f"duplicate evidence_uid: {uid}")
            seen_evidence.add(uid)
            commit = str(row.get("implementation_commit", ""))
            expected_tree = str(row.get("implementation_tree", ""))
            if verify_git and HEX_40.fullmatch(commit) and HEX_40.fullmatch(expected_tree):
                tree = _git_tree(repo_root, commit)
                if tree is None:
                    report.error(f"{uid}: implementation commit is unavailable in Git: {commit}")
                elif tree != expected_tree:
                    report.error(
                        f"{uid}: implementation tree mismatch; expected {expected_tree}, got {tree}"
                    )
            review_status = row.get("review_status")
            reviewed_by = row.get("reviewed_by")
            if review_status == "approved" and not reviewed_by:
                report.error(f"{uid}: approved evidence must name at least one reviewer")
            if review_status == "pending" and reviewed_by:
                report.error(f"{uid}: pending evidence must not claim completed reviewers")
            artifacts = row.get("artifacts")
            if not isinstance(artifacts, list):
                continue
            for artifact in artifacts:
                if not isinstance(artifact, dict):
                    continue
                raw_path = artifact.get("path")
                expected = artifact.get("sha256")
                if not isinstance(raw_path, str) or not isinstance(expected, str):
                    continue
                try:
                    artifact_path = resolve_repository_path(repo_root, raw_path)
                except ValueError as exc:
                    report.error(f"{uid}: {exc}")
                    continue
                external = raw_path.startswith(EXTERNAL_ARTIFACT_PREFIXES)
                _verify_file_hash(
                    artifact_path,
                    expected,
                    f"{uid} artifact {raw_path}",
                    report,
                    allow_missing_external=external and not strict_external_artifacts,
                )
    return report


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--repo-root",
        type=Path,
        default=Path(__file__).resolve().parents[1],
        help="repository root (defaults to the script parent repository)",
    )
    parser.add_argument(
        "--no-git",
        action="store_true",
        help="skip commit/tree availability checks (intended only for isolated tests)",
    )
    parser.add_argument(
        "--strict-external-artifacts",
        action="store_true",
        help="require ignored benchmark-artifacts to be present and hash-verifiable",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    report = validate_design_evidence(
        args.repo_root,
        verify_git=not args.no_git,
        strict_external_artifacts=args.strict_external_artifacts,
    )
    for warning in report.warnings:
        print(f"WARNING: {warning}", file=sys.stderr)
    for error in report.errors:
        print(f"ERROR: {error}", file=sys.stderr)
    if not report.valid:
        print(
            f"Z-SCOPE 2.0 design evidence invalid: {len(report.errors)} error(s), "
            f"{len(report.warnings)} warning(s)",
            file=sys.stderr,
        )
        return 2
    print(
        f"Z-SCOPE 2.0 design evidence valid: {len(report.checked_files)} local file(s) "
        f"checked, {len(report.warnings)} external limitation(s)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
