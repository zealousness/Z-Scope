#!/usr/bin/env python3
"""Verify the P5 authority contract, release latch, UI, and import isolation in a wheel."""

from __future__ import annotations

import argparse
import hashlib
import json
import stat
import tempfile
import unicodedata
import zipfile
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Mapping, Optional, Sequence

try:
    from scripts.check_p1_runtime_reachability import wheel_errors as reachability_errors
except ModuleNotFoundError:  # Direct ``python scripts/...`` execution.
    from check_p1_runtime_reachability import wheel_errors as reachability_errors
from zscope.benchmarking.p6_protocol import P6ProtocolError
from zscope.orchestration.runtime_authority import validate_p5_release_status
from zscope.orchestration.proof_promotion_qualification import (
    P6_PROOF_PROMOTION_QUALIFICATION_RESOURCE,
    SOURCE_BOUND_PATHS,
    load_successor_qualification,
    validate_successor_qualification,
)
from zscope.orchestration.successor_review_evidence import (
    SUCCESSOR_REVIEW_EVIDENCE_DIRECTORY,
    project_successor_runtime_review_status,
)
from zscope.orchestration.successor_review_integration import (
    SUCCESSOR_REVIEW_INTEGRATION_RECEIPT_RESOURCE,
    validate_successor_review_integration_receipt,
)
from zscope.orchestration.successor_runtime_review_status import (
    SUCCESSOR_RUNTIME_REVIEW_STATUS_RESOURCE,
    validate_current_successor_runtime_review_status,
    validate_successor_runtime_review_status,
)


RELEASE_STATUS = "zscope/orchestration/p5-release-status.json"
SUCCESSOR_QUALIFICATION = "zscope/orchestration/" + P6_PROOF_PROMOTION_QUALIFICATION_RESOURCE
SUCCESSOR_REVIEW_STATUS = "zscope/orchestration/" + SUCCESSOR_RUNTIME_REVIEW_STATUS_RESOURCE
SUCCESSOR_REVIEW_STATUS_MODULE = "zscope/orchestration/successor_runtime_review_status.py"
SUCCESSOR_REVIEW_STATUS_SCHEMA = (
    "zscope/orchestration/schemas/successor-runtime-review-status-v1.schema.json"
)
SUCCESSOR_REVIEW_EVIDENCE_PREFIX = (
    "zscope/orchestration/" + SUCCESSOR_REVIEW_EVIDENCE_DIRECTORY + "/"
)
SUCCESSOR_REVIEW_RECEIPT = "zscope/orchestration/" + SUCCESSOR_REVIEW_INTEGRATION_RECEIPT_RESOURCE
SUCCESSOR_REVIEW_BASE_EXACT_ENTRIES = {
    SUCCESSOR_REVIEW_STATUS,
    SUCCESSOR_REVIEW_STATUS_MODULE,
    SUCCESSOR_REVIEW_STATUS_SCHEMA,
}
SOURCE_ROOT = Path(__file__).resolve().parents[1]


def _source_review_physical_entries() -> set[str]:
    """Return every source-controlled physical review resource.

    Discovery does not grant authority.  The physical projector below still
    validates every restored artifact and receipt before a reviewed wheel can
    pass.  This set exists only to make package substitution byte-exact.
    """

    entries = set(SUCCESSOR_REVIEW_BASE_EXACT_ENTRIES)
    bundle_root = SOURCE_ROOT / SUCCESSOR_REVIEW_EVIDENCE_PREFIX.rstrip("/")
    if bundle_root.is_dir() and not bundle_root.is_symlink():
        for path in bundle_root.rglob("*"):
            if path.is_file() and not path.is_symlink():
                entries.add(path.relative_to(SOURCE_ROOT).as_posix())
    receipt = SOURCE_ROOT / SUCCESSOR_REVIEW_RECEIPT
    if receipt.is_file() and not receipt.is_symlink():
        entries.add(SUCCESSOR_REVIEW_RECEIPT)
    return entries


SUCCESSOR_REVIEW_EXACT_ENTRIES = frozenset(_source_review_physical_entries())
REQUIRED_ENTRIES = {
    RELEASE_STATUS,
    SUCCESSOR_QUALIFICATION,
    SUCCESSOR_REVIEW_STATUS,
    "zscope/orchestration/proof_promotion_qualification.py",
    "zscope/orchestration/schemas/p6-proof-promotion-qualification-v1.schema.json",
    SUCCESSOR_REVIEW_STATUS_MODULE,
    SUCCESSOR_REVIEW_STATUS_SCHEMA,
    "zscope/orchestration/runtime_authority.py",
    "zscope/orchestration/schemas/runtime-authority-manifest-v1.schema.json",
    "zscope/orchestration/schemas/p5-release-status-v1.schema.json",
    "zscope/agents/hypothesis_hunter/AGENT.md",
    "zscope/agents/proof_engine/AGENT.md",
    "zscope/semantics/security_specs/runtime.py",
    "zscope/web/static/index.html",
    "zscope/web/static/offline_template.html",
} | set(SUCCESSOR_REVIEW_EXACT_ENTRIES)
FORBIDDEN_PROOF_ADAPTER_FRAGMENTS = {
    "_run_evidence_slice_protocol",
    "submit_validator_evidence_claim",
    "execute_validator_evidence_action",
    "get_data_flow",
    "claim_verifier",
}


def _safe_zip_member(info: zipfile.ZipInfo) -> bool:
    # ``zipfile`` rewrites backslashes to the host separator on Windows.
    # ``orig_filename`` preserves the archive spelling and must therefore be
    # the value used for cross-platform safety decisions.
    name = info.orig_filename
    if (
        not name
        or "\\" in name
        or unicodedata.normalize("NFC", name) != name
        or any(ord(character) < 32 or ord(character) == 127 for character in name)
    ):
        return False
    pure = PurePosixPath(name)
    windows = PureWindowsPath(name)
    mode = (info.external_attr >> 16) & 0o170000
    canonical = pure.as_posix()
    expected = canonical.rstrip("/") + "/" if info.is_dir() else canonical
    return (
        not pure.is_absolute()
        and not windows.is_absolute()
        and not windows.drive
        and not windows.root
        and bool(pure.parts)
        and all(
            part not in {"", ".", ".."} and ":" not in part and not part.endswith((" ", "."))
            for part in pure.parts
        )
        and expected == name
        and mode in {0, stat.S_IFREG, stat.S_IFDIR}
        and (mode != stat.S_IFDIR or info.is_dir())
    )


def _canonical_zip_member_identity(info: zipfile.ZipInfo) -> str | None:
    """Return one cross-platform archive identity or reject the member."""

    if not _safe_zip_member(info):
        return None
    canonical = PurePosixPath(info.orig_filename).as_posix().rstrip("/")
    return unicodedata.normalize("NFC", canonical.casefold())


def _source_review_status(
    successor: Mapping[str, object],
) -> tuple[Mapping[str, object], str]:
    raw = json.loads((SOURCE_ROOT / SUCCESSOR_REVIEW_STATUS).read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError("source successor review status is not an object")
    valid, reason = validate_successor_runtime_review_status(
        raw,
        expected_implementation_root_sha256=str(successor.get("implementation_root_sha256") or ""),
        expected_successor_qualification_sha256=str(successor.get("content_sha256") or ""),
    )
    if not valid:
        raise ValueError("source successor runtime review status invalid: " + reason)
    bundle_root = SOURCE_ROOT / SUCCESSOR_REVIEW_EVIDENCE_PREFIX.rstrip("/")
    receipt_path = SOURCE_ROOT / SUCCESSOR_REVIEW_RECEIPT
    status = str(raw["status"])
    if status == "in_progress":
        if (
            bundle_root.exists()
            or bundle_root.is_symlink()
            or receipt_path.exists()
            or receipt_path.is_symlink()
        ):
            raise ValueError("source in-progress successor contains physical review evidence")
    else:
        current, current_reason = validate_current_successor_runtime_review_status(raw)
        if not current:
            raise ValueError("source successor physical review invalid: " + current_reason)
        if SUCCESSOR_REVIEW_RECEIPT not in SUCCESSOR_REVIEW_EXACT_ENTRIES:
            raise ValueError("source successor review integration receipt unavailable")
    return raw, status


def _project_wheel_review_status(
    archive: zipfile.ZipFile,
    *,
    successor: Mapping[str, object],
    review_status: Mapping[str, object],
) -> tuple[bool, str]:
    with tempfile.TemporaryDirectory(prefix="zscope-wheel-successor-review-") as temp_dir:
        bundle_root = Path(temp_dir) / SUCCESSOR_REVIEW_EVIDENCE_DIRECTORY
        bundle_root.mkdir()
        for name in sorted(SUCCESSOR_REVIEW_EXACT_ENTRIES):
            if not name.startswith(SUCCESSOR_REVIEW_EVIDENCE_PREFIX):
                continue
            relative = name.removeprefix(SUCCESSOR_REVIEW_EVIDENCE_PREFIX)
            pure = PurePosixPath(relative)
            target = bundle_root.joinpath(*pure.parts)
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(archive.read(name))
        projected = project_successor_runtime_review_status(
            bundle_root,
            successor_qualification=successor,
        )
    if dict(projected) != dict(review_status):
        return False, "wheel successor physical review projection mismatch"
    receipt = json.loads(archive.read(SUCCESSOR_REVIEW_RECEIPT).decode("utf-8"))
    if not isinstance(receipt, dict):
        return False, "wheel successor review integration receipt is not an object"
    valid, reason = validate_successor_review_integration_receipt(
        receipt,
        expected_status=review_status,
    )
    if not valid:
        return False, "wheel successor review integration receipt invalid: " + reason
    return True, "valid"


def wheel_errors(
    path: Path,
    *,
    expected_status: str | None = None,
    expected_successor_status: str | None = None,
) -> list[str]:
    errors: list[str] = []
    try:
        with zipfile.ZipFile(path) as archive:
            infos = archive.infolist()
            names = {info.filename for info in infos}
            if len(infos) != len(names):
                errors.append("wheel archive contains duplicate members")
            canonical_members: dict[str, str] = {}
            for info in infos:
                identity = _canonical_zip_member_identity(info)
                if identity is None:
                    errors.append("wheel archive contains an unsafe member")
                    continue
                if identity in canonical_members:
                    errors.append("wheel archive contains duplicate canonical aliases")
                else:
                    canonical_members[identity] = info.filename
            # No downstream validator may read by a trusted spelling until the
            # complete archive has one safe, globally unique canonical name
            # for every member.
            if errors:
                return sorted(set(errors))
            errors.extend(reachability_errors(path))
            exact_infos = [
                info for info in infos if info.filename in SUCCESSOR_REVIEW_EXACT_ENTRIES
            ]
            if len(exact_infos) != len({info.filename for info in exact_infos}):
                errors.append("wheel successor review contract contains duplicate members")
            for info in exact_infos:
                if not _safe_zip_member(info):
                    errors.append(
                        "wheel successor review contract member is unsafe: " + info.filename
                    )
            relevant_infos = [
                info
                for info in infos
                if info.filename.startswith(SUCCESSOR_REVIEW_EVIDENCE_PREFIX)
                or info.filename == SUCCESSOR_REVIEW_RECEIPT
            ]
            for info in relevant_infos:
                if not _safe_zip_member(info):
                    errors.append(
                        "wheel successor review archive member is unsafe: " + info.filename
                    )
            relevant_names = [info.filename for info in relevant_infos if not info.is_dir()]
            if len(relevant_names) != len(set(relevant_names)):
                errors.append("wheel successor review archive contains duplicate members")
            expected_physical = {
                name
                for name in SUCCESSOR_REVIEW_EXACT_ENTRIES
                if name.startswith(SUCCESSOR_REVIEW_EVIDENCE_PREFIX)
                or name == SUCCESSOR_REVIEW_RECEIPT
            }
            actual_physical = set(relevant_names)
            for name in sorted(actual_physical - expected_physical):
                errors.append("wheel contains unexpected successor review resource: " + name)
            errors.extend(
                f"wheel missing P5 authority entry: {name}"
                for name in sorted(REQUIRED_ENTRIES - names)
            )
            # The review-status projection is an evidence-only leaf.  A
            # schema-valid replacement inside a wheel must not be able to
            # upgrade an in-progress source candidate to reviewed.  Bind the
            # packaged data, validator implementation, and schema byte for
            # byte to the source tree on which this package gate is running.
            for name in sorted(SUCCESSOR_REVIEW_EXACT_ENTRIES & names):
                expected_bytes = (SOURCE_ROOT / name).read_bytes()
                packaged_bytes = archive.read(name)
                if packaged_bytes != expected_bytes:
                    errors.append("wheel successor review source bytes mismatch: " + name)
            if RELEASE_STATUS in names:
                raw = json.loads(archive.read(RELEASE_STATUS).decode("utf-8"))
                if not isinstance(raw, dict):
                    errors.append("P5 release status must be an object")
                else:
                    valid, reason = validate_p5_release_status(raw)
                    if not valid:
                        errors.append(f"P5 release status invalid: {reason}")
                    elif expected_status is not None and raw.get("status") != expected_status:
                        errors.append(
                            "P5 release status mismatch: "
                            f"expected {expected_status}, got {raw.get('status')}"
                        )
            successor: dict | None = None
            expected_successor: dict | None = None
            source_review_status: Mapping[str, object] | None = None
            source_review_status_value = ""
            if SUCCESSOR_QUALIFICATION in names:
                successor = json.loads(archive.read(SUCCESSOR_QUALIFICATION).decode("utf-8"))
                if not isinstance(successor, dict):
                    errors.append("P6 proof/promotion successor qualification must be an object")
                else:
                    valid, reason = validate_successor_qualification(successor)
                    if not valid:
                        errors.append(
                            "P6 proof/promotion successor qualification invalid: " + reason
                        )
                    else:
                        try:
                            expected_successor = load_successor_qualification()
                        except (OSError, TypeError, ValueError) as exc:
                            errors.append(
                                "current P6 proof/promotion successor qualification is stale: "
                                f"{exc}"
                            )
                        else:
                            if successor != expected_successor:
                                errors.append(
                                    "wheel P6 proof/promotion successor qualification mismatch"
                                )
                            try:
                                source_review_status, source_review_status_value = (
                                    _source_review_status(expected_successor)
                                )
                            except (OSError, TypeError, ValueError, P6ProtocolError) as exc:
                                errors.append(str(exc))
                        source_hashes = successor.get("source_sha256") or {}
                        for source_path in SOURCE_BOUND_PATHS:
                            if source_path not in names:
                                errors.append(
                                    "wheel missing successor-bound source: " + source_path
                                )
                                continue
                            digest = hashlib.sha256(archive.read(source_path)).hexdigest()
                            if digest != source_hashes.get(source_path):
                                errors.append(
                                    "wheel successor-bound source hash mismatch: " + source_path
                                )
            if SUCCESSOR_REVIEW_STATUS in names:
                review_status = json.loads(archive.read(SUCCESSOR_REVIEW_STATUS).decode("utf-8"))
                if not isinstance(review_status, dict):
                    errors.append("successor runtime review status must be an object")
                else:
                    expected_root = (
                        str(successor.get("implementation_root_sha256") or "")
                        if isinstance(successor, dict)
                        else None
                    )
                    expected_qualification = (
                        str(successor.get("content_sha256") or "")
                        if isinstance(successor, dict)
                        else None
                    )
                    valid, reason = validate_successor_runtime_review_status(
                        review_status,
                        expected_implementation_root_sha256=expected_root,
                        expected_successor_qualification_sha256=expected_qualification,
                    )
                    if not valid:
                        errors.append("successor runtime review status invalid: " + reason)
                    else:
                        expected_projection_status = (
                            expected_successor_status or source_review_status_value
                        )
                        if (
                            expected_projection_status
                            and review_status.get("status") != expected_projection_status
                        ):
                            errors.append(
                                "successor runtime review status mismatch: "
                                f"expected {expected_projection_status}, "
                                f"got {review_status.get('status')}"
                            )
                        if source_review_status is not None and dict(review_status) != dict(
                            source_review_status
                        ):
                            errors.append(
                                "wheel successor runtime review status differs from source"
                            )
                        if review_status.get("status") == "reviewed":
                            if not isinstance(successor, dict):
                                errors.append("wheel reviewed successor lacks exact qualification")
                            elif not expected_physical.issubset(actual_physical):
                                errors.append(
                                    "wheel reviewed successor physical evidence is incomplete"
                                )
                            else:
                                physical_valid, physical_reason = _project_wheel_review_status(
                                    archive,
                                    successor=successor,
                                    review_status=review_status,
                                )
                                if not physical_valid:
                                    errors.append(physical_reason)
            proof_agent = "zscope/agents/proof_engine/agent.py"
            if proof_agent in names:
                source = archive.read(proof_agent).decode("utf-8")
                for fragment in sorted(FORBIDDEN_PROOF_ADAPTER_FRAGMENTS):
                    if fragment in source:
                        errors.append(
                            "Proof Engine wheel retains forbidden legacy adapter path: "
                            f"{fragment}"
                        )
    except (
        KeyError,
        OSError,
        TypeError,
        ValueError,
        UnicodeError,
        P6ProtocolError,
        zipfile.BadZipFile,
    ) as exc:
        errors.append(f"cannot read P5 wheel contract: {exc}")
    return sorted(set(errors))


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("wheel", type=Path)
    parser.add_argument("--expect-status", choices=("in_progress", "complete"))
    parser.add_argument("--expect-successor-status", choices=("in_progress", "reviewed"))
    args = parser.parse_args(argv)
    errors = wheel_errors(
        args.wheel,
        expected_status=args.expect_status,
        expected_successor_status=args.expect_successor_status,
    )
    if errors:
        for value in errors:
            print(value)
        return 1
    print("P5 runtime authority wheel gate passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
