from __future__ import annotations

import hashlib
import json
import unicodedata
import zipfile
from pathlib import Path

import pytest

import scripts.check_p5_runtime_authority_package as package_gate
from scripts.check_p1_runtime_reachability import REQUIRED_WHEEL_ENTRIES
from scripts.check_p5_runtime_authority_package import (
    RELEASE_STATUS,
    REQUIRED_ENTRIES,
    SUCCESSOR_QUALIFICATION,
    SUCCESSOR_REVIEW_EXACT_ENTRIES,
    SUCCESSOR_REVIEW_EVIDENCE_PREFIX,
    SUCCESSOR_REVIEW_RECEIPT,
    SUCCESSOR_REVIEW_STATUS,
    wheel_errors,
)
from zscope.orchestration.proof_promotion_qualification import SOURCE_BOUND_PATHS
from zscope.orchestration.successor_runtime_review_status import (
    SUCCESSOR_RUNTIME_REVIEW_STATUS,
)


ROOT = Path(__file__).resolve().parents[1]


def _status(*, value: str = "in_progress") -> dict:
    body = {
        "schema_version": "zscope.p5-release-status.v1",
        "phase": "P5",
        "status": value,
        "reviewed_commit": "",
        "reviewed_tree": "",
        "qualification_manifest_sha256": "",
        "review_artifact_sha256": {
            "product_architecture": "",
            "proof_security": "",
        },
    }
    payload = json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return {**body, "content_sha256": hashlib.sha256(payload).hexdigest()}


def _wheel(
    path: Path,
    *,
    omit_status: bool = False,
    tamper: bool = False,
    legacy_adapter: bool = False,
    omit_successor: bool = False,
    tamper_successor_source: bool = False,
    omit_successor_review_status: bool = False,
    tamper_successor_review_entry: str = "",
    add_unexpected_review_resource: bool = False,
) -> None:
    entries = set(REQUIRED_WHEEL_ENTRIES) | set(REQUIRED_ENTRIES) | set(SOURCE_BOUND_PATHS)
    with zipfile.ZipFile(path, "w") as archive:
        for name in entries:
            if name == RELEASE_STATUS:
                if omit_status:
                    continue
                status = _status()
                if tamper:
                    status["cache_epoch"] = "pre-p5"
                archive.writestr(name, json.dumps(status))
            elif name == SUCCESSOR_QUALIFICATION:
                if omit_successor:
                    continue
                archive.writestr(name, (ROOT / name).read_bytes())
            elif name == SUCCESSOR_REVIEW_STATUS:
                if omit_successor_review_status:
                    continue
                source_bytes = (ROOT / name).read_bytes()
                if tamper_successor_review_entry == name:
                    # Semantically identical JSON, but not the exact reviewed
                    # source projection packaged by this candidate.
                    source_bytes += b"\n"
                archive.writestr(name, source_bytes)
            elif name in SUCCESSOR_REVIEW_EXACT_ENTRIES:
                source_bytes = (ROOT / name).read_bytes()
                if tamper_successor_review_entry == name:
                    source_bytes += b"\n"
                archive.writestr(name, source_bytes)
            elif name in SOURCE_BOUND_PATHS:
                source_bytes = (ROOT / name).read_bytes()
                if legacy_adapter and name == "zscope/agents/proof_engine/agent.py":
                    source_bytes = b"def submit_validator_evidence_claim(): pass\n"
                if tamper_successor_source and name.endswith("closure.py"):
                    source_bytes += b"\n# tampered\n"
                archive.writestr(name, source_bytes)
            else:
                source = (
                    "def submit_validator_evidence_claim(): pass\n"
                    if legacy_adapter and name == "zscope/agents/proof_engine/agent.py"
                    else ""
                )
                archive.writestr(name, source)
        if add_unexpected_review_resource:
            archive.writestr(
                SUCCESSOR_REVIEW_EVIDENCE_PREFIX + "unexpected.json",
                b"{}",
            )


def _append_raw_backslash_member(path: Path, name: str, payload: bytes) -> None:
    """Write a backslash name without Windows ``zipfile`` normalizing it."""

    assert "\\" in name
    placeholder = name.replace("\\", "!")
    with zipfile.ZipFile(path, "a") as archive:
        archive.writestr(placeholder, payload)
    archive_bytes = path.read_bytes()
    encoded_placeholder = placeholder.encode("utf-8")
    encoded_name = name.encode("utf-8")
    assert len(encoded_placeholder) == len(encoded_name)
    assert archive_bytes.count(encoded_placeholder) == 2
    path.write_bytes(archive_bytes.replace(encoded_placeholder, encoded_name))


def test_p5_package_gate_accepts_current_content_addressed_successor(
    tmp_path: Path,
) -> None:
    wheel = tmp_path / "candidate.whl"
    _wheel(wheel)

    assert (
        wheel_errors(
            wheel,
            expected_status="in_progress",
            expected_successor_status=SUCCESSOR_RUNTIME_REVIEW_STATUS,
        )
        == []
    )


def test_p5_package_gate_rejects_missing_or_tampered_release_latch(tmp_path: Path) -> None:
    missing = tmp_path / "missing.whl"
    _wheel(missing, omit_status=True)
    assert any("release-status" in value for value in wheel_errors(missing))

    tampered = tmp_path / "tampered.whl"
    _wheel(tampered, tamper=True)
    assert any("release status invalid" in value for value in wheel_errors(tampered))


def test_p5_package_gate_rejects_legacy_proof_adapter_path(tmp_path: Path) -> None:
    wheel = tmp_path / "legacy-adapter.whl"
    _wheel(wheel, legacy_adapter=True)

    assert any("forbidden legacy adapter path" in value for value in wheel_errors(wheel))


def test_p5_package_gate_requires_exact_successor_qualification(tmp_path: Path) -> None:
    missing = tmp_path / "missing-successor.whl"
    _wheel(missing, omit_successor=True)
    assert any(SUCCESSOR_QUALIFICATION in value for value in wheel_errors(missing))

    tampered_source = tmp_path / "tampered-successor-source.whl"
    _wheel(tampered_source, tamper_successor_source=True)
    assert any(
        "successor-bound source hash mismatch" in value for value in wheel_errors(tampered_source)
    )


def test_p5_package_gate_distinguishes_in_progress_and_reviewed_successor(
    tmp_path: Path,
) -> None:
    missing = tmp_path / "missing-successor-review-status.whl"
    _wheel(missing, omit_successor_review_status=True)
    assert any(SUCCESSOR_REVIEW_STATUS in value for value in wheel_errors(missing))

    candidate = tmp_path / "candidate.whl"
    _wheel(candidate)
    assert (
        wheel_errors(
            candidate,
            expected_successor_status=SUCCESSOR_RUNTIME_REVIEW_STATUS,
        )
        == []
    )
    other_status = "reviewed" if SUCCESSOR_RUNTIME_REVIEW_STATUS == "in_progress" else "in_progress"
    assert any(
        "successor runtime review status mismatch" in value
        for value in wheel_errors(candidate, expected_successor_status=other_status)
    )
    physical_entries = {
        name
        for name in SUCCESSOR_REVIEW_EXACT_ENTRIES
        if name.startswith(SUCCESSOR_REVIEW_EVIDENCE_PREFIX) or name == SUCCESSOR_REVIEW_RECEIPT
    }
    if SUCCESSOR_RUNTIME_REVIEW_STATUS == "reviewed":
        assert SUCCESSOR_REVIEW_RECEIPT in physical_entries
        assert any(name.startswith(SUCCESSOR_REVIEW_EVIDENCE_PREFIX) for name in physical_entries)
    else:
        assert physical_entries == set()


def test_p5_package_gate_rejects_unexpected_physical_review_resource(
    tmp_path: Path,
) -> None:
    wheel = tmp_path / "unexpected-review-resource.whl"
    _wheel(wheel, add_unexpected_review_resource=True)

    assert any(
        value.startswith("wheel contains unexpected successor review resource:")
        for value in wheel_errors(wheel)
    )


def test_p5_package_gate_rejects_duplicate_member_anywhere_in_wheel(tmp_path: Path) -> None:
    wheel = tmp_path / "duplicate-global-member.whl"
    _wheel(wheel)
    with zipfile.ZipFile(wheel, "a") as archive:
        archive.writestr("zscope/reporting/schema.py", b"duplicate\n")

    assert "wheel archive contains duplicate members" in wheel_errors(wheel)


@pytest.mark.parametrize(
    "alias",
    (
        SUCCESSOR_REVIEW_STATUS.replace("/", "\\"),
        "C:/" + SUCCESSOR_REVIEW_STATUS,
        SUCCESSOR_REVIEW_STATUS.replace("/orchestration/", "/orchestration/./"),
        SUCCESSOR_REVIEW_STATUS.replace("/orchestration/", "/orchestration//"),
        SUCCESSOR_REVIEW_STATUS + ".",
        SUCCESSOR_REVIEW_STATUS + " ",
    ),
)
def test_p5_package_gate_rejects_windows_and_noncanonical_shadow_members(
    tmp_path: Path, alias: str
) -> None:
    wheel = tmp_path / "unsafe-shadow.whl"
    _wheel(wheel)
    if "\\" in alias:
        _append_raw_backslash_member(wheel, alias, b"shadow\n")
    else:
        with zipfile.ZipFile(wheel, "a") as archive:
            archive.writestr(alias, b"shadow\n")

    assert "wheel archive contains an unsafe member" in wheel_errors(wheel)


def test_p5_package_gate_rejects_casefold_alias_of_trusted_status(tmp_path: Path) -> None:
    wheel = tmp_path / "casefold-shadow.whl"
    _wheel(wheel)
    with zipfile.ZipFile(wheel, "a") as archive:
        archive.writestr(SUCCESSOR_REVIEW_STATUS.upper(), b"shadow\n")

    assert "wheel archive contains duplicate canonical aliases" in wheel_errors(wheel)


def test_p5_package_gate_rejects_unicode_normalization_alias_globally(tmp_path: Path) -> None:
    wheel = tmp_path / "unicode-shadow.whl"
    _wheel(wheel)
    composed = "zscope/orchestration/caf\N{LATIN SMALL LETTER E WITH ACUTE}.json"
    decomposed = unicodedata.normalize("NFD", composed)
    assert composed != decomposed
    with zipfile.ZipFile(wheel, "a") as archive:
        archive.writestr(composed, b"first\n")
        archive.writestr(decomposed, b"shadow\n")

    assert "wheel archive contains an unsafe member" in wheel_errors(wheel)


def test_p5_package_gate_rejects_file_directory_canonical_alias(tmp_path: Path) -> None:
    wheel = tmp_path / "file-directory-shadow.whl"
    _wheel(wheel)
    with zipfile.ZipFile(wheel, "a") as archive:
        archive.writestr("zscope/orchestration/shadow", b"file\n")
        archive.writestr("zscope/orchestration/shadow/", b"")

    assert "wheel archive contains duplicate canonical aliases" in wheel_errors(wheel)


def test_p5_package_gate_rejects_unsafe_archive_before_relevant_validation(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    wheel = tmp_path / "unsafe-before-relevant.whl"
    _wheel(wheel)
    _append_raw_backslash_member(
        wheel,
        SUCCESSOR_REVIEW_STATUS.replace("/", "\\"),
        b"shadow\n",
    )

    monkeypatch.setattr(
        package_gate,
        "reachability_errors",
        lambda _path: (_ for _ in ()).throw(AssertionError("downstream validator was called")),
    )
    assert "wheel archive contains an unsafe member" in wheel_errors(wheel)


def test_reviewed_wheel_projection_uses_extracted_bundle_and_exact_receipt(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    bundle_entry = SUCCESSOR_REVIEW_EVIDENCE_PREFIX + "bundle-manifest.json"
    wheel = tmp_path / "reviewed-physical.whl"
    with zipfile.ZipFile(wheel, "w") as archive:
        archive.writestr(bundle_entry, b'{"physical":true}')
        archive.writestr(SUCCESSOR_REVIEW_RECEIPT, b'{"receipt":true}')
    reviewed = {"status": "reviewed", "content_sha256": "1" * 64}
    observed: dict[str, bytes] = {}

    def project(bundle_root: Path, *, successor_qualification):
        assert successor_qualification == {"content_sha256": "2" * 64}
        observed["bundle"] = (bundle_root / "bundle-manifest.json").read_bytes()
        return dict(reviewed)

    def validate_receipt(receipt, *, expected_status):
        assert receipt == {"receipt": True}
        assert expected_status == reviewed
        return True, "valid"

    monkeypatch.setattr(
        package_gate,
        "SUCCESSOR_REVIEW_EXACT_ENTRIES",
        frozenset({bundle_entry, SUCCESSOR_REVIEW_RECEIPT}),
    )
    monkeypatch.setattr(package_gate, "project_successor_runtime_review_status", project)
    monkeypatch.setattr(
        package_gate,
        "validate_successor_review_integration_receipt",
        validate_receipt,
    )

    with zipfile.ZipFile(wheel) as archive:
        assert package_gate._project_wheel_review_status(
            archive,
            successor={"content_sha256": "2" * 64},
            review_status=reviewed,
        ) == (True, "valid")
    assert observed == {"bundle": b'{"physical":true}'}


@pytest.mark.parametrize("entry", sorted(SUCCESSOR_REVIEW_EXACT_ENTRIES))
def test_p5_package_gate_rejects_byte_substitution_of_successor_review_contract(
    tmp_path: Path,
    entry: str,
) -> None:
    wheel = tmp_path / (Path(entry).name + ".whl")
    _wheel(wheel, tamper_successor_review_entry=entry)

    assert any(
        value == "wheel successor review source bytes mismatch: " + entry
        for value in wheel_errors(
            wheel,
            expected_successor_status=SUCCESSOR_RUNTIME_REVIEW_STATUS,
        )
    )
