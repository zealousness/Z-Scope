from __future__ import annotations

import hashlib
import io
import json
import stat
import urllib.error
import zipfile
from email.message import Message
from pathlib import Path

import pytest

from scripts import download_e0_checkpoint_artifact as checkpoint_download


ARTIFACT_ID = 9544325600
RUN_ID = "32736349777"
SOURCE_SHA = "7" * 40
NAME = f"range-v16-primary-checkpoint-fable-{SOURCE_SHA}"
REPOSITORY = "zealousness/Z-Scope"


def _metadata() -> dict:
    return {
        "id": ARTIFACT_ID,
        "name": NAME,
        "size_in_bytes": 1024,
        "expired": False,
        "digest": f"sha256:{'a' * 64}",
        "archive_download_url": (
            f"https://api.github.com/repos/{REPOSITORY}/actions/artifacts/" f"{ARTIFACT_ID}/zip"
        ),
        "workflow_run": {"id": int(RUN_ID), "head_sha": SOURCE_SHA},
    }


def _validate(metadata: dict) -> str:
    return checkpoint_download._validate_metadata(
        metadata,
        repository=REPOSITORY,
        artifact_id=ARTIFACT_ID,
        expected_run_id=RUN_ID,
        expected_source_sha=SOURCE_SHA,
        expected_name=NAME,
    )


def test_checkpoint_artifact_metadata_binds_exact_immutable_identity() -> None:
    assert _validate(_metadata()) == "a" * 64

    for field, value in (
        ("id", ARTIFACT_ID + 1),
        ("name", f"{NAME}-other"),
        ("expired", True),
        ("digest", "sha256:invalid"),
    ):
        metadata = _metadata()
        metadata[field] = value
        with pytest.raises(ValueError, match="metadata is unbound"):
            _validate(metadata)

    for field, value in (("id", int(RUN_ID) + 1), ("head_sha", "8" * 40)):
        metadata = _metadata()
        metadata["workflow_run"][field] = value
        with pytest.raises(ValueError, match="metadata is unbound"):
            _validate(metadata)


def test_checkpoint_archive_extracts_only_safe_bound_tree(tmp_path: Path) -> None:
    archive = tmp_path / "checkpoint.zip"
    output = tmp_path / "output"
    with zipfile.ZipFile(archive, "w") as bundle:
        bundle.writestr("checkpoint-manifest.json", json.dumps({"schema_version": "test"}))
        bundle.writestr("decisions/CASE-000.json", "{}")
        bundle.writestr("raw/CASE-000.json", "{}")

    checkpoint_download._extract_archive(archive, output=output)

    assert json.loads((output / "checkpoint-manifest.json").read_text(encoding="utf-8")) == {
        "schema_version": "test"
    }
    assert (output / "decisions" / "CASE-000.json").is_file()
    assert (output / "raw" / "CASE-000.json").is_file()


def test_checkpoint_download_does_not_forward_token_to_signed_redirect(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    signed_url = "https://artifact.example.invalid/signed?opaque=value"
    headers = Message()
    headers["Location"] = signed_url

    class RedirectingOpener:
        def open(self, request: object, timeout: int) -> object:
            assert getattr(request, "get_header")("Authorization") == "Bearer secret"
            raise urllib.error.HTTPError(
                "https://api.github.com/artifact",
                302,
                "Found",
                headers,
                None,
            )

    payload = b"immutable-checkpoint-archive"

    def open_signed(request: object, timeout: int) -> io.BytesIO:
        assert getattr(request, "full_url") == signed_url
        assert not getattr(request, "has_header")("Authorization")
        return io.BytesIO(payload)

    monkeypatch.setattr(
        checkpoint_download.urllib.request,
        "build_opener",
        lambda *_: RedirectingOpener(),
    )
    monkeypatch.setattr(checkpoint_download.urllib.request, "urlopen", open_signed)
    output = tmp_path / "artifact.zip"

    assert (
        checkpoint_download._download_archive(
            "https://api.github.com/artifact",
            token="secret",
            output=output,
        )
        == hashlib.sha256(payload).hexdigest()
    )
    assert output.read_bytes() == payload


@pytest.mark.parametrize("member", ("../escape", "/absolute"))
def test_checkpoint_archive_rejects_escaping_members(tmp_path: Path, member: str) -> None:
    archive = tmp_path / "checkpoint.zip"
    with zipfile.ZipFile(archive, "w") as bundle:
        bundle.writestr("checkpoint-manifest.json", "{}")
        bundle.writestr(member, "forbidden")

    output = tmp_path / "output"
    with pytest.raises(ValueError, match="archive member"):
        checkpoint_download._extract_archive(archive, output=output)
    assert not output.exists()


def test_checkpoint_archive_rejects_backslash_member_name() -> None:
    with pytest.raises(ValueError, match="member path is invalid"):
        checkpoint_download._safe_member_path("bad\\path")


def test_checkpoint_archive_rejects_symlink(tmp_path: Path) -> None:
    archive = tmp_path / "checkpoint.zip"
    symlink = zipfile.ZipInfo("decisions/link.json")
    symlink.create_system = 3
    symlink.external_attr = (stat.S_IFLNK | 0o777) << 16
    with zipfile.ZipFile(archive, "w") as bundle:
        bundle.writestr("checkpoint-manifest.json", "{}")
        bundle.writestr(symlink, "target")

    output = tmp_path / "output"
    with pytest.raises(ValueError, match="symlink"):
        checkpoint_download._extract_archive(archive, output=output)
    assert not output.exists()
