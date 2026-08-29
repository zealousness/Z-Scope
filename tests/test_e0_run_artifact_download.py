from __future__ import annotations

import hashlib
import io
import zipfile
from pathlib import Path

import pytest

from scripts import download_e0_run_artifacts as run_download


REPOSITORY = "zealousness/Z-Scope"
RUN_ID = "32835161601"
HEAD_SHA = "a" * 40
ARTIFACT_NAME = f"range-v16-arbitration-shard-0-{HEAD_SHA}"
ARTIFACT_ID = 9564149118


def test_run_artifact_listing_retries_transport_and_binds_count(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    attempts = 0
    delays: list[float] = []

    def fetch(url: str, *, token: str) -> dict:
        nonlocal attempts
        assert f"/actions/runs/{RUN_ID}/artifacts" in url
        assert token == "secret"
        attempts += 1
        if attempts < 3:
            raise run_download.CheckpointArtifactTransportError("timeout")
        return {
            "total_count": 1,
            "artifacts": [{"id": ARTIFACT_ID, "name": ARTIFACT_NAME}],
        }

    monkeypatch.setattr(run_download, "_fetch_metadata", fetch)
    monkeypatch.setattr(run_download.time, "sleep", delays.append)

    artifacts = run_download._list_run_artifacts(
        repository=REPOSITORY,
        run_id=RUN_ID,
        token="secret",
    )

    assert artifacts == [{"id": ARTIFACT_ID, "name": ARTIFACT_NAME}]
    assert attempts == 3
    assert delays == [1.0, 3.0]


def test_run_artifact_listing_rejects_duplicate_ids(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        run_download,
        "_fetch_metadata",
        lambda _url, *, token: {
            "total_count": 2,
            "artifacts": [
                {"id": ARTIFACT_ID, "name": ARTIFACT_NAME},
                {"id": ARTIFACT_ID, "name": f"{ARTIFACT_NAME}-duplicate"},
            ],
        },
    )

    with pytest.raises(ValueError, match="duplicate identities"):
        run_download._list_run_artifacts(
            repository=REPOSITORY,
            run_id=RUN_ID,
            token="secret",
        )


def test_run_artifact_download_validates_exact_metadata_digest_and_manifest(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    archive_buffer = io.BytesIO()
    with zipfile.ZipFile(archive_buffer, "w") as bundle:
        bundle.writestr("manifest.json", "{}")
        bundle.writestr("decisions/CASE-000.json", "{}")
    archive_bytes = archive_buffer.getvalue()
    digest = hashlib.sha256(archive_bytes).hexdigest()

    monkeypatch.setattr(
        run_download,
        "_fetch_metadata",
        lambda _url, *, token: {
            "id": ARTIFACT_ID,
            "name": ARTIFACT_NAME,
            "size_in_bytes": len(archive_bytes),
            "expired": False,
            "digest": f"sha256:{digest}",
            "archive_download_url": (
                f"https://api.github.com/repos/{REPOSITORY}/actions/artifacts/" f"{ARTIFACT_ID}/zip"
            ),
            "workflow_run": {"id": int(RUN_ID), "head_sha": HEAD_SHA},
        },
    )

    def download(_url: str, *, token: str, output: Path) -> str:
        assert token == "secret"
        output.write_bytes(archive_bytes)
        return digest

    monkeypatch.setattr(run_download, "_download_archive", download)
    output = tmp_path / "restored"

    actual = run_download._download_and_extract(
        repository=REPOSITORY,
        artifact_id=ARTIFACT_ID,
        run_id=RUN_ID,
        head_sha=HEAD_SHA,
        expected_name=ARTIFACT_NAME,
        token="secret",
        output=output,
    )

    assert actual == digest
    assert (output / "manifest.json").is_file()
    assert (output / "decisions" / "CASE-000.json").is_file()


def test_run_artifact_spec_stays_inside_workspace(tmp_path: Path) -> None:
    name, output = run_download._parse_artifact_spec(
        f"{ARTIFACT_NAME}=arbitration-shards/0",
        workspace=tmp_path.resolve(),
    )
    assert name == ARTIFACT_NAME
    assert output == (tmp_path / "arbitration-shards" / "0").resolve()

    with pytest.raises(ValueError, match="output path is invalid"):
        run_download._parse_artifact_spec(
            f"{ARTIFACT_NAME}=../escape",
            workspace=tmp_path.resolve(),
        )


def test_run_artifact_optional_missing_is_skipped(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    optional_name = f"range-v16-arbitration-checkpoint-3-{HEAD_SHA}"
    downloads: list[tuple[int, str, Path]] = []
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("Z_SCOPE_E0_REVIEW_ENVIRONMENT", "sealed-benchmark")
    monkeypatch.setenv("GITHUB_TOKEN", "secret")
    monkeypatch.setattr(
        run_download,
        "_list_run_artifacts",
        lambda **_kwargs: [{"id": ARTIFACT_ID, "name": ARTIFACT_NAME}],
    )

    def download_and_extract(**kwargs: object) -> str:
        output = kwargs["output"]
        assert isinstance(output, Path)
        output.mkdir()
        (output / "manifest.json").write_text("{}", encoding="utf-8")
        downloads.append(
            (
                int(kwargs["artifact_id"]),
                str(kwargs["expected_name"]),
                output,
            )
        )
        return "b" * 64

    monkeypatch.setattr(run_download, "_download_and_extract", download_and_extract)

    assert (
        run_download.main(
            [
                "--repository",
                REPOSITORY,
                "--expected-run-id",
                RUN_ID,
                "--expected-head-sha",
                HEAD_SHA,
                "--artifact",
                f"{ARTIFACT_NAME}=required",
                "--optional-artifact",
                f"{optional_name}=optional",
            ]
        )
        == 0
    )
    assert [(artifact_id, name) for artifact_id, name, _ in downloads] == [
        (ARTIFACT_ID, ARTIFACT_NAME)
    ]
    assert (tmp_path / "required" / "manifest.json").is_file()
    assert not (tmp_path / "optional").exists()


def test_run_checkpoint_artifact_requires_checkpoint_manifest(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    checkpoint_name = f"range-v16-pair-author-checkpoint-{HEAD_SHA}"
    checkpoint_id = ARTIFACT_ID + 1
    required_members_by_name: dict[str, tuple[str, ...]] = {}
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("Z_SCOPE_E0_REVIEW_ENVIRONMENT", "sealed-benchmark")
    monkeypatch.setenv("GITHUB_TOKEN", "secret")
    monkeypatch.setattr(
        run_download,
        "_list_run_artifacts",
        lambda **_kwargs: [
            {"id": ARTIFACT_ID, "name": ARTIFACT_NAME},
            {
                "id": checkpoint_id,
                "name": checkpoint_name,
                "expired": False,
                "created_at": "2026-08-28T08:44:41Z",
            },
        ],
    )

    def download_and_extract(**kwargs: object) -> str:
        output = kwargs["output"]
        required_members = kwargs["required_members"]
        expected_name = str(kwargs["expected_name"])
        assert isinstance(output, Path)
        assert isinstance(required_members, tuple)
        output.mkdir()
        for member in required_members:
            (output / member).write_text("{}", encoding="utf-8")
        required_members_by_name[expected_name] = required_members
        return "c" * 64

    monkeypatch.setattr(run_download, "_download_and_extract", download_and_extract)

    assert (
        run_download.main(
            [
                "--repository",
                REPOSITORY,
                "--expected-run-id",
                RUN_ID,
                "--expected-head-sha",
                HEAD_SHA,
                "--artifact",
                f"{ARTIFACT_NAME}=required",
                "--optional-checkpoint-artifact",
                f"{checkpoint_name}=retained-checkpoint",
            ]
        )
        == 0
    )
    assert required_members_by_name == {
        ARTIFACT_NAME: ("manifest.json",),
        checkpoint_name: ("checkpoint-manifest.json",),
    }
    assert (tmp_path / "required" / "manifest.json").is_file()
    assert (tmp_path / "retained-checkpoint" / "checkpoint-manifest.json").is_file()


def test_run_checkpoint_artifact_selects_latest_nonexpired_attempt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    checkpoint_name = f"range-v16-pair-author-checkpoint-{HEAD_SHA}"
    first_id = ARTIFACT_ID + 1
    latest_id = ARTIFACT_ID + 2
    expired_id = ARTIFACT_ID + 3
    downloads: list[int] = []
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("Z_SCOPE_E0_REVIEW_ENVIRONMENT", "sealed-benchmark")
    monkeypatch.setenv("GITHUB_TOKEN", "secret")
    monkeypatch.setattr(
        run_download,
        "_list_run_artifacts",
        lambda **_kwargs: [
            {"id": ARTIFACT_ID, "name": ARTIFACT_NAME},
            {
                "id": first_id,
                "name": checkpoint_name,
                "expired": False,
                "created_at": "2026-08-28T08:44:41Z",
            },
            {
                "id": latest_id,
                "name": checkpoint_name,
                "expired": False,
                "created_at": "2026-08-28T09:02:30Z",
            },
            {
                "id": expired_id,
                "name": checkpoint_name,
                "expired": True,
                "created_at": "2026-08-28T09:10:00Z",
            },
        ],
    )

    def download_and_extract(**kwargs: object) -> str:
        output = kwargs["output"]
        required_members = kwargs["required_members"]
        assert isinstance(output, Path)
        assert isinstance(required_members, tuple)
        output.mkdir()
        for member in required_members:
            (output / member).write_text("{}", encoding="utf-8")
        downloads.append(int(kwargs["artifact_id"]))
        return "d" * 64

    monkeypatch.setattr(run_download, "_download_and_extract", download_and_extract)

    assert (
        run_download.main(
            [
                "--repository",
                REPOSITORY,
                "--expected-run-id",
                RUN_ID,
                "--expected-head-sha",
                HEAD_SHA,
                "--artifact",
                f"{ARTIFACT_NAME}=required",
                "--optional-checkpoint-artifact",
                f"{checkpoint_name}=retained-checkpoint",
            ]
        )
        == 0
    )
    assert downloads == [ARTIFACT_ID, latest_id]
