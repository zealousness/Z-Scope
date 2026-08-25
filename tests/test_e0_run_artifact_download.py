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
