from __future__ import annotations

import hashlib
import io
import zipfile
from collections.abc import Mapping
from pathlib import Path

import pytest

from scripts import download_e0_run_artifacts as run_download


REPOSITORY = "zealousness/Z-Scope"
RUN_ID = "32835161601"
HEAD_SHA = "a" * 40
ARTIFACT_NAME = f"range-v16-arbitration-shard-0-{HEAD_SHA}"
ARTIFACT_ID = 9564149118
PRODUCER_JOB = "Arbitration review (0)"


def _source_run() -> dict[str, object]:
    return {
        "id": int(RUN_ID),
        "head_sha": HEAD_SHA,
        "head_branch": "main",
        "event": "workflow_dispatch",
        "path": ".github/workflows/range-v16-review.yml",
        "repository": {"full_name": REPOSITORY},
        "status": "in_progress",
        "conclusion": None,
    }


def _producer_job() -> dict[str, object]:
    return {
        "id": 901,
        "run_id": int(RUN_ID),
        "head_sha": HEAD_SHA,
        "name": PRODUCER_JOB,
        "status": "completed",
        "conclusion": "success",
    }


def _artifact_metadata(*, digest: str = "a" * 64) -> dict[str, object]:
    return {
        "id": ARTIFACT_ID,
        "name": ARTIFACT_NAME,
        "size_in_bytes": 1024,
        "expired": False,
        "digest": f"sha256:{digest}",
        "archive_download_url": (
            f"https://api.github.com/repos/{REPOSITORY}/actions/artifacts/" f"{ARTIFACT_ID}/zip"
        ),
        "workflow_run": {"id": int(RUN_ID), "head_sha": HEAD_SHA},
    }


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


def test_run_artifact_download_rejects_external_digest_binding_mismatch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    archive_buffer = io.BytesIO()
    with zipfile.ZipFile(archive_buffer, "w") as bundle:
        bundle.writestr("manifest.json", "{}")
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
    monkeypatch.setattr(
        run_download,
        "_download_archive",
        lambda *_args, **_kwargs: pytest.fail("archive must not be downloaded"),
    )

    with pytest.raises(ValueError, match="external digest binding mismatch"):
        run_download._download_and_extract(
            repository=REPOSITORY,
            artifact_id=ARTIFACT_ID,
            run_id=RUN_ID,
            head_sha=HEAD_SHA,
            expected_name=ARTIFACT_NAME,
            token="secret",
            output=tmp_path / "restored",
            external_digest="b" * 64,
        )


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("id", ARTIFACT_ID + 1),
        ("name", f"{ARTIFACT_NAME}-other"),
        ("size_in_bytes", 0),
        ("expired", True),
        ("digest", "sha256:invalid"),
        ("archive_download_url", "https://api.github.com/unbound"),
    ],
)
def test_exact_artifact_rejects_every_artifact_metadata_mismatch(field: str, value: object) -> None:
    metadata = _artifact_metadata()
    metadata[field] = value
    with pytest.raises(ValueError, match="artifact metadata is unbound"):
        run_download._validate_metadata(
            metadata,
            repository=REPOSITORY,
            artifact_id=ARTIFACT_ID,
            expected_run_id=RUN_ID,
            expected_source_sha=HEAD_SHA,
            expected_name=ARTIFACT_NAME,
        )


@pytest.mark.parametrize(("field", "value"), [("id", 1), ("head_sha", "b" * 40)])
def test_exact_artifact_rejects_artifact_workflow_run_mismatch(field: str, value: object) -> None:
    metadata = _artifact_metadata()
    workflow_run = metadata["workflow_run"]
    assert isinstance(workflow_run, dict)
    workflow_run[field] = value
    with pytest.raises(ValueError, match="artifact metadata is unbound"):
        run_download._validate_metadata(
            metadata,
            repository=REPOSITORY,
            artifact_id=ARTIFACT_ID,
            expected_run_id=RUN_ID,
            expected_source_sha=HEAD_SHA,
            expected_name=ARTIFACT_NAME,
        )


def test_exact_artifact_rejects_downloaded_bytes_digest_mismatch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    server_digest = "a" * 64
    monkeypatch.setattr(
        run_download,
        "_fetch_metadata",
        lambda _url, *, token: _artifact_metadata(digest=server_digest),
    )

    def download(_url: str, *, token: str, output: Path) -> str:
        output.write_bytes(b"unbound archive bytes")
        return "b" * 64

    monkeypatch.setattr(run_download, "_download_archive", download)
    monkeypatch.setattr(
        run_download,
        "_extract_archive",
        lambda *_args, **_kwargs: pytest.fail("unbound archive must not be extracted"),
    )
    with pytest.raises(ValueError, match="artifact digest mismatch"):
        run_download._download_and_extract(
            repository=REPOSITORY,
            artifact_id=ARTIFACT_ID,
            run_id=RUN_ID,
            head_sha=HEAD_SHA,
            expected_name=ARTIFACT_NAME,
            token="secret",
            output=tmp_path / "restored",
            external_digest=server_digest,
        )


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


def test_exact_run_artifact_spec_binds_name_output_id_and_digest(tmp_path: Path) -> None:
    digest = "b" * 64
    assert run_download._parse_exact_artifact_spec(
        f"{ARTIFACT_NAME}=external/shard={ARTIFACT_ID}=sha256:{digest}",
        workspace=tmp_path.resolve(),
    ) == (
        ARTIFACT_NAME,
        (tmp_path / "external" / "shard").resolve(),
        ARTIFACT_ID,
        digest,
    )

    for invalid in (
        f"{ARTIFACT_NAME}=external/shard={ARTIFACT_ID}",
        f"{ARTIFACT_NAME}=external/shard=0=sha256:{digest}",
        f"{ARTIFACT_NAME}=external/shard={ARTIFACT_ID}=sha256:invalid",
        f"{ARTIFACT_NAME}=../escape={ARTIFACT_ID}=sha256:{digest}",
    ):
        with pytest.raises(ValueError):
            run_download._parse_exact_artifact_spec(invalid, workspace=tmp_path.resolve())


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("id", 1),
        ("head_sha", "b" * 40),
        ("head_branch", "feature"),
        ("event", "push"),
        ("path", ".github/workflows/other.yml"),
        ("repository", {"full_name": "other/repository"}),
    ],
)
def test_exact_artifact_source_run_rejects_every_provenance_mismatch(
    field: str, value: object
) -> None:
    metadata = _source_run()
    metadata[field] = value
    with pytest.raises(ValueError, match="source workflow run metadata is unbound"):
        run_download._validate_source_run(
            metadata,
            repository=REPOSITORY,
            run_id=RUN_ID,
            head_sha=HEAD_SHA,
            workflow_path=run_download.E0_REVIEW_WORKFLOW_PATH,
            event=run_download.E0_REVIEW_EVENT,
            head_branch=run_download.E0_REVIEW_HEAD_BRANCH,
        )


def test_exact_artifact_source_run_allows_nonterminal_failed_run() -> None:
    metadata = _source_run()
    metadata["status"] = "completed"
    metadata["conclusion"] = "failure"
    run_download._validate_source_run(
        metadata,
        repository=REPOSITORY,
        run_id=RUN_ID,
        head_sha=HEAD_SHA,
        workflow_path=run_download.E0_REVIEW_WORKFLOW_PATH,
        event=run_download.E0_REVIEW_EVENT,
        head_branch=run_download.E0_REVIEW_HEAD_BRANCH,
    )


def test_exact_artifact_producer_job_requires_bound_success() -> None:
    run_download._validate_producer_job(
        [_producer_job()],
        expected_name=PRODUCER_JOB,
        run_id=RUN_ID,
        head_sha=HEAD_SHA,
    )

    variants: list[tuple[Mapping[str, object], str]] = []
    absent = _producer_job()
    absent["name"] = "other"
    variants.append((absent, "producer job is absent"))
    wrong_run = _producer_job()
    wrong_run["run_id"] = 1
    variants.append((wrong_run, "producer job metadata is unbound"))
    wrong_head = _producer_job()
    wrong_head["head_sha"] = "b" * 40
    variants.append((wrong_head, "producer job metadata is unbound"))
    failed = _producer_job()
    failed["conclusion"] = "failure"
    variants.append((failed, "producer job did not succeed"))
    running = _producer_job()
    running["status"] = "in_progress"
    running["conclusion"] = None
    variants.append((running, "producer job did not succeed"))

    for job, error in variants:
        with pytest.raises(ValueError, match=error):
            run_download._validate_producer_job(
                [job],
                expected_name=PRODUCER_JOB,
                run_id=RUN_ID,
                head_sha=HEAD_SHA,
            )


def test_exact_artifact_job_listing_retries_and_rejects_duplicate_ids(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    attempts = 0

    def fetch(url: str, *, token: str) -> dict[str, object]:
        nonlocal attempts
        assert f"/actions/runs/{RUN_ID}/jobs?filter=all" in url
        attempts += 1
        if attempts == 1:
            raise run_download.CheckpointArtifactTransportError("timeout")
        return {"total_count": 1, "jobs": [_producer_job()]}

    monkeypatch.setattr(run_download, "_fetch_metadata", fetch)
    monkeypatch.setattr(run_download.time, "sleep", lambda _delay: None)
    assert run_download._list_run_jobs(repository=REPOSITORY, run_id=RUN_ID, token="secret") == [
        _producer_job()
    ]
    assert attempts == 2

    monkeypatch.setattr(
        run_download,
        "_fetch_metadata",
        lambda _url, *, token: {
            "total_count": 2,
            "jobs": [_producer_job(), _producer_job()],
        },
    )
    with pytest.raises(ValueError, match="duplicate identities"):
        run_download._list_run_jobs(repository=REPOSITORY, run_id=RUN_ID, token="secret")


def test_exact_artifact_main_validates_run_job_and_external_digest(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    digest = "c" * 64
    validations: list[str] = []
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("Z_SCOPE_E0_REVIEW_ENVIRONMENT", "sealed-benchmark")
    monkeypatch.setenv("GITHUB_TOKEN", "secret")
    monkeypatch.setattr(
        run_download,
        "_fetch_and_validate_source_run",
        lambda **_kwargs: validations.append("run"),
    )
    monkeypatch.setattr(
        run_download,
        "_list_run_jobs",
        lambda **_kwargs: [_producer_job()],
    )

    def validate_job(*_args: object, **_kwargs: object) -> None:
        validations.append("job")

    monkeypatch.setattr(run_download, "_validate_producer_job", validate_job)
    monkeypatch.setattr(
        run_download,
        "_list_run_artifacts",
        lambda **_kwargs: pytest.fail("exact mode must not list artifacts by name"),
    )

    def download_and_extract(**kwargs: object) -> str:
        assert kwargs["artifact_id"] == ARTIFACT_ID
        assert kwargs["external_digest"] == digest
        output = kwargs["output"]
        assert isinstance(output, Path)
        output.mkdir()
        (output / "manifest.json").write_text("{}", encoding="utf-8")
        return digest

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
                "--exact-artifact",
                f"{ARTIFACT_NAME}=external={ARTIFACT_ID}=sha256:{digest}",
                "--expected-workflow-path",
                run_download.E0_REVIEW_WORKFLOW_PATH,
                "--expected-event",
                run_download.E0_REVIEW_EVENT,
                "--expected-head-branch",
                run_download.E0_REVIEW_HEAD_BRANCH,
                "--expected-producer-job",
                PRODUCER_JOB,
            ]
        )
        == 0
    )
    assert validations == ["run", "job"]
    assert (tmp_path / "external" / "manifest.json").is_file()


def test_exact_artifact_mode_rejects_incomplete_or_mixed_cli(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    digest = "d" * 64
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("Z_SCOPE_E0_REVIEW_ENVIRONMENT", "sealed-benchmark")
    monkeypatch.setenv("GITHUB_TOKEN", "secret")
    base = [
        "--repository",
        REPOSITORY,
        "--expected-run-id",
        RUN_ID,
        "--expected-head-sha",
        HEAD_SHA,
        "--exact-artifact",
        f"{ARTIFACT_NAME}=external={ARTIFACT_ID}=sha256:{digest}",
    ]
    with pytest.raises(ValueError, match="source workflow binding is invalid"):
        run_download.main(base)
    with pytest.raises(ValueError, match="choose exactly one"):
        run_download.main(
            [
                *base,
                "--artifact",
                f"other=required",
                "--expected-workflow-path",
                run_download.E0_REVIEW_WORKFLOW_PATH,
                "--expected-event",
                run_download.E0_REVIEW_EVENT,
                "--expected-head-branch",
                run_download.E0_REVIEW_HEAD_BRANCH,
                "--expected-producer-job",
                PRODUCER_JOB,
            ]
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


def test_checkpoint_prefix_matches_only_canonical_positive_attempt_suffix() -> None:
    prefix = f"range-v16-pair-author-checkpoint-{HEAD_SHA}"
    assert run_download._checkpoint_prefix_matches({"name": f"{prefix}-attempt-1"}, prefix=prefix)
    assert run_download._checkpoint_prefix_matches({"name": f"{prefix}-attempt-123"}, prefix=prefix)
    for name in (
        prefix,
        f"{prefix}-attempt-0",
        f"{prefix}-attempt-01",
        f"{prefix}-attempt--1",
        f"{prefix}-attempt-1-extra",
        f"other-{prefix}-attempt-1",
        f"{prefix}-other-attempt-1",
    ):
        assert not run_download._checkpoint_prefix_matches({"name": name}, prefix=prefix)
    assert not run_download._checkpoint_prefix_matches({"name": 1}, prefix=prefix)


def test_checkpoint_prefix_selects_latest_nonexpired_and_requires_checkpoint_member(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    prefix = f"range-v16-pair-author-checkpoint-{HEAD_SHA}"
    selected_name = f"{prefix}-attempt-2"
    selected_id = ARTIFACT_ID + 2
    downloads: list[tuple[int, str, tuple[str, ...]]] = []
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("Z_SCOPE_E0_REVIEW_ENVIRONMENT", "sealed-benchmark")
    monkeypatch.setenv("GITHUB_TOKEN", "secret")
    monkeypatch.setattr(
        run_download,
        "_list_run_artifacts",
        lambda **_kwargs: [
            {"id": ARTIFACT_ID, "name": ARTIFACT_NAME},
            {
                "id": ARTIFACT_ID + 1,
                "name": f"{prefix}-attempt-1",
                "expired": False,
                "created_at": "2026-08-28T08:44:41Z",
            },
            {
                "id": selected_id,
                "name": selected_name,
                "expired": False,
                "created_at": "2026-08-28T09:02:30Z",
            },
            {
                "id": ARTIFACT_ID + 3,
                "name": f"{prefix}-attempt-3",
                "expired": True,
                "created_at": "2026-08-28T09:10:00Z",
            },
            {"id": ARTIFACT_ID + 4, "name": f"{prefix}-attempt-04"},
            {"id": ARTIFACT_ID + 5, "name": f"{prefix}-attempt-4-extra"},
            {"id": ARTIFACT_ID + 6, "name": f"other-{prefix}-attempt-4"},
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
        downloads.append(
            (
                int(kwargs["artifact_id"]),
                str(kwargs["expected_name"]),
                required_members,
            )
        )
        return "e" * 64

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
                "--optional-checkpoint-prefix",
                f"{prefix}=retained-checkpoint",
            ]
        )
        == 0
    )
    assert downloads == [
        (ARTIFACT_ID, ARTIFACT_NAME, ("manifest.json",)),
        (selected_id, selected_name, ("checkpoint-manifest.json",)),
    ]
    assert (tmp_path / "retained-checkpoint" / "checkpoint-manifest.json").is_file()


def test_checkpoint_prefix_same_second_uses_artifact_id_tiebreak(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    prefix = f"range-v16-pair-author-checkpoint-{HEAD_SHA}"
    lower_id = ARTIFACT_ID + 1
    higher_id = ARTIFACT_ID + 2
    restored: list[tuple[int, str]] = []
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("Z_SCOPE_E0_REVIEW_ENVIRONMENT", "sealed-benchmark")
    monkeypatch.setenv("GITHUB_TOKEN", "secret")
    monkeypatch.setattr(
        run_download,
        "_list_run_artifacts",
        lambda **_kwargs: [
            {
                "id": lower_id,
                "name": f"{prefix}-attempt-9",
                "expired": False,
                "created_at": "2026-08-28T09:02:30Z",
            },
            {
                "id": higher_id,
                "name": f"{prefix}-attempt-1",
                "expired": False,
                "created_at": "2026-08-28T09:02:30Z",
            },
        ],
    )

    def download_and_extract(**kwargs: object) -> str:
        output = kwargs["output"]
        assert isinstance(output, Path)
        output.mkdir()
        (output / "checkpoint-manifest.json").write_text("{}", encoding="utf-8")
        restored.append((int(kwargs["artifact_id"]), str(kwargs["expected_name"])))
        return "f" * 64

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
                "--optional-checkpoint-prefix",
                f"{prefix}=retained-checkpoint",
            ]
        )
        == 0
    )
    assert restored == [(higher_id, f"{prefix}-attempt-1")]


def test_checkpoint_prefix_expired_or_nonmatching_artifacts_are_absent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    prefix = f"range-v16-pair-author-checkpoint-{HEAD_SHA}"
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("Z_SCOPE_E0_REVIEW_ENVIRONMENT", "sealed-benchmark")
    monkeypatch.setenv("GITHUB_TOKEN", "secret")
    monkeypatch.setattr(
        run_download,
        "_list_run_artifacts",
        lambda **_kwargs: [
            {
                "id": ARTIFACT_ID + 1,
                "name": f"{prefix}-attempt-1",
                "expired": True,
                "created_at": "2026-08-28T09:02:30Z",
            },
            {"id": ARTIFACT_ID + 2, "name": f"{prefix}-attempt-02"},
            {"id": ARTIFACT_ID + 3, "name": f"{prefix}-attempt-2-extra"},
            {"id": ARTIFACT_ID + 4, "name": "unrelated"},
        ],
    )
    monkeypatch.setattr(
        run_download,
        "_download_and_extract",
        lambda **_kwargs: pytest.fail("no prefix artifact should be restored"),
    )
    assert (
        run_download.main(
            [
                "--repository",
                REPOSITORY,
                "--expected-run-id",
                RUN_ID,
                "--expected-head-sha",
                HEAD_SHA,
                "--optional-checkpoint-prefix",
                f"{prefix}=retained-checkpoint",
            ]
        )
        == 0
    )
    assert not (tmp_path / "retained-checkpoint").exists()


def test_checkpoint_prefix_rejects_output_conflicts_and_exact_external_mode(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    prefix = f"range-v16-pair-author-checkpoint-{HEAD_SHA}"
    other_prefix = f"range-v16-arbitration-checkpoint-0-{HEAD_SHA}"
    digest = "a" * 64
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("Z_SCOPE_E0_REVIEW_ENVIRONMENT", "sealed-benchmark")
    monkeypatch.setenv("GITHUB_TOKEN", "secret")
    base = [
        "--repository",
        REPOSITORY,
        "--expected-run-id",
        RUN_ID,
        "--expected-head-sha",
        HEAD_SHA,
    ]
    with pytest.raises(ValueError, match="specifications are not unique"):
        run_download.main(
            [
                *base,
                "--optional-checkpoint-prefix",
                f"{prefix}=same-output",
                "--optional-checkpoint-prefix",
                f"{other_prefix}=same-output",
            ]
        )
    with pytest.raises(ValueError, match="choose exactly one"):
        run_download.main(
            [
                *base,
                "--exact-artifact",
                f"{ARTIFACT_NAME}=external={ARTIFACT_ID}=sha256:{digest}",
                "--optional-checkpoint-prefix",
                f"{prefix}=retained-checkpoint",
                "--expected-workflow-path",
                run_download.E0_REVIEW_WORKFLOW_PATH,
                "--expected-event",
                run_download.E0_REVIEW_EVENT,
                "--expected-head-branch",
                run_download.E0_REVIEW_HEAD_BRANCH,
                "--expected-producer-job",
                PRODUCER_JOB,
            ]
        )
