from __future__ import annotations

import json

from zscope.cli import benchmark as benchmark_cli


def test_pilot_cli_prints_only_answer_free_completion_summary(
    monkeypatch, capsys, tmp_path
) -> None:
    canary = "SOURCE_EXPECTED_MODEL_OUTPUT_CANARY"
    aggregate = {
        "schema_version": "zscope.formal-benchmark.v3",
        "mode": "pilot",
        "scan_depth": "balanced",
        "all_completed": True,
        "passed": True,
        "formal_benchmark": False,
        "release_eligible": False,
        "runs": [{"issue_records": [canary]}],
    }
    monkeypatch.setattr(benchmark_cli.platform, "system", lambda: "Linux")
    monkeypatch.setattr(benchmark_cli, "require_p6_provider_contract", lambda _path: object())
    monkeypatch.setattr(
        benchmark_cli,
        "reject_conflicting_provider_identity_environment",
        lambda _contract, _environment: None,
    )
    monkeypatch.setattr(benchmark_cli, "run_benchmark", lambda *_args, **_kwargs: aggregate)

    benchmark_cli.main(
        [
            "run",
            "--language",
            "c_cpp",
            "--mode",
            "pilot",
            "--scan-depth",
            "balanced",
            "--output",
            str(tmp_path / "pilot"),
        ]
    )

    stdout = capsys.readouterr().out
    assert canary not in stdout
    assert json.loads(stdout) == {
        "schema_version": "zscope.p6-cli-summary.v1",
        "mode": "pilot",
        "scan_depth": "balanced",
        "completed": True,
        "passed": True,
        "formal_benchmark": False,
        "release_eligible": False,
    }


def test_trial_cli_retains_existing_full_json_output(monkeypatch, capsys, tmp_path) -> None:
    aggregate = {
        "schema_version": "zscope.formal-benchmark.v3",
        "mode": "trial",
        "scan_depth": "balanced",
        "all_completed": True,
        "passed": False,
        "runs": [{"diagnostic": "trial-detail"}],
    }
    monkeypatch.setattr(benchmark_cli.platform, "system", lambda: "Linux")
    monkeypatch.setattr(benchmark_cli, "run_benchmark", lambda *_args, **_kwargs: aggregate)

    benchmark_cli.main(
        [
            "run",
            "--language",
            "c_cpp",
            "--mode",
            "trial",
            "--scan-depth",
            "balanced",
            "--output",
            str(tmp_path / "trial"),
        ]
    )

    assert json.loads(capsys.readouterr().out) == aggregate
