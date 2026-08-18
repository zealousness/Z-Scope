from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest


@pytest.mark.parametrize(
    "relative_path",
    (
        "scripts/audit_rule_qualifications.py",
        "scripts/aggregate_range_release_runs.py",
        "scripts/balanced_rollout_operator.py",
        "scripts/describe_validator_replay_provider.py",
        "scripts/evaluate_release_candidate.py",
        "scripts/export_validator_replay_bundle.py",
        "scripts/plan_discovery_ablation.py",
        "scripts/run_discovery_ablation_request.py",
        "scripts/run_validator_replay.py",
        "scripts/score_validator_replay_experiment.py",
        "scripts/score_discovery_ablation_experiment.py",
        "scripts/verify_balanced_default_attestation.py",
        "scripts/build_e0_attestation.py",
        "scripts/build_e0_review_manifest.py",
        "scripts/build_e0_review_provenance.py",
        "scripts/run_e0_reviewers.py",
        "scripts/verify_e0_attestation.py",
        "scripts/verify_e0_review_provenance.py",
        "scripts/score_range_v5.py",
    ),
)
def test_direct_script_help_uses_worktree(relative_path: str, tmp_path: Path) -> None:
    repository = Path(__file__).resolve().parents[1]
    completed = subprocess.run(
        [sys.executable, str(repository / relative_path), "--help"],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        check=False,
    )

    assert completed.returncode == 0, completed.stderr
    assert "usage:" in completed.stdout
