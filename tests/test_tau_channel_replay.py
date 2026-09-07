"""Drift guard: the offline tau-channel replay must mirror the pipeline policy.

The replay measurement (``scripts/replay_tau_channel.py``) re-implements
``ValidationPipeline._high_confidence_uncertain_confirms`` as an offline
predicate.  This test pins the two together so a policy change cannot silently
invalidate replay conclusions.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict

from zscope.core.validation.pipeline import ValidationPipeline
from scripts.replay_tau_channel import _tau_predicate

TRIAL = Path("benchmark-artifacts/c_cpp/trial/20260904T094432Z/run-01")


def _pipeline_with(threshold: float) -> Any:
    pipeline = ValidationPipeline.__new__(ValidationPipeline)
    pipeline.uncertain_confirm_threshold = threshold
    return pipeline


def _load_needs_review_uncertain() -> list:
    report = json.loads((TRIAL / "report.json").read_text(encoding="utf-8"))
    return [
        issue
        for issue in report.get("issues_with_needs_review") or []
        if str(issue.get("validator_verdict") or "") == "uncertain"
    ]


def test_offline_tau_predicate_matches_pipeline_policy() -> None:
    issues = _load_needs_review_uncertain()
    assert issues, "frozen trial must contain uncertain needs-review issues"

    for tau in (0.80, 0.85, 0.90):
        pipeline = _pipeline_with(tau)
        for issue in issues:
            final_score = float(issue.get("final_score") or 0.0)
            expected = _tau_predicate(issue, tau)
            actual = pipeline._high_confidence_uncertain_confirms(
                issue,
                {"confidence_score": issue.get("confidence")},
                final_score,
            )
            assert actual == expected, (
                f"tau={tau} cluster={issue.get('validation_cluster_uid')}: "
                f"offline={expected} pipeline={actual}"
            )


def test_pipeline_declines_when_threshold_disabled() -> None:
    issues = _load_needs_review_uncertain()
    pipeline = _pipeline_with(None)
    for issue in issues[:10]:
        assert (
            pipeline._high_confidence_uncertain_confirms(
                issue,
                {"confidence_score": issue.get("confidence")},
                float(issue.get("final_score") or 0.0),
            )
            is False
        )
