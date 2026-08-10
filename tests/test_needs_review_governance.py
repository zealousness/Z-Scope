import json

from scripts.replay_needs_review_governance import replay


def test_streaming_governance_replay_preserves_occurrences_and_groups_entries(
    tmp_path,
) -> None:
    observations = [
        {
            "id": f"ISSUE_{index}",
            "entry_identity": f"entry_{index}",
            "call_path": [f"entry_{index}", "sink"],
            "function": "sink",
            "location": "src/demo.c:42",
            "category": "bounds",
            "source": "len",
            "sink": "memcpy(dst, src, len)",
            "candidate_disposition": "needs_review",
            "validation_status": "needs_review",
        }
        for index in range(88)
    ]
    report = {
        "summary": {"audit_observations": len(observations)},
        "metadata": {"audit_observations": observations},
    }
    path = tmp_path / "legacy_report.json"
    path.write_text(json.dumps(report), encoding="utf-8")

    summary = replay(
        path,
        project_id="demo",
        project_root=str(tmp_path),
        revision="REV",
    )

    assert summary["raw_observation_count"] == 88
    assert summary["raw_occurrence_count"] == 88
    assert summary["retained_occurrence_count"] == 88
    assert summary["unique_validation_group_count"] == 1
    assert summary["grouped_alias_count"] == 87
    assert summary["occurrence_loss_count"] == 0


def test_streaming_governance_replay_separates_operational_obligations(
    tmp_path,
) -> None:
    report = {
        "metadata": {
            "audit_observations": [
                {
                    "candidate_uid": "ENGINE",
                    "candidate_disposition": "engine_failed",
                    "record_role": "operational_obligation",
                    "reason": "timeout",
                }
            ]
        }
    }
    path = tmp_path / "operational.json"
    path.write_text(json.dumps(report), encoding="utf-8")

    summary = replay(
        path,
        project_id="demo",
        project_root=str(tmp_path),
        revision="REV",
    )

    assert summary["displayed_review_count"] == 0
    assert summary["operational_obligation_count"] == 1
