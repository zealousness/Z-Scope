from zscope.review_memory.extractor import proposal_from_record
from zscope.review_memory.replay import paired_replay


def test_paired_replay_is_advisory_only_and_reports_potential_impact():
    record = {
        "review_id": "r",
        "project_id": "p",
        "finding": {"rule": "R", "category": "C", "stable_fingerprint": "fp"},
        "source_context": {"source_context_fingerprint": "src"},
    }
    pattern = proposal_from_record(record)
    pattern.update({"status": "advisory", "required_checks": ["recheck"]})
    payload = {
        "issues": [
            {"id": "tp", "rule": "R", "category": "C", "stable_fingerprint": "fp", "source_context_fingerprint": "src", "validation_status": "validated"},
            {"id": "fp", "rule": "R", "category": "C", "stable_fingerprint": "fp", "source_context_fingerprint": "changed", "validation_status": "rejected", "user_rebuttal": "manual"},
        ]
    }
    result = paired_replay(payload, pattern)
    assert result["candidate_count"] == 2
    assert result["matched"] == 1
    assert result["potential_false_suppression"] == 1
    assert result["verdict_changed"] is False
    assert result["validator_invoked"] is False
