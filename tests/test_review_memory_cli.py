import json
from types import SimpleNamespace

import pytest
from click.testing import CliRunner

from zscope.cli.review_memory import _filter_extraction_records, replay
from zscope.reporting.json_io import write_json_atomic
from zscope.review_memory.extractor import proposal_from_record


@pytest.mark.parametrize("shared", [False, True])
def test_replay_cli_reads_legacy_and_shared_reports(tmp_path, shared):
    finding = {
        "id": "finding-1",
        "rule": "R",
        "category": "C",
        "stable_fingerprint": "fp",
        "source_context_fingerprint": "source",
        "validation_status": "validated",
    }
    pattern = proposal_from_record({
        "review_id": "review-1",
        "project_id": "project-1",
        "finding": finding,
        "source_context": {"source_context_fingerprint": "source"},
    })
    pattern.update({"status": "advisory", "required_checks": ["recheck current source"]})
    path = tmp_path / "report.json"
    write_json_atomic(path, {"issues": [finding]}, shared=shared)
    original = path.read_bytes()
    matches = []
    audits = []
    store = SimpleNamespace(
        get_proposal=lambda _: pattern,
        save_match=matches.append,
        append_audit=lambda event, payload: audits.append((event, payload)),
    )

    result = CliRunner().invoke(
        replay, [pattern["pattern_id"], "--input", str(path)], obj={"store": store}
    )

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["candidate_count"] == payload["matched"] == 1
    assert payload["potential_false_suppression"] == 1
    assert payload["verdict_changed"] is False
    assert len(matches) == 1
    assert audits[0][0] == "pattern_replayed"
    assert path.read_bytes() == original


def test_retry_failed_only_selects_failed_records():
    records = [
        {"review_id": "pending", "status": "pending_extraction"},
        {"review_id": "failed", "status": "proposal_failed"},
        {"review_id": "done", "status": "extracted"},
    ]
    assert [item["review_id"] for item in _filter_extraction_records(records, retry_failed=True, retry_all=False)] == ["failed"]


def test_retry_all_selects_every_record():
    records = [{"review_id": value, "status": status} for value, status in (("a", "pending_extraction"), ("b", "proposal_failed"), ("c", "extracted"), ("d", "superseded"))]
    assert [item["review_id"] for item in _filter_extraction_records(records, retry_failed=False, retry_all=True)] == ["a", "b", "c"]


def test_retry_failed_excludes_superseded_records():
    records = [{"review_id": value, "status": status} for value, status in (("failed", "proposal_failed"), ("old", "superseded"))]
    assert [item["review_id"] for item in _filter_extraction_records(records, retry_failed=True, retry_all=False)] == ["failed"]


def test_default_extraction_skips_failed_and_extracted():
    records = [{"review_id": value, "status": status} for value, status in (("a", "pending_extraction"), ("b", "proposal_failed"), ("c", "extracted"))]
    assert [item["review_id"] for item in _filter_extraction_records(records, retry_failed=False, retry_all=False)] == ["a"]
