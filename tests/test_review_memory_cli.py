from zscope.cli.review_memory import _filter_extraction_records


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
