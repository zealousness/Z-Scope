import json
from pathlib import Path

from scripts.qualify_p4_hypothesis_hunter import qualify
from zscope.orchestration.hypothesis_hunter.qualification import (
    load_builtin_qualification,
)


def test_p4_neutral_corpus_qualifies_and_matches_packaged_artifact() -> None:
    generated = qualify()
    packaged = load_builtin_qualification()
    assert generated["content_sha256"] == packaged["content_sha256"]
    assert packaged["case_count"] == 120
    assert packaged["safe_case_count"] == 48
    assert packaged["safe_false_acceptance_count"] == 0
    assert packaged["near_miss_false_acceptance_count"] == 0
    assert packaged["contract_resolution_percent"] == 100.0
    assert packaged["metamorphic_consistent"] is True
    assert len(packaged["projects_with_replayable_proof"]) == 3


def test_p4_source_and_expected_contracts_are_separate() -> None:
    root = Path(__file__).resolve().parent / "fixtures/p4_hypothesis_hunter"
    source = json.loads((root / "source-corpus.json").read_text(encoding="utf-8"))
    expected = json.loads((root / "expected-results.json").read_text(encoding="utf-8"))
    assert "classification_by_variant_index" not in source
    assert "expected_registration" not in source
    assert expected["classification_by_variant_index"]
