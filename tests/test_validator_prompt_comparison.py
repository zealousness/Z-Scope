"""The live comparison must not turn abstention or protocol failure into accuracy."""

from pathlib import Path
import runpy

import pytest

EXPERIMENT = (
    Path(__file__).resolve().parent / "fixtures/validator_prompt_compaction"
)
SCORER = runpy.run_path(str(EXPERIMENT / "score.py"))


def result(verdict, *, parsed=True):
    return {
        "success": True,
        "data": {"verdict": verdict},
        "metadata": {"validator_protocol_audit": {"parsed": parsed}},
        "seconds": 1,
        "usage": {
            "consumed_tokens": 30,
            "usage_attribution": {
                "totals": dict.fromkeys(
                    (
                        "prompt_tokens",
                        "completion_tokens",
                        "total_tokens",
                        "cached_prompt_tokens",
                        "reasoning_tokens",
                        "request_count",
                        "provider_reported_calls",
                        "estimated_or_conservative_calls",
                        "failed_or_unknown_calls",
                    ),
                    0,
                )
            },
        },
    }


@pytest.mark.parametrize(
    "verdict,parsed", [("uncertain", True), ("rejected", True), ("uncertain", False)]
)
def test_known_defect_abstention_and_invalid_protocol_are_misses(verdict, parsed):
    expected = {
        "id": "c",
        "truth_class": "defect",
        "expected_verdict": "verified",
        "scope": "candidate",
        "correlation_group": "one",
    }
    before, after = result("verified"), result(verdict, parsed=parsed)
    row = SCORER["score_pair"](expected, before, after)
    metrics = SCORER["arm_metrics"]([row], {("c", "after"): after}, "after")
    assert row["regression"] and not row["agree"]
    assert metrics["false_negatives"] == 1 and metrics["true_positives"] == 0
    assert metrics["protocol_successes"] == int(parsed)


def test_two_invalid_results_do_not_count_as_consistent_decisions():
    expected = {
        "id": "c",
        "truth_class": "unresolved",
        "expected_verdict": "uncertain",
        "scope": "candidate",
        "correlation_group": "one",
    }
    invalid = result("uncertain", parsed=False)
    assert not SCORER["score_pair"](expected, invalid, invalid)["agree"]


def test_source_fragments_do_not_claim_false_line_numbers_or_expose_answer_files():
    runner = runpy.run_path(str(EXPERIMENT / "run.py"))
    case = {
        "id": "c",
        "stage": "investigation_synthesis",
        "finding": {"function": "f"},
        "source_files": {"unit.c": "int f(void) { return 0; }"},
        "visible_files": [],
        "initial_code": [{"file": "unit.c", "code": "int f(void);"}],
    }
    evidence = runner["evidence_input"](case)["evidence_slice"]
    assert "start_line" not in evidence["evidence_ref_catalog"]["SRC_1"]
    reader = runner["SourceReader"](case["source_files"])
    assert reader.validate_arguments({"file_path": "expected.json"}) is not None
    assert reader.validate_arguments({"file_path": "../expected.json"}) is not None
    assert reader.execute({"file_path": "unit.c"})["data"]["code"] == case["source_files"]["unit.c"]
