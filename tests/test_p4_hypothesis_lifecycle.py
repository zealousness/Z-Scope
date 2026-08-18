from pathlib import Path

from scripts.check_p4_hypothesis_lifecycle import check


def test_p5_hypothesis_hunter_is_candidate_registration_only() -> None:
    root = Path(__file__).resolve().parents[1]
    assert check(root) == []
