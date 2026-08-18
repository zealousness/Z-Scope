from pathlib import Path

from scripts.check_p4_hypothesis_lifecycle import check


def test_p4_hypothesis_hunter_remains_shadow_until_p5() -> None:
    root = Path(__file__).resolve().parents[1]
    assert check(root) == []
