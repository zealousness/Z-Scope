"""Tri-state depth-scoped validation flags (M1/M2/M3').

``None`` resolves by scan depth: enabled for ``balanced``, disabled
elsewhere.  Explicit True/False always wins.
"""

from types import SimpleNamespace

from test_validation_runner import _runner


def _analysis(**overrides):
    base = {
        "validation_uncertain_replay_review": None,
        "validation_demote_source_lifecycle_confirm": None,
        "validation_obligation_infunction_release_guard": None,
    }
    base.update(overrides)
    return SimpleNamespace(**base)


def _flag(depth, analysis):
    scan = SimpleNamespace(depth=depth)
    runner = _runner(
        object(),
        analysis=analysis,
        scan=scan,
    )
    return runner._depth_scoped_flag("validation_demote_source_lifecycle_confirm")


def test_balanced_depth_enables_unspecified_guards():
    assert _flag("balanced", _analysis()) is True


def test_non_balanced_depth_disables_unspecified_guards():
    assert _flag("fast", _analysis()) is False
    assert _flag("deep", _analysis()) is False
    assert _flag("", _analysis()) is False


def test_explicit_true_wins_over_depth():
    assert _flag("fast", _analysis(validation_demote_source_lifecycle_confirm=True)) is True


def test_explicit_false_wins_over_depth():
    assert _flag("balanced", _analysis(validation_demote_source_lifecycle_confirm=False)) is False


def test_missing_scan_section_disables():
    runner = _runner(object(), analysis=_analysis(), scan=None)
    assert runner._depth_scoped_flag("validation_obligation_infunction_release_guard") is False
