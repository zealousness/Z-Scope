"""Composite consumer revocation; controlled read views never edit host inputs."""

from pathlib import Path

import pytest
from test_instance_currentness_revocation_r33 import (
    native_project,
    native_context,
    digest_view,
    trust_view,
)
from zscope.orchestration.parallel_analyzer import _InstanceEntryLookupIndex
from zscope.semantics import instance_semantics

CHANGES = (
    [
        ("binary", "changed"),
        ("library", "changed"),
    ]
    + [
        (header, change)
        for header in ("/usr/include/stdlib.h", "/usr/include/features.h")
        for change in ("uid", "group_write", "other_write", "symlink", "missing")
    ]
    + [
        (parent, change)
        for parent in ("/usr/include", "/usr", "/")
        for change in ("uid", "group_write", "symlink", "missing")
    ]
)


def lookup(native):
    entry, scope = native.parallel._current_instance_entries(native.plan)[0]
    return (
        _InstanceEntryLookupIndex(native.index, scope, entry, semantics_context=native.context),
        entry.function_name,
    )


def revoke(native, monkeypatch, kind, change):
    if kind in {"binary", "library"}:
        path = Path(
            native.binary["path"]
            if kind == "binary"
            else next(iter(native.binary["shared_libraries"]))
        )
        digest_view(monkeypatch, path, "0" * 64)
    else:
        trust_view(monkeypatch, Path(kind), change)


def test_current_composite_retains_real_factory_standard_authority(native_context):
    classified, caller = lookup(native_context)
    assert classified.call_model_status("malloc", caller) == "standard_model"
    assert classified.call_model_status("free", caller) == "standard_model"


@pytest.mark.parametrize("when", ["before", "after"])
@pytest.mark.parametrize(
    "kind,change", CHANGES, ids=[f"{kind}-{change}" for kind, change in CHANGES]
)
def test_actual_classifier_rechecks_composite_authority(
    native_context, monkeypatch, when, kind, change
):
    native = native_context
    classified, caller = lookup(native)
    assert classified.call_model_status("free", caller) == "standard_model"
    materialize = instance_semantics.materialize_effect_semantics
    reached = []
    if when == "before":
        revoke(native, monkeypatch, kind, change)
    else:

        def materialize_then_revoke(snapshot):
            effects = materialize(snapshot)
            assert snapshot is native.snapshot
            reached.append(True)
            revoke(native, monkeypatch, kind, change)
            return effects

        monkeypatch.setattr(
            instance_semantics, "materialize_effect_semantics", materialize_then_revoke
        )
    with pytest.raises(ValueError, match="instance_semantics_not_current"):
        classified.call_model_status("free", caller)
    assert reached == ([] if when == "before" else [True])
    assert not native.context.is_current(native.snapshot)
