"""Real-native hot-cache reuse and include-premise invalidation (R19).

Cache bytes establish artifact stability; actual extraction processes are
independently counted by the coordinator's native process probes.

Every test here runs the real batch indexer tool against real fixtures on
this machine: cold builds really execute native processes, warm re-runs
really reuse cache packages (verified byte-stable, not by label), and every
invalidation case proves the affected TU is recompiled *and* that the
incremental facts equal a fresh clean build, so semantics and coverage are
not lost.  Nothing mocks the indexer, the backend or the cache.

The pinned contract is the current precise include-premise semantics
(``zscope.include-probes.v1``):

* a negative existence premise (``__has_include`` of a missing header) that
  is *still missing* on re-verification is reusable — a warm rebuild is not
  required and must not be forced;
* the probed header appearing, a positively probed header disappearing, or
  any new file in an include search root invalidates reuse;
* reuse never changes the extracted facts, and invalidation followed by a
  rebuild reproduces exactly what a clean build produces.
"""

from __future__ import annotations

import hashlib
import json
import os
import platform
from pathlib import Path
from typing import Any, Dict, List, Tuple

import pytest

from zscope.retrieval.clang_batch import find_indexer
from zscope.retrieval.incremental_replay import (
    _build,
    _capture,
    compare_facts,
    write_fixture,
)

pytestmark = pytest.mark.skipif(
    not os.environ.get("Z_SCOPE_TEST_CLANG_INDEXER") or platform.system() != "Linux",
    reason="native hot-cache tests require Z_SCOPE_TEST_CLANG_INDEXER on Linux",
)


def _native() -> Tuple[str, Dict[str, Any]]:
    native = find_indexer(os.environ["Z_SCOPE_TEST_CLANG_INDEXER"])
    assert native, "compatible native indexer unavailable"
    return native


def _backend(native: Tuple[str, Dict[str, Any]], area: Path):
    from zscope.retrieval.clang_backend import ClangBackend

    area.mkdir(parents=True, exist_ok=True)
    return ClangBackend(
        frontend="batch",
        clang_indexer_path=native[0],
        db_path=str(area / "facts.db"),
        max_threads=1,
    )


def _negative_test_fixture(root: Path) -> None:
    """The replay fixture with ``-DNEGATIVE_TEST=1`` on the a.c variants.

    This is exactly what ``run_fixture_replay`` does for the
    ``negative_include`` mutation: the ``__has_include("late.h")`` premise is
    genuinely evaluated by the preprocessor, and ``late.h`` does not exist at
    baseline, so the native tool records a negative existence probe.
    """

    write_fixture(root)
    commands_path = root / "compile_commands.json"
    commands = json.loads(commands_path.read_text(encoding="utf-8"))
    for command in commands:
        if Path(command["file"]).name == "a.c":
            command["arguments"].insert(1, "-DNEGATIVE_TEST=1")
    commands_path.write_text(json.dumps(commands), encoding="utf-8")


def _cache_fingerprint(backend: Any) -> List[Tuple[str, str]]:
    """Hash the TU package artifacts; the per-run stats report is bookkeeping.

    ``latest_run.json`` is rewritten by every run — including an all-reuse
    run — so it is excluded: reuse proof is about the TU packages (manifest,
    jsonl output, job file) staying byte-identical.
    """

    cache = Path(backend._db_path).resolve().parent / "clang_batch_cache"
    return sorted(
        (path.name, hashlib.sha256(path.read_bytes()).hexdigest())
        for path in cache.iterdir()
        if path.is_file() and path.name != "latest_run.json"
    )


def test_negative_premise_still_missing_reuses_and_preserves_facts(tmp_path: Path):
    """A still-missing negative premise is reusable; no forced warm rebuild.

    The re-verification in ``include_probes_current`` re-checks the recorded
    existence queries: ``late.h`` is still absent, so the warm run reuses all
    cached TU packages without AST extraction (version and loader queries are separate), and the
    extracted facts are byte-for-byte the same as the cold run's.
    """

    native = _native()
    root = tmp_path / "source"
    _negative_test_fixture(root)
    backend = _backend(native, tmp_path / "incremental")
    try:
        cold = _build(backend, root, initial=True)
        assert cold["rebuilt_tus"] == 4 and cold["reused_tus"] == 0
        before = _capture(backend, root, native)
        cache_before = _cache_fingerprint(backend)

        hot = _build(backend, root, initial=False)
        assert hot["rebuilt_tus"] == 0, "a still-missing premise must not force a rebuild"
        assert hot["reused_tus"] == 4
        after = _capture(backend, root, native)
        assert compare_facts(before, after)["equal"], "reuse changed the extracted facts"
        # TU byte stability alone does not count processes: not a single cache
        # artifact (package manifest, jsonl output, job file) was rewritten.
        assert _cache_fingerprint(backend) == cache_before
    finally:
        backend.close()


def test_missing_probe_target_appearing_invalidates_and_matches_clean(tmp_path: Path):
    """The probed header appearing flips the premise and forces a rebuild.

    ``late.h`` is created after the cold build: the recorded negative probe
    is no longer current and the search-root membership changed, so reuse is
    refused, the affected TU is recompiled, and the incremental result must
    equal a fresh clean build of the same mutated fixture (no semantics or
    coverage lost), while genuinely differing from the pre-mutation facts.
    """

    native = _native()
    root = tmp_path / "source"
    _negative_test_fixture(root)
    incremental = _backend(native, tmp_path / "incremental")
    try:
        cold = _build(incremental, root, initial=True)
        assert cold["reused_tus"] == 0
        baseline = _capture(incremental, root, native)

        (root / "late.h").write_text("#define LATE_VALUE 13\n", encoding="utf-8")
        warm = _build(incremental, root, initial=False)
        assert warm["rebuilt_tus"] >= 1, "an appearing probe target must invalidate reuse"
        assert warm["reused_tus"] < cold["rebuilt_tus"]
        after = _capture(incremental, root, native)
        assert not compare_facts(baseline, after)[
            "equal"
        ], "the appearing header must be observable in the extracted facts"
    finally:
        incremental.close()

    clean = _backend(native, tmp_path / "clean")
    try:
        _build(clean, root, initial=True)
        clean_facts = _capture(clean, root, native)
    finally:
        clean.close()
    difference = compare_facts(after, clean_facts)
    assert difference["equal"], difference["differences"][:3]


def _positive_probe_fixture(root: Path) -> None:
    """A fixture whose ``__has_include("opt.h")`` premise is positive."""

    root.mkdir(parents=True, exist_ok=False)
    (root / "shared.h").write_text(
        "#pragma once\n" "typedef struct Item { int value; } Item;\n" "int target_a(Item *);\n",
        encoding="utf-8",
    )
    (root / "opt.h").write_text("#define OPT_VALUE 7\n", encoding="utf-8")
    (root / "a.c").write_text(
        '#include "shared.h"\n'
        '#if __has_include("opt.h")\n#include "opt.h"\n#else\n#define OPT_VALUE 0\n#endif\n'
        "int entry(Item *item) { return item->value + OPT_VALUE; }\n",
        encoding="utf-8",
    )
    (root / "compile_commands.json").write_text(
        json.dumps(
            [
                {
                    "directory": str(root),
                    "file": str(root / "a.c"),
                    "arguments": ["clang", "-std=c11", "-I", str(root), "-c", str(root / "a.c")],
                }
            ]
        ),
        encoding="utf-8",
    )


def test_positively_probed_header_disappearing_invalidates(tmp_path: Path):
    """A positively probed header that disappears flips the premise.

    The recorded ``found`` probe requires its target file to still exist; a
    deletion invalidates reuse, the TU is recompiled, and the incremental
    facts equal a fresh clean build of the mutated fixture.
    """

    native = _native()
    root = tmp_path / "source"
    _positive_probe_fixture(root)
    backend = _backend(native, tmp_path / "incremental")
    try:
        cold = _build(backend, root, initial=True)
        assert cold["rebuilt_tus"] == 1 and cold["reused_tus"] == 0
        baseline = _capture(backend, root, native)

        (root / "opt.h").unlink()
        warm = _build(backend, root, initial=False)
        assert warm["rebuilt_tus"] == 1, "a disappearing probe target must invalidate reuse"
        assert warm["reused_tus"] == 0
        after = _capture(backend, root, native)
        assert not compare_facts(baseline, after)[
            "equal"
        ], "the disappearing header must be observable in the extracted facts"
    finally:
        backend.close()

    clean = _backend(native, tmp_path / "clean")
    try:
        _build(clean, root, initial=True)
        clean_facts = _capture(clean, root, native)
    finally:
        clean.close()
    difference = compare_facts(after, clean_facts)
    assert difference["equal"], difference["differences"][:3]


def _shadow_fixture(base: Path) -> Path:
    """Two TUs with a higher-priority include root that is empty at baseline.

    The higher-priority root lives *outside* the source tree (a sibling
    directory), so only ``src/a.c`` — which names it in its ``-I`` order —
    depends on its membership.  ``a.c`` resolves ``shared.h`` through the
    ``-I`` order (its own directory has no such header), so creating
    ``priority/shared.h`` shadows the source header for it; ``b.c`` sits
    next to the source header, whose quoted-include current-directory rule
    keeps resolving it, so both headers stay covered after the shadow
    appears.  Returns the source root.
    """

    root = base / "source"
    root.mkdir(parents=True, exist_ok=False)
    (base / "priority").mkdir()
    (root / "src").mkdir()
    (root / "shared.h").write_text(
        "#pragma once\n" "typedef struct Item { int value; } Item;\n" "#define HEADER_VALUE 1\n",
        encoding="utf-8",
    )
    (root / "src" / "a.c").write_text(
        '#include "shared.h"\n' "int entry(Item *item) { return item->value + HEADER_VALUE; }\n",
        encoding="utf-8",
    )
    (root / "b.c").write_text(
        '#include "shared.h"\n' "int base(Item *item) { return item->value - HEADER_VALUE; }\n",
        encoding="utf-8",
    )
    (root / "compile_commands.json").write_text(
        json.dumps(
            [
                {
                    "directory": str(root),
                    "file": str(root / "src" / "a.c"),
                    "arguments": [
                        "clang",
                        "-std=c11",
                        "-I",
                        str(base / "priority"),
                        "-I",
                        str(root),
                        "-c",
                        str(root / "src" / "a.c"),
                    ],
                },
                {
                    "directory": str(root),
                    "file": str(root / "b.c"),
                    "arguments": [
                        "clang",
                        "-std=c11",
                        "-I",
                        str(root),
                        "-c",
                        str(root / "b.c"),
                    ],
                },
            ]
        ),
        encoding="utf-8",
    )
    return root


def test_higher_priority_shadow_header_invalidates_and_changes_facts(tmp_path: Path):
    """A new header in a higher-priority search root invalidates reuse.

    The empty higher-priority root is part of ``src/a.c``'s recorded search
    premise; creating ``priority/shared.h`` changes its membership, so that TU
    is recompiled and now resolves ``shared.h`` to the shadow — observable in
    the extracted facts — while ``b.c`` (whose premise did not change)
    legitimately reuses.  The result equals a fresh clean build of the same
    mutated fixture, and both headers stay covered.
    """

    native = _native()
    root = _shadow_fixture(tmp_path)
    backend = _backend(native, tmp_path / "incremental")
    try:
        cold = _build(backend, root, initial=True)
        assert cold["rebuilt_tus"] == 2 and cold["reused_tus"] == 0
        baseline = _capture(backend, root, native)

        (tmp_path / "priority" / "shared.h").write_text(
            "#pragma once\n"
            "typedef struct Item { int value; } Item;\n"
            "#define HEADER_VALUE 5\n",
            encoding="utf-8",
        )
        warm = _build(backend, root, initial=False)
        assert warm["rebuilt_tus"] == 1, "the TU sharing the shadowed root must invalidate"
        assert warm["reused_tus"] == 1, "an unchanged premise may legitimately reuse"
        after = _capture(backend, root, native)
        assert not compare_facts(baseline, after)[
            "equal"
        ], "the higher-priority shadow must be observable in the extracted facts"
    finally:
        backend.close()

    clean = _backend(native, tmp_path / "clean")
    try:
        _build(clean, root, initial=True)
        clean_facts = _capture(clean, root, native)
    finally:
        clean.close()
    difference = compare_facts(after, clean_facts)
    assert difference["equal"], difference["differences"][:3]


def test_uncovered_new_header_is_refused_not_silently_reused(tmp_path: Path):
    """A new header no TU includes is an honest strict-batch refusal.

    The new file changes the search premise (reuse is refused and the affected
    TU is recompiled), but it is covered by no compilation unit, so strict
    batch must name it as requiring LSP instead of silently reusing stale
    packages or publishing incomplete coverage.
    """

    native = _native()
    root = tmp_path / "source"
    write_fixture(root)
    backend = _backend(native, tmp_path / "incremental")
    try:
        cold = _build(backend, root, initial=True)
        assert cold["rebuilt_tus"] == 4 and cold["reused_tus"] == 0

        (root / "unrelated.h").write_text("#define UNRELATED 1\n", encoding="utf-8")
        with pytest.raises(RuntimeError):
            _build(backend, root, initial=False)
        # The per-run report is the authoritative account of the refused run:
        # the premise change really invalidated reuse (nothing was served
        # stale) and the uncovered file is named, not hidden.
        run_report = json.loads(
            (Path(backend._db_path).parent / "clang_batch_cache" / "latest_run.json").read_text(
                encoding="utf-8"
            )
        )
        assert run_report["compiled_tus"] >= 1, "the new file must invalidate reuse"
        assert run_report["reused_tus"] == 0
        assert any(
            path.endswith("unrelated.h") for path in run_report["fallback_files"]
        ), run_report["fallback_files"]
        assert run_report["error"]
    finally:
        backend.close()


def test_focused_negative_include_replay_pins_the_current_contract(tmp_path: Path):
    """The focused replay for ``negative_include`` under current semantics.

    Cold builds 4, the unchanged warm baseline reuses 4 (the still-missing
    premise is re-verified, not rebuilt), the mutation invalidates, the
    clean control rebuilds from scratch, and the whole replay completes with
    zero unexplained semantic differences.  This is the shape the strict
    ``baseline_hot`` assertion needs to move to; the old expectation of two
    warm rebuilds encoded the pre-``include-probes.v1`` conservative
    invalidation, which the precise re-verification replaced.
    """

    from zscope.retrieval.incremental_replay import run_fixture_replay

    result = run_fixture_replay(
        tmp_path / "focused replay",
        clang_indexer=os.environ["Z_SCOPE_TEST_CLANG_INDEXER"],
        mutations=("negative_include",),
    )
    assert result["complete"], [(row["mutation"], row.get("reason")) for row in result["mutations"]]
    assert result["unexplained_semantic_differences"] == 0
    (row,) = result["mutations"]
    stages = row["stages"]
    assert stages["baseline_cold"]["rebuilt_tus"] == 4
    assert stages["baseline_cold"]["reused_tus"] == 0
    assert stages["baseline_hot"]["rebuilt_tus"] == 0
    assert stages["baseline_hot"]["reused_tus"] == 4
    assert stages["incremental"]["rebuilt_tus"] >= 1, "the appearing header must invalidate"
    assert stages["clean"]["reused_tus"] == 0
    assert row["mutation_changed_facts"] is True
    assert row["status"] == "passed"
