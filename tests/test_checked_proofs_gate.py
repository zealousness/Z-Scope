"""Checked-proofs gating: depth-scoped default plus toolchain safety gate.

``validation_checked_proofs`` auto-enables for balanced scans, but stays off
unless every compile_commands driver is bound to the fact compiler.
"""

import json
import sys
from pathlib import Path

from zscope.retrieval.validation_facts import CompleteFactStore


def _store(tmp_path, driver):
    fake_clang = Path(sys.executable)  # portable stand-in for the fact compiler
    cc = tmp_path / "build" / "compile_commands.json"
    cc.parent.mkdir(parents=True, exist_ok=True)
    cc.write_text(json.dumps([
        {
            "directory": str(tmp_path),
            "arguments": [driver, "-c", "x.c"],
            "file": "x.c",
        }
    ]), encoding="utf-8")
    return CompleteFactStore(
        tmp_path, cc, tmp_path / "facts", clang=str(fake_clang)
    )


def test_driver_bound_true_when_driver_matches_fact_compiler(tmp_path):
    fake_clang = str(Path(sys.executable))
    assert _store(tmp_path, fake_clang).driver_bound() is True


def test_driver_bound_false_for_cc_build(tmp_path):
    assert _store(tmp_path, "/usr/bin/cc").driver_bound() is False


def test_driver_bound_false_when_db_missing(tmp_path):
    store = CompleteFactStore(tmp_path, tmp_path / "missing.json", tmp_path / "facts",
                              clang=str(Path(sys.executable)))
    assert store.driver_bound() is False
