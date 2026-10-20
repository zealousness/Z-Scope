"""Actual native process counts and premise changes; fixtures, not full scans."""
import json
import hashlib
import os
from pathlib import Path
import subprocess

import pytest
from zscope.retrieval.clang_backend import ClangBackend
from zscope.retrieval.clang_batch import find_indexer
from zscope.retrieval.incremental_replay import _build, _capture, compare_facts, write_fixture


class RecordedCalls(list):
    phase = "capability"


@pytest.fixture
def native_calls(monkeypatch, request):
    executable = Path(os.environ["Z_SCOPE_TEST_CLANG_INDEXER"]).resolve()
    original = subprocess.Popen
    calls = RecordedCalls()

    def recording_popen(*args, **kwargs):
        argv = kwargs.get("args", args[0] if args else ())
        values = [os.fspath(v) for v in argv] if isinstance(argv, (tuple, list)) else []
        process = original(*args, **kwargs)
        if any(v.startswith("/") and Path(v).resolve() == executable for v in values):
            launcher = Path(values[0]).name if values else ""
            operation = "loader-provenance" if launcher == "ldd" else next((v for v in ("--job", "--check-arguments", "--capabilities", "--version") if v in values), "other")
            calls.append({"pid": process.pid, "launcher": launcher, "extraction": "--job" in values, "operation": operation, "phase": calls.phase})
        return process

    monkeypatch.setattr(subprocess, "Popen", recording_popen)
    native = find_indexer(str(executable))
    assert native
    yield native, calls
    destination = os.environ.get("ZSCOPE_NATIVE_PROCESS_EVIDENCE")
    if destination:
        output = Path(destination)
        output.mkdir(parents=True, exist_ok=True)
        name = hashlib.sha256(request.node.nodeid.encode()).hexdigest()[:16] + ".json"
        (output / name).write_text(json.dumps({"nodeid": request.node.nodeid, "calls": calls}, indent=2) + "\n", encoding="utf-8")


def backend(native, path):
    return ClangBackend(frontend="batch", clang_indexer_path=native[0], db_path=str(path / "facts.db"), max_threads=1)


def extraction_count(calls):
    return sum(r["extraction"] for r in calls)


@pytest.mark.parametrize("initially_present", [False, True])
def test_actual_native_process_reuse_and_include_premise_flip(tmp_path, native_calls, initially_present):
    native, calls = native_calls
    root = tmp_path / "source"
    write_fixture(root)
    commands_path = root / "compile_commands.json"
    commands = json.loads(commands_path.read_text(encoding="utf-8"))
    for command in commands:
        if Path(command["file"]).name == "a.c":
            command["arguments"].insert(1, "-DNEGATIVE_TEST=1")
    commands_path.write_text(json.dumps(commands), encoding="utf-8")
    late = root / "late.h"
    if initially_present:
        late.write_text("#define LATE_VALUE 13\n", encoding="utf-8")
    incremental = backend(native, tmp_path / "incremental")
    try:
        mark = len(calls)
        calls.phase = "cold"
        cold = _build(incremental, root, initial=True)
        assert cold["rebuilt_tus"] == extraction_count(calls[mark:]) == 4
        baseline = _capture(incremental, root, native)
        mark = len(calls)
        calls.phase = "hot"
        hot = _build(incremental, root, initial=False)
        unchanged = _capture(incremental, root, native)
        assert extraction_count(calls[mark:]) == 0, "unchanged warm build must launch no native extraction"
        assert not any(r["operation"] == "--check-arguments" for r in calls[mark:]), "hot argument preparation must not rerun argument checks"
        assert hot["rebuilt_tus"] == 0 and hot["reused_tus"] == 4
        assert compare_facts(baseline, unchanged)["equal"]
        if initially_present:
            late.unlink()
        else:
            late.write_text("#define LATE_VALUE 13\n", encoding="utf-8")
        mark = len(calls)
        calls.phase = "mutation"
        changed = _build(incremental, root, initial=False)
        assert changed["rebuilt_tus"] == extraction_count(calls[mark:]) >= 2
        after = _capture(incremental, root, native)
        assert not compare_facts(baseline, after)["equal"]
    finally:
        incremental.close()
    clean = backend(native, tmp_path / "clean")
    try:
        mark = len(calls)
        calls.phase = "clean"
        control = _build(clean, root, initial=True)
        assert control["rebuilt_tus"] == extraction_count(calls[mark:]) == 4
        assert control["reused_tus"] == 0
        difference = compare_facts(after, _capture(clean, root, native))
        assert difference["equal"], difference["differences"][:3]
    finally:
        clean.close()


def test_actual_native_process_observes_higher_priority_header(tmp_path, native_calls):
    native, calls = native_calls
    root, lower = tmp_path / "source", tmp_path / "external-headers"
    root.mkdir()
    lower.mkdir()
    priority = root / "priority"
    priority.mkdir()
    header = "#define HEADER_VALUE {}\n"
    (lower / "shared.h").write_text(header.format(1), encoding="utf-8")
    source = root / "a.c"
    # Angle lookup really follows -I order. The old lower-priority dependency
    # is outside the declared source inventory, so shadowing it does not leave
    # an unrelated unindexed project header behind.
    source.write_text("#include <shared.h>\nint entry(void) { return HEADER_VALUE; }\n", encoding="utf-8")
    (root / "compile_commands.json").write_text(json.dumps([{"directory": str(root), "file": str(source), "arguments": ["clang", "-I", str(priority), "-I", str(lower), "-c", str(source)]}]), encoding="utf-8")
    incremental = backend(native, tmp_path / "incremental")
    try:
        mark = len(calls)
        calls.phase = "cold"
        cold = _build(incremental, root, initial=True)
        assert cold["rebuilt_tus"] == extraction_count(calls[mark:]) == 1
        baseline = _capture(incremental, root, native)
        mark = len(calls)
        calls.phase = "hot"
        hot = _build(incremental, root, initial=False)
        assert hot["rebuilt_tus"] == 0 and extraction_count(calls[mark:]) == 0
        assert not any(r["operation"] == "--check-arguments" for r in calls[mark:])
        (priority / "shared.h").write_text(header.format(5), encoding="utf-8")
        mark = len(calls)
        calls.phase = "mutation"
        changed = _build(incremental, root, initial=False)
        assert changed["rebuilt_tus"] == extraction_count(calls[mark:]) == 1
        after = _capture(incremental, root, native)
        assert not compare_facts(baseline, after)["equal"]
    finally:
        incremental.close()
    clean = backend(native, tmp_path / "clean")
    try:
        calls.phase = "clean"
        control = _build(clean, root, initial=True)
        assert control["rebuilt_tus"] == 1 and control["reused_tus"] == 0
        difference = compare_facts(after, _capture(clean, root, native))
        assert difference["equal"], difference["differences"][:3]
    finally:
        clean.close()
