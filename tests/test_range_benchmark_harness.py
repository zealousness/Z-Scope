from __future__ import annotations

import importlib.util
import re
import sqlite3
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
CHECKER_PATH = REPO_ROOT / "test" / "range" / "benchmark" / "check_entry_coverage.py"
RUNNER_PATH = REPO_ROOT / "test" / "range" / "benchmark" / "run_auto_unified_wsl.sh"

SPEC = importlib.util.spec_from_file_location("range_entry_coverage", CHECKER_PATH)
assert SPEC is not None and SPEC.loader is not None
checker = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = checker
SPEC.loader.exec_module(checker)


def _write_source(root: Path, relative: str, text: str) -> None:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _build_db(
    path: Path,
    *,
    functions: list[tuple[str, str, str, int]],
    edges: list[tuple[str, str, str, str]],
) -> None:
    connection = sqlite3.connect(path)
    try:
        connection.executescript(
            """
            CREATE TABLE functions (
                name TEXT NOT NULL,
                file_path TEXT NOT NULL,
                signature TEXT,
                is_declaration INTEGER DEFAULT 0
            );
            CREATE TABLE call_edges (
                caller_name TEXT NOT NULL,
                caller_file TEXT NOT NULL,
                callee_name TEXT NOT NULL,
                callee_file TEXT DEFAULT ''
            );
            CREATE TABLE indirect_calls (
                caller_name TEXT NOT NULL,
                callee_name TEXT NOT NULL,
                call_file TEXT DEFAULT ''
            );
            """
        )
        connection.executemany(
            "INSERT INTO functions(name, file_path, signature, is_declaration) "
            "VALUES (?, ?, ?, ?)",
            functions,
        )
        connection.executemany(
            "INSERT INTO call_edges(caller_name, caller_file, callee_name, callee_file) "
            "VALUES (?, ?, ?, ?)",
            edges,
        )
        connection.commit()
    finally:
        connection.close()


def _fixture_project(tmp_path: Path) -> tuple[Path, Path]:
    root = tmp_path / "project"
    _write_source(root, "src/a.c", "void start(void) { helper(); }\n")
    _write_source(root, "src/b.c", "void start(void) { target(); }\n")
    _write_source(root, "src/helper.c", "void helper(void) { target(); }\n")
    _write_source(root, "src/vuln.c", "void target(void) { }\n")
    _write_source(root, "src/safe.c", "void target(void) { }\n")
    database = tmp_path / "knowledge.db"
    _build_db(
        database,
        functions=[
            ("start", "src/a.c", "void start(void)", 0),
            ("start", "src/b.c", "void start(void)", 0),
            ("helper", "src/helper.c", "void helper(void)", 0),
            ("target", "src/vuln.c", "void target(void)", 0),
            ("target", "src/safe.c", "void target(void)", 0),
        ],
        edges=[
            ("start", "src/a.c", "helper", "src/helper.c"),
            ("helper", "src/helper.c", "target", "src/vuln.c"),
            ("start", "src/b.c", "target", "src/safe.c"),
        ],
    )
    return root, database


def test_coverage_uses_forward_call_graph_reachability(tmp_path: Path) -> None:
    root, database = _fixture_project(tmp_path)

    result, valid = checker.evaluate_coverage(
        root=root,
        entries=[
            {
                "function_name": "start",
                "file_path": "src/a.c",
                "signature": "void start(void)",
            }
        ],
        vulnerabilities=[
            {
                "id": "TEST-1",
                "file": "src/vuln.c",
                "function": "target",
            }
        ],
        knowledge_db=database,
    )

    assert valid is True
    assert result["mode"] == "call_graph_reachability"
    assert result["missing_truth_entry"] == []
    assert result["root_nodes"] == 1
    assert result["reachable_function_nodes"] == 3


def test_reachability_does_not_collapse_same_name_different_file(
    tmp_path: Path,
) -> None:
    root, database = _fixture_project(tmp_path)

    result, valid = checker.evaluate_coverage(
        root=root,
        entries=[
            {
                "function_name": "start",
                "file_path": "src/b.c",
                "signature": "void start(void)",
            }
        ],
        vulnerabilities=[
            {
                "id": "TEST-2",
                "file": "src/vuln.c",
                "function": "target",
            }
        ],
        knowledge_db=database,
    )

    assert valid is False
    assert len(result["missing_truth_reachability"]) == 1
    assert result["missing_truth_reachability"][0]["required_functions"] == [
        "src/vuln.c::target"
    ]


def test_entry_duplicates_use_file_and_full_signature_identity(
    tmp_path: Path,
) -> None:
    root, database = _fixture_project(tmp_path)
    distinct_same_name = [
        {
            "function_name": "start",
            "file_path": "src/a.c",
            "signature": "void start(void)",
        },
        {
            "function_name": "start",
            "file_path": "src/b.c",
            "signature": "void start(void)",
        },
    ]
    truth = [{"id": "TEST-3", "file": "src/vuln.c", "function": "target"}]

    distinct_result, distinct_valid = checker.evaluate_coverage(
        root=root,
        entries=distinct_same_name,
        vulnerabilities=truth,
        knowledge_db=database,
    )
    duplicate_result, duplicate_valid = checker.evaluate_coverage(
        root=root,
        entries=[distinct_same_name[0], dict(distinct_same_name[0])],
        vulnerabilities=truth,
        knowledge_db=database,
    )

    assert distinct_valid is True
    assert distinct_result["duplicate_entry_names"] == ["start"]
    assert distinct_result["duplicate_entry_identities"] == []
    assert distinct_result["entries"] == 2
    assert duplicate_valid is False
    assert duplicate_result["duplicate_entry_identities"] == [
        "src/a.c::void start(void)"
    ]


def test_no_database_fallback_is_honest_direct_identity_check(
    tmp_path: Path,
) -> None:
    root, _ = _fixture_project(tmp_path)

    result, valid = checker.evaluate_coverage(
        root=root,
        entries=[
            {
                "function_name": "start",
                "file_path": "src/a.c",
                "signature": "void start(void)",
            }
        ],
        vulnerabilities=[
            {
                "id": "TEST-4",
                "file": "src/vuln.c",
                "function": "target",
            }
        ],
        knowledge_db=None,
    )

    assert valid is False
    assert result["mode"] == "direct_entry_identity"
    assert result["missing_truth_entry"]


def test_wsl_runner_separates_process_report_and_valid_scan_states() -> None:
    runner = RUNNER_PATH.read_text(encoding="utf-8")
    python_blocks = re.findall(r"<<'PY'\n(.*?)\nPY", runner, flags=re.DOTALL)

    assert python_blocks
    for index, block in enumerate(python_blocks):
        compile(block, f"{RUNNER_PATH.name}:heredoc-{index}", "exec")
    assert "report_emitted = bool(report)" in runner
    assert '"process_ended": True' in runner
    assert "report_completeness == \"complete\"" in runner
    assert "manifest_valid" in runner
    assert "valid_scan_exit" in runner
    assert '"scan_completed": scan_completed' in runner
    assert '"benchmark_valid": benchmark_valid' in runner
    assert '--knowledge-db "${knowledge_db_path}"' in runner
