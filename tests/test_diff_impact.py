from pathlib import Path
from types import SimpleNamespace

import pytest

from zscope.config.config import ConfigLoader
from zscope.config.function_entry import FunctionEntry
from zscope.core.analysis.analyzer import Analyzer
from zscope.orchestration.diff_impact import (
    ChangedFunction,
    ChangedLineRange,
    DiffImpactPlan,
    DiffImpactPlanner,
)
from zscope.orchestration.parallel_analyzer import ParallelAnalyzer


class FakeCodeIndex:
    def __init__(self, root: Path, functions, callers=None, headers=None, source_root=None):
        self.project_root = root
        self.source_root = source_root or root
        self._function_index = {}
        self.functions = {}
        for key, data in functions.items():
            display_name = str(data.get("name") or key)
            self._function_index[key] = {
                "name": display_name,
                "file": data["file"],
                "start_line": data["start_line"],
                "end_line": data["end_line"],
                "signature": f"{display_name}(...)",
                "index_name": key,
            }
            self.functions[key] = data
        self.callers = callers or {}
        self.caller_call_count = {}
        self.headers = headers or []

    def ensure_index_ready(self):
        return True

    def _resolve_file_path(self, file_path):
        path = Path(file_path)
        if path.is_absolute():
            return path
        source_candidate = self.source_root / path
        if source_candidate.exists():
            return source_candidate
        return self.project_root / path

    def get_function_impl(self, name, *args, **kwargs):
        file_path = str(kwargs.get("file_path") or "")
        data_key = self._find_function_key(name, file_path)
        data = self.functions.get(data_key)
        if not data:
            return None
        display_name = str(data.get("name") or data_key)
        return {
            "func_name": data_key,
            "index_name": data_key,
            "file": data["file"],
            "start_line": data["start_line"],
            "end_line": data["end_line"],
            "code": data.get("code", f"int {display_name}(void) {{ return 0; }}"),
            "callees": data.get("callees", []),
            "signature": f"{display_name}(...)",
        }

    def get_callers(self, name, limit=20, callee_file=""):
        key = (name, callee_file)
        self.caller_call_count[key] = self.caller_call_count.get(key, 0) + 1
        values = self.callers.get(key)
        if values is None:
            values = self.callers.get(name, [])
        rows = []
        for caller in values:
            if isinstance(caller, dict):
                rows.append(dict(caller))
            else:
                caller_key = self._find_function_key(str(caller), "")
                caller_data = self.functions.get(caller_key, {})
                rows.append({"name": str(caller), "filename": caller_data.get("file", "")})
        return rows[:limit]

    def get_header_declared_functions(self, header_files=None):
        return list(self.headers)

    def _find_function_key(self, name: str, file_path: str) -> str:
        if name in self.functions and (
            not file_path or self._same_path(self.functions[name].get("file", ""), file_path)
        ):
            return name
        matches = [
            key for key, data in self.functions.items() if str(data.get("name") or key) == name
        ]
        if file_path:
            for key in matches:
                if self._same_path(str(self.functions[key].get("file") or ""), file_path):
                    return key
        return matches[0] if matches else name

    @staticmethod
    def _same_path(left, right):
        left_norm = str(left or "").replace("\\", "/").lstrip("./")
        right_norm = str(right or "").replace("\\", "/").lstrip("./")
        return bool(
            left_norm
            and right_norm
            and (
                left_norm == right_norm
                or left_norm.endswith("/" + right_norm)
                or right_norm.endswith("/" + left_norm)
            )
        )


class StaticDiffPlanner(DiffImpactPlanner):
    def __init__(self, *args, changed_ranges, **kwargs):
        super().__init__(*args, **kwargs)
        self.changed_ranges = changed_ranges

    def _collect_changed_line_ranges(self):
        return list(self.changed_ranges)


def test_diff_entry_payload_declares_diff_mode(tmp_path: Path):
    plan = DiffImpactPlan(
        component="repo_a",
        repo_root=str(tmp_path),
        git_root=str(tmp_path),
        source_root=str(tmp_path),
        project_root=str(tmp_path),
        requested_repo_root=str(tmp_path),
        base_ref="base",
        head_ref="head",
        entries=[
            FunctionEntry(
                "Api",
                file_path="src/api.c",
                diff_focus={"mode": "diff_impact", "component": "repo_a"},
            )
        ],
        changed_functions=[
            ChangedFunction(
                "Changed",
                "src/changed.c",
                10,
                20,
                changed_lines=[12],
            )
        ],
        changed_files=["src/changed.c"],
        changed_headers=[],
    )

    payload = plan.to_entry_functions_payload()

    assert payload["mode"] == "diff_impact"
    assert payload["diff_impact"]["mode"] == "diff_impact"


def _write_numbered_file(root: Path, rel_path: str, line_count: int = 30) -> None:
    path = root / rel_path
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "".join(f"int line_{idx};\n" for idx in range(1, line_count + 1)),
        encoding="utf-8",
    )


def test_parse_git_diff_maps_new_version_hunks():
    diff_text = """
diff --git a/src/a.c b/src/a.c
index 111..222 100644
--- a/src/a.c
+++ b/src/a.c
@@ -10,0 +11,2 @@
+int x = 1;
+int y = 2;
@@ -30,2 +32,3 @@
-old
+new
+more
diff --git a/src/removed.c b/src/removed.c
--- a/src/removed.c
+++ /dev/null
@@ -1,2 +0,0 @@
-gone
"""

    ranges = DiffImpactPlanner._parse_git_diff(diff_text)

    assert [(item.file_path, item.start_line, item.end_line) for item in ranges] == [
        ("src/a.c", 11, 12),
        ("src/a.c", 32, 34),
    ]


def test_collect_changed_line_ranges_runs_git_diff_from_git_root(tmp_path: Path, monkeypatch):
    git_root = tmp_path / "dopra_ssp"
    source_root = git_root / "ssp"
    project_root = tmp_path / "AI_Audit"
    source_root.mkdir(parents=True)
    project_root.mkdir()
    calls = []

    def fake_run(cmd, capture_output, text, encoding=None, errors=None, check=False):
        calls.append((cmd, encoding, errors))
        if cmd[3:] == ["rev-parse", "--show-toplevel"]:
            return SimpleNamespace(returncode=0, stdout=str(git_root), stderr="")
        return SimpleNamespace(
            returncode=0,
            stdout=(
                "diff --git a/ssp/src/api.c b/ssp/src/api.c\n"
                "--- a/ssp/src/api.c\n"
                "+++ b/ssp/src/api.c\n"
                "@@ -2 +2 @@\n"
                "+  return 2;\n"
            ),
            stderr="",
        )

    monkeypatch.setattr("zscope.orchestration.diff_impact.subprocess.run", fake_run)
    planner = DiffImpactPlanner(
        FakeCodeIndex(project_root, {}, source_root=source_root),
        repo_root=source_root,
        base_ref="base",
    )

    ranges = planner._collect_changed_line_ranges()

    assert calls[-1][0][0:3] == ["git", "-C", str(git_root)]
    assert calls[-1][1:] == ("utf-8", "replace")
    assert [(item.file_path, item.start_line, item.end_line) for item in ranges] == [
        ("ssp/src/api.c", 2, 2)
    ]


def test_collect_changed_line_ranges_passes_diff_pathspecs(tmp_path: Path, monkeypatch):
    git_root = tmp_path / "repo"
    git_root.mkdir()
    calls = []

    def fake_run(cmd, capture_output, text, encoding=None, errors=None, check=False):
        calls.append(cmd)
        if cmd[3:] == ["rev-parse", "--show-toplevel"]:
            return SimpleNamespace(returncode=0, stdout=str(git_root), stderr="")
        return SimpleNamespace(
            returncode=0,
            stdout=(
                "diff --git a/src/net/api.c b/src/net/api.c\n"
                "--- a/src/net/api.c\n"
                "+++ b/src/net/api.c\n"
                "@@ -2 +2 @@\n"
                "+  return 2;\n"
            ),
            stderr="",
        )

    monkeypatch.setattr("zscope.orchestration.diff_impact.subprocess.run", fake_run)
    planner = DiffImpactPlanner(
        FakeCodeIndex(git_root, {}),
        repo_root=git_root,
        base_ref="base",
        diff_paths=["src/net", "src/fs", "src/net", ""],
    )

    ranges = planner._collect_changed_line_ranges()

    diff_cmd = calls[-1]
    assert diff_cmd[diff_cmd.index("--") + 1 :] == ["src/net", "src/fs"]
    assert planner.diff_pathspecs == ["src/net", "src/fs"]
    assert [(item.file_path, item.start_line, item.end_line) for item in ranges] == [
        ("src/net/api.c", 2, 2)
    ]


def test_diff_pathspecs_are_relative_to_git_root_when_source_root_is_nested(
    tmp_path: Path,
    monkeypatch,
):
    git_root = tmp_path / "repo"
    source_root = git_root / "ssp"
    project_root = tmp_path / "AI_Audit"
    source_root.mkdir(parents=True)
    project_root.mkdir()

    def fake_run(cmd, capture_output, text, encoding=None, errors=None, check=False):
        if cmd[3:] == ["rev-parse", "--show-toplevel"]:
            return SimpleNamespace(returncode=0, stdout=str(git_root), stderr="")
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr("zscope.orchestration.diff_impact.subprocess.run", fake_run)

    planner = DiffImpactPlanner(
        FakeCodeIndex(project_root, {}, source_root=source_root),
        repo_root=source_root,
        base_ref="base",
        diff_paths=["src/api"],
    )

    assert planner.diff_pathspecs == ["ssp/src/api"]


def test_absolute_diff_path_outside_git_root_is_rejected(tmp_path: Path, monkeypatch):
    git_root = tmp_path / "repo"
    source_root = git_root / "src"
    outside = tmp_path / "outside"
    source_root.mkdir(parents=True)
    outside.mkdir()

    def fake_run(cmd, capture_output, text, encoding=None, errors=None, check=False):
        if cmd[3:] == ["rev-parse", "--show-toplevel"]:
            return SimpleNamespace(returncode=0, stdout=str(git_root), stderr="")
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr("zscope.orchestration.diff_impact.subprocess.run", fake_run)

    with pytest.raises(ValueError, match="outside git root"):
        DiffImpactPlanner(
            FakeCodeIndex(git_root, {}, source_root=source_root),
            repo_root=source_root,
            base_ref="base",
            diff_paths=[str(outside)],
        )


def test_explicit_diff_repo_root_takes_precedence_over_source_root_git(tmp_path: Path, monkeypatch):
    git_root = tmp_path / "dopra_ssp"
    source_root = git_root / "ssp"
    project_root = tmp_path / "AI_Audit"
    source_root.mkdir(parents=True)
    project_root.mkdir()
    calls = []

    def fake_run(cmd, capture_output, text, encoding=None, errors=None, check=False):
        calls.append((cmd, encoding, errors))
        cwd = Path(cmd[2])
        if cmd[3:] == ["rev-parse", "--show-toplevel"]:
            stdout = str(source_root if cwd == source_root else git_root)
            return SimpleNamespace(returncode=0, stdout=stdout, stderr="")
        return SimpleNamespace(
            returncode=0,
            stdout=(
                "diff --git a/ssp/src/api.c b/ssp/src/api.c\n"
                "--- a/ssp/src/api.c\n"
                "+++ b/ssp/src/api.c\n"
                "@@ -2 +2 @@\n"
                "+  return 2;\n"
            ),
            stderr="",
        )

    monkeypatch.setattr("zscope.orchestration.diff_impact.subprocess.run", fake_run)
    planner = DiffImpactPlanner(
        FakeCodeIndex(project_root, {}, source_root=source_root),
        repo_root=git_root,
        base_ref="base",
    )

    assert planner.git_root == git_root.resolve()
    planner._collect_changed_line_ranges()
    assert calls[-1][0][0:3] == ["git", "-C", str(git_root)]
    assert calls[-1][1:] == ("utf-8", "replace")


def test_seeded_discovery_keeps_representative_external_entry_with_context(tmp_path: Path):
    _write_numbered_file(tmp_path, "api.c")
    functions = {
        "ApiA": {
            "file": "api.c",
            "start_line": 1,
            "end_line": 3,
            "code": "int ApiA(void) { return Guard(); }",
        },
        "ApiB": {
            "file": "api.c",
            "start_line": 5,
            "end_line": 7,
            "code": "int ApiB(void) { return Guard(); }",
        },
        "Guard": {
            "file": "api.c",
            "start_line": 9,
            "end_line": 11,
            "code": "int Guard(void) { return Changed(); }",
        },
        "Changed": {
            "file": "api.c",
            "start_line": 13,
            "end_line": 16,
            "code": "int Changed(void) { return 2; }",
        },
    }
    planner = StaticDiffPlanner(
        FakeCodeIndex(
            tmp_path,
            functions,
            callers={"Changed": ["Guard"], "Guard": ["ApiA", "ApiB"]},
            headers=[
                {"name": "ApiA", "filename": "api.h", "lineNumber": 1},
                {"name": "ApiB", "filename": "api.h", "lineNumber": 2},
            ],
        ),
        repo_root=tmp_path,
        base_ref="base",
        changed_ranges=[ChangedLineRange("api.c", 14, 14)],
    )

    plan = planner.plan()

    assert [entry.function_name for entry in plan.entries] == ["ApiA"]
    assert all(entry.diff_focus for entry in plan.entries)
    focus = plan.entries[0].diff_focus
    assert focus["affected_paths"][0]["path"] == ["ApiA", "Guard", "Changed"]
    assert any(item["function_name"] == "ApiB" for item in focus["context_callers"])
    assert plan.coverage_summary["changed_total"] == 1
    assert plan.function_coverage[0]["scan_entry"] == "ApiA"


def test_diff_mapping_handles_git_root_paths_when_source_root_is_nested(tmp_path: Path):
    project_root = tmp_path / "repo"
    source_root = project_root / "src"
    source_root.mkdir(parents=True)
    (source_root / "api.c").write_text(
        "int Api(void) { return Changed(); }\n" "int Changed(void) {\n" "  return 2;\n" "}\n",
        encoding="utf-8",
    )
    functions = {
        "Api": {
            "file": "api.c",
            "start_line": 1,
            "end_line": 1,
            "code": "int Api(void) { return Changed(); }",
        },
        "Changed": {
            "file": "api.c",
            "start_line": 2,
            "end_line": 4,
            "code": "int Changed(void) { return 2; }",
        },
    }
    planner = StaticDiffPlanner(
        FakeCodeIndex(
            project_root,
            functions,
            callers={"Changed": ["Api"]},
            headers=[{"name": "Api", "filename": "src/api.h", "lineNumber": 1}],
            source_root=source_root,
        ),
        repo_root=source_root,
        base_ref="base",
        changed_ranges=[ChangedLineRange("src/api.c", 3, 3)],
    )

    plan = planner.plan()

    assert [func.function_name for func in plan.changed_functions] == ["Changed"]
    assert plan.changed_functions[0].file_path == "api.c"
    assert [entry.function_name for entry in plan.entries] == ["Api"]


def test_diff_mapping_handles_index_paths_relative_to_git_root_with_external_project_root(
    tmp_path: Path,
):
    git_root = tmp_path / "dopra_ssp"
    source_root = git_root / "ssp"
    project_root = tmp_path / "AI_Audit"
    (source_root / "src").mkdir(parents=True)
    project_root.mkdir()
    (source_root / "src" / "api.c").write_text(
        "int Api(void) { return Changed(); }\n" "int Changed(void) {\n" "  return 2;\n" "}\n",
        encoding="utf-8",
    )
    functions = {
        "Api": {
            "file": "ssp/src/api.c",
            "start_line": 1,
            "end_line": 1,
            "code": "int Api(void) { return Changed(); }",
        },
        "Changed": {
            "file": "ssp/src/api.c",
            "start_line": 2,
            "end_line": 4,
            "code": "int Changed(void) { return 2; }",
        },
    }
    planner = StaticDiffPlanner(
        FakeCodeIndex(
            project_root,
            functions,
            callers={"Changed": ["Api"]},
            headers=[{"name": "Api", "filename": "ssp/src/api.h", "lineNumber": 1}],
            source_root=source_root,
        ),
        repo_root=source_root,
        base_ref="base",
        changed_ranges=[ChangedLineRange("ssp/src/api.c", 3, 3)],
    )
    planner.git_root = git_root

    plan = planner.plan()

    assert [func.function_name for func in plan.changed_functions] == ["Changed"]
    assert plan.changed_functions[0].file_path == "src/api.c"
    assert [entry.function_name for entry in plan.entries] == ["Api"]


def test_diff_mapping_handles_diff_path_with_source_root_prefix_and_source_relative_index(
    tmp_path: Path,
):
    git_root = tmp_path / "dopra_ssp"
    source_root = git_root / "ssp"
    project_root = tmp_path / "AI_Audit"
    (source_root / "src").mkdir(parents=True)
    project_root.mkdir()
    (source_root / "src" / "api.c").write_text(
        "int Api(void) { return Changed(); }\n" "int Changed(void) {\n" "  return 2;\n" "}\n",
        encoding="utf-8",
    )
    functions = {
        "Api": {
            "file": "src/api.c",
            "start_line": 1,
            "end_line": 1,
            "code": "int Api(void) { return Changed(); }",
        },
        "Changed": {
            "file": "src/api.c",
            "start_line": 2,
            "end_line": 4,
            "code": "int Changed(void) { return 2; }",
        },
    }
    planner = StaticDiffPlanner(
        FakeCodeIndex(
            project_root,
            functions,
            callers={"Changed": ["Api"]},
            headers=[{"name": "Api", "filename": "src/api.h", "lineNumber": 1}],
            source_root=source_root,
        ),
        repo_root=source_root,
        base_ref="base",
        changed_ranges=[ChangedLineRange("ssp/src/api.c", 3, 3)],
    )
    planner.git_root = git_root

    plan = planner.plan()

    assert [func.function_name for func in plan.changed_functions] == ["Changed"]
    assert plan.changed_functions[0].file_path == "src/api.c"
    assert [entry.function_name for entry in plan.entries] == ["Api"]


def test_diff_path_filter_keeps_external_root_outside_filtered_path(tmp_path: Path, monkeypatch):
    git_root = tmp_path / "repo"
    git_root.mkdir()
    _write_numbered_file(git_root, "src/net/changed.c")
    _write_numbered_file(git_root, "src/fs/ignored.c")
    _write_numbered_file(git_root, "core/owner.c")
    functions = {
        "Owner": {
            "file": "core/owner.c",
            "start_line": 1,
            "end_line": 4,
            "code": "void *Owner(void) { void *p = malloc(16); return ChangedNet(p); }",
        },
        "ChangedNet": {
            "file": "src/net/changed.c",
            "start_line": 2,
            "end_line": 5,
            "code": "int ChangedNet(void *p) { int x = 1; return x; }",
        },
        "ChangedFs": {
            "file": "src/fs/ignored.c",
            "start_line": 2,
            "end_line": 5,
            "code": "int ChangedFs(void) { return 0; }",
        },
    }

    def fake_run(cmd, capture_output, text, encoding=None, errors=None, check=False):
        if cmd[3:] == ["rev-parse", "--show-toplevel"]:
            return SimpleNamespace(returncode=0, stdout=str(git_root), stderr="")
        assert cmd[cmd.index("--") + 1 :] == ["src/net"]
        return SimpleNamespace(
            returncode=0,
            stdout=(
                "diff --git a/src/net/changed.c b/src/net/changed.c\n"
                "--- a/src/net/changed.c\n"
                "+++ b/src/net/changed.c\n"
                "@@ -3 +3 @@\n"
                "+  return 2;\n"
            ),
            stderr="",
        )

    monkeypatch.setattr("zscope.orchestration.diff_impact.subprocess.run", fake_run)
    planner = DiffImpactPlanner(
        FakeCodeIndex(
            git_root,
            functions,
            callers={"ChangedNet": ["Owner"], "ChangedFs": ["Owner"]},
        ),
        repo_root=git_root,
        base_ref="base",
        diff_paths=["src/net"],
    )

    plan = planner.plan()
    payload = plan.to_entry_functions_payload()

    assert plan.changed_files == ["src/net/changed.c"]
    assert [func.function_name for func in plan.changed_functions] == ["ChangedNet"]
    assert [entry.function_name for entry in plan.entries] == ["Owner"]
    assert plan.entries[0].file_path == "core/owner.c"
    assert payload["diff_impact"]["path_filters"] == {
        "raw_paths": ["src/net"],
        "git_pathspecs": ["src/net"],
    }


def test_duplicate_function_names_do_not_mix_reverse_call_paths(tmp_path: Path):
    _write_numbered_file(tmp_path, "src/api.c", line_count=40)
    _write_numbered_file(tmp_path, "src/real_b.c", line_count=40)
    _write_numbered_file(tmp_path, "src/decoy_b.c", line_count=40)
    _write_numbered_file(tmp_path, "src/c.c", line_count=40)
    functions = {
        "ApiReal": {
            "file": "src/api.c",
            "start_line": 1,
            "end_line": 6,
            "code": "void *ApiReal(void) { void *p = malloc(16); B(p); return p; }",
        },
        "B_real": {
            "name": "B",
            "file": "src/real_b.c",
            "start_line": 8,
            "end_line": 10,
            "code": "int B(void *p) { C(p); return 0; }",
        },
        "C": {
            "file": "src/c.c",
            "start_line": 12,
            "end_line": 14,
            "code": "void C(void *p) { free(p); }",
        },
        "A": {
            "file": "src/a.c",
            "start_line": 16,
            "end_line": 20,
            "code": "int A(void) { return B(); }",
        },
        "B_decoy": {
            "name": "B",
            "file": "src/decoy_b.c",
            "start_line": 22,
            "end_line": 24,
            "code": "int B(void) { return 0; }",
        },
    }
    planner = StaticDiffPlanner(
        FakeCodeIndex(
            tmp_path,
            functions,
            callers={
                ("C", "src/c.c"): [{"name": "B", "filename": "src/real_b.c"}],
                ("B", "src/real_b.c"): [{"name": "ApiReal", "filename": "src/api.c"}],
                ("B", "src/decoy_b.c"): [{"name": "A", "filename": "src/a.c"}],
            },
            headers=[
                {"name": "ApiReal", "filename": "api.h", "lineNumber": 1},
                {"name": "A", "filename": "api.h", "lineNumber": 2},
            ],
        ),
        repo_root=tmp_path,
        base_ref="base",
        changed_ranges=[ChangedLineRange("src/c.c", 13, 13)],
    )

    plan = planner.plan()

    assert [entry.function_name for entry in plan.entries] == ["ApiReal"]
    focus = plan.entries[0].diff_focus
    assert focus["affected_paths"][0]["path"] == ["ApiReal", "B", "C"]
    refs = focus["affected_paths"][0]["path_refs"]
    assert [ref["file_path"] for ref in refs] == ["src/api.c", "src/real_b.c", "src/c.c"]
    assert all(item["function_name"] != "A" for item in focus["context_callers"])
    assert plan.function_coverage[0]["path_refs"][0][1]["file_path"] == "src/real_b.c"


def test_diff_planner_caches_callers_by_function_and_file(tmp_path: Path):
    _write_numbered_file(tmp_path, "api.c")
    functions = {
        "Caller": {
            "file": "api.c",
            "start_line": 1,
            "end_line": 3,
            "code": "int Caller(void) { return Changed(); }",
        },
        "Changed": {
            "file": "api.c",
            "start_line": 5,
            "end_line": 7,
            "code": "int Changed(void) { return 1; }",
        },
    }
    code_index = FakeCodeIndex(
        tmp_path,
        functions,
        callers={("Changed", "api.c"): ["Caller"]},
    )
    planner = StaticDiffPlanner(
        code_index,
        repo_root=tmp_path,
        base_ref="base",
        changed_ranges=[ChangedLineRange("api.c", 6, 6)],
    )

    first = planner._get_callers("Changed", "api.c")
    second = planner._get_callers("Changed", "api.c")

    assert first == second
    assert code_index.caller_call_count[("Changed", "api.c")] == 1


def test_empty_changed_function_mapping_emits_path_diagnostics(tmp_path: Path):
    git_root = tmp_path / "dopra_ssp"
    source_root = git_root / "ssp"
    project_root = tmp_path / "AI_Audit"
    (source_root / "src").mkdir(parents=True)
    project_root.mkdir()
    (source_root / "src" / "api.c").write_text(
        "int Changed(void) {\n" "  return 2;\n" "}\n",
        encoding="utf-8",
    )
    functions = {
        "Changed": {
            "file": "ssp/src/api.c",
            "start_line": 1,
            "end_line": 3,
            "code": "int Changed(void) { return 2; }",
        },
    }
    planner = StaticDiffPlanner(
        FakeCodeIndex(project_root, functions, source_root=source_root),
        repo_root=source_root,
        base_ref="base",
        changed_ranges=[ChangedLineRange("ssp/src/api.c", 20, 20)],
    )
    planner.git_root = git_root
    planner.repo_root = git_root

    plan = planner.plan()

    assert plan.changed_functions == []
    assert any("Diff path diagnostics:" in note for note in plan.notes)
    assert any("ssp/src/api.c" in note and "exists=true" in note for note in plan.notes)
    assert any("Indexed function file samples: ssp/src/api.c" in note for note in plan.notes)


def test_overlapping_changed_functions_share_one_entry_with_all_paths(tmp_path: Path):
    _write_numbered_file(tmp_path, "api.c")
    functions = {
        "Api": {
            "file": "api.c",
            "start_line": 1,
            "end_line": 3,
            "code": "int Api(void) { return A() + B(); }",
        },
        "A": {"file": "api.c", "start_line": 5, "end_line": 7, "code": "int A(void) { return 2; }"},
        "B": {
            "file": "api.c",
            "start_line": 9,
            "end_line": 11,
            "code": "int B(void) { return 3; }",
        },
    }
    planner = StaticDiffPlanner(
        FakeCodeIndex(
            tmp_path,
            functions,
            callers={"A": ["Api"], "B": ["Api"]},
            headers=[{"name": "Api", "filename": "api.h", "lineNumber": 1}],
        ),
        repo_root=tmp_path,
        base_ref="base",
        changed_ranges=[
            ChangedLineRange("api.c", 6, 6),
            ChangedLineRange("api.c", 10, 10),
        ],
    )

    plan = planner.plan()

    assert [entry.function_name for entry in plan.entries] == ["Api"]
    focus = plan.entries[0].diff_focus
    assert [item["function_name"] for item in focus["changed_functions"]] == ["A", "B"]
    assert [item["changed_function"] for item in focus["affected_paths"]] == ["A", "B"]


def test_deep_path_keeps_single_representative_entry_with_coverage(tmp_path: Path):
    _write_numbered_file(tmp_path, "api.c")
    functions = {
        "Api": {
            "file": "api.c",
            "start_line": 1,
            "end_line": 3,
            "code": "int Api(void) { return Mid(); }",
        },
        "Mid": {
            "file": "api.c",
            "start_line": 5,
            "end_line": 7,
            "code": "int Mid(void) { return Changed(); }",
        },
        "Changed": {
            "file": "api.c",
            "start_line": 9,
            "end_line": 11,
            "code": "int Changed(void) { return 2; }",
        },
    }
    planner = StaticDiffPlanner(
        FakeCodeIndex(
            tmp_path,
            functions,
            callers={"Changed": ["Mid"], "Mid": ["Api"]},
            headers=[{"name": "Api", "filename": "api.h", "lineNumber": 1}],
        ),
        repo_root=tmp_path,
        base_ref="base",
        synthetic_depth_threshold=1,
        changed_ranges=[ChangedLineRange("api.c", 10, 10)],
    )

    plan = planner.plan()

    assert [entry.function_name for entry in plan.entries] == ["Api"]
    assert plan.function_coverage[0]["coverage_status"] == "covered_by_entry"
    assert plan.function_coverage[0]["scan_entry"] == "Api"


def test_thread_worker_is_selected_when_changed_callee_is_under_worker(tmp_path: Path):
    _write_numbered_file(tmp_path, "thread.c")
    functions = {
        "Start": {
            "file": "thread.c",
            "start_line": 1,
            "end_line": 5,
            "code": "int Start(void) { pthread_t tid; return pthread_create(&tid, 0, Worker, 0); }",
        },
        "Worker": {
            "file": "thread.c",
            "start_line": 7,
            "end_line": 9,
            "code": "void *Worker(void *arg) { Changed(); return arg; }",
        },
        "Changed": {
            "file": "thread.c",
            "start_line": 11,
            "end_line": 13,
            "code": "int Changed(void) { return 2; }",
        },
    }
    planner = StaticDiffPlanner(
        FakeCodeIndex(
            tmp_path,
            functions,
            callers={"Changed": ["Worker"], "Worker": ["Start"]},
        ),
        repo_root=tmp_path,
        base_ref="base",
        changed_ranges=[ChangedLineRange("thread.c", 12, 12)],
    )

    plan = planner.plan()

    worker = next(entry for entry in plan.entries if entry.function_name == "Worker")
    assert worker.diff_focus["entry_exposure"] == "thread"
    assert worker.diff_focus["affected_paths"][0]["path"] == ["Worker", "Changed"]


def test_report_diff_relevance_prefixes_incremental_and_existing():
    focus = {
        "mode": "diff_impact",
        "component": "core",
        "base_ref": "base",
        "head_ref": "head",
        "entry_function": "Api",
        "changed_functions": [
            {"function_name": "Changed", "file_path": "api.c", "changed_lines": [10]},
        ],
        "affected_paths": [{"path": ["Api", "Changed"], "changed_function": "Changed"}],
    }
    changed_issue = {"function": "Changed", "location": "api.c:10", "description": "bad copy"}
    existing_issue = {"function": "Other", "location": "api.c:30", "description": "old bug"}

    ParallelAnalyzer._annotate_diff_relevance(changed_issue, focus)
    ParallelAnalyzer._annotate_diff_relevance(existing_issue, focus)

    assert changed_issue["diff_relevance"] == "incremental"
    assert changed_issue["description"].startswith("[增量]")
    assert existing_issue["diff_relevance"] == "existing"
    assert existing_issue["description"].startswith("[存量]")


def test_diff_focus_snippets_use_changed_function_file_path(tmp_path: Path):
    functions = {
        "Changed_real": {
            "name": "Changed",
            "file": "src/real.c",
            "start_line": 1,
            "end_line": 3,
            "code": "int Changed(void) { return 42; /* REAL */ }",
        },
        "Changed_decoy": {
            "name": "Changed",
            "file": "src/decoy.c",
            "start_line": 1,
            "end_line": 3,
            "code": "int Changed(void) { return 0; /* DECOY */ }",
        },
    }
    analyzer = Analyzer.__new__(Analyzer)
    analyzer.code_index = FakeCodeIndex(tmp_path, functions)
    analyzer.config = SimpleNamespace(analysis=SimpleNamespace(max_function_lines=500))

    context = analyzer._build_diff_focus_agent_context(
        {
            "changed_functions": [
                {
                    "function_name": "Changed",
                    "file_path": "src/real.c",
                    "changed_lines": [2],
                }
            ]
        }
    )

    assert context["changed_function_snippets"][0]["file"] == "src/real.c"
    assert "REAL" in context["changed_function_snippets"][0]["code"]
    assert "DECOY" not in context["changed_function_snippets"][0]["code"]


def test_diff_relevance_uses_file_path_for_duplicate_function_names():
    focus = {
        "mode": "diff_impact",
        "component": "core",
        "base_ref": "base",
        "head_ref": "head",
        "entry_function": "Api",
        "changed_functions": [
            {"function_name": "B", "file_path": "src/real_b.c", "changed_lines": [10]},
        ],
        "affected_paths": [
            {
                "path": ["Api", "B"],
                "changed_function": "B",
                "path_refs": [
                    {"function_name": "Api", "file_path": "src/api.c", "start_line": 1},
                    {"function_name": "B", "file_path": "src/real_b.c", "start_line": 8},
                ],
            }
        ],
    }
    decoy_issue = {
        "function": "B",
        "location": "src/decoy_b.c:10",
        "description": "pre-existing decoy issue",
    }
    real_issue = {
        "function": "B",
        "location": "src/real_b.c:10",
        "description": "real changed issue",
    }

    ParallelAnalyzer._annotate_diff_relevance(decoy_issue, focus)
    ParallelAnalyzer._annotate_diff_relevance(real_issue, focus)

    assert decoy_issue["diff_relevance"] == "existing"
    assert real_issue["diff_relevance"] == "incremental"


def test_diff_entry_result_key_includes_component_and_file_path():
    entry = FunctionEntry(
        "helper",
        file_path="src/a.c",
        diff_focus={"mode": "diff_impact", "component": "repo_a"},
    )

    assert ParallelAnalyzer._entry_result_key(entry) == "repo_a:helper@src/a.c"


def test_many_public_wrappers_merge_into_changed_owner_root(tmp_path: Path):
    _write_numbered_file(tmp_path, "api.c", line_count=140)
    wrappers = {
        f"Api{idx}": {
            "file": "api.c",
            "start_line": idx + 1,
            "end_line": idx + 1,
            "code": f"void *Api{idx}(void) {{ return OwnerCreate(); }}",
        }
        for idx in range(100)
    }
    functions = {
        **wrappers,
        "OwnerCreate": {
            "file": "api.c",
            "start_line": 120,
            "end_line": 124,
            "code": "void *OwnerCreate(void) { void *p = malloc(16); return p; }",
        },
    }
    planner = StaticDiffPlanner(
        FakeCodeIndex(
            tmp_path,
            functions,
            callers={"OwnerCreate": list(wrappers)},
            headers=[
                {"name": name, "filename": "api.h", "lineNumber": idx + 1}
                for idx, name in enumerate(wrappers)
            ],
        ),
        repo_root=tmp_path,
        base_ref="base",
        changed_ranges=[ChangedLineRange("api.c", 122, 122)],
    )

    plan = planner.plan()

    assert [entry.function_name for entry in plan.entries] == ["OwnerCreate"]
    focus = plan.entries[0].diff_focus
    assert len(focus["context_callers"]) == 100
    assert plan.function_coverage[0]["coverage_status"] == "scanned_as_root"


def test_parent_child_entries_merge_to_nearest_context_root(tmp_path: Path):
    _write_numbered_file(tmp_path, "api.c")
    functions = {
        "ApiTop": {
            "file": "api.c",
            "start_line": 1,
            "end_line": 3,
            "code": "int ApiTop(void) { return ApiMid(); }",
        },
        "ApiMid": {
            "file": "api.c",
            "start_line": 5,
            "end_line": 7,
            "code": "int ApiMid(void) { return Changed(); }",
        },
        "Changed": {
            "file": "api.c",
            "start_line": 9,
            "end_line": 11,
            "code": "int Changed(void) { int x = 1; return x; }",
        },
    }
    planner = StaticDiffPlanner(
        FakeCodeIndex(
            tmp_path,
            functions,
            callers={"Changed": ["ApiMid"], "ApiMid": ["ApiTop"]},
            headers=[
                {"name": "ApiTop", "filename": "api.h", "lineNumber": 1},
                {"name": "ApiMid", "filename": "api.h", "lineNumber": 2},
            ],
        ),
        repo_root=tmp_path,
        base_ref="base",
        changed_ranges=[ChangedLineRange("api.c", 10, 10)],
    )

    plan = planner.plan()

    assert [entry.function_name for entry in plan.entries] == ["ApiMid"]
    assert any(
        item["function_name"] == "ApiTop" for item in plan.entries[0].diff_focus["context_callers"]
    )


def test_unique_input_boundary_is_kept_as_scan_root(tmp_path: Path):
    _write_numbered_file(tmp_path, "api.c")
    functions = {
        "ApiTop": {
            "file": "api.c",
            "start_line": 1,
            "end_line": 5,
            "code": "int ApiTop(int fd, char *buf) { read(fd, buf, 32); return ApiMid(buf); }",
        },
        "ApiMid": {
            "file": "api.c",
            "start_line": 7,
            "end_line": 8,
            "code": "int ApiMid(char *buf) { return Changed(buf); }",
        },
        "Changed": {
            "file": "api.c",
            "start_line": 10,
            "end_line": 12,
            "code": "int Changed(char *buf) { return buf[0]; }",
        },
    }
    planner = StaticDiffPlanner(
        FakeCodeIndex(
            tmp_path,
            functions,
            callers={"Changed": ["ApiMid"], "ApiMid": ["ApiTop"]},
        ),
        repo_root=tmp_path,
        base_ref="base",
        changed_ranges=[ChangedLineRange("api.c", 11, 11)],
    )

    plan = planner.plan()

    assert [entry.function_name for entry in plan.entries] == ["ApiTop"]
    assert plan.function_coverage[0]["reason"] == "covered_by_input_boundary"


def test_release_change_selects_owner_root_not_plain_dispatcher(tmp_path: Path):
    _write_numbered_file(tmp_path, "api.c")
    functions = {
        "Dispatcher": {
            "file": "api.c",
            "start_line": 1,
            "end_line": 5,
            "code": "int Dispatcher(int msg) { switch (msg) { case 1: return OwnerCreate(); } return 0; }",
        },
        "OwnerCreate": {
            "file": "api.c",
            "start_line": 7,
            "end_line": 10,
            "code": "int OwnerCreate(void) { void *p = malloc(16); return Cleanup(p); }",
        },
        "Cleanup": {
            "file": "api.c",
            "start_line": 12,
            "end_line": 14,
            "code": "int Cleanup(void *p) { ReleaseChanged(p); return 0; }",
        },
        "ReleaseChanged": {
            "file": "api.c",
            "start_line": 16,
            "end_line": 18,
            "code": "void ReleaseChanged(void *p) { free(p); }",
        },
    }
    planner = StaticDiffPlanner(
        FakeCodeIndex(
            tmp_path,
            functions,
            callers={
                "ReleaseChanged": ["Cleanup"],
                "Cleanup": ["OwnerCreate"],
                "OwnerCreate": ["Dispatcher"],
            },
        ),
        repo_root=tmp_path,
        base_ref="base",
        changed_ranges=[ChangedLineRange("api.c", 17, 17)],
    )

    plan = planner.plan()

    assert [entry.function_name for entry in plan.entries] == ["OwnerCreate"]
    assert plan.function_coverage[0]["reason"] == "merged_into_owner_root"


def test_header_declaration_change_keeps_public_api_root(tmp_path: Path):
    _write_numbered_file(tmp_path, "api.c")
    (tmp_path / "api.h").write_text("int NewApi(void);\n", encoding="utf-8")
    functions = {
        "NewApi": {
            "file": "api.c",
            "start_line": 1,
            "end_line": 3,
            "code": "int NewApi(void) { return 0; }",
        },
    }
    planner = StaticDiffPlanner(
        FakeCodeIndex(
            tmp_path,
            functions,
            headers=[{"name": "NewApi", "filename": "api.h", "lineNumber": 1}],
        ),
        repo_root=tmp_path,
        base_ref="base",
        changed_ranges=[ChangedLineRange("api.h", 1, 1)],
    )

    plan = planner.plan()

    assert [entry.function_name for entry in plan.entries] == ["NewApi"]
    assert plan.analysis_obligations[0]["intent"] == "new_external_api"
    assert plan.function_coverage[0]["coverage_status"] == "scanned_as_root"


def test_dispatcher_change_keeps_dispatcher_root(tmp_path: Path):
    _write_numbered_file(tmp_path, "api.c")
    functions = {
        "DispatchChanged": {
            "file": "api.c",
            "start_line": 1,
            "end_line": 5,
            "code": "int DispatchChanged(int msg) { switch (msg) { case 7: return Handler(); } return 0; }",
        },
        "Handler": {
            "file": "api.c",
            "start_line": 7,
            "end_line": 8,
            "code": "int Handler(void) { return 0; }",
        },
    }
    planner = StaticDiffPlanner(
        FakeCodeIndex(tmp_path, functions),
        repo_root=tmp_path,
        base_ref="base",
        changed_ranges=[ChangedLineRange("api.c", 3, 3)],
    )

    plan = planner.plan()

    assert [entry.function_name for entry in plan.entries] == ["DispatchChanged"]
    assert plan.analysis_obligations[0]["intent"] == "dispatcher_route_change"


def test_diff_coverage_records_all_changed_functions(tmp_path: Path):
    _write_numbered_file(tmp_path, "api.c")
    functions = {
        "Api": {
            "file": "api.c",
            "start_line": 1,
            "end_line": 2,
            "code": "int Api(void) { return A() + B(); }",
        },
        "A": {"file": "api.c", "start_line": 4, "end_line": 5, "code": "int A(void) { return 1; }"},
        "B": {"file": "api.c", "start_line": 7, "end_line": 8, "code": "int B(void) { return 2; }"},
    }
    planner = StaticDiffPlanner(
        FakeCodeIndex(
            tmp_path,
            functions,
            callers={"A": ["Api"], "B": ["Api"]},
            headers=[{"name": "Api", "filename": "api.h", "lineNumber": 1}],
        ),
        repo_root=tmp_path,
        base_ref="base",
        changed_ranges=[ChangedLineRange("api.c", 4, 4), ChangedLineRange("api.c", 7, 7)],
    )

    plan = planner.plan()

    assert {item["function_name"] for item in plan.function_coverage} == {"A", "B"}
    assert plan.coverage_summary["changed_total"] == 2
    assert plan.coverage_summary["covered_by_scan"] == 2
    assert all(item["scan_entry"] for item in plan.function_coverage)
    assert plan.analysis_obligations[0]["llm_triage"]["status"] == "not_invoked"


def test_high_fanout_weak_static_evidence_uses_llm_triage_selector(tmp_path: Path):
    _write_numbered_file(tmp_path, "api.c", line_count=80)
    wrappers = {
        f"Api{idx}": {
            "file": "api.c",
            "start_line": idx + 1,
            "end_line": idx + 1,
            "code": f"int Api{idx}(int x) {{ return Changed(x); }}",
        }
        for idx in range(30)
    }
    functions = {
        **wrappers,
        "Changed": {
            "file": "api.c",
            "start_line": 60,
            "end_line": 64,
            "code": "int Changed(int x) { int y = x + 1; return y * 2; }",
        },
    }
    triage_requests = []

    def triage_selector(request):
        triage_requests.append(request)
        return {
            "intent": request["intent"],
            "direction": request["direction"],
            "recommended_root": "Api17",
            "context_functions": ["Api0"],
            "confidence": 0.81,
            "stop_reason": "mock_selected_representative_boundary",
        }

    planner = StaticDiffPlanner(
        FakeCodeIndex(
            tmp_path,
            functions,
            callers={"Changed": list(wrappers)},
            headers=[
                {"name": name, "filename": "api.h", "lineNumber": idx + 1}
                for idx, name in enumerate(wrappers)
            ],
        ),
        repo_root=tmp_path,
        base_ref="base",
        changed_ranges=[ChangedLineRange("api.c", 62, 62)],
        llm_triage_selector=triage_selector,
    )

    plan = planner.plan()

    assert [entry.function_name for entry in plan.entries] == ["Api17"]
    assert triage_requests and triage_requests[0]["trigger"].startswith(
        "high_fanout_weak_static_root"
    )
    assert plan.analysis_obligations[0]["llm_triage"]["status"] == "invoked"
    assert plan.analysis_obligations[0]["llm_triage"]["recommended_root"] == "Api17"
    assert plan.function_coverage[0]["reason"] == "llm_triage_recommended_root"


def test_diff_impact_config_defaults_and_is_not_public_v2(tmp_path: Path):
    config_path = tmp_path / "zscope.yaml"
    config_path.write_text(
        f"""
config_version: 2
llms:
  default:
    api_key: test
    base_urls: [http://localhost]
    models: [test-model]
project:
  language: c_cpp
  diff_impact:
    strategy: semantic_obligation
    llm_triage: off
    caller_search_depth_by_intent:
      resource_release_change: 9
indexing:
  backend: regex
concurrency:
  entry_workers: 2
  validator_workers: 2
  investigator_workers: 1
  evidence_completion_workers: 2
  index_workers: 2
  svf_workers: 1
  llm_max_inflight: 2
""",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="project.diff_impact"):
        ConfigLoader.load(str(config_path))
