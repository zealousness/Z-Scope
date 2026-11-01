"""RAPI06: actual compilation/link records, never CDB-inferred membership."""

import json
from pathlib import Path
import shlex
import subprocess

import pytest

from test_single_slot_pool import native_index
from zscope.retrieval.link_targets import record_link, receipt_status, LinkedTargets


def build_project(root, sources=None):
    sources = sources or {
        "a.c": "int other(void); int main(void) {return other();}\n",
        "b.c": "int other(void) {return 0;}\n",
    }
    rows = []
    for file, code in sources.items():
        (root / file).write_text(code)
        rows.append(
            {
                "directory": str(root),
                "file": str(root / file),
                "arguments": [
                    "clang",
                    "-std=c11",
                    "-O0",
                    "-c",
                    str(root / file),
                    "-o",
                    str(root / Path(file).with_suffix(".o")),
                ],
            }
        )
    database = root / "compile_commands.json"
    database.write_text(json.dumps(rows))
    command = [
        "clang",
        *[str(root / Path(file).with_suffix(".o")) for file in sources],
        "-o",
        str(root / "app"),
    ]
    receipt = record_link(root, database, command, directory=root)
    return database, command, receipt


def test_actual_link_and_stale_inputs(tmp_path):
    _, _, receipt = build_project(tmp_path)
    assert receipt_status(receipt) == "current"
    assert len(receipt["members"]) == 2
    assert subprocess.run([str(tmp_path / "app")]).returncode == 0
    (tmp_path / "b.c").write_text("int other(void) {return 1;}\n")
    assert receipt_status(receipt) == "stale_link_inputs"


def test_malformed_records_report_gaps_without_aborting_scan(tmp_path):
    from types import SimpleNamespace

    store = tmp_path / ".zscope-link-targets"
    store.mkdir()
    for i, payload in enumerate(["[]", "null", "1", "{", "{}"]):
        (store / f"{i}.json").write_text(payload)
    index = SimpleNamespace(project_root=tmp_path, get_build_contexts=lambda: [])
    linked = LinkedTargets(index)
    assert not linked.targets
    assert len(linked.diagnostics) == 5
    assert {row["status"] for row in linked.diagnostics} == {"invalid_link_receipt"}
    assert linked.resolve("missing-build", "c:@F@callee")["complete"] is False


def test_actual_objects_bind_distinct_native_instances(tmp_path, monkeypatch):
    database, _, receipt = build_project(tmp_path)
    backend, index = native_index(tmp_path, tmp_path / "a.c", database)
    try:
        monkeypatch.setattr(
            subprocess, "run", lambda *a, **kw: pytest.fail("link query must not start tools")
        )
        linked = LinkedTargets(index)
        assert len(linked.targets) == 1, linked.diagnostics
        caller = index.get_function_program_facts("main", str(tmp_path / "a.c"))
        callee = linked.resolve(caller["build_context_id"], "c:@F@other")
        assert callee["complete"], callee
        assert callee["build_context_id"] != caller["build_context_id"]
        assert callee["link_target"]["target_id"] == receipt["target_id"]
        assert len(callee["link_target"]["members"]) == 2
        assert (
            linked.resolve(caller["build_context_id"], "c:b.c@F@other")["reason"]
            == "non_external_c_function"
        )
    finally:
        backend.close()


@pytest.mark.parametrize("kind", ["object", "binary", "header"])
def test_changed_receipt_inputs_do_not_reuse_membership(tmp_path, kind):
    (tmp_path / "api.h").write_text("int other(void);\n")
    _, _, receipt = build_project(
        tmp_path,
        {
            "a.c": '#include "api.h"\nint main(void) {return other();}\n',
            "b.c": '#include "api.h"\nint other(void) {return 0;}\n',
        },
    )
    path = tmp_path / {"object": "b.o", "binary": "app", "header": "api.h"}[kind]
    path.write_bytes(path.read_bytes() + b"\n")
    assert receipt_status(receipt).startswith("stale_link_")


def test_missing_object_command_and_unrecorded_library_are_rejected(tmp_path):
    database, command, _ = build_project(tmp_path)
    with pytest.raises(ValueError, match="only explicit object"):
        record_link(tmp_path, database, command + ["-lm"], directory=tmp_path)
    rows = json.loads(database.read_text())
    database.write_text(json.dumps(rows[:1]))
    with pytest.raises(ValueError, match="exactly one"):
        record_link(tmp_path, database, command, directory=tmp_path)


def test_two_real_executables_do_not_merge_targets(tmp_path):
    database, command, first = build_project(tmp_path)
    second_command = [*command[:-1], str(tmp_path / "other-app")]
    second = record_link(tmp_path, database, second_command, directory=tmp_path)
    backend, index = native_index(tmp_path, tmp_path / "a.c", database)
    try:
        linked = LinkedTargets(index)
        assert len(linked.targets) == 2, linked.diagnostics
        caller = index.get_function_program_facts("main", str(tmp_path / "a.c"))["build_context_id"]
        assert linked.resolve(caller, "c:@F@other")["reason"] == "link_target_missing_or_ambiguous"
        one = linked.resolve(caller, "c:@F@other", first["target_id"])
        assert one["complete"] and one["link_target"]["target_id"] != second["target_id"]
    finally:
        backend.close()


def test_link_member_missing_from_native_index_is_unknown(tmp_path):
    database, _, _ = build_project(tmp_path)
    backend, index = native_index(tmp_path, tmp_path / "a.c", database)
    try:
        missing = index.get_build_contexts(str(tmp_path / "b.c"))[0]["build_context_id"]
        backend.db._conn.execute("DELETE FROM compilation_facts WHERE context_id=?", (missing,))
        backend.db._conn.execute("DELETE FROM compilation_instances WHERE context_id=?", (missing,))
        backend.db.commit()
        linked = LinkedTargets(index)
        assert not linked.targets
        assert linked.diagnostics[0]["status"] == "link_member_instance_missing_or_ambiguous"
    finally:
        backend.close()


def test_object_membership_selects_actual_macro_variant(tmp_path):
    database, command, _ = build_project(
        tmp_path,
        {
            "a.c": "int other(void); int main(void) {return other();}\n",
            "b.c": "#ifndef VALUE\n#define VALUE 0\n#endif\nint other(void) {return VALUE;}\n",
        },
    )
    rows = json.loads(database.read_text())
    for row in rows:
        row["arguments"].insert(1, "-DVALUE=1")
    variant = json.loads(json.dumps(rows[1]))
    variant["arguments"][1] = "-DVALUE=2"
    variant["arguments"][-1] = str(tmp_path / "b2.o")
    database.write_text(json.dumps([*rows, variant]))
    record_link(tmp_path, database, command, directory=tmp_path)
    backend, index = native_index(tmp_path, tmp_path / "a.c", database)
    try:
        assert len(index.get_build_contexts(str(tmp_path / "b.c"))) == 2
        assert not index.get_function_program_facts("other", str(tmp_path / "b.c"))["complete"]
        caller = index.get_function_program_facts("main", str(tmp_path / "a.c"))
        resolved = LinkedTargets(index).resolve(caller["build_context_id"], "c:@F@other")
        assert resolved["complete"], resolved
        assert "-DVALUE=1" in resolved["build_context"]["command"]["arguments"]
        assert "-DVALUE=2" not in resolved["build_context"]["command"]["arguments"]
    finally:
        backend.close()


def test_static_same_name_functions_keep_their_tu_and_frame(tmp_path):
    from zscope.core.candidates.cpp_domains.lifecycle_paths import LifecyclePaths
    from zscope.semantics.contracts import ContractRegistry

    database, _, _ = build_project(
        tmp_path,
        {
            "a.c": "static int helper(void) {return 1;} int other(void); int main(void) {int n=helper(); int m=other(); if(n==m)return 1; return 0;}\n",
            "b.c": "static int helper(void) {return 2;} int other(void) {return helper();}\n",
        },
    )
    backend, index = native_index(tmp_path, tmp_path / "a.c", database)
    try:
        facts = index.get_function_program_facts("main", str(tmp_path / "a.c"))
        result = LifecyclePaths(facts, ContractRegistry(), index.get_function_program_facts).run()
        assert result["complete"], result["gaps"]
        helpers = [
            r for r in result["function_bindings"].values() if r["usr"].endswith("@F@helper")
        ]
        assert (
            len(helpers)
            == len({r["usr"] for r in helpers})
            == len({r["build_context_id"] for r in helpers})
            == 2
        )
    finally:
        backend.close()


def test_cli_records_spaced_paths_and_failed_rebuild_revokes_receipt(tmp_path):
    import sys

    root = tmp_path / "project with spaces"
    root.mkdir()
    database, command, receipt = build_project(root)
    run = subprocess.run(
        [
            sys.executable,
            "-m",
            "zscope.cli.link_record",
            "--project-root",
            str(root),
            "--compile-commands",
            str(database),
            "--",
            *command,
        ],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert run.returncode == 0 and "Recorded" in run.stdout, run.stderr
    (root / "b.c").write_text(
        "int missing_symbol(void); int other(void) {return missing_symbol();}\n"
    )
    with pytest.raises(subprocess.CalledProcessError):
        record_link(root, database, command, directory=root)
    assert not list((root / ".zscope-link-targets").glob("*.json"))


def test_cli_records_sanitized_cmake_link_file(tmp_path):
    import sys

    database, command, _ = build_project(tmp_path)
    build = tmp_path / "build"
    link_file = build / "CMakeFiles/app.dir/link.txt"
    link_file.parent.mkdir(parents=True)
    object_args = [value for value in command if value.endswith(".o")]
    link_file.write_text(
        shlex.join([command[0], "-Wall", *object_args, "-o", str(tmp_path / "app"), "-lm"]) + "\n",
        encoding="utf-8",
    )

    run = subprocess.run(
        [
            sys.executable,
            "-m",
            "zscope.cli.link_record",
            "--project-root",
            str(tmp_path),
            "--compile-commands",
            str(database),
            "--cmake-link-file",
            str(link_file),
        ],
        capture_output=True,
        text=True,
        timeout=30,
    )

    assert run.returncode == 0 and "Recorded" in run.stdout, run.stderr
    assert list((tmp_path / ".zscope-link-targets").glob("*.json"))


@pytest.mark.parametrize("packed", [False, True])
def test_cross_tu_record_layout_must_match_even_with_identical_signature(tmp_path, packed):
    from zscope.core.candidates.cpp_domains.lifecycle_paths import LifecyclePaths
    from zscope.semantics.contracts import ContractRegistry

    (tmp_path / "types.h").write_text(
        "typedef struct Box {char tag; int value;} Box;\nint consume(Box *box);\n"
    )
    database, _, _ = build_project(
        tmp_path,
        {
            "a.c": '#include "types.h"\nint main(void) {Box box={0}; return consume(&box);}\n',
            "b.c": ("#pragma pack(1)\n" if packed else "")
            + '#include "types.h"\nint consume(Box *box) {return 0;}\n',
        },
    )
    backend, index = native_index(tmp_path, tmp_path / "a.c", database)
    try:
        facts = index.get_function_program_facts("main", str(tmp_path / "a.c"))
        result = LifecyclePaths(facts, ContractRegistry(), index.get_function_program_facts).run()
        assert result["complete"] is not packed, result["gaps"]
        if packed:
            assert result["gaps"] == ["callee_linkage_or_signature_unclosed"]
    finally:
        backend.close()


def test_const_table_incompatible_function_conversion_has_no_closed_targets(tmp_path):
    database, _, _ = build_project(
        tmp_path,
        {
            "a.c": "void dispatch(void); int main(void) {dispatch(); return 0;}\n",
            "b.c": '#pragma clang diagnostic ignored "-Wincompatible-function-pointer-types"\n'
            "static void drop(int value) {}\n"
            "static void (*const operations[1])(unsigned int)={drop};\n"
            "void dispatch(void) {operations[0](1);}\n",
        },
    )
    backend, index = native_index(tmp_path, tmp_path / "a.c", database)
    try:
        facts = index.get_function_program_facts("dispatch", str(tmp_path / "b.c"))
        assert facts["complete"]
        calls = [e for e in facts["functions"][0]["events"] if e["event_kind"] == "call"]
        assert calls and all("closed_targets" not in e["callee"] for e in calls)
    finally:
        backend.close()
