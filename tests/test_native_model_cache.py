"""Real batch facts must replace generations and retain semantic cache identity."""

import json
from types import SimpleNamespace

from test_clang_batch import project, build
from test_incremental_semantic_modeling import modeler_for
from zscope.config.function_entry import FunctionEntry
from zscope.retrieval.code_index import CodeIndex
from zscope.semantics.compiler_fingerprint import compiler_structure


def run(project):
    backend, root, cdb = project
    assert build(project)
    index = CodeIndex(root, cdb, backend=backend, indexing_config=SimpleNamespace(backend="clang"))
    calls = []
    stats = modeler_for(root, index, calls).run([FunctionEntry("probe")])
    facts = index.get_function_program_facts("probe", "a.c")
    assert facts["complete"] and len(facts["functions"]) == 1
    return calls, stats, facts


def prepare(project, code):
    _, root, _ = project
    (root / "a.c").write_text(code)
    (root / "b.c").write_text('#include "shared.h"\nint unrelated(void) { return 1; }\n')
    (root / "shared.h").write_text("/* no dependencies */\n")


def test_native_format_move_reuses_model_and_replaces_old_calls(project):
    prepare(
        project,
        "extern int mystery(int);\nint probe(int n) { int local = n; return mystery(local); }\n",
    )
    calls, _, before = run(project)
    assert calls == ["probe"]
    backend, root, _ = project
    # Exercise migration of databases written by the earlier absolute TU producer.
    backend.db._conn.execute(
        "UPDATE translation_units SET file_path=? WHERE file_path='a.c'", (str(root / "a.c"),)
    )
    backend.db.commit()
    (root / "a.c").write_text(
        "\n\nextern int mystery(int);\n\nint probe(int n) {\n int local = n;\n return /* harmless */ mystery(local);\n}\n"
    )
    calls, stats, after = run(project)
    assert calls == [] and stats.cache_hit_functions == 1
    assert compiler_structure(before) == compiler_structure(after)
    rows = list(
        backend.db._conn.execute("SELECT call_line FROM call_edges WHERE caller_name='probe'")
    )
    assert [row[0] for row in rows] == [7]
    (root / "a.c").write_text("int replacement(void) { return 4; }\n")
    assert build(project)
    assert not backend.get_function_program_facts("probe", "a.c")["functions"]
    assert not list(backend.db._conn.execute("SELECT 1 FROM call_edges WHERE caller_name='probe'"))
    assert backend.get_function_program_facts("unrelated", "b.c")["complete"]


def test_native_macro_expansion_and_target_change_rebuild_model(project):
    code = "extern int mystery(int);\nint probe(void) { return mystery(CHOICE); }\n"
    prepare(project, code)
    _, _, cdb = project
    commands = json.loads(cdb.read_text())
    commands[0]["arguments"].insert(1, "-DCHOICE=1")
    cdb.write_text(json.dumps(commands))
    assert run(project)[0] == ["probe"]
    commands[0]["arguments"][1] = "-DCHOICE=2"
    cdb.write_text(json.dumps(commands))
    calls, stats, _ = run(project)
    assert calls == ["probe"]
    assert set(stats.rebuild_reasons.values()) <= {"compilation", "dependencies"}
    commands[0]["arguments"].insert(1, "--target=i386-linux-gnu")
    cdb.write_text(json.dumps(commands))
    assert run(project)[0] == ["probe"]


def test_local_usr_normalization_preserves_object_equality_and_scope():
    def facts(left, right):
        return {"events": [{"object": {"usr": left}}, {"object": {"usr": right}}]}

    one = "c:a.c@12@F@f@p"
    moved = "c:a.c@40@F@f@p"
    shadow = "c:a.c@55@F@f@p"
    assert compiler_structure(facts(one, one)) == compiler_structure(facts(moved, moved))
    assert compiler_structure(facts(one, one)) != compiler_structure(facts(moved, shadow))
    assert compiler_structure(facts(moved, shadow)) != compiler_structure(facts(shadow, moved))
    assert compiler_structure(facts(one, one)) != compiler_structure(
        facts(one.replace("a.c", "b.c"), one)
    )
