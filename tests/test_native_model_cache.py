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
    assert compiler_structure({"pointee_record_usr": one}) == compiler_structure(
        {"pointee_record_usr": moved}
    )
    assert compiler_structure({"pointee_record_usr": one}) != compiler_structure(
        {"pointee_record_usr": one.replace("@p", "@q")}
    )


def test_native_wrapper_publication_hot_reuse_and_changed_guard(project, monkeypatch):
    from zscope.semantics.native_wrappers import NativeWrapper

    prepare(project, '#include <stdlib.h>\nvoid *probe(int bad) { void *p=malloc(8); if(bad) {free(p); return 0;} return p; }\n')
    checked = []
    original = NativeWrapper.run

    def record(self):
        checked.append(self.context["func_name"])
        return original(self)

    monkeypatch.setattr(NativeWrapper, "run", record)
    calls, stats, _ = run(project)
    assert calls == [] and stats.deterministic_snapshot_count == 1
    assert checked == ["probe"]
    assert stats.resource_inference_coverage["interface_counts"] == {"source_verified": 1}
    checked.clear()
    calls, stats, _ = run(project)
    assert calls == [] and stats.cache_hit_functions == 1
    assert checked == []
    _, root, _ = project
    (root / "a.c").write_text(
        "#include <stdlib.h>\nvoid *probe(int bad) { void *p=malloc(8); if(bad) free(p); return p; }\n"
    )
    calls, stats, _ = run(project)
    assert checked and calls == ["probe"]  # Controlled discovery response; no trusted adapter.
    assert stats.cache_hit_functions == 0
    assert stats.resource_inference_coverage["interface_counts"] != {"source_verified": 1}


def test_native_wrapper_header_and_command_changes_recheck(project, monkeypatch):
    from zscope.semantics.native_wrappers import NativeWrapper

    prepare(
        project,
        '#include <stdlib.h>\n#include "shared.h"\nvoid *probe(flag_t n) { return malloc(n); }\n',
    )
    _, root, cdb = project
    (root / "shared.h").write_text("typedef int flag_t;\n")
    checks = []
    original = NativeWrapper.run

    def record(self):
        checks.append(self.build)
        return original(self)

    monkeypatch.setattr(NativeWrapper, "run", record)
    assert run(project)[1].deterministic_snapshot_count == 1
    first = checks[-1]
    (root / "shared.h").write_text("typedef long flag_t;\n")
    stats = run(project)[1]
    assert stats.cache_hit_functions == 0 and checks[-1] != first
    second = checks[-1]
    commands = json.loads(cdb.read_text())
    commands[0]["arguments"].insert(1, "-DPROJECT_VARIANT=1")
    cdb.write_text(json.dumps(commands))
    stats = run(project)[1]
    assert stats.cache_hit_functions == 0 and checks[-1] != second
    before = len(checks)
    assert run(project)[1].cache_hit_functions == 1
    assert len(checks) == before


def test_native_existence_only_include_changes_identity_and_hot_reuse(project):
    from zscope.retrieval.build_context import context_input_status

    backend, root, _ = project
    # The probe intentionally points into an excluded artifact directory:
    # directory inventories alone must not hide an actual compiler lookup.
    hidden = root / ".zscope-probe"
    hidden.mkdir()
    header = hidden / "optional.header_probe"
    prepare(
        project,
        f"""extern int first(void); extern int second(void);
#if __has_include("{header}")
#define CHOICE second
#else
#define CHOICE first
#endif
int probe(void) {{ return CHOICE(); }}
""",
    )
    contexts = []
    for present in (False, True, False):
        if present:
            header.write_text("/* queried but never entered */\n")
        elif header.exists():
            header.unlink()
        if contexts:
            assert context_input_status(contexts[-1]) == "stale_include_probe"
        assert build(project)
        facts = backend.get_function_program_facts("probe", "a.c")
        assert facts["complete"]
        context = facts["build_context"]
        assert context_input_status(context) == "current"
        assert str(header) not in context["dependencies"]
        probe = next(q for q in context["include_probes"]["queries"] if q["name"] == str(header))
        assert probe["found"] is present
        contexts.append(context)
        assert build(project)
        stats = json.loads(backend.db.get_metadata("clang_batch_stats"))
        assert stats["compiled_tus"] == 0 and stats["reused_tus"] == 2
    assert contexts[0]["build_context_id"] != contexts[1]["build_context_id"]
    assert contexts[0]["build_context_id"] == contexts[2]["build_context_id"]
