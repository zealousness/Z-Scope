"""Real compiler identity must bind type evidence without LSP/name matching."""

import json
from types import SimpleNamespace

from test_clang_batch import project, build
from zscope.retrieval.code_index import CodeIndex
from zscope.snapshots.modeling_input import build_semantic_model_input


def context(project, name):
    backend, root, cdb = project
    index = CodeIndex(root, cdb, backend=backend, indexing_config=SimpleNamespace(backend="clang"))
    return build_semantic_model_input(index, name)


def test_anonymous_typedef_nested_union_and_local_records_resolve(project):
    _, root, _ = project
    (root / "shared.h").write_text(
        "typedef struct { union { struct { int value; } one; "
        "struct { long value; } two; } choice; } Handle;\n"
    )
    (root / "a.c").write_text(
        '#include "shared.h"\nint use(Handle *p) { '
        "struct { int value; } local = {2}; "
        "p->choice.one.value = local.value; return p->choice.two.value; }\n"
    )
    (root / "b.c").write_text(
        '#include "shared.h"\nint other(Handle *p) { return p->choice.one.value; }\n'
    )
    assert build(project)
    for name in ("use", "other"):
        value = context(project, name)
        assert not value.get("unresolved_referenced_types")
        definitions = [item["full_definition"] for item in value["referenced_types"]]
        assert any("typedef struct" in definition for definition in definitions)
        assert any("int value" in definition for definition in definitions)
    refs = context(project, "use")["referenced_types"]
    assert any(
        "member_access" in item["reference_kinds"] and "typedef struct" in item["full_definition"]
        for item in refs
    )
    assert len({item["type_index_name"] for item in refs}) == len(refs)


def test_same_named_typedefs_in_different_files_keep_their_own_layout(project):
    _, root, _ = project
    (root / "shared.h").write_text("/* no common type */\n")
    (root / "a.c").write_text(
        '#include "shared.h"\ntypedef struct { int left; } Handle;\nint use(Handle *p) { return p->left; }\n'
    )
    (root / "b.c").write_text(
        '#include "shared.h"\ntypedef struct { long right; } Handle;\nint other(Handle *p) { return p->right; }\n'
    )
    assert build(project)
    for name, expected, absent in (
        ("use", "int left", "long right"),
        ("other", "long right", "int left"),
    ):
        value = context(project, name)
        assert not value.get("unresolved_referenced_types")
        text = "\n".join(item["full_definition"] for item in value["referenced_types"])
        assert expected in text and absent not in text


def test_anonymous_typedef_does_not_cross_compile_context_layout(project):
    backend, root, cdb = project
    (root / "shared.h").write_text(
        "typedef struct {\n#ifdef WIDE\nlong wide;\n#else\nint narrow;\n#endif\n} Handle;\n"
    )
    (root / "a.c").write_text('#include "shared.h"\nint use(Handle *p) { return p->narrow; }\n')
    (root / "b.c").write_text('#include "shared.h"\nint other(Handle *p) { return p->wide; }\n')
    commands = json.loads(cdb.read_text())
    commands[1]["arguments"].insert(1, "-DWIDE")
    cdb.write_text(json.dumps(commands))
    assert build(project)
    rows = list(
        backend.db._conn.execute(
            "SELECT r.type_id,r.resolution_reason FROM function_type_refs r "
            "JOIN functions f ON f.id=r.function_id WHERE f.name='other'"
        )
    )
    assert rows and all(row[0] is None and row[1] == "type_context_not_projected" for row in rows)
