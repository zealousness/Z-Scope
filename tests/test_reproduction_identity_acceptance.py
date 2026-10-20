"""Coordinator acceptance: escaped pointer slots must not authorize object proofs."""

import pytest

from test_reproduction_planner import program
from zscope.semantics.resource_identity import native_heap_witness


@pytest.mark.parametrize(
    "escape",
    [
        "char **alias = &p;\n  *alias = q;",
        "char **alias = &p;\n  char **other = alias;\n  *other = q;",
    ],
)
def test_native_pointer_slot_escape_requires_alias_analysis(program, escape):
    source, indexed, _, _ = program
    code = (
        "#include <stdlib.h>\nint main(void) {\n"
        "  char *p = malloc(4), *q = malloc(4);\n"
        "  if (!p || !q) return 1;\n  " + escape + "\n"
        "  p[8] = 1;\n  free(q);\n  return 0;\n}\n"
    )
    source.write_text(code, encoding="utf-8")
    line = next(index for index, text in enumerate(code.splitlines(), 1) if "p[8]" in text)
    backend = indexed()
    try:
        facts = backend.get_function_program_facts("main", "unit.c")
        assert facts["complete"]
        # Both allocations share a line. A file/line-only ASan allocation frame
        # cannot repair an incorrect binding of p's first generation after its
        # storage was changed through an escaped pointer-to-pointer alias.
        assert native_heap_witness(facts, name="p", site_file=str(source), site_line=line) is None
    finally:
        backend.close()
