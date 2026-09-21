"""A configured interface declaration is not an invocation of that interface."""

from dataclasses import replace
import pytest

from zscope.core.candidates.clang_ast_cfg import ClangAstCfgCandidateGenerator
from zscope.semantics.models import LocalPatternSemantics


def generator():
    semantics = LocalPatternSemantics()
    semantics.add_api("allocator", "orbit", "user_config")
    contract = semantics.contracts.find("orbit", "allocator")[0]
    semantics.contracts.add(
        replace(contract, protocol={"allocation_extent": [{"kind": "argument", "index": 0}]})
    )
    value = ClangAstCfgCandidateGenerator(semantics)
    return value


def test_definition_does_not_create_a_second_allocation_candidate():
    value = generator()
    issues = value.generate_issues(
        "orbit",
        """
10 | void *orbit(size_t size) {
11 |     void *p = malloc(size);
12 |     return p;
13 | }
""",
        "src/opaque.c",
    )
    candidates = [
        issue
        for issue in issues
        if issue["rule"] == "clang_cfg_external_size_allocation_without_limit"
    ]
    assert [issue["location"] for issue in candidates] == ["src/opaque.c:11"]


@pytest.mark.parametrize(
    "declaration",
    [
        "void *orbit(size_t size) {",
        "static inline void *orbit(size_t size)",
        "orbit(size_t size) {",
        "extern void *orbit(size_t size);",
    ],
)
def test_current_interface_declarator_is_not_a_call(declaration):
    value = generator()
    value.generate_issues("orbit", declaration + "\nreturn malloc(size);\n}", "opaque.c")
    assert value._calls(declaration) == []


def test_calls_on_definition_line_and_recursive_invocations_remain():
    value = generator()
    text = "void *orbit(size_t size) { return malloc(size); }"
    value.generate_issues("orbit", text, "opaque.c")
    assert value._calls(text) == [("malloc", "size")]
    assert value._calls("return orbit(size - 1);") == [("orbit", "size - 1")]
    assert value._calls("void *p = orbit(size);") == [("orbit", "size")]
    assert value._calls("if (orbit(size)) {") == [("if", "orbit(size)"), ("orbit", "size")]


def test_zero_argument_recursive_call_is_not_a_declaration():
    value = generator()
    value.generate_issues("orbit", "void *orbit() { return orbit(); }", "opaque.c")
    assert value._calls("orbit();") == [("orbit", "")]
    assert value._calls("return orbit();") == [("orbit", "")]


@pytest.mark.parametrize(
    "role,method",
    [("deallocator", "_match_release"), ("lock", "_match_lock"), ("unlock", "_match_unlock")],
)
def test_resource_operation_matchers_exclude_definitions(role, method):
    semantics = LocalPatternSemantics()
    semantics.add_api(role, "orbit", "user_config")
    value = ClangAstCfgCandidateGenerator(semantics)
    value.generate_issues("orbit", "void orbit(void *p) { consume(p); }", "opaque.c")
    assert getattr(value, method)("void orbit(void *p) {") is None
    assert getattr(value, method)("orbit(p);") == ("orbit", "p")
