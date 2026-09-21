"""Regression contracts for the ownership/review repair, without Range names."""

import pytest

from zscope.core.candidates.clang_ast_cfg import ClangAstCfgCandidateGenerator
from zscope.core.candidates.regex import RegexCandidateGenerator
from zscope.core.validation.evidence_completion import EvidenceCompletionQueue
from zscope.semantics.defaults import default_local_pattern_semantics
from zscope.semantics.contracts import ApiContract
from zscope.semantics.call_operands import call_operands, is_literal_string


@pytest.mark.parametrize("engine", [ClangAstCfgCandidateGenerator, RegexCandidateGenerator])
@pytest.mark.parametrize(
    "statement",
    [
        'snprintf(dst, n, "%s", input);',
        'fprintf(stream, "%s", input);',
        'syslog(level, "message");',
        'sprintf(dst, ("a" "b"));',
    ],
)
def test_literal_actual_format_never_uses_buffer_or_level_as_format(engine, statement):
    issues = engine().generate_issues("f", "void f(void) {\n" + statement + "\n}", "x.c")
    assert not [
        i
        for i in issues
        if i["rule"] in {"nonliteral_format_string", "clang_cfg_nonliteral_format_string"}
    ]


@pytest.mark.parametrize("engine", [ClangAstCfgCandidateGenerator, RegexCandidateGenerator])
def test_actual_nonliteral_format_is_preserved(engine):
    issues = engine().generate_issues("f", "void f(void) {\nsnprintf(dst, n, input);\n}", "x.c")
    hit = [
        i
        for i in issues
        if i["rule"] in {"nonliteral_format_string", "clang_cfg_nonliteral_format_string"}
    ]
    assert hit and hit[0]["source"] == "input"


def test_per_call_mapping_and_custom_argument_swap():
    registry = default_local_pattern_semantics().contracts
    registry.add(
        ApiContract.from_row(
            {
                "symbol_name": "dispatch",
                "kind": "format_sink",
                "source": "manual",
                "contract": {
                    "role": "format_sink",
                    "carrier": {"kind": "argument", "argument_index": 2},
                },
            }
        )
    )
    calls = call_operands(registry, 'dispatch(x, y, "%s"); dispatch(y, x, input);', "format_sink")
    assert [c.expression for c in calls] == ['"%s"', "input"]
    assert is_literal_string(calls[0].expression)


def test_detector_event_cannot_certify_format_exploitability():
    issue = {
        "rule": "clang_cfg_nonliteral_format_string",
        "category": "format_string",
        "evidence_pack": {
            "path": {"complete_in_function": True},
            "ast_cfg": {"events": [{"kind": "format_sink", "line": 2, "object": "dst"}]},
        },
    }
    assert (
        EvidenceCompletionQueue._cfg_obligation_confirmation_proof(
            issue, {"function_context": {"code": 'snprintf(dst, n, "%s", input);'}}
        )
        is None
    )


def test_knowledge_db_enumerates_acquisitions_even_when_any_release_name_exists(tmp_path):
    from zscope.retrieval.knowledge_db import KnowledgeDB

    db = KnowledgeDB(str(tmp_path / "facts.db"))
    try:
        for line in (2, 4):
            db.insert_call_edge("f", "x.c", "alpha", "x.c", line)
        db.insert_call_edge("f", "x.c", "omega", "x.c", 6)
        db.commit()
        rows = db.find_acquisition_calls("alpha", ["omega"])
        assert [r["line"] for r in rows] == [2, 4]
        assert db.find_acquisition_calls("alpha", ["omega"], limit=1, offset=1) == [rows[1]]
    finally:
        db.close()


@pytest.mark.parametrize("name", ["budget", "foo", "payload"])
def test_narrowing_requires_conversion_independent_of_spelling(name):
    generator = ClangAstCfgCandidateGenerator()
    good = f"void f(size_t {name}, char *s) {{\nchar*p=malloc({name});\nmemcpy(p,s,{name});\n}}"
    assert not any(
        i["rule"] == "clang_cfg_narrowed_allocation_original_length_copy"
        for i in generator.generate_issues("f", good, "x.c")
    )
    bad = f"void f(size_t {name}, char *s) {{\nsize_t x=(uint16_t){name};\nchar*p=malloc(x);\nmemcpy(p,s,{name});\n}}"
    assert any(
        i["rule"] == "clang_cfg_narrowed_allocation_original_length_copy"
        for i in generator.generate_issues("f", bad, "x.c")
    )
