import json
import os
import shutil
from types import SimpleNamespace

import pytest

from zscope.core.validation.function_ir import FunctionIRGraph
from zscope.retrieval.clang_tooling_evidence import ClangToolingEvidenceProvider


@pytest.mark.skipif(shutil.which("clang") is None, reason="requires real clang")
def test_real_clang_ast_cfg_preserve_calls_lines_and_fail_closed_shadow(tmp_path) -> None:
    source = tmp_path / "integration.c"
    source.write_text(
        "#include <stdlib.h>\n"
        "#include <unistd.h>\n"
        "#include <sys/socket.h>\n"
        "static int consume(ssize_t value) { return value < 0 ? -1 : (int)value; }\n"
        "int demo(int fd, void *buf) {\n"
        "  int first = consume(recv(fd, buf, 8, 0));\n"
        "  int second = consume(recv(fd, buf, 8, 0));\n"
        "  free(buf);\n"
        "  close(fd);\n"
        "  return first + second;\n"
        "}\n"
        "int demo(int fd, void *buf);\n"
        "static void *copy_impl(void *d, const void *s, size_t n) { (void)s; (void)n; return d; }\n"
        "void *shadow(void *d, const void *s, size_t n) {\n"
        "  void *(*memcpy)(void *, const void *, size_t) = copy_impl;\n"
        "  return memcpy(d, s, n);\n"
        "}\n",
        encoding="utf-8",
    )
    compile_commands = tmp_path / "compile_commands.json"
    compile_commands.write_text(
        json.dumps(
            [
                {
                    "directory": str(tmp_path),
                    "file": str(source),
                    "arguments": [
                        shutil.which("clang") or "clang",
                        "-std=c11",
                        "-Werror",
                        "-Wall",
                        "-Wextra",
                        "-c",
                        str(source),
                    ],
                }
            ]
        ),
        encoding="utf-8",
    )
    provider = ClangToolingEvidenceProvider(
        compile_commands,
        clang_path=shutil.which("clang") or "clang",
        execute=True,
    )

    evidence = provider.collect_for_function(
        func_name="demo",
        file_path=str(source),
        start_line=5,
        end_line=11,
    )
    target = evidence["ast_dump"]["summary"]["target_function"]
    assert evidence["ast_dump"]["summary"]["target_function_unique"] is True
    assert [row["line"] for row in target["call_exprs"] if row["callee"] == "recv"] == [
        6,
        7,
    ]
    graph = FunctionIRGraph.from_clang_evidence(
        evidence,
        function="demo",
        file=str(source),
    )
    assert graph is not None and graph.coverage_complete is True
    assert {(event.callee, event.source_line) for event in graph.events} >= {
        ("recv", 6),
        ("recv", 7),
        ("free", 8),
        ("close", 9),
    }
    standard_free = next(row for row in target["call_exprs"] if row["callee"] == "free")
    assert standard_free["callee_decl_origin"] == "external_declaration"
    assert standard_free["callee_project_definition"] is False

    shadow_evidence = provider.collect_for_function(
        func_name="shadow",
        file_path=str(source),
        start_line=14,
        end_line=17,
    )
    shadow_graph = FunctionIRGraph.from_clang_evidence(
        shadow_evidence,
        function="shadow",
        file=str(source),
    )
    assert shadow_graph is not None
    assert shadow_graph.coverage_complete is False
    assert not any(event.callee == "memcpy" for event in shadow_graph.events)


@pytest.mark.skipif(shutil.which("clang") is None, reason="requires real clang")
def test_real_clang_project_governed_names_do_not_mint_resource_or_thread_events(
    tmp_path,
) -> None:
    source = tmp_path / "collision.c"
    source.write_text(
        "typedef __SIZE_TYPE__ size_t;\n"
        "void *malloc(size_t size) { (void)size; return (void *)0; }\n"
        "void free(void *value) { (void)value; }\n"
        "typedef unsigned long thread_id;\n"
        "typedef void *(*thread_start)(void *);\n"
        "static void *worker(void *value) { return value; }\n"
        "int pthread_create(thread_id *id, const void *attr, thread_start start, void *arg) {\n"
        "  (void)id; (void)attr; return start(arg) != 0;\n"
        "}\n"
        "void *demo(void) {\n"
        "  void *value = malloc(8);\n"
        "  thread_id id = 0;\n"
        "  (void)pthread_create(&id, (void *)0, worker, value);\n"
        "  free(value);\n"
        "  return value;\n"
        "}\n",
        encoding="utf-8",
    )
    compile_commands = tmp_path / "compile_commands.json"
    compile_commands.write_text(
        json.dumps(
            [
                {
                    "directory": str(tmp_path),
                    "file": str(source),
                    "arguments": [
                        shutil.which("clang") or "clang",
                        "-std=c11",
                        "-Werror",
                        "-Wall",
                        "-Wextra",
                        "-c",
                        str(source),
                    ],
                }
            ]
        ),
        encoding="utf-8",
    )
    evidence = ClangToolingEvidenceProvider(
        compile_commands,
        clang_path=shutil.which("clang") or "clang",
        execute=True,
    ).collect_for_function(
        func_name="demo",
        file_path=str(source),
        start_line=10,
        end_line=16,
    )

    ast = evidence["ast_dump"]["summary"]
    assert {"malloc", "free", "pthread_create"} <= set(ast["project_defined_function_names"])
    governed_calls = [
        row
        for row in ast["target_function"]["call_exprs"]
        if row["callee"] in {"malloc", "free", "pthread_create"}
    ]
    assert governed_calls
    assert all(row["callee_project_definition"] is True for row in governed_calls)
    assert all(row["callee_decl_origin"] == "translation_unit_definition" for row in governed_calls)
    assert not any(
        fact["category"] == "resource_lifecycle" for fact in ast["target_function"]["matcher_facts"]
    )
    graph = FunctionIRGraph.from_clang_evidence(
        evidence,
        function="demo",
        file=str(source),
    )
    assert graph is not None and graph.coverage_complete is True
    assert {(event.callee, event.kind) for event in graph.events} >= {
        ("malloc", "call"),
        ("free", "call"),
        ("pthread_create", "call"),
    }
    assert not any(
        event.kind in {"resource_acquire", "resource_release", "thread_create"}
        for event in graph.events
    )


def test_clang_tooling_evidence_prepares_ast_and_cfg_commands(tmp_path) -> None:
    compile_commands = tmp_path / "compile_commands.json"
    source = tmp_path / "src" / "demo.c"
    source.parent.mkdir()
    source.write_text("int demo(void) { return 0; }\n", encoding="utf-8")
    compile_commands.write_text(
        json.dumps(
            [
                {
                    "directory": str(tmp_path),
                    "file": str(source),
                    "arguments": [
                        "clang",
                        "-Iinclude",
                        "-DDEBUG=1",
                        "-c",
                        str(source),
                        "-o",
                        "demo.o",
                    ],
                }
            ]
        ),
        encoding="utf-8",
    )

    provider = ClangToolingEvidenceProvider(compile_commands, execute=False)
    evidence = provider.collect_for_function(
        func_name="demo",
        file_path=str(source),
        start_line=1,
        end_line=3,
    )

    assert evidence["status"] == "command_prepared_not_executed"
    assert evidence["compile_command_found"] is True
    assert evidence["ast_dump_command"][:3] == ["clang", "-Xclang", "-ast-dump=json"]
    assert "-c" not in evidence["ast_dump_command"]
    assert "-o" not in evidence["ast_dump_command"]
    assert str(source) in evidence["ast_dump_command"]
    assert "--analyze" in evidence["cfg_dump_command"]
    assert "-analyzer-checker=debug.DumpCFG" in evidence["cfg_dump_command"]
    assert evidence["cfg_dump_command"][evidence["cfg_dump_command"].index("-o") + 1] == os.devnull


def test_clang_tooling_evidence_handles_missing_compile_command(tmp_path) -> None:
    compile_commands = tmp_path / "compile_commands.json"
    compile_commands.write_text("[]", encoding="utf-8")

    provider = ClangToolingEvidenceProvider(compile_commands, execute=False)
    evidence = provider.collect_for_function(
        func_name="demo",
        file_path=str(tmp_path / "src" / "demo.c"),
    )

    assert evidence["status"] == "compile_command_not_found"
    assert evidence["compile_command_found"] is False


def test_clang_tooling_summarizes_ast_json() -> None:
    ast = {
        "kind": "TranslationUnitDecl",
        "inner": [
            {
                "kind": "FunctionDecl",
                "name": "demo",
                "loc": {"line": 10},
                "type": {"qualType": "int (char *)"},
                "inner": [
                    {"kind": "CompoundStmt"},
                    {
                        "kind": "VarDecl",
                        "name": "p",
                        "loc": {"line": 11},
                        "type": {"qualType": "char *"},
                    },
                    {
                        "kind": "IfStmt",
                        "inner": [
                            {
                                "kind": "CallExpr",
                                "loc": {"line": 12},
                                "type": {"qualType": "int"},
                                "inner": [
                                    {
                                        "kind": "DeclRefExpr",
                                        "referencedDecl": {
                                            "kind": "FunctionDecl",
                                            "name": "memcpy",
                                            "type": {
                                                "qualType": "void *(void *, const void *, size_t)"
                                            },
                                        },
                                    }
                                ],
                            }
                        ],
                    },
                    {
                        "kind": "CallExpr",
                        "loc": {"line": 14},
                        "type": {"qualType": "void *"},
                        "inner": [
                            {
                                "kind": "DeclRefExpr",
                                "referencedDecl": {
                                    "kind": "FunctionDecl",
                                    "name": "malloc",
                                    "type": {"qualType": "void *(size_t)"},
                                },
                            },
                            {"kind": "IntegerLiteral"},
                        ],
                    },
                    {
                        "kind": "CallExpr",
                        "loc": {"line": 15},
                        "type": {"qualType": "void"},
                        "inner": [
                            {
                                "kind": "DeclRefExpr",
                                "referencedDecl": {
                                    "kind": "FunctionDecl",
                                    "name": "free",
                                    "type": {"qualType": "void (void *)"},
                                },
                            },
                            {"kind": "DeclRefExpr", "referencedDecl": {"name": "p"}},
                        ],
                    },
                    {
                        "kind": "CallExpr",
                        "loc": {"line": 16},
                        "type": {"qualType": "void"},
                        "inner": [
                            {
                                "kind": "DeclRefExpr",
                                "referencedDecl": {
                                    "kind": "FunctionDecl",
                                    "name": "free",
                                    "type": {"qualType": "void (void *)"},
                                },
                            },
                            {"kind": "DeclRefExpr", "referencedDecl": {"name": "p"}},
                        ],
                    },
                    {
                        "kind": "CallExpr",
                        "loc": {"line": 17},
                        "type": {"qualType": "int"},
                        "inner": [
                            {
                                "kind": "DeclRefExpr",
                                "referencedDecl": {
                                    "kind": "FunctionDecl",
                                    "name": "printf",
                                    "type": {"qualType": "int (const char *, ...)"},
                                },
                            },
                            {"kind": "DeclRefExpr", "referencedDecl": {"name": "p"}},
                        ],
                    },
                    {"kind": "ReturnStmt", "loc": {"line": 13}},
                ],
            }
        ],
    }

    summary = ClangToolingEvidenceProvider._summarize_ast_json(json.dumps(ast), func_name="demo")

    target = summary["target_function"]
    assert summary["parse_ok"] is True
    assert target["name"] == "demo"
    assert target["var_decls"][0]["name"] == "p"
    assert target["call_exprs"][0]["callee"] == "memcpy"
    assert target["call_exprs"][1]["arg_count"] == 1
    matcher_rules = {fact["rule_id"] for fact in target["matcher_facts"]}
    assert "clang_ast_copy_size_relation" in matcher_rules
    assert "clang_ast_resource_acquire_call" in matcher_rules
    assert "clang_ast_resource_balance_summary" in matcher_rules
    assert "clang_ast_same_argument_released_twice" in matcher_rules
    assert "clang_ast_release_then_call_argument_use" in matcher_rules
    double_free = next(
        fact
        for fact in target["matcher_facts"]
        if fact["rule_id"] == "clang_ast_same_argument_released_twice"
    )
    assert double_free["resource_symbol"] == "p"
    assert double_free["first_release_line"] == 15
    assert double_free["second_release_line"] == 16
    assert target["if_count"] == 1
    assert target["return_count"] == 1


def test_translation_unit_governed_name_collisions_are_ordinary_typed_calls() -> None:
    def direct_ref(name: str, type_name: str) -> dict:
        return {
            "kind": "DeclRefExpr",
            "referencedDecl": {
                "kind": "FunctionDecl",
                "name": name,
                "type": {"qualType": type_name},
            },
        }

    def call(name: str, type_name: str, line: int, *args: dict) -> dict:
        return {
            "kind": "CallExpr",
            "loc": {"line": line},
            "type": {"qualType": "int"},
            "inner": [direct_ref(name, type_name), *args],
        }

    definitions = [
        {
            "kind": "FunctionDecl",
            "name": "malloc",
            "type": {"qualType": "void *(size_t)"},
            "inner": [{"kind": "CompoundStmt"}],
        },
        {
            "kind": "FunctionDecl",
            "name": "free",
            "type": {"qualType": "void (void *)"},
            "inner": [{"kind": "CompoundStmt"}],
        },
        {
            "kind": "FunctionDecl",
            "name": "pthread_create",
            "type": {"qualType": "int (void *, void *, void *, void *)"},
            "inner": [{"kind": "CompoundStmt"}],
        },
    ]
    demo = {
        "kind": "FunctionDecl",
        "name": "demo",
        "loc": {"line": 10},
        "type": {"qualType": "int (void)"},
        "inner": [
            {
                "kind": "CompoundStmt",
                "inner": [
                    {
                        "kind": "VarDecl",
                        "name": "p",
                        "loc": {"line": 11},
                        "type": {"qualType": "void *"},
                        "inner": [
                            call(
                                "malloc",
                                "void *(size_t)",
                                11,
                                {"kind": "IntegerLiteral", "value": "8"},
                            )
                        ],
                    },
                    call(
                        "free",
                        "void (void *)",
                        12,
                        direct_ref("p", "void *"),
                    ),
                    call(
                        "pthread_create",
                        "int (void *, void *, void *, void *)",
                        13,
                        direct_ref("thread", "void *"),
                        {"kind": "IntegerLiteral", "value": "0"},
                        direct_ref("worker", "void *"),
                        {"kind": "IntegerLiteral", "value": "0"},
                    ),
                ],
            }
        ],
    }
    summary = ClangToolingEvidenceProvider._summarize_ast_json(
        json.dumps({"kind": "TranslationUnitDecl", "inner": [*definitions, demo]}),
        func_name="demo",
    )
    target = summary["target_function"]

    assert {"malloc", "free", "pthread_create"} <= set(summary["project_defined_function_names"])
    governed = [
        row for row in target["call_exprs"] if row["callee"] in {"malloc", "free", "pthread_create"}
    ]
    assert len(governed) == 3
    assert all(row["callee_project_definition"] is True for row in governed)
    assert target["matcher_facts"] == []

    cfg = {
        "parse_ok": True,
        "function": "demo",
        "function_section_unique": True,
        "semantic_statements_complete": True,
        "entry_blocks": ["B1"],
        "exit_blocks": ["B0"],
        "blocks": [
            {
                "id": "B1",
                "label": "ENTRY",
                "successors": ["B0"],
                "predecessors": [],
                "statements": [],
                "semantic_statements": [
                    "void *p = malloc(8)",
                    "free(p)",
                    "pthread_create(thread, 0, worker, 0)",
                ],
            },
            {
                "id": "B0",
                "label": "EXIT",
                "successors": [],
                "predecessors": ["B1"],
                "statements": [],
                "semantic_statements": [],
            },
        ],
    }
    graph = FunctionIRGraph.from_clang_evidence(
        {
            "schema": "clang_tooling_evidence_v1",
            "cfg_dump": {"summary": cfg},
            "ast_dump": {"summary": summary},
        },
        function="demo",
        file="demo.c",
    )
    assert graph is not None and graph.coverage_complete is True
    assert {(event.callee, event.kind) for event in graph.events} == {
        ("malloc", "call"),
        ("free", "call"),
        ("pthread_create", "call"),
    }

    tampered = json.loads(json.dumps(summary))
    local_malloc = next(
        row for row in tampered["target_function"]["call_exprs"] if row["callee"] == "malloc"
    )
    local_malloc["callee_project_definition"] = False
    local_malloc["callee_decl_origin"] = "external_declaration"
    tampered_graph = FunctionIRGraph.from_clang_evidence(
        {
            "schema": "clang_tooling_evidence_v1",
            "cfg_dump": {"summary": cfg},
            "ast_dump": {"summary": tampered},
        },
        function="demo",
        file="demo.c",
    )
    assert tampered_graph is not None
    assert tampered_graph.coverage_complete is False
    assert next(event for event in tampered_graph.events if event.callee == "malloc").kind == "call"

    missing_metadata = json.loads(json.dumps(summary))
    missing_metadata.pop("project_defined_function_declarations")
    missing_graph = FunctionIRGraph.from_clang_evidence(
        {
            "schema": "clang_tooling_evidence_v1",
            "cfg_dump": {"summary": cfg},
            "ast_dump": {"summary": missing_metadata},
        },
        function="demo",
        file="demo.c",
    )
    assert missing_graph is not None
    assert missing_graph.coverage_complete is False
    assert all(
        event.kind == "call"
        for event in missing_graph.events
        if event.callee in {"malloc", "free", "pthread_create"}
    )


def test_clang_tooling_seals_typed_signed_length_flow_and_guard() -> None:
    def ref(name: str, type_name: str = "") -> dict:
        referenced = {"kind": "FunctionDecl", "name": name}
        if type_name:
            referenced["type"] = {"qualType": type_name}
        return {
            "kind": "DeclRefExpr",
            "type": {"qualType": type_name},
            "referencedDecl": referenced,
        }

    recv_call = {
        "kind": "CallExpr",
        "loc": {"line": 12},
        "type": {"qualType": "ssize_t"},
        "inner": [ref("recv", "ssize_t (int, void *, size_t, int)"), ref("fd", "int")],
    }
    memcpy_call = {
        "kind": "CallExpr",
        "loc": {"line": 14},
        "type": {"qualType": "void *"},
        "inner": [
            ref("memcpy", "void *(void *, const void *, size_t)"),
            ref("dst", "void *"),
            ref("src", "const void *"),
            {
                "kind": "ImplicitCastExpr",
                "type": {"qualType": "size_t"},
                "inner": [ref("n", "ssize_t")],
            },
        ],
    }
    ast = {
        "kind": "TranslationUnitDecl",
        "inner": [
            {
                "kind": "FunctionDecl",
                "name": "demo",
                "loc": {"line": 10},
                "type": {"qualType": "void (int, void *, const void *)"},
                "inner": [
                    {"kind": "CompoundStmt"},
                    {"kind": "ParmVarDecl", "name": "fd", "type": {"qualType": "int"}},
                    {
                        "kind": "VarDecl",
                        "name": "n",
                        "loc": {"line": 12},
                        "type": {"qualType": "ssize_t"},
                        "inner": [recv_call],
                    },
                    {
                        "kind": "IfStmt",
                        "loc": {"line": 13},
                        "inner": [
                            {
                                "kind": "BinaryOperator",
                                "opcode": "<",
                                "inner": [
                                    ref("n", "ssize_t"),
                                    {"kind": "IntegerLiteral", "value": "0"},
                                ],
                            },
                            {"kind": "CompoundStmt", "inner": [{"kind": "ReturnStmt"}]},
                        ],
                    },
                    memcpy_call,
                ],
            }
        ],
    }

    summary = ClangToolingEvidenceProvider._summarize_ast_json(json.dumps(ast), func_name="demo")

    target = summary["target_function"]
    assert target["value_fact_coverage_complete"] is True
    assert target["parameters"] == [{"name": "fd", "type": "int", "line": 10}]
    assert target["call_assignments"][0]["target"] == "n"
    assert target["call_assignments"][0]["result_type"] == "ssize_t"
    memcpy = next(call for call in target["call_exprs"] if call["callee"] == "memcpy")
    assert memcpy["argument_types"][2] == "size_t"
    assert memcpy["argument_refs"][2] == ["n"]
    assert memcpy["argument_ref_types"][2] == {"n": "ssize_t"}
    assert target["terminating_guards"] == [
        {
            "line": 13,
            "comparisons": [
                {
                    "opcode": "<",
                    "lhs_refs": ["n"],
                    "rhs_refs": [],
                    "lhs_integer_literals": [],
                    "rhs_integer_literals": ["0"],
                }
            ],
            "terminates_then_branch": True,
        }
    ]


def test_ast_summary_ignores_stderr_diagnostics(monkeypatch) -> None:
    ast = {
        "kind": "TranslationUnitDecl",
        "inner": [
            {
                "kind": "FunctionDecl",
                "name": "demo",
                "inner": [{"kind": "CompoundStmt"}],
            }
        ],
    }
    monkeypatch.setattr(
        "zscope.retrieval.clang_tooling_evidence.subprocess.run",
        lambda *args, **kwargs: SimpleNamespace(
            returncode=0,
            stdout=json.dumps(ast),
            stderr="warning: diagnostic emitted after the JSON payload",
        ),
    )

    result = ClangToolingEvidenceProvider(None)._run_tool(
        ["clang", "demo.c"],
        summary_kind="ast",
        func_name="demo",
    )

    assert result["ok"] is True
    assert result["summary"]["parse_ok"] is True
    assert result["summary"]["target_function"]["name"] == "demo"


def test_clang_tooling_summarizes_cfg_dump() -> None:
    dump = """
 [B2 (ENTRY)]
   Succs (1): B1
 [B1]
   1: p = malloc(8)
   2: return 0
   Preds (1): B2
   Succs (1): B0
 [B0 (EXIT)]
   Preds (1): B1
"""

    summary = ClangToolingEvidenceProvider._summarize_cfg_dump(dump, func_name="demo")

    assert summary["parse_ok"] is True
    assert summary["entry_blocks"] == ["B2"]
    assert summary["exit_blocks"] == ["B0"]
    assert summary["edge_count"] == 2
    assert summary["blocks"][1]["statements"] == ["p = malloc(8)", "return 0"]


def test_clang_cfg_expression_dag_reconstructs_calls_and_access_roots() -> None:
    dump = """
void creator(void)
 [B2 (ENTRY)]
   Succs (1): B1
 [B1]
   1: pthread_create
   2: [B1.1] (ImplicitCastExpr, FunctionToPointerDecay, int (*)(void))
   3: thread_id
   4: &[B1.3]
   5: 0
   6: worker
   7: [B1.6] (ImplicitCastExpr, FunctionToPointerDecay, void *(*)(void *))
   8: [B1.2]([B1.4], [B1.5], [B1.7], ([B1.5]))
   9: g_demo_counter
  10: [B1.9]++
  11: 0
  12: return [B1.11];
   Preds (1): B2
   Succs (1): B0
 [B0 (EXIT)]
   Preds (1): B1
"""

    summary = ClangToolingEvidenceProvider._summarize_cfg_dump(dump, func_name="creator")

    assert summary["semantic_statements_complete"] is True
    assert summary["blocks"][1]["semantic_statements"] == [
        "pthread_create(&thread_id, 0, worker, 0)",
        "g_demo_counter++",
        "return 0;",
    ]


def test_clang_cfg_expression_dag_fails_closed_on_missing_or_cyclic_identity() -> None:
    missing = """
 [B2 (ENTRY)]
   Succs (1): B1
 [B1]
   1: sink([B1.9])
   Preds (1): B2
   Succs (1): B0
 [B0 (EXIT)]
   Preds (1): B1
"""
    cyclic = """
 [B2 (ENTRY)]
   Succs (1): B1
 [B1]
   1: [B1.2]
   2: [B1.1]
   Preds (1): B2
   Succs (1): B0
 [B0 (EXIT)]
   Preds (1): B1
"""
    detached_cycle = """
 [B2 (ENTRY)]
   Succs (1): B1
 [B1]
   1: sink(0)
   2: [B1.3]
   3: [B1.2]
   Preds (1): B2
   Succs (1): B0
 [B0 (EXIT)]
   Preds (1): B1
"""

    missing_summary = ClangToolingEvidenceProvider._summarize_cfg_dump(missing, func_name="demo")
    cyclic_summary = ClangToolingEvidenceProvider._summarize_cfg_dump(cyclic, func_name="demo")
    detached_summary = ClangToolingEvidenceProvider._summarize_cfg_dump(
        detached_cycle, func_name="demo"
    )

    assert missing_summary["semantic_statements_complete"] is False
    assert cyclic_summary["semantic_statements_complete"] is False
    assert detached_summary["semantic_statements_complete"] is False


def test_typed_call_binding_uses_exact_argument_refs_not_cfg_iteration_order() -> None:
    bindings, complete = FunctionIRGraph._typed_call_bindings(
        {"B1": ("consume(second)", "consume(first)")},
        (
            {
                "callee": "consume",
                "line": 10,
                "arg_count": 1,
                "argument_refs": [["first"]],
            },
            {
                "callee": "consume",
                "line": 20,
                "arg_count": 1,
                "argument_refs": [["second"]],
            },
        ),
        (),
    )

    assert complete is True
    assert bindings[("B1", 0)][0]["line"] == 20
    assert bindings[("B1", 1)][0]["line"] == 10


def test_typed_call_binding_fails_closed_for_ambiguous_repeated_callee() -> None:
    bindings, complete = FunctionIRGraph._typed_call_bindings(
        {"B1": ("consume(shared)", "consume(shared)")},
        (
            {
                "callee": "consume",
                "line": 10,
                "arg_count": 1,
                "argument_refs": [["shared"]],
            },
            {
                "callee": "consume",
                "line": 20,
                "arg_count": 1,
                "argument_refs": [["shared"]],
            },
        ),
        (),
    )

    assert complete is False
    assert bindings == {}


def test_function_ir_binds_events_only_to_exact_typed_ast_callees() -> None:
    dump = """
int demo(int fd, unsigned char *dst)
 [B2 (ENTRY)]
   Succs (1): B1
 [B1]
   1: recv
   2: [B1.1] (ImplicitCastExpr, FunctionToPointerDecay, ssize_t (*)(int, void *, size_t, int))
   3: fd
   4: buffer
   5: 64
   6: 0
   7: [B1.2]([B1.3], [B1.4], [B1.5], [B1.6])
   8: ssize_t received = recv(fd, buffer, 64, 0);
   9: memcpy
  10: [B1.9] (ImplicitCastExpr, FunctionToPointerDecay, void *(*)(void *, const void *, size_t))
  11: dst
  12: buffer
  13: received
  14: [B1.13] (ImplicitCastExpr, LValueToRValue, ssize_t)
  15: [B1.14] (ImplicitCastExpr, IntegralCast, size_t)
  16: [B1.10]([B1.11], [B1.12], [B1.15])
  17: 0
  18: return [B1.17];
   Preds (1): B2
   Succs (1): B0
 [B0 (EXIT)]
   Preds (1): B1
"""
    cfg = ClangToolingEvidenceProvider._summarize_cfg_dump(dump, func_name="demo")
    ast_target = {
        "parameters": [],
        "var_decls": [{"name": "received", "type": "ssize_t", "line": 4}],
        "call_exprs": [
            {"callee": "recv", "line": 4, "argument_types": [], "argument_refs": []},
            {"callee": "memcpy", "line": 5, "argument_types": [], "argument_refs": []},
        ],
        "call_assignments": [
            {"target": "received", "callee": "recv", "line": 4, "result_type": "ssize_t"}
        ],
        "conversions": [],
        "terminating_guards": [],
        "binary_ops": [],
        "value_fact_coverage_complete": True,
    }
    graph = FunctionIRGraph.from_clang_evidence(
        {
            "cfg_dump": {"summary": cfg},
            "ast_dump": {
                "summary": {
                    "parse_ok": True,
                    "target_function": ast_target,
                }
            },
        },
        function="demo",
        file="demo.c",
    )

    assert graph is not None
    assert graph.coverage_complete is True
    assert [(event.kind, event.callee, event.source_line) for event in graph.events] == [
        ("call", "recv", 4),
        ("call", "memcpy", 5),
        ("return", "", 0),
    ]
    assert not any(event.callee in {"ssize_t", "size_t", "sizeof"} for event in graph.events)
    recv_event = graph.events[0]
    recv_statement = graph.statement_map[recv_event.statement_uid]
    assert recv_statement.text == "ssize_t received = recv(fd, buffer, 64, 0);"


def test_cfg_reducer_preserves_single_argument_call_parentheses() -> None:
    semantic, complete = ClangToolingEvidenceProvider._cfg_semantic_statements(
        {
            "[B1.1]": {"block": "B1", "ordinal": 1, "code": "free"},
            "[B1.2]": {
                "block": "B1",
                "ordinal": 2,
                "code": "[B1.1] (ImplicitCastExpr, FunctionToPointerDecay, void (*)(void *))",
            },
            "[B1.3]": {"block": "B1", "ordinal": 3, "code": "p"},
            "[B1.4]": {
                "block": "B1",
                "ordinal": 4,
                "code": "[B1.3] (ImplicitCastExpr, LValueToRValue, void *)",
            },
            "[B1.5]": {"block": "B1", "ordinal": 5, "code": "[B1.2]([B1.4])"},
            "[B1.6]": {"block": "B1", "ordinal": 6, "code": "close"},
            "[B1.7]": {
                "block": "B1",
                "ordinal": 7,
                "code": "[B1.6] (ImplicitCastExpr, FunctionToPointerDecay, int (*)(int))",
            },
            "[B1.8]": {"block": "B1", "ordinal": 8, "code": "fd"},
            "[B1.9]": {"block": "B1", "ordinal": 9, "code": "[B1.7]([B1.8])"},
        },
        valid=True,
    )

    assert complete is True
    assert semantic == {"B1": ["free(p)", "close(fd)"]}


def test_ast_target_selects_unique_definition_and_ignores_trailing_prototype() -> None:
    definition = {
        "kind": "FunctionDecl",
        "name": "demo",
        "loc": {"line": 4},
        "range": {"begin": {"line": 4}, "end": {"line": 8}},
        "type": {"qualType": "int (void)"},
        "inner": [{"kind": "CompoundStmt"}],
    }
    prototype = {
        "kind": "FunctionDecl",
        "name": "demo",
        "loc": {"line": 12},
        "type": {"qualType": "int (void)"},
    }
    summary = ClangToolingEvidenceProvider._summarize_ast_json(
        json.dumps({"kind": "TranslationUnitDecl", "inner": [definition, prototype]}),
        func_name="demo",
        start_line=4,
        end_line=8,
    )

    assert summary["target_function_unique"] is True
    assert summary["target_function"]["line"] == 4
    out_of_range = ClangToolingEvidenceProvider._summarize_ast_json(
        json.dumps({"kind": "TranslationUnitDecl", "inner": [definition, prototype]}),
        func_name="demo",
        start_line=20,
        end_line=21,
    )
    assert out_of_range["target_function_unique"] is False
    assert out_of_range["target_function"] == {}


def test_ast_target_duplicate_definitions_fail_closed() -> None:
    definition = {
        "kind": "FunctionDecl",
        "name": "demo",
        "type": {"qualType": "int (void)"},
        "inner": [{"kind": "CompoundStmt"}],
    }
    summary = ClangToolingEvidenceProvider._summarize_ast_json(
        json.dumps({"kind": "TranslationUnitDecl", "inner": [definition, definition]}),
        func_name="demo",
    )

    assert summary["target_function_unique"] is False
    assert summary["target_function"] == {}


def test_ast_target_supports_one_qualified_cpp_method_definition() -> None:
    ast = {
        "kind": "TranslationUnitDecl",
        "inner": [
            {
                "kind": "NamespaceDecl",
                "name": "ns",
                "inner": [
                    {
                        "kind": "CXXRecordDecl",
                        "name": "Box",
                        "inner": [
                            {
                                "kind": "CXXMethodDecl",
                                "name": "run",
                                "type": {"qualType": "void ()"},
                                "inner": [{"kind": "CompoundStmt"}],
                            }
                        ],
                    }
                ],
            }
        ],
    }
    summary = ClangToolingEvidenceProvider._summarize_ast_json(
        json.dumps(ast),
        func_name="ns::Box::run",
    )

    assert summary["target_function_unique"] is True
    assert summary["target_function"]["name"] == "ns::Box::run"


def test_typed_call_binding_rejects_unmatched_cfg_call_root() -> None:
    bindings, complete = FunctionIRGraph._typed_call_bindings(
        {"B1": ("memcpy(dst, src, n)",)},
        (),
        (),
    )

    assert complete is False
    assert bindings == {}


def test_ast_call_rejects_local_function_pointer_named_like_governed_api() -> None:
    call = {
        "kind": "CallExpr",
        "type": {"qualType": "void *"},
        "inner": [
            {
                "kind": "ImplicitCastExpr",
                "inner": [
                    {
                        "kind": "DeclRefExpr",
                        "referencedDecl": {
                            "kind": "VarDecl",
                            "name": "memcpy",
                            "type": {"qualType": "void *(*)(void *, const void *, size_t)"},
                        },
                    }
                ],
            }
        ],
    }

    summary = ClangToolingEvidenceProvider._call_expr_summary(call, line=7)
    assert summary["callee"] == ""
    assert summary["callee_decl_identity"] == ""
    assert summary["callee_binding_complete"] is False


def test_ast_offsets_recover_distinct_lines_for_repeated_nested_calls(tmp_path) -> None:
    source = tmp_path / "repeat.c"
    text = (
        "int demo(int fd) {\n"
        "  int first = wrap(recv(fd, 0, 0, 0));\n"
        "  int second = wrap(recv(fd, 0, 0, 0));\n"
        "  return first + second;\n"
        "}\n"
    )
    source.write_text(text, encoding="utf-8")

    def direct_call(name: str, offset: int, *args: dict) -> dict:
        return {
            "kind": "CallExpr",
            "range": {"begin": {"offset": offset}},
            "type": {"qualType": "int"},
            "inner": [
                {
                    "kind": "ImplicitCastExpr",
                    "inner": [
                        {
                            "kind": "DeclRefExpr",
                            "referencedDecl": {
                                "kind": "FunctionDecl",
                                "name": name,
                                "type": {"qualType": "int (int, ...)"},
                            },
                        }
                    ],
                },
                *args,
            ],
        }

    first_offset = text.index("wrap(recv")
    second_offset = text.index("wrap(recv", first_offset + 1)
    first_recv = direct_call("recv", first_offset + len("wrap("))
    second_recv = direct_call("recv", second_offset + len("wrap("))
    ast = {
        "kind": "TranslationUnitDecl",
        "inner": [
            {
                "kind": "FunctionDecl",
                "name": "demo",
                "loc": {"offset": 4},
                "range": {"begin": {"offset": 0}, "end": {"offset": len(text) - 2}},
                "type": {"qualType": "int (int)"},
                "inner": [
                    {
                        "kind": "CompoundStmt",
                        "inner": [
                            {
                                "kind": "VarDecl",
                                "name": "first",
                                "range": {"begin": {"offset": first_offset - 12}},
                                "type": {"qualType": "int"},
                                "inner": [direct_call("wrap", first_offset, first_recv)],
                            },
                            {
                                "kind": "VarDecl",
                                "name": "second",
                                "range": {"begin": {"offset": second_offset - 13}},
                                "type": {"qualType": "int"},
                                "inner": [direct_call("wrap", second_offset, second_recv)],
                            },
                        ],
                    }
                ],
            }
        ],
    }

    summary = ClangToolingEvidenceProvider._summarize_ast_json(
        json.dumps(ast),
        func_name="demo",
        source_path=source,
        start_line=1,
        end_line=5,
    )["target_function"]
    recv_lines = [row["line"] for row in summary["call_exprs"] if row["callee"] == "recv"]
    assert recv_lines == [2, 3]
