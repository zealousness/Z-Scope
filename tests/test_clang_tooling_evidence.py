import json
import os
from types import SimpleNamespace

from zscope.retrieval.clang_tooling_evidence import ClangToolingEvidenceProvider


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
                    "arguments": ["clang", "-Iinclude", "-DDEBUG=1", "-c", str(source), "-o", "demo.o"],
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
    assert evidence["cfg_dump_command"][
        evidence["cfg_dump_command"].index("-o") + 1
    ] == os.devnull


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
                    {"kind": "VarDecl", "name": "p", "loc": {"line": 11}, "type": {"qualType": "char *"}},
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
                                        "referencedDecl": {"name": "memcpy"},
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
                                "referencedDecl": {"name": "malloc"},
                            },
                            {"kind": "IntegerLiteral"},
                        ],
                    },
                    {
                        "kind": "CallExpr",
                        "loc": {"line": 15},
                        "type": {"qualType": "void"},
                        "inner": [
                            {"kind": "DeclRefExpr", "referencedDecl": {"name": "free"}},
                            {"kind": "DeclRefExpr", "referencedDecl": {"name": "p"}},
                        ],
                    },
                    {
                        "kind": "CallExpr",
                        "loc": {"line": 16},
                        "type": {"qualType": "void"},
                        "inner": [
                            {"kind": "DeclRefExpr", "referencedDecl": {"name": "free"}},
                            {"kind": "DeclRefExpr", "referencedDecl": {"name": "p"}},
                        ],
                    },
                    {
                        "kind": "CallExpr",
                        "loc": {"line": 17},
                        "type": {"qualType": "int"},
                        "inner": [
                            {"kind": "DeclRefExpr", "referencedDecl": {"name": "printf"}},
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
    double_free = next(fact for fact in target["matcher_facts"] if fact["rule_id"] == "clang_ast_same_argument_released_twice")
    assert double_free["resource_symbol"] == "p"
    assert double_free["first_release_line"] == 15
    assert double_free["second_release_line"] == 16
    assert target["if_count"] == 1
    assert target["return_count"] == 1


def test_ast_summary_ignores_stderr_diagnostics(monkeypatch) -> None:
    ast = {
        "kind": "TranslationUnitDecl",
        "inner": [{"kind": "FunctionDecl", "name": "demo", "inner": []}],
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
