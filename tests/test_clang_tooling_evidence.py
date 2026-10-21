import json

from zscope.core.candidates.adapters import compact_clang_tooling_evidence
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


def _call(name: str, line: int, result_type: str = "void *") -> dict:
    return {
        "kind": "CallExpr",
        "loc": {"line": line},
        "type": {"qualType": result_type},
        "inner": [{"kind": "DeclRefExpr", "referencedDecl": {"name": name}}],
    }


def test_clang_tooling_records_which_call_produced_which_target() -> None:
    """A store into a member must keep ``zone->addr``, not the bare ``zone``.

    ``_decl_refs_in_node`` renders declaration names only, so ``zone->addr =
    _safe_malloc(16)`` used to produce a fact about ``zone`` and never matched
    the member expression the CFG text carries.
    """

    zone_ref = {"kind": "DeclRefExpr", "referencedDecl": {"name": "zone"}}
    member_store = {
        "kind": "BinaryOperator",
        "opcode": "=",
        "loc": {"line": 21},
        "type": {"qualType": "char *"},
        "inner": [
            {
                "kind": "MemberExpr",
                "name": "addr",
                "isArrow": True,
                "inner": [zone_ref],
            },
            {
                "kind": "ImplicitCastExpr",
                "type": {"qualType": "char *"},
                "inner": [_call("_safe_malloc", 21, "void *")],
            },
        ],
    }
    dot_store = {
        "kind": "BinaryOperator",
        "opcode": "=",
        "loc": {"line": 22},
        "type": {"qualType": "int"},
        "inner": [
            {
                "kind": "MemberExpr",
                "name": "count",
                "isArrow": False,
                "inner": [{"kind": "DeclRefExpr", "referencedDecl": {"name": "stats"}}],
            },
            _call("_count_items", 22, "int"),
        ],
    }
    # An initializer binds the call result to a named local.
    local_init = {
        "kind": "VarDecl",
        "name": "n",
        "loc": {"line": 23},
        "type": {"qualType": "ssize_t"},
        "inner": [_call("read", 23, "ssize_t")],
    }
    # Neither of these produces a value binding: no call on the right side, and
    # a comparison is not an assignment even when it holds a call.
    no_call_store = {
        "kind": "BinaryOperator",
        "opcode": "=",
        "loc": {"line": 24},
        "type": {"qualType": "int"},
        "inner": [
            {"kind": "DeclRefExpr", "referencedDecl": {"name": "x"}},
            {"kind": "IntegerLiteral", "value": "0"},
        ],
    }
    comparison_with_call = {
        "kind": "BinaryOperator",
        "opcode": "==",
        "loc": {"line": 25},
        "type": {"qualType": "bool"},
        "inner": [
            {"kind": "DeclRefExpr", "referencedDecl": {"name": "y"}},
            _call("_probe", 25, "int"),
        ],
    }
    ast = {
        "kind": "TranslationUnitDecl",
        "inner": [
            {
                "kind": "FunctionDecl",
                "name": "demo",
                "loc": {"line": 20},
                "type": {"qualType": "int (struct zone *)"},
                "inner": [member_store, dot_store, local_init, no_call_store, comparison_with_call],
            }
        ],
    }

    summary = ClangToolingEvidenceProvider._summarize_ast_json(json.dumps(ast), func_name="demo")

    assignments = summary["target_function"]["call_assignments"]
    assert [(item["target"], item["callee"]) for item in assignments] == [
        ("zone->addr", "_safe_malloc"),
        ("stats.count", "_count_items"),
        ("n", "read"),
    ]
    assert assignments[0]["result_type"] == "void *"
    assert assignments[2]["result_type"] == "ssize_t"
    assert assignments[0]["line"] == 21


def test_clang_tooling_assignment_paths_fall_back_to_declaration_names() -> None:
    """When the left side has no member path, the declaration name is kept."""

    targets = ClangToolingEvidenceProvider._assignment_target_texts(
        {"kind": "DeclRefExpr", "referencedDecl": {"name": "slot"}}
    )

    assert targets == ["slot"]
    # An unrecognized shape still yields the declaration refs inside it.
    assert ClangToolingEvidenceProvider._assignment_target_texts({"kind": "UnknownExpr"}) == []


def test_compact_clang_tooling_evidence_carries_value_bindings() -> None:
    """The validator only sees the compacted evidence, so the bindings must survive."""

    assignments = [
        {"target": f"zone->field{index}", "callee": f"_alloc{index}", "line": 30 + index}
        for index in range(10)
    ]
    evidence = {
        "schema": "zscope.clang-tooling-evidence.v1",
        "status": "ok",
        "execution_enabled": True,
        "compile_command_found": True,
        "range": {"start_line": 20, "end_line": 40},
        "ast_dump": {
            "summary": {
                "target_function": {
                    "name": "demo",
                    "line": 20,
                    "type": "int (struct zone *)",
                    "matcher_facts": [],
                    "call_assignments": assignments,
                }
            }
        },
        "cfg_dump": {"summary": {"parse_ok": True, "block_count": 2, "edge_count": 1}},
    }

    compact = compact_clang_tooling_evidence(evidence)

    kept = compact["ast_target_function"]["call_assignments"]
    # Eight bindings reach the validator; the ninth and tenth are dropped.
    assert [item["target"] for item in kept] == [f"zone->field{index}" for index in range(8)]
    assert kept[0] == {
        "target": "zone->field0",
        "callee": "_alloc0",
        "line": 30,
        "result_type": None,
    }


def test_compact_clang_tooling_evidence_without_bindings_stays_empty() -> None:
    """Old evidence has no ``call_assignments``; compaction must not invent them."""

    compact = compact_clang_tooling_evidence(
        {"ast_dump": {"summary": {"target_function": {"name": "demo", "matcher_facts": []}}}}
    )

    assert compact["ast_target_function"]["call_assignments"] == []
