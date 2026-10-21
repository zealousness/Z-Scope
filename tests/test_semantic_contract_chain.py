from pathlib import Path

from zscope.config.user_config_store import UserConfigStore
from zscope.core.candidates.clang_ast_cfg import ClangAstCfgCandidateGenerator
from zscope.core.candidates.evidence import SemanticOverlayCompiler, annotate_candidate_evidence
from zscope.core.candidates.graph import GraphCandidateGenerator
from zscope.core.candidates.regex import RegexCandidateGenerator
from zscope.core.validation.evidence_completion import EvidenceCompletionQueue
from zscope.semantics.inference import LocalPatternSemanticBuilder


def _row(name, role, pair=None, carrier=None, **extra):
    return {
        "symbol_name": name,
        "kind": role,
        "source": "user",
        "pair": pair or [],
        "contract": {
            "role": role,
            "carrier": carrier or {"kind": "argument", "argument_index": 0},
            "conditions": [],
            "pairs": pair or [],
        },
        **extra,
    }


def _load(tmp_path, rows):
    store = UserConfigStore(tmp_path / "semantics.xlsx")
    store.workbook.write_rows(rows)
    # Force a second object to exercise real XLSX parsing, not a writer cache.
    store = UserConfigStore(tmp_path / "semantics.xlsx")
    semantics = LocalPatternSemanticBuilder(None, store, None, []).semantics_from_user_config()
    overlay = SemanticOverlayCompiler(store).compile()
    return store, semantics, overlay


def test_directed_many_to_many_survives_real_workbook_and_every_consumer(tmp_path):
    rows = {
        "resource": [
            _row("alpha", "allocator", ["xi", "omega"], {"kind": "return"}),
            _row("beta", "allocator", ["omega"], {"kind": "return"}),
            _row("xi", "deallocator"),
            _row("omega", "deallocator"),
        ]
    }
    store, semantics, overlay = _load(tmp_path, rows)
    pairs = {(p["acquire_func"], p["release_func"]) for p in store.list_paired_functions()}
    assert pairs == {("alpha", "xi"), ("alpha", "omega"), ("beta", "omega")}
    assert semantics.contracts.allows("alpha", "xi")
    assert not semantics.contracts.allows("beta", "xi")
    assert semantics.contracts.acquires("omega") == {"alpha", "beta"}
    clang = ClangAstCfgCandidateGenerator(semantics, overlay)
    graph = GraphCandidateGenerator(object(), semantics, overlay)
    regex = RegexCandidateGenerator(semantics)
    for generator in (clang, graph, regex):
        assert generator.semantics.contracts.allows("beta", "omega")
        assert not generator.semantics.contracts.allows("beta", "xi")
        assert generator.semantics.contracts.version == overlay["contract_version"]
    assert "alpha" in overlay["summary"]["resource_names"]
    assert len([p for p in overlay["api_pairs"] if p["acquire"]["name"] == "alpha"]) >= 2
    assert clang._match_release("omega(p);") == ("omega", "p")
    positive = clang.generate_issues(
        "entry",
        "1 | void entry() {\n2 | void *p = beta();\n3 | xi(p);\n4 | return;\n5 | }",
        "entry.c",
    )
    negative = clang.generate_issues(
        "entry",
        "1 | void entry() {\n2 | void *p = alpha();\n3 | omega(p);\n4 | return;\n5 | }",
        "entry.c",
    )
    assert any(i["rule"] == "clang_cfg_acquire_without_release_on_exit" for i in positive)
    assert not any(i["rule"] == "clang_cfg_acquire_without_release_on_exit" for i in negative)


def test_parameter_positions_output_arguments_and_actual_global_macro_lock(tmp_path):
    store, semantics, overlay = _load(
        tmp_path,
        {
            "resource": [
                _row(
                    "gamma",
                    "allocator",
                    ["theta"],
                    {"kind": "output_argument", "argument_index": 1},
                ),
                _row("theta", "deallocator", carrier={"kind": "argument", "argument_index": 1}),
            ],
            "lock": [
                _row(
                    "ENTER",
                    "lock",
                    ["LEAVE"],
                    {"kind": "global", "global_name": "queue.mutex"},
                    symbol_type="macro",
                ),
                _row(
                    "LEAVE",
                    "unlock",
                    carrier={"kind": "global", "global_name": "queue.mutex"},
                    symbol_type="macro",
                ),
                _row(
                    "OTHER",
                    "unlock",
                    carrier={"kind": "global", "global_name": "other.mutex"},
                    symbol_type="macro",
                ),
            ],
        },
    )
    clang = ClangAstCfgCandidateGenerator(semantics, overlay)
    assert clang._match_out_param_acquire("int status = gamma(7, &ptr);") == (
        "ptr",
        "gamma",
        "7, &ptr",
        "status",
    )
    assert clang._match_release("theta(7, ptr);") == ("theta", "ptr")
    assert clang._match_lock("ENTER();") == ("ENTER", "&queue.mutex")
    assert clang._match_unlock("OTHER();") == ("OTHER", "&other.mutex")
    graph = GraphCandidateGenerator(object(), semantics, overlay)
    assert graph._lock_arg("ENTER();") == "&queue.mutex"
    assert {p["category"] for p in store.list_paired_functions()} == {"memory", "lock"}
    code = "1 | void entry() {\n2 | ENTER();\n3 | OTHER();\n4 | return;\n5 | }"
    assert any(
        i["rule"] == "clang_cfg_return_with_lock_held"
        for i in clang.generate_issues("entry", code, "entry.c")
    )
    code = code.replace("OTHER", "LEAVE")
    assert not any(
        i["rule"] == "clang_cfg_return_with_lock_held"
        for i in clang.generate_issues("entry", code, "entry.c")
    )


def test_manual_precedence_scoped_refresh_status_and_noop_write(tmp_path):
    store, _, _ = _load(
        tmp_path,
        {
            "resource": [
                _row("alpha", "allocator", ["xi"]),
                _row(
                    "old",
                    "allocator",
                    ["xi"],
                    source="inferred:semantic_modeling",
                    file_path="a.c",
                    signature="void old ( )",
                ),
                _row(
                    "elsewhere",
                    "allocator",
                    ["xi"],
                    source="inferred:semantic_modeling",
                    file_path="b.c",
                ),
                _row("failed", "allocator", status="failed"),
            ]
        },
    )
    generated = {
        "resource": [_row("alpha", "deallocator", ["wrong"], source="inferred:semantic_modeling")]
    }
    store.workbook.merge_generated(generated, covered_symbols={("old", "a.c", "void old ( )")})
    rows = store.workbook.read_rows()["resource"]
    assert not any(r["symbol_name"] == "old" for r in rows)
    assert any(r["symbol_name"] == "elsewhere" for r in rows)
    assert next(r for r in rows if r["symbol_name"] == "alpha")["kind"] == "allocator"
    assert "failed" not in {r["func_name"] for r in store.list_external_functions()}
    before = store.workbook.path.stat().st_mtime_ns
    store.workbook.merge_generated(generated, covered_symbols=set())
    assert store.workbook.path.stat().st_mtime_ns == before


def test_validator_uses_contract_positions_and_never_proves_inferred_lock_contract(tmp_path):
    _, semantics, overlay = _load(
        tmp_path,
        {
            "lock": [
                _row("alpha", "lock", ["omega"], {"kind": "argument", "argument_index": 1}),
                _row("omega", "unlock", carrier={"kind": "argument", "argument_index": 1}),
            ]
        },
    )
    issue = {
        "rule": "clang_cfg_return_with_lock_held",
        "source": "alpha(7, mu)",
        "evidence_pack": {"path": {"complete_in_function": True}},
    }
    annotate_candidate_evidence(
        issue, backend_profile="clang", checker="clang_ast_cfg", overlay=overlay
    )
    evidence = {
        "semantic_contracts": issue["semantic_contracts"],
        "function_context": {"code": "void f() {\nalpha(7, mu);\nomega(7, mu);\nreturn;\n}"},
    }
    # Direct object resolution is the same for the validator's published input.
    assert issue["semantic_contract_version"] == overlay["contract_version"]
    assert semantics.contracts.resolve_object("omega", "unlock", ["7", "mu"]) == "mu"
    assert EvidenceCompletionQueue._balanced_lock_protocol_proof(issue, evidence) is not None
    for contract in evidence["semantic_contracts"]["api_contracts"]:
        if contract["symbol"]["name"] in {"alpha", "omega"}:
            contract["source"] = "inferred:semantic_modeling"
    assert EvidenceCompletionQueue._balanced_lock_protocol_proof(issue, evidence) is None


def test_benchmark_spellings_and_unrelated_descriptions_create_no_roles(tmp_path):
    _, semantics, overlay = _load(
        tmp_path,
        {
            "resource": [
                {
                    "symbol_name": "ordinary",
                    "kind": "copy",
                    "description": "internally malloc and free and lock and unlock",
                }
            ]
        },
    )
    assert "ordinary" not in semantics.allocators
    assert "ordinary" not in semantics.lock_apis
    clang = ClangAstCfgCandidateGenerator(semantics, overlay)
    assert clang._match_lock("LOCK();") is None
    assert clang._match_release("SAFE_FREE(p);") is None
    assert "_safe_malloc" not in clang._allocator_names
    assert "_net_recv_data" not in clang._recv_source_names


def test_knowledge_db_accepts_any_legal_release_endpoint(tmp_path):
    from zscope.retrieval.knowledge_db import KnowledgeDB

    db = KnowledgeDB(str(tmp_path / "knowledge.db"))
    try:
        for caller, release in (("left", "xi"), ("right", "omega"), ("leak", "foreign")):
            db.insert_call_edge(caller, "entry.c", "alpha", "apis.c", 2)
            db.insert_call_edge(caller, "entry.c", release, "apis.c", 3)
        db.commit()
        assert {
            r["function"] for r in db.find_callers_without_any_callee("alpha", ["xi", "omega"])
        } == {"leak"}
        assert db.find_callers_without_any_callee("alpha", []) == []
    finally:
        db.close()


def test_conditional_and_ambiguous_lock_contracts_stay_unknown(tmp_path):
    _, semantics, overlay = _load(
        tmp_path,
        {
            "lock": [
                _row(
                    "alpha",
                    "lock",
                    ["omega"],
                    contract={
                        "carrier": {"kind": "argument", "argument_index": 0},
                        "conditions": [{"return_value": 0}],
                    },
                ),
                _row("omega", "unlock"),
            ]
        },
    )
    clang = ClangAstCfgCandidateGenerator(semantics, overlay)
    assert clang._match_lock("alpha(mu);") == ("alpha", "mu")
    assert semantics.contracts.match_call("alpha", "lock", ["mu"])[0].applicability == "unknown"
    assert not semantics.contracts.allows("alpha", "omega")
    from zscope.semantics.contracts import ApiContract

    for file in ("left.c", "right.c"):
        semantics.contracts.add(
            ApiContract.from_row(_row("choose", "lock", ["omega"], file_path=file))
        )
    assert not semantics.contracts.allows("choose", "omega")


def test_explicit_global_protocol_is_independent_of_interface_spelling(tmp_path):
    from zscope.core.candidates.graph import FunctionView

    _, semantics, overlay = _load(
        tmp_path,
        {
            "resource": [
                _row(
                    "alpha",
                    "allocator",
                    ["omega"],
                    {"kind": "global", "global_name": "registry.current"},
                ),
                _row(
                    "omega",
                    "deallocator",
                    carrier={"kind": "global", "global_name": "registry.current"},
                ),
            ]
        },
    )
    graph = GraphCandidateGenerator(object(), semantics, overlay)

    def view(name, code):
        return FunctionView(
            name=name,
            file_path="entry.c",
            signature=f"void {name}(void)",
            lines=tuple(graph._parse_lines(code)),
            callees=(),
        )

    first = view("alpha", "1 | void alpha(void) {\n2 | registry.current = malloc(8);\n3 | }")
    missing = view("omega", "5 | void omega(void) {\n6 | return;\n7 | }")
    assert any(
        i["rule"] == "paired_global_registration_cleanup_omitted"
        for i in graph.generate_for_views([first, missing])
    )
    complete = view("omega", "5 | void omega(void) {\n6 | free(registry.current);\n7 | }")
    assert not any(
        i["rule"] == "paired_global_registration_cleanup_omitted"
        for i in graph.generate_for_views([first, complete])
    )


def test_replacing_contract_retires_old_directed_edges():
    from zscope.semantics.contracts import ApiContract, ContractRegistry

    registry = ContractRegistry()
    registry.add(ApiContract.from_row(_row("alpha", "allocator", ["xi", "omega"])))
    registry.add(ApiContract.from_row(_row("beta", "allocator", ["omega"])))
    registry.add(ApiContract.from_row(_row("alpha", "allocator", ["xi"])))
    assert registry.releases("alpha") == {"xi"}
    assert registry.releases("beta") == {"omega"}


def test_manual_override_removes_previous_generated_scoped_row(tmp_path):
    store, _, _ = _load(
        tmp_path,
        {
            "resource": [
                _row("alpha", "copy", source="user"),
                _row(
                    "alpha",
                    "allocator",
                    ["xi"],
                    source="inferred:semantic_modeling",
                    file_path="a.c",
                ),
            ]
        },
    )
    store.workbook.merge_generated(
        {
            "resource": [
                _row(
                    "alpha",
                    "allocator",
                    ["xi"],
                    source="inferred:semantic_modeling",
                    file_path="a.c",
                )
            ]
        },
        covered_symbols={("alpha", "a.c", "")},
    )
    rows = store.workbook.read_rows()["resource"]
    assert len(rows) == 1 and rows[0]["kind"] == "copy"


def test_regex_uses_direct_pair_edges_objects_and_output_argument_positions(tmp_path):
    _, semantics, _ = _load(
        tmp_path,
        {
            "resource": [
                _row(
                    "alpha", "allocator", ["xi"], {"kind": "output_argument", "argument_index": 1}
                ),
                _row("xi", "deallocator", carrier={"kind": "argument", "argument_index": 1}),
                _row("omega", "deallocator"),
            ]
        },
    )
    rules = RegexCandidateGenerator(semantics)
    assert rules._bound_api_calls("alpha(7, &ptr);", {"allocator"})[0][1] == "ptr"
    assert rules._bound_api_calls("xi(7, ptr);", {"deallocator"})[0][1] == "ptr"
    code = "1 | void entry() {\n2 | alpha(7, &ptr);\n3 | xi(7, ptr);\n4 | return;\n5 | }"
    clean = rules.generate_issues("entry", code, "entry.c")
    wrong = rules.generate_issues("entry", code.replace("xi(7, ptr)", "xi(7, other)"), "entry.c")
    assert not any(i["rule"] == "same_function_allocation_not_released" for i in clean)
    assert any(i["rule"] == "same_function_allocation_not_released" for i in wrong)


def test_rule_scanning_cannot_mutate_published_roles_from_names():
    rules = RegexCandidateGenerator()
    version = rules.semantics.contracts.version
    rules.generate_issues(
        "entry", "void entry() {\nvoid *p = allocate_something(7);\nLOCK();\n}", "entry.c"
    )
    assert rules.semantics.contracts.version == version
    assert "allocate_something" not in rules.semantics.allocators
    assert "LOCK" not in rules.semantics.lock_apis


def test_validator_does_not_treat_allocator_spelling_or_inferred_role_as_proof(tmp_path):
    _, _, overlay = _load(
        tmp_path, {"resource": [_row("alpha", "allocator", carrier={"kind": "return"})]}
    )
    assert EvidenceCompletionQueue._allocation_call_names("allocate_something(7)") == []
    assert EvidenceCompletionQueue._allocation_call_names(
        "alpha(7)", {"semantic_contracts": overlay}
    ) == ["alpha"]
    next(c for c in overlay["api_contracts"] if c["symbol"]["name"] == "alpha")[
        "source"
    ] = "inferred:semantic_modeling"
    assert (
        EvidenceCompletionQueue._allocation_call_names("alpha(7)", {"semantic_contracts": overlay})
        == []
    )


def test_candidate_validation_identity_changes_with_published_contract_version(tmp_path):
    from zscope.orchestration.candidates import CandidateLedger, CandidateRegistrar
    from copy import deepcopy

    base = {
        "candidate_source": "deterministic_rule",
        "rule": "same_function_allocation_not_released",
        "category": "memory_leak",
        "location": "entry.c:3",
        "function": "entry",
        "description": "Check lifetime",
    }
    ledger = CandidateLedger(project_id="p", project_root=str(tmp_path), revision="r")
    registrar = CandidateRegistrar(ledger)
    for version in ("first", "second"):
        issue = dict(deepcopy(base), semantic_contract_version=version)
        registrar.register_issues([issue], source="deterministic_rule")
    assert len(ledger.records()) == 2
