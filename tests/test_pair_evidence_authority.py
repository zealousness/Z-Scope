"""A model's guessed allocator/free edge cannot discharge a resource obligation."""

from test_wrapper_contract_compiler import compile_all, context, publish
from zscope.semantics.contract_compiler import complete_transparent_pairs
from zscope.semantics.contracts import ApiContract, ObjectBinding, SymbolIdentity, contract_rows
from zscope.semantics.defaults import default_local_pattern_semantics
from zscope.config.user_config_store import UserConfigStore
from zscope.semantics.inference import LocalPatternSemanticBuilder


def test_inferred_pair_stays_unknown_after_real_workbook_reload(tmp_path):
    proposal = ApiContract(
        SymbolIdentity("obtain"),
        "allocator",
        ObjectBinding("return"),
        pairs=(SymbolIdentity("free"),),
        source="inferred:semantic_modeling",
    )
    snapshot = {
        "func_name": "obtain",
        "file_path": "unit.c",
        "interface_contracts": [proposal.to_dict()],
    }
    store = UserConfigStore(tmp_path / "user_config.xlsx")
    store.workbook.merge_generated(contract_rows([snapshot]), covered_symbols=set())
    reader = UserConfigStore(store.workbook.path)
    semantics = default_local_pattern_semantics()
    semantics.merge(
        LocalPatternSemanticBuilder(None, reader, None, []).semantics_from_user_config()
    )
    assert semantics.contracts.releases("obtain") == {"free"}
    assert not semantics.contracts.allows("obtain", "free")
    assert (
        semantics.contracts.release_status("obtain", "free", ["p"], acquired_object="p")
        == "unknown"
    )


def test_untrusted_adapters_cannot_derive_extra_pairs():
    registry = default_local_pattern_semantics().contracts
    snapshots = compile_all(
        [
            context("obtain", "void *obtain(size_t n) { void *p=malloc(n); opaque(p); return p; }"),
            context("dispose", "void dispose(void *p) { free(p); }"),
        ],
        registry,
    )
    acquire = snapshots[0]["interface_contracts"][0]
    assert not ApiContract.from_row({"contract": acquire}).effects_trusted
    complete_transparent_pairs(snapshots, registry)
    assert "dispose" not in {p["name"] for p in acquire["pairs"]}


def test_verified_composition_and_manual_edges_remain_usable(tmp_path):
    snapshots = compile_all(
        [
            context("obtain", "void *obtain(size_t n) { return malloc(n); }"),
            context("dispose", "void dispose(void *p) { free(p); }"),
        ]
    )
    _, custom, _ = publish(tmp_path, snapshots)
    semantics = default_local_pattern_semantics()
    semantics.merge(custom)
    assert semantics.contracts.allows("obtain", "dispose")
    c = ApiContract(
        SymbolIdentity("manual"),
        "allocator",
        ObjectBinding("return"),
        pairs=(SymbolIdentity("free"),),
    )
    semantics.contracts.add(c)
    assert semantics.contracts.allows("manual", "free")


def test_knowledgedb_does_not_compile_unverified_pair_guesses(tmp_path):
    from zscope.core.candidates.backend_signals import resource_release_pairs_from_overlay

    contract = ApiContract(
        SymbolIdentity("take"),
        "allocator",
        ObjectBinding("return"),
        pairs=(SymbolIdentity("free"),),
        source="inferred:semantic_modeling",
    )
    assert resource_release_pairs_from_overlay({"api_contracts": [contract.to_dict()]}) == []


def test_graph_global_cleanup_requires_same_object_and_applicable_effect():
    from zscope.core.candidates.graph import GraphCandidateGenerator, FunctionView

    semantics = default_local_pattern_semantics()
    acquire = ApiContract(
        SymbolIdentity("prepare"),
        "allocator",
        ObjectBinding("global", global_name="slot"),
        pairs=(SymbolIdentity("dispose"),),
    )
    release = ApiContract(SymbolIdentity("dispose"), "deallocator", ObjectBinding("argument", 0))
    for contract in (acquire, release):
        semantics.contracts.add(contract)
        semantics.add_api(contract.role, contract.symbol.name, contract.source)
    engine = GraphCandidateGenerator(object(), semantics)
    for suffix, missing in [
        ("dispose(slot);", False),
        ("dispose(other);", True),
        ("if (ok) dispose(slot);", True),
        ("slot=other; dispose(slot);", True),
        ("opaque(); dispose(slot);", True),
    ]:
        code = "void entry(int ok) {\nprepare();\n" + suffix + "\n}"
        view = FunctionView(
            "entry", "unit.c", "void entry(int ok)", tuple(engine._parse_lines(code)), ()
        )
        found = []
        engine._rule_global_container_lifecycle(view, found)
        assert (
            bool(
                [
                    i
                    for i in found
                    if i["rule"] == "global_container_registration_without_cleanup_path"
                ]
            )
            is missing
        )
