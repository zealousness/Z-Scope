from copy import deepcopy
import gc
import weakref

import pytest

from zscope.reporting.shared_objects import ObjectEncoder, ObjectDecoder


def view(value):
    return ObjectDecoder(ObjectEncoder().envelope(value)).root


def roundtrip(value):
    return ObjectDecoder(ObjectEncoder().envelope(value)).root


def test_reading_all_descendants_does_not_change_reference_or_force_copy():
    original = {"nested": {"items": [{"value": i} for i in range(100)]}}
    value = view(original)
    expected = ObjectEncoder().envelope(value)
    assert value == original  # recursive read materializes every cached child
    assert value._cache is not None and not value._dirty
    clone = deepcopy(value)
    assert clone._cache is None
    assert ObjectEncoder().envelope(value) == expected
    clone["nested"]["items"][0]["value"] = 700
    assert clone._dirty
    assert not value._dirty
    assert roundtrip(clone)["nested"]["items"][0]["value"] == 700
    assert value == original


@pytest.mark.parametrize(
    "mutate",
    [
        lambda d: d.__setitem__("value", 2),
        lambda d: d.__delitem__("value"),
        lambda d: d.pop("value"),
        lambda d: d.popitem(),
        lambda d: d.clear(),
        lambda d: d.setdefault("new", 2),
        lambda d: d.update(new=2),
        lambda d: d.__ior__({"new": 2}),
    ],
)
def test_every_nested_dictionary_write_invalidates_parent(mutate):
    original = {"nested": {"value": 1}}
    value = view(original)
    expected = deepcopy(original)
    mutate(value["nested"])
    mutate(expected["nested"])
    assert value._dirty
    assert roundtrip(value) == expected


@pytest.mark.parametrize(
    "mutate",
    [
        lambda d: d.__setitem__(1, 9),
        lambda d: d.__setitem__(slice(0, 1), [9, 8]),
        lambda d: d.__delitem__(1),
        lambda d: d.__delitem__(slice(0, 1)),
        lambda d: d.append(9),
        lambda d: d.extend([9, 8]),
        lambda d: d.insert(1, 9),
        lambda d: d.pop(),
        lambda d: d.clear(),
        lambda d: d.remove(2),
        lambda d: d.reverse(),
        lambda d: d.sort(),
        lambda d: d.__iadd__([9]),
        lambda d: d.__imul__(2),
    ],
)
def test_every_nested_list_write_invalidates_parent(mutate):
    original = {"nested": [3, 2, 1]}
    value = view(original)
    expected = deepcopy(original)
    mutate(value["nested"])
    mutate(expected["nested"])
    assert value._dirty
    assert roundtrip(value) == expected


def test_nested_changes_survive_repeated_snapshots_and_plain_value_insertion():
    value = view({"one": [{"two": [1]}]})
    value["one"][0]["two"].append(2)
    first = roundtrip(value)
    inserted = {"external": []}
    value["one"].append(inserted)
    inserted["external"].append("after insertion")
    second = roundtrip(value)
    assert first == {"one": [{"two": [1, 2]}]}
    assert second == {"one": [{"two": [1, 2]}, {"external": ["after insertion"]}]}


def test_retaining_a_child_does_not_retain_its_parent():
    from zscope.reporting.immutable_evidence import ImmutableEvidencePool

    # A public ObjectDecoder intentionally owns its root; the pool decoder
    # owns no particular clone, so this isolates the new weak parent links.
    value = ImmutableEvidencePool().clone({"one": [{"two": [1]}]})
    child = value["one"][0]["two"]
    reference = weakref.ref(value)
    del value
    gc.collect()
    assert reference() is None
    child.append(2)
    assert roundtrip(child) == [1, 2]


def test_noop_reads_and_existing_setdefault_stay_clean():
    value = view({"one": [1, 2]})
    assert value.get("one") == [1, 2]
    assert value.setdefault("one", []) == [1, 2]
    assert repr(value) == "{'one': [1, 2]}"
    assert list(value.items()) == [("one", [1, 2])]
    assert not value._dirty


def test_answer_free_guard_sees_new_nested_evaluation_fields():
    from zscope.core.validation.review_checkpoint import assert_answer_free

    value = view({"nested": {"items": []}})
    assert_answer_free(value)
    value["nested"]["items"].append({"is_tp": True})
    with pytest.raises(ValueError, match="offline evaluation"):
        assert_answer_free(value)


def test_read_only_frozen_view_reuses_content_after_deep_reads():
    from zscope.reporting.frozen_objects import frozen_view

    original = {"a": [1, {"b": [2]}]}
    value = frozen_view(original)
    encoded = ObjectEncoder().envelope(value)
    assert value == original
    assert not value._dirty
    assert ObjectEncoder().envelope(value) == encoded
    mutable = deepcopy(value)
    mutable["a"][1]["b"].append(3)
    assert value == original
    assert roundtrip(mutable) == {"a": [1, {"b": [2, 3]}]}


def test_real_contract_metadata_can_use_the_immutable_evidence_pool():
    from dataclasses import asdict
    import json
    from zscope.core.candidates.evidence import annotate_candidate_evidence
    from zscope.core.candidates.regex import RegexCandidateGenerator
    from zscope.reporting.immutable_evidence import ImmutableEvidencePool
    from zscope.semantics.defaults import default_local_pattern_semantics, default_overlay_models

    semantics = default_local_pattern_semantics()
    for contract in semantics.contracts.contracts:
        assert isinstance(contract.pairs, tuple)
        assert isinstance(contract.to_dict()["pairs"], list)
        assert json.dumps(contract.to_dict()) == json.dumps(asdict(contract))
    code = "void entry(void) {\n char *p=malloc(16);\n if (!p) return;\n p[0]=1;\n}\n"
    issue = RegexCandidateGenerator(semantics).generate_issues("entry", code, "unit.c")[0]
    annotate_candidate_evidence(
        issue, backend_profile="regex", checker=issue["rule"], overlay=default_overlay_models()
    )
    pool = ImmutableEvidencePool()
    clone = pool.clone(issue)
    assert pool.shared_clones == 1 and pool.fallback_clones == 0
    assert clone == issue
    independent = deepcopy(clone)
    independent["semantic_contracts"]["api_contracts"][0]["role"] = "modified"
    assert clone == issue


def test_reading_ast_preserves_function_index_and_nested_edits_invalidate_it(monkeypatch):
    import zscope.core.validation.function_index as module

    plain = {
        "ast": {
            "kind": "TranslationUnitDecl",
            "inner": [
                {
                    "kind": "FunctionDecl",
                    "name": "original",
                    "inner": [{"kind": "CompoundStmt", "inner": []}],
                }
            ],
        }
    }
    data = view(plain)
    assert module.function_definitions(data)["original"] == plain["ast"]["inner"][0]
    assert data == plain
    original_collect = module._collect

    def repeated_walk(ast):
        raise AssertionError("read-only access forced a repeated AST traversal")

    monkeypatch.setattr(module, "_collect", repeated_walk)
    assert set(module.function_definitions(data)) == {"original"}
    monkeypatch.setattr(module, "_collect", original_collect)
    data["ast"]["inner"][0]["name"] = "renamed"
    assert set(module.function_definitions(data)) == {"renamed"}


def test_json_boundary_preserves_contract_and_registry_fingerprints():
    from dataclasses import asdict
    from zscope.semantics.contracts import ApiContract, ContractRegistry, digest
    from zscope.semantics.defaults import default_local_pattern_semantics

    registry = default_local_pattern_semantics().contracts
    restored = []
    for contract in registry.contracts:
        encoded = contract.to_dict()
        assert digest(encoded) == digest(asdict(contract))
        decoded = ApiContract.from_row({"contract": encoded})
        assert decoded is not None
        assert decoded.structural() == contract.structural()
        restored.append(decoded)
    assert ContractRegistry(tuple(restored), registry.pairs).version == registry.version


def test_issue_and_final_report_accept_shared_evidence_and_isolate_changes():
    import json
    from zscope.reporting.report import Issue, FinalReport

    payload = {"evidence_pack": {"nested": [{"value": 1}]}}
    issue = Issue.from_dict(view(payload))
    exported = issue.to_dict()
    assert exported["evidence_pack"] == payload["evidence_pack"]
    exported["evidence_pack"]["nested"][0]["value"] = 2
    assert issue.evidence_pack == payload["evidence_pack"]
    final = FinalReport(entry_function="entry", overall_verdict="issues_found", issues=[issue])
    serialized = json.loads(json.dumps(final.to_dict()))
    assert serialized["issues"][0]["evidence_pack"] == payload["evidence_pack"]


def test_issue_plain_dataclass_conversion_remains_equivalent():
    from collections import defaultdict, namedtuple
    from dataclasses import asdict, dataclass
    from zscope.reporting.report import Issue

    @dataclass
    class Span:
        lines: list[int]

    Pair = namedtuple("Pair", "first second")
    evidence = {
        "nested": Span([1, 2]),
        "pair": Pair(Span([3]), 4),
        "tuple": (Span([5]),),
        "set": {6},
        "defaults": defaultdict(list, a=[Span([7])]),
    }
    issue = Issue.from_dict({"evidence_pack": evidence})
    result = issue.to_dict()
    assert result == asdict(issue)
    result["evidence_pack"]["nested"]["lines"].append(8)
    assert issue.evidence_pack["nested"].lines == [1, 2]


def test_contract_imported_from_shared_report_can_be_serialized_and_changed_independently():
    import json
    from zscope.semantics.contracts import ApiContract, ApiPair, CallSemanticMatch, SymbolIdentity
    from zscope.semantics.defaults import default_local_pattern_semantics

    original = next(
        c
        for c in default_local_pattern_semantics().contracts.contracts
        if c.symbol.name == "malloc"
    )
    raw = original.to_dict()
    shared = view(raw)
    restored = ApiContract.from_row({"contract": shared})
    assert restored is not None
    result = restored.to_dict()
    assert json.dumps(result) == json.dumps(raw)
    result["preconditions"]["op"] = "false"
    assert restored.to_dict()["preconditions"] == raw["preconditions"]
    pair = ApiPair(
        SymbolIdentity("malloc"), SymbolIdentity("free"), conditions=shared["preconditions"]
    )
    assert pair.to_dict()["conditions"] == raw["preconditions"]
    match = CallSemanticMatch(
        "allocator",
        "p",
        "unknown",
        original.symbol,
        "version",
        verification=view({"evidence": [{"line": 3}]}),
    )
    match_result = match.to_dict()
    match_result["verification"]["evidence"][0]["line"] = 4
    assert match.verification["evidence"][0]["line"] == 3


def test_real_candidate_fact_slice_and_proof_are_json_boundaries():
    from dataclasses import asdict
    import json
    from zscope.core.candidates.clang_ast_cfg import ClangAstCfgCandidateGenerator
    from zscope.core.candidates.decision_facts import attach_decision_facts
    from zscope.core.validation.proofs import deterministic_decision_proof
    from zscope.reporting.immutable_evidence import ImmutableEvidencePool
    from zscope.semantics.defaults import default_local_pattern_semantics

    source = """void entry(int fd, char *dst, char *src) {
    ssize_t count = recv(fd, src, 256, 0);
    size_t length = (size_t)count;
    memcpy(dst, src, length);
    }"""
    issues = ClangAstCfgCandidateGenerator(default_local_pattern_semantics()).generate_issues(
        "entry", source, "neutral.c"
    )
    issue = next(i for i in issues if i["rule"] == "clang_cfg_negative_length_cast_to_size_t")
    obligation = attach_decision_facts(issue)
    proof = deterministic_decision_proof(issue, outcome="confirm")
    assert proof is not None
    assert obligation.decision_fact_slice is not None
    for value in (obligation, obligation.decision_fact_slice, proof):
        assert json.dumps(value.to_dict()) == json.dumps(asdict(value))
    assert isinstance(proof.fact_ids, tuple)
    assert isinstance(obligation.required_fact_kinds, tuple)
    assert isinstance(obligation.decision_fact_slice.fact_uids, tuple)
    issue["decision_proof"] = proof.to_dict()
    pool = ImmutableEvidencePool()
    clone = pool.clone(issue)
    assert pool.fallback_clones == 0 and pool.shared_clones == 1
    assert clone == issue
    clone["decision_proof"]["fact_ids"].append("local projection edit")
    assert "local projection edit" not in issue["decision_proof"]["fact_ids"]
    assert proof.to_dict() == issue["decision_proof"]
