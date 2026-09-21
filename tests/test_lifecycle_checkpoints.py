"""Real compiler lifecycle facts must survive answer-free checkpoints."""

from copy import deepcopy

import pytest

from test_review_fact_checks import compile_facts, issue
from zscope.core.validation.review_checkpoint import ReviewCheckpointStore, assert_answer_free
from zscope.core.validation.review_checks import ReviewClaimChecker
from zscope.reporting.evidence_objects import EvidenceObjectStore
from zscope.retrieval.analysis_facts import scan_fact_cache
from zscope.retrieval.lifecycle_analysis import lifecycle_facts
from zscope.semantics.defaults import default_local_pattern_semantics


@pytest.mark.parametrize("cleanup,status", [("free(p);", "discharged"), ("", "open")])
def test_compiled_lifecycle_candidate_roundtrips_checkpoint(
    compile_facts, tmp_path, cleanup, status
):
    store, descriptor, path = compile_facts(
        "#include <stdlib.h>\nvoid f(int flag) {\n"
        "void *p=malloc(8);\nif (!p) return;\n"
        "if (flag) { free(p); return; }\n" + cleanup + "\n}\n"
    )
    candidate = issue(path)
    checker = ReviewClaimChecker(store)
    checker.prepare(candidate)
    checker.check(candidate)
    analysis = candidate["lifecycle_analysis"]
    obligation = analysis["obligations"][0]
    assert obligation["status"] == status
    # KnowledgeDB also carries the per-acquisition object on the candidate.
    candidate["lifecycle_obligation"] = deepcopy(obligation)
    original = deepcopy(candidate)
    facts = store.load(descriptor["fact_store_id"])
    checkpoints = ReviewCheckpointStore(tmp_path / "checkpoints")
    uid = checkpoints.save(candidate, stage="prepared", facts=facts, runtime={})
    loaded = checkpoints.load(uid)
    original.pop("review_checked_proof", None)
    assert loaded["candidate"] == original
    assert loaded["facts"] == facts
    constraints = [c for e in obligation["exits"] for c in e["constraints"]]
    assert {c["branch_taken"] for c in constraints} == {True, False}
    assert all("truth" not in c and c["expression"] and c["line"] > 0 for c in constraints)
    # Reuse the shared decoded evidence through another write/read cycle.
    uid2 = checkpoints.save(loaded["candidate"], stage="final", facts=loaded["facts"], runtime={})
    assert checkpoints.load(uid2)["candidate"] == original


@pytest.mark.parametrize("shared", [False, True])
@pytest.mark.parametrize("key", ["truth", "ground_truth", "matched_truth_id", "is_tp", "scoring"])
def test_nested_offline_answers_still_rejected(tmp_path, shared, key):
    payload = {"candidate": {"lifecycle_analysis": {"constraints": [{key: True}]}}}
    if shared:
        objects = EvidenceObjectStore(tmp_path / "objects")
        payload = objects.get(objects.put(payload))
    with pytest.raises(ValueError, match="offline evaluation field in checkpoint"):
        assert_answer_free(payload)


def test_old_lifecycle_cache_is_not_reused(compile_facts):
    store, descriptor, path = compile_facts(
        "#include <stdlib.h>\nvoid f(void) { void *p=malloc(8); if (p) free(p); }\n"
    )
    data = store.load(descriptor["fact_store_id"])
    function = ReviewClaimChecker._functions(data)["f"]
    registry = default_local_pattern_semantics().contracts
    cache = scan_fact_cache(store)
    old_key = (
        "zscope.lifecycle-obligations.v1",
        data["fact_store_id"],
        str(function["id"]),
        registry.version,
    )
    cache.compute(old_key, lambda: {"schema_version": old_key[0], "constraints": [{"truth": True}]})
    current = lifecycle_facts(store, registry, data, function, path.read_text())
    assert current["schema_version"] == "zscope.lifecycle-obligations.v2"
    assert_answer_free(current)
    assert lifecycle_facts(store, registry, data, function, path.read_text()) == current
    assert cache.computations == 2
