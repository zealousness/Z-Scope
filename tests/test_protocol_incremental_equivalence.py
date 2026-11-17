"""Current compiler lookups and full/incremental review projections agree."""

from copy import deepcopy
import json

from test_review_fact_checks import compile_facts, issue
from test_validation_pipeline import FakeUserConfig
from zscope.core.validation.pipeline import ValidationPipeline
from zscope.core.validation.review_checks import ReviewClaimChecker, checked_receipt
from zscope.retrieval.validation_facts import CompleteFactStore

OPTIONAL = """
#include <stdlib.h>
#if __has_include("policy.h")
#define CLEANUP(p) ((void)0)
#else
#define CLEANUP(p) free(p)
#endif
void f(void) { void *node=malloc(8); CLEANUP(node); }
"""


def evaluate(store, path):
    candidate = issue(path)
    checker = ReviewClaimChecker(store)
    checker.prepare(candidate)
    result = checker.check(candidate)
    analysis = candidate.get("lifecycle_analysis", {})
    pipeline = ValidationPipeline(FakeUserConfig(), enable_deterministic_proof_routing=True)
    outcome = pipeline.apply_deterministic_prevalidation(candidate, {"final_score": 0.5})
    if outcome is None:
        outcome = pipeline.apply_unvalidated(candidate, {"final_score": 0.5})
    return candidate, {
        "candidate": (candidate["function"], candidate["category"], candidate["source"]),
        "decision": (
            "rejected"
            if candidate["candidate_disposition"] == "rejected_with_proof"
            else candidate["candidate_disposition"]
        ),
        "report_bucket": outcome.report_bucket,
        "status": result["status"],
        "gaps": analysis.get("gaps"),
        "obligations": [(o["object"], o["status"]) for o in analysis.get("obligations", [])],
        "coverage": {
            k: result["coverage"].get(k)
            for k in ("complete", "scope", "project_call_graph_complete")
        },
    }


def test_new_optional_header_reopens_old_negative_claim(compile_facts, tmp_path):
    store, descriptor, path = compile_facts(OPTIONAL)
    candidate, before = evaluate(store, path)
    assert before["decision"] == "rejected"
    (tmp_path / "policy.h").write_text("/* existence changes cleanup */\n")
    assert not checked_receipt(candidate)
    assert not store.load(descriptor["fact_store_id"])["complete"]
    _, after = evaluate(store, path)
    assert after["decision"] == "needs_review"


def test_header_change_between_collection_and_prepare_stays_unresolved(
    compile_facts, tmp_path, monkeypatch
):
    store, _, path = compile_facts(OPTIONAL)
    collect = store.collect

    def changed(*args, **kwargs):
        descriptor = collect(*args, **kwargs)
        (tmp_path / "policy.h").write_text("/* changed after collection */")
        return descriptor

    monkeypatch.setattr(store, "collect", changed)
    candidate = issue(path)
    checker = ReviewClaimChecker(store)
    descriptor = checker.prepare(candidate)
    assert not descriptor["complete"]
    assert descriptor["reason"] == "stale_compiler_lookup_dependencies"
    assert checker.check(candidate)["status"] == "unknown"
    assert not checked_receipt(candidate)


def test_full_and_incremental_match_add_delete_and_unrelated_changes(
    compile_facts, tmp_path, monkeypatch
):
    store, _, path = compile_facts(OPTIONAL)
    calls = []
    original = store._run

    def record(args, cwd):
        calls.append(args)
        return original(args, cwd)

    monkeypatch.setattr(store, "_run", record)
    previous = None
    for action in ("initial", "unrelated", "add", "delete"):
        if action == "unrelated":
            (tmp_path / "unrelated.txt").write_text("irrelevant")
        if action == "add":
            (tmp_path / "policy.h").write_text("/* exists */")
        if action == "delete":
            (tmp_path / "policy.h").unlink()
        calls.clear()
        _, incremental = evaluate(store, path)
        if action in {"initial", "unrelated"}:
            assert not any("-ast-dump=json" in a or "--analyze" in a for a in calls)
        cold = CompleteFactStore(
            tmp_path, store.compile_commands, tmp_path / ("cold-" + action), clang=store.clang
        )
        _, full = evaluate(cold, path)
        assert incremental == full
        if action == "unrelated":
            assert incremental == previous
        assert incremental["decision"] == ("needs_review" if action == "add" else "rejected")
        previous = deepcopy(incremental)


def test_root_contract_changes_revoke_live_receipt_and_recompute(compile_facts):
    store, _, path = compile_facts(
        "#include <stdlib.h>\nvoid f(void) {void *node=malloc(8); free(node);}"
    )
    checker = ReviewClaimChecker(store)
    candidate = issue(path)
    assert checker.check(candidate)["status"] == "supported"
    assert checked_receipt(candidate)
    assert not checked_receipt(json.loads(json.dumps(candidate)))
    checker.registry.shadowed_symbols.add("free")
    assert not checked_receipt(candidate)
    assert checker.check(candidate)["status"] == "unknown"


def test_new_accessor_revokes_local_lock_coverage(compile_facts):
    code = """
typedef int pthread_mutex_t;
int pthread_mutex_lock(pthread_mutex_t*); int pthread_mutex_unlock(pthread_mutex_t*);
static pthread_mutex_t gate; static int shared;
void f(void) { if(pthread_mutex_lock(&gate)==0) {shared++; pthread_mutex_unlock(&gate);} }
"""
    store, _, path = compile_facts(code)
    candidate = issue(
        path,
        category="race",
        source="shared",
        rule_id="clang_cfg_unsynchronized_shared_flag_or_counter",
        rule_revision=9,
    )
    checker = ReviewClaimChecker(store)
    assert checker.check(candidate)["status"] == "supported"
    path.write_text(code + "void new_accessor(void) {shared++;}\n")
    assert not checked_receipt(candidate)
    checker.prepare(candidate)
    assert checker.check(candidate)["status"] == "unknown"
    path.write_text(code)
    checker.prepare(candidate)
    assert checker.check(candidate)["status"] == "supported"


def test_new_higher_priority_include_cannot_reuse_old_depfile(compile_facts, tmp_path):
    fallback = tmp_path / "fallback"
    fallback.mkdir()
    (fallback / "cleanup.h").write_text("#define CLEANUP(p) free(p)\n")
    store, descriptor, path = compile_facts(
        '#include <stdlib.h>\n#include "cleanup.h"\nvoid f(void) {void *node=malloc(8); CLEANUP(node);}',
        ["-I", str(fallback)],
    )
    candidate, before = evaluate(store, path)
    assert before["decision"] == "rejected"
    (tmp_path / "cleanup.h").write_text("#define CLEANUP(p) ((void)0)\n")
    assert not checked_receipt(candidate)
    assert not store.load(descriptor["fact_store_id"])["complete"]
    assert evaluate(store, path)[1]["decision"] == "needs_review"


def test_hot_reuses_ast_cfg_with_measured_preprocessing(
    compile_facts, tmp_path, monkeypatch, record_property
):
    import time
    from zscope.retrieval import validation_facts

    store, _, path = compile_facts(OPTIONAL)
    calls = []
    run = validation_facts.subprocess.run

    def observed(command, *args, **kwargs):
        calls.append(list(command))
        return run(command, *args, **kwargs)

    monkeypatch.setattr(validation_facts.subprocess, "run", observed)
    start = time.monotonic()
    _, hot = evaluate(store, path)
    record_property("hot_seconds", time.monotonic() - start)
    record_property("hot_preprocessor_processes", sum("-E" in c for c in calls))
    assert any("-E" in c for c in calls)
    assert not any("--analyze" in c or "-ast-dump=json" in c for c in calls)
    record_property("hot_ast_cfg_processes", 0)
    calls.clear()
    cold = CompleteFactStore(
        tmp_path, store.compile_commands, tmp_path / "independent", clang=store.clang
    )
    start = time.monotonic()
    _, full = evaluate(cold, path)
    record_property("full_seconds", time.monotonic() - start)
    record_property("full_preprocessor_processes", sum("-E" in c for c in calls))
    record_property(
        "full_ast_cfg_processes", sum("--analyze" in c or "-ast-dump=json" in c for c in calls)
    )
    assert any("--analyze" in c for c in calls) and any("-ast-dump=json" in c for c in calls)
    assert hot == full


def test_contract_edit_during_replay_cannot_sign_old_effects(compile_facts, monkeypatch):
    from zscope.retrieval.lifecycle_analysis import LifecycleAnalysis

    store, _, path = compile_facts(
        "#include <stdlib.h>\nvoid f(void) {void *node=malloc(8); free(node);}"
    )
    checker = ReviewClaimChecker(store)
    original = LifecycleAnalysis.run

    def changed(analysis):
        result = original(analysis)
        checker.registry.shadowed_symbols.add("free")
        return result

    monkeypatch.setattr(LifecycleAnalysis, "run", changed)
    candidate = issue(path)
    result = checker.check(candidate)
    assert result["status"] == "unknown" and result["reason"] == "contracts_changed_during_review"
    assert not checked_receipt(candidate)


def test_restored_fact_payload_never_executes_a_persisted_probe(compile_facts, monkeypatch):
    from zscope.retrieval import validation_facts

    store, descriptor, _ = compile_facts(OPTIONAL)
    restored = CompleteFactStore(
        store.project_root, store.compile_commands, store.directory, clang=store.clang
    )

    def forbidden(*a, **k):
        raise AssertionError("uncollected disk evidence must not execute")

    monkeypatch.setattr(validation_facts.subprocess, "run", forbidden)
    result = restored.load(descriptor["fact_store_id"])
    assert not result["complete"]
    assert result["reason"] == "compiler_lookup_requires_current_collection"
