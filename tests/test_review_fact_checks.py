import json
import shutil
from copy import deepcopy

import pytest

from zscope.retrieval.validation_facts import CompleteFactStore, split_cfg, macro_branches
from zscope.core.validation.review_checks import (
    ReviewClaimChecker,
    checked_receipt,
    guard_coverage,
    check_guard_call_sites,
)
from zscope.core.validation.proofs import deterministic_decision_proof


@pytest.fixture
def compile_facts(tmp_path):
    clang = shutil.which("clang")
    if not clang:
        pytest.skip("compiler integration requires clang")

    def compile_source(code, defines=()):
        path = tmp_path / "subject.c"
        path.write_text(code, encoding="utf-8")
        commands = tmp_path / "compile_commands.json"
        commands.write_text(
            json.dumps(
                [
                    {
                        "directory": str(tmp_path),
                        "file": str(path),
                        "arguments": [clang, "-std=c11", *defines, "-c", path.as_posix()],
                    }
                ]
            ),
            encoding="utf-8",
        )
        store = CompleteFactStore(tmp_path, commands, tmp_path / "facts", clang=clang)
        descriptor = store.collect(str(path))
        assert descriptor.get("complete"), descriptor
        return store, descriptor, path

    return compile_source


def issue(path, function="f", **kwargs):
    return {
        "id": "candidate",
        "candidate_uid": "C_test",
        "validation_cluster_uid": "V_test",
        "function": function,
        "file": str(path),
        "location": f"{path}:3",
        "line": 3,
        "category": "memory_leak",
        "source": "node allocated here",
        "rule_id": "clang_cfg_acquire_without_release_on_exit",
        "rule_revision": 1,
        "review_checked_proofs_enabled": True,
        **kwargs,
    }


def checked(store, candidate):
    checker = ReviewClaimChecker(store)
    checker.prepare(candidate)
    return checker.check(candidate)


def test_pages_preserve_complete_underlying_ast_and_cfg_function_identity(compile_facts):
    store, desc, _ = compile_facts(
        "int f(int x) { if (x) return 1; return 0; }\nint g(void) { return 2; }\n"
    )
    uid = desc["fact_store_id"]
    first = store.query(uid, "ast_nodes", symbol="f", limit=2)
    assert first["complete"] and first["display_truncated"]
    records = first["items"]
    while first["next_offset"] is not None:
        first = store.query(uid, "ast_nodes", symbol="f", offset=first["next_offset"], limit=2)
        records += first["items"]
    assert len(records) == first["total"] and not first["display_truncated"]
    functions = store.load(uid)["cfg"]
    assert len(functions) == 2 and all(f["complete"] for f in functions)
    assert functions[0]["signature"] != functions[1]["signature"]
    assert not first["project_call_graph_complete"]


def test_type_identity_proof_and_stale_or_forged_receipt_rejected(compile_facts):
    store, _, path = compile_facts(
        "typedef struct N { int name; void *payload; } N;\nvoid f(N *node) { (void)node; }\n"
    )
    candidate = issue(
        path,
        rule_id="clang_cfg_parent_release_without_owned_member_cleanup",
        description="release without common owned member node->tag cleanup",
    )
    result = checked(store, candidate)
    assert result["status"] == "supported", result
    assert not candidate.get("review_related_proposals")
    assert deterministic_decision_proof(candidate, outcome="reject")
    tampered = deepcopy(candidate)
    tampered["source"] = "other object"
    assert checked_receipt(tampered) is None
    forged = deepcopy(candidate)
    forged["review_checked_proof"]["signature"] = "model_complete"
    assert deterministic_decision_proof(forged, outcome="reject") is None
    path.write_text(path.read_text() + "\n// revision changed\n", encoding="utf-8")
    assert not store.load(result["build_identity"])["complete"]
    assert checked_receipt(candidate) is None


@pytest.mark.parametrize(
    "body,expected",
    [
        ("void *node = malloc(8); if (!node) return; free(node);", "supported"),
        ("void *node = malloc(8); if (fail) return; free(node);", "unknown"),
        ("void *node = malloc(8); if (!node) return; retain(node);", "supported"),
        ("void *node = malloc(8); if (!node) return; maybe_retain(node, fail);", "unknown"),
        ("void *node = malloc(8); owner = node; owner = 0;", "unknown"),
    ],
)
def test_ownership_all_success_failure_exits(compile_facts, body, expected):
    source = (
        "extern void *malloc(unsigned long long); extern void free(void *);\nstatic void *owner;\nvoid retain(void *p) { owner = p; }\nvoid maybe_retain(void *p, int fail) { if (fail) return; owner = p; }\nvoid f(int fail) { "
        + body
        + " }\n"
    )
    store, _, path = compile_facts(source)
    result = checked(store, issue(path))
    assert result["status"] == expected, result


def test_parent_release_does_not_prove_owned_member_cleanup(compile_facts):
    store, _, path = compile_facts(
        "extern void free(void *);\ntypedef struct N { void *payload; } N;\nvoid f(N *node) { free(node); }\n"
    )
    result = checked(
        store,
        issue(
            path,
            rule_id="clang_cfg_parent_release_without_owned_member_cleanup",
            description="release without common owned member node->payload cleanup",
        ),
    )
    assert result["status"] == "unknown"


def test_related_ownership_requires_actual_factory_assignment_and_groups_parent(compile_facts):
    code = "extern void *malloc(unsigned long); extern void free(void *);\ntypedef struct N { void *payload; struct N *next; } N;\nN *make(void) { N *p = malloc(sizeof(N)); p->payload = malloc(8); p->next = 0; return p; }\nvoid f(void) { N *node = make(); free(node); }\n"
    store, _, path = compile_facts(code)
    candidate = issue(
        path,
        rule_id="clang_cfg_parent_release_without_owned_member_cleanup",
        description="common owned member node->tag not cleaned up",
        line=4,
    )
    assert checked(store, candidate)["status"] == "supported"
    assert len(candidate["review_related_proposals"]) == 1
    proposal = candidate["review_related_proposals"][0]
    assert (
        "node->payload" in proposal["description"] and "node->next" not in proposal["description"]
    )


def test_model_complete_cannot_replace_compiler_origin_and_inline_bytes_are_not_heap(compile_facts):
    store, desc, path = compile_facts(
        "typedef struct N { char name[32]; } N;\nvoid f(N *node) { (void)node; }\n"
    )
    candidate = issue(
        path,
        rule_id="clang_cfg_parent_release_without_owned_member_cleanup",
        description="common owned member node->name not freed",
    )
    assert checked(store, candidate)["reason"] == "reported_owned_member_is_inline_byte_storage"
    other_store = CompleteFactStore(
        store.project_root, store.compile_commands, store.directory, clang=store.clang
    )
    # The same bytes and a complete descriptor still lack compiler provenance
    # in a fresh process/store until collection is rerun.
    candidate["review_fact_store"] = desc
    assert ReviewClaimChecker(other_store).check(candidate)["status"] == "unknown"


def test_user_defined_free_and_per_invocation_mutex_cannot_supply_proof(compile_facts):
    store, _, path = compile_facts(
        "extern void *malloc(unsigned long long);\nvoid free(void *p) {}\nvoid f(void) { void *node = malloc(8); free(node); }\n"
    )
    assert checked(store, issue(path))["status"] == "unknown"
    store, _, path = compile_facts(
        "extern int pthread_mutex_lock(int *);\nstatic int shared;\nvoid f(void) { int local; if (pthread_mutex_lock(&local)==0) shared++; }\n"
    )
    assert checked(store, issue(path, category="race", source="shared"))["status"] == "unknown"


@pytest.mark.parametrize(
    "condition,expected", [("i<8", "supported"), ("i<n+1", "unknown"), ("i<=8", "unknown")]
)
def test_canonical_loop_induction_is_bound_to_capacity_and_integer_semantics(
    compile_facts, condition, expected
):
    store, _, path = compile_facts(
        "void f(unsigned n) {\n int a[8];\n for (unsigned i=0; " + condition + "; i++) a[i]=0;\n}\n"
    )
    result = checked(
        store,
        issue(
            path,
            category="bounds",
            source="a",
            rule_id="clang_cfg_unbounded_count_indexes_fixed_array",
        ),
    )
    assert result["status"] == expected, result


@pytest.mark.parametrize(
    "index,expected",
    [
        ("2", "supported"),
        ("8", "contradicted"),
        ("n+1", "unknown"),
        ("(unsigned char)300", "unknown"),
    ],
)
def test_numeric_overflow_and_conversions_never_assumed_safe(compile_facts, index, expected):
    store, _, path = compile_facts("void f(unsigned n) {\n int a[8];\n a[" + index + "] = 0;\n}\n")
    result = checked(
        store,
        issue(
            path,
            category="bounds",
            source="a",
            rule_id="clang_cfg_unbounded_count_indexes_fixed_array",
        ),
    )
    assert result["status"] == expected, result


@pytest.mark.parametrize(
    "body,expected",
    [
        (
            "if (pthread_mutex_lock(&m) != 0) return; shared++; pthread_mutex_unlock(&m);",
            "supported",
        ),
        (
            "if (pthread_mutex_trylock(&m) == 0) { shared++; pthread_mutex_unlock(&m); }",
            "supported",
        ),
        ("pthread_mutex_trylock(&m); shared++;", "unknown"),
        (
            "if (pthread_mutex_lock(&m) != 0) return; shared++; pthread_mutex_unlock(&m); shared++;",
            "unknown",
        ),
        ("shared++;", "unknown"),
        (
            "if (pthread_mutex_lock(&m) != 0) return; (pthread_mutex_unlock(&m), shared++);",
            "unknown",
        ),
    ],
)
def test_lock_success_macro_expansion_and_neighbor_access(compile_facts, body, expected):
    store, _, path = compile_facts(
        "extern int pthread_mutex_lock(int *); extern int pthread_mutex_trylock(int *); extern int pthread_mutex_unlock(int *);\nstatic int m, shared;\nvoid f(void) { "
        + body
        + " }\n"
    )
    result = checked(store, issue(path, category="race", source="shared", rule_id="race"))
    assert result["status"] == expected, result


@pytest.mark.parametrize("escape", ["void reset(void) { m = 0; }", "static int *escaped = &m;"])
def test_mutex_reset_or_escape_outside_access_function_prevents_proof(compile_facts, escape):
    store, _, path = compile_facts(
        "extern int pthread_mutex_lock(int *); extern int pthread_mutex_unlock(int *);\nstatic int m, shared;\n"
        + escape
        + "\nvoid f(void) { if (pthread_mutex_lock(&m) != 0) return; shared++; pthread_mutex_unlock(&m); }\n"
    )
    result = checked(store, issue(path, category="race", source="shared", rule_id="race"))
    assert result["status"] == "unknown", result


def test_macro_branches_current_target_redefinitions_aliases(compile_facts):
    code = "#if defined(ENABLE)\n#define GUARD() do { value++; } while (0)\n#else\n#define GUARD() do {} while (0)\n#endif\n#define ALIAS GUARD\nstatic int value;\nvoid f(void) { GUARD(); }\n#undef GUARD\n#define GUARD() do {} while (0)\n"
    store, desc, _ = compile_facts(code, ["-DENABLE=1"])
    macros = store.query(desc["fact_store_id"], "macros")["items"]
    guards = [m for m in macros if m["name"] == "GUARD" and m["directive"] == "define"]
    assert [g["active"] for g in guards] == [True, False, True]
    assert guards[0]["final_definition"] is False
    assert any(m["alias"] == "GUARD" for m in macros)
    store2, desc2, _ = compile_facts(code)
    assert desc["fact_store_id"] != desc2["fact_store_id"]
    assert not store.load(desc["fact_store_id"])["complete"]
    assert store2.query(desc2["fact_store_id"], "macros")["complete"]


def test_known_guarded_callers_never_close_unknown_indirect_or_public_api(compile_facts):
    store, desc, _ = compile_facts(
        "void sink(int x) {}\nvoid f(void (*p)(int)) { sink(2); p(2); }\n"
    )
    coverage = check_guard_call_sites(store, desc["fact_store_id"], "sink", 0, 0, 8)
    assert coverage["rows"][0]["status"] == "guarded"
    assert coverage["unresolved_indirect_calls"]
    assert not coverage["all_paths_guarded"]
    empty = check_guard_call_sites(store, desc["fact_store_id"], "f", 0, 0, 8)
    assert empty["known_call_site_count"] == 0 and not empty["complete"]


def test_model_supplied_complete_guard_matrix_is_not_authority():
    coverage = guard_coverage(
        [
            {
                "checked_path": {
                    "compiler_checked": True,
                    "complete": True,
                    "guard_dominates_sink": True,
                    "parameter_mapping_complete": True,
                }
            }
        ],
        inventory_complete=True,
        unresolved_indirect_calls=False,
        external_entry_contract_complete=True,
    )
    assert coverage["rows"][0]["status"] == "unknown" and not coverage["all_paths_guarded"]


def test_truncated_cfg_and_nested_macro_conditions():
    assert not split_cfg("void f()\n [B1 (ENTRY)]\n   Succs (1): B0\n")[0]["complete"]
    macros = macro_branches(
        "#if A\n#if B\n#define X 1\n#elif C\n#define X 2\n#else\n#define X\n#endif\n#endif\n", "a.h"
    )
    assert len(macros) == 3 and "A" in macros[-1]["condition"] and "C" in macros[-1]["condition"]
    assert macros[-1]["empty_operation"]
    raw = "void f()\n [B1 (ENTRY)]\n   Succs (1): B0\n [B0 (EXIT)]\n   Preds (1): B1\n"
    assert (
        split_cfg(raw, identity="one")[0]["function_local_id"]
        != split_cfg(raw, identity="two")[0]["function_local_id"]
    )


def test_substituted_build_compiler_cannot_certify_current_configuration(compile_facts):
    store, _, path = compile_facts("void f(void) {}\n")
    commands = json.loads(store.compile_commands.read_text())
    commands[0]["arguments"][0] = "unbound-compiler-wrapper"
    store.compile_commands.write_text(json.dumps(commands))
    result = store.collect(str(path))
    assert (
        not result["complete"] and result["reason"] == "compile_driver_not_bound_to_fact_compiler"
    )


def test_target_architecture_selects_actual_macro_branch(compile_facts):
    code = "#if __SIZEOF_POINTER__ == 8\n#define GUARD() value++\n#else\n#define GUARD()\n#endif\nstatic int value;\nvoid f(void) { GUARD(); }\n"
    store64, desc64, _ = compile_facts(code, ["-m64"])
    assert [
        m["active"]
        for m in store64.query(desc64["fact_store_id"], "macros", symbol="GUARD")["items"]
    ] == [True, False]
    store32, desc32, _ = compile_facts(code, ["-m32"])
    assert [
        m["active"]
        for m in store32.query(desc32["fact_store_id"], "macros", symbol="GUARD")["items"]
    ] == [False, True]
    assert desc64["fact_store_id"] != desc32["fact_store_id"]


def test_implicit_cpp_cleanup_paths_remain_unknown(compile_facts):
    code = "extern void *malloc(unsigned long); extern void free(void *);\nstruct Guard { ~Guard() noexcept(false); };\nvoid f(void) { void *node = malloc(8); { Guard g; } free(node); }\n"
    store, _, path = compile_facts(code, ["-x", "c++", "-std=c++17"])
    assert checked(store, issue(path))["status"] == "unknown"
