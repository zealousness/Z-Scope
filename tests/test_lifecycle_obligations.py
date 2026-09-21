import pytest

from test_review_fact_checks import compile_facts
from zscope.retrieval.lifecycle_analysis import LifecycleAnalysis
from zscope.core.validation.review_checks import ReviewClaimChecker
from zscope.semantics.defaults import default_local_pattern_semantics


@pytest.mark.parametrize("flag,expected", [(0, "discharged"), (1, "open")])
def test_known_inapplicable_acquisition_creates_no_ownership(compile_facts, flag, expected):
    from zscope.semantics.contracts import ApiContract

    registry = default_local_pattern_semantics().contracts
    contract = ApiContract.from_row(
        {
            "symbol_name": "select_slot",
            "kind": "allocator",
            "source": "manual",
            "contract": {
                "role": "allocator",
                "carrier": {"kind": "return"},
                "resource_family": "slots",
                "effect_cases": [
                    {
                        "effect": "applies",
                        "when": {
                            "op": "compare",
                            "left": {"kind": "argument", "index": 0},
                            "operator": "==",
                            "right": {"kind": "literal", "value": 1},
                        },
                    }
                ],
            },
        }
    )
    registry.add(contract)
    store, descriptor, path = compile_facts(
        f"void *select_slot(int); void f(void) {{ void *p=select_slot({flag}); }}"
    )
    data = store.load(descriptor["fact_store_id"])
    result = LifecycleAnalysis(
        registry, data, ReviewClaimChecker._functions(data)["f"], path.read_text()
    ).run()
    assert result["obligations"][0]["status"] == expected


def analyze(compile_facts, body, extra=""):
    store, descriptor, path = compile_facts(
        "#include <stdlib.h>\n#include <unistd.h>\n" + extra + "\n" + body
    )
    data = store.load(descriptor["fact_store_id"])
    fn = ReviewClaimChecker._functions(data)["f"]
    return LifecycleAnalysis(
        default_local_pattern_semantics().contracts, data, fn, path.read_text()
    ).run()


@pytest.mark.parametrize(
    "body",
    [
        "void *f(void) { void *p=malloc(8); return p; }",
        "void *f(void) { return malloc(8); }",
        "void f(void **out) { void *p=malloc(8); *out=p; }",
        "void f(void) { void *p=malloc(8); if (!p) return; free(p); }",
        "void f(int x) { void *p=malloc(8); if (x) { free(p); return; } free(p); }",
        "void f(void) { void *p=malloc(8); void *q=p; free(q); }",
    ],
)
def test_all_exits_release_or_transfer_actual_object(compile_facts, body):
    data = analyze(compile_facts, body)
    assert data["obligations"] and all(
        o["status"] == "discharged" for o in data["obligations"]
    ), data


@pytest.mark.parametrize(
    "body",
    [
        "void f(void *q) { void *p=malloc(8); free(q); }",
        "void f(int x) { void *p=malloc(8); if (x) free(p); }",
        "void f(void) { void *p=malloc(8); p=malloc(9); free(p); }",
    ],
)
def test_wrong_object_branch_and_overwrite_do_not_discharge(compile_facts, body):
    data = analyze(compile_facts, body)
    assert any(o["status"] == "open" for o in data["obligations"]), data


@pytest.mark.parametrize(
    "body,extra",
    [
        ("void f(void) { void *p=malloc(8); g=p; }", "void *g;"),
        ("void f(void) { void *p=malloc(8); adopt(p); }", "void adopt(void *);"),
        ("void f(int n) { void *p=malloc(8); while(n--) {} free(p); }", ""),
    ],
)
def test_opaque_or_incomplete_transfer_is_never_proof(compile_facts, body, extra):
    data = analyze(compile_facts, body, extra)
    assert all(o["status"] == "unresolved" for o in data["obligations"]), data


def test_null_check_covers_actual_dereference(compile_facts):
    good = analyze(
        compile_facts, "void f(void) { char *p=malloc(8); if (p==NULL) return; *p=1; free(p); }"
    )
    bad = analyze(compile_facts, "void f(void) { char *p=malloc(8); *p=1; free(p); }")
    assert good["uses"] and all(u["non_null"] for u in good["uses"]), good
    assert any(not u["non_null"] for u in bad["uses"]), bad


@pytest.mark.parametrize(
    "body,extra",
    [
        ("void f(void **out) { *out=malloc(8); *out=0; }", ""),
        ("void f(void) { void *p=malloc(8); change(&p); free(p); }", "void change(void **);"),
        ("void f(void) { void *p=malloc(8); free(p); }", "void free(void *p) {}"),
    ],
)
def test_output_overwrite_escaped_address_and_project_homonym_cannot_prove_cleanup(
    compile_facts, body, extra
):
    result = analyze(compile_facts, body, extra)
    assert result["obligations"] and any(
        o["status"] != "discharged" for o in result["obligations"]
    ), result


@pytest.mark.parametrize(
    "body",
    [
        "void f(void) { void *p=malloc(8); free(&p); }",
        "void f(void) { char *p=malloc(8); p+=1; free(p); }",
        "void f(void **out) { void *local; out=&local; *out=malloc(8); }",
        'void f(void) { void *p=malloc(8); __asm__ volatile("" : "+r"(p)); free(p); }',
    ],
)
def test_invalid_pointer_and_output_mappings_stay_unknown(compile_facts, body):
    result = analyze(compile_facts, body)
    assert result["obligations"] and any(
        o["status"] != "discharged" for o in result["obligations"]
    ), result


def test_address_of_pointer_guard_does_not_prove_pointer_nonnull(compile_facts):
    data = analyze(compile_facts, "void f(void) { char *p=malloc(8); if (&p) *p=1; free(p); }")
    assert data["uses"] and any(not u["non_null"] for u in data["uses"])


def test_macro_constant_false_backedge_is_explicitly_accounted_for(compile_facts):
    store, desc, path = compile_facts(
        "#include <stdlib.h>\n#define DROP(p) do { if (p) free(p); } while (0)\nvoid f(void) { void *p=malloc(8); DROP(p); }\n"
    )
    data = store.load(desc["fact_store_id"])
    cfg = next(g for g in data["cfg"] if "f(" in g["signature"])
    assert cfg["complete"] and any(b.get("pruned_successors") for b in cfg["blocks"])
    result = LifecycleAnalysis(
        default_local_pattern_semantics().contracts,
        data,
        ReviewClaimChecker._functions(data)["f"],
        path.read_text(),
    ).run()
    assert result["obligations"][0]["status"] == "discharged"


@pytest.mark.parametrize(
    "body,expected",
    [
        ("if (x) { pthread_mutex_lock(&m); return 1; }\nreturn 0;", "supported"),
        (
            "while(x) { if(x==1) { pthread_mutex_lock(&m); return 1; } x--; }\nreturn 0;",
            "supported",
        ),
        ("if (x) { pthread_mutex_lock(&m); }\nreturn 0;", "unknown"),
        ("while(x) { pthread_mutex_lock(&m); break; }\nreturn 0;", "unknown"),
    ],
)
def test_claim_specific_lock_path_does_not_mix_exits(compile_facts, body, expected):
    from test_review_fact_checks import issue, checked

    store, _, path = compile_facts(
        "extern int pthread_mutex_lock(int*);\nint m;\nint f(int x) { " + body + "\n}\n"
    )
    candidate = issue(
        path,
        rule_id="clang_cfg_return_with_lock_held",
        category="missing_unlock",
        source="lock at line 3",
        line=4,
        location=f"{path}:4",
    )
    assert checked(store, candidate)["status"] == expected


@pytest.mark.parametrize(
    "length,expected", [("n", "supported"), ("n+1", "unknown"), ("n++", "unknown")]
)
def test_copy_claim_checks_actual_capacity_and_versions(compile_facts, length, expected):
    from test_review_fact_checks import issue, checked

    store, _, path = compile_facts(
        "#include <stdlib.h>\n#include <string.h>\nvoid f(size_t n, const char *s) { char *p=malloc(n);\nmemcpy(p,s,"
        + length
        + "); free(p); }\n"
    )
    candidate = issue(
        path,
        rule_id="clang_cfg_narrowed_allocation_original_length_copy",
        category="heap_overflow",
        line=4,
        location=f"{path}:4",
    )
    assert checked(store, candidate)["status"] == expected


def test_later_loop_iteration_cannot_reuse_old_allocation_extent(compile_facts):
    from test_review_fact_checks import issue, checked
    store, _, path = compile_facts("#include <stdlib.h>\n#include <string.h>\nvoid f(size_t n, const char *s) { char *p=malloc(n);\nwhile(n<100) { memcpy(p,s,n);\nn++; } free(p); }\n")
    candidate = issue(path, rule_id="clang_cfg_narrowed_allocation_original_length_copy", category="heap_overflow", line=4, location=f"{path}:4")
    assert checked(store, candidate)["status"] == "unknown"


@pytest.mark.parametrize("bound,expected", [("n", "supported"), ("n+1", "unknown")])
@pytest.mark.parametrize("index_type", ["unsigned", "uint32_t"])
def test_dynamic_calloc_loop_capacity(compile_facts, bound, expected, index_type):
    from test_review_fact_checks import issue, checked

    store, _, path = compile_facts(
        "#include <stdlib.h>\n#include <stdint.h>\nvoid f("
        + index_type
        + " n) { int *p=calloc(n,sizeof(int)); if(!p)return;\nfor("
        + index_type
        + " i=0;i<"
        + bound
        + ";i++) {\np[i]=1;\n}\nfree(p); p=0; }\n"
    )
    candidate = issue(
        path,
        rule_id="clang_cfg_unbounded_count_indexes_fixed_array",
        category="bounds",
        line=5,
        location=f"{path}:5",
        rule_revision=7,
    )
    assert checked(store, candidate)["status"] == expected


@pytest.mark.parametrize(
    "exit_code,expected",
    [
        ("if(fd<0) { return -1; }", "supported"),
        ("return fd;", "supported"),
        ("if(fd>=0) { return -1; }", "unknown"),
        ("if(fd==0) { return -1; }", "unknown"),
    ],
)
def test_descriptor_zero_failure_and_return_transfer(compile_facts, exit_code, expected):
    from test_review_fact_checks import issue, checked

    store, _, path = compile_facts(
        '#include <fcntl.h>\nint f(void) { int fd=open("x",O_RDONLY);\n'
        + exit_code
        + "\nreturn 0; }\n"
    )
    candidate = issue(
        path,
        rule_id="clang_cfg_fd_open_return_without_close",
        category="fd_leak",
        source='int fd=open("x",O_RDONLY);',
        line=3,
    )
    assert checked(store, candidate)["status"] == expected


@pytest.mark.parametrize(
    "operation,expected",
    [
        ("Pool *alias=a; omega(p,alias);", "discharged"),
        ("a=b; omega(p,a);", "open"),
        ("omega(p,b);", "open"),
    ],
)
def test_verified_pool_protocol_through_workbook_preserves_assignment_version(
    compile_facts, tmp_path, operation, expected
):
    from test_pool_protocol_modeling import pool_snapshots
    from test_wrapper_contract_compiler import publish

    _, semantics, _ = publish(tmp_path, pool_snapshots())
    store, desc, path = compile_facts(
        "typedef struct Pool Pool; typedef struct Node Node;\nNode *alpha(Pool*); void omega(Node*,Pool*);\nvoid f(Pool*a, Pool*b) { Node *p=alpha(a); if(!p)return; "
        + operation
        + " }\n"
    )
    data = store.load(desc["fact_store_id"])
    analysis = LifecycleAnalysis(
        semantics.contracts, data, ReviewClaimChecker._functions(data)["f"], path.read_text()
    ).run()
    assert analysis["obligations"][0]["status"] == expected, analysis
