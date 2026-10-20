import pytest

from test_review_fact_checks import compile_facts, issue, checked
from zscope.core.validation.proofs import deterministic_decision_proof
from zscope.core.validation.review_checks import checked_receipt

DECLS = """
#define EOWNERDEAD 130
extern int pthread_mutex_lock(int *);
extern int pthread_mutex_trylock(int *);
extern int pthread_mutex_unlock(int *);
extern int pthread_rwlock_rdlock(int *);
extern int pthread_rwlock_wrlock(int *);
extern int pthread_rwlock_tryrdlock(int *);
extern int pthread_rwlock_trywrlock(int *);
extern int pthread_rwlock_unlock(int *);
extern int pthread_cond_wait(int *, int *);
static int m, other, cv, shared;
"""


@pytest.mark.parametrize(
    "body,expected",
    [
        ("if(pthread_rwlock_wrlock(&m)==0) { shared++; pthread_rwlock_unlock(&m); }", "supported"),
        ("if(pthread_rwlock_rdlock(&m)==0) { shared++; pthread_rwlock_unlock(&m); }", "unknown"),
        ("if(pthread_rwlock_tryrdlock(&m)==0) { shared=1; pthread_rwlock_unlock(&m); }", "unknown"),
        (
            "if(pthread_rwlock_rdlock(&m)==0) { int x=shared; pthread_rwlock_unlock(&m); }",
            "supported",
        ),
        (
            "if(pthread_rwlock_trywrlock(&m)==0) { shared++; pthread_rwlock_unlock(&m); }",
            "supported",
        ),
        ("if(pthread_rwlock_trywrlock(&m)!=0) { shared++; }", "unknown"),
        ("pthread_rwlock_trywrlock(&m); shared++;", "unknown"),
        (
            "if(pthread_mutex_lock(&m)==EOWNERDEAD) { shared++; pthread_mutex_unlock(&m); }",
            "unknown",  # a project define is not the library errno ABI
        ),
        ("if(pthread_mutex_trylock(&m)==16) { shared++; }", "unknown"),
        (
            "if(pthread_mutex_lock(&m)!=0) return; if(pthread_mutex_lock(&m)!=0) return; pthread_mutex_unlock(&m); shared++;",
            "unknown",
        ),
        (
            "if(pthread_rwlock_rdlock(&m)!=0) return; if(pthread_rwlock_wrlock(&m)!=0) return; shared++;",
            "unknown",
        ),
        ("if(pthread_mutex_lock(&m)!=0) return; pthread_cond_wait(&cv,&m); shared++;", "unknown"),
        (
            "if(pthread_mutex_lock(&m)!=0) return; pthread_mutex_unlock(&other); shared++;",
            "unknown",
        ),
        (
            "if(pthread_rwlock_wrlock(&m)!=0) return; pthread_rwlock_unlock(&m); shared++;",
            "unknown",
        ),
        ("if(pthread_rwlock_rdlock(&m)!=0) return; ++shared;", "unknown"),
    ],
)
def test_current_compiler_lock_modes(compile_facts, body, expected):
    store, _, path = compile_facts(DECLS + "\nvoid f(void) { " + body + " }\n")
    candidate = issue(path, category="race", source="shared", rule_id="race")
    result = checked(store, candidate)
    assert result["status"] == expected, result
    proof = deterministic_decision_proof(candidate, outcome="reject")
    assert bool(proof) == (expected == "supported")
    details = result["coverage"].get("lock_analysis", {})
    if expected == "supported":
        assert details["common_locks"] and details["acquisitions"]
        assert all(a["compatible_locks"] for a in details["accesses"])
    # A race receipt must not refute a temporal memory claim on the same text.
    candidate["category"] = "use_after_free"
    assert checked_receipt(candidate) is None
    assert checked(store, candidate)["status"] == "unknown"


@pytest.mark.parametrize(
    "writer,reader,expected",
    [
        ("pthread_rwlock_wrlock(&m)", "pthread_rwlock_rdlock(&m)", "supported"),
        ("pthread_rwlock_rdlock(&m)", "pthread_rwlock_rdlock(&m)", "unknown"),
        ("pthread_rwlock_wrlock(&m)", "pthread_rwlock_rdlock(&other)", "unknown"),
    ],
)
def test_all_accessors_need_same_lock_and_compatible_mode(compile_facts, writer, reader, expected):
    code = (
        DECLS
        + f"void f(void) {{ if({writer}!=0) return; shared++; }}\nvoid g(void) {{ if({reader}!=0) return; int x=shared; }}\n"
    )
    store, _, path = compile_facts(code)
    assert (
        checked(store, issue(path, category="race", source="shared", rule_id="race"))["status"]
        == expected
    )


@pytest.mark.parametrize(
    "primitive,expected",
    [("pthread_rwlock_wrlock", "supported"), ("pthread_rwlock_rdlock", "unknown")],
)
def test_current_transparent_wrapper_chain(compile_facts, primitive, expected):
    code = (
        DECLS
        + f"int alpha(int *p) {{ return {primitive}(p); }}\nint beta(int *p) {{ return alpha(p); }}\nint omega(int *p) {{ return pthread_rwlock_unlock(p); }}\nvoid f(void) {{ if(beta(&m)!=0) return; shared++; omega(&m); }}\n"
    )
    store, _, path = compile_facts(code)
    candidate = issue(path, category="race", source="shared", rule_id="race")
    result = checked(store, candidate)
    assert result["status"] == expected, result
    if expected == "supported":
        assert {"alpha", "beta", "omega", "f"} <= set(result["checked_functions"])
        path.write_text(code.replace("return pthread_rwlock_wrlock(p);", "return 0;"))
        assert checked_receipt(candidate) is None


@pytest.mark.parametrize(
    "extra,body",
    [
        (
            "int pthread_rwlock_wrlock(int *p) { return 0; }",
            "if(pthread_rwlock_wrlock(&m)==0) shared++;",
        ),
        ("int alpha(int *p) { pthread_rwlock_wrlock(p); return 0; }", "if(alpha(&m)==0) shared++;"),
        ("static int *saved=&m;", "if(pthread_rwlock_wrlock(&m)==0) shared++;"),
        ("void reset(void) { m=0; }", "if(pthread_rwlock_wrlock(&m)==0) shared++;"),
        (
            "struct S { int guard; }; static struct S a,b;",
            "if(pthread_rwlock_wrlock(&a.guard)==0) { shared++; pthread_rwlock_unlock(&b.guard); }",
        ),
        ("void g(void) { shared++; }", "if(pthread_rwlock_wrlock(&m)==0) shared++;"),
        (
            "void g(void) { pthread_rwlock_unlock(&m); }",
            "if(pthread_rwlock_wrlock(&m)==0) shared++;",
        ),
    ],
)
def test_unsupported_protocols_and_escaped_identity_remain_unknown(compile_facts, extra, body):
    store, _, path = compile_facts(DECLS + extra + "\nvoid f(void) { " + body + " }\n")
    candidate = issue(path, category="race", source="shared", rule_id="race")
    result = checked(store, candidate)
    assert result["status"] == "unknown", result
    assert checked_receipt(candidate) is None


def test_real_posix_headers_reader_writer(compile_facts):
    code = """
#define _POSIX_C_SOURCE 200809L
#include <pthread.h>
#include <errno.h>
static pthread_rwlock_t m = PTHREAD_RWLOCK_INITIALIZER;
static int shared;
int alpha(pthread_rwlock_t *p) { return pthread_rwlock_tryrdlock(p); }
void f(void) { if (pthread_rwlock_wrlock(&m) != 0) return; shared++; pthread_rwlock_unlock(&m); }
int g(void) { if (alpha(&m) != 0) return 0; int v = shared; pthread_rwlock_unlock(&m); return v; }
"""
    store, _, path = compile_facts(code)
    candidate = issue(path, category="race", source="shared", rule_id="race")
    result = checked(store, candidate)
    assert result["status"] == "supported", result
    assert checked_receipt(candidate)


def test_pointer_read_is_not_pointee_write_protection(compile_facts):
    code = DECLS.replace("static int m, other, cv, shared;", "static int m; static int *shared;")
    code += "void f(void) { if(pthread_rwlock_rdlock(&m)!=0) return; (*shared)++; pthread_rwlock_unlock(&m); }\n"
    store, _, path = compile_facts(code)
    candidate = issue(path, category="race", source="shared", rule_id="race")
    result = checked(store, candidate)
    assert result["status"] == "unknown"
    assert checked_receipt(candidate) is None


@pytest.mark.parametrize(
    "override,expected",
    [("", "supported"), ("#undef EOWNERDEAD\n#define EOWNERDEAD 16\n", "unknown")],
)
def test_robust_status_uses_current_system_header_provenance(compile_facts, override, expected):
    code = "#define _POSIX_C_SOURCE 200809L\n#include <pthread.h>\n#include <errno.h>\n" + override
    code += "static pthread_mutex_t m=PTHREAD_MUTEX_INITIALIZER; static int shared;\nvoid f(void) { if(pthread_mutex_lock(&m)==EOWNERDEAD) { shared++; pthread_mutex_unlock(&m); }}\n"
    store, _, path = compile_facts(code)
    candidate = issue(path, category="race", source="shared", rule_id="race")
    result = checked(store, candidate)
    assert result["status"] == expected, result
