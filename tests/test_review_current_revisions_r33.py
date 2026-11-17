"""Current catalog revisions must still require actual compiler counterproofs."""

import pytest
from test_review_fact_checks import compile_facts, issue
from zscope.core.validation.review_checks import ReviewClaimChecker, checked_receipt
from zscope.core.validation.proofs import deterministic_decision_proof
from zscope.rules.catalog import RuleCatalog

RULES = [
    "unsynchronized_shared_flag_or_counter",
    "clang_cfg_unsynchronized_shared_flag_or_counter",
    "clang_cfg_parent_release_without_owned_member_cleanup",
    "clang_cfg_acquire_without_release_on_exit",
    "clang_cfg_unchecked_insert_after_ownership_handoff",
    "clang_cfg_unbounded_count_indexes_fixed_array",
    "clang_cfg_nonliteral_format_string",
    "clang_cfg_narrowed_allocation_original_length_copy",
    "clang_cfg_return_with_lock_held",
    "clang_cfg_fd_open_return_without_close",
    "clang_cfg_allocation_result_used_without_null_check",
]


def subject(rule, safe):
    if rule in RULES[:2]:
        body = (
            "if(pthread_mutex_lock(&m)!=0)return; shared++; pthread_mutex_unlock(&m);"
            if safe
            else "shared++;"
        )
        return (
            "extern int pthread_mutex_lock(int*); extern int pthread_mutex_unlock(int*);\n"
            "static int m, shared;\nvoid f(void){" + body + "}\n",
            {"category": "race", "source": "shared"},
        )
    if rule == "clang_cfg_parent_release_without_owned_member_cleanup":
        field = "name" if safe else "tag"
        return (
            f"typedef struct N {{ int {field}; }} N;\nvoid f(N *node){{(void)node;}}\n",
            {"description": "release without common owned member node->tag cleanup"},
        )
    if rule in {
        "clang_cfg_acquire_without_release_on_exit",
        "clang_cfg_unchecked_insert_after_ownership_handoff",
    }:
        cleanup = "free(node);" if safe else ""
        return (
            "extern void *malloc(unsigned long); extern void free(void*);\n"
            "void f(void){void *node=malloc(8); if(!node)return; " + cleanup + "}\n",
            {},
        )
    if rule == "clang_cfg_unbounded_count_indexes_fixed_array":
        return (
            "void f(void){\nint a[8];\na[" + ("2" if safe else "8") + "]=0;\n}\n",
            {"category": "bounds", "source": "a"},
        )
    if rule == "clang_cfg_nonliteral_format_string":
        call = 'printf("%s", s);' if safe else "printf(s);"
        return (
            "extern int printf(const char*,...);\nvoid f(char *s){\n" + call + "\n}\n",
            {"category": "format_string", "source": "s"},
        )
    if rule == "clang_cfg_narrowed_allocation_original_length_copy":
        length = "n" if safe else "n+1"
        return (
            "extern void *malloc(unsigned long); extern void *memcpy(void*,const void*,unsigned long);\n"
            "void f(unsigned long n, const void *s){char *node=malloc(n);\n"
            "memcpy(node,s," + length + ");\n}\n",
            {"category": "bounds", "source": "node"},
        )
    if rule == "clang_cfg_return_with_lock_held":
        return (
            "extern int pthread_mutex_lock(int*);\nstatic int m;\n"
            "void f(int flag){if(flag)return;\nif(pthread_mutex_lock(&m)!=0)return;\nreturn;\n}\n",
            {"source": "m acquired at line 4", "line": 3 if safe else 5},
        )
    if rule == "clang_cfg_fd_open_return_without_close":
        return (
            'extern int open(const char*,int,...);\nint f(void){\nint fd=open("p",0);\n'
            + ("return fd;" if safe else "return 0;")
            + "\n}\n",
            {"source": "fd = open", "line": 4},
        )
    assert rule == "clang_cfg_allocation_result_used_without_null_check"
    guard = "if(!node)return;" if safe else ""
    return (
        "extern void *malloc(unsigned long);\nvoid f(void){void *node=malloc(8);\n"
        + guard
        + "\n*((char*)node)=0;\n}\n",
        {"source": "node allocated here", "line": 4},
    )


@pytest.mark.parametrize("rule", RULES)
@pytest.mark.parametrize("mode", ["current_safe", "current_unsafe", "unknown_revision"])
def test_current_revision_preserves_independent_proof_requirement(compile_facts, rule, mode):
    safe = mode != "current_unsafe"
    code, fields = subject(rule, safe)
    store, _, path = compile_facts(code)
    descriptor = RuleCatalog.builtin().require(rule)
    fields["category"] = descriptor.defect_class
    candidate = issue(
        path,
        rule_id=rule,
        rule_revision=descriptor.revision + (1000 if mode == "unknown_revision" else 0),
        **fields,
    )
    checker = ReviewClaimChecker(store)
    checker.prepare(candidate)
    result = checker.check(candidate)
    if mode == "current_safe":
        assert result["status"] == "supported", result
        assert checked_receipt(candidate)
        assert deterministic_decision_proof(candidate, outcome="reject")
    else:
        assert result["status"] != "supported", result
        assert not deterministic_decision_proof(candidate, outcome="reject")
        if mode == "unknown_revision":
            assert result["reason"] == "unqualified_rule_contract_revision", result
