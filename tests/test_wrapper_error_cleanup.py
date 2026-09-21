"""Error-path cleanup does not erase an allocator returned on success."""

import pytest

from test_wrapper_contract_compiler import context, publish
from zscope.semantics.contract_compiler import derive_contracts, deterministic_contract_snapshot
from zscope.semantics.contracts import ApiContract
from zscope.semantics.defaults import default_local_pattern_semantics
from zscope.core.candidates.clang_ast_cfg import ClangAstCfgCandidateGenerator
from zscope.core.candidates.regex import RegexCandidateGenerator


@pytest.mark.parametrize(
    "primitive,args,role", [("malloc", "n", "allocator"), ("calloc", "n,1", "calloc")]
)
def test_cleanup_returns_null_but_success_returns_live_allocation(tmp_path, primitive, args, role):
    registry = default_local_pattern_semantics().contracts
    ctx = context(
        "obtain",
        f"void *obtain(size_t n, int ok) {{ void *p={primitive}({args}); if (!p) return NULL; if (!ok) {{ free(p); return NULL; }} return p; }}",
    )
    snapshot = deterministic_contract_snapshot(ctx, registry)
    assert snapshot is not None
    item = ApiContract.from_row({"contract": snapshot["interface_contracts"][0]})
    assert item.role == role and item.effects_trusted
    _, custom, overlay = publish(tmp_path, [snapshot])
    semantics = default_local_pattern_semantics()
    semantics.merge(custom)
    for cls in (ClangAstCfgCandidateGenerator, RegexCandidateGenerator):
        engine = cls(semantics)
        code = "void entry(int ok) {\nvoid *p=obtain(8,ok);\nif (!p) return;\nreturn;\n}"
        assert any(
            i["defect_class"] == "memory_leak"
            for i in engine.generate_issues("entry", code, "unit.c")
        )
        code = code.replace("\nreturn;", "\nfree(p);\nreturn;")
        assert not any(
            i["defect_class"] == "memory_leak"
            for i in engine.generate_issues("entry", code, "unit.c")
        )


@pytest.mark.parametrize(
    "tail",
    [
        "free(p); return p;",
        "if (!ok) free(p); return p;",
        "if (ok) free(p); ok=0; if (!ok) return p; return NULL;",
        "if (ok) free(p); mutate(&ok); if (!ok) return p; return NULL;",
        "if (ok) free(p); ok--; if (!ok) return p; return NULL;",
    ],
)
def test_release_reaching_nonnull_return_cannot_be_an_allocator(tail):
    registry = default_local_pattern_semantics().contracts
    ctx = context("obtain", f"void *obtain(size_t n, int ok) {{ void *p=malloc(n); {tail} }}")
    assert not any(c["role"] == "allocator" for c in derive_contracts(ctx, registry))


def test_success_return_before_cleanup_and_null_return_is_live():
    registry = default_local_pattern_semantics().contracts
    ctx = context(
        "obtain",
        "void *obtain(size_t n, int ok) { void *p=malloc(n); if (ok) return p; free(p); return NULL; }",
    )
    assert deterministic_contract_snapshot(ctx, registry) is not None


def test_alternative_borrowed_return_is_not_this_allocation():
    registry = default_local_pattern_semantics().contracts
    ctx = context(
        "obtain",
        "void *obtain(size_t n, int ok, void *borrowed) { void *p=malloc(n); if (!ok) return borrowed; return p; }",
    )
    assert not any(c["role"] == "allocator" for c in derive_contracts(ctx, registry))


def test_error_cleanup_condition_from_immutable_internal_call_result():
    registry = default_local_pattern_semantics().contracts
    ctx = context(
        "obtain",
        "void *obtain(int fd, size_t n) { void *p=malloc(n); if (!p) return NULL; int r=read(fd,p,n); if (r<0) { free(p); return NULL; } return p; }",
    )
    snapshot = deterministic_contract_snapshot(ctx, registry)
    assert snapshot is not None
    assert any(c["role"] == "allocator" for c in snapshot["interface_contracts"])


@pytest.mark.parametrize("declaration", ["", "static int ", "volatile int "])
def test_nonlocal_or_volatile_guard_result_is_not_a_frozen_slot(declaration):
    registry = default_local_pattern_semantics().contracts
    ctx = context(
        "obtain",
        f"void *obtain(int fd, size_t n) {{ void *p=malloc(n); {declaration}status=read(fd,p,n); if (status<0) free(p); mutate(); if (status>=0) return p; return NULL; }}",
    )
    assert not any(c["role"] == "allocator" for c in derive_contracts(ctx, registry))


@pytest.mark.parametrize(
    "tail",
    [
        "p++; return p;",
        "++p; return p;",
        "p+=1; return p;",
        "shared=p; return shared;",
        "void *q=p; mutate(&q); return q;",
    ],
)
def test_changed_or_shared_return_alias_cannot_prove_allocation(tail):
    registry = default_local_pattern_semantics().contracts
    ctx = context("obtain", f"void *obtain(size_t n) {{ void *p=malloc(n); {tail} }}")
    assert not any(c["role"] == "allocator" for c in derive_contracts(ctx, registry))


def test_memory_null_return_check_does_not_erase_fd_failure_sentinel():
    registry = default_local_pattern_semantics().contracts
    ctx = context(
        "accept_peer",
        "int accept_peer(int listener) { int fd=accept(listener,NULL,NULL); if (fd<0) return -1; return fd; }",
    )
    snapshot = deterministic_contract_snapshot(ctx, registry)
    assert snapshot is not None
    assert any(c["role"] == "io_acquire" for c in snapshot["interface_contracts"])


def test_buffer_element_write_does_not_modify_the_received_count():
    registry = default_local_pattern_semantics().contracts
    ctx = context(
        "obtain",
        "char *obtain(int fd, size_t n) { char *p=(char*)malloc(n+1); if (!p) return NULL; int received=read(fd,p,n); if (received<0) { free(p); return NULL; } p[received]=0; return p; }",
    )
    snapshot = deterministic_contract_snapshot(ctx, registry)
    assert snapshot is not None
    assert any(c["role"] == "allocator" for c in snapshot["interface_contracts"])


def test_member_address_does_not_escape_the_root_pointer_slot():
    registry = default_local_pattern_semantics().contracts
    ctx = context(
        "make",
        "Node *make(void) { Node *p=(Node*)calloc(1,sizeof(Node)); if (!p) return NULL; initialize(&p->lock); return p; }",
    )
    rows = derive_contracts(ctx, registry)
    allocation = next(c for c in rows if c["role"] == "calloc")
    assert not ApiContract.from_row({"contract": allocation}).effects_trusted
    assert deterministic_contract_snapshot(ctx, registry) is None


@pytest.mark.parametrize("opaque", ["populate(p)", "receive(fd,p,8)"])
def test_opaque_local_result_distinguishes_cleanup_without_proving_effects(opaque):
    ctx = context(
        "obtain",
        "char *obtain(int fd) { char *p=malloc(8); if (!p) return NULL; int rc="
        + opaque
        + "; if (rc<0) { free(p); return NULL; } p[rc]=0; return p; }",
    )
    contracts = derive_contracts(ctx, default_local_pattern_semantics().contracts)
    allocation = [c for c in contracts if c["role"] == "allocator"]
    assert len(allocation) == 1
    assert not ApiContract.from_row({"contract": allocation[0]}).effects_trusted


@pytest.mark.parametrize("change", ["rc=0;", "mutate(&rc);", "rc++;"])
def test_mutated_opaque_result_does_not_exclude_release(change):
    ctx = context(
        "obtain",
        "void *obtain(void) { void *p=malloc(8); if (!p) return NULL; int rc=populate(p); if (rc<0) { free(p); } "
        + change
        + " if (rc<0) return NULL; return p; }",
    )
    contracts = derive_contracts(ctx, default_local_pattern_semantics().contracts)
    assert not any(c["role"] == "allocator" for c in contracts)


@pytest.mark.parametrize("callee", ["read(fd,p,8)", "receive(fd,p,8)"])
def test_reassigned_result_does_not_keep_prior_call_guard(callee):
    from zscope.semantics.contract_compiler import read_source_facts

    ctx = context(
        "obtain", "void obtain(int fd, char *p) { int rc=" + callee + "; rc=0; if (rc<0) free(p); }"
    )
    facts = read_source_facts(ctx, default_local_pattern_semantics().contracts)
    release = next(c for c in facts.calls if c.name == "free")
    from zscope.semantics.contract_conditions import evaluate

    assert "call_result" not in str(release.guard)
    assert evaluate(release.guard) == "does_not_apply"  # rc was overwritten with zero.


def test_reassigned_parameter_is_not_the_incoming_guard_or_member_base():
    from zscope.semantics.contract_compiler import read_source_facts

    ctx = context(
        "finish",
        "void finish(int ok, Node *p) { ok=1; p=replacement(); if (ok && p->ready) free(p); }",
    )
    facts = read_source_facts(ctx, default_local_pattern_semantics().contracts)
    release = next(c for c in facts.calls if c.name == "free")
    assert "argument" not in str(release.guard)


def test_parameter_rebinding_cannot_release_the_callers_original_object():
    from zscope.semantics.contracts import ObjectBinding, SymbolIdentity

    registry = default_local_pattern_semantics().contracts
    registry.add(
        ApiContract(SymbolIdentity("dispose"), "deallocator", ObjectBinding("argument", 0))
    )
    ctx = context("finish", "void finish(void *p, void *other) { p=other; dispose(p); }")
    rows = derive_contracts(ctx, registry)
    assert len(rows) == 1
    contract = ApiContract.from_row({"contract": rows[0]})
    assert contract.carrier.resolve(["original", "replacement"]) == "replacement"
    assert contract.carrier.resolve(["original", "replacement"]) != "original"


def test_parameter_rebinding_cannot_publish_the_wrong_pool_domain():
    from zscope.semantics.contracts import ObjectBinding, SymbolIdentity

    registry = default_local_pattern_semantics().contracts
    registry.add(
        ApiContract(
            SymbolIdentity("take"),
            "allocator",
            ObjectBinding("return"),
            resource_domain=ObjectBinding("argument", 0),
        )
    )
    ctx = context(
        "obtain", "void *obtain(Pool *pool, Pool *other) { pool=other; return take(pool); }"
    )
    rows = derive_contracts(ctx, registry)
    assert len(rows) == 1
    contract = ApiContract.from_row({"contract": rows[0]})
    assert contract.resource_domain is not None
    assert contract.resource_domain.resolve(["original_pool", "replacement_pool"]) == "replacement_pool"
    assert contract.resource_domain.resolve(["original_pool", "replacement_pool"]) != "original_pool"
