"""Regressions exposed by the real, answer-isolated modeling trial."""

from concurrent.futures import ThreadPoolExecutor
import threading

import pytest

from zscope.common.cancellation import CancellationToken
from zscope.orchestration.semantic_modeling import _propagate_modeling_interrupt
from zscope.semantics.contract_compiler import compile_snapshot, derive_contracts, read_source_facts
from zscope.semantics.contracts import ApiContract
from zscope.semantics.defaults import default_local_pattern_semantics


def context(code):
    return {
        "func_name": "adapter",
        "file_path": "adapter.c",
        "signature": code.split("{")[0],
        "index_name": "adapter@adapter.c:1-1",
        "code": code,
        "start_line": 1,
        "end_line": 1,
        "referenced_globals": [],
        "referenced_types": [],
        "referenced_macros": [],
    }


def contracts(code, role):
    rows = derive_contracts(context(code), default_local_pattern_semantics().contracts)
    return [ApiContract.from_row({"contract": row}) for row in rows if row["role"] == role]


@pytest.mark.parametrize(
    "prefix,expected",
    [
        ("Item *p = (Item*)raw;", "first"),
        ("Item *p = (Item*)raw; Item *saved = p; p = other; p = saved;", "first"),
        ("Item *p = (Item*)raw; p = other;", "second"),
    ],
)
def test_frozen_pointer_alias_maps_the_current_object(prefix, expected):
    found = contracts(
        f"void adapter(void *raw, Item *other) {{ {prefix} free(p); }}", "deallocator"
    )
    assert len(found) == 1
    assert found[0].carrier.resolve(["first", "second"]) == expected
    assert found[0].effects_trusted


@pytest.mark.parametrize(
    "body",
    [
        "Item *p = (Item*)raw; mutate(&p); free(p);",
        "Item *p = (Item*)raw; free(&p);",
        "char *p = (char*)raw + 1; free(p);",
    ],
)
def test_escaped_shifted_or_local_slot_alias_has_no_parameter_release(body):
    assert not contracts(f"void adapter(void *raw) {{ {body} }}", "deallocator")


def test_alias_member_binding_preserves_carrier_and_guard():
    found = contracts(
        "void adapter(State *raw) { State *copy = raw; if (copy->ptr) free(copy->ptr); }",
        "deallocator",
    )
    assert len(found) == 1
    assert found[0].carrier.resolve(["state"]) == "state->ptr"
    assert found[0].effects_trusted


def test_opaque_inline_return_distinguishes_cleanup_and_live_return():
    ctx = context(
        "int adapter(void) { int fd = socket(2, 1, 0); "
        "if (fd < 0) return -1; if (inspect(fd) < 0) { close(fd); return -1; } return fd; }"
    )
    registry = default_local_pattern_semantics().contracts
    facts = read_source_facts(ctx, registry)
    observed = next(c for c in facts.opaque_calls if c.name == "inspect")
    assert observed.result in facts.local_variables
    proposed = {
        "interface_contracts": [
            {
                "role": "io_acquire",
                "carrier": {"kind": "return"},
                "resource_family": "descriptor",
                "evidence": [{"lines": "1"}],
            }
        ]
    }
    assert compile_snapshot(proposed, ctx, registry) == []
    retained = [
        ApiContract.from_row({"contract": row})
        for row in proposed["interface_contracts"]
        if row["role"] == "io_acquire"
    ]
    assert len(retained) == 1
    assert not retained[0].effects_trusted  # The opaque call could consume fd.


def test_initialization_alone_still_refutes_a_lock_proposal():
    proposed = {
        "interface_contracts": [
            {
                "role": "lock",
                "carrier": {"kind": "argument", "argument_index": 0},
                "resource_family": "mutex",
                "evidence": [{"lines": "1"}],
            }
        ]
    }
    errors = compile_snapshot(
        proposed,
        context("int adapter(pthread_mutex_t *m) { return pthread_mutex_init(m, 0); }"),
        default_local_pattern_semantics().contracts,
    )
    assert "role_not_supported_by_source_operations" in errors
    assert all(row["role"] != "lock" for row in proposed["interface_contracts"])


def test_keyboard_interrupt_cancels_scan_before_joining_workers():
    root = CancellationToken()
    child = root.child()
    entered = threading.Event()

    def worker():
        entered.set()
        assert root.wait(2), "executor joined workers before propagating scan cancellation"

    with pytest.raises(KeyboardInterrupt):
        with ThreadPoolExecutor(1) as pool, _propagate_modeling_interrupt(child):
            future = pool.submit(worker)
            assert entered.wait(2)
            raise KeyboardInterrupt
    future.result()
    assert root.reason == "semantic_modeling_interrupted"


def test_system_socket_state_calls_preserve_a_verified_descriptor_wrapper():
    found = contracts(
        "int adapter(void) { int fd = socket(2, 1, 0); "
        "if (fd < 0) return -1; if (bind(fd, 0, 0) < 0) { close(fd); return -1; } "
        "if (listen(fd, 16) < 0) { close(fd); return -1; } return fd; }",
        "io_acquire",
    )
    assert len(found) == 1
    assert found[0].effects_trusted
    assert found[0].resource_family == "descriptor"
    registry = default_local_pattern_semantics().contracts
    registry.add(found[0])
    assert registry.allows("adapter", "close")
    assert not registry.allows("adapter", "free")


def test_parameterless_system_queries_use_the_actual_return_carrier():
    registry = default_local_pattern_semantics().contracts
    for name in ("getpid", "getppid", "pthread_self"):
        assert all(c.carrier.kind == "return" for c in registry.find(name))
