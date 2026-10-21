"""Native-USR contract identity: publish chain, selection, and forgery guards.

Unit-level cases run on fact frames shape-identical to the native receipts;
the real-extraction cases run the actual clang-indexer tool (overloads in one
TU, same-name statics in two TUs, conditionally mixed callees), publish
contracts through the real compiler chain, and consume them through the real
selection chain (``bind_call_context`` → ``match_call``).
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import pytest

from zscope.semantics.build_scope import bind_build_scope
from zscope.semantics.call_context import bind_call_context, callee_usr_map, current_callee_usr
from zscope.semantics.contracts import (
    ApiContract,
    CONTRACT_COMPILER_VERSION,
    ContractRegistry,
    ObjectBinding,
    SymbolIdentity,
    contract_rows,
)
from zscope.semantics.contract_compiler import compile_snapshot, derive_contracts
from zscope.semantics.build_scope import context_symbol_usr

needs_native = pytest.mark.skipif(
    not os.environ.get("Z_SCOPE_TEST_CLANG_INDEXER"),
    reason="real contract USR tests require Z_SCOPE_TEST_CLANG_INDEXER",
)


def frame(
    build: str = "b1", *, events: list[dict[str, Any]] | None = None, usr: str = "c:@F@dispose"
) -> dict[str, Any]:
    """A shape-identical native receipt frame for one complete function."""

    event_template = {
        "event_id": "1:0",
        "event_kind": "call",
        "block": 1,
        "ordinal": 0,
        "expression": "operate(p)",
        "arguments": ["p"],
        "callee": {"name": "operate", "usr": "c:@F@operate#I#"},
        "location": {"offset": 24},
    }
    body = {
        "complete": True,
        "fact_version": "zscope.program-events.v5",
        "owner": {"name": "dispose", "usr": usr, "file": "unit.c"},
        "events": events if events is not None else [event_template],
    }
    return {
        "func_name": "dispose",
        "file_path": "unit.c",
        "signature": "void dispose(void *p)",
        "code": "void dispose(void *p) { operate(p); }",
        "program_facts": {
            "complete": True,
            "build_context_id": build,
            "functions": [body],
            "function_identity": {"build_context_id": build, "usr": usr},
        },
    }


def contract(name: str, usr: str, *, role: str = "deallocator", signature: str = "") -> ApiContract:
    # Name-level build scope (no pinned build): USR precision is independent
    # of the build scoping, which has its own dedicated coverage.
    return ApiContract(
        SymbolIdentity(name, "api.cpp", signature, usr=usr),
        role,
        ObjectBinding("argument", 0),
        source="user",
    )


# --- unit: exact-USR selection ------------------------------------------------------


def test_exact_usr_lifts_the_same_name_overload_false_rejection():
    registry = ContractRegistry(
        [
            contract("operate", "c:@F@operate#I#", signature="void operate(int)"),
            contract("operate", "c:@F@operate#PC#", signature="void operate(char *)"),
        ]
    )
    # Name-only stays ambiguous: a role cannot pick the overload.
    assert not registry.match_call("operate", "deallocator", ["buffer"])
    # Each exact native USR selects its own overload.
    selected = registry.match_call("operate", "deallocator", ["buffer"], usr="c:@F@operate#I#")
    assert [match.symbol.usr for match in selected] == ["c:@F@operate#I#"]
    other = registry.match_call("operate", "deallocator", ["buffer"], usr="c:@F@operate#PC#")
    assert [match.symbol.usr for match in other] == ["c:@F@operate#PC#"]
    # An unknown USR is not a wildcard either.
    assert not registry.match_call("operate", "deallocator", ["buffer"], usr="c:@F@other")


def test_omitted_usr_without_identity_rejects_a_pinned_contract():
    registry = ContractRegistry(
        [contract("operate", "c:@F@operate#I#", signature="void operate(int)")]
    )
    # A bare build binding states no callee or entry identity: omission is an
    # unknown identity, and the single published record is not borrowed.
    with bind_build_scope({"build_context_id": "b1"}):
        assert not registry.match_call("operate", "deallocator", ["buffer"])
        assert registry.find_for_call("operate", "deallocator") == []
        # Raw find stays the discovery-level API.
        assert registry.find("operate", "deallocator")


def test_usr_less_source_record_cannot_answer_an_exact_usr_query():
    registry = ContractRegistry(
        [
            contract("operate", "c:@F@operate#I#", signature="void operate(int)"),
            contract("operate", "", signature="void operate(char *)"),
        ]
    )
    # A USR-less source record cannot wildcard an exact-USR query: only the
    # identity the compiler pinned is selected, never the name-level twin.
    selected = registry.match_call("operate", "deallocator", ["buffer"], usr="c:@F@operate#I#")
    assert [match.symbol.usr for match in selected] == ["c:@F@operate#I#"]
    lone = ContractRegistry([contract("operate", "", signature="void operate(char *)")])
    assert not lone.match_call("operate", "deallocator", ["buffer"], usr="c:@F@operate#I#")


def test_builtin_standard_root_stays_selectable_under_a_usr_query():
    registry = ContractRegistry(
        [contract("operate", "c:@F@operate#I#", signature="void operate(int)")]
    )
    builtin = ApiContract(
        SymbolIdentity("operate"),
        "deallocator",
        ObjectBinding("argument", 0),
        source="builtin_defaults",
    )
    registry.add(builtin)
    scoped = registry.for_context({"program_facts": {"build_context_id": "b1"}})
    selected = scoped.match_call("operate", "deallocator", ["buffer"], usr="c:@F@operate#I#")
    assert [c.symbol.usr for c in selected] == ["c:@F@operate#I#"]


def test_from_row_strips_usr_from_user_rows_but_keeps_compiler_rows():
    user_row = {
        "symbol_name": "operate",
        "source": "user",
        "contract": {
            "role": "deallocator",
            "carrier": {"kind": "argument", "argument_index": 0},
            "effect_cases": [{"when": {"op": "true"}, "effect": "applies"}],
            "symbol": {"name": "operate", "usr": "c:@F@forged"},
        },
    }
    compiler_row = {
        "symbol_name": "operate",
        "source": "inferred:semantic_modeling",
        "contract": dict(user_row["contract"], symbol={"name": "operate", "usr": "c:@F@real"}),
    }
    assert ApiContract.from_row(user_row).symbol.usr == ""
    assert ApiContract.from_row(compiler_row).symbol.usr == "c:@F@real"


def test_compiler_version_moved_past_the_usr_less_records():
    assert CONTRACT_COMPILER_VERSION == "zscope.contract-compiler.v26"


# --- unit: callee map and entry-USR helpers -----------------------------------------


def test_callee_usr_map_requires_one_unambiguous_usr_per_name():
    single = frame()
    assert callee_usr_map(single) == {"operate": "c:@F@operate#I#"}
    mixed = frame(
        events=[
            {"event_kind": "call", "callee": {"name": "operate", "usr": "c:@F@operate#I#"}},
            {"event_kind": "call", "callee": {"name": "operate", "usr": "c:@F@operate#PC#"}},
        ]
    )
    assert callee_usr_map(mixed) == {}
    unresolved = frame(events=[{"event_kind": "call", "callee": {"name": "operate", "usr": ""}}])
    assert callee_usr_map(unresolved) == {}
    incomplete = frame()
    incomplete["program_facts"]["complete"] = False
    assert callee_usr_map(incomplete) == {}


def test_context_symbol_usr_only_from_complete_native_facts():
    assert context_symbol_usr(frame()) == "c:@F@dispose"
    owner_only = frame()
    owner_only["program_facts"].pop("function_identity")
    assert context_symbol_usr(owner_only) == "c:@F@dispose"
    incomplete = frame()
    incomplete["program_facts"]["complete"] = False
    assert context_symbol_usr(incomplete) == ""
    assert context_symbol_usr({"func_name": "dispose"}) == ""


def test_context_symbol_usr_rejects_ambiguous_owners_and_foreign_receipts():
    ambiguous = frame()
    second = dict(frame()["program_facts"]["functions"][0])
    second["owner"] = {"name": "dispose", "usr": "c:@F@dispose#other", "file": "unit.c"}
    ambiguous["program_facts"]["functions"].append(second)
    assert context_symbol_usr(ambiguous) == ""
    foreign = frame()
    foreign["program_facts"]["function_identity"] = {
        "usr": "c:@F@foreign",
        "build_context_id": "other-build",
    }
    assert context_symbol_usr(foreign) == ""


def test_match_call_resolves_the_bound_callee_usr():
    registry = ContractRegistry(
        [
            contract("operate", "c:@F@operate#I#", signature="void operate(int)"),
            contract("operate", "c:@F@operate#PC#", signature="void operate(char *)"),
        ]
    )
    with bind_call_context(frame(), registry):
        assert current_callee_usr(registry, "operate") == "c:@F@operate#I#"
        selected = registry.match_call("operate", "deallocator", ["p"])
        assert len(selected) == 1 and selected[0].symbol.usr == "c:@F@operate#I#"
    # Outside the bound body there is no USR precision, never a guessed one.
    assert current_callee_usr(registry, "operate") == ""
    assert not registry.match_call("operate", "deallocator", ["p"])


def test_derive_contracts_uses_callee_usr_for_overload_pairing():
    # Same-name lock/unlock overloads pinned to distinct USRs; the body calls
    # the int overloads only, so the compiler must pair them through the map.
    registry = ContractRegistry(
        [
            ApiContract(
                SymbolIdentity("gate", "api.cpp", "void gate(int)", "b1", "c:@F@gate#I#"),
                "lock",
                ObjectBinding("argument", 0),
                source="user",
            ),
            ApiContract(
                SymbolIdentity("gate", "api.cpp", "void gate(char *)", "b1", "c:@F@gate#PC#"),
                "lock",
                ObjectBinding("argument", 0),
                source="user",
            ),
            ApiContract(
                SymbolIdentity("ungate", "api.cpp", "void ungate(int)", "b1", "c:@F@ungate#I#"),
                "unlock",
                ObjectBinding("argument", 0),
                source="user",
            ),
            ApiContract(
                SymbolIdentity("ungate", "api.cpp", "void ungate(char *)", "b1", "c:@F@ungate#PC#"),
                "unlock",
                ObjectBinding("argument", 0),
                source="user",
            ),
        ]
    )
    context = frame(
        usr="c:@F@session",
        events=[
            {"event_kind": "call", "callee": {"name": "gate", "usr": "c:@F@gate#I#"}},
            {"event_kind": "call", "callee": {"name": "ungate", "usr": "c:@F@ungate#I#"}},
        ],
    )
    context["func_name"] = "session"
    context["signature"] = "void session(void *p)"
    context["code"] = "void session(void *p) { gate(1); ungate(1); }"
    with bind_call_context(context, registry):
        rows = derive_contracts(context, registry)
    # The int overloads pair internally; nothing is published for the session
    # wrapper, and crucially the ambiguity of the char* twins never blocks the
    # pairing (the pre-USR behaviour rejected it).
    assert rows == []


# --- real native extraction ---------------------------------------------------------

LOG_CPP = """\
void log_msg(int value) {}
void log_msg(const char *text) {}
void only_int(int mode) { log_msg(mode); }
void mixed(int mode) { if (mode) { log_msg(mode); } else { log_msg("x"); } }
"""

A_C = "static void service(int handle) {}\nvoid use_a(int h) { service(h); }\n"
B_C = "static void service(int handle) {}\nvoid use_b(int h) { service(h); }\n"


@pytest.fixture
def native_index(tmp_path, monkeypatch):
    executable = os.environ.get("Z_SCOPE_TEST_CLANG_INDEXER")
    if not executable:
        pytest.skip("real contract USR tests require Z_SCOPE_TEST_CLANG_INDEXER")
    from zscope.retrieval.clang_backend import ClangBackend

    monkeypatch.setenv("Z_SCOPE_CLANG_BATCH_MEMORY_MB", "512")
    monkeypatch.setattr(
        ClangBackend, "_ensure_extractor", lambda self: pytest.fail("unexpected LSP")
    )
    (tmp_path / "log.cpp").write_text(LOG_CPP, encoding="utf-8")
    (tmp_path / "a.c").write_text(A_C, encoding="utf-8")
    (tmp_path / "b.c").write_text(B_C, encoding="utf-8")
    rows = [
        {
            "directory": str(tmp_path),
            "file": str(tmp_path / name),
            "arguments": [driver, "-c", str(tmp_path / name)],
        }
        for name, driver in (
            ("log.cpp", "clang++"),
            ("a.c", "clang"),
            ("b.c", "clang"),
        )
    ]
    cdb = tmp_path / "compile_commands.json"
    cdb.write_text(__import__("json").dumps(rows), encoding="utf-8")
    backend = ClangBackend(frontend="batch", clang_indexer_path=executable, max_threads=2)
    assert backend.initialize(str(tmp_path), compile_commands_path=str(cdb))
    try:
        from zscope.config.config import IndexingConfig
        from zscope.retrieval.code_index import CodeIndex

        yield CodeIndex(
            tmp_path, cdb, backend=backend, indexing_config=IndexingConfig(backend="clang")
        ), tmp_path
    finally:
        backend.close()


def _build_for(index: Any, file_path: str) -> str:
    contexts = index.get_build_contexts(file_path)
    assert len(contexts) == 1, contexts
    return str(contexts[0]["build_context_id"])


def _publish(
    index: Any,
    registry: ContractRegistry,
    *,
    func_name: str,
    file_path: str,
    signature: str,
    code: str,
    line: int,
    usr: str,
    build: str,
) -> None:
    """Publish one contract for one exact native symbol through the compiler."""

    from zscope.retrieval.instance_index import InstanceScope, wrap_scoped_code_index

    scoped = wrap_scoped_code_index(
        index,
        InstanceScope(
            build_context_id=build,
            usr=usr,
            identity=usr,
            source=file_path,
            function_names=(func_name,),
        ),
    )
    facts = scoped.get_function_program_facts(func_name, file_path)
    assert facts.get("complete") is True, facts.get("reason")
    assert str((facts.get("function_identity") or {}).get("usr") or "") == usr
    context = {
        "func_name": func_name,
        "file_path": file_path,
        "signature": signature,
        "code": code,
        "start_line": line,
        "end_line": line,
        "is_macro": False,
        "program_facts": facts,
    }
    snapshot = {
        "func_name": func_name,
        "file_path": file_path,
        "signature": signature,
        "interface_contracts": [
            {
                "role": "io_acquire",
                "carrier": {"kind": "argument", "argument_index": 0},
                "effect_cases": [{"when": {"op": "true"}, "effect": "applies"}],
                "evidence": [{"lines": str(line)}],
            }
        ],
    }
    errors = compile_snapshot(snapshot, context, registry)
    assert errors == [], errors
    published_rows = [row for rows in contract_rows([snapshot]).values() for row in rows]
    assert published_rows
    for row in published_rows:
        published = ApiContract.from_row(row)
        assert published is not None and published.symbol.usr == usr
        registry.add(published)


@needs_native
def test_real_overloads_publish_and_select_through_usr(native_index):
    index, root = native_index
    build = _build_for(index, "log.cpp")
    ambiguous = index.get_function_program_facts("log_msg", "log.cpp", build_context_id=build)
    assert ambiguous.get("complete") is False
    assert ambiguous.get("reason") == "ambiguous_function_identity"
    owners = {
        int(owner["line"]): str(owner["usr"] or "")
        for owner in ambiguous.get("function_choices", [])
    }
    int_usr, char_usr = owners[1], owners[2]
    assert int_usr and char_usr and int_usr != char_usr

    registry = ContractRegistry([])
    _publish(
        index,
        registry,
        func_name="log_msg",
        file_path="log.cpp",
        signature="void log_msg(int value)",
        code="void log_msg(int value) {}",
        line=1,
        usr=int_usr,
        build=build,
    )
    _publish(
        index,
        registry,
        func_name="log_msg",
        file_path="log.cpp",
        signature="void log_msg(const char *text)",
        code="void log_msg(const char *text) {}",
        line=2,
        usr=char_usr,
        build=build,
    )

    # The real consumer: only_int's native facts bind the callee USR, and the
    # selection resolves the int overload without a signature hint.
    caller_facts = index.get_function_program_facts("only_int", "log.cpp", build_context_id=build)
    assert caller_facts.get("complete") is True
    assert callee_usr_map({"program_facts": caller_facts}) == {"log_msg": int_usr}
    caller = {
        "func_name": "only_int",
        "file_path": "log.cpp",
        "signature": "void only_int(int mode)",
        "code": "void only_int(int mode) { log_msg(mode); }",
        "program_facts": caller_facts,
    }
    with bind_call_context(caller, registry):
        selected = registry.match_call("log_msg", "io_acquire", ["mode"])
        # An explicit query for the other overload selects exactly that one.
        other = registry.match_call("log_msg", "io_acquire", ["mode"], usr=char_usr)
        # An unknown USR selects nothing.
        foreign = registry.match_call("log_msg", "io_acquire", ["mode"], usr="c:@F@nope")
    assert [match.symbol.usr for match in selected] == [int_usr]
    assert [match.symbol.usr for match in other] == [char_usr]
    assert foreign == []

    # A body that conditionally calls both overloads has no unambiguous callee
    # USR: selection stays conservative instead of guessing.
    mixed_facts = index.get_function_program_facts("mixed", "log.cpp", build_context_id=build)
    assert mixed_facts.get("complete") is True
    assert callee_usr_map({"program_facts": mixed_facts}) == {}
    mixed = {
        "func_name": "mixed",
        "file_path": "log.cpp",
        "signature": "void mixed(int mode)",
        "code": 'void mixed(int mode) { if (mode) { log_msg(mode); } else { log_msg("x"); } }',
        "program_facts": mixed_facts,
    }
    with bind_call_context(mixed, registry):
        assert not registry.match_call("log_msg", "io_acquire", ["mode"])

    # Only the int overload published: the mixed body's unresolved callee
    # identity must not borrow the single published record either.
    lone = ContractRegistry([])
    _publish(
        index,
        lone,
        func_name="log_msg",
        file_path="log.cpp",
        signature="void log_msg(int value)",
        code="void log_msg(int value) {}",
        line=1,
        usr=int_usr,
        build=build,
    )
    with bind_call_context(mixed, lone):
        assert not lone.match_call("log_msg", "io_acquire", ["mode"])
    with bind_call_context(caller, lone):
        assert [m.symbol.usr for m in lone.match_call("log_msg", "io_acquire", ["mode"])] == [
            int_usr
        ]


@needs_native
def test_real_dual_tu_homonyms_reject_the_foreign_usr(native_index):
    index, root = native_index
    build_a = _build_for(index, "a.c")
    build_b = _build_for(index, "b.c")
    assert build_a != build_b
    facts_a = index.get_function_program_facts("service", "a.c", build_context_id=build_a)
    facts_b = index.get_function_program_facts("service", "b.c", build_context_id=build_b)
    usr_a = str((facts_a.get("function_identity") or {}).get("usr") or "")
    usr_b = str((facts_b.get("function_identity") or {}).get("usr") or "")
    assert usr_a and usr_b and usr_a != usr_b

    registry = ContractRegistry([])
    _publish(
        index,
        registry,
        func_name="service",
        file_path="a.c",
        signature="void service(int handle)",
        code="static void service(int handle) {}",
        line=1,
        usr=usr_a,
        build=build_a,
    )

    def caller_context(name: str, facts: dict[str, Any]) -> dict[str, Any]:
        return {
            "func_name": name,
            "file_path": f"{name[-1]}.c",
            "signature": f"void {name}(int h)",
            "code": f"void {name}(int h) {{ service(h); }}",
            "program_facts": facts,
        }

    use_a = index.get_function_program_facts("use_a", "a.c", build_context_id=build_a)
    use_b = index.get_function_program_facts("use_b", "b.c", build_context_id=build_b)
    assert callee_usr_map({"program_facts": use_a}) == {"service": usr_a}
    assert callee_usr_map({"program_facts": use_b}) == {"service": usr_b}
    with bind_call_context(caller_context("use_a", use_a), registry):
        assert [m.symbol.usr for m in registry.match_call("service", "io_acquire", ["h"])] == [
            usr_a
        ]
    # The other TU's static homonym is a different native symbol: the a.c
    # contract must not be selected for b.c's call, explicitly or via the map.
    with bind_call_context(caller_context("use_b", use_b), registry):
        assert not registry.match_call("service", "io_acquire", ["h"])
        assert not registry.match_call("service", "io_acquire", ["h"], usr=usr_a)
