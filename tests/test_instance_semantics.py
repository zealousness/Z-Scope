"""S01 instance semantics: builtin-current, manual-advisory, no-inferred.

These are the module-level slice tests for ``S01-INSTANCE-SEMANTICS-MIN-R23``,
repaired under the R24 and R25 source reviews
(``S01-R24-P1-01``..``S01-R24-P2-04``, ``S01-R25-P1-01``/``-02``).  They
verify the frozen R23 typed interface: builtin effects are minted only by the
packaged factory and only for roots whose exact-build native receipts prove
the standard declaration (system-header origin, external linkage, exact C
native USR, platform canonical signature, non-user-controlled declaration
path), manual workbook rows stay name-only advisory behind their real
per-sheet selectors, every inferred row is excluded with its reason
preserved, snapshots are factory-issued objects that reject forged content
with self-consistent digests, denial travels through the materialized
semantics and the overlay (together with the coordinator-provided shared
``merge_overlay`` shadow pruning), and currency requires the full
context-input verification.  Real Analyzer/Validator consumer wiring, plan
identity and settlement are coordinator-owned integration, not this file.

Native-gated tests run the real batch clang indexer through
``Z_SCOPE_TEST_CLANG_INDEXER``; the synthetic doubles exercise the same
authority logic with receipt-shaped rows and never substitute for native
acceptance.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import replace
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import pytest

from zscope.config.function_entry import FunctionEntry
from zscope.retrieval.build_context import program_facts_result
from zscope.retrieval.indexing_identity import (
    command_identity,
    digest_json,
    file_digest,
    search_directories_snapshot,
)
from zscope.retrieval.instance_index import InstanceScope, ScopedCodeIndex
from zscope.semantics.contracts import CONTRACT_COMPILER_VERSION, expand_api_pattern
from zscope.semantics.defaults import default_local_pattern_semantics
from zscope.semantics.instance_semantics import (
    ADVISORY_AUTHORITY,
    AUTHORITY_POLICY,
    INSTANCE_SEMANTICS_SCHEMA,
    INFERRED_EXCLUSION_REASON,
    ORIGIN_ABI_UNPROVEN,
    ORIGIN_AMBIGUOUS_IDENTITY,
    ORIGIN_IDENTITY_MISMATCH,
    ORIGIN_NO_RECEIPT,
    ORIGIN_NON_SYSTEM_RECEIPT,
    ORIGIN_PROJECT_DEFINED,
    ORIGIN_SIGNATURE_MISMATCH,
    ORIGIN_SYSTEM_RECEIPT,
    ORIGIN_UNVERIFIABLE_COMMAND,
    ORIGIN_USER_INCLUDE_DECLARATION,
    FrozenJSON,
    FrozenWorkbookRows,
    InstanceSemanticsSnapshot,
    SemanticsDependencies,
    SemanticsUnavailable,
    _snapshot_digest,
    _strict_json_loads,
    advisory_context,
    builtin_semantics_fingerprint,
    build_instance_semantics,
    freeze_workbook_rows,
    materialize_effect_semantics,
)
from zscope.semantics.models import MERGE_ATTRS, LocalPatternSemantics


# ── Synthetic exact-context doubles (native facts are not faked by these) ──


# Canonical signatures the real Linux glibc LP64 native tool records for the
# verifiable standard roots (captured from actual batch-indexer receipts).
_STD_SIGNATURES = {
    "malloc": "void *(unsigned long)",
    "calloc": "void *(unsigned long, unsigned long)",
    "realloc": "void *(void *, unsigned long)",
    "free": "void (void *)",
}


def _write(root: Path, name: str, text: str) -> Path:
    path = root / name
    path.write_text(text, encoding="utf-8")
    return path


def _facts(usr: str, name: str, file_path: str, line: int = 1) -> Dict[str, Any]:
    return {
        "kind": "program_function",
        "complete": True,
        "owner": {"usr": usr, "name": name, "file": file_path, "line": line},
        "location": {"file": file_path, "line": line},
        "events": [],
    }


def _call_receipt(
    name: str,
    *,
    system: bool = True,
    signature: str = "",
    usr: str = "",
    external_linkage: bool = True,
    declaration_file: str = "",
) -> Dict[str, Any]:
    """A receipt-shaped native call row for the pinned build.

    By default the row carries the exact identity a genuine Linux glibc LP64
    system declaration records; tests override individual fields to model
    wrong signatures, wrong native identities and user-controlled
    declarations.
    """

    origin_file = declaration_file or ("/usr/include/stdlib.h" if system else "unit.c")
    receipt_usr = usr or f"c:@F@{name}"
    receipt_signature = signature or _STD_SIGNATURES.get(name, "void (void *)")
    return {
        "kind": "call",
        "owner": {"usr": "c:@F@f", "name": "f", "file": "unit.c", "line": 1},
        "target": {
            "qualified_name": name,
            "name": name,
            "usr": receipt_usr,
            "referenced_usr": receipt_usr,
            "is_system_header": system,
            "external_linkage": external_linkage,
            "has_definition": False,
            "canonical_signature": receipt_signature,
            "signature": receipt_signature,
            "declaration": {"file": origin_file, "line": 1},
            "location": {"file": origin_file, "line": 1},
        },
        "location": {"file": "unit.c", "line": 2},
        "call_type": "direct",
    }


def _scope(
    context_id: str, usr: str, source: Path, names: Tuple[str, ...] = ("f",)
) -> InstanceScope:
    return InstanceScope(
        build_context_id=context_id,
        usr=usr,
        identity=f"{context_id}:{usr}",
        source=str(source),
        function_names=names,
    )


class _InstanceIndex:
    """Exact-context program-facts/call-receipt double; navigation is unused."""

    def __init__(
        self,
        contexts: List[Dict[str, Any]],
        rows: Dict[str, List[Dict[str, Any]]],
        call_rows: Optional[Dict[str, List[Dict[str, Any]]]] = None,
    ):
        self.contexts = [dict(context) for context in contexts]
        self.rows = {key: [dict(row) for row in value] for key, value in rows.items()}
        self.call_rows = {
            key: [dict(row) for row in value] for key, value in (call_rows or {}).items()
        }
        self.calls: List[str] = []

    def get_build_contexts(self, file_path: str = "") -> List[Dict[str, Any]]:
        self.calls.append("get_build_contexts")
        if not file_path:
            return [dict(context) for context in self.contexts]
        return [dict(context) for context in self.contexts if context["source"] == file_path]

    def get_compilation_facts(
        self, context_id: str, *, kinds: Tuple[str, ...] = (), symbol: str = "", file_path: str = ""
    ) -> List[Dict[str, Any]]:
        self.calls.append(f"receipts:{context_id}:{','.join(sorted(kinds))}")
        wanted = set(kinds)
        out: List[Dict[str, Any]] = []
        for row in self.rows.get(context_id, []) + self.call_rows.get(context_id, []):
            if wanted and row.get("kind") not in wanted:
                continue
            if symbol and (row.get("owner") or {}).get("name") != symbol:
                continue
            out.append(dict(row))
        return out

    def get_function_program_facts(
        self, name: str, file_path: str = "", *, build_context_id: str = ""
    ) -> Dict[str, Any]:
        self.calls.append(f"facts:{build_context_id}:{name}")
        if not build_context_id:
            return {"complete": False, "events": [], "accesses": [], "reason": "unscoped_query"}
        context = next(
            (item for item in self.contexts if item["build_context_id"] == build_context_id),
            None,
        )
        if context is None:
            return {
                "complete": False,
                "events": [],
                "accesses": [],
                "functions": [],
                "reason": "build_context_not_found",
                "build_context_id": build_context_id,
            }
        rows = list(self.rows.get(build_context_id, []))
        if name.startswith("c:"):
            rows = [row for row in rows if row["owner"]["usr"] == name]
        else:
            rows = [row for row in rows if row["owner"]["name"] == name]
        if not rows:
            return {
                "complete": False,
                "events": [],
                "accesses": [],
                "functions": [],
                "reason": "function_identity_not_found",
                "build_context_id": build_context_id,
            }
        return program_facts_result(rows, context=context)


class _CannedIndex(_InstanceIndex):
    """Serves canned program-facts answers to model unverifiable origins."""

    def __init__(
        self,
        contexts: List[Dict[str, Any]],
        rows: Dict[str, List[Dict[str, Any]]],
        responses: Dict[Tuple[str, str], Dict[str, Any]],
        call_rows: Optional[Dict[str, List[Dict[str, Any]]]] = None,
    ):
        super().__init__(contexts, rows, call_rows)
        self.responses = dict(responses)

    def get_function_program_facts(
        self, name: str, file_path: str = "", *, build_context_id: str = ""
    ) -> Dict[str, Any]:
        canned = self.responses.get((build_context_id, name))
        if canned is not None:
            self.calls.append(f"facts:{build_context_id}:{name}")
            return dict(canned)
        return super().get_function_program_facts(
            name, file_path, build_context_id=build_context_id
        )


def _full_context(
    context_id: str, source: Path, cdb: Path, *, arguments: Optional[List[str]] = None
) -> Dict[str, Any]:
    directory = str(source.parent)
    arguments = arguments if arguments is not None else ["clang", "-c", str(source)]
    identity = command_identity(
        {"file": str(source), "directory": directory, "arguments": arguments},
        Path(directory),
    )
    return {
        "build_context_id": context_id,
        "source": str(source),
        "status": "indexed",
        "dependencies_complete": True,
        "dependencies": {str(source): file_digest(source)},
        "command": {"source": str(source), "directory": directory, "arguments": arguments},
        "command_id": digest_json(identity),
        "compilation_database": {"path": str(cdb), "sha256": file_digest(cdb)},
        "search_directories": search_directories_snapshot([source.parent]),
        "search_excludes": [],
    }


def _dependencies(**overrides: str) -> SemanticsDependencies:
    fingerprint = builtin_semantics_fingerprint()
    values = {
        "compiler_version": fingerprint["compiler_version"],
        "standard_api_version": fingerprint["standard_api_version"],
        "builtin_payload_sha256": fingerprint["builtin_payload_sha256"],
        "business_answers_sha256": hashlib.sha256(b"answers-v1").hexdigest(),
        "effective_policy_sha256": hashlib.sha256(b"policy-v1").hexdigest(),
    }
    values.update(overrides)
    return SemanticsDependencies(**values)


def _workbook(
    external: Tuple[Dict[str, Any], ...] = (),
    paired: Tuple[Dict[str, Any], ...] = (),
    other: Tuple[Dict[str, Any], ...] = (),
    label: str = "workbook-v1",
) -> FrozenWorkbookRows:
    return freeze_workbook_rows(
        workbook_sha256=hashlib.sha256(label.encode("utf-8")).hexdigest(),
        external_rows=external,
        paired_rows=paired,
        other_advisory_rows=other,
    )


def _setup(
    tmp_path: Path,
    *,
    context_id: str = "ctx-a",
    call_rows: Optional[Dict[str, List[Dict[str, Any]]]] = None,
) -> Tuple[ScopedCodeIndex, InstanceScope]:
    source = _write(tmp_path, "unit.c", "int f(void){return 0;}\n")
    cdb = _write(tmp_path, "compile_commands.json", "[]\n")
    context = _full_context(context_id, source, cdb)
    index = _InstanceIndex([context], {context_id: [_facts("c:@F@f", "f", str(source))]}, call_rows)
    scope = _scope(context_id, "c:@F@f", source)
    return ScopedCodeIndex(index, scope), scope


def _build(
    scoped: ScopedCodeIndex,
    scope: InstanceScope,
    workbook: FrozenWorkbookRows | None = None,
    dependencies: SemanticsDependencies | None = None,
    project_contracts_override: Optional[List[Dict[str, Any]]] = None,
) -> InstanceSemanticsSnapshot | SemanticsUnavailable:
    return build_instance_semantics(
        scope=scope,
        scoped_index=scoped,
        workbook=workbook if workbook is not None else _workbook(),
        dependencies=dependencies if dependencies is not None else _dependencies(),
        project_contracts_override=project_contracts_override,
    )


def _snapshot(
    result: InstanceSemanticsSnapshot | SemanticsUnavailable,
) -> InstanceSemanticsSnapshot:
    assert isinstance(result, InstanceSemanticsSnapshot), result
    return result


def _reforged(
    snapshot: InstanceSemanticsSnapshot,
    *,
    effect: Optional[Any] = None,
    advisory: Optional[Any] = None,
) -> InstanceSemanticsSnapshot:
    """Rebuild a snapshot with tampered payload bytes and a matching digest.

    The digest is recomputed exactly like the factory does, so any rejection
    proves the issuance boundary rather than digest self-consistency.
    """

    effect_payload = (
        effect
        if isinstance(effect, bytes)
        else FrozenJSON(
            json.dumps(effect, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode(
                "utf-8"
            )
        )
    )
    advisory_payload = (
        advisory
        if isinstance(advisory, bytes)
        else (
            snapshot.advisory_payload
            if advisory is None
            else FrozenJSON(
                json.dumps(
                    advisory, ensure_ascii=False, sort_keys=True, separators=(",", ":")
                ).encode("utf-8")
            )
        )
    )
    return replace(
        snapshot,
        effect_payload=effect_payload,
        advisory_payload=advisory_payload,
        digest=_snapshot_digest(
            scope=snapshot.scope,
            dependencies=snapshot.dependencies,
            workbook_sha256=snapshot.workbook_sha256,
            effect_payload=effect_payload,
            advisory_payload=advisory_payload,
            excluded_rows=snapshot.excluded_rows,
        ),
    )


def _native_instance(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    source_text: str,
) -> Tuple[Any, Any, InstanceScope]:
    """Build one real native TU with the batch indexer and plan its entry."""

    import os

    from zscope.orchestration.entry_instances import plan_entry_instances
    from zscope.retrieval.clang_backend import ClangBackend
    from zscope.retrieval.instance_index import instance_scope_from_entry_instance
    from test_instance_analysis import _native_index

    executable = os.environ.get("Z_SCOPE_TEST_CLANG_INDEXER")
    if not executable:
        pytest.skip("instance semantics native tests require Z_SCOPE_TEST_CLANG_INDEXER")
    source = _write(tmp_path, "unit.c", source_text)
    cdb = tmp_path / "compile_commands.json"
    cdb.write_text(
        json.dumps(
            [
                {
                    "directory": str(tmp_path),
                    "file": str(source),
                    "arguments": ["clang", "-c", str(source)],
                }
            ]
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(
        ClangBackend, "_ensure_extractor", lambda self: pytest.fail("LSP fallback forbidden")
    )
    backend = ClangBackend(frontend="batch", clang_indexer_path=executable, max_threads=1)
    assert backend.initialize(str(tmp_path), compile_commands_path=str(cdb))
    index = _native_index(backend, tmp_path, cdb)
    plan = plan_entry_instances(index, [FunctionEntry("f", file_path="unit.c")])
    assert plan.status == "planned"
    assert len(plan.instances) == 1
    scope = instance_scope_from_entry_instance(plan.instances[0])
    return backend, index, scope


# ── S01-P01: builtin effects for the exact scope (real native positive) ──


def test_builtin_effects_materialize_for_exact_scope(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    backend, index, scope = _native_instance(
        tmp_path,
        monkeypatch,
        "#include <stdlib.h>\n"
        "void f(void) {\n"
        "    char *p = malloc(4);\n"
        "    char *q = calloc(2, 4);\n"
        "    if (!p) { return; }\n"
        "    q = realloc(q, 8);\n"
        "    free(p);\n"
        "    free(q);\n"
        "}\n",
    )
    try:
        scoped = ScopedCodeIndex(index, scope)

        result = _build(scoped, scope)

        snapshot = _snapshot(result)
        assert snapshot.schema == INSTANCE_SEMANTICS_SCHEMA
        assert snapshot.authority_policy == AUTHORITY_POLICY
        assert snapshot.scope == scope
        assert len(snapshot.digest) == 64
        semantics, overlay = materialize_effect_semantics(snapshot)
        assert semantics.allocators["malloc"] == ["builtin_defaults"]
        assert semantics.deallocators["free"] == ["builtin_defaults"]
        assert semantics.calloc_allocators["calloc"] == ["builtin_defaults"]
        assert semantics.reallocators["realloc"] == ["builtin_defaults"]
        matches = semantics.contracts.find("malloc", "allocator")
        assert matches and all(contract.effects_trusted for contract in matches)
        assert semantics.contracts.allows("malloc", "free") is True
        assert overlay["api_contracts"]
        assert overlay["contract_version"] == semantics.contracts.version
        assert overlay["resource_models"]
        payload = json.loads(snapshot.effect_payload)
        for root in ("malloc", "free", "calloc", "realloc"):
            assert root not in payload["shadowed_symbols"]
            assert payload["symbol_origins"][root] == ORIGIN_SYSTEM_RECEIPT
        # Roots without any in-build origin receipt stay denied.
        assert payload["symbol_origins"]["fopen"] == ORIGIN_NO_RECEIPT
        assert "fopen" in overlay["shadowed_symbols"]
        assert all(row["source"] == "builtin_defaults" for row in payload["contracts"])
    finally:
        backend.close()


def test_extended_standard_api_families_materialize_from_real_receipts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    backend, index, scope = _native_instance(
        tmp_path,
        monkeypatch,
        "#include <fcntl.h>\n"
        "#include <pthread.h>\n"
        "#include <signal.h>\n"
        "#include <string.h>\n"
        "#include <sys/socket.h>\n"
        "#include <time.h>\n"
        "#include <unistd.h>\n"
        "static void handler(int value) { (void)value; }\n"
        "void f(void) {\n"
        "  char a[8] = {0}, b[8] = {0};\n"
        "  pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;\n"
        "  struct timespec ts = {0};\n"
        "  memcpy(a, b, sizeof(a));\n"
        '  int fd = open("/dev/null", O_RDONLY);\n'
        "  int sock = socket(AF_INET, SOCK_STREAM, 0);\n"
        "  pthread_mutex_lock(&lock);\n"
        "  pthread_mutex_unlock(&lock);\n"
        "  signal(SIGUSR1, handler);\n"
        "  clock_gettime(CLOCK_REALTIME, &ts);\n"
        "  close(sock);\n"
        "  close(fd);\n"
        "}\n",
    )
    try:
        snapshot = _snapshot(_build(ScopedCodeIndex(index, scope), scope))
        semantics, overlay = materialize_effect_semantics(snapshot)
        for root in (
            "memcpy",
            "open",
            "close",
            "socket",
            "pthread_mutex_lock",
            "pthread_mutex_unlock",
            "signal",
            "clock_gettime",
        ):
            assert overlay["symbol_origins"][root] == ORIGIN_SYSTEM_RECEIPT
            assert root not in overlay["shadowed_symbols"]
        assert "memcpy" in semantics.copy_sinks
        assert "open" in semantics.io_acquirers
        assert "close" in semantics.io_releasers
        assert "pthread_mutex_lock" in semantics.lock_apis
        assert "pthread_mutex_unlock" in semantics.unlock_apis
        assert "signal" in semantics.callback_registrars
    finally:
        backend.close()


def test_foreign_scope_cannot_borrow_this_instance(tmp_path: Path) -> None:
    source_a = _write(tmp_path, "a.c", "int f(void){return 0;}\n")
    source_b = _write(tmp_path, "b.c", "int f(void){return 1;}\n")
    cdb = _write(tmp_path, "compile_commands.json", "[]\n")
    contexts = [_full_context("ctx-a", source_a, cdb), _full_context("ctx-b", source_b, cdb)]
    index = _InstanceIndex(
        contexts,
        {
            "ctx-a": [_facts("c:@F@f#a", "f", str(source_a))],
            "ctx-b": [_facts("c:@F@f#b", "f", str(source_b))],
        },
    )
    scope_a = _scope("ctx-a", "c:@F@f#a", source_a)
    scope_b = _scope("ctx-b", "c:@F@f#b", source_b)
    scoped_a = ScopedCodeIndex(index, scope_a)
    scoped_b = ScopedCodeIndex(index, scope_b)

    snapshot_a = _snapshot(_build(scoped_a, scope_a))
    mismatch = _build(scoped_a, scope_b)
    assert isinstance(mismatch, SemanticsUnavailable)
    assert mismatch.reason == "scope_mismatch"

    snapshot_b = _snapshot(_build(scoped_b, scope_b))
    assert snapshot_a.digest != snapshot_b.digest
    assert snapshot_a.scope != snapshot_b.scope


# ── S01-P02 / S01-N05: manual rows are advisory only ──


def test_manual_allocator_and_pair_rows_are_advisory_only(tmp_path: Path) -> None:
    scoped, scope = _setup(tmp_path)
    workbook = _workbook(
        external=(
            {
                "func_name": "my_alloc",
                "kind": "allocator",
                "symbol_type": "function",
                "description": "project pool allocator",
                "source": "user",
            },
        ),
        paired=(
            {
                "category": "memory",
                "acquire_func": "my_alloc",
                "release_func": "my_release",
                "description": "pool release",
                "source": "user",
            },
        ),
    )

    snapshot = _snapshot(_build(scoped, scope, workbook=workbook))

    text = advisory_context(
        snapshot,
        function_name="f",
        source_text="p = my_alloc(4); my_release(p);",
        file_path=str(scope.source),
    )
    assert "my_alloc" in text
    assert "my_release" in text
    assert "project pool allocator" in text
    assert ADVISORY_AUTHORITY in text
    semantics, _ = materialize_effect_semantics(snapshot)
    assert "my_alloc" not in semantics.allocators
    assert "my_release" not in semantics.deallocators
    assert semantics.contracts.find("my_alloc") == []
    assert semantics.contracts.find("my_release") == []
    assert semantics.contracts.allows("my_alloc", "my_release") is False
    assert all(pair.acquire.name != "my_alloc" for pair in semantics.contracts.pairs)


def test_advisory_relevance_and_scope_filtering(tmp_path: Path) -> None:
    scoped, scope = _setup(tmp_path)
    workbook = _workbook(
        external=(
            {"func_name": "used_api", "description": "referenced", "source": "user"},
            {"func_name": "unrelated_api", "description": "not referenced", "source": "user"},
        ),
        other=(
            {
                "pointer_location": "cb",
                "scope": "*unit.c",
                "target_functions": '["handler"]',
                "context": "dispatch table",
                "source": "user",
            },
            {
                "pointer_location": "other_cb",
                "scope": "*elsewhere.c",
                "target_functions": '["handler"]',
                "context": "other file",
                "source": "user",
            },
        ),
    )
    snapshot = _snapshot(_build(scoped, scope, workbook=workbook))

    text = advisory_context(
        snapshot,
        function_name="f",
        source_text="cb = handler(p); used_api();",
        file_path=str(scope.source),
    )

    assert "used_api" in text
    assert "unrelated_api" not in text
    assert "pointer_location=cb" in text
    assert "other_cb" not in text


# ── S01-N01 / S01-N02: every inferred row is excluded ──


def test_inferred_row_with_exact_identity_and_valid_verification_is_excluded(
    tmp_path: Path,
) -> None:
    scoped, scope = _setup(tmp_path)
    workbook = _workbook(
        external=(
            {
                "func_name": "pool_create",
                "kind": "allocator",
                "source": "inferred:semantic_modeling",
                "usr": "c:@F@pool_create",
                "build_context_id": "ctx-a",
                "status": "active",
                "confidence": 0.9,
                "verification": {
                    "method": "source_composition",
                    "compiler_version": CONTRACT_COMPILER_VERSION,
                    "source_hash": hashlib.sha256(b"pool").hexdigest(),
                    "effect_strength": "must_under_guard",
                },
            },
        )
    )

    snapshot = _snapshot(_build(scoped, scope, workbook=workbook))

    assert len(snapshot.excluded_rows) == 1
    excluded = json.loads(snapshot.excluded_rows[0])
    assert excluded["reason"] == INFERRED_EXCLUSION_REASON
    assert excluded["authority_policy"] == AUTHORITY_POLICY
    assert excluded["row"]["func_name"] == "pool_create"
    text = advisory_context(
        snapshot, function_name="f", source_text="p = pool_create();", file_path=str(scope.source)
    )
    assert "pool_create" not in text.replace("[Excluded inferred workbook rows: 1]", "")
    assert "excluded" in text.lower()
    semantics, _ = materialize_effect_semantics(snapshot)
    assert "pool_create" not in semantics.allocators
    assert semantics.contracts.find("pool_create") == []


def test_inferred_rows_of_unknown_or_foreign_identity_stay_excluded(tmp_path: Path) -> None:
    scoped, scope = _setup(tmp_path)
    workbook = _workbook(
        external=(
            {
                "func_name": "pool_create",
                "kind": "allocator",
                "source": "inferred:semantic_modeling",
                "usr": "",
                "build_context_id": "",
            },
            {
                "func_name": "f",
                "kind": "allocator",
                "source": "inferred:semantic_modeling",
                "usr": "c:@F@f#other",
                "build_context_id": "ctx-other",
            },
        ),
        other=(
            {
                "symbol_name": "f",
                "file_path": "",
                "intents": "[inferred:guard] return owned",
                "source": "user",
            },
        ),
    )

    snapshot = _snapshot(_build(scoped, scope, workbook=workbook))

    assert len(snapshot.excluded_rows) == 3
    semantics, _ = materialize_effect_semantics(snapshot)
    assert "pool_create" not in semantics.allocators
    assert semantics.contracts.find("pool_create") == []
    # Even an inferred row carrying the entry's own name cannot grant effects.
    assert semantics.contracts.find("f", "allocator") == []


# ── S01-N03: forged workbook authority stays workbook content ──


def test_manual_forged_builtin_source_usr_and_confirmed_stay_advisory(tmp_path: Path) -> None:
    scoped, scope = _setup(tmp_path)
    forged = _workbook(
        external=(
            {
                "func_name": "wrap_alloc",
                "kind": "allocator",
                "source": "builtin_defaults",
                "usr": "c:@F@wrap_alloc",
                "status": "confirmed",
                "verification": {"method": "manual_specification"},
                "effect_strength": "must_under_guard",
                "description": "claims builtin authority",
            },
        )
    )

    forged_snapshot = _snapshot(_build(scoped, scope, workbook=forged))
    plain_snapshot = _snapshot(_build(scoped, scope, workbook=_workbook(label="workbook-v2")))

    assert forged_snapshot.effect_payload == plain_snapshot.effect_payload
    assert forged_snapshot.digest != plain_snapshot.digest
    text = advisory_context(
        forged_snapshot,
        function_name="f",
        source_text="p = wrap_alloc();",
        file_path=str(scope.source),
    )
    assert "wrap_alloc" in text
    assert ADVISORY_AUTHORITY in text
    assert "workbook source: builtin_defaults" in text
    semantics, _ = materialize_effect_semantics(forged_snapshot)
    assert "wrap_alloc" not in semantics.allocators
    assert semantics.contracts.find("wrap_alloc") == []


# ── S01-N04 / R24 P1-03: project shadowing and origin evidence ──


def test_project_defined_malloc_shadows_builtin_for_this_instance(tmp_path: Path) -> None:
    source = _write(
        tmp_path,
        "unit.c",
        "void* malloc(unsigned n){return 0;} int f(void){return 0;}\n",
    )
    cdb = _write(tmp_path, "compile_commands.json", "[]\n")
    context = _full_context("ctx-a", source, cdb)
    index = _InstanceIndex(
        [context],
        {
            "ctx-a": [
                _facts("c:@F@f", "f", str(source)),
                _facts("c:@F@malloc", "malloc", str(source)),
            ]
        },
        # A system-header call receipt for malloc does not rescue the builtin:
        # the project definition inside this exact build wins.
        {"ctx-a": [_call_receipt("malloc"), _call_receipt("free")]},
    )
    scope = _scope("ctx-a", "c:@F@f", source)
    scoped = ScopedCodeIndex(index, scope)

    snapshot = _snapshot(_build(scoped, scope))

    payload = json.loads(snapshot.effect_payload)
    assert payload["symbol_origins"]["malloc"] == ORIGIN_PROJECT_DEFINED
    assert "malloc" in payload["shadowed_symbols"]
    assert payload["symbol_origins"]["free"] == ORIGIN_SYSTEM_RECEIPT
    assert "free" not in payload["shadowed_symbols"]
    semantics, overlay = materialize_effect_semantics(snapshot)
    assert "malloc" not in semantics.allocators
    assert semantics.contracts.find("malloc") == []
    assert semantics.contracts.allows("malloc", "free") is False
    assert semantics.contracts.releases("malloc") == set()
    assert semantics.deallocators["free"] == ["builtin_defaults"]
    assert semantics.contracts.find("free", "deallocator")
    assert all(row.get("name") != "malloc" for row in overlay["resource_models"])
    assert overlay["shadowed_symbols"]


def test_unverifiable_builtin_origin_denies_authority(tmp_path: Path) -> None:
    source = _write(tmp_path, "unit.c", "int f(void){return 0;}\n")
    cdb = _write(tmp_path, "compile_commands.json", "[]\n")
    context = _full_context("ctx-a", source, cdb)
    index = _CannedIndex(
        [context],
        {"ctx-a": [_facts("c:@F@f", "f", str(source))]},
        {
            ("ctx-a", "malloc"): {
                "complete": False,
                "events": [],
                "accesses": [],
                "functions": [],
                "reason": "native_receipt_unavailable",
                "build_context_id": "ctx-a",
            }
        },
    )
    scope = _scope("ctx-a", "c:@F@f", source)
    scoped = ScopedCodeIndex(index, scope)

    snapshot = _snapshot(_build(scoped, scope))

    payload = json.loads(snapshot.effect_payload)
    assert payload["symbol_origins"]["malloc"] == ORIGIN_AMBIGUOUS_IDENTITY
    assert "malloc" in payload["shadowed_symbols"]
    semantics, _ = materialize_effect_semantics(snapshot)
    assert semantics.contracts.find("malloc") == []


def test_system_call_receipt_authorizes_builtin_in_exact_build(tmp_path: Path) -> None:
    scoped, scope = _setup(
        tmp_path, call_rows={"ctx-a": [_call_receipt("malloc"), _call_receipt("free")]}
    )

    snapshot = _snapshot(_build(scoped, scope))

    payload = json.loads(snapshot.effect_payload)
    assert payload["symbol_origins"]["malloc"] == ORIGIN_SYSTEM_RECEIPT
    assert payload["symbol_origins"]["free"] == ORIGIN_SYSTEM_RECEIPT
    assert "malloc" not in payload["shadowed_symbols"]
    semantics, overlay = materialize_effect_semantics(snapshot)
    assert semantics.allocators["malloc"] == ["builtin_defaults"]
    assert semantics.deallocators["free"] == ["builtin_defaults"]
    assert semantics.contracts.allows("malloc", "free") is True
    assert "malloc" not in overlay["shadowed_symbols"]


def test_missing_body_empty_answer_and_no_reason_do_not_authorize_builtin(
    tmp_path: Path,
) -> None:
    source = _write(tmp_path, "unit.c", "int f(void){return 0;}\n")
    cdb = _write(tmp_path, "compile_commands.json", "[]\n")
    context = _full_context("ctx-a", source, cdb)
    entry = {"ctx-a": [_facts("c:@F@f", "f", str(source))]}
    canned_answers = (
        {},
        {"complete": False, "events": [], "accesses": [], "functions": []},
        {
            "complete": False,
            "events": [],
            "accesses": [],
            "functions": [],
            "reason": "function_identity_not_found",
        },
    )
    scope = _scope("ctx-a", "c:@F@f", source)
    for answer in canned_answers:
        index = _CannedIndex([context], entry, {("ctx-a", "malloc"): answer})
        scoped = ScopedCodeIndex(index, scope)

        snapshot = _snapshot(_build(scoped, scope))

        payload = json.loads(snapshot.effect_payload)
        assert payload["symbol_origins"]["malloc"] == ORIGIN_NO_RECEIPT
        assert "malloc" in payload["shadowed_symbols"]
        semantics, overlay = materialize_effect_semantics(snapshot)
        assert "malloc" not in semantics.allocators
        assert semantics.contracts.find("malloc") == []
        assert semantics.contracts.find_for_call("malloc", usr="") == []
        assert not semantics.contracts.allows("malloc", "free")
        rebuilt = LocalPatternSemantics()
        rebuilt.merge_overlay(overlay)
        assert rebuilt.contracts.find_for_call("malloc", usr="") == []
        assert "malloc" not in rebuilt.allocators


def test_non_system_external_declaration_denies_builtin(tmp_path: Path) -> None:
    scoped, scope = _setup(
        tmp_path,
        call_rows={"ctx-a": [_call_receipt("malloc", system=False)]},
    )

    snapshot = _snapshot(_build(scoped, scope))

    payload = json.loads(snapshot.effect_payload)
    assert payload["symbol_origins"]["malloc"] == ORIGIN_NON_SYSTEM_RECEIPT
    assert "malloc" in payload["shadowed_symbols"]
    semantics, _ = materialize_effect_semantics(snapshot)
    assert "malloc" not in semantics.allocators
    assert semantics.contracts.find("malloc") == []


def test_project_macro_with_builtin_name_leaves_no_receipt_and_denies(tmp_path: Path) -> None:
    # A project macro that rewrites the call leaves a receipt only for the
    # expanded callee; the builtin spelling itself has no origin receipt.
    scoped, scope = _setup(tmp_path, call_rows={"ctx-a": [_call_receipt("my_malloc")]})

    snapshot = _snapshot(_build(scoped, scope))

    payload = json.loads(snapshot.effect_payload)
    assert payload["symbol_origins"]["malloc"] == ORIGIN_NO_RECEIPT
    assert "malloc" in payload["shadowed_symbols"]
    semantics, _ = materialize_effect_semantics(snapshot)
    assert semantics.contracts.find("malloc") == []


def test_foreign_build_receipts_do_not_authorize(tmp_path: Path) -> None:
    source = _write(tmp_path, "unit.c", "int f(void){return 0;}\n")
    other = _write(tmp_path, "other.c", "int f(void){return 1;}\n")
    cdb = _write(tmp_path, "compile_commands.json", "[]\n")
    contexts = [_full_context("ctx-a", source, cdb), _full_context("ctx-b", other, cdb)]
    index = _InstanceIndex(
        contexts,
        {
            "ctx-a": [_facts("c:@F@f", "f", str(source))],
            "ctx-b": [_facts("c:@F@f#b", "f", str(other))],
        },
        # The system receipt exists only inside build ctx-b.
        {"ctx-b": [_call_receipt("malloc")]},
    )
    scope = _scope("ctx-a", "c:@F@f", source)
    scoped = ScopedCodeIndex(index, scope)

    snapshot = _snapshot(_build(scoped, scope))

    payload = json.loads(snapshot.effect_payload)
    assert payload["symbol_origins"]["malloc"] == ORIGIN_NO_RECEIPT
    assert "malloc" in payload["shadowed_symbols"]
    semantics, _ = materialize_effect_semantics(snapshot)
    assert semantics.contracts.find("malloc") == []


def test_real_native_non_system_declaration_denies_builtin(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    backend, index, scope = _native_instance(
        tmp_path,
        monkeypatch,
        "void *malloc(unsigned n);\n"
        "void f(void) {\n"
        "    void *p = malloc(4);\n"
        "    (void)p;\n"
        "}\n",
    )
    try:
        scoped = ScopedCodeIndex(index, scope)

        snapshot = _snapshot(_build(scoped, scope))

        payload = json.loads(snapshot.effect_payload)
        assert payload["symbol_origins"]["malloc"] in {
            ORIGIN_NON_SYSTEM_RECEIPT,
            ORIGIN_NO_RECEIPT,
        }
        assert "malloc" in payload["shadowed_symbols"]
        semantics, overlay = materialize_effect_semantics(snapshot)
        assert "malloc" not in semantics.allocators
        assert semantics.contracts.find("malloc") == []
        rebuilt = LocalPatternSemantics()
        rebuilt.merge_overlay(overlay)
        assert "malloc" not in rebuilt.allocators
    finally:
        backend.close()


# ── R25 S01-R25-P1-02: standard-root ABI and identity verification ──


def test_wrong_signature_system_marked_declaration_denies_builtin(tmp_path: Path) -> None:
    scoped, scope = _setup(
        tmp_path,
        call_rows={"ctx-a": [_call_receipt("malloc", signature="int (int)")]},
    )

    snapshot = _snapshot(_build(scoped, scope))

    payload = json.loads(snapshot.effect_payload)
    assert payload["symbol_origins"]["malloc"] == ORIGIN_SIGNATURE_MISMATCH
    assert "malloc" in payload["shadowed_symbols"]
    semantics, overlay = materialize_effect_semantics(snapshot)
    assert "malloc" not in semantics.allocators
    assert semantics.contracts.find("malloc") == []
    assert "malloc" in overlay["shadowed_symbols"]


def test_user_include_path_system_marked_declaration_denies_builtin(tmp_path: Path) -> None:
    vendor = tmp_path / "vendor"
    vendor.mkdir()
    source = _write(tmp_path, "unit.c", "int f(void){return 0;}\n")
    cdb = _write(tmp_path, "compile_commands.json", "[]\n")
    # The declaration carries genuine stdlib facts, but the build reaches it
    # through a user-controlled -isystem root, so it is not platform ABI
    # evidence for this compilation.
    context = _full_context(
        "ctx-a",
        source,
        cdb,
        arguments=["clang", "-fno-builtin", "-isystem", str(vendor), "-c", str(source)],
    )
    index = _InstanceIndex(
        [context],
        {"ctx-a": [_facts("c:@F@f", "f", str(source))]},
        {"ctx-a": [_call_receipt("malloc", declaration_file=str(vendor / "vendor_alloc.h"))]},
    )
    scope = _scope("ctx-a", "c:@F@f", source)
    scoped = ScopedCodeIndex(index, scope)

    snapshot = _snapshot(_build(scoped, scope))

    payload = json.loads(snapshot.effect_payload)
    assert payload["symbol_origins"]["malloc"] == ORIGIN_USER_INCLUDE_DECLARATION
    assert "malloc" in payload["shadowed_symbols"]
    semantics, _ = materialize_effect_semantics(snapshot)
    assert semantics.contracts.find("malloc") == []
    # Joined -Ivendor spelling reaches the same denial.
    joined = _full_context(
        "ctx-a",
        source,
        cdb,
        arguments=["clang", "-fno-builtin", f"-I{vendor}", "-c", str(source)],
    )
    index_joined = _InstanceIndex(
        [joined],
        {"ctx-a": [_facts("c:@F@f", "f", str(source))]},
        {"ctx-a": [_call_receipt("malloc", declaration_file=str(vendor / "vendor_alloc.h"))]},
    )
    scoped_joined = ScopedCodeIndex(index_joined, scope)
    snapshot_joined = _snapshot(_build(scoped_joined, scope))
    payload_joined = json.loads(snapshot_joined.effect_payload)
    assert payload_joined["symbol_origins"]["malloc"] == ORIGIN_USER_INCLUDE_DECLARATION


def test_native_identity_mismatch_and_unproven_abi_denied(tmp_path: Path) -> None:
    scoped, scope = _setup(
        tmp_path,
        call_rows={"ctx-a": [_call_receipt("malloc", usr="c:@F@malloc#vendor")]},
    )
    snapshot = _snapshot(_build(scoped, scope))
    payload = json.loads(snapshot.effect_payload)
    assert payload["symbol_origins"]["malloc"] == ORIGIN_IDENTITY_MISMATCH
    assert "malloc" in payload["shadowed_symbols"]

    scoped_static, scope_static = _setup(
        tmp_path,
        call_rows={"ctx-a": [_call_receipt("malloc", external_linkage=False)]},
    )
    snapshot_static = _snapshot(_build(scoped_static, scope_static))
    payload_static = json.loads(snapshot_static.effect_payload)
    assert payload_static["symbol_origins"]["malloc"] == ORIGIN_IDENTITY_MISMATCH

    # Supported roots still require the exact platform signature.  A generic
    # pointer signature cannot authorize the pthread ABI.
    scoped_lock, scope_lock = _setup(
        tmp_path,
        call_rows={"ctx-a": [_call_receipt("pthread_mutex_lock", signature="int (void *)")]},
    )
    snapshot_lock = _snapshot(_build(scoped_lock, scope_lock))
    payload_lock = json.loads(snapshot_lock.effect_payload)
    assert payload_lock["symbol_origins"]["pthread_mutex_lock"] == ORIGIN_SIGNATURE_MISMATCH
    assert "pthread_mutex_lock" in payload_lock["shadowed_symbols"]
    semantics_lock, overlay_lock = materialize_effect_semantics(snapshot_lock)
    assert "pthread_mutex_lock" not in semantics_lock.lock_apis
    assert "pthread_mutex_lock" in overlay_lock["shadowed_symbols"]


def test_response_file_command_leaves_abi_unverifiable(tmp_path: Path) -> None:
    response = _write(tmp_path, "flags.rsp", "-DUSE_POOL=1\n")
    source = _write(tmp_path, "unit.c", "int f(void){return 0;}\n")
    cdb = _write(tmp_path, "compile_commands.json", "[]\n")
    context = _full_context(
        "ctx-a",
        source,
        cdb,
        arguments=["clang", f"@{response}", "-c", str(source)],
    )
    index = _InstanceIndex(
        [context],
        {"ctx-a": [_facts("c:@F@f", "f", str(source))]},
        {"ctx-a": [_call_receipt("malloc")]},
    )
    scope = _scope("ctx-a", "c:@F@f", source)
    scoped = ScopedCodeIndex(index, scope)

    snapshot = _snapshot(_build(scoped, scope))

    payload = json.loads(snapshot.effect_payload)
    assert payload["symbol_origins"]["malloc"] == ORIGIN_UNVERIFIABLE_COMMAND
    assert "malloc" in payload["shadowed_symbols"]
    semantics, _ = materialize_effect_semantics(snapshot)
    assert "malloc" not in semantics.allocators


def test_checker_only_roots_are_in_the_deny_universe(tmp_path: Path) -> None:
    scoped, scope = _setup(tmp_path)

    snapshot = _snapshot(_build(scoped, scope))

    payload = json.loads(snapshot.effect_payload)
    # Packaged checker-only names (defaults.yaml checker_roles, e.g. the
    # clang copy sink ``bcopy``) are part of the deny universe; the graph
    # release name ``delete`` is a pair endpoint and is in the universe the
    # same way.  Neither has an in-build origin receipt here.
    assert "bcopy" in payload["checker_only_roots"]
    assert "delete" in payload["symbol_origins"]
    assert payload["symbol_origins"]["delete"] == ORIGIN_NO_RECEIPT
    assert payload["symbol_origins"]["bcopy"] == ORIGIN_NO_RECEIPT
    assert "delete" in payload["shadowed_symbols"]
    assert "bcopy" in payload["shadowed_symbols"]
    semantics, overlay = materialize_effect_semantics(snapshot)
    assert "delete" in semantics.contracts.shadowed_symbols
    assert "bcopy" in semantics.contracts.shadowed_symbols
    assert semantics.contracts.find("delete") == []
    rebuilt = LocalPatternSemantics()
    rebuilt.merge_overlay(overlay)
    assert "delete" in rebuilt.contracts.shadowed_symbols
    assert "bcopy" in rebuilt.contracts.shadowed_symbols
    default = default_local_pattern_semantics()
    default.merge_overlay(overlay)
    assert "delete" not in default.deallocators
    assert "bcopy" not in default.copy_sinks


def test_real_native_wrong_signature_system_header_denies_builtin(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The real -fno-builtin/-isystem vendor-header counterexample.

    Mirrors the coordinator origin probe: a vendor header declaring
    ``int malloc(int)`` compiled with ``-fno-builtin -isystem vendor`` yields
    real native receipts with system-header classification and a wrong
    signature; the packaged allocator must stay denied.
    """

    import os

    from zscope.retrieval.clang_backend import ClangBackend
    from zscope.orchestration.entry_instances import plan_entry_instances
    from zscope.retrieval.instance_index import instance_scope_from_entry_instance
    from test_instance_analysis import _native_index

    executable = os.environ.get("Z_SCOPE_TEST_CLANG_INDEXER")
    if not executable:
        pytest.skip("instance semantics native tests require Z_SCOPE_TEST_CLANG_INDEXER")
    vendor = tmp_path / "vendor"
    vendor.mkdir()
    (vendor / "vendor_alloc.h").write_text("int malloc(int n);\n", encoding="utf-8")
    source = tmp_path / "unit.c"
    source.write_text(
        "#include <vendor_alloc.h>\nint f(void){return malloc(4);}\n", encoding="utf-8"
    )
    cdb = tmp_path / "compile_commands.json"
    cdb.write_text(
        json.dumps(
            [
                {
                    "directory": str(tmp_path),
                    "file": str(source),
                    "arguments": [
                        "clang",
                        "-fno-builtin",
                        "-isystem",
                        str(vendor),
                        "-c",
                        str(source),
                    ],
                }
            ]
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(
        ClangBackend, "_ensure_extractor", lambda self: pytest.fail("LSP fallback forbidden")
    )
    backend = ClangBackend(frontend="batch", clang_indexer_path=executable, max_threads=1)
    try:
        assert backend.initialize(str(tmp_path), compile_commands_path=str(cdb))
        index = _native_index(backend, tmp_path, cdb)
        plan = plan_entry_instances(index, [FunctionEntry("f", file_path="unit.c")])
        assert len(plan.instances) == 1
        scope = instance_scope_from_entry_instance(plan.instances[0])

        snapshot = _snapshot(_build(ScopedCodeIndex(index, scope), scope))

        payload = json.loads(snapshot.effect_payload)
        assert payload["symbol_origins"]["malloc"] in {
            ORIGIN_USER_INCLUDE_DECLARATION,
            ORIGIN_SIGNATURE_MISMATCH,
        }
        assert "malloc" in payload["shadowed_symbols"]
        local, overlay = materialize_effect_semantics(snapshot)
        assert "malloc" not in local.allocators
        assert local.contracts.find("malloc") == []
        assert "malloc" in overlay["shadowed_symbols"]
    finally:
        backend.close()


# ── R24 S01-R24-P1-02: denial travels through the overlay ──


def test_overlay_preserves_deny_set_and_excludes_denied_content(tmp_path: Path) -> None:
    source = _write(
        tmp_path,
        "unit.c",
        "void* malloc(unsigned n){return 0;} int f(void){return 0;}\n",
    )
    cdb = _write(tmp_path, "compile_commands.json", "[]\n")
    context = _full_context("ctx-a", source, cdb)
    index = _InstanceIndex(
        [context],
        {
            "ctx-a": [
                _facts("c:@F@f", "f", str(source)),
                _facts("c:@F@malloc", "malloc", str(source)),
            ]
        },
        {"ctx-a": [_call_receipt("malloc"), _call_receipt("free")]},
    )
    scope = _scope("ctx-a", "c:@F@f", source)
    scoped = ScopedCodeIndex(index, scope)

    snapshot = _snapshot(_build(scoped, scope))
    local, overlay = materialize_effect_semantics(snapshot)

    # The factory-issued local object denies malloc everywhere.
    assert local.contracts.find("malloc") == []
    assert not local.contracts.allows("malloc", "free")
    assert local.contracts.releases("malloc") == set()
    assert local.contracts.acquires("free") == set()
    # The overlay carries the deny set and omits denied executable content.
    assert "malloc" in overlay["shadowed_symbols"]
    assert overlay["symbol_origins"]["malloc"] == ORIGIN_PROJECT_DEFINED
    assert all(
        (row.get("symbol") or {}).get("name") != "malloc" for row in overlay["api_contracts"]
    )
    assert all(
        row.get("acquire", {}).get("name") != "malloc"
        and row.get("release", {}).get("name") != "malloc"
        for row in overlay["api_pairs"]
    )
    assert all(row.get("name") != "malloc" for row in overlay["resource_models"])

    # An overlay-only consumer starting from an empty registry keeps the deny.
    rebuilt = LocalPatternSemantics()
    rebuilt.merge_overlay(overlay)
    assert "malloc" in rebuilt.contracts.shadowed_symbols
    assert "malloc" not in rebuilt.allocators
    assert rebuilt.contracts.find("malloc") == []
    assert not rebuilt.contracts.allows("malloc", "free")
    expanded = expand_api_pattern(r"malloc\s*\(", rebuilt)
    assert "malloc" not in expanded.replace("aligned_alloc", "")

    # A default-preseeded overlay-only consumer now keeps the deny in the raw
    # role buckets as well: the coordinator-provided shared ``merge_overlay``
    # shadow pruning (readonly dependency installed per
    # followups-r12/s01-repair-r25-readonly-dependencies.json) replaced the
    # previous add-only residual this test used to document.  Absence,
    # guards and effect consumers all deny.
    default = default_local_pattern_semantics()
    default.merge_overlay(overlay)
    assert "malloc" in default.contracts.shadowed_symbols
    assert "malloc" not in default.allocators
    assert default.contracts.find("malloc") == []
    assert default.contracts.find_for_call("malloc", usr="") == []
    assert not default.contracts.allows("malloc", "free")
    default_expanded = expand_api_pattern(r"malloc\s*\(", default)
    assert "malloc" not in default_expanded.replace("aligned_alloc", "")
    denied = set(overlay["shadowed_symbols"])
    for attr in MERGE_ATTRS:
        assert not denied & set(getattr(default, attr))
        assert not denied & set(getattr(rebuilt, attr))
    # Preseeded raw pairs stay visible through releases/acquires on the
    # default registry (shared seam); the effect-consuming call sites remain
    # guarded by allows, which denies above.
    assert default.contracts.releases("malloc") == {"free"}


def test_real_native_project_malloc_denied_across_local_and_overlay(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    backend, index, scope = _native_instance(
        tmp_path,
        monkeypatch,
        "#include <stdlib.h>\n"
        "void *malloc(size_t n){return 0;}\n"
        "void f(void){(void)malloc(4);}\n",
    )
    try:
        scoped = ScopedCodeIndex(index, scope)

        snapshot = _snapshot(_build(scoped, scope))

        payload = json.loads(snapshot.effect_payload)
        assert payload["symbol_origins"]["malloc"] == ORIGIN_PROJECT_DEFINED
        local, overlay = materialize_effect_semantics(snapshot)
        assert local.contracts.find("malloc") == []
        assert not local.contracts.allows("malloc", "free")
        assert local.contracts.releases("malloc") == set()
        assert "malloc" in overlay["shadowed_symbols"]
        assert all(
            (row.get("symbol") or {}).get("name") != "malloc" for row in overlay["api_contracts"]
        )
        rebuilt = LocalPatternSemantics()
        rebuilt.merge_overlay(overlay)
        assert "malloc" in rebuilt.contracts.shadowed_symbols
        assert "malloc" not in rebuilt.allocators
        assert rebuilt.contracts.find("malloc") == []
        assert not rebuilt.contracts.allows("malloc", "free")
        # The original default-registry oracle: with the coordinator-provided
        # shared merge_overlay pruning (readonly dependency per
        # followups-r12/s01-repair-r25-readonly-dependencies.json), the
        # preseeded default registry also drops the denied root from its raw
        # allocator bucket.
        default = default_local_pattern_semantics()
        default.merge_overlay(overlay)
        assert "malloc" in default.contracts.shadowed_symbols
        assert "malloc" not in default.allocators
        assert default.contracts.find("malloc") == []
        assert not default.contracts.allows("malloc", "free")
    finally:
        backend.close()


# ── R24 S01-R24-P1-01: factory issuance boundary ──


def test_forged_self_consistent_builtin_contract_is_rejected(tmp_path: Path) -> None:
    scoped, scope = _setup(
        tmp_path, call_rows={"ctx-a": [_call_receipt("malloc"), _call_receipt("free")]}
    )
    snapshot = _snapshot(_build(scoped, scope))
    payload = json.loads(snapshot.effect_payload)
    fake = json.loads(
        json.dumps(next(row for row in payload["contracts"] if row["symbol"]["name"] == "malloc"))
    )
    fake["symbol"] = {"name": "review_fake_alloc"}
    fake["pairs"] = []
    fake["source"] = "builtin_defaults"
    payload["contracts"].append(fake)
    payload["roles"]["allocators"]["review_fake_alloc"] = ["builtin_defaults"]

    forged = _reforged(snapshot, effect=payload)

    with pytest.raises(ValueError):
        materialize_effect_semantics(forged)


def test_modified_builtin_contract_content_with_recomputed_digest_is_rejected(
    tmp_path: Path,
) -> None:
    scoped, scope = _setup(
        tmp_path, call_rows={"ctx-a": [_call_receipt("malloc"), _call_receipt("free")]}
    )
    snapshot = _snapshot(_build(scoped, scope))
    payload = json.loads(snapshot.effect_payload)
    malloc_row = next(row for row in payload["contracts"] if row["symbol"]["name"] == "malloc")
    # Same name and builtin source, different executable content.
    malloc_row["carrier"] = {"kind": "argument", "argument_index": 0}
    malloc_row["effect_cases"] = [{"when": {"op": "true"}, "effect": "applies"}]

    forged = _reforged(snapshot, effect=payload)

    with pytest.raises(ValueError):
        materialize_effect_semantics(forged)


def test_removed_shadow_denial_with_recomputed_digest_is_rejected(tmp_path: Path) -> None:
    source = _write(
        tmp_path,
        "unit.c",
        "void* malloc(unsigned n){return 0;} int f(void){return 0;}\n",
    )
    cdb = _write(tmp_path, "compile_commands.json", "[]\n")
    context = _full_context("ctx-a", source, cdb)
    index = _InstanceIndex(
        [context],
        {
            "ctx-a": [
                _facts("c:@F@f", "f", str(source)),
                _facts("c:@F@malloc", "malloc", str(source)),
            ]
        },
    )
    scope = _scope("ctx-a", "c:@F@f", source)
    scoped = ScopedCodeIndex(index, scope)
    snapshot = _snapshot(_build(scoped, scope))
    assert "malloc" in json.loads(snapshot.effect_payload)["shadowed_symbols"]

    payload = json.loads(snapshot.effect_payload)
    payload["shadowed_symbols"] = [name for name in payload["shadowed_symbols"] if name != "malloc"]
    payload["symbol_origins"]["malloc"] = ORIGIN_SYSTEM_RECEIPT

    forged = _reforged(snapshot, effect=payload)

    with pytest.raises(ValueError):
        materialize_effect_semantics(forged)


def test_forged_pair_checker_and_injected_inferred_advisory_are_rejected(
    tmp_path: Path,
) -> None:
    scoped, scope = _setup(
        tmp_path, call_rows={"ctx-a": [_call_receipt("malloc"), _call_receipt("free")]}
    )
    snapshot = _snapshot(_build(scoped, scope))
    effect = json.loads(snapshot.effect_payload)
    effect["pairs"].append(
        {
            "acquire": {"name": "review_fake_alloc"},
            "release": {"name": "free"},
            "conditions": [],
            "source": "builtin_defaults",
            "evidence": [],
        }
    )
    effect["checker_models"]["resource_models"].append(
        {"name": "review_fake_alloc", "kind": "allocator", "source": "builtin_defaults"}
    )
    with pytest.raises(ValueError):
        materialize_effect_semantics(_reforged(snapshot, effect=effect))

    advisory = json.loads(snapshot.advisory_payload)
    advisory["external_functions"].append(
        {"func_name": "pool_create", "kind": "allocator", "source": "inferred:semantic_modeling"}
    )
    with pytest.raises(ValueError):
        advisory_context(
            _reforged(snapshot, advisory=advisory),
            function_name="f",
            source_text="pool_create();",
            file_path=str(scope.source),
        )


def test_strict_payload_decoder_rejects_adversarial_bytes() -> None:
    with pytest.raises(ValueError):
        _strict_json_loads(b'{"a": 1, "a": 2}')
    with pytest.raises(ValueError):
        _strict_json_loads(b'{"a": NaN}')
    with pytest.raises(ValueError):
        _strict_json_loads(b'{"a": Infinity}')
    with pytest.raises(ValueError):
        _strict_json_loads(b'{"a": \xff}')


# ── R24 S01-R24-P2-04: per-sheet advisory selectors ──


def test_foreign_file_dispatcher_lifecycle_intent_rows_do_not_leak(tmp_path: Path) -> None:
    scoped, scope = _setup(tmp_path)
    workbook = _workbook(
        other=(
            {
                "sheet": "dispatcher",
                "dispatcher_name": "dispatch",
                "handler_name": "handle",
                "file_path": "*/other.c",
                "description": "FOREIGN_DISPATCHER_MARKER",
                "source": "user",
            },
            {
                "sheet": "dispatcher",
                "dispatcher_name": "dispatch",
                "handler_name": "handle",
                "file_path": "*unit.c",
                "description": "LOCAL_DISPATCHER_MARKER",
                "source": "user",
            },
            {
                "sheet": "module_lifecycle",
                "symbol_name": "handle",
                "kind": "init",
                "pair": "",
                "file_path": "*/other.c",
                "description": "FOREIGN_LIFECYCLE_MARKER",
                "source": "user",
            },
            {
                "sheet": "module_lifecycle",
                "symbol_name": "handle",
                "kind": "init",
                "pair": "",
                "file_path": "*unit.c",
                "description": "LOCAL_LIFECYCLE_MARKER",
                "source": "user",
            },
            {
                "symbol_name": "other_func",
                "file_path": "",
                "intents": "returns owned memory",
                "source": "user",
            },
            {
                "symbol_name": "f",
                "file_path": "",
                "intents": "expects caller-owned buffer",
                "source": "user",
            },
        ),
    )
    snapshot = _snapshot(_build(scoped, scope, workbook=workbook))

    text = advisory_context(
        snapshot,
        function_name="f",
        source_text="handle();",
        file_path=str(scope.source),
    )

    assert "FOREIGN_DISPATCHER_MARKER" not in text
    assert "FOREIGN_LIFECYCLE_MARKER" not in text
    assert "returns owned memory" not in text
    assert "LOCAL_DISPATCHER_MARKER" in text
    assert "LOCAL_LIFECYCLE_MARKER" in text
    assert "expects caller-owned buffer" in text
    assert ADVISORY_AUTHORITY in text


# ── S01-N06 / R23-CONTRACT-N1: currency is the full context-input check ──


def test_stale_source_dependency_rejects_build(tmp_path: Path) -> None:
    scoped, scope = _setup(tmp_path)
    Path(scope.source).write_text("int f(void){return 1;}\n", encoding="utf-8")

    result = _build(scoped, scope)

    assert isinstance(result, SemanticsUnavailable)
    assert result.reason == "dependencies_not_current:stale_build_context"


def test_stale_compilation_database_rejects_build_even_with_current_dependencies(
    tmp_path: Path,
) -> None:
    scoped, scope = _setup(tmp_path)
    cdb = tmp_path / "compile_commands.json"
    cdb.write_text('[{"arguments": ["clang"], "file": "unit.c"}]\n', encoding="utf-8")
    # The recorded dependency digests only cover the source file, so the
    # dependency-only status stays current; the full context-input check
    # must still reject the changed compilation database.
    assert scoped.dependencies_current_status() == "current"

    result = _build(scoped, scope)

    assert isinstance(result, SemanticsUnavailable)
    assert result.reason == "context_inputs_not_current:stale_compilation_database"


def test_stale_build_command_rejects_build(tmp_path: Path) -> None:
    source = _write(tmp_path, "unit.c", "int f(void){return 0;}\n")
    cdb = _write(tmp_path, "compile_commands.json", "[]\n")
    context = _full_context("ctx-a", source, cdb)
    context["command"] = {
        **context["command"],
        "arguments": ["clang", "-c", "-O2", str(source)],
    }
    index = _InstanceIndex([context], {"ctx-a": [_facts("c:@F@f", "f", str(source))]})
    scope = _scope("ctx-a", "c:@F@f", source)
    scoped = ScopedCodeIndex(index, scope)

    result = _build(scoped, scope)

    assert isinstance(result, SemanticsUnavailable)
    assert result.reason == "context_inputs_not_current:stale_build_command"


def test_new_include_search_entry_rejects_build(tmp_path: Path) -> None:
    scoped, scope = _setup(tmp_path)
    _write(tmp_path, "rogue_header.h", "int rogue;\n")

    result = _build(scoped, scope)

    assert isinstance(result, SemanticsUnavailable)
    assert result.reason == "context_inputs_not_current:stale_include_search"


def test_stale_include_probe_rejects_build(tmp_path: Path) -> None:
    source = _write(tmp_path, "unit.c", "int f(void){return 0;}\n")
    cdb = _write(tmp_path, "compile_commands.json", "[]\n")
    context = _full_context("ctx-a", source, cdb)
    context["include_probes"] = {
        "version": "zscope.include-probes.v1",
        "search_directories": [str(tmp_path)],
        "queries": [
            {
                "name": "stdlib.h",
                "angled": True,
                "found": True,
                "target_file": str(tmp_path / "missing_stdlib.h"),
            }
        ],
    }
    index = _InstanceIndex([context], {"ctx-a": [_facts("c:@F@f", "f", str(source))]})
    scope = _scope("ctx-a", "c:@F@f", source)
    scoped = ScopedCodeIndex(index, scope)

    result = _build(scoped, scope)

    assert isinstance(result, SemanticsUnavailable)
    assert result.reason == "context_inputs_not_current:stale_include_probe"


def test_unknown_build_context_rejects_build(tmp_path: Path) -> None:
    scoped, pinned = _setup(tmp_path)
    # An index that binds the missing scope (not the ctx-a facade, which must
    # first reject the foreign scope as a mismatch) still finds no pinned
    # build record, so the instance stays explicitly unknown.
    missing = replace(pinned, build_context_id="ctx-gone", identity="ctx-gone:x")
    scoped_gone = ScopedCodeIndex(scoped.base_index(), missing)

    result = _build(scoped_gone, missing)

    assert isinstance(result, SemanticsUnavailable)
    assert result.reason == "dependencies_not_current:unknown_build_context"


def test_missing_entry_receipt_rejects_build(tmp_path: Path) -> None:
    source = _write(tmp_path, "unit.c", "int f(void){return 0;}\n")
    cdb = _write(tmp_path, "compile_commands.json", "[]\n")
    context = _full_context("ctx-a", source, cdb)
    index = _InstanceIndex([context], {"ctx-a": []})
    scope = _scope("ctx-a", "c:@F@f", source)
    scoped = ScopedCodeIndex(index, scope)

    result = _build(scoped, scope)

    assert isinstance(result, SemanticsUnavailable)
    assert result.reason == "entry_receipt_unavailable:function_identity_not_found"


# ── Dependency fingerprint and input shape rejections ──


def test_dependency_fingerprint_mismatch_rejects_build(tmp_path: Path) -> None:
    scoped, scope = _setup(tmp_path)

    stale_compiler = _build(
        scoped, scope, dependencies=_dependencies(compiler_version="zscope.contract-compiler.v0")
    )
    assert isinstance(stale_compiler, SemanticsUnavailable)
    assert stale_compiler.reason == "stale_compiler_version"

    stale_payload = _build(
        scoped,
        scope,
        dependencies=_dependencies(builtin_payload_sha256=hashlib.sha256(b"other").hexdigest()),
    )
    assert isinstance(stale_payload, SemanticsUnavailable)
    assert stale_payload.reason == "stale_builtin_payload"

    invalid_answers = _build(scoped, scope, dependencies=_dependencies(business_answers_sha256=""))
    assert isinstance(invalid_answers, SemanticsUnavailable)
    assert invalid_answers.reason == "invalid_dependency_digest:business_answers_sha256"

    invalid_workbook = _build(
        scoped, scope, workbook=FrozenWorkbookRows("not-a-digest", (), (), ())
    )
    assert isinstance(invalid_workbook, SemanticsUnavailable)
    assert invalid_workbook.reason == "invalid_workbook_digest"


def test_inexact_scope_and_unscoped_index_rejected(tmp_path: Path) -> None:
    scoped, scope = _setup(tmp_path)
    index = scoped.base_index()

    unscoped = build_instance_semantics(
        scope=scope,
        scoped_index=index,  # type: ignore[arg-type]
        workbook=_workbook(),
        dependencies=_dependencies(),
    )
    assert isinstance(unscoped, SemanticsUnavailable)
    assert unscoped.reason == "scoped_index_required"

    nameless = replace(scope, usr="", identity="ctx-a:")
    result = _build(scoped, nameless)
    assert isinstance(result, SemanticsUnavailable)
    assert result.reason == "inexact_instance_scope"


# ── S01-P03: independent per-consumer copies ──


def test_materializations_are_independent_deep_copies(tmp_path: Path) -> None:
    scoped, scope = _setup(
        tmp_path, call_rows={"ctx-a": [_call_receipt("malloc"), _call_receipt("free")]}
    )
    snapshot = _snapshot(_build(scoped, scope))

    first_semantics, first_overlay = materialize_effect_semantics(snapshot)
    second_semantics, second_overlay = materialize_effect_semantics(snapshot)

    assert first_semantics is not second_semantics
    assert first_semantics.contracts is not second_semantics.contracts
    first_semantics.allocators["injected"] = ["user"]
    first_semantics.contracts.shadowed_symbols.add("free")
    first_semantics.contracts.contracts.clear()
    first_overlay["api_contracts"].clear()
    assert "injected" not in second_semantics.allocators
    assert "free" not in second_semantics.contracts.shadowed_symbols
    assert second_semantics.contracts.contracts
    assert second_overlay["api_contracts"]
    third_semantics, _ = materialize_effect_semantics(snapshot)
    assert "injected" not in third_semantics.allocators
    assert third_semantics.contracts.find("free", "deallocator")


def test_materialized_overlay_reports_exact_project_contracts(tmp_path: Path) -> None:
    scoped, scope = _setup(tmp_path)
    project_contract = {
        "symbol": {
            "name": "project_alloc",
            "file_path": scope.source,
            "signature": "void *(unsigned long)",
            "symbol_type": "function",
            "build_context_id": scope.build_context_id,
            "usr": "c:@F@project_alloc",
        },
        "role": "allocator",
        "carrier": {"kind": "return"},
        "pairs": [{"name": "free"}],
        "resource_family": "heap",
        "source": "inferred:project_semantics:project:function:project_alloc",
        "status": "confirmed",
        "preconditions": {"op": "true"},
        "effect_cases": [],
        "protocol": {},
        "evidence": [],
        "verification": {
            "method": "source_composition",
            "compiler_version": CONTRACT_COMPILER_VERSION,
            "effect_strength": "must_under_guard",
            "source_hash": "a" * 64,
            "identity_verified": True,
            "project_semantics_id": "project:function:project_alloc",
            "authority": "native_current",
        },
    }
    snapshot = _snapshot(_build(scoped, scope, project_contracts_override=[project_contract]))

    semantics, overlay = materialize_effect_semantics(snapshot)

    # A materialization belongs to one exact instance.  Consumers make a
    # restricted copy before binding an individual call, so the registry must
    # carry that BuildContext already; otherwise every exact project contract
    # is filtered out while build-less builtin roots survive.
    assert semantics.contracts.build_context_id == scope.build_context_id
    assert semantics.contracts.find("project_alloc", "allocator")
    assert semantics.contracts.find(
        "project_alloc", "allocator", build_context_id=scope.build_context_id
    )
    assert len(overlay["project_contracts"]) == 1
    reported_symbol = overlay["project_contracts"][0]["symbol"]
    assert reported_symbol["name"] == "project_alloc"
    assert reported_symbol["usr"] == "c:@F@project_alloc"
    assert reported_symbol["build_context_id"] == scope.build_context_id
    assert overlay["project_contracts"][0]["verification"] == project_contract["verification"]
    assert overlay["project_semantics"] == {
        "contracts": 1,
        "assumptions": 0,
        "contract_ids": ["project:function:project_alloc"],
    }

    from zscope.core.candidates.regex import _restricted_semantics

    restricted = _restricted_semantics(semantics)
    assert restricted.contracts.find("project_alloc", "allocator")
    caller = {
        "func_name": "f",
        "file_path": scope.source,
        "build_context_id": scope.build_context_id,
        "code": "int f(void) { void *p = project_alloc(1); return p != 0; }",
        "program_facts": {
            "complete": True,
            "build_context_id": scope.build_context_id,
            "function_identity": {
                "build_context_id": scope.build_context_id,
                "usr": scope.usr,
            },
            "functions": [
                {
                    "complete": True,
                    "owner": {"name": "f", "usr": scope.usr},
                    "events": [
                        {
                            "event_kind": "call",
                            "callee": {
                                "name": "project_alloc",
                                "usr": "c:@F@project_alloc",
                            },
                        }
                    ],
                }
            ],
        },
    }
    project_events = restricted.contracts.trace_calls(caller)
    assert [event["source"] for event in project_events] == [project_contract["source"]]
    assert project_events[0]["symbol"]["usr"] == "c:@F@project_alloc"
    assert project_events[0]["effects_trusted"] is True


# ── Snapshot identity binding and fail-closed decoding ──


def test_snapshot_digest_binds_identity_components(tmp_path: Path) -> None:
    scoped, scope = _setup(tmp_path)
    base = _snapshot(_build(scoped, scope))
    other_workbook = _snapshot(_build(scoped, scope, workbook=_workbook(label="workbook-v2")))
    other_answers = _snapshot(
        _build(
            scoped,
            scope,
            dependencies=_dependencies(
                business_answers_sha256=hashlib.sha256(b"answers-v2").hexdigest()
            ),
        )
    )
    with_manual_row = _snapshot(
        _build(
            scoped,
            scope,
            workbook=_workbook(external=({"func_name": "extra_api", "source": "user"},)),
        )
    )
    with_inferred_row = _snapshot(
        _build(
            scoped,
            scope,
            workbook=_workbook(external=({"func_name": "extra_api", "source": "inferred:x"},)),
        )
    )
    digests = {
        base.digest,
        other_workbook.digest,
        other_answers.digest,
        with_manual_row.digest,
        with_inferred_row.digest,
    }
    assert len(digests) == 5


def test_tampered_snapshot_fails_closed(tmp_path: Path) -> None:
    scoped, scope = _setup(
        tmp_path, call_rows={"ctx-a": [_call_receipt("malloc"), _call_receipt("free")]}
    )
    snapshot = _snapshot(_build(scoped, scope))

    swapped = replace(snapshot, effect_payload=FrozenJSON(snapshot.effect_payload + b" "))
    with pytest.raises(ValueError):
        materialize_effect_semantics(swapped)

    tampered_advisory = replace(
        snapshot, advisory_payload=FrozenJSON(b'{"advisory_authority": "effects"}')
    )
    with pytest.raises(ValueError):
        advisory_context(
            tampered_advisory, function_name="f", source_text="", file_path=str(scope.source)
        )

    # Self-consistent digests do not rescue forged content: provenance is the
    # factory issuance boundary, not digest self-consistency.
    payload = json.loads(snapshot.effect_payload)
    payload["contracts"][0]["source"] = "user"
    with pytest.raises(ValueError):
        materialize_effect_semantics(_reforged(snapshot, effect=payload))

    with pytest.raises(ValueError):
        materialize_effect_semantics(
            _reforged(snapshot, effect=b'{"schema": "zscope.instance-semantics.v1", "v": NaN}')
        )

    with pytest.raises(ValueError):
        materialize_effect_semantics(_reforged(snapshot, effect=b'{"schema": "a", "schema": "b"}'))


def test_freeze_workbook_rows_rejects_non_json_values() -> None:
    with pytest.raises(ValueError):
        freeze_workbook_rows(
            workbook_sha256=hashlib.sha256(b"w").hexdigest(),
            external_rows=({"func_name": "x", "confidence": float("nan")},),
        )
    with pytest.raises(ValueError):
        freeze_workbook_rows(
            workbook_sha256=hashlib.sha256(b"w").hexdigest(),
            external_rows=({"func_name": "x", "tags": {1, 2}},),
        )
    with pytest.raises(ValueError):
        freeze_workbook_rows(
            workbook_sha256=hashlib.sha256(b"w").hexdigest(),
            external_rows=({1: "x"},),
        )


def test_non_canonical_workbook_bytes_rejected(tmp_path: Path) -> None:
    scoped, scope = _setup(tmp_path)
    workbook = FrozenWorkbookRows(
        hashlib.sha256(b"w").hexdigest(),
        (FrozenJSON(b'{"func_name": "x", "func_name": "y"}'),),
        (),
        (),
    )

    result = _build(scoped, scope, workbook=workbook)

    assert isinstance(result, SemanticsUnavailable)
    assert result.reason == "workbook_row_not_canonical_json"


def test_builtin_fingerprint_is_stable_and_accepted(tmp_path: Path) -> None:
    first = builtin_semantics_fingerprint()
    second = builtin_semantics_fingerprint()
    assert first == second
    assert first["compiler_version"] == CONTRACT_COMPILER_VERSION
    assert first["standard_api_version"].startswith("zscope.standard-api.")
    digest = first["builtin_payload_sha256"]
    assert len(digest) == 64 and all(char in "0123456789abcdef" for char in digest)

    scoped, scope = _setup(tmp_path)
    snapshot = _snapshot(_build(scoped, scope))
    assert snapshot.dependencies.builtin_payload_sha256 == first["builtin_payload_sha256"]


# ── Isolation: scoped queries only, no project-wide traversal ──


def test_build_uses_only_pinned_scoped_queries(tmp_path: Path) -> None:
    scoped, scope = _setup(tmp_path)
    index = scoped.base_index()

    _snapshot(_build(scoped, scope))

    assert isinstance(index, _InstanceIndex)
    assert f"facts:ctx-a:{scope.usr}" in index.calls
    assert "receipts:ctx-a:call" in index.calls
    assert all(
        call == "get_build_contexts"
        or call.startswith("facts:ctx-a:")
        or call == "receipts:ctx-a:call"
        or call == "receipts:ctx-a:macro_reference,symbol_reference"
            or call == "receipts:ctx-a:program_function"
        for call in index.calls
    )


# R31 additions. The complete pre-R31 file above is retained byte for byte.
# Older synthetic positives supplied only a system-marked call and a source
# digest. They now need the same additional input shapes as the production
# verifier. This file-local fixture strengthens those synthetic prerequisites;
# it neither changes an old assertion nor patches the production verifier or
# native CodeIndex. Independent immutable probes and real native tests obtain
# their own actual receipts. Synthetic receipts still prove isolation only.
_R31_ORIGINAL_FULL_CONTEXT = _full_context
_R31_ORIGINAL_GET_FACTS = _InstanceIndex.get_compilation_facts


@pytest.fixture(autouse=True)
def _r31_synthetic_origin_inputs(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import sys

    tool = _write(tmp_path, "synthetic-native-tool-input", "synthetic identity fixture only\n")
    tool_digest = file_digest(tool)

    def context_with_standard_inputs(*args: Any, **kwargs: Any) -> Dict[str, Any]:
        context = _R31_ORIGINAL_FULL_CONTEXT(*args, **kwargs)
        context["target"] = {
            "target.triple": "x86_64-pc-linux-gnu",
            "target.libc": "glibc",
            "target.pointer_bits": 64,
        }
        context["tool"] = {
            "binary": {"path": str(tool), "sha256": tool_digest, "shared_libraries": {}},
            "capability": {"protocol": "zscope.clang-facts.v2", "target_origin_version": 1},
        }
        for path in ("/usr/include/stdlib.h", "/usr/include/features.h"):
            context["dependencies"][path] = file_digest(Path(path))
        context["include_probes"] = {
            "version": "zscope.include-probes.v1",
            "search_directories": ["/usr/include"],
            "queries": [],
        }
        context["r31_synthetic_origin_fixture"] = True
        return context

    def facts_with_standard_include(
        self: _InstanceIndex,
        context_id: str,
        *,
        kinds: Tuple[str, ...] = (),
        symbol: str = "",
        file_path: str = "",
    ) -> List[Dict[str, Any]]:
        rows = _R31_ORIGINAL_GET_FACTS(
            self, context_id, kinds=kinds, symbol=symbol, file_path=file_path
        )
        context = next((row for row in self.contexts if row["build_context_id"] == context_id), {})
        calls = self.call_rows.get(context_id, [])
        if (
            "include" in kinds
            and context.get("r31_synthetic_origin_fixture")
            and any(
                (row.get("target", {}).get("declaration") or {}).get("file")
                == "/usr/include/stdlib.h"
                for row in calls
            )
        ):
            rows.append(
                {
                    "kind": "include",
                    "target_file": "/usr/include/stdlib.h",
                    "location": {"file": context["command"]["source"], "line": 1},
                }
            )
        return rows

    monkeypatch.setattr(sys.modules[__name__], "_full_context", context_with_standard_inputs)
    monkeypatch.setattr(_InstanceIndex, "get_compilation_facts", facts_with_standard_include)


@pytest.mark.parametrize(
    "flag",
    ["-I", "-isystem", "-isystem-after", "-iquote", "-idirafter", "-isysroot"],
)
@pytest.mark.parametrize("spelling", ["split", "joined", "equals"])
def test_r31_include_grammar_retains_every_supported_root(
    tmp_path: Path, flag: str, spelling: str
) -> None:
    from zscope.semantics.instance_semantics import _user_include_roots

    vendor = tmp_path / "vendor"
    vendor.mkdir()
    flags = (
        [flag, "vendor"]
        if spelling == "split"
        else [flag + ("=" if spelling == "equals" else "") + "vendor"]
    )
    roots, unknown = _user_include_roots(
        {
            "directory": str(tmp_path),
            "source": str(tmp_path / "unit.c"),
            "arguments": ["clang", *flags],
        }
    )
    assert vendor.resolve() in roots
    assert unknown is (flag == "-isysroot")


@pytest.mark.parametrize(
    "flags",
    [
        ["-isystem"],
        ["-isystem", "-c"],
        ["-isystemmissing-directory"],
        ["-iwithsysrootcustom"],
        ["-Xclang", "-internal-isystem"],
        ["-ivfsoverlay", "virtual.yaml"],
        ["--config=custom.cfg"],
        ["-resource-dir=custom"],
        ["-working-directory=/tmp"],
        ["--include-directory=/tmp"],
        ["-stdlib++-isystem/tmp"],
        ["--sysroot=/"],
    ],
)
def test_r31_unknown_include_surfaces_cannot_authorize_host_builtin(
    tmp_path: Path, flags: List[str]
) -> None:
    source = _write(tmp_path, "unit.c", "int f(void){return 0;}\n")
    cdb = _write(tmp_path, "compile_commands.json", "[]\n")
    context = _full_context("ctx-a", source, cdb, arguments=["clang", *flags, "-c", str(source)])
    index = _InstanceIndex(
        [context],
        {"ctx-a": [_facts("c:@F@f", "f", str(source))]},
        {"ctx-a": [_call_receipt("malloc")]},
    )
    scope = _scope("ctx-a", "c:@F@f", source)
    snapshot = _snapshot(_build(ScopedCodeIndex(index, scope), scope))
    local, overlay = materialize_effect_semantics(snapshot)
    assert overlay["symbol_origins"]["malloc"] == ORIGIN_UNVERIFIABLE_COMMAND
    assert "malloc" in overlay["shadowed_symbols"]
    assert "malloc" not in local.allocators
    assert local.contracts.find("malloc") == []


@pytest.mark.parametrize(
    "missing",
    [
        "target",
        "libc",
        "pointer_bits",
        "triple",
        "tool",
        "tool_digest",
        "libraries",
        "stdlib",
        "features",
        "native_search",
        "native_include",
    ],
)
def test_r31_standard_source_needs_each_positive_witness(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, missing: str
) -> None:
    from zscope.semantics.instance_semantics import ORIGIN_STANDARD_SOURCE_UNPROVEN

    scoped, scope = _setup(tmp_path, call_rows={"ctx-a": [_call_receipt("malloc")]})
    index = scoped.base_index()
    context = index.contexts[0]
    if missing == "target":
        del context["target"]
    elif missing in {"libc", "pointer_bits", "triple"}:
        del context["target"][f"target.{missing}"]
    elif missing == "tool":
        del context["tool"]
    elif missing == "tool_digest":
        context["tool"]["binary"]["sha256"] = "0" * 64
    elif missing == "libraries":
        del context["tool"]["binary"]["shared_libraries"]
    elif missing in {"stdlib", "features"}:
        del context["dependencies"][f"/usr/include/{missing}.h"]
    elif missing == "native_search":
        del context["include_probes"]
    else:
        monkeypatch.setattr(_InstanceIndex, "get_compilation_facts", _R31_ORIGINAL_GET_FACTS)
    snapshot = _snapshot(_build(scoped, scope))
    local, overlay = materialize_effect_semantics(snapshot)
    assert overlay["symbol_origins"]["malloc"] == ORIGIN_STANDARD_SOURCE_UNPROVEN
    assert "malloc" in overlay["shadowed_symbols"]
    assert "malloc" not in local.allocators
    assert local.contracts.find("malloc") == []


def test_r31_unknown_context_cannot_use_call_identity_as_source_witness(tmp_path: Path) -> None:
    from zscope.semantics.instance_semantics import ORIGIN_STANDARD_SOURCE_UNPROVEN

    source = _write(tmp_path, "unit.c", "int f(void){return 0;}\n")
    cdb = _write(tmp_path, "compile_commands.json", "[]\n")
    context = _R31_ORIGINAL_FULL_CONTEXT("ctx-a", source, cdb)
    index = _InstanceIndex(
        [context],
        {"ctx-a": [_facts("c:@F@f", "f", str(source))]},
        {"ctx-a": [_call_receipt("malloc")]},
    )
    scope = _scope("ctx-a", "c:@F@f", source)
    snapshot = _snapshot(_build(ScopedCodeIndex(index, scope), scope))
    local, overlay = materialize_effect_semantics(snapshot)
    assert overlay["symbol_origins"]["malloc"] == ORIGIN_STANDARD_SOURCE_UNPROVEN
    assert "malloc" not in local.allocators


def _r31_native_with_flags(
    root: Path, monkeypatch: pytest.MonkeyPatch, source_text: str, flags: List[str]
) -> Tuple[Any, Any, InstanceScope]:
    import os

    from test_instance_analysis import _native_index
    from zscope.orchestration.entry_instances import plan_entry_instances
    from zscope.retrieval.clang_backend import ClangBackend
    from zscope.retrieval.instance_index import instance_scope_from_entry_instance

    executable = os.environ.get("Z_SCOPE_TEST_CLANG_INDEXER")
    if not executable:
        pytest.skip("real batch indexer required")
    source = _write(root, "unit.c", source_text)
    cdb = _write(
        root,
        "compile_commands.json",
        json.dumps(
            [
                {
                    "directory": str(root),
                    "file": str(source),
                    "arguments": ["clang", *flags, "-c", str(source)],
                }
            ]
        ),
    )
    monkeypatch.setattr(
        ClangBackend, "_ensure_extractor", lambda self: pytest.fail("LSP fallback forbidden")
    )
    backend = ClangBackend(frontend="batch", clang_indexer_path=executable, max_threads=1)
    assert backend.initialize(str(root), compile_commands_path=str(cdb))
    index = _native_index(backend, root, cdb)
    plan = plan_entry_instances(index, [FunctionEntry("f", file_path="unit.c")])
    assert len(plan.instances) == 1
    return backend, index, instance_scope_from_entry_instance(plan.instances[0])


@pytest.mark.parametrize("form", ["joined_isystem", "pragma_relative", "pragma_outside_source"])
def test_r31_real_native_same_abi_custom_origin_is_denied(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, form: str
) -> None:
    root = tmp_path / "source"
    root.mkdir()
    vendor = (tmp_path if form == "pragma_outside_source" else root) / "vendor"
    vendor.mkdir()
    header = _write(
        vendor, "custom_alloc.h", "#pragma GCC system_header\nvoid *malloc(unsigned long);\n"
    )
    if form == "joined_isystem":
        include, flags = "#include <custom_alloc.h>\n", ["-isystem" + str(vendor)]
    else:
        include = (
            '#include "'
            + ("../" if form == "pragma_outside_source" else "")
            + 'vendor/custom_alloc.h"\n'
        )
        flags = []
    backend, index, scope = _r31_native_with_flags(
        root, monkeypatch, include + "void f(void){(void)malloc(4);}\n", ["-fno-builtin", *flags]
    )
    try:
        targets = [
            row["target"]
            for row in index.get_compilation_facts(scope.build_context_id, kinds=("call",))
            if row.get("target", {}).get("name") == "malloc"
        ]
        assert targets
        assert all(row["is_system_header"] is True for row in targets)
        assert all(row["canonical_signature"] == _STD_SIGNATURES["malloc"] for row in targets)
        assert all(row["usr"] == "c:@F@malloc" for row in targets)
        assert all(
            Path(row["declaration"]["file"]).resolve() == header.resolve() for row in targets
        )
        snapshot = _snapshot(_build(ScopedCodeIndex(index, scope), scope))
        local, overlay = materialize_effect_semantics(snapshot)
        assert "malloc" in overlay["shadowed_symbols"]
        assert "malloc" not in local.allocators
        assert local.contracts.find("malloc") == []
    finally:
        backend.close()


def test_r31_real_standard_origin_survives_unrelated_user_include_and_rechecks_inputs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    vendor = tmp_path / "vendor"
    vendor.mkdir()
    dependency = _write(tmp_path, "guard.h", "#define LOCAL_GUARD 1\n")
    backend, index, scope = _r31_native_with_flags(
        tmp_path,
        monkeypatch,
        '#include "guard.h"\n#include <stdlib.h>\nvoid f(void){void *p=malloc(4);free(p);}\n',
        ["-isystem" + str(vendor)],
    )
    try:
        scoped = ScopedCodeIndex(index, scope)
        snapshot = _snapshot(_build(scoped, scope))
        local, overlay = materialize_effect_semantics(snapshot)
        assert "malloc" in local.allocators and "free" in local.deallocators
        assert overlay["symbol_origins"]["malloc"] == ORIGIN_SYSTEM_RECEIPT
        assert overlay["symbol_origins"]["free"] == ORIGIN_SYSTEM_RECEIPT
        dependency.write_text("#define LOCAL_GUARD 2\n", encoding="utf-8")
        stale = _build(scoped, scope)
        assert isinstance(stale, SemanticsUnavailable)
        assert "current" in stale.reason or "stale" in stale.reason
    finally:
        backend.close()


@pytest.mark.parametrize("signature,system,expected", [
    ("int (int, struct sockaddr *, unsigned int *)", True, ORIGIN_SYSTEM_RECEIPT),
    ("int (int, __SOCKADDR_ARG, unsigned int *)", True, ORIGIN_SYSTEM_RECEIPT),
    ("int (int, void *, unsigned int *)", True, ORIGIN_SIGNATURE_MISMATCH),
    ("int (int, struct sockaddr *, unsigned int *)", False, ORIGIN_NON_SYSTEM_RECEIPT),
])
def test_accept_declaration_variants_keep_origin_gates(tmp_path, signature, system, expected):
    from zscope.semantics.instance_semantics import _builtin_origin_status
    from types import SimpleNamespace
    header = tmp_path / "socket.h"
    header.write_text("/* receipt fixture */")
    target = _call_receipt("accept", system=system, signature=signature, declaration_file=str(header))["target"]
    index = SimpleNamespace(get_function_program_facts=lambda *args: {"functions": [], "reason": "function_identity_not_found"})
    assert _builtin_origin_status(index, "accept", [("accept", target)], [], False, frozenset({header})) == expected
