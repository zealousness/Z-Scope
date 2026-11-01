from __future__ import annotations

import hashlib
import json
from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace

import pytest

from zscope.config.project_semantics import (
    EFFECT_CONSUMERS,
    ProjectSemanticsError,
    ProjectSemanticsStore,
    compiled_project_contracts,
    empty_project_semantics,
    rebind_project_semantics,
    semantics_readiness,
    validate_project_semantics,
)
from zscope.config.user_config_store import UserConfigStore
from zscope.orchestration.primitive_discovery import (
    _bind_configured_primitives,
    _configured_discovery_contracts,
    _dispatcher_candidates,
    _exact_pointer_bindings,
    _human_discovery_receipt,
    _stream_function_work,
    _lock_wrapper_candidate,
    _macro_candidates,
    _macro_reference_bindings,
    _cxx_new_factory_candidate,
    _owned_object_factory_candidate,
    _returned_aggregate_member_factory_candidate,
    _candidate_review_payloads,
    _payload_batches,
    _review_discovery_candidates,
    _semantics_relevant_scopes,
)
from zscope.orchestration.instance_semantics_context import freeze_project_semantics
from zscope.retrieval.instance_index import InstanceScope
from zscope.semantics.contracts import ApiContract, ContractRegistry, ObjectBinding, SymbolIdentity
from zscope.semantics.c_linux_catalog import (
    CATALOG_VERSION,
    catalog_audit,
    classification_for,
)


def _sha(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _interface(root: Path, *, status: str = "confirmed") -> dict:
    source = root / "memory.c"
    source.write_text("void *project_alloc(unsigned long n) { return 0; }\n", encoding="utf-8")
    digest = _sha(source.read_bytes())
    return {
        "id": "project:allocator",
        "primitive": True,
        "selector": {
            "kind": "function",
            "name": "project_alloc",
            "file": "memory.c",
            "signature": "void *(unsigned long)",
            "usr": "c:@F@project_alloc",
        },
        "basis": "expected_contract",
        "status": status,
        "cases": [{"when": {"op": "true"}, "effect": "applies"}],
        "effects": [
            {
                "domain": "resource",
                "role": "allocator",
                "operation": "allocate",
                "carrier": {
                    "root": "return",
                    "phase": "post",
                    "dereference": 0,
                    "members": [],
                },
                "strength": "must_under_guard",
                "resource_family": "heap",
            }
        ],
        "otherwise": "unknown",
        "pairs": ["builtin:free"],
        "derived_from": [],
        "evidence_summary": "Reviewed native wrapper.",
        "evidence_ref": ".zscope_snapshots/semantics/evidence.json#project:allocator",
        "evidence_digest": digest,
        "variants": [
            {
                "target_id": "main",
                "build_context_id": "build-a",
                "usr": "c:@F@project_alloc",
                "signature": "void *(unsigned long)",
                "file": "memory.c",
                "source_sha256": digest,
                "evidence_sha256": digest,
                "native_input_hash": digest,
                "identity_status": "exact",
            }
        ],
        "review_note": "keep this extension and its comment",
    }


def _document(root: Path, *, status: str = "confirmed") -> dict:
    document = empty_project_semantics()
    document["interfaces"] = [_interface(root, status=status)]
    document["discovery_receipt"] = {"schema": "zscope.primitive-discovery.v1"}
    return document


def test_configured_primitive_short_cpp_name_binds_only_when_file_is_unique(
    tmp_path: Path,
) -> None:
    source = tmp_path / "env_posix.cc"
    source.write_text("void placeholder() {}\n", encoding="utf-8")
    document = _document(tmp_path, status="pending")
    row = document["interfaces"][0]
    row["selector"] = {"kind": "function", "name": "LockFile", "file": source.name}
    scope = InstanceScope(
        build_context_id="build-a",
        usr="c:@N@leveldb@S@PosixEnv@F@LockFile#",
        identity="build-a:c:@N@leveldb@S@PosixEnv@F@LockFile#",
        source=str(source),
        function_names=("leveldb::(anonymous namespace)::PosixEnv::LockFile",),
        selected_by="test",
    )
    work = {
        "build-a": [
            (
                scope,
                {"file": str(source)},
                {},
                "leveldb::(anonymous namespace)::PosixEnv::LockFile",
                "Status (const std::string &, FileLock **)",
            )
        ]
    }

    bound, gaps = _bind_configured_primitives(document, root=tmp_path, work=work)

    assert gaps == []
    assert bound[0]["selector"]["name"] == (
        "leveldb::(anonymous namespace)::PosixEnv::LockFile"
    )
    assert bound[0]["selector"]["usr"] == scope.usr
    assert bound[0]["variants"][0]["identity_status"] == "exact"


def test_discovery_alone_can_bind_a_confirmed_unbound_primitive_proposal(
    tmp_path: Path,
) -> None:
    path = tmp_path / "zscope.semantics.yaml"
    document = _document(tmp_path)
    row = document["interfaces"][0]
    current_variants = deepcopy(row.pop("variants"))
    path.write_text(json.dumps(document), encoding="utf-8")
    store = ProjectSemanticsStore(path)

    with pytest.raises(ProjectSemanticsError, match="exact native variant"):
        store.read()
    proposal = store.read(allow_unbound_primitive_proposals=True)
    assert proposal["interfaces"][0]["status"] == "confirmed"

    rebound = deepcopy(row)
    rebound["variants"] = current_variants
    rebound["evidence_digest"] = "f" * 64
    stats = store.merge_discovery(
        interfaces=[rebound],
        receipt={"schema": "zscope.primitive-discovery.v1"},
        allow_unbound_primitive_proposals=True,
    )

    assert stats["stale"] == 1
    persisted = store.read()
    assert persisted["interfaces"][0]["status"] == "stale"
    assert persisted["interfaces"][0]["variants"] == current_variants


def test_discovery_freeze_accepts_only_explicit_unbound_primitive_proposals(
    tmp_path: Path,
) -> None:
    path = tmp_path / "zscope.semantics.yaml"
    document = _document(tmp_path)
    document["interfaces"][0].pop("variants")
    path.write_text(json.dumps(document), encoding="utf-8")

    with pytest.raises(ProjectSemanticsError, match="exact native variant"):
        freeze_project_semantics(path)

    frozen = freeze_project_semantics(
        path,
        allow_unbound_primitive_proposals=True,
    )
    thawed = json.loads(bytes(frozen.project_document))
    assert thawed["interfaces"][0]["primitive"] is True
    assert thawed["interfaces"][0]["status"] == "confirmed"


def test_discovery_relaxation_does_not_authorize_unbound_derived_interfaces(
    tmp_path: Path,
) -> None:
    document = _document(tmp_path)
    row = document["interfaces"][0]
    row["primitive"] = False
    row["basis"] = "derived_wrapper"
    row.pop("variants")

    with pytest.raises(ProjectSemanticsError, match="exact native variant"):
        validate_project_semantics(document, allow_unbound_primitive_proposals=True)


def test_round_trip_preserves_comments_order_and_interface_extensions(tmp_path: Path) -> None:
    path = tmp_path / "zscope.semantics.yaml"
    document = _document(tmp_path)
    path.write_text(
        "# reviewer-owned header\n"
        "schema_version: zscope.project-semantics.v1\n"
        "interfaces: [] # reviewed rows\n"
        "dispatchers: []\n"
        "function_pointer_bindings: []\n"
        "discovery_receipt: {}\n",
        encoding="utf-8",
    )

    ProjectSemanticsStore(path).write(document)

    rendered = path.read_text(encoding="utf-8")
    assert rendered.startswith("# reviewer-owned header\n")
    assert "interfaces:" in rendered and "# reviewed rows" in rendered
    assert "review_note: keep this extension and its comment" in rendered
    assert list(ProjectSemanticsStore(path).read()) == [
        "schema_version",
        "interfaces",
        "dispatchers",
        "function_pointer_bindings",
        "discovery_receipt",
    ]


def test_discovery_never_overwrites_same_evidence_human_decision(tmp_path: Path) -> None:
    path = tmp_path / "zscope.semantics.yaml"
    document = _document(tmp_path)
    ProjectSemanticsStore(path).write(document)
    candidate = dict(document["interfaces"][0])
    candidate["status"] = "pending"

    stats = ProjectSemanticsStore(path).merge_discovery(
        interfaces=[candidate], receipt={"schema": "zscope.primitive-discovery.v1"}
    )

    assert stats["preserved"] == 1
    assert ProjectSemanticsStore(path).read()["interfaces"][0]["status"] == "confirmed"


def test_changed_evidence_marks_human_decision_stale(tmp_path: Path) -> None:
    path = tmp_path / "zscope.semantics.yaml"
    document = _document(tmp_path)
    ProjectSemanticsStore(path).write(document)
    candidate = dict(document["interfaces"][0])
    candidate["evidence_digest"] = "f" * 64

    stats = ProjectSemanticsStore(path).merge_discovery(
        interfaces=[candidate], receipt={"schema": "zscope.primitive-discovery.v1"}
    )

    assert stats["stale"] == 1
    assert ProjectSemanticsStore(path).read()["interfaces"][0]["status"] == "stale"


def test_absent_primitive_root_is_not_staled_by_discovery(tmp_path: Path) -> None:
    path = tmp_path / "zscope.semantics.yaml"
    ProjectSemanticsStore(path).write(_document(tmp_path))

    stats = ProjectSemanticsStore(path).merge_discovery(
        interfaces=[], receipt={"schema": "zscope.primitive-discovery.v1"}
    )

    assert stats["stale"] == 0
    assert ProjectSemanticsStore(path).read()["interfaces"][0]["status"] == "confirmed"


def test_readiness_and_compiler_are_exact_build_scoped(tmp_path: Path) -> None:
    document = _document(tmp_path)
    readiness = semantics_readiness(document, project_root=tmp_path, build_context_ids=["build-a"])
    assert readiness.ready is True
    rows = compiled_project_contracts(document, build_context_id="build-a")
    assert len(rows) == 1
    assert rows[0]["symbol"]["usr"] == "c:@F@project_alloc"
    assert rows[0]["verification"]["authority"] == "native_current"
    assert rows[0]["role"] == "allocator"
    assert compiled_project_contracts(document, build_context_id="build-b") == []


def test_compiler_preserves_owned_member_path_on_returned_object(tmp_path: Path) -> None:
    document = _document(tmp_path)
    document["interfaces"][0]["effects"].append(
        {
            "domain": "resource",
            "role": "allocator",
            "operation": "allocate",
            "carrier": {
                "root": "return",
                "phase": "post",
                "dereference": 0,
                "members": ["payload"],
            },
            "strength": "may",
            "resource_family": "heap",
        }
    )

    rows = compiled_project_contracts(document, build_context_id="build-a")

    assert [row["carrier"].get("member_path", "") for row in rows] == ["", "->payload"]


def test_compiler_preserves_reviewed_builtin_wrapper_provenance(tmp_path: Path) -> None:
    document = _document(tmp_path)
    document["interfaces"][0]["derived_from"] = ["builtin:malloc"]

    rows = compiled_project_contracts(document, build_context_id="build-a")

    assert rows[0]["delegates"] == [
        {
            "symbol": {"name": "malloc"},
            "role": "allocator",
            "transparent": True,
        }
    ]


def test_pending_and_unsupported_rows_cannot_enter_execution(tmp_path: Path) -> None:
    document = _document(tmp_path, status="pending")
    readiness = semantics_readiness(document, project_root=tmp_path)
    assert readiness.ready is False
    assert readiness.pending == ("project:allocator",)
    assert compiled_project_contracts(document, build_context_id="build-a") == []

    document["interfaces"][0]["status"] = "confirmed"
    document["interfaces"][0]["effects"][0]["role"] = "not_implemented"
    with pytest.raises(ProjectSemanticsError, match="unsupported"):
        validate_project_semantics(document)


def test_external_model_requires_exact_build_and_never_crosses_variants(
    tmp_path: Path,
) -> None:
    document = _document(tmp_path)
    row = document["interfaces"][0]
    row["basis"] = "external_model"
    row["variants"] = []
    with pytest.raises(ProjectSemanticsError, match="exact native variant"):
        validate_project_semantics(document)

    row["selector"]["build_context_id"] = "build-a"
    validate_project_semantics(document)
    assert len(compiled_project_contracts(document, build_context_id="build-a")) == 1
    assert compiled_project_contracts(document, build_context_id="build-b") == []


def test_project_pair_must_reference_a_known_interface(tmp_path: Path) -> None:
    document = _document(tmp_path)
    document["interfaces"][0]["pairs"] = ["project:missing"]
    with pytest.raises(ProjectSemanticsError, match="references unknown"):
        validate_project_semantics(document)


def test_yaml_store_does_not_expose_function_intents(tmp_path: Path) -> None:
    path = tmp_path / "zscope.semantics.yaml"
    ProjectSemanticsStore(path).write(_document(tmp_path))
    store = UserConfigStore(path)
    assert store.list_function_intents() == []
    assert store.get_function_intent("project_alloc") is None
    with pytest.raises(ValueError, match="LLM Wiki"):
        store.upsert_function_intent("project_alloc")


def test_every_executable_role_has_a_static_consumer() -> None:
    assert EFFECT_CONSUMERS
    assert all(EFFECT_CONSUMERS.values())


def test_c_linux_catalog_has_no_active_gaps_and_exposes_full_baseline_debt() -> None:
    audit = catalog_audit()
    assert audit["catalog_version"] == CATALOG_VERSION
    assert audit["active"] >= 200
    assert audit["neutral"] > 0
    assert audit["unsupported"] > 0
    assert audit["active_missing_abi"] == []
    assert audit["active_missing_source"] == []
    assert audit["active_missing_consumer"] == []
    assert audit["baseline_interfaces"] == 1243
    assert audit["classified_interfaces"] <= len(audit["records"])
    assert audit["unaudited"]
    assert "fork" in audit["unaudited"]
    assert classification_for("malloc") == "active"
    assert classification_for("abs") == "neutral"
    assert classification_for("syscall") == "unsupported"
    assert classification_for("project_alloc") == ""


def test_discovery_llm_is_advisory_and_uses_at_most_one_completion_round(
    tmp_path: Path,
) -> None:
    candidate = _interface(tmp_path, status="pending")
    candidate["primitive"] = False
    candidate["basis"] = "derived_wrapper"
    candidate["effects"][0]["strength"] = "may"
    candidate["derived_from"] = ["builtin:malloc"]

    class FakeLLM:
        def __init__(self) -> None:
            self.calls = 0
            self.kwargs = []

        def chat_completion(self, *_args, **kwargs):
            self.calls += 1
            self.kwargs.append(kwargs)
            if self.calls == 1:
                content = (
                    '{"reviews":[{"id":"project:allocator","verdict":"insufficient",'
                    '"rationale":"need path","evidence_refs":[],"missing_fact_kinds":'
                    '["path","def_use"]}]}'
                )
            else:
                content = (
                    '{"reviews":[{"id":"project:allocator","verdict":"refine",'
                    '"rationale":"effect is conditional","evidence_refs":["path"],'
                    '"refined_effects":[{"strength":"may"}]}]}'
                )
            return {"choices": [{"message": {"content": content}}]}

    scope = InstanceScope(
        build_context_id="build-a",
        usr="c:@F@project_alloc",
        identity="build-a:c:@F@project_alloc",
        source=str(tmp_path / "memory.c"),
        function_names=("project_alloc",),
    )
    before_effects = candidate["effects"].copy()
    client = FakeLLM()
    audit = _review_discovery_candidates(
        client,
        [candidate],
        document=empty_project_semantics(),
        work={
            "build-a": [
                (
                    scope,
                    {
                        "file": str(tmp_path / "memory.c"),
                        "signature": "void *(unsigned long)",
                        "code": "void *project_alloc(unsigned long n) { return malloc(n); }",
                    },
                    {"complete": True, "functions": []},
                    "project_alloc",
                    "void *(unsigned long)",
                )
            ]
        },
    )

    assert client.calls == 2
    assert all(call["max_tokens"] == 1536 for call in client.kwargs)
    assert all(call["thinking"] == {"type": "disabled"} for call in client.kwargs)
    assert audit["evidence_completion_rounds"] == 1
    assert audit["reviewed"] == 1
    assert audit["provider_results"]["project:allocator"]["evidence_delta"] is True
    assert audit["provider_results"]["project:allocator"]["provided"]["path"] == ["builtin:malloc"]
    assert audit["provider_results"]["project:allocator"]["unsupported_or_empty"] == []
    assert audit["invalid_fact_requests"] == [
        {"id": "project:allocator", "fact_kinds": ["def_use"]}
    ]
    assert candidate["status"] == "pending"
    assert candidate["effects"] == before_effects
    assert candidate["llm_review"]["verdict"] == "refine"
    assert candidate["llm_review"]["authority"] == "advisory_human_confirmation_required"


def test_discovery_llm_groups_identical_build_variant_evidence(tmp_path: Path) -> None:
    candidate = _interface(tmp_path, status="pending")
    candidate["primitive"] = False
    candidate["basis"] = "derived_wrapper"
    candidate["effects"][0]["strength"] = "may"
    candidate["derived_from"] = ["builtin:malloc"]
    scopes = []
    variants = []
    for index in range(20):
        build = f"build-{index}"
        scope = InstanceScope(
            build_context_id=build,
            usr="c:@F@project_alloc",
            identity=f"{build}:c:@F@project_alloc",
            source=str(tmp_path / "memory.c"),
            function_names=("project_alloc",),
        )
        facts = {
            "complete": True,
            "functions": [
                {
                    "parameters": [],
                    "events": [
                        {
                            "event_kind": "call",
                            "callee": {"name": "malloc", "usr": "c:@F@malloc"},
                            "arguments": ["n"],
                        }
                    ],
                }
            ],
        }
        scopes.append(
            (
                scope,
                {
                    "file": str(tmp_path / "memory.c"),
                    "signature": "void *(unsigned long)",
                    "code": "void *project_alloc(unsigned long n) { return malloc(n); }",
                },
                facts,
                "project_alloc",
                "void *(unsigned long)",
            )
        )
        variants.append(
            {
                "build_context_id": build,
                "usr": scope.usr,
                "identity_status": "exact",
            }
        )
    candidate["variants"] = variants

    [payload] = _candidate_review_payloads(
        [candidate],
        document=empty_project_semantics(),
        work={item[0].build_context_id: [item] for item in scopes},
    )

    assert len(payload["native_excerpts"]) == 1
    assert len(payload["native_excerpts"][0]["build_context_ids"]) == 20
    assert payload["native_excerpt_coverage"] == {
        "total_variants": 20,
        "unique_evidence_shapes": 1,
        "included_evidence_shapes": 1,
        "omitted_evidence_shapes": 0,
        "omitted_evidence_digest": "",
    }


def test_discovery_llm_records_empty_truncated_response_as_protocol_error(
    tmp_path: Path,
) -> None:
    candidate = _interface(tmp_path, status="pending")
    candidate["primitive"] = False
    candidate["basis"] = "derived_wrapper"
    candidate["effects"][0]["strength"] = "may"

    class EmptyLLM:
        def chat_completion(self, *_args, **_kwargs):
            return {"choices": [{"message": {"content": ""}, "finish_reason": "length"}]}

    audit = _review_discovery_candidates(
        EmptyLLM(),
        [candidate],
        document=empty_project_semantics(),
        work={},
    )

    assert audit["reviewed"] == 0
    assert audit["errors"] == ["initial_review_batch_1:empty_response:finish_reason=length"]


def test_dispatcher_candidates_keep_compile_variants_as_distinct_rows(tmp_path: Path) -> None:
    source = str(tmp_path / "dispatch.c")
    work = {}
    for build in ("build-a", "build-b"):
        dispatcher = InstanceScope(
            build_context_id=build,
            usr="c:@F@dispatch",
            identity=f"{build}:c:@F@dispatch",
            source=source,
            function_names=("dispatch",),
        )
        handler = InstanceScope(
            build_context_id=build,
            usr="c:@F@handle_one",
            identity=f"{build}:c:@F@handle_one",
            source=source,
            function_names=("handle_one",),
        )
        work[build] = [
            (
                dispatcher,
                {
                    "file": source,
                    "code": "switch (kind) { case 1: handle_one(); break; }",
                },
                {},
                "dispatch",
                "void (int)",
            ),
            (
                handler,
                {"file": source, "code": "void handle_one(void) {}"},
                {},
                "handle_one",
                "void ()",
            ),
        ]

    rows = _dispatcher_candidates(work)

    assert len(rows) == 2
    assert len({row["id"] for row in rows}) == 2
    assert {row["build_context_id"] for row in rows} == {"build-a", "build-b"}
    document = empty_project_semantics()
    document["dispatchers"] = rows
    validate_project_semantics(document)


def test_dispatcher_candidates_deduplicate_repeated_native_instance(tmp_path: Path) -> None:
    source = str(tmp_path / "dispatch.c")
    dispatcher = InstanceScope(
        build_context_id="build-a",
        usr="c:@F@dispatch",
        identity="build-a:c:@F@dispatch",
        source=source,
        function_names=("dispatch",),
    )
    handler = InstanceScope(
        build_context_id="build-a",
        usr="c:@F@handle_one",
        identity="build-a:c:@F@handle_one",
        source=source,
        function_names=("handle_one",),
    )
    dispatcher_row = (
        dispatcher,
        {
            "file": source,
            "code": "switch (kind) { case 1: handle_one(); break; }",
        },
        {},
        "dispatch",
        "void (int)",
    )
    work = {
        "build-a": [
            dispatcher_row,
            dispatcher_row,
            (
                handler,
                {"file": source, "code": "void handle_one(void) {}"},
                {},
                "handle_one",
                "void ()",
            ),
        ]
    }

    rows = _dispatcher_candidates(work)

    assert len(rows) == 1
    document = empty_project_semantics()
    document["dispatchers"] = rows
    validate_project_semantics(document)


def test_dispatcher_candidates_only_emit_rooted_handler_instances(tmp_path: Path) -> None:
    source = str(tmp_path / "dispatch.c")
    dispatcher = InstanceScope(
        build_context_id="build-a",
        usr="c:@F@dispatch",
        identity="build-a:c:@F@dispatch",
        source=source,
        function_names=("dispatch",),
    )
    rooted = InstanceScope(
        build_context_id="build-a",
        usr="c:@F@rooted",
        identity="build-a:c:@F@rooted",
        source=source,
        function_names=("rooted",),
    )
    unrelated = InstanceScope(
        build_context_id="build-a",
        usr="c:@F@unrelated",
        identity="build-a:c:@F@unrelated",
        source=source,
        function_names=("unrelated",),
    )
    work = {
        "build-a": [
            (
                dispatcher,
                {
                    "file": source,
                    "code": (
                        "switch (kind) { case 1: rooted(); break; " "case 2: unrelated(); break; }"
                    ),
                },
                {},
                "dispatch",
                "void (int)",
            ),
            (rooted, {"file": source, "code": "void rooted(void) {}"}, {}, "rooted", "void ()"),
            (
                unrelated,
                {"file": source, "code": "void unrelated(void) {}"},
                {},
                "unrelated",
                "void ()",
            ),
        ]
    }

    rows = _dispatcher_candidates(
        work,
        eligible_handler_instances={("build-a", "c:@F@rooted")},
        root=tmp_path,
    )

    assert len(rows) == 1
    assert rows[0]["handler_usr"] == "c:@F@rooted"
    assert rows[0]["file"] == "dispatch.c"


def test_confirmed_dispatcher_projects_runtime_overlay_field_names(tmp_path: Path) -> None:
    path = tmp_path / "zscope.semantics.yaml"
    document = empty_project_semantics()
    document["dispatchers"] = [
        {
            "id": "project:dispatcher:one",
            "status": "confirmed",
            "dispatcher": "dispatch",
            "file": "dispatch.c",
            "build_context_id": "build-a",
            "usr": "c:@F@dispatch",
            "handler_name": "handle_one",
            "handler_usr": "c:@F@handle_one",
            "guard": "MESSAGE_ONE",
            "evidence_summary": "Reviewed exact switch branch.",
            "evidence_digest": "a" * 64,
        }
    ]
    ProjectSemanticsStore(path).write(document)

    rows = ProjectSemanticsStore(path).list_dispatchers()

    assert len(rows) == 1
    assert rows[0]["dispatcher_name"] == "dispatch"
    assert rows[0]["file_path"] == "dispatch.c"
    assert rows[0]["message_type"] == "MESSAGE_ONE"
    assert rows[0]["handler_kind"] == "configured_dispatcher"


def test_macro_discovery_requires_exact_native_definition_binding(tmp_path: Path) -> None:
    header = tmp_path / "wrappers.h"
    header.write_text("\n#define SAFE_FREE(p) free(p)\n", encoding="utf-8")
    root = {
        "id": "builtin:free",
        "cases": [{"when": {"op": "true"}, "effect": "applies"}],
        "effects": [
            {
                "domain": "resource",
                "role": "deallocator",
                "operation": "deallocator",
                "carrier": {
                    "root": "argument",
                    "index": 0,
                    "phase": "post",
                    "dereference": 0,
                    "members": [],
                },
                "strength": "must_under_guard",
            }
        ],
        "pairs": ["builtin:malloc"],
    }

    assert _macro_candidates(root=tmp_path, bindings={}, interfaces=[], roots={"free": root}) == []
    rows = _macro_candidates(
        root=tmp_path,
        bindings={
            ("SAFE_FREE", "wrappers.h", 2): [
                {
                    "build_context_id": "build-a",
                    "usr": "c:wrappers.h@macro@SAFE_FREE",
                    "native_input_hash": "a" * 64,
                }
            ]
        },
        interfaces=[],
        roots={"free": root},
    )

    assert len(rows) == 1
    assert rows[0]["status"] == "pending"
    assert rows[0]["selector"]["usr"] == "c:wrappers.h@macro@SAFE_FREE"
    assert rows[0]["variants"][0]["build_context_id"] == "build-a"


def test_macro_discovery_closes_transitive_wrapper_chain_with_global_carrier(
    tmp_path: Path,
) -> None:
    header = tmp_path / "wrappers.h"
    header.write_text(
        "#define LOCK(p) pthread_mutex_lock(p)\n"
        "#define COUNTER_SLOT_LOCK() LOCK(&g_counter_lock)\n",
        encoding="utf-8",
    )
    root = {
        "id": "builtin:pthread_mutex_lock",
        "cases": [{"when": {"op": "true"}, "effect": "unknown"}],
        "effects": [
            {
                "domain": "lock",
                "role": "lock",
                "operation": "lock",
                "carrier": {
                    "root": "argument",
                    "index": 0,
                    "phase": "post",
                    "dereference": 0,
                    "members": [],
                },
                "strength": "may",
                "protocol": {
                    "kind": "standard_api_effects",
                    "transitions": [
                        {
                            "when": {"op": "true"},
                            "actions": [
                                {
                                    "kind": "acquire",
                                    "object": {"kind": "argument", "argument_index": 0},
                                }
                            ],
                        }
                    ],
                },
            }
        ],
        "pairs": ["builtin:pthread_mutex_unlock"],
    }
    rows = _macro_candidates(
        root=tmp_path,
        bindings={
            ("LOCK", "wrappers.h", 1): [
                {
                    "build_context_id": "build-a",
                    "usr": "c:wrappers.h@0@macro@LOCK",
                    "native_input_hash": "a" * 64,
                }
            ],
            ("COUNTER_SLOT_LOCK", "wrappers.h", 2): [
                {
                    "build_context_id": "build-a",
                    "usr": "c:wrappers.h@42@macro@COUNTER_SLOT_LOCK",
                    "native_input_hash": "b" * 64,
                }
            ],
        },
        interfaces=[],
        roots={"pthread_mutex_lock": root},
    )

    by_name = {row["selector"]["name"]: row for row in rows}
    assert set(by_name) == {"LOCK", "COUNTER_SLOT_LOCK"}
    assert by_name["COUNTER_SLOT_LOCK"]["derived_from"] == [by_name["LOCK"]["id"]]
    assert by_name["COUNTER_SLOT_LOCK"]["effects"][0]["carrier"] == {
        "root": "global",
        "name": "g_counter_lock",
        "phase": "post",
        "dereference": 0,
        "members": [],
    }
    assert by_name["COUNTER_SLOT_LOCK"]["effects"][0]["protocol"]["transitions"][0]["actions"][0][
        "object"
    ] == {
        "kind": "global",
        "global_name": "g_counter_lock",
        "address_of": True,
    }


def test_macro_binding_uses_exact_definition_receipt_even_without_callsite(tmp_path: Path) -> None:
    header = tmp_path / "wrappers.h"
    header.write_text("#define LOCK_READ(p) read_lock(p)\n", encoding="utf-8")

    class FakeIndex:
        @staticmethod
        def get_compilation_facts(build, *, kinds=()):
            assert build == "build-a"
            assert tuple(kinds) == ("macro",)
            return [
                {
                    "kind": "macro",
                    "name": "LOCK_READ",
                    "usr": "c:wrappers.h@0@macro@LOCK_READ",
                    "definition": "#define LOCK_READ(p) read_lock(p)",
                    "begin": {"file": str(header), "line": 1},
                }
            ]

    bindings, gaps = _macro_reference_bindings(FakeIndex(), root=tmp_path, build_ids=["build-a"])

    assert gaps == []
    assert list(bindings) == [("LOCK_READ", "wrappers.h", 1)]
    assert bindings[("LOCK_READ", "wrappers.h", 1)][0]["build_context_id"] == "build-a"


def test_duplicate_cfg_projection_does_not_hide_lock_wrapper(tmp_path: Path) -> None:
    source = tmp_path / "lock.c"
    source.write_text(
        "void wrap(void *p) { int rc = pthread_mutex_lock(p); (void)rc; }\n",
        encoding="utf-8",
    )
    contract = ApiContract(
        SymbolIdentity("pthread_mutex_lock"),
        "lock",
        ObjectBinding("argument", 0),
        source="builtin_defaults",
        protocol={"lock_mode": "exclusive"},
    )
    parameter = {"usr": "c:lock.c@F@wrap@p", "name": "p"}
    event = {
        "event_kind": "call",
        "callee": {"name": "pthread_mutex_lock"},
        "argument_uses": [[parameter]],
        "event_id": "1:0",
    }
    facts = {
        "functions": [
            {
                "parameters": [parameter],
                "events": [event, {**event, "event_id": "1:1"}],
            }
        ]
    }
    candidate = _lock_wrapper_candidate(
        facts=facts,
        semantics=SimpleNamespace(contracts=ContractRegistry([contract])),
        root=tmp_path,
        source=str(source),
        code=source.read_text(encoding="utf-8"),
        build="build-a",
        usr="c:@F@wrap",
        name="wrap",
        signature="void (void *)",
    )

    assert candidate is not None
    assert [effect["role"] for effect in candidate["effects"]] == ["lock"]
    assert candidate["effects"][0]["protocol"]["lock_mode"] == "exclusive"


def test_format_selection_control_dependency_is_not_a_format_wrapper(tmp_path: Path) -> None:
    source = tmp_path / "format.c"
    source.write_text(
        'int format_addr(char *out, unsigned long n, const char *ip) {'
        ' return snprintf(out, n, strchr(ip, ":") ? "[%s]" : "%s", ip); }\n',
        encoding="utf-8",
    )
    parameters = [
        {"usr": "c:format.c@F@format_addr@out", "name": "out"},
        {"usr": "c:format.c@F@format_addr@n", "name": "n"},
        {"usr": "c:format.c@F@format_addr@ip", "name": "ip"},
    ]
    facts = {
        "functions": [
            {
                "parameters": parameters,
                "events": [
                    {
                        "event_kind": "call",
                        "callee": {"name": "snprintf"},
                        "arguments": [
                            "out",
                            "n",
                            'strchr(ip, ":") ? "[%s]" : "%s"',
                            "ip",
                        ],
                        "argument_uses": [
                            [parameters[0]],
                            [parameters[1]],
                            [parameters[2]],
                            [parameters[2]],
                        ],
                    }
                ],
            }
        ]
    }
    contract = ApiContract(
        SymbolIdentity("snprintf"),
        "format_sink",
        ObjectBinding("argument", 2),
        source="builtin_defaults",
    )

    candidate = _lock_wrapper_candidate(
        facts=facts,
        semantics=SimpleNamespace(contracts=ContractRegistry([contract])),
        root=tmp_path,
        source=str(source),
        code=source.read_text(encoding="utf-8"),
        build="build-a",
        usr="c:@F@format_addr",
        name="format_addr",
        signature="int (char *, unsigned long, const char *)",
    )

    assert candidate is None


def test_direct_public_format_parameter_remains_discoverable(tmp_path: Path) -> None:
    source = tmp_path / "log.c"
    source.write_text(
        "void log_message(const char *fmt) { printf(fmt); }\n", encoding="utf-8"
    )
    parameter = {"usr": "c:log.c@F@log_message@fmt", "name": "fmt"}
    facts = {
        "functions": [
            {
                "parameters": [parameter],
                "events": [
                    {
                        "event_kind": "call",
                        "callee": {"name": "printf"},
                        "arguments": ["fmt"],
                        "argument_uses": [[parameter]],
                    }
                ],
            }
        ]
    }
    contract = ApiContract(
        SymbolIdentity("printf"),
        "format_sink",
        ObjectBinding("argument", 0),
        source="builtin_defaults",
    )

    candidate = _lock_wrapper_candidate(
        facts=facts,
        semantics=SimpleNamespace(contracts=ContractRegistry([contract])),
        root=tmp_path,
        source=str(source),
        code=source.read_text(encoding="utf-8"),
        build="build-a",
        usr="c:@F@log_message",
        name="log_message",
        signature="void (const char *)",
    )

    assert candidate is not None
    assert candidate["effects"][0]["carrier"]["index"] == 0


def test_confirmed_interface_rejects_yaml_boolean_predicate(tmp_path: Path) -> None:
    path = tmp_path / "zscope.semantics.yaml"
    document = empty_project_semantics()
    row = _interface(tmp_path)
    row["id"] = "project:bad-bool"
    row["cases"] = [{"when": {"op": True}, "effect": "applies"}]
    document["interfaces"] = [row]

    with pytest.raises(ProjectSemanticsError, match="unsupported_predicate_operator"):
        ProjectSemanticsStore(path).write(document)


def test_confirmed_interface_requires_executable_applies_case(tmp_path: Path) -> None:
    path = tmp_path / "zscope.semantics.yaml"
    document = empty_project_semantics()
    row = _interface(tmp_path)
    row["id"] = "project:unknown-only"
    row["cases"] = [{"when": {"op": "true"}, "effect": "unknown"}]
    document["interfaces"] = [row]

    with pytest.raises(ProjectSemanticsError, match="at least one applies case"):
        ProjectSemanticsStore(path).write(document)


def test_discovery_probe_executes_unknown_candidate_without_publishing_it(tmp_path: Path) -> None:
    row = _interface(tmp_path, status="pending")
    row["cases"] = [{"when": {"op": "true"}, "effect": "unknown"}]
    document = empty_project_semantics()
    document["interfaces"] = [deepcopy(row)]

    contracts = _configured_discovery_contracts(document, [row], "build-a")

    assert len(contracts) == 1
    assert contracts[0].effect_cases == [
        {"when": {"op": "true"}, "effect": "applies"}
    ]
    assert document["interfaces"][0]["status"] == "pending"
    assert document["interfaces"][0]["cases"][0]["effect"] == "unknown"


def test_owned_object_factory_discovers_returned_member_ownership(tmp_path: Path) -> None:
    source = tmp_path / "factory.c"
    source.write_text(
        "struct Node *make(void) { struct Node *node = project_calloc(1, sizeof(*node)); "
        'node->payload = project_dup("x"); return node; }\n',
        encoding="utf-8",
    )
    node = {
        "name": "node",
        "expression": "node",
        "usr": "c:factory.c@F@make@node",
        "value_kind": "local",
    }
    payload = {
        "name": "payload",
        "expression": "node->payload",
        "base_expression": "node",
        "usr": "c:@S@Node@FI@payload",
        "value_kind": "field",
    }
    facts = {
        "functions": [
            {
                "events": [
                    {
                        "event_kind": "call",
                        "event_id": "1:0",
                        "callee": {"name": "project_calloc", "usr": "c:@F@project_calloc"},
                        "object": node,
                        "defs": [node],
                    },
                    {
                        "event_kind": "call",
                        "event_id": "1:1",
                        "callee": {"name": "project_dup", "usr": "c:@F@project_dup"},
                        "object": payload,
                        "defs": [payload],
                    },
                    {
                        "event_kind": "return",
                        "event_id": "1:2",
                        "return_value": "node",
                    },
                ]
            }
        ]
    }
    contracts = ContractRegistry(
        [
            ApiContract(
                SymbolIdentity(
                    "project_calloc", build_context_id="build-a", usr="c:@F@project_calloc"
                ),
                "calloc",
                ObjectBinding("return"),
                resource_family="heap",
                source="configured",
            ),
            ApiContract(
                SymbolIdentity("project_dup", build_context_id="build-a", usr="c:@F@project_dup"),
                "allocator",
                ObjectBinding("return"),
                resource_family="heap",
                source="configured",
            ),
        ]
    )

    candidate = _owned_object_factory_candidate(
        facts=facts,
        semantics=SimpleNamespace(contracts=contracts),
        root=tmp_path,
        source=str(source),
        code=source.read_text(encoding="utf-8"),
        build="build-a",
        usr="c:@F@make",
        name="make",
        signature="struct Node *(void)",
    )

    assert candidate is not None
    assert [effect["carrier"]["members"] for effect in candidate["effects"]] == [
        [],
        ["payload"],
    ]
    assert [effect["role"] for effect in candidate["effects"]] == [
        "allocator",
        "allocator",
    ]
    assert candidate["effects"][0]["protocol"] == {}
    assert all(effect["strength"] == "may" for effect in candidate["effects"])


def test_cxx_new_factory_and_returned_aggregate_member_are_review_candidates(
    tmp_path: Path,
) -> None:
    cache_source = tmp_path / "cache.cc"
    cache_source.write_text(
        "Cache* NewCache(size_t n) { return new Cache(n); }\n",
        encoding="utf-8",
    )
    cache_facts = {
        "functions": [
            {
                "events": [
                    {
                        "event_kind": "acquire",
                        "ast_kind": "CXXNewExpr",
                        "expression": "new Cache(n)",
                    },
                    {
                        "event_kind": "return",
                        "return_value": "new Cache(n)",
                    },
                ]
            }
        ]
    }

    cache_candidate = _cxx_new_factory_candidate(
        facts=cache_facts,
        root=tmp_path,
        source=str(cache_source),
        code=cache_source.read_text(encoding="utf-8"),
        build="cache-build",
        usr="c:@F@NewCache#l#",
        name="NewCache",
        signature="Cache *(size_t)",
    )

    assert cache_candidate is not None
    assert cache_candidate["status"] == "pending"
    assert cache_candidate["effects"][0]["carrier"]["root"] == "return"
    assert cache_candidate["effects"][0]["protocol"]["acquire"] == "cxx_new"

    options_source = tmp_path / "options.cc"
    options_source.write_text(
        "Options Sanitize(const Options& src) { Options result = src; "
        "if (result.cache == NULL) { result.cache = NewCache(8); } return result; }\n",
        encoding="utf-8",
    )
    field = {
        "name": "cache",
        "expression": "result.cache",
        "base_expression": "result",
        "value_kind": "field",
    }
    options_facts = {
        "functions": [
            {
                "events": [
                    {
                        "event_kind": "call",
                        "callee": {"name": "NewCache", "usr": "c:@F@NewCache#l#"},
                        "object": field,
                        "defs": [field],
                    },
                    {"event_kind": "return", "return_value": "result"},
                ]
            }
        ]
    }
    aggregate_candidate = _returned_aggregate_member_factory_candidate(
        facts=options_facts,
        semantics=SimpleNamespace(contracts=ContractRegistry()),
        direct_cxx_new_factories={"c:@F@NewCache#l#"},
        root=tmp_path,
        source=str(options_source),
        code=options_source.read_text(encoding="utf-8"),
        build="options-build",
        usr="c:@F@Sanitize#&1$@S@Options#",
        name="Sanitize",
        signature="Options (const Options &)",
    )

    assert aggregate_candidate is not None
    assert aggregate_candidate["status"] == "pending"
    assert aggregate_candidate["effects"][0]["carrier"]["members"] == ["cache"]
    assert aggregate_candidate["effects"][0]["strength"] == "may"


def test_reviewed_cxx_new_and_returned_member_candidates_rebind_to_current_facts(
    tmp_path: Path,
) -> None:
    cache_source = tmp_path / "cache.cc"
    cache_source.write_text(
        "Cache* NewCache(size_t n) { return new Cache(n); }\n",
        encoding="utf-8",
    )
    cache_events = [
        {
            "event_kind": "acquire",
            "ast_kind": "CXXNewExpr",
            "expression": "new Cache(n)",
        },
        {"event_kind": "return", "return_value": "new Cache(n)"},
    ]
    cache_usr = "c:@F@NewCache#l#"
    cache_signature = "Cache *(size_t)"
    cache_candidate = _cxx_new_factory_candidate(
        facts={"functions": [{"events": cache_events}]},
        root=tmp_path,
        source=str(cache_source),
        code=cache_source.read_text(encoding="utf-8"),
        build="old-cache-build",
        usr=cache_usr,
        name="NewCache",
        signature=cache_signature,
    )
    assert cache_candidate is not None

    options_source = tmp_path / "options.cc"
    options_source.write_text(
        "Options Sanitize(const Options& src) { Options result = src; "
        "if (result.cache == NULL) { result.cache = NewCache(8); } return result; }\n",
        encoding="utf-8",
    )
    field = {
        "name": "cache",
        "expression": "result.cache",
        "base_expression": "result",
        "value_kind": "field",
    }
    options_events = [
        {
            "event_kind": "call",
            "callee": {"name": "NewCache", "usr": cache_usr},
            "object": field,
            "defs": [field],
        },
        {"event_kind": "return", "return_value": "result"},
    ]
    options_usr = "c:@F@Sanitize#&1$@S@Options#"
    options_signature = "Options (const Options &)"
    options_candidate = _returned_aggregate_member_factory_candidate(
        facts={"functions": [{"events": options_events}]},
        semantics=SimpleNamespace(contracts=ContractRegistry()),
        direct_cxx_new_factories={cache_usr},
        root=tmp_path,
        source=str(options_source),
        code=options_source.read_text(encoding="utf-8"),
        build="old-options-build",
        usr=options_usr,
        name="Sanitize",
        signature=options_signature,
    )
    assert options_candidate is not None

    for candidate in (cache_candidate, options_candidate):
        candidate["status"] = "confirmed"
        candidate["cases"] = [{"when": {"op": "true"}, "effect": "applies"}]
        candidate["variants"][0]["target_id"] = "main"
    document = empty_project_semantics()
    document["interfaces"] = [cache_candidate, options_candidate]

    cache_definition = {
        "kind": "program_function",
        "owner": {
            "name": "NewCache",
            "usr": cache_usr,
            "file": str(cache_source),
        },
        "callable": {
            "canonical_signature": cache_signature,
            "external_linkage": True,
        },
        "events": cache_events,
    }
    options_definition = {
        "kind": "program_function",
        "owner": {
            "name": "Sanitize",
            "usr": options_usr,
            "file": str(options_source),
        },
        "callable": {
            "canonical_signature": options_signature,
            "external_linkage": True,
        },
        "events": options_events,
    }

    class FakeIndex:
        @staticmethod
        def get_build_contexts():
            return [{"build_context_id": "current-build"}]

        @staticmethod
        def get_compilation_facts(build, *, kinds=()):
            assert build == "current-build"
            assert tuple(kinds) == ("program_function", "macro", "call")
            return [cache_definition, options_definition]

        @staticmethod
        def linked_targets():
            return SimpleNamespace(targets=[])

    rebound, audit = rebind_project_semantics(
        document,
        project_root=tmp_path,
        target_id="main",
        code_index=FakeIndex(),
    )

    assert audit["ready"] is True
    assert audit["unresolved"] == []
    assert {row["id"] for row in audit["contracts"]} == {
        cache_candidate["id"],
        options_candidate["id"],
    }
    assert len(compiled_project_contracts(rebound, build_context_id="current-build")) == 2


def test_returned_aggregate_member_discovery_requires_null_guard(tmp_path: Path) -> None:
    source = tmp_path / "options.cc"
    source.write_text(
        "Options Sanitize(const Options& src) { Options result = src; "
        "result.cache = NewCache(8); return result; }\n",
        encoding="utf-8",
    )
    field = {
        "name": "cache",
        "expression": "result.cache",
        "base_expression": "result",
        "value_kind": "field",
    }
    facts = {
        "functions": [
            {
                "events": [
                    {
                        "event_kind": "call",
                        "callee": {"name": "NewCache", "usr": "c:@F@NewCache#l#"},
                        "object": field,
                        "defs": [field],
                    },
                    {"event_kind": "return", "return_value": "result"},
                ]
            }
        ]
    }

    candidate = _returned_aggregate_member_factory_candidate(
        facts=facts,
        semantics=SimpleNamespace(contracts=ContractRegistry()),
        direct_cxx_new_factories={"c:@F@NewCache#l#"},
        root=tmp_path,
        source=str(source),
        code=source.read_text(encoding="utf-8"),
        build="options-build",
        usr="c:@F@Sanitize#&1$@S@Options#",
        name="Sanitize",
        signature="Options (const Options &)",
    )

    assert candidate is None


def test_llm_review_payloads_are_partitioned_once_per_candidate() -> None:
    payloads = [{"id": f"candidate-{index}", "value": "x" * 9000} for index in range(9)]
    batches = _payload_batches(payloads)

    assert len(batches) > 1
    assert [row["id"] for batch in batches for row in batch] == [row["id"] for row in payloads]
    assert all(len(batch) <= 4 for batch in batches)


def test_reviewed_contract_rebinds_only_through_current_link_record(tmp_path: Path) -> None:
    source = tmp_path / "wrapper.c"
    source.write_text(
        "void *project_alloc(unsigned long n) { return malloc(n); }\n",
        encoding="utf-8",
    )
    document = _document(tmp_path)
    row = document["interfaces"][0]
    row["selector"]["file"] = "wrapper.c"
    row["selector"]["usr"] = "c:@F@project_alloc"
    row["selector"]["signature"] = "void *(unsigned long)"
    row["derived_from"] = ["builtin:malloc"]
    row["variants"] = [
        {
            "target_id": "range",
            "build_context_id": "old-build",
            "usr": "c:@F@project_alloc",
            "signature": "void *(unsigned long)",
            "file": "wrapper.c",
            "source_sha256": _sha(source.read_bytes()),
            "evidence_sha256": "a" * 64,
            "native_input_hash": "b" * 64,
            "identity_status": "exact",
        }
    ]
    definition = {
        "kind": "program_function",
        "owner": {
            "name": "project_alloc",
            "usr": "c:@F@project_alloc",
            "file": str(source),
        },
        "callable": {
            "canonical_signature": "void *(unsigned long)",
            "external_linkage": True,
        },
        "events": [{"event_kind": "call", "callee": {"name": "malloc"}}],
    }
    call = {
        "kind": "call",
        "target": {"name": "project_alloc", "usr": "c:@F@project_alloc"},
    }

    class Linked:
        targets = [
            {
                "receipt": {"target_id": "range-linked", "schema": "test"},
                "members": {"new-definition": {}, "new-consumer": {}},
            }
        ]

    class FakeIndex:
        @staticmethod
        def get_build_contexts():
            return [
                {"build_context_id": "new-definition"},
                {"build_context_id": "new-consumer"},
            ]

        @staticmethod
        def get_compilation_facts(build, *, kinds=()):
            assert tuple(kinds) == ("program_function", "macro", "call")
            return [definition] if build == "new-definition" else [call]

        @staticmethod
        def linked_targets():
            return Linked()

    rebound, audit = rebind_project_semantics(
        document,
        project_root=tmp_path,
        target_id="range",
        code_index=FakeIndex(),
    )

    assert audit["ready"] is True
    assert audit["contracts"][0]["link_target_ids"] == ["range-linked"]
    assert {variant["build_context_id"] for variant in rebound["interfaces"][0]["variants"]} == {
        "new-definition",
        "new-consumer",
    }
    consumer_contracts = compiled_project_contracts(rebound, build_context_id="new-consumer")
    assert len(consumer_contracts) == 1
    assert consumer_contracts[0]["verification"]["revalidated_current"] is True


def test_reviewed_project_primitive_is_a_root_not_a_direct_builtin_wrapper(
    tmp_path: Path,
) -> None:
    source = tmp_path / "memory.c"
    source.write_text(
        "void *project_alloc(unsigned long n) { return private_alloc(n); }\n",
        encoding="utf-8",
    )
    document = _document(tmp_path)
    row = document["interfaces"][0]
    row["derived_from"] = ["builtin:malloc"]
    row["variants"][0]["source_sha256"] = _sha(source.read_bytes())
    definition = {
        "kind": "program_function",
        "owner": {
            "name": "project_alloc",
            "usr": "c:@F@project_alloc",
            "file": str(source),
        },
        "callable": {
            "canonical_signature": "void *(unsigned long)",
            "external_linkage": True,
        },
        "events": [{"event_kind": "call", "callee": {"name": "private_alloc"}}],
    }

    class FakeIndex:
        @staticmethod
        def get_build_contexts():
            return [{"build_context_id": "current-build"}]

        @staticmethod
        def get_compilation_facts(build, *, kinds=()):
            assert build == "current-build"
            return [definition]

        @staticmethod
        def linked_targets():
            return SimpleNamespace(targets=[])

    rebound, audit = rebind_project_semantics(
        document,
        project_root=tmp_path,
        target_id="main",
        code_index=FakeIndex(),
    )

    assert audit["ready"] is True
    assert audit["contracts"][0]["status"] == "authorized"
    assert rebound["interfaces"][0]["variants"][0]["build_context_id"] == "current-build"


def test_discovery_rebinds_unbound_user_primitive_to_current_native_variant(
    tmp_path: Path,
) -> None:
    source = tmp_path / "memory.c"
    source.write_text(
        "void *project_alloc(unsigned long n) { return private_alloc(n); }\n",
        encoding="utf-8",
    )
    document = _document(tmp_path)
    row = document["interfaces"][0]
    row["selector"]["file"] = source.name
    row["variants"] = []
    definition = {
        "kind": "program_function",
        "owner": {
            "name": "project_alloc",
            "usr": "c:@F@project_alloc",
            "file": str(source),
        },
        "callable": {
            "canonical_signature": "void *(unsigned long)",
            "external_linkage": False,
        },
        "events": [{"event_kind": "call", "callee": {"name": "private_alloc"}}],
    }

    class FakeIndex:
        @staticmethod
        def get_build_contexts():
            return [{"build_context_id": "current-build"}]

        @staticmethod
        def get_compilation_facts(build, *, kinds=()):
            assert build == "current-build"
            return [definition]

        @staticmethod
        def linked_targets():
            return SimpleNamespace(targets=[])

    with pytest.raises(ProjectSemanticsError, match="exact native variant"):
        rebind_project_semantics(
            document,
            project_root=tmp_path,
            target_id="main",
            code_index=FakeIndex(),
        )

    rebound, audit = rebind_project_semantics(
        document,
        project_root=tmp_path,
        target_id="main",
        code_index=FakeIndex(),
        allow_unbound_primitive_proposals=True,
    )

    assert audit["ready"] is True
    assert rebound["interfaces"][0]["variants"][0]["build_context_id"] == "current-build"
    assert rebound["interfaces"][0]["variants"][0]["source_sha256"] == _sha(
        source.read_bytes()
    )


def test_unclosed_cross_tu_contract_keeps_only_safe_local_variant(tmp_path: Path) -> None:
    source = tmp_path / "memory.c"
    source.write_text(
        "void *project_alloc(unsigned long n) { return private_alloc(n); }\n",
        encoding="utf-8",
    )
    document = _document(tmp_path)
    row = document["interfaces"][0]
    row["variants"][0]["source_sha256"] = _sha(source.read_bytes())
    definition = {
        "kind": "program_function",
        "owner": {
            "name": "project_alloc",
            "usr": "c:@F@project_alloc",
            "file": str(source),
        },
        "callable": {
            "canonical_signature": "void *(unsigned long)",
            "external_linkage": True,
        },
        "events": [{"event_kind": "call", "callee": {"name": "private_alloc"}}],
    }
    call = {
        "kind": "call",
        "target": {"name": "project_alloc", "usr": "c:@F@project_alloc"},
    }

    class FakeIndex:
        @staticmethod
        def get_build_contexts():
            return [
                {"build_context_id": "definition-build"},
                {"build_context_id": "unclosed-caller-build"},
            ]

        @staticmethod
        def get_compilation_facts(build, *, kinds=()):
            return [definition] if build == "definition-build" else [call]

        @staticmethod
        def linked_targets():
            return SimpleNamespace(targets=[])

    rebound, audit = rebind_project_semantics(
        document,
        project_root=tmp_path,
        target_id="main",
        code_index=FakeIndex(),
    )

    assert audit["ready"] is False
    assert audit["unresolved"] == ["project:allocator:caller_outside_observed_link"]
    assert audit["contracts"][0]["status"] == "partial"
    assert audit["contracts"][0]["unclosed_consumer_build_context_ids"] == [
        "unclosed-caller-build"
    ]
    assert {variant["build_context_id"] for variant in rebound["interfaces"][0]["variants"]} == {
        "definition-build"
    }
    assert len(compiled_project_contracts(rebound, build_context_id="definition-build")) == 1
    assert compiled_project_contracts(rebound, build_context_id="unclosed-caller-build") == []


def test_reviewed_legacy_short_cpp_name_rebinds_only_with_same_exact_usr(
    tmp_path: Path,
) -> None:
    source = tmp_path / "env_posix.cc"
    source.write_text("void placeholder() {}\n", encoding="utf-8")
    document = _document(tmp_path)
    row = document["interfaces"][0]
    row["selector"].update(
        name="LockFile",
        file=source.name,
        signature="Status (void)",
        usr="c:@N@leveldb@S@PosixEnv@F@LockFile#",
    )
    row["derived_from"] = ["builtin:open"]
    row["variants"] = [
        {
            "target_id": "range",
            "build_context_id": "old-build",
            "usr": row["selector"]["usr"],
            "signature": row["selector"]["signature"],
            "file": source.name,
            "source_sha256": _sha(source.read_bytes()),
            "evidence_sha256": "a" * 64,
            "native_input_hash": "b" * 64,
            "identity_status": "exact",
        }
    ]
    definition = {
        "kind": "program_function",
        "owner": {
            "name": "leveldb::(anonymous namespace)::PosixEnv::LockFile",
            "usr": row["selector"]["usr"],
            "file": str(source),
        },
        "callable": {
            "canonical_signature": row["selector"]["signature"],
            "external_linkage": False,
        },
        "events": [{"event_kind": "call", "callee": {"name": "open"}}],
    }

    class FakeIndex:
        @staticmethod
        def get_build_contexts():
            return [{"build_context_id": "current-build"}]

        @staticmethod
        def get_compilation_facts(build, *, kinds=()):
            assert build == "current-build"
            return [definition]

        @staticmethod
        def linked_targets():
            return SimpleNamespace(targets=[])

    rebound, audit = rebind_project_semantics(
        document,
        project_root=tmp_path,
        target_id="range",
        code_index=FakeIndex(),
    )

    assert audit["ready"] is True
    assert rebound["interfaces"][0]["variants"][0]["build_context_id"] == "current-build"


def test_reviewed_macro_rebind_resolves_project_interface_root(tmp_path: Path) -> None:
    wrapper_source = tmp_path / "wrapper.c"
    wrapper_source.write_text(
        "void lock_wrapper(void *lock) { pthread_mutex_lock(lock); }\n",
        encoding="utf-8",
    )
    header = tmp_path / "wrappers.h"
    header.write_text(
        "#define LOCK(lock) lock_wrapper(lock)\n",
        encoding="utf-8",
    )
    document = _document(tmp_path)
    wrapper = document["interfaces"][0]
    wrapper["id"] = "project:function:lock_wrapper"
    wrapper["selector"].update(
        name="lock_wrapper",
        file="wrapper.c",
        signature="void (void *)",
        usr="c:@F@lock_wrapper",
    )
    wrapper["derived_from"] = ["builtin:pthread_mutex_lock"]
    wrapper["variants"] = [
        {
            "target_id": "range",
            "build_context_id": "old-build",
            "usr": "c:@F@lock_wrapper",
            "signature": "void (void *)",
            "file": "wrapper.c",
            "source_sha256": _sha(wrapper_source.read_bytes()),
            "evidence_sha256": "a" * 64,
            "native_input_hash": "b" * 64,
            "identity_status": "exact",
        }
    ]
    macro = deepcopy(wrapper)
    macro["id"] = "project:macro:LOCK"
    macro["selector"].update(
        kind="macro",
        name="LOCK",
        file="wrappers.h",
        signature="#define LOCK(lock)",
        usr="c:wrappers.h@0@macro@LOCK",
    )
    macro["derived_from"] = [wrapper["id"]]
    macro["variants"] = [
        {
            "target_id": "range",
            "build_context_id": "old-build",
            "usr": "c:wrappers.h@0@macro@LOCK",
            "signature": "#define LOCK(lock)",
            "file": "wrappers.h",
            "source_sha256": _sha(header.read_bytes()),
            "evidence_sha256": "c" * 64,
            "native_input_hash": "d" * 64,
            "identity_status": "exact",
        }
    ]
    document["interfaces"].append(macro)
    facts = [
        {
            "kind": "program_function",
            "owner": {
                "name": "lock_wrapper",
                "usr": "c:@F@lock_wrapper",
                "file": str(wrapper_source),
            },
            "callable": {
                "canonical_signature": "void (void *)",
                "external_linkage": True,
            },
            "events": [{"event_kind": "call", "callee": {"name": "pthread_mutex_lock"}}],
        },
        {
            "kind": "macro",
            "name": "LOCK",
            "usr": "c:wrappers.h@0@macro@LOCK",
            "definition": "#define LOCK(lock) lock_wrapper(lock)",
            "begin": {"file": str(header)},
        },
    ]

    class FakeIndex:
        @staticmethod
        def get_build_contexts():
            return [{"build_context_id": "current-build"}]

        @staticmethod
        def get_compilation_facts(build, *, kinds=()):
            assert build == "current-build"
            return facts

        @staticmethod
        def linked_targets():
            return SimpleNamespace(targets=[])

    rebound, audit = rebind_project_semantics(
        document,
        project_root=tmp_path,
        target_id="range",
        code_index=FakeIndex(),
    )

    assert audit["ready"] is True
    assert {row["id"] for row in audit["contracts"]} == {
        "project:function:lock_wrapper",
        "project:macro:LOCK",
    }
    assert rebound["interfaces"][1]["variants"][0]["build_context_id"] == "current-build"


def test_unclosed_pointer_call_is_coverage_gap_not_unconfirmable_row(tmp_path: Path) -> None:
    scope = InstanceScope(
        build_context_id="build-a",
        usr="c:@F@dispatch",
        identity="build-a:c:@F@dispatch",
        source=str(tmp_path / "dispatch.c"),
        function_names=("dispatch",),
    )
    event = {
        "event_id": "1:0",
        "event_kind": "call",
        "callee": {
            "name": "handler",
            "usr": "c:dispatch.c@F@dispatch@handler",
            "value_kind": "parameter",
            "canonical_signature": "void (*)(int)",
        },
        "location": {"file": str(tmp_path / "dispatch.c"), "line": 3},
    }
    rows, gaps = _exact_pointer_bindings(
        {
            "build-a": [
                (
                    scope,
                    {"file": str(tmp_path / "dispatch.c")},
                    {"functions": [{"events": [event]}]},
                    "dispatch",
                    "void (void (*)(int))",
                )
            ]
        }
    )

    assert rows == []
    assert gaps == ["indirect_call_target_set_unclosed:build-a:c:@F@dispatch:1:0"]


def test_human_discovery_receipt_keeps_machine_detail_out_of_yaml() -> None:
    facts = [{"analysis_unit_id": f"unit-{index}"} for index in range(3)]
    gaps = [f"indirect_call_target_set_unclosed:build:caller:{index}" for index in range(70)]

    projected = _human_discovery_receipt(
        {
            "schema": "zscope.primitive-discovery.v1",
            "function_fact_summaries": facts,
            "coverage_gaps": gaps,
            "blocking_coverage_gaps": [],
            "evidence_ref": ".zscope_snapshots/semantics/discovery-test.json",
        }
    )

    assert "function_fact_summaries" not in projected
    assert projected["function_fact_summary_count"] == 3
    assert projected["function_fact_summary_digest"]
    assert projected["coverage_gap_count"] == 70
    assert projected["coverage_gap_digest"]
    assert projected["coverage_gaps"] == sorted(gaps)[:50]
    assert projected["coverage_gaps_truncated"] is True
    assert projected["blocking_coverage_gaps"] == []


def test_discovery_batches_function_facts_once_per_build_context(tmp_path: Path) -> None:
    source = tmp_path / "wrappers.c"
    source.write_text(
        "void *wrap(unsigned long n) { return malloc(n); }\n" "int business(void) { return 1; }\n",
        encoding="utf-8",
    )
    wrapper = {
        "kind": "program_function",
        "complete": True,
        "owner": {"usr": "c:@F@wrap", "name": "wrap", "file": str(source), "line": 1},
        "callable": {
            "canonical_signature": "void *(unsigned long)",
            "external_linkage": True,
            "location": {"file": str(source), "line": 1, "offset": 6},
        },
        "events": [
            {
                "event_kind": "call",
                "callee": {
                    "name": "malloc",
                    "usr": "c:@F@malloc",
                    "canonical_signature": "void *(unsigned long)",
                    "is_system_header": True,
                },
            }
        ],
    }
    business = {
        "kind": "program_function",
        "complete": True,
        "owner": {
            "usr": "c:@F@business",
            "name": "business",
            "file": str(source),
            "line": 2,
        },
        "callable": {
            "canonical_signature": "int (void)",
            "external_linkage": True,
            "location": {"file": str(source), "line": 2, "offset": 61},
        },
        "events": [],
    }

    class FakeIndex:
        def __init__(self) -> None:
            self.calls = 0

        def get_build_contexts(self):
            return [
                {
                    "build_context_id": "build-a",
                    "source": str(source),
                    "status": "indexed",
                    "dependencies_complete": True,
                }
            ]

        def get_compilation_facts(self, build, *, kinds=()):
            assert build == "build-a"
            assert tuple(kinds) == ("program_function", "program_access")
            self.calls += 1
            return [wrapper, business]

    index = FakeIndex()
    scopes, gaps, work, manifests = _stream_function_work(index, tmp_path)

    assert gaps == []
    assert index.calls == 1
    assert len(manifests) == 2
    assert len(work["build-a"]) == 2
    assert all(item[2]["build_context_id"] == "build-a" for item in work["build-a"])
    assert all("build_context" not in item[2] for item in work["build-a"])
    relevant, candidates = _semantics_relevant_scopes(work, [])
    assert [(scope.build_context_id, scope.usr) for scope in relevant] == [("build-a", "c:@F@wrap")]
    assert candidates == {"build-a:c:@F@wrap"}


def test_direct_primitive_wrapper_is_not_dropped_by_cfg_size_limit(tmp_path: Path) -> None:
    """Direct semantic roots outrank the transitive-wrapper size heuristic."""

    source = tmp_path / "network.c"
    source.write_text("int receive(void *buffer) { return 0; }\n", encoding="utf-8")
    scope = InstanceScope(
        build_context_id="build-a",
        usr="c:@F@receive",
        identity="build-a:c:@F@receive",
        source=str(source),
        function_names=("receive",),
    )
    parameter = {"usr": "c:network.c@F@receive@buffer", "name": "buffer"}
    recv_call = {
        "event_kind": "call",
        "callee": {"name": "recv", "usr": "c:@F@recv"},
        "argument_uses": [[], [parameter], [], []],
    }
    # A realistic retry loop can project many CFG events even though the
    # semantic relationship itself is the exact direct recv call above.
    facts = {
        "functions": [
            {
                "parameters": [parameter],
                "events": [recv_call]
                + [{"event_kind": "branch", "event_id": f"branch:{index}"} for index in range(65)],
            }
        ]
    }
    work = {
        "build-a": [
            (
                scope,
                {"file": str(source)},
                facts,
                "receive",
                "int (void *)",
            )
        ]
    }

    relevant, candidates = _semantics_relevant_scopes(work, [])

    assert [(item.build_context_id, item.usr) for item in relevant] == [("build-a", "c:@F@receive")]
    assert candidates == {"build-a:c:@F@receive"}

    recv_contract = ApiContract(
        SymbolIdentity("recv"),
        "recv_source",
        ObjectBinding("argument", 1),
        source="builtin_defaults",
    )
    candidate = _lock_wrapper_candidate(
        facts=facts,
        semantics=SimpleNamespace(contracts=ContractRegistry([recv_contract])),
        root=tmp_path,
        source=str(source),
        code=source.read_text(encoding="utf-8"),
        build="build-a",
        usr=scope.usr,
        name="receive",
        signature="int (void *)",
    )

    assert candidate is not None
    assert candidate["effects"][0]["role"] == "recv_source"
    assert candidate["effects"][0]["carrier"]["index"] == 0


def test_standard_operation_wrapper_is_scheduled_for_native_discovery(tmp_path: Path) -> None:
    source = tmp_path / "path.c"
    source.write_text(
        "int path_exists(const char *path) { struct stat st; return stat(path, &st) == 0; }\n",
        encoding="utf-8",
    )
    scope = InstanceScope(
        build_context_id="build-a",
        usr="c:@F@path_exists",
        identity="build-a:c:@F@path_exists",
        source=str(source),
        function_names=("path_exists",),
    )
    work = {
        "build-a": [
            (
                scope,
                {"file": str(source)},
                {
                    "functions": [
                        {
                            "events": [
                                {
                                    "event_kind": "call",
                                    "callee": {"name": "stat", "usr": "c:@F@stat"},
                                }
                            ]
                        }
                    ]
                },
                "path_exists",
                "int (const char *)",
            )
        ]
    }

    relevant, candidates = _semantics_relevant_scopes(work, [])

    assert [(item.build_context_id, item.usr) for item in relevant] == [
        ("build-a", "c:@F@path_exists")
    ]
    assert candidates == {"build-a:c:@F@path_exists"}


def test_generic_standard_operation_wrapper_is_not_a_human_review_candidate(
    tmp_path: Path,
) -> None:
    source = tmp_path / "strings.c"
    source.write_text(
        "int same(const char *a, const char *b) { return strcmp(a, b) == 0; }\n",
        encoding="utf-8",
    )
    scope = InstanceScope(
        build_context_id="build-a",
        usr="c:@F@same",
        identity="build-a:c:@F@same",
        source=str(source),
        function_names=("same",),
    )
    work = {
        "build-a": [
            (
                scope,
                {"file": str(source)},
                {
                    "functions": [
                        {
                            "events": [
                                {
                                    "event_kind": "call",
                                    "callee": {"name": "strcmp", "usr": "c:@F@strcmp"},
                                }
                            ]
                        }
                    ]
                },
                "same",
                "int (const char *, const char *)",
            )
        ]
    }

    relevant, candidates = _semantics_relevant_scopes(work, [])

    assert relevant == []
    assert candidates == set()


def test_copy_root_is_not_projected_as_incomplete_one_carrier_contract(tmp_path: Path) -> None:
    source = tmp_path / "copy.c"
    source.write_text(
        "void copy_bytes(void *dst, const void *src, unsigned long n) { memcpy(dst, src, n); }\n",
        encoding="utf-8",
    )
    parameters = [
        {"usr": "c:copy.c@F@copy_bytes@dst", "name": "dst"},
        {"usr": "c:copy.c@F@copy_bytes@src", "name": "src"},
        {"usr": "c:copy.c@F@copy_bytes@n", "name": "n"},
    ]
    facts = {
        "functions": [
            {
                "parameters": parameters,
                "events": [
                    {
                        "event_kind": "call",
                        "callee": {"name": "memcpy", "usr": "c:@F@memcpy"},
                        "argument_uses": [[parameters[0]], [parameters[1]], [parameters[2]]],
                    }
                ],
            }
        ]
    }
    contract = ApiContract(
        SymbolIdentity("memcpy"),
        "copy",
        ObjectBinding("argument", 0),
        source="builtin_defaults",
    )

    candidate = _lock_wrapper_candidate(
        facts=facts,
        semantics=SimpleNamespace(contracts=ContractRegistry([contract])),
        root=tmp_path,
        source=str(source),
        code=source.read_text(encoding="utf-8"),
        build="build-a",
        usr="c:@F@copy_bytes",
        name="copy_bytes",
        signature="void (void *, const void *, unsigned long)",
    )

    assert candidate is None


def test_discovery_propagates_wrappers_across_real_link_group_only(tmp_path: Path) -> None:
    alloc_source = tmp_path / "alloc.c"
    factory_source = tmp_path / "factory.c"
    alloc_source.write_text("void *project_calloc(void) { return calloc(1, 1); }\n")
    factory_source.write_text(
        "void *make(void) { return project_calloc(); }\n",
        encoding="utf-8",
    )
    alloc_scope = InstanceScope(
        build_context_id="build-alloc",
        usr="c:@F@project_calloc",
        identity="build-alloc:c:@F@project_calloc",
        source=str(alloc_source),
        function_names=("project_calloc",),
    )
    factory_scope = InstanceScope(
        build_context_id="build-factory",
        usr="c:@F@make",
        identity="build-factory:c:@F@make",
        source=str(factory_source),
        function_names=("make",),
    )
    work = {
        "build-alloc": [
            (
                alloc_scope,
                {"file": str(alloc_source)},
                {
                    "functions": [
                        {
                            "events": [
                                {
                                    "event_kind": "call",
                                    "callee": {"name": "calloc", "usr": "c:@F@calloc"},
                                }
                            ]
                        }
                    ]
                },
                "project_calloc",
                "void *(void)",
            )
        ],
        "build-factory": [
            (
                factory_scope,
                {"file": str(factory_source)},
                {
                    "functions": [
                        {
                            "events": [
                                {
                                    "event_kind": "call",
                                    "callee": {
                                        "name": "project_calloc",
                                        "usr": "c:@F@project_calloc",
                                    },
                                }
                            ]
                        }
                    ]
                },
                "make",
                "void *(void)",
            )
        ],
    }

    _, isolated = _semantics_relevant_scopes(work, [])
    _, linked = _semantics_relevant_scopes(
        work,
        [],
        link_groups=[["build-alloc", "build-factory"]],
    )

    assert isolated == {alloc_scope.identity}
    assert linked == {alloc_scope.identity, factory_scope.identity}


def test_standard_operation_wrapper_candidate_maps_exact_public_argument(tmp_path: Path) -> None:
    source = tmp_path / "path.c"
    source.write_text(
        "int path_allowed(const char *path) { struct stat st; return stat(path, &st); }\n",
        encoding="utf-8",
    )
    parameter = {"usr": "c:path.c@F@path_allowed@path", "name": "path"}
    stat_contract = ApiContract(
        SymbolIdentity("stat"),
        "standard_operation",
        ObjectBinding("argument", 0),
        source="builtin_defaults",
    )
    facts = {
        "functions": [
            {
                "parameters": [parameter],
                "events": [
                    {
                        "event_kind": "call",
                        "callee": {"name": "stat", "usr": "c:@F@stat"},
                        "argument_uses": [[parameter], []],
                        "event_id": "1:0",
                    }
                ],
            }
        ]
    }

    candidate = _lock_wrapper_candidate(
        facts=facts,
        semantics=SimpleNamespace(contracts=ContractRegistry([stat_contract])),
        root=tmp_path,
        source=str(source),
        code=source.read_text(encoding="utf-8"),
        build="build-a",
        usr="c:@F@path_allowed",
        name="path_allowed",
        signature="int (const char *)",
    )

    assert candidate is not None
    assert candidate["derived_from"] == ["builtin:stat"]
    assert candidate["effects"][0]["role"] == "standard_operation"
    assert candidate["effects"][0]["carrier"]["index"] == 0
    assert candidate["effects"][0]["strength"] == "may"
