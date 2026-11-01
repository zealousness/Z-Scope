"""RAPI02-05: real native CFGs -> contracts -> workbook -> existing consumers."""

from copy import deepcopy
import json

import pytest

from test_single_slot_pool import native_context, native_index
from test_wrapper_contract_compiler import publish
from zscope.semantics.build_scope import bind_build_scope
from zscope.semantics.contract_compiler import compile_snapshot, derive_contracts
from zscope.semantics.contracts import ApiContract
from zscope.semantics.defaults import default_local_pattern_semantics
from zscope.semantics.native_wrappers import infer_native_wrapper

CODE = """
#define _POSIX_C_SOURCE 200112L
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
typedef struct Box { void *slot; } Box;
void opaque(void *);
void note(int);
void *saved;
void *direct(void) { return malloc(8); }
void *sized(size_t n) { return malloc(n); }
void *logged_failure(size_t n) { void *p=malloc(n); if(!p && n>0) {note(1); return NULL;} return p; }
void *resize(void *old,size_t n) {void *p=realloc(old,n); if(!p && n>0) {note(2); return NULL;} return p;}
char *duplicate(const char *s) {if(!s) return NULL; size_t n=strlen(s)+1; char *p=malloc(n); if(p) memcpy(p,s,n); return p;}
char *duplicate_nested(const char *s) {if(!s) return NULL; size_t n=strlen(s)+1; char *p=logged_failure(n); if(p) memcpy(p,s,n); return p;}
char *duplicate_cast(const char *s) {if(!s) return NULL; size_t n=strlen(s)+1; char *p=(char*)logged_failure(n); if(p) memcpy(p,s,n); return p;}
void *alias(void) { void *p=malloc(8); void *q=p; p=0; return q; }
void *cleanup(int bad) { void *p=malloc(8); if(!p) return NULL; if(bad) {free(p); return NULL;} return p; }
int make(void **out, int bad) {void *p=malloc(8); if(!p) return 1; if(bad) {free(p); return 2;} *out=p; return 0;}
int make2(int bad,void **out) {int r=make(out,bad); if(r != 0) return -1; return 0;}
int field(Box *box) {void *p=malloc(8); if(!p) return 1; box->slot=p; return 0;}
int field_aligned(Box *box) {int rc=posix_memalign(&box->slot,16,32); if(rc != 0) return 1; return 0;}
int alias_out(void **out) {void **pp=out; void *p=malloc(8); if(!p) return 1; *pp=p; return 0;}
void *aligned(void) {void *p; int rc=posix_memalign(&p,16,32); if(rc != 0) return NULL; return p;}
void *unchecked(void) {void *p; posix_memalign(&p,16,32); return p;}
void *borrowed(void *old,int keep) {if(keep) return old; return malloc(8);}
void *released(void) {void *p=malloc(8); free(p); return p;}
void *escaped(void) {void *p=malloc(8); saved=p; return p;}
void *retained(Box *box) {void *p=malloc(8); box->slot=p; return p;}
int alias_slots(void **out,void **other) {void *p=malloc(8); if(!p) return 1; *out=p; *other=0; return 0;}
void *varying_extent(int big) {int n=8; if(big) n=16; return malloc(n);}
void *opaque_call(void) {void *p=malloc(8); opaque(p); return p;}
void *two(void) {void *p=malloc(8); void *q=malloc(8); free(q); return p;}
void *indirect(void (*fn)(void *)) {void *p=malloc(8); fn(p); return p;}
void *overwritten(void *old) {void *p=malloc(8); p=old; return p;}
int status_conflict(void **out,int bad) {void *p=malloc(8); if(!p) return 0; *out=p; return 0;}
int ignored_malloc(void **out) {*out=malloc(8); return 0;}
void *narrow(int n) {void *p=malloc(8); unsigned char c=n; if(c) free(p); return p;}
void dispose(int enabled,void *p) {void *q=p; p=0; if(enabled) free(q);}
void repeat(void *p) {free(p); free(p);}
void use_status(void) {void *p; int status=make(&p,0); if(status != 0) return; free(p);}
int path_exists(const char *path) {if(!path) return 0; struct stat st; return stat(path,&st)==0;}
"""


@pytest.fixture(scope="module")
def wrapper_project(tmp_path_factory):
    root = tmp_path_factory.mktemp("native-wrapper")
    source, database = root / "wrappers.c", root / "compile_commands.json"
    source.write_text(CODE)
    database.write_text(
        json.dumps(
            [
                {
                    "directory": str(root),
                    "file": str(source),
                    "arguments": ["clang", "-std=c11", "-c", str(source)],
                }
            ]
        )
    )
    backend, index = native_index(root, source, database)
    try:
        yield index, source
    finally:
        backend.close()


def checked(project, name, registry=None):
    index, source = project
    context = native_context(index, source, name)
    registry = registry or default_local_pattern_semantics().contracts
    return context, infer_native_wrapper(context, registry)


@pytest.mark.parametrize(
    "name,kind,index,path",
    [
        ("direct", "return", None, ""),
        ("alias", "return", None, ""),
        ("cleanup", "return", None, ""),
        ("make", "output_argument", 0, ""),
        ("field", "argument", 0, "->slot"),
        ("aligned", "return", None, ""),
        ("sized", "return", None, ""),
        ("logged_failure", "return", None, ""),
        ("duplicate", "return", None, ""),
        ("alias_out", "output_argument", 0, ""),
        ("field_aligned", "argument", 0, "->slot"),
    ],
)
def test_native_positive_carrier_and_success(wrapper_project, name, kind, index, path):
    ctx, result = checked(wrapper_project, name)
    assert result["attempted"] and not result["reasons"], result
    (raw,) = result["contracts"]
    contract = ApiContract.from_row({"contract": raw})
    assert contract.effects_trusted
    assert (
        contract.carrier.kind,
        contract.carrier.argument_index,
        contract.carrier.member_path,
    ) == (kind, index, path)
    assert contract.verification["checker"] == "native_wrapper_value_flow.v2"
    assert not contract.verification["fresh_no_alias"]
    assert raw["evidence"][0]["function_usr"] == "c:@F@" + name
    assert raw["evidence"][0]["build_context_id"] == ctx["program_facts"]["build_context_id"]


def test_native_reallocator_preserves_replace_and_failure_protocol(wrapper_project):
    _, result = checked(wrapper_project, "resize")
    assert result["attempted"] and not result["reasons"], result
    (raw,) = result["contracts"]
    contract = ApiContract.from_row({"contract": raw})
    assert contract.effects_trusted and contract.role == "reallocator"
    assert contract.carrier.kind == "return"
    actions = [
        action
        for transition in contract.protocol["transitions"]
        for action in transition["actions"]
    ]
    replacement = next(action for action in actions if action["kind"] == "replace")
    preservation = next(action for action in actions if action["kind"] == "preserve")
    assert replacement["old"] == {"kind": "argument", "index": 0}
    assert replacement["new"] == {"kind": "return"}
    assert preservation["object"] == {"kind": "argument", "index": 0}


def test_native_allocator_wrapper_fixed_point_supports_copying_wrapper(wrapper_project):
    registry = default_local_pattern_semantics().contracts
    _, inner = checked(wrapper_project, "logged_failure", registry)
    registry.add(ApiContract.from_row({"contract": inner["contracts"][0]}))
    _, outer = checked(wrapper_project, "duplicate_nested", registry)
    assert outer["attempted"] and not outer["reasons"], outer
    contract = ApiContract.from_row({"contract": outer["contracts"][0]})
    assert contract.effects_trusted and contract.role == "allocator"


def test_native_wrapper_uses_exact_callee_usr_without_scan_call_context(wrapper_project):
    registry = default_local_pattern_semantics().contracts
    context, inner = checked(wrapper_project, "logged_failure", registry)
    row = deepcopy(inner["contracts"][0])
    row["symbol"]["usr"] = context["program_facts"]["functions"][0]["owner"]["usr"]
    registry.add(ApiContract.from_row({"contract": row}))
    _, result = checked(wrapper_project, "duplicate_nested", registry)
    assert result["contracts"] and not result["reasons"], result
    other = default_local_pattern_semantics().contracts
    row["symbol"]["usr"] = "c:@F@different_function"
    other.add(ApiContract.from_row({"contract": row}))
    _, rejected = checked(wrapper_project, "duplicate_nested", other)
    assert not rejected["contracts"] and rejected["reasons"]


def test_native_standard_operation_wrapper_preserves_argument_guard(wrapper_project):
    _, result = checked(wrapper_project, "path_exists")

    assert result["attempted"] and not result["reasons"], result
    contract = ApiContract.from_row({"contract": result["contracts"][0]})
    assert contract.effects_trusted and contract.role == "standard_operation"
    assert contract.carrier.kind == "argument" and contract.carrier.argument_index == 0
    assert contract.applicability(["path"], facts={"path": None}) == "does_not_apply"
    assert contract.applicability(["path"], facts={"path": "/tmp/key"}) == "applies"
    assert contract.verification["checker"] == "native_standard_wrapper_value_flow.v1"


def test_native_allocator_wrapper_preserves_exact_call_identity_through_pointer_cast(
    wrapper_project,
):
    registry = default_local_pattern_semantics().contracts
    _, inner = checked(wrapper_project, "logged_failure", registry)
    registry.add(ApiContract.from_row({"contract": inner["contracts"][0]}))

    _, outer = checked(wrapper_project, "duplicate_cast", registry)

    assert outer["attempted"] and not outer["reasons"], outer
    contract = ApiContract.from_row({"contract": outer["contracts"][0]})
    assert contract.effects_trusted and contract.role == "allocator"


@pytest.mark.parametrize(
    "name",
    [
        "unchecked",
        "borrowed",
        "released",
        "escaped",
        "opaque_call",
        "two",
        "indirect",
        "overwritten",
        "status_conflict",
        "ignored_malloc",
        "narrow",
        "retained",
        "alias_slots",
        "varying_extent",
        "repeat",
    ],
)
def test_native_negative_never_falls_back_to_token_authority(wrapper_project, name):
    ctx, result = checked(wrapper_project, name)
    assert result["attempted"] and result["reasons"] and not result["contracts"], result
    registry = default_local_pattern_semantics().contracts
    assert not any(
        ApiContract.from_row({"contract": r}).effects_trusted
        for r in derive_contracts(ctx, registry)
    )
    snap = {**ctx, "interface_contracts": []}
    compile_snapshot(snap, ctx, registry)
    assert any(
        d["action"] == "native_value_flow" and d["errors"] for d in snap["contract_diagnostics"]
    )


def test_two_layers_and_reordered_output_survive_workbook(wrapper_project, tmp_path):
    registry = default_local_pattern_semantics().contracts
    ctx, result = checked(wrapper_project, "make", registry)
    (raw,) = result["contracts"]
    registry.add(ApiContract.from_row({"contract": raw}))
    outer, second = checked(wrapper_project, "make2", registry)
    assert second["contracts"], second
    (outer_raw,) = second["contracts"]
    assert outer_raw["carrier"]["argument_index"] == 1
    _, custom, overlay = publish(
        tmp_path,
        [{**ctx, "interface_contracts": [raw]}, {**outer, "interface_contracts": [outer_raw]}],
    )
    effective = default_local_pattern_semantics()
    effective.merge(custom)
    with bind_build_scope(ctx):
        assert not effective.contracts.find_for_call("make2")
    with bind_build_scope(outer):
        (contract,) = effective.contracts.find_for_call("make2")
        assert contract.effects_trusted and contract.carrier.resolve(["bad", "&p"], "rc") == "p"
        assert contract.applicability(["bad", "&p"], "rc", facts={"rc": 0}) == "applies"
        assert contract.applicability(["bad", "&p"], "rc", facts={"rc": -1}) == "does_not_apply"
        assert contract.applicability(["bad", "&p"], "rc") == "unknown"
    assert overlay["api_contracts"]


def test_release_wrapper_keeps_entry_alias_and_guard(wrapper_project):
    _, result = checked(wrapper_project, "dispose")
    assert result["contracts"], result
    contract = ApiContract.from_row({"contract": result["contracts"][0]})
    assert contract.role == "deallocator" and contract.carrier.argument_index == 1
    assert (
        contract.applicability(["enabled", "p"], facts={"enabled": 1, "p": {"identity": "live"}})
        == "applies"
    )
    assert (
        contract.applicability(["enabled", "p"], facts={"enabled": 0, "p": {"identity": "live"}})
        == "does_not_apply"
    )
    assert contract.applicability(["enabled", "p"]) == "unknown"


def test_published_native_output_is_the_same_object_in_consumers(wrapper_project, tmp_path):
    from zscope.core.candidates.regex import RegexCandidateGenerator
    from zscope.core.candidates.clang_ast_cfg import ClangAstCfgCandidateGenerator
    from zscope.core.candidates.graph import GraphCandidateGenerator
    from zscope.config.function_entry import FunctionEntry
    from zscope.semantics.security_map import ZeroLLMSecurityMapBuilder

    ctx, result = checked(wrapper_project, "make")
    _, custom, overlay = publish(tmp_path, [{**ctx, "interface_contracts": result["contracts"]}])
    semantics = default_local_pattern_semantics()
    semantics.merge(custom)
    index, source = wrapper_project
    caller = native_context(index, source, "use_status")
    for cls in (RegexCandidateGenerator, ClangAstCfgCandidateGenerator):
        engine = cls(semantics, program_facts_provider=index.get_function_program_facts)
        engine.generate_issues("use_status", caller["code"], str(source))
        calls = [c for c in engine.last_semantic_events if c["symbol"]["name"] == "make"]
        assert calls and {c["object"] for c in calls} == {"p"}
        assert all(
            c["applicability"] == "unknown" for c in calls
        )  # Status not established at the call.
    graph = GraphCandidateGenerator(index, semantics, overlay)
    calls = graph.semantics.contracts.trace_calls(caller)
    assert {c["object"] for c in calls if c["symbol"]["name"] == "make"} == {"p"}
    security = ZeroLLMSecurityMapBuilder(
        index,
        project_id="wrappers",
        revision="fixture",
        profile="balanced",
        semantic_overlay=overlay,
    ).build([FunctionEntry("use_status", file_path=str(source))])
    claims = [
        c.value["call_semantics"]
        for c in security.claims
        if c.value.get("call_semantics", {}).get("symbol", {}).get("name") == "make"
    ]
    assert claims and {c["object"] for c in claims} == {"p"}


def test_changed_or_unverified_root_cannot_keep_native_effects(wrapper_project):
    from dataclasses import replace

    ctx, result = checked(wrapper_project, "make")
    root = ApiContract.from_row({"contract": result["contracts"][0]})
    registry = default_local_pattern_semantics().contracts
    registry.add(root)
    outer, good = checked(wrapper_project, "make2", registry)
    assert good["contracts"]
    registry.add(replace(root, verification={"method": "schema_only"}, confidence=1.0))
    assert not infer_native_wrapper(outer, registry)["contracts"]


@pytest.mark.parametrize(
    "change", ["receipt", "cfg", "source", "source_guard", "scope", "value", "guard"]
)
def test_conflicting_native_input_is_not_authority(wrapper_project, change):
    ctx, _ = checked(wrapper_project, "make")
    ctx = deepcopy(ctx)
    body = ctx["program_facts"]["functions"][0]
    if change == "receipt":
        body.pop("lifecycle_value_facts_version")
    elif change == "cfg":
        body.pop("cfg_entry")
    elif change == "source":
        ctx["code"] = ctx["code"].replace("return 0", "return 7")
    elif change == "source_guard":
        ctx["code"] = ctx["code"].replace("if(bad)", "if(!bad)")
    elif change == "scope":
        ctx["build_context_id"] = "wrong-build"
    elif change == "value":
        body["parameters"][0]["usr"] = "foreign-frame"
    else:
        for edge in body["cfg_edges"]:
            if edge.get("condition"):
                edge["condition"] = "unknown_guard()"
    result = infer_native_wrapper(ctx, default_local_pattern_semantics().contracts)
    assert result["attempted"] and result["reasons"] and not result["contracts"], result


def test_error_cleanup_retains_all_root_proof_dependencies(wrapper_project):
    from zscope.semantics.contract_review import proof_key

    _, result = checked(wrapper_project, "cleanup")
    registry = default_local_pattern_semantics().contracts
    expected = {proof_key(c) for name in ("malloc", "free") for c in registry.find(name)}
    assert expected <= set(result["contracts"][0]["verification"]["proof_dependencies"])


def test_native_project_definition_cannot_inherit_standard_malloc(tmp_path):
    source, database = tmp_path / "shadow.c", tmp_path / "compile_commands.json"
    source.write_text(
        "void *malloc(__SIZE_TYPE__ n) {return (void *)0;}\n"
        "void *shadow_wrapper(void) {return malloc(8);}\n"
    )
    database.write_text(
        json.dumps(
            [
                {
                    "directory": str(tmp_path),
                    "file": str(source),
                    "arguments": ["clang", "-std=c11", "-c", str(source)],
                }
            ]
        )
    )
    backend, index = native_index(tmp_path, source, database)
    try:
        ctx, result = checked((index, source), "shadow_wrapper")
        assert result["attempted"] and not result["contracts"]
        assert "project_shadows_standard" in result["reasons"]
        assert not derive_contracts(ctx, default_local_pattern_semantics().contracts)
    finally:
        backend.close()
