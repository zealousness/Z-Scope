"""No-YAML native closure, actual consumer effects and conservative gaps."""

from copy import deepcopy
import json

import pytest

from test_single_slot_pool import native_context, native_index
from test_instance_analysis import _native_config
from zscope.config.function_entry import FunctionEntry
from zscope.orchestration.entry_instances import plan_entry_instances
from zscope.orchestration.instance_semantics_context import freeze_instance_context
from zscope.retrieval.instance_index import instance_scope_from_entry_instance
from zscope.semantics.automatic import (
    AUTOMATIC_SOURCE,
    configuration_requirements,
    derive_automatic_contracts,
)
from zscope.semantics.contracts import ApiContract
from zscope.semantics.defaults import default_local_pattern_semantics
from zscope.semantics.instance_semantics import materialize_effect_semantics

CODE = """
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <pthread.h>
void *z_make(size_t n) { return malloc(n); }
void *a_make(size_t n) { return z_make(n); }
void drop(void *p) { free(p); }
void copy_bytes(void *out, const void *in, size_t n) { memcpy(out,in,n); }
int lock_now(pthread_mutex_t *m) { return pthread_mutex_lock(m); }
void lock_hidden(pthread_mutex_t *m) { pthread_mutex_lock(m); }
int close_now(int fd) { return close(fd); }
int close_hidden(int fd) { close(fd); return 0; }
ssize_t get_bytes(int fd, void *out, size_t n) { if(!out) return -1; return read(fd,out,n); }
int emit(const char *fmt) { return printf(fmt); }
void offset_copy(char *out, const char *in, size_t n) { memcpy(out+1,in,n); }
void mutate_copy(char *out, const char *in, size_t n) { out=0; memcpy(out,in,n); }
int transformed_lock(pthread_mutex_t *m) { return !pthread_mutex_lock(m); }
int parent_lock(pthread_mutex_t *m) { return lock_now(m); }
int narrow_fd(long fd) { return close(fd); }
int narrow_read(int fd, void *out, size_t n) { return read(fd,out,n); }
ssize_t reordered_read(void *out, int fd, size_t n) { return read(fd,out,n); }
void f(void) {
    void *p=a_make(8);
    if (!p) return;
    drop(p);
}
void leak(void) {
    void *p=a_make(8);
    if (!p) return;
    return;
}
void leaks_two(void) {
    void *p=a_make(8);
    void *q=a_make(16);
    return;
}
void releases_two(void) {
    void *p=a_make(8);
    void *q=a_make(16);
    drop(p);
    drop(q);
    return;
}
"""


@pytest.fixture
def automatic_project(tmp_path):
    source = tmp_path / "unit.c"
    source.write_text(CODE)
    cdb = tmp_path / "compile_commands.json"
    cdb.write_text(
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
    _native_config(tmp_path, cdb)
    backend, index = native_index(tmp_path, source, cdb)
    try:
        yield index, source, cdb
    finally:
        backend.close()


def derive(project, names):
    index, source, _ = project
    contexts = {"c:@F@" + name: native_context(index, source, name) for name in names}
    registry = default_local_pattern_semantics().contracts
    registry.build_context_id = next(iter(contexts.values()))["program_facts"]["build_context_id"]
    return derive_automatic_contracts(contexts, registry), contexts, registry


def test_native_closure_works_without_confirming_each_wrapper(automatic_project):
    result, _, _ = derive(
        automatic_project, ["a_make", "z_make", "drop", "parent_lock", "lock_now"]
    )
    roles = {(c["symbol"]["name"], c["role"]) for c in result["contracts"]}
    assert {
        ("a_make", "allocator"),
        ("z_make", "allocator"),
        ("drop", "deallocator"),
        ("lock_now", "lock"),
        ("parent_lock", "lock"),
    } <= roles, result
    assert result["llm_calls"] == 0
    assert result["derivation_attempts"] < 3 * len(result["units"])
    assert all(c["source"] == AUTOMATIC_SOURCE for c in result["contracts"])


@pytest.mark.parametrize(
    "name,role",
    [
        ("copy_bytes", "copy"),
        ("get_bytes", "recv_source"),
        ("emit", "format_sink"),
        ("close_now", "io_release"),
    ],
)
def test_native_forwarder_maps_real_effects(automatic_project, name, role):
    result, _, _ = derive(automatic_project, [name])
    assert any(c["role"] == role for c in result["contracts"]), result


@pytest.mark.parametrize(
    "name",
    [
        "offset_copy",
        "mutate_copy",
        "transformed_lock",
        "lock_hidden",
        "close_hidden",
        "narrow_fd",
        "narrow_read",
        "reordered_read",
    ],
)
def test_native_forwarder_does_not_guess_unsupported_effects(automatic_project, name):
    result, _, _ = derive(automatic_project, [name])
    assert not result["contracts"], result
    assert not result["complete_coverage_proven"]


def test_foreign_or_missing_callee_cannot_seed_a_closure(automatic_project):
    result, contexts, registry = derive(automatic_project, ["a_make"])
    assert not result["contracts"]
    raw = {
        "symbol": {"name": "z_make", "usr": "c:@F@z_make", "build_context_id": "foreign"},
        "role": "allocator",
        "carrier": {"kind": "return"},
        "source": "user",
    }
    registry.add(ApiContract.from_row({"contract": raw}))
    assert not derive_automatic_contracts(contexts, registry)["contracts"]


def test_source_changes_cannot_reuse_native_mapping(automatic_project):
    _, contexts, registry = derive(automatic_project, ["copy_bytes"])
    changed = deepcopy(contexts)
    changed["c:@F@copy_bytes"]["code"] = changed["c:@F@copy_bytes"]["code"].replace(
        "memcpy(out", "memcpy(out+1"
    )
    assert not derive_automatic_contracts(changed, registry)["contracts"]


def test_configuration_equivalence_does_not_confuse_same_object_with_same_guards(automatic_project):
    result, _, _ = derive(automatic_project, ["z_make"])
    configured = deepcopy(result["contracts"])
    configured[0]["source"] = "inferred:project_semantics:confirmed"
    configured[0]["verification"]["project_semantics_id"] = "user:allocator"
    result1 = configuration_requirements(configured, result["contracts"])
    assert result1["rows"][0]["status"] == "automatically_equivalent"
    configured[0]["effect_cases"] = [{"when": {"op": "true"}, "effect": "applies"}]
    result2 = configuration_requirements(configured, result["contracts"])
    assert result2["rows"][0]["status"] == "boundary_derived_contract_differs"
    assert not result2["rows"][0]["removal_proven"]
    assert not result2["minimum_proven"]


def test_project_relative_selector_does_not_create_a_second_native_identity(automatic_project):
    from zscope.semantics.automatic import align_project_identities
    from zscope.semantics.contracts import ContractRegistry

    result, _, registry = derive(automatic_project, ["z_make"])
    raw = result["contracts"][0]
    configured = deepcopy(raw)
    configured["symbol"]["file_path"] = "unit.c"
    configured["source"] = "inferred:project_semantics:confirmed"
    configured["pairs"] = []
    aligned = align_project_identities([raw], [configured])[0]
    merged = ContractRegistry(build_context_id=registry.build_context_id)
    merged.add(ApiContract.from_row({"contract": raw}))
    merged.add(ApiContract.from_row({"contract": aligned}))
    assert len(merged.find_for_call("z_make", "allocator", usr="c:@F@z_make")) == 1
    assert not merged.pairs  # Explicit empty pairing overrides automatic edges.
    assert configured["symbol"]["file_path"] == "unit.c"
    other = deepcopy(configured)
    other["symbol"]["build_context_id"] = "other-variant"
    assert align_project_identities([raw], [other])[0]["symbol"] == other["symbol"]


def test_empty_yaml_publishes_native_closure_and_revokes_after_edit(automatic_project):
    index, source, cdb = automatic_project
    config = _native_config(source.parent, cdb)
    plan = plan_entry_instances(index, [FunctionEntry("f", file_path="unit.c")])
    scopes = [instance_scope_from_entry_instance(i) for i in plan.instances]
    frozen = freeze_instance_context(
        config=config, code_index=index, semantics_path=config.project.semantics_file, scopes=scopes
    )
    assert not frozen.unavailable, frozen.unavailable
    snapshot = next(iter(frozen.snapshots.values()))
    semantics, overlay = materialize_effect_semantics(snapshot)
    assert not overlay["project_contracts"]
    assert overlay["automatic_derivation"]["llm_calls"] == 0
    assert semantics.contracts.find_for_call("a_make", "allocator", usr="c:@F@a_make")
    assert semantics.contracts.find_for_call("drop", "deallocator", usr="c:@F@drop")
    assert not semantics.contracts.find_for_call("a_make", "allocator", usr="")
    from zscope.core.candidates.clang_ast_cfg import ClangAstCfgCandidateGenerator

    findings = {}
    for name in ["f", "leak", "leaks_two", "releases_two"]:
        ctx = native_context(index, source, name)
        generator = ClangAstCfgCandidateGenerator(
            semantics,
            restrict_to_semantics=True,
            program_facts_provider=lambda *args, f=ctx["program_facts"]: f,
        )
        findings[name] = generator.generate_issues(name, ctx["code"], str(source))
        assert any(c["symbol"]["name"] == "a_make" for c in generator.last_semantic_events)
    assert any(c.get("defect_class") == "memory_leak" for c in findings["leak"]), findings
    assert not any(c.get("defect_class") == "memory_leak" for c in findings["f"]), findings
    distinct = [
        c
        for c in findings["leaks_two"]
        if c["rule_id"] == "clang_cfg_acquire_without_release_on_exit"
    ]
    assert len(distinct) == 2, findings["leaks_two"]
    assert len({c["candidate_id"] for c in distinct}) == 2
    assert not any(
        c["rule_id"] == "clang_cfg_acquire_without_release_on_exit"
        for c in findings["releases_two"]
    )
    assert frozen.is_current(snapshot)
    source.write_text(CODE.replace("return z_make(n);", "return 0;"))
    assert not frozen.is_current(snapshot)


@pytest.mark.parametrize("link_mode", ["current", "missing", "ambiguous"])
def test_automatic_exports_follow_actual_link_and_revoke_definition_edits(tmp_path, link_mode):
    from test_link_targets import build_project
    from zscope.retrieval.link_targets import record_link

    database, command, _ = build_project(
        tmp_path,
        {
            "a.c": "#include <stdlib.h>\nvoid *make(size_t); void drop(void*); int main(void) {void *p=make(8); drop(p); return 0;}\n",
            "b.c": "#include <stdlib.h>\nvoid *make(size_t n) {return malloc(n);} void drop(void *p) {free(p);}\n",
        },
    )
    if link_mode == "ambiguous":
        record_link(
            tmp_path, database, [*command[:-1], str(tmp_path / "other-app")], directory=tmp_path
        )
    if link_mode == "missing":
        for path in (tmp_path / ".zscope-link-targets").glob("*.json"):
            path.unlink()
    config = _native_config(tmp_path, database)
    backend, index = native_index(tmp_path, tmp_path / "a.c", database)
    try:
        plan = plan_entry_instances(
            index, [FunctionEntry("main", file_path="a.c"), FunctionEntry("make", file_path="b.c")]
        )
        scopes = [instance_scope_from_entry_instance(i) for i in plan.instances]
        frozen = freeze_instance_context(
            config=config,
            code_index=index,
            semantics_path=config.project.semantics_file,
            scopes=scopes,
        )
        assert not frozen.unavailable, frozen.unavailable
        snapshot = next(s for s in frozen.snapshots.values() if s.scope.usr == "c:@F@main")
        semantics, overlay = materialize_effect_semantics(snapshot)
        matches = semantics.contracts.find_for_call("make", "allocator", usr="c:@F@make")
        if link_mode != "current":
            assert not matches
            return
        assert matches and overlay["automatic_derivation"]["linked_imports"] == 2, overlay[
            "automatic_derivation"
        ]
        assert (
            matches[0].verification["definition_build_context_id"]
            != snapshot.scope.build_context_id
        )
        assert frozen.is_current(snapshot)
        source = tmp_path / "b.c"
        source.write_text(source.read_text().replace("malloc(n)", "0"))
        assert not frozen.is_current(snapshot)
    finally:
        backend.close()
