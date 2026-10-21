import json
import os
from pathlib import Path
import shutil
import sys
import time
from types import SimpleNamespace

import pytest

import zscope.core.validation.dynamic_reproduction as dynamic_reproduction
from zscope.core.validation.dynamic_reproduction import (
    AsanReproductionRunner,
    CandidateBinding,
    DynamicReproductionError,
    DynamicReproductionPolicy,
    SanitizerFinding,
    match_witness_to_candidate,
)
from zscope.core.validation.reproduction_planner import SessionReproductionPlanner
from zscope.retrieval.clang_backend import ClangBackend
from zscope.semantics.resource_identity import native_heap_witness


@pytest.fixture
def program(tmp_path):
    executable = os.environ.get("Z_SCOPE_TEST_CLANG_INDEXER")
    compiler = shutil.which("clang")
    if not executable or not compiler:
        pytest.skip("real native indexing and clang required")
    project = tmp_path / "project"
    project.mkdir()
    source = project / "unit.c"
    source.write_text(
        "#include <stdlib.h>\n"
        "int main(void) {\n"
        "  char *p = malloc(4);\n"
        "  if (!p) return 1;\n"
        "#ifdef SAFE\n"
        "  p[0] = 1;\n"
        "#else\n"
        "  p[8] = 1;\n"
        "#endif\n"
        "  free(p);\n"
        "  return 0;\n}\n",
        encoding="utf-8",
    )

    def indexed(*flags):
        database = project / "compile_commands.json"
        database.write_text(
            json.dumps(
                [
                    {
                        "file": str(source),
                        "directory": str(project),
                        "arguments": [compiler, "-c", str(source), *flags],
                    }
                ]
            )
        )
        backend = ClangBackend(frontend="batch", clang_indexer_path=executable, max_threads=1)
        assert backend.initialize(str(project), compile_commands_path=str(database))
        return backend

    config = SimpleNamespace(
        project=SimpleNamespace(project_root=project, project_id="test-project"),
        analysis=SimpleNamespace(snapshot_dir=tmp_path / "artifacts"),
    )
    issue = {
        "id": "overflow",
        "defect_class": "heap_buffer_overflow",
        "location": "unit.c:8",
        "function": "main",
        "resource_identity": "p",
    }
    return source, indexed, config, issue


def test_real_automatic_plan_build_execute_and_witness(program):
    source, indexed, config, issue = program
    original = source.read_bytes()
    backend = indexed()
    try:
        service = SessionReproductionPlanner(config, backend)
        service.attempt(issue, DynamicReproductionPolicy(enabled=True))
        assert issue["dynamic_reproduction_attempt"]["status"] == "attempted", issue[
            "dynamic_reproduction_attempt"
        ]
        result_path = (
            Path(issue["dynamic_reproduction_attempt"]["artifact_directory"]) / "result.json"
        )
        result = json.loads(result_path.read_text())
        assert result["proof_attached"], result
        assert source.read_bytes() == original
        assert not list(source.parent.glob("*.o"))
        plan = json.loads((result_path.parent / "plan.json").read_text())
        assert plan["binding"]["build_configuration"] == issue["build_context_id"]
        assert plan["harness_ref"] == str(source)
    finally:
        backend.close()


def test_real_safe_build_stays_unresolved_not_rejected(program):
    source, indexed, config, issue = program
    backend = indexed("-DSAFE=1")
    try:
        SessionReproductionPlanner(config, backend).attempt(
            issue, DynamicReproductionPolicy(enabled=True)
        )
        assert issue["dynamic_reproduction_attempt"]["status"] == "attempted", issue[
            "dynamic_reproduction_attempt"
        ]
        result = json.loads(
            (
                Path(issue["dynamic_reproduction_attempt"]["artifact_directory"]) / "result.json"
            ).read_text()
        )
        assert not result["proof_attached"]
        assert "deterministic_proofs" not in issue
        assert "candidate_disposition" not in issue
    finally:
        backend.close()


def test_changed_source_does_not_execute_cached_plan(program):
    source, indexed, config, issue = program
    backend = indexed()
    try:
        service = SessionReproductionPlanner(config, backend)
        source.write_text(source.read_text() + "\n/* changed */\n")
        service.attempt(issue, DynamicReproductionPolicy(enabled=True))
        assert issue["dynamic_reproduction_attempt"]["reason"] == "stale_build_dependencies"
        assert not service.artifact_root.exists()
    finally:
        backend.close()


def test_compile_outputs_are_redirected_and_macro_flags_preserved(tmp_path):
    argv = SessionReproductionPlanner._build_arguments(
        ["clang", "-c", "unit.c", "-DSAFE=1", "-O3", "-o", "unit.o", "-MMD", "-MF", "unit.d"],
        {},
        "/usr/bin/clang",
        tmp_path / "program",
        "asan",
    )
    assert argv == [
        "/usr/bin/clang",
        "unit.c",
        "-DSAFE=1",
        "-fsanitize=address",
        "-g",
        "-O0",
        "-fno-omit-frame-pointer",
        "-o",
        str(tmp_path / "program"),
    ]


# --------------------------------------------------------------------------
# Shared build receipt: one verified build per verification, never a rebind
# --------------------------------------------------------------------------


def _shared_budget(policy, run_limit=3):
    return dynamic_reproduction._ExecutionBudget(
        run_limit=run_limit, deadline=time.monotonic() + policy.deadline_seconds
    )


def test_replay_reuses_the_verified_build_without_recompiling(program):
    source, indexed, config, issue = program
    backend = indexed()
    try:
        service = SessionReproductionPlanner(config, backend)
        policy = DynamicReproductionPolicy(enabled=True)
        plan = service.plan(issue, policy)
        runner = AsanReproductionRunner(policy=policy)
        budget = _shared_budget(policy)
        runner.use_budget(budget)
        primary = runner.execute(plan)
        assert primary.outcome == "witness_observed"
        assert primary.build_exit_code == 0
        assert budget.builds_started == 1
        replay = runner.execute(plan)
        assert replay.outcome == "witness_observed"
        # No second compile: the replay re-executed the binary the primary
        # build produced and verified, bound by the shared receipt.
        assert replay.build_exit_code is None
        assert replay.build_argv == primary.build_argv
        assert "binary_reused_from_shared_build_receipt" in replay.limitations
        assert replay.binary_digest == primary.binary_digest
        assert replay.binary_identity_source == "post_build_output"
        assert replay.plan_digest == primary.plan_digest
        assert budget.builds_started == 1
        assert budget.runs_started == 2
    finally:
        backend.close()


def test_tampered_binary_after_build_stops_the_replay(program):
    source, indexed, config, issue = program
    backend = indexed()
    try:
        service = SessionReproductionPlanner(config, backend)
        policy = DynamicReproductionPolicy(enabled=True)
        plan = service.plan(issue, policy)
        runner = AsanReproductionRunner(policy=policy)
        budget = _shared_budget(policy)
        runner.use_budget(budget)
        primary = runner.execute(plan)
        assert primary.outcome == "witness_observed"
        binary = Path(plan.binary_path)
        binary.write_bytes(binary.read_bytes() + b"tampered")
        replay = runner.execute(plan)
        assert replay.outcome == "unsupported"
        assert replay.detail == "plan_identity_changed_during_execution"
        assert "binary_identity_mismatch" in replay.limitations
        assert "unverified_plan_never_launched" in replay.limitations
        assert replay.runs == ()
        # The tampered binary was never launched and the receipt never rebinds:
        # a later attempt stops the same way instead of rebuilding.
        again = runner.execute(plan)
        assert again.outcome == "unsupported"
        assert "binary_identity_mismatch" in again.limitations
        assert budget.builds_started == 1
        assert budget.runs_started == 1
    finally:
        backend.close()


def test_build_receipt_conflict_is_refused():
    budget = _shared_budget(DynamicReproductionPolicy(enabled=True), run_limit=1)
    assert budget.build_receipt("plan-a") == ""
    budget.record_build_receipt("plan-a", "a" * 64)
    assert budget.build_receipt("plan-a") == "a" * 64
    budget.record_build_receipt("plan-a", "a" * 64)
    with pytest.raises(dynamic_reproduction._PlanViolation, match="build_receipt_conflict"):
        budget.record_build_receipt("plan-a", "b" * 64)


# --------------------------------------------------------------------------
# Session isolation
# --------------------------------------------------------------------------


def test_session_refuses_a_different_index(program):
    source, indexed, config, issue = program
    backend = indexed()
    try:
        service = SessionReproductionPlanner(config, backend)
        with pytest.raises(ValueError, match="reproduction_session_index_changed"):
            service.attach_index(object())
    finally:
        backend.close()


def test_session_plan_does_not_consult_the_global_provider(program):
    source, indexed, config, issue = program
    backend = indexed()
    try:
        service = SessionReproductionPlanner(config, backend)

        def forbidden(*_args):
            raise AssertionError("process-global provider consulted by a session")

        dynamic_reproduction.register_dynamic_reproduction_plan_provider(forbidden)
        try:
            service.attempt(issue, DynamicReproductionPolicy(enabled=True))
        finally:
            dynamic_reproduction.register_dynamic_reproduction_plan_provider(None)
        assert issue["dynamic_reproduction_attempt"]["status"] == "attempted"
    finally:
        backend.close()


# --------------------------------------------------------------------------
# Compile argument rewriting keeps semantics, redirects only outputs
# --------------------------------------------------------------------------


def test_compile_arguments_keep_language_modes_and_drop_joined_outputs(tmp_path):
    argv = SessionReproductionPlanner._build_arguments(
        ["clang", "-c", "unit.m", "-ObjC", "-O2", "-ofoo.o", "-MT", "dep", "-MQjoined"],
        {},
        "/usr/bin/clang",
        tmp_path / "program",
        "asan",
    )
    assert argv == [
        "/usr/bin/clang",
        "unit.m",
        "-ObjC",
        "-fsanitize=address",
        "-g",
        "-O0",
        "-fno-omit-frame-pointer",
        "-o",
        str(tmp_path / "program"),
    ]


def test_compile_arguments_keep_object_naming_and_drop_dependency_files(tmp_path):
    argv = SessionReproductionPlanner._build_arguments(
        ["clang", "-c", "unit.m", "-object-file-name=original.o", "-dependency-file", "dep.d"],
        {},
        "/usr/bin/clang",
        tmp_path / "program",
        "asan",
    )
    assert "-object-file-name=original.o" in argv
    assert "-dependency-file" not in argv
    assert "dep.d" not in argv


def test_compile_arguments_reject_source_migration_actions(tmp_path):
    with pytest.raises(DynamicReproductionError, match="unsupported_build_mode"):
        SessionReproductionPlanner._build_arguments(
            ["clang", "-c", "unit.m", "-objcmt-migrate"],
            {},
            "/usr/bin/clang",
            tmp_path / "program",
            "asan",
        )


def test_compile_arguments_replace_only_the_sanitizer_selection(tmp_path):
    argv = SessionReproductionPlanner._build_arguments(
        ["clang", "-c", "unit.c", "-fsanitize=undefined", "-fno-sanitize=vptr"],
        {},
        "/usr/bin/clang",
        tmp_path / "program",
        "tsan",
    )
    assert "-fsanitize=thread" in argv
    assert "-fsanitize=undefined" not in argv
    assert "-fno-sanitize=vptr" not in argv


def test_compile_arguments_reject_sanitizer_modifier_flags(tmp_path):
    with pytest.raises(DynamicReproductionError, match="unsupported_sanitizer_option"):
        SessionReproductionPlanner._build_arguments(
            ["clang", "-c", "unit.c", "-fsanitize-recover=all"],
            {},
            "/usr/bin/clang",
            tmp_path / "program",
            "asan",
        )


# --------------------------------------------------------------------------
# Explicit gaps stay undecided instead of producing a wrong confirmation
# --------------------------------------------------------------------------


def test_translation_unit_without_main_stays_unresolved(program):
    source, indexed, config, issue = program
    source.write_text(
        "#include <stdlib.h>\n"
        "int helper(void) {\n"
        "  char *p = malloc(4);\n"
        "  p[8] = 1;\n"
        "  free(p);\n"
        "  return 0;\n}\n",
        encoding="utf-8",
    )
    backend = indexed()
    try:
        helper_issue = dict(issue, location="unit.c:3", function="helper")
        SessionReproductionPlanner(config, backend).attempt(
            helper_issue, DynamicReproductionPolicy(enabled=True)
        )
        attempt = helper_issue["dynamic_reproduction_attempt"]
        assert attempt["status"] == "plan_unavailable"
        assert attempt["reason"] == "standalone_program_entry_unavailable"
    finally:
        backend.close()


def test_ambiguous_build_context_stays_unresolved(program):
    source, indexed, config, issue = program
    compiler = shutil.which("clang")
    executable = os.environ["Z_SCOPE_TEST_CLANG_INDEXER"]
    database = source.parent / "compile_commands.json"
    database.write_text(
        json.dumps(
            [
                {
                    "file": str(source),
                    "directory": str(source.parent),
                    "arguments": [compiler, "-c", str(source), "-DONE=1"],
                },
                {
                    "file": str(source),
                    "directory": str(source.parent),
                    "arguments": [compiler, "-c", str(source), "-DTWO=1"],
                },
            ]
        )
    )
    backend = ClangBackend(frontend="batch", clang_indexer_path=executable, max_threads=1)
    assert backend.initialize(str(source.parent), compile_commands_path=str(database))
    try:
        service = SessionReproductionPlanner(config, backend)
        service.attempt(issue, DynamicReproductionPolicy(enabled=True))
        attempt = issue["dynamic_reproduction_attempt"]
        assert attempt["status"] == "plan_unavailable"
        assert attempt["reason"] == "ambiguous_or_missing_build_context"
    finally:
        backend.close()


@pytest.mark.skipif(sys.platform != "linux", reason="automatic reproduction requires Linux")
def test_defect_family_without_sanitizer_strategy_stays_unresolved(tmp_path):
    config = SimpleNamespace(
        project=SimpleNamespace(project_root=tmp_path, project_id="test-project"),
        analysis=SimpleNamespace(snapshot_dir=tmp_path / "artifacts"),
    )
    issue = {"id": "x", "defect_class": "sql_injection", "location": "unit.c:1"}
    SessionReproductionPlanner(config).attempt(issue, DynamicReproductionPolicy(enabled=True))
    attempt = issue["dynamic_reproduction_attempt"]
    assert attempt["status"] == "plan_unavailable"
    assert attempt["reason"] == "defect_family_has_no_sanitizer_strategy"


# --------------------------------------------------------------------------
# native_heap_witness: only a single, local, acyclic allocation binds
# --------------------------------------------------------------------------


def _v5_facts(events, *, edges=(), scope="ctx-1", complete=True):
    return {
        "complete": complete,
        "build_context_id": scope,
        "functions": [
            {
                "kind": "program_function",
                "owner": {"name": "main"},
                "complete": True,
                "fact_version": "zscope.program-events.v5",
                "events": list(events),
                "cfg_edges": list(edges),
            }
        ],
    }


def _event(event_id, kind, line, **fields):
    event = {
        "event_id": event_id,
        "event_kind": kind,
        "location": {"file": "unit.c", "line": line},
        "expression": "",
        "defs": [],
        "uses": [],
        "macro_expansion": False,
    }
    event.update(fields)
    return event


def _alloc(event_id="e1", name="p", usr="u:p", line=3):
    return _event(
        event_id,
        "call",
        line,
        expression=f"{name} = malloc(4)",
        object={"name": name, "usr": usr},
        callee={"name": "malloc", "is_system_header": True},
    )


def _write_access(event_id="e2", name="p", line=8, expression=None):
    return _event(
        event_id,
        "assignment",
        line,
        expression=expression if expression is not None else f"{name}[8] = 1",
    )


def _free(event_id="e3", name="p", usr="u:p", line=9):
    return _event(
        event_id,
        "call",
        line,
        expression=f"free({name})",
        callee={"name": "free", "is_system_header": True},
        uses=[{"name": name, "usr": usr}],
    )


def test_native_heap_witness_binds_simple_allocation_to_access():
    facts = _v5_facts([_alloc(), _write_access(), _free()])
    witness = native_heap_witness(facts, name="p", site_file="unit.c", site_line=8)
    assert witness is not None
    assert witness.access_kind == "write"
    assert witness.expression == "p"
    assert witness.function == "main"
    assert witness.object_ref.region == "heap"
    assert witness.object_ref.allocation_site == "unit.c:3"
    assert witness.object_ref.build_context_id == "ctx-1"


def test_native_heap_witness_rejects_a_conflicting_object_name():
    impostor = _event(
        "e9",
        "assignment",
        6,
        expression="q = p",
        uses=[{"name": "p", "usr": "u:other"}],
    )
    facts = _v5_facts([_alloc(), impostor, _write_access(), _free()])
    assert native_heap_witness(facts, name="p", site_file="unit.c", site_line=8) is None


def test_native_heap_witness_rejects_multiple_objects_on_one_line():
    facts = _v5_facts(
        [
            _alloc(),
            _write_access(),
            _write_access(event_id="e2b", expression="q[8] = 1"),
            _free(),
        ]
    )
    assert native_heap_witness(facts, name="p", site_file="unit.c", site_line=8) is None


def test_native_heap_witness_rejects_reallocation_and_reassignment():
    doubled = _v5_facts([_alloc(), _alloc(event_id="e1b", line=5), _write_access(), _free()])
    assert native_heap_witness(doubled, name="p", site_file="unit.c", site_line=8) is None
    reassigned = _v5_facts(
        [
            _alloc(),
            _event(
                "e8",
                "assignment",
                6,
                expression="p = realloc(p, 8)",
                assignment_target="p",
                defs=[{"name": "p", "usr": "u:p"}],
            ),
            _write_access(),
            _free(),
        ]
    )
    assert native_heap_witness(reassigned, name="p", site_file="unit.c", site_line=8) is None


def test_native_heap_witness_rejects_opaque_pointer_calls_and_loops():
    opaque = _event(
        "e7",
        "call",
        6,
        expression="memset(p, 0, 4)",
        callee={"name": "memset", "is_system_header": True},
        uses=[{"name": "p", "usr": "u:p"}],
    )
    facts = _v5_facts([_alloc(), opaque, _write_access(), _free()])
    assert native_heap_witness(facts, name="p", site_file="unit.c", site_line=8) is None
    cyclic = _v5_facts(
        [_alloc(), _write_access(), _free()],
        edges=[{"from": 1, "to": 2}, {"from": 2, "to": 1}],
    )
    assert native_heap_witness(cyclic, name="p", site_file="unit.c", site_line=8) is None


def test_native_heap_witness_tolerates_duplicate_native_call_events():
    # The native extractor emits the allocation call twice with the same
    # location, callee and expression; the object-less duplicate is not a
    # second allocation and not a reassignment.
    duplicate = _event(
        "e1b",
        "call",
        3,
        expression="p = malloc(4)",
        callee={"name": "malloc", "is_system_header": True},
        defs=[{"name": "p", "usr": "u:p"}],
    )
    facts = _v5_facts([_alloc(), duplicate, _write_access(), _free()])
    witness = native_heap_witness(facts, name="p", site_file="unit.c", site_line=8)
    assert witness is not None


def test_native_heap_witness_rejects_pointer_slot_escape():
    escape = _event(
        "e6",
        "declaration_initializer",
        5,
        expression="char **alias = &p;",
        defs=[{"name": "alias", "usr": "u:alias"}],
        uses=[{"name": "p", "usr": "u:p"}],
        assignment_target="alias",
    )
    facts = _v5_facts([_alloc(), escape, _write_access(), _free()])
    assert native_heap_witness(facts, name="p", site_file="unit.c", site_line=8) is None


def test_native_heap_witness_rejects_same_line_second_allocation():
    other = _event(
        "e1c",
        "call",
        3,
        expression="malloc(4)",
        location={"file": "unit.c", "line": 3, "column": 29},
        object={"name": "q", "usr": "u:q"},
        callee={"name": "malloc", "is_system_header": True},
        defs=[{"name": "q", "usr": "u:q"}],
    )
    facts = _v5_facts([_alloc(), other, _write_access(), _free()])
    assert native_heap_witness(facts, name="p", site_file="unit.c", site_line=8) is None
    # On a different line the second allocation is distinguishable again.
    apart = _event(
        "e1d",
        "call",
        4,
        expression="malloc(4)",
        location={"file": "unit.c", "line": 4, "column": 13},
        object={"name": "q", "usr": "u:q"},
        callee={"name": "malloc", "is_system_header": True},
        defs=[{"name": "q", "usr": "u:q"}],
    )
    facts = _v5_facts(
        [
            _alloc(),
            apart,
            _write_access(),
            _free(),
            _free(event_id="e4", name="q", usr="u:q", line=10),
        ]
    )
    assert native_heap_witness(facts, name="p", site_file="unit.c", site_line=8) is not None


# --------------------------------------------------------------------------
# Exact-object matching: a name in a stack is not object evidence
# --------------------------------------------------------------------------


def _binding(**overrides):
    values = {
        "project_id": "p1",
        "source_revision": "r1",
        "candidate_uid": "c1",
        "validation_cluster_uid": "v1",
        "object_identity": "p",
        "site": "/repo/unit.c:8",
        "defect_family": "heap_buffer_overflow",
        "build_configuration": "ctx-1",
        "toolchain_id": "tc-1",
    }
    values.update(overrides)
    return CandidateBinding(**values)


def _finding(**overrides):
    values = {
        "kind": "heap-buffer-overflow",
        "access": "write",
        "frames": ("main /repo/unit.c:8",),
        "allocation_frames": ("main /repo/unit.c:3",),
        "object_ref": "0x502000000018",
        "site": "/repo/unit.c:8",
        "source_mapping": ("/repo/unit.c:8",),
        "raw_digest": "d" * 64,
    }
    values.update(overrides)
    return SanitizerFinding(**values)


def _witness(scope="ctx-1"):
    facts = _v5_facts([_alloc(), _write_access(), _free()], scope=scope)
    return native_heap_witness(facts, name="p", site_file="unit.c", site_line=8)


def test_exact_object_matching_binds_the_witness_build_context():
    witness = _witness()
    ok, facts, _ = match_witness_to_candidate(
        _binding(), _finding(), object_witness=witness, require_exact_object=True
    )
    assert ok and facts["candidate_object_matched"]
    wrong_build, facts, reasons = match_witness_to_candidate(
        _binding(build_configuration="ctx-2"),
        _finding(),
        object_witness=witness,
        require_exact_object=True,
    )
    assert not wrong_build
    assert not facts["candidate_object_matched"]
    assert "candidate_object_absent_from_frames" in reasons


def test_function_name_in_frames_is_not_object_proof_for_exact_plans():
    binding = _binding(object_identity="vulnerable_fn")
    finding = _finding(
        frames=("vulnerable_fn /repo/unit.c:8",),
        allocation_frames=("main /repo/unit.c:3",),
    )
    ok, facts, _ = match_witness_to_candidate(binding, finding, require_exact_object=True)
    assert not ok and not facts["candidate_object_matched"]
    # The legacy manual-plan path keeps the weaker frame-name match only when
    # exact object proof was never requested; automatic plans never use it.
    weak, facts, _ = match_witness_to_candidate(binding, finding, require_exact_object=False)
    assert weak and facts["candidate_object_matched"]
