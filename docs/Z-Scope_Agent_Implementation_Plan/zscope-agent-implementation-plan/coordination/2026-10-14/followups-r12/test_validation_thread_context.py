"""Independent real-native scopes through the actual Validator thread boundary.

Only the model response is controlled; index, native variant planning,
ValidationRunner.run, executors and ScanScheduler execute the product code.
"""
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import sys
import threading

import pytest

from zscope.core.validation import runner as runner_module
from zscope.config.function_entry import FunctionEntry
from zscope.framework.base import AgentResponse
from zscope.orchestration.entry_instances import plan_entry_instances
from zscope.orchestration.scheduler import ScanScheduler
from zscope.retrieval.instance_index import InstanceScope, ScopedCodeIndex
from zscope.semantics.build_scope import bind_build_scope, current_build_id

sys.path.insert(0, str(Path(runner_module.__file__).resolve().parents[3] / "tests"))
from test_instance_analysis import native_variants, _native_index  # noqa: E402
from test_validation_runner import _runner, _state, _issue  # noqa: E402


@pytest.mark.parametrize("scheduled", [False, True])
def test_actual_shared_validator_threads_bind_native_instance(native_variants, scheduled):
    backend, root, cdb = native_variants
    index = _native_index(backend, root, cdb)
    plan = plan_entry_instances(index, [FunctionEntry("f", file_path="unit.c")])
    assert len(plan.instances) == 2
    seen = []
    lock = threading.Lock()
    scheduler = ScanScheduler(entry_workers=2, validator_workers=2, investigator_workers=1) if scheduled else None

    def execute(instance):
        build = instance.build_context_id
        scoped = ScopedCodeIndex(index, InstanceScope.from_entry_instance(instance))

        def observe(stage):
            with lock:
                seen.append((stage, build, current_build_id(), threading.current_thread().name))

        class ModelBoundary:
            def run(self, input_data):
                observe("validator")
                return AgentResponse(success=True, data={"verdict":"verified", "reasoning":"Controlled thread-context probe", "confidence_score":1.0, "source":"arg", "sink":"free"})

        validator = _runner(None, code_index=scoped, scheduler=scheduler, validator_agent_factory=lambda *a, **kw: ModelBoundary())
        original_prepare = validator._prepare_issue_for_validation

        def prepare(*args, **kwargs):
            observe("prepare")
            return original_prepare(*args, **kwargs)

        validator._prepare_issue_for_validation = prepare
        issues = []
        for number in (1, 2):
            issue = _issue(id=f"{build}-{number}", function="f", entry_function="f", location=f"unit.c:{number+5}", dedup_key=f"{build}-{number}", build_context_id=build)
            issue["evidence_pack"]["build_context_id"] = build
            issues.append(issue)
        state = _state(issues[0])
        state.update(entry_func="f", pending_new_issues=issues)
        state["agent_context"].update(func_name="f", build_context_id=build, instance_scope=scoped.scope.to_payload())
        with bind_build_scope({"build_context_id":"outer-" + build}):
            validator.run(state)
            assert current_build_id() == "outer-" + build
        assert current_build_id() == ""

    try:
        with ThreadPoolExecutor(max_workers=2) as parents:
            list(parents.map(execute, plan.instances))
            assert parents.submit(current_build_id).result() == ""
        assert len([row for row in seen if row[0] == "prepare"]) == 4, seen
        assert len([row for row in seen if row[0] == "validator"]) == 4, seen
        assert all(expected == actual for stage, expected, actual, thread in seen), seen
        assert current_build_id() == ""
    finally:
        if scheduler is not None:
            scheduler.shutdown(wait=True, cancel_futures=True)


@pytest.mark.parametrize("binding", ["unknown", "pack_conflict", "foreign"])
def test_scoped_runner_does_not_authorize_unknown_or_conflicting_candidate(native_variants, binding):
    backend, root, cdb = native_variants
    index = _native_index(backend, root, cdb)
    plan = plan_entry_instances(index, [FunctionEntry("f", file_path="unit.c")])
    instance = plan.instances[0]
    build = instance.build_context_id
    other = plan.instances[1].build_context_id
    scoped = ScopedCodeIndex(index, InstanceScope.from_entry_instance(instance))
    calls = []

    class ModelBoundary:
        def run(self, input_data):
            calls.append(current_build_id())
            return AgentResponse(success=True, data={"verdict":"verified", "reasoning":"Controlled response cannot supply a missing build receipt", "confidence_score":1.0, "source":"arg", "sink":"free"})

    issue = _issue(id="scope-negative", function="f", entry_function="f", location="unit.c:5", dedup_key="scope-negative")
    if binding == "pack_conflict":
        issue["build_context_id"] = build
        issue["evidence_pack"]["build_context_id"] = other
    elif binding == "foreign":
        issue["build_context_id"] = other
        issue["evidence_pack"]["build_context_id"] = other
    state = _state(issue)
    state["agent_context"].update(func_name="f", build_context_id=build, instance_scope=scoped.scope.to_payload())
    _runner(ModelBoundary(), code_index=scoped).run(state)
    assert calls == [], (binding, calls, issue)
    assert issue.get("validation_status") != "validated", issue
    if binding == "unknown":
        assert not issue.get("build_context_id"), "scope must not manufacture candidate identity"
