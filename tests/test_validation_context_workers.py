"""Real-chain execution-context tests for validation workers (R18).

Every test drives the real chain — ``ValidationRunner.run`` → the real
``ValidatorAgent`` protocol → the real ``EvidenceCompletionQueue`` fact
provider executor — with only the model response and provider wait
boundaries controlled.  The native fixtures run the actual clang-indexer
tool over double-macro BASE/ALT variants and a same-name overload TU; the
recorded observations come from inside the real worker threads (the model
boundary and the provider task), never from a stubbed Validator.
"""

from __future__ import annotations

import json
import os
import threading
from pathlib import Path
from types import SimpleNamespace

import pytest

from test_validation_runner import FakeUserConfig, _issue, _state
from zscope.agents.validator_agent.agent import ValidatorAgent
from zscope.config.function_entry import FunctionEntry
from zscope.core.validation.evidence_completion import EvidenceCompletionQueue
from zscope.core.validation.execution_context import (
    EMPTY_EXECUTION_CONTEXT,
    ExecutionContext,
    current_execution_context,
    rebound_execution_context,
)
from zscope.core.validation.pipeline import ValidationPipeline
from zscope.core.validation.runner import ValidationRunner
from zscope.framework.llm_client import LLMClient
from zscope.orchestration.entry_instances import plan_entry_instances
from zscope.retrieval.instance_index import InstanceScope, ScopedCodeIndex
from zscope.semantics.build_scope import bind_build_scope, current_build_id
from zscope.semantics.call_context import (
    bind_call_context,
    current_call_facts,
    current_call_values,
    current_callee_usr,
)
from zscope.semantics.build_scope import current_scope_symbol_usr

needs_native = pytest.mark.skipif(
    not os.environ.get("Z_SCOPE_TEST_CLANG_INDEXER"),
    reason="native execution-context tests require Z_SCOPE_TEST_CLANG_INDEXER",
)


# --- controlled model boundary -----------------------------------------------------


def _v3_uncertain_result(issue, fact_kind="lockset"):
    # The strict v3 parser rejects any additional property; the field set is
    # exactly the provider-facing schema's required list.
    return {
        "schema_version": "zscope.validator-result.v3",
        "candidate_uid": str(issue.get("candidate_uid") or ""),
        "validation_cluster_uid": str(issue.get("validation_cluster_uid") or ""),
        "pass": "initial",
        "verdict": "uncertain",
        "reasoning": "需要确定性事实闭环（受控模型边界响应）。",
        "positive_evidence": [],
        "negative_evidence": [],
        "evidence_refs": [],
        "blocking_negative_evidence": False,
        "missing_fact_request": {
            "fact_kind": fact_kind,
            "subject_uid": str(issue.get("resource_identity") or ""),
            "function_uid": str(issue.get("function") or ""),
            "reason": "obligation requires a deterministic lockset fact",
        },
        "stop_reason": "missing_fact",
    }


class ControlledModelBoundary:
    """The model-response boundary: one fixed v3 response per call.

    Serves both wire modes the real agent uses — the direct v3
    ``chat_completion`` structured response and the legacy tool-conversation
    loop — and records the execution context observed at each model call so
    the tests can verify the real agent ran under the worker's precise
    scope.
    """

    def __init__(self, issues):
        self._by_cluster = {
            str(issue.get("validation_cluster_uid")): _v3_uncertain_result(issue)
            for issue in issues
        }
        self.calls: list[ExecutionContext] = []
        self.lock = threading.Lock()

    # -- shared selection -------------------------------------------------------

    def _next_response(self, messages):
        text = json.dumps(messages, ensure_ascii=False, default=str)
        for cluster, response in self._by_cluster.items():
            if cluster and cluster in text:
                return response
        return next(iter(self._by_cluster.values()))

    def _record(self):
        with self.lock:
            self.calls.append(current_execution_context())

    # -- direct v3 structured completion (chat_completion) ---------------------

    def chat_completion(self, messages, **kwargs):
        self._record()
        payload = self._next_response(messages)
        content = json.dumps(payload, ensure_ascii=False)
        return {
            "choices": [
                {
                    "finish_reason": "stop",
                    "message": {"role": "assistant", "content": content},
                }
            ],
            "model": "controlled-boundary",
            "usage": {"prompt_tokens": 64, "completion_tokens": 32},
        }

    # -- legacy tool-conversation loop -------------------------------------------

    def run_conversation_with_tools(self, **kwargs):
        self._record()
        conversation = kwargs.get("messages") or []
        content = json.dumps(self._next_response(conversation), ensure_ascii=False)
        return {
            "content": content,
            "conversation": list(conversation),
            "message": {"role": "assistant", "content": content},
            "terminal_tool_payload": None,
            "terminal_tool_name": None,
            "terminal_tool_valid": False,
            "terminal_tool_call_count": 0,
            "terminal_invalid_call_count": 0,
            "iterations": 1,
            "context_tokens": 64,
            "api_call_count": 1,
            "cumulative_prompt_tokens": 64,
            "cumulative_completion_tokens": 32,
            "cumulative_total_tokens": 96,
            "tool_call_count": 0,
            "final_tool_call_count": 0,
            "finish_reason": "stop",
            "provider_model": "controlled-boundary",
        }


# --- real runner harness -----------------------------------------------------------


def _make_real_runner(
    issues,
    *,
    code_index,
    queue=None,
    validator_workers=2,
    scheduler=None,
):
    model = ControlledModelBoundary(issues)
    llm = LLMClient(api_key="test", base_url="http://example.invalid", models=["unit-model"])
    llm.chat_completion = model.chat_completion
    llm.run_conversation_with_tools = model.run_conversation_with_tools

    def agent_factory(*args, **kwargs):
        return ValidatorAgent(llm, [])

    config = SimpleNamespace(
        analysis=None,
        scan=None,
        concurrency=SimpleNamespace(
            validator_workers=validator_workers, evidence_completion_workers=1
        ),
        project=SimpleNamespace(
            agents=[SimpleNamespace(name="validator_agent", enabled=True, llm_ref="default")]
        ),
    )
    runner = ValidationRunner(
        config=config,
        llm_clients={"default": llm},
        validation_pipeline=ValidationPipeline(FakeUserConfig()),
        code_index=code_index,
        snapshot_store=SimpleNamespace(load_snapshot=lambda name: None),
        get_tools=lambda agent_name: [],
        tool_policy_for_agent=lambda agent_name: None,
        attach_agent_contract=lambda context, agent_name: None,
        remember_validation_result=lambda issue, status: None,
        validator_agent_factory=agent_factory,
        scheduler=scheduler,
    )
    if queue is not None:
        runner._evidence_completion_queue = queue
    return runner, model


def _instrument_queue(queue, recordings, *, before=None):
    """Record the real provider task's inside-thread observations.

    The wrapper delegates to the real provider dispatch; only the wait
    boundary and the observation are controlled.
    """

    real = queue._requested_completion_proofs

    def recording(fact_kind, issue, validation_evidence):
        context = current_execution_context()
        entry_name, entry_usr = context.entry_symbol
        recordings.append(
            {
                "fact_kind": fact_kind,
                "build": context.build_context_id,
                "entry_name": entry_name,
                "entry_usr": entry_usr,
                "thread": threading.current_thread().name,
                "issue_marker": str(issue.get("probe_marker") or ""),
                "ambient_after": None,
            }
        )
        if before is not None:
            before()
        return real(fact_kind, issue, validation_evidence)

    queue._requested_completion_proofs = recording


def _issues(count, prefix, build=""):
    issues = [
        _issue(
            id=f"{prefix}{index}",
            candidate_uid=f"CAND_{prefix}{index}",
            validation_cluster_uid=f"VAL_{prefix}{index}",
            rule="unsynchronized_shared_access",
            function="release_owner",
            entry_function="release_owner",
            probe_marker=f"frozen-{prefix}{index}",
            evidence_pack={"path": {"complete_in_function": True}},
        )
        for index in range(count)
    ]
    if build:
        for issue in issues:
            issue["build_context_id"] = build
            issue["evidence_pack"]["build_context_id"] = build
    return issues


def _multi_state(issues):
    state = _state(issues[0])
    state["pending_new_issues"] = list(issues)
    return state


# --- execution context unit semantics ----------------------------------------------


def test_empty_context_explicitly_clears_ambient_leftovers():
    with bind_build_scope({"build_context_id": "OTHER-AMBIENT"}):
        with rebound_execution_context(EMPTY_EXECUTION_CONTEXT):
            assert current_build_id() == ""
        assert current_build_id() == "OTHER-AMBIENT"
    assert current_build_id() == ""


def test_rebound_context_restores_on_exception():
    with bind_build_scope({"build_context_id": "OUTER"}):
        with pytest.raises(RuntimeError):
            with rebound_execution_context(ExecutionContext("INNER", ("f", "u"))):
                assert current_build_id() == "INNER"
                raise RuntimeError("boom")
        assert current_build_id() == "OUTER"


def test_runner_execution_context_carries_instance_identity():
    from test_validation_runner import FakeCodeIndex

    class ScopedFake(FakeCodeIndex):
        def __init__(self):
            super().__init__()
            self.scope = InstanceScope(
                build_context_id="build-x",
                usr="c:@F@entry",
                identity="build-x:c:@F@entry",
                source="unit.c",
                function_names=("entry",),
            )

    from zscope.core.validation.runner import ValidationRunner as VR

    class Probe(VR):
        @property
        def probe_context(self):
            return self._execution_context

    config = SimpleNamespace(
        analysis=None,
        scan=None,
        concurrency=SimpleNamespace(validator_workers=1, evidence_completion_workers=1),
        project=SimpleNamespace(agents=[]),
    )
    probe = Probe(
        config=config,
        llm_clients={"default": object()},
        validation_pipeline=ValidationPipeline(FakeUserConfig()),
        code_index=ScopedFake(),
        snapshot_store=SimpleNamespace(load_snapshot=lambda name: None),
        get_tools=lambda agent_name: [],
        tool_policy_for_agent=lambda agent_name: None,
        attach_agent_contract=lambda context, agent_name: None,
        remember_validation_result=lambda issue, status: None,
    )
    assert probe._execution_context == ExecutionContext("build-x", ("entry", "c:@F@entry"))


def test_unscoped_runner_execution_context_is_empty():
    from test_validation_runner import FakeCodeIndex

    class Probe(ValidationRunner):
        @property
        def probe_context(self):
            return self._execution_context

    config = SimpleNamespace(
        analysis=None,
        scan=None,
        concurrency=SimpleNamespace(validator_workers=1, evidence_completion_workers=1),
        project=SimpleNamespace(agents=[]),
    )
    probe = Probe(
        config=config,
        llm_clients={"default": object()},
        validation_pipeline=ValidationPipeline(FakeUserConfig()),
        code_index=FakeCodeIndex(),
        snapshot_store=SimpleNamespace(load_snapshot=lambda name: None),
        get_tools=lambda agent_name: [],
        tool_policy_for_agent=lambda agent_name: None,
        attach_agent_contract=lambda context, agent_name: None,
        remember_validation_result=lambda issue, status: None,
    )
    assert probe._execution_context == EMPTY_EXECUTION_CONTEXT


# --- provider-pool context semantics on the real queue ------------------------------


def test_provider_pool_threads_bind_and_finally_restore_the_captured_scope():
    queue = EvidenceCompletionQueue(enabled=True, max_workers=1, fact_timeout_seconds=30.0)
    recordings = []
    _instrument_queue(queue, recordings)
    issue = {
        "validation_cluster_uid": "VAL_POOL",
        "verdict_guard": True,
        "probe_marker": "frozen-pool",
        "evidence_pack": {"path": {"complete_in_function": True}},
    }
    try:
        with bind_build_scope({"build_context_id": "build-pool"}):
            # The entry symbol binding mirrors what the runner's scope sets.
            from zscope.semantics import build_scope as bs

            marker = bs._ACTIVE_SCOPE_SYMBOL.set(("release_owner", "c:@F@release_owner"))
            try:
                resolution = queue.resolve_requested_fact(
                    dict(issue),
                    validator_data={
                        "verdict": "uncertain",
                        "missing_fact_request": {"fact_kind": "lockset"},
                    },
                    validation_evidence=issue["evidence_pack"],
                )
            finally:
                bs._ACTIVE_SCOPE_SYMBOL.reset(marker)
        assert resolution is not None
        assert recordings, "the real provider task must run"
        record = recordings[0]
        assert record["build"] == "build-pool"
        assert record["entry_name"] == "release_owner"
        assert record["entry_usr"] == "c:@F@release_owner"
        assert record["thread"].startswith("zscope-fact-provider")
        # The reused pool thread is exactly as scoped after the task as before.
        probe: list[str] = []
        queue._fact_provider_executor.submit(lambda: probe.append(current_build_id())).result(
            timeout=15
        )
        assert probe == [""]
    finally:
        queue._fact_provider_executor.shutdown(wait=True)


def test_provider_input_is_frozen_against_parent_thread_mutation():
    queue = EvidenceCompletionQueue(enabled=True, max_workers=1, fact_timeout_seconds=30.0)
    recordings = []
    inside = threading.Event()
    release = threading.Event()
    _instrument_queue(queue, recordings, before=lambda: inside.set() or release.wait(10))
    issue = {
        "validation_cluster_uid": "VAL_FREEZE",
        "probe_marker": "original-value",
        "evidence_pack": {"path": {"complete_in_function": True}},
    }
    try:
        with bind_build_scope({"build_context_id": "build-freeze"}):
            resolver = threading.Thread(
                target=lambda: queue.resolve_requested_fact(
                    dict(issue),
                    validator_data={
                        "verdict": "uncertain",
                        "missing_fact_request": {"fact_kind": "lockset"},
                    },
                    validation_evidence=issue["evidence_pack"],
                )
            )
            resolver.start()
            assert inside.wait(timeout=15)
            # Parent-thread mutation during provider execution.
            issue["probe_marker"] = "mutated-by-parent"
            release.set()
            resolver.join(timeout=30)
        assert recordings and recordings[0]["issue_marker"] == "original-value"
    finally:
        release.set()
        queue._fact_provider_executor.shutdown(wait=True)


def test_provider_timeout_returns_honest_status_and_late_result_stays_isolated():
    queue = EvidenceCompletionQueue(enabled=True, max_workers=1, fact_timeout_seconds=0.05)
    late_records: list[str] = []
    real = queue._requested_completion_proofs

    def slow_provider(fact_kind, issue, validation_evidence):
        late_records.append(current_build_id())
        threading.Event().wait(0.4)
        late_records.append(current_build_id())
        return real(fact_kind, issue, validation_evidence)

    queue._requested_completion_proofs = slow_provider
    issue = {
        "validation_cluster_uid": "VAL_TIMEOUT",
        "probe_marker": "timeout-input",
        "evidence_pack": {"path": {"complete_in_function": True}},
    }
    try:
        live_issue = dict(issue)
        with bind_build_scope({"build_context_id": "build-timeout"}):
            resolution = queue.resolve_requested_fact(
                live_issue,
                validator_data={
                    "verdict": "uncertain",
                    "missing_fact_request": {"fact_kind": "lockset"},
                },
                validation_evidence=issue["evidence_pack"],
            )
        assert resolution is not None
        assert live_issue["evidence_completion_status"] == "timeout"
        assert live_issue["evidence_completion_terminal_status"] == "timeout"
        # The late task still runs (and finishes) on the pool thread: it must
        # observe the captured scope while executing and restore afterwards.
        deadline = threading.Event()
        timer = threading.Timer(1.0, deadline.set)
        timer.start()
        try:
            while len(late_records) < 2 and not deadline.is_set():
                threading.Event().wait(0.02)
        finally:
            timer.cancel()
        assert len(late_records) >= 1 and late_records[0] == "build-timeout"
        probe: list[str] = []
        queue._fact_provider_executor.submit(lambda: probe.append(current_build_id())).result(
            timeout=15
        )
        assert probe == [""]
    finally:
        queue._fact_provider_executor.shutdown(wait=True)


def test_provider_exception_is_contained_and_pool_thread_restored():
    queue = EvidenceCompletionQueue(enabled=True, max_workers=1, fact_timeout_seconds=30.0)

    def broken_provider(fact_kind, issue, validation_evidence):
        assert current_build_id() == "build-error"
        raise RuntimeError("controlled provider failure")

    queue._requested_completion_proofs = broken_provider
    issue = {
        "validation_cluster_uid": "VAL_ERROR",
        "probe_marker": "error-input",
        "evidence_pack": {"path": {"complete_in_function": True}},
    }
    try:
        live_issue = dict(issue)
        with bind_build_scope({"build_context_id": "build-error"}):
            resolution = queue.resolve_requested_fact(
                live_issue,
                validator_data={
                    "verdict": "uncertain",
                    "missing_fact_request": {"fact_kind": "lockset"},
                },
                validation_evidence=issue["evidence_pack"],
            )
        assert resolution is not None
        assert live_issue["evidence_completion_status"] == "provider_error"
        assert "RuntimeError" in str(live_issue.get("evidence_completion_error") or "")
        probe: list[str] = []
        queue._fact_provider_executor.submit(lambda: probe.append(current_build_id())).result(
            timeout=15
        )
        assert probe == [""]
    finally:
        queue._fact_provider_executor.shutdown(wait=True)


# --- real native double-macro BASE/ALT end to end -----------------------------------

FLAGS_H = "#include <stdlib.h>\n#ifdef ALT\n#define RELEASE(p) do { free(p); free(p); } while (0)\n#else\n#define RELEASE(p) do { free(p); } while (0)\n#endif\n"
UNIT_C = (
    '#include <stdlib.h>\n#include "flags.h"\n'
    "void release_owner(void) {\n"
    "    char *p = malloc(8);\n"
    "    if (!p) { return; }\n"
    "    RELEASE(p);\n"
    "}\n"
)


@pytest.fixture
def native_variants(tmp_path, monkeypatch):
    executable = os.environ.get("Z_SCOPE_TEST_CLANG_INDEXER")
    if not executable:
        pytest.skip("native execution-context tests require Z_SCOPE_TEST_CLANG_INDEXER")
    from zscope.retrieval.clang_backend import ClangBackend
    from zscope.retrieval.code_index import CodeIndex

    monkeypatch.setenv("Z_SCOPE_CLANG_BATCH_MEMORY_MB", "512")
    monkeypatch.setattr(
        ClangBackend, "_ensure_extractor", lambda self: pytest.fail("unexpected LSP")
    )
    (tmp_path / "flags.h").write_text(FLAGS_H, encoding="utf-8")
    (tmp_path / "unit.c").write_text(UNIT_C, encoding="utf-8")
    rows = [
        dict(
            directory=str(tmp_path),
            file=str(tmp_path / "unit.c"),
            arguments=["clang", "-c", str(tmp_path / "unit.c"), *flags],
        )
        for flags in ([], ["-DALT=1"])
    ]
    cdb = tmp_path / "compile_commands.json"
    cdb.write_text(json.dumps(rows), encoding="utf-8")
    backend = ClangBackend(frontend="batch", clang_indexer_path=executable, max_threads=2)
    assert backend.initialize(str(tmp_path), compile_commands_path=str(cdb))
    try:
        from zscope.config.config import IndexingConfig

        yield CodeIndex(
            tmp_path, cdb, backend=backend, indexing_config=IndexingConfig(backend="clang")
        ), tmp_path
    finally:
        backend.close()


def _variant_instances(index):
    plan = plan_entry_instances(index, [FunctionEntry("release_owner", file_path="unit.c")])
    assert plan.status == "planned" and len(plan.instances) == 2
    by_flag = {}
    for instance in plan.instances:
        build = instance.build_context_id
        facts = index.get_function_program_facts("release_owner", "unit.c", build_context_id=build)
        assert facts.get("complete") is True
        commands = facts.get("build_context", {}).get("command", {}).get("arguments", [])
        by_flag["ALT" if "-DALT=1" in commands else "BASE"] = instance
    assert set(by_flag) == {"BASE", "ALT"}
    return by_flag


@needs_native
def test_real_chain_binds_exact_variant_scope_through_agent_and_providers(native_variants):
    index, root = native_variants
    for label, instance in _variant_instances(index).items():
        scoped = ScopedCodeIndex(index, InstanceScope.from_entry_instance(instance))
        build = instance.build_context_id
        queue = EvidenceCompletionQueue(enabled=True, max_workers=1, fact_timeout_seconds=30.0)
        recordings = []
        _instrument_queue(queue, recordings)
        issues = _issues(2, label, build=build)
        runner, model = _make_real_runner(issues, code_index=scoped, queue=queue)
        state = _multi_state(issues)
        try:
            runner.run(state)
        finally:
            queue._fact_provider_executor.shutdown(wait=True)

        # The real agent (model boundary) ran under the exact variant build.
        assert model.calls, "the real ValidatorAgent must run"
        assert {context.build_context_id for context in model.calls} == {build}
        assert {context.entry_symbol[0] for context in model.calls} == {"release_owner"}
        # The real provider tasks ran on the queue's pool under the same scope.
        assert recordings
        assert {record["build"] for record in recordings} == {build}
        assert {record["entry_usr"] for record in recordings} == {instance.usr}
        # No candidate was validated away by the other variant.
        assert all(record["thread"].startswith("zscope-fact-provider") for record in recordings)


@needs_native
def test_two_concurrent_runners_share_one_provider_pool_without_cross_binding(native_variants):
    index, root = native_variants
    instances = _variant_instances(index)
    shared_queue = EvidenceCompletionQueue(enabled=True, max_workers=1, fact_timeout_seconds=30.0)
    recordings = []
    _instrument_queue(shared_queue, recordings)

    runners = {}
    models = {}
    for label, instance in instances.items():
        scoped = ScopedCodeIndex(index, InstanceScope.from_entry_instance(instance))
        issues = _issues(3, label, build=instance.build_context_id)
        runner, model = _make_real_runner(issues, code_index=scoped, queue=shared_queue)
        runners[label] = (runner, _multi_state(issues), instance)
        models[label] = model

    errors: list[BaseException] = []

    def drive(label):
        runner, state, _ = runners[label]
        try:
            runner.run(state)
        except BaseException as exc:  # surfaced by the assertions below
            errors.append(exc)

    threads = [threading.Thread(target=drive, args=(label,)) for label in runners]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=180)
    try:
        assert not errors
        by_label = {
            label: {
                record["build"]
                for record in recordings
                if record["build"] == instance.build_context_id
            }
            for label, (_, _, instance) in runners.items()
        }
        # Each variant's provider tasks observed exactly its own build.
        for label, (_, _, instance) in runners.items():
            assert by_label[label] == {instance.build_context_id}, (label, by_label)
        assert {record["thread"] for record in recordings} == {
            "zscope-fact-provider_0"
        }, "a single-worker pool forces real thread reuse across variants"
        # The reused pool thread ends up exactly as scoped as it started.
        probe: list[str] = []
        shared_queue._fact_provider_executor.submit(
            lambda: probe.append(current_build_id())
        ).result(timeout=15)
        assert probe == [""]
        # Both real agents ran, each under its own variant build.
        for label in runners:
            assert {c.build_context_id for c in models[label].calls} == {
                instances[label].build_context_id
            }
    finally:
        shared_queue._fact_provider_executor.shutdown(wait=True)


@needs_native
def test_scoped_runner_rejects_wrong_and_unknown_builds_on_the_real_chain(native_variants):
    index, root = native_variants
    instances = _variant_instances(index)
    base = instances["BASE"]
    alt = instances["ALT"]
    scoped = ScopedCodeIndex(index, InstanceScope.from_entry_instance(base))
    queue = EvidenceCompletionQueue(enabled=True, max_workers=1, fact_timeout_seconds=30.0)
    recordings = []
    _instrument_queue(queue, recordings)
    foreign = _issues(1, "FOREIGN", build=alt.build_context_id)
    unknown = _issues(1, "UNKNOWN", build="")
    runner, model = _make_real_runner(foreign + unknown, code_index=scoped, queue=queue)
    state = _multi_state(foreign + unknown)
    try:
        runner.run(state)
    finally:
        queue._fact_provider_executor.shutdown(wait=True)
    assert model.calls == [], "neither candidate may reach the real agent"
    assert recordings == [], "neither candidate may reach the provider pool"
    assert foreign[0]["build_scope_rejection"]["code"] == "candidate_build_mismatch"
    assert unknown[0]["build_scope_rejection"]["code"] == "candidate_build_missing"
    assert not unknown[0].get("build_context_id"), "scope must not manufacture identity"


@needs_native
def test_unscoped_runner_clears_ambient_variant_on_the_real_chain(native_variants):
    from test_validation_runner import FakeCodeIndex

    index, root = native_variants
    instances = _variant_instances(index)
    alt = instances["ALT"]
    issues = _issues(2, "AMB", build=alt.build_context_id)
    queue = EvidenceCompletionQueue(enabled=True, max_workers=1, fact_timeout_seconds=30.0)
    recordings = []
    _instrument_queue(queue, recordings)
    runner, model = _make_real_runner(issues, code_index=FakeCodeIndex(), queue=queue)
    state = _multi_state(issues)
    try:
        with bind_build_scope({"build_context_id": "AMBIENT-" + alt.build_context_id}):
            runner.run(state)
            assert current_build_id() == "AMBIENT-" + alt.build_context_id
    finally:
        queue._fact_provider_executor.shutdown(wait=True)
    assert current_build_id() == ""
    # The real agent and the provider pool both ran under the explicitly
    # empty context, never the ambient leftover.
    assert model.calls and {context.build_context_id for context in model.calls} == {""}
    assert recordings and {record["build"] for record in recordings} == {""}


# --- real native same-name overload callee selection inside workers ------------------

OVERLOAD_CPP = """\
void log_event(int value) {}
void log_event(const char *text) {}
void call_int(int mode) { log_event(mode); }
void call_mixed(int mode) { if (mode) { log_event(mode); } else { log_event("x"); } }
"""


@pytest.fixture
def native_overloads(tmp_path, monkeypatch):
    executable = os.environ.get("Z_SCOPE_TEST_CLANG_INDEXER")
    if not executable:
        pytest.skip("native overload tests require Z_SCOPE_TEST_CLANG_INDEXER")
    from zscope.retrieval.clang_backend import ClangBackend
    from zscope.retrieval.code_index import CodeIndex

    monkeypatch.setenv("Z_SCOPE_CLANG_BATCH_MEMORY_MB", "512")
    monkeypatch.setattr(
        ClangBackend, "_ensure_extractor", lambda self: pytest.fail("unexpected LSP")
    )
    (tmp_path / "log.cpp").write_text(OVERLOAD_CPP, encoding="utf-8")
    rows = [
        dict(
            directory=str(tmp_path),
            file=str(tmp_path / "log.cpp"),
            arguments=["clang++", "-c", str(tmp_path / "log.cpp")],
        )
    ]
    cdb = tmp_path / "compile_commands.json"
    cdb.write_text(json.dumps(rows), encoding="utf-8")
    backend = ClangBackend(frontend="batch", clang_indexer_path=executable, max_threads=2)
    assert backend.initialize(str(tmp_path), compile_commands_path=str(cdb))
    try:
        from zscope.config.config import IndexingConfig

        yield CodeIndex(
            tmp_path, cdb, backend=backend, indexing_config=IndexingConfig(backend="clang")
        ), tmp_path
    finally:
        backend.close()


@needs_native
def _overload_project(index):
    """Publish the int overload and return the registry plus caller contexts."""

    from test_contract_usr_scope import _publish
    from zscope.semantics.contracts import ContractRegistry

    build = index.get_build_contexts("log.cpp")[0]["build_context_id"]
    choices = index.get_function_program_facts("log_event", "log.cpp", build_context_id=build)
    owners = {int(row["line"]): str(row["usr"]) for row in choices["function_choices"]}
    int_usr, char_usr = owners[1], owners[2]
    assert int_usr and char_usr and int_usr != char_usr

    registry = ContractRegistry([])
    _publish(
        index,
        registry,
        func_name="log_event",
        file_path="log.cpp",
        signature="void log_event(int value)",
        code="void log_event(int value) {}",
        line=1,
        usr=int_usr,
        build=build,
    )

    def caller_context(name, code):
        facts = index.get_function_program_facts(name, "log.cpp", build_context_id=build)
        assert facts.get("complete") is True
        return {
            "func_name": name,
            "file_path": "log.cpp",
            "signature": "void " + name + "(int mode)",
            "code": code,
            "program_facts": facts,
        }

    only_int = caller_context("call_int", "void call_int(int mode) { log_event(mode); }")
    mixed = caller_context(
        "call_mixed",
        'void call_mixed(int mode) { if (mode) { log_event(mode); } else { log_event("x"); } }',
    )
    return registry, build, int_usr, only_int, mixed


def _queue_observing_callees(queue, registry, observed):
    """Provider-task observation: no manual rebinding inside the task.

    The recording wrapper runs in the real provider thread under whatever
    context the framework carried there, then delegates to the real
    dispatch.  Everything it reports was resolved by the framework's own
    bindings — exactly what a real registry-consuming provider sees.
    """

    def observing_provider(fact_kind, issue, validation_evidence):
        record = {
            "build": current_build_id(),
            "call_facts": current_call_facts() is not None,
            "callee_usr": current_callee_usr(registry, "log_event"),
            "match": [
                m.symbol.usr for m in registry.match_call("log_event", "io_acquire", ["mode"])
            ],
        }
        observed.append(record)
        return []

    queue._requested_completion_proofs = observing_provider


@needs_native
def test_same_entry_call_facts_carry_into_the_real_provider_thread(native_overloads):
    index, root = native_overloads
    registry, build, int_usr, only_int, _ = _overload_project(index)
    queue = EvidenceCompletionQueue(enabled=True, max_workers=1, fact_timeout_seconds=30.0)
    observed = []
    _queue_observing_callees(queue, registry, observed)
    issue = {
        "validation_cluster_uid": "VAL_CARRY",
        "probe_marker": "carry",
        "evidence_pack": {"path": {"complete_in_function": True}},
    }
    try:
        # The verified entry context is bound on the submitting thread; the
        # framework captures it at submit and carries it into the provider
        # thread — no manual rebinding inside the task.
        with bind_call_context(only_int, registry):
            resolution = queue.resolve_requested_fact(
                dict(issue),
                validator_data={
                    "verdict": "uncertain",
                    "missing_fact_request": {"fact_kind": "lockset"},
                },
                validation_evidence=issue["evidence_pack"],
            )
        assert resolution is not None
        assert observed and observed[0]["build"] == build
        assert observed[0]["call_facts"] is True
        # Same-entry valid mapping: the provider resolves the exact callee
        # USR and the pinned int-overload contract is selected.
        assert observed[0]["callee_usr"] == int_usr
        assert observed[0]["match"] == [int_usr]
    finally:
        queue._fact_provider_executor.shutdown(wait=True)


@needs_native
def test_mixed_caller_stays_unknown_in_the_real_provider_thread(native_overloads):
    index, root = native_overloads
    registry, build, int_usr, _, mixed = _overload_project(index)
    queue = EvidenceCompletionQueue(enabled=True, max_workers=1, fact_timeout_seconds=30.0)
    observed = []
    _queue_observing_callees(queue, registry, observed)
    issue = {
        "validation_cluster_uid": "VAL_MIXED",
        "probe_marker": "mixed",
        "evidence_pack": {"path": {"complete_in_function": True}},
    }
    try:
        with bind_call_context(mixed, registry):
            resolution = queue.resolve_requested_fact(
                dict(issue),
                validator_data={
                    "verdict": "uncertain",
                    "missing_fact_request": {"fact_kind": "lockset"},
                },
                validation_evidence=issue["evidence_pack"],
            )
        assert resolution is not None
        assert observed and observed[0]["build"] == build
        # Mixed overloads are evidence against a single identity: the
        # provider must not borrow the only published overload.
        assert observed[0]["callee_usr"] == ""
        assert observed[0]["match"] == []
    finally:
        queue._fact_provider_executor.shutdown(wait=True)


@needs_native
def test_switching_entry_clears_the_prior_native_callee_map_in_providers(native_overloads):
    from zscope.config.function_entry import FunctionEntry
    from zscope.orchestration.entry_instances import plan_entry_instances

    index, root = native_overloads
    registry, build, int_usr, only_int, mixed = _overload_project(index)
    instance = plan_entry_instances(
        index, [FunctionEntry("call_mixed", file_path="log.cpp")]
    ).instances[0]
    queue = EvidenceCompletionQueue(enabled=True, max_workers=1, fact_timeout_seconds=30.0)
    observed = []
    original = queue._requested_completion_proofs

    def switched_provider(fact_kind, issue, validation_evidence):
        # Inside the provider thread the carried context is call_int's; the
        # framework then rebinds to the new entry's context — the prior
        # entry's callee map must be gone, and mixed stays unknown.
        with rebound_execution_context(ExecutionContext(build, ("call_mixed", instance.usr))):
            observed.append(
                {
                    "callee_usr": current_callee_usr(registry, "log_event"),
                    "match": [
                        m.symbol.usr
                        for m in registry.match_call("log_event", "io_acquire", ["mode"])
                    ],
                    "entry_usr": current_scope_symbol_usr("call_mixed"),
                }
            )
        return original(fact_kind, issue, validation_evidence)

    queue._requested_completion_proofs = switched_provider
    issue = {
        "validation_cluster_uid": "VAL_SWITCH",
        "probe_marker": "switch",
        "evidence_pack": {"path": {"complete_in_function": True}},
    }
    try:
        with bind_call_context(only_int, registry):
            resolution = queue.resolve_requested_fact(
                dict(issue),
                validator_data={
                    "verdict": "uncertain",
                    "missing_fact_request": {"fact_kind": "lockset"},
                },
                validation_evidence=issue["evidence_pack"],
            )
        assert resolution is not None
        assert observed
        # The new entry (mixed overloads) resolves nothing for log_event;
        # the stale call_int receipt never grants the int contract.
        assert observed[0]["callee_usr"] == ""
        assert observed[0]["match"] == []
        assert observed[0]["entry_usr"] == instance.usr
    finally:
        queue._fact_provider_executor.shutdown(wait=True)


@needs_native
def test_runner_workers_do_not_borrow_caller_ambient_callee_map(native_variants):
    """The real chain never inherits the caller's ambient entry map.

    ``runner.run`` is invoked inside another entry's verified call context;
    the runner's own binding deliberately clears it, so neither the real
    agent nor the real provider tasks resolve that entry's callees.
    """
    from zscope.semantics.call_context import current_call_facts

    index, root = native_variants
    instances = _variant_instances(index)
    base = instances["BASE"]
    scoped = ScopedCodeIndex(index, InstanceScope.from_entry_instance(base))
    queue = EvidenceCompletionQueue(enabled=True, max_workers=1, fact_timeout_seconds=30.0)
    recordings = []
    _instrument_queue(queue, recordings)
    issues = _issues(2, "AMBC", build=base.build_context_id)
    runner, model = _make_real_runner(issues, code_index=scoped, queue=queue)

    # A verified call context for the release_owner entry, bound by the
    # caller around the whole run — the runner must not let its workers
    # borrow this map for a different scope decision.
    unrelated = {
        "func_name": "release_owner",
        "file_path": "unit.c",
        "signature": "void release_owner(void)",
        "code": UNIT_C,
        "program_facts": index.get_function_program_facts(
            "release_owner", "unit.c", build_context_id=base.build_context_id
        ),
    }
    from zscope.semantics.defaults import default_local_pattern_semantics

    semantics = default_local_pattern_semantics()
    state = _multi_state(issues)
    try:
        with bind_call_context(unrelated, semantics.contracts):
            runner.run(state)
    finally:
        queue._fact_provider_executor.shutdown(wait=True)
    # The real agent and provider tasks ran under the runner's own scope:
    # correct build, and the ambient callee map never leaked into them.
    assert model.calls
    assert {c.build_context_id for c in model.calls} == {base.build_context_id}
    assert recordings
    assert {record["build"] for record in recordings} == {base.build_context_id}
    for record in recordings:
        assert record["entry_usr"] == base.usr
    # The runner's own binding clears call facts: rebinding it on this
    # thread (which still holds the ambient map) yields a clean slate.
    with rebound_execution_context(runner._execution_context):
        assert current_call_facts() is None


@needs_native
def test_captured_snapshot_freezes_nested_call_values_too(native_overloads):
    """Parent mutation of a live entry's nested call values changes nothing.

    The freeze covers the per-call entries (arguments/results/values), not
    just the top-level observation map: a parent rewriting its own live
    binding after capture cannot change what a rebind worker resolves.
    """
    index, root = native_overloads
    registry, build, int_usr, only_int, _ = _overload_project(index)
    with bind_call_context(only_int, registry):
        captured = current_execution_context()
        live = current_call_facts()
        # Parent rewrites the live entry's call values dict (index 3 of one
        # entry) and the observations map; both are separate objects from
        # the frozen snapshot after capture.
        if live[1]:
            live[1][0][3]["mode"] = {"forged": True}
        live[2]["log_event"] = "c:@F@forged"
        with rebound_execution_context(captured):
            assert current_callee_usr(registry, "log_event") == int_usr
            assert [
                m.symbol.usr for m in registry.match_call("log_event", "io_acquire", ["mode"])
            ] == [int_usr]
            from zscope.semantics.call_context import current_call_values

            values = current_call_values(registry, "log_event", ["mode"], "")
            assert "forged" not in values


@needs_native
def test_real_native_target_values_survive_capture_non_empty(native_overloads):
    """Valid native target.* facts are preserved, not erased, by the freeze.

    The int-overload caller's entry carries real native facts (pointer
    width, triple); a non-empty exact match before and after capture is the
    positive the isolation fix must not sacrifice.
    """
    index, root = native_overloads
    registry, build, int_usr, only_int, _ = _overload_project(index)
    with bind_call_context(only_int, registry):
        before = current_call_values(registry, "log_event", ["mode"], "")
        assert before, "the real native caller must expose non-empty call values"
        assert "target.pointer_bits" in before and before["target.pointer_bits"] == 64
        captured = current_execution_context()
        with rebound_execution_context(captured):
            after = current_call_values(registry, "log_event", ["mode"], "")
    assert after == before
    assert after and after["target.pointer_bits"] == 64
    assert after.get("target.triple") == before.get("target.triple")


@needs_native
def test_consumer_list_arguments_match_the_frozen_snapshot(native_overloads):
    """A plain consumer argument list still matches its frozen entry.

    The freeze keeps arguments as lists; the downstream comparison
    (``args == arguments``) must keep matching so freezing storage never
    silently erases a valid call.
    """
    index, root = native_overloads
    registry, build, int_usr, only_int, _ = _overload_project(index)
    with bind_call_context(only_int, registry):
        captured = current_execution_context()
        # Parent adds a controlled payload to its own live binding AFTER the
        # capture: the snapshot must not see it.
        live = current_call_facts()
        for entry in live[1]:
            if entry[0] == "log_event":
                entry[3]["late_probe"] = {"values": [1, 2]}
        with rebound_execution_context(captured):
            values = current_call_values(registry, "log_event", ["mode"], "")
    assert values, "list-argument match must keep returning the frozen values"
    assert "late_probe" not in values
    assert values.get("target.pointer_bits") == 64


@needs_native
def test_parent_nested_payload_mutation_never_reaches_the_snapshot(native_overloads):
    """Parent mutation at any nesting depth leaves the snapshot untouched."""
    from copy import deepcopy

    index, root = native_overloads
    registry, build, int_usr, only_int, _ = _overload_project(index)
    with bind_call_context(only_int, registry):
        live = current_call_facts()
        entry = next(e for e in live[1] if e[0] == "log_event")
        entry[3]["nested"] = {"samples": [1, {"value": 2}]}
        expected = deepcopy(current_call_values(registry, "log_event", ["mode"], ""))
        captured = current_execution_context()
        # Mutate through the parent's live nested structures after capture.
        entry[3]["nested"]["samples"][1]["value"] = 99
        entry[3]["nested"]["samples"].append("late")
        entry[3]["brand_new"] = "after-capture"
        with rebound_execution_context(captured):
            values = current_call_values(registry, "log_event", ["mode"], "")
    assert values == expected
    assert values["nested"] == {"samples": [1, {"value": 2}]}


@needs_native
def test_real_provider_path_returns_non_empty_valid_values(native_overloads):
    """The real provider framework carries valid values, not just isolation.

    The submit happens under the verified entry context; the provider task
    (real dispatch, wait-boundary observation only) resolves non-empty
    exact native facts through the frozen snapshot.
    """
    index, root = native_overloads
    registry, build, int_usr, only_int, _ = _overload_project(index)
    queue = EvidenceCompletionQueue(enabled=True, max_workers=1, fact_timeout_seconds=30.0)
    observed = []

    original = queue._requested_completion_proofs

    def provider(fact_kind, issue, validation_evidence):
        observed.append(dict(current_call_values(registry, "log_event", ["mode"], "")))
        return original(fact_kind, issue, validation_evidence)

    queue._requested_completion_proofs = provider
    issue = {
        "validation_cluster_uid": "VAL_VALUES",
        "evidence_pack": {"path": {"complete_in_function": True}},
    }
    try:
        with bind_call_context(only_int, registry):
            resolution = queue.resolve_requested_fact(
                dict(issue),
                validator_data={
                    "verdict": "uncertain",
                    "missing_fact_request": {"fact_kind": "lockset"},
                },
                validation_evidence=issue["evidence_pack"],
            )
        assert resolution is not None
        assert observed, "the real provider task must run"
        values = observed[0]
        assert values, "the provider must see non-empty valid call values"
        assert values.get("target.pointer_bits") == 64
        assert values.get("target.triple") == "x86_64-pc-linux-gnu"
    finally:
        queue._fact_provider_executor.shutdown(wait=True)


@needs_native
def test_same_pool_concurrent_snapshots_are_independent(native_overloads):
    """Two concurrent resolves on one pool keep separate submit snapshots.

    Each provider boundary captures its own frozen snapshot at submit; a
    parent mutating one live binding (or one provider finishing) never
    rewrites the other's submit-time identity on the reused pool thread.
    """
    index, root = native_overloads
    registry, build, int_usr, only_int, mixed = _overload_project(index)
    queue = EvidenceCompletionQueue(enabled=True, max_workers=1, fact_timeout_seconds=30.0)
    observed = []
    gate = threading.Event()

    original = queue._requested_completion_proofs

    def provider(fact_kind, issue, validation_evidence):
        # Both tasks share the single pool thread; record under the frozen
        # submit snapshot each task actually carries.
        gate.wait(15)
        observed.append(
            {
                "thread": threading.current_thread().name,
                "callee_usr": current_callee_usr(registry, "log_event"),
                "match": [
                    m.symbol.usr for m in registry.match_call("log_event", "io_acquire", ["mode"])
                ],
            }
        )
        return original(fact_kind, issue, validation_evidence)

    queue._requested_completion_proofs = provider
    results = []
    errors = []

    def resolve(label, context):
        try:
            with bind_call_context(context, registry):
                results.append(
                    queue.resolve_requested_fact(
                        {
                            "validation_cluster_uid": f"VAL_{label}",
                            "evidence_pack": {"path": {"complete_in_function": True}},
                        },
                        validator_data={
                            "verdict": "uncertain",
                            "missing_fact_request": {"fact_kind": "lockset"},
                        },
                        validation_evidence={"path": {"complete_in_function": True}},
                    )
                )
        except BaseException as exc:
            errors.append(exc)

    try:
        first = threading.Thread(target=resolve, args=("SNAPA", only_int))
        first.start()
        # Let the first task occupy the single pool worker, then submit the
        # second (mixed) task; both snapshots were frozen at their submits.
        threading.Event().wait(0.2)
        second = threading.Thread(target=resolve, args=("SNAPB", mixed))
        second.start()
        threading.Event().wait(0.3)
        gate.set()
        first.join(timeout=30)
        second.join(timeout=30)
        assert not errors, errors
        assert len(observed) == 2
        assert all(record["thread"] == "zscope-fact-provider_0" for record in observed)
        # Exactly one task carried the int entry's valid map (int USR match)
        # and the other the mixed entry's unknown snapshot — independent of
        # submission or execution order on the reused thread.
        matches = sorted((record["callee_usr"], tuple(record["match"])) for record in observed)
        assert matches == [("", ()), (int_usr, (int_usr,))]
    finally:
        gate.set()
        queue._fact_provider_executor.shutdown(wait=True)


@needs_native
def test_cross_variant_concurrent_providers_share_pool_without_callee_leak(native_variants):
    from zscope.semantics.call_context import current_call_facts

    index, root = native_variants
    instances = _variant_instances(index)
    shared_queue = EvidenceCompletionQueue(enabled=True, max_workers=1, fact_timeout_seconds=30.0)
    records = []
    original = shared_queue._requested_completion_proofs

    def observing(fact_kind, issue, validation_evidence):
        records.append(
            {
                "build": current_build_id(),
                "call_facts": current_call_facts() is not None,
                "thread": threading.current_thread().name,
            }
        )
        return original(fact_kind, issue, validation_evidence)

    shared_queue._requested_completion_proofs = observing

    runners = {}
    for label, instance in instances.items():
        scoped = ScopedCodeIndex(index, InstanceScope.from_entry_instance(instance))
        issues = _issues(2, label, build=instance.build_context_id)
        runner, _ = _make_real_runner(issues, code_index=scoped, queue=shared_queue)
        runners[label] = (runner, _multi_state(issues), instance)

    errors = []

    def drive(label):
        runner, state, _ = runners[label]
        try:
            runner.run(state)
        except BaseException as exc:
            errors.append(exc)

    threads = [threading.Thread(target=drive, args=(label,)) for label in runners]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=180)
    try:
        assert not errors
        assert records
        # Every provider task ran under its own runner's exact build, on the
        # one reused pool thread, with no carried callee map from any entry.
        for label, (_, _, instance) in runners.items():
            builds = {r["build"] for r in records if r["build"] == instance.build_context_id}
            assert builds == {instance.build_context_id}, label
        assert all(record["thread"] == "zscope-fact-provider_0" for record in records)
        assert all(record["call_facts"] is False for record in records)
    finally:
        shared_queue._fact_provider_executor.shutdown(wait=True)
