"""Query plans cross builds; observations, facts and decisions never do."""

import json
import os
from copy import deepcopy
from types import SimpleNamespace

import pytest

from zscope.agents.validator_agent.agent import ValidatorAgent
from zscope.core.validation import investigation_reuse
from zscope.core.validation.runner import _PreparedValidation
from zscope.framework.base import BaseTool
from zscope.framework.llm_client import LLMClient
from zscope.snapshots.store import SnapshotStore

from test_validation_runner import _runner
from test_validator_v3_protocol import _slice, _result


class CurrentCallers(BaseTool):
    def __init__(self):
        super().__init__("get_callers", "Read current caller membership")
        self.members = ["caller: consumes resource"]
        self.calls = 0
        self.failed = False

    def execute(self, arguments):
        self.calls += 1
        if self.failed:
            return {"success": False, "error": "current query unavailable"}
        return {"success": True, "data": {"callers": self.members[:], "truncated": False}}

    def get_schema(self):
        return {
            "type": "function",
            "function": {
                "name": self.name,
                "description": self.description,
                "parameters": {
                    "type": "object",
                    "properties": {"func_name": {"type": "string"}},
                    "required": ["func_name"],
                },
            },
        }


class QueryTransport:
    """Only the provider response is replaced; the real client loop/accounts run."""

    def __init__(self, *, compact=False):
        self.calls = 0
        self.finish = "decision_complete"
        self.requests = []
        self.compact = compact

    def __call__(self, url, payload):
        self.calls += 1
        self.requests.append(deepcopy(payload))
        messages = payload["messages"]
        current = None
        recorded = None
        tool_names = {}
        for message in messages:
            for call in message.get("tool_calls") or []:
                tool_names[call["id"]] = call["function"]["name"]
            content = message.get("content") or ""
            if message.get("role") == "user" and content.startswith("These read-only queries"):
                current = json.loads(content.split("\n", 1)[1])[0]["current_result"]
            elif message.get("role") == "tool":
                value = json.loads(content)
                tool_name = tool_names.get(message.get("tool_call_id"))
                if tool_name == "get_callers":
                    current = value
                elif tool_name == "record_validator_investigation_fact":
                    recorded = value["fact"]
        if current is None:
            name, args = "get_callers", {"func_name": "f"}
        elif current.get("evidence_ref") and recorded is None:
            name, args = "record_validator_investigation_fact", {
                "fact_kind": "ownership_transfer",
                "evidence_refs": [current["evidence_ref"]],
                "summary": "当前调用者集合已经重新读取，仍需由当前裁决解释所有权。",
            }
        else:
            # Deliberately keep empty/failed membership unknown, never safe.
            members = (current.get("data") or {}).get("callers") or []
            verdict = "verified" if members and "leaks" in members[0] else "uncertain"
            name = "emit_validator_result_v3"
            evidence = json.loads(
                next(
                    message["content"].rsplit("\n\n", 1)[-1]
                    for message in messages
                    if message.get("role") == "user"
                    and message["content"].startswith(
                        "Investigate the candidate's unresolved conditions."
                    )
                )
            )
            args = _result(
                candidate_uid=evidence["obligation"]["candidate_uid"],
                validation_cluster_uid=evidence["obligation"]["validation_cluster_uid"],
                verdict=verdict,
                evidence_refs=[recorded["fact_uid"]] if recorded else [],
                stop_reason=(
                    "unsupported_fact"
                    if verdict == "uncertain" and self.finish == "decision_complete"
                    else self.finish
                ),
            )
            args["pass"] = "investigation_synthesis"
            if self.compact:
                for key in (
                    "schema_version",
                    "candidate_uid",
                    "validation_cluster_uid",
                    "pass",
                    "stop_reason",
                ):
                    del args[key]
        return (
            {
                "role": "assistant",
                "content": "",
                "tool_calls": [
                    {
                        "id": f"query-{self.calls}",
                        "type": "function",
                        "function": {"name": name, "arguments": json.dumps(args)},
                    }
                ],
            },
            "tool_calls",
            {"prompt_tokens": 11, "completion_tokens": 7, "total_tokens": 18},
        )


def setup_runner(tmp_path, tool, transport):
    client = LLMClient(
        api_key="fixture",
        base_url="https://fixture.invalid/v1",
        models=["fixture-model"],
        max_retries=0,
        supports_structured_output=True,
    )
    client._transport = "curl"
    client._curl_chat_completion = transport
    agent = ValidatorAgent(client, [tool])
    index = SimpleNamespace(
        get_build_contexts=lambda path: [
            {"build_context_id": "build-a", "command_id": "compile-main"},
            {"build_context_id": "build-b", "command_id": "compile-main"},
        ]
    )
    runner = _runner(agent, code_index=index, llm_clients={"default": client})
    runner.config.project.project_root = str(tmp_path)
    runner.snapshot_store = SnapshotStore(tmp_path / "snapshots")
    return runner, agent, client


def request(build="build-a"):
    issue = {
        "build_context_id": build,
        "function": "f",
        "location": "unit.c:4",
        "rule_id": "test.resource",
        "defect_class": "resource_leak",
        "security_obligation": {"subject_uid": "resource-p"},
    }
    evidence = _slice()
    evidence["validation_pass"] = "investigation_synthesis"
    evidence["obligation"] = {
        "candidate_uid": "CAND_" + build,
        "validation_cluster_uid": "VAL_" + build,
    }
    return _PreparedValidation(0, issue, "f", "void f(void) {}", {}, allow_v3=True), {
        "evidence_slice": evidence,
        "validation_pass": "investigation_synthesis",
        "candidate_build_context_id": build,
        "candidate_subject_uid": "resource-p",
    }


@pytest.mark.parametrize("compact", [False, True])
def test_cross_build_query_replay_uses_current_membership_and_current_facts(tmp_path, compact):
    tool, transport = CurrentCallers(), QueryTransport(compact=compact)
    runner, agent, client = setup_runner(tmp_path, tool, transport)
    try:
        item, view = request()
        runner._instance_semantics_digest = "old-build-semantics"
        cold = runner._investigate_with_query_reuse(item, agent, view)
        assert cold.success and cold.metadata["validator_query_reuse"]["writes"] == 1
        assert transport.calls == 3 and tool.calls == 1
        before = transport.calls
        tool.members = ["new caller: leaks resource"]
        item, view = request("build-b")
        runner._instance_semantics_digest = "new-build-semantics"
        warm = runner._investigate_with_query_reuse(item, agent, view)
        assert warm.success and warm.data["verdict"] == "verified"
        assert transport.calls - before == 2 and tool.calls == 2
        counts = warm.metadata["validator_query_reuse"]
        assert counts["hits"] == counts["changed_results"] == counts["replayed_queries"] == 1
        assert warm.metadata["cumulative_total_tokens"] == 36
        assert all(
            fact["build_context_id"] == "build-b"
            for fact in warm.metadata["validator_investigation_facts"]
        )
        assert not set(cold.data["evidence_refs"]) & set(warm.data["evidence_refs"])
        item, view = request("build-b")
        runner._initial_reuse_enabled = False
        fresh = runner._investigate_with_query_reuse(item, agent, view)
        assert fresh.data == warm.data
    finally:
        client.close()


def test_empty_subscription_reopens_when_a_new_caller_appears(tmp_path):
    tool, transport = CurrentCallers(), QueryTransport()
    tool.members = []
    runner, agent, client = setup_runner(tmp_path, tool, transport)
    try:
        item, view = request()
        cold = runner._investigate_with_query_reuse(item, agent, view)
        assert cold.data["verdict"] == "uncertain"
        assert cold.metadata["validator_query_reuse"]["writes"] == 1
        tool.members = ["new caller: leaks resource"]
        item, view = request("build-b")
        current = runner._investigate_with_query_reuse(item, agent, view)
        assert current.metadata["validator_query_reuse"]["changed_results"] == 1
        assert current.data["verdict"] == "verified"
        tool.members = []
        item, view = request("build-b")
        removed = runner._investigate_with_query_reuse(item, agent, view)
        assert removed.data["verdict"] == "uncertain"
        assert removed.metadata["validator_query_reuse"]["changed_results"] == 1
    finally:
        client.close()


@pytest.mark.parametrize("change", ["model", "disabled"])
def test_query_plan_contract_and_completion_boundaries(tmp_path, monkeypatch, change):
    tool, transport = CurrentCallers(), QueryTransport()
    runner, agent, client = setup_runner(tmp_path, tool, transport)
    try:
        item, view = request()
        runner._investigate_with_query_reuse(item, agent, view)
        if change == "model":
            client.models = ["other-model"]
        elif change == "disabled":
            monkeypatch.setattr(investigation_reuse, "ENABLED", False)
        item, view = request("build-b")
        response = runner._investigate_with_query_reuse(item, agent, view)
        assert response.metadata["validator_query_reuse"]["hits"] == 0
        assert response.metadata["validator_query_reuse"]["replayed_queries"] == 0
    finally:
        client.close()


def test_incomplete_investigation_preserves_only_successful_queries(tmp_path):
    tool, transport = CurrentCallers(), QueryTransport()
    runner, agent, client = setup_runner(tmp_path, tool, transport)
    try:
        transport.finish = "fact_timeout"
        item, view = request()
        prior = runner._investigate_with_query_reuse(item, agent, view)
        assert prior.data["verdict"] == "uncertain"
        assert prior.metadata["validator_query_reuse"]["writes"] == 1
        tool.members = ["new caller: leaks resource"]
        transport.finish = "decision_complete"
        item, view = request("build-b")
        current = runner._investigate_with_query_reuse(item, agent, view)
        assert current.data["verdict"] == "verified"
        assert current.metadata["validator_query_reuse"]["hits"] == 1
        assert current.metadata["validator_query_reuse"]["changed_results"] == 1
        assert current.metadata["validator_query_reuse"]["replayed_queries"] == 1
        assert transport.calls == 5 and tool.calls == 2
    finally:
        client.close()


def test_failed_current_query_does_not_restore_a_prior_verdict(tmp_path):
    tool, transport = CurrentCallers(), QueryTransport()
    tool.members = ["caller: leaks resource"]
    runner, agent, client = setup_runner(tmp_path, tool, transport)
    try:
        item, view = request()
        prior = runner._investigate_with_query_reuse(item, agent, view)
        assert prior.data["verdict"] == "verified"
        tool.failed = True
        item, view = request("build-b")
        current = runner._investigate_with_query_reuse(item, agent, view)
        assert current.data["verdict"] == "uncertain"
        assert current.metadata["validator_query_reuse"]["failed_queries"] == 1
        assert current.metadata["validator_query_reuse"]["writes"] == 0
        assert current.metadata["validator_investigation_facts"] == []
    finally:
        client.close()


def test_cancelled_query_replay_stops_before_tools_or_model(tmp_path):
    from zscope.common.cancellation import (
        CancellationError,
        CancellationToken,
        bind_cancellation_token,
    )

    tool, transport = CurrentCallers(), QueryTransport()
    runner, agent, client = setup_runner(tmp_path, tool, transport)
    try:
        item, view = request()
        runner._investigate_with_query_reuse(item, agent, view)
        calls = transport.calls, tool.calls
        token = CancellationToken()
        token.cancel("scan_cancelled")
        item, view = request("build-b")
        with bind_cancellation_token(token), pytest.raises(CancellationError):
            runner._investigate_with_query_reuse(item, agent, view)
        assert calls == (transport.calls, tool.calls)
    finally:
        client.close()


def test_current_model_can_correct_conflicting_terminal_request(tmp_path):
    class ConflictingTerminal(QueryTransport):
        def __init__(self):
            super().__init__()
            self.sent_conflict = False
            self.received_correction = False

        def __call__(self, url, payload):
            message, finish, usage = super().__call__(url, payload)
            call = message["tool_calls"][0]["function"]
            if call["name"] == "emit_validator_result_v3":
                if not self.sent_conflict:
                    value = json.loads(call["arguments"])
                    value["missing_fact_request"] = {
                        "fact_kind": "caller_contract",
                        "reason": "none",
                    }
                    call["arguments"] = json.dumps(value)
                    self.sent_conflict = True
                else:
                    self.received_correction = any(
                        "missing_fact_request only for an uncertain decision"
                        in (entry.get("content") or "")
                        for entry in payload["messages"]
                        if entry.get("role") == "tool"
                    )
            return message, finish, usage

    tool, transport = CurrentCallers(), ConflictingTerminal()
    tool.members = ["caller: leaks resource"]
    runner, agent, client = setup_runner(tmp_path, tool, transport)
    try:
        item, view = request()
        result = runner._investigate_with_query_reuse(item, agent, view)
        assert transport.received_correction
        assert transport.calls == 4
        assert result.data["verdict"] == "verified"
        assert result.data["missing_fact_request"] is None
    finally:
        client.close()


@pytest.mark.parametrize("correct", [True, False])
def test_raw_tool_refs_require_fact_registration_and_cannot_escape_via_history(tmp_path, correct):
    class UnregisteredTerminal(QueryTransport):
        premature = False
        received_correction = False

        def __call__(self, url, payload):
            message, finish, usage = super().__call__(url, payload)
            call = message["tool_calls"][0]["function"]
            self.received_correction |= any(
                "Final evidence_refs must cite recorded FACT_V3" in (entry.get("content") or "")
                for entry in payload["messages"]
                if entry.get("role") == "tool"
            )
            if call["name"] == "record_validator_investigation_fact" and (
                not self.premature or not correct
            ):
                raw = json.loads(call["arguments"])["evidence_refs"]
                value = _result(
                    candidate_uid="CAND_build-a",
                    validation_cluster_uid="VAL_build-a",
                    evidence_refs=raw,
                    stop_reason="decision_complete",
                )
                value["pass"] = "investigation_synthesis"
                call.update(name="emit_validator_result_v3", arguments=json.dumps(value))
                self.premature = True
            return message, finish, usage

    tool, transport = CurrentCallers(), UnregisteredTerminal()
    tool.members = ["caller: leaks resource"]
    runner, agent, client = setup_runner(tmp_path, tool, transport)
    try:
        item, view = request()
        result = runner._investigate_with_query_reuse(item, agent, view)
        assert transport.received_correction
        if correct:
            assert result.data["verdict"] == "verified"
            assert transport.calls == 4
            fact = result.metadata["validator_investigation_facts"][0]
            assert result.data["evidence_refs"] == [fact["fact_uid"]]
        else:
            assert result.data["verdict"] == "uncertain"
            assert result.metadata["validator_investigation_facts"] == []
            assert not result.metadata["validator_protocol_audit"]["parsed"]
    finally:
        client.close()


class NativeQueryTransport:
    def __init__(self):
        from test_instance_analysis import _ArtifactReuseTransport

        self.base = _ArtifactReuseTransport()
        self.calls = 0

    def __call__(self, url, payload):
        self.calls += 1
        tools = {tool["function"]["name"] for tool in payload.get("tools", [])}
        if "emit_contract_summary" in tools:
            return self.base(url, payload)
        messages = payload["messages"]
        investigation = next(
            (
                message
                for message in messages
                if message.get("role") == "user"
                and (message.get("content") or "").startswith(
                    "Investigate the candidate's unresolved conditions."
                )
            ),
            None,
        )
        if investigation is None:
            message, finish, usage = self.base(url, payload)
            value = json.loads(message["content"])
            value.update(verdict="uncertain", stop_reason="unsupported_fact")
            message["content"] = json.dumps(value)
            return message, finish, usage
        evidence = json.loads(investigation["content"].rsplit("\n\n", 1)[-1])
        current, recorded, names = None, None, {}
        for message in messages:
            for call in message.get("tool_calls") or []:
                names[call["id"]] = call["function"]["name"]
            content = message.get("content") or ""
            if message.get("role") == "user" and content.startswith("These read-only queries"):
                current = json.loads(content.split("\n", 1)[1])[0]["current_result"]
            elif message.get("role") == "tool":
                value = json.loads(content)
                if names.get(message.get("tool_call_id")) == "read_code":
                    current = value
                elif (
                    names.get(message.get("tool_call_id")) == "record_validator_investigation_fact"
                ):
                    recorded = value["fact"]
        if current is None:
            name, args = "read_code", {"file_path": "unit.c", "start_line": 1, "end_line": 20}
        elif recorded is None:
            assert current.get("evidence_ref"), current
            name, args = "record_validator_investigation_fact", {
                "fact_kind": "cleanup_coverage",
                "evidence_refs": [current["evidence_ref"]],
                "summary": "当前完整函数源码中成功分配后退出，未出现释放操作。",
            }
            if evidence["obligation"].get("positive_conditions"):
                args["condition_ids"] = evidence["obligation"]["positive_conditions"]
                args["condition_outcome"] = "supported"
        else:
            name = "emit_validator_result_v3"
            args = _result(
                candidate_uid=evidence["obligation"]["candidate_uid"],
                validation_cluster_uid=evidence["obligation"]["validation_cluster_uid"],
                evidence_refs=[recorded["fact_uid"], *list(evidence["evidence_ref_catalog"])[:20]],
            )
            args["pass"] = "investigation_synthesis"
        return (
            {
                "role": "assistant",
                "content": "",
                "tool_calls": [
                    {
                        "id": f"native-{self.calls}",
                        "type": "function",
                        "function": {"name": name, "arguments": json.dumps(args)},
                    }
                ],
            },
            "tool_calls",
            {"prompt_tokens": 11, "completion_tokens": 7, "total_tokens": 18},
        )


def test_native_query_reuse_matches_fresh_after_change_and_repair(tmp_path_factory):
    from test_instance_analysis import _native_artifact_config, _run_native_artifact_scan
    from zscope.framework.llm_usage import ensure_scan_token_usage_ledger
    from zscope.retrieval.clang_backend import ClangBackend

    executable = os.environ.get("Z_SCOPE_TEST_CLANG_INDEXER")
    if not executable:
        pytest.skip("native query replay requires Z_SCOPE_TEST_CLANG_INDEXER")
    root = tmp_path_factory.mktemp("query-reuse-project")
    cdb = root / "compile_commands.json"
    cdb.write_text(
        json.dumps(
            [
                {
                    "directory": str(root),
                    "file": str(root / "unit.c"),
                    "arguments": ["clang", "-c", str(root / "unit.c"), *flags],
                }
                for flags in ([], ["-DALT=1"])
            ]
        )
    )
    backend = ClangBackend(frontend="batch", clang_indexer_path=executable, max_threads=1)
    cache = tmp_path_factory.mktemp("query-reuse-native")

    def scan(label, *, reuse, repair=False):
        config = _native_artifact_config(
            root, cdb, cache / ("shared" if reuse else label), cache / "users"
        )
        config.analysis.validation_v3_reattempt = True
        config.analysis.max_tool_iterations = 6
        config.rules.enabled_ids = ["same_function_allocation_not_released"]
        ledger = ensure_scan_token_usage_ledger(config)
        client = LLMClient(
            api_key="fixture",
            base_url="https://fixture.invalid/v1",
            models=["fixture-model"],
            max_retries=0,
            supports_structured_output=True,
            token_usage_ledger=ledger,
        )
        client._transport = "curl"
        transport = NativeQueryTransport()
        client._curl_chat_completion = transport
        try:
            assert backend.initialize(str(root), compile_commands_path=str(cdb))
            result = _run_native_artifact_scan(
                backend, root, cdb, config, client, reuse=reuse, require_candidates=not repair
            )
            assert result["usage"]["event_count"] == transport.calls
            assert result["usage"]["consumed_tokens"] == transport.calls * 18
            if not repair:
                assert result["findings"], "The comparison must include an actual reported issue."
            return result
        finally:
            client.close()

    for stage, value, cleanup in (
        ("baseline", 1, ""),
        ("changed", 2, ""),
        ("repaired", 2, "free(p);"),
    ):
        (root / "unit.c").write_text(
            "#include <stdlib.h>\n"
            f"int unrelated(void) {{ return {value}; }}\n"
            "void f(void) {\n  char *p = malloc(8);\n  if (!p) return;\n"
            f"  {cleanup}\n}}\n"
        )
        current = scan(stage, reuse=True, repair=bool(cleanup))
        if stage == "baseline":
            assert current["metadata"]["artifact_reuse"]["investigation_queries"]["writes"] == 2
        else:
            fresh = scan("fresh-" + stage, reuse=False, repair=bool(cleanup))
            assert current["findings"] == fresh["findings"]
            assert current["candidates"] == fresh["candidates"]
            if stage == "changed":
                metrics = current["metadata"]["artifact_reuse"]["investigation_queries"]
                assert metrics["hits"] == metrics["replayed_queries"] == 2
                assert metrics["changed_results"] == 2
                assert metrics["condition_rows"] > 0
                assert metrics["reopened_conditions"] > 0
                assert current["usage"]["event_count"] < fresh["usage"]["event_count"]
            else:
                assert current["findings"] == []
    backend.close()
