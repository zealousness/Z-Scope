"""Saved-config MCP preparation uses the real shared read-only projection.

These tests require no native tool, provider, index, model, scan or server.
Transport handling is invoked directly; no service/socket is started.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

import pytest
from click.testing import CliRunner

from zscope.cli.config_cli import main as config_cli
from zscope.config.config import ConfigLoader
from zscope.config.v3_preparation import prepare_saved_config as real_prepare
from zscope.mcp.provider import ZScopeMcpProvider
from zscope.mcp.server import handle_jsonrpc_request
from zscope.tools.policy import ToolPolicy
from zscope.tools.runtime import ToolsRuntime
from zscope.web.services import ConfigService

TOOL = "zscope.config.prepare"
RESOURCE = "zscope://config/preparation"
FIXED_NOW = datetime(2026, 10, 14, 7, 0, tzinfo=timezone.utc)


class _Index:
    backend_name = "unified"
    language = "c_cpp"
    _index_epoch = 1
    _function_index: dict = {}

    def list_functions(self, *args, **kwargs):
        raise AssertionError("preparation must not query the index")

    def resolve_existing_file(self, *args, **kwargs):
        raise AssertionError("preparation must not query the index")

    def close(self):
        pass


class _Snapshots:
    snapshot_dir = Path(".")

    def list_snapshots(self):
        raise AssertionError("preparation must not query snapshots")


def _document(root: Path, version: int = 3) -> dict:
    llms = {
        "default": {
            "base_urls": ["http://prepare-only.invalid/v1"],
            "models": ["private-model-marker"],
            "api_key": "private-key-marker",
        }
    }
    if version == 2:
        return {
            "config_version": 2,
            "llms": llms,
            "project": {"root": str(root), "source_root": ".", "language": "c_cpp"},
            "scan": {"task": ""},
            "indexing": {"backend": "regex"},
            "concurrency": {
                "entry_workers": 1,
                "validator_workers": 1,
                "investigator_workers": 1,
                "evidence_completion_workers": 1,
                "index_workers": 1,
                "svf_workers": 1,
                "llm_max_inflight": 1,
            },
        }
    return {
        "config_version": 3,
        "llms": llms,
        "project": {
            "root": str(root),
            "language": "c_cpp",
            "platform": "linux_user",
            "targets": [{"id": "first", "compile_commands": "first.json"}],
        },
        "scan": {"preset": "quick", "focus": ["memory"], "reproduction": "auto"},
        "execution": {"timezone": "UTC", "stop_at": "08:00", "max_workers": 4},
    }


def _write(path: Path, value: dict) -> None:
    path.write_text(json.dumps(value), encoding="utf-8")


def _project(root: Path, version: int = 3) -> Path:
    root.mkdir()
    (root / "unit.c").write_text("int run(void) { return 0; }\n", encoding="utf-8")
    rows = [
        {
            "directory": str(root),
            "file": "unit.c",
            "arguments": ["private-compiler-marker", "-c", "unit.c"],
        }
    ]
    _write(root / "first.json", rows)
    _write(root / "second.json", rows)
    path = root / "zscope.yaml"
    _write(path, _document(root, version))
    return path


def _provider(path: Path, profile: str = "default", *, policy=None, bound=True):
    config = ConfigLoader.load(str(path), read_only=True)
    policy = policy or ToolPolicy.allow_all()
    kwargs = {
        "config_path": path if bound else None,
        "profile": profile,
        "tool_policy": policy,
        "max_result_chars": 100000,
    }
    if profile == "default":
        index, snapshots = _Index(), _Snapshots()
        kwargs.update(
            code_index=index,
            snapshot_store=snapshots,
            tools_runtime=ToolsRuntime(index, snapshots, tool_policy=policy),
        )
    return ZScopeMcpProvider(config, **kwargs)


def _state(root: Path) -> dict:
    return {
        path.relative_to(root).as_posix(): (
            ("file", path.stat().st_mtime_ns, hashlib.sha256(path.read_bytes()).hexdigest())
            if path.is_file()
            else ("directory", path.stat().st_mtime_ns)
        )
        for path in (root, *root.rglob("*"))
    }


def _shared(monkeypatch):
    calls = []

    def forward(path):
        calls.append(path)
        return real_prepare(path, now=FIXED_NOW)

    # Only time is controlled. Every call forwards to the actual shared parser,
    # composition and preparation implementation, never a fabricated payload.
    monkeypatch.setattr("zscope.config.v3_preparation.prepare_saved_config", forward)
    return calls


def _forbid_execution(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("preparation attempted index/model/scan/process execution")

    for name in (
        "subprocess.run",
        "subprocess.Popen",
        "zscope.retrieval.code_index.CodeIndex.__init__",
        "zscope.snapshots.store.SnapshotStore.__init__",
        "zscope.framework.llm_client.LLMClient.chat_completion",
        "zscope.orchestration.scan_session.ScanSessionRunner.run",
        "zscope.orchestration.jobs.service.ScanJobService.start",
    ):
        monkeypatch.setattr(name, forbidden)


@pytest.mark.parametrize("version", [2, 3])
@pytest.mark.parametrize("profile", ["default", "read_only"])
def test_prepare_matches_real_shared_CLI_Web_projection_without_execution(
    tmp_path, monkeypatch, version, profile
):
    path = _project(tmp_path / "project", version)
    provider = _provider(path, profile)
    calls = _shared(monkeypatch)
    _forbid_execution(monkeypatch)
    before = _state(path.parent)
    expected = real_prepare(str(path), now=FIXED_NOW)

    cli = CliRunner().invoke(config_cli, ["prepare", "--config", str(path), "--json"])
    assert cli.exit_code == 0, cli.output
    web = ConfigService(path).prepare_project()
    tool = provider.call_tool(TOOL, {})
    resource = provider.read_resource(RESOURCE)

    assert tool["success"] is True
    assert json.loads(cli.output) == web == tool["data"] == expected
    assert json.loads(resource["contents"][0]["text"]) == expected
    assert calls == [str(path)] * 4
    assert _state(path.parent) == before
    serialized = json.dumps(tool)
    for marker in (
        "private-key-marker",
        "private-model-marker",
        "prepare-only.invalid",
        "private-compiler-marker",
    ):
        assert marker not in serialized
    if version == 3:
        v3 = tool["data"]["version3"]
        assert v3["schema"] == "zscope.config-v3-preparation.v1"
        assert v3["targets"][0]["id"] == "first"
        assert v3["start_capability"]["startable"] is True
        assert set(v3["declared_not_consumed"]) == {
            "project.platform",
            "scan.focus",
            "scan.reproduction",
            "execution.max_workers",
        }
        assert v3["machine_flags"]["focus_wired"] is False
        assert v3["machine_flags"]["reproduction_wired"] is False
        assert v3["machine_flags"]["max_workers_wired"] is False
        assert v3["machine_flags"]["platform_wired"] is False
        assert v3["execution"]["resolved_stop_time"] == "2026-10-14T08:00:00+00:00"
    else:
        assert "version3" not in tool["data"]


@pytest.mark.parametrize("profile", ["default", "read_only"])
def test_saved_multi_target_can_prepare_but_still_cannot_compose_execution(
    tmp_path, monkeypatch, profile
):
    path = _project(tmp_path / "project")
    provider = _provider(path, profile)
    document = _document(path.parent)
    document["project"]["targets"].append({"id": "second", "compile_commands": "second.json"})
    _write(path, document)
    calls = _shared(monkeypatch)
    _forbid_execution(monkeypatch)
    before = _state(path.parent)

    tool = provider.call_tool(TOOL)
    resource = json.loads(provider.read_resource(RESOURCE)["contents"][0]["text"])

    assert tool["success"] is True
    assert tool["data"] == resource == real_prepare(str(path), now=FIXED_NOW)
    v3 = tool["data"]["version3"]
    assert [target["id"] for target in v3["targets"]] == ["first", "second"]
    assert v3["start_capability"]["startable"] is False
    assert "multi_target_execution_unwired" in {
        reason["code"] for reason in v3["start_capability"]["reasons"]
    }
    with pytest.raises(ValueError, match="exactly one"):
        ConfigLoader.load(str(path), read_only=True)
    assert calls == [str(path)] * 2
    assert _state(path.parent) == before
    assert not (path.parent / ".zscope_jobs").exists()


@pytest.mark.parametrize("profile", ["default", "read_only"])
@pytest.mark.parametrize("protocol", ["2024-11-05", "2025-06-18"])
def test_prepare_schema_and_existing_config_resource_remain_compatible(tmp_path, profile, protocol):
    path = _project(tmp_path / "project")
    provider = _provider(path, profile)
    schemas = {item["name"]: item for item in provider.list_tools(protocol)}
    schema = schemas[TOOL]
    assert schema["inputSchema"] == {
        "type": "object",
        "properties": {},
        "additionalProperties": False,
    }
    assert schema["annotations"] == {
        "readOnlyHint": True,
        "idempotentHint": True,
        "destructiveHint": False,
        "openWorldHint": False,
    }
    assert ("outputSchema" in schema) == (protocol == "2025-06-18")
    resources = {item["uri"] for item in provider.list_resources()}
    assert RESOURCE in resources and "zscope://config" in resources
    old_config = json.loads(provider.read_resource("zscope://config")["contents"][0]["text"])
    assert old_config["project"]["root"] == str(path.parent)
    assert "effective_scan" in old_config and "llm_usage" in old_config


@pytest.mark.parametrize(
    "arguments",
    [
        {"config_path": "/unrelated/config.yaml"},
        {"target": "second"},
        {"scan_depth": "deep"},
        {"now": "tomorrow"},
        {"argv": ["scan"]},
        [],
    ],
)
def test_no_caller_selected_config_target_clock_or_execution_arguments(
    tmp_path, monkeypatch, arguments
):
    path = _project(tmp_path / "project")
    provider = _provider(path)
    calls = _shared(monkeypatch)
    result = provider.call_tool(TOOL, arguments)
    assert result["success"] is False
    assert calls == []


@pytest.mark.parametrize(
    "suffix", ["?config_path=other", "?config_path=", "?target=second", "#alternate"]
)
def test_preparation_resource_accepts_only_its_fixed_URI(tmp_path, monkeypatch, suffix):
    path = _project(tmp_path / "project")
    provider = _provider(path)
    calls = _shared(monkeypatch)
    with pytest.raises(ValueError, match="no URI parameters"):
        provider.read_resource(RESOURCE + suffix)
    assert calls == []


def test_candidate_blind_does_not_gain_configuration_prepare_access(tmp_path, monkeypatch):
    path = _project(tmp_path / "project")
    provider = _provider(path, "candidate_blind")
    calls = _shared(monkeypatch)
    assert TOOL not in {item["name"] for item in provider.list_tools()}
    assert provider.list_resources() == []
    assert provider.call_tool(TOOL, {})["status"] == "forbidden"
    with pytest.raises(PermissionError):
        provider.read_resource(RESOURCE)
    assert calls == []


def test_explicit_tool_and_resource_policy_still_intersects_profile(tmp_path, monkeypatch):
    path = _project(tmp_path / "project")
    provider = _provider(
        path,
        policy=ToolPolicy(
            allowed_tools={"zscope.code.search"}, allowed_resources={"zscope://config"}
        ),
    )
    calls = _shared(monkeypatch)
    assert TOOL not in {item["name"] for item in provider.list_tools()}
    assert RESOURCE not in {item["uri"] for item in provider.list_resources()}
    assert provider.call_tool(TOOL, {})["success"] is False
    with pytest.raises(PermissionError):
        provider.read_resource(RESOURCE)
    assert calls == []


def test_provider_without_saved_path_has_no_prepare_advertisement_or_CWD_fallback(
    tmp_path, monkeypatch
):
    path = _project(tmp_path / "project")
    provider = _provider(path, bound=False)
    monkeypatch.chdir(path.parent)
    calls = _shared(monkeypatch)
    assert TOOL not in {item["name"] for item in provider.list_tools()}
    assert RESOURCE not in {item["uri"] for item in provider.list_resources()}
    result = provider.call_tool(TOOL, {})
    assert result["success"] is False and result["code"] == "preparation_unavailable"
    assert calls == []


def test_fresh_saved_values_and_bound_path_survive_CWD_change(tmp_path, monkeypatch):
    path = _project(tmp_path / "project")
    provider = _provider(path)
    calls = _shared(monkeypatch)
    other = tmp_path / "other"
    other.mkdir()
    monkeypatch.chdir(other)
    first = provider.call_tool(TOOL, {})
    document = _document(path.parent)
    document["scan"]["focus"] = ["resources"]
    document["execution"]["max_workers"] = 9
    _write(path, document)
    second = provider.call_tool(TOOL, {})
    assert first["data"]["version3"]["focus"] == ["memory"]
    assert second["data"]["version3"]["focus"] == ["resources"]
    assert second["data"]["version3"]["max_workers"] == 9
    assert second["data"]["version3"]["machine_flags"]["max_workers_wired"] is False
    assert calls == [str(path)] * 2


@pytest.mark.parametrize("invalid", ["deleted", "malformed"])
def test_preparation_errors_are_honest_and_do_not_expose_document_values(
    tmp_path, monkeypatch, invalid
):
    path = _project(tmp_path / "project")
    provider = _provider(path)
    _shared(monkeypatch)
    if invalid == "deleted":
        path.unlink()
    else:
        path.write_text("config_version: private-key-marker\n", encoding="utf-8")
    result = provider.call_tool(TOOL, {})
    assert result == {
        "success": False,
        "code": "preparation_unavailable",
        "error": "Saved configuration preparation is unavailable.",
    }
    assert "private-key-marker" not in json.dumps(result)
    with pytest.raises(ValueError, match="preparation is unavailable"):
        provider.read_resource(RESOURCE)


@pytest.mark.parametrize("protocol", ["2024-11-05", "2025-06-18"])
def test_JSONRPC_handling_preserves_preparation_envelope_without_server(
    tmp_path, monkeypatch, protocol
):
    path = _project(tmp_path / "project")
    provider = _provider(path)
    _shared(monkeypatch)
    _forbid_execution(monkeypatch)
    provider.protocol_version = protocol
    response = handle_jsonrpc_request(
        provider,
        {
            "jsonrpc": "2.0",
            "id": 7,
            "method": "tools/call",
            "params": {"name": TOOL, "arguments": {}},
        },
    )
    assert response["id"] == 7 and response["result"]["isError"] is False
    result = response["result"]
    assert ("structuredContent" in result) == (protocol == "2025-06-18")
    body = json.loads(result["content"][0]["text"])
    assert body == {"success": True, "data": real_prepare(str(path), now=FIXED_NOW)}
    if protocol == "2025-06-18":
        assert result["structuredContent"] == body


@pytest.mark.parametrize("profile", ["default", "read_only", "candidate_blind"])
def test_exact_tools_and_resources_for_all_profiles(tmp_path, monkeypatch, profile):
    path = _project(tmp_path / "project")
    provider = _provider(path, profile)
    _shared(monkeypatch)
    expected_tools = {
        "zscope.code.search",
        "zscope.code.read",
        "zscope.semantic.context",
        "zscope.graph.query",
        "zscope.flow.trace",
        "zscope.findings.query",
    }
    if profile == "default":
        expected_tools.update(
            {
                TOOL,
                "zscope.knowledge.query",
                "zscope.entries.discover",
                "zscope.scan.run",
                "zscope.scan.status",
                "zscope.jobs.list",
                "zscope.jobs.events",
                "zscope.jobs.result",
                "zscope.jobs.cancel",
                "zscope.jobs.resume",
                "zscope.wiki.status",
                "zscope.wiki.query",
            }
        )
    elif profile == "read_only":
        expected_tools.add(TOOL)
    else:
        expected_tools.remove("zscope.findings.query")
    tools = provider.list_tools()
    assert {tool["name"] for tool in tools} == expected_tools
    assert (
        len(tools)
        == len(expected_tools)
        == {
            "default": 18,
            "read_only": 7,
            "candidate_blind": 5,
        }[profile]
    )
    if profile == "default":
        expected_resources = {
            "zscope://config",
            RESOURCE,
            "zscope://knowledge/stats",
            "zscope://knowledge/functions",
            "zscope://snapshots/list",
            "zscope://reports/latest",
            "zscope://rules/effective",
        }
    elif profile == "read_only":
        expected_resources = {"zscope://config", RESOURCE, "zscope://reports/latest"}
    else:
        expected_resources = set()
    resources = provider.list_resources()
    assert {resource["uri"] for resource in resources} == expected_resources
    assert len(resources) == len(expected_resources)
    if profile == "candidate_blind":
        assert provider.call_tool(TOOL, {})["status"] == "forbidden"
        with pytest.raises(PermissionError):
            provider.read_resource(RESOURCE)
    else:
        assert provider.call_tool(TOOL, {})["success"] is True
        assert json.loads(provider.read_resource(RESOURCE)["contents"][0]["text"]) == (
            real_prepare(str(path), now=FIXED_NOW)
        )


@pytest.mark.parametrize("version", [2, 3])
@pytest.mark.parametrize("profile", ["default", "read_only"])
def test_literal_home_path_matches_formal_loader_from_other_CWD(
    tmp_path, monkeypatch, version, profile
):
    home = tmp_path / "home"
    home.mkdir()
    path = _project(home / "project", version)
    other = tmp_path / "elsewhere"
    other.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.chdir(other)
    # Both transports pass this original Path spelling after the real loader.
    spelling = Path("~/project/zscope.yaml")
    loaded = ConfigLoader.load(str(spelling), read_only=True)
    assert loaded.project.project_root == path.parent
    assert str(spelling) == "~/project/zscope.yaml"
    assert not (other / spelling).exists()
    provider = _provider(spelling, profile)
    assert provider.config_path == path.resolve()
    if profile == "default":
        assert provider.jobs_adapter is not None
        assert provider.jobs_adapter.config_path == provider.config_path
        assert provider.jobs_adapter._service is None
    else:
        assert provider.jobs_adapter is None
    calls = _shared(monkeypatch)
    _forbid_execution(monkeypatch)
    before = _state(tmp_path)
    expected = real_prepare(str(spelling), now=FIXED_NOW)

    tool = provider.call_tool(TOOL, {})
    resource = provider.read_resource(RESOURCE)

    assert tool == {"success": True, "data": expected}
    assert json.loads(resource["contents"][0]["text"]) == expected
    assert calls == [str(path.resolve())] * 2
    assert _state(tmp_path) == before
