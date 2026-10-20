"""Task-local standard MCP stdio client for the installed Agent Bridge service.

No private RPC, worker CLI, configuration edit, preference edit, or credentials
lookup. Keeps one server instance alive so dispatched tasks remain monitorable.
"""

from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path
import re
import sys

from dispatch_safety import DispatchJournal, DispatchStopped, verify_entry

from mcp import ClientSession, StdioServerParameters, stdio_client

HERE = Path(__file__).resolve().parent
PROJECT = HERE.parents[4]
if "--route-check" in sys.argv:
    HERE = HERE / "route-check"
    HERE.mkdir(exist_ok=True)
elif "--verify-entry-fix" in sys.argv:
    HERE = HERE / "persistent-preflight"
    HERE.mkdir(exist_ok=True)
elif "--dsh-native" in sys.argv:
    HERE = HERE / "dsh-native"
    HERE.mkdir(exist_ok=True)
BRIDGE = Path(r"C:\Users\10273\.local\bin\agent-bridge.exe")
ALLOWED = {"list_agents", "dispatch_task", "wait_task", "check_task", "get_result", "get_transcript", "list_sessions", "cancel_task", "end_session"}


def public_agents(value: dict) -> dict:
    return {
        "ok": value.get("ok"),
        "coordinator": value.get("coordinator"),
        "agents": value.get("agents"),
        "environment_warnings": (value.get("env") or {}).get("warnings"),
    }


def unwrap(result) -> dict:
    value = getattr(result, "structured_content", None) or getattr(result, "structuredContent", None)
    if isinstance(value, dict):
        return value
    parts = [c.text for c in result.content if getattr(c, "type", "") == "text"]
    if len(parts) == 1:
        try:
            value = json.loads(parts[0])
            if isinstance(value, dict):
                return value
        except ValueError:
            pass
    return {"is_error": getattr(result, "is_error", None), "content": parts}


def emit(value: dict) -> None:
    print(json.dumps(value, ensure_ascii=False), flush=True)


async def main() -> None:
    # Preserve the real inherited worker/coordinator context without changing it.
    env = dict(os.environ)
    env["AGENT_BRIDGE_SKIP_SKILL"] = "1"
    if "--route-check" in sys.argv:
        env["AGENT_BRIDGE_HOME"] = str(PROJECT / ".coordination" / "20261014" / "bridge-route-check")
        # This diagnostic process cannot rediscover the known old shared npm
        # DSH. User/Machine PATH and other live Bridge instances are unchanged.
        old_npm = str(Path(r"C:\Users\10273\home\tool\npm-global")).casefold()
        env["PATH"] = ";".join(p for p in env.get("PATH", "").split(";") if p.rstrip("\\/").casefold() != old_npm)
        if "--zcode-bootstrap" in sys.argv:
            # Authorized process-local official bootstrap parameters. Keep the
            # existing provider credentials and baseURL in their native store.
            env["ZCODE_BIN"] = r"C:\Users\10273\AppData\Local\Programs\ZCode\resources\glm\zcode.cjs"
            env["ZCODE_NODE"] = r"C:\Program Files\nodejs\node.exe"
            env["ZCODE_PROVIDER"] = "97ad75c3-e785-4369-9730-55a5ee47c71c"
            env["ZCODE_MODEL"] = "glm-5.3"
            env.pop("ZCODE_BASE_URL", None)
    elif "--verify-entry-fix" in sys.argv:
        env["AGENT_BRIDGE_HOME"] = str(PROJECT / ".coordination" / "20261014" / "bridge-persistent-preflight")
    elif "--dsh-native" in sys.argv:
        env["AGENT_BRIDGE_HOME"] = str(PROJECT / ".coordination" / "20261014" / "bridge-dsh-native")
        old_npm = str(Path(r"C:\Users\10273\home\tool\npm-global")).casefold()
        env["PATH"] = ";".join(p for p in env.get("PATH", "").split(";") if p.rstrip("\\/").casefold() != old_npm)
    params = StdioServerParameters(command=str(BRIDGE), cwd=str(PROJECT), env=env)
    journal = DispatchJournal(HERE / "dispatch-journal.sqlite")
    with (HERE / "bridge-service-stderr.log").open("a", encoding="utf-8") as errors:
        async with stdio_client(params, errlog=errors) as streams:
            async with ClientSession(*streams) as client:
                await client.initialize()
                catalog = await client.list_tools()
                tools = {t.name: t for t in catalog.tools}
                (HERE / "bridge-tools.json").write_text(
                    json.dumps([t.model_dump(mode="json") for t in catalog.tools], ensure_ascii=False, indent=2) + "\n",
                    encoding="utf-8",
                )
                agents = unwrap(await client.call_tool("list_agents", {}))
                emit({"event": "connected", "tools": sorted(tools), "list_agents": public_agents(agents)})
                coordinator = agents.get("coordinator") or {}
                can_dispatch = bool(coordinator.get("dispatch_enabled"))
                if "--verify-entry-fix" in sys.argv or "--read-only-reconnect" in sys.argv:
                    can_dispatch = False
                connection_state = "ready"
                queue = HERE / "bridge-queue"
                queue.mkdir(exist_ok=True)
                seen = set()
                while True:
                    pending = [p for p in sorted(queue.glob("*.request.json")) if p.name not in seen and not p.with_suffix(".consumed").exists()]
                    if not pending:
                        await asyncio.sleep(0.25)
                        continue
                    path = pending[0]
                    request = json.loads(path.read_text(encoding="utf-8"))
                    if not re.fullmatch(r"[a-zA-Z0-9_-]+", str(request.get("id", ""))):
                        raise ValueError("request id must be a safe task-local filename")
                    seen.add(path.name)
                    # Persist before the public call. A crash leaves an uncertain
                    # outcome to inspect; it must never replay an old dispatch.
                    path.with_suffix(".consumed").write_text("consumed; inspect response before any retry\n", encoding="utf-8")
                    if (HERE / f"bridge-response-{request['id']}.json").exists():
                        continue
                    name = request.get("tool")
                    if ("--verify-entry-fix" in sys.argv or "--read-only-reconnect" in sys.argv) and name not in {"list_agents", "list_sessions", "check_task", "get_result", "get_transcript"}:
                        emit({"request": request.get("id"), "ok": False, "error": "readonly_persistent_preflight"})
                        continue
                    if name not in ALLOWED or name not in tools:
                        emit({"request": request.get("id"), "ok": False, "error": "tool_not_allowed"})
                        continue
                    if name == "dispatch_task" and not can_dispatch:
                        emit({"request": request.get("id"), "ok": False, "error": "dispatch_disabled_by_real_coordinator_context"})
                        continue
                    arguments = request.get("arguments") or {}
                    if arguments.get("task_id") == "task_0947f2854f":
                        emit({"request": request.get("id"), "ok": False, "error": "user_reserved_task_do_not_touch"})
                        continue
                    if name == "dispatch_task" and Path(arguments.get("cwd", "")).resolve() != PROJECT:
                        emit({"request": request.get("id"), "ok": False, "error": "cwd_must_be_current_project"})
                        continue
                    if name == "dispatch_task":
                        if arguments.get("agent") in {"dsh", "zcode"}:
                            bindings = json.loads((Path(__file__).resolve().parent / "ENTRY_BINDINGS.json").read_text(encoding="utf-8"))
                            if not bindings[arguments["agent"]].get("dispatch_ready"):
                                emit({"request": request.get("id"), "ok": False, "error": "pinned_route_or_prior_prompt_outcome_not_verified_no_dispatch"})
                                continue
                            if arguments["agent"] == "dsh":
                                wrapper = Path(r"C:\Users\10273\AppData\Local\Programs\DeepSeek Harness\resources\runtime\cli\bin\dsh.cmd")
                                verify_entry(wrapper, "c6c38be7f9f66a7bfb96d5ac9490618f9713df5ffb552cb7e66b831affb20ab9")
                                verify_entry(Path(r"C:\Users\10273\.dsh\profiles\acp\cordis.patch.yml"), "23259e019f6a7293ebb429654d7cc223414d3651d5be542968a81fc6265fc38b")
                                if "--dsh-native" not in sys.argv or arguments.get("model") != "deepseek/deepseek-v4.1-flash":
                                    emit({"request": request.get("id"), "ok": False, "error": "dsh_exact_pinned_native_route_required_no_dispatch"})
                                    continue
                            # ZCode already imports this exact current registry;
                            # Bridge itself strictly sets the advertised model
                            # before sending the prompt, with no default fallback.
                        if arguments.get("agent") == "zcode":
                            provider = "97ad75c3-e785-4369-9730-55a5ee47c71c"
                            expected_model = provider + "/glm-5.3"
                            wrapper = Path(r"C:\Users\10273\.agent-bridge\adapters\zcode-acp-0.67.0\node_modules\.bin\zcode-acp-server.cmd")
                            adapter = wrapper.parent.parent / "zcode-acp-server"
                            verify_entry(wrapper, "d494fa23bcb31a4b208a553eb2f13a5765ac3538c2e79759ea9541b44fe90ef2")
                            verify_entry(adapter / "dist/config/provider-registry.js", "43261f0a286b47d8c4130ad21c0cd13580745ae3aa0a9997569a330946b89011")
                            package = json.loads((adapter / "package.json").read_text(encoding="utf-8"))
                            config = json.loads(Path(r"C:\Users\10273\.zcode\v2\config.json").read_text(encoding="utf-8"))
                            route = config.get("provider", {}).get(provider, {})
                            if ("--route-check" not in sys.argv or "--zcode-bootstrap" not in sys.argv or package.get("version") != "0.67.0" or arguments.get("model") != expected_model or route.get("options", {}).get("baseURL") != "https://st8tp3ajl0df3n8b8l8qu.apigateway-cn-beijing.volceapi.com/v1" or "glm-5.3" not in route.get("models", {})):
                                emit({"request": request.get("id"), "ok": False, "error": "zcode_pinned_entry_or_current_route_mismatch_no_dispatch"})
                                continue
                        if not request.get("branch") or not arguments.get("request_id"):
                            emit({"request": request.get("id"), "ok": False, "error": "durable_request_id_and_branch_required"})
                            continue
                        try:
                            claim = journal.claim(arguments["request_id"], request["branch"], arguments, connection_state=connection_state)
                        except DispatchStopped as error:
                            emit({"request": request.get("id"), "ok": False, "error": str(error)})
                            continue
                        if not claim["send"]:
                            if claim["state"] == "queued" and journal.begin_send(arguments["request_id"]):
                                claim["send"] = True
                            else:
                                emit({"request": request.get("id"), "duplicate": claim})
                                continue
                    try:
                        result = unwrap(await client.call_tool(name, arguments))
                    except Exception:
                        if name == "dispatch_task":
                            journal.uncertain(arguments["request_id"])
                        connection_state = "disconnected"
                        emit({"request": request.get("id"), "ok": False, "error": "public_tool_transport_outcome_uncertain; inspect_before_retry"})
                        continue
                    if name == "dispatch_task" and result.get("ok") and result.get("task_id"):
                        journal.accepted(arguments["request_id"], result["task_id"])
                    elif name == "dispatch_task":
                        journal.uncertain(arguments["request_id"])
                    if name in {"check_task", "wait_task", "get_result"} and result.get("status") in {"completed", "failed", "cancelled"} and not result.get("from_state") and not (result.get("failure") or {}).get("prompt_may_have_been_sent"):
                        try:
                            journal.terminal(result["task_id"], result["status"])
                        except DispatchStopped:
                            pass
                    if name == "list_agents":
                        result = public_agents(result)
                    (HERE / f"bridge-response-{request['id']}.json").write_text(
                        json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
                    )
                    emit({"request": request.get("id"), "result": result})


if __name__ == "__main__":
    sys.stdout.reconfigure(encoding="utf-8")
    asyncio.run(main())
