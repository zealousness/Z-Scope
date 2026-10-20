"""Verify approved settings with a fresh environment and a read-only MCP clone."""

from __future__ import annotations

import ctypes
import json
import os
from pathlib import Path
import subprocess
import tomllib
import winreg

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
STATE = ROOT / ".coordination/20261014/bridge-persistent-preflight"
SCRIPT = HERE / "bridge_mcp_client.py"
PYTHON = Path(r"C:\Users\10273\AppData\Roaming\uv\tools\agent-bridge\Scripts\python.exe")


def main():
    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, "Environment") as key:
        user, _ = winreg.QueryValueEx(key, "Path")
    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\Session Manager\Environment") as key:
        machine, _ = winreg.QueryValueEx(key, "Path")
    fresh = dict(os.environ)
    fresh["PATH"] = os.path.expandvars(machine + ";" + user)
    config = tomllib.loads(Path(r"C:\Users\10273\.agent-bridge\agents.toml").read_text(encoding="utf-8-sig"))
    STATE.mkdir(parents=True, exist_ok=True)
    # Copy only the explicitly changed non-secret entry fields, never env,
    # credentials, proxy URLs or private preferences into project artifacts.
    lines = ['[coordinator]', 'mode = "manual"', '', '[quota]', 'enabled = false', '']
    command_evidence = {}
    for agent in ("dsh", "zcode"):
        selected = config["agents"][agent]
        lines.extend([f"[agents.{agent}]", "command = " + json.dumps(selected["command"]), "fallback_commands = " + json.dumps(selected["fallback_commands"]), ""])
        command_evidence[agent] = selected["command"]
    (STATE / "agents.toml").write_text("\n".join(lines), encoding="utf-8")
    # Notify Explorer's future launch environment; no process is restarted.
    result = ctypes.c_size_t()
    ctypes.windll.user32.SendMessageTimeoutW(0xFFFF, 0x001A, 0, "Environment", 0x0002, 2000, ctypes.byref(result))
    shell = Path(r"C:\Users\10273\.cache\codex-runtimes\codex-primary-runtime\dependencies\native\powershell\pwsh.exe")
    if not shell.is_file():
        shell = Path(os.environ["SystemRoot"]) / "System32/WindowsPowerShell/v1.0/powershell.exe"
    lookup = subprocess.check_output([str(shell), "-NoProfile", "-Command", "[Console]::OutputEncoding=[System.Text.UTF8Encoding]::new($false); (Get-Command dsh).Source"], env=fresh).decode("utf-8").strip()
    expected = r"C:\Users\10273\AppData\Local\Programs\DeepSeek Harness\resources\runtime\cli\bin\dsh.cmd"
    if lookup.casefold() != expected.casefold():
        raise RuntimeError("fresh process does not resolve the pinned DSH entry")
    process = subprocess.Popen([str(PYTHON), str(SCRIPT), "--verify-entry-fix"], cwd=ROOT, env=fresh, stdin=subprocess.DEVNULL, stdout=(HERE / "persistent-preflight.stdout.jsonl").open("w", encoding="utf-8"), stderr=(HERE / "persistent-preflight.stderr.log").open("w", encoding="utf-8"), creationflags=subprocess.CREATE_NO_WINDOW | subprocess.DETACHED_PROCESS)
    evidence = {"fresh_process_dsh_resolution": lookup, "non_secret_commands_copied_from_persisted_config": command_evidence, "readonly_preflight_pid": process.pid, "no_development_task_created": True, "current_kimi_bridge_restarted": False}
    (HERE / "entry-fix-verification.json").write_text(json.dumps(evidence, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(evidence, ensure_ascii=False))


if __name__ == "__main__":
    main()
