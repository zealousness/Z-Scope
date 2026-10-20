"""Launch a separate public MCP client pinned to the approved bundled DSH."""
from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]


def main() -> None:
    state = ROOT / ".coordination/20261014/bridge-dsh-native"
    state.mkdir(parents=True, exist_ok=True)
    command = [
        r"C:\Windows\System32\cmd.exe", "/d", "/c", "call",
        r"C:\Users\10273\AppData\Local\Programs\DeepSeek Harness\resources\runtime\cli\bin\dsh.cmd",
        "--profile", "acp",
    ]
    path = state / "agents.toml"
    if path.exists():
        raise RuntimeError("DSH development bridge already initialized; inspect instead of relaunch")
    path.write_text(
        '[coordinator]\nmode = "manual"\n\n[quota]\nenabled = false\n\n[agents.dsh]\n'
        + "command = " + json.dumps(command) + "\nfallback_commands = " + json.dumps([command]) + "\n",
        encoding="utf-8",
    )
    process = subprocess.Popen(
        [r"C:\Users\10273\AppData\Roaming\uv\tools\agent-bridge\Scripts\python.exe",
         str(HERE / "bridge_mcp_client.py"), "--dsh-native"],
        cwd=ROOT, env=dict(os.environ), stdin=subprocess.DEVNULL,
        stdout=(HERE / "dsh-native.stdout.jsonl").open("w", encoding="utf-8"),
        stderr=(HERE / "dsh-native.stderr.log").open("w", encoding="utf-8"),
        creationflags=subprocess.CREATE_NO_WINDOW | subprocess.DETACHED_PROCESS,
    )
    evidence = {"pid": process.pid, "command": command,
                "mode": "bundled native ACP route", "kimi_bridge_restarted": False,
                "credentials_copied": False, "persistent_external_config_changed": False}
    (HERE / "dsh-bridge-launch.json").write_text(json.dumps(evidence, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(evidence))


if __name__ == "__main__":
    main()
