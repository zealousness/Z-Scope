"""Apply the two explicitly approved, non-secret user-level entry corrections."""

from __future__ import annotations

import copy
import datetime as dt
import hashlib
import json
from pathlib import Path
import re
import shutil
import sys
import tomllib
import winreg

HERE = Path(__file__).resolve().parent
CONFIG = Path(r"C:\Users\10273\.agent-bridge\agents.toml")
BIN = r"C:\Users\10273\AppData\Local\Programs\DeepSeek Harness\resources\runtime\cli\bin"
OLD = r"C:\Users\10273\home\tool\npm-global"
DSH = BIN + r"\dsh.cmd"
ZCODE = r"C:\Users\10273\.agent-bridge\adapters\zcode-acp-0.67.0\node_modules\.bin\zcode-acp-server.cmd"
COMMANDS = {
    "dsh": [r"C:\Windows\System32\cmd.exe", "/d", "/c", "call", DSH, "--profile", "acp"],
    "zcode": [ZCODE],
}


def edited(text: str) -> str:
    newline = "\r\n" if "\r\n" in text else "\n"
    lines = text.splitlines(keepends=True)
    for name, command in COMMANDS.items():
        header = f"[agents.{name}]"
        start = next((i for i, line in enumerate(lines) if line.strip() == header), None)
        if start is None:
            if lines and not lines[-1].endswith(("\n", "\r")):
                lines[-1] += newline
            lines.extend([newline, header + newline])
            start = len(lines) - 1
        end = next((i for i in range(start + 1, len(lines)) if re.match(r"\s*\[", lines[i])), len(lines))
        # Repeating the same absolute command replaces legacy fallback arrays;
        # an empty list is ignored by Bridge 0.1.0's overlay merger.
        fields = {"command": command, "fallback_commands": [command]}
        for key, value in fields.items():
            index = next((i for i in range(start + 1, end) if re.match(rf"\s*{key}\s*=", lines[i])), None)
            replacement = key + " = " + json.dumps(value, ensure_ascii=False) + newline
            if index is None:
                lines.insert(end, replacement)
                end += 1
            else:
                # Refuse unsupported multiline edits rather than regenerate
                # unrelated config or silently drop comments/settings.
                try:
                    tomllib.loads(lines[index])
                except tomllib.TOMLDecodeError:
                    raise RuntimeError(f"multiline {name}.{key} requires a precise separate edit") from None
                lines[index] = replacement
    result = "".join(lines)
    expected = copy.deepcopy(tomllib.loads(text))
    for name, command in COMMANDS.items():
        section = expected.setdefault("agents", {}).setdefault(name, {})
        section["command"] = command
        section["fallback_commands"] = [command]
    if tomllib.loads(result) != expected:
        raise RuntimeError("unrelated configuration changed; refuse update")
    return result


def main():
    if sys.argv[1:] != ["--apply"]:
        raise SystemExit("explicit --apply required; user approval covers only PATH/User and two agent entry sections")
    if CONFIG.resolve() != CONFIG or not CONFIG.is_file():
        raise RuntimeError("configuration target missing or redirected; inspect before update")
    for path, wanted in [
        (Path(DSH), "c6c38be7f9f66a7bfb96d5ac9490618f9713df5ffb552cb7e66b831affb20ab9"),
        (Path(ZCODE), "d494fa23bcb31a4b208a553eb2f13a5765ac3538c2e79759ea9541b44fe90ef2"),
    ]:
        if not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest() != wanted:
            raise RuntimeError("official pinned entry changed; inspect installation, no fallback")
    raw = CONFIG.read_bytes()
    has_bom = raw.startswith(b"\xef\xbb\xbf")
    text = raw.decode("utf-8-sig")
    output = edited(text).encode("utf-8")
    if has_bom:
        output = b"\xef\xbb\xbf" + output
    stamp = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    private_backup = CONFIG.with_name(CONFIG.name + ".backup-" + stamp)
    if private_backup.exists():
        raise RuntimeError("backup already exists; refuse overwrite")
    path_backup = HERE / ("user-path-backup-" + stamp + ".json")
    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, "Environment", 0, winreg.KEY_READ | winreg.KEY_SET_VALUE) as user:
        original, kind = winreg.QueryValueEx(user, "Path")
        parts = original.split(";")
        wanted = BIN.rstrip("\\").casefold()
        preserved = [p for p in parts if p.rstrip("\\/").casefold() != wanted]
        position = next((i for i, p in enumerate(preserved) if p.rstrip("\\/").casefold() == OLD.casefold()), 0)
        preserved.insert(position, BIN)
        new_path = ";".join(preserved)
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\Session Manager\Environment") as machine:
            machine_before = winreg.QueryValueEx(machine, "Path")
        shutil.copy2(CONFIG, private_backup)
        path_backup.write_text(json.dumps({"scope": "User", "value_name": "Path", "original_value": original, "registry_type": kind}, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        try:
            winreg.SetValueEx(user, "Path", 0, kind, new_path)
            # Writing the named existing file preserves its ACL; the byte-exact
            # private backup provides recovery without altering security settings.
            with CONFIG.open("wb") as handle:
                handle.write(output)
            if winreg.QueryValueEx(user, "Path") != (new_path, kind) or CONFIG.read_bytes() != output:
                raise RuntimeError("write verification failed")
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\Session Manager\Environment") as machine:
                if winreg.QueryValueEx(machine, "Path") != machine_before:
                    raise RuntimeError("machine PATH changed concurrently; inspect")
        except BaseException:
            winreg.SetValueEx(user, "Path", 0, kind, original)
            with CONFIG.open("wb") as handle:
                handle.write(raw)
            raise
    receipt = {
        "applied_at": stamp, "scope": "User only", "path_inserted_before": OLD, "new_entry": BIN,
        "shared_directory_preserved": True, "system_path_unchanged": True,
        "config": str(CONFIG), "private_config_backup": str(private_backup), "path_backup": str(path_backup),
        "changed_fields": [f"agents.{name}.{key}" for name in COMMANDS for key in ("command", "fallback_commands")],
        "commands": COMMANDS, "credentials_or_permissions_changed": False, "running_bridge_restarted": False,
        "rollback": "restore original User Path with its registry type from path_backup and original agents.toml bytes from private_config_backup; restart only idle affected clients",
    }
    (HERE / "entry-fix-receipt.json").write_text(json.dumps(receipt, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(receipt, ensure_ascii=False))


if __name__ == "__main__":
    main()
