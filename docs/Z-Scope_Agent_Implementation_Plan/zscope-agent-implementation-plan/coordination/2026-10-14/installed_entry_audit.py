"""Inspect package metadata inside installed ASAR files without launching workers."""
from __future__ import annotations
import json
from pathlib import Path
import struct

HERE = Path(__file__).resolve().parent
ROOT = Path(r"C:\Users\10273\AppData\Local\Programs")


def audit(name: str, package: str | None = None) -> dict:
    path = ROOT / name / "resources/app.asar"
    with path.open("rb") as handle:
        first = handle.read(16)
        _, header_size, _, json_size = struct.unpack("<4I", first)
        header = json.loads(handle.read(json_size))
        found = []
        def walk(files, prefix=""):
            for key, value in files.items():
                current = prefix + key
                if "files" in value:
                    walk(value["files"], current + "/")
                elif "acp" in key.lower() and len(found) < 20:
                    found.append(current)
        walk(header["files"])
        result = {"installation": name, "asar": str(path), "acp_named_files": found}
        if package:
            node = header
            for part in package.split("/"):
                node = node["files"][part]
            handle.seek(8 + header_size + int(node["offset"]))
            content = json.loads(handle.read(node["size"]))
            result["package"] = {key: content.get(key) for key in ("name", "version", "bin")}
        return result


if __name__ == "__main__":
    results = [
        audit("DeepSeek Harness", "dsh/node_modules/@deepseek-ai/dsh-desktop-host/package.json"),
        audit("ZCode", "package.json"),
    ]
    (HERE / "installed-entry-audit.json").write_text(json.dumps(results, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(results, ensure_ascii=False))
