"""Stage reviewable consumer notes; do not change Root during acceptance."""
from pathlib import Path
import hashlib
import json

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
OUT = ROOT / "artifacts/staged-job-cli-notes-r20-20261015"
OUT.mkdir(exist_ok=False)
replacements = {
    "AGENTS.md": ("resume 不重新套用配置窗口。MCP", "resume 不重新套用配置窗口。owner 启动的 CLI 仅消费当前 job/run/owner/input 与运行目录绑定核实后的持久窗口；合法空窗口不回退配置，部分或失效绑定拒绝启动。MCP"),
    "README.md": ("同 request_id 重放保留原窗口，resume 不重新套用配置窗口。这不表示完整 U01/S08 已完成。", "同 request_id 重放保留原窗口，resume 不重新套用配置窗口。作业启动的 CLI 采用该 attempt 保存的窗口；恢复后保存的空窗口表示本轮没有停止窗口。身份或输入已失效时拒绝启动。独立 CLI 仍使用配置窗口。这不表示完整 U01/S08 已完成。"),
    "docs/modules/configuration-state.md": ("resume 不重新套用配置窗口。prepare 仍仅", "resume 不重新套用配置窗口。owner 启动的 CLI 核对当前 job/run/owner/input 与运行目录绑定后，以持久 SQL 窗口为唯一预算来源，包括合法空窗口；部分环境或失效绑定不回退配置。独立 CLI 继续使用配置窗口。prepare 仍仅"),
    "docs/modules/execution-orchestration.md": ("resume 仍开新 attempt 且不重新套用配置窗口。逐实例", "resume 仍开新 attempt 且不重新套用配置窗口。owner 启动的 CLI 核对当前作业、run、owner、输入版本和运行目录后，从持久窗口收紧同一共享令牌；SQL 空窗口不回退配置，部分环境或失效绑定拒绝启动。独立 CLI 保留配置窗口。逐实例"),
}
rows = []
for name, (old, new) in replacements.items():
    original = (ROOT / name).read_bytes()
    source = original.decode("utf-8")
    assert source.count(old) == 1, name
    updated = source.replace(old, new).encode("utf-8")
    assert not updated.startswith(b"\xef\xbb\xbf") and b"\r\n" not in updated and updated.endswith(b"\n")
    target = OUT / name
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(updated)
    rows.append({"path": name, "before": hashlib.sha256(original).hexdigest(), "after": hashlib.sha256(updated).hexdigest()})
(OUT / "staging.json").write_text(json.dumps({"scope": "Draft notes, gated on final code/independent acceptance; no Root change", "files": rows}, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
print(json.dumps({"files": len(rows), "root_changed": False}), flush=True)
