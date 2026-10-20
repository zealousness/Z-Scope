"""Resume exact failed sessions after verified app-update transport loss."""
from pathlib import Path
import datetime as dt
import hashlib
import json
import uuid

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
PUBLIC = HERE / "current-public/c725deddeaf7"
proof = {"at": dt.datetime.now(dt.timezone.utc).isoformat(), "public_snapshot": str(PUBLIC.relative_to(HERE)), "branches": []}
for number, label, isolate, task, session in (
    (43, "s01-cdb-coverage", "s01-coverage", "task_6dceb47315", "sess_c3c6c01381"),
    (44, "s08-fair-queue", "s08-scheduling", "task_d3ceded741", "sess_a3dc643fae"),
):
    state = json.loads((PUBLIC / f"{label}-state.json").read_text(encoding="utf-8"))
    assert state["task_id"] == task and state["status"] == "failed" and state["error"] == "bridge_restarted"
    assert state.get("failure") is None
    permission = json.loads((PUBLIC / f"{label}-permission-summary.json").read_text(encoding="utf-8"))
    assert permission["has_more"] is False and permission["events_read"] == 0
    baseline = json.loads((HERE / f"baseline-{isolate}.json").read_text(encoding="utf-8"))
    workspace = ROOT / ".coordination/20261014/workspaces" / isolate
    for item in baseline["files"]:
        assert hashlib.sha256((workspace / item["path"]).read_bytes()).hexdigest() == item["sha256"], item["path"]
    assert all(not (workspace / name).exists() for name in baseline["owned_new_files"])
    original = json.loads((HERE / "route-check/bridge-queue" / f"{number-2:03d}-{label}.request.json").read_text(encoding="utf-8"))
    arguments = dict(original["arguments"], session_id=session, request_id=str(uuid.uuid4()))
    arguments["message"] = (
        "应用更新重启后的普通传输恢复，只续接本原会话原后端切片。原任务 " + task +
        " 已公开 failed/error=bridge_restarted；原owner/worker PID均已确认不存在。公开工具/助手/permission全游标已读完，无保存的权限拒绝，965输入SHA均未变，两个owned新文件尚未存在。不是内容/权限拒绝重试，不改变路由/权限，不新建重叠分支，不覆盖产物。请保留原输入立即接续实现，跳过重新找目录/大盘点。"
        "\n合同绝对路径：" + str(HERE / "NEXT_BACKEND_CONTRACT.md") +
        "\n可写隔离目录：" + str(workspace) + "\n" + original["arguments"]["message"]
    )
    request = dict(original, id=label + "-post-update", arguments=arguments)
    queue = HERE / "route-check/bridge-queue" / f"{number:03d}-{request['id']}.request.json"
    with queue.open("x", encoding="utf-8", newline="\n") as output:
        output.write(json.dumps(request, ensure_ascii=False, indent=2) + "\n")
    proof["branches"].append({"label": label, "prior_task": task, "prior_status": "failed", "reason": "bridge_restarted", "session_id": session, "input_files_unchanged": len(baseline["files"]), "owned_new_files_absent": True, "permission_complete_no_recorded_denial": True, "request_id": arguments["request_id"]})
with (HERE / "post-update-recovery-checkpoint.json").open("x", encoding="utf-8", newline="\n") as output:
    output.write(json.dumps(proof, ensure_ascii=False, indent=2) + "\n")
print(json.dumps(proof, ensure_ascii=False))
