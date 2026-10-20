"""Fix reproduced identity defects only after exact original-session terminals."""
from pathlib import Path
import json
import uuid

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
PUBLIC = HERE / "current-public/38d10c7690cd"
for number, label, branch, task, session, isolate in (
    (48, "s01-cdb-coverage", "S01-CDB-COVERAGE", "task_352c00bca8", "sess_c3c6c01381", "s01-coverage"),
    (49, "s08-fair-queue", "S08-QUEUE-CORE", "task_fd839f09e6", "sess_a3dc643fae", "s08-scheduling"),
):
    state = json.loads((PUBLIC / f"{label}-state.json").read_text(encoding="utf-8"))
    assert state["task_id"] == task and state["status"] == "completed"
    assert state["observed_model"] == "97ad75c3-e785-4369-9730-55a5ee47c71c/glm-5.3"
    permission = json.loads((PUBLIC / f"{label}-permission-summary.json").read_text(encoding="utf-8"))
    assert permission["has_more"] is False and permission["events_read"] == 0
    message = (
        "原切片已完成/observed精确hw/glm-5.3，尚未导入root；协调者发现稳定源码下的实际身份边界缺陷，请在同一原session与原隔离目录做最小验收返修，保留此前字节和所有原约束。不要重做盘点、扩大文件所有权或弱化断言。\n"
        "只读复现与具体正反例要求：" + str(HERE / "NEXT_PRODUCER_REVIEW.md") +
        "\n只处理本文与你相应的S01-CDB-COVERAGE或S08-QUEUE-CORE节，另一节文件由另一作者独占，不代做。"
        "\n隔离目录：" + str(ROOT / ".coordination/20261014/workspaces" / isolate) +
        "\n仅两个自有新模块/测试与自己DELIVERY/artifacts允许写，根checkout、共同scan_session/owner/store/Web/config/静态/UI/锁/文档以及其他隔离目录不动。"
        "\nS01必须缺失/外来BuildContext不补命令覆盖，并保留native正确relative source/双宏，复用既有BuildContext身份；S08 complete/defer必须当前claim token，省略token不得绕过已重新分派的lease，不给尚不存在的兼容调用留洞。"
        "\nWSL /home/zeal/venv313/bin/python，绝对隔离PYTHONPATH，native只用已有d39cbe72...263399，不重建、不安装、不真实LLM/formal。最终一个相关稳定集合JUnit/SHA/compileall/mypy/Black，不累加前17或队列测试。旧原生任务/被拦caller分支不查询/恢复/实施，发现新真实拒绝准确停报，不换模型或session绕过。不reset/clean/commit/push/改项目外配置/凭据。默认实验不变；模块依然不冒称共享scanner接线或整个S01/JOB04/JOB06。"
    )
    request = {"id": label + "-identity-fix", "branch": branch, "tool": "dispatch_task", "arguments": {
        "agent": "zcode", "model": "97ad75c3-e785-4369-9730-55a5ee47c71c/glm-5.3", "cwd": str(ROOT),
        "session_id": session, "title": label + "原会话身份返修", "user_requested": True,
        "request_id": str(uuid.uuid4()), "message": message}}
    with (HERE / "route-check/bridge-queue" / f"{number:03d}-{request['id']}.request.json").open("x", encoding="utf-8", newline="\n") as output:
        output.write(json.dumps(request, ensure_ascii=False, indent=2) + "\n")
    print(json.dumps({"branch": branch, "prior_task": task, "prior_completed": True, "model_observed_exact": True, "request_id": request["arguments"]["request_id"]}))
