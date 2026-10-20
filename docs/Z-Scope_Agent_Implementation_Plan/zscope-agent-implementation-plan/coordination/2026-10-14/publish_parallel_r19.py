"""Reconcile the real failed gates and disjoint R19 dispatches into the DAG."""
from pathlib import Path
import datetime as dt
import json

HERE = Path(__file__).resolve().parent
at = dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat()
path = HERE / "tasks.json"
ledger = json.loads(path.read_text(encoding="utf-8"))
remaining = {r["id"] for r in ledger["tasks"]}
done, layers = set(), []
while remaining:
    ready = [r["id"] for r in ledger["tasks"] if r["id"] in remaining and set(r.get("depends_on", [])) <= done]
    assert ready, "cycle or unknown dependency"
    layers.append(ready)
    done.update(ready)
    remaining.difference_update(ready)
ledger["topological_layers"] = layers
ledger["updated_at"] = at
path.write_text(json.dumps(ledger, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
note = f"## {at} · R19 两项实证追加门禁与隔离并行\n\n当前Root2079项联合在19:32:36结束：2078过/1失败/0error/0skip；唯一deadline用例SQL序号3→4墙钟回退0.426562s，结束事件仍早于持久化绝对截止。源码/native/launcher冻结，收据 artifacts/coordinator-r18-queue-receipt-repaired-20261015/review.json。队列SQL事件定位迁移后的native/owner/HTTP/browser用例已通过。当前同字节完整132文件/六命令重跑 artifacts/coordinator-r18-same-bytes-clock-observed-20261015，附只读时钟观测，不改时钟/测试/超时；尚未通过。\n\n上下文task_bf7efdfce3独立1074/0及四质量命令0于19:34:03完成，但真实native/实际provider提交快照两额外探针2/2失败（19:34:36）：父映射修改能把mixed未知身份变为int契约选择。1074仅切片，整体未验收/未集成。新返修task_d4f97ce947于19:39:20在同sess_a0adb99b15/六文件开始。证据 artifacts/coordinator-validation-snapshot-r19-probes-20261015/review.json。\n\n当前Root独立native增量重放28项为27过/1失败（19:33:43），semantic complete/零未解释差异通过，旧negative_include热轮断言要求重编2但实际重编0/复用4。全部热轮都是0/4，负include变异轮4/0；projection_complete=false另行披露，不将实例提取完整当投影完整。证据 artifacts/coordinator-current-native-replay-r19-20261015/{{review.json,native-metrics.json,actual-native-report.json}}。新ZCode诊断task_7118aeca55于19:39:20在fresh native-hot-cache-r19/sess_3b6b9a19b2开始，1030输入冻结；两个源码+一个新测试的初始所有权。先区分旧基线与真实失效缺口，原测试只读，不强制无必要重编凑数。\n\n共享token/HTTP预算返修task_9565621a54仍执行，19:17:03开始，七自有路径；未独验/未集成。三个GLM目录/文件无交叠，两Linux测试槽保持。Kimi目录冻结无新派单，Astra已验收导入的UI仍等当前联合；正常Bridge owner80748不变，旧S06未操作。真实项目/模型、全包、条件扩展、正式benchmark/portable仍开放；各集合不相加。DAG {len(done)}节点/{len(layers)}层，无未知依赖/环。\n\n---\n\n"
for filename in ("PROGRESS.md", "DAG.md"):
    path = HERE / filename
    path.write_text(note + path.read_text(encoding="utf-8"), encoding="utf-8", newline="\n")
print(json.dumps({"at": at, "nodes": len(done), "layers": len(layers), "root_joint_passed": False}), flush=True)
