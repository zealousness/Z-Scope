"""Stage truthful module/handover notes for the bounded R19 batch; root untouched."""
from pathlib import Path
import hashlib
import json

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
out = ROOT / "artifacts/staged-r19-module-notes-20261015"
out.mkdir(exist_ok=False)
changes = {}
def replace(path, old, new):
    current = changes.get(path, (ROOT/path).read_text(encoding="utf-8"))
    assert current.count(old) == 1, path+": "+old
    changes[path] = current.replace(old,new)
replace("AGENTS.md", "focus/reproduction/max_workers/platform 与配置 stop_at 尚未消费；MCP 与其他消费端仍有剩余，不把此切片视为完整 U01。", "focus/reproduction/max_workers/platform 尚未消费；配置 execution.stop_at 已由 CLI 和新建持久作业消费，显式作业窗口优先，同 request_id 重放不重解析窗口；resume 不重新套用配置窗口。MCP 与其他消费端仍有剩余，不把此切片视为完整 U01/S08。")
replace("README.md", "当前执行链一次只支持一个 target。focus、reproduction、platform、max_workers 和配置时窗\n仍是未消费的声明，不因保存成功而启用这些能力。", "当前执行链一次只支持一个 target。focus、reproduction、platform 和 max_workers\n仍是未消费的声明。配置 execution.stop_at 已由 CLI 和新建持久作业消费；显式作业窗口优先，\n同 request_id 重放保留原窗口，resume 不重新套用配置窗口。这不表示完整 U01/S08 已完成。")
replace("README.md", "配置时窗也尚未接入 S08 调度；MCP 与其他消费端迁移仍有剩余，不能把已解析意图当作已执行能力。", "配置时窗已由 CLI 和新建持久作业消费，resume 不重新套用配置窗口；MCP 与其他消费端迁移仍有剩余，不能把其他已解析意图当作已执行能力。")
replace("README.md", "配置中的 execution.stop_at 暂只解析展示，任务的显式 stop_at 才是本次作业窗口；focus/reproduction/max_workers/platform 尚不代表已执行。", "配置中的 execution.stop_at 作用于 CLI 和新建持久作业，任务的显式 stop_at 优先；同 request_id 重放保留原窗口，resume 不重新套用配置窗口。focus/reproduction/max_workers/platform 尚不代表已执行。")
replace("docs/modules/configuration-state.md", "该边界尚无 S08 消费方。", "CLI 和新建持久作业已消费该边界；resume 不重新套用配置窗口。")
replace("docs/modules/configuration-state.md", "focus/reproduction/max_workers/platform 与配置 execution.stop_at 暂未接实际消费者；配置时窗与作业显式 stop_at 分开，不能因为字段合法就显示调度已启用。", "focus/reproduction/max_workers/platform 暂未接实际消费者。配置 execution.stop_at 已接 CLI 共享令牌预算与新建持久作业窗口；显式作业 stop_at 优先，同 request_id 重放保留原窗口，resume 不重新套用配置窗口。prepare 仍仅核对配置、路径和工具存在，不表示扫描已完成或模型已连接。")
replace("docs/modules/analysis-pipeline.md", "上述边界不代表 Validator 所有内部 Registry 调用、EvidenceCompletionQueue 内部线程、全建模和所有消费端已迁移；未接入部分继续作为独立剩余工作。", "正常 Validator 与 EvidenceCompletionQueue 定点事实工作线程显式携带精确 build、入口 native USR 和提交时调用快照。调用参数与嵌套值复制隔离并保留消费者列表/字典语义；切换入口或绑定 legacy 空上下文清除旧 callee 映射，超时、异常及线程复用均恢复原绑定。execution_* 审计元数据不授予事实权限，候选自报字符串不能代替当前 native 收据。上述切片仍不代表所有 investigate 多轮、多 fact-kind、全建模和所有消费端已迁移；未接入部分继续单列。")
for path, note in {
    "docs/modules/execution-orchestration.md": "\n### 配置停止窗口与真实预算\n\nv3 execution.stop_at 的时区与本轮绝对边界只解析一次。CLI 把剩余窗口收紧到 ScanSessionRunner 已共享的同一个 CancellationToken，供 HTTP 等消费者读取真实剩余预算；已有更早期限、父取消及其原因保留，自身窗口先到才转为该窗口取消。release 停止 watcher，预算不因释放而延长。新建持久作业在未显式传入非空 stop_at 时保存配置窗口，显式请求优先；同 request_id 返回原作业及原窗口。已过窗口不滚到明天；resume 仍开新 attempt 且不重新套用配置窗口。逐实例部分恢复、完整扫描调度、其余 U01 字段及真实项目效果仍未完成。\n",
    "docs/modules/retrieval-backends.md": "\n### 原生热复用的观测范围\n\n当前 include-probes.v1 对存在性前提重新核验：仍缺失的头文件可热复用，目标出现、消失或更高优先级候选变化必须失效。rebuilt_tus 计量 AST 提取；热轮零提取、零参数检查不表示零进程，工具版本及 ldd 依赖来源核验仍可能运行。缓存工件摘要只证明工件稳定，提取进程由独立执行计数核对。extraction_complete、projection_complete 与全扫描 coverage 分开；当前受限 replay 的 projection_complete=false 不可提升为导航或全项目完成。\n",
}.items():
    changes[path] = (ROOT/path).read_text(encoding="utf-8").rstrip()+"\n"+note
rows=[]
for p,text in changes.items():
    target=out/p
    target.parent.mkdir(parents=True,exist_ok=True)
    target.write_text(text,encoding="utf-8",newline="\n")
    rows.append({"path":p,"before":hashlib.sha256((ROOT/p).read_bytes()).hexdigest(),"after":hashlib.sha256(target.read_bytes()).hexdigest()})
(out/"staging.json").write_text(json.dumps({"root_changed":False,"acceptance_required_before_intake":True,"files":rows},ensure_ascii=False,indent=2)+"\n",encoding="utf-8",newline="\n")
print(json.dumps({"root_changed":False,"staged_module_notes":len(rows)}),flush=True)
