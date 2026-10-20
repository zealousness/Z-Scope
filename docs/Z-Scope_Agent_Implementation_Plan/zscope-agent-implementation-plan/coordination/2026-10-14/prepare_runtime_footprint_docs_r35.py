"""Prepare module documentation for the final source review, without intake."""
from pathlib import Path
import datetime as dt
import hashlib
import json
import sys

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
STAGE = ROOT / ".coordination/20261014/workspaces/coordinator-instance-integration-r24"
OUT = ROOT / "artifacts/runtime-footprint-module-docs-r35-20261017"
sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
if sys.platform != "linux" or sys.flags.optimize:
    raise RuntimeError("Unoptimized Linux Python required")
floor = json.loads((ROOT / "artifacts/stage-checkpoint-contract-intake-r34-20261017/receipt.json").read_text(encoding="utf-8"))
snippets = {
    "docs/modules/retrieval-backends.md": """
### 作业输出与编译输入的隔离

`zscope.include-lookups.v1` 独立记录实际预处理器的普通 include 查找：展开后的名字、引入文件、实际目标与有序搜索位置，包含系统和间接引入的头文件。它与 `include-probes.v1` 的存在性查询分别核验；前者不能代替后者。新增更高优先级候选，即使旧目标内容不变，也必须撤回依赖该查找的实例。

作业在工程内部写运行产物时，只有当前索引签发、与真实作业绑定一致的受限对象可以核对预先声明的精确输出名。冻结时的完整目录前提仍须重现，原有成员不能消失或改变；未知新名字、源码/头文件重叠及符号链接或硬链接别名不能被目录排除规则掩盖。旧工具、缺收据、VFS/remap/别名及未支持查找模式不能授权这项输出核对。附加 lookup 不完整与原有 native 依赖提取不完整分别报告，不因此降低未启用此作业输出机制的既有检查。
""",
    "docs/modules/execution-orchestration.md": """
### 同线程事务复用与运行目录保护

`JobStore.bound_attempt` 在同一线程已有真实 Store 写事务时，可借用同一物理数据库的当前连接，再次核对 job/run/owner/input 和状态；借用方不另开 BEGIN，也不提交、回滚或关闭原连接。同一规范数据库的不同 Python wrapper 可以借用，外来数据库、文件别名、未知连接和过期事务保持拒绝；其他线程仍按原独立 BEGIN 协议等待。实际数据库身份、原连接和事务代次共同决定资格，普通读取及复制的 frame 不能签发资格。事务退出、SQL/API 结束事务和 trace 回调中真实 SQL 重入都使旧代次失效；结束后重新 BEGIN 不恢复原资格。

绑定作业输出先检查实际编译查找与输出位置是否冲突，再在当前 SQL 绑定与运行目录命名空间的保护内执行原文件写入。锁序保持 Store→命名空间，检查过程中不反向取得 Store 锁；借用方仍复核当前输入和运行目录。codec 临时文件在真实发布期间保留保护，不能按随机文件后缀泛化排除；pending 写入也保留原 payload、容量及事件语义。该机制只保护受限作业产物，不表示完整公平调度、所有停止路径或真实项目扫描效果已经验收。
""",
    "docs/modules/configuration-state.md": """
### 当前实例与作业输出资格

实例的源码、头文件、普通 include 查找、存在性查询和原始命名空间前提保持冻结。受限作业输出资格由当前索引的进程内工厂签发，并继续核对真实 SQL 中的 job/run/owner/input 与物理运行目录；它不修改保存的 native 收据或重新建立基线。JSON、布尔标记、可调用对象和重建 dataclass 均不能授予该权限。原 owner 的对象不能继承后续 owner 的资格，未知文件变化与当前消费者源码变化仍撤回旧语义。

这项内部资格不新增 public YAML，不授权忽略整个输出目录，也不提升 `metadata.build_coverage` 或完整扫描覆盖。未满足原实例当前性时仍拒绝分析、恢复、结算和报告发布；历史报告与持久结果不能补造当前资格。
""",
}
if OUT.exists():
    raise RuntimeError("Preserve existing documentation draft")
OUT.mkdir()
before, after = {}, {}
for name, addition in snippets.items():
    path = STAGE / name
    assert sha(path) == floor["complete_inputs_after"][name]
    before[name] = sha(path)
    candidate = OUT / Path(name).name
    candidate.write_text(path.read_text(encoding="utf-8").rstrip() + "\n" + addition.strip("\n") + "\n", encoding="utf-8", newline="\n")
    after[name] = sha(candidate)
record = dict(actual_task="/root", prepared_at=dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat(),
    status="draft_pending_final_implementation_source_review", original_stage_sha256=before,
    candidate_sha256=after, changes="Only appended contract sections; existing module content retained with UTF-8 LF normalization.",
    integration_condition="Review these statements against the final native/Python/Store implementation and include final documentation bytes before the independent complete-source freeze.",
    product_acceptance=False, stage_intake=False, root_intake=False)
(OUT / "preparation.json").write_text(json.dumps(record, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
print(json.dumps(record))
