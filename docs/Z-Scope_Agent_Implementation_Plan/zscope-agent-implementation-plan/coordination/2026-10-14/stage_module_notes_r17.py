"""Stage documentation for accepted future intake; do not change current root."""
from pathlib import Path
import datetime as dt
import hashlib
import json

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
updates = {}

def stage(name, replacements, suffix=""):
    path = ROOT / name
    original = path.read_text(encoding="utf-8")
    result = original
    for old, new in replacements:
        assert result.count(old) == 1, (name, old[:80], result.count(old))
        result = result.replace(old, new)
    result = result.rstrip() + "\n" + suffix
    updates[name] = {"before_sha256": hashlib.sha256(path.read_bytes()).hexdigest(), "after_sha256": hashlib.sha256(result.encode("utf-8")).hexdigest(), "contents": result}

stage("docs/modules/execution-orchestration.md", [
    ("  - zscope/orchestration/jobs/session_scheduler.py\n", "  - zscope/orchestration/jobs/session_scheduler.py\n  - zscope/orchestration/jobs/scan_work.py\n"),
    ("  - tests/test_job_session_scheduler.py\n", "  - tests/test_job_session_scheduler.py\n  - tests/test_scan_session_instances.py\n  - tests/test_scan_session_jobs.py\n  - tests/test_scan_checkpoint_resume.py\n  - tests/test_job_bound_completion.py\n"),
    ("- C/C++ 所有扫描档位在入口与索引/Wiki 就绪后，先对可达并集进行增量语义建模", "- C/C++ 既有非实例分析路径在入口与索引/Wiki 就绪后，先对可达并集进行增量语义建模"),
    ("当前 `ScanSessionRunner` 尚未调用该入口，普通扫描仍使用旧导航投影；计划枚举不等于实际逐实例扫描，完整覆盖仍为 false。", "普通 C/C++ `ScanSessionRunner` 在当前 native 计划可核验时实际进入逐实例 Analyzer，单入口、批量和恢复共用这条路径；无法核验的实例保留缺口，不回退名称报告。计划枚举、实际分析和全扫描覆盖分别报告，当前全扫描覆盖仍为 false。"),
    ("当前 owner 截止仅对扫描进程执行有界停止，resume 启动新 attempt；协作停止新工作、持续剩余队列、公平后续批次尚待与真实扫描器接线。独立 producer 的测试通过不能关闭 JOB04/JOB06、INC05 或完整主包。", "owner 截止先触发当前扫描令牌的合作停止，调度器停止领取新工作并保存真实剩余，在途 Analyzer/验证有界收尾；watchdog 处理未退出进程。resume 启动新 attempt。当前保存的是扫描范围的整体完成，逐实例部分恢复、公平持续批次和完整 JOB04/JOB06、INC05 仍未完成。"),
    ("### 已接收的持久队列消费接口（完整扫描接线仍待完成）", "### 持久队列与精确实例扫描"),
    ("这些接口已用真实 SQLite、回调和 detached owner/scanner 子进程验证，**生产 ScanSession/ParallelAnalyzer 尚未消费该调度接口**；当前普通作业的截止仍不能宣称已完成工作项级停止、公平续跑或完整 JOB04/JOB06。", "生产 ScanSession 已通过 `scan_work` 登记实际实例分析、扫描范围集中验证和整体检查点三个阶段，消费该持久调度接口；同一扫描复用 CandidateLedger、验证缓存与一次集中裁决。取消与截止的在途停止已接入该路径，完整持续调度、公平续跑及逐实例 durable 恢复仍单独保留。"),
], '''
### 绑定完成收据与跨运行复用

`JobStore.append_bound_event` 在同一事务复核 job、run、owner、输入后发布绑定事件；普通日志和手写 JSON 不会形成完成收据。`trusted_completion` 只返回同 job、输入、计划的真实生产坐标，文件和语义资格由扫描消费者继续核验。完成文件位于 producer 的 run 目录，先原子发布并计算摘要，再提交收据；缺少收据时保持未完成。

新 attempt 先实际构建当前 native 索引和精确计划，再核对实例集合、输入、编译器与默认契约内容版本、可核验语义/回答依赖及文件摘要。包含确认或 proof 权限的序列化结果保持 miss，重新执行当前分析与裁决。最终报告发布与当前 job/run/owner/input 检查共用事务围栏，避免检查后交接仍覆盖当前报告。缓存实例、本轮实际执行实例和生产 run 分开计量。

每次 attempt 使用独立队列，owner 从该 run 的真实 scheduler 收据读取全部状态；canonical 队列及 sidecar 保留。当前整体检查点复用不代表逐实例部分恢复，也不代表全变体建模、SVF、真实链接或真实项目效果已经验收。
''')

stage("docs/modules/analysis-pipeline.md", [
    ("  - tests/test_validation_runner.py\n", "  - tests/test_validation_runner.py\n  - tests/test_validation_build_scope.py\n  - tests/test_contract_usr_scope.py\n"),
], '''
## 当前原生身份与验证绑定

契约生产和效果消费保留精确 BuildContext 与 native USR。效果查询省略 USR 时，只能从当前完整且无冲突的入口或实际 callee 收据解析；缺失、过期、混合重载或构建冲突保持未知。原始 Registry `find` 可供发现，记录唯一不能证明调用选择了它；入口 owner 也不能覆盖同名递归调用的目标歧义。契约编译与 Registry 版本参与缓存失效，覆盖统计使用实际当前函数身份，不能把缺失绑定误报为未发布。

共享 `ValidationRunner.run` 按 scoped index 的真实实例核对候选及 evidence 的构建，在 executor/scheduler 工作入口绑定并在退出时恢复上下文。未知或冲突候选不会通过补标签取得验证资格。上述边界不代表 Validator 所有内部 Registry 调用、EvidenceCompletionQueue 内部线程、全建模和所有消费端已迁移；未接入部分继续作为独立剩余工作。
''')
target = HERE / "staged-module-updates-r17.json"
assert not target.exists()
target.write_text(json.dumps({"staged_at": dt.datetime.now(dt.timezone.utc).isoformat(), "apply_only_after_independent_main_contract_checkpoint_and_api_gates": True, "root_changed": False, "updates": updates}, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
print(json.dumps({"staged_modules": sorted(updates), "root_changed": False}))
