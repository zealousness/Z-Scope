# 已接入基础后的独立后端增量

2026-10-14 UTC+8：S01 实例边界、U01 核心/只读准备、S08 owner/store/input/report 已受控导入，具体 SHA 在 intake 回执。S01 完整实例分析和 S08 JOB04/JOB06 尚未完成；新模块也必须先通过独立验证，再由协调者接入共享执行器。

| 节点 | 已满足输入 | 独占新增文件 | 输出/验收 | 尚未授予的能力 |
|---|---|---|---|---|
| S01-CDB-COVERAGE | 当前 entry_instances、CodeIndex、BuildContext、实际编译数据库 | `entry_instance_coverage.py`、`test_entry_instance_coverage.py`，隔离 s01-coverage | 逐 source/command_id 核对预期与 current stored contexts；实际 native 双宏、失效、错命令、缺分母反例 | 不授予链接、逐实例 Analyzer/Validator 或完整扫描 |
| S08-QUEUE-CORE | 已验 owner/store 与 API、现有 S07 oracle | `jobs/work_queue.py`、`test_scan_job_work_queue.py`，隔离 s08-scheduling | 真实 SQLite 队列、下一批新根、去重、公平/有界尝试、停止新 claim、真实 remaining 与重开/输入变化 | 不以独立队列代替 scanner 接线或完整 JOB04/06 |

两分支难度/风险均 high，由用户授权普通 Kimi API 故障转交后的既定 ZCode hw/glm-5.3 路由承担。各自不改既有输入文件；公共 `scan_session.py`、owner/store 和报告接线由协调者统一持有。Astra 独占静态目录、所有前端/用户体验及其 UI 测试。没有 native 重建、模型扫描、formal 或额外配置/凭据修改。

S01 接口：`reconcile_entry_instance_coverage(code_index, *, compile_commands_path, source_root, include_paths=None, exclude_paths=None)`；返回 `schema,status,expected_commands,current_commands,missing_commands,stale_contexts,unexpected_contexts,gaps,command_coverage_complete,scan_coverage_complete`。未知分母 null；只有当前真实索引命令可以填已处理数；`scan_coverage_complete` 此阶段始终 false。过滤/当前性复用现有索引事实，不通过相同数目或文件名授予覆盖。

S08 接口：传入项目内 SQLite 路径与 `job_id,input_revision`，队列 API 支持 enqueue、claim_batch、complete、defer、snapshot、recover。工作键包含 kind、精确 build 与稳定范围；未知 build 单独保留，不能跨构建复用。事务内 claim；新发现下一批；截止后停止新 claim；有界尝试/批次与未决年龄防止只选易例。重开必须保留真实剩余项，输入变化撤销旧完成状态；不会从持久 JSON 恢复进程内证明、执行命令或启用实验规则。

用户已确认旧 S06-R02 观察线程完成并归档；其不再是待用户处理阻塞。本轮不恢复、重派或操作此前被拦轮次；允许读取的已有产物也须独立核对后才用于依赖判断，用户确认不等于整体独立验收。
