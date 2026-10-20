# S01 R2 之后独立验收必须继续检查的作用域边界

2026-10-14 21:47 +08:00 静态审查记录；不是动态失败收据，未修改正在执行的 worker 副本，也未提前验收或导入。

R1 源码和目前 R2 运行中副本的 `parallel_analyzer.py` 中，实例分支跳过项目级发现后仍调用 `_run_scan_validation_queue()`。该方法约 930 行创建一个共享 `Analyzer`，传入未包装的 `self.code_index`、`self.semantic_result` 和共享语义；此方法并未显式传入实例作用域。现有 review checks 对部分精确 facts 显式读取 build_context_id，不自动证明所有 Validator 工具/反证路径都已隔离。

在稳定 R2 交付后，需要动态检查实际实例候选进入共享验证队列时使用的索引、语义和工具作用域，不能仅凭前置 Analyzer 已包装、候选带构建身份或事后结果过滤接受。必要时在现有拥有的 parallel_analyzer.py 分组保留精确 BuildContext/native USR，或者将未接路径明确降为缺口；不得退回全局索引提供反证。保持义务去重/一次裁决与生命周期不变量。

另需检查 R2 类型/宏上下文的“收据”是否只有 build_context_id 标签。计划要求当前 native USR/源码范围及构建事实核对；同名类型、宏或重载的构建标签本身不证明来源。现有原始 CodeIndex 投影未提供完整实例收据时，应消费处拒绝并保留缺口。动态探针应调用真实消费者；合成隔离探针与真实 native 效果各自记录。

现有协调探针、R1 稳定源码和 292 项 worker JUnit 已在 `artifacts/coordinator-s01-r1-consumers-20261014/initial-delivery/` 保全。原 2 守卫通过和新增 5 失败见该目录上级收据。R2 `task_09da468c8a` 当前实际执行中，不因本静态发现恢复/重派旧 S06，不创建重复 worker，不把源码疑点写成已动态复现。
