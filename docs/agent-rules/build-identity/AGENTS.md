# 构建身份与证据隔离

[返回根入口](../../../AGENTS.md) · 候选、证明、缓存、报告聚合、人工反馈及 SVF/Saber 归属变化时读取。

本专题的身份与摘要约束用于产品证据归属和缓存有效性，不要求冻结开发代码、先拍整仓快照或禁止修改计划。相关输入变化时更新对应事实和受影响测试，不能借用失效证据，也不因此默认重跑全项目。

涉及候选、证明、缓存、报告聚合或人工反馈时，同时检查 `build_context_id` 是否贯穿；未知构建不是通配符，不能将另一编译变体的证据或误报决定复用过来。身份链路回归见 `tests/test_candidate_build_identity.py`，全变体扫描覆盖仍以报告中的 `metadata.build_coverage` 为准；该覆盖逐实例复核当前输入，`status="indexed"` 不再等于输入仍 current（陈旧实例进 `uncurrent_instances`，无收据记 `unmeasured`）。SVF/Saber 信号同样按编译命令归属：生产者给 `command_id` 与 `exact/ambiguous/unattributed` 判定，实例侧只经 `ScopedCodeIndex.get_instance_backend_signals()` 读，回归见 `tests/test_svf_build_identity.py`；链接组仍是多变体合并分析，不因此变成逐变体 SVF。
