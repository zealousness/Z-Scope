# R21 当前 UI 与覆盖投影整改合同

状态：只读源码审计后的准备合同，尚未开发派发，不授予 Root 写权限。R20 九文件已独验并于23:00:31导入；R21 两项测试 fixture 经独立审查和隔离验证于23:55:20导入。R21 联合验证为2538通过、1计时断言失败，五项质量检查通过，失败收据保留。CURRENT-JOINT-R22 于2026-10-16 01:11:29完成2539项通过、0失败/错误/跳过和六命令0，发布前实时复核通过；本开发项仍等待协调者投影依赖暂存验收及所有权核对。

## 已核对的问题

- `index.html` 的作业创建提示称留空不设置截止；当前服务在请求无显式非空时间时使用已保存 v3 配置窗口。
- 配置页称时区与配置停止时间仅声明；当前 v3 已将配置窗口接入实际共享令牌及持久作业。max_workers 等未消费字段仍须保留声明状态。
- 作业提示称只有进程级停止；当前实例调度器已停止新工作、有限收尾并记录未决。完整逐实例候选/义务恢复仍未完成，不能改成保证只运行剩余项。
- `acceptance._coverage_gaps` 对任意 `entry_instances.scan_coverage_complete=False` 无条件生成 `entry_instance_analysis_unwired`。已有独立实例分析的报告也会被误述为尚未接入。False 仅证明覆盖不完整，不能推断具体原因。

依据为协调者与 Astra 独立静读当前源码，实际审计收据已保存于 `artifacts/astra-ux-remaining-audit-r21-20261015/`。该审计没有重新扫描或形成真实项目效果结论。

## 所有权

| 角色 | 独占范围 | 边界 |
|---|---|---|
| Astra，新的隔离副本 | `zscope/web/static/index.html`、`zscope/web/static/dashboard_workbench.js`、`tests/test_agent_workbench_ui.py`、`tests/fixtures/agent_workbench_ui.cjs`、`tests/test_instance_coverage_ui.py`、`tests/fixtures/instance_coverage_ui.cjs`、新的 `tests/test_ux_capability_boundaries_ui.py` 及 `tests/fixtures/ux_capability_boundaries_ui.cjs` | 仅实际提示、呈现及专用浏览器验收，不改共享 HTTP、投影、配置、运行时或资源锁 |
| 协调者，独立暂存后作为只读依赖交付 | `zscope/reporting/acceptance.py`、新的 `tests/test_coverage_gap_provenance.py`、既有 `tests/test_agent_integration_boundaries.py` 的过期原因断言窄迁移、对应模块文档、`requirements/portable/web-assets.lock.json` | 投影区分一般覆盖不完整与生产者明确提供的未接入原因；保留显式 variant 缺口及其余集成测试；资源锁按真实静态字节统一更新 |
| 既有交付 | R18 native 浏览器轮与历史97 synthetic 轮 | 冻结成果，不重复派单或把其测试数据当真实项目效果 |

## 必须保留的行为与验收

1. 未提供覆盖为 unknown/null；已分析或已复用计数不授予完整语义建模、全图、链接或真实项目扫描能力。
2. 明确的 `entry_instance_analysis_unwired` 生产者缺口仍保留；一般 False 使用准确的一般缺口，保留其他原始缺口，不制造安全结论。
3. 配置窗口、显式请求覆盖、合法无窗口及 resume 清空分开描述。配置时区与浏览器显式绝对时间的时区分别保留。
4. native 两宏实例已分析但覆盖仍不完整时，不显示虚假的未接入；旧报告或缺少实例结果时保持未知。两类来源不能串用。
5. 原实际 HTTP/SQLite/owner、报告内容与 scope 绑定、409/草稿、失效报告、desktop/mobile 和未知分母验收保留。只改已核实过期的文案断言并记录原因，不移除真实请求或状态断言。
6. 开发者自验、协调者独验、共享导入和当前版本联合验证分开记录 task ID、时间、SHA、JUnit 和证据路径。所有测试仍用 WSL/Linux、默认 fd、ext4 临时目录、单层两槽。

## 尚未授予的结论

不启用 focus/reproduction/max_workers/platform，不实现多目标执行、不保证逐实例候选/义务恢复，不启用实验规则。真实外部模型、真实项目准确率、formal benchmark、portable smoke 和 S01/S08/U01 整包仍独立。
