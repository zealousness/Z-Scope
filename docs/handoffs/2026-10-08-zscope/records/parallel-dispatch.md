# 并行批次：parallel-20261008

用户已授权按剩余工作包拓扑实际实施。工作区基础与环境见 `parallel-G0.json`；Windows Git 的原始 dirty 列表和内容摘要见 `parallel-G0-native.json`。WSL Git 因既有 CRLF 文件额外显示换行差异，本轮未转码或改写这些文件。无新分支、提交或重置。所有者之外的文件只读；跨域接线先发送总控请求，不同时改同一文件。

## 所有权

- 总控：TASKS.yaml、PROGRESS.md、共享文档；candidates.py、parallel_analyzer.py、core/analysis/analyzer.py 单入口、config.py/runtime_defaults.yaml、验证主 pipeline/runner、公共工具契约/runtime/registry 接线。
- Agent A（topology_dependencies）：active_discovery.py、security_map.py、新调查模块及专项测试；D01 → D02 → D03 → K01 → 条件 A01。
- Agent B（topology_ownership）：索引身份/inventory、index-audit、差分 replay 与专项测试；P01 → 条件 P02/R01/R02。建模文件接管须待 K02 明确释放。
- Agent C（topology_gates）：contracts/conditions/compiler、独立验证 provider/runner、隔离 fixture、离线导入及专项测试；D01 集成后 K02 → V01 → 条件 V02/A02。

各 agent 只写所属 TASK record；状态与共享模块文档由总控统一更新。Python 变更仅使用已有 WSL Black；不安装工具。

## 执行环境与测试

WSL Ubuntu，工作目录 `/mnt/c/Users/10273/home/work/Z-Scope_1.31/Z-Scope`；解释器 `/home/zeal/venv313/bin/python`。命令使用 G0 中固定 Linux PATH（venv、Go、LLVM18、SVF、系统目录），不依赖 Windows PATH 或 shell 启动差异。测试临时目录 `/tmp/zscope-parallel-20261008/<TASK>/<run>/`，每次 pytest 独立 basetemp/cache/output。

轻量专项测试最多三路。Clang/SVF 重建、ASAN/TSAN 及性能实验仅一个重型名额，由总控明确发放。性能测量前全体停止写入与其他测试。最终验收也须冻结输入，记录命令、退出码、输入摘要和 passed/failed/skipped/not_run。

## 第一轮派工

- A 实施 D01。可先消费 T01 源码证据和已有 build identity；不得将 unknown/may 提升为 proof，不修改公共工具或候选登记入口。
- B 实施 P01。复用现有 command_identity/inventory，必要的公共接口变更先通知 A/总控。首次真实重建需申请重型名额。
- C 暂只读审查 K02/V01 现有能力和 D01 资格边界；待 D01 集成验收后开始 K02。

下游只在总控确认上游 G2 通过后解锁。外部模型/服务缺失不阻塞无依赖本地任务，但真实必需验收缺失不得标 done。权限边界、默认 off/shadow、主 Ledger freeze 与统一裁决保持。

## D02 G2 后的临时派工

D02 以 455 项稳定输入回归通过 G2。A 继续拥有 D03 地图/覆盖代码；B 在等待 D03 期间独占新增 `external_investigation.py` 与 `test_external_investigation.py`，完成 A01 的 fake/离线接口，随后才接 P02。C 独占新增 `external_findings.py` 与 `test_external_findings_import.py`，完成不依赖 V01 的 A02 被动导入。B/C 不改 A 的调查/地图文件，跨域需要仍发总控协调。

V01 因平台内容检查中止且没有产品半成品，保持 blocked；V02 未解锁。不会更换 agent 重试被中止的实现。R01/R02 的启动条件不满足，当前只保存 readiness 记录。

## D03 G2 后的派工与用户最新调整

D03/A01/A02 的冻结组合 646 项通过。A 转 K01，独占 snapshot_candidates.py、snapshot_observations.py 及对应专项测试；B 转 P02，独占 semantic_modeling.py、global_modeler.py、semantic_demand.py 及对应专项测试。K01 的建模 schema/输入绑定 hook 由 B 单写，A 提供 helper 契约。总控负责两扫描入口、RuntimeSpec、裁决 shadow 边界、resume/maintain 报告复用、共享文档与状态。

用户曾明确恢复 V01 原任务，同一 C agent 在原有范围继续只读核对与接口设计；用户随后报告再次被拦截，并明确指示先遗留该任务。已停止 V01/V02 实施和执行，没有 provider、fixture 或测试半成品。C 转为 K01/P02 独立只读审查，只写独立 review record，不替代 A/B 实施或重试 V01。记录保留各次历史，不将被拦截或未执行项登记为 passed。
