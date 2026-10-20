# P02：语义需求影子规划

## 当前状态

实现已落地，**G1 已通过，产品与测试冻结，等待总控 G2**。模式保持内部 `off|shadow`，默认 off；没有实际跳过函数，没有真实模型调用、外部依赖安装、源码外发、提交或推送。

- 所有者：Agent B / topology_ownership。
- HEAD：`010f40210b54ba0f79a088312ce5d8be3a82ace0`；分支 `v1.3.1_feat/llm-wiki`；保留共享工作树已有修改。
- 实际 cwd：`/mnt/c/Users/10273/home/work/Z-Scope_1.31/Z-Scope`。
- 解释器：WSL Ubuntu `/home/zeal/venv313/bin/python`。
- PATH：`/home/zeal/venv313/bin:/home/zeal/go/bin:/usr/lib/llvm-18/bin:/home/zeal/.local/svf/SVF-linux-x86_64/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin`。
- 本任务写入：新 `zscope/orchestration/semantic_demand.py`、`tests/test_semantic_demand.py`，以及获授单写的 `semantic_modeling.py`、`global_modeler.py`；未改 `modeling_coordinator.py`、核心 `_schedule`、public Config v2 或候选裁决路径。
- 内部配置和报告 metadata 由总控持有；K01 的 schema/binding helper 由 Agent A 持有。B 仅串行接入建模文件的三个 hook。

## 接口和行为

`GlobalModeler` 接受可选程序入口 `demand_hints`、`demand_security_map` 和 `demand_audit_units`。`SemanticDemandHint` 绑定既有 `SymbolIdentity`、当前源码 SHA-256 和有限缺口类别，不按函数裸名跨文件绑定；它是调查提示，不是 proof。

前置规划直接读取现有准备完成的 context 和受限源码事实，覆盖未知接口、间接调用／回调、对象表达式的别名未知、输入／调用图截断。候选缺失事实、文档冲突可通过类型化且绑定源码的 hints 输入，因此没有候选时仍可入选。对象语法只提示需求，不推导确定性角色或别名关系。D03 typed CoverageKey/occurrence 仅作补充，分别保留对象、站点、build 和入口路径；源码匹配不核验当前项目／revision／build，每行明确 `current_project_revision_build=unverified`。旧或无法绑定的补充项保留在 unbound。

规划复用现有 SCC 划分，执行 SCC 与 callee 依赖闭包，记录 selected/deferred/unknown 和原因。deferred 仍执行原完整调度，所有计划行 `safety_status=unknown`。无法解析的入口与缺失实现也保留 unknown，不创建任何安全缓存或独立任务身份。

结果写入 `SessionSemanticResult.demand_plan` 和 shadow-only publication audit。建模任务、六项输入指纹、singleflight、重试所有权、冻结 SCC 轮次、静态 wrapper、人工契约优先、提交和发布屏障继续复用原实现。需求审计故障包括准备阶段故障被隔离为 unavailable，取消仍传播，不能阻断实际完整调度或授权缩小范围。

K01 hook：off 保留原 spec 字典与 digest，不调用 schema/binding/inventory helper；shadow 扩展有效语言 schema，在 attach_contract 后复制并扩展 context schema，并把实际 schema 摘要加入 shadow 输入。自定义 schema 无法不执行任意 attachment hook 而重新核验，故不给 ObservationBinding，后续保守重新建模。默认热缓存仍复用快照，但 conditional observations 仅作背景，不重新签发绑定；共享任务复用也不替其他执行签发输入收据。

只有本轮默认 schema 的实际模型调用前取得输入收据，发布后记录 inputs 与收据一致，当前模型规格、schema、context、callee 输出、人工工作簿和有限本地输入库存仍一致，才产生进程内 ObservationBinding。注册阶段再次动态核验；模型／头文件／构建配置／人工契约／源码变化均可撤销。仅必要非密钥规格进入摘要，不打印凭据。JSON 不能恢复该授权。

资格范围是有界且可解析的本地自包含源码。现有或新出现的任何 `compile_commands.json`、非空显式 `compile_commands_path`（含非标准文件名）、无法本地核验的 include／输入、许可或扫描预算不足都不给当前观察资格；不创建新编译器参数解析器，不安装工具、不调用 backend。snapshot/cache 与生成工作簿排除于源码库存，人工行使用新的只读工作簿实例核验。该守卫只在 K01 shadow 使用，P02-only 与 off 零库存工作；不改变完整调度和普通缓存行为。

## 验收范围

- AC09：D03 两对象／两入口／不同 build 分开保留，未知 build 和旧覆盖显式标记；不声称完整义务覆盖。
- AC12：固定 fake 输出重放比较 off/shadow 的实际调用、全部会话快照、契约版本与 overlay；冷热调用分开；P01 的真实索引增量结论不在此重复执行。
- AC13：callee 失效、递归不收敛、K01 关闭身份／schema／源码漂移、wrapper 与条件契约回归；shadow 不生成确定性安全证明。
- AC14：无初始候选的 `alpha` 接口 fixture 经实际建模发布和工作簿重读后，重新运行实际 Clang 规则消费者产生 memory_leak 候选；不是只修改 Validator 上下文。shadow 不实际跳过任务。
- AC16：本轮只核对固定输出的模型调用和原计量字段。真实 LLM token、物理请求、多次实验、性能收益及真实工程准确率均 **not_run**；没有按 fixture 时间宣传加速。

## 迭代证据（保留原始失败）

| 运行 | 命令与退出码 | passed | failed | skipped | 输入状态 |
|---|---|---:|---:|---:|---|
| unit1 | `python -m pytest -q tests/test_semantic_demand.py`，exit 1 | 22 | 4 | 0 | 6 项摘要稳定 |
| unit2 | 同专项，exit 1 | 28 | 1 | 0 | 7 项摘要稳定 |
| regression1 | 下列 8 文件，exit 0 | 135 | 0 | 0 | 10 项摘要稳定，非最终 G1 |
| regression1 mypy | 三个所属产品模块，exit 1 | N/A | 4 diagnostics | N/A | 递归检查进入 A 的在建模块 |
| unit3 | 新鲜度 hook 与 planner 专项，exit 0 | 36 | 0 | 0 | 8 项摘要稳定，后续仍补边界 |

独立目录分别为 `/tmp/zscope-parallel-20261008/P02/unit1`、`unit2`、`regression1`，完整 argv、stdout/stderr、退出码、前后摘要记录在各目录 `execution.json`。pytest 使用各运行独立 basetemp 和 cache；没有重型工具或用户缓存清理。

unit1 原因：alias 提示未覆盖指针语法（1 项产品缺口）；测试误用 `resource_lifecycle` 作为 AuditUnit kind（3 项 fixture 错误，改为已有 `resource_protocol`）。unit2 原因：fixture 直接构造未规范化签名的 SymbolIdentity，现改用既有 `from_value`。regression1 mypy 的 4 条报错来自 `snapshot_candidates.py:336–337` 对可空 binding 的属性访问，已交 Agent A 修正；未抑制、未改其所有权文件，也未将此轮标为最终通过。

regression1 文件列表：`test_semantic_demand.py`、`test_incremental_semantic_modeling.py`、`test_global_modeler.py`、`test_wrapper_contract_compiler.py`、`test_semantic_modeling_usage.py`、`test_semantic_model_retry.py`、`test_java_semantic_modeler_schema.py`、`test_conditional_ownership_contracts.py`。

独立审查：Agent C 提出的 shadow 准备阶段故障隔离及 source-only D03 补充绑定已修正，并增加准备阶段异常不阻断完整调度的反例。后续 G1 还将覆盖 deferred 仍执行、无法解析入口明确 unknown 两项边界。

## 最终 G1（冻结输入）

运行目录：`/tmp/zscope-parallel-20261008/P02/G1-final1`。持久证据：[P02-G1-validation.json](P02-G1-validation.json)；早期原始失败及输出：[P02-iterations.json](P02-iterations.json)。证据只有受控 fixture、命令、结果和摘要，无真实凭据或用户项目源码；不依赖临时目录继续交接。

| 验证 | 命令范围 | 退出码 | 结果 |
|---|---|---:|---|
| pytest | 上述 8 文件；新专项 38，既有回归 105 | 0 | **143 passed、0 failed、0 skipped**，34.72 秒；该时间不是隔离性能测量 |
| mypy | semantic_demand.py、semantic_modeling.py、global_modeler.py | 0 | 3 source files，0 issues |
| compileall | 三模块与 test_semantic_demand.py，`-f -q` | 0 | passed |
| Black | 同 4 文件，`--check` | 0 | 全部无需改动 |
| diff check | 同 4 文件，`git diff --check -- ...` | 0 | passed；未跟踪新文件由 Black／compile 覆盖 |
| 输入审计 | 产品、配置、schema、prompt、helper、工作簿、工具与测试共 29 文件 | 0 | 前后全部 SHA-256 一致 |

完整 argv、输出和 29 项摘要均在 JSON。测试基准目录、pytest/mypy cache 和 compile pycache 全部独立；验证期间没有产品或测试写入。deferred 仍真实执行、入口无法解析保留 unknown、自定义 schema 变化保守重建、不重签热缓存，以及模型／header／新 compileDB／非标准编译配置／manual 修改后拒绝旧 binding 的验收均通过。P02-only 和 K01 off 明确验证不调用输入库存。

K01 编译输入限制进一步收紧：有任何编译数据库或显式编译数据库路径都不授权观察；helper 同时拒绝未核验的隐式编译环境和 Java classpath。数据中的 modeling 调用均为固定 fake 输出；发布与规则消费者是真实产品代码，未调用 native Clang/SVF 或真实 LLM。

## 未执行和恢复条件

真实模型实验、生产实际跳过、成本收益和跨工程准确率均未执行。只有固定重放及真实模型多次对照证明发现／义务覆盖等价后，才另行批准受限 fixture 的实际跳过；本次不能据 shadow selected 数量推导加速或召回率。TASKS／PROGRESS 和最终 G2 由总控维护。
