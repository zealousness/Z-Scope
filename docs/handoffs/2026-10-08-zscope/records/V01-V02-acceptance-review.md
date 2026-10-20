# V01 / V02 独立验收：退回修订

- 日期：2026-10-09（Asia/Taipei）。用户请求：验收 DeepSeek 交付的 V01/V02。
- 结论：**未通过，不能维持 done。** 已有 ASAN/TSAN provider 与测试代码，但 AC06、AC11、AC18 的必需约束未满足。
- implementation_status：已有实现，需修订；verification_status：failed。V02 的共享基础依赖 V01，本次不放行下游。
- 本轮只新增验收脚本、记录和状态更正，不修补或覆盖产品实现，不回滚既有 B00–P02 修改。
- 原实施记录 [V01](V01-dynamic-reproduction.md)、[V02](V02-dynamic-reproduction.md) 及观测 JSON 原样保留，属于提交者的历史验证声明；当前验收结论以本记录为准。

## 基线与验证范围

本地分支 `v1.3.1_feat/llm-wiki`，HEAD `010f40210b54ba0f79a088312ce5d8be3a82ace0`，工作区仍含前批及本次未提交实现。没有切分支、提交、推送、安装依赖或外发源码。适用开发规范为根 `AGENTS.md`；未修改 `test/range`、truth 或用户服务。

提交者 [工作区记录](V01-V02-final-workspace.json) 的 `frozen_inputs.files` 实际列出 **17** 个文件（文字称 18）；本轮核对这些文件全部与所列 SHA-256 一致。独立验收另记录全体产品、测试、脚本、native、requirements、模块文档的执行前后摘要，结果见 [验证 JSON](V01-V02-acceptance-validation.json)。

WSL 专项、负例、兼容回归及质量检查使用已安装当前仓库的 `/home/zeal/venv313/bin/python`（3.13.15）。实际 PATH、命令、退出码、日志与用例统计均写入 JSON。验收负例的断言表达应满足的约束，失败就是发现的问题，没有改为 xfail 或调整产品代码迎合测试。

## 阻止放行的问题

### F01 / P1：确认时没有重新绑定当前候选和源码身份

位置：`dynamic_reproduction.py:893–910`、`:2093–2104`。

登记时只比较 project/source_revision/candidate_uid/cluster 四项，忽略对象、站点、缺陷族、构建和工具链。裁决时又只检查 UID 以及 proof 中复制的旧 `code_hash`，没有把当前候选的完整身份与授权身份比较。相同 UID 在源码、项目、对象、位点或构建变化后仍能使用旧证明。

实测：`test_registration_rechecks_entire_candidate_binding` 的 5 项，以及 `test_adjudication_rejects_changed_current_identity` 的 8 项全部失败；`deterministic_decision_proof(..., outcome="confirm")` 对变化后的候选仍返回确认证明。

修订要求：由程序核验完整的当前身份，并在最终裁决再次检查；源码、头文件、构建、规则/契约、工具链等适用身份变化应失效。不能比较两个都源于旧 plan 的字符串来声称 current。

### F02 / P1：执行计划中的源码、输入与二进制身份没有真正核验

位置：`dynamic_reproduction.py:1357–1385`、`:1955–1967`。

执行器仅 hash `binary_path`，没有核验 `harness_ref`/`input_refs` 的实际内容，也没有保证 `run_argv[0]` 是被核验的二进制。`source_identity_bound` 只要求两个字符串非空。源码或输入已变化仍启动；声明 `/bin/true` 的摘要却执行另一程序也被允许。工具链及构建配置同样只是调用方声明。

实测：`test_runner_checks_actual_inputs_before_launch` 的 harness/input/executable 三项全部失败，执行 spy 均被调用。此处只用了临时文件和 spy，没有执行未知代码。

修订要求：核验获准的实际源码/harness/输入和执行文件，建立可核验的构建来源与工具链身份；执行及裁决之间的替换需要再检查或使用不可变输入。无法核验时保持未决。

### F03 / P1：同一行被无条件视为同一对象

位置：`dynamic_reproduction.py:1082–1090`。

对象未匹配时，只要文件和行号相同就令 `candidate_object_matched=true`，即使候选明确写的是另一个对象。一个表达式或同一行中的多对象访问、同位点不同实例、不同输入触发的对象均不能用行号等同。

实测：候选 `other_buffer`、witness `actual_buffer`，仅站点相同，`test_wrong_named_object_at_same_site_is_not_a_match` 失败并返回匹配。

修订要求：保留对象及访问角色的程序绑定，无法映射 ASAN 地址或 TSAN 对象时返回 unknown；站点命中不能补造对象证明。

### F04 / P1：独立重放可被普通数据或不一致结果替代

位置：`dynamic_reproduction.py:1903–1930`、`:1972–1988`。

`ReplayEvidence` 没有 live receipt/authority，手工构造相同摘要与分类即可通过。`replay_witness` 忽略每次执行的终态和完整分类，只要存在 finding 就取第一个 kind；一个内部已判 `inconclusive` 的混合重放因此能被压缩成两次成功。重放在另一对象/位点发生同类错误也会通过。

实测：`test_serialized_replay_claim_requires_live_execution_receipt`、`test_mixed_independent_replay_cannot_be_collapsed_to_success`、`test_independent_replay_for_other_site_cannot_confirm` 全部失败，均产生 `proof_attached=True`。

修订要求：保留每次真实执行的身份、终态、对象/站点 witness 及版本化 receipt；资格检查逐次匹配全部证据，不以分类字符串或最后一次二进制摘要代替。

### F05 / P1：live token 表示“跑过”，却被当成“已通过确认资格”

位置：`dynamic_reproduction.py:808–847`、`:1716–1735`、`:1894–1900`、`:2035–2071`；`proofs.py:324–328`。

所有执行记录（包括没有报告的成功运行）都会授予 attestation；fake provider 也使用生产授权表。授权表不记录已通过的资格/完整 proof，只核对原始记录摘要和 UID。公共 proof 工厂又无条件写入所有确认 facts。因此一个真实 `/bin/true` 的 `not_reproduced` 记录也能被拼接为 selector 接受的确认证明。token 还写进普通 issue 的 `deterministic_proofs`；同进程 JSON 往返保留权限，原测试只在主动清空整个注册表后验证失效。

实测：`test_clean_execution_cannot_be_given_unqualified_positive_proof`、`test_fake_provider_cannot_mint_production_confirmation`、`test_serialized_issue_has_no_authority_even_in_same_process` 全部失败。第一个仅运行良性的 `/bin/true`，并非 fake 执行。

修订要求：执行真实性与确认资格分离；只有完整匹配及独立重放后才签发不可从序列化数据恢复的确认能力。fake 限定为测试替身，不能授予生产确认；生命周期结束时释放对应 authority，不能依赖全局手动清空。

### F06 / P1：隔离失败后仍执行，资源声明也不满足计划约束

位置：`dynamic_reproduction.py:1314–1334`、`:1386–1411`、`:1515–1524`、`:1707–1711`。

请求 `user_net_namespace` 而探测失败时，只设置 `isolation_verified=False`，随后仍运行原 argv；资格检查不检查隔离是否生效。build 阶段在此之前运行，未包裹该命名空间。执行根检查只检查 cwd 和临时目录，空 roots 代表任意范围，没有只读输入/写入范围约束。ASAN 的单次 allocation cap 不能限制总 RSS；TSAN 实际不施加内存限制却记录 `memory_limit_mode=rlimit_as`。输出日志亦无总字节限制。

实测：`test_unavailable_requested_isolation_prevents_launch` 失败；强制探测不可用后执行 spy 仍被调用。资源与 build 路径问题为源码审查发现，没有用耗尽资源来验证。

修订要求：build/run 使用经核验的同一隔离授权；请求条件缺失返回 unavailable/unsupported，不执行降级后的命令。资源限制须由实际执行边界施加并如实记录。外部验收容器的能力不能算成产品 runner 的能力。

### F07 / P2：默认关闭未在执行边界强制，主扫描尚未调用新能力

位置：`dynamic_reproduction.py:1260–1307`、`:1168–1189`；`validator_protocol.py:239`。

默认 `DynamicReproductionPolicy(enabled=False)` 的 runner 仍可执行，只有事后的注册函数检查 enabled；`availability()` 也会编译运行。`make_dynamic_reproduction_policy`、plan/execute/register 的产品调用方均缺失：全仓产品路径只有 `proofs.py` 消费已附加的证明。仅把 RuntimeSpec 设为 on/shadow 不会形成从扫描候选到执行的运行链，请求仍序列化为 `reserved_not_implemented`。

实测：`test_disabled_runner_never_launches` 失败；主链缺口由全仓调用搜索确认。原集成测试直接手工调用 helper 和 `ValidationPipeline(None)`，不能证明真实主扫描接线。

修订要求：在最外层及 runner 边界执行开关/授权检查，并提供获准 plan 的真实消费入口及取消/关闭接线；若明确只交付库级 provider，应修订能力声明并保留运行集成未完成状态。

### F08 / P2：默认执行记录不保留可审计的完整重放产物

位置：`dynamic_reproduction.py:1426–1429`、`:1487–1489`、`:1560–1561`、`:1609–1610`、`:2132–2144`。

每轮覆盖同一 stdout/stderr 文件；record 中保留第一轮 finding、最后一轮日志摘要以及最多 8192 字节摘录，finally 默认删除整个日志目录。artifact_refs 是没有存储定位的 hash 字符串。多轮结果可能来自不同位点但同 kind，无法从 receipt 恢复逐次原始证据；长日志在分类前也被截断。本模块没有接入已有 immutable evidence store。

修订要求：持久登记每次执行的完整有界 artifact、输入与二进制来源，记录逐轮 witness 和可解析 ref；清理临时目录前先发布可重放证据。预算耗尽应可观察，不能把截断后缺失 sanitizer 输出解释为完整未复现。

## 执行结果

结果以本轮生成 JSON 为准，不沿用提交者旧计数。测试组可能覆盖相同功能，不把历史数量相加。

| 组 | passed | failed | errors | skipped | 说明 |
|---|---:|---:|---:|---:|---|
| 提交者专项单测 | 62 | 0 | 0 | 0 | WSL，exit 0 |
| 独立必需约束负例 | 0 | 25 | 0 | 0 | WSL，exit 1；不是预期跳过 |
| 外层断网容器 sanitizer 测试 | 9 | 0 | 0 | 3 | 8 项 ASAN 执行 + 1 项证据导出；TSAN 3 项探测失败后跳过 |
| 兼容回归 | 1539 | 0 | 0 | 0 | 相关 77 个测试文件，exit 0；3 项重型索引测试 deselected/not_run |

`compileall`、`mypy zscope`（307 source files）与 Linux `git diff --check` 全部 exit 0。执行前后输入摘要一致，`changed_inputs=[]`；通过的兼容回归不抵消新增能力的失败。3 项未执行的重型用例为 `test_real_mutation_replay`、`test_real_direct_bitcode_dependency_cache_and_svf`、`test_native_code_to_real_terminal_tool_workbook_and_pool_consumers`，本轮不复用其历史通过记录作为新验收结果。

外层容器使用本机已有 pinned Python 3.13 镜像，`--pull=never`，没有下载镜像或依赖。当前仓库和已有 venv 的依赖以只读卷挂载；容器 Python 3.13.15、GCC 14.2.0。真实探测确认：仅 loopback 网络、仓库只读、CapEff=0、NoNewPrivs=1、memory.max=2 GiB、pids.max=256、cpu.max=2 CPU。ASAN 的 user/net namespace 用例实际生效；**这些能力属于验收外壳，不属于产品实现**。容器用后自动删除，另以任务专属名称检查清理，exit 0。命令、观测 receipt 和限制见 [容器验证 JSON](V01-V02-container-validation.json)。

TSAN 在此容器内返回 `sanitizer_probe_failed`，三项为 skipped/real execution not_run；未修改保护条件或切到无隔离宿主来凑通过。提交者既有 WSL/Clang TSAN 观测保留为历史记录，本轮不重新背书其 G3 结论。没有运行正式 Range、真实模型、外部扫描、CBMC 或真实用户工程；这些均 not_run。

## 修订与复验入口

1. 保持现有实现和全部历史记录，先修 F01–F06，再完成 F07/F08 的能力与交付边界。
2. 将 [独立负例](V01-V02-acceptance-regressions.py) 迁入合适的正式测试并补足真实执行负例；不得删掉断言以取得通过。fake 的生产 authority 测试应在修订后使用受控、明确的测试授权注入。
3. V01 重新通过 G1/G2/G3 后再放行 V02。TSAN 在获准隔离环境中取得可运行工具链时重跑真实验收；缺失条件保留未执行，不自动安装。
4. 本轮复验命令已保存在 [WSL driver](V01-V02-acceptance-driver.py) 和 [容器 driver](V01-V02-container-review.py)。运行前重新核对工作区摘要与目录，勿覆盖本轮证据；应使用新的结果文件名。
