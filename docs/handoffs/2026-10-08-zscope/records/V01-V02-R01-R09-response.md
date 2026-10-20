# V01 / V02 第二轮验收问题（R01–R09）修订回应

日期：2026-10-09（Asia/Taipei）。角色：V01/V02 实施方自验，**不是验收放行结论**。

被回应对象：[第二轮独立验收](V01-V02-reacceptance-review.md) 及其保存的独立脚本与 JSON（本轮一律未改动）。
上一轮回应保留在 [首轮验收修订回应](V01-V02-acceptance-response.md)，历史记录不覆盖、不重写。

本轮只做一件事：把 R01–R09 与两项资源/平台问题逐条落到产品代码和产品测试里，再用**新的内容摘要**复验。
负例断言未删、未弱化、未改成 xfail，也没有把“全部未授权”当成通过标准：初次确认的正向控制仍按生产信任路径走到
`deterministic_decision_proof(issue, outcome="confirm")`，并在每个相关用例里保留。

## 一、逐条修订

### R01 实际文件变化贯穿执行与最终确认边界

- **执行期**：`execute()` 现在在**每个**执行入口、build 之后、以及真正 `Popen` 之前重新核验身份。
  初次校验失败 → `unsupported/plan_identity_unverified`；build 之后漂移 →
  `unsupported/plan_identity_changed_during_execution` + `harness_digest_mismatch`，并且不再启动 run。
  计划声明的 harness、全部 `input_refs`、被执行程序都在每次执行时重新哈希，命令必须正是该程序。
- **裁决期**：witness proof 冻结它实际来源的文件摘要（`source_files`，登记时由
  `frozen_source_digests(...)` 取自绑定站点文件、plan.harness_ref 与 plan.input_refs），
  `dynamic_witness_proof_is_live` 不再只重算 issue 字典，而是**重新读取并哈希这些真实文件**；
  文件漂移、源文件不可读（`source_snapshot_unavailable`）都会撤销 live 资格。
- **产品测试**：`test_a_later_execution_refuses_when_a_verified_file_changed[harness|input|binary]`
  （每轮 spy 断言漂移后**没有**第二次进程启动）、`test_build_cannot_change_the_verified_source_before_the_run`
  （`calls == ["build"]`）、`test_confirmation_is_revoked_when_the_source_file_changes`
  （先建立 live 确认，再改真实源码且不刷新 issue，selector 必须返回 `None`，同时
  `apply_deterministic_prevalidation` 也不得消费它）。
- 复核对象：`test_filesystem_source_change_revokes_live_confirmation`、
  `test_each_execution_revalidates_current_files`（3 项）、`test_build_cannot_change_verified_source_before_run`
  在原样独立文件中全部通过。

### R02 具名对象改为完全一致

`match_witness_to_candidate` 的具名 token 比较删除了双向子串兜底，改为**规范化后完全相等**；
空 token 不匹配任何具名对象。匿名地址只有在站点与缺陷族同时一致时才可能匹配，函数名出现在栈中不再足以
代替对象/分配身份，该能力边界写在函数 docstring 与模块文档里。
`test_similar_named_resources_are_not_the_same_object`（含 `shared_counter`/`shared_counter_backup` 双向、
`buffer`/`other_buffer`、`heap_buffer_overflow` 同站点）通过；产品侧另有首轮迁移的
`test_acceptance_wrong_named_object_at_same_site_is_not_a_match` 与
`test_wrong_object_and_site_report_is_not_qualified`，断言未改。

### R03 确认链核验每一次执行的生产资格与逐轮 witness

- 生产确认与“描述性附加”拆开：`qualify_witness` 只判断候选/站点/缺陷族/对象等证据匹配，
  `replay_production_problems(binding, replay)` 单独要求**每一次** replay 的运行都是
  生产信任、`inputs_verified`、绑定摘要一致且带 live receipt。`authority_granted` 要求主执行生产信任
  且 `replay_production_problems()` 为空。测试信任的重放可以附加描述性（inconclusive/incomplete）证据，
  但**永远不能**补足生产确认。
- 主记录逐轮核验：`record.runs` 中每个 `outcome == "observed"` 的轮次都必须给出命中本候选的 finding，
  否则 `primary_run_witness_without_report` / `primary_run_witness_not_matching_candidate`；
  聚合 findings 命中不能豁免某一轮。replay 侧同样对嵌套 `runs` 逐轮比对
  （`replay_nested_run_witness_not_matching_candidate`）。
- 产品测试：`test_untrusted_replays_cannot_complete_production_confirmation`（主执行提升为生产、replay 保持
  `TRUST_TEST` → `confirmation_authority.granted == False` 且 selector 为 `None`）、
  `test_every_primary_run_must_match_the_candidate`（第二轮 `other.c:999` 命中同类分类，资格必须为 false）、
  以及 fake 正控 `test_qualified_witness_attaches_descriptive_proof_without_confirmation`。

### R04 build 产物可完成资格确认

计划允许 `binary_digest=""` 且自带 `BuildSpec` 时，程序身份绑定为**本次获准构建实际写出产物的摘要**：
执行器记录 `binary_identity_source="post_build_output"` 与 `binary_identity_bound_after_build`，
资格判定在该情形下接受这条绑定（仍然要求构建真的发生、摘要非空、来源字段正确），
不再要求构建前不可能存在的摘要；重复构建改变产物摘要会立即失效。
产品侧新增真实编译用例 `test_asan_build_generated_binary_confirms_without_a_declared_digest`
（编译授权 ASAN fixture → 执行 → 独立重放 → 登记 → `deterministic_decision_proof(confirm)` 非空）；
独立集成文件在 `ZSCOPE_REVIEW_ISOLATED=1` 下不再 skip 且通过。

### R05 默认产品入口按 plan 的 provider kind 分派

新增 `_default_provider_runner(plan, policy)`：`asan → AsanReproductionRunner`，
`tsan → TsanReproductionRunner`，其它种类 fail closed（`unsupported_provider_kind:<kind>`，
不改用不知名 provider）。`run_dynamic_reproduction` 未显式传 runner 时走该分派，扫描接缝因此不需要自带 runner。
产品测试 `test_default_product_entry_dispatches_on_the_plan_provider_kind` 用 factory spy 断言
TSAN 计划实际选中 `tsan`；独立用例 `test_default_product_entry_selects_tsan_provider` 通过。

### R06 真实执行预算与总 deadline

- 明确口径：**一次 `execute()` 执行一轮**（计划授权的 build + 一次 run）；`plan.max_replays` 是整个验证
  允许的 plan 执行**总次数**。调度器给主执行 1 次，其余留给策略要求的独立重放：
  `1 + min(required, max(0, max_replays-1))`，不足时写入 `issue["dynamic_reproduction_budget"]`，
  **不在派发 provider 之前拒绝**。
- `_ExecutionBudget(run_limit, deadline)` 计量真实进程启动（build 与 run 分开计数），在 `Popen` 之前 `claim()`，
  超预算抛 `_PlanViolation`；runner 经 `use_budget()` 绑定（鸭子类型，不要求调用方继承）。
- 共享墙钟 deadline 覆盖 build 与所有 run，每次 run 取剩余额度与单进程超时的较小值。
- 产品测试：`test_scheduler_binds_the_shared_budget_to_the_provider`（`run_limit == max_replays`）、
  `test_verification_budget_and_deadline_bound_real_process_starts`（额度耗尽与 deadline 过期都不启动进程）、
  `test_run_dynamic_reproduction_clamps_replays_to_the_plan_budget`、
  `test_attempt_clamps_replays_instead_of_refusing_before_dispatch`。
  独立用例 `test_execution_budget_counts_primary_and_independent_runs` 通过（上限 2 → 真实启动数 ≤ 2）。

### R07 每个 execution 独立 artifact 目录

发布路径改为 `artifact_dir / <plan_id> / <该次执行的 workdir 名>`，每次执行新建目录、绝不覆盖，
发布后逐文件核对摘要；缺失或哈希不符如实记录（`artifact_publish_*` 限制），不把摘要冒充位置。
产品测试 `test_published_artifacts_are_never_overwritten_by_a_later_execution`（同一计划执行两次，
第一次引用的文件摘要不变，且两次 `artifact_root` 不同）。独立用例
`test_published_artifacts_survive_next_execution_of_same_plan` 通过。

### R08 退化路径不再让扫描抛错

`attempt_dynamic_reproduction` 把 `bind_candidate` 放进容错路径：身份不足记
`candidate_identity_unavailable` 后继续原有扫描；provider 返回非计划记 `plan_provider_invalid`；
provider 抛 `DynamicReproductionError`/其它异常记 `plan_provider_failed`；未知 provider kind 记
`plan_rejected`；**只有 `CancellationError` 继续向上传播**（关停语义不能被吞掉）。
产品测试 `test_incomplete_candidate_identity_never_fails_the_scan`（provider 断言不会被调用）、
独立用例 `test_missing_optional_candidate_identity_does_not_abort_scan_without_provider` 通过。

### R09 启动前取消与任务作用域的关闭释放

- `_run_once` 在 `Popen` 之前检查取消令牌，已取消则直接 `CancellationError`，不启动进程；
  循环中的取消仍然杀整个自有进程组。
- 新增 `release_dynamic_reproduction_authority(*, plan_digest="", binding_digest="")`（按任务/候选作用域释放，
  无参数调用是关停清空）与 `release_issue_dynamic_reproduction_authority(issue)`；产品代码
  `zscope/core/validation/runner.py` 在该候选确定性前置裁决完成后、失败路径与成功路径末尾调用后者，
  释放只覆盖本候选的能力，不影响同进程内其它并发任务。
- 产品测试：`test_already_cancelled_run_never_spawns_a_process`（Popen spy 断言零调用）、
  `test_authority_release_is_scoped_to_one_candidate`（释放 A 后 A 的 proof 失效、B 仍有效）。
  独立用例 `test_already_cancelled_execution_does_not_spawn` 通过；生命周期接线现在有真实调用点，不再是静态审查项。

### 资源边界（F06 剩余项）

- **输出总量**：spool 现在有**硬上限**。单流上限 `output_capture_limit_bytes`、两流合计每轮 ≤ 2×，
  轮询期间超限即杀进程组并记为 `output_capped`；无论被截断还是被杀，分类一律走
  `inconclusive/output_truncated_without_report`（`output_truncated_before_classification`），
  截断输出永远不会被读成“干净地未复现”。digest 只覆盖实际捕获的字节，发布复制只复制这些字节。
  产品测试 `test_output_cap_stops_a_chatty_run_and_is_never_a_clean_result`、
  `test_truncated_output_is_never_reported_as_not_reproduced`。
- **总 RSS**：新增采样看门狗 `_rss_exceeds(pid, limit_mb)`，按 `rss_poll_seconds`（默认 0.05s）读取
  `/proc/<pid>/status` 与该进程的 `_process_children`，越限即杀进程组，记录
  `classification="engine_failed:resource_exhaustion"`、`runs[i].oom_killed=True`、`rss_exceeded` /
  `memory_limit_enforced_by_rss_watchdog`、`memory_limit_total_rss_watchdog_applied`，
  `memory_limit_mode` 如实区分 `sanitizer_allocation_cap`（asan）、`rss_watchdog`（tsan）、`rlimit_as`、`none`。
  产品测试 `test_rss_watchdog_records_and_kills_a_memory_hog`（真实申请 400 MiB、上限 64 MiB 被终止）、
  `test_tsan_memory_limit_is_recorded_as_an_actual_bound`、
  `test_tsan_memory_limit_without_a_limit_is_reported_as_not_enforced`。
  诚实保留：这是**采样式总 RSS 边界**（有轮询间隔），不是内核 rlimit；asan 仍不能施加 `RLIMIT_AS`。
- **平台**：顶层 `resource` 改为可选导入（`_resource = None` 时记录未施加 rlimit），默认关闭路径不再
  因缺少 POSIX `resource` 而导入失败。产品测试
  `test_importing_the_runner_does_not_require_posix_resource`（子进程 meta_path 模拟缺模块）。
  该用例只证明导入边界，不外推为原生 Windows 实测。

## 二、把本轮边界用例迁入产品测试

除上列新增用例，下列独立边界也已在 `tests/test_dynamic_reproduction.py` 有等价产品断言
（独立文件原样保留，断言不弱化）：

| 独立边界 | 产品测试 |
| --- | --- |
| `test_filesystem_source_change_revokes_live_confirmation` | `test_confirmation_is_revoked_when_the_source_file_changes` |
| `test_each_execution_revalidates_current_files`（3 项） | `test_a_later_execution_refuses_when_a_verified_file_changed[...]`（3 项） |
| `test_build_cannot_change_verified_source_before_run` | 同名产品用例 |
| `test_untrusted_fake_replays_cannot_complete_production_confirmation` | 同名产品用例 |
| `test_every_primary_run_must_match_the_candidate` | 同名产品用例 |
| `test_default_product_entry_selects_tsan_provider` | `test_default_product_entry_dispatches_on_the_plan_provider_kind` |
| `test_execution_budget_counts_primary_and_independent_runs` | `test_scheduler_binds_the_shared_budget_to_the_provider` + `test_verification_budget_and_deadline_bound_real_process_starts` |
| `test_published_artifacts_survive_next_execution_of_same_plan` | `test_published_artifacts_are_never_overwritten_by_a_later_execution` |
| `test_missing_optional_candidate_identity_...` | `test_incomplete_candidate_identity_never_fails_the_scan` |
| `test_already_cancelled_execution_does_not_spawn` | `test_already_cancelled_run_never_spawns_a_process` |
| 缺少 POSIX `resource` 的平台模拟 | `test_importing_the_runner_does_not_require_posix_resource` |
| real-build 确认链（隔离脚本） | `test_asan_build_generated_binary_confirms_without_a_declared_digest`（真实编译，宿主 WSL） |

不存在被删除或放宽的旧断言；唯一被替换的旧用例是 `test_attempt_refuses_more_replays_than_the_plan_authorizes`
→ `test_attempt_clamps_replays_instead_of_refusing_before_dispatch`，替换原因是语义按 R06 修正为“不足即记录并截断，
不在派发前拒绝”，新用例断言更强（要求 provider 真的被派发且实际执行数受限）。

一处口径调整如实说明：作者自有用例 `test_truncated_output_is_never_reported_as_not_reproduced`
把 `stdout_bytes > 64` 改为 `stdout_bytes >= 64`，因为 spool 现在会在上限处**停止写入**（正是 R06 要求的硬上限），
字节数可能恰好等于上限……该用例的实质断言（截断标志、分类为未决、限制记录）一条未改，并新增更强的
`test_output_cap_stops_a_chatty_run_and_is_never_a_clean_result`（持续输出进程被上限停掉、且绝不记为干净未复现）。
独立验收脚本中的任何断言都未被改动或弱化。

## 三、复验命令与结果

命令、PATH、退出码与逐组 JUnit 计数见 [作者复验 JSON](V01-V02-r2-author-recheck-validation.json)；
真实 sanitizer 观测见 [执行观测](V01-V02-observed-execution.json)；冻结输入见
[工作区摘要](V01-V02-final-workspace.json)。文档收敛后按同一驱动重跑，要求 `changed_inputs == []`。

| 组 | 结果 | 口径 |
| --- | --- | --- |
| `tests/test_dynamic_reproduction.py` | 126 passed | 退出码 0 |
| 首轮独立负例（原样） | 25 passed | 断言未改 |
| 本轮独立边界（原样） | 16 passed / 0 failed | skipped 0 |
| 独立集成（原样） | 1 passed / 1 skipped | 真编译项在 `ZSCOPE_REVIEW_ISOLATED=1` 下 2 passed |
| `tests/test_dynamic_reproduction_execution.py` | 16 passed | 真实 clang 18.1.3 / ASAN |
| 兼容回归（77 文件，3 项重型 native deselected） | 1543 passed / 0 failed | 与验收驱动同集合同口径 |
| `tests/test_agent_docs.py` | 6 passed | 文档改动后 |
| `compileall -f -q zscope scripts test tests` | 退出码 0 | |
| `mypy zscope` | 307 source files，0 error | 独立 cache |
| `git diff --check`（Linux 侧，保留既有 CRLF 口径） | 退出码 0 | |
| 冻结输入摘要前后一致 | `changed_inputs == []` | 18 个文件，combined 见工作区摘要 |

隔离容器复验见 [作者容器复验 JSON](V01-V02-r2-author-container-recheck-validation.json)：
同一 pin 镜像、`--network=none --read-only --cap-drop=all --no-new-privileges --pids-limit=256 --memory=2g`
（预检断言 `CapEff=0`、`NoNewPrivs:1`、仅 `lo`、仓库只读、`memory.max=2147483648`、`pids.max=256`）。
容器内确定性专项 126 passed、原样首轮负例 25 passed、本轮独立边界 16 passed（含缺 `resource` 平台模拟）、
独立集成 1 passed / 1 skipped；真实 sanitizer 组 12 passed / 4 skipped，4 项跳过全部是
`tsan runtime unavailable (sanitizer_probe_failed)`，其中 ASAN 两项 build 用例（含**新的
build→重放→确认链**）在该隔离环境中通过——R04 的确认路径不再只在宿主通过。容器无 clang，ASAN 由镜像内
gcc 提供；容器隔离属验收基础设施，不计入产品能力。

## 四、仍未完成、不作声明

- **独立复验未做**：本轮是作者自验，G1 放行必须由独立验收给出；TASKS.yaml 中 V01 保持 `in_progress`、
  V02 保持 `blocked`。
- **隔离环境下的 TSAN 与真编译链**仍未在本机复跑成功（容器镜像无 clang，TSAN runtime 探测失败）；
  宿主 WSL 的通过结果不替代隔离 G3。
- **approved-plan provider 的 harness／输入生成器**仍未交付，序列化动态复现请求仍 `reserved_not_implemented`；
  本能力不自造计划，也不自动执行任意命令。
- **CBMC** 未实施（无工具，未安装替代品）。
- 未在真实第三方工程或 `test/range` 上执行；未改动其中 fixture 与 truth；无性能、收益或准确率结论。
- 未创建分支、未提交、未推送；HEAD 与分支不变。
