# V01 / V02 验收退回的修订回应（F01–F08）

- 日期：2026-10-09（Asia/Taipei）。用户请求：按 [独立验收报告](V01-V02-acceptance-review.md) 继续完善 V01/V02。
- 角色声明：本记录是**提交方对退回意见的修订回应与自验证据**，不是验收结论。V01 仍为 `in_progress`、V02 仍为 `blocked`；放行需要新的独立复验。
- 范围：保留既有实现与全部历史记录，只修订 `zscope/core/validation/dynamic_reproduction.py`、`zscope/core/validation/runner.py`（扫描接缝）、两个专项测试文件、`docs/modules/analysis-pipeline.md`、`docs/modules/configuration-state.md`，并新增本记录、作者自验脚本与作者容器复验脚本。未改 `test/range`、truth、既有历史记录、验收方脚本（[regressions](V01-V02-acceptance-regressions.py) `ac66899b…`、[driver](V01-V02-acceptance-driver.py) `b2110b23…`、[container](V01-V02-container-review.py) `5b5d3ae4…`）与本轮验收证据（`V01-V02-acceptance-validation.json`、`V01-V02-container-validation.json` 均未覆盖）；未切分支、未提交、未推送。
- 复验命令与结果：`records/V01-V02-author-recheck.py`（与验收 driver 同命令集、同输入摘要窗口，写入新文件名）→ [作者自验 JSON](V01-V02-author-recheck-validation.json)。冻结输入 18 个文件的执行前后摘要一致（`changed_inputs=[]`），combined `470e2722d7d4abf4fe1c3e02398cf219507feb5e1282fc905781901b00fcd867`。

## 1. 逐条回应

### F01 / P1：确认时没有重新绑定当前候选和源码身份 → 已修订

- 根因：登记只比较 4 个字段；裁决只比 UID 与 proof 里复制的旧 `code_hash`；`source_revision` 缺省还会退回 `dependency_code_hash`，使两个都来自旧 plan 的字符串可以自称 current。
- 修订：`CandidateBinding` 增加 `dependency_code_hash` 并引入 `digest()`（把 project、source revision、依赖内容 hash、对象、站点、缺陷族、构建配置、工具链全部纳入的完整身份摘要）与 `mismatched_fields()`；`register_dynamic_reproduction` 在任何字段不一致时抛 `plan_issue_identity_mismatch:<fields>`；`dynamic_witness_proof_is_live(proof, issue)` 在裁决时用**当前 issue** 重新派生绑定并逐字段比较，proof 的 `code_hash` 与授权身份的 `binding_digest` 都必须等于该摘要，任一不一致即撤回确认（不降级为部分匹配）。`source_revision` 不再回落到依赖 hash。
- 证据：`tests/test_dynamic_reproduction.py::test_acceptance_registration_rechecks_entire_candidate_binding`（5 项）、`::test_acceptance_adjudication_rejects_changed_current_identity`（8 项，含 project/source/dependency/object/site/defect/build/toolchain）全部通过；shadow 候选在 `rollout_visibility` 变化后即使持有 live proof 也失效（`test_shadow_candidate_stays_unconfirmed_after_rollout_change`）。

### F02 / P1：执行计划中的源码、输入与二进制身份没有真正核验 → 已修订

- 根因：只 hash 二进制，未核验 harness／inputs，也未保证 `run_argv[0]` 就是被核验的程序；`source_identity_bound` 只要求非空。
- 修订：`SanitizerReproductionRunner.authorization_problems(plan, workdir, require_binary=...)` 在**任何进程启动之前**重新读取文件系统：harness 必须存在且摘要等于声明、每个 `input_refs[i]` 必须存在且摘要等于 `input_digests[i]`、执行文件必须存在且摘要匹配、`run_argv[0]` 必须解析为同一个程序（realpath），且所有路径都必须落在显式授权的执行根内。任一失败返回 `unsupported/plan_identity_unverified`（`limitations` 列出具体原因 + `unverified_plan_never_launched`），不启动任何进程。声明“由本次 build 产出”二进制的 plan（`binary_digest=""` 且带 `BuildSpec`）改在 build 之后、运行之前核验其真实摘要，并记录 `binary_identity_bound_after_build`；若 build 后摘要与声明不符同样拒绝执行。
- 证据：`::test_acceptance_runner_checks_actual_inputs_before_launch`（harness／input／executable 三项，spy 未被调用）、`::test_declared_inputs_are_reverified_before_launch`、`::test_command_must_be_the_verified_binary`、`::test_stale_declared_binary_digest_stops_execution`、`::test_undeclared_exec_roots_authorize_nothing`；真实执行测试 `test_asan_stale_binary_reference_never_launches` 观测 `unsupported/plan_identity_unverified`、`runs=()`（见 [观测证据](V01-V02-observed-execution.json) 的 `asan_stale_binary`）。

### F03 / P1：同一行被无条件视为同一对象 → 已修订

- 根因：`match_witness_to_candidate` 在对象未匹配时用“同文件同行”兜底置 `candidate_object_matched=true`。
- 修订：删除该兜底。具名对象必须与候选对象 token 相同；匿名地址必须要求候选对象标识符出现在 sanitizer 帧中，否则返回未匹配并给出原因（`candidate_object_unmatched|_undeclared|_name_mismatch|_absent_from_frames`）。站点命中只证明站点，不再补造对象证明。
- 证据：`::test_acceptance_wrong_named_object_at_same_site_is_not_a_match`、`::test_wrong_named_object_at_same_site_is_not_a_match`、`::test_object_mismatch_...` 系列；真实执行测试 `test_asan_unrelated_crash_is_never_a_match` 观测 `candidate_site_mismatch`。

### F04 / P1：独立重放可被普通数据或不一致结果替代 → 已修订

- 根因：`ReplayEvidence` 无 live receipt，手工构造相同摘要与分类即可通过；`replay_witness` 只看“是否存在 finding”，把已判 inconclusive 的混合重放压成两次成功，也不校验每次执行的终态、对象与站点。
- 修订：`ReplayEvidence` 增加逐次 `runs`（index/outcome/classifications/findings/binary digest/execution token），`qualify_witness` **逐次**校验：必须有 live 的 `REPLAY_AUTHORITY` receipt（按对象身份登记，`entry.evidence is evidence`）、plan/binding/token 仍 live、每次执行的扁平分类集合必须等于主记录的集合、每次执行都必须是 `witness_observed`、且每次 finding 都必须通过完整候选匹配。任一不满足产生 `independent_replay_missing|replay_evidence_not_live|replay_run_without_witness|replay_run_non_deterministic|replay_run_witness_not_matching_candidate`。`ReplayEvidence.to_dict()` 不写出 execution token。
- 证据：`::test_acceptance_serialized_replay_claim_requires_live_execution_receipt`、`::test_acceptance_mixed_independent_replay_cannot_be_collapsed_to_success`、`::test_acceptance_independent_replay_for_other_site_cannot_confirm` 全部通过；真实执行测试 `test_tsan_flaky_fixture_distribution_is_recorded_and_never_forced` 观测到混合重放被判 `inconclusive/non_deterministic_replay` 且不产生确认。

### F05 / P1：live token 表示“跑过”却被当成“已通过确认资格” → 已修订

- 根因：所有执行（含无报告的成功运行）都签发 attestation，fake 也用生产授权表；授权表不记录资格，公共 proof 工厂无条件写全部确认 facts；token 写进普通 issue 的 `deterministic_proofs`，同进程 JSON 往返仍有效。
- 修订：拆成三个进程内注册表 —— `EXECUTION_AUTHORITY`（**执行真实性**，含 `TRUST_PRODUCTION|TRUST_TEST` 与 `inputs_verified`）、`REPLAY_AUTHORITY`（重放真实性，按证据对象身份）、`CONFIRMATION_AUTHORITY`（**确认能力**，按被签发的那个 proof 对象的身份登记，`entry.proof is proof`）。规则：真实生产 runner 登记 `TRUST_PRODUCTION`；fake／测试 runner 登记 `TRUST_TEST`，注册时只附加描述性证明（`outcome=inconclusive`、`completeness=incomplete`、`facts=[]`、`producer_trust=unauthorized`），因此 `proof_attached=True` 与“selector 接受确认”被彻底分开；只有完整资格通过且 `entry.production` 的执行才会 `mint` 确认能力。公共工厂 `dynamic_witness_proof_record(...)` 默认 `authorized=False`；不再把 token 写入普通 issue proof，只写 `witness_record_digest`。序列化副本（含同进程 JSON 往返）因对象身份不同而无权限；能力带 TTL 自动过期，`release_dynamic_reproduction_authority()` 用于关闭。设备/测试需要走确认路径时，唯一入口是显式 `inject_test_execution_authority(token, reason=...)`（要求理由、token 必须 live，且**全仓产品代码无调用**）。
- 证据：`::test_acceptance_clean_execution_cannot_be_given_unqualified_positive_proof`、`::test_acceptance_fake_provider_cannot_mint_production_confirmation`、`::test_acceptance_serialized_issue_has_no_authority_even_in_same_process`、`::test_qualified_witness_attaches_descriptive_proof_without_confirmation`、`::test_injected_test_authority_confirms_through_unified_adjudication`、`::test_test_authority_injection_is_explicit_and_never_in_product_code`（扫描 `zscope/` 中除定义模块外的所有文件，确认无调用）、`::test_authority_entries_expire_without_a_global_clear`。

### F06 / P1：隔离失败后仍执行，资源声明也不满足计划约束 → 已修订

- 修订：
  1. 隔离在 build **之前**决定，并对 build 与 run 使用同一前缀；请求 `user_net_namespace` 而探测失败时返回 `unsupported/requested_isolation_unavailable`（`limitations=requested_isolation_not_applied`），**不执行降级后的命令**。
  2. 执行根改为失败关闭：`_allowed_root` 对空 roots 一律不授权；run cwd、二进制目录、build cwd、harness、inputs 都必须落在显式授权根内。
  3. 资源声明如实：ASAN 不能施加 `RLIMIT_AS`（记 `rlimit_as_not_applied_to_sanitizer_runtime`），上限由 `ASAN_OPTIONS=max_allocation_size_mb` 施加并同时记录 `memory_limit_is_per_allocation_not_total_rss`；TSAN 记 `memory_limit_mode="none"` + `memory_limit_not_enforced_for_tsan`，不再声称 `rlimit_as`。
  4. 输出有界且如实：`output_capture_limit_bytes`（默认 4 MiB）限制保留前缀，但摘要对**完整文件**计算；被截断的运行标记 `output_truncated`、记 `output_truncated_before_classification`，并且**永不**被判为 `not_reproduced`（分类为 `inconclusive/output_truncated_without_report`）。
- 证据：`::test_acceptance_unavailable_requested_isolation_prevents_launch`、`::test_truncated_output_is_never_reported_as_not_reproduced`、`::test_undeclared_exec_roots_authorize_nothing`；真实执行测试 `test_asan_net_namespace_wrap_is_reported_truthfully`（本机实测 `net_namespace_applied`）、`test_tsan_memory_limit_is_recorded_as_not_enforced`（`memory_limit_mode=="none"`）、`test_asan_allocation_limit_stays_undecided`（`engine_failed/resource_exhaustion` 仍未决）。验收容器的隔离能力不属于产品 runner 能力，本记录不做此声明。

### F07 / P2：默认关闭未在执行边界强制，主扫描尚未调用新能力 → 已修订（计划生成器仍不在范围内）

- 已修订：`availability()` 在 disabled 时直接返回 `dynamic_reproduction_disabled`（不探测、不编译）；`execute()` 首先检查 `policy.enabled` 并抛 `dynamic_reproduction_disabled`；`register_dynamic_reproduction()` 与库级入口 `run_dynamic_reproduction()` 同样检查。`make_dynamic_reproduction_policy` 对未知/缺失取值失败关闭到 `off`。
- **扫描侧真实消费入口**：`ValidationRunner._attempt_dynamic_reproduction` 在确定性前置裁决之前调用 `attempt_dynamic_reproduction(issue, policy=...)`；策略来自 RuntimeSpec（默认 `off` ⇒ 立即返回、issue 一字不改）。`on`/`shadow` 时向进程内单槽的 approved-plan provider 取计划，取得后经 `run_dynamic_reproduction` 执行主 run + 必需次数的独立重放并交给 `register_dynamic_reproduction`，合格 witness 由既有 `apply_deterministic_prevalidation` 分支裁决。取消经既有 `CancellationToken` 传播（`cancelled` 记录、永不确认），进程组随取消终止；能力带 TTL，`release_dynamic_reproduction_authority()` 用于关闭。
- **明确不做的部分**：本能力**不自造计划**。没有 provider、provider 返回空、provider 抛错、计划过期、计划与当前候选不符、或计划授权的执行次数少于策略要求的复现次数时，只把原因写入 `dynamic_reproduction_attempt`（`no_plan_provider`／`no_plan_available`／`plan_provider_failed`／`plan_rejected`／`shadow_candidate_not_attempted`）并继续原有流程，不产生证明、不改变 disposition。harness／输入的计划生成器属后续工作包，`validator_protocol` 的序列化动态复现请求仍为 `reserved_not_implemented`；因此 V01/V02 **不**维持 `done`（V01 `in_progress`、V02 `blocked`）。
- 证据：`::test_acceptance_disabled_runner_never_launches`、`::test_disabled_availability_never_probes_the_toolchain`、`::test_run_dynamic_reproduction_refuses_disabled_and_stale_plans`、`::test_run_dynamic_reproduction_executes_replays_and_registers`、`::test_run_dynamic_reproduction_propagates_cancellation`、`::test_attempt_is_inert_when_disabled_and_leaves_the_issue_untouched`、`::test_attempt_records_why_no_plan_was_available`、`::test_attempt_never_touches_a_shadow_candidate`、`::test_attempt_rejects_a_stale_plan_without_breaking_the_scan`、`::test_attempt_refuses_more_replays_than_the_plan_authorizes`、`::test_attempt_consumes_an_approved_plan_through_unified_adjudication`、`::test_plan_provider_registry_is_explicit_and_process_local`、`::test_scan_hook_is_inert_by_default_and_executes_when_enabled`（off 时 issue 不变；on 且无 provider 时记 `no_plan_provider`；注册 provider 后真实执行 `/bin/sh`，`not_reproduced` 且确认/反证都为空）、`::test_scan_hook_policy_comes_from_the_runtime_config`。

### F08 / P2：默认执行记录不保留可审计的完整重放产物 → 已修订（无既有 immutable evidence store 可接入）

- 修订：`RunEvidence` 逐轮保存 index/outcome/detail/exit code/signal/timed out/OOM/分类/findings/stdout 与 stderr 摘要、字节数、截断标志与 artifact 路径；`ExecutionRecord.runs` 保留全部轮次。`_publish_artifacts` 在删除临时目录**之前**把 `run-<i>.stdout|.stderr`（以及 `build.*`）复制到 `policy.artifact_dir`，`artifact_refs` 与逐轮 `artifacts` 都是可解析的真实路径；未配置目录时记录 `execution_logs_not_published`，不把摘要当成定位。摘要始终对完整文件计算，摘录有界；预算耗尽（截断）可观察且判为未决。
- 边界：仓库中没有面向该执行路径的 immutable evidence store（`zscope/rules/qualification_evidence.py` 是规则治理用的 content-addressed 清单，不适用执行日志），本轮不新建第二套存储体系；发布目录为普通文件，只保证“逐轮可解析 + 内容摘要 + 截断如实”。
- 证据：`::test_run_records_per_run_evidence_and_published_artifacts`（artifact 文件真实存在、逐轮 ref 属于发布集合）、`::test_run_without_artifact_dir_says_logs_were_not_published`、`::test_truncated_output_is_never_reported_as_not_reproduced`；真实执行观测 `asan_positive` 的 `runs` 含 2 条逐轮记录（`stderr_bytes` 等）。

## 2. 负例迁移与新增真实执行负例

- 验收负例 [V01-V02-acceptance-regressions.py](V01-V02-acceptance-regressions.py) 的 25 项断言**逐条迁移**到 `tests/test_dynamic_reproduction.py` 的 “Migrated independent acceptance negatives” 区段（命名加 `acceptance_` 前缀），断言未删除、未弱化、未改 xfail；独立文件保持原样作为验收方产物。fake 的生产 authority 场景按报告要求改为显式受控注入（`inject_test_execution_authority`）。
- 另补真实执行负例/边界：无隔离即拒绝、截断未决、逐轮 artifact、TSAN 内存模式为 none、未声明执行根不授权、命令必须是被核验程序、stale plan 拒绝、取消不确认。

## 3. 本轮自验结果（作者自验，非验收结论）

| 组 | 命令 | 结果 |
| --- | --- | --- |
| 提交者专项单测 | `python -m pytest -q -p no:cacheprovider tests/test_dynamic_reproduction.py` | **109 passed**（exit 0） |
| 独立负例（原样文件，未改断言） | `python -m pytest -q -p no:cacheprovider records/V01-V02-acceptance-regressions.py` | **25 passed**（exit 0） |
| 真实 ASAN/TSAN 执行 | `tests/test_dynamic_reproduction_execution.py`，设置证据路径 | **13 passed / 0 skipped**（exit 0） |
| 兼容回归（同 driver 文件列表，3 项重型用例 not_run） | `pytest -k "not test_real_mutation_replay and not test_real_direct_bitcode_dependency_cache_and_svf and not test_native_code_to_real_terminal_tool_workbook_and_pool_consumers"` | **1539 passed / 0 failed / 0 skipped**（exit 0） |
| 质量门禁 | `tests/test_agent_docs.py`；`compileall -f -q`；`mypy zscope`；`git -c core.whitespace=... diff --check` | **6 passed**；exit 0；`Success: no issues found in 307 source files`；exit 0 |

执行窗口前后输入摘要一致（`changed_inputs=[]`），冻结 18 个文件的 combined 与声明一致（`frozen_combined_matches=true`）。逐项命令、退出码、耗时与 JUnit 计数见 [作者自验 JSON](V01-V02-author-recheck-validation.json)。

真实执行观测（本机 WSL，clang 18.1.3）：ASAN 正例 `witness_observed/sanitizer_report` 且经统一裁决确认；ASAN 反例 `not_reproduced`（无 reject proof）；无关 crash 因对象/站点不符永不确认；stale binary 与未核验输入 `unsupported/plan_identity_unverified` 且 `runs=0`；请求 `user_net_namespace` 实测生效；TSAN 正例确认、反例未复现、flaky 样本逐次记录且混合重放判未决、`memory_limit_mode=none`；取消返回 `cancelled`。证据见 [观测记录](V01-V02-observed-execution.json)（sha256 `fccfc43a0477519ad809a89463bf6c6d04b5a27b291ebc608d72abfcf531dd41`）。

在外层隔离容器中重跑（同一 pin 镜像 `python@sha256:de8ba566…`，`--pull=never --network=none --read-only --userns=keep-id --cap-drop=all --security-opt=no-new-privileges --pids-limit=256 --memory=2g --cpus=2`，探针实测 `interfaces=["lo"]`、`repo_readonly=true`、`CapEff=0`、`NoNewPrivs=1`、`memory.max=2147483648`、`pids.max=256`、无 clang（gcc 14.2.0）；**容器隔离归属验收基础设施，不计入 V01/V02 能力**）：

| 组 | 容器内结果 |
| --- | --- |
| `tests/test_dynamic_reproduction_execution.py` | **9 passed / 4 skipped**（该镜像内 TSAN runtime 探测失败 `sanitizer_probe_failed`，故 4 项 TSAN 用例 not_run；ASAN 全跑） |
| `records/V01-V02-acceptance-regressions.py`（原样） | **25 passed / 0 failed** |
| `tests/test_dynamic_reproduction.py` | **109 passed / 0 failed** |

脚本与逐条命令、stdout/stderr、退出码、JUnit 计数见 [作者容器复验 JSON](V01-V02-author-container-recheck-validation.json)（新文件名，未覆盖验收方 `V01-V02-container-validation.json`）。首轮容器尝试把 `--basetemp` 放到 `/work`，验收 harness 的 `_plan` 使用宿主默认执行根（`/bin`、`/usr/bin`、`/tmp`、fixture 目录），因此 `test_clean_execution_cannot_be_given_unqualified_positive_proof` 得到 `unsupported` 而非 `not_reproduced` —— 这是工作目录未授权时的失败关闭行为，不是产品缺陷；把 basetemp 改到容器 tmpfs 内后 25/25 通过。该更正已记入容器 JSON 的 `corrections` 字段，不隐藏首轮结果。

## 4. 冻结输入

18 个文件（产品代码、配置、测试与 fixture；`zscope/core/validation/runner.py` 因扫描接缝由本轮加入），执行前后摘要一致，公式与逐文件摘要见 [工作区摘要](V01-V02-final-workspace.json)：

```
combined: 470e2722d7d4abf4fe1c3e02398cf219507feb5e1282fc905781901b00fcd867
```

## 5. 未执行 / not_run

- **独立复验未做**：本记录与容器复验都是提交方自验；G1/G2/G3 的独立结论仍需验收方重跑，本记录不代替，V01/V02 不标记 `done`。
- **计划生成器未交付**：扫描接缝已接通（`ValidationRunner._attempt_dynamic_reproduction` → `attempt_dynamic_reproduction` → `run_dynamic_reproduction`），但没有 provider 时它**不自造 harness／输入计划**，只记 `no_plan_provider`／`no_plan_available`；`validator_protocol` 的序列化动态复现请求仍为 `reserved_not_implemented`（见 F07）。
- **容器内 TSAN 仍未跑成**：该镜像 TSAN runtime 探测失败（`sanitizer_probe_failed`），4 项 TSAN 用例在容器内 not_run；TSAN 真实结论只来自本机 WSL（clang 18.1.3），不作为容器隔离下的 G3 背书。
- **CBMC 未实施**：工具缺失，禁止安装替代品，无 harness/外部模型/循环边界定义。
- **未做性能、收益或第三方工程结论**；未改 `test/range` 与 truth；未切分支、未提交、未推送。
