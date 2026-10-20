# V02 扩展 TSAN 验证适配结果记录

> **2026-10-09 修订更新**：本记录的完成声明已被 [独立验收报告](V01-V02-acceptance-review.md) 退回（F01–F08，V02 因依赖 V01 保持 `blocked`）。修订与作者自验见 [修订回应](V01-V02-acceptance-response.md)。以下正文保留为**历史声明**；现状补充：TSAN 仍复用 V01 runner，但执行记录为 `zscope.dynamic-execution-record.v2`，内存上限如实记为 `memory_limit_mode="none"`（TSAN 不施加内存限制），重放逐次留证，且本机 WSL 的 TSAN 13 项真实验证**不**重新背书 G3 —— G3 需在获准隔离环境且工具链可用时重跑，验收容器内 TSAN `sanitizer_probe_failed` 保持 not_run。

- 任务：V02 扩展 TSAN／CBMC 验证适配（M4 / P2，code_map CM06、CM09，acceptance AC06、AC11、AC15、AC18）
- 上位文档：`WORK_PACKAGES.md` (V02)、`CODE_MAP.md` (CM06/CM09)、`ACCEPTANCE.md`、`DECISIONS.md`
- implementation_status：TSAN 分支完成并复用 V01 的 runner、执行记录与独立重放；**CBMC 分支未实施**（`cbmc`／`goto-cc` 不在环境中，任务禁止安装替代品，harness／外部模型／循环边界未定义）。
- verification_status：通过（TSAN 范围）。真实 TSAN 执行覆盖正例、反例、非确定性触发与混合重放；确定性用例另覆盖工具不支持、错误对象／身份、超时、取消。相关回归与质量门禁与 V01 同窗口通过。
- 结论：V02 验收清单（复用 runner／记录／重放、独立 TSAN 构建、不与 ASAN 混用、正例、反例、非确定性触发、工具不支持、错误对象／版本、超时、取消）全部满足；CBMC 分支保持未实施，不得据此声称 CBMC 能力。
- 更新的文件：`TASKS.yaml` V02 由 `deferred` 改为 `done`，`result_record` 指向本文件；历史记录 [V02-deferred.md](V02-deferred.md) 保留为过程史。

## 1. 交付物

V02 没有新增独立模块，全部实现位于 `zscope/core/validation/dynamic_reproduction.py`（V01 已交付），以 provider 维度扩展：

| 组成 | 说明 |
| --- | --- |
| `TsanReproductionRunner` | `kind="tsan"`，独立编译参数（`-fsanitize=thread -g -O0 -pthread`）、独立运行时选项、独立报告解析 |
| `parse_tsan_report` | 提取 `data-race` 分类、读写访问类型、线程、全局对象名与访问栈；无帧的报告块被丢弃 |
| `match_witness_to_candidate` | TSAN 分支按对象名／站点／缺陷族匹配，族匹配表包含 `race_without_happens_before` 与 `data-race` |
| `data_race_positive.c` / `data_race_negative.c` / `data_race_flaky.c` | 真实 TSAN fixture：正例、反例、计时相关样本 |
| `tests/test_dynamic_reproduction_execution.py` | TSAN 真实执行用例（正例、反例、非确定性分布与混合重放） |
| `tests/test_dynamic_reproduction.py` | TSAN 解析、族匹配、工具不支持、超时与取消的确定性用例 |

## 2. 关键实现决定

1. **复用 V01 闭环，不新开链路。** TSAN 与 ASAN 共用 `ExecutionPlan`／`ExecutionRecord`／`ReplayEvidence`／attestation／`register_dynamic_reproduction`；差异只在 provider kind、编译参数、运行时选项与解析器。TSAN witness 同样只能经 `dynamic_witness_candidate_match` 确认，从不产生反证。
2. **ASAN 与 TSAN 严格不混用。** 两者从不链接到同一二进制：`COMPILER_FLAGS` 按 kind 分离；provider 与 plan 的 kind 必须一致，否则抛 `provider_plan_kind_mismatch`；TSAN 记录带 `memory_limit_not_enforced_for_tsan`，不把 ASAN 的内存上限结论套到 TSAN。
3. **移植性退回路径已知但本轮未触发。** clang 18.1.3 在本机可直接运行 TSAN，未出现 `unexpected memory mapping`；若出现，已知退回方式是 `setarch -R`。本轮不隐藏该条件，也不把未触发的路径写成已验证。
4. **非确定性必须实测，不能假设。** 计时相关样本的判定完全交给真实重放：单次运行的分类集合可以混合，只要记录内的重放分类不一致就判 `inconclusive`／`non_deterministic_replay`，不确认候选。fixture 的窗口参数来自本机实测，而非猜测。
5. **工具不支持是环境事实，不是否定。** 编译工具或 sanitizer 运行时缺失时 provider 返回 `unsupported`，映射为 `inconclusive`；缺工具的 skip 不记为通过。

## 3. 真实 TSAN 执行证据

```
ZSCOPE_DYNAMIC_REPRODUCTION_EVIDENCE=docs/handoffs/2026-10-08-zscope/records/V01-V02-observed-execution.json \
  python -m pytest -q -p no:cacheprovider tests/test_dynamic_reproduction_execution.py
12 passed in 7.21s            (exit 0)
```

| 观测项 | outcome / detail | 说明 |
| --- | --- | --- |
| `tsan_positive` | `witness_observed` / `sanitizer_report` | 重放分类 `data-race｜data-race`，两次一致，经统一裁决确认 |
| `tsan_negative` | `not_reproduced` / `no_sanitizer_report` | 无报告；不产生 reject proof |
| `tsan_flaky`（10 次单跑） | 分类 `none`×7、`data-race`×3 | 真实混合分布，`observed_non_deterministic=true`；断言只要求取值属于允许集合 |
| `tsan_flaky_multi_replay`（8 次真实重放） | `inconclusive` / `non_deterministic_replay` | 分类 `data-race,data-race,none×6`；`replay_consistent=false`，候选保持未确认 |

非确定性 fixture 的窗口由实测选定（20 次单跑每组，clang 18.1.3 / TSAN / `-O0`）：

```
setter=500us  reader=500us   ->  5/20 报告
setter=500us  reader=1000us  ->  7/20 报告   (提交值)
setter=1000us reader=500us   ->  0/20 报告
setter=2000us reader=1500us  ->  0/20 报告
```

两个窗口都是墙钟时间，因此换机器只改变比例、不固定结果；这正是 runner 必须容忍的情形。窗口参数、测量表与理由写在 fixture 头部注释中。

## 4. 确定性覆盖（TSAN 相关）

- 报告解析：`test_parse_tsan_report_extracts_data_race_and_object`、`test_parse_sanitizer_report_dispatches_by_provider_kind`、`test_report_text_that_only_mentions_the_error_word_is_not_a_finding`。
- 缺陷族匹配：`test_family_matching`（含 `race_without_happens_before` 与 sanitizer 分类的接受标记子集规则）、`test_wrong_defect_family_is_not_qualified`、`test_wrong_object_and_site_report_is_not_qualified`。
- 身份／版本漂移：`test_plan_digest_binds_every_reproducible_identity`、`test_binding_requires_complete_candidate_identity`、`test_record_for_another_plan_is_never_qualified`、`test_stale_binary_digest_is_not_qualified`、`test_stale_declared_binary_digest_stops_execution`（真实执行中另以错误声明摘要覆盖 `binary_identity_mismatch`）。
- 工具不支持：`test_missing_build_tool_is_unsupported_not_a_refutation`、`test_provider_availability_probes_the_compiler_instead_of_assuming_it`。
- 超时／取消：`test_timeout_kills_the_owned_process_tree`、`test_cancellation_kills_only_the_owned_process_tree`、`test_cancelled_record_is_undecided`。
- 重放与未决：`test_missing_independent_replay_blocks_confirmation`、`test_inconsistent_replay_blocks_confirmation`、`test_undecided_outcomes_never_confirm_or_reject`（含 `not_reproduced`／`inconclusive`／`timeout`／OOM／build-failed／unsupported）。

## 5. 验证汇总

| 项 | 结果 |
| --- | --- |
| 专项确定性（含 TSAN 解析与门禁） | 62 passed，exit 0 |
| 真实 sanitizer 执行（ASAN + TSAN） | 12 passed，exit 0 |
| RuntimeSpec 接线与公共配置边界 | 89 passed，exit 0 |
| 相关回归（8 组，含 shadow／Ledger／tools-MCP／Java） | 1339 passed、2 skipped、0 failed |
| `compileall` / `mypy` / `test_agent_docs.py` / `diff --check` | exit 0；mypy 307 source files；docs 6 passed |
| 冻结输入窗口 | 18 文件摘要前后一致，combined `bb66f04b89ab3ccbcd2b92dd3f2dd73c299cc7700c26f1cc295ec94296a46980` |

证据文件 `records/V01-V02-observed-execution.json` sha256 `b0c70730a21c85eba068cbb6cab87e7b976ac09bc87218723517050e2a6373c7`（与 V01 同一次执行窗口）。

## 6. 未执行 / not_run

- **CBMC 分支未实施**：工具缺失且不得安装替代品；harness、外部模型与循环边界均未定义。任何 CBMC 能力声明都无效。
- **锁与访问栈的完整重放未验证**：解析器提取线程、对象名与访问栈，但没有构造真实锁语义或多线程交错的重放测试。
- **未在真实第三方工程上运行 TSAN**：只用新建最小 fixture；未修改 `test/range` 的植入样本与 truth。
- **未做性能、收益或准确率结论**；未提交、未推送。

## 7. 复现命令

```bash
export PATH=/home/zeal/venv313/bin:/usr/lib/llvm-18/bin:$PATH
cd <repo>
python -m pytest -q -p no:cacheprovider tests/test_dynamic_reproduction.py
ZSCOPE_DYNAMIC_REPRODUCTION_EVIDENCE=docs/handoffs/2026-10-08-zscope/records/V01-V02-observed-execution.json \
  python -m pytest -q -p no:cacheprovider tests/test_dynamic_reproduction_execution.py
```

TSAN 单次运行会有比例波动，因此非确定性用例不断言固定比例，只断言取值合法、混合重放必须未决且不得确认。
