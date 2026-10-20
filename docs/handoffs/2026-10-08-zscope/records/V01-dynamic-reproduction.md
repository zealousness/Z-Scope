# V01 受控动态复现最小闭环（ASAN）结果记录

> **2026-10-09 修订更新**：本记录的完成声明已被 [独立验收报告](V01-V02-acceptance-review.md) 退回（F01–F08）。修订与作者自验见 [修订回应](V01-V02-acceptance-response.md)；V01 在 TASKS.yaml 中为 `in_progress`，本记录以下正文（含 62/12 计数、`_WitnessAuthority`、`dynamic_execution_record.v1`、18 文件等描述）保留为**历史声明**，不再代表当前实现：现状是 `zscope.dynamic-execution-record.v2`、三个进程内注册表（执行／重放／确认）、`CandidateBinding.digest()` 完整身份、执行前实际输入核验、逐轮重放证据与 artifact 发布、以及扫描侧 `ValidationRunner._attempt_dynamic_reproduction` → `attempt_dynamic_reproduction` 的 approved-plan 接缝（`off` 时不改动 issue；无 provider 时不自造计划）。冻结文件数最初为 **17**，加入 `zscope/core/validation/runner.py` 后为 **18**（原文称 18 但只列 17，已更正）。

- 任务：V01 ASAN 可执行验证最小闭环（M3 / P1，code_map CM06、CM09，acceptance AC06、AC10、AC11、AC17、AC18）
- 上位文档：`WORK_PACKAGES.md` (V01)、`CODE_MAP.md` (CM06/CM09)、`ACCEPTANCE.md`、`DECISIONS.md`
- implementation_status：完成。provider 协议、执行计划、执行记录、fake runner、真实 ASAN runner 与统一裁决接线均已实现并保持默认关闭。
- verification_status：通过。专项确定性测试 62 passed；真实 ASAN 执行 12 passed；相关回归 1339 passed / 2 skipped / 0 failed；质量门禁全部 exit 0；冻结输入前后摘要一致。
- 结论：V01 的必需实现与真实执行验收已满足，V02（TSAN）解锁并已交付，见 [V02 记录](V02-dynamic-reproduction.md)。
- 更新的文件：`TASKS.yaml` V01 由 `blocked` 改为 `done`，`result_record` 指向本文件；历史阻塞记录 [V01-blocked.md](V01-blocked.md) 保留为过程史，不再代表当前状态。

## 1. 交付物

| 文件 | 角色 |
| --- | --- |
| `zscope/core/validation/dynamic_reproduction.py` | 新增模块。provider 协议（plan/record/replay/availability/witness）、`_WitnessAuthority` 进程内授权、ASAN/TSAN 报告解析与候选匹配、`SanitizerReproductionRunner` 及其子类、fake runner、`qualify_witness`、`register_dynamic_reproduction` |
| `zscope/core/validation/proofs.py` | 确认表新增 `dynamic_witness_candidate_match`；`deterministic_decision_proof` 对该 kind 追加 live attestation 门禁 |
| `zscope/config/config.py` | `AnalysisConfig` 新增 6 个 `dynamic_reproduction_*` 字段及 `__post_init__` 严格校验 |
| `zscope/config/v2.py` | RuntimeSpec 键白名单与类型化 loader（6 个键） |
| `zscope/config/runtime_defaults.yaml` | 6 个键的随包默认值，`dynamic_reproduction_mode: "off"` |
| `tests/test_dynamic_reproduction.py` | 新增，62 项确定性测试（含配置门禁、身份漂移、伪造日志、重放与取消） |
| `tests/test_dynamic_reproduction_execution.py` | 新增，12 项真实编译与 sanitizer 执行测试（另 1 项仅在显式设置证据路径时运行） |
| `tests/test_investigation_runtime.py` | 追加 V01 的 RuntimeSpec 门禁与公共配置边界测试 |
| `tests/fixtures/dynamic_reproduction/` | 新增独立最小 fixture（README + 8 个 C 样本） |
| `docs/modules/analysis-pipeline.md`、`configuration-state.md` | 数据流、不变量与内部开关说明 |
| `records/V01-V02-observed-execution.json` | 真实执行证据（由执行测试在显式设置路径时写出的观测记录） |

未新增产品终态体系：候选身份仍为 `zscope.candidate.v3.4`，结果协议仍为 `zscope.validator-result.v3`，报告与抑制路径不变。

## 2. 关键实现决定

1. **复用既有协议，不另立终态。** `zscope/common/validator_protocol.py` 中预留的 `DYNAMIC_REPRODUCTION_REQUEST_VERSION`／`DYNAMIC_REPRODUCTION_RESULT_VERSION` 继续作为请求／结果协议版本；执行细节以 `dynamic_execution_plan.v1`／`dynamic_execution_record.v1` 表达，不引入新的报告格式。
2. **确认通道只经 `deterministic_decision_proof`。** 动态 witness 以确认 proof kind `dynamic_witness_candidate_match` 进入统一裁决；`ValidationPipeline.apply_deterministic_prevalidation` 的既有确认分支与 `promotion_reason` 语义未改。现有仅用于反证的 `deterministic_proof_verifier` 回调没有被改作确认通道。
3. **默认关闭且惰性。** `dynamic_reproduction_mode` 默认 `off`：不编译、不执行、不注册授权，仅读取一个配置字段。`shadow` 执行并登记 provider 元数据但显式附加 `shadow_mode_proof_not_attached`，不授予确认权限；`on` 才允许合格 witness 进入确认。未知取值按 `off` 处理并记入结果说明。
4. **身份绑定在计划层。** `ExecutionPlan` 绑定 project、source revision、候选对象／站点／缺陷族、build 配置、toolchain、harness argv、输入摘要和二进制 digest。结构性不一致（plan 与 issue 身份不符）直接抛 `plan_issue_identity_mismatch:<fields>`；证据层问题（声明 digest 与真实二进制不符、站点／缺陷族不匹配、重放不一致、记录未获 attestation）只产生未决结果，绝不产生反证。
5. **确认权限留在进程内。** `_WitnessAuthority` 只存在于当前进程，token 从不序列化；`deterministic_decision_proof` 对 `dynamic_witness_candidate_match` 额外校验 live token、记录摘要、`code_hash` 与 plan 绑定摘要一致、以及 proof 的候选 UID 与 `bind_candidate(issue)` 一致。序列化日志、内容 hash 或模型自报结果都不能恢复确认权限；进程重启后同一 proof 失效。
6. **未决不是否定。** `not_reproduced`、`inconclusive`、`engine_failed`、`unsupported`、`cancelled` 都不构成安全反证：provider outcome 到 `DYNAMIC_REPRODUCTION_RESULT_VERSION` 的映射保持 `reproduced|not_reproduced|inconclusive|failed`，取消与工具不支持映射为 `inconclusive`。
7. **shadow 候选隔离。** 新模块的 `is_shadow_candidate`／`bind_candidate` 与 `ValidationPipeline._is_rollout_shadow_candidate` 语义对齐并有交叉断言测试；即使持有 live proof，shadow 候选仍保持 `shadow_observation`、`report_bucket=None`，K01 相关发现隔离不变。
8. **执行边界如实记录。** 每次执行使用 `start_new_session=True` 的独立进程组，取消／超时按组终止（只终止本任务拥有的进程）；`unshare --user --map-root-user --net` 只在真实探测成功后应用并记 `net_namespace_applied`；`isolation_notes` 恒定写入 `subprocess_is_not_a_container_sandbox`，不把普通子进程说成容器沙箱。
9. **内存限制不得伪装。** ASAN 运行时需要巨大虚拟地址空间，`RLIMIT_AS` 不能施加于 sanitizer 进程，因此内存上限通过 `ASAN_OPTIONS=max_allocation_size_mb=<mb>` 施加，并在 `limitations` 中同时记录 `rlimit_as_not_applied_to_sanitizer_runtime` 与 `memory_limit_enforced_by_sanitizer_allocation_cap`。

## 3. 必须保持的不变量

- 只有与候选对象、站点和缺陷族都相符、且通过身份与二进制校验的受控 witness 才能确认原候选；无关 crash 不得确认原候选，也不得否定它。
- 未复现、超时、OOM、构建失败、工具不可用、取消一律保持未决；`not_reproduced` 永远不是反证，不进入任何 reject proof。
- 确认权限不可从磁盘恢复：proof 的 live attestation、plan 绑定摘要与候选 UID 三者缺一不可。
- `off` 模式下不产生编译、执行、授权或额外报告字段；公共 Config v2 不新增字段，`dynamic_reproduction_*` 只能经 RuntimeSpec 内部覆盖。
- 动态复现不改变六工具名称、Clang AST+SVF 主链、候选冻结和统一裁决，也不让 shadow 候选进入默认确认结果。

## 4. 验证证据

### 4.1 专项确定性测试

```
python -m pytest -q -p no:cacheprovider tests/test_dynamic_reproduction.py
62 passed in 4.22s            (exit 0)
```

覆盖：默认关闭与配置门禁（off/shadow/on、非法模式与非法隔离拒绝）、身份绑定（逐字段摘要漂移、不完整绑定、plan↔issue 不一致、plan↔record 不一致）、合格 witness 经 `apply_deterministic_prevalidation` 确认、shadow 模式只登记元数据、shadow 候选拒绝与流水线隔离（持有 live proof 仍不晋升）、错误对象／站点／缺陷族、过期二进制、手工构造与 `attest=False` 的伪造记录、手写 proof 被拒、`witness_authority_clear` 与序列化后权限失效、重指向或编辑 live proof 后失效、未决 outcome 参数化（not_reproduced／inconclusive／timeout／OOM／build-failed／unsupported）、重放缺失与不一致、真实 `/bin/sh` 进程组超时与取消（标记文件不存在、`detail.startswith("cancelled")`、`process_group_isolated`）、执行根拒绝、工具缺失→`unsupported`、provider 与 plan kind 不匹配、记录校验、ASAN/TSAN 解析样本、`families_match` 对照表、fixture 完整性、`WITNESS_AUTHORITY.live_count`。

### 4.2 真实编译与 sanitizer 执行

```
ZSCOPE_DYNAMIC_REPRODUCTION_EVIDENCE=docs/handoffs/2026-10-08-zscope/records/V01-V02-observed-execution.json \
  python -m pytest -q -p no:cacheprovider tests/test_dynamic_reproduction_execution.py
12 passed in 7.21s            (exit 0)
```

| 观测项 | outcome / detail | 说明 |
| --- | --- | --- |
| `asan_positive` | `witness_observed` / `sanitizer_report` | 重放分类 `heap-buffer-overflow｜heap-buffer-overflow`；站点命中 fixture 标记行 19；经统一裁决确认 |
| `asan_build` | `witness_observed` / `sanitizer_report` | 由 runner 自己执行 `BuildSpec` 编译，再计算真实二进制摘要 |
| `asan_namespace` | `witness_observed` / `sanitizer_report` | `isolation=user_net_namespace`、`isolation_verified=true`、`net_namespace_applied` |
| `asan_unrelated` | `witness_observed` / `sanitizer_report` | 报告存在但函数／站点与候选不符，`candidate_site_mismatch`，永不确认 |
| `asan_negative` | `not_reproduced` / `no_sanitizer_report` | 两次重放均为 `none`；不产生 reject proof |
| `asan_build_failure` | `engine_failed` / `build_failed` | 编译失败不等于复现失败，保持未决 |
| `asan_allocation_limit` | `engine_failed` / `resource_exhaustion` | 超过 `max_allocation_size_mb` 上限 |
| `asan_stale_binary` | `engine_failed` / `binary_identity_mismatch` | 计划声明摘要与真实二进制不符 |

证据文件摘要：`records/V01-V02-observed-execution.json`，sha256 `b0c70730a21c85eba068cbb6cab87e7b976ac09bc87218723517050e2a6373c7`。该文件只在显式设置 `ZSCOPE_DYNAMIC_REPRODUCTION_EVIDENCE` 时写出，普通 pytest 运行不会写入仓库。

### 4.3 执行环境与隔离实测

- 在真实测试进程内确认：`python 3.13.15`（`/home/zeal/venv313/bin/python`）、`clang` 18.1.3（`/usr/lib/llvm-18/bin/clang`）、`gcc`、`unshare`、`setarch`；ASAN 与 TSAN 均通过真实编译＋运行探测得到 `{'available': True}`。
- `unshare --user --map-root-user --net -- true` 返回 0，因此命名空间包装实际生效；执行记录写明实际施加的边界，并明确普通子进程不等于容器沙箱。
- 每次测试使用自己的临时工程、构建目录和 DB；真实编译与 sanitizer 执行只有一路。

### 4.4 相关回归

| 分组 | 结果 |
| --- | --- |
| validation-core（12 文件） | 238 passed，exit 0 |
| review-and-proofs（14 文件） | 213 passed、1 skipped，exit 0 |
| ledger-and-candidates（7 文件） | 90 passed，exit 0 |
| shadow-rollout-and-investigation（12 文件） | 410 passed，exit 0 |
| tools-and-mcp（9 文件） | 103 passed，exit 0 |
| java-backends（8 文件） | 77 passed，exit 0 |
| config-and-docs（9 文件） | 135 passed，exit 0 |
| dynamic-reproduction（2 文件） | 73 passed、1 skipped，exit 0 |

合计 **1339 passed、2 skipped、0 failed**。两个 skipped 分别是既有的 review 跳过项与证据导出用例（未设置证据路径时不写出仓库文件），不是本轮通过。

### 4.5 质量门禁（冻结窗口内）

| 命令 | 结果 |
| --- | --- |
| `python -m compileall -f -q zscope scripts test tests` | exit 0 |
| `python -m mypy zscope` | `Success: no issues found in 307 source files`，exit 0 |
| `python -m pytest -q tests/test_agent_docs.py` | 6 passed，exit 0 |
| `git -c core.whitespace=blank-at-eol,blank-at-eof,space-before-tab,cr-at-eol diff --check` | exit 0 |
| `tests/test_investigation_runtime.py` + `tests/test_config_v2.py` | 89 passed，exit 0 |

### 4.6 冻结输入摘要

冻结集为产品代码、配置、测试与 fixture；记录文件本身是产出，不参与冻结。执行窗口开始与结束后两次计算，18 个文件逐一摘要相同，合并摘要一致：

```
7f60a13d91216f3450e2a8da4a1bf7008fba43b264325dae11a65ec2c1fa5841  zscope/core/validation/dynamic_reproduction.py
3c1cdef9476f91feb99cb1d95983cc271bd2512b4ad486157dd1a8e190b7c119  zscope/core/validation/proofs.py
2bf751767bbfb8effd5bc7f048005cde7dba4435329ea82effb1f60926eb0f7c  zscope/config/config.py
b4f77d7fd376376cd9ebd0ebbba0823eee17f50146a38de5db8668fa59275ade  zscope/config/v2.py
7cfb5f643446227d99cabf307f34de04ba2ad611c32948562b7d9d35eaeb065d  zscope/config/runtime_defaults.yaml
7a2d5d12ea2b31cc5347a1dfcbc2710aaa587880c087c8130128d822316fcc9b  tests/test_dynamic_reproduction.py
99160be6fd58f86dafb6c121a306749affef6aef9305fffc9055834f0404f891  tests/test_dynamic_reproduction_execution.py
0ea447c82181752cc0996b9e93395a4e203f8028558dbb63ef49a8d92ffa144b  tests/test_investigation_runtime.py
0e7061a5ae90b5c580a43edc82f3750862e7ed133d3384a4ef3fc6162adae84f  tests/fixtures/dynamic_reproduction/README.md
bf489e01279b1297f922a1326603c83cb8e11119768b23c4c3fcfda4a5fffb3d  tests/fixtures/dynamic_reproduction/allocation_oversize.c
800c7ec64cc272fce99737f340e5b4d6f4c749d48746b808c6c142b3479af944  tests/fixtures/dynamic_reproduction/broken_build.c
db4fb375995e08b9c1415f024f4e97193473033275c6100daadf0f34cad8b137  tests/fixtures/dynamic_reproduction/data_race_flaky.c
f391d00de333904e60cb99f3c0d97939568db190530f3614b940ac8cae80b133  tests/fixtures/dynamic_reproduction/data_race_negative.c
d0bdb615fd46f35eb53858a121b16f1045d0850b89d9cbcdcde2cc1881416865  tests/fixtures/dynamic_reproduction/data_race_positive.c
e1099d8ac99f49975294a4b7345f016593e7b483c8fdf0126e69fbb696dc16f6  tests/fixtures/dynamic_reproduction/heap_overflow_negative.c
85685a7ac23bb653a51ae0333bae9687f0afac998d57e110f7b2ccbd21ab26fc  tests/fixtures/dynamic_reproduction/heap_overflow_positive.c
89772514029c32e42538f5ae881503b3624ec9063d8ecfcf565bfe935e59ff1b  tests/fixtures/dynamic_reproduction/unrelated_crash.c
combined: bb66f04b89ab3ccbcd2b92dd3f2dd73c299cc7700c26f1cc295ec94296a46980
```

## 5. 未执行 / not_run

- **CBMC 分支未实施**：`cbmc`／`goto-cc` 不在环境中，且任务明确禁止安装替代品；harness、外部模型与循环边界均未定义。该分支不属于 V01。
- **真实容器隔离未验证**：`user_net_namespace` 已实测生效，但没有验证 seccomp、只读根文件系统或 CPU／磁盘配额；执行记录只声明进程组与命名空间边界。
- **未在真实第三方工程上执行**：本轮只使用本任务新建的最小 fixture，未对 `test/range` 或用户工程编译执行，未修改其中的植入缺陷与 truth。
- **未做性能或收益结论**：没有测量复现耗时对扫描总时长的影响，也没有把动态复现计入准确率或收益声明。
- **未运行正式 Range／portable／真实模型**：均为 not_run，与本任务无关，不作为通过依据。
- **未提交**：没有创建分支、提交或推送；实现保留为工作区增量。

## 6. 复现命令

```bash
export PATH=/home/zeal/venv313/bin:/usr/lib/llvm-18/bin:$PATH
cd <repo>
python -m pytest -q -p no:cacheprovider tests/test_dynamic_reproduction.py
ZSCOPE_DYNAMIC_REPRODUCTION_EVIDENCE=docs/handoffs/2026-10-08-zscope/records/V01-V02-observed-execution.json \
  python -m pytest -q -p no:cacheprovider tests/test_dynamic_reproduction_execution.py
python -m pytest -q -p no:cacheprovider tests/test_investigation_runtime.py tests/test_config_v2.py
python -m compileall -f -q zscope scripts test tests
python -m mypy zscope
python -m pytest -q -p no:cacheprovider tests/test_agent_docs.py
git -c core.whitespace=blank-at-eol,blank-at-eof,space-before-tab,cr-at-eol diff --check
```

无 sanitizer 可用时，真实执行用例改为 skip（记 not_run），确定性用例仍全部运行。运行环境缺少 `clang` 时不会把 skip 记成通过。

## 7. 已知限制与工作区条件

- TSAN 在本机 clang 18.1.3 下可直接运行；若出现 `unexpected memory mapping`，退回 `setarch -R` 重试，本轮未触发该路径。
- 动态复现只证明“在该 plan、该 harness、该输入与该二进制下，候选对象／站点／缺陷族的受控 witness 是否可复现”；它不证明全程序安全，也不覆盖计划未声明的配置。
- 未复现只说明当前 harness 与输入下未观测到问题，报告与评估措辞必须保持这一限制。
- 工作区条件：`zscope/config/runtime_defaults.yaml` 在本轮编辑前已被写成 CRLF，而 HEAD 与 `.gitattributes`（`eol: lf`）为 LF。本轮在加入 6 个新键后把该文件规范化为 LF，内容差异仍为 17 行新增、0 行删除；其余 CRLF 文件属于既有未提交工作区状态，未触碰，已在 [最终工作区摘要](V01-V02-final-workspace.json) 中列出。
