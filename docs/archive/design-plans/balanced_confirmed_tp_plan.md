# Balanced 模式 confirmed TP 提升总体计划

> **历史文档，2026-11-17 归档。** 原位置：`new_docs/balanced_confirmed_tp_plan.md`。本文保留 2026-09 固定 trial 上的诊断、实验路线及已实施记录；当时的开关默认值、阶段计划和“单一事实源”声明不再作为现行要求。未完成实验及预期收益不视为已交付。当前验证路径见[分析流水线](../../modules/analysis-pipeline.md)，评测入口与资格见[Benchmark](../../modules/benchmarking.md)，后续开发见[现行实施计划](../../Z-Scope_Agent_Implementation_Plan/zscope-agent-implementation-plan/README.md)。

> 基线：range trial `benchmark-artifacts/c_cpp/trial/20260904T094432Z`（fast 档，分支 `v1.3.1_feat/llm-wiki @ 977226c`，模型 `deepseek-v4-flash`，endpoint volceapi 网关）。
> 本计划为开发与验收的单一事实源；执行中的产出物路径、门禁数值以本文为准，代码以实现为准。

## 0. 基线事实（来自冻结 trial）

### 0.1 结果

| 视图 | TP | recall | precision |
|---|---|---|---|
| confirmed | 63/136 | 46.32% | 100% |
| with_review | 134/136 | 98.53% | 59.56% |

- with_review TP 中 74 个配对来自 needs_review finding（69 个为 confirmed 完全未覆盖的 ground truth，5 个重复覆盖）。
- confirmed TP 归因：62 个 `deterministic_proof`（V0 自证）+ **1 个 `validator_llm`（V1，RANGE-013，`clang_cfg_heap_thread_argument_owner_not_released` @ src/main.c:188 td_init）**；LLM 独立发现为 0。
- LLM 参与度：176 次调用全部 V1 单轮、0 工具调用、V2 事实补全 0 产出、V3 从未触发；usage ledger 1,653,405 tokens（≈14% / 12M per-run 门禁），录制器累计 1,255,910 tokens。

### 0.2 瓶颈定位（决定阶段优先级）

| # | 事实 | 代码位置 | 意义 |
|---|---|---|---|
| F1 | 161/162 needs_review 的 V2 事实补全尝试 1–5 次后 `exhausted`，全部 "Fact resolution produced no new decision evidence." | `zscope/core/validation/runner.py:1607` | **fact provider 产不出事实**是最大桶（41/74 TP 缺 `lockset`/`event:acquire`/`event:exit`/`event:shared_state_access`） |
| F2 | `verdict=="uncertain"` 无条件 needs_review（即使 conf 0.90、事实齐、无 negative_evidence） | `zscope/core/validation/pipeline.py:560` | 150 个 uncertain 中 31 个 complete-fact TP 被政策挡住 |
| F3 | `verdict=="verified"` 需过 `final_score>=0.6` + `_has_confirmed_evidence()`；而 `evidence_completeness` 恒 `unknown`、`proof_coverage` 恒 `None` | `pipeline.py:533-547` | 3 个 verified TP 搁浅 |
| F4 | promotion 终态：`triage_lead`(115, missing_required_decision_facts) / `candidate`(47, structured_security_obligation_complete)，无一提升 | `zscope/orchestration/candidates.py` | 义务完整也不确认 |
| F5 | 8 个 `model_verdict=rejected` 混在 needs_review，呈现上无法与 uncertain 区分 | `report.issues_with_needs_review` | 用户困惑点 |

## 1. 目标与硬门禁

- **主目标**：balanced 档 confirmed TP 中位数 ≥ 116/136（对齐 range balanced 实验目标）；with_review recall 不低于基线 98.5% − 1pp。
- **硬门禁（每级改动单独过）**：actionable FDR 相对冻结基线 +1pp 以内；provider usage 覆盖 100%；token 守恒；队列清空；无无 proof 静默拒绝；5 轮 TP Jaccard ≥ 0.90、recall 极差 ≤ 2pp。
- 中间 pilot 一律 `release_eligible=false`；只有最终配置进 5 轮 formal。

## 2. 阶段计划

### Phase 0 — 基线冻结（0.5 天）
- 冻结 trial 产物为基线：TP 集合、74 needs-review TP 清单、161 个 no_evidence_gain 集群清单、`validator-replay-bundle.json`。
- 固定对照身份：Git SHA、RuntimeSpec、rules、model/prompt、provider；产出 `escalation_ledger` 空 schema 基线行。

### Phase 1 — 证据缺口补齐（最大收益桶）

| 步骤 | 内容 | 验收 |
|---|---|---|
| 1.1 Provider 诊断 harness | 对 161 个集群 × 4 类 fact-kind 直调确定性 provider，分类 `unsupported`/`timeout`/`empty`；核对 provider 注册、profile/深度开关、bc/CFG 输入链路 | 161×4 失败分类表（零 LLM 成本）**（harness 已落地：`scripts/provider_diagnosis.py --report … --project-root test/range`，用 regex CodeIndex 重建 scan 时验证包后逐门诊断；基线 131 行（161 集群 × missing fact-kinds）全 `empty_no_proof`，gate 分桶：**lockset 44/47 allowlist_uncovered**（请求方规则无 provider 白名单覆盖，如 unsynchronized_shared_flag_or_counter×14、container_unlink_free_after_unlock×4 等）+ 3 行 covered_deep_gate（样本分析表明需要调用方持锁这一跨过程事实）；**cleanup_coverage/ownership_transfer 各 18 行 path_incomplete**（path.complete_in_function≠True 使 provider 结构性禁用）+ 各 24 行 covered_deep_gate（事件提取缺字段敏感形状）；`fact_completion_by_kind` 全库无生产者（仅消费端）。1.2 修复按此三分桶展开，工件 `provider_diagnosis_baseline.json`）** |
| 1.2 修 provider | 锁语义：SVF lockset 对 fixture 适配或 clang CFG 锁配对 fallback；`event:acquire/exit` 复用 `clang_cfg_acquire_without_release_on_exit` 等检查器的事件提取作为 fact 源。**首批落地**：`_source_lifecycle_acquire_exit_proof`（v12 表，cleanup_coverage+ownership_transfer 双注册）——为无 CFG 事件的 SVF value-flow leak 候选从验证包 function code 重建生命周期事实，仅确认"全函数体无释放且无所有权转移"的路径无关否定存在（多分配点钉住未清理 subject；address-of 逃逸与部分泄漏保持可审），诊断基线由 0→2 行 produced（`_net_handle_error`），`td_init` 因 `&thread_ids[i]` 逃逸被正确拒绝。**第二批**：`_source_lockset_dominance_proof`（v12 表，lockset+happens_before 双注册）——unsynchronized 系规则（7 条白名单）的可反驳条件收紧为：sink 是写 ∧ 全部写点被同一 LOCK 括住且有 UNLOCK；读型声明（DCL 惯用法）明确保持可审，冻结基线上 0 产出为正确行为（fixture 的未同步写声明属实）。**第三批（调用方持锁）**：`caller_lock_states` 进验证包（scan 时由 call_paths 提直接调用者、逐 caller 词法 LOCK/UNLOCK 括号分析调用点持锁态；调用点未命中=unresolved）+ `_caller_lock_context_proof`（v12 lockset）——全部已解析调用方持同一把锁才 REJECT `caller_lock_context_dominates`，任一未解析/未持锁保持可审；需求表同步。冻结基线 4 行跨过程声明全部正确拒绝（refcount 声明属实、signal-sem 调用方状态混合） | no_evidence_gain 占比 98%→<30%（后续轮次继续：分支级 REJECT、调用方锁事实、lockset 白名单扩展 44 行） |
| 1.3 接通确认通道 | 新事实 → `confirmation_proof` 完整走既有 V0 自动确认（确认通道走 V3 模型复检 Phase 4 R2）。**已接通**：验收通过的 proof 追加进 `issue["deterministic_proofs"]`，由 `apply_deterministic_prevalidation` V0 路由消费；需求表新增 `source_lifecycle_acquire_without_release`（4 facts 精确钉定）与 `source_lockset_dominates_access`（lock_dominates_access + all_writes_guarded），facts 集合不全的证明一律拒绝（防模型自证）。端到端测试覆盖 provider→验收→V0 DecisionProof + 手工缺 fact 负例 | needs-review TP 缺失实占比 55%→<20%（依赖 pilot 实测） |

### Phase 2 — 裁决策略与置信度（31 个 complete-fact uncertain TP + 47 obligation-complete）

| 步骤 | 内容 | 验收 |
|---|---|---|
| 2.1 高置信 uncertain 确认通道 | `uncertain && conf>=τ && structured_security_obligation_complete && 无 negative_evidence` → confirmed，`promotion_reason="model_high_confidence_confirmation"`；τ 进 policy 参数化，replay 测 τ∈{0.80,0.85,0.90}。**已测量（M3 τ 臂，20260904 冻结 trial）**：离线重放脚本 `scripts/replay_tau_channel.py`（谓词与 `_high_confidence_uncertain_confirms` 逐项对齐，漂移防护测试 `tests/test_tau_channel_replay.py`）。结果：base 谓词通过 22/150 uncertain；τ0.80 → +1TP/+14FP（FDR +17.9pp）、τ0.85 → +1TP/+3FP（+4.5pp）、τ0.90 → +0TP/+1FP（+1.6pp）——**无任何 τ 通过 ≤1pp 门槛**，FP 横跨 clang_ast_cfg/graph_rule 双引擎、conf 0.80-0.90 无判别特征；通道保持默认关闭，confirmed TP 增长必须走证据补齐（M2 provider）而非置信度带提升。工件 `tau_channel_replay.json` | replay 上 FDR 增量 ≤1pp 的最大 τ（**测量结论：不存在**，通道停用） |
| 2.2 verified 搁浅修复 | `_has_confirmed_evidence()` 纳入 `decision_fact_coverage`/`evidence_completeness`；先修这两个恒空字段的产出链**（已修正诊断并落地产出链，2026-09-05）**：冻结 trial 复核推翻原前提——4 个 verified 判定项实际 `candidate_disposition=confirmed`（with_needs_review 视图本就包含已确认项，属视图包含关系而非搁浅），其 ledger `terminal_disposition=confirmed` 一致；结构化放宽模拟显示只会 +0TP/+2FP（complete-coverage 项均 UNMATCHED），不做。真实缺口是 `evidence_completeness` 恒空（225/225 unknown）：已修产出链——`ValidationRunner._evidence_completeness_from_issue`（decision_fact_coverage 优先，evidence_completion_status 兜底，completed_partial→partial）在 `_record_validator_attribution` 统一写入；冻结 trial 实测 review 视图 88 complete/137 partial、terminal states 114/158。测试 `tests/test_evidence_completeness_chain.py`（6 项） | verified 不再因启发式缺数据搁浅 |
| 2.2b 诊断复核（2026-09-05 重跑） | 重跑 `provider_diagnosis.py`（脚本 gate 表已同步 v12 provider 规则表，修正误导标签）：lockset 56 行中 21 行过 allowlist（原标签 3），35 行真不在表内；对 14 行 `unsynchronized_shared_flag_or_counter` 逐行实测——7 行 sink 为读访问（provider 有意只反驳未同步写声明），7 行写匹配项因函数体内存在无锁写点（初始化路径）而正确保持 needs_review。结论：lockset provider 按设计工作，残余是语义边界而非实现缺陷；分支级 REJECT 需要路径敏感证据，继续搁置 |
| 2.3 裁决锚定 | 用会话录制 JSONL 的完整 reasoning 做 150 个 uncertain 错误分析归类 → validator prompt 置信度 rubric 按 defect class 锚定。**（错误分析已完成，2026-09-05，离线部分）**：`scripts/uncertain_error_analysis.py` 从冻结 trial 生成 `uncertain_error_analysis.json`。结论：150 uncertain = 3TP/147 unmatched；按缺失事实桶 event_lifecycle 40(1TP)、lockset_pair 30(1TP)、lockset 14(0TP)、obligation_complete 65(1TP)；置信带 ≥0.80 为 2/76 TP、0.70-0.79 为 1/73——再次证实置信度无判别力，prompt rubric 锚定收益有限；3 个 TP 的缺口恰好每桶一个，provider 补齐是唯一路径；全部 150 项止步 initial pass（fast trial 未进 V2/V3）。prompt 变更 + replay A/B 待 LLM 接入 | 错误分析报告 ✅ + prompt 变更（待 LLM）+ replay A/B（待 LLM） |

### Phase 3 — rejected 呈现（用户困惑修复）

| 步骤 | 内容 |
|---|---|
| 3.1 disposition 细分 | needs_review 内部拆 `model_uncertain` / `model_rejected_unproven` / `policy_pending_promotion` 三子态（issue 字段 + SARIF/Markdown 呈现）**（已落地）**：纯函数 `needs_review_sub_state`（pipeline.py，三子态枚举 `NEEDS_REVIEW_SUB_STATES`）+ 三个 validator 落点（uncertain fall-through / structural downgrade / rejected 无证明 fall-through）写入 issue 字段；views 层 `annotate_needs_review_sub_state` 对旧报告派生兜底 + `_compact_observation` 白名单补齐 validator_verdict/missing_fact_kinds/negative_evidence 等呈现字段（修复 compaction 丢判定字段问题）；Markdown 待复核区渲染子状态/缺失事实清单/建议动作。冻结 trial 实测分布：model_uncertain 128 / policy_pending_promotion 22（与 τ 臂 base-OK 独立计数精确吻合）/ model_rejected_unproven 8（=F5）/ 空 4（verified-unproven 故意留空）|
| 3.2 呈现内容 | 展示 `model_verdict` + 拒绝理由 + 缺失事实清单 + 建议动作（"补 X 证据后复验"）**（已落地）**：`needs_review_presentation` 捆绑（model_verdict + rejection_reason + missing_fact_kinds + suggested_action 三态文案）随 with_needs_review 视图与 Markdown 输出|
| 3.3 口径保护 | 默认不改计分归属；operator opt-in 将 `model_rejected_unproven` 降级 dismissed（报告留痕、分数视图单独标注）**（已落地）**：`build_report_views(..., demote_unproven_rejections=False)` operator opt-in——仅 review 视图内把 model_rejected_unproven 降为 `dismissed_unproven_rejection` 并留 `downgraded_from_disposition` 痕迹字段 + 视图级 `unproven_rejection_dismissed_count`；默认视图与计分归零改动。测试 `tests/test_needs_review_sub_states.py`（7 项）|

### Phase 4 — LLM 参与度阶梯（每 rung 独立开关）

> 落地开关（M1 已实现，`runtime.analysis` 严格白名单内，默认全关）：`validation_v3_reattempt`（R2）、`validation_v2b_adjudication`（R3）、`validation_uncertain_confirm_threshold`（τ 通道，null 关闭，取值 (0.5, 1.0]）。

| rung | 开关 | 触发 | 预计增量 tokens | 预期收益 |
|---|---|---|---|---|
| R1 balanced 基线 | depth=balanced | 常开 | +0.3–0.5M（discovery 16 单元 + enrichment） | 主动发现独占 TP |
| R2 V3 复判 | `runtime.analysis.validation_v3_reattempt` | provider 产出新事实的集群 | 162×~10K ≈ +1.6M | 缺事实桶转确认 |
| R3 V2b 二次裁决 | `runtime.analysis.validation_v2b_adjudication` | uncertain 0.70–0.85 带 | 150×~10K ≈ +1.5M | 置信带收敛 |
| R4 profile 扩展 | discovery profile 参数 | pilot 通过后 | 按 profile | 边际 TP |

全开 ≈ +3.5–4M，仍 <45% per-run 门禁；5 轮 formal 每轮中位数门禁（≤12M）安全。全开最终是否保留由 Phase 5 差分表决定。

### Phase 5 — 分级归因观测（验证阶段的观测手段）

**Schema（M1 已实现）**
- issue：确认时写 `confirmed_via`（issue + attribution 双写）；当前枚举 `deterministic_proof | validator_model | high_confidence_band`（M2/M3 的 V3/V2b 确认沿用 `validator_model` 并以 `validator_policy_outcome.decision_level` 区分层级）；`escalation_path` 时间线随 M3 replay 臂一并落地。scorer 归因新增 `by_confirmed_via` 交叉表（已上线）。
- usage event：加 `escalation_rung` 字段（v1 契约保持、未递增版本）；由 `call_kind` 派生（`initial→R1_validator_v1`、`targeted_investigation/investigation_synthesis→R2_v3_reattempt`、`v2b_adjudication→R3_v2b_adjudication`，其余为空=非升级调用）；benchmark 归档校验要求新产出事件显式携带该字段，读取端对旧工件按 `call_kind` 回填（`_read_usage_events_jsonl` 兼容 shim）。conversation session metadata 的 rung 同步**（已接入，2026-09-05）**：`ConversationRecorder.begin_session` 从 label 的 `call_kind` 派生 rung 写入 `ConversationSession.escalation_rung`，随 session_start 事件与 index 落盘（非升级调用保持无键）。测试 `tests/test_conversation_recorder.py`。
- 冻结基线（20260904T094432Z）176 个 usage 事件回填后全部归 `R1_validator_v1`。

**配置可归因前提**：Phase 4 每个 rung 独立 on/off；同 rung 不叠两个手段。

**两种测量法**
1. 验证级手段（R2/R3/τ）→ **answer-free replay 臂**：复用 `validator-replay-bundle.v1` + `scripts/run_validator_replay.py` + `scripts/score_validator_replay_experiment.py`，每 rung 组合为一臂离线重放，臂间差分即边际贡献，无需重扫。
2. 扫描级手段（R1/R4）→ **累积式 cold pilot**：同冻结输入依次 R1 → +R2 → +R3 → 全开（各单轮冷扫，身份固定），差分表：
| ← **M5 启动就绪（2026-09-05）**：修复 `zscope/cli/benchmark.py` `_wsl_argv` 反斜杠吞失 bug（wsl.exe 裸 argv 会把 `C:\Users` 剥成 `C:Users`，改用 `as_posix()` 传 wslpath，带回归测试）；WSL `~/.profile` 补工具链激活（gclang/get-bc/wpa/saber 登录 shell 可见）；env 转发链（WSLENV→WSL→ConfigLoader）与大模型 HTTP 出网端到端验证通过；试跑完整走通 build/index/scan/验证队列（88 入口、308 义务，确定性层零回归）。唯一阻塞：本地两份 `zscope.local.env` 的 `Z_SCOPE_API_KEY` 均已失效（HTTP 401），待提供有效 key 后单命令启动 R1 冷扫 |
| **M5 R1 pilot 完成（2026-09-05，run 20260905T102807Z）**：同冻结输入、同端点模型（deepseek-v4-flash @ volceapi 网关）、开关全关 R1 冷扫。差分：confirmed TP **64 vs 63**（+1），recall **47.06% vs 46.32%**（+0.74pp ≤ 2pp 门禁✓），precision **1.0 = 1.0**、FDR **0 = 0**✓，confirmed 集 **Jaccard 0.9538 ≥ 0.90 ✓**（交集 62，新增 GRAPH_LOST_WAKEUP/SVF_VALUE_FLOW 各 1，丢失 CLANG_CFG_MEMORY_LEAK 1），tokens **1,875,131 vs 1,653,405**（+13.4%：冷扫推理噪声 + decision_explainer 29.8k，后续 rung 差分需超过此噪声底）。M1 funnel 与 M4 子态首次在真实运行中生效：`confirmed_by_rung={R1:64}`、`reached_by_rung={R1:272}`；needs_review 子态 model_uncertain 132 / policy_pending 24 / model_rejected_unproven 2 / evidence_conflict 1。执行环境备注：系统/虚拟环境 editable 安装均指向旧 checkout（work/Z-Scope @ c2f97a6），必须 `PYTHONPATH=$REPO` 钉住本树；launcher：`benchmarks/experiments/balanced_confirmed_tp/launch_r1_pilot.sh` |

| rung | TP_added | TP_loss | FP_added | confirmed precision Δ | tokens_added | marginal tokens/TP | 队列清空 |
|---|---|---|---|---|---|---|---|

TP_added 按 `confirmed_via` 分解；FP_added 同表盯 FDR +1pp 门禁。

**落地物**
- **bundle→validation pack 重建助手（2026-09-05）**：`zscope/benchmarking/replay_pack_rebuild.py` —— bundle 组的 `function_context` 按设计缺失（函数体属项目内容，执行时从挂载的 answer-free 项目解析）；该助手用组内 candidate 投影（issue 级字段）+ `CodeIndex` 走生产同一 `build_validation_evidence_pack` 重建 pack。冻结 bundle 实测 40/40 组恢复函数体与 `caller_lock_states`，`decision_fact_slice`/coverage 传播至 issue 级供 provider 门控。**parity 已全量对账达成（同日）**：重建 issue 补齐 issue 级 evidence_pack（ast_cfg/事件供 `_ast_pack` 门控）、组根 `validation_cluster_uid`、并以整函数体（绝对行号）替换原始 snippet；生产端同步修正 `_external_callback_under_lock_v12_proof` 的取码顺序（此前偏好 ±12 行短 snippet 窗口，可让有序性证明因窗口截断而搁浅——现与其余 provider 一致优先 `_function_code` 全函数体）。冻结 bundle 全量对账：**163 个 (cluster, fact_kind) 交叠行 0 分类差异、0 proof 数差异**（bundle 覆盖 188 行 > 报告 166 行，多出部分为 confirmed/rejected 集群）；顺带发现 round-10 保存的 rerun 工件含陈旧/受资源竞争影响的行并已刷新（131→166 行）。测试 `tests/test_replay_pack_rebuild.py`（4 项）
- `scripts/rung_attribution.py`（M1 已实现）：输入 N 份 run artifact（`--run-dir` 按阶梯顺序，`--usage-jsonl` 可指 replay 臂 ledger），输出差分表（`TP_added/TP_lost/FP_added/tokens_added/marginal tokens/TP`）+ `confirmed_via × truth` 清单 + per-rung token 汇总；校验流程只读 score/report/usage 侧car，不做 exchange 对账（对账项随 M2 harness 补）。
- scorer 扩展 `attribution.by_confirmed_via`（已上线）；`candidate_funnel` 的 rung 维度**（已上线，2026-09-05）**：`canonical_group_attribution` 新增 `reached_by_rung`/`confirmed_by_rung`/`drop_reason_by_rung`（R1 由 V1 reached 派生；R2 由 `validator_v3_entered`/investigation_synthesis pass 派生；R3 前向兼容读 `validator_v2b_entered`/v2b_adjudication pass，R3 臂交付前恒 0）。冻结 trial 实测：R1 272/272、confirmed_by_rung.R1=63（与基线一致）、R2/R3=0（开关关闭正确）。
- P0 基线冻结工件（已生成）：`benchmarks/experiments/balanced_confirmed_tp/baseline_fast_20260904T094432Z.json`（63 confirmed TP / 74 needs-review TP / 69 新真值 / 161 no_evidence_gain 集群 / tokens by rung）。

**M1 状态（2026-09-05）：已完成。** 交付：三开关 + τ 通道（默认关）+ `confirmed_via`/`escalation_rung` schema + 兼容回填 + `rung_attribution.py` + 基线冻结工件 + 28 项单测（`tests/test_escalation_observability.py`）。

### Phase 6 — 外部变更验收：自定义接口识别强化（另一会话交付，不列入本计划开发）

该变更影响候选生成（扫描期），无法用 replay 隔离，采用 **A/B 全扫描对照**：

| 步骤 | 内容 |
|---|---|
| 6.1 可见性要求 | 其改动需带独立配置开关（或至少可由 Git 身份区分）；若在 candidate/finding 上有 attribution 标记（如 `candidate_source`/`discovered_by` 的 custom-interface 标记）则直接计数，否则退化为纯差分。**（6.1 已就绪，2026-09-05）**：开关 `analysis.llm_interface_inference`（+budget）已在；probe usage 事件以 `agent=user_config_interface_probe` 可辨（token 成本可从 ledger 计）；新增报告级聚合 `run_manifest.interface_probe`（probed/classified/declined/skip 原因/role 分布/前 64 个 classified_functions），A/B 可直接对齐 probe 影响面而非纯差分。测试 `tests/test_interface_probe_visibility.py` |
| **M5 执行环境与 R2/R3 门禁备注（2026-09-05）**：① R2（V3 复判）有硬深度门禁——`_assign_v3_investigation_budget` 仅在 balanced/deep 生效，fast 下 `allow_v3` 恒为 False，故 balanced 差分行需先补一次无 rung 参照；② R3（v2b 裁决）目前仅有 attribution 映射（`llm_usage.py` call_kind → R3），调用点属 Phase 3 剩余实现项；③ 系统/虚拟环境 editable 安装均指向旧 checkout（work/Z-Scope @ c2f97a6），pilot 必须 `PYTHONPATH=$REPO` 钉住本树；④ 用户授权调高 benchmark yaml（test/range/zscope.benchmark.yaml）并发：base_url_max_concurrent_requests 4→8、llm_max_inflight 4→8、validator_workers 4→6、investigator_workers 1→4，balanced 参照与 R2 行共用此身份；⑤ rung 开关位于 runtime spec（`Z_SCOPE_RUNTIME_SPEC` + `Z_SCOPE_DEVELOPER_MODE=1`，公共 config schema 拒绝 runtime 节）；⑥ `validation_v3_reattempt` 原本无消费点（本轮已接线 `_assign_v3_investigation_budget`），且为保持 shipped balanced 行为，默认 **True**，仅显式 false 时关闭（参照行用 `runtime_spec_ref.yaml`，R2 行用 `runtime_spec_r2.yaml`）；⑦ clangd 偶发「indexing did not become ready」瞬时失败，重试即可。 |
| **M5 balanced 参照 row 完成（2026-09-05，run 20260905T120239Z）**：V3 off（`runtime_spec_ref.yaml`）。confirmed **64**、recall **47.06%**、precision **1.0**、F1 0.64，tokens **1,852,607**（validator 1,823,353 + decision_explainer 29,254；本 fixture 小，balanced 与 fast 发现组完全一致 272 组，故 cost ≈ fast，策略表 10–12M 预期不适用）。确认集 Jaccard：vs R1-fast **0.9692**、vs P0 基线 **0.9538**。run 归因 `confirmed_by_rung={R1:64,R2:0,R3:0}` 验证开关与 funnel 投影生效。R2 行（`runtime_spec_r2.yaml`，V3 on）已启动。 |
| **M5 +R2 row 完成（2026-09-05，run 20260905T130307Z）**：V3 复判开（`runtime_spec_r2.yaml`）。**TP 门禁达成（注意标签：139 为确认数而非 TP）：confirmed 139 = TP 119 + FP 20（参照 64 全 TP，+55 纯增量、零丢失）；recall 87.5% vs 47.06%；TP 门禁 119 ≥ 116/136 ✓（余量 3）**，但 **FDR 门禁失败**：precision 0.8561（FDR +14.4pp ≫ +1pp），且 tokens **41.8M**（22.6x 参照，V3 多轮调查 76 项×高迭代）。漏报 17 项均为 race/UAF/锁序/指针身份类，其中 13 项在 needs_review（严格键匹配 16 个候选，3 真值×2 候选）、另 4 项（RANGE-024/053、ISSUE43-009/017）从未成为候选（发现层缺口；官方宽松匹配器口径 with_review_recall 99.26% 则认为仅 1 项不可达）；review 层严格分类：新 TP 候选 16 / 已确认真值重复 25 / 无真值对应 57；若 review 全升级：recall 99.26%、precision 仅 56.96%（score.json with_review_* 官方口径）；FP 定位：20 个 FP 中 19 个来自 `investigation_synthesis` 确认（V3 叙述性确认，即计划预警的“模型自证”风险），1 个 deterministic_proof。**下一杠杆：V3 确认验收收紧**——synthesis 确认必须携带完整 required fact kinds 的 decision_proof（接 EvidenceCompletionQueue 缺事完整性），不完整→ needs_review；可选叠加 V3 迭代/资格预算收紧以降 token（当前 50 迭代上限×76 项资格）。 |
| **R2 三项复盘分析（2026-09-05）**：① TP 贡献分解：V0+V1 基线管道（~1.65M tok）63–64 TP；**V3 复判 rung（+39.9M tok：validator +34.6M、semantic_modeler +5.3M，后者仅在 V3 调查中触发）：59 TP（毛）/55 净新增真值 + 4 项“V1 方差掉出→V3 救回”组合**；decision_explainer（+29.8k）纯呈现层 0 TP；τ 通道 off。效率：~726k tok/净新增 TP（基线 ~26k，28x）。② 20 个 confirmed FP 重新定性：**12 个是同函数同类别真值的重复确认**（9 V3 + 3 deterministic_proof；dedupe 层仅按 alias 去重，仅挡 2 个）；**纯 FP 仅 8 个**（公共 API 无界 size_t CWE-190/770 ×4、OOM 路径 CWE-690、CWE-479 信号安全、mesh 泄漟—真值 excluded 清单明记 retired-as-duplicate、INVALID_FREE det-proof×1）；且代码层面叙事多数属实（packet_pool free-后-解引用、payload strdup 泄漟均经源码核对属实）——分歧主要是基准范围约定而非证据链错误。若按真值去重：confirmed 唯一 127，precision 回升至 **93.7%**（FDR 6.3pp，仍超 +1pp 门禁）。③ review 98 为何不拒绝：sub_state 分布 model_rejected_unproven 48 / model_uncertain 40 / policy_pending_promotion 7 / 其它 3；57 个无真值项中模型已拒绝 33 但拒绝终态需确定性证明（rejected_with_proof 仅 33 项全部落地），无证拒绝按设计挂起；停机原因 decision_complete 37 / no_evidence_gain 29 / investigation_complete 19 / investigation_exhausted 7 / missing_fact 5。改进杠杆：②真值无关的确认去重→FDR 6.3pp；③ R3/v2b 裁决 rung 处理 unproven 拒绝；① V3 确认验收仍需 fact-kind 完整性硬门禁。 |
| **真值去重的 TP 风险评估（2026-09-05）**：计分层重标注（FP→DUPLICATE）零 TP 风险（计分器每真值至多配一 issue，重复项从未计入 TP），但属汇报口径变更，正式 sealed 门禁仍用原口径；**管道层粗键硬去重否决——实证有 TP 损害路径**：① 真值集唯一双条目键 ('race','main.c','_worker_thread') 的 RANGE-009/016 由 td_cleanup 中两个不同证据锚点（g_running vs g_receiver_running）的 issue 分别匹配，同键多真值时 keep-one 直接丢 TP；② reader_channel 单真值 4 候选（1295×2/1296/1300）中 scorer 匹配 1295 的 GRAPH 候选，keep-wrong-representative 风险真实。安全替代：软标记 duplicate_of_confirmed（零风险，报告单列 unique 视图）；V3 调度去重省 token 需 line-cluster 键 + A/B 门禁（Jaccard ≥0.90 且 TP 不降）。 |
| **三杠杆决策标定（2026-09-05）**：① 去重：发现计分器已有双口径——score.json 同时携带 root_cause（亲和性去重后 precision 1.0/FDR 0，duplicate_of_matched_count=20）与 actionable（保守口径 0.8561/0.1439，sealed 门禁绑定此口径）；② 机械性确认门禁标定失败：16 个 V3 FP 全部 closure-complete（fact-kind 门禁无效）；**30/59 V3 TP 与纯 FP 共享“公共 API 可控性”画像（甚至同函数成对：_net_recv_string TP RANGE-015 vs 纯 FP#13；_serialize_task TP RANGE-017 vs FP#6）**，且真值也计 770 类（RANGE-006 _safe_malloc）——类条件规则无分离力，管道层机械门禁否决；可行窄形式 = fp_audit 审计分类器按声明式约定（excluded 清单理由）打 scope-excluded 标签，仅审计不改判。③ R3/v2b 裁决：回收上限 +7 真值（+5.1pp recall，其中 7 个真值覆盖候选被模型无证拒绝）；可用 replay pack 在现有 R2 产物上验证（~0.5M tok，无需全重扫描）。 |
| 6.2 A/B pilot | 同冻结输入两次冷扫（开关 on/off，其余身份一致），对比：candidate_funnel 增量、truth 覆盖差集（新增/丢失 TP 清单）、`confirmed_via × discovered_by` 交叉、tokens/候选 |
| 6.3 交互验证 | 在本计划最优 rung 配置上叠加其开关做 on/off pilot，确认无回退（TP Jaccard、FDR、队列） |
| 6.4 最终验收 | 合并后以交付 Git 身份进入 5 轮 formal；其贡献以 6.2/6.3 差分表 + formal 中 `confirmed_via/discovered_by` 归因呈现 |

### Phase 7 — 验证顺序与治理

1. 顺序：单测（promotion policy/provider/rung schema）→ answer-free replay（FDR 对照）→ balanced cold pilot（累积差分）→ 5 轮 trial → 交付验收（含 Phase 6）。
2. 治理：动规则语义同步 `zscope/rules/builtin_catalog.yaml` revision；更新 `docs/modules/analysis-pipeline.md`、`docs/modules/benchmarking.md`；不动 truth 隔离、sealed 口径与 `AGENTS.md` 运行时 prompt。

## 3. 里程碑与依赖

| 里程碑 | 内容 | 工作量 | 依赖 |
|---|---|---|---|
| M1 | P0 冻结 + P5 schema/开关/rung 标记 + `rung_attribution.py` | ~2 天 | 无（可与外部会话并行） |
| M2 | P1 provider 诊断与修复 | 3–5 天 | M1（harness 用 rung 标记产出） |
| M3 | P2 策略通道 + replay 臂测量 | 2–3 天 | M1（τ/V2b 臂） |
| M4 | P3 呈现 | 1–2 天 | 无强依赖 |
| M5 | P4 累积 pilots（R1→全开差分） | 2–3 天 | M2/M3 |
| M6 | P6 外部 A/B + 5 轮 formal + 交付验收 | 3–4 天 | M5 + 外部变更就绪 |

## 4. 风险与回退

| 风险 | 信号 | 回退 |
|---|---|---|
| fact provider 对 fixture 根本不可行 | 1.1 分类表 `unsupported` 占主导 | 转向 R3 V2b 复判 + 2.3 prompt 锚定；预期上限下修 |
| 高置信通道推高 FDR | replay 臂 FP_added/TP_added 超折算线 | τ 上调或关 2.1 |
| token 超预期 | per-cluster 成本中位数越界 | token governor 收紧 R2/R3 触发范围（只跑 TP 候选带） |
| 外部变更与本计划冲突 | 合并 pilot Jaccard/FDR 回退 | 以 rung/开关矩阵二分定位，必要时错峰合并 |
| V3 复判引入循环 | 复判后仍 uncertain 的重复请求 | `duplicate_fact_request` 已有防护；加 per-cluster 复判次数上限。**（2026-09-05 核验：无需额外上限）**`_run_v3_targeted_investigation` 每 validation item 结构性只进入一次（`allow_v3` + requires-review 探针门控），内部 `investigate(max_iterations)` 限工具迭代，item 只验证一次 + 结果缓存，无 cluster 级重入路径 |

## 5. 预期与最终验收清单

- 预期：confirmed TP 63 → **95–110**（仅 P1+P2 保守）；叠加 R2/R3 全量 → **110–120**；with_review recall 保持 ≥97.5%；confirmed precision 由 replay/τ 校准控制。
- 交付物：差分观测表（每 rung / 外部 A/B）、错误分析报告、5 轮 formal artifact（`zscope.formal-benchmark.v3`，含 per-rung 守恒与归因）、更新后的模块文档与 policy 文件。
- 最终验收以 `rung_attribution.py` 输出 + formal 门禁全部通过为准；外部自定义接口识别强化的效果以 Phase 6 差分表单列呈现，不计入本计划开发项。
