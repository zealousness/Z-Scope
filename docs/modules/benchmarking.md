---
doc_contract: zscope-module-v1
covers:
  - zscope/benchmarking
sources:
  - zscope/benchmarking/protocol.py
  - zscope/benchmarking/runner.py
  - zscope/benchmarking/policy.py
  - zscope/benchmarking/isolation.py
  - zscope/benchmarking/attestation.py
  - zscope/benchmarking/replay_bundle.py
  - zscope/benchmarking/replay_provider.py
  - zscope/benchmarking/validator_replay.py
  - zscope/benchmarking/validator_experiment.py
  - zscope/benchmarking/discovery_ablation.py
  - zscope/benchmarking/discovery_ablation_experiment.py
  - zscope/benchmarking/postscore_trace.py
  - zscope/cli/benchmark.py
  - scripts/external_benchmark.py
  - scripts/evaluate_range_regression.py
  - scripts/aggregate_range_release_runs.py
  - scripts/check_benchmark_hygiene.py
  - scripts/evaluate_release_candidate.py
  - scripts/run_validator_replay.py
  - scripts/describe_validator_replay_provider.py
  - scripts/score_validator_replay_experiment.py
  - scripts/plan_discovery_ablation.py
  - scripts/run_discovery_ablation_request.py
  - scripts/score_discovery_ablation_experiment.py
  - scripts/compare_range_matchers.py
  - scripts/build_postscore_decision_trace.py
  - docs/range-benchmark.md
  - test/range/benchmark/check_entry_coverage.py
tests:
  - tests/test_benchmark_protocol.py
  - tests/test_benchmark_leakage.py
  - tests/test_benchmark_runner.py
  - tests/test_range_benchmark_regression.py
  - tests/test_range_release_aggregate.py
  - tests/test_formal_benchmark_runner.py
  - tests/test_release_contract.py
  - tests/test_benchmark_v4_contract.py
  - tests/test_benchmark_attestation.py
  - tests/test_validator_replay.py
  - tests/test_validator_experiment.py
  - tests/test_external_benchmark_oci.py
  - tests/test_discovery_ablation.py
  - tests/test_discovery_ablation_experiment.py
  - tests/test_range_matcher_comparison.py
  - tests/test_postscore_decision_trace.py
---

# Benchmark

## 职责与非职责

本子系统负责统一 benchmark 数据形状、ground truth 匹配、双视图指标、外部 suite 准备/运行、Range 回归和发布结果聚合。`test/range` 是包含故意缺陷的 fixture，用来测量检出与误报，不是待修复的普通 C 项目。

它不负责给扫描模型提供答案，不负责通过定制 benchmark 名称提升规则命中，也不把一次历史成绩写成永久产品事实。

## 主入口和数据流

- `zscope/benchmarking/protocol.py` 提供 `zscope.benchmark.v4` 单次评分、候选生命周期漏斗、发现/决策二维归因和成本指标；旧 schema 仅作只读兼容。
- `zscope-benchmark` 是内置 fixture 的唯一公开入口；`smoke`、`trial`、`formal` 分别承担离线结构门禁、单轮预览和至少五轮的发布门禁。
- `scripts/external_benchmark.py` 是外部 suite 和 Range JSON 报告的标准评测入口。public external formal 当前只接受 `full_zscope_pipeline`，通过 `RootlessOciExecutor` 实际执行 scanner、采集 inspect evidence 并在容器退出后由 host scorer 读 truth；静态 `oci_capability` 不能形成 formal 结果。
- `scripts/evaluate_range_regression.py` 评估确定性候选的 Range 覆盖。
- `check_entry_coverage.py` 在正式扫描前核对入口覆盖；它可以读取 truth，但不得把 truth 传入扫描 prompt。
- 扫描报告生成后，独立 scorer 读取报告与 ground truth，输出 matched pairs、TP、FN、raw/effective FP、precision、recall 和 F1。`zscope.truth-matcher.v2` 只把类别兼容且 `file + function + line range` 来自同一结构化锚点的 pair 交给最大权匹配；关键词、自由文本、call path 和 `related_functions` 只能形成审计记录。
- `zscope.formal-benchmark.v3` 聚合至少五轮 cold run；`zscope.benchmark-policy.v1` 是发布门禁的唯一政策源。
- answer-free `validator_replay_bundle.v1` 只导出 canonical validation groups、证据/事实与哈希，不含 truth、历史 Validator verdict 或评分结果，用于固定候选集上的 A–E 隔离实验。bundle 合约显式区分 V1 初始 facts 与 provider-resolvable frozen reservoir；同一 fact record 或 UID 出现在两个分区时 fail closed，V2 只能从 reservoir 取得新增量。
- balanced/deep 产品分档召回实验与历史 A–E arm 分开解释：生产 V3 已移除 top-5%/top-20% 截断，balanced 调查 high/critical 或外部可达且有可闭合证据缺口的未决 cluster，deep 调查全部无完整反证的非 shadow 未决 cluster；每个 cluster 使用一个最多 50 次模型迭代的只读工具会话。实验必须先做 cold pilot 的 eligible→entered→promotion 链路检查，通过后才运行每档五轮，并同时归档双视图、V3 fact/transition 与逐 agent/stage token。
- 打包的 `validator_arms.v1.json` 固定 A–D 的 pass、repair、事实补充和调查轨迹，并把 E 定义为冻结旧多轮 Validator 的 17M 预期成本/召回上界；E 不是 bounded v3 调查的别名。A 冻结当前 generic loop 的精确 forced-final 指令和 terminal-tool bridge，与 B 的直接结构化 V1 严格分离；D 只对 high/critical、外部可达、达到 balanced 风险阈值并位于 top 5% 的 V2 未决 cluster 开放一条、最多两次冻结只读查询的轨迹。`scripts/run_validator_replay.py` 只接受已验哈希的 answer-free bundle、可选 post-run cost expectation 和 executor/model/prompt 身份，按 cluster 顺序生成 `zscope.validator-replay-run.v1` 调用与 token ledger。A–D 可用 `--builtin-provider-config` 从严格的 answer-free provider JSON 构造 fresh `LLMClient`，每次 executor 调用只允许一个 HTTP attempt且必须返回 provider usage；失败/中断或不合法 usage 按请求投影保守计量，但仍可继续既定 repair。`scripts/describe_validator_replay_provider.py` 离线派生实际配置、Prompt模板与加载代码的三个哈希，run CLI 再与调度方外部冻结的 expected hashes 核对。当前 legacy Validator 缺少 replay-safe 的逐 attempt usage/session 接口，内置 E 因而 fail closed，并保留显式 external adapter；外部 E 的一次调用仍必须是完整旧多轮 session并聚合所有 provider usage 与 `api_attempt_count`。普通 CLI 中的 `package.module` adapter 一律标为 non-formal，不接受自报 OCI evidence；在 host-side RootlessOciExecutor 实际执行/inspect 并受保护地签入 evidence 之前，formal E 实验 fail closed。truth 匹配必须由执行完成后的独立 scorer 完成。
- `scripts/score_validator_replay_experiment.py` 是 A–E 正式实验的独立 scorer。它要求每个 arm 恰好五轮 cold ledger、25 个外部预期 run SHA、统一 executor/model/prompt 身份和外部预期 bundle/catalog/truth SHA；先完成全部 answer-free ledger 的 schema、hash、身份、顺序与守恒校验，之后才首次读取 truth。输出 `zscope.validator-replay-experiment.v1`，绑定所有输入文件与内容哈希，计算 TP/recall/actionable FDR、五轮 TP Jaccard/recall 极差、token 中位数/最大值、provider usage、队列、协议和守恒门禁，并在 passing arms 的 recall 相差严格小于 1pp 时选择 token 中位数最低者。Arm E 可用 17M 作为执行上界，但其实际每轮 token 仍须通过统一的 12M 默认门禁。
- Validator arm 冻结后，`discovery_ablation_arms.v1.json` 与 `scripts/plan_discovery_ablation.py` 定义 D0–D4 语义/主动发现消融。五个 arm 共用显式 balanced 档、同一 12M post-run 成本预期、同一 Validator selected arm/spec/catalog/model/prompt、rules/scanner 身份和各五轮 isolated-cold 运行；plan 与 25 份 request 均绑定外部期望 SHA，且生成阶段递归拒绝 truth、历史 finding、候选 Ledger 和 scorer/score 字段。D0 不建语义地图也不发现，D1 只建图并补语义（包括禁止读取缓存 discovery report），D2 在零 LLM 骨架上 candidate-blind 发现，D3 同时启用二者。`scripts/run_discovery_ablation_request.py --execution-mode non-formal-in-process` 的 `package.module` adapter 只是开发执行入口：它必须绑定全套 Validator 与每轮独立 cold snapshot/cache identity，禁止 resume/maintain，并以和 report 同一 artifact 目录中的原始 usage JSONL 实际 SHA、call/stage/run token 守恒和 100% provider usage 复核 report；输出固定 `answer_free_attested=false`、`formal_eligible=false`、`release_eligible=false`，不能作为 formal 隔离证据。
- D4 是 `zscope.discovery-ablation-legacy-full-entry-executor.v1` 外部协议：独立 legacy adapter 必须实际运行冻结的全入口 semantic-modeler/vulnerability-analyzer 路径并接受同一 12M cap。生产 bounded pipeline 会拒绝把 D4 runtime override 当作自身模式执行；没有外部 executor/artifact 时不得伪造 D4 成本上界。任意 Python adapter 与 scanner 同进程，技术上可访问其进程权限范围内的文件，因此不能自行证明 answer-free；formal/sealed 消融只能由中央控制面通过 digest-pinned `RootlessOciExecutor` 在只挂载 answer-free input、fresh cache 和 artifact output 的 rootless OCI 中执行，隔离能力或固定协议缺失时 fail closed。所有 D0–D4 artifact 都带 `benchmark_ablation` 标记，formal Release 会无条件拒绝，独立 scorer 只能在 25 份 scanner report 全部冻结后读取 truth。
- `scripts/score_discovery_ablation_experiment.py` 是 D0–D4 的独立后置 scorer。它要求每个 arm 恰好五轮、25 份 execution、对应 report 与 raw usage JSONL，并分别接受外部冻结的 canonical/file/sidecar SHA；先校验 plan/dataset/config/Validator/arm/cold/12M、execution→report→usage 交叉哈希、complete 状态、双视图和 provider usage/token/by-stage 守恒，再首次打开 truth。输出 `zscope.discovery-ablation-experiment.v1`，按 confirmed/with-review 汇总 TP、recall、raw FP、actionable precision/FDR、发现来源独占/交集、tokens/独占 TP，以及五轮 median/p50/p95/Jaccard/range。当前协议只有 isolated-cold run，因此热缓存收益必须显式为 `N/A`，不能由 cached prompt token 推断；D4 只标记为成本上界，不参与质量 arm 选择，整个实验永久 `release_eligible=false`。
- `zscope/benchmarking/runner.py` 在 WSL 原生临时文件系统运行 C/C++ scan/state，再导出 artifact；它分别记录 scan wall 与 end-to-end wall、验证队列/API call telemetry、双质量视图、命令哈希、Git tree、输入文件清单和 provenance。正式 Release 按 workflow run ID 下载不可变 artifact，并由 `scripts/evaluate_release_candidate.py` 校验 SHA、输入清单、truth 隔离和门禁。仓库归档只用于历史基线。

## 必须保持的不变量

- 扫描上下文与评分答案严格隔离；benchmark leakage 测试必须持续通过。
- replay bundle 必须把同一 canonical cluster 的 alias occurrences、evidence 和 facts 做顺序无关的 union，并绑定 candidate/occurrence/entry/evidence/facts 的内容哈希；初始 facts 与 frozen reservoir 必须分区且无 record/UID 重叠。执行时还必须由调用方提供预期 bundle SHA，防止攻击者修改内容后自行重算内部哈希。
- trial扫描失败或人工早停时，runner在清理临时answer-free workspace前只归档usage、decision/coverage trace、evidence objects和model events，生成`zscope.interrupted-benchmark-diagnostics.v1`并固定`release_eligible=false`；不得复制源码、配置、truth、scorer或reasoning正文。正常完成的run仍必须走report绑定的严格归档与守恒校验，partial诊断不能替代正式结果。
- Range 是分布内开发/回归集，不是生产泛化结论。发布必须依次报告 Range、public external、独立团队保管的 sealed 集和真实项目 shadow；没有 sealed attestation 不能宣称通过生产门禁。
- formal/sealed 扫描必须在 rootless OCI 隔离中运行，只挂载 answer-free 项目、配置、工具链和输出目录；scanner cwd、mount 和环境不得可达源码 checkout、`test/`、truth 或 scorer。缺少 Podman/Docker 隔离能力时 fail closed。
- OCI 网络成员必须来自运行时证据。Docker 使用 `network inspect`；Podman 还使用精确 network filter 的 `ps --all` 成员快照，以兼容不在 `network inspect` 中暴露容器列表的 4.x 版本。两个来源同时可用时必须一致，快照摘要写入 preflight 与逐阶段 evidence。
- Z-SCOPE 2.0 的评测轨新增 `zscope.benchmark.v5`、`zscope.formal-benchmark.v4`、`zscope.benchmark-policy.v2` 与 `zscope.defect-taxonomy.v1`。v5继续复用matcher v2的强结构化配对，不允许keyword、自由文本或跨锚点拼接形成TP；confirmable、pattern-model和retired truth分开计量。Security Spec、Hypothesis Hunter与Proof Engine指标缺失时开发评分显示`not_available`，formal v5则fail closed。Token在v5中只作运行后成本与Pareto度量，不是产品运行时门限。
- Benchmark v5 的paired formal输入不是两个布尔值：每条记录必须绑定Truth v16的pair UID、pair manifest hash、两侧source hash、两份scanner report hash和`answer_material_present=false`。正式单轮还必须绑定Finding-root v2和完整Scorer依赖bundle，按agent、stage重新求和的token都必须等于总token。五轮聚合重新校验每份score content hash，分别输出default/with-review、组件、safe-pair和成本分布，按project/CWE/contract/taxonomy输出macro指标，并要求外部提供冻结baseline precision后才执行policy v2门禁。
- formal workflow 除要求 `repository@sha256:<digest>` 外，还校验 scanner image 的 `org.opencontainers.image.revision` 等于被测 Git SHA；每轮 summary 绑定 report、score、input manifest、tool health、Validator replay bundle 与原始 usage sidecar 的实际字节 SHA，Release evaluator 会从下载 artifact 重新计算并逐项对账。
- GitHub `actions/upload-artifact` 返回 64 位裸 SHA-256；受保护审核 workflow 必须在 provenance 边界补全 `sha256:` 算法标识，再由严格 provenance schema 与 attestation 消费，不能放宽 schema 接纳无算法 digest。
- Safe-pair 匿名性提取必须从调用形状中排除完整 C11 关键字，避免把 `return (`、`for (` 等语言结构当作项目函数；C 标识符只按完整 token 匹配，truth ID 等非 C 标识符按完整字面量匹配，项目函数、宏与其他专有标识仍严格 fail closed。
- Safe-pair author 只允许一次 answer-free contract repair：冻结 packet/decision/role/model identity，只提供被拒绝对象、枚举 validation class 和从同一 packet 重算的确定性约束；每次调用的 per-packet JSON Schema 还必须以 `const` 绑定 truth ID、packet SHA-256 和 final-decision SHA-256，并从绑定 packet 重算完整禁止标识符 catalog，对两份完整源码施加与 validator 等价的零匹配约束。raw v2 复核时从绑定 packet/decision 独立重算并拒绝任何身份未绑定、禁止标识符弱化或仅约束字段形状的 schema。`source_not_anonymous` 可提供完整 catalog、固定匹配语义，以及用同一匹配器产生的两份源码逐字段冲突清单与计数，但不提供审核正文或答案。修复后的两份完整源码必须都没有任何剩余匹配，包括注释、字面量和预处理文本。raw v2 必须绑定两次 envelope、唯一 accepted attempt 及最终 author 逐字段一致性，repair 后仍不合规即 fail closed，禁止第三次调用。
- public external formal 必须把项目复制到 checkout 外的临时 sealed input，再复制到独立的 writable cache project；只读输入、writable artifact 和 writable cache 三个 mount 必须互不包含。entries 要先通过 answer-key 字段检查，容器 config/compile commands 只含容器路径，truth 必须等 scanner 退出并通过 `require_release_isolation` 后才由 host scorer 加载。
- 正式 unified 结果要求 Linux 用户态和完整工具链，SVF/Saber 降级结果不能冒充正式结果。
- Windows 主机使用 WSL；原生 Linux 直接运行等价命令；原生 Windows 不形成正式结果。
- `test/` 不包含执行 runner、历史报告或后台 launcher；fixture 根每种语言只保留一份正式配置。
- C/C++ formal 不读取 deterministic entry manifest，入口必须由隔离副本中的自动发现产生。
- scorer 以结构化 file/function/category/location/evidence 的同锚点 pair 匹配，并保留 `matched_pairs` 供人工审计；新 formal artifact 必须使用 `zscope.truth-matcher.v2`，缺失 matcher 版本的历史 v4 artifact 只能只读。
- raw FP、`same_product_root`、`truth_covered_additional`、`cross_anchor_overlap`、`weak_legacy_overlap` 和 effective FP 必须分开保留，不能通过静默删除重复报告美化指标。`duplicate_of_matched_count` 仅作为 `same_product_root_count` 的弃用别名。
- 没有 safe units/true negatives 的数据集不得把 `FP/(TP+FP)` 称为经典 FPR；应报告 actionable FDR、raw FP 和 precision。经典 FPR 仅在 truth 明确给出 safe units 时计算。
- 每次正式评分必须输出 `discovered_by × decided_by` 交叉表、LLM 独占 TP、tokens/TP、marginal tokens/新增 TP、tokens/KLOC、p50/p95、五轮 Jaccard/极差和 Range→sealed generalization gap。
- 新 formal finding 显式归因覆盖率必须至少 99%，call 级 usage 与 run summary、by-agent、by-stage 聚合必须守恒。
- v15 及更早 truth 是只读描述性回归；新 formal Range 必须具有独立签发的 `zscope.range-truth-contract.v2`，confirmed 门槛按 `ceil(0.85 × confirmable_truth_count)` 动态计算。历史 111/136、116/136 和 10M/12M 只能作为旧实验/成本期望，不是产品 token admission。聚合器继续执行 FDR、TP Jaccard、recall 极差、provider usage、归因、队列、telemetry、token 守恒和协议异常门禁；缺少 v16 contract 或任一字段均 fail closed。
- Truth v16 的受保护双人审核把 raw stdout、decision、packet hash 和 reviewer command identity 分别归档并交叉验证。为兼容冻结协议，`fable`/`opus` 仍是机器槽位名称；实际路由分别是 Claude Code 2.1.233 + `glm-5.3` high，以及 Codex CLI 0.144.4 + `gpt-5.6-sol` xhigh。Codex 负责 mandatory/disagreement 仲裁与 safe-pair author，固定 read-only/ephemeral、忽略用户配置和规则、禁用 shell tool，并用内容绑定 JSON Schema 与 canonical schema hash 限制直接 JSON 输出。第二主审固定为 DSH 0.1.0-rc.6，通过临时只读 patch 绑定小写 provider `deepseek`、model `deepseek-v4-pro-0813` 与 `reasoningEffort=max`。三个槽位的初次 reviewer 进程非零退出时只允许一次同输入、同命令、同冻结身份的 transport-only 重试；初次输出正文不保留而只绑定 stdout/stderr 哈希，第二次失败即停止。DeepSeek 的隔离 schema 以 `const` 绑定当前 packet/reviewer 身份；有界 format-only 重试必须同时通过严格 JSON、schema、packet/role 绑定和模型身份校验，可解析但字段不合法的对象仍会继续有界重试或 fail closed。格式重试耗尽或 Claude/Codex 首次 contract 失败后，只允许一次同 packet、同 reviewer 的 contract regeneration。可解析失败对象先剥离 provider transport envelope，再一次性枚举全部 answer-free 递归 schema 约束、独立确定性语义约束和冻结 binding 字段差异，由完整问题集产生最小 material 修复 allowlist；单次 regeneration 必须修复全部已列问题，allowlist 外字段用投影哈希冻结，纯身份错误的 allowlist 为空，无法证明修复边界时不声明 material 守恒。三个槽位对已通过 schema/身份但未通过 packet grounding 的输出最多执行一次 grounding-only 纠正；纠正仍使用原 reviewer 的冻结 harness/模型身份，只有 anchors/evidence refs 可变，实质投影哈希必须守恒。DeepSeek grounding 输出若不是严格 JSON artifact，只能进行最多两次有界 transport-only 重发；第二次只读取前一次格式输出和更新后的 answer-free 校验反馈，且每次最终非 grounding 投影仍须与原 decision 一致。已解析且只有冻结 identity 错误的 grounding 输出不再触发模型，而由版本化 `frozen_identity_rebind_v1` 写入系统已知 identity，并同时绑定原输出、feedback、变更字段、完整 material 投影和 rebind 输出哈希。任何 non-binding contract 问题、二次 grounding、投影变化或 raw/decision 不一致都会停止审核。失败 checkpoint 只复制重新通过全部 primary 校验的 raw/decision 对，并以内容哈希、源 SHA、受保护 run identity、计数、answer-free failure code、有限 retry/exit 信号和失败 retry 的通用 validation class/error hash 绑定；恢复调用必须同时绑定 protected run ID、不可变 artifact ID 与 source SHA。harness 通过 GitHub REST 单 artifact 端点逐一校验 metadata、run/source/name/expiry、服务端 SHA-256 digest 和 ZIP 路径安全，再把 manifest 的 workflow run identity 与预期 run ID 逐字比较；禁止依赖会按同名 artifact 过滤旧版本的 `latest` 列表。它固定为 non-formal，恢复时针对当前 packet 逐对象重验，孤立或无效输出不复制且不能进入仲裁、provenance 或 attestation，恢复 manifest 在继续主审前移除。双主审 matrix 不 fail-fast，失败后 checkpoint 步骤显式使用 `failure()`，retained-workspace recovery 必须在新 checkout 前冻结指定主审的原 workspace，并用当前受保护 harness 生成同一严格 checkpoint。
- 新 workflow SHA 可以通过显式 run/source identity 引用已完成的 Fable/DeepSeek primary artifact。当前 harness 会先把全部 136 对 raw/decision 逐对象重验为 complete checkpoint；任一 invalid、incomplete、missing 或 failure record 都在模型调用前 fail closed，且完整 artifact 与失败 checkpoint 输入互斥。只有 136/136 门禁通过后，primary 才以 `resume` 生成全 `reused` manifest，从而在升级编排代码时保持两个 primary 零重跑。
- Codex 仲裁计划（`opus` 兼容槽位）绑定全部 packet 以及两侧 primary decision/raw 哈希，并按 truth ID 的 SHA-256 确定性分为 4 个单 worker shard。每个 packet 的输出立即写入按 run/attempt/shard 隔离的 runner 临时目录；重跑优先恢复已上传 checkpoint，否则从同一 runner 的上一 attempt 重新构造并全量复验 checkpoint，跨 runner 时最多只损失一个 shard。每个 shard 独立完成、上传和重跑；失败 checkpoint 只保留该 shard 内重新通过 Codex 全校验的成对输出，并绑定 source/run、全计划哈希和 shard identity。最终合并重新计算计划、逐 shard 和逐对象复验，要求 shard 0..3、mandatory、全部主审分歧与证据缺口的并集精确覆盖且无重复，然后才恢复下游使用的单一 `zscope.range-v16-arbitration-run.v1` manifest。这样 `rerun-failed` 不会重做已成功 shard，也不会把 non-formal checkpoint 当作 provenance 或 attestation 输入。
- Codex protected review 在任何 primary/shard 启动前先由共享 readiness job 校验脱敏 doctor 的凭据、provider HTTPS、安装和 runtime provenance，再以不含 benchmark 材料的常量 schema 对冻结模型执行一次活性探针；各 shard 和 safe-pair author runner 另做 doctor-only 校验。`CODEX_API_KEY` 只注入 Codex 调用步骤，空 secret 不得覆盖 sealed runner 的 `CODEX_HOME` 登录。readiness 只输出固定 answer-free failure class，不归档 doctor 正文或探针输出；失败后通过 `rerun-failed` 恢复，禁止用四 shard 首包失败反复探测服务状态。
- `zscope.range-gap-analysis.v1` 是 answer-bearing 后置分析：每个 default FN 只能有一个主因，输出绑定 report/score/truth/usage/replay SHA 与 run identity。它不参与扫描或候选生成，避免把 truth 反馈进产品逻辑。
- `zscope.postscore-decision-trace.v1` 只在报告和 scorer 输出都冻结后读取 truth，把 TP/FP/FN 关联到 decision/coverage trace，并指出最早可诊断环节。该产物固定 `answer_material_present=true`、`product_trace_mutated=false`；不能被扫描器、Planner、Agent 或产品 trace 读取。
- Balanced 默认切换与后续非回归分别读取 policy 的 `sealed_delta_gates` 和 `non_regression_gates`。public external、sealed 与 shadow 结论只能由独立 attestation 注入，scanner 自己的报告不能自我签发。`zscope.balanced-default-attestation.v1` 绑定 Juliet/SV-COMP/Magma formal aggregate、dataset、truth、scanner bundle、scorer、Git、配置、rules、policy、model spec 和 baseline SHA。benchmark 聚合也必须通过 `--balanced-attestation-workflow-run-id` 接受调用方从受保护工作流取得的独立运行身份，缺失或与 artifact 不一致时 fail closed；它不把自包含 content hash 当成签名。受保护的 `balanced-default-attestation.yml` 只能从 scanner checkout 之外导入独立测试团队保管的证据；Release 按 workflow run ID 下载不可变 artifact，并通过 `evaluate_release_candidate.py --balanced-default-attestation --balanced-attestation-workflow-run-id` 同时绑定 release SHA 与签发运行身份。内容摘要负责完整性，签发信任来自受保护的独立测试环境和 artifact 链。
- 性能门禁只读取 `scan_wall_seconds`；`end_to_end_wall_seconds` 单独展示，`wall_seconds` 仅作为历史 v2 artifact 的兼容别名。
- confirmed 与 with-review 的 recall/precision 必须同时展示，旧顶层 `recall` 只能解释为 confirmed 兼容视图。
- 正式成本账本必须归档去重后的逐 HTTP attempt `llm_usage_events.jsonl`，绑定 SHA 与 call count，并逐项校验 provider usage、finish reason、cached/reasoning 子项、retry/repair、工具数和新增事实数；Prompt、响应与 reasoning 正文不得进入该 sidecar。报告还应给出 tokens/KLOC、tokens/TP，以及绑定 Arm A 后的 marginal tokens/新增 TP。
- `validator-replay-bundle.v1` 与打包的 `validator_arms.v1.json` 构成 A–E 隔离实验输入；replay CLI 不得读 truth，scorer 只能在结果 ledger 冻结后独立运行。Arm E 只定义可复现的旧多轮执行契约和不超过 17M 的 run cap，不能在没有实际 replay artifact 时宣称已有 GLM-5.1 结果。
- D0–D4 消融 plan/request 只描述 answer-free scanner 输入，不是评分结果；所有 arm 每轮都使用同一 12M post-run 成本预期、固定 Validator 和冷缓存，且 scanner report 必须显式携带 plan/arm/config/Validator SHA。消融 artifact 永远不能进入 formal Release，D4 也不能由 D3 或生产流水线别名代替。
- A–E 严格实验 scorer 不接受调用方传入的 truth object、自报 hash 或少于五轮的 arm；`--cold-trials-attested` 只是外部调度对独立 cold run 的操作员声明，不是签名，也不替代 OCI/CI attestation。其输出固定 `release_eligible=false`，胜出 arm 必须在后续受保护 formal 扫描中重新满足发布门禁。E 的 17M 只放宽 replay 执行实验上界，不改变所有 arm 共用的 12M `per_run_tokens` 发布门禁。
- 不在通用规则、Agent prompt 或源码注释中嵌入 truth id、专用函数名或答案描述。
- 正式 benchmark 结果不得通过提交到发布 SHA 自身来完成绑定；Release 必须消费受保护 Environment 产生、名称和内部 `git_sha` 均匹配发布 SHA 的不可变 workflow artifact。

## 常见变更应落到哪里

- 通用 benchmark schema、匹配或产物：`zscope/benchmarking/protocol.py`。
- CLI harness、suite 准备和评估：`scripts/external_benchmark.py`。
- 确定性 Range 回归：`scripts/evaluate_range_regression.py` 和对应测试。
- Range fixture、入口或 truth：`test/range/`，必须同步映射、覆盖预检和版本化评测资产。
- 正式运行协议和环境：`docs/range-benchmark.md` 与 `docs/java-benchmark.md`。

## 对应测试与验证命令

```bash
python -m pytest -q tests/test_benchmark_protocol.py tests/test_benchmark_leakage.py
python -m pytest -q tests/test_benchmark_runner.py tests/test_range_benchmark_regression.py
python -m pytest -q tests/test_range_release_aggregate.py
python -m pytest -q tests/test_benchmark_v4_contract.py
python -m pytest -q tests/test_validator_replay.py
python -m pytest -q tests/test_replay_provider_executor.py
python -m pytest -q tests/test_validator_experiment.py
python -m pytest -q tests/test_discovery_ablation.py
python -m pytest -q tests/test_discovery_ablation_experiment.py
python -m pytest -q tests/test_external_benchmark_oci.py
python scripts/check_benchmark_hygiene.py
python scripts/evaluate_range_regression.py --deterministic-candidates
```

完整 LLM/unified 扫描需要有效模型配置和 Linux 工具链，不应作为普通单元测试自动启动。

## 权威源码和关联文档

- 稳定入口见本文 frontmatter 的 `sources`。
- Range 执行、隔离和评分协议以 `docs/range-benchmark.md` 为准。
- 外部 suite 协议见 `docs/progress_docs/external_benchmark_protocol.md`。
- 历史结果只从当次 run 目录和 release 报告读取，不复制到本模块说明。
