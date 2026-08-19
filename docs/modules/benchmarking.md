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
- Truth v16 的受保护双人审核把 raw stdout、decision、packet hash 和 reviewer command identity 分别归档并交叉验证。第二主审固定为 tool-free OpenCode 1.18.18 + `alibaba-cn/glm-5.2` + `variant=max`；DSH/DeepSeek 不具有 E0 reviewer 资格。GLM 对已通过 schema/身份但未通过 packet grounding 的输出最多执行一次 grounding-only 纠正；只有 anchors/evidence refs 可变，实质投影哈希必须守恒，任何二次失败或 raw/decision 不一致都会停止审核。
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
