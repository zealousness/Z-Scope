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
  - zscope/benchmarking/review_experiment.py
  - scripts/replay_review_experiment.py
  - scripts/score_review_experiment.py
  - scripts/pilot_review_claims.py
  - zscope/benchmarking/discovery_ablation.py
  - zscope/benchmarking/discovery_ablation_experiment.py
  - zscope/cli/benchmark.py
  - scripts/external_benchmark.py
  - scripts/evaluate_range_regression.py
  - scripts/aggregate_range_release_runs.py
  - scripts/check_benchmark_hygiene.py
  - scripts/portable_release.py
  - scripts/evaluate_release_candidate.py
  - scripts/run_validator_replay.py
  - scripts/describe_validator_replay_provider.py
  - scripts/score_validator_replay_experiment.py
  - scripts/plan_discovery_ablation.py
  - scripts/run_discovery_ablation_request.py
  - scripts/score_discovery_ablation_experiment.py
  - docs/range-benchmark.md
  - test/range/benchmark/check_entry_coverage.py
tests:
  - tests/test_portable_release.py
  - tests/test_benchmark_protocol.py
  - tests/test_review_experiment_protocol.py
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
---

# Benchmark

## 职责与非职责

本子系统负责统一 benchmark 数据形状、ground truth 匹配、双视图指标、外部 suite 准备/运行、Range 回归和发布结果聚合。`test/range` 是包含故意缺陷的 fixture，用来测量检出与误报，不是待修复的普通 C 项目。

它不负责给扫描模型提供答案，不负责通过定制 benchmark 名称提升规则命中，也不把一次历史成绩写成永久产品事实。

## 主入口和数据流

- `zscope/benchmarking/protocol.py` 提供 `zscope.benchmark.v4` 单次评分、候选生命周期漏斗、发现/决策二维归因和成本指标；旧 schema 仅作只读兼容。漏斗的 `canonical_group_attribution` 同时投影验证升级阶梯：`reached_by_rung`/`confirmed_by_rung`/`drop_reason_by_rung`（R1=R1_validator_v1、R2=R2_v3_reattempt、R3=R3_v2b_adjudication，R3 臂交付前恒 0）。
- 验证级 rung 实验（R2/R3/τ）用 answer-free replay 臂离线差分：`scripts/replay_tau_channel.py`（τ 扫描，谓词与 pipeline 逐项对齐）与 `scripts/run_validator_replay.py`/`scripts/score_validator_replay_experiment.py`；扫描级 rung 累积差分用 `scripts/rung_attribution.py`（输入多份 run artifact 输出 TP_added/FP_added/tokens 差分表）。
- `zscope-benchmark` 是内置 fixture 的唯一公开入口；`smoke`、`trial`、`formal` 分别承担离线结构门禁、单轮预览和至少五轮的发布门禁。
- `scripts/external_benchmark.py` 是外部 suite 和 Range JSON 报告的标准评测入口。public external formal 当前只接受 `full_zscope_pipeline`，通过 `RootlessOciExecutor` 实际执行 scanner、采集 inspect evidence 并在容器退出后由 host scorer 读 truth；静态 `oci_capability` 不能形成 formal 结果。
- `scripts/evaluate_range_regression.py` 评估确定性候选的 Range 覆盖。
- `check_entry_coverage.py` 在正式扫描前核对入口覆盖；它可以读取 truth，但不得把 truth 传入扫描 prompt。
- 扫描报告生成后，独立 scorer 读取报告与 ground truth，输出 matched pairs、TP、FN、raw/effective FP、precision、recall 和 F1。
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

- Review 实验 checkpoint 保存完整事实、构建依赖、前序 ValidatorResult 和原始工具结果；拒绝 truth、评分和离线标签字段。报告投影只允许 compiler pilot 诊断，缺少精确前序结果或失效依赖时不得当作可恢复 replay。
- `replay_review_experiment.py` 在 Linux/WSL 中按冻结 RC 清单恢复，使用真实 ValidationRunner 的最终分流与关联 Ledger；baseline、protocol、facts、neutral、positive、related 各组独立运行。neutral 与 positive 使用相同工具、模型、迭代预算，只有 V3 任务目标不同。输出写在独立实验目录，正式 unified 协议、答案隔离和成本要求保持不变。
- 独立审计分类为 true_defect、provable_fp、duplicate、out_of_scope、unknown，审计文件以内容哈希冻结，不能以未匹配 truth 推导 FP。`compare_paired_replays` 需要五个独立配对、每轮 truth 集合不退化、confirmed FP 不增加、全部原候选可追踪，以及自动拒绝可重新检查。新增关联 FP 纳入 review 总量，任何未知审计项或缺失正式 truth 集合都不得给出达标结论。

- 扫描上下文与评分答案严格隔离；benchmark leakage 测试必须持续通过。
- replay bundle 必须把同一 canonical cluster 的 alias occurrences、evidence 和 facts 做顺序无关的 union，并绑定 candidate/occurrence/entry/evidence/facts 的内容哈希；初始 facts 与 frozen reservoir 必须分区且无 record/UID 重叠。执行时还必须由调用方提供预期 bundle SHA，防止攻击者修改内容后自行重算内部哈希。
- Range 是分布内开发/回归集，不是生产泛化结论。发布必须依次报告 Range、public external、独立团队保管的 sealed 集和真实项目 shadow；没有 sealed attestation 不能宣称通过生产门禁。
- formal/sealed 扫描必须在 rootless OCI 隔离中运行，只挂载 answer-free 项目、配置、工具链和输出目录；scanner cwd、mount 和环境不得可达源码 checkout、`test/`、truth 或 scorer。缺少 Podman/Docker 隔离能力时 fail closed。
- formal workflow 除要求 `repository@sha256:<digest>` 外，还校验 scanner image 的 `org.opencontainers.image.revision` 等于被测 Git SHA；每轮 summary 绑定 report、score、input manifest、tool health、Validator replay bundle 与原始 usage sidecar 的实际字节 SHA，Release evaluator 会从下载 artifact 重新计算并逐项对账。
- public external formal 必须把项目复制到 checkout 外的临时 sealed input，再复制到独立的 writable cache project；只读输入、writable artifact 和 writable cache 三个 mount 必须互不包含。entries 要先通过 answer-key 字段检查，容器 config/compile commands 只含容器路径，truth 必须等 scanner 退出并通过 `require_release_isolation` 后才由 host scorer 加载。
- 正式 unified 结果要求 Linux 用户态和完整工具链，SVF/Saber 降级结果不能冒充正式结果。
- Windows 主机使用 WSL；原生 Linux 直接运行等价命令；原生 Windows 不形成正式结果。
- `test/` 不包含执行 runner、历史报告或后台 launcher；fixture 根每种语言只保留一份正式配置。
- C/C++ formal 不读取 deterministic entry manifest，入口必须由隔离副本中的自动发现产生。
- scorer 以结构化 file/function/category/location/evidence 匹配，并保留 `matched_pairs` 供人工审计。类别门是单向任一命中：truth 单一 `category` 命中 issue 的类别集合（`category`/`categories`/`defect_class`/`defect_family` 等）即 `category_exact`；两侧 CWE 集合（含 `cwes` 列表与斜杠复合标签）有交集即 `cwe_exact`；同预定义族为 `category_family`。配对策略为多 TP：每个 truth 独立认领其分数最高的强配对，同一 issue（例如聚合后的多 CWE 位点）可命中多个 truth，而每个 truth 无论被多少 issue 命中都只计一个 TP；额外的同位 issue 走 `truth_covered_additional`/`same_product_root` 豁免。
- raw FP、duplicate-of-matched 和 effective FP 必须分开保留，不能通过静默删除重复报告美化指标。
- 没有 safe units/true negatives 的数据集不得把 `FP/(TP+FP)` 称为经典 FPR；应报告 actionable FDR、raw FP 和 precision。经典 FPR 仅在 truth 明确给出 safe units 时计算。
- 每次正式评分必须输出 `discovered_by × decided_by` 交叉表、LLM 独占 TP、tokens/TP、marginal tokens/新增 TP、tokens/KLOC、p50/p95、五轮 Jaccard/极差和 Range→sealed generalization gap。
- 新 formal finding 显式归因覆盖率必须至少 99%，call 级 usage 与 run summary、by-agent、by-stage 聚合必须守恒。
- 新 formal Range 使用冻结 Arm A 的五轮 paired baseline；聚合器实际执行 111 TP、10M 中位数、12M 单轮硬上限、FDR +1pp、TP Jaccard 0.90、recall 极差 2pp，以及 provider usage、归因、队列、telemetry、token 守恒和协议异常门禁。缺失字段不能按零值或历史默认通过。
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

Review 实验由 `replay_review_experiment.py` 读取无答案的完整检查点；`score_review_experiment.py` 在回放输出冻结后独立读取审计和 truth，复用官方评分并重放拒绝证明。五轮必须属于同一 arm、拥有不同 pair ID，并绑定相同输入、模型、调查限额和审计摘要。所有 unknown 审计项仍阻止验收通过；未匹配 truth 不能推断为 FP。

开启 review RuntimeSpec 的 trial 会保留原生 Linux 工作目录，并在产物目录写 `review-workspace.json`，确保绝对依赖路径可重放；源码归档仍只复制密封输入。失败或中断也保留已产生的检查点。默认 trial 继续清理临时目录。此实验能力尚未取得正式资格，formal 入口拒绝这些开关，既有发布门禁不变。

## 权威源码和关联文档

- 稳定入口见本文 frontmatter 的 `sources`。
- Range 执行、隔离和评分协议以 `docs/range-benchmark.md` 为准。
- 外部 suite 协议见 `docs/progress_docs/external_benchmark_protocol.md`。
- 历史结果只从当次 run 目录和 release 报告读取，不复制到本模块说明。

## Portable 发行验证

`scripts/portable_release.py` 负责四个语言/架构发行件，`scripts/portable/abi.py` 分开审计运行 ELF、当前架构的 JAR 原生资源和编译 sysroot。manifest v2 校验要求四包、哈希、逐包 SPDX 与实际离线 smoke；正式发布另要求干净源码、匹配 tag 和签名，旧 v1 资产校验继续兼容。兼容性 smoke 使用普通用户、只读发布目录和断网容器，ARM 证据注明 QEMU。该证据验证发行可用性，不替代本模块的正式 benchmark、源码隔离和受保护 attestation 门禁。具体命令统一维护在根 `AGENTS.md`。
