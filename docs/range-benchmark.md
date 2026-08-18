# Range C/C++ benchmark protocol

## 唯一入口

所有本地与发布执行都通过 `zscope-benchmark`：

```bash
zscope-benchmark run --language c_cpp --mode smoke
zscope-benchmark run --language c_cpp --mode trial
zscope-benchmark run --language c_cpp --mode formal --runs 5
```

`smoke` 不调用 LLM，只验证 fixture、配置、truth、CMake 构建和结构门禁；
`trial` 恰好执行一次冷扫描且永远不具备发布资格；`formal` 拒绝少于五轮并执行发布门禁。Windows 上 C/C++ 命令自动转入 WSL，Linux 直接执行。

## 真源与输入隔离

`test/range/benchmark/ground_truth.json` 是唯一评分真源。当前 v15 只用于描述性回归；新 formal 结果必须绑定独立签发的 v16 truth contract。任一版本的 `total_vulnerabilities` 都必须与记录数及唯一 ID 一致，文档不维护另一份漏洞表。

每轮从 fixture 复制严格 allowlist：`src/**`、`include/**`、`internal/**`、`CMakeLists.txt` 和中性 README。整个 `benchmark/`、报告、缓存、构建目录和本地运行历史都不能进入 scan-input。health/index/scan 环境不含 truth 路径，报告落盘后才由独立 score 子进程读取 truth。Range 仅是分布内开发回归集；它没有 safe control，也不能代替跨项目 public external、sealed 与 shadow 结果。

`benchmark/deterministic_entries.json` 只服务无 LLM 的确定性候选回归，不是 fixed-entry 正式协议，也不参与自动入口发现。

## 环境与门禁

C/C++ trial/formal 需要 Linux 用户态以及 CMake、clangd、gclang、get-bc、LLVM、SVF/Saber 全工具链，并要求显式设置 `Z_SCOPE_LLM_BASE_URL`、`Z_SCOPE_LLM_MODEL` 和 `Z_SCOPE_API_KEY`。任何深度工具缺失都会失败，不允许以降级结果形成 unified 结论。

首次执行前应在**实际运行 benchmark 的 Linux/WSL shell** 中完成以下 bootstrap。示例路径对应 README 中的 SVF 3.2/LLVM 18 安装布局；自定义安装必须换成实际路径：

```bash
cd /path/to/Z-Scope

# 使用 WSL/Linux Python 安装当前 checkout；不要复用 Windows Python。
python3 -m venv "$HOME/.venvs/zscope"
source "$HOME/.venvs/zscope/bin/activate"
python3 -m pip install -e .

export PATH="$HOME/go/bin:/usr/lib/llvm-18/bin:$HOME/.local/svf/SVF-linux-x86_64/bin:$PATH"
export LD_LIBRARY_PATH="$HOME/.local/svf/SVF-linux-x86_64/lib:$HOME/.local/svf/llvm-18.1.0.obj/lib:${LD_LIBRARY_PATH:-}"
export LLVM_COMPILER=clang
export LLVM_CC_NAME=clang-18

# 使用实际 provider endpoint/model；密钥应来自本地秘密文件或 CI secret store。
export Z_SCOPE_LLM_BASE_URL='https://provider.example/v1'
export Z_SCOPE_LLM_MODEL='your-model-id'
export Z_SCOPE_API_KEY='your-secret-from-a-secret-store'
```

`zscope-benchmark` 不会自动读取 `test/range/zscope.local.env`。若本地选择使用未纳入 Git 的 env 文件，该文件必须提供上述三个 LLM 变量，并由操作者在启动命令前显式加载，例如 `set -a; source /path/to/private.env; set +a`。不得在日志、报告或提交中输出密钥值。

运行前执行 preflight；每个命令都必须成功，`ldd` 不能出现 `not found`：

```bash
for tool in cmake gcc clang clangd gclang get-bc llvm-link llvm-nm wpa saber; do
  command -v "$tool" || { echo "missing tool: $tool" >&2; exit 1; }
done

python3 -c 'import zscope; print(zscope.__file__)'

if ldd "$(command -v wpa)" | grep -q 'not found'; then
  ldd "$(command -v wpa)" >&2
  exit 1
fi
if ldd "$(command -v saber)" | grep -q 'not found'; then
  ldd "$(command -v saber)" >&2
  exit 1
fi

zscope-benchmark run --language c_cpp --mode smoke
```

从 Windows PowerShell 启动时，前端只会通过 `WSLENV` 转发当前 Windows 进程中已经存在的三个 LLM 变量；它不会读取 WSL 的 `~/.bashrc` 或私有 env 文件。最稳妥的方式是在已经完成上述 bootstrap 的 WSL shell 中直接运行 `zscope-benchmark`。若必须从 PowerShell 启动，则应先在同一 PowerShell 进程中设置 `$env:Z_SCOPE_LLM_BASE_URL`、`$env:Z_SCOPE_LLM_MODEL`、`$env:Z_SCOPE_API_KEY`，并保证 WSL 的非交互 shell 也能找到完整工具链和共享库。

在 WSL 中，trial 会把 scan-input、构建目录、索引和 Z-SCOPE 状态放到 WSL 原生文件系统的临时工作区，结束后只把密封输入、日志、报告和评分结果导出到 `benchmark-artifacts/`。可用绝对路径环境变量 `Z_SCOPE_BENCHMARK_WORK_ROOT` 覆盖临时根；C/C++ 会拒绝 `/mnt/<drive>`，避免 DrvFS I/O 进入正式性能结果。

formal 与 sealed 还必须在 rootless Podman/Docker 容器中执行 scanner。只读挂载 answer-free scan-input、配置和工具链，只写挂载输出；不得挂载 Z-SCOPE 源码 checkout、`test/`、truth 或 scorer，容器工作目录也不能位于源码树中。网络仅允许配置的模型 endpoint。runner 必须保存 runtime、cwd、mount 和 network-policy evidence，并在隔离能力缺失或越界挂载时 fail closed；评分在 scanner 容器退出后由独立进程完成。

受保护的 formal 环境必须配置 `Z_SCOPE_BENCHMARK_OCI_IMAGE`（`repository@sha256:<64-hex>`）、`Z_SCOPE_BENCHMARK_OCI_NETWORK` 和 `Z_SCOPE_BENCHMARK_OCI_MODEL_PROXY_CONTAINER`。该 internal network 在启动 scanner 前只能包含一个带 policy digest 的模型 endpoint proxy；缺少变量、rootless 证明、镜像 digest 或实际 inspect 证据都会直接阻断 formal 运行。

计时口径显式拆分：`scan_wall_seconds` 来自扫描报告的 `summary.batch_wall_seconds`，用于跨轮比较和 rollout 的 p95 回退判断；`end_to_end_wall_seconds` 是 runner 从输入准备到评分完成的总耗时。兼容字段 `wall_seconds` 等于 `scan_wall_seconds`。artifact 另记录验证队列 wall time、session/API call 数和实际 Validator/LLM 并发配置。

质量也必须按两种视图读取：`confirmed_recall`/`confirmed_precision` 只统计已确认 finding，`with_review_recall`/`with_review_precision` 将 needs-review 纳入人工复核队列。旧顶层 `recall` 仅是 confirmed 视图的兼容字段，不能称为“总召回”；两种视图的完整计数保存在 `quality_views`。Range 没有 true negatives，`FP/(TP+FP)` 必须称 actionable FDR，不能称经典 FPR。

新评分必须声明 `scoring_contract.matcher_version=zscope.truth-matcher.v2`。matcher v2 只消费 finding 的显式 category/defect family/CWE 与版本化通用别名，并要求 finding 和 truth 的 `file + function + line range` 来自同一对结构化锚点；call path、`related_functions`、truth keyword 和自由文本只生成弱诊断，不能形成 TP。一个 truth 已被强匹配后，额外 finding 分为 `same_product_root`、`truth_covered_additional`、`cross_anchor_overlap`、`weak_legacy_overlap` 或普通 `false_positive`。`actionable_precision=TP/(TP+raw_fp)` 始终惩罚所有额外展示项；`root_cause_precision` 仅从 effective FP 中排除前两类，跨锚点与弱文本重叠仍计为 effective FP。兼容字段 `duplicate_of_matched_count` 仅是 `same_product_root_count` 的弃用别名。

历史 `zscope.benchmark.v4` 没有 matcher v2 标记时仍可只读，但不得与新结果直接作召回回归结论，也不得进入新的 formal 结果。可用 `scripts/compare_range_matchers.py` 对冻结报告先做 answer-free Finding-root v2 投影，再分别保存 matcher-v2 score 与 v1/v2 差异审计；该工具不会重跑扫描，也不会覆盖旧 score。弱匹配经独立审计确认确属漏洞时，只能在单独治理变更中补充结构化 truth anchor 或新增 truth，不能为某个 truth ID 增加 scorer 特例。

新正式 artifact 使用 `zscope.formal-benchmark.v3`，单轮评分使用 `zscope.benchmark.v4`，唯一门禁源为版本化 `zscope.benchmark-policy.v1`。它们附加输入文件 SHA-256、manifest SHA-256、canonical phase argv、RuntimeSpec、Rule Catalog/qualification、配置、模型/prompt、token usage、归因和隔离 evidence。Release evaluator 验证这些字段、truth 隔离、五轮稳定性和 policy；历史 v2 artifact 只读，不改写也不能用于新 Release。

Validator A–E 隔离实验使用 `validator_replay_bundle.v1`。bundle 只含 canonical validation groups、事实、证据和全部身份哈希，禁止包含 truth、matched pairs、历史 Validator 输出或 verdict。事实合约显式分为 V1 初始 facts 和 provider-resolvable frozen reservoir；两区 record/UID 重叠时 fail closed，V2 不得把 V1 已见 fact 重新当作 delta。每轮必须导出 raw occurrence → grouped candidate → V0/V1/V2/V3 的漏斗、`discovered_by × decided_by` 交叉表、active-discovery 独占 TP，以及 call/by-agent/by-stage token 守恒结果。

v15 及更早 Range truth 只保留为描述性分布内回归，历史 111/136、116/136 与 10M/12M 数值不得再解释为当前产品运行时门限或 v16 正式资格。新 formal Range 必须绑定独立测试团队签发的 `zscope.range-truth-contract.v2`：只有 `concrete_trigger` 与 `public_api_contract` 进入 confirmed 分母，`pattern_model` 单列 design-risk/with-review，`retired` 不进入分母；门槛由 manifest 动态计算为 `ceil(0.85 × confirmable_truth_count)`。五轮仍须满足 actionable FDR、TP Jaccard、recall 极差、provider usage、归因、队列、token 守恒与规则 qualification 门禁；token 数值只是完整扫描后的 Pareto/非回归评价，不参与模型请求准入或提前终止。缺少 v16 contract、独立 attestation、冻结 Arm A 或任一绑定字段时 formal fail closed。

P0 replay 使用打包的 `validator_arms.v1.json` 与 `scripts/run_validator_replay.py`。输入只能是 answer-free `validator-replay-bundle.v1`；执行 ledger 会绑定 bundle、arm spec、模型、Prompt、每组 evidence slice/result 与 token 的哈希，truth 只能在全部输出冻结后由独立 scorer 读取。CLI 可传 run 级 `--expected-total-tokens`；2M/5M/8M/10M/12M 和 Arm E 的 17M 都是完整 replay 结束后的成本对照线，不会拒绝请求、缩短输出或跳过 cluster。P0 funnel 同时输出 occurrence、candidate、validation group、V0/V1/V2/V3（V4仅预留）及报告 finding 的不同计数单位，并以 `reached_by_level`、`transition_counts`、`drop_reason` 记录真实到达和停止原因，禁止把不同单位直接相除。

扩大默认视图召回的 balanced/deep 实验使用产品分档状态机，而不是把历史 replay Arm D 的 top-5% 短轨迹当作生产配置。先从同一冻结输入导出 answer-free replay bundle，验证多 fact 补全、V1→V2→V3 转移和 V3 新事实回写 promotion policy；随后每档只运行一次 cold pilot。若存在 eligible cluster 却没有 V3 调用，或 V3 verified 无法凭新增可解析事实重新进入 promotion policy，立即停止，不运行五轮。pilot 通过后才各运行五轮 cold unified 扫描，并固定 Git、配置、RuntimeSpec、rules、模型、Prompt、provider 和答案隔离身份。

旧 V3 trace 的零模型离线重验使用 `scripts/reverify_v3_trace.py --trace-root <snapshot_dir> --output <result.json>`。该命令只读取 manifest 绑定的 trace/evidence，不接受 truth、report scorer 或模型配置；它把旧 claim 重新分类为有效证书、`provider_semantic_mismatch` 或 `coverage_incomplete`。中断扫描的 trace 可用于协议诊断，但不能冒充 terminal canary：只有 manifest complete、全部目标 cluster 有终态且新 EvidenceAction 会话满足闭合率门禁后，才允许启动 cold balanced pilot。

新 action canary 前先在 Linux/WSL 运行 `scripts/prepare_v3_action_canary.py`，把旧 V3-entered obligation 绑定到当前 answer-free source tree 和 compile database，并执行有限本地 action。输出只含 source/certificate hash、action 状态和 clause delta，不调用模型、不读取 truth；历史上 required fact 为空或当前没有 action 的 cluster 会单列为旧资格错误，不得进入当前模型 canary。最多选择前12个当前可执行 cluster（冻结样本不足12个时选择全部）；少于3个可执行 session，或其中少于3个能由本地 action 关闭至少一个 clause时返回2。该 preflight 通过只表示可以启动真实模型 session，不等同于“V3 session 已完成”的最终门禁。

preflight 通过后使用 `scripts/run_v3_action_canary.py`，并通过 `--expected-preflight-sha256` 外部绑定其 artifact。该命令只对 preflight 选中的当前可执行 cluster 发起连续 V3 session，固定最多50轮，执行当前源码上重新生成的有限 action，并输出每个 cluster 的 clause delta、模型轮数、工具调用和 provider usage。它不接受 truth/scorer 参数，产物永久标记为 non-formal；只有至少3个 cluster 关闭 clause、协议错误为0、provider usage覆盖100%，且同 cluster V3 token 相对冻结历史下降至少50%时返回0。即使返回0，trace manifest 不完整或尚未完成 cold scan 时也不得形成 balanced 质量结论。

该实验每档必须同时报告 default 与 with-needs-review 的 TP、raw/effective FP、precision、recall、F1 和 FDR；V0/V1/本地 fact/V2/V3 到达、退出和 verdict transition；fact kind 的 `resolved/no_match/unsupported/timeout/provider_error/conflicting`；V3 按来源终态、风险层、fact kind 的 eligible/entered/confirmed；每个 V3 新增默认 TP 的模型轮数、工具调用数和 token；semantic modeling、active discovery、Validator V1/V2/V3 的逐 agent/stage token；以及五轮 median、min/max、TP Jaccard 和 recall 极差。v16 实验目标为默认视图 median recall 至少 85%，其绝对 TP 门槛从签发 manifest 的 confirmable 分母计算，precision 相对同档冻结基线下降不超过 1 个百分点，同时要求 provider usage 覆盖 100%、token 守恒、队列排空且没有无 proof 静默拒绝。该结果只代表分布内验证，不能替代 external/sealed 门禁。

`scripts/analyze_range_gaps.py` 在 report/score/truth 全部冻结后生成 `zscope.range-gap-analysis.v1`，把每个 default FN 唯一归入反证错误、V3 资格、fact exhaustion、V3 事实消费、模型拒绝、错误 obligation/anchor、无候选或 truth 争议，并绑定 report、score、truth、usage sidecar 与 replay bundle SHA。该后置账本用于区分产品提升、Scorer 变化与 truth 治理变化，不进入扫描上下文。

v16 不能由扫描实现方自行签发。当前争议项只登记在 `docs/benchmark-maintenance/range/range_v15_truth_review_queue.json`，状态固定为 pending/non-formal；独立测试团队必须按双人审查、第三人仲裁把每项归为 `concrete_trigger/public_api_contract/pattern_model/retired`，绑定审查证据与 attestation 后，才能生成 formal-eligible v16。禁止为通过门禁而在同一产品变更中修改 fixture、truth 和检测逻辑。

五轮输出冻结后由 `scripts/score_validator_replay_experiment.py` 独立评分。调用方必须传入 bundle、catalog、truth 和 Arm A–E 各 1–5 轮的外部预期 SHA，并显式签署 `--cold-trials-attested`；scorer 会先校验完 25 份 answer-free ledger，才打开 truth。结果严格绑定输入文件/内容/run/scorer/policy 哈希，计算每轮 TP、recall、actionable FDR 和 token，以及每 arm 的中位数、最大值、Jaccard、recall 极差、provider usage、队列、协议和守恒门禁。Arm E 即使以 17M cap 执行，也没有 12M `per_run_tokens` 发布门禁豁免。

固定胜出的 Validator 后，D0–D4 语义/主动发现消融使用 `scripts/plan_discovery_ablation.py` 生成 `zscope.discovery-ablation-plan.v1` 和 25 份 hash-bound run request。所有 arm 使用同一 answer-free input/config/RuntimeSpec/rules/model/prompt/scanner 身份、同一 Validator selected arm/spec/catalog/model/prompt、balanced 的 12M 完成后成本预期和五轮 isolated-cold 缓存。D0 为规则/backend；D1 仅安全语义地图及选择性语义补全；D2 为零 LLM 地图骨架上的 candidate-blind 主动发现；D3 同时启用二者；D4 必须由独立 adapter 执行冻结的旧全入口多 Agent 路径，只作成本上界。开发入口 `scripts/run_discovery_ablation_request.py --execution-mode non-formal-in-process` 校验 request/executor/report arm，并从 scanner 指定的原始 usage sidecar 重新计算 SHA、provider coverage、stage/run 守恒和成本预期；同时绑定每轮 fresh snapshot/cache identity，resume/maintain 直接失败。D4 无 adapter 时 fail closed，不能用 D3 结果代替。

消融 planner 环境不得含 truth/scorer 变量，plan 输入也不得含候选 Ledger、历史 finding、规则结论或评分字段。`package.module` adapter 与 scanner 同进程，不能凭自身声明证明无法访问 truth，所以其 report/execution 固定 `answer_free_attested=false`、`formal_eligible=false`；正式消融必须由中央控制面使用 digest-pinned `RootlessOciExecutor` 与 sealed answer-free mount 执行，缺少 rootless OCI 或固定执行协议即 fail closed。25 份 report 全部冻结后才允许独立 scorer 读取 truth。所有 D0–D4 report 显式标注 `benchmark_ablation` 且永久 `release_eligible=false`；它们用于归因/成本实验，不能替代 Range、public external、sealed 或 shadow 的正式发布产物。

后置评分使用 `scripts/score_discovery_ablation_experiment.py`。调用方必须为每个 D0–D4/trial 组合同时传入 execution、report、raw usage JSONL，以及外部记录的 execution/report canonical SHA、文件 SHA和 usage SHA，并显式签署五轮 isolated-cold 属性；scorer 在读取 truth 前冻结全部 25 组 artifact，核对同一 plan/dataset/config/Validator、balanced/12M、arm/run 身份、execution→report→usage hash、complete、双视图与 provider usage/token/by-stage 守恒。输出同时保留 confirmed 与 with-review 的 TP/recall/raw FP/actionable precision/FDR、发现来源独占/交集、tokens/独占 TP 和五轮分布/Jaccard。由于该矩阵没有 paired warm run，热缓存收益固定报告为不可用；D4 仅解释为成本上界。评分产物本身同样永久 `release_eligible=false`。

Arm E 是冻结旧 Validator 多轮协议的成本/召回上界，不是第二个 bounded Validator v3 调查档位，也不表示仓库已经产生真实 GLM-5.1 或 17M 结果。A 冻结 generic loop 当前精确 forced-final 指令/terminal bridge；B 是不含该指令的真正单次结构化 V1。D 只在 high/critical、外部可达、risk≥80 且位于 top 5% 的 cluster 上，于 V2 仍不确定时执行一条最多两次冻结只读查询的轨迹。对 A–D，一次 replay executor 调用严格代表一次 HTTP attempt；对 E，一次调用代表一个 validation cluster 的完整旧多轮 session。E executor 只能读取 bundle 中冻结的 evidence/facts，并在单个 `usage` 对象中汇总所有内部 attempt 的 prompt/completion/cached/reasoning token、工具调用数及 `api_attempt_count`。未知/不合法 usage 使用请求投影做保守计量；runner 校验聚合守恒，并在完整执行后评价 17M 成本预期。

A–D 可直接使用内置真实 provider executor，不再要求项目自建 Python 插件。其专用 JSON 配置严格使用 `zscope.validator-replay-provider.v1`，只允许 endpoint、API key 环境变量名、单一模型、timeout、structured-output、temperature 和固定 `requests` transport；不接受项目路径、truth、scorer 或自定义 Prompt。例如：

```json
{
  "schema_version": "zscope.validator-replay-provider.v1",
  "base_url": "https://model-endpoint.example/v1",
  "api_key_env": "Z_SCOPE_REPLAY_API_KEY",
  "model": "glm-5.1",
  "timeout_seconds": 120,
  "supports_structured_output": true,
  "temperature": 0,
  "transport": "requests"
}
```

先在不解析 API key、也不发网络请求的步骤中导出实际配置、内置模板和加载代码派生的三个身份哈希，再由实验调度方冻结这些值：

```bash
python scripts/describe_validator_replay_provider.py --provider-config /answer-free/provider.json
```

执行时通过 `--builtin-provider-config` 和 `--expected-executor-sha256`、`--expected-model-spec-sha256`、`--expected-prompt-sha256` 传回外部冻结值；任一不符都在首个 HTTP attempt 前失败。executor hash 覆盖本执行器选择的已加载 bytecode 与 model/prompt hashes，但不声称递归哈希整个 Python 依赖闭包；formal artifact 还必须独立绑定 scanner bundle、Git SHA、RuntimeSpec 和 arm catalog，二者共同形成完整 provenance。每次 A–D executor 调用新建一个无 retry/fallback 的单 endpoint、单 model `LLMClient`；HTTP 前除 runner 的 evidence reservation 外，还按实际 system/user messages、JSON schema/terminal tool、response framing、max completion 和保守 framing envelope 对剩余额度做完整二次准入，不足即 fail closed。执行器只接受 provider 最终 usage，并如实计入 terminal tool call；ledger 不保存 Prompt、原始响应或 reasoning metadata，隔离 attempt 期间也禁用可能记录 provider error body 的 LLMClient logger，避免错误响应回显 Prompt。当前旧 Validator 没有同时满足“仅冻结 facts 工具”和“逐 HTTP attempt 完整 usage”的安全 session 接口，因此内置模式对 E fail closed；普通 `--executor package.module:callable` 仅能生成 non-formal ledger，不接受用户自报的 OCI evidence。formal E 必须等待 host-side RootlessOciExecutor 实际执行与 inspect 证据绑定；本轮未实现该 wrapper，因而 formal E fail closed。`--cold-trials-attested` 也只是调度方声明，不是签名；A–E 后置评分产物固定 `release_eligible=false`，只能用于选 arm，不能直接充当 Release 证据。

Balanced 默认切换在 Range 之外还要求：sealed recall 相对 fast 至少提升 3 个百分点、actionable precision 最多下降 1 个百分点、high/critical recall 不下降；主动发现独占 TP 覆盖至少 3 个项目和 2 个 CWE 家族；safe-entry alert rate 不超过 10% 且相对 fast 最多增加 1 个百分点；shadow precision@25 至少 70%、high/critical precision 至少 80%；budget-limited 扫描不超过 5%，并且无无 proof 静默拒绝。后续版本的 sealed recall、precision、high/critical recall 最多下降 2 个百分点，tokens/KLOC 或 tokens/TP 最多增长 25%。这些值只从 `zscope.benchmark-policy.v1` 加载，文档不是第二门禁源。

生产默认切换还需要独立测试团队签发 `zscope.balanced-default-attestation.v1`，绑定 Juliet、SV-COMP、Magma 三套 public external formal aggregate，以及 sealed dataset/truth、scanner bundle、scorer、Git、配置、rules、policy、model 和 baseline 哈希，并通过 Release evaluator 的 `--balanced-default-attestation` 显式传入。sealed 至少覆盖 6 个无关 C/C++ 项目、3 个领域、120 个漏洞/修复对与 1,200 个 safe audit units；单项目/CWE 不超过 25%，每季度或 sealed major 至少轮换 20%，活跃 case 只反馈聚合结果。attestation 同时记录至少 3 个 shadow 项目的双人盲审和分歧仲裁证据。Range 分数或 scanner 自报字段本身不能构成该 attestation；缺失时 fail closed。

## 清理

```bash
zscope-benchmark clean --scope c_cpp
zscope-benchmark clean --scope c_cpp --apply
zscope-benchmark clean --scope c_cpp --apply --include-runs
```

清理默认只预览。`--apply` 仅处理声明过的生成目录/文件；大型 runs、CodeQL 和 conversation 必须再给 `--include-runs`。tracked 文件、local env/config、SARIF、越界路径和符号链接永久受保护。

## 旧命令迁移

| 旧入口 | 新入口 |
| --- | --- |
| auto unified WSL runner | `zscope-benchmark run --language c_cpp --mode trial` |
| fixed-entry scan runner | `scripts/evaluate_range_regression.py` 的确定性回归；不再是 LLM benchmark |
| formal Python script | `zscope-benchmark run --language c_cpp --mode formal --runs 5` |
| background/alert/rebuild runner | 已删除；使用 foreground artifact 或专用产品命令 |

Global-model 诊断保存在 `benchmarks/experiments/range_global_model/`，明确为非发布实验。
