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

E0完成后，v16位于独立的`benchmark/v16/`治理目录，使用`zscope.range-truth-contract.v2`和动态confirmable分母；`pattern_model`只进入design-risk/with-review指标，`retired`不评分。`scripts/score_range_v5.py`产生`zscope.benchmark.v5`，正式五轮聚合产生`zscope.formal-benchmark.v4`。v4/v15保持只读，不能与v5/v16直接宣称召回回归；缺少受保护E0 attestation时formal v5必须fail closed。

单轮formal v5还要求Security Spec、Hypothesis Hunter、Proof Engine、provider usage、token守恒和answer-isolation字段齐全；paired结果必须逐项绑定Truth v16中的pair UID、manifest/source hash及两个扫描报告hash。五轮聚合必须显式传入冻结基线precision，用于执行policy v2的precision-delta门禁：

```bash
python scripts/score_range_v5.py aggregate \
  --trial run-1/score-v5.json --trial run-2/score-v5.json \
  --trial run-3/score-v5.json --trial run-4/score-v5.json \
  --trial run-5/score-v5.json \
  --e0-attestation e0-attestation.json \
  --workflow-run-id "$TRUSTED_E0_RUN_ID" \
  --head-sha "$TRUSTED_E0_HEAD_SHA" \
  --baseline-actionable-precision 0.95 \
  --output formal-v4.json
```

`--workflow-run-id`和`--head-sha`必须来自调用方已验证的受保护GitHub artifact元数据，不能从attestation正文自取。输入JSON拒绝重复key和非有限数。

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

Podman 4.x 的 `network inspect` 可能不返回容器成员。此时 runner 必须额外使用带精确 network filter 的 `podman ps --all --format json` 重建成员快照，并验证每个返回容器都显式绑定目标网络；若两个来源都提供成员，则集合必须一致。成员快照进入 evidence hash，缺失 ID、网络归属、唯一 proxy 或执行阶段 scanner/proxy 二元成员关系时继续 fail closed。

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

GitHub `actions/upload-artifact` 的 `artifact-digest` 输出是 64 位裸 SHA-256；受保护 workflow 必须在 provenance 边界显式规范化为 `sha256:<64-hex>`，再交给严格 schema 和下游 attestation 校验。不得放宽 provenance schema 来接纳无算法标识的 digest。所有受保护审核上传统一经过仓库内 bounded composite：首次 CreateArtifact/FinalizeArtifact 失败后分别退避 3 秒和 7 秒，最多三次；后续尝试允许覆盖同名半成品，并且只有实际成功 attempt 的 immutable artifact ID、URL 和 digest 可以输出给 provenance。三次均失败必须 fail closed，不能用无限重跑掩盖外部传输故障。

受保护审核的必需 artifact 恢复不得重复依赖 `actions/download-artifact` 的 latest-list 查询。跨 run 的完整 primary reuse 必须提供精确的 `{run_id, source_sha, artifact_id, sha256}`；可复用的 arbitration shard 必须来自同一显式来源 run/source，并为每个选中 shard 提供精确的 `{artifact_id, sha256}`。只要选择任一 shard 复用，就必须同时提供两份完整 primary 的全部精确字段，且不能混用 failure-checkpoint 输入。下载器逐 ID 验证 repository、workflow path、`workflow_dispatch` event、`main` branch、来源 head/source、成功的 producer job、名称、ID、未过期状态、服务端与外部 SHA-256 digest，再以不向签名重定向转发 `GITHUB_TOKEN` 的方式下载。ZIP 必须通过路径穿越、反斜杠、symlink、重复成员和解压大小检查；普通 primary/shard 必须含 `manifest.json`，checkpoint 必须含 `checkpoint-manifest.json`，最终 reviewed、provenance、pair-author 则分别强制 `review-bundle-manifest.json`、`review-provenance.json`、以及 `normalized-decisions.json` 与 `author/manifest.json`，验证后才能原子安装。所有显式跨 run shard 先由单一 deterministic preflight 恢复并逐对象重验这两份 primary，再用当前 packets、当前 arbitration plan 和冻结模型身份逐对象重验全部选中 shard；该 preflight 是 Codex readiness 的依赖，因此任一显式输入缺失、组合不完整、producer job 未成功，或 metadata、digest、ZIP、plan、packet、primary/model binding 不一致，都会在任何模型调用（包括 readiness 活性探针）前 fail closed。只有全部选中 shard 都通过，才分别上传当前 run 的 complete reuse checkpoint 并放行 readiness、primary 与 arbitration matrix。matrix 恢复 checkpoint 后 zero-call resume，再把结果作为当前 run/source 的正式 shard 重新上传；同 shard 的当前 run failure checkpoint 优先于 preflight reuse checkpoint，禁止静默回退。finalize 的两份 primary 与四份当前 run 正式 shard，以及 arbitration 与 safe-pair author 的同 run checkpoint，继续使用严格不可变 artifact 恢复；`rerun-failed` 不触碰已经成功的 primary 或 shard。

每个 arbitration shard 的 job-local Codex doctor 可能在 `arbitrate` 创建输出目录前失败。该边界必须先建立只含空 `decisions/raw/failures` 的 answer-free checkpoint 骨架并发出固定 `codex_preflight_failed_before_arbitration` annotation，再由同一严格 checkpoint 构建器生成可上传、必须在 `rerun-failed` 时逐项重验的 non-formal checkpoint；不得因缺少输出目录让诊断构建和 artifact 上传连锁失败。

Safe-pair 匿名性检查从 packet 的函数调用形状和项目宏提取禁止标识符，但必须先排除完整 C11 关键字集合；`return (`、`for (` 等合法语言结构不能被误判为项目函数。C 标识符按完整 token 比较，不能因短项目名只是另一个新标识符的子串而误拒；truth ID 等非 C 标识符仍按完整字面量拒绝。项目函数、项目宏、truth ID 和其他专有标识仍须严格 fail closed。

Safe-pair author 首次返回严格对象但未通过确定性 author contract 时，只允许一次 answer-free contract repair。严格 contract schema 从同一冻结 packet 重算完整禁止标识符 catalog，并对两份完整源码施加与 validator 等价的零匹配约束；交给 Codex response format 的 wire schema 只保留 Structured Outputs 支持的约束子集，但仍以 `const` 绑定 truth ID、packet SHA-256 和 final-decision SHA-256。wire 省略的长度、唯一性或复杂匿名正则约束必须由同一严格 schema 和确定性 validator 在接纳前重新强制执行，不能成为治理降级。所有交给 Codex response format 的 `const` 与 `enum` 节点必须同时保留显式 JSON `type`；任一节点缺少类型或出现未批准的 wire keyword/regex 都必须在 readiness 或 reviewer 调用处 fail closed，不能把结构化输出编译失败误判为 reviewer 决策失败。raw v5 复核时必须从绑定 packet/decision 独立重算并精确核对 wire schema 与严格 contract schema 的两个 canonical SHA-256，不能接受只约束字段形状、未绑定身份或弱化本地禁止标识符验证的命令。repair 只能接收同一冻结 packet/decision、被拒绝的 author 对象、枚举 validation class，以及从同一 packet 重新计算的确定性约束；`source_not_anonymous` 约束列出完整禁止标识符 catalog、固定匹配语义，以及用同一匹配器计算的两份完整源码逐字段冲突清单和计数，注释、字符串、字符字面量与预处理文本中的命中同样必须清除；`sources_identical` 约束必须明确要求规范化换行后两份源码不同，并只重写 safe side 以落实冻结的 `safe_pair_recommendation`，禁止用注释、格式、纯重命名或不可达代码伪造差异；`independent_compile_failure` 只反馈未通过的 source 字段和冻结的 `cc -std=c11 -Werror -Wall -Wextra -c` 契约，不携带编译器 stdout/stderr 正文。初次对象、repair 对象以及 checkpoint/resume 重验都必须在接纳前让两份完整源码分别通过该编译契约。packet、decision、role、model identity 继续由 schema 与 validator 双重锁定，不允许重新仲裁。raw v5 envelope 必须保留初次与 repair 两次 stdout、stderr hash、调用种类、validation class 和唯一 accepted attempt，并验证最终 raw 输出与 author artifact 逐字段一致；repair 仍不合规时立即 fail closed，不允许第三次调用。

Safe-pair author 的 Codex 进程首次非零退出只允许一次同 Prompt、同命令和同冻结身份的 transport-only retry；初次 stdout/stderr 正文不保留，只绑定哈希。整个 review workflow 固定最多两个 run attempt（初次执行加一次最小 `rerun-failed`）；独立 attempt-budget job 在 readiness、artifact reuse 和任何模型调用前机器化拒绝 attempt 3 及以后，并只发出固定 `e0_review_attempt_budget_exhausted` annotation，不能依赖操作员纪律避免无界重跑。最多 8 路的 batch 必须等待并收集全部已完成 future，再以固定 answer-free failure class/count 汇总失败，不能因首个 future 抛错丢失同批已成功结果；出现失败后不启动下一批。失败作业把逐对象重验通过的 author/raw 对构造成 non-formal checkpoint；同一 workflow run 的 `rerun-failed` 从 runner 的前一 attempt 临时目录或已上传 checkpoint 重建恢复集合，逐对象复验 packet、decision、schema、command 和 raw/author 一致性后以 `--resume` 只处理缺失记录。每个逻辑 checkpoint 使用 `-attempt-<workflow-run-attempt>` 不可变名称保留全部历史；当前 run 的自动恢复只接受该严格后缀，并选择 `created_at` 最新且未过期的一份，用 artifact ID 作为同秒决胜键。单次 bounded upload 内部重试只可覆盖本 attempt 的半成品，不能删除旧 attempt。author 全部成功后必须先构造要求完整的 non-formal verified checkpoint，再尝试上传正式 pair artifact；checkpoint 构造失败是确定性协议失败并 fail closed，checkpoint 的纯上传失败不阻止正式 artifact 上传，正式上传失败后的 `rerun-failed` 可从已上传完整 checkpoint zero-call 恢复，而且完整恢复不执行 provider doctor。author 失败时自动运行现有 answer-free checkpoint diagnosis，只报告固定 class/count，并在 GitHub Actions 中把同一固定投影发为 notice annotation，允许监控方在不读取 job log/summary 的前提下分类；checkpoint diagnostics 不含审核正文。

当 GitHub 只能显示通用进程退出码时，`.github/workflows/range-v16-pair-author-diagnostic.yml` 可以在 sealed runner 上按显式 review run、source SHA、不可变 checkpoint artifact ID 和外部绑定 digest 恢复单个工件。下载器只在显式开启严格 `-attempt-<正整数>` 后缀校验时接受 review workflow 产生的 attempt-scoped checkpoint，不能放宽基础 artifact 名称。它只校验 checkpoint manifest 并把既有 failure record 投影为固定枚举及计数；若 checkpoint 无诊断信号或自身不满足读取契约，则只输出固定 rejection code，不回显异常正文。它不读取或输出 reviewer stderr、审核正文、truth ID、生成源码或 normalized decision，也不调用模型、不修改 checkpoint、不触发 review 重跑。诊断输出固定为 non-formal answer-free artifact，并以相同固定投影发出 notice annotation，只用于决定应修复 transport、author contract、诊断契约还是 checkpoint/resume 边界。

为兼容已经冻结的 artifact、truth 字段和 attestation schema，工作流继续使用 `fable` 与 `opus` 作为机器槽位名称；它们不再表示实际模型。`fable` 槽位现在由 Claude Code 2.1.233 调用 `glm-5.3`（high effort），`opus` 槽位的仲裁和 safe-pair author 现在由 Codex CLI 0.144.4 调用 `gpt-5.6-sol`（`xhigh`）。Codex 调用固定为 read-only、ephemeral、忽略用户配置和规则、禁用 shell tool，并通过内容绑定的 provider-supported wire JSON Schema 约束直接 JSON 输出；raw envelope 同时绑定 wire schema、严格本地 contract schema 的 canonical SHA-256 和完整 command identity。除这三条显式冻结的 reviewer 路由外，其他 CLI/provider/model 组合均不具有 E0 reviewer 资格。

safe-pair author 不重新接收完整 review packet、code windows 或完整最终 decision。它只接收由当前 normalized record 确定性投影出的 frozen packet identity、最终 decision hash、contract kind 和 `safe_pair_recommendation`，并明确限定为授权的防御性、无外部效果 benchmark 构造；完整 packet 仍只由本地 validator 用于匿名化和身份复验。raw envelope 以版本化 request schema 和 canonical request SHA-256 绑定该最小权限投影，同时继续绑定完整 packet/final-decision identity、wire schema 和严格本地 contract schema；请求投影或绑定不一致必须 fail closed。

Codex reviewer 启动前必须先通过受保护的 answer-free readiness 门禁。共享 job 在任何 primary 或仲裁调用前运行 Codex 0.144.4 的脱敏 machine-readable doctor，只接受凭据、OpenAI provider HTTPS 可达性、安装和 runtime provenance 四类必需检查，并用不含 packet、review、truth、fixture 或 scorer 的常量对象填充完整代表性仲裁 wire schema，对 `gpt-5.6-sol:xhigh` 执行一次 schema 编译与活性探针。每个实际仲裁 runner 与 safe-pair author runner 在调用前还要重复 doctor-only 检查，避免共享探针掩盖单个 self-hosted runner 的凭据或网络差异。受保护 Environment 可以用 `CODEX_API_KEY` secret 仅注入这些 Codex 步骤；未配置 secret 时空值必须从子进程环境删除，以免覆盖 sealed runner 的 `CODEX_HOME` 登录。doctor 正文和探针输出均不归档，只报告固定的 `codex_auth_unavailable`、`codex_provider_unreachable`、`codex_runtime_invalid`、`codex_model_probe_nonzero` 或 contract-invalid 类别及必要哈希。readiness 失败会在首个 benchmark packet 调用前阻断后续 job，修复外部凭据或网络后只运行 `rerun-failed`，不能用四 shard 首包失败充当可用性探针。

受保护 reviewer 输出必须逐对象绑定 packet、raw envelope 和最终 decision。第二主审固定为 DSH 0.1.0-rc.6，并由 DSH 临时只读 patch 严格绑定小写 provider `deepseek`、model `deepseek-v4-pro-0813` 与 `reasoningEffort=max`。Fable、DeepSeek 或 Opus 兼容槽位的初次 reviewer 进程非零退出时，只允许一次同输入、同命令和同冻结身份的 transport-only 重试；初次 stdout/stderr 不归档正文，只在 raw envelope 绑定哈希，第二次非零退出立即 fail closed。DeepSeek 的隔离 `decision-schema.json` 还以 `const` 绑定当前 packet UID/hash、role 和 model，且有界 format-only 重试只有在输出同时通过严格 JSON、schema、packet/role 绑定和模型身份校验后才算成功；可解析但字段不合法的对象不会被规范化或接纳。若格式重试耗尽，或 Fable/Opus 兼容槽位首次输出未满足 contract，只允许一次同 packet、同 reviewer 的 contract regeneration；它接收原 packet、严格 schema、规范化为纯 decision 对象的前一可解析输出和 answer-free 校验反馈，不把 provider transport envelope 再交给模型。harness 一次收集完整递归 schema 约束、全部独立确定性语义约束和冻结 binding 字段差异，再计算最小 material 修复 allowlist，允许在一次 regeneration 中修复所有已检测的缺失或无效字段，并用投影哈希冻结 allowlist 之外的全部 material 字段；公共 strict validator 仍按原顺序在首个错误处 fail closed，无法证明有限修复面的输出不得声称 material 守恒。纯身份错误的 allowlist 为空，全部 material 字段必须完全不变。所有重试只接收机器从同一冻结 schema 和 validator 生成的 answer-free 校验反馈（固定错误类别、JSON 路径、约束名、必需/实际/缺失/多余字段、类型及 binding 字段名，不含字段值），反馈文件 SHA-256、修复 allowlist 和冻结投影 SHA-256 写入 raw retry envelope。Fable、DeepSeek 或 Opus 兼容槽位只有在完整 JSON 已通过严格 schema/身份校验、但 anchor 或 evidence 未落在 packet 提供的窗口时，才允许一次同 packet 的 grounding-only 纠正；纠正调用继续使用原 reviewer 的冻结 harness/模型身份，只能调整 anchors 和 evidence refs，其他实质字段由投影哈希冻结。若 DeepSeek 的单次 grounding 输出不是严格 JSON artifact，只允许最多两次 transport-only 格式重发同一纠正；第二次只读取前一次格式输出与更新后的 answer-free 校验反馈，且每次最终非 grounding 投影仍必须与原 decision 完全一致。若该 grounding 输出已经解析且全部错误严格限定为缺失或错误的冻结 envelope identity，harness 不再调用模型，而是用版本化 `frozen_identity_rebind_v1` 写入系统已知的 schema/packet/reviewer identity，并绑定原输出哈希、answer-free feedback hash、变更字段表、完整 material 投影和 rebind 输出哈希。它不是语义规范化；任何额外字段、material contract 问题或投影变化都会立即 fail closed。格式重发和 identity rebind 均不能成为第二次 grounding 决策。纠正输出仍不合法、改变 disposition/taxonomy/predicate/safe-pair 等实质字段，或 raw/decision 不一致时，整次审核 fail closed。

主审失败时，受保护作业只把已经重新通过 packet、reviewer identity、strict schema、grounding 和 raw/decision 一致性校验的成对结果复制到短期 checkpoint；孤立 raw、无效 decision 和未验证正文不进入 checkpoint。失败后的 checkpoint 步骤必须显式使用 GitHub `failure()` 状态检查，双主审 matrix 不 fail-fast，避免一位主审的传输失败取消另一位已经排队的独立审核。`checkpoint-manifest.json`只记录哈希、计数、有限 retry/exit 信号、answer-free failure code、失败 retry 的通用 validation class/error hash 和最多一个 8 路 worker batch 的未验证 ID，不记录审核正文或字段值；checkpoint 本身仍含受保护审核材料，固定为 non-formal，恢复时必须逐对象重新校验且不能直接进入仲裁或 attestation。恢复必须同时提供 protected run ID、不可变 artifact ID 和 source SHA；harness 先用 GitHub REST 的单 artifact 端点读取并绑定 metadata，再从同一 ID 下载 ZIP、校验服务端 SHA-256 digest，并安全解压，不能使用会把同名旧 artifact 过滤掉的 `latest` 列表语义。manifest 的 workflow run identity 还必须与调用方预期 run ID 一致。每个 primary failure checkpoint 同样使用 `-attempt-<workflow-run-attempt>` 不可变名称保留历史；`rerun-failed` 优先恢复当前 run 最新的严格 attempt checkpoint，再考虑显式跨 run checkpoint 或完整 primary 输入。恢复校验成功后 manifest 会在继续主审前移除，最终正式 artifact 不携带恢复元数据。checkpoint 可以绑定先前的 packet source SHA，但恢复时仍须针对当前冻结 packet 逐对象重验，不能借此迁移发生变化的 packet。新 workflow SHA 只可通过精确 `{run_id, source_sha, artifact_id, sha256}` 引用受保护 run 的完整 primary artifact；任何提供的完整 primary（即使没有复用 arbitration shard）都必须在 Codex readiness 和任何模型调用前下载，并把 136/136 raw/decision 全部逐对象重验为 complete checkpoint，任何 invalid、incomplete、missing 或 failure record 都会 fail closed。只有这个完整门禁通过后，primary 步骤才以 `resume` 生成全 `reused` manifest，因此不会补跑 Fable 或 DeepSeek。完整 artifact 与失败 checkpoint 输入互斥。`range-v16-review-recover.yml`只用于 sealed runner 在新 checkout 清理前冻结指定 Fable 或 DeepSeek workspace，并用当前受保护 harness 构造同样的严格 checkpoint；它不签发 E0 证据。

Codex 仲裁（`opus` 兼容槽位）先从 136 个冻结 packet 与两份逐对象重验的主审结果计算内容绑定计划；计划哈希覆盖 packet、两侧 decision/raw 文件哈希、分歧字段、证据缺口和 mandatory 标记。入选 ID 按 truth ID 的 SHA-256 固定分成 4 个 shard；这 4 个 shard 是独立失败与恢复域，不表示单 runner 上的天然并发。受保护 workflow 的 primary 与 arbitration matrix 都固定 `max-parallel: 1`，workflow concurrency group 保证任一时刻只有一个 review run 使用模型；primary、arbitration、其 checkpoint 和 safe-pair author 统一最多 8 路调用，因此全局在途模型调用永不超过 8。每个 8 路 batch 必须收齐全部 future；若其中有失败，保留同批成功输出与固定 failure marker，批次结束后停止且不启动下一批。每个 packet 的 decision/raw 在完成后立即写入按 workflow run、attempt 和 shard 隔离的 runner 临时目录；重跑优先使用当前 run 已上传 checkpoint，其次才使用同一 runner 上一 attempt，或者显式且严格校验的跨 run 正式 shard。每个 shard 独立完成、上传和重跑；失败 checkpoint 只保留该 shard 内重新通过 Codex 全校验的成对输出，并绑定 source/run、全计划哈希、shard identity、两份主审输入哈希和 checkpoint workflow run ID。`rerun-failed` 不触碰已成功 shard；跨 run 正式 shard 通过当前 packets、primary 和 plan 全量复验后 zero-call resume 并重新签发为当前 run/source 的 shard。最终合并先通过精确 ID 恢复上述六份当前 run artifact，再重新计算同一计划，要求 4 个 shard identity 恰好各出现一次、无重复/缺失/越界 ID，并逐对象重验 Codex 输出后才生成原有单一仲裁 manifest；任一绑定不一致都 fail closed，checkpoint 或 shard manifest 不能直接进入 provenance、normalization 或 attestation。

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
