# Range C/C++ benchmark protocol

配置输入统一为 `config_version: 3`，扫描档位写入 `scan.preset`；C/C++ 与 Java 共用同一格式。旧输入先用 `zscope-config migrate` 显式迁移，历史评分/报告 schema 版本不受此变更影响。

## 唯一入口

所有本地与发布执行都通过 `zscope-benchmark`：

```bash
zscope-benchmark run --language c_cpp --mode smoke
zscope-benchmark run --language c_cpp --mode prepare --scan-depth fast
zscope-benchmark run --language c_cpp --mode trial
zscope-benchmark run --language c_cpp --mode formal --runs 5
```

`smoke` 不调用 LLM，只验证 fixture、配置、truth、CMake 构建和结构门禁；
`trial` 恰好执行一次冷扫描且永远不具备发布资格；`formal` 拒绝少于五轮并执行发布门禁。Windows 上 C/C++ 命令自动转入 WSL，Linux 直接执行。

## 接口语义准备与独立发现评测

使用 Python 3.13+ 的 Linux/WSL 虚拟环境，并安装当前 checkout 的 `.[benchmark]`。C/C++ 工具检查还包括 PATH 中的 `zscope-clang-indexer`；测试专用 `Z_SCOPE_TEST_CLANG_INDEXER` 不替代运行时 PATH。

`test/range/zscope.semantics.yaml` 是根据源码独立构造、逐项审阅的唯一语义参照，同时作为 fast/balanced/deep 正式扫描输入。它不从模型或 native 发现提议生成。当前包含 56 条 confirmed 正向契约和审阅元数据中的 9 条反向边界；各条 `review_reason` 指向源码与条件。`declaration: none_known` 表示没有另行声明自定义根原语，封装的底层效果来自已知标准原语。正向范围覆盖返回值/出参/成员所有权、资源配对、锁模式、隐藏失败的 may 效果、复制、I/O、命令/格式串传递及回调注册。复杂业务生命周期、动态回调目标集、未编译平台和当前 schema 无法忠实表达的内部偏移池明确列为范围外，不宣称覆盖全部可能接口。

该 YAML 是可迁移的审阅输入，不携带伪造的当前工作区完成收据。`discovery_receipt.benchmark_review` 绑定全部源码、审阅范围与语义决定。每轮 runner 直接将已审阅契约交给正式 `rebind_project_semantics`，核对当前 native 定义、USR/签名、源码摘要、根调用与真实链接关系，生成本轮 BuildContext、工具和依赖收据，再完成正式审阅门禁。这个过程不运行契约发现，也不要求发现器能找到参照中的契约；无法绑定必须失败，不能删除对应义务。密封输入始终不改写，当前 YAML、证据和准备结果归档在执行现场及 scan-extras 中。formal 的准备阶段也在 OCI 中运行。

三种模式可以先只做预备检查，不调用模型、不执行漏洞扫描、不读取漏洞 truth：

```bash
for depth in fast balanced deep; do
  zscope-benchmark run --language c_cpp --mode prepare --scan-depth "$depth" \
    --output "$HOME/benchmark-ready/$depth" \
    --work-directory "$HOME/benchmark-work/$depth"
done
```

各输出和工作目录必须尚不存在。`ready: true` 表示当前 native 构建、接口语义重绑定及 doctor 检查成功，不代表模型连接、扫描质量或 formal OCI 已通过。正常 trial/formal 自动执行同一准备步骤；成本单列 `phase_seconds.semantics_prepare`。

独立评测接入模型的发现命令：

```bash
zscope-benchmark semantics \
  --output "$HOME/benchmark-interfaces/model-trial-01" \
  --work-directory "$HOME/benchmark-work/model-trial-01"
```

需要显式提供三个模型环境变量，使用标准 `--discover-primitives` 命令。模型工作目录中的初始 YAML 只含空 interfaces/dispatchers/function_pointer_bindings 和 none_known 声明；已审阅配置、接口答案、漏洞 truth、历史 finding 均不进入发现上下文。子进程结束并归档原始 YAML 后，host scorer 才读取正式输入 `zscope.semantics.yaml`，复核源码绑定与运行前文件摘要，并归档为 `reference.semantics.yaml`。不再维护独立的 `interface_truth.json`。修改 fixture 后须按源码重新审阅，不能接受模型结果来补写参照或改变本次分母。

评分假设每条输出都被用户 confirm，但不修补未知分支、不写回正式配置。每个效果契约是一项义务，多效果行拆分、相同效果去重；ID、证据路径、构建位置、签名空格、集合顺序及布尔恒等式不影响比较，对象、守卫、锁模式、may/must、配对和责任转换仍须匹配。`strict_precision` 是输出效果与参照一致的比例；`strict_recall` 的分母固定为参照的全部正向效果，模型完全没发现的也记 missing。整份文件的假设确认合法性另记 `all_confirm_document_valid`。

结果区分 correct、incorrect（触犯源码已确认的反向边界）、invalid、mismatch（已知接口但契约不一致）、unreviewed（范围外新接口）及 duplicate。机械比较不冒充一般语义等价证明；mismatch 和 unreviewed 要求独立审查，报告上下界，不直接当作误报。`semantic_accuracy_complete=false` 时只能给出契约一致率和范围，不能宣称最终语义准确率。模型 advisory 与 native 推导、实际 token 成本分别保留；`model_evaluation_complete=false` 表示模型审阅有遗漏/错误或缺少实际调用证据。旧 v1 的 known_precision/22.2% 不可与新参照混算。

`missing` 表示未严格匹配，不能一概称为没有发现。`reference_coverage` 逐项区分 matched、invalid_candidate、contract_difference、absent_effect，并保留对应候选 ID；分母仍是全部参照义务。比较归一化包括逻辑取反、De Morgan 和明确 unsigned 标量参数的零边界等价（如 `n <= 0` 与 `n == 0`），不推测 typedef、指针、字段或平台 char 的符号性；签名仍属于严格匹配身份。不忽略对象阶段、守卫、may/must 或资源配对。同一对象的 allocator/calloc 子类变化计为 contract_difference，不误标为 absent_effect；严格匹配仍要求原角色一致，不增加 TP。原始模型输出不在评分阶段被修补。

发现命令除 native 包装器推导和 advisory 点评外，还为有精确根调用关系的缺口生成源码契约提案。它读取实际编译函数与有真实链接关系的被调者，输出 typed pending 契约。v14 每次请求只裁决一个函数，去重其被调者源码和内置根契约，去掉重复的派生调用文本与协议元数据；完整精确身份留在程序侧校验，不缩减调查范围。多目标共享批次目前只作离线成本对照，未因成本更低而默认采用。模型使用目标参数名和受限布尔表达式，参数类型从当前 native callable 签名读取。数据缓冲与描述符、返回状态与分配指针、回调与回调数据分别检查；源码节点引用不能被根目录编号替代或跨目标借用。数据经局部缓冲复制到输出时分别检查 copy 与 recv_source；描述符经局部成员传递仍检查 io_release。实际零字节写入不能支撑 copy/recv_source 的 must。native 变量身份和赋值链提供偏移反证，阻止将内部地址释放或可能向对象之前写入误写为根对象契约。宏跨 TU 传播要求真实链接组、实际调用的精确 USR 和唯一实现。

标准根输入以类型化目录为准；旧词法 API 名称表不再补造 copy 等额外角色。模型须跟踪收到的内容经过局部缓冲后的传播，并区分回调存储注册与单纯调用。偏移反证只在所有已知相关调用/别名定义均冲突时阻止根对象契约；存在直接基址备选时保留调查，不把多个定义当成累计偏移。

目标的返回类型与可观察返回值分开校验：void 目标不得引用返回值或借用被调者状态；可变参数的省略号不抹去固定参数类型。效果对象范围不限制守卫读取源码中的 global.NAME。返回结构的独立分配成员属于额外所有权输出，不能在删除初始化 copy 时一并丢弃。直接调用形式的宏若不能替换输入守卫，可在既有三次上限内请求有源码依据的等价返回守卫；不猜 sizeof 或具体返回常量，无法闭合的宏映射单独记录为 macro_guard_gaps。

函数初次生成有契约输出或存在结构错误时，进行一次源码反证复核或修正；简单完整证据使用普通复核；调用图不完整、多节点/多分支组合、成员对象、多条款、依赖返回/全局状态的 no_effect 及 native 偏移冲突启用推理。may 不会绕过复杂证据的复核。若仍有结构错误，可再进行一次有界修正，最多三次请求。首轮合法空结果不强制第二次调用；完成计数表示已返回合法提案或空结果，不代表否定结论已被证明。独立有效条款保留，缺失或错误的另一目标不连带丢弃整批。省略排除分支只表示 unknown，不能自动补成 no_effect。未知项、不支持的表达式或协议保留诊断，不以模型置信度授权。已有 native 契约保留；未确认的模型提案不参与自动释放配对或 dispatcher 根扩散。`contract_proposals` 单独记录进入/完成/失败、实际请求包、原始响应、复核模式和压缩前后字符量；总成本以 provider usage 为准，cached prompt 是其中子集，不能再次相加。新增真实接口、冗余动作和错误契约的源码补充审阅单独归档，既不扩写固定参照，也不送回发现上下文。压缩收益必须连同全量召回、错误和未完成单位报告，不能只报 token 降幅。

产物包括初始/最终语义 YAML、input-manifest、机器证据、score、summary、原始 usage JSONL 与 usage 汇总；失败也保留已产生的语义证据和调用成本。接口考试不修改正式输入，没有发布资格。各模式漏洞 trial 与接口考试独立运行，避免把接口配置差异混入模式收益。

## 真源与输入隔离

`test/range/benchmark/ground_truth.json` 是唯一评分真源。当前机器校验要求其版本为 v17，`total_vulnerabilities` 与 141 条记录及唯一 ID 一致；文档不维护另一份漏洞表。v17 由独立复核后的 7 个新增根、5 个重复或不成立记录的退休，以及确定的源码锚点修正组成；审计原始结论保存在 `test/range/benchmark/maintenance/`，不得进入扫描上下文。

每轮从 fixture 复制严格 allowlist：`src/**`、`include/**`、`internal/**`、`CMakeLists.txt`、中性 README 和已审阅的 `zscope.semantics.yaml`。整个 `benchmark/`、报告、缓存、构建目录和本地运行历史都不能进入 scan-input。health/index/scan 环境不含 truth 路径，报告落盘后才由独立 score 子进程读取 truth。Range 仅是分布内开发回归集；它没有 safe control，也不能代替跨项目 public external、sealed 与 shadow 结果。

`benchmark/deterministic_entries.json` 只服务无 LLM 的确定性候选回归，不是 fixed-entry 正式协议，也不参与自动入口发现。

## 环境与门禁

C/C++ trial/formal 需要 Linux 用户态以及 CMake、clangd、gclang、get-bc、LLVM、SVF/Saber 全工具链，并要求显式设置 `Z_SCOPE_LLM_BASE_URL`、`Z_SCOPE_LLM_MODEL` 和 `Z_SCOPE_API_KEY`。任何深度工具缺失都会失败，不允许以降级结果形成 unified 结论。

首次执行前应在**实际运行 benchmark 的 Linux/WSL shell** 中完成以下 bootstrap。示例路径对应 README 中的 SVF 3.2/LLVM 18 安装布局；自定义安装必须换成实际路径：

```bash
cd /path/to/Z-Scope

# 使用 WSL/Linux Python 安装当前 checkout；不要复用 Windows Python。
python3.13 -m venv "$HOME/.venvs/zscope"
source "$HOME/.venvs/zscope/bin/activate"
python3 -m pip install -e '.[benchmark]'

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
for tool in cmake gcc clang clangd zscope-clang-indexer gclang get-bc llvm-link llvm-nm wpa saber; do
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

在 WSL 中，trial 会把 scan-input、构建目录、索引和 Z-SCOPE 状态放到 WSL 原生文件系统的临时工作区。每轮结束前，runner 会把密封输入、日志、报告和评分结果导出到 `benchmark-artifacts/`，并将 `.zscope_conversations/`、`.zscope_snapshots/`、`.zscope_knowledge/`、扫描报告等额外扫描产物按原相对路径归档到 `run-XX/scan-extras/`；`scan-extras-manifest.json` 记录逐文件大小和 SHA-256。可重建的 `build/`、bitcode、SVF 与 Joern 缓存不进入该目录。可用绝对路径环境变量 `Z_SCOPE_BENCHMARK_WORK_ROOT` 覆盖临时根；C/C++ 会拒绝 `/mnt/<drive>`，避免 DrvFS I/O 进入正式性能结果。

需要完整保留执行现场时，显式传入 `--work-directory /home/<user>/zscope-benchmark-runs/<run-name>`。该目录必须是尚不存在的绝对路径；每轮使用其中独立的 `run-NN`，成功、失败或中断后均不自动清理。它保留源码、构建、索引、快照、用量日志和报告，产物中的 `workspace.json` 在扫描前记录路径；归档仅复制密封输入，不删除现场中的生成文件。C/C++ 在 WSL 下同样要求原生文件系统。此选项不改变冷扫描、truth 隔离、评分或资格门禁。

trial/formal 需要 `benchmark` 安装附加项中的流式 JSON 解析器。大报告读取保留全部字段但不构造整份文本副本；归档与回放包使用原子流式写入，父进程在独立评分前释放完整报告对象。

formal 与 sealed 还必须在 rootless Podman/Docker 容器中执行 scanner。只读挂载 answer-free scan-input、配置和工具链，只写挂载输出；不得挂载 Z-SCOPE 源码 checkout、`test/`、truth 或 scorer，容器工作目录也不能位于源码树中。网络仅允许配置的模型 endpoint。runner 必须保存 runtime、cwd、mount 和 network-policy evidence，并在隔离能力缺失或越界挂载时 fail closed；评分在 scanner 容器退出后由独立进程完成。

受保护的 formal 环境必须配置 `Z_SCOPE_BENCHMARK_OCI_IMAGE`（`repository@sha256:<64-hex>`）、`Z_SCOPE_BENCHMARK_OCI_NETWORK` 和 `Z_SCOPE_BENCHMARK_OCI_MODEL_PROXY_CONTAINER`。该 internal network 在启动 scanner 前只能包含一个带 policy digest 的模型 endpoint proxy；缺少变量、rootless 证明、镜像 digest 或实际 inspect 证据都会直接阻断 formal 运行。

计时口径显式拆分：`scan_wall_seconds` 来自扫描报告的 `summary.batch_wall_seconds`，用于跨轮比较和 rollout 的 p95 回退判断；`end_to_end_wall_seconds` 是 runner 从输入准备到评分完成的总耗时。兼容字段 `wall_seconds` 等于 `scan_wall_seconds`。artifact 另记录验证队列 wall time、session/API call 数和实际 Validator/LLM 并发配置。

质量也必须按两种视图读取：`confirmed_recall`/`confirmed_precision` 只统计已确认 finding，`with_review_recall`/`with_review_precision` 将 needs-review 纳入人工复核队列。旧顶层 `recall` 仅是 confirmed 视图的兼容字段，不能称为“总召回”；两种视图的完整计数保存在 `quality_views`。Range 没有 true negatives，`FP/(TP+FP)` 必须称 actionable FDR，不能称经典 FPR。

新正式 artifact 使用 `zscope.formal-benchmark.v3`，单轮评分使用 `zscope.benchmark.v4`，唯一门禁源为版本化 `zscope.benchmark-policy.v1`。它们附加输入文件 SHA-256、manifest SHA-256、canonical phase argv、RuntimeSpec、Rule Catalog/qualification、配置、模型/prompt、token usage、归因和隔离 evidence。Release evaluator 验证这些字段、truth 隔离、五轮稳定性和 policy；历史 v2 artifact 只读，不改写也不能用于新 Release。

Validator A–E 隔离实验使用 `validator_replay_bundle.v1`。bundle 只含 canonical validation groups、事实、证据和全部身份哈希，禁止包含 truth、matched pairs、历史 Validator 输出或 verdict。事实合约显式分为 V1 初始 facts 和 provider-resolvable frozen reservoir；两区 record/UID 重叠时 fail closed，V2 不得把 V1 已见 fact 重新当作 delta。每轮必须导出 raw occurrence → grouped candidate → V0/V1/V2/V3 的漏斗、`discovered_by × decided_by` 交叉表、active-discovery 独占 TP，以及 call/by-agent/by-stage token 守恒结果。

正式 Range 门禁按五轮聚合：confirmed TP 中位数至少 111/141，token 中位数不超过 10M 且任一轮不超过 12M，actionable FDR 相对冻结 Arm A 最多增加 1 个百分点，TP Jaccard 至少 0.90，recall 极差最多 2 个百分点。五轮还必须全部满足 provider usage 覆盖 100%、显式 finding 归因覆盖至少 99%、队列清空、token 守恒、逐调用 JSONL usage ledger 完整且协议异常为零；默认启用规则还必须有当前 revision 的 qualified 记录。每轮 artifact 必须携带同一 replay bundle 与冻结 Arm A baseline 的 SHA 绑定，且 Arm A 绑定中的 replay SHA 必须等于该轮 target 导出的 replay bundle SHA；`scripts/aggregate_range_release_runs.py` 则要求同时提供五个 `--arm-a-summary`。缺失基线、哈希不一致或任一字段缺失时 fail closed。v17 改变了 truth 集合，历史 v15/v16 基线不得冒充当前分母，新的正式结论必须重新冻结五轮 Arm A。

P0 replay 使用打包的 `validator_arms.v1.json` 与 `scripts/run_validator_replay.py`。输入只能是 answer-free `validator-replay-bundle.v1`；执行 ledger 会绑定 bundle、arm spec、模型、Prompt、每组 evidence slice/result 与 token 的哈希，truth 只能在全部输出冻结后由独立 scorer 读取。CLI 可传 run 级 `--expected-total-tokens`；2M/5M/8M/10M/12M 和 Arm E 的 17M 都是完整 replay 结束后的成本对照线，不会拒绝请求、缩短输出或跳过 cluster。P0 funnel 同时输出 occurrence、candidate、validation group、V0/V1/V2/V3（V4仅预留）及报告 finding 的不同计数单位，并以 `reached_by_level`、`transition_counts`、`drop_reason` 记录真实到达和停止原因，禁止把不同单位直接相除。

扩大默认视图召回的 balanced/deep 实验使用产品分档状态机，而不是把历史 replay Arm D 的 top-5% 短轨迹当作生产配置。先从同一冻结输入导出 answer-free replay bundle，验证多 fact 补全、V1→V2→V3 转移和 V3 新事实回写 promotion policy；随后每档只运行一次 cold pilot。若存在 eligible cluster 却没有 V3 调用，或 V3 verified 无法凭新增可解析事实重新进入 promotion policy，立即停止，不运行五轮。pilot 通过后才各运行五轮 cold unified 扫描，并固定 Git、配置、RuntimeSpec、rules、模型、Prompt、provider 和答案隔离身份。

该实验每档必须同时报告 default 与 with-needs-review 的 TP、raw/effective FP、precision、recall、F1 和 FDR；V0/V1/V2/V3 到达、退出和 verdict transition；V3 按来源终态、风险层、fact kind 的 eligible/entered/confirmed；每个 V3 新增默认 TP 的模型轮数、工具调用数和 token；semantic modeling、active discovery、Validator V1/V2/V3 的逐 agent/stage token；以及五轮 median、min/max、TP Jaccard 和 recall 极差。Range 实验目标为默认视图 median TP 至少 120/141、median recall 至少 85%，precision 相对同档冻结基线下降不超过 1 个百分点，同时要求 provider usage 覆盖 100%、token 守恒、队列排空且没有无 proof 静默拒绝。该结果只代表分布内验证，不能替代 external/sealed 门禁。

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
