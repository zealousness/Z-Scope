# 验收与验证协议

## 1. 状态含义

`passed`：实际执行且满足明确断言。`failed`：执行后断言或程序失败。`skipped`：测试框架跳过。`not_run`：未执行。`blocked`：缺失必要环境／权限／依赖。后二者不能转述成通过。

任务可以完成实现但仍未完成真实集成验收；此时在 records 中分别写 implementation_status 和 verification_status，任务保持 in_progress／blocked，而非靠 fixture 或旧提交记录宣布全部完成。

不要求所有任务都运行全仓统一后端；按变更风险选择测试。新增核心能力应有 deterministic fake tests，真实模型和重型引擎结果单列。

## 2. 验收矩阵

### AC01 — 基线与环境

核对本地分支／HEAD／dirty paths，记录当前工具 schema、effective scan depth、RuntimeSpec 及相关 flag。Python 与平台遵循本地 pyproject 和 AGENTS.md。仓库当前要求 Linux／WSL、Python ≥3.13。[R01、R02]

基线记录的旧失败不得掩盖新增失败；也不得未经比较把所有失败归为既有债务。至少定位 T01/T02 的实际实现及可执行目标测试。

### AC02 — 契约向后兼容

旧 search_code 调用省略 scope 时输出形状、符号 ID、排序及参数错误保持；read_code 已有两种输入路径不损坏；语义查询旧默认保持。六工具词汇不膨胀。Agent/MCP 使用同源 ToolContract；portable schema、本地递归校验、strict nullable-required 及首轮 strict fallback 均回归。

新增字段不破坏旧报告／缓存读者；输出仍是完整 JSON，分页只裁完整条目／源码行，不能截断序列化字符串。共享 C/C++／Java 工具的更改要保留 Java 回归，即使新增调查只针对 C/C++。

### AC03 — 文本与文件检索

| 类别 | 至少包含的检查 |
|---|---|
| 功能 | 日志字符串、配置键、测试断言、文件路径子串；search→read 定位同一片段 |
| 隔离 | 搜索不启动 AST／clangd／SVF／LLM；安全路径与 read_code 一致 |
| 数据 | UTF-8 中文、多字节列、CRLF、超长行、二进制、不可读文件、空目录 |
| 路径 | `..`、绝对路径、目录 symlink、文件 symlink 越界、读取前路径被替换 |
| 分页 | 相同视图稳定顺序、无漏项／重项；视图变更拒绝旧页或明确重启 |
| 边界 | 文件／字节／命中／时间预算分别可观察；partial 不伪装 not_found |
| 语料 | secrets、报告、truth、运行指令文件不因全文检索重新暴露 |

首版不支持的 regex／glob 明确报错。MVP 不需要全仓完备倒排索引；扫描边界与已返回结果页完整度必须分离。

### AC04 — cache_only 无语义副作用

对 resolver、LLM transport、snapshot/user_config/KnowledgeDB 写方法、建模任务提交、后端启动设置 spy。cache_only 在 current/missing/stale/corrupt/unverifiable 五类情况下都不得调用这些接口。

不通过会隐式建立 symbol/type context 的 helper 验证缓存。可读取已有元数据和源码摘要；无法确认 freshness 返回未知，而不是擅自升级为 current。允许普通工具审计日志，不允许写语义状态。

正常模式省略参数保持旧语义；只读 profile 拒绝显式刷新。构建上下文、头文件、文档／契约版本变化分别覆盖。

### AC05 — MCP 只读与客户端兼容

协议初始化、tools/list、schema、本地搜索－读取、只读语义、越权、错误恢复和取消通过自动测试。stdio stdout 只含协议消息；不能启动 scan.run 或以参数切换任意 project root/cwd/env。

mixed 工具注册保守 non-readonly；read-only profile 必须以服务端执行保证标签正确。客户端 allowlist 不代替服务端权限。

真实 Codex 联调单列：记录客户端版本、host（Windows/WSL/Linux）、server 解释器、tools/list 实际名称；不记录凭据。没有可用客户端不伪造截图或联调结论。

### AC06 — 新证据身份与绑定

只有程序登记的 ref 可被模型引用。拒绝过期代码／构建／规则版本、同名不同 TU、跨项目对象、未授权扩展、未登记路径、篡改 artifact、工具输出自报 proof。

may alias／may flow、文本命中、编译器结构事实、模型推理和动态 witness 类型不可混淆。保存序列化结果不恢复进程内证明权限。查询后源码变化时，不将新旧事实拼成一个已闭合命题。

### AC07 — 候选盲隔离与提示注入

构造包含候选结论、旧报告、GROUND_TRUTH、人工复核说明的受保护语料，确认搜索、read_code、semantic_context、graph metadata 和错误正文都不能泄露这些内容给盲发现角色。

对文档／代码中的“忽略指令、启动扫描、读取密钥”等提示注入当作被分析数据，不执行。用类型化投影控制字段，正常源码中的 candidate/rule 等词不被无差别删除。history-guided／snapshot-guided 任务必须另设归因，不能冒充独立发现。

### AC08 — 调查循环与恢复

fake 模型至少覆盖：一次即可结束；第二次查询才拿到关键事实；工具暂不可用；反复请求同一事实；非法 ref；越界扩展；输出截断／格式错误；轮次耗尽；用户取消；worker 异常。

每类情况都有可解释终止和已收集证据，不丢失未完成义务。重试有边界且计量，不换 ID 规避预算。取消只清理拥有的任务，不取消其他扫描共享的工作。

### AC09 — 审计覆盖与去重

同文件两个对象、同对象两个入口、同名不同构建、注册回调无 caller、间接调用未知、超限 deferred 都有测试。只合并等价义务，保留入口 occurrence 与原始证据。

分别报告计划／尝试／完成／未覆盖单元；若当前只实现两类单元，不宣称另外两类也覆盖。候选存在性只是排序线索，不等于全位点已检查。

### AC10 — Ledger 与安全终态

主 freeze 后新增候选身份或集合修改必须失败。V3／验证器相关发现复用 append Ledger，最多代际规则保持。pending、engine_failed、interrupted 和需要人工复核的候选不能静默消失。

新增 evidence/provider 不改变原有 disposition 枚举、rule/backend/LLM 归因和 baseline／suppression 边界。不通过模型 confidence 或多数投票伪造程序证明。

### AC11 — 可执行验证

必测：真实正例、相似正确反例、错误候选 crash、构建失败、无 sanitizer 输出、超时、工具缺失、源码／二进制变化、含空格参数、非零退出、取消子进程树、伪造 Agent 执行日志。

独立 runner 必须能重放 witness，且 witness 与对象／站点／性质相符。not_reproduced 不形成拒绝证明。隔离条件及运行次数记录在 receipt；一段 subprocess 代码不能宣称具备容器级隔离。

TSAN／CBMC 后续验收包含模型边界、调度非确定性、外部函数假设和展开限制。不具备真实工具环境时，相关验收保持 not_run，不能用 mock 的 sanitizer 字符串代替。

### AC12 — 索引与增量等价

对每个 mutation，从相同基线分叉：A 路增量更新，B 路清空独立测试状态后干净重建。两者最终源码和编译输入一致。不得清理用户真实缓存。

规范化函数／符号、调用边、类型引用、宏、资源事件、删除与构建变体映射；比较完整受支持事实，而非仅比告警数。只忽略时间、运行 ID 等非语义字段。

固定支持 fixture 的硬门槛是 **0 个未解释的语义差异**。有意语义变化需独立说明，不能把发现的不一致加入忽略名单消除失败。实际大仓结果报告范围与 incomplete，不外推到任意 C/C++ 特性。

### AC13 — 条件契约与怀疑点资格

覆盖成功／失败、不同对象／资源池、转移与保留、条件别名、未知调用、文档冲突、过期快照、无法定位、包装转发、递归 SCC、人工契约优先。

未经验证的契约可引导调查，不能解除义务；模糊怀疑点不能生成独立确定性告警。shadow 不进入默认已确认视图。契约版本或输入变化正确触发失效，副作用由现有提交／发布路径统一负责。

### AC14 — 按需建模不形成候选闭环盲区

必须有“未建模时规则根本不产生候选”的正例，验证未知敏感接口／回调／协议冲突仍会入队。新契约发布后重跑受影响规则，不只改变验证器上下文。

第一阶段 shadow 不实际跳过原任务；比较拟跳过与真实需求。独立 LLM 调用可能有随机性，先固定输出重放验证调度正确，再单列真实模型多次试验。

### AC15 — 外部依赖、权限与退化

固定供应商版本、许可证与接口；核对实际认证和运行条件。没有外部工具、没有网络、没有凭据、没有访问资格不使原生路径失败。依赖缺失返回 unavailable／blocked，而不是自动安装／降级后冒充完整结果。

绝不自动向 GitHub、Linear 或其他服务发布结果。外部扫描阶段相互隔离，不传 ground truth；导入保留来源与 coverage，拒绝越界 path 和过期引用。外部 verdict 不自带 Z-Scope proof 权限。

### AC16 — 性能、成本与能力指标

**测量前固定**：代码版本、配置及有效策略、模型／prompt／tool schema、编译数据库、工具链、CPU/RAM、并发、缓存状态、输入 corpus 与权限。计量账本保持原有语义，不为了做 benchmark 改变运行时预算。

| 指标 | 口径 |
|---|---|
| 时间 | 首次可查询、分阶段 wall、端到端 wall；不累加并行子任务当 wall |
| 资源 | CPU 时间、peak RSS、临时盘；SVF worker 各自及整体峰值 |
| 索引 | TU inventory、实际重建／复用／失败、编译变体覆盖、事实差分 |
| LLM | 物理 attempt、唯一建模任务、合并等待、prompt/completion、cached token 子集、unknown usage |
| 调查 | 单元计划／完成／未覆盖、新增有效证据、无增益停止、独占发现来源 |
| 能力 | 按根因去重 TP、FP、FN（有 truth 才算）、needs_review、独占 TP |
| 人工成本 | 每个候选／真问题的复核时间；未测就写 unavailable |

初始实验建议小型固定集 5 次、较大工程 3 次独立运行，记录样本量、中位数和范围；样本不足不强调 p95 的稳定性。这些是测量建议，不是生产门禁数字。

`precision=TP/(TP+FP)`；`recall=TP/(TP+FN)`；`FDR=FP/(TP+FP)`。没有 TN 分母不能把 FDR 称为 FPR。分母为零用 N/A，不写 0%／100%。review/unknown 不偷偷算 TP、FP 或安全样本；报告可分别给出已裁决口径和总工作量。

端到端加速是等价范围的 `baseline_time/new_time`。无范围等价不能用排除了大量 TU 的结果宣传加速。LLM-only 独占 TP 按 canonical root 和来源集合定义，不按文本相似度随意合并。

### AC17 — Benchmark 与答案隔离

遵循仓库根 Range 路线。GROUND_TRUTH 只用于允许的入口覆盖预检和扫描结束后独立评分；不得进入扫描／工具证据／Wiki。不要修复故意漏洞，不修改 truth 迎合结果。

新动态测试 fixture 独立创建，含明示安全与缺陷样本；运行前遵守权限和隔离要求。补丁驱动规则生成与评测按项目／缺陷家族分割，防止近重复泄漏。

### AC18 — 关闭、回滚与共享资源

新增实验关闭后旧扫描默认、报告读取、语义缓存及工具行为保持。新缓存 schema 如需迁移，明确兼容／失效策略，不能删除用户产物。取消与关闭不留下后端／外部 worker、不损坏已发布 DB，不错误关闭借用客户端。

变更应可分小批次回滚；无须为了“回滚简单”先引入整个新架构。

## 3. 建议测试命令

以下来自已核对仓库规范／模块文档的已知入口，**并非本次已执行的结果**。本地先检查文件和命令是否存在；名称变化时查真实映射。占位条件和工具缺失不应被忽略。

```bash
# Linux/WSL，仓库根，使用符合 pyproject 的已安装环境。
python -m pytest -q --collect-only \
  tests/test_tool_registry.py tests/test_evidence_tools.py \
  tests/test_tool_schema_strict.py tests/test_tool_policy.py

# 第一阶段核心回归。
python -m pytest -q \
  tests/test_tool_registry.py tests/test_evidence_tools.py \
  tests/test_tool_schema_strict.py tests/test_tool_policy.py \
  tests/test_tool_use_eval.py

# MCP；先确认本地测试名称。
python -m pytest -q tests/test_mcp_policy.py tests/test_mcp_security.py

# 调查／候选；按任务适用运行。
python -m pytest -q tests/test_active_discovery.py tests/test_candidate_ledger.py

# 索引实验需实际前置依赖；skipped 不代表 native 验证通过。
python -m pytest -q tests/test_clang_batch.py tests/test_clang_identity_validation.py

# 跨模块交付前按根 AGENTS.md 补充质量检查。
python -m compileall -f -q zscope scripts test tests
python -m mypy zscope
git diff --check
```

先针对变更文件运行格式检查，避免全仓无关格式化。新测试文件的名字由实施者确定，不把文档建议名当作当前仓库已有文件。

真实扫描、benchmark、doctor 或 index-audit 先运行对应 `--help`，核对配置及实际 cwd/project.root。不要凭本包猜 flag，更不要未设置批准的 LLM 环境就运行付费扫描。端点／密钥不进入结果记录。

## 4. 消融实验顺序

A：当前固定配置基线；B：实际生效的现有 balanced/deep；C：仅增加有界主动取证；D：单独增加建模 shadow；E：独立外部扫描器；F：在相同候选集上增加可执行验证。

每一步只改变一个主要因素；在所有扫描完成前不交换输出。补充证据对已有候选的判定收益与新发现带来的召回收益分开统计。

## 5. 每个任务的完成记录

复用 [records/TEMPLATE.md](records/TEMPLATE.md)，记录实际执行命令、环境、exit code、通过／失败／跳过、产物路径和局限。不要记录 API key、Authorization、供应商隐藏思维正文或无必要的私有源码。
