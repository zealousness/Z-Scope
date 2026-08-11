# Z-SCOPE v1.3.1

**Z-SCOPE** 是一款基于 **多智能体（Multi-Agent）** 协作的 C/C++ 静态分析平台，并提供 Java Preview。它把可插拔代码索引、确定性规则、结构/值流后端信号、项目语义配置、人工反馈记忆与大语言模型（LLM）验证结合起来，模拟资深安全研究员的审计过程。

v1.3.1 是 C/C++ 稳定化、离线交付和 Python 3.9 兼容版本，同时落地 Java Preview 的结构索引与规则候选基础。包内 `1.3.1` 是版本唯一真源，发布标签必须为 `v1.3.1`；`zscope.candidate.v3.3` 等字符串仅代表内部数据协议，不是产品版本。详见 [v1.3.1 发布说明](docs/releases/v1.3.1.md)。

## 核心特性

- **多智能体分治与声明式编排**：采用 `AGENT.md` 与 `SKILL.md` 契约定义各智能体与技能。支持 `语义建模 Agent`、`漏洞扫描 Agent`、`Issue Reconciler Agent`、`验证 Agent` 以及隔离上下文的聚焦型 `Deep Worker` 独立协作。分析流程由 `zscope/workflows/*.yaml` 与 `WorkflowRunner` 驱动实际执行步骤，而不是仅作为提示词上下文注入。
- **Task 驱动的漏洞 Skill 选择**：`vulnerability_analyzer.task` 不只是提示词描述。系统会结合本地关键词规则与可选 LLM 语义路由选择 `resource_lifecycle`、`bounds_and_integer`、`null_and_failure`、`concurrency_lock_order` 等漏洞挖掘 Skill；低置信或冲突判断会保守回退到全量 Skill，避免漏扫。
- **三种运行模式**：全新扫描（默认）、断点续扫（`--resume`）、增量维护（`--maintain`）。Workflow 选择由 CLI 运行模式控制，不允许在 `zscope.yaml` 中配置。另支持告警验证模式；C/C++ 的 `--mode ruledriven` 仅作为 1.x 弃用兼容入口。
- **Diff impact 增量影响扫描**：支持 `--diff-base/--diff-head`、`--diff-repo-root` 与可重复 `--diff-path`。v1.2 通过 `project.diff_impact` 按变更意图生成 `analysis_obligations`、caller 搜索深度和可选 `llm_triage`，选择最小必要扫描 root，写出 `entry_functions_diff.json`、路径过滤信息、覆盖摘要和 `[增量]` / `[存量]` / `[影响待确认]` 标注。
- **自动入口发现**：支持基于启发式的智能扫描入口发现（`--discover-entries` 或 `project.entry_discovery.enabled`），自动识别头文件暴露的公共 API、网络收发、线程入口及用户输入点，并把候选写入项目根目录的 `entry_functions_list.json`。若未显式配置 `entry_functions_list`，发现结果会作为本轮批量入口。
- **可审阅用户配置工作簿**：`user_config.xlsx` 与 `--infer-user-config` 可从源码、函数式宏、语义快照中生成 resource/lock/dispatcher/module lifecycle/pointer target/function intent 候选；v1.2 会用默认 LLM 并行筛选、修订或丢弃候选行。运行时只注入当前函数真正引用到的用户配置，降低上下文噪声。
- **证据优先的候选流水线**：`CandidatePipeline` 汇总本地规则、Clang AST/CFG、SVF/Saber、跨函数图候选与 KnowledgeDB/Joern 后端信号。v1.2 继续扩展协议/运行时形态，覆盖 fd 表示契约、raw/encoded fd 混用、EAGAIN/EINTR 无预算重试、协议元素数与字节数错配、宏锁可能编译为空、部分资源初始化失败回滚等模式。
- **风险自适应预算**：`RiskBudgetPlanner` 会把 `max_recursion_depth`、`max_premodel_depth`、`max_premodel_callees` 与 `max_subagent_tickets` 视为硬上限，再按入口复杂度、调用扇出、后端/图候选和历史缺陷生成每个入口的 `effective_budget`。它会识别 runtime/protocol callee 与 thin facade，提升直接 callee 规则扫描预算，同时支持 `subagent_max_turns`、`subagent_ticket_timeout` 和按 Skill 的子 Agent 路由配置。
- **验证组终态与确定性 proof**：`CandidateEnvelope v3.3`、`DecisionFact`、`SecurityObligation` 和 scan-level validation group 共同保证每个安全义务只验证一次，并闭合为 `confirmed`、`rejected_with_proof`、`needs_review`、`engine_failed` 或 `interrupted`。只有完整、可追溯且无冲突的 proof 能改变安全终态；引擎故障不会伪装成漏洞。
- **有界 Validator 证据协议**：`ValidatorEvidenceSlice v2` 只传递 canonical occurrence、结构化 source/sink/object、一个代表性入口路径、决策事实和精确代码片段；alias 只传数量与 UID。Validator 首轮必须给出终态或类型化缺失事实请求，补证后最多再响应一次，不再进行开放式多轮代码探索。
- **本地与实验性远程 MCP Server**：原生内置 Model Context Protocol (MCP) stdio Server；同时提供实验性的 Streamable HTTP 传输。远程绑定必须显式配置 bearer token 环境变量与客户端 allowlist，避免把代码索引和工具总线无保护暴露到网络。
- **多模型配置、endpoint 池与路由**：支持在 `zscope.yaml` 中定义多个大模型配置（如 `fast_model` / `smart_model`），不同 Agent 可按需绑定最佳模型；同一 LLM profile 可配置多个 `base_urls`，并用每 endpoint 限流与并发上限分摊批量请求。
- **按语言隔离的可插拔后端**：C/C++ 默认使用 Regex、Clang 或 Unified（Clang + SVF），不再默认安装或探测 Joern；Java Preview 使用 source/java_unified 索引以及 SootUp、WALA、Joern 信号提供器，CodeQL 仅支持用户自备。
- **最多 12 个分析工具与工具策略**：函数源码获取、调用图分析、结构体查询、污点追踪、指针别名查询、深度调用上下文聚合等工具由运行时提供；实际对 Agent 暴露的集合由 `AGENT.md`、后端能力和 `ToolPolicy` 共同决定，并支持参数校验、敏感路径拦截和审计日志记录。
- **用户辅助配置系统**：通过 WebUI 或 `user_config.xlsx` 管理外部函数描述、配对函数、函数指针指向、dispatcher 分支、模块生命周期和函数意图等信息；手工验证反馈会写入误报抑制与 finding baseline，后续扫描自动复用。
- **智能增量分析与稳定缺陷身份**：支持断点续扫（`--resume`）和基于语义哈希的增量维护扫描（`--maintain`）。`zscope/common/issue_identity.py` 统一提供 `canonical_issue_key`、`stable_issue_fingerprint` 与 source context fingerprint，让去重、baseline、SARIF partial fingerprints 和 benchmark 匹配使用同一套身份逻辑。
- **Canonical 报告与结构化根因投影**：`ReportAssembler` 只从冻结的 canonical outcome 集合生成默认视图和含复核视图。`FindingRoot v1` 仅合并 defect family、结构化 subject、decision region、代码和 proof 上下文完全等价的义务；入口、wrapper、detector 和文本相似度不能单独触发合并。CLI 支持 `--export-sarif` 输出 SARIF v2.1.0。
- **Web 仪表盘**：Alpine.js + DaisyUI 构建的交互式界面，集成扫描结果查看、报告视图切换、`validated` / `needs_review` / `uncertain` / `unvalidated` / `pending` / `rejected` 状态标记、用户配置管理和配置告警。
- **可追踪持久化与反馈记忆**：分析产生的终极漏洞（Issues）与语义模型会写入本地 `.zscope_snapshots/snapshots.db`；`code_knowledge.db` schema v7 持久化代码事实、macro 定义、Inspection IR、候选 source/sink、资源事件、锁事件、共享访问与路径切片，并带调用图查询缓存和删除 TU 清理；用户领域知识落在 `user_config.xlsx`，反馈状态通过旁路 state DB 和 `ReviewMemory` 复用。
- **自动报告备份护城河**：每次批量生成或覆盖 JSON 分析主报告前，自动创建带时间戳的增量备份至 `.zscope_knowledge/backups/` 目录。
- **严格编译与类型检查**：开发环境支持 `compileall` 强制编译检查和 `mypy` 静态类型检查，避免 Python 解释执行到冷门分支时才暴露错误。
- **Benchmark 与发布门禁**：内置 Range 开发集与外部 benchmark harness。v1.3.1 冻结 C 基线的五轮中位数为 confirmed TP 89、raw FP 2、precision 97.80%、with-review TP 134、needs-review 135、tokens 1,324,485、wall time 2,105.97 秒；`fab8398` 复核候选另行归档且因 sealed-set 缺失只允许 RC。正式 precision 始终按 `TP / (TP + raw FP)` 计算。
- **纯 YAML 驱动**：所有项目分析参数通过 `zscope.yaml` 统一定义，支持 `${ENV_VAR}` 环境变量展开；运行态 workflow 由 CLI flags 决定，`analysis.workflow_name` 写入配置会被拒绝。

## 系统架构

```
CLI / Web / MCP / SARIF 入口层
    │
    ├─→ 默认/批量模式 (WorkflowRunner + Analyzer)
    ├─→ 规则驱动兼容模式 --mode ruledriven（C/C++ 在 1.x 弃用，2.0 删除）
    ├─→ 告警验证模式 --mode alert-verify
    ├─→ SARIF 标准导出 --export-sarif
    ├─→ 自动入口发现 --discover-entries
    ├─→ Diff impact 扫描 --diff-base/--diff-head [--diff-repo-root] [--diff-path]
    ├─→ 用户配置工作簿推断 --infer-user-config
    └─→ MCP 服务 --mcp-stdio / --mcp-http
          │
          ▼
声明式工作流编排 (workflows/ + SpecRegistry)
          │
          ▼
CodeIndex (可插拔后端 + per-run cache) + SnapshotStore + UserConfigStore(XLSX + state DB) + KnowledgeDB IR
          │
          ├─ CodeBackend ABC (backend_base.py)
          │  ├─ JoernBackend    — Java 信号；C/C++ 仅保留 1.x 兼容入口
          │  ├─ ClangBackend    — clangd LSP 批量提取 → KnowledgeDB
          │  ├─ UnifiedBackend  — ClangBackend + SvfAnalyzer (entry cluster + bitcode pool)
          │  ├─ JavaSource/UnifiedBackend — Java source + SootUp/WALA/Joern signals
          │  └─ RegexBackend    — 正则回退
          │
          ├─→ 证据候选层 (CandidatePipeline + CandidateLedger + issue_identity + semantic dedup)
          ├─→ 风险自适应预算 (RiskBudgetPlanner → effective_budget)
          ├─→ 工具总线 (ToolsRuntime + ToolPolicy) ── 外部 MCP 集成
          │
          ▼
多智能体管线 (agents/ + skills/)
语义建模 Agent → [漏洞扫描 Agent ⇌ Deep Worker] → Issue Reconciler → 验证 Agent
          │
          ▼
ValidationRunner (fast-path + parallel) + ReviewMemory + ReportAssembler + 语义去重 + SARIF 导出 + Web 反馈闭环
```

## 数据安全与审计留痕
Z-Scope 内置了多层防丢失和可追溯机制：
1. **快照级持久化**：语义快照与单函数最终报告会写入 `.zscope_snapshots/snapshots.db`，`--resume` 和 `--maintain` 都以该库作为跳过、复用和调和依据。
2. **热备份轮转**：在汇总合并最终的 `zscope_batch_report.json` 前，旧版本 JSON 会自动加盖时间戳并归档至 `.zscope_knowledge/backups/` 目录。
3. **证据 IR 与索引留痕**：确定性规则与后端信号产生的候选会将 source/sink、路径切片、资源/锁/共享状态事件写入 `code_knowledge.db` 的 IR 表；Clang 后端还会记录 macro 定义、翻译单元哈希和删除文件影响，便于复查和回归分析。
4. **人工反馈复用**：Web 仪表盘中的验证状态会持久化为 `finding_suppressions` 与 `finding_baselines`。`ReviewMemory` 会在验证、评分和报告前复用这些状态，后续扫描自动抑制已确认误报，并把历史反馈纳入评分。
5. **稳定身份、结构化根因与标准报告导出**：`candidate_uid`、`occurrence_uid`、`validation_cluster_uid`、`finding_root_uid` 和 `stable_issue_fingerprint` 分别服务候选、入口溯源、验证复用、报告投影与 baseline/SARIF。v1.3.1 报告保留 alias occurrence、入口路径、decision proof、affected subjects 和聚类遥测，便于复核每次确认、拒绝与合并。Web 前端可导出自包含 HTML 审计报告；CLI 可通过 `--export-sarif` 输出 SARIF v2.1.0。
6. **差异影响留痕**：diff impact 扫描会把 `base_ref`、`head_ref`、路径过滤器、变更函数、分析义务、覆盖摘要、fallback 原因和报告级 `diff_relevance` 写入结构化 JSON，避免把增量审计结论和存量问题混在一起。
7. **MCP 暴露面约束**：stdio MCP 默认本地使用；HTTP MCP 为实验性能力，远程 bind 需要 `--mcp-auth-token-env` 与 `--mcp-client-allowlist`，工具调用还会经过 `ToolPolicy`。
8. **模型与验证成本留痕**：LLM 客户端会记录累计 prompt/completion token、工具调用次数和 endpoint 等待信息；Validator fast-path、并行验证和告警验证也会把 token 与命中统计汇总进报告或 benchmark 成本指标。

## 依赖说明

### Python 依赖

Z-SCOPE 源码兼容和 CI 门禁覆盖 Python 3.9–3.14；推荐和离线包内置 CPython 3.13。Python 3.9 已于 2025-10-31 结束官方维护，仅作为客户存量环境下限（见 [Python 官方版本状态](https://devguide.python.org/versions/)）。运行时依赖以 `pyproject.toml` 为准，每个小版本的带哈希约束位于 `requirements/constraints/`。

| 包名 | 用途 |
|------|------|
| `openai>=1.0.0` | LLM 客户端（OpenAI 兼容 API） |
| `requests>=2.31.0` | HTTP 请求 |
| `cpgqls-client>=0.0.5` | Java 可选依赖组中的 Joern CPGQL 客户端 |
| `click>=8.1.0` | CLI 框架 |
| `tqdm>=4.66.0` | 进度条 |
| `pyyaml>=6.0` | YAML 配置解析 |

开发依赖（可选）：`pytest`、`pytest-cov`、`black`、`mypy`、`types-PyYAML`、`types-requests`。

质量门禁固定使用 `mypy==1.19.1` 与 `black==25.11.0`，两者目标均为 Python 3.9；存量质量债务采用不可扩张基线管理。

### 外部工具依赖（按后端）

| 后端 | 必需工具 | 说明 |
|------|---------|------|
| `regex` | 无 | 纯正则，零外部依赖 |
| `joern` | Joern CLI + JDK 21 | Java 信号提供器；C/C++ 仅保留 1.x 弃用兼容入口 |
| `clang` | clangd >= 20.1 + compile_commands.json | clangd LSP 符号提取，无需 `pip install libclang` |
| `unified` | clangd >= 20.1 + (可选) clang-18 + Go/gllvm + binutils/objcopy + SVF 3.2 + LLVM/llvm-link/llvm-nm | Clang AST + SVF 深度分析，SVF 不可用时优雅降级；clang-18 仅用于 SVF/gllvm bitcode 链路，llvm-nm 用于入口裁剪后的符号闭包 |
| `java_source` / `java_unified` | Temurin 21、Maven、SootUp/WALA runner；默认信号还需 Joern | CodeQL 仅用户自备 |

## 安装指南

### 1. 隔离网络一键安装（推荐）

从同一个 GitHub Release 下载 `install.sh`、`SHA256SUMS`、签名、公钥、应用包和所需语言依赖包，放在同一目录：

```bash
./install.sh --profile cpp --asset-dir .
./install.sh --profile java --asset-dir .
./install.sh --profile all --asset-dir .
```

安装器校验签名与 SHA-256，默认写入 `~/.local/share/zscope`，不会修改 `/opt`、`/etc/profile`、系统 Python 或 shell profile。升级使用原子 `current` 链接，回滚使用 `./install.sh --rollback 1.3.1`。完整资产布局和制作流程见 [离线安装与发布](docs/offline-installation.md)。Windows 用户使用 WSL2，不支持原生 Windows 离线包。

### 2. 从源码安装

```bash
git clone https://github.com/zealousness/Z-Scope.git
cd Z-Scope
python -m pip install -e .

# Java Preview（包含 Joern Python 客户端；CodeQL 仍须用户自备）
python -m pip install -e ".[java]"

# 含开发依赖
python -m pip install -e ".[dev]"
```

先运行 `zscope-init --language auto` 生成最小配置，再运行 `zscope-doctor --profile auto --config zscope.yaml` 检查环境。

### 3. 安装后端依赖（按需选择）

**Regex 后端**（零依赖，开箱即用）：无需额外安装。

**Java Joern 信号提供器**（C/C++ Joern 已弃用）：

```bash
# 下载 Joern CLI（需要 JDK 21）
curl -L https://github.com/joernio/joern/releases/latest/download/joern-install.sh | bash

# 或手动下载解压到 dependency/joern/
# 验证
joern --version
```

**Clang 后端**：

```bash
# 1. 安装 clangd（用于 LSP 符号提取）
#    方法 A: 系统包（如果发行版提供 clangd >= 20.1）
sudo apt install clangd-20
#    方法 B: 独立二进制（无需 root）
mkdir -p ~/.local/clangd && cd ~/.local/clangd
curl -sL https://github.com/clangd/clangd/releases/download/22.1.0/clangd-linux-22.1.0.zip -o clangd.zip
unzip clangd.zip
# 然后在 zscope.yaml 中配置 clangd_path

# 2. 生成 compile_commands.json（Clang 后端必须）
cmake -DCMAKE_EXPORT_COMPILE_COMMANDS=ON ..
# 或使用 bear: bear -- make
```

> **注意**: Clang 后端使用 clangd LSP 进行符号提取和调用图构建，不需要 `pip install libclang`。建议使用 clangd >= 20.1；`callHierarchy/outgoingCalls` 从 clangd 20.1.0 起支持，旧版会自动降级到 regex + definition fallback。

**Unified 后端**（Clang + SVF，完整安装）：

Unified 模式 = Clang AST 提取 + SVF 深度分析。Clang 部分为必需，SVF 部分为可选（不可用时会自动降级并显示告警）。

```bash
# ═══ 必需：Clang AST 提取 ═══

# 1. clangd（同 Clang 后端，建议 >= 20.1）
sudo apt install clangd-20

# 2. compile_commands.json
cmake -DCMAKE_EXPORT_COMPILE_COMMANDS=ON ..

# ═══ 可选：SVF 深度分析 ═══
# 如果不安装 SVF，unified 模式退化为 clang 模式（自动告警）

# 3. 安装 Clang 编译器（仅 SVF/gllvm bitcode 链路需要；需与 SVF 预编译包匹配）
sudo apt install clang-18

# 4. 安装 LLVM 工具链（llvm-link）
sudo apt install llvm

# 5. 安装 binutils（objcopy，gclang 嵌入 bitcode 需要）
sudo apt install binutils

# 6. 安装 Go（gllvm 依赖）
sudo apt install golang

# 7. 安装 gllvm（LLVM bitcode 提取：gclang, get-bc）
go install github.com/SRI-CSL/gllvm/cmd/...@latest
# 确保 ~/go/bin 在 PATH 中

# 8. 安装 SVF（指针分析 + 内存缺陷检测）
#    从 GitHub Release 下载预编译包：
curl -sL -o svf.zip \
  https://github.com/SVF-tools/SVF/releases/download/SVF-3.2/SVF-3.2-ubuntu-24.04-x86_64.zip
unzip svf.zip -d ~/.local/svf/
#    SVF 还需要配套的 LLVM 共享库：
curl -sL -o llvm.tar.gz \
  https://github.com/SVF-tools/SVF/releases/download/SVF-3.2/llvm-18.1.0-ubuntu20-rtti-x86-64.tar.gz
tar xzf llvm.tar.gz -C ~/.local/svf/
```

**环境变量**（SVF 所需，建议加入 `~/.bashrc`）：

```bash
export PATH="$HOME/go/bin:/usr/lib/llvm-18/bin:$HOME/.local/svf/SVF-linux-x86_64/bin:$PATH"
export LLVM_COMPILER=clang
export LLVM_CC_NAME=clang-18
```

**zscope.yaml 配置示例**（unified 模式）：

```yaml
indexing:
  backend: unified
  clangd_path: clangd             # clangd >= 20.1；也可填完整路径
  svf_bin_dir: ~/.local/svf/SVF-linux-x86_64/bin
  gclang_path: gclang             # 或 ~/go/bin/gclang
  get_bc_path: get-bc
  llvm_link_path: llvm-link       # 或 /usr/lib/llvm-18/bin/llvm-link
  svf_scope: auto                 # full | auto | entry；按入口裁剪 bitcode，必要时保守回退
  svf_entry_depth: 4              # entry scope 沿调用图扩展深度
  svf_max_selected_tus: 200       # 入口裁剪后最多保留的翻译单元数，0 表示不限制
  svf_fallback: full              # full | skip；裁剪不可靠时的回退策略
  svf_always_include: []          # 总是纳入 SVF 链接的源码路径或片段
  svf_symbol_closure: true        # 使用 llvm-nm 根据 undefined symbol 补齐依赖 bitcode
  # svf_exclusive_pools: []       # 可选：互斥源码池，避免同名强符号被链接进同一个 SVF bitcode
  # svf_shared_pools: []          # 可选：多个互斥 variant 可共享的依赖池
```

> **WSL 用户注意**: SVF 的 bitcode 构建（gclang + objcopy）在 NTFS 挂载路径 (`/mnt/c/...`) 上可能失败，Z-SCOPE 会自动重定向到 Linux 原生临时目录。启用入口裁剪时，构建目录还会写入 `bitcode_scope_<group>.json`，记录本次 SVF 选择了哪些源码和 `.bc` 文件，便于复查。详见 `.agents/workflows/wsl-pitfalls.md`。

## 端到端使用指南

### Step 1：准备配置文件

在项目根目录创建 `zscope.yaml`：

```yaml
# 支持多模型配置路由，Agent 可指定 llm_ref
llms:
  default:
    provider: openai
    base_url: http://127.0.0.1:11434/v1   # Ollama 本地或其他 OpenAI 兼容服务
    models:
      - qwen3:latest
    api_key: ollama
    temperature: 0.1
    max_tokens: 4096
    timeout: 180
  smart_model:
    provider: openai
    # 单 endpoint 仍可使用 base_url；多个兼容网关可用 base_urls 做负载分摊
    base_urls:
      - https://api-gateway-1.example.com/v1
      - https://api-gateway-2.example.com/v1
    # 每个 base_url 的分钟请求上限与并发上限；0 或省略表示不额外限制
    base_url_rate_limit_per_minute: 60
    base_url_max_concurrent_requests: 4
    models:
      - Qwen/Qwen3-Coder-30B-Instruct
    api_key: ${Z_SCOPE_API_KEY}

project:
  root: .                    # 被扫描项目根目录
  source_root: .             # 源码搜索根目录
  language: auto             # auto | c_cpp | java
  entry_function: main       # 单入口模式或入口发现为空时的回退入口
  # entry_functions_list: functions.json  # 批量模式配置

  entry_discovery:           # 自动入口发现机制
    enabled: true            # 为 true 时每次运行都会发现入口；未提供 entry_functions_list 时发现结果作为批量入口
    max_candidates: 200
    max_functions: 10000
    header_files: []         # 可选：限制 public header 入口发现；不影响函数体入口发现
    # search_root: /absolute/path/to/module  # 可选：限制入口发现范围，必须是绝对目录

  diff_impact:               # diff 模式入口语义收敛配置；通过 CLI 的 --diff-base 启用
    strategy: semantic_obligation
    llm_triage: on_demand    # on_demand | off；仅在高 fan-out 或静态选根不清时用于选根
    caller_search_depth_by_intent:
      new_external_api: 3
      resource_acquire_change: 4
      input_boundary_change: 4
      dispatcher_route_change: 3
      thread_or_callback_entry_change: 4
      resource_release_change: 6
      sink_or_check_change: 5
      lock_release_change: 5
      destroy_or_unregister_change: 6
      ownership_transfer_change: 5
      container_registration_change: 5
      lifecycle_contract_change: 5
      local_logic_change: 2
      comment_or_trivial_change: 1
      declaration_or_contract_change: 3

  # compile_commands_path: build/compile_commands.json
  include_paths: []
  exclude_paths:
    - build
    - tmp

  agents:
    - name: semantic_modeler
      enabled: true
      llm_ref: default

    - name: vulnerability_analyzer
      enabled: true
      llm_ref: smart_model
      can_spawn_subagents: true  # 允许创建 Deep Worker 分析上下文
      # task 会选择本次启用的漏洞挖掘 Skill；未识别/为空时保持全量 Skill。
      # 当前支持的漏洞扫描 Skill：
      # resource_lifecycle（资源/句柄生命周期）
      # bounds_and_integer（边界、拷贝、整数溢出）
      # temporal_memory（UAF、double free、invalid free）
      # null_and_failure（空指针、失败返回未检查）
      # stack_escape（栈地址逃逸到异步上下文）
      # concurrency_lock_order（锁顺序、缺失解锁、递归死锁）
      # shared_state_race（共享状态竞态、TOCTOU、refcount、condvar）
      # ownership_contract（所有权/借用/转移契约）
      # string_and_format（字符串、格式串、命令构造）
      # 例如："只查找资源泄漏和空指针问题。" -> resource_lifecycle, null_and_failure
      # 例如："只关注并发风险，不关心内存安全。" -> concurrency_lock_order, shared_state_race, stack_escape
      task: "查找逻辑漏洞、内存安全问题和并发风险。"

    - name: issue_reconciler_agent
      enabled: true

    - name: validator_agent
      enabled: true
      llm_ref: smart_model

indexing:
  backend: auto                # C/C++: regex | clang | unified；Java: java_source | java_unified
  java:
    structure: [sootup, wala]
    signals: [joern]           # CodeQL 仅用户自备，不随产品分发
  clangd_path: clangd
  knowledge_db_path: .zscope_knowledge/code_knowledge.db
  batch_size: 50
  max_clangd_threads: 8
  # svf_bin_dir: /path/to/svf/bin
  # gclang_path: gclang
  # get_bc_path: get-bc
  # llvm_link_path: llvm-link
  # svf_heap_limit_mb: 32768
  # svf_timeout: 1800
  # svf_groups_config: svf_groups.json
  svf_scope: auto              # full | auto | entry；按入口裁剪 SVF bitcode
  svf_entry_depth: 4
  svf_max_selected_tus: 200
  svf_fallback: full           # full | skip
  svf_always_include: []
  svf_symbol_closure: true
  # svf_exclusive_pools:
  #   - name: normal
  #     paths: ["src/pool/normal/**"]
  #   - name: compat
  #     paths: ["src/pool/compat/**"]
  # svf_shared_pools:
  #   - name: generic
  #     paths: ["src/pool/generic/**"]
  #     conflicts_with: ["compat"]

analysis:
  max_recursion_depth: 3
  max_function_lines: 500
  max_tool_iterations: 50
  snapshot_dir: .zscope_snapshots
  enable_snapshot_cache: true
  user_config_db: ""          # 可填 .xlsx 或目录；为空时使用 {snapshot_dir}/user_config.xlsx 和旁路 .state.db
  parallel_workers: 5
  max_premodel_depth: 3
  max_premodel_callees: 20
  trivial_function_max_lines: 5
  enable_subagent_workers: true
  max_subagent_tickets: 4      # Deep Worker 执行预算硬上限；effective_budget 会按风险调低但不丢候选
  subagent_max_turns: 20
  subagent_ticket_timeout: 0
  validation_parallel_workers: 0 # 0 表示自动；>0 时限制单入口 Validator 并发数
  subagent_spawn_allowlist:
    - deep_worker
  subagent_skill_llm_refs: {}
  subagent_skill_efforts: {}
  tool_audit_log: ""           # 可选 JSONL 审计日志，记录工具/MCP policy 事件

reporting:
  semantic_dedup:              # 最终报告语义去重；先走程序化 guardrail，再可选调用 issue_reconciler_agent
    enabled: true
    llm_enabled: true
    llm_confidence_threshold: 0.85
    max_cluster_size: 8
```

本地 API key 建议放在 git 忽略的环境文件中。例如 range benchmark 可复制
`test/range/zscope.local.env.example` 为 `test/range/zscope.local.env`，填入
`Z_SCOPE_API_KEY` 并取消注释；`test/range/benchmark/run_zscope_scan.sh` 会自动加载它。

#### Vulnerability Analyzer 的 task 语义

`project.agents[].task` 对 `vulnerability_analyzer` 有特殊含义：它会先被解析为用户关心的漏洞类别，再映射到内置 Skill。运行时只会注入匹配的 Skill 契约，`SubAgentOrchestrator` 也只会为这些 Skill 生成 Deep Worker 工单；最终报告还会过滤明显不属于激活 Skill 家族的 finding。

常见写法：

| task 内容 | 激活方向 |
|-----------|----------|
| `只查找资源泄漏和空指针问题。` | `resource_lifecycle`, `null_and_failure` |
| `查找内存安全问题和并发风险。` | 内存安全相关 Skill + 并发相关 Skill |
| `只关注并发风险，不关心内存安全。` | `concurrency_lock_order`, `shared_state_race`, `stack_escape` |

如果 `task` 为空或没有命中已知关键词，系统会保持旧行为：启用 `vulnerability_analyzer` 的全部默认 Skill，避免老配置意外漏扫。

#### 风险自适应预算与 Deep Worker 结果回收

配置中的 `max_recursion_depth`、`max_premodel_depth`、`max_premodel_callees` 和 `max_subagent_tickets` 是硬上限。运行时 `RiskBudgetPlanner` 会根据入口源码、调用扇出、资源/回调/dispatcher 形态、协议/运行时 callee、图候选、后端候选和历史缺陷计算每个入口的 `effective_budget`。低风险入口会自动缩小预建模深度、图遍历范围和 Worker 数量；高风险入口才接近上限。预算结果、风险分数和原因会写入最终报告 metadata。

`max_subagent_tickets` 只限制本轮实际执行的 Deep Worker 数量，不会丢弃超过预算的候选点。`SubAgentOrchestrator` 会先收集所有候选点，再按风险启发式排序选择预算内工单；未执行的候选点会作为 `subagent_unassigned_candidates` 传给主 `vulnerability_analyzer`，由主 Agent 继续纳入分析。v1.3.1 延续 `subagent_max_turns`、`subagent_ticket_timeout`、`subagent_spawn_allowlist`、`subagent_skill_llm_refs` 和 `subagent_skill_efforts` 控制工单执行边界与不同 Skill 的模型路由；安全验证由扫描级全局队列统一调度，软预算只记录超限，不会把服务可用时的候选提前终止。

每个 Worker 报告都会带明确状态：`completed`、`failed`、`invalid`、`partial` 或 `killed`。其中 `invalid` 表示 Worker 返回了文本但没有合法 `worker_report` JSON；原始输出和 partial text 会保留给主 Agent，但不会被当作可靠证据。

#### 证据候选、评分与观察项

v1.3.1 的主路径是“事实先于候选，proof 先于 LLM”：项目级确定性遍历先构建控制流、值域、所有权、锁、happens-before 和调用契约事实；只有形成结构化安全义务的 lead 才晋级候选。确定性规则覆盖整数/边界错误、资源泄漏、UAF、double/invalid free、栈逃逸、缺失解锁、回调持锁、条件变量误用、signed/unsigned 转换、空指针、共享状态竞态、格式串、命令注入、stale fd/mmap 等通用形态；无法形成完整 proof 的候选再交给 Validator，而不是让 LLM 从全仓库重新发现事实。

`CandidatePipeline.collect_signal_candidates()` 会收集 `local_candidates`、`graph_candidates`、`backend_candidates` 和 `merged_candidates`。其中本地候选来自 regex、Clang AST/CFG 与项目语义；图候选覆盖持锁调用会重入加锁的 helper、清理函数类型不匹配、线程入口使用短生命周期参数、全局容器注册/注销不完整、timer/pipe 等级联等待和锁顺序反转；后端候选会归一化 Clang KnowledgeDB call-edge、Joern CPG rule match 和 SVF/Saber 信号。候选进入 `CandidateLedger` 去重后，会按激活 Skill 下发给 Deep Worker；即使超过 `max_subagent_tickets`，剩余候选也会作为上下文传回主 Agent。

Validator 启用时使用三态语义：`verified` 表示证据可闭合，`rejected` 表示被源码或用户配置否决，`uncertain` 表示值得人工复查但不应直接报告。Z-SCOPE 会计算 `final_score`；默认只有高分验证结果进入 `issues`，`needs_review` / `uncertain` 进入 `metadata.audit_observations`，退出码也只基于 `issues` 判断。若关闭 Validator，候选会以 `unvalidated` 状态进入报告，供人工后续复核。

#### Workflow 选择规则

Workflow 选择是运行时行为，不是 YAML 配置项。普通 `zscope -c zscope.yaml` 固定使用 `default.yaml`；传入 `--resume` 时 CLI 会把当前运行切换为 `resume.yaml`；传入 `--maintain` 时切换为 `maintain.yaml`。如果 `zscope.yaml` 中出现 `analysis.workflow_name`，配置加载会直接报错。

工作流文件定义的是运行时步骤，例如 `compare_hashes`、`reuse_unchanged`、`reconcile_changed`、`rescan_changed`。Analyzer 会按这些步骤推进 Agent 编排，并在最终报告的 `metadata.workflow_progress` 中记录当前 workflow 执行到了哪一步。

#### Diff impact 增量影响扫描

`--diff-base` 会进入自 v1.2 起提供的差异影响扫描模式。`DiffImpactPlanner` 调用 `git diff --unified=0` 获取新版本行号，把变更行映射到当前 `CodeIndex` 中的函数，再按变更语义生成 `analysis_obligations`：新增外部 API、输入边界、资源申请等偏正向扩展；资源释放、sink/check、unlock/destroy 等偏反向寻找 owner/source/acquire/input；所有权转移、生命周期契约等双向收敛。最终扫描入口来自这些义务的最小必要 root，而不是直接枚举所有外部反向路径。`project.diff_impact` 可配置每类 intent 的 caller 搜索深度，`llm_triage=on_demand` 只在高 fan-out 或静态根选择不清时参与选根。

入口选择会做上下文合并：thin wrapper、纯 facade、无额外语义的父级调用会进入 `context_callers`，不重复作为独立 root；唯一不可信输入边界、真正的 owner/acquire root、影响 handler/resource/state 分支的 dispatcher 会保留为扫描入口。所有 changed functions 都会进入 `diff_impact.function_coverage[]`，未独立扫描的函数会标出 `covered_by_entry`、`context_only`、`triage_only` 或 `unresolved` 以及合并/忽略原因。

默认情况下，diff 扫描会从 `project.source_root` 自动推断 git worktree 根目录。若 `source_root` 是仓库子目录且 diff 路径带有上层目录前缀，可用 `--diff-repo-root /path/to/git/root` 显式指定执行 `git diff` 的仓库根。

可重复传入 `--diff-path` 限定本轮只纳入特定路径下的变更文件，例如 `--diff-path src/net --diff-path src/fs`。相对路径默认按 `project.source_root` 解释；如果 `source_root` 位于 git 根目录的子目录内，会自动转换成 git-root 相对 pathspec；绝对路径必须能归入 git worktree，否则会报出清晰错误。路径过滤只约束 changed files / changed functions，最终扫描 root 仍可位于路径外，例如路径内 release 变更需要路径外 acquire/owner root 才能完整分析时会保留该 root。

该模式会写出项目根目录的 `entry_functions_diff.json`，并把每个入口的 `diff_focus` 注入 Agent 上下文。`diff_impact` 会包含 `path_filters`、`changed_functions`、`analysis_obligations`、`coverage_summary` 和 `function_coverage`。批量报告会给 issue 和 audit observation 标注 `diff_relevance`：`incremental` 表示直接落在变更函数、变更行或受影响路径上；`existing` 表示本轮入口发现到的存量问题；`unknown` 表示需要人工确认变更影响。若路径过滤后没有可扫描入口，系统仍会写出空的 `entry_functions_diff.json`，随后停止并提示过滤条件没有匹配入口，不会回退到 `entry_function: main`。`--diff-base` 不能与 `--resume` 或 `--maintain` 同时使用。

#### 用户配置工作簿与自动推断

`--infer-user-config` 会构建代码索引，调用默认 LLM 配置筛选/修订候选行，生成或刷新一个可人工审阅的 `user_config.xlsx`，然后退出，不执行漏洞扫描。LLM 筛选并发数来自 `analysis.parallel_workers`，会统计 reviewed / kept / revised / dropped / unreviewed / errors。默认路径为 `{snapshot_dir}/user_config.xlsx`；如果 `analysis.user_config_db` 填的是 `.xlsx`，则使用该文件；如果填的是目录，则使用目录下的 `user_config.xlsx`。反馈、baseline 和配置告警会写入同名 `.state.db`。

工作簿包含六类 sheet：

| Sheet | 用途 |
|-------|------|
| `resource` | allocator/reallocator/deallocator/copy 等资源语义与多对多释放关系 |
| `lock` | 自定义 lock/unlock API 与配对关系 |
| `dispatcher` | 消息分发函数、message type、handler、handler 资源语义和分支配对 |
| `module_lifecycle` | init/finit、模块级资源和错误路径清理要求 |
| `pointer_targets` | 函数指针、ops 表、hook slot 的目标函数 |
| `function_intents` | 人工确认的函数设计意图、调用约束和特殊说明 |

推断来源包括函数名、函数体调用、函数式宏、历史语义快照和常见 C API 语义。生成行会带 `source=inferred:*` 与 `confidence`，再次推断时会刷新或移除过期 inferred 行；人工填写的行会保留。扫描时 `UserConfigStore` 会优先读取工作簿，并把抑制与 baseline 状态继续写到旁路的 `.state.db`，所以用户知识和审计反馈可以同时生效。

运行时不会把整张表塞入 LLM 上下文。Analyzer 会按当前函数源码标识符、文件路径 scope、dispatcher 分支、module lifecycle 和 function intent 过滤，只注入与当前入口相关的用户配置片段。

### Step 2：执行分析

运行入口由配置决定：未配置 `entry_functions_list` 且未启用 `project.entry_discovery.enabled` 时走单入口；配置了 `entry_functions_list`，或入口发现产生了候选时走批量入口。

```bash
# 单入口模式：从 entry_function 开始分析
zscope -c zscope.yaml --verbose

# 批量扫描模式：从 entry_functions_list JSON 开始
zscope -c zscope.yaml

# 断点续扫：跳过已完成的函数，继续中断的批量扫描
zscope -c zscope.yaml --resume

# 增量维护：仅对代码有变化的函数重新检视，复用未变化函数的历史报告
# CLI 会自动选择 zscope/workflows/maintain.yaml
zscope -c zscope.yaml --maintain

# 强制自动发现入口点并扫描：基于启发式扫描项目网络收发、线程与 API 暴露点
# 发现结果会写入项目根目录 entry_functions_list.json
zscope -c zscope.yaml --discover-entries

# 差异影响扫描：根据 git diff 自动选择受影响入口
# 生成 entry_functions_diff.json，并在报告中标注增量/存量/影响待确认
zscope -c zscope.yaml --diff-base origin/main --diff-head HEAD
# 若 source_root 是仓库子目录，可显式指定 git worktree 根
zscope -c zscope.yaml --diff-base origin/main --diff-head HEAD --diff-repo-root /path/to/git/root
# 只规划 src/net 与 src/fs 下的变更；必要的扫描 root 仍可位于路径外
zscope -c zscope.yaml --diff-base origin/main --diff-head HEAD --diff-path src/net --diff-path src/fs

# 推断/刷新人工可审阅的用户配置工作簿，然后退出
zscope -c zscope.yaml --infer-user-config

# 作为本地 MCP Server 运行（配合 Claude Desktop 等 MCP 客户端使用）
zscope -c zscope.yaml --mcp-stdio

# 作为实验性 Streamable HTTP MCP Server 运行（远程绑定必须提供 token 与 allowlist）
export ZSCOPE_MCP_TOKEN="replace-me"
zscope -c zscope.yaml --mcp-http --mcp-host 127.0.0.1 --mcp-port 8765 \
  --mcp-auth-token-env ZSCOPE_MCP_TOKEN --mcp-client-allowlist 127.0.0.1

# 1.x 兼容入口；C/C++ 已弃用并告警，2.0 删除
zscope --mode ruledriven -c zscope.yaml

# 告警验证模式：导入外部工具的 SARIF 报告，LLM 二次确认
zscope --mode alert-verify --sarif cppcheck_results.sarif -c zscope.yaml

# 扫描完成后导出 SARIF v2.1.0
zscope -c zscope.yaml --export-sarif zscope-results.sarif

# 仅构建代码索引（预热，不执行分析）
zscope --build-index -c zscope.yaml
# --build-cpg 仅是 1.x 弃用别名，2.0 删除
```

### Step 3：查看分析结果

分析完成后会按运行模式在项目根目录生成：

| 文件 / 目录 | 说明 |
|------|------|
| `report.md` | 单入口模式的人类可读报告 |
| `report.json` | 单入口模式的结构化缺陷数据，包含 `issues[]`、`report_views` 与 metadata |
| `zscope_batch_report.md` | 批量模式的人类可读审计汇总报告 |
| `zscope_batch_report.json` | 批量模式的结构化缺陷数据（可供 CI 集成），包含 `issues[]`、`report_views`、严重度分组和批量统计；覆盖前会把旧 JSON 备份到 `.zscope_knowledge/backups/` |
| `zscope_alert_verify_report.json` | 告警验证模式的验证结果 |
| `zscope-results.sarif` | `--export-sarif` 指定路径上的 SARIF v2.1.0 导出结果 |
| `entry_functions_list.json` | `--discover-entries` 或 `project.entry_discovery.enabled` 生成的候选入口列表 |
| `entry_functions_diff.json` | `--diff-base` 生成的差异影响入口列表，包含 `diff_impact.path_filters`、`analysis_obligations`、`coverage_summary`、`function_coverage` 和每个入口的 `diff_focus` |
| `.zscope_snapshots/` | 语义快照缓存（加速重复扫描） |
| `.zscope_snapshots/user_config.xlsx` | `--infer-user-config` 生成的人工可审阅用户配置工作簿 |
| `.zscope_snapshots/user_config.state.db` | 配置告警、finding suppression 与 baseline 的旁路状态库（若 `analysis.user_config_db` 指向其他 workbook，则与该 workbook 同名） |
| `.zscope_knowledge/code_knowledge.db` | 代码索引、SVF/Saber 信号和候选证据 IR |
| `.zscope_bc/bitcode_scope_<group>.json` | SVF 入口裁剪计划，记录选中的源码、bitcode、可达函数、link variants、重复符号和回退原因；WSL/NTFS 场景可能重定向到 Linux 原生临时目录 |
| `.zscope_bc/entry_cluster_layout_<group>.json` / `bitcode_manifest.json` | SVF 入口聚类布局与 bitcode/link 缓存 manifest，用于复用未变化的聚类和构建产物 |

单函数最终报告的 `metadata` 会记录 `candidate_signal_summary`、`candidate_ledger_summary`、`semantic_dedup_summary`、`effective_budget`、`budget_scores`、`budget_reasons`、`diff_focus`、`report_view_summary`、`audit_observation_count`、`audit_observations`、累计 token、Validator fast-path 和工具调用统计。批量 diff impact 报告还会记录 `metadata.diff_relevance_summary` 和 `metadata.diff_impact_coverage`，Markdown summary 会展示 changed function 覆盖摘要与未独立扫描函数预览。`report_views.default` 只包含默认可报告问题，`report_views.with_needs_review` 会额外包含需要人工复核的观察项。`issues[]` 中的缺陷会带 `finding_kind`、`final_score`、`score_components`、`source`、`sink`、`positive_evidence`、`negative_evidence`、`duplicate_sources`、`alternate_evidence`、`resource_signature` 等字段。

退出码：默认漏洞报告中的 `issues` 非空返回 `1`，无缺陷返回 `0`。`needs_review` / `uncertain` 观察项不会单独拉高退出码，适合 CI/CD 只阻断已验证或高分问题。

### Step 4：启动 Web 仪表盘（可选）

```bash
zscope --dashboard -c zscope.yaml
# 可选：zscope --dashboard -c zscope.yaml --dashboard-host 127.0.0.1 --dashboard-port 8000
```

仪表盘提供四个主要页面：
- **审计发现**：查看缺陷列表、报告视图和 evidence，支持六种验证状态标记，并将 `rejected` 反馈持久化为误报抑制和 baseline
- **项目配置**：查看和编辑 `zscope.yaml` 中的项目、入口发现、索引后端、工具路径与分析行为配置
- **用户配置**：以 `user_config.xlsx` 为入口维护 resource、lock、dispatcher、module lifecycle、pointer targets 和 function intents，支持保存、导入与下载
- **看板**：展示验证状态分布、风险概览、配置告警和审计进度

## 分析工具清单（最多 12 个内置 Agent 工具）

| # | 工具名 | 用途 | 有效数据来源 |
|---|--------|------|---------|
| 1 | `get_function_impl` | 获取函数完整源码 | 全部 |
| 2 | `get_function_snapshot` | 语义缓存复用 | 全部 |
| 3 | `list_known_functions` | 函数发现（正则搜索） | 全部 |
| 4 | `get_file_snippet` | 读取指定行范围的上下文代码 | 全部 |
| 5 | `get_callers` | 调用者查询（漏洞可达性分析） | joern/clang/unified；regex 返回空结果 |
| 6 | `get_type_info` | 结构体/类型定义查询 | joern/clang/unified；regex 返回空结果 |
| 7 | `get_call_graph` | 调用图聚合（直接调用；unified 可合并 SVF 间接调用） | joern/unified |
| 8 | `get_data_flow` | 污点追踪 | joern/unified |
| 9 | `find_function_pointers` | 回调/钩子发现 | joern/unified |
| 10 | `query_pointer_alias` | 指针别名查询 | unified |
| 11 | `verify_taint_reachability` | SVF/Saber 内存缺陷查询 | unified |
| 12 | `get_deep_call_context` | 高聚合查询（调用者+被调用者+间接调用+污点缺陷） | unified |

Agent 工具可见性由 `AGENT.md` 与后端 gate 共同决定：`semantic_modeler` 主要使用前 6 个工具；`vulnerability_analyzer` 在 joern/unified 后端下再开放第 7-12 个高级查询，其中 SVF 特有结果只有 unified 后端会返回有效数据。MCP Server 会额外暴露 `query_knowledge`（只读查询 `code_knowledge.db`）与 `discover_entries`（入口发现）两个工具，供外部 MCP 客户端交互式审计使用。MCP 侧还提供 `zscope.code.*`、`zscope.graph.*`、`zscope.knowledge.query`、`zscope.entries.discover` 等 namespaced aliases；无论 stdio 还是 HTTP 传输，工具调用都会经过 `ToolPolicy`。

## 用户辅助配置

静态分析工具存在能力边界，Z-SCOPE 支持用户通过 Web 仪表盘补充以下信息，分析时自动注入上下文：

| 配置类型 | 说明 | 示例 |
|----------|------|------|
| 外部库函数描述 | 无法获取实现的外部函数的内存/并发行为 | `pthread_mutex_lock` 的锁语义 |
| 自定义配对函数 | 用户实现的 malloc/free、lock/unlock 等配对 | `my_alloc` ↔ `my_free` |
| 函数指针指向 | 函数指针、ops 表或 hook slot 的具体目标函数 | `handler_ptr` → `handle_read` |
| Dispatcher 分支 | 消息分发入口、message type、handler 及其资源 acquire/release 关系 | `MSG_APPLY` → `handle_apply` |
| 模块生命周期 | init/finit 配对、全局容器、错误路径是否必须回滚 | `module_init` ↔ `module_finit` |
| 函数设计意图 | 函数对调用者的约束和并发关系 | "此函数不会被并发调用" |
| Finding 抑制 | 对已确认误报按函数、位置、类别或规则进行抑制 | `src/demo.c:42` 的 `double_free` |
| Finding baseline | 记录历史验证结论，影响后续评分与过滤 | `true_positive` / `false_positive` / `needs_review` |

这些信息可以通过 Web 仪表盘维护，也可以放在 `user_config.xlsx` 中人工编辑。`--infer-user-config` 会生成候选行供审阅，人工确认后的行会在后续扫描中作为项目语义参与确定性候选生成、上下文注入和评分。Web 仪表盘保存验证结果时会自动维护 `finding_suppressions` 与 `finding_baselines`；命中误报抑制或 `false_positive` baseline 的候选会被过滤，命中 `true_positive` 的历史项会提高评分中的历史反馈分。

## 后端对比

| 特性 | regex（C/C++） | joern（Java；C 仅 1.x 兼容） | clang（C/C++） | unified（C/C++） |
|------|-------|-------|-------|---------|
| 外部依赖 | 无 | JDK 21 + Joern | clangd >= 20.1 | clangd >= 20.1 + Go/gllvm + binutils/objcopy + SVF + LLVM/llvm-link/llvm-nm |
| 函数源码提取 | 正则匹配 | CPGQL 精确 | AST 精确 | AST 精确 |
| 调用图 | 不支持 | 完整 CPG | 直接调用 | 直接 + 间接（SVF 指针分析） |
| 类型查询 | 不支持 | 完整 | AST 精确 | AST 精确 |
| 污点分析 | 不支持 | 数据流追踪 | 不支持 | SVF saber（内存泄漏/UAF/双重释放） |
| 间接调用解析 | 不支持 | 有限 | 不支持 | SVF Andersen 指针分析 |
| SVF bitcode 裁剪 | 不适用 | 不适用 | 不适用 | 支持按入口调用图、入口聚类、always include、互斥/共享 pool 和符号闭包裁剪，必要时回退 full/skip |
| 候选/信号入报告链路 | regex 本地候选进入 `CandidatePipeline` | Joern rule match 可归一化为候选；规则驱动模式可直接验证 | Clang KnowledgeDB call_edges / AST matcher fact 可归一化为候选 | SVF/Saber、Clang 和 KnowledgeDB 信号归一化为候选并进入证据 IR |
| 规则驱动模式 | 普通规则进入统一候选流水线 | Java 信号支持；C 兼容模式已弃用 | 普通规则进入统一候选流水线 | 普通规则进入统一候选流水线 |
| 内存占用 | 极低 | 高（JVM） | 中 | 中高 |

## 开发命令

```bash
# 安装开发依赖
python -m pip install -e ".[dev]"

# 格式化
black zscope/ --line-length 100

# 严格类型检查
python -m mypy zscope

# 强制编译检查，覆盖 Python 解释执行前可能隐藏的分支语法/导入问题
python -m compileall -f -q zscope scripts test tests

# 运行测试
python -m pytest

# v1.3.1 关键面回归
python -m pytest -q tests/test_candidate_ledger.py tests/test_decision_facts.py tests/test_evidence_completion.py tests/test_finding_roots.py tests/test_validation_runner.py tests/test_validator_evidence_slice.py tests/test_report_schema_v2.py tests/test_range_release_aggregate.py tests/test_range_benchmark_harness.py

# 仅评估确定性候选在 range benchmark 上的覆盖率
python scripts/evaluate_range_regression.py --deterministic-candidates

# 外部 benchmark 协议：准备好的 suite 会输出 zscope.benchmark.v3 summary/evaluation
python scripts/external_benchmark.py run-prepared --suite-root benchmarks/external/workspace/<suite> --condition candidate_layer --run-kind smoke
```

## 更新日志

### v1.3.1
- **版本与 Python 门禁**：包版本、CLI/MCP/Web 同步到 `1.3.1`，Python 3.9–3.14 使用独立带哈希约束和真实解释器 CI。
- **离线交付**：新增签名校验的一键安装器、CPython 3.13 应用包、按语言拆分依赖包、SBOM、许可证与升级/回滚布局。
- **Java Preview**：迁入 Java source/java_unified 索引、SootUp/WALA/Joern 信号接口、48 条本地规则和 58 条 truth（覆盖 49 个规则 ID）/54 个入口的结构 benchmark；`c047dca` 上已归档首个五轮 Preview LLM 基线，但不参与 v1.3.1 C/C++ 发布门禁。
- **统一规则扩展**：新增 `rule_pack_version: 1` YAML 校验、`zscope.rule_providers` entry point、语言隔离、重复 ID/未知 Skill 失败以及 `zscope-rules list|validate|test`。
- **候选生命周期 v3.3**：项目事实、结构化安全义务、validation group、occurrence alias 和 canonical outcome 进入单一流水线；正常完成时不允许残留 `pending`、`requested`、`running` 或 `validation_not_completed`。
- **确定性证据闭环**：新增 guard/边界、所有权/生命周期、锁/HB、调用契约等 proof provider。完整正向 proof 直接确认，完整反证才允许拒绝，证据冲突或缺失保守进入一个组级 `needs_review`。
- **低噪声根因投影**：`FindingRoot v1` 按结构化对象、sink/exit、decision region、代码和 proof 上下文投影 primary/alias，保留全部 occurrence 与 provenance，不使用 LLM 文本去重隐藏告警。
- **Validator token 收敛**：`ValidatorEvidenceSlice v2`、类型化补证、项目事实复用和最多两响应协议消除重复上下文及无边界浏览。五轮正式 Range 冷扫描 tokens 中位数为 1.324M。
- **发布门禁与证据**：五轮 WSL、自动入口发现、unified+SVF、GLM-5.1 正式扫描均完成 88/88 入口并通过硬门槛；Confirmed TP 中位数 89、raw FP 中位数 2、含复核 TP 固定 134。聚合和哈希清单保存在 `docs/range_reports/v33_release_final2_glm51_20260810/`。

### v1.2
- **版本号刷新**：包版本、README、架构文档和 Web 默认展示同步到 `1.2`。
- **Diff impact 精细化**：`--diff-repo-root`、重复 `--diff-path`、`project.diff_impact`、按 intent 的 caller 搜索深度、按需 `llm_triage`、`coverage_summary` 与 `function_coverage` 共同约束扫描 root，不再把所有反向外部路径都当成独立入口。
- **Unified/SVF 性能增强**：SVF entry scope 默认上限收敛为 200 TU，新增入口聚类布局缓存、bitcode/link manifest、互斥/共享 bitcode pool、link variant 记录和重复符号审计，批量入口可先共享 Clang 索引再延迟运行 SVF。
- **Clang 与 KnowledgeDB 增量鲁棒性**：Clang 后端用文件哈希跳过未变 TU，清理删除文件及其关联缓存，持久化 macro 定义；KnowledgeDB 增加调用图查询缓存、WAL/per-thread connection 和删除 TU 影响分析。
- **LLM 与验证链路提速**：LLM profile 支持多个 `base_urls`、每 endpoint RPM/并发上限、429/5xx cooldown 与累计 token 统计；Validator 增加 compact evidence fast-path、并行验证、entry-root retry 和更宽容的 JSON 解析；alert-verify 也可并行复核。
- **候选与去重精度增强**：本地/Clang/图候选新增或细化 fd 类型/编码契约、协议版本过滤、EAGAIN/EINTR 无预算重试、协议元素数与字节数错配、宏锁 no-op、部分资源重试失败清理等形态；语义去重继续使用类别家族、资源签名和 root-cause key 控制合并边界。
- **Benchmark 审计协议补强**：range ground truth 仍为 version 13 / 121 个有效漏洞；`zscope.benchmark.v3` 增加 false-positive audit 分类、duplicate-of-matched 拆分、suite-specific FP 审计规则和 benchmark 泄漏守卫。

### v1.1
- **版本号刷新**：包版本、README、架构文档、Web 默认展示和根配置样例同步到 `1.1`。
- **Diff impact 扫描落地**：新增 `--diff-base` / `--diff-head` / `--diff-path`，从 git diff 映射变更函数，按语义义务选择扫描 root，输出 `entry_functions_diff.json`、覆盖摘要和路径过滤 metadata，并在报告中标注增量、存量和影响待确认。
- **最终报告语义去重**：`reporting.semantic_dedup` 新增程序化同根因合并和可选 LLM 判重；报告保留 `semantic_dedup_summary`、`duplicate_sources`、`alternate_evidence`、`dedup_decisions`、`category_family` 与 `resource_signature`。
- **协议/运行时类候选扩展**：候选层新增对象发布顺序、语义单位错配、字节序逻辑、reader/global/slot/shared-memory race、lost wakeup、状态机、signal deadlock、callback self-destroy、文件类型验证和 FD 表示契约等规则。
- **Deep Worker 与预算控制细化**：新增 `subagent_max_turns`、`subagent_ticket_timeout`、`subagent_spawn_allowlist`、`subagent_skill_llm_refs`、`subagent_skill_efforts` 和 `tool_audit_log` 配置；风险预算会识别 thin facade 与 protocol/runtime callee，扩大必要的直接 callee 扫描。
- **Benchmark v13**：range ground truth 升级到 version 13，当前包含 121 个有效漏洞；评分协议支持把已命中 TP 的重复报告从有效 FP 中区分出来，并能读取嵌套 evidence location anchor。

### v1.0
- **首个正式发布版本**：版本号统一为 `1.0`，README、架构文档、Web 前端和 MCP `serverInfo.version` 同步展示 v1.0。
- **架构模块拆分完成**：原先集中在 `Analyzer` 与 `zscope/core/*.py` 的职责拆分到 `zscope/core/analysis/`、`zscope/core/candidates/`、`zscope/core/validation/`、`zscope/reporting/`、`zscope/common/issue_identity.py`、`zscope/memory/`、`zscope/semantics/`、`zscope/tools/` 和 `zscope/orchestration/`。
- **候选流水线稳定化**：`CandidatePipeline` 统一收集 local / graph / backend candidates；Clang AST/CFG、SVF value-flow、Joern CPG、KnowledgeDB call-edge 与用户语义 overlay 都进入同一 evidence-only 候选面。
- **稳定缺陷身份落地**：`canonical_issue_key`、`stable_issue_fingerprint` 与 source context fingerprint 统一服务报告去重、ReviewMemory、SARIF partial fingerprints、baseline 命中和 benchmark 匹配。
- **验证与反馈闭环收敛**：`ValidationRunner`、`ValidationPipeline`、`ReviewMemory` 和 `ReportAssembler` 明确分层；`verified` / `rejected` / `uncertain` / `needs_review` / `unvalidated` 的报告与 Web 复核语义保持一致。
- **Web 与用户配置工作簿升级**：Dashboard 增加项目配置、用户配置工作簿、看板和配置告警视图；`GET/POST /api/user_config/workbook`、`POST /api/user_config/workbook/import` 与下载接口支撑 `user_config.xlsx` 作为人工配置入口。
- **MCP 暴露面加强**：stdio MCP 保持本地集成；实验性 Streamable HTTP MCP 增加 bearer token 环境变量、客户端 allowlist、loopback 检查和 `ToolPolicy` 审计。
- **Benchmark 体系扩展**：range fixture 当前 ground truth version 10，包含 93 个有效漏洞；外部 benchmark harness 输出 `zscope.benchmark.v3`，记录双视图指标、matched pairs、stable identity、cost、trajectory 和多 trial 稳定性。

### v0.6.0
- **证据优先候选流水线成型**：新增 `DeterministicCandidateGenerator`，以通用 C 语言模式生成带 `candidate_id`、`dedup_key`、source/sink、正反证据和 `evidence_pack` 的候选，覆盖整数/边界、资源生命周期、时序内存、栈逃逸、空指针、锁与共享状态、格式串、命令注入和 stale fd/mmap 等问题。
- **跨函数图候选补强**：新增 `GraphCandidateGenerator`，从调用图、锁区域、生命周期协议和 liveness 形态中生成候选，覆盖跨函数递归锁、锁顺序反转、错误清理契约、线程参数生命周期、全局容器生命周期、timer/pipe 等级联等待和 stale tree/list 链接。
- **后端信号进入同一报告链路**：Unified 后端产生的 SVF/Saber/KnowledgeDB 信号会被规范化为 `backend_signal` 候选，与本地规则和 LLM finding 一起进入 CandidateLedger、Deep Worker、Validator、去重和报告输出。
- **风险自适应预算**：新增 `RiskBudgetPlanner`，把配置中的最大递归、预建模、图遍历和 Deep Worker 数量转为每入口 `effective_budget`，并在报告 metadata 中保留 `budget_scores` 与 `budget_reasons`，让低风险函数更轻量、高风险函数保留深挖空间。
- **KnowledgeDB schema v7 与 Inspection IR**：`code_knowledge.db` 新增 `ir_statements`、`ir_resource_events`、`ir_lock_events`、`ir_shared_accesses`、`ir_path_slices` 和 `function_contracts`，用于保存候选证据、路径切片、资源/锁/共享状态事件及评分组件。
- **三态验证与评分分层**：Validator 支持 `verified` / `rejected` / `uncertain`，Analyzer 计算 `final_score` 与 `score_components`。高分结果进入 `issues`；`needs_review`、`uncertain` 和验证失败的候选进入 `metadata.audit_observations`，默认不触发 CI 失败。
- **报告视图、根因去重与 SARIF 导出**：新增 `report_views.default` / `report_views.with_needs_review`，当时通过根因级去重合并重复 finding；CLI 新增 `--export-sarif`，可把完成后的 Z-SCOPE 报告导出为 SARIF v2.1.0。该去重链路在 v1.0 已统一到 `zscope/common/issue_identity.py`。
- **人工反馈闭环落地**：`UserConfigStore` 新增 `finding_suppressions` 与 `finding_baselines`。Web 仪表盘支持六种验证状态，并会把 `rejected` 写成误报抑制，把 `validated` / `needs_review` / `uncertain` 写成 baseline，后续扫描自动过滤或调整评分。
- **用户配置工作簿与推断链路**：移除批量 `prompt_autofill` 流程，新增 `user_config.xlsx`、`UserConfigWorkbook` 和 `--infer-user-config`。系统可推断 resource/lock API、多对多配对、dispatcher 分支、module lifecycle、pointer target 与 function intent，并在扫描时只注入相关配置片段。
- **入口发现结果落盘**：`--discover-entries` 会把候选入口、exposure、reasons、confidence 和审计提示写入项目根目录 `entry_functions_list.json`；`entry_discovery.search_root` 可把发现范围限制到指定绝对目录。
- **Range benchmark 回归体系扩展到 v6**：`test/range` 新增全局容器注册生命周期、scheduler/pipe 复合并发失败、嵌套 child-list 清理、AVL key 截断/陈旧节点和宏门控锁场景，总漏洞数提升到 45 个，并由 pytest 回归用例约束确定性候选覆盖率。
- **索引与构建鲁棒性补强**：Clang/regex 函数识别支持更多 C 声明修饰；`CodeIndex.get_function_impl()` 会附带声明/实现前导注释块，帮助 Agent 看到头文件契约；SVF bitcode 构建自动注入兼容 flag，并支持 `svf_scope` 入口裁剪、`llvm-nm` 符号闭包和 `bitcode_scope_<group>.json` 审计计划；Deep Worker 会接收结构化 evidence，Validator 输出兼容旧 `is_valid` 与新 `verdict` 格式。

### v0.5.0
- **全架构重构与扁平化**：扁平化了冗余的 `zscope/zscope` 目录结构，统一通过 `pip install -e .` 安装，更贴合标准 Python 打包规范。大幅强化三库同源（`code_knowledge.db`, `snapshots.db`, `user_config.db`）的底层持久化隔离与可观测性。
- **声明式工作流与智能体编排**：引入 `workflows/` 机制（如 default/maintain/resume 工作流）和基于 Markdown Frontmatter 的 `AGENT.md`/`SKILL.md` 契约。`zscope/workflows/*.yaml` 现在驱动实际执行步骤和 Agent 编排，报告 metadata 会记录 `workflow_progress` 与当前步骤。
- **Task 驱动的 Skill 选择**：`vulnerability_analyzer.task` 现在会解析用户关注点并限制本轮启用的漏洞挖掘 Skill。Agent 契约注入、Deep Worker 工单规划和最终 finding 过滤都遵循同一组 active skills，从源头减少用户不关心类别的检出。
- **批量 custom_prompt 自动补齐（历史能力）**：v0.5 曾提供 `zscope-prompt-autofill` 与 `PromptAutofillExecutor`，用于在批量扫描前补齐 `entry_functions_list` 中缺失或过短的 `custom_prompt`。该链路在 v0.6 已由 `user_config.xlsx` 与 `--infer-user-config` 取代。
- **C 内存/并发确定性候选层**：新增通用候选生成与证据包路径，覆盖边界/整数、资源生命周期、时序内存、栈逃逸、锁与共享状态等高价值缺陷，并接入 Deep Worker、Validator、报告分层和回归评测。
- **CLI Workflow 自动映射**：`--maintain` 自动选择 `maintain.yaml`，`--resume` 自动选择 `resume.yaml`。`analysis.workflow_name` 是运行时内部字段，禁止写入 `zscope.yaml`；两种 CLI 模式互斥，CLI 会提前拦截非法组合。
- **Deep Worker 启发式任务规划**：引入 `SubAgentOrchestrator`，基于启发式自动探测函数内的分配、拷贝、加锁等关键操作，先全量收集候选点，再按风险和预算下发给聚焦型 `Deep Worker`。未执行候选、失败/invalid/partial Worker 结果都会回传给主 Agent，避免预算截断造成静默漏检。
- **智能入口点自动发现**：新增 `--discover-entries` 特性。如果未给定分析列表，通过 `EntryDiscovery` 启发式扫描公共头文件 API、通信 IPC 接口、线程创建函数和标准 IO 输入源，自动推测最优的安全审计切入点。
- **原生支持 MCP (Model Context Protocol)**：内置本地 MCP stdio Server (`--mcp-stdio`)，对外暴露了 Z-SCOPE 专有的 `CodeIndex` 结构化查询、语义快照索引等能力，允许第三方 MCP 客户端（如 Claude Desktop）安全地调取分析底座的数据与工具链。
- **递归预建模与并发防护**：引入 `SnapshotLockManager`，在实际漏洞分析前通过 BFS 逆拓扑遍历，提前将所有可达子函数推给 `语义建模Agent` 并在多 Worker 间互斥上锁。彻底消除上下文膨胀问题以及多线程同时并发请求同一个下层函数的复述问题。
- **平凡函数旁路拦截器**：结合极简代码行数（默认 `≤5`）和危险关键字黑名单正则（杜绝 `alloc`、`lock` 等操作漏网），直接在调度层利用 Python 硬拼装阻断 LLM API 请求，实现零成本微快照注入，整体节约 `20~40%` 并发扫描 Token 开销。
- **引入 IssueReconcilerAgent 增量分析优化**。支持断点续扫（`--resume`）特性的完善支持。利用大语言模型（LLM）精准跟踪源码变更情况下历史已验证缺陷的存在状态；对扫描阶段产生的新缺陷进行语义级别的去重判决。
- **第三方告警标准化适配**：重构告警验证模式，引入统一的 `AlertAdapter` 适配层与 `ExternalAlert` 模型，轻松接入 Coverity/CodeQL/Cppcheck 等第三方 SAST 的告警确认。
- **严格类型与编译检查补强**：开发依赖新增类型存根，并固定兼容的 `mypy<2.0`。当前代码通过 `python -m mypy zscope` 与 `python -m compileall -f -q zscope scripts test` 检查，降低解释型语言冷门分支延迟暴露错误的风险。

### v0.4.2 (2026-03-05)
- **绝对行号注入法**：摒弃了大模型容易产生幻觉的相对偏移（Offset）行号计算，采用在源码侧直接注入绝对行号前缀的方式，将报告的定位精度提升至 100% 物理行级。
- **快照指纹抗扰动**：优化了语义特征的哈希计算逻辑，自动忽略源码中新注入的行号前缀，确保历史语义快照缓存持久有效。
- **跨环境扫描增强**：优化了 `rglob` 文件遍历逻辑，自动忽略因权限不足或 WSL 符号链接（如 `venv/lib64`）引发的 `OSError` 崩溃，大幅提升了在 Windows/WSL 混合环境下的扫描鲁棒性。

### v0.4.1 (2026-03-01)
- **SVF 3.2 兼容性**：更新 `svf_parser.py` DOT 正则以支持 SVF 3.x `{CallGraphNode ID: N \{fun: name\}|...}` 节点格式和端口化边引用。
- **SVF 3.2 saber 兼容性**：移除无效 `-uaf` 标志，新增 SVF 3.x `NeverFree/DoubleFree/...` 输出解析器（兼容 v2/v3）。
- **gllvm 环境自动检测**：`build_llvm.py` 新增 `_make_gllvm_env()` 自动检测 `clang-{version}` 并设置 `LLVM_COMPILER`/`LLVM_CC_NAME`。
- **WSL NTFS 兼容**：检测 `/mnt/` 路径时自动重定向 bitcode 输出到 Linux 原生临时目录。
- **SVF 共享库自动发现**：`svf_runner.py` 自动发现 SVF/LLVM `LD_LIBRARY_PATH`。
- **SVF 优雅降级**：SVF 工具不可用时输出框式告警并继续运行 Clang 部分。
- **修复**：`build_llvm.py` 中 `Path.with_suffix(".o.bc")` 改为字符串拼接，修复复合后缀不可靠问题。

### v0.4.0 (2026-02-28)
- **UnifiedBackend Facade**：新增 `unified` 后端，组合 ClangBackend + SvfAnalyzer，共享 KnowledgeDB，通过 `(file_path, line)` 坐标缝合 Clang AST 与 SVF LLVM IR 结果。
- **告警验证模式**：新增 `--mode alert-verify --sarif <file>`，导入外部工具 SARIF 报告，LLM 二次确认。
- **新增工具**：`get_deep_call_context`（高聚合查询：调用者+被调用者+间接调用+污点缺陷一次返回）。
- **KnowledgeDB schema v3**：`indirect_calls` 表增加 `call_file`/`call_line` 坐标列，新增 `find_function_at()` 和 `get_enriched_taint_bugs()` 缝合查询。
- **废弃 SvfBackend**：独立 SVF 后端已废弃，功能合并至 `unified` 后端。

### v0.3.0 (2026-02-20)
- **三种分析模式**：新增自上而下模式（`--mode topdown`）和规则驱动模式（`--mode ruledriven`）。
- **用户配置系统**：SQLite 存储外部函数描述、配对函数、函数指针指向、函数设计意图，分析时自动注入上下文。
- **Joern 异步 CPG 构建**：后台线程构建 CPG，支持 `--build-cpg` 预构建和 Web 端触发。
- **规则引擎**：集成 Joern `run.scan.toJson` 内置规则、自定义 `.sc` 脚本、配对函数检查。
- **Web 仪表盘**：新增配置管理（5 子页签）、CPG 状态监控、误报标记、配置告警展示。
- **误报反馈闭环**：按 `(function, location, subcategory)` 匹配，报告生成前自动过滤。

### v0.2.0 (2026-02-18)
- **重大重构**：代码索引后端从 clangd LSP 迁移至 Joern CPG。
- **新增工具**：`get_callers`、`get_type_info`、`get_call_graph`、`get_data_flow`、`find_function_pointers`。
- **依赖变更**：移除 `libclang`，新增 `cpgqls-client`。

### v0.1.0
- 初始版本：多智能体协作、语义建模缓存、模型自动降级。
