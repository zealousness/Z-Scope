# Z-SCOPE (v0.6.0)

**Z-SCOPE** 是一款基于 **多智能体（Multi-Agent）** 协作的 C 项目深度静态分析工具。它把可插拔代码索引、确定性 C 内存/并发候选、SVF/Saber 后端信号与大语言模型（LLM）语义验证结合起来，模拟资深安全研究员的审计过程，旨在精准发现内存安全、资源生命周期、并发时序、逻辑漏洞及跨文件资源管理问题。

## 核心特性

- **多智能体分治与声明式编排**：采用 `AGENT.md` 与 `SKILL.md` 契约定义各智能体与技能。支持 `语义建模 Agent`、`漏洞扫描 Agent`、`Issue Reconciler Agent`、`验证 Agent` 以及隔离上下文的聚焦型 `Deep Worker` 独立协作。分析流程由 `zscope/workflows/*.yaml` 驱动实际执行步骤，而不是仅作为提示词上下文注入。
- **Task 驱动的漏洞 Skill 选择**：`vulnerability_analyzer.task` 不只是提示词描述。系统会结合本地关键词规则与可选 LLM 语义路由选择 `resource_lifecycle`、`bounds_and_integer`、`null_and_failure`、`concurrency_lock_order` 等漏洞挖掘 Skill；低置信或冲突判断会保守回退到全量 Skill，避免漏扫。
- **三种运行模式**：全新扫描（默认）、断点续扫（`--resume`）、增量维护（`--maintain`）。Workflow 选择由 CLI 运行模式控制，不允许在 `zscope.yaml` 中配置。另支持规则驱动模式和告警验证模式。
- **自动入口发现**：支持基于启发式的智能扫描入口发现（`--discover-entries`），自动识别头文件暴露的公共 API、网络收发、线程入口及用户输入点，并把候选写入项目根目录的 `entry_functions_list.json` 供后续复用和人工调整。
- **可审阅用户配置工作簿**：新增 `user_config.xlsx` 人工配置格式与 `--infer-user-config` 推断命令，可从源码、宏、语义快照中生成 resource/lock/dispatcher/module lifecycle/pointer target/function intent 候选。运行时只注入当前函数真正引用到的用户配置，降低上下文噪声。
- **证据优先的候选流水线**：`DeterministicCandidateGenerator` 针对 C 内存和并发缺陷生成通用候选，并会吸收用户配置、语义快照、函数命名和 typedef alias 形成项目级确定性语义；SVF/Saber/KnowledgeDB 后端信号会被归一化为同一类候选。候选携带 source/sink、对象或锁、正反证据、`dedup_key` 与 `evidence_refs`，再交给 Deep Worker 与 Validator 收敛误报。
- **三态验证与审计观察项**：Validator 支持 `verified` / `rejected` / `uncertain` 三态输出。Validator 启用时，Z-SCOPE 会计算 `final_score`，高分缺陷进入默认漏洞报告，`needs_review` / `uncertain` 进入 `metadata.audit_observations`，避免把证据不足的候选直接当成漏洞。
- **本地 MCP Server**：原生内置 Model Context Protocol (MCP) 标准的 stdio Server，允许外部工具（如 Claude Desktop）直接调用 Z-SCOPE 的代码索引、快照资源及工具总线。
- **多模型配置与路由**：支持在 `zscope.yaml` 中定义多个大模型配置（如 `fast_model` / `smart_model`），不同 Agent 可按需绑定最佳模型。
- **可插拔后端架构**：支持 Joern CPG、Clang（clangd LSP）、Unified（Clang + SVF）、Regex 四种后端，按需选择分析深度。
- **12 个分析工具**：函数源码获取、调用图分析、结构体查询、污点追踪、指针别名查询、深度调用上下文聚合等。
- **用户辅助配置系统**：通过 WebUI 或 `user_config.xlsx` 管理外部函数描述、配对函数、函数指针指向、dispatcher 分支、模块生命周期和函数意图等信息；手工验证反馈会写入误报抑制与 finding baseline，后续扫描自动复用。
- **智能增量分析与缺陷去重**：支持断点续扫（`--resume`）和基于语义哈希的增量维护扫描（`--maintain`）。自动跟踪和验证缺陷随代码流转的修复状态。
- **Web 仪表盘**：Alpine.js + DaisyUI 构建的交互式界面，集成扫描结果查看、`validated` / `needs_review` / `uncertain` / `unvalidated` / `pending` / `rejected` 状态标记、用户配置管理和配置告警。
- **可追踪持久化**：分析产生的终极漏洞（Issues）与语义模型会写入本地 `.zscope_snapshots/snapshots.db`；`code_knowledge.db` schema v7 新增轻量 Inspection IR 表，持久化候选 source/sink、资源事件、锁事件、共享访问与路径切片；用户领域知识可落在 `user_config.xlsx`，反馈状态继续由 SQLite 管理。
- **自动报告备份护城河**：每次批量生成或覆盖 JSON 分析主报告前，自动创建带时间戳的增量备份至 `.zscope_knowledge/backups/` 目录。
- **严格编译与类型检查**：开发环境支持 `compileall` 强制编译检查和 `mypy` 静态类型检查，避免 Python 解释执行到冷门分支时才暴露错误。
- **纯 YAML 驱动**：所有分析参数通过 `zscope.yaml` 统一定义，支持 `${ENV_VAR}` 环境变量展开。

## 系统架构

```
CLI 入口层 (cli.py)
    │
    ├─→ 默认/批量模式 (analyzer.py)
    ├─→ 规则驱动模式 --mode ruledriven
    ├─→ 告警验证模式 --mode alert-verify
    ├─→ 自动入口发现 --discover-entries
    ├─→ 用户配置工作簿推断 --infer-user-config
    └─→ 本地 MCP 服务 --mcp-stdio
          │
          ▼
声明式工作流编排 (workflows/ + SpecRegistry)
          │
          ▼
CodeIndex (可插拔后端) + SnapshotStore + UserConfigStore(XLSX/SQLite) + KnowledgeDB IR
          │
          ├─ CodeBackend ABC (backend_base.py)
          │  ├─ JoernBackend    — CPGQL via WebSocket
          │  ├─ ClangBackend    — clangd LSP 批量提取 → KnowledgeDB
          │  ├─ UnifiedBackend  — ClangBackend + SvfAnalyzer (共享 KnowledgeDB)
          │  └─ RegexBackend    — 正则回退
          │
          ├─→ 证据候选层 (DeterministicCandidateGenerator + Backend Signals + CandidateLedger)
          ├─→ 工具总线 (tools_runtime.py) ── 外部 MCP 集成
          │
          ▼
多智能体管线 (agents/ + skills/)
语义建模 Agent → [漏洞扫描 Agent ⇌ Deep Worker] → Issue Reconciler → 验证 Agent
          │
          ▼
报告生成 + 快照持久化 + Web 反馈闭环
```

## 数据安全与审计留痕
Z-Scope 内置了多层防丢失和可追溯机制：
1. **快照级持久化**：语义快照与单函数最终报告会写入 `.zscope_snapshots/snapshots.db`，`--resume` 和 `--maintain` 都以该库作为跳过、复用和调和依据。
2. **热备份轮转**：在汇总合并最终的 `zscope_batch_report.json` 前，旧版本 JSON 会自动加盖时间戳并归档至 `.zscope_knowledge/backups/` 目录。
3. **证据 IR 留痕**：确定性规则与后端信号产生的候选会将 source/sink、路径切片、资源/锁/共享状态事件写入 `code_knowledge.db` 的 IR 表，便于复查和回归分析。
4. **人工反馈复用**：Web 仪表盘中的验证状态会持久化为 `finding_suppressions` 与 `finding_baselines`。后续扫描会自动抑制已确认误报，并把历史反馈纳入评分。
5. **离线报告导出**：Web 前端可导出自包含 HTML 审计报告，用于脱离仪表盘查看和归档；该报告不依赖在线服务即可浏览。

## 依赖说明

### Python 依赖

| 包名 | 用途 |
|------|------|
| `openai>=1.0.0` | LLM 客户端（OpenAI 兼容 API） |
| `requests>=2.31.0` | HTTP 请求 |
| `cpgqls-client>=0.0.5` | Joern CPGQL WebSocket 客户端 |
| `click>=8.1.0` | CLI 框架 |
| `tqdm>=4.66.0` | 进度条 |
| `pyyaml>=6.0` | YAML 配置解析 |

开发依赖（可选）：`pytest`、`pytest-cov`、`black`、`mypy`。

类型检查依赖包含 `mypy>=1.5,<2.0`、`types-PyYAML` 和 `types-requests`；`mypy<2.0` 是为了兼容当前 `pyproject.toml` 中的 Python 3.9 类型检查目标。

### 外部工具依赖（按后端）

| 后端 | 必需工具 | 说明 |
|------|---------|------|
| `regex` | 无 | 纯正则，零外部依赖 |
| `joern` | Joern CLI + JDK 21 | 从 [Joern Releases](https://github.com/joernio/joern/releases) 下载 |
| `clang` | clangd >= 20.1 + compile_commands.json | clangd LSP 符号提取，无需 `pip install libclang` |
| `unified` | clangd >= 20.1 + (可选) clang-18 + gllvm + SVF 3.2 + LLVM | Clang AST + SVF 深度分析，SVF 不可用时优雅降级；clang-18 仅用于 SVF/gllvm bitcode 链路 |

## 安装指南

### 1. 安装 Z-SCOPE

```bash
git clone https://github.com/zealousness/Z-Scope.git
cd Z-Scope
python -m pip install -e .

# 含开发依赖
python -m pip install -e ".[dev]"
```

### 2. 安装后端依赖（按需选择）

**Regex 后端**（零依赖，开箱即用）：无需额外安装。

**Joern 后端**：

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
```

> **WSL 用户注意**: SVF 的 bitcode 构建（gclang + objcopy）在 NTFS 挂载路径 (`/mnt/c/...`) 上可能失败，Z-SCOPE 会自动重定向到 Linux 原生临时目录。详见 `.agents/workflows/wsl-pitfalls.md`。

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
    base_url: https://api.siliconflow.cn/v1
    models:
      - Qwen/Qwen3-Coder-30B-Instruct
    api_key: ${Z_SCOPE_API_KEY}

project:
  root: .                    # 被扫描项目根目录
  source_root: .             # 源码搜索根目录
  entry_function: main       # 单函数入口模式
  # entry_functions_list: functions.json  # 批量模式配置

  entry_discovery:           # 自动入口发现机制
    enabled: true            # 为 true 时，如果未提供 entry_functions_list 则自动发现
    max_candidates: 200
    max_functions: 10000
    # search_root: /absolute/path/to/module  # 可选：限制入口发现范围，必须是绝对目录

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
  backend: unified             # joern | clang | unified | regex
  clangd_path: clangd
  knowledge_db_path: .zscope_knowledge/code_knowledge.db
  # joern_path: dependency/joern/joern
  # svf_bin_dir: /path/to/svf/bin
  # gclang_path: gclang
  # get_bc_path: get-bc
  # llvm_link_path: llvm-link

analysis:
  max_recursion_depth: 3
  max_function_lines: 500
  max_tool_iterations: 50
  snapshot_dir: .zscope_snapshots
  enable_snapshot_cache: true
  user_config_db: ""          # 可填 .xlsx 或目录；为空时优先使用 {snapshot_dir}/user_config.xlsx，否则回退 user_config.db
  parallel_workers: 5
  max_premodel_depth: 3
  max_premodel_callees: 20
  trivial_function_max_lines: 5
  enable_subagent_workers: true
  max_subagent_tickets: 4  # Deep Worker 执行预算；候选点会全量保留并传给主 Agent
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

#### Deep Worker 预算与结果回收

`max_subagent_tickets` 只限制本轮实际执行的 Deep Worker 数量，不会丢弃超过预算的候选点。`SubAgentOrchestrator` 会先收集所有候选点，再按风险启发式排序选择预算内工单；未执行的候选点会作为 `subagent_unassigned_candidates` 传给主 `vulnerability_analyzer`，由主 Agent 继续纳入分析。

每个 Worker 报告都会带明确状态：`completed`、`failed`、`invalid`、`partial` 或 `killed`。其中 `invalid` 表示 Worker 返回了文本但没有合法 `worker_report` JSON；原始输出和 partial text 会保留给主 Agent，但不会被当作可靠证据。

#### 证据候选、评分与观察项

v0.6 的主路径是“候选先于结论”：本地确定性规则会先识别通用 C 缺陷形态，例如整数/边界错误、资源泄漏、`realloc` 误用、UAF、double/invalid free、栈逃逸、缺失解锁、回调持锁、条件变量误用、signed/unsigned 转换、空指针、共享状态竞态、格式串、命令注入、stale fd 和 stale mmap 指针。

Unified 后端中的 SVF/Saber 结果也会被转为同一类 `backend_signal` 候选。候选进入 `CandidateLedger` 去重后，会按激活 Skill 下发给 Deep Worker；即使超过 `max_subagent_tickets`，剩余候选也会作为上下文传回主 Agent。

Validator 启用时使用三态语义：`verified` 表示证据可闭合，`rejected` 表示被源码或用户配置否决，`uncertain` 表示值得人工复查但不应直接报告。Z-SCOPE 会计算 `final_score`；默认只有高分验证结果进入 `issues`，`needs_review` / `uncertain` 进入 `metadata.audit_observations`，退出码也只基于 `issues` 判断。若关闭 Validator，候选会以 `unvalidated` 状态进入报告，供人工后续复核。

#### Workflow 选择规则

Workflow 选择是运行时行为，不是 YAML 配置项。普通 `zscope -c zscope.yaml` 固定使用 `default.yaml`；传入 `--resume` 时 CLI 会把当前运行切换为 `resume.yaml`；传入 `--maintain` 时切换为 `maintain.yaml`。如果 `zscope.yaml` 中出现 `analysis.workflow_name`，配置加载会直接报错。

工作流文件定义的是运行时步骤，例如 `compare_hashes`、`reuse_unchanged`、`reconcile_changed`、`rescan_changed`。Analyzer 会按这些步骤推进 Agent 编排，并在最终报告的 `metadata.workflow_progress` 中记录当前 workflow 执行到了哪一步。

#### 用户配置工作簿与自动推断

`--infer-user-config` 会构建代码索引并生成或刷新一个可人工审阅的 `user_config.xlsx`，然后退出，不执行漏洞扫描。默认路径为 `{snapshot_dir}/user_config.xlsx`；如果 `analysis.user_config_db` 填的是 `.xlsx`，则使用该文件；如果填的是目录，则使用目录下的 `user_config.xlsx`。

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

```bash
# 默认模式：从 entry_function 开始分析
zscope -c zscope.yaml --verbose

# 批量扫描模式 (从 functions_list JSON 开始)：
zscope -c zscope.yaml

# 断点续扫：跳过已完成的函数，继续中断的批量扫描
zscope -c zscope.yaml --resume

# 增量维护：仅对代码有变化的函数重新检视，复用未变化函数的历史报告
# CLI 会自动选择 zscope/workflows/maintain.yaml
zscope -c zscope.yaml --maintain

# 自动发现入口点并扫描：基于启发式扫描项目网络收发、线程与 API 暴露点
# 发现结果会写入项目根目录 entry_functions_list.json
zscope -c zscope.yaml --discover-entries

# 推断/刷新人工可审阅的用户配置工作簿，然后退出
zscope -c zscope.yaml --infer-user-config

# 作为本地 MCP Server 运行（配合 Claude Desktop 等 MCP 客户端使用）
zscope -c zscope.yaml --mcp-stdio

# 规则驱动模式：Joern 内置规则扫描 + LLM 验证
zscope --mode ruledriven -c zscope.yaml

# 告警验证模式：导入外部工具的 SARIF 报告，LLM 二次确认
zscope --mode alert-verify --sarif cppcheck_results.sarif -c zscope.yaml

# 仅构建代码索引（预热，不执行分析）
zscope --build-cpg -c zscope.yaml
```

### Step 3：查看分析结果

分析完成后在项目根目录生成：

| 文件 | 说明 |
|------|------|
| `zscope_batch_report.md` | 人类可读的审计汇总报告 |
| `zscope_batch_report.json` | 结构化缺陷数据（可供 CI 集成），包含 `issues[]`、严重度分组和批量统计 |
| `zscope_alert_verify_report.json` | 告警验证模式的验证结果 |
| `entry_functions_list.json` | `--discover-entries` 生成的候选入口列表（仅启用入口发现时） |
| `.zscope_snapshots/` | 语义快照缓存（加速重复扫描） |
| `.zscope_snapshots/user_config.xlsx` | `--infer-user-config` 生成的人工可审阅用户配置工作簿 |
| `.zscope_knowledge/code_knowledge.db` | 代码索引、SVF/Saber 信号和候选证据 IR |

单函数最终报告的 `metadata` 会记录 `candidate_signal_summary`、`candidate_ledger_summary`、`audit_observation_count` 和 `audit_observations`。`issues[]` 中的缺陷会带 `finding_kind`、`final_score`、`score_components`、`source`、`sink`、`positive_evidence`、`negative_evidence` 等字段。

退出码：默认漏洞报告中的 `issues` 非空返回 `1`，无缺陷返回 `0`。`needs_review` / `uncertain` 观察项不会单独拉高退出码，适合 CI/CD 只阻断已验证或高分问题。

### Step 4：启动 Web 仪表盘（可选）

```bash
zscope --dashboard -c zscope.yaml
```

仪表盘提供三个主要页面：
- **扫描结果**：查看缺陷列表，支持六种验证状态标记，并将 `rejected` 反馈持久化为误报抑制和 baseline
- **配置管理**：管理外部函数描述、配对函数、函数指针指向、函数设计意图 + CPG 构建控制
- **配置告警**：展示工具怀疑缺少的配置信息，引导用户补充

## 分析工具清单（12 个内置 Agent 工具）

| # | 工具名 | 用途 | 后端要求 |
|---|--------|------|---------|
| 1 | `get_function_impl` | 获取函数完整源码 | 全部 |
| 2 | `get_function_snapshot` | 语义缓存复用 | 全部 |
| 3 | `list_known_functions` | 函数发现（正则搜索） | 全部 |
| 4 | `get_file_snippet` | 读取指定行范围的上下文代码 | 全部 |
| 5 | `get_callers` | 调用者查询（漏洞可达性分析） | joern/clang/unified |
| 6 | `get_type_info` | 结构体/类型定义查询 | joern/clang/unified |
| 7 | `get_call_graph` | 精确调用图（直接+间接） | joern/clang/unified |
| 8 | `get_data_flow` | 污点追踪 | joern/clang/unified |
| 9 | `find_function_pointers` | 回调/钩子发现 | joern/clang/unified |
| 10 | `query_pointer_alias` | 指针别名查询 | unified |
| 11 | `verify_taint_reachability` | 污点可达性验证 | unified |
| 12 | `get_deep_call_context` | 高聚合查询（调用者+被调用者+间接调用+污点缺陷） | unified |

MCP Server 会额外暴露 `query_knowledge`（只读查询 `code_knowledge.db`）与 `discover_entries`（入口发现）两个工具，供外部 MCP 客户端交互式审计使用。

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

| 特性 | regex | joern | clang | unified |
|------|-------|-------|-------|---------|
| 外部依赖 | 无 | JDK 21 + Joern | clangd >= 20.1 | clangd >= 20.1 + gllvm + SVF + LLVM |
| 函数源码提取 | 正则匹配 | CPGQL 精确 | AST 精确 | AST 精确 |
| 调用图 | 不支持 | 完整 CPG | 直接调用 | 直接 + 间接（SVF 指针分析） |
| 类型查询 | 不支持 | 完整 | AST 精确 | AST 精确 |
| 污点分析 | 不支持 | 数据流追踪 | 不支持 | SVF saber（内存泄漏/UAF/双重释放） |
| 间接调用解析 | 不支持 | 有限 | 不支持 | SVF Andersen 指针分析 |
| 后端信号入报告链路 | 不支持 | 规则驱动模式 | 不支持 | SVF/Saber 信号归一化为候选并进入证据 IR |
| 规则驱动模式 | 不支持 | 支持 | 不支持 | 不支持 |
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

# 仅评估确定性候选在 range benchmark 上的覆盖率
python scripts/evaluate_range_regression.py --deterministic-candidates
```

## 更新日志

### v0.6.0
- **证据优先候选流水线成型**：新增 `DeterministicCandidateGenerator`，以通用 C 语言模式生成带 `candidate_id`、`dedup_key`、source/sink、正反证据和 `evidence_pack` 的候选，覆盖整数/边界、资源生命周期、时序内存、栈逃逸、空指针、锁与共享状态、格式串、命令注入和 stale fd/mmap 等问题。
- **后端信号进入同一报告链路**：Unified 后端产生的 SVF/Saber/KnowledgeDB 信号会被规范化为 `backend_signal` 候选，与本地规则和 LLM finding 一起进入 CandidateLedger、Deep Worker、Validator、去重和报告输出。
- **KnowledgeDB schema v7 与 Inspection IR**：`code_knowledge.db` 新增 `ir_statements`、`ir_resource_events`、`ir_lock_events`、`ir_shared_accesses`、`ir_path_slices` 和 `function_contracts`，用于保存候选证据、路径切片、资源/锁/共享状态事件及评分组件。
- **三态验证与评分分层**：Validator 支持 `verified` / `rejected` / `uncertain`，Analyzer 计算 `final_score` 与 `score_components`。高分结果进入 `issues`；`needs_review`、`uncertain` 和验证失败的候选进入 `metadata.audit_observations`，默认不触发 CI 失败。
- **人工反馈闭环落地**：`UserConfigStore` 新增 `finding_suppressions` 与 `finding_baselines`。Web 仪表盘支持六种验证状态，并会把 `rejected` 写成误报抑制，把 `validated` / `needs_review` / `uncertain` 写成 baseline，后续扫描自动过滤或调整评分。
- **用户配置工作簿与推断链路**：移除批量 `prompt_autofill` 流程，新增 `user_config.xlsx`、`UserConfigWorkbook` 和 `--infer-user-config`。系统可推断 resource/lock API、多对多配对、dispatcher 分支、module lifecycle、pointer target 与 function intent，并在扫描时只注入相关配置片段。
- **入口发现结果落盘**：`--discover-entries` 会把候选入口、exposure、reasons、confidence 和审计提示写入项目根目录 `entry_functions_list.json`；`entry_discovery.search_root` 可把发现范围限制到指定绝对目录。
- **Range benchmark 回归体系扩展到 v6**：`test/range` 新增全局容器注册生命周期、scheduler/pipe 复合并发失败、嵌套 child-list 清理、AVL key 截断/陈旧节点和宏门控锁场景，总漏洞数提升到 45 个，并由 pytest 回归用例约束确定性候选覆盖率。
- **索引与构建鲁棒性补强**：Clang/regex 函数识别支持更多 C 声明修饰；`CodeIndex.get_function_impl()` 会附带声明/实现前导注释块，帮助 Agent 看到头文件契约；SVF bitcode 构建自动注入兼容 flag；Deep Worker 会接收结构化 evidence，Validator 输出兼容旧 `is_valid` 与新 `verdict` 格式。

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
