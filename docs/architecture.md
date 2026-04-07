# Z-SCOPE 架构文档

## 1. 概述

Z-SCOPE 是一款基于多智能体协作的 C 语言深度静态分析工具。核心思路是将 **可插拔代码分析后端**（Clang/Joern/SVF）的精确解析能力与 **LLM Agent 的语义理解能力** 结合，针对内存安全、资源泄漏、逻辑缺陷和并发问题进行高召回率、低误报率的代码审计。

### 关注的缺陷类型

| 大类 | 子类 |
|------|------|
| 内存安全 | 缓冲区越界、Use-After-Free、双重释放、空指针解引用 |
| 资源管理 | 内存泄漏、文件描述符泄漏、锁未释放 |
| 逻辑缺陷 | 整数溢出、类型混淆、错误返回值处理 |
| 并发安全 | 数据竞争、死锁、时序问题 |

### 设计约束

- 运行环境内存 16GB，被扫描项目约 100 万行 C 代码
- 项目分 500+ 模块，按模块独立扫描
- LLM 使用 OpenAI 兼容 API，支持 Ollama、SiliconFlow 等本地/云端提供商
- **LLM 上下文感知**：每轮工具调用迭代实时估算并汇报当前上下文 Token 占用

## 2. 整体架构

```
┌──────────────────────────────────────────────────────────────┐
│                        CLI 入口层                             │
│  zscope -c zscope.yaml                                       │
│    [--resume] [--maintain] [--dashboard] [--build-cpg]       │
│    [--mode default|ruledriven|alert-verify] [--sarif *.sarif]│
└──────┬─────────┬──────────┬──────────┬───────────────────────┘
       │         │          │          │
  ┌────▼────┐ ┌──▼───┐ ┌───▼────┐ ┌───▼──────┐
  │ 默认 /  │ │规则  │ │ Alert  │ │Dashboard │
  │ 批量模式│ │驱动  │ │ Verify │ │ WebUI    │
  │analyzer │ │mode  │ │ mode   │ │ server   │
  └────┬────┘ └──┬───┘ └───┬────┘ └──────────┘
       │         │         │
  ┌────▼─────────▼─────────▼───────────────────┐
  │        多智能体系统 (agents/)                │
  │ ┌──────────┐ ┌──────────┐ ┌────────────┐   │
  │ │ 语义建模 │→│ 漏洞挖掘 │→│  验证Agent  │  │
  │ │  Agent   │ │  Agent   │ │            │   │
  │ └────┬─────┘ └────┬─────┘ └─────┬──────┘   │
  │      │    ┌───────┐│    ┌───────┐│          │
  │      │    │ 问题  ││    │ deep  ││          │
  │      │    │ 调和  ││    │ worker││          │
  │      │    │ Agent ││    │(预留) ││          │
  │      │    └───────┘│    └───────┘│          │
  └──────┼─────────────┼────────────┼──────────┘
         │             │            │
  ┌──────▼─────────────▼────────────▼──────────┐
  │         工具总线 (tools_runtime.py)          │
  │  代码检索 · 快照查询 · 调用图 · 类型信息     │
  │  文件切片 · 数据流 · 污点追踪(预留)          │
  │  + 用户配置自动注入                          │
  └──────┬─────────────┬────────────┬──────────┘
         │             │            │
  ┌──────▼────┐ ┌──────▼───┐ ┌─────▼─────────┐
  │ CodeIndex │ │ Snapshot │ │ UserConfig    │
  │ 可插拔    │ │ Store    │ │ Store         │
  │ 后端      │ │ SQLite   │ │ SQLite WAL    │
  └──────┬────┘ └──────────┘ └───────────────┘
         │
  ┌──────▼──────────────────────────────────────┐
  │      CodeBackend ABC (backend_base.py)      │
  │  ┌────────┐ ┌───────┐ ┌─────────┐ ┌──────┐ │
  │  │ Joern  │ │ Clang │ │ Unified │ │ Regex│ │
  │  └────┬───┘ └───┬───┘ └────┬────┘ └──────┘ │
  └───────┼─────────┼──────────┼────────────────┘
          │         │          │
     CPGQL WS   KnowledgeDB(SQLite)
                libclang  ClangBackend+SvfAnalyzer
```

## 3. CLI 命令行设计

### 3.1 扫描模式

| 命令 | 说明 |
|------|------|
| `zscope -c zscope.yaml` | **默认全新扫描**：对所有入口函数执行完整的多智能体分析 |
| `zscope -c zscope.yaml --resume` | **断点续扫**：自动跳过已完成的函数，重扫失败/未完成的函数 |
| `zscope -c zscope.yaml --maintain` | **增量维护扫描**：基于函数级源码哈希，跳过未变动的函数（零 Token 消耗） |
| `zscope -c zscope.yaml --mode ruledriven` | **规则驱动模式**：Joern 规则先扫 → LLM 验证过滤误报 |
| `zscope -c zscope.yaml --mode alert-verify --sarif alerts.sarif` | **告警验证模式**：对外部工具（如 Coverity/Cppcheck）的 SARIF 输出进行 LLM 二次确认 |
| `zscope -c zscope.yaml --dashboard` | **启动 Web 仪表盘**：查看扫描结果、管理用户配置 |
| `zscope -c zscope.yaml --build-cpg` | **仅构建索引**：构建代码索引后退出，不执行分析 |

> `--resume` 和 `--maintain` 互斥，不可同时使用。

### 3.2 `--resume` 断点续扫逻辑

```
遍历全部入口函数：
  ├─ 有 final_report 且 verdict ≠ error 且无 pending issues → 【跳过】
  ├─ 有 final_report 但 verdict = error → 【重扫】
  ├─ 有 final_report 但存在 pending issues   → 【重扫】
  └─ 无 final_report                         → 【重扫】

扫描结束后，跳过的函数从 SQLite 快照库拉取历史报告，与本次结果合并为完整报告。
```

### 3.3 `--maintain` 增量维护逻辑

```
对每个入口函数：
  源码哈希未变 且 有历史报告 → 直接复用历史报告（0 Token 消耗）
  源码哈希已变 → 全量重扫 + Issue Reconciler 对历史缺陷做修复验证
```

## 4. 多智能体系统

五个 Agent 各司其职，通过工具总线访问代码信息：

| Agent | 目录 | 职责 | 输入 | 输出 |
|-------|------|------|------|------|
| 语义建模 Agent | `agents/semantic_modeler/` | 理解函数语义、识别关键路径和副作用 | 函数源码 + 工具 | 语义快照 JSON |
| 漏洞挖掘 Agent | `agents/vulnerability_analyzer/` | 基于语义模型和代码上下文发现潜在缺陷 | 语义模型 + 代码上下文 + 工具 | 疑似缺陷列表 |
| 验证 Agent | `agents/validator_agent/` | 二次确认疑似缺陷的真实性，过滤误报 | 疑似缺陷 + 源码 | validated / rejected |
| Issue Reconciler | `agents/issue_reconciler/` | 代码变动后验证历史缺陷是否仍然存在；去重新旧缺陷 | 历史缺陷 + 新代码 | still_exists / fixed |
| Deep Worker（预留） | `agents/deep_worker/` | 接收 Manager 下发的聚焦工单，做深层定向分析 | DFG 切片 + Hypothesis | Worker 报告 |

### 4.1 分析管线流程

```
入口函数源码
    │
    ▼
[语义建模 Agent] → 输出语义快照 → 存入 SnapshotStore
    │
    ▼
[漏洞挖掘 Agent] → 输出疑似缺陷列表
    │                  │
    │    ┌─────────────▼──────────────┐
    │    │  Issue Reconciler Agent    │
    │    │  (去重 + 历史缺陷调和)      │
    │    └─────────────┬──────────────┘
    │                  │
    ▼                  ▼
[验证 Agent] → validated / rejected
    │
    ▼
Final Report (JSON + Markdown)
    │
    ▼
SnapshotStore 持久化（断电安全）
```

### 4.2 关键机制说明

> **绝对行号注入法**：工具总线在构造"函数源码"和"代码上下文"时，自动注入绝对行号前缀（例如 `142 |     int a = 0;`）。Agent 仅需直接读取前缀即可输出高精度的 `file:line` 物理坐标，根治模型基于扁平 Token 难以计算偏移量的"定位幻觉"问题。

> **XML Tool-Calls 兜底**：针对国内代理模型（如 Minimax、早期 GLM）无法返回 OpenAI 标准 JSON 工具格式、转而在正文输出 `<invoke name="xxx">` XML 的特征，LLM 客户端拦截并强行进行了正则替换重排，确保国产模型向下兼容。

> **上下文 Token 监控**：`LLMClient.run_conversation_with_tools()` 在每轮工具调用迭代时实时估算并日志输出当前上下文大小（`context ≈ N tokens`），对话结束后汇报最终 Token 消耗。批量扫描时每个 Worker 完成后打印其峰值 Token 占用，最终报告汇总全局 Token 消耗总量。

> **无阻塞并发中断与断点续传**：大并发扫描遇到超长深思模型导致挂起时，`Ctrl+C` 触发 `ThreadPoolExecutor.shutdown(wait=False)` 无条件瞬间销毁线程池，输出全部已完成报告。下次通过 `--resume` 可无缝衔接。

> **Validator 拒绝策略**：Validator Agent 判定为 `rejected` 的缺陷立即丢弃，不写入最终报告。用户通过 Web Dashboard 手动拒绝的缺陷标记 `rejection_source: "user"`，由 Issue Reconciler 在后续扫描中自动抑制同类缺陷。

## 5. 用户配置与上下文注入

### 5.1 设计原则

**上下文注入而非 Agent 查询** — 用户配置不暴露为 LLM 工具，而是在两个时机自动注入：

1. **工具返回时**：`tools_runtime.py` 调用 `get_function_impl` 找不到实现时，自动查询 `UserConfigStore` 并附加外部函数描述
2. **Agent prompt 构建时**：`analyzer.py` 将配对函数列表和函数设计意图注入 Agent 的 system prompt

### 5.2 UserConfigStore（6 张表）

```
┌─────────────────────────────────────────┐
│         user_config.db (SQLite WAL)     │
├─────────────────────────────────────────┤
│ external_functions     外部库函数描述    │
│ paired_functions       配对函数          │
│ function_pointer_targets 函数指针指向   │
│ function_intent        函数设计意图      │
│ false_positives        已确认误报        │
│ config_warnings        缺失配置告警      │
└─────────────────────────────────────────┘
```

### 5.3 误报反馈闭环

```
用户在 WebUI 标记误报 → false_positives 表写入 (function, location, subcategory)
                      → 下次扫描时 analyzer 自动过滤匹配项
```

### 5.4 配置告警

当 `tools_runtime.py` 遇到未知外部函数（既无源码也无用户描述）时，自动写入 `config_warnings` 表，WebUI 展示给用户引导补充。

## 6. 代码索引引擎

### 6.1 路径过滤

`zscope.yaml` 中的 `include_paths` 和 `exclude_paths` 配置项控制源码扫描范围：

```yaml
source_root: /usr1/prj
include_paths:
  - src
  - platform
  - tools
exclude_paths:
  - src/test
```

- 相对路径基于 `source_root` 解析为绝对路径
- 使用目录边界感知的 `is_subpath` 判定（`src` 不会误匹配 `src_util`）
- 使用 `.absolute()` 而非 `.resolve()` 保护符号链接的逻辑路径结构
- `include_paths` 和 `exclude_paths` 支持写在 YAML 顶层或 `project:` 节点内

### 6.2 CodeIndex 可插拔后端

`retrieval/code_index.py` 提供统一的代码查询接口，通过 `indexing.backend` 配置选择后端：

| 后端 | 实现 | 适用场景 |
|------|------|---------||
| `clang` | ClangBackend — libclang → KnowledgeDB | **推荐**。精确 AST 解析，无需 JVM |
| `joern` | JoernBackend — CPGQL WebSocket | 完整 CPG 查询，规则驱动模式 |
| `unified` | UnifiedBackend — ClangBackend + SvfAnalyzer | Clang AST + SVF 间接调用/污点分析 |
| `regex` | RegexBackend — 正则扫描源文件 | 轻量回退，无外部依赖 |

所有后端实现 `CodeBackend` ABC（`retrieval/backend_base.py`），提供统一的 `get_callers`、`get_callees`、`get_type_info`、`get_data_flow` 等方法。

### 6.3 SVF 深度分析管线（unified 模式）

```
UnifiedBackend.initialize()
    │
    ├─ 阶段1: ClangBackend → KnowledgeDB (functions, call_edges, types)
    │
    └─ 阶段2: SvfAnalyzer (共享同一个 KnowledgeDB)
         │
         compile_commands.json
             │  BitcodeBuilder (build_llvm.py)
             ▼
         gclang -g -O0 编译 → get-bc 提取 → llvm-link 合并
             │
             ▼  merged.bc
         SvfRunner (svf_runner.py)
             ├─ wpa -ander → callgraph_final.dot
             └─ saber -leak -uaf -dfree
             │
             ▼  SvfOutputMapper (svf_parser.py) — 坐标缝合
         KnowledgeDB
             ├─ indirect_calls 表 (caller, callee, call_file, call_line)
             └─ taint_signatures 表 (bug_type, file, line)
```

坐标缝合原理：Clang AST 与 LLVM IR DWARF 在 `-g -O0` 下共享 `(file_path, line)` 坐标系。`SvfOutputMapper` 通过 `db.get_function(caller)` 查询 Clang 已入库的函数位置，将 SVF 结果关联回源码。

## 7. LLM 客户端

`framework/llm_client.py` 实现 OpenAI 兼容的 LLM 通信层：

### 7.1 核心特性

| 特性 | 说明 |
|------|------|
| 模型优先级回退 | `models: [model_a, model_b]`，model_a 失败自动切换 model_b |
| 流式传输 | 强制 `stream=True` 绕过中间代理超时（如 504 on 120s limit） |
| 指数退避 | 429/5xx 错误自动 `2^n + jitter` 退避重试 |
| 工具调用循环 | `run_conversation_with_tools()` 自动迭代工具调用直到模型输出最终报告 |
| 上下文 Token 估算 | `estimate_tokens()` 在每轮迭代实时估算上下文大小 |
| JSON 修复 | 多级 fallback 修复畸形 JSON 工具参数（`literal_eval` → 正则 → 启发式） |
| XML 回退 | 拦截非标准 `<invoke>` XML 工具调用并转换为 JSON 格式 |
| 自动续写 | `finish_reason=length` 时自动发送 "请继续" 消息 |

### 7.2 Token 监控数据流

```
LLMClient.run_conversation_with_tools()
    │ 每轮迭代: logger.info("context ≈ N tokens")
    │ 对话结束: logger.info("final context ≈ N tokens")
    ▼
VulnerabilityAnalyzer.run()
    │ AgentResponse.metadata["context_tokens"]
    ▼
Analyzer.run()
    │ final_report.metadata["context_tokens"]
    ▼
ParallelAnalyzer._analyze_single_entry()
    │ ParallelAnalysisResult.context_tokens
    │ logger.info("[3/100] func: issues_found (2 issues, ctx ≈ 18,332 tokens)")
    ▼
Combined Batch Report
    └─ summary.total_context_tokens
```

## 8. Web 仪表盘

`web/server.py` 提供 HTTP REST API，`web/static/index.html` 为 Alpine.js + DaisyUI 单页应用。

### 8.1 API 端点

| 方法 | 路径 | 功能 |
|------|------|------|
| GET | `/api/cpg_status` | 查询 CPG 构建状态 |
| POST | `/api/build_cpg` | 触发异步 CPG 构建 |
| GET | `/api/report` | 获取扫描报告 |
| POST | `/api/mark_false_positive` | 标记误报 |
| GET | `/api/false_positives` | 列出已标记误报 |
| GET/POST/DELETE | `/api/user_config/<resource>` | 用户配置 CRUD |
| GET | `/api/user_config/warnings` | 获取配置告警 |

### 8.2 前端页面结构

```
仪表盘
├── 扫描结果 Tab
│   ├── 缺陷列表（按严重度排序）
│   ├── 缺陷详情（代码片段 + 验证状态）
│   └── 误报标记按钮（附原因输入）
├── 配置管理 Tab
│   ├── 外部函数描述
│   ├── 配对函数
│   ├── 函数指针指向
│   ├── 函数设计意图
│   └── CPG 管理（状态 + 构建触发）
└── 配置告警 Tab
    └── 缺失配置列表（引导用户补充）
```

## 9. 目录结构

```
Z-Scope/
├── pyproject.toml              # Python 打包配置
├── setup.py                    # setuptools 入口
├── README.md                   # 项目文档
├── zscope.yaml                 # 项目分析配置
│
├── zscope/                     # Python 包根目录
│   ├── __init__.py
│   ├── cli/
│   │   └── cli.py              # CLI 入口，参数解析与模式分发
│   ├── agents/
│   │   ├── semantic_modeler/   # 语义建模 Agent
│   │   ├── vulnerability_analyzer/ # 漏洞挖掘 Agent
│   │   ├── validator_agent/    # 验证 Agent
│   │   ├── issue_reconciler/   # 缺陷调和 Agent（去重 + 修复验证）
│   │   └── deep_worker/        # 深度工单 Agent（预留）
│   ├── core/
│   │   ├── analyzer.py         # 默认模式编排器（单函数 + 批量）
│   │   ├── parallel_analyzer.py# 多线程并行分析 + 报告生成
│   │   ├── rule_engine.py      # Joern 规则引擎
│   │   ├── rule_driven_analyzer.py # 规则驱动模式编排器
│   │   ├── alert_verifier.py   # SARIF 告警验证器
│   │   ├── sarif_adapter.py    # SARIF 格式解析适配器
│   │   ├── tools_runtime.py    # 工具总线 + 上下文注入
│   │   ├── snapshot_store.py   # 语义快照/报告持久化（SQLite）
│   │   └── report.py           # 报告生成（JSON + Markdown）
│   ├── retrieval/
│   │   ├── backend_base.py     # CodeBackend ABC + 数据类
│   │   ├── code_index.py       # 统一查询接口（工厂方法选后端 + 路径过滤）
│   │   ├── joern_backend.py    # Joern CPGQL 后端
│   │   ├── clang_backend.py    # Clang libclang → KnowledgeDB
│   │   ├── clang_extractor.py  # Clang AST 提取引擎
│   │   ├── unified_backend.py  # Unified Facade（Clang + SVF 共享 DB）
│   │   ├── svf_analyzer.py     # SVF 分析器（非 CodeBackend，接受外部 DB）
│   │   ├── knowledge_db.py     # SQLite schema（含 indirect_calls/taint_signatures）
│   │   ├── build_llvm.py       # gllvm BitcodeBuilder
│   │   ├── svf_runner.py       # SVF 执行引擎
│   │   └── svf_parser.py       # DOT 解析 + 结果导入
│   ├── common/
│   │   ├── joern_client.py     # Joern 服务管理 + CPGQL 查询
│   │   └── utils.py            # 共用工具函数（JSON 提取、日志配置等）
│   ├── config/
│   │   ├── config.py           # YAML 配置加载（含 include/exclude 路径解析）
│   │   ├── function_entry.py   # 批量函数入口加载器
│   │   └── user_config_store.py# 用户配置 SQLite 存储
│   ├── framework/
│   │   ├── base.py             # BaseAgent / BaseTool ABC
│   │   └── llm_client.py       # LLM 客户端（OpenAI 兼容 + Token 监控）
│   ├── tools/
│   │   ├── code_retrieval.py   # GetFunctionImplTool
│   │   ├── snapshot_tool.py    # GetFunctionSnapshotTool
│   │   ├── taint_tool.py       # FollowTaintTool（预留，DFG 切片追踪）
│   │   └── utils.py            # ListFunctions, GetFileSnippet, GetCallers 等
│   └── web/
│       ├── server.py           # HTTP REST API
│       └── static/index.html   # 前端单页应用
│
├── docs/                       # 项目文档
├── scripts/                    # 辅助脚本
├── test/                       # 测试用例
└── dependency/                 # 外部依赖
```

## 10. 数据流总览

```
zscope.yaml ──→ ConfigLoader.load()
                  │
                  ├─→ include_paths / exclude_paths 路径解析
                  │
                  ├─→ CodeIndex 初始化（含路径过滤）
                  │
                  ├─→ UserConfigStore 加载
                  │
                  └─→ CLI 模式分发
                        │
          ┌─────────────┼─────────────┬──────────────┐
          ▼             ▼             ▼              ▼
       默认模式    规则驱动模式   Alert-Verify   Dashboard
          │             │             │
          ▼             ▼             ▼
     Agent 管线    规则引擎→验证   SARIF→验证
          │             │             │
          ▼             ▼             ▼
     Issue Reconciler（去重 + 调和历史缺陷）
          │
          ▼
     Validator Agent（confirmed / rejected）
          │
          ▼
     误报过滤（UserConfigStore）
          │
          ▼
     报告生成（MD + JSON）
          │
          ▼
     SnapshotStore 持久化（支持 --resume / --maintain）
```

## 11. 技术栈

| 组件 | 技术选型 |
|------|---------||
| 语言 | Python 3.9+ |
| 代码分析后端 | Clang (libclang) / Joern (CPGQL via WebSocket) / SVF (wpa + saber) |
| LLM 接口 | OpenAI 兼容 API（Function Calling + Streaming） |
| 数据存储 | SQLite (WAL mode) + JSON |
| 前端 | Alpine.js + DaisyUI + Tailwind CSS |
| 配置 | YAML（支持 `${ENV_VAR}` 展开） |
| 打包 | setuptools + pyproject.toml |
| 格式化 | black (100 字符行宽) |
| 类型检查 | mypy |
| 测试 | pytest |

## 12. 持久化数据库详解

Z-SCOPE 在工作过程中产生三个 SQLite 数据库文件，全部使用 WAL 模式以保证并发安全和断电恢复。

```
<project_root>/
└── .zscope_knowledge/
    ├── code_knowledge.db     ← 代码结构知识图谱（Clang/Joern 提取）
    └── .zscope_snapshots/
        ├── snapshots.db      ← 语义快照 + 漏洞报告索引
        ├── user_config.db    ← 用户自定义分析配置
        ├── func_name_*.json  ← 语义快照 JSON 文件
        └── func_name_*_final.json ← 最终漏洞报告 JSON 文件
```

---

### 12.1 code_knowledge.db — 代码结构知识图谱

由 `ClangBackend` / `JoernBackend` 在索引阶段填充，存储从源码中提取的全部结构化信息。

| 表名 | 用途 | 关键字段 |
|------|------|----------|
| `translation_units` | 编译单元注册表（每个 .c 文件一行） | `file_path`, `status`(pending/indexed), `file_hash` |
| `functions` | 函数定义/声明索引 | `name`, `file_path`, `start_line`, `end_line`, `signature`, `is_static`, `is_declaration` |
| `type_definitions` | struct/union/enum/typedef 定义 | `name`, `kind`, `file_path`, `full_definition` |
| `type_members` | 结构体成员列表 | `type_id`→type_definitions, `member_name`, `member_type` |
| `call_edges` | 直接函数调用关系图 | `caller_name`, `callee_name`, `caller_file`, `call_line`, `call_type` |
| `macro_definitions` | 宏定义 | `name`, `file_path`, `line`, `definition`, `is_function_like` |
| `global_variables` | 全局变量 | `name`, `type_str`, `file_path`, `is_extern` |
| `include_edges` | 头文件包含关系 | `source_file`, `included_file`, `is_system` |
| `indirect_calls` | 间接调用关系（SVF 分析产出） | `caller_name`, `callee_name`, `source`(svf-ander), `confidence` |
| `taint_signatures` | 污点缺陷签名（SVF/Saber 产出） | `bug_type`(leak/uaf/dfree), `file_path`, `line`, `source_func`, `sink_func` |
| `metadata` | 元数据（schema 版本、SVF 哈希缓存等） | `key`, `value` |

**查询示例**：

```bash
# 打开数据库
sqlite3 .zscope_knowledge/code_knowledge.db

# 查看索引统计
SELECT 'functions' as tbl, COUNT(*) FROM functions
UNION ALL SELECT 'call_edges', COUNT(*) FROM call_edges
UNION ALL SELECT 'types', COUNT(*) FROM type_definitions;

# 查看某函数的签名和位置
SELECT name, file_path, start_line, end_line, signature
FROM functions WHERE name = 'cache_get' AND is_declaration = 0;

# 查看某函数调用了哪些子函数
SELECT callee_name, call_line FROM call_edges WHERE caller_name = 'cache_get';

# 查看谁调用了某函数
SELECT caller_name, caller_file, call_line FROM call_edges WHERE callee_name = 'cache_get';

# 查看某个 struct 的成员定义
SELECT td.name, td.full_definition, tm.member_name, tm.member_type
FROM type_definitions td
JOIN type_members tm ON tm.type_id = td.id
WHERE td.name = 'cache_node';

# 查看 SVF 发现的所有内存泄漏
SELECT bug_type, file_path, line, source_func, sink_func
FROM taint_signatures WHERE bug_type LIKE '%leak%';

# 查看 SVF 发现的间接调用（函数指针解析结果）
SELECT caller_name, callee_name, confidence FROM indirect_calls ORDER BY confidence DESC;

# 查看还有多少文件没完成提取
SELECT COUNT(*) FROM translation_units WHERE status = 'pending';
```

---

### 12.2 snapshots.db — 语义快照与漏洞报告索引

由 `SnapshotStore` 在分析阶段填充，是 `--resume` 和 `--maintain` 模式的核心数据源。

**表结构**：`snapshots`（唯一的表）

| 字段 | 类型 | 说明 |
|------|------|------|
| `func_name` | TEXT (PK) | 函数名 |
| `file_path` | TEXT (PK) | 函数所在文件路径（与 func_name 组成复合主键） |
| `code_hash` | TEXT | 函数源码的 SHA256 哈希（精确匹配） |
| `semantic_hash` | TEXT | 去除注释/空白后的语义指纹（区分"代码真改了"还是"只改了注释"） |
| `location` | TEXT | 函数位置 `file:start_line-end_line` |
| `timestamp` | DATETIME | 最后更新时间 |
| `snapshot_file` | TEXT | 对应的语义快照 JSON 文件名 |
| `final_report_file` | TEXT | 对应的最终漏洞报告 JSON 文件名（可为 NULL） |

**工作原理**：

- **语义快照**（`*_snapshot.json`）：由 Semantic Modeler Agent 产出，记录函数的语义摘要（副作用、数据流、状态转换等）。供其他 Agent 作为"子函数速查表"使用，避免拉取完整源码撑爆上下文。
- **最终报告**（`*_final.json`）：由完整分析管线产出，包含 `overall_verdict`、`issues[]`（每个 issue 含 `validation_status`）、`notes` 和 `metadata`。是 `--resume` 模式判断是否跳过该函数的唯一依据。

**查询示例**：

```bash
sqlite3 .zscope_snapshots/snapshots.db

# 查看所有已分析的函数
SELECT func_name, file_path, timestamp, final_report_file FROM snapshots ORDER BY timestamp DESC;

# 查看哪些函数有最终报告
SELECT func_name, file_path FROM snapshots WHERE final_report_file IS NOT NULL;

# 查看哪些函数还没跑完（只有快照没有报告）
SELECT func_name, file_path FROM snapshots WHERE final_report_file IS NULL;

# 查看某函数的源码哈希（用于判断是否需要重扫）
SELECT func_name, code_hash, semantic_hash FROM snapshots WHERE func_name = 'cache_get';

# 删除某函数的结果（下次 --resume 时会重新扫描）
DELETE FROM snapshots WHERE func_name = 'cache_get';
```

**直接读取 JSON 报告**：

```bash
# 查看某函数的最终漏洞报告
cat .zscope_snapshots/cache_get_path_to_file_c_final.json | python -m json.tool

# 查看报告中的缺陷列表
python -c "
import json
with open('.zscope_snapshots/cache_get_path_to_file_c_final.json') as f:
    report = json.load(f)
print(f'Verdict: {report[\"overall_verdict\"]}')
for issue in report.get('issues', []):
    print(f'  [{issue[\"impact_level\"]}] {issue[\"id\"]}: {issue[\"description\"]}')
"
```

---

### 12.3 user_config.db — 用户自定义分析配置

由用户通过 Web Dashboard 或 API 主动填写，用于向 Agent 注入领域知识。

| 表名 | 用途 | 关键字段 |
|------|------|----------|
| `external_functions` | 外部库函数描述（如 `pthread_mutex_lock`） | `func_name`(PK), `library`, `description`, `memory_behavior`(JSON), `concurrency_behavior`(JSON), `return_semantics` |
| `paired_functions` | 配对资源管理函数（如 malloc↔free） | `category`, `acquire_func`, `release_func`, `description` |
| `function_pointer_targets` | 函数指针可能指向的目标函数列表 | `pointer_location`, `scope`, `target_functions`(JSON数组), `context` |
| `function_intent` | 函数设计意图和并发约束 | `func_name`+`file_path`(复合PK), `caller_constraints`(JSON), `concurrency_group`, `concurrent_with`(JSON数组), `notes` |
| `config_warnings` | 配置缺失告警（系统自动生成） | `warning_type`, `context`, `message` |

**查询示例**：

```bash
sqlite3 .zscope_snapshots/user_config.db

# 查看所有已配置的外部函数描述
SELECT func_name, library, description FROM external_functions;

# 查看配对函数（资源泄漏检测依据）
SELECT category, acquire_func, release_func, description FROM paired_functions;

# 查看函数指针映射
SELECT pointer_location, target_functions FROM function_pointer_targets;

# 查看未处理的配置告警（哪些外部函数缺少描述）
SELECT warning_type, context, message FROM config_warnings ORDER BY created_at DESC;

# 查看某函数的并发约束配置
SELECT func_name, concurrency_group, concurrent_with, notes
FROM function_intent WHERE func_name = 'process_request';
```

---

### 12.4 通用技巧

```bash
# 以表格模式查看任意数据库
sqlite3 -header -column <database.db>

# 查看数据库中所有的表
.tables

# 查看某张表的表结构
.schema functions

# 导出为 CSV
.mode csv
.output functions.csv
SELECT * FROM functions WHERE is_declaration = 0;
.output stdout

# Python 一行脚本快速浏览
python -c "
import sqlite3, json
conn = sqlite3.connect('.zscope_knowledge/code_knowledge.db')
conn.row_factory = sqlite3.Row
for r in conn.execute('SELECT * FROM functions LIMIT 5'):
    print(dict(r))
"
```

