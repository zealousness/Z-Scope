# Z-SCOPE 架构文档

## 1. 概述

Z-SCOPE 是一款基于多智能体协作的 C 语言深度静态分析工具。核心思路是将 **Joern CPG 的图查询能力** 与 **LLM Agent 的语义理解能力** 结合，针对内存安全和并发缺陷进行高召回率、低误报率的代码检视。

### 关注的缺陷类型

| 大类 | 子类 |
|------|------|
| 内存类 | 内存泄漏、Use-After-Free、双重释放、空指针解引用、缓冲区越界 |
| 并发类 | 数据竞争、死锁、时序问题 |

### 设计约束

- 运行环境内存 16GB，被扫描项目约 100 万行 C 代码
- 项目分 500+ 模块，按模块独立扫描
- LLM 使用 OpenAI 兼容 API，支持 Ollama、SiliconFlow 等本地/云端提供商

## 2. 整体架构

```
┌─────────────────────────────────────────────────────────┐
│                      CLI 入口层                          │
│  cli.py  --mode default|topdown|ruledriven              │
│          --build-cpg  --dashboard  --verbose             │
└──────────┬──────────────┬───────────────┬───────────────┘
           │              │               │
     ┌─────▼─────┐ ┌─────▼──────┐ ┌──────▼──────┐
     │  默认模式  │ │ 自上而下   │ │ 规则驱动    │
     │ analyzer   │ │ parallel_  │ │ rule_driven │
     │   .py      │ │ analyzer   │ │ _analyzer   │
     └─────┬──────┘ └─────┬──────┘ └──────┬──────┘
           │              │               │
     ┌─────▼──────────────▼───────────────▼──────┐
     │           多智能体系统 (agents/)            │
     │  ┌──────────┐ ┌──────────┐ ┌────────────┐ │
     │  │ 语义建模 │→│ 漏洞扫描 │→│  验证Agent  │ │
     │  │  Agent   │ │  Agent   │ │            │ │
     │  └────┬─────┘ └────┬─────┘ └─────┬──────┘ │
     └───────┼────────────┼─────────────┼────────┘
             │            │             │
     ┌───────▼────────────▼─────────────▼────────┐
     │          工具总线 (tools_runtime.py)        │
     │  11 个分析工具 + 1 个高聚合查询 + 用户配置自动注入  │
     └───────┬────────────┬─────────────┬────────┘
             │            │             │
     ┌───────▼───┐ ┌──────▼───┐ ┌──────▼────────┐
     │ CodeIndex │ │ Snapshot │ │ UserConfig    │
     │ 可插拔   │ │ Store    │ │ Store         │
     │ 后端     │ │ SQLite   │ │ SQLite WAL    │
     └───────┬───┘ └──────────┘ └───────────────┘
             │
     ┌───────▼──────────────────────────────────┐
     │     CodeBackend ABC (backend_base.py)    │
     │  ┌────────┐ ┌───────┐ ┌─────────┐ ┌───────┐ │
     │  │ Joern  │ │ Clang │ │ Unified │ │ Regex │ │
     │  └────┬───┘ └───┬───┘ └────┬────┘ └───────┘ │
     └───────┼─────────┼──────────┼────────────────┘
             │         │          │
        CPGQL WS   KnowledgeDB(SQLite)
                   libclang  ClangBackend+SvfAnalyzer
```

## 3. 三种分析模式

### 3.1 默认模式 (`--mode default`)

从 `zscope.yaml` 中指定的 `entry_function` 出发，按函数级别逐一分析。

```
入口函数 → 语义建模 Agent → 漏洞扫描 Agent → 验证 Agent → 报告
```

- 由 `core/analyzer.py` 编排
- 支持 `parallel_workers > 1` 时多线程并发
- 快照缓存避免重复分析未变更的函数

### 3.2 自上而下模式 (`--mode topdown`)

从 `.h` 头文件暴露的公开接口出发，自动发现所有对外 API 并逐一分析。

```
.h 文件 → 提取公开函数声明 → 批量分析 → 验证 Agent → 报告
```

- 由 `core/parallel_analyzer.py` 的 `run_topdown_mode()` 编排
- `code_index.get_header_declared_functions()` 提取头文件函数（Joern 优先，regex 回退）
- 适合模块级扫描，无需手动指定入口函数

### 3.3 规则驱动模式 (`--mode ruledriven`)

利用 Joern 内置规则先发现疑似问题，再由 LLM 验证 Agent 确认是否为真实缺陷。

```
Joern run.scan ──┐
配对函数检查 ────┤→ 按函数分组 → 验证 Agent → 误报过滤 → 报告
自定义 .sc 脚本 ─┘
```

- 由 `core/rule_driven_analyzer.py` 编排
- `core/rule_engine.py` 执行三类规则检查：
  - `run.scan.toJson`：Joern 内置/社区安全规则
  - 配对函数检查：基于用户配置的 malloc/free、lock/unlock 等配对
  - 自定义 `.sc` 脚本：用户编写的 Scala 查询脚本

## 4. 多智能体系统

三个 Agent 各司其职，通过工具总线访问代码信息：

| Agent | 职责 | 输入 | 输出 |
|-------|------|------|------|
| 语义建模 Agent | 理解函数语义、识别关键路径 | 函数源码 + 调用图 | 语义模型（数据流、状态转换） |
| 漏洞扫描 Agent | 基于语义模型发现潜在缺陷 | 语义模型 + 代码上下文 | 疑似缺陷列表 |
| 验证 Agent | 二次确认疑似缺陷的真实性 | 疑似缺陷 + 源码 | 验证结论（confirmed/rejected） |

每个 Agent 位于 `agents/<name>/` 目录，包含独立的 system prompt 和输出 schema。

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
                      → 下次扫描时 analyzer / rule_driven_analyzer 自动过滤匹配项
```

### 5.4 配置告警

当 `tools_runtime.py` 遇到未知外部函数（既无源码也无用户描述）时，自动写入 `config_warnings` 表，WebUI 展示给用户引导补充。

## 6. Joern CPG 引擎

### 6.1 JoernClient 生命周期

```
start_server() → import_cpg() 或 import_cpg_async() → query() × N → stop_server()
```

- `import_cpg_async()` 在后台线程执行，通过 `threading.Lock` 保护状态机：`idle → building → ready | error`
- `wait_for_cpg(timeout)` 阻塞等待构建完成
- `cpg_status` 属性实时查询当前状态

### 6.2 CodeIndex 可插拔后端

`retrieval/code_index.py` 提供统一的代码查询接口，通过 `indexing.backend` 配置选择后端：

| 后端 | 实现 | 适用场景 |
|------|------|---------|
| `joern` | JoernBackend — CPGQL WebSocket | 完整 CPG 查询，规则驱动模式 |
| `clang` | ClangBackend — libclang → KnowledgeDB | 精确 AST 解析，无需 JVM |
| `unified` | UnifiedBackend — ClangBackend + SvfAnalyzer (共享 KnowledgeDB) | Clang AST + SVF 间接调用/污点分析 |
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

设计原则：**全局稀疏建图，按需局部查询**。

## 7. Web 仪表盘

`web/server.py` 提供 HTTP REST API，`web/static/index.html` 为 Alpine.js + DaisyUI 单页应用。

### 7.1 API 端点

| 方法 | 路径 | 功能 |
|------|------|------|
| GET | `/api/cpg_status` | 查询 CPG 构建状态 |
| POST | `/api/build_cpg` | 触发异步 CPG 构建 |
| GET | `/api/report` | 获取扫描报告 |
| POST | `/api/mark_false_positive` | 标记误报 |
| GET | `/api/false_positives` | 列出已标记误报 |
| GET/POST/DELETE | `/api/user_config/<resource>` | 用户配置 CRUD |
| GET | `/api/user_config/warnings` | 获取配置告警 |

### 7.2 前端页面结构

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

## 8. 目录结构

```
zscope/zscope/
├── cli/cli.py                  # CLI 入口，参数解析
├── agents/
│   ├── semantic_modeler/       # 语义建模 Agent
│   ├── vulnerability_analyzer/ # 漏洞扫描 Agent
│   └── validator_agent/        # 验证 Agent
├── core/
│   ├── analyzer.py             # 默认模式编排器
│   ├── parallel_analyzer.py    # 并行 + 自上而下模式
│   ├── rule_engine.py          # Joern 规则引擎
│   ├── rule_driven_analyzer.py # 规则驱动模式编排器
│   ├── tools_runtime.py        # 工具总线 + 上下文注入
│   ├── snapshot_store.py       # 语义快照缓存
│   └── report.py               # 报告生成
├── retrieval/
│   ├── backend_base.py         # CodeBackend ABC + 数据类
│   ├── code_index.py           # 统一查询接口（工厂方法选后端）
│   ├── joern_backend.py        # Joern CPGQL 后端
│   ├── clang_backend.py        # Clang libclang → KnowledgeDB
│   ├── svf_backend.py          # SVF 后端（已废弃，使用 unified 替代）
│   ├── unified_backend.py      # Unified Facade（Clang + SVF 共享 DB）
│   ├── svf_analyzer.py         # SVF 分析器（非 CodeBackend，接受外部 DB）
│   ├── knowledge_db.py         # SQLite schema v3（含 indirect_calls/taint_signatures + 坐标缝合）
│   ├── build_llvm.py           # gllvm BitcodeBuilder
│   ├── svf_runner.py           # SVF 执行引擎
│   └── svf_parser.py           # DOT 解析 + 结果导入
├── common/
│   └── joern_client.py         # Joern 服务管理 + CPGQL 查询
├── config/
│   ├── config.py               # YAML 配置加载
│   └── user_config_store.py    # 用户配置 SQLite 存储
├── framework/
│   └── llm_client.py           # LLM 客户端（OpenAI 兼容）
├── tools/                      # 12 个分析工具定义
└── web/
    ├── server.py               # HTTP REST API
    └── static/index.html       # 前端单页应用
```

## 9. 数据流总览

```
zscope.yaml ─→ Config 加载
                 │
                 ├─→ JoernClient.start_server()
                 │     └─→ import_cpg_async() ─→ CPG 就绪
                 │
                 ├─→ CodeIndex 初始化（等待或非阻塞）
                 │
                 ├─→ UserConfigStore 加载
                 │
                 └─→ 分析模式分发
                       │
            ┌──────────┼──────────┐
            ▼          ▼          ▼
         默认模式   自上而下    规则驱动
            │          │          │
            ▼          ▼          ▼
        Agent 管线  Agent 管线  规则引擎→验证
            │          │          │
            └──────────┼──────────┘
                       ▼
                  误报过滤（UserConfigStore）
                       │
                       ▼
                 报告生成（MD + JSON）
```

## 10. 技术栈

| 组件 | 技术选型 |
|------|---------|
| 语言 | Python 3.9+ |
| CPG 引擎 | Joern (CPGQL via WebSocket) / Clang (libclang) / SVF (wpa + saber) |
| LLM 接口 | OpenAI 兼容 API（tool calling） |
| 数据存储 | SQLite (WAL mode) + JSON |
| 前端 | Alpine.js + DaisyUI + Tailwind CSS |
| 配置 | YAML（支持 `${ENV_VAR}` 展开） |
| 格式化 | black (100 字符行宽) |
| 类型检查 | mypy |
| 测试 | pytest |
