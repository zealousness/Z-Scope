# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Z-SCOPE 是一个基于开源大模型的 C 语言 AI 代码检视工具。利用 Joern CPG（CPGQL）的图查询能力配合 LLM Agent 的语义理解能力，针对 C 语言最常见的缺陷类型进行深度检视，目标是高召回率的同时保持较低误报率。

**关注的缺陷类型**：
- 内存类：内存泄漏、Use-After-Free、双重释放、空指针解引用、缓冲区越界
- 并发类：数据竞争、死锁、时序问题

**项目语言**：文档、注释、Agent prompt 均使用中文。

## Build & Development Commands

```bash
# Install (editable mode)
python -m pip install -e zscope

# Install with dev dependencies
python -m pip install -e "zscope[dev]"

# Run analysis (default mode)
zscope --verbose

# Top-down mode (from .h public APIs)
zscope --mode topdown -c zscope.yaml

# Rule-driven mode (Joern rules + validator)
zscope --mode ruledriven -c zscope.yaml

# Build CPG only (async-ready)
zscope --build-cpg -c zscope.yaml

# Launch web dashboard
zscope --dashboard

# Run tests
pytest zscope/tests/

# Run integration tests
python tmp/test_integration.py

# Run a single test
pytest zscope/tests/test_xxx.py -v

# Format code
black zscope/zscope/ --line-length 100

# Type check
mypy zscope/zscope/
```

**输出文件**：分析完成后在 `project_root` 下生成 `zscope_batch_report.json` 和 `zscope_batch_report.md`，快照缓存在 `.zscope_snapshots/` 目录。

## Architecture

主包位于 `zscope/zscope/`，入口：`cli/cli.py` → `main()`（Click CLI）。

### 整体架构

```
CLI 入口层 (cli.py --mode default|topdown|ruledriven)
    │
    ├─→ 默认模式 (analyzer.py)
    ├─→ 自上而下模式 (parallel_analyzer.py)
    └─→ 规则驱动模式 (rule_driven_analyzer.py + rule_engine.py)
          │
          ▼
    多智能体管线 (agents/)
    语义建模 Agent → 漏洞扫描 Agent → 验证 Agent
          │
          ▼
    工具总线 (tools_runtime.py) — 12 个分析工具 + 用户配置自动注入
          │
          ▼
    CodeIndex (可插拔后端) + SnapshotStore + UserConfigStore
          │
          ▼
    CodeBackend ABC (backend_base.py)
    ├─ JoernBackend    — CPGQL via WebSocket
    ├─ ClangBackend    — libclang 批量解析 → KnowledgeDB
    ├─ UnifiedBackend  — ClangBackend + SvfAnalyzer (共享 KnowledgeDB)
    └─ RegexBackend    — 正则回退
```

### 三种分析模式

1. **默认模式**（`--mode default`）：从 `zscope.yaml` 指定的 `entry_function` 出发，按函数级别逐一分析。由 `core/analyzer.py` 编排，支持多线程并发。
2. **自上而下模式**（`--mode topdown`）：从 `.h` 头文件暴露的公开接口出发，自动发现所有对外 API 并批量分析。由 `core/parallel_analyzer.py` 的 `run_topdown_mode()` 编排。
3. **规则驱动模式**（`--mode ruledriven`）：利用 Joern 内置规则先发现疑似问题，再由验证 Agent 确认。由 `core/rule_driven_analyzer.py` 编排，`core/rule_engine.py` 执行三类规则（`run.scan.toJson`、配对函数检查、自定义 `.sc` 脚本）。

### 多智能体管线

| Agent | 目录 | 职责 |
|-------|------|------|
| 语义建模 Agent | `agents/semantic_modeler/` | 理解函数语义、识别关键路径，输出语义模型 |
| 漏洞扫描 Agent | `agents/vulnerability_analyzer/` | 基于语义模型发现潜在缺陷 |
| 验证 Agent | `agents/validator_agent/` | 二次确认疑似缺陷的真实性（confirmed/rejected） |

每个 Agent 有独立的 system prompt 和输出 schema。`agents/analyst_agent/` 为遗留/备用 Agent。

### 用户辅助配置（UserConfigStore）

Joern 存在能力边界，以下信息需用户通过 WebUI 配置，存入 SQLite（WAL mode）的 6 张表：

| 表名 | 用途 |
|------|------|
| `external_functions` | 外部库函数的内存/并发行为描述 |
| `paired_functions` | 自定义 malloc/free、lock/unlock 等配对函数 |
| `function_pointer_targets` | 函数指针的具体指向 |
| `function_intent` | 函数设计意图与并发关系 |
| `false_positives` | 已确认误报，按 `(function, location, subcategory)` 匹配过滤 |
| `config_warnings` | 工具发现的缺失配置告警 |

### 关键模块概览

- **`core/`** — 分析编排层。`analyzer.py`（单函数编排 + 用户配置注入 + 误报过滤）、`parallel_analyzer.py`（线程池批量 + topdown 模式）、`rule_driven_analyzer.py` + `rule_engine.py`（规则驱动管线）、`tools_runtime.py`（12 个工具实现 + 外部函数描述自动注入，含 `get_deep_call_context` 高聚合查询）、`snapshot_store.py`（SQLite+JSON 语义缓存，复合键 `(func_name, file_path)`）。
- **`retrieval/`** — 可插拔后端层。`backend_base.py`（CodeBackend ABC）、`code_index.py`（统一查询接口，工厂方法按 `indexing.backend` 创建后端）、`joern_backend.py`（Joern CPGQL）、`clang_backend.py`（libclang 批量解析 → KnowledgeDB）、`unified_backend.py`（Facade：ClangBackend + SvfAnalyzer 共享 KnowledgeDB）、`svf_analyzer.py`（SVF 分析器，非 CodeBackend，接受外部 DB）、`svf_backend.py`（已废弃，指引使用 unified）、`knowledge_db.py`（SQLite schema v3，含 `indirect_calls` + `taint_signatures` 表，坐标缝合查询）、`build_llvm.py`（BitcodeBuilder）、`svf_runner.py`（SvfRunner）、`svf_parser.py`（DOT 解析 + 坐标缝合导入）。
- **`common/joern_client.py`** — Joern 服务进程管理 + CPGQL WebSocket 查询。`import_cpg_async()` 后台线程构建，状态机：`idle → building → ready | error`。
- **`framework/llm_client.py`** — OpenAI 兼容客户端，支持 tool calling 循环、模型优先级回退、指数退避。
- **`config/`** — `config.py`（dataclass 配置，YAML 加载，支持 `${ENV_VAR}`）、`user_config_store.py`（用户配置 SQLite 存储）。
- **`web/`** — `server.py`（REST API）+ `static/index.html`（Alpine.js + DaisyUI 单页应用）。
- **`llm/`** — 遗留目录，`framework/llm_client.py` 为当前使用的 LLM 客户端。

### 关键设计决策

- **OpenAI 兼容 API** — LLM 客户端使用 OpenAI 格式，兼容 Ollama、SiliconFlow 等提供商。
- **上下文注入而非 Agent 查询** — 用户配置不暴露为 LLM 工具，而是在 `tools_runtime.py` 返回结果时和 `analyzer.py` 构建 prompt 时自动注入。
- **异步 CPG 构建** — `import_cpg_async()` 后台线程执行，`threading.Lock` 保护状态机。Joern 只启动 1 次，多次扫描复用。
- **误报过滤闭环** — 用户在 WebUI 标记误报 → `false_positives` 表写入 → 下次扫描自动过滤。
- **Joern 规则兼容** — 规则驱动模式通过 `run.scan.toJson` 执行 Joern 内置/社区规则，不自造规则格式。
- **可插拔后端架构** — `CodeBackend` ABC 定义统一接口，`code_index.py` 工厂方法按 `indexing.backend` 配置创建对应后端（joern / clang / unified / regex）。
- **UnifiedBackend Facade** — `unified` 模式组合 ClangBackend（AST 提取）+ SvfAnalyzer（深度分析），共享同一个 KnowledgeDB，通过 `(file_path, line)` 坐标缝合 Clang AST 与 SVF LLVM IR 结果。设计原则：全局稀疏建图，按需局部查询。
- Joern CPG 在 v0.2.0 替代了之前的 clangd LSP 后端；v0.3.0 引入 Clang/SVF 可插拔后端；v0.4.0 引入 UnifiedBackend Facade。
- 所有配置集中在项目根目录的 `zscope.yaml`。

## 项目目录结构

- `zscope/` — 主 Python 包（`pyproject.toml` + `zscope/` 源码 + `tests/`）
- `dependency/` — 外部依赖（Joern CLI、JDK21），已 gitignore
- `test/` — 测试用 C 项目（`junior/` 简单、`middle/` 中等如 mbedtls 子集、`senior/` 完整 mbedtls、`svf_test/` SVF 函数指针测试）
- `docs/architecture.md` — 详细架构文档（含数据流图、API 端点表）
- `workspace/` — 运行时工作目录
- `zscope.yaml` — 全局配置文件

### zscope.yaml 配置结构

```yaml
llm:          # LLM 提供商配置（base_url, api_key, models, temperature, max_tokens）
project:      # 项目配置（project_root, source_root, compile_commands_path, entry_function/entry_functions_list）
indexing:     # 后端配置（backend: joern|clang|unified|regex）
              #   Joern: joern_path, host, port, heap_size
              #   Clang: clang_db_path, compile_commands_path
              #   SVF (unified 模式): svf_bin_dir, gclang_path, get_bc_path, llvm_link_path, svf_heap_limit_mb, svf_timeout
analysis:     # 分析参数（max_depth, max_function_lines, snapshot_dir, parallel_workers, user_config_db）
```

支持 `${ENV_VAR}` 环境变量展开。

## 运行约束

- 运行环境内存 16GB，被扫描项目约 100 万行 C 代码、2000 个 TU、500+ 模块。
- 按模块独立扫描，单次扫描通常涉及十几到几十个依赖模块。
- 重量级工具，不要求快速完成，但需注意内存占用控制。

## Code Style

- Python 3.9+, black formatter with 100 char line length
- `mypy` with `disallow_untyped_defs = false`
