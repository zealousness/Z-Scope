# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Z-SCOPE 是一个基于开源大模型的 C 语言 AI 代码检视工具。利用 Joern CPG（CPGQL）的图查询能力配合 LLM Agent 的语义理解能力，针对 C 语言最常见的缺陷类型进行深度检视，目标是高召回率的同时保持较低误报率。

**关注的缺陷类型**：
- 内存类：内存管理、指针访问、读写越界
- 并发类：数据竞争、时序问题

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

## Architecture

The main Python package lives in `zscope/zscope/`. Entry point: `zscope/zscope/cli/cli.py` → `main()`.

### Two Analysis Modes

1. **自上而下模式**：以对外接口（.h 文件暴露的函数）为起点，自上而下进行代码检视，发现疑似问题后提交审查 Agent 二次确认。
2. **规则驱动模式**：利用 Joern 已有规则发现疑似问题，再由审查 Agent 确认是否为真实缺陷。

### User-Provided Configuration（用户辅助信息）

Joern 存在能力边界，以下信息需要用户通过 WebUI 配置并存入数据库：

1. **外部库函数描述** — 无法获取实现的外部函数，用户按模板补充其内存/并发相关行为。
2. **compile_commands.json** — 提供准确的宏定义和预处理分支。
3. **函数指针指向** — 找不到具体指向时打印告警并提供模板，支持：函数内局部指向、全局变量指向、用户标记为可忽略。
4. **自定义配对函数** — 用户实现的 malloc/free、lock/unlock 等关键函数，按类别配对输入。
5. **函数设计意图与并发关系** — 函数对调用者的约束（如指针一定合法、不会并发调用），以及接口/任务间的并发关系。

### Key Modules

- **`agents/`** — Three agents: `semantic_modeler/`, `vulnerability_analyzer/`, `validator_agent/`. Each has its own system prompt and output schema.
- **`core/analyzer.py`** — Main orchestrator. Runs the agent pipeline, resolves issue locations, manages snapshot caching. Injects user config context (paired functions, function intents) into agent prompts; filters false positives before report generation.
- **`core/parallel_analyzer.py`** — Batch mode with thread pool. Shares `CodeIndex` and `SnapshotStore` across workers. Provides `run_topdown_mode()` for header-driven analysis.
- **`core/rule_engine.py`** — Executes Joern built-in scan (`run.scan.toJson`), custom `.sc` scripts, and paired function checks via CPGQL. Returns `RuleMatch` list.
- **`core/rule_driven_analyzer.py`** — Rule-driven pipeline: Joern rules → group by function → ValidatorAgent confirmation → false positive filtering → report.
- **`core/snapshot_store.py`** — Semantic cache using SQLite + JSON files. Composite key: `(func_name, file_path)`. Detects code changes for smart refresh.
- **`core/tools_runtime.py`** — Tool implementations for LLM agents. Auto-injects external function descriptions from `UserConfigStore` when implementation not found; records `config_warning` for unknown externals.
- **`retrieval/code_index.py`** — Dual backend: Joern CPG (primary) with regex fallback. Provides function lookup, call graph, data flow, type queries. Supports `wait_for_cpg=False` non-blocking mode and `get_header_declared_functions()`.
- **`common/joern_client.py`** — Manages Joern server subprocess, executes CPGQL queries via WebSocket. Supports async CPG build (`import_cpg_async`) with thread-safe status tracking.
- **`config/user_config_store.py`** — SQLite (WAL mode) store for user-provided config: 6 tables (external_functions, function_pointer_targets, paired_functions, function_intent, false_positives, config_warnings).
- **`framework/llm_client.py`** — OpenAI-compatible client with tool-calling loop, model fallback (priority list), and exponential backoff for rate limiting.
- **`tools/`** — 9 analysis tools exposed to LLM agents (get_function_impl, get_call_graph, get_data_flow, etc.).
- **`config/config.py`** — Dataclass-based config loaded from `zscope.yaml`. Supports `${ENV_VAR}` expansion. `AnalysisConfig.user_config_db` specifies user config DB path.
- **`web/server.py`** — HTTP server with REST API for findings, config CRUD, CPG management, false positive marking, and config warnings.
- **`web/static/index.html`** — Alpine.js + DaisyUI dashboard with tabs: findings (with validation/false-positive marking), user config management (5 sub-tabs), and warnings.

### Key Design Decisions

- LLM client uses OpenAI-compatible API format — works with Ollama, SiliconFlow, and other providers.
- Joern CPG replaced the previous clangd LSP backend in v0.2.0.
- Snapshot store uses composite keys `(func_name, file_path)` to handle same-named functions across files.
- All configuration is centralized in `zscope.yaml` at the project root.
- **上下文注入而非 Agent 查询** — 用户配置不暴露为工具，而是在工具返回结果时和构建 Agent prompt 时自动注入（如外部函数无实现时自动附加用户描述）。
- **Joern 规则兼容性** — 规则驱动模式通过 `run.scan.toJson` 执行 Joern 内置/社区规则，不自造规则格式。
- **异步 CPG 构建** — `import_cpg_async()` 在后台线程执行，通过 `threading.Lock` 保护状态（idle → building → ready/error）。
- **误报过滤** — `false_positives` 表按 `(function, location, subcategory)` 匹配，报告生成前自动过滤。

## Performance Constraints

- 运行环境内存有限（16GB），被扫描项目约 100 万行代码、2000 个 TU。
- 项目分为 500+ 模块，扫描一个上层模块通常只涉及十几到几十个依赖模块，不同模块分开扫描。
- 这是重量级工具，不要求快速完成，但需注意内存占用控制。

## Usability Requirements

- **Joern 异步构建**：CPG 构建可能缓慢，需做成异步。Joern 只启动 1 次，扫描任务可能有几十次，构建不应在工具启动时才做。
- **WebUI 界面**：用户通过 WebUI 配置辅助信息（外部函数、函数指针、配对函数等）和查看扫描结果。工具怀疑缺少的配置信息也需展示给用户。
- **结果可读性**：扫描结果需站在用户角度设计，能被快速看懂。
- **误报反馈**：提供误报标记机制，下次扫描时自动过滤已标记的误报。

## Code Style

- Python 3.9+, black formatter with 100 char line length
- `mypy` with `disallow_untyped_defs = false`
