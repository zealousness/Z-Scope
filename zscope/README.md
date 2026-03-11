# Z-SCOPE (v0.2.0)

**Z-SCOPE** 是一款基于 **多智能体（Multi-Agent）** 协作的 C 项目深度静态分析工具。它通过模拟资深安全研究员的思考过程，利用大语言模型（LLM）对代码进行深度的语义建模与漏洞扫描，旨在精准发现内存安全、逻辑漏洞及跨文件资源管理问题。

## 核心特性

- **多智能体分治**：采用 `语义建模 Agent`、`漏洞扫描 Agent` 与 `验证 Agent` 独立协作，深度挖掘逻辑缺陷。
- **四种分析模式**：默认模式（指定入口函数）、自上而下模式（从 `.h` 公开接口出发）、规则驱动模式（Joern 规则 + LLM 验证）、告警验证模式（SARIF 导入 + LLM 二次确认）。
- **可插拔后端架构**：支持 Joern CPG、Clang libclang、Unified（Clang + SVF）、Regex 四种后端，按需选择分析深度。
- **12 个分析工具**：函数源码获取、调用图分析、结构体查询、污点追踪、指针别名查询、深度调用上下文聚合等。
- **用户辅助配置系统**：通过 WebUI 管理外部函数描述、配对函数、函数指针指向等信息，自动注入分析上下文。
- **误报反馈闭环**：支持标记误报，下次扫描自动过滤已确认的误报。
- **Web 仪表盘**：Alpine.js + DaisyUI 构建的交互式界面，集成扫描结果查看、用户配置管理和配置告警。
- **批量函数并行扫描**：支持多 worker 并发，共享代码索引与快照数据库。
- **SQLite 原生级持久化**：分析产生的终极漏洞（Issues）将直接与语义模型一同被永久锁定存入本地 `.zscope_snapshots/snapshots.db`，确保灾难级恢复能力。
- **自动报告备份护城河**：每次批量生成或覆盖 JSON 分析主报告前，自动创建带时间戳的增量备份至 `.zscope_knowledge/backups/` 目录。
- **纯 YAML 驱动**：所有分析参数通过 `zscope.yaml` 统一定义，支持 `${ENV_VAR}` 环境变量展开。

## 系统架构

```
CLI 入口层 (cli.py --mode default|topdown|ruledriven|alert-verify)
    │
    ├─→ 默认模式 (analyzer.py)         — 指定入口函数逐一分析
    ├─→ 自上而下模式 (parallel_analyzer.py) — 从 .h 公开接口批量分析
    ├─→ 规则驱动模式 (rule_driven_analyzer.py) — Joern 规则 + LLM 验证
    └─→ 告警验证模式 (alert_verifier.py)    — SARIF 导入 + LLM 二次确认
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

## 数据安全与强制恢复机制 (New in v0.2.0)
Z-Scope 内置了严密的数据防丢失功能：
1. **快照级持久化**：所有的 `VulnerabilityAnalyzer` 输出（即真正发现的漏洞 JSON）都会在扫描结束的第一时间原封不动被硬编码打入 SQLite 数据库。哪怕程序异常终止，单函数的成果也绝对不会丢失。
2. **热备份轮转**：在汇总合并最终的 `zscope_batch_report.json` 时，旧版本的文件会被自动加盖时间戳并归档至 `.zscope_knowledge/backups/` 目录下。
3. **离线报告起死回生**：如果您不慎清空了所有的 JSON 与 SQLite 数据库，但手中恰好还有一份从网页前端导出的**离线 HTML 审计报告**（`offline_template.html`），可以使用根目录的救灾脚本瞬间将数据逆向复原进 SQLite 数据库中：
   ```bash
   python restore_from_html.py zscope_offline_report.html
   ```

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

### 外部工具依赖（按后端）

| 后端 | 必需工具 | 说明 |
|------|---------|------|
| `regex` | 无 | 纯正则，零外部依赖 |
| `joern` | Joern CLI + JDK 21 | 从 [Joern Releases](https://github.com/joernio/joern/releases) 下载 |
| `clang` | clangd + compile_commands.json | clangd LSP 符号提取，无需 `pip install libclang` |
| `unified` | clangd + (可选) clang-18 + gllvm + SVF 3.2 + LLVM | Clang AST + SVF 深度分析，SVF 不可用时优雅降级 |

## 安装指南

### 1. 安装 Z-SCOPE

```bash
git clone https://github.com/user/Z-Scope.git
cd Z-Scope
python -m pip install -e zscope

# 含开发依赖
python -m pip install -e "zscope[dev]"
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
#    方法 A: 系统包（推荐）
sudo apt install clangd-18      # Ubuntu 24.04
#    方法 B: 独立二进制（无需 root）
mkdir -p ~/.local/clangd && cd ~/.local/clangd
curl -sL https://github.com/clangd/clangd/releases/download/18.1.3/clangd-linux-18.1.3.zip -o clangd.zip
unzip clangd.zip
# 然后在 zscope.yaml 中配置 clangd_path

# 2. 生成 compile_commands.json（Clang 后端必须）
cmake -DCMAKE_EXPORT_COMPILE_COMMANDS=ON ..
# 或使用 bear: bear -- make
```

> **注意**: Clang 后端使用 clangd LSP 进行符号提取和调用图构建，不需要 `pip install libclang`，只需要 clangd 二进制。

**Unified 后端**（Clang + SVF，完整安装）：

Unified 模式 = Clang AST 提取 + SVF 深度分析。Clang 部分为必需，SVF 部分为可选（不可用时会自动降级并显示告警）。

```bash
# ═══ 必需：Clang AST 提取 ═══

# 1. clangd（同 Clang 后端）
sudo apt install clangd-18

# 2. compile_commands.json
cmake -DCMAKE_EXPORT_COMPILE_COMMANDS=ON ..

# ═══ 可选：SVF 深度分析 ═══
# 如果不安装 SVF，unified 模式退化为 clang 模式（自动告警）

# 3. 安装 Clang 编译器（gclang 依赖）
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
  clangd_path: clangd-18          # 或完整路径
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
llm:
  provider: openai
  base_url: http://127.0.0.1:11434/v1   # Ollama 本地
  models:
    - qwen3:latest
  api_key: ollama
  temperature: 0.1
  max_tokens: 4096

project:
  root: .                    # 被扫描项目根目录
  source_root: .             # 源码搜索根目录（clangd/SVF 基于此查找源码）
  entry_function: main       # 默认模式入口函数
  # entry_functions_list: functions.json  # 批量模式：函数列表文件
  # compile_commands_path: build/compile_commands.json  # Clang/Unified 需要
  # ↑ 相对路径基于 source_root 解析；不配则自动在 source_root 和 root 下查找
  agents:
    - name: semantic_modeler
      enabled: true
    - name: vulnerability_analyzer
      task: "查找逻辑漏洞、内存安全问题和并发风险。"
      enabled: true

indexing:
  backend: joern             # joern | clang | unified | regex

  # ── Joern 后端 ──
  joern_path: dependency/joern/joern
  joern_server_host: 127.0.0.1
  joern_server_port: 8080
  joern_heap_size: 8g

  # ── Clang 后端 ──
  # knowledge_db_path: .zscope_knowledge/code_knowledge.db

  # ── SVF 配置（unified 模式）──
  # svf_bin_dir: dependency/svf/bin
  # gclang_path: gclang
  # get_bc_path: get-bc
  # llvm_link_path: llvm-link
  # svf_heap_limit_mb: 32768
  # svf_timeout: 1800
  # svf_groups_config: svf_groups.json  # 解决 symbol multiply defined：用于多态链接隔离的 JSON 配置

analysis:
  max_recursion_depth: 3
  max_function_lines: 500
  snapshot_dir: .zscope_snapshots
  enable_snapshot_cache: true
  parallel_workers: 5
```

### Step 2：执行分析

```bash
# 默认模式：从 entry_function 开始分析
zscope -c zscope.yaml --verbose

# 自上而下模式：从 .h 头文件公开接口出发，自动发现所有 API
zscope --mode topdown -c zscope.yaml

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
| `zscope_batch_report.json` | 结构化缺陷数据（可供 CI 集成） |
| `zscope_alert_verify_report.json` | 告警验证模式的验证结果 |
| `.zscope_snapshots/` | 语义快照缓存（加速重复扫描） |

退出码：发现缺陷返回 `1`，无缺陷返回 `0`，可直接用于 CI/CD 流水线。

### Step 4：启动 Web 仪表盘（可选）

```bash
zscope --dashboard -c zscope.yaml
```

仪表盘提供三个主要页面：
- **扫描结果**：查看缺陷列表，支持验证状态标记和误报反馈
- **配置管理**：管理外部函数描述、配对函数、函数指针指向、函数设计意图 + CPG 构建控制
- **配置告警**：展示工具怀疑缺少的配置信息，引导用户补充

## 分析工具清单（12 个）

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

## 用户辅助配置

静态分析工具存在能力边界，Z-SCOPE 支持用户通过 Web 仪表盘补充以下信息，分析时自动注入上下文：

| 配置类型 | 说明 | 示例 |
|----------|------|------|
| 外部库函数描述 | 无法获取实现的外部函数的内存/并发行为 | `pthread_mutex_lock` 的锁语义 |
| 自定义配对函数 | 用户实现的 malloc/free、lock/unlock 等配对 | `my_alloc` ↔ `my_free` |
| 函数指针指向 | 函数指针的具体目标函数 | `handler_ptr` → `handle_read` |
| 函数设计意图 | 函数对调用者的约束和并发关系 | "此函数不会被并发调用" |

## 后端对比

| 特性 | regex | joern | clang | unified |
|------|-------|-------|-------|---------|
| 外部依赖 | 无 | JDK 21 + Joern | libclang | libclang + gllvm + SVF + LLVM |
| 函数源码提取 | 正则匹配 | CPGQL 精确 | AST 精确 | AST 精确 |
| 调用图 | 不支持 | 完整 CPG | 直接调用 | 直接 + 间接（SVF 指针分析） |
| 类型查询 | 不支持 | 完整 | AST 精确 | AST 精确 |
| 污点分析 | 不支持 | 数据流追踪 | 不支持 | SVF saber（内存泄漏/UAF/双重释放） |
| 间接调用解析 | 不支持 | 有限 | 不支持 | SVF Andersen 指针分析 |
| 规则驱动模式 | 不支持 | 支持 | 不支持 | 不支持 |
| 内存占用 | 极低 | 高（JVM） | 中 | 中高 |

## 开发命令

```bash
# 格式化
black zscope/zscope/ --line-length 100

# 类型检查
mypy zscope/zscope/

# 运行测试
pytest zscope/tests/

# 运行集成测试
python tmp/test_integration.py
```

## 更新日志

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
