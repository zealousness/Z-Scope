# Z-SCOPE

**Z-SCOPE** 是一款基于 **多智能体（Multi-Agent）** 协作的 C 项目深度静态分析工具。它通过模拟资深安全研究员的思考过程，利用大语言模型（LLM）对代码进行深度的语义建模与漏洞扫描，旨在精准发现内存安全、逻辑漏洞及跨文件资源管理问题。

## 核心特性

- **多智能体分治**：采用 `语义建模 Agent` 与 `漏洞扫描 Agent` 独立协作，保证分析深度与准确性。
- **批量函数扫描**：支持通过 JSON 定义多个入口函数，共享 AST 索引，大幅提升大工程（100万行+）的分析效率。
- **高可用模型降级**：支持多模型优先级配置，当高参数模型响应异常时，自动平滑切换至后续模型。
- **语义快照缓存**：升级为路径感知的复合主键（函数名+文件路径），精准区分同名函数，加速分析并支持大规模并发。
- **纯 YAML 驱动**：废弃繁琐的命令行参数，所有分析任务、并发数及模型参数均通过 `zscope.yaml` 灵活定制。
- **多模型兼容**：同时支持云端模型（SiliconFlow）和本地模型（Ollama），灵活切换无需修改代码。
- **健壮的 JSON 解析**：自动处理 LLM 输出的各种格式，包括 markdown 代码块、嵌套结构和部分截断的输出。

## 系统架构

Z-SCOPE 将公共框架能力（LLM 访问、模型降级、工具调用）与具体的分析逻辑解耦。

```mermaid
graph TD
    User([用户/项目]) --> CLI[CLI 命令行]
    CLI --> Config[Yaml 配置加载]
    
    subgraph Agents [多智能体系统]
        Config --> Modeler[语义建模 Agent]
        Config --> Analyzer[漏洞扫描 Agent]
        Config --> Validator[验证 Agent]
    end
    
    subgraph Framework [核心框架层]
        Modeler --> ToolBus[工具总线]
        Analyzer --> ToolBus
        Validator --> ToolBus
        Modeler --> LLM[LLM 客户端]
        Analyzer --> LLM
        Validator --> LLM
    end
    
    subgraph Infrastructure [基础设施]
        LLM --> Fallback["模型自动回退 (Priority List)"]
        ToolBus --> CodeIndex["代码索引 (Regex/LibClang)"]
        ToolBus --> SnapStore["快照数据库 (SQLite)"]
    end
    
    Analyzer --> Reports["分析报告 (Markdown/JSON)"]
```

## 安装指南

需要 Python 3.9+。

```bash
# 克隆仓库
git clone https://github.com/zealousness/Z-Scope.git
cd Z-Scope

# 安装核心包
python -m pip install -e zscope
```

## 快速上手

### 1. 配置 `zscope.yaml`
在项目根目录编辑 `zscope.yaml`，支持配置模型优先级及并发扫描参数：

```yaml
llm:
  provider: openai
  base_url: https://api.siliconflow.cn/v1  # 或 http://localhost:11434/v1 for Ollama
  models:
    - Qwen/Qwen3-Coder-480B-A35B-Instruct # 优先级 1
    - Qwen/Qwen3-Coder-30B-A3B-Instruct  # 优先级 2
  api_key: sk-xxx  # 本地模型可省略
  temperature: 0.1
  max_tokens: 16384

project:
  root: .
  entry_function: main                      # 单函数模式入口 (可选，如果启用了批量模式)
  # entry_functions_list: entry_funcs.json  # 开启批量扫描模式
  agents:
    - name: semantic_modeler
      enabled: true
    - name: vulnerability_analyzer
      task: "查找逻辑漏洞、内存安全问题和并发风险。"
      enabled: true

analysis:
  parallel_workers: 5      # 批量扫描并发数
  max_recursion_depth: 3   # 函数分析深度
  max_tool_iterations: 50  # 单次对话最大工具调用次数
  snapshot_dir: .zscope_snapshots
  enable_snapshot_cache: true

indexing:
  backend: libclang        # 可选: libclang (精确) 或 regex (回退)
```

### 2. 配置代码索引 (LSP/Clangd)

Z-SCOPE 支持两种代码索引后端：
- **libclang/clangd** (推荐)：基于 LLVM 的精确 AST 解析，支持跨文件符号解析
- **regex**：正则表达式回退方案，无需额外依赖

#### 安装 clangd

**Windows:**
```bash
# 使用 winget
winget install LLVM.clangd

# 或下载预编译包
# https://github.com/clangd/clangd/releases
# 解压后将 bin 目录添加到 PATH
```

**macOS:**
```bash
brew install llvm
# clangd 在 /opt/homebrew/opt/llvm/bin/clangd
```

**Ubuntu/Debian:**
```bash
sudo apt install clangd
```

#### 生成 compile_commands.json

clangd 需要 `compile_commands.json` 来理解项目结构：

**使用 CMake:**
```bash
cmake -DCMAKE_EXPORT_COMPILE_COMMANDS=ON -B build
cp build/compile_commands.json .
```

**使用 Bear (任意 Makefile 项目):**
```bash
# 安装 Bear
pip install bear  # 或 apt install bear

# 生成编译数据库
bear -- make
```

**手动创建 (简单项目):**
```json
[
  {
    "directory": "/path/to/project",
    "command": "gcc -c -I./include src/main.c -o main.o",
    "file": "src/main.c"
  }
]
```

#### 配置索引后端

```yaml
indexing:
  backend: libclang  # 使用 clangd (需要 compile_commands.json)
  # backend: regex   # 回退方案，无需额外配置
```

> **注意**: 如果 clangd 启动失败，Z-SCOPE 会自动回退到 regex 模式并输出警告日志。

### 3. 批量扫描配置 (可选)
创建 `entry_funcs.json` 定义多个扫描目标，可为每个函数附加特定的提示词：

```json
{
  "functions": [
    {
      "function_name": "process_data",
      "file_path": "src/core.c",
      "custom_prompt": "关注处理逻辑中的整数溢出"
    },
    {
      "function_name": "main",
      "custom_prompt": "扫描程序初始化过程中的资源泄露"
    }
  ]
}
```

### 4. 执行分析

```bash
zscope --config zscope.yaml
```

### 5. 使用本地模型 (Ollama)

```yaml
llm:
  provider: openai
  base_url: http://localhost:11434/v1
  models:
    - alibayram/Qwen3-30B-A3B-Instruct-2507:latest
  temperature: 0.1
  max_tokens: 16384
```

## 输出结果

分析完成后，Z-SCOPE 将在项目目录下生成：
- `report.json`：**详细分析报告** (JSON 格式)，包含完整的缺陷信息和验证结果。
- `report.md`：**中文分析报告**，包含缺陷等级、根本原因分析及修复建议。
- `zscope_batch_report.json`：批量扫描汇总报告 (JSON 格式)。
- `zscope_batch_report.md`：**批量扫描汇总报告 (Markdown 格式)**，方便快速查阅。
- `.zscope_snapshots/`：存储函数的语义建模快照（SQLite + JSON）。

## 示例输出

```markdown
# Z-SCOPE 分析报告

**入口函数**: `cache_get`
**整体结论**: 🔴 发现缺陷

## 缺陷列表

### 🟠 [ISSUE_1] memory_safety: buffer_overflow
- **所在函数**: `cache_get`
- **代码位置**: `src/cache_core.c:149`
- **置信度**: 90%

**问题描述**:
在缓存获取操作中，未验证输出缓冲区大小，可能导致缓冲区溢出。

**修复建议**:
> 在 memcpy 前添加检查：if (buffer_size < node->value_size) return -1;
```

## 更新日志

### v0.1.1 (2026-01-26)
- 修复 JSON 解析逻辑，增强对本地 LLM 输出格式的兼容性
- 添加健壮的 JSON 提取策略（支持嵌套结构、markdown 代码块、部分截断恢复）
- 修复 Agent 模块中缺失的 logger 导入
- 优化配置模板，增加 `max_tokens` 和 `max_tool_iterations` 参数

### v0.1.0
- 初始版本发布
- 多智能体协作分析架构
- 批量函数扫描支持
- 模型自动降级机制
