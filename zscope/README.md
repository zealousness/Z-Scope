# Z-SCOPE

**Z-SCOPE** 是一款基于 AI 的 C 项目静态分析工具。它利用大语言模型（LLM）对代码进行深度的语义分析，旨在发现真实的程序缺陷（如资源泄漏、并发问题和逻辑漏洞），同时忽略无关紧要的风格问题。

## 核心特性

- **语义分析**：不仅限于正则表达式或标准的静态分析 AST 检查。利用 LLM 理解代码逻辑意图。
- **增量分析**：缓存函数的“语义快照”。如果代码变更但语义未变（如重命名变量），则跳过重新分析。
- **工具辅助**：LLM 可以请求查看被调用函数实现，跨越函数边界追踪逻辑。
- **结构化报告**：提供 JSON 和 Markdown 格式的报告，包含置信度评分和影响级别。

## 系统架构

Z-SCOPE 采用代理（Agentic）循环架构，协调代码检索、状态管理和 LLM 推理。

```mermaid
graph TD
    User([用户/项目]) --> CLI[CLI 命令行]
    CLI --> Config[配置加载器]
    Config --> Analyzer[分析器核心]
    
    subgraph "核心引擎"
        Analyzer --> ToolRuntime[工具运行时]
        Analyzer --> LLMClient[LLM 客户端]
        ToolRuntime --> CodeIndex[代码索引 (libclang/Regex)]
        ToolRuntime --> SnapshotStore[快照存储 (SQLite)]
    end
    
    LLMClient --> SiliconFlow["LLM API (硅基流动/OpenAI)"]
    CodeIndex --> CFiles["C 源代码 (.c/.h)"]
    CFiles --> CompilationDB["编译数据库 (compile_commands.json)"]
    
    Analyzer --> Reports["分析报告 (Markdown/JSON)"]
```

### 主要组件说明
- **Analyzer (分析器)**：流程编排核心，负责维护与 LLM 的对话上下文和决策循环。
- **Code Index (代码索引)**：基于 `libclang` 或正则解析，负责精确定位函数定义和跨文件搜索。
- **Snapshot Store (快照存储)**：持久化存储函数的语义指纹，支持智能缓存。
- **Tool Runtime (工具运行时)**：为 LLM 提供一组“能力接口”（如 `get_function_impl`），使其能探索代码库。

## 安装指南

需要 Python 3.9+。

```bash
# 克隆仓库
git clone https://github.com/zealousness/Z-Scope.git
cd Z-Scope

# 安装依赖
python -m pip install -e zscope
```

## 使用说明

### 1. 准备工作
- **编译数据库**：为了获得最佳效果，请为 C 项目生成 `compile_commands.json`（例如使用 CMake 时设置 `set(CMAKE_EXPORT_COMPILE_COMMANDS ON)`）。
- **LLM API**：配置 Silicon Flow 或其他兼容 OpenAI 的 API 密钥。

### 2. 运行分析

可以通过配置文件 `zscope.yaml` 进行简单运行：

```bash
$env:PYTHONPATH="zscope"
python -m zscope.cli.cli --config zscope.yaml
```

或者使用命令行参数：

```bash
python -m zscope.cli.cli \
  --project ./test/test_c_project_multi \
  --entry main \
  --task "检查内存泄漏和缓冲区溢出"
```

## 输出结果

分析完成后，Z-SCOPE 会生成：
- `report.json`：全量分析数据的机器可读报告。
- `report.md`：包含缺陷详情和修复建议的人类可读总结。
- `.zscope_snapshots/`：存储缓存语义快照的目录。
