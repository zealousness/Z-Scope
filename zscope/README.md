# Z-SCOPE

**Z-SCOPE** 是一款基于 **多智能体（Multi-Agent）** 协作的 C 项目深度静态分析工具。它通过模拟资深安全研究员的思考过程，利用大语言模型（LLM）对代码进行深度的语义建模与漏洞扫描，旨在精准发现内存安全、逻辑漏洞及跨文件资源管理问题。

## 核心特性

- **多智能体分治**：采用 `语义建模 Agent` 与 `漏洞扫描 Agent` 独立协作，保证分析深度与准确性。
- **批量函数扫描**：支持通过 JSON 定义多个入口函数，共享 AST 索引，大幅提升大工程（100万行+）的分析效率。
- **高可用模型降级**：支持多模型优先级配置，当高参数模型响应异常时，自动平滑切换至后续模型。
- **语义快照缓存**：升级为路径感知的复合主键（函数名+文件路径），精准区分同名函数，加速分析并支持大规模并发。
- **纯 YAML 驱动**：废弃繁琐的命令行参数，所有分析任务、并发数及模型参数均通过 `zscope.yaml` 灵活定制。

## 系统架构

Z-SCOPE 将公共框架能力（LLM 访问、模型降级、工具调用）与具体的分析逻辑解耦。

```mermaid
graph TD
    User([用户/项目]) --> CLI[CLI 命令行]
    CLI --> Config[Yaml 配置加载]
    
    subgraph Agents [多智能体系统]
        Config --> Modeler[语义建模 Agent]
        Config --> Analyzer[漏洞扫描 Agent]
    end
    
    subgraph Framework [核心框架层]
        Modeler --> ToolBus[工具总线]
        Analyzer --> ToolBus
        Modeler --> LLM[LLM 客户端]
        Analyzer --> LLM
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
  base_url: https://api.siliconflow.cn/v1
  models:
    - Qwen/Qwen3-Coder-480B-A35B-Instruct # 优先级 1
    - Qwen/Qwen3-Coder-30B-A3B-Instruct  # 优先级 2
  api_key: sk-xxx
  temperature: 0.1

project:
  root: .
  entry_function: main                      # 单函数模式入口
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
  snapshot_dir: .zscope_snapshots
  enable_snapshot_cache: true
```

### 2. 批量扫描配置 (可选)
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

### 3. 执行分析

```bash
zscope --config zscope.yaml
```

## 输出结果

分析完成后，Z-SCOPE 将在项目目录下生成：
- `report.md`：**中文分析报告**，包含缺陷等级、根本原因分析及修复建议。
- `zscope_batch_report.json`：批量扫描汇总报告（仅批量模式）。
- `.zscope_snapshots/`：存储函数的语义建模快照（SQLite + JSON）。
