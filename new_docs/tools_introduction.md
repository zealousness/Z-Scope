# Tools introduction

本文列出 Z-SCOPE 中不同 Agent 可以使用的本地工具集合。口径以当前代码为准：

- Agent 的基础工具声明来自 `zscope/agents/*/AGENT.md`。
- Skill 的工具声明来自 `zscope/skills/*/SKILL.md` 的 `allowed_tools`。
- 运行时有效工具由 `zscope/orchestration/agent_policy.py` 中的 `tool_policy_for_agent` 决定：当 Agent tools 和 active Skill tools 都存在时，取二者交集。
- `zscope/core/analysis/analyzer.py::_get_tools` 会根据底层索引后端能力（`code_index.backend_name`）对工具池进行过滤：
  - **基础工具**（`get_function_impl`, `get_function_info`, `get_function_snapshot`, `list_known_functions`, `get_file_snippet`, `get_callers`, `get_type_info`）在所有后端（包括 `regex` / `clangdFallback`）下均受支持并注入工具池。
  - **高级图与分析工具**（`get_call_graph`, `get_data_flow`, `find_function_pointers`, `query_pointer_alias`, `verify_taint_reachability`, `get_deep_call_context`）只有在高级分析后端（即 `joern`, `svf`, `unified`）下才会被添加。由于当前基线使用的是 `unified` 后端，这 6 个高级工具也是可用的。
- `deny_sensitive_paths_hook` 对所有 Agent 生效，会拒绝明显敏感路径参数。

## 一、全部工具的介绍

Z-SCOPE 运行时支持的全部本地工具共 13 个，其 OpenAI Schema 声明与参数校验在 [runtime.py](file:///Ubuntu-22.04/home/jager/Z-Scope/zscope/tools/runtime.py) 中定义，功能涵盖代码基础检索、图结构查询、底层指针与污点静态分析等。以下是每个工具的详细输入参数和输出数据结构：

### 1. `get_function_impl`
* **工具说明**：获取函数的实现源码。根据函数名检索其 C 语言源代码实现以供代码审计。
* **输入参数 (Inputs)**：
  - `func_name` (string, **必填**): 目标函数的名称。
  - `max_lines` (integer, 选填, 默认 200): 返回的代码行数上限。
* **输出数据 (Outputs)**：
  - 执行成功返回 `{"success": true, "data": {...}}`，其中 `data` 的结构如下：
    ```json
    {
      "func_name": "函数名称",
      "file": "源文件相对路径",
      "index_name": "函数唯一标识名",
      "start_line": 128, // 起始行号
      "end_line": 210, // 结束行号
      "code": "带行号的源码内容，包含头部声明与实现前置注释",
      "callees": ["内部调用的直接子函数名称列表"],
      "signature": "函数原型签名原型声明",
      "truncated": false, // 是否被截断
      "comment_blocks": [
        {
          "kind": "comment kind", // 如 header/implementation
          "code": "注释的具体文本"
        }
      ]
    }
    ```
  - **`index_name`**：符号索引库中用于存储该函数条目的唯一主键名称。目前与 `func_name` 保持一致，架构上预留以支持 C++ 重载/命名空间等场景下的解耦。
  - **`signature`**：从编译器 AST/分析引擎中提取的完整 C 语言原型声明（包含返回类型、形参类型和参数名，如 `int td_init(const char* config_str)`）。
  - **外部函数回退机制 (External Function Fallback)**：
    若在项目内部的源文件和 AST 索引中找不到该函数的具体实现（例如对于 `pthread_mutex_init`、`malloc` 等标准库或第三方库函数），工具会触发外部函数机制：
    * **存在用户配置的外部函数描述时**：工具会成功返回如下的模拟实现结构，将库信息、并发与内存行为及返回语义以 C 风格注释代码段形式透传出来：
      ```json
      {
        "success": true,
        "data": {
          "code": "/* 外部函数 (来自 库名称)\n * 描述: 函数功能描述\n * 内存行为: 内存分配释放规约\n * 并发行为: 锁与并发安全性说明\n * 返回语义: 返回码定义描述\n */",
          "file": "[external]",
          "start_line": 0,
          "end_line": 0,
          "is_external": true
        }
      }
      ```
    * **不存在用户配置描述时**：系统会向用户配置管理器中记录一条未定义外部函数警告（`missing_external_func`），并返回执行失败信息：`{"success": false, "error": "Function '...' not found in project index"}`。

### 1.1 `get_function_info`
* **工具说明**：获取函数结构化元信息和调用关系，不返回源码正文。适合先定位函数身份、文件位置、行号范围、签名、上游调用者和下游被调用者，再按需使用 `get_file_snippet` 读取精确代码证据。
* **输入参数 (Inputs)**：
  - `func_name` (string, **必填**): 函数名称，可为简单名、限定名或已有 `index_name`。
  - `file_path` (string, 选填): 函数所在源文件路径，用于同名函数消歧。
  - `callers_limit` (integer, 选填, 默认 30): 每个命中函数返回的调用者数量上限。
  - `callees_limit` (integer, 选填, 默认 30): 每个命中函数返回的被调用者数量上限。
* **输出数据 (Outputs)**：
  - 执行成功返回 `{"success": true, "data": {...}}`，其中 `data` 的结构如下：
    ```json
    {
      "match_count": 1,
      "matches": [
        {
          "function_name": "Target",
          "file_path": "src/shared.c",
          "index_name": "Target@src/a/shared.c:1",
          "start_line": 1,
          "end_line": 20,
          "signature": "int Target(void)",
          "callers": [
            {
              "caller_name": "Caller",
              "caller_file": "src/main.c",
              "callsite_line": 100
            }
          ],
          "callees": [
            {
              "callee_name": "Callee",
              "callee_file": "src/helper.c",
              "callsite_line": 120,
              "call_type": "direct"
            }
          ]
        }
      ]
    }
    ```
  - `match_count=0` 表示查询成功但未命中；`match_count>1` 表示存在同名、重载或路径歧义。
  - `call_type` 在 `svf` / `unified` 后端可返回 `direct` 或 `indirect`；仅 `clang` / `clangd` 能力可用时自动降级为 `direct`。
  - 只有命中用户配置的外部函数时才返回 `is_external: true`；普通内部函数默认不返回 `is_external: false`。

### 2. `get_function_snapshot`
* **工具说明**：获取之前已保存的函数语义快照（语义规约）。
* **输入参数 (Inputs)**：
  - `func_name` (string, **必填**): 函数名称。
  - `file_path` (string, 选填): 函数所在的源文件路径。
* **输出数据 (Outputs)**：
  - 执行成功返回 `{"success": true, "data": {...}}`，若不存在快照则 `data` 为 `null`。
  - **快照结构的双重表现形式**：
    由于快照的生成来源有两种，返回的 `data` 结构也会有不同的表现：
    
    1. **由大模型（`semantic_modeler`）生成的深度语义快照 (LLM-modeled Snapshots)**：
       此快照会附带大量结构化语义推导信息。其典型结构如下（可能包含大模型无损输出的 `callers`、`parameters`、`return_value` 等键名）：
       ```json
       {
         "function_name": "函数名",
         "file_path": "文件路径",
         "start_line": 100,
         "end_line": 120,
         "signature": "函数原型",
         "summary": "中文功能概括",
         "parameters": [
           {
             "name": "参数名",
             "type": "类型",
             "meaning": "语义说明",
             "nullable": false,
             "ownership": "所有权（借用/转移）",
             "constraints": "值约束条件"
           }
         ],
         "return_value": {
           "type": "返回类型",
           "meaning": "返回值语义",
           "success_value": "成功返回值",
           "error_values": ["错误返回值"]
         },
         "callees": [
           {
             "name": "子函数名",
             "location": "调用行号/位置",
             "purpose": "调用目的",
             "error_handling": "出错后如何处理",
             "security_relevance": "是否涉及安全风险"
           }
         ],
         "callers": [ // 由大模型生成的额外辅助字段，记录静态分析识别出的上游调用源
           {
             "function": "调用者函数名",
             "file": "调用者文件路径",
             "line": 150
           }
         ],
         "key_semantics": ["关键语义说明列表"],
         "resources": {
           "memory": [{"action": "分配/释放/泄露风险", "target": "目标对象", "ownership": "所有权归属"}],
           "file_descriptors": [],
           "locks": [],
           "handles": [],
           "global_variables": []
         },
         "error_paths": [
           {
             "location": "出错行号",
             "condition": "触发错误的条件分支",
             "description": "错误处理流程",
             "resource_cleanup": "资源清理释放动作"
           }
         ],
         "contracts": {
           "preconditions": ["前置条件"],
           "postconditions": ["后置状态"],
           "invariants": []
         },
         "side_effects": {
           "io_operations": [],
           "global_state_modifications": [],
           "thread_effects": "线程级影响"
         },
         "security_notes": [
           {
             "severity": "高/中/低",
             "issue": "问题描述",
             "location": "代码位置",
             "impact": "安全后果"
           }
         ]
       }
       ```
    
    2. **由静态分析引擎规则自动生成的平凡/轻量级快照 (Lightweight/Trivial Snapshots)**：
       对应简单包装函数或宏定义，结构扁平，仅包含：
       `type` ("function_snapshot")、`func_name`、`location`、`file_path`、`start_line`、`end_line`、`signature`、`summary`、`snapshot_kind`、`is_trivial`、`code`、`inputs`、`outputs`、`resources` (字典型，如 `{"allocation": "...", "ownership": "..."}` )、`error_handling`、`concurrency`、`semantic_fingerprint`、`suspicious_points`、`callees` (字符串数组，如 `["func_a", "func_b"]`)。不含 `callers` 等动态键。

### 3. `list_known_functions`
* **工具说明**：列出项目索引中匹配正则表达式的已知函数名。
* **输入参数 (Inputs)**：
  - `pattern` (string, 选填): 用于过滤函数名的正则表达式。
  - `limit` (integer, 选填, 默认 50): 限制最大返回数量。
* **输出数据 (Outputs)**：
  - 执行成功返回 `{"success": true, "data": {...}}`，其中 `data` 结构如下：
    ```json
    {
      "functions": ["函数名1", "函数名2"], // 匹配到的已知函数名数组
      "count": 2, // 匹配到的总数
      "pattern": "正则表达式" // 本次过滤使用的正则
    }
    ```

### 4. `get_file_snippet`
* **工具说明**：获取源文件指定行数范围的代码片段。
* **输入参数 (Inputs)**：
  - `file_path` (string, **必填**): 相对于源码根目录的源文件路径，如 `src/main.c`。
  - `start_line` (integer, **必填**): 截取的起始行号（从 1 开始，包含）。
  - `end_line` (integer, **必填**): 截取的结束行号（从 1 开始，包含）。若小于起始行或未填，默认至多返回 200 行。
* **输出数据 (Outputs)**：
  - 执行成功返回 `{"success": true, "data": {...}}`，其中 `data` 结构如下：
    ```json
    {
      "file": "标准化后的文件路径",
      "start_line": 10,
      "end_line": 20,
      "code": "10 | int a = 1;\n11 | return a;\n..." // 附带行号前缀的纯代码片段
    }
    ```

### 5. `get_callers`
* **工具说明**：寻找并获取调用了目标函数的所有上游调用者列表。
* **输入参数 (Inputs)**：
  - `func_name` (string, **必填**): 目标函数名。
  - `limit` (integer, 选填, 默认 20): 返回的调用者记录行数上限。
* **输出数据 (Outputs)**：
  - 执行成功返回 `{"success": true, "data": {...}}`，其中 `data` 结构如下：
    ```json
    {
      "callers": [
        {
          "name": "调用者函数名称",
          "filename": "调用者源文件名",
          "callee_filename": "被调用函数所在的源文件名",
          "lineNumber": 150 // 调用发生的具体代码行号
        }
      ],
      "count": 1
    }
    ```

### 6. `get_type_info`
* **工具说明**：检索 struct/union/enum 的类型定义和数组成员结构。
* **输入参数 (Inputs)**：
  - `type_name` (string, **必填**): 目标数据类型的名称。
* **输出数据 (Outputs)**：
  - 执行成功返回 `{"success": true, "data": {...}}`，其中 `data` 结构如下：
    ```json
    {
      "id": 43,
      "name": "类型名称",
      "kind": "class/struct/union/enum",
      "file_path": "定义文件路径",
      "start_line": 117,
      "end_line": 128,
      "full_definition": "类型定义的具体源码段（若可用）",
      "tu_id": 12, // 编译单元 ID (Translation Unit ID)
      "members": [
        {
          "member_name": "成员名",
          "member_type": "成员类型",
          "offset_idx": 0 // 成员顺序/字节偏移量索引
        }
      ]
    }
    ```
  - **`tu_id`（编译单元标识符）**：关联到 C 语言物理源编译文件（`.c` 等）的外键，主要供系统在源码文件发生改动时，用来执行局部增量索引的清理和重新构建。

### 7. `get_call_graph`
* **工具说明**：获取指定函数周围的调用图（同时包含上游 callers 和下游 callees）。
* **输入参数 (Inputs)**：
  - `func_name` (string, **必填**): 目标函数名。
  - `depth` (integer, 选填, 默认 1): 调用图遍历层级深度。
  - `limit` (integer, 选填, 默认 30): 返回的节点数上限。
* **输出数据 (Outputs)**：
  - 执行成功返回 `{"success": true, "data": {...}}`，其中 `data` 结构如下：
    ```json
    {
      "function": "目标函数名称",
      "callers": [
        {
          "name": "上游调用者函数名",
          "filename": "文件",
          "lineNumber": 100
        }
      ],
      "callees": [
        {
          "name": "下游被调用子函数名",
          "filename": "文件",
          "lineNumber": 120,
          "call_type": "direct" // 调用类型：direct (直接调用) 或 indirect (间接函数指针调用)
        }
      ]
    }
    ```

### 8. `get_data_flow`
* **工具说明**：追踪特定输入参数（Source）到接收端（Sink）的数据流动关系（污点传播路径）。
* **输入参数 (Inputs)**：
  - `source_func` (string, **必填**): 数据流起点所在的函数。
  - `source_param` (string, **必填**): 数据流起点的参数名或位置。
  - `sink_pattern` (string, **必填**): 汇聚汇入点匹配特征（如危险函数调用名）。
* **输出数据 (Outputs)**：
  - 执行成功返回 `{"success": true, "data": {...}}`，其中 `data` 结构如下：
    ```json
    {
      "flows": [
        {
          "path": [
            {
              "code": "数据流或污点流经的代码/语句",
              "lineNumber": 85,
              "filename": "源文件相对路径"
            }
          ]
        }
      ],
      "count": 1
    }
    ```

### 9. `find_function_pointers`
* **工具说明**：查找函数指针赋值和回调函数注册的具体代码位置。
* **输入参数 (Inputs)**：
  - `func_name` (string, **必填**): 目标函数名称。
* **输出数据 (Outputs)**：
  - 执行成功返回 `{"success": true, "data": {...}}`。
  - **后端依赖的表现差异**：
    由于使用的静态分析后端不同，返回的 `references` 数组里的字段会有所区别：
    
    1. **若当前处于 Joern 后端**，其数据结构如下：
       ```json
       {
         "references": [
           {
             "code": "包含函数指针赋值或取地址的源码行内容",
             "filename": "发现引用的源文件名",
             "lineNumber": 220
           }
         ],
         "count": 1
       }
       ```
       
    2. **若当前处于 Clang 或 Unified 后端**，其数据结构如下：
       ```json
       {
         "references": [
           {
             "caller": "调用了该函数指针的函数名",
             "file": "发现引用的源文件名",
             "line": 220
           }
         ],
         "count": 1
       }
       ```

### 10. `query_pointer_alias`
* **工具说明**：查询 SVF Andersen 指针分析解析出的间接调用（函数指针）的实际指向目标列表。
* **输入参数 (Inputs)**：
  - `func_name` (string, **必填**): 包含函数指针间接调用的函数名。
  - `limit` (integer, 选填, 默认 30): 返回的目标条数上限。
* **输出数据 (Outputs)**：
  - 执行成功返回 `{"success": true, "data": {...}}`，其中 `data` 结构如下：
    ```json
    {
      "function": "查询的函数名",
      "indirect_callees": [
        {
          "name": "可能的真实目标函数名",
          "source": "分析来源 (如 andersen/saber)",
          "confidence": 1.0,
          "svf_group": 1,
          "svf_groups": [1],
          "call_file": "发生间接调用的源文件相对路径",
          "call_line": 40
        }
      ],
      "count": 1
    }
    ```

### 11. `verify_taint_reachability`
* **工具说明**：查询 SVF Saber 静态缺陷检测引擎发现的污点可达性缺陷（内存泄漏/UAF/双重释放等）。
* **输入参数 (Inputs)**：
  - `bug_type` (string, 选填): 缺陷类别过滤（如 `leak`/`uaf`/`doublefree`）。如果不传入，返回所有检测到的缺陷。
  - `limit` (integer, 选填, 默认 50): 限制条数。
* **输出数据 (Outputs)**：
  - 执行成功返回 `{"success": true, "data": {...}}`，其中 `data` 结构如下：
    ```json
    {
      "bugs": [
        {
          "bug_type": "缺陷类别，例如 doublefree/leak",
          "source_func": "产生污点的起点函数",
          "sink_func": "触发缺陷的终点/汇聚点函数",
          "file_path": "缺陷报告文件路径",
          "line": 55,
          "tool": "静态检测工具（如 saber）",
          "svf_group": 1,
          "svf_groups": [1]
        }
      ],
      "count": 1
    }
    ```

### 12. `get_deep_call_context`
* **工具说明**：高级高聚合检索工具，一次性查询并合并返回函数原型签名、控制流调用图、函数指针间接别名调用及污点检测报告，避免模型多次反复往返调用。
* **输入参数 (Inputs)**：
  - `func_name` (string, **必填**): 目标函数名称。
* **输出数据 (Outputs)**：
  - 执行成功返回 `{"success": true, "data": {...}}`，其中 `data` 结构如下：
    ```json
    {
      "function": "查询的函数名",
      "method_info": { // 函数的基本信息，可能为 null
        "name": "目标函数名",
        "filename": "所在文件相对路径",
        "lineNumber": 50,
        "lineNumberEnd": 80,
        "signature": "原型签名"
      },
      "callers": [ /* 同 get_callers */ ],
      "callees": [ /* 同 get_call_graph 中的 callees，含 call_type */ ],
      "indirect_callees": [ /* 同 query_pointer_alias 中的 indirect_callees */ ],
      "taint_bugs": [ /* 该函数路径中涉及的污点缺陷列表（同 verify_taint_reachability 中的 bugs） */ ]
    }
    ```

## 二、不同 Agent 可使用的工具集合

### 1. semantic_modeler

默认步骤：

- `premodel_reachable_callees`
- `model_entry`

默认 active skill：

- `code_semantic_modeling`

Agent 声明工具：

| 工具 | 说明 |
|---|---|
| `get_function_impl` | 获取函数实现 |
| `get_function_snapshot` | 获取函数语义快照 |
| `list_known_functions` | 列出已知函数 |
| `get_file_snippet` | 获取文件片段 |
| `get_callers` | 获取调用者 |
| `get_type_info` | 获取类型信息 |

默认运行时有效工具：

| 工具 | 来源 |
|---|---|
| `get_function_impl` | Agent tools ∩ `code_semantic_modeling` |
| `get_function_snapshot` | Agent tools ∩ `code_semantic_modeling` |
| `get_file_snippet` | Agent tools ∩ `code_semantic_modeling` |
| `get_callers` | Agent tools ∩ `code_semantic_modeling` |
| `get_type_info` | Agent tools ∩ `code_semantic_modeling` |

说明：`list_known_functions` 在 Agent 声明中存在，但不在 `code_semantic_modeling.allowed_tools` 中，因此默认建模流程下运行时不可见。

### 2. skill_selection

默认步骤：

- `focused_subagent_planning` 前的 skill routing
- `vulnerability_mining` 前的 skill routing

工具集合：

| 类型 | 工具 |
|---|---|
| 本地工具 | 无 |

说明：`skill_selection` 是一次 LLM 分类调用，用于选择 vulnerability skills；它不进入工具调用循环。

### 3. deep_worker

默认步骤：

- `focused_subagent_planning` 中由 `vulnerability_analyzer` 生成 ticket 后派生执行

Agent 声明工具：

| 工具 | 说明 |
|---|---|
| `get_function_snapshot` | 获取函数语义快照 |
| `list_known_functions` | 列出已知函数 |
| `get_file_snippet` | 获取文件片段 |
| `get_callers` | 获取调用者 |
| `get_type_info` | 获取类型信息 |
| `get_call_graph` | 获取调用图 |
| `get_data_flow` | 查询数据流 |
| `query_pointer_alias` | 查询指针别名 |
| `verify_taint_reachability` | 验证污点可达性 |

默认 broad vulnerability skill selection 下的有效工具：

| 工具 | 来源 |
|---|---|
| `get_function_snapshot` | Agent tools ∩ active vulnerability skills |
| `get_file_snippet` | Agent tools ∩ active vulnerability skills |
| `get_callers` | Agent tools ∩ active vulnerability skills |
| `get_type_info` | Agent tools ∩ active vulnerability skills |
| `get_call_graph` | Agent tools ∩ active vulnerability skills |
| `get_data_flow` | Agent tools ∩ active vulnerability skills |
| `query_pointer_alias` | Agent tools ∩ active vulnerability skills |
| `verify_taint_reachability` | Agent tools ∩ active vulnerability skills |

说明：`list_known_functions` 在 Agent 声明中存在，但当前 vulnerability skills 未声明该工具，因此默认 broad skill selection 下运行时不可见。

### 4. vulnerability_analyzer

默认步骤：

- `focused_subagent_planning`
- `vulnerability_mining`

默认 active skills：

- `bounds_and_integer`
- `resource_lifecycle`
- `temporal_memory`
- `null_and_failure`
- `stack_escape`
- `concurrency_lock_order`
- `shared_state_race`
- `ownership_contract`
- `string_and_format`

Agent 声明工具：

| 工具 | 说明 |
|---|---|
| `get_function_snapshot` | 获取函数语义快照 |
| `list_known_functions` | 列出已知函数 |
| `get_file_snippet` | 获取文件片段 |
| `get_callers` | 获取调用者 |
| `get_type_info` | 获取类型信息 |
| `get_call_graph` | 获取调用图 |
| `get_data_flow` | 查询数据流 |
| `find_function_pointers` | 查找函数指针 |
| `query_pointer_alias` | 查询指针别名 |
| `verify_taint_reachability` | 验证污点可达性 |
| `get_deep_call_context` | 获取深层调用上下文 |

默认 broad vulnerability skill selection 下的有效工具：

| 工具 | 来源 |
|---|---|
| `get_function_snapshot` | Agent tools ∩ active vulnerability skills |
| `get_file_snippet` | Agent tools ∩ active vulnerability skills |
| `get_callers` | Agent tools ∩ active vulnerability skills |
| `get_type_info` | Agent tools ∩ active vulnerability skills |
| `get_call_graph` | Agent tools ∩ active vulnerability skills |
| `get_data_flow` | Agent tools ∩ active vulnerability skills |
| `find_function_pointers` | Agent tools ∩ active vulnerability skills |
| `query_pointer_alias` | Agent tools ∩ active vulnerability skills |
| `verify_taint_reachability` | Agent tools ∩ active vulnerability skills |

说明：

- `list_known_functions` 在 Agent 声明中存在，但当前 vulnerability skills 未声明该工具，默认运行时不可见。
- `get_deep_call_context` 在 Agent 声明中存在，但当前 skills 未声明该工具，默认运行时不可见。
- `get_function_impl` 出现在多个 vulnerability skill 中，但不在 `vulnerability_analyzer` 的 Agent tools 中，因此默认运行时不可见。

### 5. validator_agent

默认步骤：

- `validate_findings`

默认 active skill：

- `evidence_validation`

Agent 声明工具：

| 工具 | 说明 |
|---|---|
| `get_function_impl` | 获取函数实现 |
| `get_function_snapshot` | 获取函数语义快照 |
| `list_known_functions` | 列出已知函数 |
| `get_file_snippet` | 获取文件片段 |
| `get_callers` | 获取调用者 |
| `get_type_info` | 获取类型信息 |
| `get_call_graph` | 获取调用图 |

默认运行时有效工具：

| 工具 | 来源 |
|---|---|
| `get_function_impl` | Agent tools ∩ `evidence_validation` |
| `get_function_snapshot` | Agent tools ∩ `evidence_validation` |
| `list_known_functions` | Agent tools ∩ `evidence_validation` |
| `get_file_snippet` | Agent tools ∩ `evidence_validation` |
| `get_type_info` | Agent tools ∩ `evidence_validation` |
| `get_call_graph` | Agent tools ∩ `evidence_validation` |

说明：`get_callers` 在 Agent 声明中存在，但不在 `evidence_validation.allowed_tools` 中，因此默认验证流程下运行时不可见。

### 6. issue_reconciler_agent

默认步骤：

- `persist_report` 中的语义去重/问题合并

Agent 声明工具：

| 类型 | 工具 |
|---|---|
| Agent tools | 无 |

实际可调用工具：

| 类型 | 工具 |
|---|---|
| 本地工具 | 无 |

说明：`issue_reconciler_agent` 的 Agent 构造函数传入 `tools=[]`，因此即使 policy 层可能从 `evidence_validation` 推导出 allowed tools，实际工具 schema 为空，不能发起本地工具调用。

## 三、非默认 Workflow 中出现的 Agent

### alert_verifier

用途：

- 交叉验证第三方静态分析告警。

Agent 声明工具：

| 工具 |
|---|
| `get_function_impl` |
| `get_function_snapshot` |
| `list_known_functions` |
| `get_file_snippet` |
| `get_callers` |
| `get_type_info` |
| `get_call_graph` |

默认 skill：

- `evidence_validation`

按当前 policy 规则推导的有效工具：

| 工具 |
|---|
| `get_function_impl` |
| `get_function_snapshot` |
| `list_known_functions` |
| `get_file_snippet` |
| `get_type_info` |
| `get_call_graph` |

说明：`get_callers` 会被 `evidence_validation` 的 allowed tools 过滤掉。

## 四、按 Skill 划分的 allowed_tools

| Skill | allowed_tools |
|---|---|
| `code_semantic_modeling` | `get_function_impl`, `get_function_snapshot`, `get_file_snippet`, `get_callers`, `get_type_info` |
| `evidence_validation` | `get_function_impl`, `get_function_snapshot`, `list_known_functions`, `get_file_snippet`, `get_call_graph`, `get_type_info` |
| `bounds_and_integer` | `get_function_impl`, `get_function_snapshot`, `get_file_snippet`, `get_type_info`, `get_data_flow`, `verify_taint_reachability` |
| `resource_lifecycle` | `get_function_impl`, `get_function_snapshot`, `get_file_snippet`, `get_call_graph`, `get_callers`, `get_type_info`, `verify_taint_reachability` |
| `temporal_memory` | `get_function_impl`, `get_function_snapshot`, `get_file_snippet`, `get_call_graph`, `query_pointer_alias`, `verify_taint_reachability` |
| `null_and_failure` | `get_function_impl`, `get_function_snapshot`, `get_file_snippet`, `get_type_info`, `get_callers` |
| `stack_escape` | `get_function_impl`, `get_file_snippet`, `get_callers`, `get_call_graph` |
| `concurrency_lock_order` | `get_function_impl`, `get_function_snapshot`, `get_file_snippet`, `get_call_graph`, `get_callers`, `get_type_info` |
| `shared_state_race` | `get_function_impl`, `get_function_snapshot`, `get_file_snippet`, `get_call_graph`, `get_callers`, `find_function_pointers`, `query_pointer_alias` |
| `ownership_contract` | `get_function_impl`, `get_function_snapshot`, `get_callers`, `get_call_graph`, `get_type_info` |
| `string_and_format` | `get_function_impl`, `get_file_snippet`, `get_data_flow`, `get_type_info` |

## 五、工具可见性优化关注点

| 现象 | 说明 |
|---|---|
| Agent 声明了工具但默认运行时不可见 | 例如 `semantic_modeler.list_known_functions`、`validator_agent.get_callers`、`vulnerability_analyzer.get_deep_call_context`。原因是 active Skill allowed_tools 未包含这些工具。 |
| Skill 声明了工具但 Agent 未声明 | 例如 vulnerability skills 中的 `get_function_impl` 对 `vulnerability_analyzer` 不可见。原因是 Agent tools 与 Skill tools 取交集。 |
| `issue_reconciler_agent` 无工具 | 它是纯 LLM 语义合并/去重 Agent，当前实现没有向其传入工具列表。 |
| 后端能力会进一步过滤工具 | 框架会检测 `code_index.backend_name` 是否包含在 `["joern", "svf", "unified"]` 中。如果使用非高级后端（如轻量级正则 `regex` 后端），这 6 个图分析与重型分析工具（`get_call_graph`, `get_data_flow`, `find_function_pointers`, `query_pointer_alias`, `verify_taint_reachability`, `get_deep_call_context`）将被强行从工具池中剥离，仅保留 6 个基础检索工具。 |
