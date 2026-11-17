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

Z-SCOPE 运行时支持的全部本地工具共 13 个，其 OpenAI Schema 声明与参数校验在 [runtime.py](../zscope/tools/runtime.py) 中定义，功能涵盖代码基础检索、图结构查询、底层指针与污点静态分析等。以下是每个工具的详细输入参数和输出数据结构：

### 1 `get_function_info`

* **工具说明**：按函数名、限定名或 canonical `index_name` 返回函数/函数式宏的 identity 与调用边元数据。普通项目函数不返回源码；function-like macro 额外返回完整定义源码。全局变量、宏、类型及其 truncation 元数据不属于此工具输出。
* **输入参数 (Inputs)**：
  - `func_name` (string, **必填**): 函数名称、限定名或已有 `index_name`。
  - `file_path` (string, 选填): 用于同名函数或宏消歧。
* **输出数据 (Outputs)**：
  - 成功时返回全部候选，工具不擅自选择：
    ```json
    {
      "success": true,
      "data": {
        "match_count": 1,
        "matches": [
          {
            "function_name": "Target",
            "file_path": "src/shared.c",
            "index_name": "Target@src/shared.c:1-20",
            "start_line": 1,
            "end_line": 20,
            "signature": "int Target(void)",
            "is_static": false,
            "is_macro": false,
            "project_callees": [],
            "external_callees": []
          }
        ]
      }
    }
    ```
  - 每个 match 均不包含 `referenced_globals`、`referenced_macros`、`referenced_types`、`unresolved_referenced_types`，也不包含这三类字段的 truncation 元数据。
  - `match_count` 与 `matches` 长度一致；大于 1 表示调用方必须用 `index_name` 或 `file_path` 消歧。
  - 若非空 `file_path` 的限定查询零命中，工具自动以相同 `func_name` 重试一次无路径查询。重试命中时，顶层附加 `file_path_fallback`，其中包含原路径、原因和提示；返回的仍是全部候选。
  - `project_callees` 仅含项目函数调用边；`external_callees` 仅含外部调用边。`call_type` 为 `direct` / `indirect` 的数组。调用者关系由独立的 `get_callers` 提供。
  - 项目函数和 function-like macro 均未命中时，工具查询用户配置的外部函数描述；仍未命中则返回 `{"success": false, "error": ...}`。对象式宏不作为 match 返回。
  - macro match 的 `is_macro=true`，并额外含完整 `code`；它同样不返回 globals/macros/types 及相关 truncation 字段。

### 1.1 `get_function_impl`（已弃用）
* **工具说明**：根据函数名、签名或 `index_name` 获取函数或宏实现源码。工具保留原始查询，CodeIndex 先执行精确匹配，仅在零命中时进行受控 simple-name fallback。
* **输入参数 (Inputs)**：
  - `func_name` (string, **必填**): 目标函数名称、签名或已有 `index_name`。
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
      "is_static": false,
      "truncated": false, // 是否被截断
      "comment_blocks": [
        {
          "kind": "comment kind", // 如 header/implementation
          "code": "注释的具体文本"
        }
      ]
    }
    ```
  - **`index_name`**：符号索引库中的唯一主键，统一使用 `func_name@file_path:start_line-end_line`。精确签名和位置键优先参与查询，只有精确查询失败后才提取简单名 fallback。
  - **`signature`**：从编译器 AST/分析引擎中提取的完整 C 语言原型声明（包含返回类型、形参类型和参数名，如 `int td_init(const char* config_str)`）。
  - **`is_static`**：普通项目函数始终返回 bool。`true` 表示函数具有 `static` storage class，`false` 表示没有；该字段不表示函数是否 `inline`、是否定义在头文件中或是否可由当前调用图到达。function-like macro 和 external function 省略该字段。
  - 从签名或陈旧位置键降级出的 fallback 只有一个候选时返回该实现；如果产生多个 overload，工具不会静默选择错误实现。调用方原本只传简单名时继续保持现有确定性选择行为。
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

### 2. `get_function_snapshot`

* **工具说明**：解析唯一函数 identity 后读取当前语义 snapshot。注入 on-demand resolver 时，resolver 自行处理缓存检查和缺失/过期 snapshot 的构建。
* **输入参数 (Inputs)**：
  - `func_name` (string, **必填**): 函数名称、签名片段或 canonical `index_name`。无 resolver 时，工具先规范化该值以完成 snapshot 查询。
  - `file_path` (string, 选填): 用于函数 identity 消歧。
* **无 resolver 的查询行为**：
  - 工具先用 `build_semantic_model_input()` 解析唯一 identity、源码和当前 symbol context；解析失败时外层返回 `success=false` 及稳定 `reason`，例如 `function_info_not_found`、`function_info_ambiguous` 或 `function_impl_not_found`。
* **输出数据 (Outputs)**：
  - **命中当前有效 snapshot** 时，`data` 是完整语义 snapshot，而非 function-info 简表：
    ```json
    {
      "success": true,
      "data": {
        "func_name": "parse_request",
        "index_name": "parse_request@src/parser.c:40-120",
        "file_path": "src/parser.c",
        "start_line": 40,
        "end_line": 120,
        "signature": "int parse_request(Request *request)",
        "snapshot_kind": "LLM-modeled",
        "is_static": true,
        "is_macro": false,
        "referenced_globals": [],
        "referenced_macros": [],
        "referenced_types": [],
        "summary": "校验并解析请求对象。",
        "parameters": [],
        "return_values": {"return_type": "int"},
        "effects": [],
        "error_handling": {"error_paths": []},
        "project_callees": [],
        "external_callees": [],
        "suspicious_points": []
      }
    }
    ```
    snapshot 的 symbol context（globals/macros/types）是 snapshot 自身的一部分，不受 `get_function_info` 输出过滤影响。
  - **snapshot 缺失或 stale** 时，外层返回 `data: null`、`snapshot_status`（`missing` 或 `stale`）和消息；并以**原始** `get_function_snapshot` 的 `func_name` 与可选 `file_path` 直接执行一次 `get_function_info`。其完整对象响应不做选择、裁剪或重塑，原样作为 `function_info` 字段的值；字段结构直接见第 1.1 节，不在此重复。
  - stale 响应的结构相同，但 `snapshot_status` 为 `stale`、消息为 `Saved snapshot is stale and must be rebuilt.`。当前外层响应不暴露 refresh reason。
  - 因为 `function_info` 是完整工具响应，它可以保留 `match_count>1`、`file_path_fallback`，或嵌套的 `success=false`；调用方必须检查该嵌套结果，不能假设它是单个 canonical match。
* **On-demand resolver 行为**：
  - resolver 接收规范化后的 `func_name` 与 `file_path`，并可直接返回有效 snapshot 或在缺失/过期时构建、保存后返回。
  - resolver 的返回由 resolver 定义；上述本地 `function_info` fallback 仅适用于未注入 resolver 的路径。
* **Snapshot 内容与存储**：
  - snapshot 本身仍保存 identity/provenance、程序提取的 symbol context 与语义字段；这与 `get_function_info` 的精简输出相互独立。
  - SnapshotStore、JSON 文件、refresh 与锁均以完整 `index_name` 为键；`file_path` 仅用于查询消歧和展示。

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
* **工具说明**：查询唯一普通函数或 function-like macro 的上游调用者，并按 canonical caller identity 聚合调用位置和 direct/indirect 调用类型。
* **输入参数 (Inputs)**：
  - `func_name` (string, **必填**): 函数/宏名称、qualified name 或 canonical `index_name`。
  - `file_path` (string, 选填): 目标函数或宏所在源文件，用于同名目标消歧。
  - caller 上限由工具内部固定为 20，不作为输入参数暴露。
* **输出数据 (Outputs)**：
  - 执行成功返回 `{"success": true, "data": {...}}`，其中 `data` 结构如下：
    ```json
    {
      "callers": [
        {
          "caller_index_name": "Caller@src/caller.c:10-40",
          "callsite_lines": [21, 27],
          "call_type": ["direct", "indirect"]
        }
      ]
    }
    ```
  - 结果以 `caller_index_name` 聚合，`callsite_lines` 去重并升序排列；caller identity 无法解析时降级保留后端 caller name。
  - `call_type` 是数组，值限定为 `direct`、`indirect`；同一 caller 同时存在两类调用边时完整保留 `["direct", "indirect"]`。
  - 聚合完成后最多返回 20 个 caller records。历史调用即使额外传入 `limit`，也不会改变固定上限。
  - 普通函数未命中时会回退查询 function-like macro；同名同文件的条件编译宏定义按一个宏符号目标聚合，因为调用边不携带具体宏定义行或预处理分支绑定。
  - 同名宏分布在多个文件时仍视为歧义；提供 `file_path` 或精确宏 `index_name` 后再查询。
  - 目标零命中时返回 `success=false`、`reason=function_not_found`；目标存在歧义时返回 `reason=ambiguous_function`，调用方应提供 `file_path` 或 `index_name`。
  - 唯一目标没有 caller 时返回成功和空数组。

### 6. `get_type_info`
* **工具说明**：检索 struct/union/enum/typedef/class 类型定义；同名类型可以返回多个候选，每个候选包含完整源码定义。
* **输入参数 (Inputs)**：
  - `type_name` (string, **必填**): 类型名称或 qualified type name。
  - `file_path` (string, 选填): 类型声明所在的源文件或头文件，用于同名类型消歧。
* **输出数据 (Outputs)**：
  - 执行成功返回 `{"success": true, "data": {...}}`，其中 `data` 结构如下：
    ```json
    {
      "match_count": 2,
      "matches": [
        {
          "name": "State",
          "kind": "struct",
          "file_path": "include/state.h",
          "start_line": 117,
          "end_line": 128,
          "full_definition": "struct State { int status; };"
        }
      ]
    }
    ```
  - 单命中也返回 `match_count=1` 和单元素 `matches`；多命中属于成功结果。
  - 已知声明文件时应传入 `file_path`；路径限定查询零命中时，Tool 自动执行一次无 `file_path` 查询。若无路径查询命中，顶层返回包含 `reason=file_path_not_matched`、原始 `requested_file_path` 和明确提示的 `file_path_fallback`，并在 `data.matches` 中直接返回全部无路径候选；无路径查询仍零命中时才返回未命中。
  - `full_definition` 是类型主体的唯一公开表示，保留 typedef、嵌套类型、数组、位域、函数指针和属性等源码语义；Tool 不再重复返回派生的 `members`。
  - Tool 输出不包含数据库内部主键 `id` 或增量索引外键 `tu_id`。

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
## get_function_info 的输出边界

`CodeIndex.find_function_infos()` 仍在内部维护并供 semantic-model input 使用 globals、macros 和 types 上下文；`get_function_info` 仅在工具输出边界过滤它们。因此每个公开 match 不包含 `referenced_globals`、`referenced_macros`、`referenced_types`、`unresolved_referenced_types`，以及三类对应的 truncation 字段。

`project_callees` 与 `external_callees` 继续保留在工具输出中。前者只包含真实项目函数调用边，后者只包含外部调用边；调用者关系仍应使用 `get_callers` 查询。

`get_function_snapshot` 的 missing/stale fallback 直接嵌入一次 `get_function_info` 的完整响应，所以同样不会重新暴露这些被过滤的字段。类型定义的详细查询应使用 `get_type_info`；snapshot 本身的 symbol context 与此工具输出边界相互独立。
