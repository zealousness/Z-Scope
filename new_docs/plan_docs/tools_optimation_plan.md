# 工具优化计划

本文按以下五条工作流重新组织工具优化计划：一、新增 `get_function_info`；二、simple-name fallback；三、`is_static` 输出扩展；四、`get_callers` 重构；五、`get_type_info` 重构。除特别标注为“已实施”的章节外，其余内容均为实施计划；全程不修改任何 fallback 文件。

## 一、新增 `get_function_info`

### 1.1 设计结论

#### 1.1.1 保留方向

新增 `get_function_info`，用于查询函数的结构化元信息；代码正文仍由 `get_file_snippet` 读取。

建议分工如下：

| 工具 | 职责 | 是否返回代码正文 |
|---|---|---|
| `get_function_info` | 按函数名和可选文件路径查询函数身份、位置、签名、调用者、被调用者 | 否 |
| `get_file_snippet` | 按文件路径和行号读取源码片段 | 是 |
| `get_function_snapshot` | 返回较高层的函数摘要和安全相关上下文 | 否或少量摘要 |
| `get_function_impl` | 过渡期兼容旧流程，后续降级或删除 | 是 |

这样可以避免一个工具一次返回大量代码、签名、callee、comment、外部函数信息，导致 token 成本过高；同时也避免把函数定位能力完全压到 `get_file_snippet` 上，因为 snippet 本身不知道函数名、签名、同名函数数量和调用关系。

#### 1.1.2 关于歧义判断

不需要额外返回 `ambiguous` 字段。LLM 可以直接根据 `match_count` 判断：

| `match_count` | 含义 | 建议行为 |
|---:|---|---|
| 0 | 未找到函数 | 不应继续盲目读取代码；可改用更精确函数名或 `list_known_functions` |
| 1 | 唯一命中 | 可直接用该 match 的 `file_path`、`start_line`、`end_line` 调用 `get_file_snippet` |
| >1 | 存在同名/重载/路径歧义 | 需要结合调用链、候选文件、entry evidence 或用户上下文选择目标 |

#### 1.1.3 关于 `index_name`

`index_name` 应作为函数索引中的稳定身份字段返回。当前 `CodeIndex` 中函数记录存储在 `_function_index`，写入时会调用 `_unique_function_index_key()` 生成 `index_name`，形式可能包括：

- `Target`
- `Item::Item(int value)`
- `Target@src/a/shared.c:1`
- `Target@src/shared.c:1#2`

需要注意，当前 `CodeIndex.get_function_impl()` 返回结果中存在设计问题：

```python
"func_name": lookup_name,
"index_name": lookup_name,
```

这里 `func_name` 和 `index_name` 都使用解析后的 `lookup_name`，会混淆“用户查询名”和“索引主键”。`get_function_info` 应避免复用这个语义错误：

| 字段 | 含义 |
|---|---|
| `function_name` | 函数原始/规范名称，用于人读和后续查询 |
| `index_name` | CodeIndex 内部唯一索引键，用于消歧和稳定引用 |
| `file_path` | 归一化后的源码相对路径，用于 `get_file_snippet` |

### 1.2 建议接口

#### 1.2.1 Inputs

| 字段 | 类型 | 必填 | 说明 |
|---|---|---|---|
| `func_name` | string | 是 | 函数名称，可为简单名、限定名或已有 `index_name` |
| `file_path` | string | 否 | 函数所在源文件路径，用于同名函数消歧 |
| `callers_limit` | integer | 否 | 返回调用者数量上限，默认 30 |
| `callees_limit` | integer | 否 | 返回被调用者数量上限，默认 30 |

不加入通用 `limit`。函数名精确查询通常不应返回大量函数匹配；如果后续需要模糊搜索，应由 `list_known_functions` 或新增 `search_functions` 承担。`callers_limit` 和 `callees_limit` 只限制每个 match 下的调用关系数组长度。

#### 1.2.2 Success Output

```json
{
  "success": true,
  "data": {
    "match_count": 2,
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
            "callsite_lines": [100, 125]
          }
        ],
        "callees": [
          {
            "callee_name": "Callee",
            "callee_file": "src/helper.c",
            "callsite_lines": [120],
            "call_type": "direct"
          }
        ]
      }
    ]
  }
}
```

说明：

- `match_count` 等于 `matches` 长度。
- `match_count=0` 仍返回 `success: true`，表示查询正常完成但没有命中；只有参数非法、索引不可用、内部异常才返回 `success: false`。
- `is_external` 维持 `get_function_impl` 的外部函数语义，但默认不返回 `false`。只有命中用户配置的外部函数时，才返回 `is_external: true`。
- `callers` / `callees` 先按调用者或被调用者聚合，再按 `callers_limit` / `callees_limit` 截断；同一函数对的多个调用点统一放入 `callsite_lines`。
- `call_type` 在 `svf` / `unified` 后端可用时支持 `direct` 和 `indirect`；仅 `clang` / `clangd` 能力可用时自动降级为 `direct`，避免把不完整的间接调用推断伪装成 SVF 级别结论。

#### 1.2.3 Not Found Output

```json
{
  "success": true,
  "data": {
    "match_count": 0,
    "matches": []
  }
}
```

#### 1.2.4 External Function Output

```json
{
  "success": true,
  "data": {
    "match_count": 1,
    "matches": [
      {
        "function_name": "malloc",
        "file_path": "[external]",
        "index_name": "malloc",
        "start_line": 0,
        "end_line": 0,
        "signature": "malloc(...)",
        "callers": [],
        "callees": [],
        "is_external": true
      }
    ]
  }
}
```

外部函数只在 `user_config.get_external_function(func_name)` 命中时返回；否则按 not found 处理。

### 1.3 与现有工具的关系

#### 1.3.1 与 `get_function_impl`

`get_function_info` 应覆盖 `get_function_impl` 中除代码正文以外的主要元信息：

| 当前 `get_function_impl` 字段 | 新归属 | 说明 |
|---|---|---|
| `func_name` | `get_function_info.function_name` | 避免继续混用 lookup key |
| `index_name` | `get_function_info.index_name` | 使用真实索引键 |
| `file` | `get_function_info.file_path` | 统一字段名 |
| `start_line` / `end_line` | `get_function_info` | 供 snippet 精确读取 |
| `signature` | `get_function_info` | 元信息 |
| `callees` | `get_function_info.callees` | 结构化调用关系 |
| `comment_blocks` | 暂不迁移 | 后续可考虑独立 `get_function_comments` |
| `code` | `get_file_snippet` | 代码正文不放进 info 工具 |
| `truncated` | `get_file_snippet` | 只和代码读取相关 |
| `is_external` | `get_function_info` | 默认不返回 false |

过渡期可以保留 `get_function_impl`，但在 validator prompt 中降级为 fallback：只有 `get_function_info + get_file_snippet` 无法满足验证时才调用。

#### 1.3.2 与 `get_file_snippet`

`get_file_snippet` 不应该承担函数解析责任。推荐调用顺序为：

1. 调用 `get_function_info(func_name, file_path?)` 定位函数。
2. 如果 `match_count=1`，使用返回的 `file_path/start_line/end_line` 调用 `get_file_snippet`。
3. 如果 `match_count>1`，先选择目标 match，再读取 snippet。
4. 如果 `match_count=0`，不要盲目猜路径读取。

#### 1.3.3 与 `list_known_functions`

`get_function_info` 是精确查询工具，不做模糊搜索；`list_known_functions` 是候选发现工具。两者边界如下：

| 场景 | 推荐工具 |
|---|---|
| 已有明确函数名，想知道位置/签名/调用关系 | `get_function_info` |
| 函数名可能不完整，需要用 pattern 找候选 | `list_known_functions` |
| 已经有文件和行号，需要代码证据 | `get_file_snippet` |
| 需要函数安全摘要 | `get_function_snapshot` |

#### 1.3.4 与 `get_callers`

`get_function_info` 返回 `callers` 后，`get_callers` 会有一定重复。短期建议保留 `get_callers`：

- `get_function_info` 返回的是函数身份查询时顺带的有限调用者信息。
- `get_callers` 可继续作为 reachability 深查工具，支持更大 `limit` 或更复杂的调用者查询。

如果后续指标显示 `get_callers` 调用很少且完全被 `get_function_info` 覆盖，再考虑合并。

### 1.4 初版实现计划

#### 1.4.1 CodeIndex 层新增查询方法

建议新增方法：

```python
def find_function_infos(
    self,
    func_name: str,
    file_path: str = "",
    callers_limit: int = 30,
    callees_limit: int = 30,
) -> List[Dict[str, Any]]:
    ...
```

实现要求：

| 要求 | 说明 |
|---|---|
| 返回所有匹配 | 不像 `_resolve_function_name()` 那样只返回第一个命中 |
| 支持 `file_path` 消歧 | 复用 `_record_matches_file_hint()` 的 suffix/path hint 规则 |
| 保留 `index_name` | 使用 record 中真实 `index_name` 或 `_function_index` key |
| 不返回代码正文 | 只返回位置、签名、调用关系等结构化信息 |
| 命中 external config | 返回单条 external match，并设置 `is_external: true` |
| 调用关系可限长 | `callers_limit` 和 `callees_limit` 默认 30，避免一次查询返回过大 |
| 后端能力降级 | `svf` / `unified` 保留 direct/indirect；`clang` / `clangd` 输出 direct |

匹配逻辑建议：

1. 生成 `func_name` 的 query variants。
2. 遍历 `_function_index` 记录，使用 `_function_record_query_variants(index_key, info)` 判断名称是否匹配。
3. 如果传入 `file_path`，再用 `_record_matches_file_hint(info, file_path)` 过滤。
4. 按精确程度、文件路径、起始行、`index_name` 稳定排序。
5. 对每个 match 查询 callers/callees，先按调用者或被调用者聚合多个调用点，再归一化为 `caller_name/caller_file/callsite_lines` 与 `callee_name/callee_file/callsite_lines/call_type`。
6. 将 record 转换为工具输出字段。

#### 1.4.2 新增工具文件

新增文件：

```text
zscope/tools/function_info.py
```

类名建议：

```python
class GetFunctionInfoTool(BaseTool):
    name = "get_function_info"
```

工具 schema：

```json
{
  "type": "function",
  "function": {
    "name": "get_function_info",
    "description": "Retrieve structured metadata and call relationships for a function by name, optionally scoped by file path.",
    "parameters": {
      "type": "object",
      "properties": {
        "func_name": {
          "type": "string",
          "description": "Function name, qualified name, or index_name"
        },
        "file_path": {
          "type": "string",
          "description": "Optional source file path used to disambiguate same-name functions"
        },
        "callers_limit": {
          "type": "integer",
          "default": 30,
          "description": "Maximum callers returned per matched function"
        },
        "callees_limit": {
          "type": "integer",
          "default": 30,
          "description": "Maximum callees returned per matched function"
        }
      },
      "required": ["func_name"]
    }
  }
}
```

#### 1.4.3 工具注册

需要更新：

| 文件 | 修改 |
|---|---|
| `zscope/core/analysis/analyzer.py` | 在 `_get_tools()` 中导入并注册 `GetFunctionInfoTool` |
| 相关 Agent/Skill 配置 | 先暴露给 `validator_agent` 和 `semantic_modeler` |
| `new_docs/tools_introduction.md` | 补充工具说明 |
| `new_docs/tools_optimation.md` | 记录实施结果 |

#### 1.4.4 Agent 使用策略

validator 推荐顺序：

| 顺序 | 动作 |
|---:|---|
| 1 | 优先使用已有 evidence pack / snapshot |
| 2 | 需要定位函数时调用 `get_function_info` |
| 3 | 需要源码证据时用 `get_file_snippet` 读取精确行段 |
| 4 | 只有前面无法满足时，fallback 到 `get_function_impl` |

semantic_modeler 推荐顺序：

| 顺序 | 动作 |
|---:|---|
| 1 | 已知函数名时调用 `get_function_info` 获取 signature/callees |
| 2 | 需要摘要时调用 `get_function_snapshot` |
| 3 | 需要具体代码片段时调用 `get_file_snippet` |

### 1.5 初版测试计划

#### 1.5.1 单元测试

建议新增或扩展测试：

| 测试 | 预期 |
|---|---|
| 同名函数不同文件，无 `file_path` | `match_count=2`，返回两个 match |
| 同名函数不同文件，传入 `file_path` | `match_count=1`，返回目标文件中的函数 |
| C++ 重载函数 | 返回不同 `index_name`，signature 可区分 |
| 传入已有 `index_name` | 精确返回对应函数 |
| 未找到函数 | `success=true`，`match_count=0` |
| external function 命中 | `is_external=true`，`file_path=[external]` |
| 参数为空 | `success=false` |
| `callers_limit` / `callees_limit` 生效 | 每个 match 下 callers/callees 数量不超过限制 |
| unified/SVF 后端有间接调用 | `call_type` 可返回 `indirect` |
| clang/clangd 后端 | `call_type` 自动降级为 `direct` |

#### 1.5.2 回归指标

引入该工具后，重点观察：

| 指标 | 预期变化 |
|---|---|
| `get_function_impl` 调用次数 | 明显下降 |
| `get_file_snippet` 调用次数 | 可能小幅上升，但每次更精确 |
| validator_agent token | 下降 |
| Loop Guard warning/block | 不上升 |
| Default Recall / Precision | 不下降 |

### 1.6 初版风险与处理

| 风险 | 原因 | 处理 |
|---|---|---|
| `callers` 查询增加 backend 成本 | 每次 info 都查上下游关系 | 默认 `callers_limit=30`、`callees_limit=30`，必要时后续增加 `include_callers` |
| 和 `get_callers` 功能重叠 | 两者都能返回调用者 | 短期保留，基于指标决定是否合并 |
| 同名函数选择错误 | LLM 忽略 `match_count>1` | 在 Agent prompt 中明确多命中时必须说明选择依据 |
| `index_name` 语义混乱延续 | 复用 `get_function_impl` 返回逻辑 | 新方法直接读取 record 的真实 `index_name` |
| 输出过大 | callers/callees 过多 | 默认设置 `callers_limit=30`、`callees_limit=30`，由调用方按需调小 |

### 1.7 初版实施顺序

| 顺序 | 任务 | 产出 |
|---:|---|---|
| 1 | 在 `CodeIndex` 中实现 `find_function_infos()` | 结构化函数信息查询能力 |
| 2 | 新增 `zscope/tools/function_info.py` | `get_function_info` 工具 |
| 3 | 实现 `callers_limit` / `callees_limit` 与 `call_type` 后端降级 | 满足调用关系输出约束 |
| 4 | 注册工具并暴露给目标 Agent/Skill | 默认流程可调用 |
| 5 | 将 `semantic_modeler` / `validator_agent` 的 `AGENT.md` 中 `get_function_impl` 替换为 `get_function_info` | 降低旧工具优先级 |
| 6 | 增加同名函数、file_path、external、not found、limit、call_type 测试 | 防止消歧和调用关系退化 |
| 7 | 小规模 benchmark 对比 | 确认工具调用和 token 成本下降 |
| 8 | 决定是否删除或隐藏 `get_function_impl` | 基于回归指标收尾；本阶段不删除实现 |

### 1.8 阶段性结论

`get_function_info + get_file_snippet` 是比继续扩展 `get_function_impl` 更清晰的设计。前者负责回答“这个函数是谁、在哪里、和谁相连”，后者负责回答“对应源码是什么”。这能保留 `get_function_impl` 中有价值的 signature、line range、caller/callee、external 信息，同时避免每次函数查询都返回完整代码正文。

### 1.9 函数语义上下文扩展计划

#### 1.9.1 目标与边界

扩展 `get_function_info` 的默认 match 输出，使函数身份、callee 和引用符号上下文在一次查询中返回，回答：

- 当前函数实际引用了哪些全局变量；
- 当前函数实际依赖了哪些宏；
- 相关全局变量和宏的声明或定义文件与位置；
- 全局对象在当前函数中是读取、写入还是读写；

该扩展不返回“文件中的全部全局变量”或独立的头文件列表。无关文件级数据会扩大上下文并诱导 Agent 做项目级探索。返回范围必须以当前函数的真实符号引用为边界，符号来源直接通过各条目的 `file_path` 表达。

`get_file_snippet(file_path, 1, 50)` 只保留为查看条件编译、复杂 initializer 或宏附近源码的 fallback，不作为发现全局变量和宏的主要方式。

#### 1.9.2 接口调整

本节定义第二阶段接口修订；与前文初版接口发生冲突时，以本节为准。调整内容：

- 从 `get_function_info` inputs 删除 `callers_limit`和`callees_limit`；
- 从每个 match 删除 `callers`，callers 和向上 reachability 继续由 `get_callers` 提供；
- 后端固定限制每个 match 最多返回 30 个 callees、50 个 referenced globals 和 30 个 referenced macros；
- 只有发生截断时才返回对应截断元数据，未截断时不输出常驻完整度字段；
- 不增加 `include_symbol_context` 开关。每个函数 match 默认直接包含：`referenced_globals`， `referenced_macros`；

以下可选字段只在对应数组被后端固定上限截断时出现：

- `callees_truncation`；
- `referenced_globals_truncation`；
- `referenced_macros_truncation`。

工具不增加 `include_all_file_globals` 参数，也不提供独立的 headers 输出，避免退化为文件浏览接口。

#### 1.9.3 扩展输出

每个 match 默认直接返回引用符号字段，不增加 `semantic_context` 外层：

```json
{
  "function_name": "process_request",
  "file_path": "src/runtime.c",
  "index_name": "process_request@src/runtime.c:120",
  "start_line": 120,
  "end_line": 180,
  "signature": "int process_request(struct request *req)",
  "callees": [],
  "referenced_globals": [
    {
      "name": "g_runtime_state",
      "type": "struct runtime_state *",
      "file_path": "src/runtime.c",
      "line": 42,
      "is_extern": false,
      "access": "read_write",
      "reference_lines": [132, 148]
    }
  ],
  "referenced_macros": [
    {
      "name": "RUNTIME_LOCK",
      "file_path": "include/runtime.h",
      "line": 31,
      "definition": "#define RUNTIME_LOCK(ctx) ...",
      "is_function_like": true,
      "reference_lines": [130]
    }
  ]
}
```

未截断时不输出任何完整度或 truncation 字段。发生截断时，只附加对应数组的元数据，例如：

```json
{
  "callees_truncation": {
    "truncated": true,
    "returned": 30,
    "total": 83
  },
  "referenced_globals_truncation": {
    "truncated": true,
    "returned": 50,
    "total": 73
  },
  "referenced_macros_truncation": {
    "truncated": true,
    "returned": 30,
    "total": 47
  }
}
```

三个字段彼此独立。只有实际被截断的数组才返回对应字段，不能因为其中一个数组截断而给其他数组附加完整度信息。

字段约束：

- `referenced_globals` 只包含当前函数中有引用证据的全局对象。
- `access` 使用 `read`、`write`、`read_write`、`unknown`。
- `reference_lines` 使用去重、升序、1-based 行号。
- `referenced_macros` 只包含当前函数体实际出现或展开的宏。
- 全局变量和宏的来源直接使用条目中的 `file_path` 和 `line` 表达，不增加独立头文件数组。
- `callees` 在确定性排序后最多返回 30 项；发生截断时返回 `callees_truncation`。
- `referenced_globals` 在确定性排序后最多返回 50 项，`referenced_macros` 最多返回 30 项。
- globals 或 macros 发生截断时，分别返回 `referenced_globals_truncation` 或 `referenced_macros_truncation`，不使用共享的 symbol context 完整度字段。
- truncation 对象固定包含 `truncated`、 `returned`和`total`。 `truncated`为布尔型true，`returned`和`total`为非负整数。
- `total` 统计应用固定上限前、完成聚合去重后的最终数组条目数，不统计原始 call edge 或 reference 记录数。callees 先聚合同一 callee 的 callsites，globals/macros 先聚合同一符号的 reference lines，再计算 `total` 和执行截断。

#### 1.9.4 KnowledgeDB 数据层

现有数据库已经包含：

- `global_variables(name, type_str, file_path, line, is_extern)`；
- `macro_definitions(name, file_path, line, definition, is_function_like)`；
- `include_edges(source_file, included_file, line, is_system)`，首期仅作为内部辅助数据，不直接暴露到工具输出。

但这些表只能回答“项目中有哪些符号”，不能回答“某函数实际引用了哪些符号”。需要新增函数到符号的引用关系。建议增加统一表：

```sql
CREATE TABLE function_symbol_refs (
    id                  INTEGER PRIMARY KEY,
    function_name       TEXT NOT NULL,
    function_file       TEXT NOT NULL,
    symbol_name         TEXT NOT NULL,
    symbol_kind         TEXT NOT NULL,
    symbol_file         TEXT DEFAULT '',
    reference_line      INTEGER DEFAULT 0,
    access_kind         TEXT DEFAULT 'unknown',
    UNIQUE(
        function_name,
        function_file,
        symbol_name,
        symbol_kind,
        reference_line
    )
);
```

`symbol_kind` 首期支持 `global` 和 `macro`；后续需要时再扩展 `type`、`enum_constant`、`field`。不要在首期把所有 AST symbol 种类一次纳入。

需要为 `function_name/function_file` 和 `symbol_name/symbol_kind` 建索引，并将表纳入 TU 删除、增量刷新、schema version migration 和数据库统计。

#### 1.9.5 Clang 抽取修正

当前全局变量抽取条件是“变量位于文件前五行或 detail 包含 extern”，存在两个问题：

1. 文件级全局变量可能位于文件任意位置；
2. 无法区分真正的文件作用域变量和函数内部变量。

扩展前应先将判断改为基于 Clang symbol scope/AST parent 的文件作用域识别，不再依赖 `start_line <= 5`。同时建议补充以下可结构化字段：

| 字段 | 首期要求 |
|---|---|
| `storage_class` | `static`、`extern`、普通 global、unknown |
| `qualifiers` | 至少识别 `const`、`volatile`、`atomic` |
| `initializer` | best-effort；过长时截断并标记 |
| `definition_kind` | declaration、definition、unknown |

函数引用关系优先从 Clang AST 的 `DeclRefExpr`、宏展开位置和 def/use 信息提取：

- 引用全局变量时写入 `symbol_kind=global`；
- 根据读写上下文归一化 `access_kind`；
- 宏引用写入 `symbol_kind=macro`；
- 无法从 AST 获取宏引用时，可在函数源码 token 与 `macro_definitions` 之间做精确名称交集。

禁止只根据字符串子串匹配全局变量名，以免字段名、局部变量和注释造成误命中。

#### 1.9.6 CodeIndex 与后端降级

建议新增内部方法：

```python
def get_function_symbol_context(
    self,
    index_name: str,
) -> Dict[str, Any]:
    ...
```

`find_function_infos()` 对每个 match 默认调用该方法，并把 `referenced_globals` 和 `referenced_macros` 直接附加到 match；只有对应数组被截断时再附加独立 truncation 元数据。

第二阶段 `find_function_infos()` 签名调整为：

```python
def find_function_infos(
    self,
    func_name: str,
    file_path: str = "",
) -> List[Dict[str, Any]]:
    ...
```

不再接收 `callers_limit`和`callees_limit`，也不执行 caller 查询。CodeIndex 内部使用固定上限：

- `callees`: 30；
- `referenced_globals`: 50；
- `referenced_macros`: 30。

查询实现必须在截断前获得未截断总数；如果只能使用 `limit + 1` 判断存在更多结果，则需要继续执行计数查询以填写准确的 `total`。不能仅根据返回数组长度推断是否截断。所有集合先按稳定规则排序，再应用固定上限，保证重复调用结果一致。

后端策略：

| 后端 | 行为 |
|---|---|
| `clang` / `unified` | 使用 KnowledgeDB 的结构化引用关系 |
| `joern` | 可从 CPG symbol/reference 查询适配相同输出；未实现前返回空数组，不伪造引用条目 |
| `regex` | 使用函数源码 token 与已知 global/macro 名称的精确交集 |
| external function | 返回空 globals/macros，并依靠现有 `is_external=true` 表明实现不可用 |

缺少后端能力时不能回退为读取文件前 50 行并声称结果完整。

#### 1.9.7 Tool 层兼容性

`GetFunctionInfoTool` 需要：

1. 从工具 schema 和参数校验中删除 `callers_limit`和`callees_limit`；
2. 只向 `CodeIndex.find_function_infos()` 传递 `func_name` 和可选 `file_path`；
3. 每个 match 始终返回 `referenced_globals` 和 `referenced_macros`，无命中时使用空数组；
4. 不返回常驻 complete/limitations 字段；
5. 后端固定上限导致截断时，只保留对应的 `callees_truncation`、`referenced_globals_truncation` 或 `referenced_macros_truncation`；
6. 不返回 `callers`，也不在工具层解析源码或重新推断符号关系。

#### 1.9.8 Agent 使用策略

`semantic_modeler` 推荐流程：

1. 使用 `get_function_info(func_name, file_path?)` 一次获取函数身份、callees、globals 和 macros；
2. 需要 callers 或向上 reachability 时单独调用 `get_callers`；
3. 直接消费 match 顶层的 `referenced_globals` 和 `referenced_macros`；
4. 任一 truncation 字段存在时，不得把对应数组解释为完整集合，并在建模结果中保留相应不确定性；字段不存在只表示未触发固定上限，不代表后端语义抽取绝对完整；
5. 只有 initializer、条件编译或宏定义仍不明确时，才按返回的准确文件和行号调用 `get_file_snippet`；
6. 不使用 `list_known_functions` 发现全局变量或宏。

validator 是否暴露该扩展由后续 validator 优化阶段决定，本阶段不扩大其默认上下文。

#### 1.9.9 测试计划

建议新增以下测试：

| 测试 | 预期 |
|---|---|
| 默认调用不传新参数 | 每个 match 直接包含 globals/macros；未截断时不包含完整度或 truncation 字段 |
| 任意 match 输出 | 不包含 `semantic_context` 和 `callers` |
| 函数读取一个 static global | 返回 `access=read` 和准确 reference line |
| 函数写入一个 extern global | 返回 `access=write`、声明位置和 `is_extern=true` |
| 同一函数先读后写同一 global | 聚合为 `read_write`，reference lines 去重排序 |
| 局部变量与 global 同名 | 不把局部变量误报为 global reference |
| struct field 与 global 同名 | 不发生字符串子串误命中 |
| 函数使用 function-like macro | 返回宏定义、引用行和 `is_function_like=true` |
| 宏来自项目头文件 | 宏条目的 `file_path/line` 指向对应定义位置 |
| callees 超过 30 项 | 返回前 30 项，并只增加 `callees_truncation={truncated: true, returned: 30, total: N}` |
| referenced globals 超过 50 项 | 返回前 50 项，并只增加 `referenced_globals_truncation={truncated: true, returned: 50, total: N}` |
| referenced macros 超过 30 项 | 返回前 30 项，并只增加 `referenced_macros_truncation={truncated: true, returned: 30, total: N}` |
| 仅 macros 被截断 | 不输出 `callees_truncation` 或 `referenced_globals_truncation` |
| 所有数组均未截断 | 不输出任何 complete、limitations 或 truncation 字段 |
| regex fallback | 只返回函数源码 token 与已知 global/macro 名称的精确交集，不产生字符串子串误命中 |
| external function | 不伪造 globals/macros 信息 |
| TU 删除或重建 | 对应 `function_symbol_refs` 被清理并重建 |

#### 1.9.10 指标与验收标准

扩展上线后重点观察：

| 指标 | 预期 |
|---|---|
| semantic_modeler 的 `get_file_snippet` 文件头读取 | 明显下降 |
| semantic_modeler 的 `list_known_functions` 调用 | 降为 0，可从工具列表移除 |
| `get_function_info` 单次返回 token | globals/macros 默认返回但受后端固定上限控制；移除 callers 抵消部分增量 |
| callees/globals/macros 截断率 | 分别记录，确认固定上限主要处理异常大函数而不是常态截断 |
| global/macro 相关 snapshot 字段完整度 | 提升 |
| 全局变量误识别率 | 不高于现有实现，并通过同名局部变量测试 |
| snapshot 建模 token | 不因默认调用增加而上升 |
| benchmark Recall / Precision | 不下降 |

验收条件：

1. 新接口默认直接返回 globals/macros，并完成所有调用方迁移；
2. Clang/unified 后端能够结构化返回函数实际引用的 globals 和 macros；
3. 全局变量和宏通过自身 `file_path/line` 表达来源，不增加独立 headers 输出；
4. fallback 后端只返回可由精确名称交集支持的引用，不伪造未命中的 globals/macros；
5. 任一固定上限触发时，只输出对应数组的 truncation 字段，`truncated=true`，并准确反映聚合去重后的 `returned/total`；
6. semantic_modeler 不再需要通过文件头 snippet 或 `list_known_functions` 获取此类上下文。

#### 1.9.11 实施顺序

| 顺序 | 任务 | 产出 |
|---:|---|---|
| 1 | 修正 Clang 文件作用域 global 抽取 | 可靠的 global 基础数据 |
| 2 | 新增 `function_symbol_refs` 与增量清理逻辑 | 函数到 global/macro 的引用关系 |
| 3 | 实现 Clang 引用、读写和宏使用提取 | 结构化 symbol evidence |
| 4 | 增加 KnowledgeDB 查询与 CodeIndex `get_function_symbol_context()` | 后端无关的归一化结果 |
| 5 | 扩展 `find_function_infos()` 和 `GetFunctionInfoTool` 输出及后端固定上限 | 默认返回 globals/macros，截断时按数组返回 truncation 元数据，且不返回 callers |
| 6 | 增加 regex/joern 降级和 limitation 标记 | 后端能力透明 |
| 7 | 更新 semantic_modeler 使用策略并移除 `list_known_functions` | 收紧 Agent 探索边界 |
| 8 | 完成单元测试、增量缓存测试和小规模 benchmark | 验证准确率与 token 收益 |

### 1.10 `get_function_info` 宏函数查询支持计划

#### 1.10.1 目标与边界

扩展 `get_function_info(func_name, file_path?)`，使其在普通函数索引未命中时能够查询项目中的 function-like macro。宏函数命中后仍放入现有 `matches` 数组，并在普通函数身份字段之外额外返回：

- `is_macro: true`；
- `code`：带 1-based 行号的完整宏定义源码。

本节与前文“`get_function_info` 不返回代码正文”的描述冲突时，以本节为准。普通函数 match 仍不返回 `code`；只有宏函数 match 返回宏定义源码。这样可以让 Agent 直接理解多行宏的替换体，同时避免所有普通函数查询重新携带源码。

本阶段只把 function-like macro 作为“宏函数”返回。对象式宏仍通过普通函数的 `referenced_macros` 暴露，不把 `#define FLAG 1` 一类参数宏伪装成可调用函数。

宏 match 使用独立的最小返回结构，不返回 `callees`、`referenced_globals` 或 `referenced_macros`。仅凭宏定义文本无法可靠区分普通函数调用、嵌套宏调用、函数指针和可调用宏参数，也无法脱离具体展开位置确认标识符是否解析为全局对象。完整 `code` 是宏语义的主要证据，禁止把 best-effort 名称匹配包装成结构化调用或符号引用事实。

#### 1.10.2 返回契约

宏函数查询成功时返回：

```json
{
  "success": true,
  "data": {
    "match_count": 1,
    "matches": [
      {
        "function_name": "ALLOC_WRAP",
        "file_path": "include/macros.h",
        "index_name": "ALLOC_WRAP@include/macros.h:10-12",
        "start_line": 10,
        "end_line": 12,
        "signature": "#define ALLOC_WRAP(sz)",
        "is_macro": true,
        "code": "10 | #define ALLOC_WRAP(sz) \\\n11 |     alloc(sz) \\\n12 |     + 1\n"
      }
    ]
  }
}
```

字段规则：

- `function_name` 使用宏名称。
- `file_path/start_line/end_line/signature` 直接复用宏实现 payload 的语义。
- `index_name` 使用统一唯一键格式 `macro_name@file_path:start_line-end_line`，但不要求把宏写入 `_function_index`。
- `is_macro` 只在宏函数 match 中返回且固定为 `true`；普通函数不增加 `is_macro: false`。
- `code` 返回该宏定义的全量源码，包括连续反斜杠组成的所有行，不附带文件头或相邻源码。
- 宏 match 不返回 `truncated` 或其他 code completeness 字段。`get_function_info` 的宏查询不应用 `get_function_impl.max_lines` 上限。
- 宏 match 省略 `callees`、`callees_truncation`、`referenced_globals`、`referenced_globals_truncation`、`referenced_macros` 和 `referenced_macros_truncation`，不返回空数组，以免错误表达这些集合已经被可靠分析且确认为空。
- 下游通过 `is_macro=true` 识别条件结构，并直接使用完整 `code` 建模；需要确认某个 token 的实际绑定时，应结合具体展开位置和对应 TU 的 Clang 证据，而不是从宏定义查询结果推断。

如果存在多个同名 function-like macro 定义，`matches` 返回所有符合 `file_path` 条件的定义，`match_count` 等于实际返回数量；不能只返回第一个定义并用 `macro_alternates_count` 代替歧义信息。

#### 1.10.3 查询优先级与兼容性

查询顺序固定为：

1. 按现有逻辑查询 `_function_index` 中的普通函数；
2. 普通函数存在 match 时保持当前输出，不继续追加同名宏；
3. 普通函数零命中时查询 function-like macro；
4. 宏仍零命中时再执行 external function fallback；
5. external config 命中时返回单个 `is_external=true` match；仍未命中时与 `get_function_impl` 一致，记录可用的 `missing_external_func` warning 并返回 `success=false`。

普通函数优先用于保持现有调用方行为稳定。宏和真实函数同名但需要强制查询宏时，调用方应传入宏定义所在的 `file_path`；实现需先按文件过滤普通函数，如果该文件中没有普通函数 match，再进入宏查询。

`file_path` 对宏查询使用与函数查询一致的 suffix/path hint 规则，至少支持项目相对路径、绝对路径和唯一文件名后缀。多文件同名宏在未传 `file_path` 时必须作为多个 match 返回，不能依赖后端或文件扫描顺序隐式选中一个定义。

#### 1.10.4 复用 `get_function_impl` 宏逻辑

不要在 `find_function_infos()` 中重新实现一套宏扫描。应把 `get_function_impl()` 当前使用的宏查询和 payload 构造整理为共享内部能力，供两个入口复用：

```python
def _find_macro_impls(
    self,
    macro_name: str,
    *,
    file_path: str = "",
    max_lines: Optional[int] = 500,
    function_like_only: bool = False,
    include_callees: bool = True,
) -> List[Dict[str, Any]]:
    ...
```

共享逻辑负责：

- 优先调用后端 `get_macro_definitions()`；后端无结果时使用 `_get_macro_definition_index()` 正则索引；
- 对名称和可选 `file_path` 做统一过滤；
- 对候选按规范化文件路径、定义起始行稳定排序并去重；
- 继续使用 `_macro_definition_payload()` 构造宏实现 payload；`max_lines=None` 时返回全量宏源码，整数值时保留现有截断行为；
- 保留 `_macro_replacement_body()` 和 `_macro_signature()`，不复制多行宏解析代码；
- 支持返回全部候选，而不是只返回当前 `get_function_impl()` 所需的第一项。

`get_function_impl()` 改为调用 `_find_macro_impls()` 并继续传入自身的 `max_lines`，保持原有兼容行为：返回第一个候选，同时继续通过 `macro_alternates_count` 表达其余候选数量。`get_function_info` 则以 `max_lines=None, function_like_only=True, include_callees=False` 查询全部候选，既不执行 callee 提取，也不在转换后的 match 中输出内部 `truncated` 字段。

不建议让 `find_function_infos()` 直接调用完整的 `get_function_impl()`：完整入口只返回一个宏候选，并包含普通函数动态补查、源码读取和函数体校验等无关分支。复用应发生在宏查找、宏解析和 payload 构造层，以避免递归查询和同名宏丢失。

#### 1.10.5 CodeIndex 与 Tool 层改动

`CodeIndex` 层：

1. 将 `_find_backend_macro_definition()` 和 `_find_macro_definition()` 的单结果逻辑收敛到共享的 `_find_macro_impls()`；保留旧私有方法时也只能作为兼容包装，不再维护独立解析逻辑。
2. 新增宏 payload 到 function-info match 的转换方法，只生成最小身份字段、稳定 `index_name`、`is_macro=true` 和完整 `code`。
3. `find_function_infos()` 先完成普通函数匹配；仅在零 match 时调用宏查询。
4. 不对宏 replacement body 执行 callee、global 或 nested macro 推断；`_macro_definition_payload()` 中为 `get_function_impl` 保留的内部 `callees` 不复制到 function-info macro match。
5. 宏候选不写入 `_function_index`、函数 alias index 或函数调用图，避免污染真实函数数量和现有函数消歧逻辑。

`GetFunctionInfoTool` 层：

1. input schema 不增加新参数，继续使用 `func_name` 和可选 `file_path`。
2. 更新工具 description，明确既可查询函数也可查询 function-like macro，且只有宏 match 包含 `is_macro` 和 `code`。
3. external function fallback 必须位于 CodeIndex 宏查询之后。
4. 工具层不读取文件、不解析宏，也不根据 `signature` 猜测是否为宏。

#### 1.10.6 缓存与后端一致性

- 共享宏查询继续复用现有 `_macro_definition_index`、`_macro_definition_miss_cache` 和函数实现缓存的失效时机。
- 负缓存的 key 需要包含足以区分查询语义的信息；加入 `file_path` 和 `function_like_only` 后，不能因为一次无文件限定的 miss 阻止后续文件限定查询。
- Clang/unified 后端与 regex fallback 必须产生同一 match 字段结构。
- 后端记录和 regex 索引命中同一 `name/file/line` 时只保留一项，优先使用后端 definition 和 `is_function_like` 元数据。
- `get_function_impl` 的既有宏返回结构保持兼容，不因共享逻辑重构而新增或删除现有字段。

#### 1.10.7 测试计划

| 测试 | 预期 |
|---|---|
| 查询单行 function-like macro | 返回一个 match，包含 `is_macro=true` 和准确 `code` |
| 查询多行 function-like macro | `start_line/end_line/code/signature` 覆盖完整连续定义 |
| 查询对象式宏 | 不作为宏函数 match 返回 |
| 普通函数与宏同名 | 未指定宏文件时保持普通函数优先 |
| 普通函数与宏同名且指定宏文件 | 普通函数文件不匹配后返回宏 match |
| 多文件存在同名宏 | 返回全部宏定义，顺序稳定且 `match_count` 准确 |
| 使用 `file_path` 消歧同名宏 | 只返回路径匹配的宏定义 |
| 宏替换体包含函数调用、嵌套宏和全局名称 | 只在完整 `code` 中保留原始 token，不返回 callees/globals/macros 字段 |
| 宏参数被当作函数调用 | 不尝试生成 `callee_index_name` |
| 超长多行宏定义 | 返回从 `#define` 到最后一个续行的全量 `code`，且不包含 `truncated` 字段 |
| 后端宏查询命中 | 不执行 regex 文件扫描，输出与 fallback 一致 |
| 后端未命中 | regex fallback 能返回相同结构 |
| 宏未命中但 external config 命中 | 返回 external function match |
| 重复宏查询 | 复用缓存且返回内容不发生可见变异 |
| `get_function_impl` 宏回归 | 既有字段和首候选行为保持不变 |
| 普通函数查询回归 | 不增加 `is_macro`、`code` 或额外 token |

需要重点扩展：

- `tests/test_function_info_tool.py`：工具与 runtime 契约、普通函数回归、宏查询及 external precedence；
- `tests/test_code_index_cache.py`：共享宏查询、后端/regex fallback、多行宏、负缓存和 `get_function_impl` 兼容性；
- 相关工具 schema/description 测试：确保不增加 input 参数且描述宏输出的条件字段。

#### 1.10.8 实施顺序与验收

| 顺序 | 任务 | 产出 |
|---:|---|---|
| 1 | 为现有宏查询补充覆盖全部候选、路径过滤和 function-like 过滤的测试 | 锁定共享逻辑行为 |
| 2 | 提取 `_find_macro_impls()` 并让 `get_function_impl()` 复用 | 消除宏查找与 payload 构造重复 |
| 3 | 增加宏到 function-info 最小 match 的转换 | 返回身份、位置、签名、`is_macro` 和完整 `code` |
| 4 | 将宏 fallback 接入 `find_function_infos()` | `get_function_info` 支持宏函数查询 |
| 5 | 调整 external precedence 和工具 description | 工具行为与 Agent 可见语义一致 |
| 6 | 完成 focused tests、相关回归测试和 `git diff --check` | 验证兼容性 |
| 7 | 将实际改动、测试结果和偏差更新到 `new_docs/tools_optimation.md` 对应实施记录 | 保持计划与实现同步 |

验收条件：

1. `get_function_info` 可以通过名称和可选文件路径查询 function-like macro；
2. 每个宏 match 包含 `is_macro=true` 和准确、完整的带行号 `code`，不包含 `truncated` 字段；普通函数输出不增加 `is_macro` 或 `code`；
3. 宏 match 不包含 callees、referenced globals、referenced macros 及其 truncation 字段；
4. 多行宏、同名宏和后端/regex fallback 行为确定且一致；
5. 宏查询最大程度复用 `get_function_impl` 的现有查找、签名、替换体和源码 payload 逻辑；
6. `get_function_impl` 现有调用方和返回契约不发生破坏性变化；
7. 实现完成后实施记录追加到`new_docs/tools_optimation.md`。

## 二、simple-name fallback

### 2.1 目标与问题

将 `GetFunctionImplTool` 当前在工具层执行的 `sanitize_func_name()` 移除，改为由 `CodeIndex` 在精确查询失败后统一执行 simple-name fallback。目标是同时满足：

- 首次查询保留完整 `index_name`、函数签名、C++ 限定名和 overload 信息；
- 陈旧 `index_name`、参数名称不一致的签名或带返回类型的完整声明在精确查询失败后仍有恢复机会；
- `find_function_infos()` fallback 后返回全部候选，通过 `match_count` 暴露歧义；
- `get_function_impl()` 不因 fallback 静默选择错误 overload；
- function-like macro 查询顺序和第 1.10 节最小宏 match 契约不被破坏。
  
当前工具层提前清理存在信息损失：

```text
Target(int value) -> Target
```

这使 `get_function_impl` 在进入 CodeIndex 前失去签名消歧能力。另一方面，现有 `sanitize_func_name()` 不能处理统一位置键：

```text
Target@src/a.c:10-20 -> Target@src/a.c:10-20
```

因此不能把该函数原样移动到 CodeIndex；需要新增结构化 fallback 提取逻辑。

### 2.2 查询阶段

普通函数查询分为 strict 和 fallback 两阶段：

1. 使用原始输入生成 `_function_query_variants()`，精确匹配 `index_name`、signature alias、限定名和简单名；
2. strict match 非空时立即返回，不执行 fallback；
3. strict match 为空时，根据查询形态提取 fallback simple name；
4. 使用 fallback name 重新匹配函数索引，并继续应用显式 `file_path`；
5. 函数 strict/fallback 均未命中时，才进入 function-like macro 或 external function fallback。

fallback 不是模糊搜索，不执行前缀、子串或编辑距离匹配。只允许从可识别的结构中恢复名称：

| 输入 | fallback name |
|---|---|
| `Target@src/a.c:10-20` | `Target` |
| `Target(int value)` | `Target` |
| `static int Target(int value)` | `Target` |
| `Namespace::Target(int value)` | `Namespace::Target` |
| `Namespace :: Target ( int value )` | `Namespace::Target` |
| `#define WRAP(x)` | 不执行函数 simple-name fallback，直接按显式宏查询处理 |
| `foo bar` | 不生成 fallback，避免把任意文本误当作函数声明 |

fallback name 必须符合 C/C++ 简单名或限定名格式。不能仅使用 `split()[-1]` 接受任意尾部 token。

### 2.3 共享匹配层

抽取只负责函数索引匹配、不负责 payload 构造的共享方法：

```python
def _find_function_matches(
    self,
    func_name: str,
    file_path: str = "",
    *,
    allow_simple_fallback: bool = False,
) -> List[Tuple[str, Dict[str, Any]]]:
    ...
```

返回值保持 `(index_key, copied_record)`，并使用当前稳定排序：匹配精度、文件路径、起始行和 `index_name`。该方法统一复用：

- `_function_query_variants()`；
- `_function_record_query_variants()`；
- `_record_matches_file_hint()`；
- `_function_info_match_rank()`。

同时新增结构化提取方法：

```python
def _fallback_function_name(self, query: str) -> str:
    ...
```

`find_function_infos()` 和 `_resolve_function_name()` 都基于 `_find_function_matches()`，避免当前两套遍历、过滤和排序逻辑继续分化：

- `find_function_infos()` 消费全部 matches；
- `_resolve_function_name()` 只在调用方明确需要单结果时选择第一项；
- `_resolve_function_name()` 保留现有简单名调用的确定性选择行为，但需让 `get_function_impl()` 区分 strict 命中与 fallback 命中。

### 2.4 `find_function_infos()` 行为

`find_function_infos()` 使用 `allow_simple_fallback=True`：

- 有效 `index_name`：只返回精确位置记录；
- 陈旧 `index_name`：按其中的函数名和路径 hint 重新查询，返回当前文件中的全部同名函数；
- 精确 signature alias：只返回参数字符串匹配的 overload；
- 签名不匹配：退化为限定名或简单名，返回全部同名 overload；
- fallback 后有多个结果：全部返回，不隐式选择；
- fallback 后仍无结果：再进入 function-like macro 查询。

当输入自身携带位置键且未显式传入 `file_path` 时，可将键中的路径作为 fallback path hint；调用方显式提供的 `file_path` 优先。旧键中的行号只用于 strict match，不在 fallback 阶段继续限制新位置，否则无法恢复函数移动后的记录。

不新增 `fallback_used` 或 `match_quality` 输出字段。调用方通过返回的实际 `index_name`、`file_path` 和 `match_count` 判断结果；实现可以记录 debug 日志用于诊断。

### 2.5 `get_function_impl()` 行为

`get_function_impl()` 必须先保留原始查询执行 strict match，再决定是否 fallback：

1. strict match 唯一：读取该实现；
2. strict match 多个：保持现有精确排序和确定性选择行为；
3. strict match 为空：执行 simple-name fallback；
4. fallback 只有一个 match：读取该实现；
5. fallback 有多个 match：不静默选择错误 overload，记录 warning/debug 并返回 `None`；
6. fallback 仍为空：执行现有后端 `get_method()` 补查，再进入宏查询。

对于调用方原本就只传简单名的情况，不视为 fallback，继续保持现有同名函数确定性选择行为，避免破坏旧流程。只有“从更具体输入降级得到简单名”且产生多个候选时才拒绝隐式选择。

后端补查也遵循 strict-first：先使用原始 query variants 调用 `get_method()`；仅 strict backend lookup 失败后，才使用 fallback name 补查。后端 fallback 返回的位置应加入 `_function_index` 后重新走共享匹配，不能直接绕过 CodeIndex 唯一键和 alias 注册。

缓存 key 应在最终函数 match 确定后使用规范 `index_name` 构造。不同陈旧签名或旧位置键 fallback 到同一函数时，应复用同一个实现缓存，而不是按原始错误输入产生多份缓存。

### 2.6 函数与宏查询歧义

普通函数和宏共用 `name@file_path:start_line-end_line` 外观，必须避免把宏位置键无条件降级成普通函数简单名。

查询分类和优先级：

1. `#define NAME(...)`：显式宏查询，不执行函数 simple-name fallback；
2. 位置键 `NAME@file:start-end`：先精确查普通函数位置，再精确查同位置 function-like macro；二者均未命中后才按 `NAME + file hint` 做函数 fallback；
3. 普通 signature `NAME(params)` 或完整函数声明：先 strict function signature，再 function simple-name fallback，最后查询同名 function-like macro；
4. 普通简单名：保持普通函数优先，普通函数零命中后查询宏。

为支持位置键精确宏查询，宏 query parser 需要保留可选 `start_line/end_line`，而不是只提取宏名和文件路径。精确宏位置未命中后，是否返回同文件其他位置的同名宏由普通宏 fallback 负责，并继续通过多个 matches 暴露歧义。

### 2.7 Tool 层调整

`GetFunctionImplTool.execute()` 删除：

```python
from ..common.utils import sanitize_func_name
func_name = sanitize_func_name(arguments.get("func_name", ""))
```

改为与 `GetFunctionInfoTool` 一致，只做类型归一化和空值检查：

```python
func_name = str(arguments.get("func_name") or "").strip()
```

`sanitize_func_name()` 暂不删除，因为 `get_callers`、`get_call_graph`、snapshot、data-flow 等其他工具仍在使用。本阶段只移除 `get_function_impl` 的提前清理；其他工具是否迁移应分别评估其查询是否需要保留签名和位置键。

工具 schema 不增加参数。更新 `get_function_impl` description，明确支持函数名、签名和 `index_name`，并由 CodeIndex 在精确查询失败后执行受控 fallback。

### 2.8 测试计划

| 测试 | 预期 |
|---|---|
| 有效 `index_name` | strict 命中唯一函数，不执行 fallback |
| 陈旧 `index_name`，同文件函数已移动 | 使用名称和旧键路径恢复到新 `index_name` |
| 陈旧 `index_name`，显式 `file_path` 不同 | 显式路径优先 |
| 精确 overload signature | 只返回对应 overload |
| 参数名称不一致导致签名未命中 | fallback 后返回全部同名 overload |
| 完整声明 `static int Target(int value)` | strict 规范化签名可命中，不提前丢失参数 |
| fallback 唯一候选 | `get_function_impl` 返回该实现 |
| fallback 多个候选 | `find_function_infos` 返回全部；`get_function_impl` 不隐式选择 |
| 原始输入是简单名且有多个候选 | `get_function_impl` 保持现有确定性选择 |
| `#define WRAP(x)` | 直接查询 function-like macro，不被同名函数 fallback 抢占 |
| 有效宏 `index_name` | 精确返回对应宏定义 |
| 陈旧函数位置键与同名宏共存 | 先按位置判断，未命中后按函数 fallback 规则处理 |
| strict backend lookup 命中 | 不执行 simple-name backend fallback |
| strict backend lookup 未命中且 fallback 唯一 | 注册后端函数并返回规范唯一键 |
| 工具传入签名 | `GetFunctionImplTool` 不再提前调用 `sanitize_func_name()` |
| 缓存复用 | 不同旧签名 fallback 到同一函数时复用 canonical implementation cache |

重点更新：

- `tests/test_function_info_tool.py`：strict/fallback matches、陈旧 index、签名 mismatch、宏优先级；
- `tests/test_code_index_cache.py`：`get_function_impl` 唯一/歧义 fallback、canonical cache key、后端补查；
- 新增或扩展 `GetFunctionImplTool` 测试：确认工具保留原始签名和位置键；
- 相关 Runtime/registry 测试：schema 单源和执行结果保持一致。

### 2.9 实施顺序与验收

| 顺序 | 任务 | 产出 |
|---:|---|---|
| 1 | 为签名、陈旧位置键、宏位置键和歧义 fallback 增加失败测试 | 锁定目标行为 |
| 2 | 实现 `_fallback_function_name()` 和查询形态解析 | 受控 simple-name fallback |
| 3 | 抽取 `_find_function_matches()` 并迁移 `find_function_infos()` | 单一函数匹配规则 |
| 4 | 调整 `_resolve_function_name()` / `get_function_impl()` 的 strict-first 与歧义处理 | 保留精确信息并避免误选 overload |
| 5 | 扩展宏位置键解析与函数/宏优先级 | 避免统一键格式下的错误 fallback |
| 6 | 从 `GetFunctionImplTool` 移除提前 sanitizer 并更新 description | 工具原样传递查询信息 |
| 7 | 更新工具文档并运行 focused/broader regression | 验证兼容性 |
| 8 | 将实施细节、测试结果和计划偏差记录到 `new_docs/tools_optimation.md` | 保持实施记录同步 |

验收条件：

1. `get_function_impl` 工具不再在进入 CodeIndex 前丢失 signature 或 `index_name`；
2. strict index/signature 查询行为不变，fallback 只在零命中时发生；
3. `find_function_infos` fallback 后返回全部候选并保留 `match_count` 歧义；
4. `get_function_impl` 对 fallback 产生的多个 overload 不静默选择；
5. 陈旧函数位置键可以恢复到移动后的函数，同时不破坏有效宏位置键查询；
6. 普通函数、function-like macro 和 external fallback 顺序确定且有测试覆盖；
7. 实现缓存以最终 canonical `index_name` 为身份，不按错误原始输入重复缓存；
8. 不修改任何 fallback Agent 文件，实施记录更新到 `new_docs/tools_optimation.md`。

## 三、`is_static` 输出扩展

### 3.1 目标与字段语义

为 `get_function_info` 和 `get_function_impl` 的普通项目函数结果增加布尔字段：

```json
"is_static": true
```

普通函数 match/implementation 中该字段必须始终为 JSON boolean，不返回 `null`、字符串或整数。语义定义如下：

| 目标类型 | `is_static` |
|---|---|
| C 文件作用域 `static` 函数 | `true` |
| C++ `static` member function | `true` |
| 普通全局函数、非 static member function | `false` |

function-like macro 和 external function 不适用该属性，必须省略 `is_static`，不能返回 `false`。这样可以区分“已确认是非 static 项目函数”和“该结果类型没有 static 函数语义”。

本阶段不增加 `is_inline`、`is_declaration` 或 storage-class enum。`is_static` 是两个工具需要对齐的最小身份字段。

### 3.2 输出契约

普通函数的 `get_function_info` match：

```json
{
  "function_name": "local_helper",
  "file_path": "src/helper.c",
  "index_name": "local_helper@src/helper.c:10-20",
  "start_line": 10,
  "end_line": 20,
  "signature": "static int local_helper(void)",
  "is_static": true,
  "callees": [],
  "referenced_globals": [],
  "referenced_macros": []
}
```

普通函数的 `get_function_impl.data`：

```json
{
  "func_name": "local_helper",
  "file": "src/helper.c",
  "index_name": "local_helper@src/helper.c:10-20",
  "start_line": 10,
  "end_line": 20,
  "signature": "static int local_helper(void)",
  "is_static": true,
  "code": "...",
  "callees": [],
  "truncated": false,
  "comment_blocks": []
}
```

function-like macro 的最小 match 以及两个工具的 external payload 均保持现有结构，不增加 `is_static`。

### 3.3 数据来源优先级

`is_static` 按以下优先级确定：

1. 后端函数记录中的结构化 `is_static`；
2. CodeIndex regex 索引在解析函数定义头部时提取的 `static` storage-class；
3. 后端未提供该字段时，从函数定义起始行到函数体第一个 `{` 之间的源码头部做精确 token fallback；
4. 内部函数仍无 static 证据时返回 `false`。

源码 fallback 只检查函数声明头部，必须先屏蔽注释和字符串，使用 `\bstatic\b` token 匹配。禁止扫描整个函数体，否则局部 `static` 变量会把普通函数误判为 static：

```c
int process(void) {
    static int counter;
}
```

该函数的 `is_static` 必须为 `false`。

结构化字段无论来自 SQLite 的 `0/1`、Python bool 还是其他后端 truthy 值，进入 CodeIndex 时统一归一化为 `bool`。如果字段存在，应优先于源码 fallback，避免 C++ static member function 的类内声明与类外定义分离时丢失属性。

### 3.4 KnowledgeDB 与 Clang 后端

KnowledgeDB 的 `functions` 表已经包含 `is_static INTEGER DEFAULT 0`，无需升级 schema version。需要修正字段透传：

- `get_all_functions()` 的 SELECT 增加 `is_static`，并在每个 function index record 中返回 `"is_static": bool(...)`；
- `get_function_records()` 增加 `is_static`，保证增量、诊断和测试读取完整元数据；
- `get_function()` 已使用 `SELECT *`，保持字段可用；
- 不改变唯一函数键、函数签名或调用图表结构。

`ClangExtractor` 已在函数写入时计算并保存 `is_static`。需要补齐：

- `ClangBackend.build_function_index()` 通过 KnowledgeDB 获得该字段；
- `ClangBackend.get_method()` 返回 `is_static`，供 CodeIndex 动态补查路径使用；
- `UnifiedBackend` 继续透传 ClangBackend 结果，不单独重新推断；
- 增量重建和旧数据库读取不需要迁移，现有默认值 `0` 保持兼容。

应补充测试确认 Clang detail 中的 `static` 能写入 DB，并最终出现在两个工具输出中，而不只停留在数据库表内。

### 3.5 Regex 与其他后端

CodeIndex regex 索引在 `_extract_functions_regex()` 中已经获得 `before_brace/signature`。写入 `_add_function_index_entry()` 时增加：

```python
"is_static": bool(re.search(r"\bstatic\b", before_brace))
```

该判断只覆盖函数定义头部，不读取函数体。

Joern 等后端策略：

- 能直接提供 method modifier 时，映射为 `is_static`；
- 后端只返回 name/file/line/signature 时，由 CodeIndex 源码头部 fallback 补齐；
- 不在 Tool 层根据 signature 字符串重新判断；
- 后端记录中的缺失字段与明确 `false` 必须区分，只有缺失时才执行源码 fallback。

对于 C++ static member function，Joern/Clang 的结构化 modifier 优先。类外定义通常不再出现 `static` token，仅靠实现源码可能得到 false，因此不能覆盖后端明确提供的 true。

### 3.6 CodeIndex 归一化

新增内部方法：

```python
def _function_record_is_static(self, info: Dict[str, Any]) -> bool:
    ...
```

职责：

- 如果 `info` 包含 `is_static`，直接归一化并返回；
- 否则尝试从 `signature` 的 storage-class token 判断；
- signature 无证据时读取 `file/start_line` 附近的函数定义头部；
- 文件不存在、行号无效或解析失败时安全返回 `false`；
- 不修改输入 record，不在调用方 payload 构造处复制判断逻辑。

调用位置：

- `_function_info_payload()`：普通函数 match 添加 `is_static`；
- `get_function_impl()`：普通函数 implementation payload 添加 `is_static`；
- 后端动态 `get_method()` 写入 `_function_index` 时保留 `is_static`；
- macro 和 external payload 构造路径不添加 `is_static`。

建议 `_add_function_index_entry()` 在 record 已包含 `is_static` 时立即归一化为 bool；缺失时不提前写入 false，以便 payload 阶段仍能识别“字段缺失”并执行源码 fallback。

### 3.7 缓存与兼容性

- 不修改 `_function_impl_cache` key；`is_static` 随 implementation payload 一起缓存。
- `_file_lines_cache` 可供源码 fallback 复用，禁止为每次工具调用重复打开函数文件。
- `_build_index()`、增量索引或缓存清理后，新 record 自然重新计算；不增加独立 `is_static` cache。
- `find_function_infos()` 没有完整结果缓存，每次 payload 构造读取相同 record；源码内容由 `_file_lines_cache` 复用。
- 新字段是向后兼容的附加字段，但严格比较完整 dict 的测试、文档示例和调用方 schema fixture 需要同步更新。

semantic modeler schema 已包含 required `is_static`，该扩展可以让工具返回与 snapshot identity 对齐。Agent prompt 不增加新的工具使用规则；字段语义应由工具 description 和工具文档表达。

### 3.8 Tool 与文档调整

`GetFunctionInfoTool` 和 `GetFunctionImplTool`：

- input schema 不变；
- description 增加“普通项目函数结果包含 boolean `is_static`，macro/external 不包含该字段”；
- external fallback payload 保持现有结构，不增加 `is_static`；
- Tool 层不解析源码，不根据函数名或文件名猜测 static。

更新 `new_docs/tools_introduction.md`：

- 普通函数示例增加 `is_static`；
- 宏最小 match 和 external 示例明确省略 `is_static`；
- 明确该字段是函数身份属性，不代表函数是否 inline、是否在头文件定义或是否 externally reachable。

### 3.9 测试计划

| 测试 | 预期 |
|---|---|
| regex `static int helper(void)` | 两个工具均返回 `is_static=true` |
| regex 普通全局函数 | 两个工具均返回 `is_static=false` |
| 函数体包含 local static 变量 | 函数本身仍返回 `false` |
| backend record `is_static=1` | 归一化为 JSON `true` |
| backend record `is_static=0` | 归一化为 JSON `false`，不再触发源码覆盖 |
| backend record 缺失字段，源码头含 static | CodeIndex fallback 返回 `true` |
| Clang KnowledgeDB round trip | insert/build index/get_method 保留 `is_static` |
| C++ static member 有后端结构化 true | 类外定义无 `static` token时仍返回 `true` |
| function-like macro | `get_function_info` 和 `get_function_impl` 均省略 `is_static` |
| configured external function | 两个工具均省略 `is_static` |
| 同名 static/non-static 函数 | 每个 match 根据自身 record 独立返回正确值 |
| strict/fallback/canonical cache | fallback 后返回最终目标的正确 `is_static`，缓存命中不丢字段 |
| Runtime registry 路径 | Runtime 与直接 Tool 调用返回相同 bool 类型字段 |

重点更新：

- `tests/test_function_info_tool.py`：normal/static/macro/external 和 Runtime 输出；
- `tests/test_code_index_cache.py`：`get_function_impl`、源码 fallback、缓存；
- `tests/test_knowledge_db_ir_and_config.py`：KnowledgeDB 字段 round trip；
- `tests/test_clang_incremental_extraction.py`：Clang static metadata；
- 严格 dict/schema fixture：补齐 `is_static` 断言。

### 3.10 实施顺序与验收

| 顺序 | 任务 | 产出 |
|---:|---|---|
| 1 | 为 regex/backend 增加 `is_static` 测试，并为 macro/external 增加字段省略测试 | 锁定条件契约 |
| 2 | 修正 KnowledgeDB/ClangBackend 字段透传 | 结构化 static 元数据进入 CodeIndex |
| 3 | 在 regex 索引写入 `is_static` 并实现 CodeIndex 源码 fallback | 覆盖无结构化字段后端 |
| 4 | 扩展普通函数的 info/impl payload | 普通函数返回 bool，macro 保持现有结构 |
| 5 | 更新两个工具 description，保持 external payload 不变 | Tool 条件契约完整 |
| 6 | 更新工具文档与严格 dict fixture | 文档和测试同步 |
| 7 | 运行 focused、retrieval、Runtime 和 broader regression | 验证兼容性与类型稳定性 |
| 8 | 将实现细节和测试结果追加到 `new_docs/tools_optimation.md` | 保存实施记录 |

验收条件：

1. `get_function_info` 与 `get_function_impl` 的每个普通项目函数结果都包含 bool 类型 `is_static`；
2. 普通函数字段反映真实 static 属性，宏和 external 均省略该字段；
3. Clang/Unified、regex 和缺失字段 backend 路径均有测试覆盖；
4. local static 变量不会导致函数误判，C++ static member 的结构化 true 不被源码 fallback 覆盖；
5. strict/fallback、同名函数、宏查询和 canonical cache 行为不发生回归；
6. input schema 不变，工具文档和 implementation record 完成同步；
7. 不修改任何 fallback Agent 文件。

## 四、`get_callers` 重构

> 状态：已于 2026-07-20 实施。实际实现与本节目标一致；详细过程和测试结果见 `new_docs/tools_optimation.md` 同日记录。

### 4.1 目标

将 `get_callers` 从“简单函数名 + 可调 limit + 后端原始 caller rows”改为固定用途接口：

- 输入保留原始 `func_name`，支持普通名称、qualified name、签名和 canonical `index_name`；
- 可选 `file_path` 用于同名函数消歧；
- caller limit 固定为 20，不向模型暴露；
- 输出按 canonical `caller_index_name` 聚合调用边；
- 同一 caller 的调用点合并到 `callsite_lines`；
- `call_type` 保持数组，完整保留 direct/indirect 混合证据；
- 不改变 CodeIndex 供编排、验证和 diff impact 使用的通用 `get_callers(..., limit=...)` 接口。

本节只规划 `get_callers` tool 的查询和输出重构，不修改任何 fallback 文件，也不改变 `get_call_graph` 等其他工具的输入契约。

### 4.2 Tool 输入 schema

`GetCallersTool.get_schema()` 改为：

```python
"parameters": {
    "type": "object",
    "properties": {
        "func_name": {
            "type": "string",
            "description": "Function name, qualified name, or index_name for exact match.",
        },
        "file_path": {
            "type": "string",
            "description": "Optional source file path used to disambiguate same-name functions.",
        },
    },
    "required": ["func_name"],
}
```

实施要求：

- 删除公开的 `limit` property；
- `execute()` 不再读取 `arguments["limit"]`，内部统一使用模块常量 `GET_CALLERS_LIMIT = 20`；
- 删除 `LLMClient._normalize_tool_args()` 为 `get_callers` 自动补充 `limit=20` 的分支，使 repeat-call key 与实际公开输入一致；
- Tool 层不再调用 `sanitize_func_name()`，避免签名、qualified name 和 `index_name` 在进入 CodeIndex 前被破坏；
- `file_path` 只用于目标函数匹配和消歧，不作为 caller 结果过滤条件。

### 4.3 Tool 输出契约

成功结果改为：

```json
{
  "success": true,
  "data": {
    "callers": [
      {
        "caller_index_name": "caller@src/caller.c:10-40",
        "callsite_lines": [21, 27],
        "call_type": ["direct", "indirect"]
      }
    ]
  }
}
```

caller record 的目标 schema 为：

```python
"callers": {
    "type": "array",
    "items": {
        "type": "object",
        "required": [
            "caller_index_name",
            "callsite_lines",
        ],
        "properties": {
            "caller_index_name": {"type": "string"},
            "callsite_lines": {
                "type": "array",
                "items": {"type": "integer"},
            },
            "call_type": {
                "type": "array",
                "items": {"enum": ["direct", "indirect"]},
                "minItems": 1,
                "uniqueItems": True,
            },
        },
    },
}
```

输出约束：

- 删除现有冗余 `count` 字段，成功数据只包含 `callers`；
- 按 `caller_index_name` 聚合，最终最多返回 20 个 caller records，而不是最多读取 20 条原始调用边；
- `callsite_lines` 只保留正整数，去重后升序排列；无可靠行号时返回空数组；
- `call_type` 只保留 `direct`、`indirect`，按 `direct`、`indirect` 的稳定顺序输出；
- 同一 canonical caller 同时存在两种调用边时输出 `["direct", "indirect"]`，不得提前去重或压缩为 scalar；
- caller identity 无法解析为项目内 canonical `index_name` 时，保留后端 caller name 作为降级值，不伪造路径或行号。

Tool framework 当前只向模型注册 input schema，不注册独立 output JSON schema。因此输出契约由 `execute()`、CodeIndex normalization、单元测试和工具文档共同锁定。

### 4.4 目标函数匹配与失败语义

新增 Tool 专用的 CodeIndex 查询入口，例如：

```python
def find_function_callers(
    self,
    func_name: str,
    file_path: str = "",
    limit: int = 20,
) -> List[Dict[str, Any]]:
    ...
```

该入口复用 `find_function_infos()` 使用的 strict match、canonical `index_name`、签名 fallback 和 `file_path` 消歧规则，不在 Tool 层复制名称解析逻辑。实现时应抽取或调用轻量 identity resolver，不直接构建完整 function-info payload，避免 caller 查询额外触发 callees、globals 和 macros 收集。

匹配规则：

1. `index_name` 或严格 qualified/signature 查询唯一命中时，使用该 match 的 canonical identity 和真实文件路径查询 callers；
2. 严格查询零命中时，沿用 `find_function_infos()` 的受控 simple-name fallback；
3. `file_path` 参与每一步匹配；
4. 零命中返回 `success=false`、`reason=function_not_found`；
5. 多命中返回 `success=false`、`reason=ambiguous_function`，并记录 `match_count`，不得静默选取第一个同名函数；
6. 唯一命中但没有 caller 时返回成功和空数组。

Tool 调用 CodeIndex 时传入固定 `limit=20`。CodeIndex 方法仍保留 limit 参数，便于内部测试和未来非 LLM 调用复用，但该参数不进入 Tool schema。

### 4.5 后端证据与聚合设计

当前 `CodeIndex.get_callers()` 返回后端原始 rows；KnowledgeDB direct caller 查询未稳定透传 `call_type`，UnifiedBackend 还会按 caller name 提前合并 direct/indirect，无法生成 mixed 数组。实施时增加面向结构化 caller context 的内部路径，不直接改变现有通用查询的返回形状。

建议增加 backend 可选方法 `get_function_info_callers()`，与现有 `get_function_info_callees()` 对称：

- KnowledgeDB direct rows 显式返回 `caller_name`、`caller_file`、`call_line`、`call_type=direct`；
- SVF indirect rows 返回 `caller_name`、可用文件/行号和 `call_type=indirect`；
- UnifiedBackend 在该专用路径中拼接 direct 和 indirect 原始证据，不按 caller name 提前丢弃任一类型；
- Clang/Joern 只有直接调用证据时统一标记为 `direct`；
- backend 不实现专用方法时，CodeIndex fallback 到现有 `get_callers()`，并通过 `_function_info_call_type()` 归一化；
- regex-only 索引如能定位调用表达式则返回 `direct`，否则保持当前空结果，不用正则猜测 indirect 调用。

CodeIndex 新增 caller 聚合 helper：

- 先解析 caller name/file 到 canonical `caller_index_name`；
- 以 `caller_index_name` 为唯一聚合键；
- 汇总全部 callsite 和 call type 后再应用 20 条上限；
- 原始边读取上限使用现有 `_function_info_raw_edge_limit(20)` 或等价 over-fetch，避免某个 caller 的重复 callsites 挤占最终 caller 数量；
- 结果按稳定顺序输出，优先保持后端首次出现顺序；同一 caller 内部的 lines 和 call types 使用确定性排序。

### 4.6 兼容边界

- `CodeIndex.get_callers(func_name, limit, callee_file)` 保持现有签名，避免影响 entry discovery、validation、diff impact、alert verifier 和 call graph；
- `GetCallGraphTool` 继续消费原始 caller rows，不切换到新结构；
- MCP 对 `get_callers` 的工具映射自动获得新 Tool schema 和输出，不额外保留 `limit`；
- 直接向 Tool 传入历史 `limit` 时，`execute()` 不读取该值，结果仍固定上限 20；
- 本计划不修改 Semantic Modeler snapshot 的 `callers` 或 `callees` schema，也不将 caller tool 输出自动写入 snapshot；
- 更新所有提示模型可传 `limit` 的文档、测试 fixture 和示例，避免隐藏参数继续出现在调用记录中。

### 4.7 测试计划

| 测试 | 预期 |
|---|---|
| Tool schema | 只暴露 `func_name`、`file_path`，required 仅包含 `func_name` |
| LLM 参数 normalization | `get_callers` 不再自动注入 `limit` |
| simple name 唯一命中 | 返回 canonical caller records |
| canonical `index_name` 查询 | 精确匹配目标函数，不经过破坏性 sanitize |
| qualified/signature 查询 | 保留完整查询并正确解析 |
| 同名函数 + `file_path` | 只查询指定目标定义的 callers |
| 同名函数未消歧 | `success=false`、`reason=ambiguous_function` |
| 查询无结果 | `success=false`、`reason=function_not_found` |
| 无 caller | 成功返回 `callers=[]` |
| 同一 caller 多个 callsites | 聚合为升序去重的 `callsite_lines` |
| direct + indirect 同一 caller | `call_type=["direct", "indirect"]` |
| 重复/非法 call type | 过滤非法值并稳定去重 |
| 超过 20 个 caller | 聚合完成后固定返回前 20 个 |
| 历史调用传入 `limit=1` | Tool 忽略该值，仍使用内部上限 20 |
| Clang/Joern direct caller | 输出 `call_type=["direct"]` |
| Unified/SVF indirect caller | 输出 `call_type=["indirect"]` 或 mixed 数组 |
| MCP/ToolsRuntime 调用 | 与直接 Tool 调用返回相同结构 |
| 其他 CodeIndex consumers | 原始 `get_callers(..., limit=...)` 行为不变 |

重点修改或新增测试：

- `tests/test_tool_registry.py`：schema、固定 limit、输出结构和 runtime dispatch；
- 新增或扩展 `tests/test_callers_tool.py`：匹配、消歧、聚合和失败语义；
- `tests/test_knowledge_db_ir_and_config.py`：direct caller type、文件消歧和多 callsite；
- Unified/SVF backend 测试：mixed direct/indirect 不丢失；
- `zscope/framework/llm_client.py` 对应测试：repeat-call normalization 不再补 limit。

### 4.8 文档与实施记录

实施完成后同步：

- `new_docs/tools_introduction.md`：更新输入、固定 limit、失败语义和 caller record 示例；
- Semantic Modeler、Validator、Deep Worker 等使用 `get_callers` 的说明只需删除可调 limit 表述，不增加额外工作流规则；
- `new_docs/tools_optimation.md` 或当前实施记录文件：按阶段记录 CodeIndex、backend、Tool、测试和回归结果；
- 不修改任何 fallback Agent 文件。

### 4.9 实施顺序与验收

| 顺序 | 任务 | 产出 |
|---:|---|---|
| 1 | 增加 Tool schema、精确查询、歧义和 mixed call-type 失败测试 | 锁定新契约 |
| 2 | 增加 backend 结构化 caller evidence 路径 | direct/indirect 原始证据不丢失 |
| 3 | 实现 CodeIndex canonical caller 聚合入口 | identity、lines、types 统一 |
| 4 | 修改 `GetCallersTool` 输入和固定 20 上限 | 新接口生效 |
| 5 | 删除 LLMClient 的隐藏 limit 注入 | 调用参数与公开 schema 一致 |
| 6 | 更新 Runtime/MCP、文档和严格 fixture | 所有暴露面同步 |
| 7 | 运行 focused、backend、tool registry 和全量回归 | 验证兼容性 |
| 8 | 追加实施记录 | 保存实际改动与偏差 |

验收条件：

1. Tool schema 与本节给定 schema 一致，不再暴露 `limit`；
2. `func_name` 原样进入 canonical 匹配，`file_path` 能可靠消歧；
3. 成功响应只在 `data.callers` 中返回结构化 caller records，不再返回 `count`；
4. caller 以 canonical `caller_index_name` 聚合，callsite lines 去重排序；
5. direct/indirect 以数组保留，mixed evidence 不丢失；
6. 最终 caller 上限固定为 20，历史输入中的 limit 不改变结果；
7. 通用 `CodeIndex.get_callers()` 和其他工具行为不回归；
8. 文档、测试和实施记录同步完成，且未修改任何 fallback 文件。

## 五、`get_type_info` 重构

> 状态：已于 2026-07-20 实施。详细过程与验证结果见 `new_docs/tools_optimation.md` 同日记录。
>
> 后续决策：公开 match 保留完整 `full_definition` 并删除派生 `members`，本节中关于 public members 输出与成员隔离的要求由该决策覆盖；数据库旧单结果接口仍可保留内部 members。

### 5.1 目标

将 `get_type_info` 从“仅按名称查询并静默返回一个定义”改为显式多候选接口：

- 输入增加可选 `file_path`，用于同名类型消歧或限定查询范围；
- 同名类型存在多个定义时正常返回全部候选，不静默选择第一项；
- 成功响应统一返回 `match_count` 和 `matches`；
- Tool 输出删除 KnowledgeDB 内部字段 `id` 和 `tu_id`；
- 每个 match 的 members 必须只属于该类型定义，禁止把不同文件中的同名类型成员合并；
- 保留现有内部单结果 `CodeIndex.get_type_info()` 和 backend `get_type_info()`，避免影响尚未迁移的非 Tool 调用方。

本节只规划主工具链和非 fallback 文档，不修改任何 fallback Agent 文件。

### 5.2 Tool 输入 schema

`GetTypeInfoTool.get_schema()` 改为：

```python
"parameters": {
    "type": "object",
    "properties": {
        "type_name": {
            "type": "string",
            "description": "Struct, union, enum, typedef, class, or qualified type name.",
        },
        "file_path": {
            "type": "string",
            "description": "Optional source or header path used to disambiguate same-name types.",
        },
    },
    "required": ["type_name"],
}
```

执行要求：

- `type_name` 只做 trim，不使用函数名 sanitizer；
- `file_path` 缺省为空字符串，非字符串输入返回参数错误；
- `file_path` 使用项目现有 path normalization 和 `_paths_match_hint()` 语义，兼容绝对路径、项目相对路径和规范化分隔符；
- Tool 调用新的多候选 CodeIndex API，不再调用单结果 `get_type_info()`。

### 5.3 输出契约

成功结果统一为：

```json
{
  "success": true,
  "data": {
    "match_count": 2,
    "matches": [
      {
        "name": "State",
        "kind": "struct",
        "file_path": "include/a.h",
        "start_line": 10,
        "end_line": 18,
        "full_definition": "struct State { ... };",
        "members": [
          {
            "member_name": "status",
            "member_type": "int",
            "offset_idx": 0
          }
        ]
      },
      {
        "name": "State",
        "kind": "struct",
        "file_path": "include/b.h",
        "start_line": 5,
        "end_line": 9,
        "full_definition": "struct State { ... };",
        "members": []
      }
    ]
  }
}
```

输出规则：

- 单命中也使用相同外层结构，返回 `match_count=1` 和单元素 `matches`；
- 多命中属于成功结果，不返回 ambiguity error；
- 零命中保持现有失败语义：`success=false`、`error=Type '...' not found`；
- 每个 match 删除 `id`、`tu_id`，不得将数据库主键或增量索引外键暴露给 Agent；
- `members` 始终为数组，没有成员时返回空数组；
- match 按 `file_path`、`start_line`、`kind`、`name` 稳定排序；
- 不额外生成 type `index_name`，本轮使用 `type_name + file_path` 完成消歧；
- backend 缺少某个描述字段时保留该后端当前可表达的信息，不伪造定义文本、结束行或类型类别。

### 5.4 KnowledgeDB 多候选查询

新增：

```python
def find_type_infos(
    self,
    name: str,
    file_path: str = "",
) -> List[Dict[str, Any]]:
    ...
```

实现要求：

- 查询 `type_definitions WHERE name=?`，不再使用 `LIMIT 1`；
- 可选 `file_path` 在查询后使用 `_paths_match_hint()` 过滤，避免数据库路径格式差异导致误失配；
- 为每条 type row 单独按其 `id` 查询 `type_members`；
- members 按 `offset_idx` 稳定排序，并复制为独立数组；
- 对外结果删除 `id` 和 `tu_id`，但内部查询期间继续使用 `id` 完成成员关联；
- 现有 `KnowledgeDB.get_type_info()` 暂时保留单结果接口，可改为调用 `find_type_infos(name)` 后返回第一项，以减少重复 SQL，但不得改变其返回类型；
- `tu_id` 继续保留在数据库中用于增量索引清理，只从 Tool-facing payload 删除。

需要明确覆盖以下同名情况：

- 相同 name、kind，不同 file；
- 相同 name、不同 kind；
- 头文件中的同名类型由不同 TU 提取；
- 前向声明和完整定义并存时，按数据库实际记录分别返回，不静默合并不同文件的记录。

### 5.5 Backend 与 CodeIndex 设计

在 `CodeBackend` 增加非抽象默认方法：

```python
def find_type_infos(
    self,
    type_name: str,
    file_path: str = "",
) -> List[Dict[str, Any]]:
    info = self.get_type_info(type_name)
    ...
```

默认实现用于兼容旧 backend：

- 单结果存在且路径匹配时包装为单元素数组；
- 不存在或路径不匹配时返回空数组；
- 默认实现不能发现 backend 已经静默丢弃的其他候选，因此 Clang/Unified/Joern 必须提供专用实现。

各后端策略：

- `ClangBackend.find_type_infos()`：委托 KnowledgeDB 多候选查询；
- `UnifiedBackend.find_type_infos()`：委托 ClangBackend，SVF 不提供类型定义身份；
- `JoernBackend.find_type_infos()`：调用新的 JoernClient 多 typeDecl 查询，返回所有同名声明并按 `file_path` 过滤；
- Joern 查询应在每个 `typeDecl` 上直接收集自己的 members，禁止继续使用 `cpg.typeDecl.name(...).member` 后再把全部成员附加到第一个 declaration；
- regex backend 当前没有结构化 type index，继续返回空数组，不通过宽泛 regex 伪造类型定义。

CodeIndex 新增：

```python
def find_type_infos(
    self,
    type_name: str,
    file_path: str = "",
) -> List[Dict[str, Any]]:
    ...
```

职责：

- 调用 backend 多候选接口；
- 统一路径字段名称，例如 Joern `filename` 映射为 `file_path`；
- 统一行号字段名称，例如 `lineNumber` 映射为 `start_line`；
- 确保 `members` 为 list；
- 删除 `id`、`tu_id`，即使第三方 backend 意外返回也不透传；
- 稳定排序后返回，不在 CodeIndex 层选择第一项；
- 现有 `CodeIndex.get_type_info()` 保持 Optional dict 返回类型，继续服务旧内部调用方。

### 5.6 Runtime 负缓存修正

当前 ToolsRuntime 的 `get_type_info` negative cache key 只有 `type_name`。增加 `file_path` 后改为：

```python
("get_type_info", normalized_type_name, normalized_file_path)
```

否则 `State + include/a.h` 的未命中会错误缓存并阻断 `State + include/b.h` 的有效查询。

要求：

- lookup 和 write 使用相同 key helper；
- 路径分隔符和空值规范化一致；
- 同一 `type_name/file_path` 的失败继续复用 negative cache；
- 不同 `file_path` 的查询相互隔离；
- 多命中和单命中的成功结果都不进入 negative cache。

### 5.7 Agent policy 与文档同步

主 [Semantic Modeler AGENT.md] 中当前规则“Only `get_function_info` may return multiple matches”需要更新为：

- `get_function_info` 和 `get_type_info` 可以正常返回多个 matches；
- `get_function_snapshot` 和 `get_callers` 仍要求唯一函数命中；
- 调用 `get_type_info` 时，已知声明文件则优先传 `file_path`；
- Agent 必须根据目标字段类型和源码 include/声明证据选择正确 type match，不得默认使用 `matches[0]`。

不修改 fallback Agent 文件。

同步 `new_docs/tools_introduction.md`：

- 增加 `file_path` 输入；
- 将单对象示例改为 `match_count/matches`；
- 删除 `id`、`tu_id`；
- 解释多命中、文件消歧和 members 隔离语义；
- 删除将 `tu_id` 作为 Tool 输出字段的现有说明，同时保留其数据库内部用途说明时应放到架构文档，而非工具返回结构。

### 5.8 兼容边界

- Tool 成功数据从单个 type dict 改为 `match_count/matches`，所有直接读取 `data.members` 的 Agent 提示、测试或客户端必须同步；
- MCP 映射自动获得新 input schema 和输出结构；
- `CodeIndex.get_type_info()`、backend `get_type_info()` 和现有内部测试继续保持单结果兼容；
- KnowledgeDB schema 不删除 `id` 或 `tu_id`，只调整查询和 Tool-facing projection；
- 不为 type 引入 canonical `index_name`，避免在没有统一 C/C++ type identity 规则前制造不稳定主键；
- 不修改 `get_function_info`、`get_function_snapshot`、`get_callers` 的行为。

### 5.9 测试计划

| 测试 | 预期 |
|---|---|
| Tool schema | 暴露 required `type_name` 和 optional `file_path` |
| 单命中 | `match_count=1`、`matches` 单元素 |
| 多文件同名类型 | 成功返回全部 matches |
| `file_path` 消歧 | 只返回路径匹配的类型 |
| 路径不存在 | 返回 type not found，不回退到其他文件 |
| 同名不同 kind | 分别返回，不静默覆盖 |
| match payload | 不包含 `id`、`tu_id` |
| members 隔离 | 每个 match 只包含自身 type id/typeDecl 的成员 |
| members 为空 | 返回 `[]` |
| 稳定排序 | 多次查询顺序一致 |
| Joern 多 typeDecl | 返回全部定义且成员不混合 |
| backend default fallback | 旧单结果 backend 仍返回单元素 matches |
| negative cache 同 key | 第二次相同失败命中缓存 |
| negative cache 不同 file | 一个文件未命中不污染另一个文件 |
| Runtime/MCP | 与直接 Tool 调用结构一致 |
| 旧 CodeIndex API | `get_type_info()` 仍返回 Optional dict |
| Semantic Modeler policy | 明确两个多候选工具和两个唯一命中工具 |

重点修改或新增测试：

- 新增 `tests/test_type_info_tool.py`：Tool schema、单/多命中、file path、字段投影和 backend fallback；
- `tests/test_knowledge_db_ir_and_config.py`：多文件同名、不同 kind、member isolation、内部 `tu_id` 保留；
- Joern client/backend 测试：多 declaration 与 per-declaration members；
- `tests/test_tool_registry.py`：Runtime negative cache key 纳入 `file_path`；
- Semantic Modeler AGENT 静态契约测试：多候选规则文本同步；
- 工具文档示例和严格 dict fixture：删除 `id/tu_id`，改为 `match_count/matches`。

### 5.10 实施顺序与验收

| 顺序 | 任务 | 产出 |
|---:|---|---|
| 1 | 增加 Tool、KnowledgeDB、Joern 和 negative cache 失败测试 | 锁定多候选契约 |
| 2 | 实现 KnowledgeDB 多类型查询和 members 隔离 | Clang 数据源完整 |
| 3 | 增加 backend/CodeIndex 多候选接口和字段归一化 | 跨后端 matches 统一 |
| 4 | 修改 `GetTypeInfoTool` input/output | 新 Tool 契约生效 |
| 5 | 修正 Runtime negative cache key | 文件限定查询不互相污染 |
| 6 | 更新主 AGENT policy、工具文档和严格 fixture | 上下文与接口同步 |
| 7 | 运行 focused、backend、Runtime、Agent 和全量回归 | 验证兼容性 |
| 8 | 将分阶段实施过程追加到 `new_docs/tools_optimation.md` | 保存实际改动和偏差 |

验收条件：

1. `get_type_info` input schema 包含 required `type_name` 和 optional `file_path`；
2. 单命中和多命中均成功返回 `match_count/matches`；
3. `file_path` 可可靠限定同名类型，未命中时不静默选择其他文件；
4. 所有 Tool matches 均不含 `id`、`tu_id`，数据库内部关联仍正常；
5. 每个 match 的 members 与其定义严格对应，Joern 不再合并同名类型成员；
6. Runtime negative cache 按 `type_name + file_path` 隔离；
7. 旧单结果 CodeIndex/backend API 和其他工具行为不回归；
8. 主 AGENT policy、工具文档、测试和实施记录同步，且未修改任何 fallback 文件。
