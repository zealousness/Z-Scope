# Tools Optimation Plan

本文记录 `get_function_info` 工具重构计划。该计划基于当前 `get_function_impl`、`get_file_snippet`、`list_known_functions`、`get_callers` 的功能重叠问题，目标是把“函数元信息”和“代码片段读取”拆清楚，降低 validator 阶段对 `get_function_impl` 的高频依赖。

## 一、设计结论

### 1.1 保留方向

新增 `get_function_info`，用于查询函数的结构化元信息；代码正文仍由 `get_file_snippet` 读取。

建议分工如下：

| 工具 | 职责 | 是否返回代码正文 |
|---|---|---|
| `get_function_info` | 按函数名和可选文件路径查询函数身份、位置、签名、调用者、被调用者 | 否 |
| `get_file_snippet` | 按文件路径和行号读取源码片段 | 是 |
| `get_function_snapshot` | 返回较高层的函数摘要和安全相关上下文 | 否或少量摘要 |
| `get_function_impl` | 过渡期兼容旧流程，后续降级或删除 | 是 |

这样可以避免一个工具一次返回大量代码、签名、callee、comment、外部函数信息，导致 token 成本过高；同时也避免把函数定位能力完全压到 `get_file_snippet` 上，因为 snippet 本身不知道函数名、签名、同名函数数量和调用关系。

### 1.2 关于歧义判断

不需要额外返回 `ambiguous` 字段。LLM 可以直接根据 `match_count` 判断：

| `match_count` | 含义 | 建议行为 |
|---:|---|---|
| 0 | 未找到函数 | 不应继续盲目读取代码；可改用更精确函数名或 `list_known_functions` |
| 1 | 唯一命中 | 可直接用该 match 的 `file_path`、`start_line`、`end_line` 调用 `get_file_snippet` |
| >1 | 存在同名/重载/路径歧义 | 需要结合调用链、候选文件、entry evidence 或用户上下文选择目标 |

### 1.3 关于 `index_name`

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

## 二、建议接口

### 2.1 Inputs

| 字段 | 类型 | 必填 | 说明 |
|---|---|---|---|
| `func_name` | string | 是 | 函数名称，可为简单名、限定名或已有 `index_name` |
| `file_path` | string | 否 | 函数所在源文件路径，用于同名函数消歧 |
| `callers_limit` | integer | 否 | 返回调用者数量上限，默认 30 |
| `callees_limit` | integer | 否 | 返回被调用者数量上限，默认 30 |

不加入通用 `limit`。函数名精确查询通常不应返回大量函数匹配；如果后续需要模糊搜索，应由 `list_known_functions` 或新增 `search_functions` 承担。`callers_limit` 和 `callees_limit` 只限制每个 match 下的调用关系数组长度。

### 2.2 Success Output

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
}
```

说明：

- `match_count` 等于 `matches` 长度。
- `match_count=0` 仍返回 `success: true`，表示查询正常完成但没有命中；只有参数非法、索引不可用、内部异常才返回 `success: false`。
- `is_external` 维持 `get_function_impl` 的外部函数语义，但默认不返回 `false`。只有命中用户配置的外部函数时，才返回 `is_external: true`。
- `call_type` 在 `svf` / `unified` 后端可用时支持 `direct` 和 `indirect`；仅 `clang` / `clangd` 能力可用时自动降级为 `direct`，避免把不完整的间接调用推断伪装成 SVF 级别结论。

### 2.3 Not Found Output

```json
{
  "success": true,
  "data": {
    "match_count": 0,
    "matches": []
  }
}
```

### 2.4 External Function Output

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

## 三、与现有工具的关系

### 3.1 与 `get_function_impl`

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

### 3.2 与 `get_file_snippet`

`get_file_snippet` 不应该承担函数解析责任。推荐调用顺序为：

1. 调用 `get_function_info(func_name, file_path?)` 定位函数。
2. 如果 `match_count=1`，使用返回的 `file_path/start_line/end_line` 调用 `get_file_snippet`。
3. 如果 `match_count>1`，先选择目标 match，再读取 snippet。
4. 如果 `match_count=0`，不要盲目猜路径读取。

### 3.3 与 `list_known_functions`

`get_function_info` 是精确查询工具，不做模糊搜索；`list_known_functions` 是候选发现工具。两者边界如下：

| 场景 | 推荐工具 |
|---|---|
| 已有明确函数名，想知道位置/签名/调用关系 | `get_function_info` |
| 函数名可能不完整，需要用 pattern 找候选 | `list_known_functions` |
| 已经有文件和行号，需要代码证据 | `get_file_snippet` |
| 需要函数安全摘要 | `get_function_snapshot` |

### 3.4 与 `get_callers`

`get_function_info` 返回 `callers` 后，`get_callers` 会有一定重复。短期建议保留 `get_callers`：

- `get_function_info` 返回的是函数身份查询时顺带的有限调用者信息。
- `get_callers` 可继续作为 reachability 深查工具，支持更大 `limit` 或更复杂的调用者查询。

如果后续指标显示 `get_callers` 调用很少且完全被 `get_function_info` 覆盖，再考虑合并。

## 四、实现计划

### 4.1 CodeIndex 层新增查询方法

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
5. 对每个 match 查询 callers/callees，并归一化为 `caller_name/caller_file/callsite_line` 与 `callee_name/callee_file/callsite_line/call_type`。
6. 将 record 转换为工具输出字段。

### 4.2 新增工具文件

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

### 4.3 工具注册

需要更新：

| 文件 | 修改 |
|---|---|
| `zscope/core/analysis/analyzer.py` | 在 `_get_tools()` 中导入并注册 `GetFunctionInfoTool` |
| 相关 Agent/Skill 配置 | 先暴露给 `validator_agent` 和 `semantic_modeler` |
| `new_docs/tools_introduction.md` | 补充工具说明 |
| `new_docs/tools_optimation.md` | 记录实施结果 |

### 4.4 Agent 使用策略

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

## 五、测试计划

### 5.1 单元测试

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

### 5.2 回归指标

引入该工具后，重点观察：

| 指标 | 预期变化 |
|---|---|
| `get_function_impl` 调用次数 | 明显下降 |
| `get_file_snippet` 调用次数 | 可能小幅上升，但每次更精确 |
| validator_agent token | 下降 |
| Loop Guard warning/block | 不上升 |
| Default Recall / Precision | 不下降 |

## 六、风险与处理

| 风险 | 原因 | 处理 |
|---|---|---|
| `callers` 查询增加 backend 成本 | 每次 info 都查上下游关系 | 默认 `callers_limit=30`、`callees_limit=30`，必要时后续增加 `include_callers` |
| 和 `get_callers` 功能重叠 | 两者都能返回调用者 | 短期保留，基于指标决定是否合并 |
| 同名函数选择错误 | LLM 忽略 `match_count>1` | 在 Agent prompt 中明确多命中时必须说明选择依据 |
| `index_name` 语义混乱延续 | 复用 `get_function_impl` 返回逻辑 | 新方法直接读取 record 的真实 `index_name` |
| 输出过大 | callers/callees 过多 | 默认设置 `callers_limit=30`、`callees_limit=30`，由调用方按需调小 |

## 七、实施顺序

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

## 八、阶段性结论

`get_function_info + get_file_snippet` 是比继续扩展 `get_function_impl` 更清晰的设计。前者负责回答“这个函数是谁、在哪里、和谁相连”，后者负责回答“对应源码是什么”。这能保留 `get_function_impl` 中有价值的 signature、line range、caller/callee、external 信息，同时避免每次函数查询都返回完整代码正文。
