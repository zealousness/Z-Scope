# Semantic Modeler Agent 说明

本文说明当前主路径 `semantic_modeler` agent 的职责、输入构造、prompt 组织、工具策略、输出契约和 snapshot 持久化流程。实现以以下文件为准：

- `zscope/agents/semantic_modeler/AGENT.md`
- `zscope/agents/semantic_modeler/agent.py`
- `zscope/agents/semantic_modeler/schema.py`
- `zscope/snapshots/modeling_input.py`
- `zscope/snapshots/policy.py`
- `zscope/snapshots/store.py`

## 一、职责

Semantic Modeler 面向单个 C/C++ 函数或函数式宏，将源码转换为可复用的函数语义快照 `function_snapshot`。

主要职责：

- 总结函数目的、主要行为和对调用方可见的契约。
- 建模参数、返回值、副作用和错误路径。
- 结合预加载 callee 信息补充 callee 行为。
- 记录后续审计值得关注的事实，但不直接确认漏洞。
- 将不确定信息保留为 `unknown`，不根据缺失证据猜测。

非职责：

- 不负责对目标函数执行漏洞定性或最终验证。
- 不负责生成函数 identity、源码范围和 snapshot provenance。
- 不负责重新提取目标函数的全局变量和宏引用。
- 不应广泛探索与目标函数无关的代码。

## 二、运行入口

当前 Semantic Modeler 主要在以下路径中运行：

1. entry function 建模。
2. global model 批量建模。
3. premodel reachable callees。
4. 按需构建 `get_function_snapshot`。
5. 对外部 LLM snapshot 保存前重新解析 canonical context。

前四条路径通过 `build_semantic_model_input()` 构造统一输入。第五条路径不重新调用 Semantic Modeler，但会复用相同输入解析流程补齐程序提取字段并保存 snapshot。

在 global、premodel 和按需建模路径中，snapshot build lock 使用 canonical `index_name`，避免多个 worker 同时构建同一个函数快照。

global model、premodel 和按需 snapshot 在调用 Semantic Modeler 前还会执行 deterministic policy。简单函数、已知宏和轻量 wrapper 可以直接生成 `syntactic/lightweight` snapshot，不创建 LLM session。entry 主路径在未启用 global model 时仍直接执行 Semantic Modeler。

## 三、输入构造流程

### 3.1 唯一函数解析

`build_semantic_model_input()` 首先调用 `CodeIndex.find_function_infos()`，并按以下信息消歧：

1. 已有 `index_name`。
2. `file_path`。
3. `start_line`。

必须得到唯一匹配。查询无结果、匹配不唯一或 identity 不完整时，在调用 LLM 前终止，不从函数名或 location 字符串猜测身份。

### 3.2 完整源码获取

唯一匹配后，程序使用 canonical `index_name` 调用：

```python
code_index.get_function_impl(
    index_name,
    max_lines=None,
    warn_missing=False,
    include_context=...,
    file_path=file_path,
)
```

`max_lines=None` 表示 Semantic Modeler 输入使用完整函数定义，不受 `analysis.max_function_lines` 限制。普通代码检索仍保留自己的默认行数限制。

程序会校验 function info 与 implementation 的以下字段一致：

- `index_name`
- `file_path`
- `start_line`

### 3.3 必填输入字段

```json
{
  "func_name": "parse_request",
  "index_name": "parse_request@src/parser.c:40-120",
  "file_path": "src/parser.c",
  "start_line": 40,
  "end_line": 120,
  "signature": "int parse_request(Request *request)",
  "is_static": true,
  "is_macro": false,
  "code": "40 | static int parse_request(...) {\n...\n120 | }\n",
  "callees": [],
  "referenced_globals": [],
  "referenced_macros": []
}
```

| 字段 | 来源 | 说明 |
|---|---|---|
| `func_name` | function info | canonical function name |
| `index_name` | function info | snapshot 的唯一身份 |
| `file_path` | function info | 规范化源码路径 |
| `start_line` | function info | 完整定义起始行 |
| `end_line` | function info | 完整定义结束行 |
| `signature` | function info | 函数或宏签名 |
| `is_static` | function info | 是否为 static function |
| `is_macro` | function info | 是否为函数式宏 |
| `code` | function implementation | 带绝对行号的完整源码 |
| `callees` | function info | 预提取 callee identity、调用行和调用类型 |
| `referenced_globals` | function info | 程序提取的全局变量引用证据 |
| `referenced_macros` | function info | 程序提取的宏引用证据 |

### 3.4 可选输入字段

| 字段 | 说明 |
|---|---|
| `callees_truncation` | callee 数组达到上限时说明 returned/total |
| `referenced_globals_truncation` | 全局变量引用数组截断信息 |
| `referenced_macros_truncation` | 宏引用数组截断信息 |
| `user_config_context` | 与目标函数相关的用户项目配置 |
| `schema` | 自定义完整 snapshot schema，可为 object 或 JSON string |
| `agent_contract` | 运行时解析后的 agent system contract |
| `workflow_context` | 可选 workflow contract |
| `skill_contracts` | 可选 skill contract 内容 |

输入中不再包含用于 snapshot identity 的 `location`。

## 四、Prompt 组织

### 4.1 System prompt

system prompt 主要来自 `semantic_modeler/AGENT.md` 对应的 agent contract，并可追加：

- workflow contract；
- loaded skill contracts；
- 当前可见工具约束。

### 4.2 User prompt

user prompt 由三部分组成：

1. 目标函数名称。
2. `Target function metadata` JSON。
3. 带行号的完整函数源码。

存在 `user_config_context` 时追加项目上下文。

metadata JSON 包含 identity、callees、referenced globals、referenced macros 以及相应 truncation 信息。prompt 不再单独输出 `Location: ...`。

## 五、工具

Semantic Modeler 当前可见工具：

| 工具 | 用途 |
|---|---|
| `get_function_snapshot` | 优先读取 callee 已有语义快照 |
| `get_function_info` | 查询其他相关函数的 identity、callee 和符号引用上下文 |
| `get_file_snippet` | snapshot 或 function info 不足时读取精确源码范围 |
| `get_callers` | 仅在契约依赖调用方行为时查询 caller |
| `get_type_info` | 解析必要的类型、字段和布局信息 |

约束：

- 不得对目标函数调用 `get_function_snapshot`。
- 不得对目标函数重复调用 `get_function_info`。
- 运行时会拦截目标函数的冗余 `get_function_info`，返回 `target_function_info_preloaded`。
- `get_function_snapshot` 在禁用按需构建且 snapshot 缺失或 stale 时返回 `data=null` 和当前 `function_info`；agent 应直接复用，不再对同一函数调用 `get_function_info`。
- 不得使用相同参数重复调用同一工具。
- `get_file_snippet` 请求范围不得与初始源码或之前结果重叠。
- 对 callee 优先使用 snapshot，只在证据不足时继续查询 function info 或源码。

## 六、字段所有权

完整 snapshot 由程序字段、程序透传字段和 LLM 语义字段三部分组成。

### 6.1 程序生成字段

以下字段不暴露给 LLM 输出 schema：

```text
func_name
index_name
file_path
start_line
end_line
signature
snapshot_kind
is_static
is_macro
```

其中 `snapshot_kind` 固定为 `LLM-modeled`，其余字段来自统一输入。

### 6.2 程序透传字段

以下字段来自 function info，程序直接写入最终 snapshot，不允许 LLM 改写：

```text
referenced_globals
referenced_macros
```

存在时同时透传：

```text
referenced_globals_truncation
referenced_macros_truncation
```

这些字段是原始符号依赖证据，不等同于 LLM 对 global-state effect 的总结。

### 6.3 LLM 负责字段

LLM 主要输出：

```text
summary
parameters
return_values
effects
error_handling
callees
suspicious_points
```

完整 schema 中还定义了可选 `callers`，但它不是当前顶层 required 字段，也不是 Semantic Modeler 的主要建模要求；caller 信息通常由 `get_callers` 按需获取。

LLM 即使返回程序所有字段中的同名值，也会在后处理阶段被删除并由程序值覆盖。

### 6.4 Deterministic snapshot 字段

trivial/lightweight builder 不调用 LLM，但输出与主 schema 对齐的语义字段。十九个必需顶层字段为：

```text
func_name
index_name
file_path
start_line
end_line
signature
snapshot_kind
is_static
is_macro
referenced_globals
referenced_macros
summary
parameters
return_values
effects
error_handling
callees
suspicious_points
code
```

输入存在时额外透传：

```text
referenced_globals_truncation
referenced_macros_truncation
callees_truncation
```

其中两个 referenced truncation 位于 symbol-context 数组之后，`callees_truncation` 位于 `callees` 之后，`code` 始终位于最后。

deterministic builder 不再输出 `type/is_trivial/inputs/outputs/resources/concurrency/key_semantics`。其确定性映射包括：

- logging helper -> IO effect；
- lock/unlock wrapper -> lock effect；
- return/goto guard -> error path；
- checked allocator -> pointer return contract、memory/ownership effects 和 NULL failure path；
- pure expression macro -> empty effects；
- trivial suspicious point -> schema category、`lines` 和保留的证据元数据。

无法可靠推断的 parameter、return 或 callee behavior 使用空集合或 unknown contract，不通过字符串猜测补齐语义。

## 七、LLM 输出要求

### 7.1 Summary

`summary` 使用中文简洁描述：

- 函数目的；
- 主要行为；
- 对调用方可见的重要契约。

### 7.2 Parameters

每个参数记录：

- `parameter_name`
- `parameter_type`
- `meaning`
- `input_origin`
- `nullable`
- 可选 `ownership_effect`
- `constraints`

### 7.3 Return values

记录：

- `return_type`
- `meaning`
- `nullable`
- 可选 `ownership`
- `success_cases`
- `failure_cases`
- 可选 `caller_obligation`

void 函数仍需要输出 `return_values`，但 success/failure cases 可以为空数组。

### 7.4 Effects

所有可观察副作用统一写入 `effects`。支持的 category：

```text
memory, resource, ownership, alias, bounds, shared_state, lock,
thread, sync_protocol, io, callback, global_state, registry, other
```

每条 effect 必须包含：

- `category`
- `description`
- `line`
- `object`

可按证据补充 `api`、`condition`、状态变化、相关参数、`guard` 和 category-specific `details`。

### 7.5 Error handling

`error_handling.error_paths` 中每条错误路径记录：

- `trigger`
- `exit_line`
- `exit_action`
- `exit_states`
- 可选 `return_value`

`exit_states` 用于表达内存、资源、锁、引用或状态变量在该错误出口的最终状态。

### 7.6 Callees

预加载 callee 提供 identity、调用行和调用类型，LLM 负责补充 `callee_behavior`。

最终每个 callee 使用：

```json
{
  "callee_index_name": "decode@src/decode.c:10-80",
  "callsite_lines": [65],
  "call_type": ["direct"],
  "callee_behavior": "解析输入缓冲区并返回解码后的对象。"
}
```

如果完整源码中出现 function info 未提供的新 callee，agent 使用相同字段输出，并在必要时通过工具解析 canonical identity。不能解析时不得伪造 identity 或行为。

`call_type` 保持数组结构。同一 `callee_index_name` 聚合到 direct 和 indirect 两类调用边时返回 `["direct", "indirect"]`，不丢弃任一调用类型。

### 7.7 Suspicious points

记录供后续 validator 审计的事实，不直接声明漏洞成立。每项包含：

- `category`
- `lines`
- `description`

category 必须使用 schema enum。

## 八、最终输出示例

```json
{
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
  "summary": "校验请求对象并解析其输入缓冲区，成功时更新解析状态。",
  "parameters": [
    {
      "parameter_name": "request",
      "parameter_type": "Request *",
      "meaning": "待解析的请求对象。",
      "input_origin": "external",
      "nullable": "no",
      "ownership_effect": "mutate_borrowed",
      "constraints": ["request->data 必须指向可读缓冲区。"]
    }
  ],
  "return_values": {
    "return_type": "int",
    "meaning": "解析结果。",
    "nullable": "not_applicable",
    "success_cases": [
      {"value": "0", "condition": "请求解析成功。"}
    ],
    "failure_cases": [
      {"value": "负错误码", "condition": "参数无效或解码失败。"}
    ]
  },
  "effects": [
    {
      "category": "shared_state",
      "description": "解析成功后更新请求对象状态。",
      "line": 105,
      "object": "request->state",
      "condition": "decode 成功",
      "state_after": "parsed"
    }
  ],
  "error_handling": {
    "error_paths": [
      {
        "trigger": "request 为空",
        "exit_line": 45,
        "exit_action": "立即返回参数错误",
        "exit_states": [],
        "return_value": "-EINVAL"
      }
    ]
  },
  "callees": [
    {
      "callee_index_name": "decode@src/decode.c:10-80",
      "callsite_lines": [78],
      "call_type": ["direct"],
      "callee_behavior": "解码请求数据并返回解析对象。"
    }
  ],
  "suspicious_points": []
}
```

## 九、输出拼接与校验

运行时从完整 snapshot schema 派生 LLM schema，并删除程序生成/透传字段。LLM 完成 structured output 后：

1. 删除 LLM payload 中所有程序负责字段。
2. 合并 LLM 语义字段。
3. 最后覆盖写入程序生成字段和符号引用字段。
4. 返回 `AgentResponse(success=True, data=complete_snapshot, metadata=...)`。

输入缺少程序字段或符号引用字段类型错误时，不调用 LLM，返回：

```text
reason=semantic_model_input_invalid
llm_called=false
```

当前 JSON conversation 使用 structured final tool/response schema 约束输出，同时保留 JSON block 提取回退。

## 十、失败原因

LLM 调用前的稳定失败原因：

| reason | 含义 |
|---|---|
| `function_info_not_found` | function info 无匹配 |
| `function_info_ambiguous` | 多个定义无法唯一消歧 |
| `function_info_incomplete` | identity 字段不完整 |
| `function_impl_not_found` | 无法读取目标实现 |
| `function_info_impl_mismatch` | function info 与实现身份不一致 |
| `semantic_model_input_invalid` | Semantic Modeler 输入缺字段或类型错误 |

工具策略失败：

| reason | 含义 |
|---|---|
| `target_function_info_preloaded` | agent 重复查询目标函数 function info |

调用方还可能返回 `semantic_model_llm_missing`、`semantic_model_failed`、`semantic_model_exception` 或 `snapshot_lock_timeout`。

## 十一、持久化与复用

成功生成完整 snapshot 后，由 `SnapshotStore.save_snapshot()` 保存：

- `index_name` 是 SQLite 主键。
- snapshot 文件名由完整 `index_name` 的可读前缀和稳定 hash 派生。
- cache、lock、load/save/delete/refresh/fingerprint 全部使用 `index_name`。
- 保存时校验调用参数与 payload 的 `index_name` 完全一致。
- 保存 code hash、semantic hash 和 symbol context hash。

刷新判断同时考虑：

- 完整函数源码变化；
- 语义 fingerprint 变化；
- `referenced_globals` / `referenced_macros` 上下文变化。
- deterministic snapshot 是否仍符合当前 required/optional 字段集合和字段顺序；旧结构返回 `snapshot_shape_changed` 并触发廉价重建。

## 十二、日志

相关稳定日志前缀：

- `[snapshot-resolve]`：function info 解析和实现一致性。
- `[snapshot-lock]`：等待、获得或超时。
- `[snapshot-llm]`：建模入口、`index_name`、成功状态和 token。
- `[snapshot-store]`：保存、加载、缺失和 identity mismatch。
- `[snapshot-migration]`：旧 snapshot 数据迁移。

日志不应记录完整源码、完整 prompt、用户配置全文或完整 snapshot JSON。

## 十三、当前边界

- 应用层不再按代码行数截断 Semantic Modeler 源码，但仍受所选模型/provider 的上下文窗口限制。超出模型上下文时应由上层预算或模型配置处理，不能静默截断函数定义。
- function info 的 callee 数组存在固定上限；出现 `callees_truncation` 时不是完整集合。
- direct call 提取通常较可靠，函数指针和回调目标仍取决于 backend/SVF 能力。
- agent 可以从完整源码补充新 callee，但当前主要依靠 prompt 约束，尚未对新增 callee 执行统一的程序化 callsite/identity 验证。
- `is_valid_snapshot()` 对新 payload 要求完整 semantic field set，并保留 `type=function_snapshot` 的历史兼容入口；LLM 严格字段约束仍主要依赖 structured output schema，deterministic snapshot 由 policy shape checker 约束。
