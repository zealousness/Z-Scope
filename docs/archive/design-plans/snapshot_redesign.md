# Snapshot Redesign

> **历史文档，2026-11-17 归档。** 原位置：`new_docs/stage1optimation/snapshot_redesign.md`。本文保存已实施的多轮快照重构、被后续章节覆盖的旧方案及当时验证边界，不再作为新一轮重构清单。当前职责见[配置、语义与状态](../../modules/configuration-state.md)，当时实施过程见[上下文优化实施记录](../implementation/agent-context.md)。

本文记录 `semantic_modeler` 函数快照结构的设计、实施结果和后续计划。前八章所述方案均已实施；各章末记录实际偏差和已知问题。

## 一、Effects 统一设计

> 实施状态：已实施。

### 1.1 背景

当前 LLM-modeled snapshot 中，副作用相关信息分散在多个字段：

- `memory`
- `resources`
- `concurrency`
- 未来可能新增的 `side_effects`

这些字段各自有价值，但边界容易重叠：

| 当前字段 | 典型内容 | 问题 |
|---|---|---|
| `memory` | allocation、free、ownership、alias、buffer bounds | 和 resource lifecycle、return ownership 有交叉 |
| `resources` | fd/socket/file/mmap 等资源获取释放和 exit 状态 | 当前复用通用 events，和 memory/concurrency 混杂 |
| `concurrency` | shared state、lock、thread、atomic/refcount | lock/thread/refcount 也是资源或副作用 |
| `side_effects` | IO、全局状态、回调、注册表修改等 | 如果单独新增，容易再次变成杂项桶 |

更清晰的方向是：把这些都归入一个统一的 `effects` 字段，用 `kind` / `category` 区分事件类型。这样每个副作用都是一条结构化事实，而不是散落在多个 section 里。

### 1.2 设计目标

#### 1.2.1 目标

- 用一个字段表达函数对外部世界、对象状态、资源和并发状态的影响。
- 减少 schema 顶层字段数量，降低 LLM 输出负担。
- 避免 `memory` / `resources` / `concurrency` 之间重复记录同一事实。
- 让 validator 能按 `category` 过滤需要的证据。
- 保留行号、对象、条件、状态变化、风险说明这些审计必需信息。

#### 1.2.2 非目标

- 不在本阶段删除现有 schema 字段。
- 不在本阶段修改 `fallback` 文件。
- 不在本阶段修改 trivial/lightweight snapshot。
- 不在本阶段要求所有旧 snapshot 迁移。

### 1.3 核心思路

新增统一字段：

```json
"effects": []
```

`effects` 是数组。每个元素表示一个可审计的行为事实，例如：

- 分配内存
- 释放资源
- 转移 ownership
- 写共享状态
- 加锁/解锁
- 创建线程
- 调用回调
- 执行 IO
- 修改全局表/链表/注册表
- 做 buffer bounds 检查

每条 effect 由稳定的通用字段 + 按类别补充的 detail 字段组成。
其中 `description` 是必填中文自然语言字段，用于人工审阅；其余结构化字段仍是下游程序判断和过滤的主要依据。

### 1.4 初版结构

#### 1.4.1 顶层字段

```json
{
  "effects": [
    {
      "category": "memory",
      "action": "allocate",
      "description": "当 len 为正数时使用 malloc 分配 buf。",
      "line": 12,
      "object": "buf",
      "api": "malloc",
      "condition": "len 大于 0",
      "state_before": "尚未分配",
      "state_after": "已分配",
      "owner_before": "none",
      "owner_after": "local",
      "guard": "",
      "related_parameters": ["len"],
      "risk": "",
      "details": {
        "size": "len + 1",
        "failure_behavior": "returns NULL"
      }
    }
  ]
}
```

#### 1.4.2 通用字段

| 字段 | 类型 | 必填 | 说明 |
|---|---|---|---|
| `category` | enum | 是 | 副作用大类 |
| `action` | enum/string | 是 | 行为动作 |
| `description` | string | 是 | 给人工审阅的中文摘要，只描述当前 effect |
| `line` | integer/null | 是 | 发生位置 |
| `object` | string | 是 | 被影响对象、资源、状态或缓冲区 |
| `api` | string | 否 | 触发行为的 API 或 callee |
| `condition` | string | 否 | 中文触发条件或路径条件 |
| `state_before` | string | 否 | 中文行为前状态 |
| `state_after` | string | 否 | 中文行为后状态 |
| `owner_before` | string | 否 | 行为前 owner |
| `owner_after` | string | 否 | 行为后 owner |
| `guard` | string | 否 | 中文保护条件、锁、范围检查或协议说明 |
| `related_parameters` | string[] | 否 | 相关形参 |
| `risk` | string | 否 | 中文风险说明。无明显风险时填空字符串 |
| `details` | object | 否 | 类别专用补充字段 |

#### 1.4.3 category 候选

```json
[
  "memory",
  "resource",
  "ownership",
  "alias",
  "bounds",
  "shared_state",
  "lock",
  "thread",
  "sync_protocol",
  "io",
  "callback",
  "global_state",
  "registry",
  "other"
]
```

#### 1.4.4 action 候选

`action` 可以先采用宽松 enum，必要时按 category 细化。

```json
[
  "allocate",
  "release",
  "transfer",
  "retain",
  "borrow",
  "alias",
  "read",
  "write",
  "read_write",
  "check",
  "acquire",
  "try_acquire",
  "unlock",
  "create",
  "join",
  "detach",
  "schedule",
  "cancel",
  "call",
  "register",
  "unregister",
  "open",
  "close",
  "map",
  "unmap",
  "return",
  "goto",
  "unknown"
]
```

### 1.5 类别示例

#### 1.5.1 memory

```json
{
  "category": "memory",
  "action": "allocate",
  "description": "当 count 为正数时使用 calloc 分配 node。",
  "line": 18,
  "object": "node",
  "api": "calloc",
  "condition": "count 大于 0",
  "state_before": "尚未分配",
  "state_after": "已分配",
  "owner_before": "none",
  "owner_after": "local",
  "related_parameters": ["count"],
  "risk": "",
  "details": {
    "size": "sizeof(*node) * count",
    "failure_behavior": "returns NULL"
  }
}
```

#### 1.5.2 resource

```json
{
  "category": "resource",
  "action": "open",
  "description": "路径校验成功后调用 open 打开 fd。",
  "line": 22,
  "object": "fd",
  "api": "open",
  "condition": "路径校验成功",
  "state_before": "尚未获取",
  "state_after": "已获取",
  "owner_before": "none",
  "owner_after": "local",
  "risk": "",
  "details": {
    "resource_kind": "fd",
    "failure_value": "-1"
  }
}
```

#### 1.5.3 bounds

```json
{
  "category": "bounds",
  "action": "check",
  "description": "写入 dst 前检查 len 不超过 dst_size。",
  "line": 31,
  "object": "dst",
  "api": "",
  "condition": "len 不超过 dst_size",
  "state_before": "尚未校验",
  "state_after": "已校验",
  "guard": "通过 if 分支检查 len 不超过 dst_size，否则返回 -EINVAL。",
  "related_parameters": ["dst", "len"],
  "risk": "",
  "details": {
    "operation": "memcpy",
    "size_source": "len",
    "validated": "yes"
  }
}
```

#### 1.5.4 shared_state

```json
{
  "category": "shared_state",
  "action": "write",
  "description": "在 ctx->lock 保护下写入 ctx->state。",
  "line": 44,
  "object": "ctx->state",
  "condition": "状态转换成功",
  "state_before": "旧状态",
  "state_after": "新状态",
  "guard": "由 ctx->lock 保护。",
  "risk": "",
  "details": {
    "access": "write",
    "guard_kind": "mutex",
    "race_risk": "unknown"
  }
}
```

#### 1.5.5 lock

```json
{
  "category": "lock",
  "action": "acquire",
  "description": "修改 ctx 前获取 ctx->lock。",
  "line": 40,
  "object": "ctx->lock",
  "api": "pthread_mutex_lock",
  "condition": "修改 ctx 前",
  "state_before": "未持有锁",
  "state_after": "已持有锁",
  "risk": "",
  "details": {
    "lock_kind": "mutex",
    "held_after": "yes"
  }
}
```

#### 1.5.6 thread

```json
{
  "category": "thread",
  "action": "schedule",
  "description": "将 ctx->work 调度为异步执行。",
  "line": 75,
  "object": "ctx->work",
  "api": "queue_work",
  "condition": "请求异步处理时",
  "state_before": "尚未调度",
  "state_after": "已调度",
  "owner_after": "worker",
  "risk": "ctx 生命周期必须覆盖异步 work 执行期间。",
  "details": {
    "entry": "worker_main",
    "shared_objects": ["ctx"],
    "lifetime_note": "ctx must remain valid until work completes"
  }
}
```

### 1.6 与现有字段的映射

| 旧字段 | 新字段 |
|---|---|
| `memory.allocations` | `effects[category=memory, action=allocate]` |
| `memory.releases` | `effects[category=memory, action=release]` |
| `memory.ownership_transfers` | `effects[category=ownership]` |
| `memory.aliases` | `effects[category=alias]` |
| `memory.buffer_bounds` | `effects[category=bounds]` |
| `resources.events` | `effects[category=resource]` |
| `concurrency.shared_state_accesses` | `effects[category=shared_state]` |
| `concurrency.locks` | `effects[category=lock]` |
| `concurrency.lock_order_by_path` | `effects[category=lock]` with `details.order` |
| `concurrency.thread_effects` | `effects[category=thread]` |
| `concurrency.atomic_or_refcount_protocols` | `effects[category=sync_protocol]` |
| `side_effects.io_operations` | `effects[category=io]` |
| `side_effects.global_state_modifications` | `effects[category=global_state]` |

说明：本轮 redesign 不迁移 `error_paths`，也不要求下游对 `error_path` category 做适配。错误路径相关信息仍由现有 `error_paths` 字段承载；`resources.final_state_by_exit` 暂不纳入 `effects` 映射，避免把路径级事实混入事件级副作用列表。

### 1.7 初版 schema 草案

```json
{
  "effects": {
    "type": "array",
    "items": {
      "type": "object",
      "required": [
        "category",
        "action",
        "description",
        "line",
        "object",
        "condition",
        "risk"
      ],
      "properties": {
        "category": {
          "enum": [
            "memory",
            "resource",
            "ownership",
            "alias",
            "bounds",
            "shared_state",
            "lock",
            "thread",
            "sync_protocol",
            "io",
            "callback",
            "global_state",
            "registry",
            "other"
          ]
        },
        "action": {"type": "string"},
        "description": {"type": "string"},
        "line": {"type": ["integer", "null"]},
        "object": {"type": "string"},
        "api": {"type": "string"},
        "condition": {"type": "string"},
        "state_before": {"type": "string"},
        "state_after": {"type": "string"},
        "owner_before": {"type": "string"},
        "owner_after": {"type": "string"},
        "guard": {"type": "string"},
        "related_parameters": {
          "type": "array",
          "items": {"type": "string"}
        },
        "risk": {"type": "string"},
        "details": {"type": "object"}
      }
    }
  }
}
```

### 1.8 迁移建议

#### 1.8.1 第一阶段：并行新增

- 保留旧字段。
- 新增 optional `effects`。
- 让 `semantic_modeler` 优先输出 `effects`，旧字段仍可为空或按需保留。

#### 1.8.2 第二阶段：下游读取迁移

- validator 和 subagent 读取 `effects`。
- 按 `category` 过滤证据：
  - bounds/string: `bounds`, `memory`
  - resource lifecycle: `resource`, `memory`, `ownership`
  - concurrency: `shared_state`, `lock`, `thread`, `sync_protocol`
  - callback/reentrancy: `callback`, `lock`
- 本阶段不适配 `error_path` category；需要错误路径语义时继续读取现有 `error_paths`。

#### 1.8.3 第三阶段：删除旧字段

确认新 benchmark 指标稳定后，再从主 schema 删除旧字段：

- `memory`
- `resources`
- `concurrency`
- 未来如存在 `side_effects`，也不再单独保留

### 1.9 风险与注意事项

| 风险 | 说明 | 缓解 |
|---|---|---|
| `effects` 变成新杂项桶 | 过度自由会失去结构化价值 | 固定 `category`，要求 `action/object/line/condition/risk` |
| 单条 effect 信息过长 | LLM 可能塞入大段解释 | `description` 限制为中文一句话；`risk` 和 `details` 保持短句 |
| 下游暂不兼容 | validator 当前可能还读旧字段 | 第一阶段并行新增，不立即删除旧字段 |
| 事件重复 | 同一行为可能被记录两次 | 后续可按 `category/action/object/line` 去重 |
| fallback 被同步改动 | fallback 应保留降级/对照价值 | 除非明确要求，不修改任何 fallback 文件 |

### 1.10 初步结论

将 `memory`、`resources`、`concurrency`、`side_effects` 合并为 `effects` 是合理的。它可以降低顶层 schema 复杂度，也能把所有可审计副作用统一成事件事实。建议先以 optional `effects` 并行引入，等 validator 和 benchmark 适配后，再考虑删除旧字段。

## 二、Semantic Modeler 输入与身份字段程序化生成计划

> 实施状态：已实施（2026-07-17）。实施记录、测试结果、计划偏差和已知问题见 `new_docs/agent_optimation.md` 的“2026-07-17 Snapshot identity 重构”。

### 2.1 目标

以下字段不再要求 `semantic_modeler` 通过 LLM 输出，而是在 LLM 返回语义字段后直接复用 agent 输入中的程序值：

```json
[
  "func_name",
  "index_name",
  "file_path",
  "start_line",
  "end_line",
  "signature",
  "snapshot_kind",
  "is_static",
  "is_macro"
]
```

除固定值 `snapshot_kind="LLM-modeled"` 外，其余身份字段统一从 `CodeIndex.find_function_infos()` 的唯一匹配结果获取。目标函数的 `callees`、`referenced_globals` 和 `referenced_macros` 也随输入直接注入 user prompt，使初始上下文等价于预先执行一次目标函数的 `get_function_info`，避免 agent 再发起同样的工具调用。

### 2.2 `find_function_infos()` 输出契约

普通函数和宏的 function info payload 统一提供：

```json
{
  "function_name": "canonical function name",
  "index_name": "func@path:start-end",
  "file_path": "normalized/source/path.c",
  "start_line": 10,
  "end_line": 42,
  "signature": "int func(void)",
  "is_static": false,
  "is_macro": false,
  "callees": [],
  "referenced_globals": [],
  "referenced_macros": []
}
```

实施时需要统一当前接口差异：

- 普通函数显式输出 `is_macro=false`。
- 宏显式输出 `is_static=false`，并保留 `is_macro=true`。
- 不存在 callee、全局变量或宏引用时，对应字段返回空数组。
- `start_line` 和 `end_line` 表示索引中的完整定义范围，不受传给 LLM 的源码截断范围影响。
- `index_name`、路径和行号由 `find_function_infos()` 内部统一规范化，调用方不得再次自行拼接 canonical key。
- 如果存在 `callees_truncation`、`referenced_globals_truncation` 或 `referenced_macros_truncation`，应一并传入 prompt，避免模型把截断结果误认为完整集合。

程序生成的 snapshot 字段映射如下：

| snapshot 字段 | function info/input 来源 |
|---|---|
| `func_name` | `function_name` 映射为输入 `func_name` |
| `index_name` | `index_name` |
| `file_path` | `file_path` |
| `start_line` | `start_line` |
| `end_line` | `end_line` |
| `signature` | `signature` |
| `snapshot_kind` | 程序固定为 `LLM-modeled` |
| `is_static` | `is_static` |
| `is_macro` | `is_macro` |

`callees`、`referenced_globals` 和 `referenced_macros` 是预加载建模证据，不属于本轮直接拼接的九个身份字段。其中 snapshot 的 `callees` 仍由模型输出，因为模型需要基于预加载的 callee index、callsite 和 call type 补充 schema 要求的 `callee_behavior`。

### 2.3 查询、消歧与代码获取

四条 LLM 建模路径，包括全局建模、entry 建模、premodel 和按需 snapshot，都采用相同顺序：

1. 使用任务中的原始函数名和可用文件提示调用 `find_function_infos()`。
2. 如果已有 canonical `index_name`，优先用它查询；否则按 `func_name + file_path` 查询。
3. 返回多个结果时，使用已有 `index_name`、文件路径和起始行精确消歧。
4. 得到唯一 function info 后，使用其 `index_name` 调用 `get_function_impl()` 获取对应代码。
5. 查询无结果或无法唯一匹配时终止本次 LLM snapshot 构建，不从源码、函数名或 location 字符串猜测身份字段。

该顺序保证 function info 和 `code` 属于同一个函数定义，避免同名函数、重载或宏出现元数据与源码错配。

### 2.4 Semantic Modeler 输入契约

删除现有 `location` 输入。`SemanticModeler.run()` 的目标函数输入调整为：

```json
{
  "func_name": "canonical function name",
  "index_name": "func@path:start-end",
  "file_path": "normalized/source/path.c",
  "start_line": 10,
  "end_line": 42,
  "signature": "int func(void)",
  "is_static": false,
  "is_macro": false,
  "code": "numbered function source",
  "callees": [],
  "referenced_globals": [],
  "referenced_macros": []
}
```

现有可选输入，例如 `user_config_context`、`schema` 和 agent contract，保持不变。truncation 元数据仅在 `find_function_infos()` 返回时附加。

user prompt 直接包含两部分：

1. 目标函数 metadata JSON，包含上述身份字段、callee 和符号引用上下文。
2. `code` 对应的编号源码。

prompt 不再单独输出 `Location: ...`。需要源码位置时直接使用 `file_path`、`start_line` 和 `end_line`。snapshot 的查询、锁定、保存和加载统一使用 `index_name`，调用方不再为 snapshot 生命周期构造 location 字符串。

### 2.5 schema 拆分

保留完整 snapshot schema 作为持久化结构和下游契约，同时从它派生 LLM 输出 schema：

- 从 LLM schema 的 `required` 中删除九个程序生成字段。
- 从 LLM schema 的 `properties` 中删除九个程序生成字段。
- 自定义 semantic_modeler schema 同样执行该转换。
- `emit_function_snapshot` final tool 和 structured-output response format 都使用 LLM schema。
- `callees` 继续保留在 LLM schema 中；`referenced_globals` 和 `referenced_macros` 只作为输入证据，不新增为 snapshot 顶层字段。
- 本阶段不迁移未列出的字段，也不展开通用 validator 重构。

### 2.6 运行时拼接

LLM 完成结构化输出后，直接从 `input_data` 选取九个程序字段并覆盖合并：

```python
program_fields = {
    "func_name": input_data["func_name"],
    "index_name": input_data["index_name"],
    "file_path": input_data["file_path"],
    "start_line": input_data["start_line"],
    "end_line": input_data["end_line"],
    "signature": input_data["signature"],
    "snapshot_kind": "LLM-modeled",
    "is_static": input_data["is_static"],
    "is_macro": input_data["is_macro"],
}

complete_snapshot = {
    **llm_semantic_payload,
    **program_fields,
}
```

程序字段必须最后合并。即使模型通过自由文本或非严格 provider 返回同名字段，也由输入值覆盖。只有完整 snapshot 才能进入 `AgentResponse.data` 和 `SnapshotStore.save_snapshot()`。

### 2.7 SnapshotStore 的 `index_name` 存储模型

snapshot 存储层不再使用 `location` 或 `(func_name, file_path)` 标识记录。`index_name` 成为 snapshot 生命周期中的唯一标识，并同时用于：

- snapshot JSON 文件名的唯一来源；
- final report JSON 文件名的唯一来源；
- SQLite 主键；
- 内存 snapshot cache key；
- final report cache key；
- snapshot build lock key；
- fingerprint、refresh、delete 和 load/save API 的查询键。

建议将接口统一为：

```python
save_snapshot(index_name, snapshot, code)
load_snapshot(index_name)
save_final_report(index_name, final_report)
load_final_report(index_name)
get_fingerprints(index_name)
needs_refresh(index_name, current_code)
delete_snapshot(index_name)
lock_manager.acquire(index_name)
lock_manager.release(index_name, success=...)
lock_manager.invalidate(index_name)
```

`save_snapshot()` 必须校验参数 `index_name` 与 `snapshot["index_name"]` 完全一致；不一致时拒绝保存，防止调用方把 snapshot 写入错误记录。

#### 2.7.1 文件名

snapshot 文件名由完整 `index_name` 唯一派生：

```text
<encoded-index-name>.json
<encoded-index-name>_final.json
```

由于 `index_name` 包含 `/`、`:`、模板符号等不适合直接出现在文件名中的字符，需要提供统一的编码函数。编码结果必须：

- 只由 `index_name` 决定；
- 在不同进程中稳定；
- 避免不同 `index_name` 清洗后发生碰撞；
- 控制文件名长度，超长时保留可读前缀并追加完整 `index_name` 的稳定短 hash。

禁止继续按 `func_name + sanitized file_path` 生成文件名。

#### 2.7.2 SQLite schema

新的 snapshots 表以 `index_name` 为单列主键，并删除 `location`：

```sql
CREATE TABLE snapshots (
    index_name TEXT PRIMARY KEY,
    func_name TEXT NOT NULL,
    file_path TEXT NOT NULL,
    start_line INTEGER NOT NULL,
    end_line INTEGER NOT NULL,
    code_hash TEXT NOT NULL,
    semantic_hash TEXT NOT NULL,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    snapshot_file TEXT NOT NULL,
    final_report_file TEXT
);
```

`func_name`、`file_path` 和行范围保留为展示、筛选及诊断字段，但不再参与主键或 snapshot 选择。存储层不得再根据函数名、路径偏好或 location 猜测应加载哪条记录。

#### 2.7.3 数据库迁移

新增一次显式 schema migration：

1. 读取旧表中的 snapshot JSON。
2. 优先使用 JSON 内已有的 `index_name`。
3. 缺少 `index_name` 时，使用 snapshot 的 `func_name/file_path/start_line/end_line` 构造 canonical index name。
4. 无法获得完整身份字段时，将该记录计为 migration failure，不覆盖其他记录，也不静默生成模糊 key。
5. 发现两个旧记录映射到同一个 `index_name` 时记录 collision error，并停止自动覆盖。
6. 使用新的 index-name 文件名重命名或重写 snapshot/final report 文件。
7. 全部可迁移记录写入新表后，再切换表名并提交事务。

迁移需要输出总记录数、成功数、跳过数、失败数和冲突数。失败不能导致原表或原 JSON 文件被删除。

#### 2.7.4 location 清理边界

以下 snapshot 身份消费点全部改为 `index_name`：

- `SnapshotStore.save_snapshot()` 和 `save_final_report()`；
- snapshot/final report load、delete、refresh 和 fingerprint；
- cache 与 lock manager；
- global model、entry model、premodel、按需 snapshot 的保存和复用逻辑；
- on-demand snapshot tool 及其他调用 SnapshotStore 的 adapter；
- web snapshot 回写中用于定位 snapshot/final report 的逻辑。

删除 `_file_path_from_location()` 以及 snapshot store 中所有 location 解析和路径偏好选择代码。

本项只删除 location 作为 snapshot 身份标识的用途。issue、candidate、suspicious point 和 evidence 中用于表示具体源码行的 `location` 仍然保留，因为它们表达的是证据位置，不是 snapshot 主键。

### 2.8 工具与 prompt 策略调整

更新 `semantic_modeler/AGENT.md`：

- 删除要求模型 preserve 或输出九个身份字段的 Identity 描述。
- 明确模型只负责 LLM schema 中剩余的语义字段。
- 明确目标函数的 identity、callees、referenced globals 和 referenced macros 已由初始 prompt 提供。
- 禁止对目标函数再次调用 `get_function_info`。
- 允许对 callee 或其他相关函数调用 `get_function_info`，但优先使用 snapshot；只有预加载信息不足以完成语义建模时才查询。
- 保持 parameters、return values、effects、error handling、callees 和 suspicious points 的建模要求不变。

### 2.9 日志设计

日志应使用稳定前缀和结构化关键字段，区分解析、LLM、锁、存储和迁移阶段。不得记录完整源码、完整 prompt、用户配置内容或完整 snapshot JSON。

#### 2.9.1 Function info 解析日志

| 场景 | 级别 | 必要字段 |
|---|---|---|
| 开始解析 | `DEBUG` | `query_func`、`file_hint`、`index_hint` |
| 唯一匹配 | `DEBUG` | `index_name`、`match_count` |
| 无匹配 | `WARNING` | `query_func`、`file_hint`、`reason=function_info_not_found` |
| 多匹配无法消歧 | `WARNING` | `query_func`、`match_count`、候选 `index_name` 列表、`reason=function_info_ambiguous` |
| function info 与 impl 不一致 | `ERROR` | `index_name`、不一致字段、`reason=function_info_impl_mismatch` |

无匹配或无法消歧时必须额外记录 `llm_called=false`，并把稳定 reason 写入返回结果或 `AgentResponse.error`。

示例：

```text
[snapshot-resolve] function info not found query_func=foo file_hint=src/a.c llm_called=false reason=function_info_not_found
[snapshot-resolve] ambiguous function info query_func=foo matches=2 candidates=[foo@src/a.c:10-20,...] llm_called=false reason=function_info_ambiguous
```

#### 2.9.2 锁与建模日志

现有 `[snapshot-lock]` 日志改为只使用 `index_name`：

```text
[snapshot-lock] waiting index_name=foo@src/a.c:10-20 context=premodel
[snapshot-lock] outcome index_name=foo@src/a.c:10-20 status=acquired waited=0.02s
```

LLM 建模日志至少包含 `index_name`、建模入口、成功状态、token 统计和稳定失败 reason。不得再以 `func_name + file_path` 作为唯一诊断标识。

#### 2.9.3 存储日志

| 场景 | 级别 | 必要字段 |
|---|---|---|
| 保存成功 | `INFO` | `index_name`、`snapshot_file` |
| 加载未命中 | `DEBUG` | `index_name` |
| DB 记录存在但文件缺失 | `WARNING` | `index_name`、`snapshot_file` |
| snapshot 参数与内容不一致 | `ERROR` | 参数和 payload 中的 `index_name` |
| 删除成功 | `INFO` | `index_name` |
| final report 无对应 snapshot | `WARNING` | `index_name` |

#### 2.9.4 迁移日志

迁移开始和结束使用 `INFO`，单条无法迁移记录使用 `WARNING`，key collision 或事务失败使用 `ERROR`。结束日志输出：

```text
[snapshot-migration] completed total=... migrated=... skipped=... failed=... collisions=...
```

所有异常路径都必须保证 lock 以 `success=false` 释放，并记录对应 `index_name`；尚未解析出 `index_name` 时记录原始 query hints。

### 2.10 实施步骤

1. 统一 `find_function_infos()` 对普通函数和宏的 identity、callees 和符号引用上下文输出。
2. 增加 function info 唯一解析 helper，实现严格消歧。
3. 由 helper 使用唯一结果的 `index_name` 获取代码并构造统一 Semantic Modeler 输入。
4. 在全局建模、entry 建模、premodel 和按需 snapshot 四条路径中复用该输入构造流程。
5. 从 Semantic Modeler 输入中删除 `location`，并将 metadata JSON 与 code 直接写入 user prompt。
6. 在 schema 模块中保留完整 schema，并派生删除九个程序字段后的 LLM schema。
7. 在 `SemanticModeler` 中从 `input_data` 选取程序字段并对 LLM payload 执行最终覆盖合并。
8. 将 SnapshotStore API、cache、lock、fingerprint 和 final report 全部迁移到 `index_name`。
9. 增加 SQLite index-name 主键迁移和 index-name 文件重命名逻辑。
10. 更新所有 SnapshotStore 调用方，删除 snapshot 生命周期中的 location 构造和解析。
11. 更新 `AGENT.md` 的目标函数工具调用约束。
12. 按日志设计补齐解析、锁、LLM、存储和迁移日志。
13. 更新相关单元测试和集成测试。

### 2.11 验收条件

- Semantic Modeler 输入不再包含 `location`。
- 输入包含 identity、`code`、`callees`、`referenced_globals` 和 `referenced_macros`。
- 初始 user prompt 的 metadata 内容等价于一次成功且唯一匹配的目标函数 `get_function_info` 结果。
- semantic_modeler 不再对目标函数重复调用 `get_function_info`。
- LLM final tool schema 不包含九个程序生成字段，但仍包含 `callees`。
- LLM 只输出语义字段时，最终持久化 snapshot 仍包含完整身份字段。
- LLM 输出错误身份字段时，最终值由 Semantic Modeler 输入覆盖。
- snapshot callee 记录复用预加载的 index、callsite 和 call type，并由模型补充 `callee_behavior`。
- 普通函数、static 函数、宏、同名不同文件函数和同文件重载函数均能唯一解析。
- 长函数的 snapshot `end_line` 是完整定义结束行，而不是源码截断行。
- 无匹配或多匹配无法消歧时不调用 LLM，也不保存 snapshot。
- 无匹配、多匹配、存储失败和迁移失败均产生包含稳定 reason 的日志。
- snapshot 文件名由 `index_name` 唯一派生，清洗或截断后不会发生碰撞。
- SQLite snapshots 表以 `index_name` 为唯一主键且不再包含 `location`。
- load/save/delete/refresh/fingerprint/final report/cache/lock 全部只使用 `index_name`。
- DB 中的 `index_name`、snapshot payload 的 `index_name` 和调用参数始终一致。
- 同名不同文件函数和同文件重载函数能够独立保存、加载、刷新和删除。
- 旧数据库迁移失败时不破坏旧表和旧 JSON 文件。
- deterministic trivial/lightweight snapshot 的语义内容保持不变，但同样补齐并使用 canonical `index_name` 保存。

## 三、Deterministic Snapshot 输出结构统一计划

> 实施状态：已实施（2026-07-20）。实施过程、测试结果、计划偏差和已知问题见 `new_docs/agent_optimation.md` 的“2026-07-20 Deterministic snapshot 输出结构统一”。

### 3.1 目标

将 `build_trivial_snapshot()` 和 `build_lightweight_snapshot()` 新生成的 snapshot 统一为以下十九个必需顶层字段，并保持该顺序：

```json
[
  "func_name",
  "index_name",
  "file_path",
  "start_line",
  "end_line",
  "signature",
  "snapshot_kind",
  "is_static",
  "is_macro",
  "referenced_globals",
  "referenced_macros",
  "summary",
  "parameters",
  "return_values",
  "effects",
  "error_handling",
  "callees",
  "suspicious_points",
  "code"
]
```

如果统一输入中存在对应 truncation 元数据，则额外透传：

```json
[
  "referenced_globals_truncation",
  "referenced_macros_truncation",
  "callees_truncation"
]
```

字段位置固定为：

- `referenced_globals_truncation`、`referenced_macros_truncation` 位于两个 symbol-context 数组之后、`summary` 之前。
- `callees_truncation` 位于 `callees` 之后、`suspicious_points` 之前。

不存在时不输出对应 truncation 字段。除这三个条件字段外，不允许增加其他 deterministic snapshot 顶层字段。

本节只统一 deterministic trivial/lightweight snapshot。LLM-modeled snapshot 的输出字段和 LLM schema 暂不增加 `code`，也不修改任何 fallback 文件。

`referenced_globals` 和 `referenced_macros` 的数据获取及 builder 透传已经实现：`build_semantic_model_input()` 从唯一 function info 中提供两个数组，`policy.py::_program_symbol_context()` 已将其写入 trivial/lightweight snapshot。本节实施时保留该能力，并将两个数组纳入最终固定字段集合。

`snapshot_kind` 保留现有来源区分：

- trivial snapshot：`syntactic`
- lightweight snapshot：`lightweight`

### 3.2 当前差异

当前两类 deterministic snapshot 仍使用旧结构：

- 顶层包含 `type=function_snapshot`、`is_trivial=true`。
- 使用 `inputs`、`outputs`，而不是 `parameters`、`return_values`。
- 使用 `resources`、`concurrency` 和 `key_semantics` 表达静态摘要，而不是统一的 `effects`。
- `error_handling` 的内容是自由 object，不满足当前语义 schema 要求的 `error_paths` 结构。
- `callees` 可能是字符串数组，也可能是 function-info 风格的结构化记录，尚未统一为 snapshot callee 结构。
- `referenced_globals` 和 `referenced_macros` 已由程序写入，但尚未纳入统一字段常量、shape refresh 判断和严格输出测试。
- trivial suspicious point 包含详细证据字段，但 `category` 和必填字段尚未统一到当前 snapshot schema。

需要删除的旧顶层字段为：

```json
[
  "type",
  "is_trivial",
  "inputs",
  "outputs",
  "resources",
  "concurrency",
  "key_semantics"
]
```

这些字段中的有效语义不能直接丢弃，应映射到 `summary`、`return_values`、`effects`、`error_handling` 或 `suspicious_points`。

### 3.3 统一构造策略

在 `zscope/snapshots/policy.py` 中增加一个 deterministic snapshot 基础构造 helper，由 trivial 和 lightweight builder 共同使用。helper 负责：

1. 按固定顺序写入十九个必需顶层字段。
2. 从统一 Semantic Modeler input/implementation context 复制九个 identity/provenance 字段、`callees`、两个 symbol-context 数组及存在的三类 truncation 元数据。
3. 初始化 schema-compatible 的 `parameters`、`return_values`、`effects`、`error_handling`、`callees` 和 `suspicious_points`。
4. 将完整带行号源码写入最后一个 `code` 字段。
5. 构造结束时检查顶层 key 集合，防止旧字段重新进入 deterministic snapshot。

建议定义必需字段和允许的条件字段常量：

```python
DETERMINISTIC_SNAPSHOT_REQUIRED_FIELDS = (
    "func_name",
    "index_name",
    "file_path",
    "start_line",
    "end_line",
    "signature",
    "snapshot_kind",
    "is_static",
    "is_macro",
    "referenced_globals",
    "referenced_macros",
    "summary",
    "parameters",
    "return_values",
    "effects",
    "error_handling",
    "callees",
    "suspicious_points",
    "code",
)

DETERMINISTIC_SNAPSHOT_OPTIONAL_FIELDS = (
    "referenced_globals_truncation",
    "referenced_macros_truncation",
    "callees_truncation",
)
```

### 3.4 字段生成规则

#### 3.4.1 Identity 与源码

- `func_name`、`index_name`、`file_path`、`start_line`、`end_line`、`signature`、`is_static`、`is_macro` 直接复用统一输入，不再次解析 `location` 或自行拼接 identity。
- `snapshot_kind` 由 builder 固定写入，不允许调用方覆盖。
- `code` 保留完整带行号源码。trivial/lightweight 本身受长度策略限制，因此不额外截断。
- 缺少 canonical identity 时沿用 SnapshotStore 的 identity 校验并拒绝保存，不生成猜测值。

#### 3.4.2 `referenced_globals` 与 `referenced_macros`

- 直接复用统一输入中的数组，不要求 deterministic builder 再次查询 CodeIndex 或扫描源码。
- 没有引用时固定输出空数组，不省略字段。
- 保持 function info 已提供的定义位置、引用行、access、definition 和 `is_function_like` 等结构化内容。
- builder 应复制数组及其 item，避免调用方或下游修改 snapshot 时反向污染统一输入。
- 当前 `_program_symbol_context()` 已会可选透传 `referenced_globals_truncation` 和 `referenced_macros_truncation`，该行为保留。
- truncation 字段仅在统一输入实际包含时输出，内容原样复制，保持 `truncated`、`returned` 和 `total`。
- 输出顺序固定为对应 symbol-context 数组之后、`summary` 之前；只有一个 truncation 字段存在时只输出该字段。
- builder 应复制 truncation object，避免 snapshot 与输入共享可变对象。
- 本项只确认透传和结构统一，不修复 `KI-002` 中 backend-backed macro symbol context 缺少降级提取的问题。

#### 3.4.3 `parameters`

第一阶段不新增不可靠的 C/C++ signature 字符串解析器：

- 默认输出空数组 `[]`。
- 不把旧 `inputs=[]` 机械改名为带虚假语义的 parameter 记录。
- 后续如果 CodeIndex 提供结构化参数信息，再单独扩展 deterministic parameter 生成，不纳入本轮。

#### 3.4.4 `return_values`

`return_values` 始终使用当前 schema 要求的 object 结构，而不是旧 `outputs=[]`：

```json
{
  "return_type": "unknown",
  "meaning": "Deterministic snapshot does not infer a complete return contract.",
  "nullable": "unknown",
  "success_cases": [],
  "failure_cases": []
}
```

- 普通 trivial、logging、lock、pure-expression 和 guard wrapper 默认使用保守 unknown contract，不从复杂签名文本猜测返回类型。
- checked allocator wrapper 使用已有确定性规则生成更具体的 contract：pointer return、`nullable=yes`、`ownership=caller_owned`、成功返回 pointer、失败返回 `NULL` 和 caller null-check obligation。
- 能由现有确定性分支直接证明的返回事实可以填写；无法证明时保持 unknown，不把 summary 当成结构化返回值证据。

#### 3.4.5 `effects`

删除 `resources`、`concurrency` 和 `key_semantics` 后，将有确定性证据的行为映射为 schema-compatible effects：

| lightweight 类型 | effects 计划 |
|---|---|
| logging helper | 一条 `category=io` 的日志输出 effect |
| lock/unlock wrapper | 一条 `category=lock` 的 acquire/release effect；动作放入 description/details，不新增旧 action 顶层字段 |
| checked allocator wrapper | 一条 `category=memory` 的 allocation effect，必要时增加 `category=ownership` 的 caller-owned return effect |
| pure expression macro | 空数组 |
| return/goto guard macro | 通常为空；控制流语义写入 `error_handling` |
| 普通 trivial function | 默认空数组；不进行超出既有规则的副作用推断 |

每条 effect 至少包含当前 schema required 的：

- `category`
- `description`
- `line`
- `object`

已有 `key_semantics` 中未能结构化为 effect 的说明合并进 `summary`，不保留新的同义杂项字段。

#### 3.4.6 `error_handling`

所有 deterministic snapshot 至少输出：

```json
{
  "error_paths": []
}
```

- `RETURN_IF_*` / `GOTO_IF_*` guard macro 生成 trigger、exit line、exit action 和空 `exit_states` 的结构化 error path。
- checked allocator wrapper 为底层分配失败生成 `return_value=NULL` 的 error path，并记录相关内存对象处于 `not_acquired` 状态。
- 其他类型没有确定性错误路径时保持空数组。
- 删除当前 lightweight builder 中自由格式的 `control_flow`、`failure` 和 `caller_obligation` object；其中 caller obligation 移入 `return_values.caller_obligation`。

#### 3.4.7 `callees`

增加统一 callee normalization helper，兼容当前输入可能出现的字符串或 function-info callee record：

```json
{
  "callee_index_name": "callee@src/a.c:10-20",
  "callsite_lines": [12],
  "call_type": ["direct"],
  "callee_behavior": "Deterministic snapshot does not model callee behavior."
}
```

- 优先复用 function info 中的 canonical `callee_index_name` 和 `callsite_lines`。
- 输入为旧字符串时，将字符串暂作 `callee_index_name`，调用行使用空数组，不猜测文件和行号。
- `call_type` 保持 function info 的数组结构，过滤非法值并按输入顺序去重。
- 同时存在 direct/indirect 时完整保留 `["direct", "indirect"]`，不转换为 scalar，也不省略 mixed 类型。
- `callee_behavior` 使用明确的 deterministic/unknown 描述，不伪造 callee 语义。
- 统一输入存在 `callees_truncation` 时原样复制 `truncated`、`returned` 和 `total`，并将该字段放在 `callees` 之后。
- 不存在 `callees_truncation` 时不生成占位字段；输出 object 不与输入共享可变对象。

#### 3.4.8 `suspicious_points`

保留 trivial snapshot 已有的安全证据检测，但将记录补齐到当前 schema：

- 增加 required `lines` 字符串。
- 将当前细粒度 category 映射到 schema 大类，例如：
  - invalid free/untrusted pointer -> `memory_safety`
  - copy length/out-of-bounds -> `bounds`
  - lock protocol -> `concurrency`
  - protocol/state mismatch -> `state_protocol`
  - unchecked return -> `error_handling`
  - facade forwarding -> `api_contract`
  - 无法映射 -> `other`
- 当前 `type`、`reason`、`location`、`line`、`confidence` 和 `source` 作为 suspicious point 内部的可选证据元数据保留，不再作为 snapshot 顶层字段。
- lightweight snapshot 没有 suspicious point 时保持空数组。

### 3.5 下游消费点迁移

统一 builder 输出后，需要同步以下旧字段消费点：

1. `zscope/core/validation/evidence.py::compact_snapshot()`：
   - 删除 `resources`、`concurrency`、`key_semantics`。
   - 改为传递 `summary`、`effects`、`error_handling` 和 `suspicious_points`。
2. `zscope/semantics/inference.py::snapshot_contract_text()`：
   - 删除 `outputs`、`key_semantics`、lightweight-only `resources/concurrency`。
   - 改从 `summary`、`return_values`、`effects` 和 `error_handling` 提取确定性语义文本。
3. `zscope/common/utils.py::is_valid_snapshot()`：
   - 不再依赖 `type/key_semantics/inputs` 识别 snapshot。
   - 使用 canonical identity 与核心语义字段判定。
4. 测试、fake snapshot 和文档中所有只针对 deterministic snapshot 的旧字段断言同步更新。
5. 其他仍需要兼容历史 LLM/fallback snapshot 的通用消费者，不在本轮删除旧格式兼容分支。

### 3.6 历史 snapshot 兼容策略

本轮不原地重写已有 snapshot JSON，也不修改 SQLite schema。采用渐进式更新：

- 新生成的 trivial/lightweight snapshot 必须包含十九个必需字段，并且只允许额外包含输入中实际存在的三个 truncation 字段。
- `SnapshotStore.needs_refresh()` 增加 deterministic shape 检查；已保存的 `syntactic/lightweight` snapshot 如果仍包含旧字段或缺少新字段，返回 `needs_refresh=true`、`reason=snapshot_shape_changed`。
- global model、entry reuse、premodel 和按需 snapshot 在复用前都必须尊重该 refresh reason，重新执行廉价 deterministic builder。
- 通用下游消费者在迁移期保留旧字段 fallback，避免直接读取尚未刷新历史 snapshot 时丢失信息。
- final report 不因 deterministic snapshot shape 更新而主动删除；重建 snapshot 时是否清除 final report 沿用现有 SnapshotStore 行为，并在测试中明确验证。

### 3.7 实施步骤

1. 在 `policy.py` 定义 deterministic 顶层字段常量和基础构造 helper，并将已存在的 `_program_symbol_context()` 合并进固定字段构造流程。
2. 增加 canonical empty/default builders：return values、error handling、callee normalization 和 suspicious point normalization。
3. 重写 `build_trivial_snapshot()`，删除旧字段并输出十九个必需字段及存在的 truncation 字段。
4. 重写 `build_lightweight_snapshot()`，把 resources/concurrency/key semantics 映射到 return values/effects/error handling。
5. 为 deterministic snapshot 增加严格顶层 key 检查：十九个必需字段必须完整，额外字段只能来自允许的三个 truncation 字段。
6. 更新 validation evidence、semantic inference 和 snapshot validity 判断。
7. 增加旧 deterministic shape 的 refresh reason，并审计四条 snapshot 复用路径。
8. 更新 analyzer/global model 单元测试、snapshot store refresh 测试和相关 fake snapshot。
9. 更新 `new_docs/tools_introduction.md` 中 deterministic snapshot 示例。
10. 运行聚焦测试和完整回归测试；实施期间不修改 fallback 文件。

### 3.8 测试计划

- 对 trivial 和 lightweight builder 分别断言：
  - 无 truncation 时，`list(snapshot.keys()) == list(DETERMINISTIC_SNAPSHOT_REQUIRED_FIELDS)`；
  - 有 symbol-context truncation 时，对应条件字段位于两个数组之后、`summary` 之前；
  - 有 `callees_truncation` 时，该字段位于 `callees` 之后、`suspicious_points` 之前；
  - 顶层 key 集合不超过 required 与 optional 常量的并集；
  - 不存在 `type/is_trivial/inputs/outputs/resources/concurrency/key_semantics`；
  - `code` 是最后一个字段且内容未变化。
- 覆盖以下 lightweight 分支：
  - logging；
  - lock；
  - unlock；
  - pure expression；
  - return/goto guard；
  - checked malloc/calloc/realloc wrapper。
- 验证 allocator 的 return ownership、NULL failure path 和 allocation effect。
- 验证 structured function-info callee、旧字符串 callee、空 callee 和 mixed call type 的归一化。
- 验证 `callees_truncation` 存在时原样透传，不存在时不生成占位字段，并且输出对象不与输入共享可变对象。
- 验证 `referenced_globals` 和 `referenced_macros` 在 trivial/lightweight snapshot 中原样保留，无结果时为空数组，且输出对象不与输入共享可变 item。
- 验证 `referenced_globals_truncation` 和 `referenced_macros_truncation` 存在时原样透传，不存在时不生成占位字段，并且输出对象不与输入共享可变对象。
- 验证 trivial suspicious point category/lines 映射且原证据位置仍保留。
- 验证旧 deterministic snapshot 返回 `snapshot_shape_changed` 并被各建模路径重建。
- 验证 validation evidence 和 semantic inference 不再依赖旧 deterministic 字段。
- 运行 snapshot、global model、analyzer semantics、validation、semantic inference 相关测试后，再运行完整 `pytest`。

### 3.9 验收条件

- 新生成的 trivial 和 lightweight snapshot 始终包含指定十九个必需字段，额外字段只能是输入中实际存在的三个 truncation 字段。
- 两类 snapshot 的字段顺序一致，`code` 位于最后。
- identity 字段继续来自 canonical input，并与 SnapshotStore 参数和 SQLite `index_name` 一致。
- `referenced_globals` 和 `referenced_macros` 继续来自唯一 function info，不触发额外工具调用或源码查询。
- 所有新语义字段满足当前 schema 的数据类型和 required 子字段要求。
- 旧 resources/concurrency/key semantics 中仍有价值的确定性语义已映射，不发生静默丢失。
- `callees` 和 `suspicious_points` 不再输出旧的非统一结构。
- validator evidence 和 semantic inference 能消费新结构。
- 历史 deterministic snapshot 能以 `snapshot_shape_changed` 原因触发重建。
- 不修改 LLM-modeled snapshot 的 `code` 策略，不修改任何 fallback 文件。

## 四、Project / External Callee 分流与 Snapshot 拼接计划

> 实施状态：已实施（2026-07-21）。本文档中的“外部 callee”表示当前 CodeIndex 无法解析为项目函数或项目 function-like macro 的调用目标；其中可能包含标准库、第三方库、系统调用、外部配置函数、未解析间接调用和 backend 不完整事实。它不是对 API 语义或安全性的判断。

### 4.1 背景与问题

当前 `CodeIndex._function_info_callee_index_name()` 会优先将可解析项目函数转换为 canonical `index_name`，无法解析时保留原始名称。因此同一个 `callees` 数组同时包含：

- `foo@src/foo.c:10-30` 这类可安全查询 snapshot 的项目函数；
- `SAFE_FREE@include/common.h:24-24` 这类应保留的项目 function-like macro；
- `system`、`printf`、`memcpy`、`pthread_mutex_init` 等无项目定义的外部调用；
- 无法由当前 backend 唯一解析的调用目标。

Semantic Modeler 当前会在 user prompt 中看到全部 `callees`，同时 Agent policy 要求优先使用 `get_function_snapshot` 补充 callee behavior。于是模型会合理但无效地对 `system`、`printf` 等外部函数发起 snapshot 查询。全局建模 benchmark 已确认：

- `get_function_snapshot` 有 39 个明确 `success=false` 的失败；
- 其中多数是 libc、pthread、syscall 或无法唯一解析的宏；
- 这些调用不能获得项目 snapshot，却会增加工具轮次、prompt 和 completion 成本。

直接删除 CodeIndex 的外部调用边不可接受：外部 API 仍是源码依赖、effect 建模、callsite 证据和 snapshot refresh 的重要输入。设计目标是只把它们排除出 LLM 可查询的 project-callee 上下文，而不丢失程序证据。

### 4.2 目标与非目标

#### 4.2.1 目标

1. 将每个函数的调用目标按项目可解析性拆分为 `project_callees` 与 `external_callees`。
2. 两类 callee 在 CodeIndex 聚合后分别应用固定上限：project 为 30，external 为 20。
3. `get_function_info`、统一 Semantic Model 输入和 deterministic snapshot 使用同一份 CodeIndex 分流结果。
4. Semantic Modeler 的 LLM prompt 只暴露 `project_callees`，使其 callee-behavior 建模上下文不含 external/unresolved 调用。
5. LLM 仅补充项目 callee 的 `callee_behavior`；程序始终拥有 callee identity、callsite lines、call type 及全部 external callee 记录。
6. 最终 LLM-modeled snapshot 与 deterministic snapshot 均持久化两个 callee 字段，外部调用不丢失。
7. dependency-context fingerprint、refresh、validation evidence、semantic inference 和工具文档同步迁移到双数组契约。

#### 4.2.2 非目标

- 不在本轮为每个 libc、pthread 或 syscall 自动生成完整语义模型。
- 不根据名称猜测外部 API 的安全属性；外部调用语义仍以源码 effect 为准。后续接入 `external_function.config` 后，再单独设计外部函数的可查询行为、语义注入与权限边界。
- 不通过删除调用边隐藏 `system`、`memcpy`、`open` 等安全相关事实。
- 不在本期实施 `get_function_snapshot` 的 project-callee runtime allowlist 或 `callee_snapshot_not_allowed` 拒绝路径；现有工具访问行为保持不变。
- 不修改任何 fallback 文件，也不为旧字段增加生产 fallback。
- 所有实施、测试、文档和 benchmark 产物改动严格限制在 `/home/jager/Z-Scope` 工作树；`/home/jager/Z-Scope-baseline` 仅作为只读 Baseline 对照和历史证据，不修改其中任何文件。

### 4.3 最终数据契约

旧字段 `callees` 将从 function-info 输出、Semantic Model 输入和完整 snapshot 顶层契约中移除，替换为以下两个数组：

```json
{
  "project_callees": [
    {
      "callee_index_name": "parse@src/parser.c:10-30",
      "callsite_lines": [42],
      "call_type": ["direct"],
      "is_static": true,
      "is_macro": false,
      "callee_behavior": "由 LLM 或 deterministic builder 补充。"
    }
  ],
  "external_callees": [
    {
      "callee_index_name": "system",
      "callsite_lines": [37],
      "call_type": ["direct"]
    }
  ]
}
```

字段规则：

- `project_callees[]`：最终 snapshot 中 required `callee_index_name`、`callsite_lines`、`call_type`、`is_static`、`is_macro`、`callee_behavior`。`is_static` 和 `is_macro` 均为程序生成的 bool：普通项目函数保留其定义的 internal-linkage 状态并固定 `is_macro=false`；项目 function-like macro 固定 `is_static=false`、`is_macro=true`。identity、调用边和这两个标记由程序覆盖；只有 `callee_behavior` 可由 LLM 补充。
- `external_callees[]`：最终 snapshot 中 required `callee_index_name`、`callsite_lines`、`call_type`，不要求且不接受 LLM 生成 `callee_behavior`。
- `project_callees_truncation` 与 `external_callees_truncation`：仅在各自数组被截断时存在，结构固定为 `truncated`、`returned`、`total`。
- 旧 `callees` 与 `callees_truncation` 不再写入新 snapshot。其出现视为旧 shape，需要 refresh。
- 两类数组的 item 都按 canonical identity 聚合；调用行去重升序；调用类型仅保留稳定的 `direct`、`indirect` 数组。`project_callees` 的 `is_static`、`is_macro` 取 canonical 项目定义，不能由 callsite 或 LLM 推断；`external_callees` 不增加这两个字段。

`external_callees` 包含所有“未被 CodeIndex 解析为项目定义”的调用，因此其名称不等同于可由 `UserConfigStore.get_external_function()` 命中的外部配置函数。若未来增加外部语义 registry，可在不改变本契约的前提下向 external item 补充程序生成的来源/摘要字段。

### 4.4 CodeIndex 分流与截断策略

#### 4.4.1 分类规则

在 `zscope/retrieval/code_index.py` 中将现有单值 `_function_info_callee_index_name()` 扩展为返回 identity 与分类信息的内部 helper。分类必须发生在 limit 之前：

1. 能唯一解析到 `_function_index` 中项目函数的 callee -> `project_callees`，使用 canonical function `index_name`，并从其定义写入 `is_static`，写入 `is_macro=false`。
2. 能唯一解析到项目 function-like macro 定义的 callee -> `project_callees`，使用 canonical macro `index_name`，写入 `is_static=false`、`is_macro=true`。
3. 其他 callee -> `external_callees`，保留当前规范化名称；不调用 external fallback，不按名称推断库类别。
4. indirect edge 若无法唯一绑定项目定义，也进入 `external_callees`；不能为了填充 project array 而猜测目标文件。

普通函数 backend 路径、regex fallback 路径和 macro body 扫描路径必须共用同一分类 helper。项目 macro 不得因不在 `_function_index` 中而被误归为 external。

#### 4.4.2 聚合、排序与独立上限

- 先对全部 raw edge 按分类后的 `callee_index_name` 聚合，再合并 callsite lines 和 call type；project item 同时保留 canonical definition 的 `is_static`、`is_macro`。
- `project_callees` 按 canonical identity 稳定排序，独立应用上限 30。
- `external_callees` 按规范化名称稳定排序，独立应用上限 20。
- 两个 `total` 都以各自聚合后的总数计算；外部调用不能占用项目 callee 的 30 个名额，反之亦然。
- 两类 truncation metadata 独立输出；未截断的数组不输出对应 metadata。
- 不允许在 `build_semantic_model_input()` 中对已有 30 项旧 `callees` 再做后置过滤，因为那样会造成外部调用先占满 limit、项目调用已被丢弃的问题。

#### 4.4.3 Function Info Tool

`zscope/tools/function_info.py` 的成功 match 输出改为：

```json
{
  "project_callees": [],
  "external_callees": [],
  "project_callees_truncation": {
    "truncated": true,
    "returned": 30,
    "total": 42
  },
  "external_callees_truncation": {
    "truncated": true,
    "returned": 20,
    "total": 27
  }
}
```

- 旧 `callees` 和 `callees_truncation` 从 Tool 数据契约、description、JSON 示例和测试中删除。
- macro、external fallback 和零命中结构都返回两个空数组；只在真实截断时返回对应 metadata。
- Tool 不在本层调用 LLM 或 UserConfigStore 来为 external callee 生成行为。

### 4.5 Semantic Model 输入、schema 与最终拼接

#### 4.5.1 输入职责

`zscope/snapshots/modeling_input.py` 继续只通过 `find_function_infos()` 获取函数事实，并保留两个数组作为程序上下文：

```json
{
  "project_callees": [],
  "external_callees": []
}
```

但 `SemanticModeler._prompt_metadata()` 只向 LLM 暴露 `project_callees` 与其 truncation metadata：

- `external_callees` 和 `external_callees_truncation` 不进入 user prompt；
- LLM 仍可从目标源码看到外部 API 调用，因此应使用源码 effect 或 `unknown`，而不是请求其 snapshot；
- 完整双数组继续作为 `_save_snapshot_from_llm()`、SnapshotStore dependency context、global/premodel/on-demand refresh 的程序输入。

#### 4.5.2 LLM schema 与 program ownership

在 `zscope/agents/semantic_modeler/schema.py` 中：

- 以 `project_callees`、`external_callees` 替换完整 snapshot schema 的 `callees`。
- `external_callees`、`external_callees_truncation` 列入 program passthrough/excluded fields，LLM final tool 和 structured output schema 中不出现它们。
- LLM schema 中的 `project_callees` 只允许补充 `callee_behavior`；其 identity、callsite lines、call type、`is_static` 和 `is_macro` 在最终结果中均由程序输入覆盖。
- 两类 project/external truncation metadata 均不由 LLM 生成。
- 删除旧 `callees`、`callees_truncation` 的 required/properties 和相关 schema 常量，不保留旧 shape fallback。

#### 4.5.3 Agent merge 与工具约束

在 `zscope/agents/semantic_modeler/agent.py` 中新增 program merge：

1. 将 LLM 返回的 `project_callees` 按 `callee_index_name` 建立 behavior 映射。
2. 丢弃不在程序输入 `project_callees` key 集合中的 LLM item。
3. 用程序输入覆盖每个 project callee 的 identity、callsite lines、call type、`is_static`、`is_macro`，仅保留对应 LLM behavior；缺失 behavior 时写入明确的 unknown/未建模行为描述。
4. 深拷贝并原样附加程序 `external_callees` 与两类 truncation metadata。
5. 不新增或修改当前 Semantic Modeler 对 callee item 内容的 validation；仅沿用现有顶层 required-field 存在性检查，确保迁移后的 `project_callees`、`external_callees` 等顶层字段存在。不得增加 key 集合、顺序、callsite lines、call type、`is_static`、`is_macro` 或 `callee_behavior` 的逐项比对。

Agent policy 更新为：

- 只将 `project_callees` 作为需要补充 `callee_behavior` 的预加载上下文；`external_callees` 不进入 prompt。
- 对源码中可见的 external/unresolved 调用，基于可见源码事实描述 effect；无法确认行为时标为 unknown。
- 不在本期新增或修改 `get_function_snapshot`、`get_function_info`、`get_callers` 的 runtime 调用权限。外部函数的工具查询和配置语义待 `external_function.config` 接入时统一定义。
- 不得对 C 基础标量类型（如 `int`、`char`、`size_t` 及其指针/限定形式）调用 `get_type_info`。

### 4.6 Deterministic Snapshot 与 refresh

`zscope/snapshots/policy.py` 的 trivial/lightweight builder 改为：

- 从同一 Semantic Model input 复制 `project_callees`、`external_callees` 及各自 truncation metadata；
- project callee 原样保留 `is_static`、`is_macro`，并使用明确的 deterministic/unknown `callee_behavior`；
- external callee 原样保存 identity 与调用边，不生成虚构 behavior；
- 删除 `_normalize_callees()`、`callees_truncation` 和旧顶层 `callees` 的输出路径；
- 更新 deterministic required/optional field 常量、字段顺序和 shape checker。

SnapshotStore 的 dependency-context hash 必须投影两个数组和两个 truncation object：

- project/external 分类变化；
- canonical project identity 或其 `is_static`、`is_macro` 变化；
- external 原始名称变化；
- callsite line、call type 或任一 truncation 变化；

均应触发 `symbol_context_changed`。旧 snapshot 只含 `callees` 或 `callees_truncation` 时，统一返回 `snapshot_shape_changed` 并重建，不静默将旧字段映射为新字段。

### 4.7 需要修改的文件

#### 4.7.1 生产代码

至少修改以下文件：

1. `zscope/retrieval/code_index.py`
   - callee 分类、项目 macro 识别、双数组聚合、30/20 独立 limit 和双 truncation。
2. `zscope/tools/function_info.py`
   - Tool description、成功/external/macro payload 说明与输出字段同步。
3. `zscope/snapshots/modeling_input.py`
   - 统一输入透传双数组；prompt projection 只使用 project 侧；输入校验和稳定日志更新。
4. `zscope/agents/semantic_modeler/schema.py`
   - 双数组 final schema、LLM excluded/passthrough fields、truncation 与旧 field 删除。
5. `zscope/agents/semantic_modeler/agent.py`
   - project behavior merge 与 external passthrough；不修改当前 Semantic Modeler 输出的 callee 内容 validation，也不修改现有 snapshot 工具的 runtime 访问控制。
6. `zscope/agents/semantic_modeler/AGENT.md`
   - project-only callee-behavior prompt 上下文、external/unresolved 处理、基础类型查询限制；不增加 snapshot runtime allowlist。
7. `zscope/snapshots/policy.py`
   - deterministic 双数组输出、truncation、field order 和 shape checker。
8. `zscope/snapshots/store.py`
   - dependency-context hash、refresh reason 与旧 snapshot shape 检查。
9. 所有依赖 snapshot `callees` 的生产消费者（至少审计 validation evidence、semantic inference、snapshot tool、report/history 路径）。

不修改 fallback 文件。

#### 4.7.2 测试

至少新增或更新：

- `tests/test_function_info_tool.py`
- `tests/test_code_index_cache.py`
- `tests/test_semantic_model_input.py`
- `tests/test_json_output_agents.py`
- `tests/test_analyzer_semantics.py`
- `tests/test_global_modeler.py`
- `tests/test_snapshot_store.py`
- 受 `callees` 消费变更影响的 validation、snapshot tool、scan resume 与 report assembler 测试。

#### 4.7.3 文档与实施记录

实施时同步更新：

- `new_docs/agent_optimation.md`
- `new_docs/agent_introduction.md`
- `new_docs/tools_introduction.md`
- 本计划章节的状态、实际偏差、测试结果和已知限制。

### 4.8 实施顺序

1. 阶段 0：静态审计所有 `callees` / `callees_truncation` 生产者、消费者、schema、hash 和测试替身，记录不可省略的迁移点。
2. 阶段 1：实现 CodeIndex 分类 helper，覆盖 backend、regex 和 macro，完成双数组聚合及 30/20 truncation。
3. 阶段 2：迁移 `get_function_info` Tool 与 CodeIndex 测试，删除旧 `callees` 输出断言。
4. 阶段 3：迁移 `build_semantic_model_input()`、Semantic Modeler schema/AGENT/agent merge；验证 `system/printf` 不出现在 prompt 的 `project_callees`，仅检查迁移后顶层字段存在，不新增 callee item 内容验证，也不改变现有 snapshot 工具的 runtime 访问控制。
5. 阶段 4：迁移 deterministic snapshot policy、SnapshotStore hash/refresh 与下游消费者；旧 snapshot 必须走 `snapshot_shape_changed`。
6. 阶段 5：补齐四条 LLM 建模路径、snapshot tool、history/scan resume 和完整回归测试。
7. 阶段 6：运行 global-model benchmark，对比外部 snapshot 失败数、工具调用数、API calls、Prompt/Completion token 和项目 callee behavior 完整性。

### 4.9 测试矩阵

#### 4.9.1 CodeIndex 与 Tool 契约

- 项目函数、项目 macro、libc API、第三方未解析名称和 indirect unresolved edge 分别进入正确数组；普通函数的 `is_static` 与定义一致且 `is_macro=false`，项目 macro 固定为 `is_static=false`、`is_macro=true`。
- 同一 project/external callee 的多条 edge 合并调用行及 direct/indirect 类型。
- 31 个 project callee 只截断 project array，external array 不受影响；21 个 external callee 只截断 external array，project array 不受影响。
- project/external 两侧同时超限时，两个 truncation 的 `returned/total` 各自正确。
- `get_function_info` 普通函数、macro、external fallback、同名消歧和零结果均不返回旧 `callees` 字段。

#### 4.9.2 Semantic Modeler

- `platform_execute_task` 类输入中 `system`、`printf` 只存在于程序 external context，不出现在 prompt `project_callees`；不对其是否调用现有 snapshot 工具作断言。
- 有 canonical project callee 时，LLM schema 与 prompt 只含该 project callee；只断言迁移后的 required 顶层字段存在。
- 不新增针对 project/external callee item identity、callsite line、call type、`is_static`、`is_macro` 或 `callee_behavior` 的输出内容验证测试。
- `get_function_snapshot` 现有 runtime 访问行为不变；本期不新增 allowlist 拒绝路径，待 `external_function.config` 接入后另行测试其权限语义。
- `get_type_info("int")`、`get_type_info("const char *")` 被 policy/guard 拒绝，项目自定义类型仍可查询。

#### 4.9.3 Snapshot、refresh 与消费者

- LLM、trivial、lightweight snapshot 均只含 `project_callees`、`external_callees` 及存在的双 truncation 字段，不含旧 `callees`。
- external callee 的增加、删除、callsite/type 变化及 external truncation 变化都触发 `symbol_context_changed`。
- project/external 重新分类，或 project callee 的 `is_static` / `is_macro` 变化，均触发 refresh。
- 历史 snapshot 含旧 `callees` 或 `callees_truncation` 时返回 `snapshot_shape_changed`，重建后恢复 current。
- validation evidence、semantic inference、snapshot tool、history reconciliation、scan resume 与 final report 均消费双数组，不再读取旧字段。

#### 4.9.4 回归与 benchmark

- 聚焦运行 CodeIndex、function-info、Semantic Model input/schema、policy、store、global model、analyzer semantics、snapshot tool 和 validation 测试。
- 对修改模块执行 `py_compile` / `compileall` 与 `git diff --check`。
- 完整 `pytest` 通过；若存在既有失败，单独记录并证明与本计划无关。
- 对全局建模 benchmark 比较实施前后：外部 snapshot 查询尝试/失败（仅作观测）、总工具调用、API calls、Prompt Tokens、Completion Tokens、Total Tokens 与 project callee behavior 覆盖率。

### 4.10 验收条件

- `get_function_info`、Semantic Model input、LLM snapshot 和 deterministic snapshot 的 callee 契约均为 `project_callees` + `external_callees`，不再产生旧 `callees`。
- Semantic Modeler 本期只保证迁移后 required 顶层字段存在；不修改当前实现，也不新增 callee item 内容的 validation。
- project/external 分类在 backend、regex 和 macro 路径一致，且发生在独立 30/20 截断之前。
- 外部/unresolved callee 不再出现在 Semantic Modeler prompt 的 project callee 区域；本期不改变其现有工具查询可达性，后续由 `external_function.config` 集成方案定义。
- 项目函数和项目 macro 仍可在 prompt 中保留 canonical identity 及程序提供的 `is_static`、`is_macro`，并获得 LLM 或 deterministic `callee_behavior`。
- 最终 snapshot 不丢失 external callsite、call type 或 refresh 依赖事实。
- `platform_execute_task` 类场景中 `system`、`printf` 不出现在 prompt 的 `project_callees`，最终 snapshot 仍保留这两个 external callee；不对其现有工具调用行为作额外验证。
- 旧 snapshot 通过明确 refresh reason 重建；不修改任何 fallback 文件。

## 五、Semantic Modeler 单会话 Final Tool 与重复输出削减计划

> 实施状态：已实施（2026-07-22）。实施记录、测试结果、计划偏差和已知问题见 `new_docs/agent_optimation.md` 的“2026-07-22 Semantic Modeler 单会话 Final Tool”。

### 5.1 背景与问题

当前 `SemanticModeler.run()` 调用 `_run_json_conversation()` 时启用
`require_structured_finalization=True`，实际流程分为两个 LLM 会话：

1. 初始工具探索会话：暴露检索工具，模型收集 callee、类型和源码证据，并可能输出一份自由文本或非最终 schema 的 snapshot 草稿。
2. 独立 structured finalization 会话：复用完整探索 conversation，再次调用 LLM，并强制调用 `emit_function_snapshot` 或使用 structured output schema。

在本次 global-model benchmark 中，`platform_execute_task` 的探索会话产生了约 1,133 completion tokens，finalization 会话又产生了约 989 completion tokens；两个会话分别被记录为普通 Semantic Modeler session 和 `json_finalization=1` session。234 个 LLM snapshot 对应 468 个 Semantic Modeler session，说明当前设计普遍存在“先输出一次语义草稿，再输出一次最终 snapshot”的重复成本。

本计划选择方案二：将 `emit_function_snapshot` 作为初始工具循环中的终止工具，使模型在同一个工具 conversation 中完成证据收集并直接提交最终 snapshot，成功时不再创建独立的 `json_finalization=1` 会话。

### 5.2 目标与非目标

#### 5.2.1 目标

- Semantic Modeler 在同一 conversation/session 中完成检索、证据收集和最终 `emit_function_snapshot` 调用。
- 成功路径每个函数只产生一次最终 snapshot payload；不再先生成完整自由文本 snapshot，再重复生成结构化 snapshot。
- 保留当前 schema 校验、program-owned 字段覆盖、callees/symbol context 程序拼接和 snapshot 持久化契约。
- 保留必要的 repair 能力：final tool 参数不合法或 payload 语义校验失败时，可以在同一 conversation 中追加一次受控 repair；只有 repair 仍失败才返回错误。
- 保留工具循环的重复调用保护、最大迭代数、conversation recorder、token 统计和 `llm_called` 日志语义。
- 通过 opt-in 配置或 agent 参数只启用 Semantic Modeler；Validator、Vulnerability Analyzer、Issue Reconciler 和其他 JSON Agent 继续使用现有独立 finalization 行为。
- 让探索阶段的 assistant 文本不再被当作一个需要完整生成的 snapshot，降低 Completion Tokens 和 API 调用数。

#### 5.2.2 非目标

- 不在本计划中删除 `project_callees`、`external_callees` 或其他程序生成上下文；第四章负责其输入分流，本章负责最终输出时机。
- 不在本计划中实现第四章明确排除的 `get_function_snapshot` project-callee runtime allowlist 或 `callee_snapshot_not_allowed` 拒绝路径。
- 不修改 fallback 文件，不修改 `/home/jager/Z-Scope-baseline` 中的任何文件。
- 不保证每个函数只发生一次 HTTP/API request；探索工具调用和必要 repair 仍可能产生多次 API request。本计划保证的是一次成功 final payload 和一个主 conversation session。
- 不把初始模型的自由文本强制转换为最终 snapshot；旧的自由文本只作为 conversation context，最终结果必须来自 validated final tool payload。

### 5.3 最终会话协议

Semantic Modeler 的 opt-in 会话工具集合为：

```text
检索工具...
emit_function_snapshot  # terminal final tool
```

`emit_function_snapshot` 使用当前 `JsonOutputSpec` 的 final tool schema，参数仍为 semantic-only LLM schema；identity、snapshot provenance、referenced globals/macros 和其他 program passthrough 字段继续由程序生成或覆盖。

会话状态机：

1. 初始请求：发送目标 metadata、源码、Agent contract、检索工具和 terminal final tool schema。
2. 检索阶段：模型可调用允许的检索工具；runtime 追加 tool result 后继续同一个 conversation。
3. 最终提交：模型调用 `emit_function_snapshot`，runtime 识别 terminal tool，不把它当普通工具执行，也不再发送新的普通 assistant turn。
4. 本地校验：对 terminal tool arguments 执行 JSON schema/semantic validator，并调用现有 `post_process` 完成 program field merge。
5. 校验成功：立即返回 `AgentResponse(success=True, data=merged_payload)`，关闭同一个 recorder session。
6. 校验失败：在同一 conversation 中追加一次结构化 repair 指令；repair 成功后返回，失败后按现有错误/fallback policy 结束。

terminal tool 的识别必须基于明确的 tool name 和当前 `JsonOutputSpec`，不能根据任意函数名、JSON 内容或 assistant prose 猜测最终结果。

### 5.4 Runtime 状态机调整

#### 5.4.1 `JsonToolAgent` / `ToolCallingAgent`

- 为 `_run_json_conversation()` 增加 opt-in 参数，例如 `single_pass_final_tool`，默认 `False`，确保其他 Agent 行为不变。
- opt-in 时将 `_final_json_tool_schema(json_output_spec)` 合并到初始 `tools_schema`；避免在会话末尾再次创建独立 finalization request。
- 区分普通工具和 terminal final tool：普通工具进入现有 `tool_executor`；terminal final tool 进入 final payload capture/validation 分支。
- terminal tool 成功后停止 while loop，禁止继续调用检索工具、普通工具或再次生成自由文本最终答案。
- terminal tool 参数无效时，将 schema/semantic 错误作为结构化 tool result 或 repair prompt 放回同一个 conversation；repair 仍使用同一 recorder session 和同一 trace label。
- terminal tool 调用次数超过一次时，第一次合法 payload进入校验，后续调用被拒绝并记录稳定 reason，避免一次函数产生多个竞争 snapshot。
- assistant 返回普通 prose 且没有 tool call 时，opt-in 路径不立即把 prose 当成功结果；追加短指令要求调用 `emit_function_snapshot`，达到受控次数后进入现有失败处理。
- max iteration、loop guard、provider 返回 tool call 但 tools 已禁用等异常状态需要继续沿用现有错误 metadata，不得静默持久化不完整 snapshot。

#### 5.4.2 `LLMClient.run_conversation_with_tools`

- 增加可选 terminal tool 配置，或由上层传入 final tool name/handler，使 LLMClient 在收到 terminal tool call 后立即返回 `terminal_tool_call` payload。
- terminal tool 不应经过普通 `tool_executor` 的业务执行路径，也不应触发位置上下文、negative cache、工具 post-hook 等普通工具副作用。
- 仍记录 terminal tool 的 assistant message、arguments、校验结果和最终 session end，确保 conversation recorder 可完整复盘。
- `tool_call_count` 保留普通工具结果数量；新增或明确 `final_tool_call_count`、`terminal_tool_name` 和 `terminal_tool_valid` metadata，避免将最终提交误计为普通工具调用。
- XML invoke fallback 若产生同名 terminal tool，必须走同一 capture/validation 分支，不能生成普通未知工具错误。
- 支持 structured-output 的模型在本 opt-in 路径中统一使用 terminal function tool 作为最终输出协议；不再同时发起独立 `response_format` finalization，避免 provider 对 tools 与 response_format 组合行为不一致。

#### 5.4.3 `SemanticModeler`

- 将当前 `require_structured_finalization=True` 替换为单会话 terminal final tool opt-in。
- 保留 `_program_snapshot_fields()`、`_merge_program_snapshot_fields()` 和 `llm_function_snapshot_schema()` 的职责不变。
- final tool schema 仍只暴露 semantic fields；模型不得生成 identity、snapshot kind、referenced symbol arrays 或 program truncation metadata。
- 初始 system/user prompt 增加明确阶段语义：模型可以先检索，但不得输出完整 snapshot prose；完成证据收集后必须调用 `emit_function_snapshot`。
- 与第四章配合时，external callee 不进入 project callee behavior 区域；是否允许某个 project callee 查询由第四章输入分流决定，本计划不新增 runtime allowlist。
- 对 `get_type_info` 的基础类型限制沿用第四章策略；terminal final tool 方案不改变该工具权限。

### 5.5 Program merge、持久化与锁语义

- terminal payload 通过现有 `post_process` 进入 program merge，程序生成字段覆盖顺序保持不变。
- `save_snapshot()` 只接收经过 validator 和 merge 的最终 payload；探索阶段 prose、非结构化 JSON 或中间 assistant 内容不得写入 SnapshotStore。
- snapshot lock 只在最终 payload准备保存时沿用现有 `index_name` lock 语义；terminal tool 捕获失败时释放失败状态，允许后续重试。
- finalization repair 成功后仍使用同一 `index_name` 保存，不能生成第二份 snapshot 或第二个 final report。
- `dependency_context`、symbol/dependency hash 和 deterministic snapshot 分支不改变；本计划只替换 LLM semantic snapshot 的提交时机。

### 5.6 日志、conversation 与 token 指标

新增或统一以下字段：

- `[snapshot-llm]` 日志增加 `finalization_mode=single_pass_tool`。
- 成功日志包含 `terminal_tool=emit_function_snapshot`、`terminal_tool_valid=true`、`final_tool_call_count=1` 和累计 token。
- repair 日志明确 `terminal_tool_repair_attempted`、`terminal_tool_repair_accepted` 或失败 reason。
- 成功路径不再生成独立的 `json_finalization=1` recorder session；主 session label 保留 `function=<name>` 并记录 terminal tool。
- 兼容旧的 `finalization_attempted` 等 metadata，但新路径必须能区分“单会话 final tool”与“旧独立 finalization”。

Benchmark 指标必须同时报告：

- 每个函数的普通工具 API calls；
- terminal final tool calls；
- total API calls；
- Prompt/Completion/Total Tokens；
- `terminal_tool_valid` 成功率；
- repair 比例和 repair token；
- 独立 finalization session 数量，目标为 `0`；
- 每个成功 LLM snapshot 的 conversation session 数量，目标为 `1`。

### 5.7 需要修改的文件

本计划实施时预计涉及：

#### 5.7.1 生产代码

1. `zscope/agents/base.py`
   - 单会话 terminal tool 参数、capture/validation、repair 和 metadata。
2. `zscope/framework/llm_client.py`
   - terminal tool 识别、循环终止、recorder/session 记录和 XML fallback 对齐。
3. `zscope/agents/semantic_modeler/agent.py`
   - 启用 single-pass opt-in，更新阶段提示和 final tool 接入；保留 program merge。
4. `zscope/agents/semantic_modeler/schema.py`
   - 仅在测试证明需要时调整 final tool schema；不重复引入 program-owned 字段。
5. `zscope/agents/semantic_modeler/AGENT.md`
   - 说明探索阶段不得输出完整 snapshot，最终必须调用 terminal final tool。
6. `zscope/framework/conversation_recorder.py`
   - 如现有 recorder 无法区分 terminal tool 和普通工具，则补充事件字段；不改变历史记录解析兼容性。

#### 5.7.2 测试

- `tests/test_json_output_agents.py`
- `tests/test_llm_client_tokens.py`
- `tests/test_json_agent_loop_guard.py`
- 新增 Semantic Modeler single-pass final tool 专项测试
- 现有 Validator、Vulnerability Analyzer、Issue Reconciler JSON 流程回归测试
- conversation recorder/session label 和 token metadata 测试

#### 5.7.3 文档与实施记录

- `new_docs/agent_optimation.md`
- `new_docs/agent_introduction.md`
- `new_docs/tools_introduction.md`（如工具暴露说明发生变化）
- 本章状态、偏差、benchmark 对比和已知问题

不修改任何 fallback 文件。

### 5.8 实施顺序

1. 阶段 0：审计现有 `_run_json_conversation()`、`run_conversation_with_tools()`、recorder、terminal tool metadata 和所有 JSON Agent 测试，锁定旧路径行为。
2. 阶段 1：在底层增加 terminal tool 的识别与返回协议，先用假 LLM 覆盖普通工具 -> terminal tool -> session end 的最小状态机。
3. 阶段 2：在 `JsonToolAgent` 增加单会话 opt-in、payload validator、program merge 和同会话 repair；默认路径保持不变。
4. 阶段 3：仅为 Semantic Modeler 开启 opt-in，更新探索阶段 prompt，确保模型不再先生成完整 snapshot prose。
5. 阶段 4：补齐 loop guard、max iteration、XML invoke、非法 terminal payload、重复 terminal call、provider 不支持 tools 等异常路径。
6. 阶段 5：补齐 recorder、token metadata、日志和 benchmark metrics，验证不再出现独立 `json_finalization=1` session。
7. 阶段 6：运行 Semantic Modeler 专项回归，再运行完整回归；最后用同一 benchmark 对比单会话前后的 API calls、Prompt/Completion/Total Tokens、repair 比例和 snapshot 成功率。

### 5.9 测试矩阵

#### 5.9.1 成功路径

- 无需检索即可建模的函数：首轮直接调用 terminal final tool，成功保存一次 snapshot。
- 需要一个或多个检索工具的函数：检索结果完整进入同一 conversation，随后调用 terminal final tool 并成功保存。
- 探索阶段不接受自由 snapshot 作为最终结果，最终只接受 `emit_function_snapshot` payload。
- project/external callee 双数组输入与 terminal final tool 同时存在时，程序字段 merge 和 snapshot shape 正确。

#### 5.9.2 失败与修复路径

- terminal tool 参数缺字段、类型错误或 schema 不合法：同一 session 追加 repair，repair 成功后只保存一次。
- terminal payload 语义 validator 失败：记录稳定 reason，不接受探索阶段 prose，按 repair/failure policy 结束。
- 模型返回 prose 而不调用 terminal tool：追加短指令；超过限制后失败，不写入 snapshot。
- 模型重复调用 terminal tool：只允许一个合法提交，后续调用被拦截并记录 reason。
- 普通工具重复调用触发 loop guard：保留现有 recovery 行为，最终仍通过 terminal tool 或明确失败结束。
- terminal tool 在 max iteration 或 tools-disabled 状态下返回：验证不会被当成普通未知工具，也不会丢弃 payload。

#### 5.9.3 隔离与回归

- Validator、Vulnerability Analyzer、Issue Reconciler 的默认 JSON 流程仍创建并使用各自原有 finalization/repair 路径。
- structured-output 支持和 function-tool-only 模型均能完成最终 payload；单会话 Semantic Modeler 不再发起独立 finalization。
- recorder 中每个成功 Semantic Modeler snapshot 恰有一个主 session，`json_finalization=1` session 数为 0。
- token metadata 的累计值等于日志中各 API Trace 之和，terminal tool 不重复计入普通 tool calls。
- 现有 snapshot identity、symbol/dependency refresh、deterministic shape 和 program merge 测试不回归。

### 5.10 验收条件

- Semantic Modeler 成功路径只使用一个 conversation session，且最终 snapshot 由 `emit_function_snapshot` terminal tool 产生。
- 成功路径不再创建独立 `json_finalization=1` session；独立 finalization session 数为 0。
- 探索阶段的自由文本、旧 shape JSON 和 reasoning 不会直接持久化为 snapshot。
- 程序生成字段仍覆盖模型 payload，所有 snapshot identity、symbol context、snapshot kind 和 schema required fields 正确。
- 必要 repair 仍可在同一 session 完成；repair 失败时有稳定 reason、完整日志和可重试 lock 状态。
- 普通工具调用、terminal tool 调用、API calls 和 token 指标可分离统计；`final_tool_call_count` 成功路径为 1。
- Validator 等非 Semantic Modeler Agent 的默认行为和测试保持不变。
- global-model benchmark 对比显示：每个成功 LLM snapshot 的 session 数从约 2 降至 1，Completion Tokens、Total Tokens 和独立 finalization API calls 有可重复的下降测量；若 token 未下降，必须记录 provider/schema/reasoning 等原因，不得仅以调用次数下降宣称成本优化。
- 不修改任何 fallback 文件或 `/home/jager/Z-Scope-baseline` 文件。

### 5.11 计划偏差

- terminal payload 的 schema/semantic 校验由 `JsonToolAgent` handler 注入底层循环；没有把 Semantic Modeler 专用逻辑硬编码到 `LLMClient`。
- 非法 terminal payload 的修复依赖同一循环中的后续模型轮次；达到 `max_iterations` 后直接返回失败，不再额外创建独立 repair session。这样保证成功路径不回到双 session，但失败路径不会自动复用旧 finalization fallback。
- recorder 增加 terminal summary 事件，但没有改变历史 JSONL 事件格式的解析器；旧记录仍按原字段读取。
- 本轮只扩展 global-model 的 `[snapshot-llm]` 日志字段；entry、on-demand 和 premodel 的日志仍主要依赖 response metadata，未逐处改写日志格式。
- XML fallback 复用已有参数解析器；复杂嵌套 XML 参数的完整 JSON 恢复没有在本节新增专用解析器。

### 5.12 已知问题

- 当前测试环境缺少 `scripts` Python 包，完整 `pytest` 仍无法收集 `test_benchmark_protocol.py` 与 `test_range_benchmark_regression.py`；排除这两个文件后回归为 `716 passed`。
- 尚未在同一 global-model benchmark 上重新跑完整成本对比，因此 Completion Tokens、Total Tokens 和 API calls 的实际下降幅度仍需实测；本节只提供可分离统计字段。
- provider 若在 terminal tool 参数中持续返回 schema-invalid payload，单会话会消耗迭代预算并最终失败；这是有界行为，不会写入不完整 snapshot，但需要上层重试策略处理。
- terminal tool 与普通工具混合在同一 assistant 响应时，terminal 提交会被拒绝并要求模型重试；普通工具调用仍会执行，因此该异常路径可能增加一次 API 轮次。

## 六、Callee Summary 程序透传与无 LLM Refresh

> 实施状态：已实施（2026-07-22）。本章取代此前的 Known / Unknown canonical identity merge 方案。Semantic Modeler 的 LLM 输出 schema 已完全移除 project_callees；callee summary 仅来自 canonical callee snapshot，并由程序在最终 snapshot 中透传和刷新。不实施 snapshot runtime allowlist，不接入 external_function.config，不修改任何 fallback 文件。

### 6.1 最终职责划分

Semantic Modeler 只负责当前目标函数的语义字段：

- summary
- parameters
- return_values
- effects
- error_handling
- suspicious_points

程序负责并最终覆盖：

- 当前函数 identity、signature、snapshot_kind、is_static、is_macro
- project_callees、external_callees
- referenced_globals、referenced_macros
- project/external callee truncation metadata
- globals/macros truncation metadata

project callee 的 callee_summary 只允许逐字复用对应 callee snapshot 的顶层 summary。没有可用 summary 时使用稳定值 unknown。Semantic Modeler 可以查看 unknown callee 的 snapshot、function info 或代码来完善当前函数语义，但不得生成、返回或修改任何 callee summary。

### 6.2 Schema 与 Prompt 契约

完整 persisted snapshot schema 继续保留 project_callees property。最终记录结构为：

    {
      "callee_index_name": "parse@src/parser.c:10-30",
      "callsite_lines": [42],
      "call_type": ["direct"],
      "is_static": true,
      "is_macro": false,
      "callee_summary": "解析输入并返回结构化结果。"
    }

Semantic Modeler 的 LLM schema：

- properties 中不存在 project_callees。
- required 中不存在 project_callees。
- 不存在 callee_index_name/callee_summary 的 LLM item schema。
- external callee、identity、symbol context 和 truncation metadata 同样不由 LLM 输出。

user prompt 继续包含 project_callees、external_callees、两侧 truncation metadata、symbol context、目标函数 identity 和代码。known callee summary 可直接作为证据；unknown 时只允许按需检索以理解当前函数。

project_callees 已加入程序 passthrough 字段集合。Semantic Modeler 输入缺少该字段或字段不是 array 时，在调用 LLM 前失败。

### 6.3 Semantic Modeler 合并

旧的 canonical identity summary merge 已删除。最终合并过程为：

1. 丢弃 LLM payload 中所有 program-owned 字段。
2. 保留通过 LLM schema 校验的当前函数语义字段。
3. 从 Semantic Model input 深拷贝完整 project_callees、external_callees、symbol context、truncation metadata 和 identity。
4. program-owned 字段最后覆盖，形成最终 AgentResponse.data。

模型即使额外返回 project_callees，也不会影响最终数组。程序不再处理 LLM callee 的乱序、稀疏、重复、空 identity 或未知 identity。

### 6.4 初次 Summary Hydration

调用 Semantic Modeler 或读取已有 snapshot 前，统一执行程序侧 hydration：

1. 按 callee_index_name 查询 current callee snapshot。
2. snapshot summary 非空时逐字写入 callee_summary。
3. snapshot 缺失、stale 或 summary 为空时写入 unknown。
4. 不改变 callee 数量、顺序、identity、调用行、调用类型或 static/macro 标记。
5. self recursion 若已有自身 snapshot，可直接复用自身顶层 summary；首次建模仍为 unknown。
6. hydration 不启动 LLM。

该路径已接入 global、entry、premodel、on-demand、scan-session 和 snapshot tool。已有 caller snapshot 在再次消费前会尝试执行 program-only reconciliation；reconciliation timeout 或失败会终止当前语义输入构造，避免向下游返回已知过期的 callee summary。

deterministic snapshot 使用同一程序 hydration，不因 unknown 启动 LLM。

### 6.5 Fingerprint 拆分

SnapshotStore 将原本混合在一起的结构依赖和 summary 依赖拆分为：

- symbol_context_hash：跟踪 project callee identity、调用边、static/macro 标记、external callee、globals/macros 和 truncation；不包含 callee summary。
- callee_summary_hash：只跟踪 canonical project callee identity 和透传 summary。

SQLite snapshots 表新增 callee_summary_hash。新建数据库直接包含该列；已有 index-name 数据库启动时自动回填 callee_summary_hash，并按新规则重算 symbol_context_hash；旧数据库迁移同样写入两个 hash。

refresh 分类：

- 当前函数代码发生语义变化：code_changed，需要 LLM refresh。
- 调用结构、symbol context 或 truncation 变化：symbol_context_changed，需要 LLM refresh。
- 仅 callee summary 变化：callee_summary_changed，不调用 LLM。
- 旧 callee_behavior、缺失 callee_summary 或旧 deterministic shape：snapshot_shape_changed。
- 纯源码格式变化：cosmetic_change_only。

### 6.6 Program-only Atomic Reconciliation

SnapshotStore 新增 reconcile_project_callee_summaries：

1. 使用 canonical index_name 的独立 refresh lock 串行化更新。
2. 校验当前结构 hash 与已保存 symbol_context_hash 一致；结构变化时返回 llm_refresh_required，不把结构变化伪装成 summary patch。
3. 深拷贝当前 program input 的完整 project_callees。
4. 只替换 persisted snapshot 的 program-owned project_callees，保留全部 LLM semantic fields。
5. 原子写入 JSON，更新 callee_summary_hash、timestamp、snapshot cache。
6. 不清除或重新生成当前函数 semantic fields，不增加 API Calls。
7. 返回 refreshed、unchanged、missing、llm_refresh_required、timeout 或 failed。

并发 reconciliation 使用同一 index lock；相同目标的并发更新最终形成一个 refreshed 和后续 unchanged，不产生部分 JSON 或丢失字段。

### 6.7 Global Model 阶段末 Reconciliation

全局建模所有 component 完成后，如果没有建模失败和 unresolved entry，则执行阶段末 reconciliation：

1. 从本轮全部成功且 current 的 snapshot 冻结 summary_map：

       callee_index_name -> snapshot.summary

2. 对每个 caller 重新构造 canonical program input。
3. 以 caller program input 的 project_callees 数量和顺序为准，exact match summary_map。
4. 命中非空 summary 时写入；未命中保持 unknown。
5. 调用 SnapshotStore program-only reconciliation。
6. 统计 reconciled_functions、reconciliation_unchanged_functions、reconciliation_failures 和 unknown_project_callees。

summary_map 在任何 caller patch 前冻结，因此一次 pass 即可处理：

- self recursion
- mutual recursion SCC
- 并发 component 的完成顺序差异
- caller 先于某个 callee 保存时产生的暂时 unknown

匹配使用 exact canonical index_name，不做别名、路径、大小写或位置归一化。

### 6.8 全局阶段门禁与断点恢复

GlobalModelStats 增加：

- unresolved_entry_functions
- reconciled_functions
- reconciliation_unchanged_functions
- reconciliation_failures
- unknown_project_callees
- stage_complete

stage_complete 仅在以下条件全部满足时为 true：

- failed_functions 等于 0。
- unresolved_entry_functions 等于 0。
- reconciliation_failures 等于 0。

ParallelAnalyzer 在 global model 未完成时直接阻止 entry fan-out，不再关闭 enable_global_model 后降级到逐入口建模。

API、网络或模型服务失败时，已成功 snapshot 保留；恢复后重新运行，全量 current snapshot 命中 cache，只重试失败或缺失函数。失败时不生成 fallback summary，也不为 callee summary 启动额外 LLM。

完整 benchmark 入口列表可使每个列出的函数成为 depth-0 root，但普通配置仍受入口范围、max_premodel_depth 和 max_premodel_callees 限制。“全局完成”只覆盖本轮要求建模、可唯一解析且通过阶段门禁的函数。

### 6.9 Backend、External 与截断边界

本方案不修复 extractor 没有提供的调用边：

- backend 没有解析出调用边：不进入 project/external 数组，没有 callee summary。
- 调用名称无法唯一解析到项目定义：进入 external_callees，可能进入 prompt，但没有 callee summary。
- project callee 超过 30 条：仅保留前 30 条，被截断项没有 summary，由 project_callees_truncation 报告。
- external callee 超过 20 条：由 external_callees_truncation 报告。
- 被遗漏或截断的函数即使因为完整入口列表而独立拥有 snapshot，也不会被猜测并拼回 caller。
- 全局图的深度/宽度限制与 Function Info 的 30/20 输出上限分别统计。

因此“完整 snapshot”表示被 CodeIndex 保留的 project callee 尽可能具备 canonical summary，不表示恢复源码中的全部真实调用边。

### 6.10 修改文件

生产代码：

- zscope/agents/semantic_modeler/schema.py
- zscope/agents/semantic_modeler/agent.py
- zscope/agents/semantic_modeler/AGENT.md
- zscope/snapshots/modeling_input.py
- zscope/snapshots/store.py
- zscope/snapshots/policy.py
- zscope/orchestration/global_modeler.py
- zscope/orchestration/parallel_analyzer.py
- zscope/core/analysis/analyzer.py
- zscope/orchestration/scan_session.py
- zscope/tools/snapshot_tool.py

测试：

- tests/test_json_output_agents.py
- tests/test_semantic_model_input.py
- tests/test_snapshot_store.py
- tests/test_global_modeler.py
- tests/test_parallel_shared_semantics.py
- tests/test_snapshot_tool.py
- 既有 analyzer、function-info 和 deterministic snapshot 回归

文档：

- new_docs/agent_optimation.md
- new_docs/agent_introduction.md
- new_docs/tools_introduction.md
- [本历史快照方案](snapshot_redesign.md)

不修改 fallback 文件，不修改 /home/jager/Z-Scope-baseline，不回退用户手动修改的 schema 字段。

### 6.11 验证结果

聚焦验证覆盖：

- LLM schema 的 properties/required 均不存在 project_callees。
- prompt 仍包含 project/external callee。
- LLM 伪造、乱序、稀疏或重复 project callee 无法改变 program records。
- known、unknown 和 self-recursive hydration。
- callee summary-only refresh 不调用 LLM。
- semantic fields 在 program-only refresh 后逐字保持。
- self recursion、mutual SCC 一轮 reconciliation 收敛。
- summary_map 多余 identity 被忽略，缺失 identity 保持 unknown。
- 并发 program-only refresh 串行化。
- failed function 和 unresolved entry 使 stage_complete=false。
- global stage failure 阻止 entry analysis。

执行结果：

- Semantic Modeler、hydration、SnapshotStore、global model、parallel gate 与 snapshot tool 聚焦集合：68 passed。
- 可收集完整回归：728 passed。
- python -m compileall -q zscope：通过。
- git diff --check：通过。
- 完整 pytest 仍有两个 benchmark 测试因环境缺少 scripts Python package 无法收集；本轮未修改相关 fallback 或环境文件。

### 6.12 实施偏差与后续项

- 计划中的 semantic_input_hash 没有新增同名数据库列；实际沿用并收窄既有 symbol_context_hash，使其只表达需要重新建模的结构化上下文，另增 callee_summary_hash。这避免不必要的数据库字段重命名和迁移。
- 非全局路径未实现常驻反向依赖监听器；统一 hydration 在 snapshot 正式消费前执行局部 program-only reconciliation。全局路径仍执行完整阶段末 reconciliation。
- 未重新运行同配置 global-model benchmark，因此 Completion Tokens、Total Tokens 和 API Calls 的实际降幅尚待实测；功能测试已证明 summary refresh 不增加 Semantic Modeler 调用。
- external callee summary 继续等待 external_function.config。
- snapshot runtime allowlist 保持未实施。

## 七、Referenced Types 程序注入与类型上下文刷新计划

> 实施状态：已实施（2026-07-23）。
>
> 计划基线：2026-07-23 `global_model_20260723_090135`。本章采用完整实现：在索引层建立精确的函数到类型引用关系，将直接 `referenced_types` 作为 program-owned context 注入并持久化，并使类型定义变化参与 snapshot refresh。本轮不修改 `get_type_info` Tool 的参数、查询、fallback、返回结构或错误语义；除非用户另行明确要求，不修改任何 fallback 文件，不修改 `/home/jager/Z-Scope-baseline`，不回退用户手动修改的文件。

### 7.1 背景、现状与问题证据

当前 Semantic Modeler 输入已经由程序提供：

- 当前函数 identity、signature 和完整函数源码；
- `project_callees` 与 `external_callees`；
- `referenced_globals` 与 `referenced_macros`；
- 上述数组存在的 truncation metadata。

类型定义仍依赖 LLM 主动调用 `get_type_info`。这会产生三个问题：

1. 模型只看到目标函数体和目标文件路径，不一定知道类型声明所在的头文件。
2. `get_type_info.file_path` 表示声明文件，而模型容易把目标函数的使用文件当成声明文件。
3. 同一个常用类型会被不同函数重复查询，增加工具调用、API 轮次和 Prompt Tokens。

`_plugin_register@src/plugin.c:32-64` 是确定的复现案例：

- 初始上下文包含 `PluginRegistry*` 参数和 `Plugin*` 局部变量，但没有类型声明位置。
- 模型调用：

  ```json
  {"type_name": "PluginRegistry", "file_path": "src/plugin.c"}
  {"type_name": "Plugin", "file_path": "src/plugin.c"}
  ```

- 两次调用均返回 `Type not found`。
- 两个类型实际已正确索引在 `include/types.h`：
  - `Plugin@include/types.h:90-98`
  - `PluginRegistry@include/types.h:110-115`
- 源码 include 链为：

  ```text
  src/plugin.c
    -> internal/plugin.ph
    -> internal/types.ph
    -> include/types.h
  ```

- 模型最终通过多次 `get_file_snippet` 自行追踪头文件后才获得定义。

同一次 global-model benchmark 中：

- `get_type_info` 调用 264 次；
- 失败 43 次；
- 其中大量调用查询 `Task`、`Plugin`、`PluginRegistry`、`Dispatcher` 等项目类型；
- 重复参数调用率为 59.47%。

现有底层能力已经具备：

- KnowledgeDB 的 `type_definitions` 保存名称、kind、声明文件、行范围和 `full_definition`；
- ClangExtractor 能从 LSP range 提取完整类型定义；
- CodeIndex 的 `find_type_infos()` 能按名称和声明文件返回多候选；
- KnowledgeDB 已保存 `include_edges`；
- function info 已提供 signature、函数范围和完整源码。

当前缺口为：

- 没有 `function_type_refs` 表；
- `function_symbol_refs` 只覆盖 global 和 macro，不覆盖 type；
- backend/CodeIndex 没有统一 `get_function_type_context()` 接口；
- `find_function_infos()` 和 `build_semantic_model_input()` 不提供类型上下文；
- Semantic Modeler prompt、program merge 和完整 snapshot schema 没有 `referenced_types`；
- SnapshotStore 没有独立类型依赖 hash，类型定义变化不会单独触发 snapshot refresh。

### 7.2 目标与非目标

#### 7.2.1 目标

1. 在索引阶段建立函数到类型定义的精确引用关系，而不是由 LLM 猜测声明文件。
2. 覆盖函数签名和函数体中与语义建模相关的直接类型引用。
3. 只返回函数 signature 和函数体直接引用的项目类型，不递归展开类型定义内部依赖。
4. `find_function_infos()` 和统一 Semantic Model input 直接提供 `referenced_types`。
5. Semantic Modeler 初始 prompt 直接包含程序解析出的完整类型定义，避免对已预加载类型调用 `get_type_info`。
6. `referenced_types` 由程序拥有、校验、排序和覆盖，LLM 不生成或修改该字段。
7. LLM、trivial 和 lightweight snapshot 使用一致的 program type-context 契约。
8. 类型定义或类型引用关系变化时，以独立 `type_context_changed` reason 触发需要重新建模的 snapshot refresh。
9. 对直接类型数量和总定义大小设置确定性预算，防止大类型或大量直接引用造成 prompt 无界增长。
10. 保留现有 `get_type_info` 作为 unresolved、ambiguous、truncated 或按需额外探索的工具，本轮不改变其行为。
11. 通过 benchmark 分离统计预加载后减少的 `get_type_info` 调用、失败、API calls、token 和耗时。

#### 7.2.2 非目标

- 不把整个项目的全部类型定义注入每个函数。
- 不对 C builtin scalar、builtin pointer、`void` 或只由语言内建提供的类型建立 type-info 记录。
- 不依赖 LLM 从 include 文本推断类型声明文件。
- 不在同名类型无法由定义位置或可见性唯一解析时静默选择第一项。
- 不递归解析 `referenced_types` 的成员类型、underlying typedef 或其他类型依赖；只保留目标函数直接引用。
- 不要求 `get_type_info` 下线；未预加载或被预算截断的类型仍可按需查询。
- 不修改 `get_type_info` 的参数 schema、路径限定规则、底层查询、fallback、成功/失败判定、返回 payload 或 reason；类型预加载只减少调用需求，不改变该 Tool 的单次调用语义。
- 不在本计划中改变外部库类型的配置语义；无法解析到项目定义的类型只记录 unresolved，不伪造 definition。
- 不把类型定义变化当作 callee-summary-only patch；类型变化可能改变当前函数语义，必须重新执行 Semantic Modeler。

### 7.3 最终数据契约

#### 7.3.1 `referenced_types`

Function Info、Semantic Model input 和新生成 snapshot 顶层新增 required 数组：

```json
{
  "referenced_types": [
    {
      "type_index_name": "PluginRegistry@include/types.h:110-115",
      "kind": "struct",
      "full_definition": "110 | typedef struct { ... } PluginRegistry;\n111 | ...\n115 | } PluginRegistry;\n",
      "reference_kinds": ["parameter", "member_access"],
      "reference_lines": [32, 43, 45, 58, 60]
    }
  ]
}
```

字段规则：

| 字段 | 类型 | 规则 |
|---|---|---|
| `type_index_name` | string | 程序生成的 canonical type identity：`name@file:start-end`；匿名类型使用稳定的 `kind@file:start-end` |
| `kind` | enum | `struct`、`union`、`enum`、`typedef`、`class`、`unknown` |
| `full_definition` | string | 完整、未截断的源码定义；由 `CodeIndex.get_file_snippet()` 生成，每行使用绝对行号的 `N | source` 格式；定义超预算时整项不进入 prompt，不注入残缺语法 |
| `reference_kinds` | enum[] | 稳定去重后的引用来源类别 |
| `reference_lines` | integer[] | 当前目标函数中的直接引用行，去重升序；resolved item 至少包含一个引用行 |

声明名称、文件和完整定义范围只保留在 `type_index_name` 中，不作为 resolved item 的独立字段；内部索引仍可使用定位信息读取源码，但不得将其透传进 snapshot 或 LLM context。

`reference_kinds` 初始枚举：

```json
[
  "return",
  "parameter",
  "local",
  "cast",
  "sizeof",
  "alignof",
  "offsetof",
  "compound_literal",
  "member_access",
  "function_pointer"
]
```

同一个 canonical type 在数组中只出现一次；其引用类别和行号聚合。排序固定为：

1. 是否出现在 signature，signature 类型优先；
2. 首个 `reference_line` 升序；
3. `type_index_name` 字典序。

#### 7.3.2 Unresolved 与 truncation

程序输入可选提供 `unresolved_referenced_types` 数组；仅在非空时输出，零 unresolved 时省略该字段：

```json
{
  "unresolved_referenced_types": [
    {
      "name": "ThirdPartyContext",
      "reference_kinds": ["parameter"],
      "reference_lines": [20],
      "reason": "definition_not_indexed"
    }
  ]
}
```

`reason` 使用稳定枚举：

```json
[
  "definition_not_indexed",
  "definition_ambiguous",
  "definition_incomplete",
  "definition_too_large",
  "context_budget_exceeded"
]
```

只在 `referenced_types` 发生数量或字节预算截断时输出 `referenced_types_truncation`：

```json
{
  "truncated": true,
  "returned": 30,
  "total": 37,
  "definition_bytes_returned": 28640,
  "definition_bytes_limit": 32768
}
```

初始确定性预算：

- `referenced_types` 只包含直接类型，最多 30 项；
- 单个 `full_definition` 最大 8 KiB；超过时不注入残缺定义，记录 `definition_too_large`；
- 所有 `full_definition` UTF-8 总大小最大 32 KiB；
- signature 直接类型优先于 body 直接类型。

预算常量集中定义，不允许各调用路径使用不同上限。benchmark 后可调整常量，但调整必须触发 extractor/context version 更新并执行回归。

### 7.4 KnowledgeDB 数据模型与迁移

#### 7.4.1 Canonical type identity

`type_definitions` 保留现有主键和字段，并新增统一 helper 生成 `type_index_name`。identity 由以下字段决定：

```text
<name-or-anonymous-kind>@<normalized-file-path>:<start-line>-<end-line>
```

不得只用名称作为 identity；同名类型跨文件或不同声明范围必须独立保存和引用。

#### 7.4.2 `function_type_refs` 表

KnowledgeDB schema version 增加一版，新增：

```sql
CREATE TABLE function_type_refs (
    id INTEGER PRIMARY KEY,
    function_id INTEGER NOT NULL,
    type_id INTEGER,
    type_index_name TEXT NOT NULL DEFAULT '',
    referenced_name TEXT NOT NULL,
    reference_file TEXT NOT NULL,
    reference_line INTEGER NOT NULL,
    reference_kind TEXT NOT NULL,
    resolution_reason TEXT DEFAULT '',
    UNIQUE(
        function_id,
        referenced_name,
        type_index_name,
        reference_line,
        reference_kind
    ),
    FOREIGN KEY(function_id) REFERENCES functions(id),
    FOREIGN KEY(type_id) REFERENCES type_definitions(id)
);

CREATE INDEX idx_function_type_refs_function
    ON function_type_refs(function_id);
CREATE INDEX idx_function_type_refs_type
    ON function_type_refs(type_id);
CREATE INDEX idx_function_type_refs_name
    ON function_type_refs(referenced_name);
```

规则：

- resolved 引用必须有 `type_id` 和非空 `type_index_name`；unresolved 引用使用 `type_id=NULL`、空 `type_index_name` 并写入 `resolution_reason`。UNIQUE 使用非空字符串字段而不是 nullable `type_id`，避免 SQLite 允许重复 NULL 组合。
- `reference_file/reference_line` 表示引用位置，不表示定义位置。
- 表中只保存函数直接类型引用，不保存类型定义内部的依赖引用。
- 删除或重建函数所属 TU 时删除该函数拥有的 refs。
- 删除类型定义所属 TU 时删除指向该 `type_id` 的 resolved refs；受影响函数在后续类型上下文重建前不得继续复用旧关联。
- migration 只新增表和索引，不回写历史猜测数据；首次索引刷新统一重建。

#### 7.4.3 Extractor version

新增 metadata：

```text
function_type_ref_extractor_version=1
```

metadata 缺失或版本变化时：

1. 将相关 TU 标为 pending；
2. 重建 type definitions；
3. 重建直接 function type refs；
4. 完成 resolved/unresolved 聚合后写入当前版本。

不得在部分 TU 仍使用旧引用关系时写入新版本。重建异常时保留可诊断日志，并使受影响函数进入 unresolved/refresh 路径。

### 7.5 类型引用提取与解析

#### 7.5.1 Clang/clangd 主路径

主路径以 clangd definition resolution 为准，不使用名称优先猜测：

1. 从函数 signature 源码范围提取返回类型、参数类型和函数指针类型 token。
2. 从函数 body 提取局部声明、cast、`sizeof`、`_Alignof/alignof`、`offsetof`、compound literal 和明确的类型位置 token。
3. 对候选 token 调用 clangd definition，获取声明文件和范围。
4. 使用 definition location 精确关联 `type_definitions`。
5. definition 指向 typedef 时记录函数源码直接使用的 typedef identity，不继续展开 underlying named type。
6. definition 指向 forward declaration 时，在可见 include closure 内寻找同一 canonical 类型的完整定义；无法唯一匹配时记录 unresolved。
7. 相同类型的多次出现聚合 reference kinds 和 lines。

候选过滤：

- 排除 C/C++ builtin scalar、builtin pointer、`void`、关键字和 storage qualifiers；
- 排除已解析为函数、变量、字段、label 或 macro 的 token；
- 字段访问中的 field name 不作为类型名；但字段所属完整类型可记录 `member_access`；
- `struct Foo`、`union Foo`、`enum Foo` 应保留 tag kind；typedef alias 与 tag 只有在目标函数源码中分别直接出现时才分别记录；
- 匿名类型没有可从函数上下文单独引用的名称时不创建虚假名称；若通过 typedef 引用，只记录 typedef identity。

当前 clangd LSP 未直接暴露稳定 `TypeRef` AST 节点，因此允许使用“语法位置候选 + definition resolution”实现；最终 resolved 记录必须以 definition location 命中为门槛，候选正则本身不能证明类型身份。

#### 7.5.2 直接引用边界与聚合

`referenced_types` 只描述目标函数自身直接使用的类型：

- signature 中的返回值、参数和函数指针类型；
- body 中的局部声明、cast、`sizeof`、`alignof`、`offsetof`、compound literal 和 member access 所属类型；
- 同一个 canonical type 的多种 reference kind 和多处 reference line 聚合为一个 item；
- 不扫描 `full_definition` 来补充成员类型、underlying typedef、数组元素类型或嵌套 named type；
- 不为 self reference、mutual recursive type 或其他间接依赖生成额外 item；
- 类型 A 的定义引用类型 B，但目标函数没有直接使用 B 时，只返回 A，不返回 B。

例如目标函数只在 signature 中使用 `PluginRegistry*` 时，只注入 `PluginRegistry`；即使其定义包含 `Plugin* plugins`，也不递归注入 `Plugin`。只有目标函数自身另有 `Plugin*` 局部声明、cast、sizeof 或成员访问类型证据时，`Plugin` 才作为直接 referenced type 返回。

#### 7.5.3 Regex fallback

regex backend 或 clangd definition 不可用时采用保守降级：

1. 从 signature 和函数源码提取语法位置候选；
2. 只在已索引 `type_definitions.name` 中进行 exact identifier 交集；
3. 计算当前函数文件的规范化 transitive include closure；
4. 候选在可见 closure 中只有一个完整定义时才解析为 resolved；
5. 多候选、无候选或 include graph 不足时记录 unresolved，不按排序选择第一项；
6. regex 路径使用与 clang 主路径相同的直接引用聚合、排序和预算 helper。

为支持该路径，现有 `include_edges.included_file` 必须规范化为 source-root 相对 canonical path。`../internal/plugin.ph`、`"types.h"` 和绝对路径不能作为三个不同节点。系统头文件继续标记 `is_system=true`，不纳入项目类型闭包。

#### 7.5.4 Joern 与 Unified backend

- `CodeBackend` 新增默认 `get_function_type_context()`，无能力的 backend 返回空 resolved 数组和明确的 capability metadata。
- `ClangBackend` 使用 KnowledgeDB 的精确 refs。
- `JoernBackend` 使用 method parameter/local/typeFullName 与 typeDecl location 构造同一契约；无法获得源码完整定义时记录 `definition_incomplete`。
- `UnifiedBackend` 以 Clang/KnowledgeDB identity 和 `full_definition` 为主；Joern 只补充 Clang 未覆盖且能映射到同一 source definition 的引用，不以 typeFullName 文本覆盖 canonical identity。
- backend 合并后再次执行 canonical 去重、排序和预算，确保不同后端输出一致。

### 7.6 查询接口与 Function Info 集成

#### 7.6.1 KnowledgeDB 与 backend API

新增：

```python
KnowledgeDB.get_function_type_context(
    function_name,
    function_file,
    function_start_line,
) -> dict

CodeBackend.get_function_type_context(...) -> dict
CodeIndex.get_function_type_context(...) -> dict
```

返回结构：

```json
{
  "referenced_types": []
}
```

存在 unresolved 时附加 `unresolved_referenced_types`；存在真实截断时附加 `referenced_types_truncation`。`function_start_line` 必须参与函数 identity，避免同名同文件的 overload/static 记录混合。公开 payload 不输出空 unresolved 数组或 `null` truncation。

#### 7.6.2 `find_function_infos()`

普通项目函数的每个 match 新增 required：

```json
{
  "referenced_types": []
}
```

存在 unresolved 时附加 `unresolved_referenced_types`，存在截断时附加 `referenced_types_truncation`。

边界：

- function-like macro 没有结构化函数 signature/body type refs，默认只返回 `referenced_types=[]`；后续若 macro 参数或 body 存在 `sizeof(Type)`，可作为独立增强，不在首期完整实现中猜测。
- external function fallback 只返回 `referenced_types=[]`，不伪造项目类型定义。
- 类型上下文失败不应使函数 identity 查询整体失败；match 仍返回，但在 unresolved 中记录稳定 reason，并产生 `[type-context]` warning。
- 类型定义和函数 identity 都来自 CodeIndex，调用方不再自行扫描 include 或调用 Tool 拼装初始上下文。

#### 7.6.3 `get_function_info` 透明透传

`get_function_info` Tool 必须把 `CodeIndex.find_function_infos()` 作为 function match 的唯一事实来源，并透明透传其类型上下文行为：

- 每个返回 match 原样携带 required `referenced_types`，包括空数组；
- 仅当对应 match 中实际存在时，原样携带 `unresolved_referenced_types` 和 `referenced_types_truncation`；
- 不在 Tool 层重新查询、重新解析、重新排序、重新截断、重命名或丢弃上述字段；
- ordinary function、function-like macro 和 external fallback 的边界与 `find_function_infos()` 完全一致；
- 零结果、多候选、文件路径消歧及 Tool 外层 success/error envelope 保持现有行为，只扩展成功 match 中由 CodeIndex 提供的字段；
- Tool description 补充三个 type-context 字段的含义，但不得承诺 CodeIndex 契约之外的解析或 fallback。

对应关系为：

```text
CodeIndex.find_function_infos() result match
  -> get_function_info result match
     referenced_types                 原样透传（required）
     unresolved_referenced_types      存在时原样透传（optional）
     referenced_types_truncation      存在时原样透传（optional）
```

#### 7.6.4 `get_type_info` 保持现状

`get_type_info` 继续用于：

- `unresolved_referenced_types` 中的类型；
- 被 `referenced_types_truncation` 省略的类型；
- LLM 在建模时发现、但程序未识别的确切项目类型；
- 需要查看同名类型全部候选的诊断场景。

本轮只调整上游预加载和 Agent 的调用需求，不修改 `get_type_info` Tool 本身。其参数 schema、`file_path` 语义、限定查询行为、底层 `find_type_infos()` 调用、fallback、返回结构、成功/失败判定和错误 reason 均保持实施前现状。即使现有路径限定查询未命中，本轮也不在 Tool 层新增无路径重试、候选诊断或自动消歧。

### 7.7 Semantic Model Input、Prompt 与 Program Ownership

#### 7.7.1 统一输入

`build_semantic_model_input()` 从唯一 function info 深拷贝：

```json
{
  "referenced_types": []
}
```

存在且非空时透传 `unresolved_referenced_types`，存在截断时透传 `referenced_types_truncation`。四条 LLM 建模路径、global reconciliation、scan-session 和 snapshot tool 必须复用同一个 input builder，不允许仅在 global model 特判注入。

输入校验：

- required `referenced_types` 必须为数组；
- `unresolved_referenced_types` 存在时必须为非空数组；空数组必须在输入边界省略；
- truncation 存在时必须为 object；
- resolved item 必须包含完整 identity 和 definition，不接收或生成 `definition_hash` 字段；
- resolved 与 unresolved 中同一 canonical identity 不得重复；
- 校验失败以 `reason=semantic_model_input_invalid`、`llm_called=false` 终止当前建模，不能让 LLM 修复程序事实。

#### 7.7.2 Prompt projection

`SemanticModeler._prompt_metadata()` 新增 required `referenced_types`，并在存在时附加 unresolved 与 truncation。模型在首轮即可看到目标函数相关类型定义，不需要从目标源码文件猜测声明文件。程序内部计算的类型 hash 不进入 prompt metadata。

Agent policy 增加：

- `referenced_types` 中已存在完整定义的类型禁止再次调用 `get_type_info`。
- 只有 unresolved、truncated 或模型发现的必要额外项目类型才允许查询。
- 调用 `get_type_info` 时，`file_path` 必须是声明候选路径；只知道使用文件时省略 `file_path`。
- 查询失败时遵循现有 Tool 返回语义；Prompt 不假设新增候选列表或新增错误 reason，也不要求 Tool 层自动 fallback。
- builtin scalar、builtin pointer 和 `void` 继续禁止查询。

#### 7.7.3 Schema 与最终拼接

完整 persisted snapshot schema 新增 required：

- `referenced_types`

可选：

- `unresolved_referenced_types`（仅非空时输出）
- `referenced_types_truncation`

在 `semantic_modeler/schema.py` 中将其加入 program passthrough/excluded fields：

- LLM final tool schema 和 structured-output schema 不包含上述字段；
- LLM payload 即使伪造同名字段也在 merge 前删除；
- `_program_snapshot_fields()` 从 input 深拷贝并最后覆盖；
- deterministic builder 同样复制字段并遵守 canonical 字段顺序；
- compact evidence 和 snapshot tool 是否携带完整定义按消费者预算处理，但不得丢失 type identity 和 truncation 状态。类型 hash 仅由程序在 refresh/diagnostic 路径临时计算，不作为 snapshot item 或 LLM context 字段。

### 7.8 Snapshot 持久化、指纹与历史兼容

#### 7.8.1 独立 `type_context_hash`

SQLite snapshots 表新增：

```sql
type_context_hash TEXT NOT NULL
```

hash 投影只包含程序拥有的规范事实：

- `type_index_name`、kind；
- 对规范化 `full_definition` 在 hash 计算函数内部得到的 SHA-256；该中间 hash 不写入 snapshot 或 prompt；
- reference kinds、reference lines；
- unresolved names/reasons；
- truncation metadata。

hash 不依赖 JSON item 输入顺序；数组按 canonical identity 排序，引用类别和行号稳定排序。程序在构造 fingerprint 投影时对每个规范化 `full_definition` 计算临时 hash，并只把临时 hash 放入内部投影；`referenced_types` 对外结构和 LLM context 均不包含该字段。

内部定义 hash 的规范化：

- CRLF 转 LF；
- 删除每行尾随空白；
- 保留 token、注释、属性、数组大小、位域和成员顺序；
- 不进行可能改变宏或属性语义的通用空白折叠。

#### 7.8.2 Refresh 分类

新增：

```text
type_context_changed
```

以下变化触发需要 LLM 重建：

- 函数新增或删除直接类型引用；
- 类型定义 identity 或程序计算的定义内容 hash 变化；
- resolved/unresolved 状态变化；
- reference kind 或 reference line 变化；
- truncation 状态或预算输出变化。

类型变化不能使用 program-only reconciliation，因为 parameters、effects、error handling 和 suspicious points 可能随布局、成员、enum 或函数指针契约变化。

#### 7.8.3 数据库迁移与旧 snapshot

- 新建数据库直接创建 `type_context_hash`。
- 已有 index-name 数据库增量增加该列，初始回填 canonical empty-type-context hash。
- 旧 snapshot 缺少 required `referenced_types` 时返回 `snapshot_shape_changed`；缺少 optional unresolved 字段不属于旧 shape。
- 首次用新 input 检查旧记录时，empty hash 与当前 type context 不一致，触发一次性重建。
- 不原地猜测或补写旧 snapshot 的类型定义；类型上下文必须从当前 CodeIndex 重新解析。
- migration 失败保留旧表和 JSON，记录稳定 reason，不删除用户数据。

### 7.9 日志与可观测性

新增统一前缀 `[type-context]`。

| 场景 | 级别 | 必要字段 |
|---|---|---|
| 提取开始 | DEBUG | `index_name`、backend、candidate count |
| 提取完成 | INFO/DEBUG | resolved、unresolved、returned、bytes、truncated |
| definition miss | WARNING | type name、reference line、reason |
| definition ambiguous | WARNING | type name、candidate type identities、include closure |
| 预算截断 | INFO | returned、total、bytes、limit |
| extractor rebuild | INFO | version、TU count、ref count、failure count |
| type refresh | INFO | `index_name`、old/new hash、`reason=type_context_changed` |

不得记录完整 `full_definition`、完整 prompt 或整个 type-context JSON。diagnostic 日志需要 hash 时由程序即时计算，只记录 identity、计数、临时 hash 短前缀和稳定 reason，不把 hash 写入 LLM context。

Benchmark 指标新增：

- resolved/unresolved type references；
- 每函数 injected type count 和 definition bytes；
- type-context truncation rate；
- `get_type_info` 总调用、失败、重复参数调用；
- 按现有 `get_type_info` 返回语义统计失败分布，不新增 reason 分类；
- 每个 LLM snapshot 的 API calls、Prompt/Completion/Total Tokens；
- `type_context_changed` refresh 数量；
- 与未注入基线的 wall time 和 snapshot 成功率对比。

### 7.10 需要修改的文件

#### 7.10.1 生产代码

至少涉及：

1. `zscope/retrieval/knowledge_db.py`
   - schema version、`function_type_refs`、insert/clear/query、TU 清理和迁移。
2. `zscope/retrieval/clang_extractor.py`
   - signature/body 直接类型候选、definition resolution、include path 规范化和 extractor version。
3. `zscope/retrieval/backend_base.py`
   - `get_function_type_context()` 默认 capability 契约。
4. `zscope/retrieval/clang_backend.py`
   - KnowledgeDB type-context 查询。
5. `zscope/retrieval/joern_backend.py` 与 `zscope/common/joern_client.py`
   - typeFullName/typeDecl 引用和源码位置查询。
6. `zscope/retrieval/unified_backend.py`
   - Clang 主结果与 Joern 补充结果的 canonical merge。
7. `zscope/retrieval/code_index.py`
   - canonical type identity、聚合、排序、预算、function info 字段和 regex fallback。
8. `zscope/tools/function_info.py`
   - 将 `find_function_infos()` 返回 match 中的 required `referenced_types` 及存在时的 optional unresolved/truncation 原样透传，并更新 tool description；不在 Tool 层重复构造类型上下文。
9. `zscope/snapshots/modeling_input.py`
   - 输入透传、验证与四条建模路径统一。
10. `zscope/agents/semantic_modeler/schema.py`
   - persisted schema、program passthrough/excluded fields 和 truncation。
11. `zscope/agents/semantic_modeler/agent.py`
   - prompt projection、program merge 和伪造字段删除。
12. `zscope/agents/semantic_modeler/AGENT.md`
   - 预加载类型优先、声明路径语义和现有 Tool 失败语义下的调用 policy。
13. `zscope/snapshots/policy.py`
   - deterministic snapshot 字段、顺序和 shape checker。
14. `zscope/snapshots/store.py`
   - `type_context_hash`、migration、refresh reason 和 fingerprint API。
15. 消费 snapshot program context 的 validation evidence、semantic inference、snapshot tool、history/scan resume 和 report 路径。

本轮生产代码清单不包含 `zscope/tools/type_info.py`；若实现过程中发现必须修改该文件，应停止并另行确认，不得把行为变更夹带进类型上下文注入。

不修改 fallback 文件。

#### 7.10.2 测试

至少新增或更新：

- `tests/test_knowledge_db_ir_and_config.py`
- `tests/test_clang_incremental_extraction.py`
- `tests/test_function_info_tool.py`
- `tests/test_code_index_cache.py`
- `tests/test_semantic_model_input.py`
- `tests/test_json_output_agents.py`
- `tests/test_snapshot_store.py`
- `tests/test_analyzer_semantics.py`
- `tests/test_global_modeler.py`
- `tests/test_snapshot_tool.py`
- validation、semantic inference、scan resume 和 report 相关回归测试。

#### 7.10.3 文档与实施记录

实施时同步：

- `new_docs/agent_optimation.md`
- `new_docs/tools_optimation.md`
- `new_docs/agent_introduction.md`
- `new_docs/tools_introduction.md`
- 本章实施状态、实际偏差、测试结果和已知问题。

### 7.11 实施阶段

#### 阶段 0：契约与现状审计

- 锁定 `referenced_types`、optional unresolved、truncation 和 canonical identity schema。
- 审计所有 function info、Semantic Model input、snapshot shape、hash 和消费点。
- 固化 `_plugin_register`、同名类型、typedef chain、recursive struct 和 oversized type fixture。
- 记录实施前 benchmark 的 `get_type_info`/token/time 基线。

#### 阶段 1：KnowledgeDB 与直接引用提取

- 新增表、索引、版本和 TU 清理。
- 实现 Clang signature/body 直接 type refs。
- 完成 definition location 到 `type_definitions` 的精确 join。
- 先以 DB 查询测试证明 `PluginRegistry` 和 `Plugin` 能从 `_plugin_register` 解析。

#### 阶段 2：直接引用聚合、include 规范化与 backend

- 实现直接 typedef/tag/member-access 引用聚合、canonical 去重和预算，不扫描类型定义做递归展开。
- 规范化 include graph。
- 接入 ClangBackend、UnifiedBackend、Joern 和 regex fallback。
- 锁定不同 backend 的 canonical output 一致性。

#### 阶段 3：CodeIndex、Function Info 与 Tool

- 接入 `get_function_type_context()`。
- `find_function_infos()` 输出 resolved/unresolved/truncation。
- 更新 `get_function_info` Tool，使其逐 match 原样透传 `find_function_infos()` 的 required resolved 与存在时的 optional unresolved/truncation 字段。
- 用 Tool 测试锁定普通函数、空数组、optional 字段、macro、external fallback、零结果和多候选均与 CodeIndex 输出一致。
- 不修改 `get_type_info` Tool；只以既有行为作为回归基线。

#### 阶段 4：Semantic Modeler 与 deterministic snapshot

- 统一输入透传和校验。
- Prompt 注入完整 `referenced_types`。
- Schema 排除 LLM ownership，program fields 最后覆盖。
- deterministic builder、字段顺序和 shape checker 同步。
- Agent 禁止重复查询已预加载类型。

#### 阶段 5：SnapshotStore 与消费者

- 新增 `type_context_hash`、migration 和 `type_context_changed`。
- 接入 global、entry、premodel、on-demand、history、resume、snapshot tool。
- 更新 validation evidence 和 semantic inference 的 type-context 压缩策略。
- 验证旧 snapshot 一次性重建和新 snapshot 稳定复用。

#### 阶段 6：回归、指标与文档

- 运行聚焦测试、可收集完整 pytest、compileall 和 diff check。
- 使用相同模型、入口、并发和 snapshot 冷启动条件重跑 global-model benchmark。
- 对比 `get_type_info` 调用/失败、API calls、token、wall time、snapshot 成功率和 prompt type bytes。
- 更新实施记录、介绍文档、本章状态、偏差和已知限制。

### 7.12 测试矩阵

#### 7.12.1 数据库与增量索引

- `function_type_refs` resolved/unresolved 写入、聚合、查询和稳定排序。
- 函数 TU 删除只清理其拥有的 refs；类型 TU 删除清理 incoming resolved refs。
- extractor version 缺失/变化时 unchanged TU 仍强制重建。
- 失败事务不留下部分 refs 或错误版本 metadata。
- 同名类型在不同文件中保持独立 type identity。

#### 7.12.2 类型解析

- `_plugin_register` 解析 `PluginRegistry` 与 `Plugin` 到 `include/types.h`，不使用 `src/plugin.c` 作为声明文件。
- 返回类型、参数、局部变量、cast、sizeof、offsetof、compound literal、函数指针类型分别产生正确 kind/line。
- builtin scalar/pointer/void 不产生 refs。
- typedef alias 与 underlying type 只有在目标函数中分别直接出现时才分别记录；不得因 alias 定义递归补充 underlying type。
- self-referential struct 和 mutual recursive types 不触发定义递归扫描；只保留函数直接使用的 canonical item。
- forward declaration 能解析到可见完整定义；多候选时进入 unresolved。
- 字段名、变量名、函数名和宏不误识别为类型。
- regex fallback 只接受 include closure 内唯一 exact type，不按排序猜测。

#### 7.12.3 预算与 truncation

- 31 个直接类型触发 count truncation，`returned=30`，优先级和 total 正确。
- 单项定义超过 8 KiB 时不注入残缺源码，进入 unresolved `definition_too_large`。
- 总定义超过 32 KiB 时稳定截断，signature 类型优先保留。
- 输入顺序变化不影响最终排序或程序计算的 type-context hash。

#### 7.12.4 Function Info Tool

- 普通函数的 `get_function_info` match 与对应 `find_function_infos()` match 具有相同的 `referenced_types` 内容和顺序。
- CodeIndex 返回空 `referenced_types=[]` 时 Tool 仍保留 required 空数组。
- CodeIndex 不返回 optional 字段时 Tool 不补空数组或 `null`；返回非空 unresolved 或 truncation 时 Tool 原样保留。
- function-like macro 与 external fallback 的空类型上下文原样透传，不在 Tool 层猜测类型。
- 零结果、多候选与文件路径消歧保持现有 Tool envelope 行为，每个成功候选的 type-context 字段均不丢失。
- spy/mock 证明 Tool 只消费 `find_function_infos()` 结果，不额外调用 `find_type_infos()` 或自行执行类型预算。

#### 7.12.5 Semantic Modeler

- Prompt 含完整 `Plugin`/`PluginRegistry` 定义。
- 预加载类型不出现在 LLM 普通工具调用中；`get_type_info` 调用次数为 0。
- LLM 伪造、修改或删除 `referenced_types` 不影响最终 snapshot。
- unresolved/truncated 类型允许按 policy 调用现有 `get_type_info`；resolved 类型重复查询由 Prompt 约束并通过 recorder 指标审计，不为此修改 Tool runtime。
- `get_type_info` 参数、路径限定、fallback、返回 payload 和错误 reason 与实施前保持一致；Prompt 和测试不得依赖新增候选诊断字段。
- semantic-only final tool schema 不包含 program type fields。
- 单会话 terminal final tool、repair 和 recorder metadata 不回归。

#### 7.12.6 Snapshot 与 refresh

- LLM、trivial、lightweight snapshot 均包含 required `referenced_types`；`unresolved_referenced_types` 只在非空时存在。
- 旧 shape 缺字段时返回 `snapshot_shape_changed`。
- type definition member、enum value、typedef target、array size、bit field 或 function pointer signature 变化触发 `type_context_changed`。
- 仅 item 顺序、换行风格或行尾空白变化不触发 refresh。
- 类型 resolved/unresolved 转换和 truncation 变化触发 refresh。
- callee summary-only reconciliation 不修改 type context 或 type hash。
- 类型变化必须调用 LLM，不走 program-only patch。

#### 7.12.7 消费者与 benchmark

- snapshot tool 返回当前 type context，不返回 stale 类型证据。
- validation evidence 对 full definitions 应用明确预算，同时保留 identity/truncation；内部 hash 不进入 evidence 或 LLM context。
- semantic inference 不依赖 LLM 再次查询已持久化类型。
- scan resume 在 type context 变化时不复用旧 final report。
- benchmark 使用唯一 `tool_call_id` 统计实际工具调用，避免 conversation 历史消息重复计数。
- benchmark 对比使用同一入口列表、模型、并发、类型 extractor version 和冷缓存状态。

### 7.13 验收条件

- KnowledgeDB 存在可增量维护的 `function_type_refs`，并能精确关联函数 identity 与类型 definition identity。
- Clang 主路径的 resolved type ref 必须由 definition location 证明；regex/Joern fallback 不静默选择歧义候选。
- `find_function_infos()`、`get_function_info` Tool、Semantic Model input、LLM snapshot 和 deterministic snapshot 使用相同 type-context 契约。
- `get_function_info` 的每个 match 原样透传 `find_function_infos()` 的 required `referenced_types`，并仅在源 match 存在时透传 optional unresolved/truncation；Tool 层不重新解析、排序、截断或改写这些字段。
- `referenced_types` 为 required program-owned 字段；optional unresolved 和 truncation 同样不由 LLM 生成，最终值只能来自 CodeIndex 输入。
- 直接引用边界、30 项上限、排序和 truncation 在所有 backend/建模路径中一致。
- 类型定义或引用关系变化返回 `type_context_changed` 并执行语义重建；顺序和规范化空白变化不产生误刷新。
- 历史 snapshot 缺少新字段时通过明确 reason 一次性重建，不原地猜测类型上下文。
- `get_type_info` 仍按实施前行为查询未预加载类型；本轮不改变其参数、限定路径、fallback、返回 payload、成功/失败判定或错误 reason。
- 聚焦测试与可收集完整回归通过；编译检查和相关文件 `git diff --check` 通过。
- 相同 benchmark 条件下，项目类型的 `get_type_info` 路径错误应降为 0；总 `get_type_info` 调用和失败显著下降。
- benchmark 必须同时报告 Prompt 增量与 API/tool 调用下降；只有总 token 或 wall time 实际改善时才能宣称成本优化。
- 不修改任何 fallback 文件，不修改 baseline 工作树，不回退用户手动改动。

### 7.14 风险、权衡与缓解

| 风险 | 影响 | 缓解 |
|---|---|---|
| 全定义注入导致 Prompt 变大 | 每轮都携带类型文本，可能抵消工具调用节省 | 30 项/8 KiB 单项/32 KiB 总量预算，signature 优先，benchmark 同时看总 token |
| 名称正则误识别 | 注入错误类型会污染语义和 refresh | Clang 主路径必须由 definition location 证明；regex 只接受 include closure 内唯一 exact match |
| 同名类型错误消歧 | 可能注入其他 TU 的布局 | canonical type identity 包含文件与行范围，歧义进入 unresolved |
| 直接引用类型过多 | Prompt、索引时间和 snapshot 体积增长 | 不展开间接依赖；直接类型固定上限 30，并使用单项/总字节预算 |
| 大定义被截断后误导模型 | 残缺结构可能产生错误成员推断 | 不注入残缺定义；整项转 unresolved `definition_too_large`，保留 Tool 兜底 |
| 类型定义变化未刷新 snapshot | 下游继续使用旧布局/enum/回调契约 | 独立 `type_context_hash` 和 `type_context_changed`，scan resume 同步检查 |
| 增量删除留下悬空 refs | 查询返回不存在的 type_id | 显式 TU 清理、incoming ref 删除、事务和 extractor version 测试 |
| backend 输出差异 | 相同项目在 clang/joern/regex 下 prompt 不一致 | 统一 contract、canonical merge、backend capability 和对照测试 |
| snapshot 体积增长 | IO、cache、evidence 压缩成本增加 | consumer-specific projection；持久化完整程序事实，证据包按预算压缩 |
| Prompt 约束仍被模型忽略 | 重复调用已预加载类型 | Agent policy + recorder 审计指标；本轮不通过修改 `get_type_info` runtime 行为解决 |

### 7.15 计划完成后的实施记录要求

实施完成后，本章开头状态改为“已实施”，并在 `new_docs/agent_optimation.md` 至少记录：

- 实际 schema 和数据库 migration；
- extractor/backend 实现与计划偏差；
- type-context hash 和历史 refresh 行为；
- 聚焦测试、完整回归、compileall 和 diff check；
- 未解决的 backend、外部类型、anonymous type 或超预算问题。

若最终实现没有证明总 token 或 wall time下降，只能记录“工具调用减少”和具体成本权衡，不能把该结果表述为整体成本优化。

### 7.16 实施结果、计划偏差与已知问题

#### 7.16.1 实施结果

- KnowledgeDB schema v9、`function_type_refs`、TU owned/incoming 清理、canonical include closure 和 extractor version 已实现。
- Clang 主路径覆盖 direct return/parameter/local/cast/sizeof/alignof/offsetof/compound literal/member access/function pointer；不扫描 `full_definition` 展开依赖。
- backend、CodeIndex、`find_function_infos()`、`get_function_info`、Semantic Model input、Prompt、program merge、LLM/deterministic snapshot 和 snapshot Tool 已统一使用 `referenced_types` 契约；resolved item 只含 `type_index_name`、`kind`、带绝对行号的 `full_definition`、`reference_kinds` 和 `reference_lines`。
- required resolved、optional non-empty unresolved、optional truncation，以及 30 项/8 KiB 单项/32 KiB 总定义预算已实现。
- SnapshotStore 新增独立 `type_context_hash`、SQLite migration 和 `type_context_changed`；definition digest 仅在内部 projection 即时计算。
- `get_type_info` Tool 行为未修改。
- range 本地索引 extractor v2 离线重建 887 条 direct refs，其中 858 resolved、29 unresolved；`_plugin_register` 的 4 个直接项目类型全部解析到 `include/types.h`，无 unresolved。
- 非 benchmark 回归 `751 passed`，`compileall` 和 `git diff --check` 通过。

#### 7.16.2 计划偏差

- extractor version 最终为 2。v1 本地构建发现 parenthesized value/function argument 被宽松 cast 模式误识别；修复后升版以强制旧索引重建。
- UnifiedBackend 当前实际组成是 Clang + SVF，因此 type context 直接使用 Clang/KnowledgeDB 主结果；JoernBackend 独立实现同一契约，没有执行架构中不存在的 Clang/Joern 同时在线 merge。
- Joern 首期稳定覆盖 method return/parameter/local；其他 body type roles 依赖 Clang 主路径。
- validation evidence 使用 16 KiB consumer-specific definition budget，低于 persisted context 的 32 KiB 总预算；identity、reference 和 truncation 状态始终保留。
- 根据用户后续明确要求未执行完整 global-model benchmark，因此不提供 token/API/wall-time 改善结论。两个临时 run 均已终止，输出不具备完整 benchmark 可比性。

#### 7.16.3 已知问题

- 系统/平台 SDK 类型未进入项目 `type_definitions`，`pthread_t`、`FILE`、Windows API structs 等保持 unresolved；外部类型配置不在本章范围。
- Joern-only 与 regex backend 的 type role/source-definition 精度低于 Clang 主路径；复杂嵌套匿名 record、宏展开和模板定义可能保守 unresolved。
- 完整定义注入是否降低 Total Tokens 或 wall time 尚未实测，当前不能宣称整体成本优化。
- 当前完整 pytest 在两个 range benchmark regression 文件开始附近会无总结终止；按“不运行全量 benchmark”的要求未继续执行这两项，其他 751 项通过。

## 八、Project Callee 宏去重与 Macro Context 单一归属计划

> 实施状态：已实施（2026-07-23）。本章将 function-like macro 从 `project_callees` 中移除，由 `referenced_macros` 独占宏引用事实；可唯一解析的项目宏不会转入 `external_callees`。本章覆盖第四章中“项目 function-like macro 进入 project callee”的旧契约，以及第六章中针对 macro callee summary 的相关行为；旧章节保留为历史实施记录。本章未修改任何 fallback 文件。

### 8.1 背景与问题

当前 `find_function_infos()` 会把可唯一解析的项目 function-like macro 同时表示为两类事实：

1. `project_callees[]` 中的项目 callee：

   ```json
   {
     "callee_index_name": "WRAP@include/wrap.h:10-10",
     "callsite_lines": [42],
     "call_type": ["direct"],
     "is_static": false,
     "callee_summary": "unknown"
   }
   ```

2. `referenced_macros[]` 中的宏引用：

   ```json
   {
     "name": "WRAP",
     "file_path": "include/wrap.h",
     "line": 10,
     "definition": "#define WRAP(x) helper(x)",
     "is_function_like": true,
     "reference_lines": [42]
   }
   ```

这两条记录表达同一个预处理期依赖，却同时进入 Semantic Modeler 的初始 metadata。重复表示带来以下问题：

- LLM 可能把宏展开误解为运行时函数调用，并重复消费 `callee_summary` 与 `definition`。
- 宏记录占用 `project_callees` 的 30 项上限，可能挤掉真实项目函数。
- `is_static=false` 和 `call_type=["direct"]` 对宏只是兼容性占位，不是有价值的宏语义。
- 宏 snapshot 的 summary 与当前宏定义可能形成两套语义来源；两者刷新时机不同，增加一致性成本。
- callee-summary hydration、hash 和 reconciliation 会处理宏记录，即使 caller 已经持有完整宏定义。

本章会同时将第二类记录迁移为以 `macro_index_name` 为唯一 identity、以带绝对行号源码为 definition 的新契约，避免在删除 macro callee 后继续保留不完整的宏定位字段。

从语言模型看，function-like macro 是预处理期按名称展开的符号，不是可取地址、可由函数指针间接调用的运行时实体。宏展开后产生的真实函数调用应作为函数 callee 表达；宏本身应归入 symbol context。

### 8.2 目标与非目标

#### 8.2.1 目标

1. `project_callees` 只包含能唯一解析到项目普通函数定义的运行时调用边。
2. 所有可证明的宏引用，包括 object-like 和 function-like macro，只由 `referenced_macros` 表达。
3. 可唯一解析的 function-like macro 调用不得因移出 `project_callees` 而进入 `external_callees`。
4. backend callee edge 与 symbol-context 结果不一致时，先合并宏事实，再删除重复 callee，避免宏依赖静默丢失。
5. `project_callees` 的 30 项截断在排除宏后计算；`referenced_macros` 使用当前 50 项上限。
6. Semantic Model input、LLM prompt、LLM/deterministic snapshot、SnapshotStore fingerprint 和下游消费者使用相同契约。
7. 历史 snapshot 的 `project_callees[]` 仍包含 `is_macro`，或 `referenced_macros[]` 仍使用 `name/file_path/line` 时，以稳定 reason 触发重建。
8. 保留宏定义、引用行、宏类型和 refresh 能力，降低 prompt 重复内容和无效 callee-summary reconciliation。

#### 8.2.2 非目标

- 不在本章实现完整 C/C++ 预处理器或递归宏展开器。
- 不把宏定义内部的全局变量、嵌套宏或函数调用递归拼入 caller 的 symbol context。
- 不修改 external function 配置、snapshot runtime allowlist 或外部 API 语义建模。
- 不删除目标 snapshot identity 中的顶层 `is_macro`；目标本身仍可能是 function-like macro。
- 不保留 `project_callees[].is_macro` 兼容字段；本章直接从 persisted schema、deterministic shape 和程序输入中删除该字段。
- 不保留 `referenced_macros[].name/file_path/line` 兼容字段；宏 identity 统一改为数据库生成的 `macro_index_name`。
- 不改变 `referenced_macros` 的 50 项上限和 truncation 基础结构。
- 不修改任何 fallback 文件，不修改 baseline 工作树，不回退用户手动改动。

### 8.3 最终数据契约

#### 8.3.1 `project_callees`

`project_callees` 仅保存项目函数：

```json
{
  "callee_index_name": "helper@src/helper.c:20-48",
  "callsite_lines": [42],
  "call_type": ["direct"],
  "is_static": true,
  "callee_summary": "校验输入后更新内部状态。"
}
```

约束：

- `callee_index_name` 必须解析到普通函数定义，而不是 macro definition。
- `is_static` 来自 canonical function definition。
- `call_type` 继续允许 `direct`、`indirect` 或二者组合。
- `callee_summary` 只来自 canonical function snapshot 的顶层 `summary`。
- `project_callees` item 不再包含 `is_macro`；历史 item 中存在该字段时属于旧 shape，不得继续保存为 current snapshot。

#### 8.3.2 `referenced_macros`

`referenced_macros` 成为宏引用的唯一持久化来源：

```json
{
  "macro_index_name": "WRAP@include/wrap.h:10-11",
  "definition": "10 | #define WRAP(x) \\\n11 |     helper(x)\n",
  "is_function_like": true,
  "reference_lines": [42]
}
```

约束：

- object-like 与 function-like macro 使用同一数组。
- `macro_index_name` 使用 `name@normalized_file_path:start_line-end_line`，作为宏在数据库、Function Info、Semantic Model input、snapshot 和 refresh 中的唯一 identity。
- `name`、`file_path`、`line` 不再作为 `referenced_macros` item 顶层字段输出；调用方从 `macro_index_name` 解析展示信息，宏定义范围由该 identity 提供。
- 同一宏的 `reference_lines` 去重升序。
- function-like macro 的调用行同时属于宏引用行，不再另存为 callee callsite。
- `definition` 必须是带绝对 1-based 行号的源码文本，例如 `10 | ...`；不能只保存无行号的数据库原始文本。
- `definition` 由 CodeIndex 按 `macro_index_name` 的文件和行范围复用 `get_file_snippet()` 读取并生成；不能从函数名、路径或 location 猜测范围。
- 当前不增加 `macro_summary`；`definition` 是提供给 LLM 的宏语义事实。
- 宏定义变化继续通过 symbol-context fingerprint 触发 LLM refresh。

#### 8.3.3 `external_callees`

`external_callees` 继续只表示无法解析到项目函数的运行时调用目标。分类规则为：

1. 唯一项目函数 -> `project_callees`。
2. 唯一项目 function-like macro -> `referenced_macros`，不进入任何 callee 数组。
3. 已由 symbol extractor 证明为宏、但 callee extractor 同时产出同名 edge -> `referenced_macros`，删除重复 callee edge。
4. 无法证明是函数还是宏的调用目标 -> 保守保留在 `external_callees`，不得按大写命名、前缀或调用形式猜测为宏。

### 8.4 数据库、CodeIndex 提取、合并与截断

#### 8.4.1 数据库层 canonical macro identity

当前 `macro_definitions` 仅保存 `name/file_path/line/definition/is_function_like`，而 `function_symbol_refs` 的 macro 行也使用名称和文件定位。这不足以稳定区分同名宏、表示多行定义，也无法直接向 LLM 提供完整绝对行号源码。本章新增一次显式数据库 migration：

- `macro_definitions` 增加 `macro_index_name`、`start_line` 和 `end_line`；`macro_index_name` 为唯一键，格式固定为 `name@normalized_file_path:start_line-end_line`。
- `name`、`file_path`、`start_line`、`end_line` 继续作为数据库内部查询和展示列保留，但不再直接暴露为 `referenced_macros` item 字段。
- 现有 `line` 迁移为 `start_line`；`end_line` 根据完整宏定义的实际物理行范围计算。无法可靠计算范围时记录 migration failure 并触发 extractor 重建，不静默生成 `start-end` 猜测值。
- 对旧 `macro_definitions` 重复键执行 canonical collision 检查；冲突不覆盖旧记录，要求重建或人工处理。
- 将 function-to-macro 引用迁移到带 canonical macro identity 的关系中。推荐新增 `function_macro_refs(function_id, macro_id, reference_line)`，保留 `(function_id, macro_id, reference_line)` 唯一约束；旧 `function_symbol_refs` 中的 macro rows 在确认迁移成功后删除或仅保留 global rows。
- `function_macro_refs` 的 `macro_id` 必须外键关联 `macro_definitions.id`，查询时通过 join 得到 `macro_index_name`，不再按 `name/file_path` 模糊匹配同名宏。
- `KnowledgeDB.get_function_symbol_context()` 的 macro 查询结果改为返回 `macro_index_name`、`is_function_like` 和 `reference_lines`；无行号 raw definition 只作为数据库内部数据，不直接穿透到上层。
- Clang/Unified/其他 backend 保持 canonical `macro_index_name` 不变，不得在 backend adapter 中拆回 `name/file_path/line`。
- 数据库 schema/extractor version 递增；旧库先完成 macro definition range、canonical identity 和 function-to-macro refs 重建，再允许新的 Semantic Model input 读取。
- migration 输出总宏定义数、成功数、collision 数、无法计算范围数和重建数；失败不删除旧表或旧 JSON。

数据库仍可保存无行号的原始 `definition` 作为 extractor/cache 数据，但对外 `referenced_macros[].definition` 必须由源码范围重新渲染为带绝对行号的文本。

#### 8.4.2 三类分类结果

将当前 callee descriptor 从二分结果扩展为内部三分结果：

```text
project_function
project_macro
external_or_unresolved
```

`project_macro` 是中间分类，只用于把 callee extractor 发现的宏事实合并进 `referenced_macros`；它不直接出现在公开 function info payload。

普通函数 backend、regex fallback 和 macro body 扫描必须复用同一分类 helper。对于 macro body：

- 宏定义内直接调用的真实项目函数仍进入该宏 snapshot 的 `project_callees`。
- 宏定义内调用的另一个 function-like macro 进入该宏 snapshot 的 `referenced_macros`。
- 当前目标本身是宏时，顶层 identity 仍保留 `is_macro=true`、`is_static=false`。

#### 8.4.3 Macro fact 合并

不能先过滤 macro callee、再假定 symbol extractor 一定提供同一条 `referenced_macros`。统一构造流程应为：

1. 获取当前函数的全部 raw callee edges，不截断。
2. 获取当前函数的全部 raw macro symbol refs，不截断。
3. 将 raw callee edge 分类为 project function、project macro、external/unresolved。
4. 对每条 project macro edge 读取 canonical macro definition metadata。
5. 按 `macro_index_name` 与 function-to-macro refs 合并，补齐或合并 `reference_lines`。
6. 对合并后的 `referenced_macros` 去重、稳定排序，再应用 50 项上限。
7. 对排除 macro 后的 project functions 聚合、稳定排序，再应用 30 项上限。
8. external/unresolved 独立聚合并应用 20 项上限。

该顺序保证 backend 只在 callee edge 中识别出宏、但 symbol-ref 表遗漏同一引用时，最终 payload 仍保留宏事实。

#### 8.4.4 Definition hydration 与 Truncation

宏 record 构造必须通过 canonical range 获取源码：

1. 解析 `macro_index_name` 得到 normalized file path、`start_line` 和 `end_line`。
2. 调用 `CodeIndex.get_file_snippet(file_path, start_line, end_line, max_lines=end_line-start_line+1)`，复用其绝对 1-based 行号格式。
3. 将返回值的 `code` 作为 `definition`，并校验返回的 `file/start_line/end_line` 与 canonical identity 一致。
4. 文件不存在、范围越界或返回范围不完整时，记录稳定 reason `macro_definition_unavailable`，不得把无行号旧 definition 当作 current LLM evidence；当前函数的 Semantic input 构造失败，不调用 LLM、不保存新 snapshot。
5. 代码读取失败不改变 `macro_index_name`；修复索引或源码后允许重试。

`get_file_snippet` 的 public tool 上限不改变；内部 canonical macro hydration 可以按已知完整范围传入 `max_lines`，确保多行宏不会被默认 50/500 行策略意外截断。

Truncation 规则：

- `project_callees_truncation.total` 只统计排除宏后的项目函数数。
- `referenced_macros_truncation.total` 统计 symbol refs 与 macro edges 合并去重后的宏数。
- 被移除的重复 macro callee 不计入 project 或 external total。
- 只有对应最终集合实际超过上限时才输出 truncation 字段。
- 同一输入重复构建必须得到稳定顺序、相同 total 和相同 returned。

### 8.5 Semantic Model 输入与 Prompt

`build_semantic_model_input()` 继续透传程序生成的：

- `project_callees`
- `external_callees`
- `referenced_macros`
- 三者实际存在的 truncation metadata

数据库字段按以下顺序逐层穿透，任何上层不得重新拼接 macro identity 或重新编号 definition：

```text
macro_definitions/function_macro_refs
  -> backend.get_function_symbol_context()
  -> CodeIndex.find_function_infos()
  -> get_function_info Tool
  -> build_semantic_model_input()
  -> SemanticModeler._prompt_metadata()
  -> persisted snapshot
```

每层 `referenced_macros` item 固定为：

```json
{
  "macro_index_name": "WRAP@include/wrap.h:10-11",
  "definition": "10 | #define WRAP(x) \\\n11 |     helper(x)\n",
  "is_function_like": true,
  "reference_lines": [42]
}
```

中间层不得重新增加 `name`、`file_path` 或 `line`。输入同时必须满足：

```text
all("is_macro" not in item for item in project_callees)
all(set(item) == {"macro_index_name", "definition", "is_function_like", "reference_lines"}
    for item in referenced_macros)
```

`SemanticModeler._prompt_metadata()` 仍可同时投影 `project_callees` 和 `referenced_macros`，因为二者已经分别表示函数调用与宏引用，不再重复。Agent contract 更新为：

- 只把 `project_callees` 解释为可查询 canonical function snapshot 的项目函数。
- 直接使用 `referenced_macros[].definition` 理解宏展开，不为同一宏请求 function snapshot。
- 需要定位宏定义时使用 `macro_index_name` 和 definition 中的绝对行号，不再寻找已删除的 `name/file_path/line` 字段。
- 宏定义中出现的函数调用只作为理解当前函数的证据；是否额外查询对应函数仍由已预加载 project callee 或按需证据需求决定。
- `external_callees` 不包含已证明的项目宏。

### 8.6 Schema、Program Merge 与 Deterministic Snapshot

#### 8.6.1 完整 snapshot schema

- `project_callees[].is_macro` 从完整 persisted schema、Function Info/Semantic input 契约、deterministic shape 和 program merge 中删除；LLM schema 继续整体排除 program-owned `project_callees`。
- `project_callees`、`external_callees` 和 `referenced_macros` 继续是 persisted snapshot required 字段。
- LLM schema 继续排除全部 program-owned 字段，不要求模型输出或修复 callee/macro 数组。
- `referenced_macros` item schema 的 required 字段为 `macro_index_name`、`definition`、`is_function_like`、`reference_lines`；不再包含 `name`、`file_path`、`line`，也不增加 summary 字段。

#### 8.6.2 Program merge

Semantic Modeler 最终合并继续以 program input 覆盖模型 payload。即使模型伪造：

- `project_callees` 中的 macro item；
- `referenced_macros` 中的额外或伪造 `macro_index_name`；
- 任一 truncation metadata；

最终 snapshot 也必须完全等于程序输入中的 canonical 数组。

#### 8.6.3 Deterministic snapshot

trivial/lightweight builder 使用同一新输入：

- `_normalize_project_callees()` 拒绝任何仍包含 `is_macro` 的旧 item，不把宏转移到 external。
- `referenced_macros` 原样深拷贝程序合并结果，item 只含 `macro_index_name`、带绝对行号的 `definition`、`is_function_like` 和 `reference_lines`。
- project callee 的 deterministic summary 只针对真实函数。
- 顶层目标若是宏，仍可生成独立 macro snapshot；这不意味着 caller 把它保存为 project callee。

### 8.7 SnapshotStore、Fingerprint 与 Reconciliation

#### 8.7.1 Shape 迁移

历史 snapshot 满足以下任一条件时返回 `snapshot_shape_changed`：

- `project_callees` item 仍包含 `is_macro` 字段；
- `referenced_macros` item 仍包含 `name`、`file_path` 或 `line`，或缺少 `macro_index_name`；
- 同一 canonical macro 同时存在于 `project_callees` 和 `referenced_macros`；
- deterministic snapshot 的 project callee 仍使用旧宏 shape。

不对历史 JSON 做原地删除或 program-only patch。LLM-modeled snapshot 重新构建语义字段，deterministic snapshot 重新执行 builder，确保新 prompt 和新依赖归属一致。

#### 8.7.2 Fingerprint

- `symbol_context_hash` 继续包含 project/external call edges 与 `referenced_macros`。
- 宏的 `macro_index_name`、带绝对行号的 definition、引用行或 truncation 变化继续返回 `symbol_context_changed`。
- 宏从 project callee 移到 referenced macro 的首次迁移优先返回 `snapshot_shape_changed`。
- `callee_summary_hash` 只包含普通项目函数 identity 与 summary，不再包含 macro snapshot summary。
- 已移除宏的 summary 晚到或变化，不触发 caller program-only reconciliation。

#### 8.7.3 Reconciliation

`hydrate_project_callee_summaries()`、`hydrate_project_callee_summaries_from_map()` 和 `reconcile_project_callee_summaries()` 只处理新的项目函数 item schema。若输入中意外出现旧 macro item 或任意 `is_macro` 字段：

- 建模前返回稳定输入错误或 shape error；
- 不查询 macro snapshot；
- 不写入 `callee_summary`；
- 不静默把宏移到其他数组。

### 8.8 Global Model 与依赖发现

持久化 snapshot 的 callee 契约与内部建模图需要明确区分：

- snapshot `project_callees` 只表示运行时项目函数调用边。
- Global Model 内部可以继续沿 macro expansion dependency 发现和分析宏定义，避免丢失宏体内才出现的真实函数依赖。
- 内部 macro dependency 不得再次序列化为 caller 的 `project_callees`，也不参与 caller 的 callee-summary reconciliation。
- 显式作为 entry 或按需查询的 function-like macro 仍可拥有独立 snapshot。
- 后续若要停止全局阶段对宏节点建模，应先证明展开后真实函数边已由 backend 完整提供；不在本章直接删除内部遍历能力。

全局阶段末统计需要确认：

- `unknown_project_callees` 只统计普通项目函数。
- macro snapshot 缺失不导致 caller reconciliation failure。
- self recursion 和 SCC 只按真实函数 callee summary 收敛；宏依赖不伪装为函数递归边。

### 8.9 下游消费者

同步检查并迁移：

1. `zscope/core/validation/evidence.py`
   - function calls 从 `project_callees` 读取；
   - macro evidence 从 `referenced_macros` 读取；
   - 不为同一宏重复生成 evidence。
2. semantic inference
   - 不再从 project callee summary 提取宏行为；
   - 需要宏行为时使用 `macro_index_name`、带绝对行号的 definition 和 reference lines。
3. snapshot tool
   - 返回 current 新 shape；历史重复 shape 返回 stale/missing fallback，不返回旧 snapshot。
4. scan resume/final report
   - shape 或 macro fingerprint 变化时不复用旧 final report。
5. 文档与工具说明
   - 删除“项目 function-like macro 属于 project callee”的现行描述；
   - 明确 macro 只属于 referenced symbol context。

### 8.10 需要修改的文件

生产代码预计包括：

- `zscope/retrieval/knowledge_db.py`
- `zscope/retrieval/clang_extractor.py`
- `zscope/retrieval/backend_base.py`
- `zscope/retrieval/clang_backend.py`
- `zscope/retrieval/unified_backend.py`
- `zscope/retrieval/code_index.py`
- `zscope/snapshots/modeling_input.py`
- `zscope/snapshots/policy.py`
- `zscope/snapshots/store.py`
- `zscope/agents/semantic_modeler/schema.py`
- `zscope/agents/semantic_modeler/agent.py`
- `zscope/agents/semantic_modeler/AGENT.md`
- `zscope/orchestration/global_modeler.py`
- `zscope/core/validation/evidence.py`
- 其他直接消费 `project_callees` 或 `referenced_macros` 的 adapter

测试预计包括：

- `tests/test_knowledge_db_ir_and_config.py`
- `tests/test_clang_incremental_extraction.py`
- `tests/test_function_info_tool.py`
- `tests/test_semantic_model_input.py`
- `tests/test_json_output_agents.py`
- `tests/test_snapshot_store.py`
- `tests/test_analyzer_semantics.py`
- `tests/test_global_modeler.py`
- `tests/test_snapshot_tool.py`
- deterministic snapshot 与 validation evidence 相关测试

文档预计包括：

- `new_docs/agent_optimation.md`
- `new_docs/agent_introduction.md`
- `new_docs/tools_introduction.md`
- [本历史快照方案](snapshot_redesign.md)

### 8.11 实施顺序

1. 审计各 backend 的 macro callee 与 macro symbol-ref 覆盖率，建立同一 fixture 的对照测试。
2. 为 macro definitions 和 function-to-macro refs 实施数据库 migration、canonical `macro_index_name`、完整行范围和 extractor version 重建。
3. 增加内部三分 callee 分类，保留 project macro 中间结果，不立即改变公开 payload。
4. 实现 macro edge 与 canonical macro refs 的 merge，并使用 `get_file_snippet()` 生成带绝对行号的 definition；验证 backend 漏一侧时仍不丢宏。
5. 在 merge 后生成公开 `project_callees`、`external_callees`、新 shape `referenced_macros` 和独立 truncation。
6. 更新 Function Info Tool、Semantic Model input、prompt 和 program passthrough contract，禁止旧宏字段回流。
7. 从完整 schema、deterministic shape 和 normalization 删除 `project_callees[].is_macro`。
8. 更新 SnapshotStore shape、hash、refresh 和 callee-summary reconciliation。
9. 更新 Global Model 统计及内部 macro dependency 与 persisted call edge 的边界。
10. 迁移 validation、semantic inference、snapshot tool 和 scan resume 消费点。
11. 更新聚焦测试、文档和实施记录，再运行可收集完整回归。

### 8.12 测试矩阵

#### 8.12.1 CodeIndex 与 Function Info

- 普通函数调用项目函数：只进入 `project_callees`。
- 普通函数调用 function-like macro：只进入 `referenced_macros`。
- 普通函数引用 object-like macro：只进入 `referenced_macros`。
- macro body 调用项目函数：宏 snapshot 的函数 callee 正常保留。
- macro body 调用另一个宏：只进入该宏 snapshot 的 `referenced_macros`。
- backend 同时返回 macro callee edge 和 macro symbol ref：最终只保留一个 macro record，引用行合并。
- backend 只返回 macro callee edge：从 canonical definition 补齐 `referenced_macros`，不丢失依赖。
- backend 只返回 macro symbol ref：不产生 callee item。
- macro definition 跨多行：`macro_index_name` 的 start/end 覆盖完整物理范围，definition 使用 `get_file_snippet()` 返回的绝对行号文本。
- 同名 macro 位于不同文件或不同行范围：使用不同 `macro_index_name` 独立保存、引用和 refresh。
- 旧数据库缺少 end line 或 macro ref canonical identity：migration 记录失败并触发重建，不生成模糊 key。
- 无法证明为宏的 unresolved call：继续进入 `external_callees`。
- 项目函数与宏同名或多定义歧义：不猜测，按唯一解析规则保守处理。
- SVF/unified 把 macro edge 标记为 indirect：宏仍不进入 callee 数组，避免暴露无意义 call type。
- 30 个项目函数加多个宏：宏不占 project limit。
- 合并后超过 50 个宏：truncation returned/total 正确且稳定。

#### 8.12.2 Semantic Modeler 与 Snapshot

- 初始 prompt 中每个 function-like macro 只出现于 `referenced_macros` 区域。
- `project_callees` item 不包含 `is_macro`，仍保留函数 summary hydration。
- LLM 伪造 macro project callee 无法进入最终 snapshot。
- deterministic snapshot 不包含 macro project callee。
- 目标本身是宏时顶层 `is_macro=true`，其 referenced macros 与真实函数 callees 仍正确分流。
- 宏定义变化触发 `symbol_context_changed` 和 LLM refresh。
- 宏 summary 变化不再触发 caller `callee_summary_changed`。
- 历史 macro callee shape 返回 `snapshot_shape_changed` 并重建。
- program-only function summary reconciliation 不处理宏。

#### 8.12.3 消费者与回归

- validation evidence 不重复输出同一宏。
- snapshot tool 不返回旧重复 shape。
- global reconciliation 的 unknown/reconciled 统计不包含宏。
- macro expansion dependency 仍可支持全局依赖发现，不序列化成函数 callee。
- referenced globals/types、external callees 和现有 function summary 行为不回归。
- 普通函数、static 函数、间接函数调用、递归/SCC、trivial/lightweight snapshot 回归通过。

### 8.13 验收条件

- 新生成的任意 snapshot 中，`project_callees` item 均不包含 `is_macro`。
- 可唯一解析的 function-like macro 不存在于 `project_callees` 或 `external_callees`，只存在于 `referenced_macros`。
- 每个 `referenced_macros` item 只包含 `macro_index_name`、带绝对行号的 `definition`、`is_function_like` 和 `reference_lines`，不包含 `name/file_path/line`。
- 数据库以 `macro_index_name` 和完整 start/end line 范围唯一定位宏；function-to-macro refs 不再按名称或路径模糊关联。
- Function Info 及后续 LLM 输入中的 macro definition 与 `get_file_snippet()` 对同一 canonical 范围的 `code` 完全一致，并保留绝对 1-based 行号。
- macro callee edge 与 macro symbol ref 任一来源缺失时，合并流程仍能保留可证明的 canonical macro 引用。
- `project_callees` 的 limit/total 不统计宏；`referenced_macros` 继续使用 50 项上限并报告准确 total。
- Semantic Modeler prompt 不再重复提供同一 macro 的 callee record 和 macro definition。
- project callee summary hydration、hash 和 reconciliation 只处理真实项目函数。
- 历史重复 shape 通过 `snapshot_shape_changed` 重建，不原地猜测或静默删除字段。
- 宏定义和引用变化继续触发 caller LLM refresh；宏 snapshot summary 变化不再单独刷新 caller。
- Global Model 内部依赖发现不因持久化契约调整而静默漏掉宏体中的真实函数依赖。
- Function Info、Semantic Modeler、SnapshotStore、Global Model、deterministic snapshot、validation 和 snapshot tool 聚焦测试通过。
- 可收集完整回归、`compileall` 和相关文件 `git diff --check` 通过。
- 不修改 fallback 文件，不修改 baseline 工作树，不回退用户手动改动。

### 8.14 风险、权衡与缓解

| 风险 | 影响 | 缓解 |
|---|---|---|
| backend 只报 macro callee、不报 symbol ref | 直接过滤会丢失宏定义和 refresh 依赖 | 先保留 project-macro 中间事实，与 canonical macro definitions 合并后再过滤 |
| backend 无法证明某目标是宏 | 错删真实 external call | 只有唯一 macro definition 或可靠 symbol ref 才分类为宏，不按名称猜测 |
| 移除 macro summary 后语义变弱 | 复杂宏可能仅靠 definition 难以概括 | 保留完整 definition、引用行和按需源码工具；benchmark 比较建模质量 |
| project limit 语义变化 | 历史 truncation total 与新结果不同 | 明确 shape migration，重建后按真实函数重新计算 |
| Global Model 不再遍历宏 | 可能漏掉只在宏体出现的函数 | 区分内部 macro dependency 与 persisted callee，首期保留内部发现能力 |
| 删除 `is_macro` 破坏历史 item | 旧 snapshot 或测试仍携带字段 | 明确 `snapshot_shape_changed`，一次性重建；不接受兼容字段回流 |
| macro range migration 不完整 | 生成错误 `macro_index_name` 或读取错误源码 | extractor version 强制重建；无法可靠计算 end line 时失败，不猜测 |
| canonical range 对应源码不可读 | LLM 获得空 definition 或旧缓存文本 | 返回 `macro_definition_unavailable`，不调用 LLM、不保存 snapshot |
| 历史 snapshot 大量重建 | 首次运行增加 LLM/API 成本 | 稳定 reason、cache 命中日志和可恢复批次；不原地修改旧语义 |
| definition 与实际预处理展开不同 | 条件宏、token pasting 可能仍不完整 | 保留不确定性，不实现伪预处理；需要时使用 backend/工具补证 |

### 8.15 实施记录要求

实施完成后，将本章状态改为“已实施”，并在 `new_docs/agent_optimation.md` 至少记录：

- 各 backend 的 macro edge/symbol-ref 对照结果；
- 最终三分分类与 macro merge 实现；
- 数据库 schema、macro range/index migration、extractor version 和 function-to-macro refs；
- complete snapshot schema、shape migration、fingerprint 和 reconciliation 行为；
- `get_file_snippet()` definition hydration 与绝对行号验证；
- Global Model 内部 macro dependency 的实际处理；
- 聚焦测试、可收集完整回归、compileall 和 diff check；
- prompt 中重复 macro 数、project callee 可用配额和 snapshot rebuild 数的前后对比；
- 未解决的条件宏、token pasting、backend 缺失事实和复杂宏问题。

只有在同配置 benchmark 证明 Total Tokens、API Calls 或 wall time 实际下降时，才能宣称成本优化；仅减少重复字段时应记录为“上下文去重和契约收敛”。

### 8.16 实施结果、计划偏差与已知问题

#### 8.16.1 实施结果

- KnowledgeDB schema 升至 v10；`macro_definitions` 新增 canonical `macro_index_name`、`start_line` 和 `end_line`，并增加唯一索引。
- 新增 `function_macro_refs(function_id, macro_id, reference_line)`，函数宏引用通过外键关联 canonical macro definition；旧 `function_symbol_refs` 只继续承载 global symbol refs。
- macro extractor 与 symbol-context extractor version 均升至 2，旧索引会强制重建。TU 清理、incoming macro dependency 和统计已覆盖新表。
- CodeIndex 将 raw callee 分为 project function、project macro 和 external/unresolved。project macro 只作为内部中间事实与 macro refs 合并，不进入任一公开 callee 数组。
- `project_callees` item 已从完整 schema、Function Info/Semantic input、deterministic snapshot、hash projection 和 reconciliation 中删除 `is_macro`。
- `referenced_macros` item 已统一为 `macro_index_name/definition/is_function_like/reference_lines`，不再输出 `name/file_path/line`。
- macro definition 由 `CodeIndex.get_file_snippet()` 按 canonical start/end range 读取，输出绝对 1-based 行号；范围不可读时返回 `macro_definition_unavailable`，不保存新 snapshot。
- Semantic Modeler program validation、prompt、program merge、SnapshotStore shape refresh、deterministic builder、snapshot tool、validation evidence 和 scan resume 已迁移到新 shape。
- Global Model 的内部 `get_callees()` 可达图遍历保持不变；callee-summary hydration、hash、reconciliation 和 `unknown_project_callees` 只处理真实项目函数。
- 历史 `project_callees[].is_macro` 或旧 `referenced_macros` item 通过 `snapshot_shape_changed` 重建，不做原地字段删除。

#### 8.16.2 验证结果

- 数据库/extractor、Function Info、Semantic input、Semantic Modeler、SnapshotStore、deterministic snapshot、Global Model、snapshot tool、parallel/scan resume 聚焦集合：`199 passed`。
- 排除 `tests/test_benchmark_protocol.py` 与 `tests/test_range_benchmark_regression.py` 的可收集完整回归：`762 passed`。
- `python -m compileall -q zscope`：通过。
- `git diff --check`：通过。
- 未调用外部 LLM，未运行 global-model benchmark。

#### 8.16.3 计划偏差

- 数据库内部仍保留 `macro_definitions.name/file_path/line/definition` 作为查询、迁移和 extractor cache 字段；删除的是公开 `referenced_macros` item 的旧字段。canonical identity 和关系查询只使用新增范围与外键。
- `insert_macro_definitions_batch()` 暂时接受旧五字段内部调用并立即规范化为 v10 七字段记录，便于局部 adapter 迁移；数据库查询、Function Info、snapshot 和 LLM 输入不会返回旧 shape。
- 旧 macro definition 的 `end_line` 可由已保存完整 definition 的物理行数确定时直接回填；无法可靠恢复或发生 canonical collision 时迁移失败并要求 extractor 重建。
- 没有删除 Global Model 的内部 macro dependency 遍历，因此本轮只收敛 persisted snapshot/LLM 上下文，不宣称减少 reachable node 数或宏 snapshot 建模次数。

#### 8.16.4 已知问题

- 条件编译下同名宏定义的精确可见分支仍依赖 backend；无法唯一证明时保守保留 unresolved/external 边，不按名称猜测。
- token pasting、递归宏展开以及展开后才出现的完整函数边不在本章实现范围。
- canonical macro source range 在 snapshot 构建时必须可读；源码与数据库索引不同步会返回 `macro_definition_unavailable`，需要先刷新索引。
- 完整 `pytest` 仍会在两个 range benchmark regression 文件附近无总结终止；终止前未出现失败，本轮按既有口径完成其余 `762` 项回归。
- 未执行同配置 benchmark，因此当前只能表述为“上下文去重和契约收敛”，不能宣称 Total Tokens、API Calls 或 wall time 已下降。
