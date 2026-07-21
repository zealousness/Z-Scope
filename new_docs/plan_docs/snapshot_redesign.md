# Snapshot Redesign

本文记录 `semantic_modeler` 函数快照结构的设计与实施计划。第一至十节的统一 `effects` 设计仍为草案；第十一节的 Semantic Modeler 输入、snapshot identity 和存储重构已于 2026-07-17 实施。

## 一、背景

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

## 二、设计目标

### 2.1 目标

- 用一个字段表达函数对外部世界、对象状态、资源和并发状态的影响。
- 减少 schema 顶层字段数量，降低 LLM 输出负担。
- 避免 `memory` / `resources` / `concurrency` 之间重复记录同一事实。
- 让 validator 能按 `category` 过滤需要的证据。
- 保留行号、对象、条件、状态变化、风险说明这些审计必需信息。

### 2.2 非目标

- 不在本阶段删除现有 schema 字段。
- 不在本阶段修改 `fallback` 文件。
- 不在本阶段修改 trivial/lightweight snapshot。
- 不在本阶段要求所有旧 snapshot 迁移。

## 三、核心思路

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

## 四、初版结构

### 4.1 顶层字段

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

### 4.2 通用字段

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

### 4.3 category 候选

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

### 4.4 action 候选

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

## 五、类别示例

### 5.1 memory

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

### 5.2 resource

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

### 5.3 bounds

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

### 5.4 shared_state

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

### 5.5 lock

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

### 5.6 thread

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

## 六、与现有字段的映射

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

## 七、初版 schema 草案

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

## 八、迁移建议

### 8.1 第一阶段：并行新增

- 保留旧字段。
- 新增 optional `effects`。
- 让 `semantic_modeler` 优先输出 `effects`，旧字段仍可为空或按需保留。

### 8.2 第二阶段：下游读取迁移

- validator 和 subagent 读取 `effects`。
- 按 `category` 过滤证据：
  - bounds/string: `bounds`, `memory`
  - resource lifecycle: `resource`, `memory`, `ownership`
  - concurrency: `shared_state`, `lock`, `thread`, `sync_protocol`
  - callback/reentrancy: `callback`, `lock`
- 本阶段不适配 `error_path` category；需要错误路径语义时继续读取现有 `error_paths`。

### 8.3 第三阶段：删除旧字段

确认新 benchmark 指标稳定后，再从主 schema 删除旧字段：

- `memory`
- `resources`
- `concurrency`
- 未来如存在 `side_effects`，也不再单独保留

## 九、风险与注意事项

| 风险 | 说明 | 缓解 |
|---|---|---|
| `effects` 变成新杂项桶 | 过度自由会失去结构化价值 | 固定 `category`，要求 `action/object/line/condition/risk` |
| 单条 effect 信息过长 | LLM 可能塞入大段解释 | `description` 限制为中文一句话；`risk` 和 `details` 保持短句 |
| 下游暂不兼容 | validator 当前可能还读旧字段 | 第一阶段并行新增，不立即删除旧字段 |
| 事件重复 | 同一行为可能被记录两次 | 后续可按 `category/action/object/line` 去重 |
| fallback 被同步改动 | fallback 应保留降级/对照价值 | 除非明确要求，不修改任何 fallback 文件 |

## 十、初步结论

将 `memory`、`resources`、`concurrency`、`side_effects` 合并为 `effects` 是合理的。它可以降低顶层 schema 复杂度，也能把所有可审计副作用统一成事件事实。建议先以 optional `effects` 并行引入，等 validator 和 benchmark 适配后，再考虑删除旧字段。

## 十一、Semantic Modeler 输入与身份字段程序化生成计划

> 实施状态：已完成。实施记录、测试结果、计划偏差和已知问题见 `new_docs/agent_optimation.md` 的“2026-07-17 Snapshot identity 重构”。

### 11.1 目标

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

### 11.2 `find_function_infos()` 输出契约

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

### 11.3 查询、消歧与代码获取

四条 LLM 建模路径，包括全局建模、entry 建模、premodel 和按需 snapshot，都采用相同顺序：

1. 使用任务中的原始函数名和可用文件提示调用 `find_function_infos()`。
2. 如果已有 canonical `index_name`，优先用它查询；否则按 `func_name + file_path` 查询。
3. 返回多个结果时，使用已有 `index_name`、文件路径和起始行精确消歧。
4. 得到唯一 function info 后，使用其 `index_name` 调用 `get_function_impl()` 获取对应代码。
5. 查询无结果或无法唯一匹配时终止本次 LLM snapshot 构建，不从源码、函数名或 location 字符串猜测身份字段。

该顺序保证 function info 和 `code` 属于同一个函数定义，避免同名函数、重载或宏出现元数据与源码错配。

### 11.4 Semantic Modeler 输入契约

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

### 11.5 schema 拆分

保留完整 snapshot schema 作为持久化结构和下游契约，同时从它派生 LLM 输出 schema：

- 从 LLM schema 的 `required` 中删除九个程序生成字段。
- 从 LLM schema 的 `properties` 中删除九个程序生成字段。
- 自定义 semantic_modeler schema 同样执行该转换。
- `emit_function_snapshot` final tool 和 structured-output response format 都使用 LLM schema。
- `callees` 继续保留在 LLM schema 中；`referenced_globals` 和 `referenced_macros` 只作为输入证据，不新增为 snapshot 顶层字段。
- 本阶段不迁移未列出的字段，也不展开通用 validator 重构。

### 11.6 运行时拼接

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

### 11.7 SnapshotStore 的 `index_name` 存储模型

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

#### 11.7.1 文件名

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

#### 11.7.2 SQLite schema

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

#### 11.7.3 数据库迁移

新增一次显式 schema migration：

1. 读取旧表中的 snapshot JSON。
2. 优先使用 JSON 内已有的 `index_name`。
3. 缺少 `index_name` 时，使用 snapshot 的 `func_name/file_path/start_line/end_line` 构造 canonical index name。
4. 无法获得完整身份字段时，将该记录计为 migration failure，不覆盖其他记录，也不静默生成模糊 key。
5. 发现两个旧记录映射到同一个 `index_name` 时记录 collision error，并停止自动覆盖。
6. 使用新的 index-name 文件名重命名或重写 snapshot/final report 文件。
7. 全部可迁移记录写入新表后，再切换表名并提交事务。

迁移需要输出总记录数、成功数、跳过数、失败数和冲突数。失败不能导致原表或原 JSON 文件被删除。

#### 11.7.4 location 清理边界

以下 snapshot 身份消费点全部改为 `index_name`：

- `SnapshotStore.save_snapshot()` 和 `save_final_report()`；
- snapshot/final report load、delete、refresh 和 fingerprint；
- cache 与 lock manager；
- global model、entry model、premodel、按需 snapshot 的保存和复用逻辑；
- on-demand snapshot tool 及其他调用 SnapshotStore 的 adapter；
- web snapshot 回写中用于定位 snapshot/final report 的逻辑。

删除 `_file_path_from_location()` 以及 snapshot store 中所有 location 解析和路径偏好选择代码。

本项只删除 location 作为 snapshot 身份标识的用途。issue、candidate、suspicious point 和 evidence 中用于表示具体源码行的 `location` 仍然保留，因为它们表达的是证据位置，不是 snapshot 主键。

### 11.8 工具与 prompt 策略调整

更新 `semantic_modeler/AGENT.md`：

- 删除要求模型 preserve 或输出九个身份字段的 Identity 描述。
- 明确模型只负责 LLM schema 中剩余的语义字段。
- 明确目标函数的 identity、callees、referenced globals 和 referenced macros 已由初始 prompt 提供。
- 禁止对目标函数再次调用 `get_function_info`。
- 允许对 callee 或其他相关函数调用 `get_function_info`，但优先使用 snapshot；只有预加载信息不足以完成语义建模时才查询。
- 保持 parameters、return values、effects、error handling、callees 和 suspicious points 的建模要求不变。

### 11.9 日志设计

日志应使用稳定前缀和结构化关键字段，区分解析、LLM、锁、存储和迁移阶段。不得记录完整源码、完整 prompt、用户配置内容或完整 snapshot JSON。

#### 11.9.1 Function info 解析日志

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

#### 11.9.2 锁与建模日志

现有 `[snapshot-lock]` 日志改为只使用 `index_name`：

```text
[snapshot-lock] waiting index_name=foo@src/a.c:10-20 context=premodel
[snapshot-lock] outcome index_name=foo@src/a.c:10-20 status=acquired waited=0.02s
```

LLM 建模日志至少包含 `index_name`、建模入口、成功状态、token 统计和稳定失败 reason。不得再以 `func_name + file_path` 作为唯一诊断标识。

#### 11.9.3 存储日志

| 场景 | 级别 | 必要字段 |
|---|---|---|
| 保存成功 | `INFO` | `index_name`、`snapshot_file` |
| 加载未命中 | `DEBUG` | `index_name` |
| DB 记录存在但文件缺失 | `WARNING` | `index_name`、`snapshot_file` |
| snapshot 参数与内容不一致 | `ERROR` | 参数和 payload 中的 `index_name` |
| 删除成功 | `INFO` | `index_name` |
| final report 无对应 snapshot | `WARNING` | `index_name` |

#### 11.9.4 迁移日志

迁移开始和结束使用 `INFO`，单条无法迁移记录使用 `WARNING`，key collision 或事务失败使用 `ERROR`。结束日志输出：

```text
[snapshot-migration] completed total=... migrated=... skipped=... failed=... collisions=...
```

所有异常路径都必须保证 lock 以 `success=false` 释放，并记录对应 `index_name`；尚未解析出 `index_name` 时记录原始 query hints。

### 11.10 实施步骤

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

### 11.11 验收条件

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

## 十二、Deterministic Snapshot 输出结构统一计划

> 实施状态：已于 2026-07-20 完成。实施过程、测试结果、计划偏差和已知问题见 `new_docs/agent_optimation.md` 的“2026-07-20 Deterministic snapshot 输出结构统一”。

### 12.1 目标

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

### 12.2 当前差异

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

### 12.3 统一构造策略

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

### 12.4 字段生成规则

#### 12.4.1 Identity 与源码

- `func_name`、`index_name`、`file_path`、`start_line`、`end_line`、`signature`、`is_static`、`is_macro` 直接复用统一输入，不再次解析 `location` 或自行拼接 identity。
- `snapshot_kind` 由 builder 固定写入，不允许调用方覆盖。
- `code` 保留完整带行号源码。trivial/lightweight 本身受长度策略限制，因此不额外截断。
- 缺少 canonical identity 时沿用 SnapshotStore 的 identity 校验并拒绝保存，不生成猜测值。

#### 12.4.2 `referenced_globals` 与 `referenced_macros`

- 直接复用统一输入中的数组，不要求 deterministic builder 再次查询 CodeIndex 或扫描源码。
- 没有引用时固定输出空数组，不省略字段。
- 保持 function info 已提供的定义位置、引用行、access、definition 和 `is_function_like` 等结构化内容。
- builder 应复制数组及其 item，避免调用方或下游修改 snapshot 时反向污染统一输入。
- 当前 `_program_symbol_context()` 已会可选透传 `referenced_globals_truncation` 和 `referenced_macros_truncation`，该行为保留。
- truncation 字段仅在统一输入实际包含时输出，内容原样复制，保持 `truncated`、`returned` 和 `total`。
- 输出顺序固定为对应 symbol-context 数组之后、`summary` 之前；只有一个 truncation 字段存在时只输出该字段。
- builder 应复制 truncation object，避免 snapshot 与输入共享可变对象。
- 本项只确认透传和结构统一，不修复 `KI-002` 中 backend-backed macro symbol context 缺少降级提取的问题。

#### 12.4.3 `parameters`

第一阶段不新增不可靠的 C/C++ signature 字符串解析器：

- 默认输出空数组 `[]`。
- 不把旧 `inputs=[]` 机械改名为带虚假语义的 parameter 记录。
- 后续如果 CodeIndex 提供结构化参数信息，再单独扩展 deterministic parameter 生成，不纳入本轮。

#### 12.4.4 `return_values`

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

#### 12.4.5 `effects`

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

#### 12.4.6 `error_handling`

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

#### 12.4.7 `callees`

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

#### 12.4.8 `suspicious_points`

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

### 12.5 下游消费点迁移

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

### 12.6 历史 snapshot 兼容策略

本轮不原地重写已有 snapshot JSON，也不修改 SQLite schema。采用渐进式更新：

- 新生成的 trivial/lightweight snapshot 必须包含十九个必需字段，并且只允许额外包含输入中实际存在的三个 truncation 字段。
- `SnapshotStore.needs_refresh()` 增加 deterministic shape 检查；已保存的 `syntactic/lightweight` snapshot 如果仍包含旧字段或缺少新字段，返回 `needs_refresh=true`、`reason=snapshot_shape_changed`。
- global model、entry reuse、premodel 和按需 snapshot 在复用前都必须尊重该 refresh reason，重新执行廉价 deterministic builder。
- 通用下游消费者在迁移期保留旧字段 fallback，避免直接读取尚未刷新历史 snapshot 时丢失信息。
- final report 不因 deterministic snapshot shape 更新而主动删除；重建 snapshot 时是否清除 final report 沿用现有 SnapshotStore 行为，并在测试中明确验证。

### 12.7 实施步骤

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

### 12.8 测试计划

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

### 12.9 验收条件

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
