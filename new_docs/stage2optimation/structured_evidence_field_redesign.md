# Deep Worker 与 Vulnerability Analyzer Structured Evidence 字段分析与重构建议

本文对比分析 `deep_worker` 与 `vulnerability_analyzer` 中五类 `Structured evidence` 的字段结构。每章依次列出 `deep_worker` 原始字段及其重复和必要性分析、`vulnerability_analyzer` 原始字段及与 `deep_worker` 的差异、`deep_worker` 新字段，以及 `vulnerability_analyzer` 新字段。

分析基准为：

- 会话目录：`/home/jager/Z-Scope-benchmark/test/range/.zscope_conversations/run_20260721_145040_359477`
- 原始运行日期：2026-07-21
- 逻辑 Ticket 数：1172
- Candidate 来源：`source_rule`、`semantic_snapshot`、`graph_rule`、`clang_ast_cfg`、`svf_value_flow`
- `clang_ast_cfg` 有普通单函数和入口到内部 Sink 两个变体，因此五类来源对应六种顶层字段签名

当前 Deep Worker Prompt 共同包含以下 Ticket 外层字段：

```text
Ticket ID
Skill
Trigger + line
Origin
Sink
Sources
Call paths
Structured evidence
Task
Execution policy
Worktree isolation
Nested subagent spawning allowed
Skill Contract
Focused Code Context
```

本文使用以下必要性标记：

| 标记 | 含义 |
|---|---|
| 必须 | 直接参与 Candidate 验证，应发送给大模型 |
| 条件保留 | 仅在非空、可解析或对当前 Candidate 有实际作用时发送 |
| 移出 Prompt | 运行时、调度、去重、审计需要，但大模型不需要 |
| 删除或合并 | 与其他字段重复，或者当前没有可靠语义 |

## 第一章 `source_rule`

本次运行中共有 669 个 `source_rule` Ticket。它们由源码正则或启发式规则直接匹配某一行代码产生，是五类结构中最简单的一类。

### 1.1 `deep_worker` 原始字段

原始 `Structured evidence`：

```json
{
  "function": "_peer_publish_shared_session",
  "line": 1829,
  "matched_text": "return -1;",
  "candidate_record": {
    "defect_class": "ownership_contract",
    "canonical_source": "_peer_publish_shared_session:1829:return -1;",
    "canonical_sink": "_peer_publish_shared_session:1829:return -1;",
    "root_cause_key": "ownership_contract|unknown|..."
  }
}
```

字段含义：

| 字段 | 含义 |
|---|---|
| `function` | 命中规则的函数 |
| `line` | 命中规则的源码行 |
| `matched_text` | 该行的规范化源码文本 |
| `candidate_record.defect_class` | Candidate 的统一缺陷分类 |
| `canonical_source` | 去重使用的规范化 source |
| `canonical_sink` | 去重使用的规范化 sink |
| `root_cause_key` | CandidateLedger 使用的根因去重键 |

#### 1.1.1 Deep Worker 字段的重复和必要性分析

| 原始字段 | 必要性 | 分析 |
|---|---|---|
| `function` | 必须 | 大模型需要定位目标函数。可以与外层 `Call paths[0][0]` 合并为一个 `entry_function` 或 `location.function`。 |
| `line` | 必须 | 是最低成本、最可靠的源码定位信息，但与外层 Trigger 的 `at line` 重复。 |
| `matched_text` | 必须 | 它是启发式规则的直接命中事实。若 Focused Code Context 一定包含该行，可只保留一次。 |
| `candidate_record.defect_class` | 必须但应上移 | 大模型需要知道要验证的缺陷类型，但应规范化到 `hypothesis.defect_class`。 |
| `canonical_source` | 移出 Prompt | 通常与外层 `Origin` 完全相同，只用于去重。 |
| `canonical_sink` | 移出 Prompt | 通常与外层 `Sink` 完全相同，只用于去重。 |
| `root_cause_key` | 移出 Prompt | 只用于 CandidateLedger 去重，不参与漏洞推理。 |
| 外层 `Origin` / `Sink` | 删除或合并 | 对 source-rule Candidate，二者通常等于同一个匹配语句，没有必要重复三次。 |
| 外层 `Sources` | 移出 Prompt | 表示候选来源，不是程序数据流 source。 |
| 外层 `Call paths` | 删除或合并 | 通常只有当前函数一个节点，不构成真实调用路径。 |
| 外层 `Task` | 删除或合并 | 与 Skill Contract 的验证要求重复。 |
| Execution/Isolation/Spawn 字段 | 移出 Prompt | 应由运行时策略执行，不需要模型阅读。 |

对于 `source_rule`，模型真正需要的信息只有：缺陷假设、命中函数、命中行、命中语句和局部代码上下文。该类 Candidate 尚未提供 source-to-sink、调用路径或守卫证明，不应通过字段名称制造“路径已经存在”的印象。

固定值备注：`source_rule` 的原始 `Structured evidence` 没有一个跨 Ticket 保持相同的业务字段值；`function`、`line`、`matched_text` 和 `defect_class` 都会变化。但当前生成方式存在以下固定关系或固定形状：

| 字段 | 固定值或固定关系 | 备注 |
|---|---|---|
| 外层 `Sources` | 固定为单个 `source_rule:<function>` 来源标签 | `source_rule:` 前缀固定，函数名变化；它是生成来源，不是数据流 source。 |
| 外层 `Origin` / `Sink` | 两者固定取同一个规则命中位置 | 值本身随 Ticket 变化。这是单点 Candidate 的构造约定，不是 source-to-sink 证明。 |
| `canonical_source` / `canonical_sink` | 两者固定相等 | 只用于规范化和去重；当前可读取的 `source_rule` 会话中未发现例外。 |
| 外层 `Call paths` | 固定为只包含当前函数的单节点数组 | 形如 `[["<function>"]]`；不是经过调用图验证的跨函数路径。 |

上述项目属于“固定关系/固定结构”，不是所有 Ticket 都具有相同的字符串或行号。它们没有区分 Candidate 的能力，可以由 `candidate_kind=source_rule` 和命中位置推导，不必重复发送给大模型。

### 1.2 `vulnerability_analyzer` 原始字段及与 `deep_worker` 的差异

`vulnerability_analyzer` 不使用 Deep Worker 的文本形式 `Structured evidence:`。它将同一个 Ticket 放入 `Focused subagent candidates discovered before budget selection` 列表，并在 CandidateLedger 外层增加状态、去重和调度字段。`source_rule` 的典型原始输入结构为：

```json
{
  "candidate_id": "CAND_57932eac4be9",
  "status": "planned",
  "defect_class": "null_and_failure",
  "dedup_key": "...",
  "root_cause_key": "...",
  "sources": [
    "source_rule:_runtime_read_control_magic"
  ],
  "call_paths": [
    [
      "_runtime_read_control_magic"
    ]
  ],
  "duplicate_count": 0,
  "canonical_source": "_runtime_read_control_magic:1376:if (!blob || len < 16)",
  "canonical_sink": "_runtime_read_control_magic:1376:if (!blob || len < 16)",
  "worker_report_id": null,
  "ticket": {
    "id": "CAND_57932eac4be9",
    "skill": "null_and_failure",
    "line": 1376,
    "priority_score": 28,
    "trigger": "if (!blob || len < 16)",
    "origin": "_runtime_read_control_magic:1376:if (!blob || len < 16)",
    "sink": "_runtime_read_control_magic:1376:if (!blob || len < 16)",
    "dedup_key": "...",
    "sources": [
      "source_rule:_runtime_read_control_magic"
    ],
    "call_paths": [
      [
        "_runtime_read_control_magic"
      ]
    ],
    "task": "Audit failure/null handling at this branch or return...",
    "priority_reasons": [
      "near_early_return",
      "copy_or_input_context"
    ],
    "resource_kind": "unknown",
    "source": "source_rule",
    "evidence": {
      "function": "_runtime_read_control_magic",
      "line": 1376,
      "matched_text": "if (!blob || len < 16) {",
      "candidate_record": {
        "defect_class": "null_and_failure",
        "root_cause_key": "... [truncated_chars=...]",
        "canonical_source": "_runtime_read_control_magic:1376:if (!blob || len < 16)",
        "canonical_sink": "_runtime_read_control_magic:1376:if (!blob || len < 16)",
        "__compacted__": true
      },
      "__compacted__": true
    }
  }
}
```

以下差异均以 Deep Worker 的 `Structured evidence` 对象为比较基准。Analyzer 的 `ticket` 中部分字段也出现在 Deep Worker Prompt 外层，但它们不属于 `Structured evidence`，因此仍记为 Analyzer 新增字段。

| 字段 | 与 `deep_worker` 的差异 | 含义 |
|---|---|---|
| `candidate_id` | Analyzer 新增字段 | CandidateLedger 中 Ticket 的规范化 ID。 |
| `status` | Analyzer 新增字段 | Candidate 当前状态，例如 `planned`、`unassigned`、`completed`。 |
| `defect_class` | Analyzer 新增字段 | CandidateLedger 上移的缺陷分类。 |
| `dedup_key` | Analyzer 新增字段 | Candidate 合并使用的去重键。 |
| `root_cause_key` | Analyzer 新增字段 | 根因级去重键。 |
| `sources` | Analyzer 新增字段 | Candidate 来源标签列表。 |
| `call_paths` | Analyzer 新增字段 | CandidateLedger 保存的调用路径摘要。 |
| `duplicate_count` | Analyzer 新增字段 | 被合并到该 Candidate 的重复项数量。 |
| `canonical_source` | Analyzer 新增字段 | CandidateLedger 外层的规范化 source。 |
| `canonical_sink` | Analyzer 新增字段 | CandidateLedger 外层的规范化 sink。 |
| `worker_report_id` | Analyzer 新增字段 | 关联的 Deep Worker report ID；未执行时为 `null`。 |
| `ticket` | Analyzer 新增字段 | 将原 Ticket 嵌套到 CandidateLedger entry 中的包装对象。 |
| `ticket.id` | Analyzer 新增字段 | 原 Ticket ID。 |
| `ticket.skill` | Analyzer 新增字段 | 为该 Ticket 选择的验证 Skill。 |
| `ticket.line` | Analyzer 新增字段 | Ticket 触发行。 |
| `ticket.priority_score` | Analyzer 新增字段 | Ticket 的预算选择和调度分数。 |
| `ticket.trigger` | Analyzer 新增字段 | 触发规则或命中表达式。 |
| `ticket.origin` | Analyzer 新增字段 | Ticket 外层的 origin 字符串。 |
| `ticket.sink` | Analyzer 新增字段 | Ticket 外层的 sink 字符串。 |
| `ticket.dedup_key` | Analyzer 新增字段 | Ticket 内重复保存的去重键。 |
| `ticket.sources` | Analyzer 新增字段 | Ticket 内的来源标签列表。 |
| `ticket.call_paths` | Analyzer 新增字段 | Ticket 内的调用路径摘要，不是 evidence path。 |
| `ticket.task` | Analyzer 新增字段 | 分配给 Worker 的验证任务说明。 |
| `ticket.priority_reasons` | Analyzer 新增字段 | 形成优先级分数的原因列表。 |
| `ticket.resource_kind` | Analyzer 新增字段 | Candidate 涉及的资源类型。 |
| `ticket.source` | Analyzer 新增字段 | Candidate 生成器类型 `source_rule`。 |
| `ticket.evidence` | 字段名和位置不同 | 对应 Deep Worker 的 `Structured evidence`；Analyzer 将其放在 `entry.ticket` 下。 |
| `ticket.evidence.function` | 字段名相同、位置不同 | 对应 `Structured evidence.function`，表示规则命中函数。 |
| `ticket.evidence.line` | 字段名相同、位置不同 | 对应 `Structured evidence.line`，表示规则命中行。 |
| `ticket.evidence.matched_text` | 字段名相同、位置不同 | 对应 `Structured evidence.matched_text`，表示命中的源码文本。 |
| `ticket.evidence.candidate_record` | 字段名相同、位置不同 | 对应 `Structured evidence.candidate_record`，保存统一分类和去重信息。 |
| `ticket.evidence.candidate_record.defect_class` | 字段名相同、位置不同 | Candidate 的统一缺陷分类。 |
| `ticket.evidence.candidate_record.root_cause_key` | 位置不同且内容可能减少 | 对应完整 `root_cause_key`；Analyzer 可能截断长字符串。 |
| `ticket.evidence.candidate_record.canonical_source` | 字段名相同、位置不同 | evidence 内的规范化 source。 |
| `ticket.evidence.candidate_record.canonical_sink` | 字段名相同、位置不同 | evidence 内的规范化 sink。 |
| `ticket.evidence.candidate_record.__compacted__` | Analyzer 新增字段 | 表示该嵌套对象经过 Prompt 压缩。 |
| `ticket.evidence.__compacted__` | Analyzer 新增字段 | 表示整个 evidence 对象经过 Prompt 压缩。 |

因此，`source_rule` 除 `Structured evidence` 改名并移动为 `entry.ticket.evidence` 外，Analyzer JSON 的其余 wrapper、ledger、调度和压缩字段均为新增字段；原 evidence 业务字段没有删除。

### 1.3 `deep_worker` 新字段

推荐模型输入：

```json
{
  "candidate_kind": "source_rule",
  "function": {
    "function_name": "_peer_publish_shared_session",
    "file_path": "src/lifecycle.c",
    "start_line": 1822,
    "end_line": 1847,
  },
  "suspicious_point": {
    "defect_class": "ownership_contract",
    "matched_text": "return -1",
    "line": 1829
  },
}
```

新增或改名字段说明：

| 推荐字段 | 来源或取值方法 | 含义 |
|---|---|---|
| `candidate_kind` | 固定为 Candidate 生成器类型 `source_rule`；对应原 Ticket 的来源类型，不是程序的数据流 source。 | 标识推荐结构的证据家族，供解析和路由使用。 |
| `function.function_name` | 由原 `function` 直接归一化。 | 规则命中点所在的函数名。 |
| `function.file_path` | 由源码索引按 `function_name` 解析；存在同名函数时必须结合当前编译单元消歧，无法唯一确定时不应猜测。 | 函数定义所在文件。 |
| `function.start_line` / `function.end_line` | 由源码索引中的函数定义范围取得；索引失败时省略或设为 `null`。 | 函数定义的起止行，只表示代码范围。 |
| `suspicious_point` | 由原 `line`、`matched_text` 和 `candidate_record.defect_class` 重组；它不是新增的分析结果。 | 集中表示规则命中的待验证位置和假设。 |
| `suspicious_point.defect_class` | 由原 `candidate_record.defect_class` 迁入。 | 需要验证的统一缺陷类别。 |
| `suspicious_point.matched_text` | 由原 `matched_text` 迁入，不把匹配文本重新解释为规则名称。 | 保存规则直接命中的源码文本。 |
| `suspicious_point.line` | 由原顶层 `line` 迁入。 | 规则命中的源码行。 |

`function.file_path/start_line/end_line` 是推荐补充的定位信息，当前原始 `source_rule` evidence 并未直接提供；只有索引查询成功时才能填写。

### 1.4 `vulnerability_analyzer` 新字段

```json
{
  "candidate_id": "CAND_57932eac4be9",
  "candidate_kind": "source_rule",
  "function": {
    "function_name": "_peer_publish_shared_session",
    "file_path": "src/lifecycle.c",
    "start_line": 1822,
    "end_line": 1847,
  },
  "suspicious_point": {
    "defect_class": "ownership_contract",
    "matched_text": "return -1",
    "line": 1829
  },
  "priority_score": 28,
  "priority_reasons": [
      "near_early_return",
      "copy_or_input_context"
    ],
}
```
相比`deep_worker`，增加`candidate_id`，`priority_score`和`priority_reasons`。

## 第二章 `semantic_snapshot`

本次运行中共有 235 个 `semantic_snapshot` Ticket。它们来自函数语义快照中的 `suspicious_points`，主要提供模型生成的函数摘要和可疑点描述。

### 2.1 `deep_worker` 原始字段

原始 `Structured evidence`：

```json
{
  "function": "_runtime_read_control_magic@src/lifecycle.c:1375-1385",
  "location": "_runtime_read_control_magic@src/lifecycle.c:1375-1385:1",
  "snapshot_summary": "该函数读取控制数据并复制预览内容。",
  "suspicious_point": {
    "category": "bounds",
    "lines": "1383",
    "description": "count 未经上限验证即作为 memcpy 长度。"
  },
  "candidate_record": {
    "defect_class": "bounds_and_integer",
    "canonical_source": "...:snapshot_suspicious_point",
    "canonical_sink": "...:snapshot_suspicious_point",
    "root_cause_key": "..."
  }
}
```

Focused Code Context 当前还会重复包含：

```text
Function: <function>
Snapshot summary: <snapshot_summary>
Suspicious point: <suspicious_point>
Key semantics: <semantic fingerprint>
```

字段含义：

| 字段 | 含义 |
|---|---|
| `function` | 产生语义快照的函数 identity |
| `location` | 快照可疑点的逻辑位置；不一定是精确源码行 |
| `snapshot_summary` | 模型生成的函数整体语义摘要 |
| `suspicious_point.category` | 可疑点类别 |
| `suspicious_point.lines` | 可疑点关联源码行 |
| `suspicious_point.description` | 可疑行为的自然语言描述 |
| `candidate_record` | 去重和统一分类记录 |

#### 2.1.1 Deep Worker 字段的重复和必要性分析

| 原始字段 | 必要性 | 分析 |
|---|---|---|
| `function` | 必须 | 需要转换为规范化的 `location.function/file/range`，避免模型解析 `@file:start-end` 字符串。 |
| `location` | 条件保留 | 若只是 `snapshot point 1` 之类逻辑位置，应拆出真实源码行；无法映射时才保留逻辑 ID。 |
| `snapshot_summary` | 条件保留 | 可帮助理解函数，但不能作为源码事实。当前它在 evidence 和 Focused Code Context 中重复。 |
| `suspicious_point.category` | 必须但应合并 | 与 `candidate_record.defect_class`、Skill 存在重叠，应归一化到 `hypothesis`。 |
| `suspicious_point.lines` | 必须 | 是可疑点与源码的主要连接。应标准化为数字数组。 |
| `suspicious_point.description` | 必须 | 是该类 Candidate 的核心假设，但应标记为待验证描述，而不是事实。 |
| `candidate_record` | 移出 Prompt | 除 `defect_class` 外均为去重元数据；`defect_class` 应上移。 |
| 外层 Trigger | 删除或合并 | 固定为 `snapshot_suspicious_point` 时信息量很低。 |
| 外层 Origin / Sink | 删除或合并 | 通常都是合成的 snapshot point 标识，并非具体 source/sink。 |
| Focused Code Context 中的 summary/point | 删除重复 | evidence 和 context 只能保留一份。 |

语义快照由模型生成，因此 `snapshot_summary` 和 `suspicious_point.description` 只能作为待验证线索。真正用于确认漏洞的证据仍应来自源码、类型、调用者、callee 和具体守卫。

固定值备注：`semantic_snapshot` 的函数、摘要、可疑点类别、行号和描述都会变化，但当前生成方式存在以下固定值或固定关系：

| 字段 | 固定值或固定关系 | 备注 |
|---|---|---|
| 外层 `Trigger` | `snapshot_suspicious_point` | 当前 235 个 Ticket 全部相同，只表示 Candidate 来自 snapshot 可疑点，不能区分具体问题。 |
| 外层 `Sources` | 固定为单个 `semantic_snapshot:<function>` 来源标签 | `semantic_snapshot:` 前缀固定，函数 identity 变化。 |
| 外层 `Origin` / `Sink` | 两者固定取同一个合成 snapshot point | 值本身随函数和 point 序号变化；它们不是真实数据流端点。 |
| `candidate_record.canonical_source` / `canonical_sink` | 两者固定相等 | 当前 235 个 Ticket 均如此，只服务于单点 Candidate 去重。 |
| 外层 `Call paths` | 固定为只包含 snapshot 函数的单节点数组 | 不表示已经完成调用链分析。 |

这些固定字段可以由 `candidate_kind=semantic_snapshot` 和结构化函数定位推导。尤其是固定 Trigger、重复的 Origin/Sink 和单节点 Call paths，不应占用 Deep Worker Prompt。

### 2.2 `vulnerability_analyzer` 原始字段及与 `deep_worker` 的差异

`semantic_snapshot` 在 Analyzer 中同样位于 CandidateLedger entry 的 `ticket.evidence`。典型原始结构为：

```json
{
  "candidate_id": "CAND_1af794db95cc",
  "status": "planned",
  "defect_class": "concurrency_lock_order",
  "dedup_key": "...",
  "root_cause_key": "...",
  "sources": [
    "semantic_snapshot:_runtime_cancel_wheel_timer@src/lifecycle.c:2750-2760"
  ],
  "call_paths": [
    [
      "_runtime_cancel_wheel_timer@src/lifecycle.c:2750-2760"
    ]
  ],
  "duplicate_count": 0,
  "canonical_source": "...:snapshot_suspicious_point",
  "canonical_sink": "...:snapshot_suspicious_point",
  "worker_report_id": null,
  "ticket": {
    "id": "CAND_1af794db95cc",
    "skill": "concurrency_lock_order",
    "line": 1,
    "priority_score": 18,
    "trigger": "snapshot_suspicious_point",
    "origin": "...:snapshot_suspicious_point",
    "sink": "...:snapshot_suspicious_point",
    "sources": [
      "semantic_snapshot:_runtime_cancel_wheel_timer@src/lifecycle.c:2750-2760"
    ],
    "call_paths": [
      [
        "_runtime_cancel_wheel_timer@src/lifecycle.c:2750-2760"
      ]
    ],
    "task": "Verify this suspicious point from the semantic snapshot...",
    "priority_reasons": [
      "semantic_snapshot_suspicious_point"
    ],
    "resource_kind": "lock",
    "source": "semantic_snapshot",
    "evidence": {
      "function": "_runtime_cancel_wheel_timer@src/lifecycle.c:2750-2760",
      "location": "_runtime_cancel_wheel_timer@src/lifecycle.c:2750-2760:1",
      "snapshot_summary": "取消运行时轮询定时器，根据调用上下文采取不同的同步策略...",
      "suspicious_point": {
        "category": "concurrency",
        "lines": "2752-2756",
        "description": "当 call_from_callback 为真时...",
        "__compacted__": true
      },
      "candidate_record": {
        "defect_class": "concurrency_lock_order",
        "root_cause_key": "... [truncated_chars=...]",
        "canonical_source": "...:snapshot_suspicious_point",
        "canonical_sink": "...:snapshot_suspicious_point",
        "__compacted__": true
      },
      "__compacted__": true
    }
  }
}
```

与 Deep Worker 的差异：

| 字段 | 与 `deep_worker` 的差异 | 含义 |
|---|---|---|
| `candidate_id` | Analyzer 新增字段 | CandidateLedger 中 Ticket 的规范化 ID。 |
| `status` | Analyzer 新增字段 | Candidate 当前状态。 |
| `defect_class` | Analyzer 新增字段 | CandidateLedger 上移的缺陷分类。 |
| `dedup_key` | Analyzer 新增字段 | Candidate 去重键。 |
| `root_cause_key` | Analyzer 新增字段 | 根因去重键。 |
| `sources` | Analyzer 新增字段 | Candidate 来源标签列表。 |
| `call_paths` | Analyzer 新增字段 | CandidateLedger 调用路径摘要。 |
| `duplicate_count` | Analyzer 新增字段 | 合并的重复 Candidate 数量。 |
| `canonical_source` | Analyzer 新增字段 | CandidateLedger 外层的规范化 source。 |
| `canonical_sink` | Analyzer 新增字段 | CandidateLedger 外层的规范化 sink。 |
| `worker_report_id` | Analyzer 新增字段 | 关联的 Worker report ID。 |
| `ticket` | Analyzer 新增字段 | 原 Ticket 的包装对象。 |
| `ticket.id` | Analyzer 新增字段 | 原 Ticket ID。 |
| `ticket.skill` | Analyzer 新增字段 | 为该 snapshot point 选择的 Skill。 |
| `ticket.line` | Analyzer 新增字段 | snapshot point 的逻辑序号或行值。 |
| `ticket.priority_score` | Analyzer 新增字段 | Ticket 调度分数。 |
| `ticket.trigger` | Analyzer 新增字段 | 固定触发器 `snapshot_suspicious_point`。 |
| `ticket.origin` | Analyzer 新增字段 | 合成 snapshot origin。 |
| `ticket.sink` | Analyzer 新增字段 | 合成 snapshot sink。 |
| `ticket.sources` | Analyzer 新增字段 | Ticket 来源标签。 |
| `ticket.call_paths` | Analyzer 新增字段 | 单节点 snapshot 函数路径摘要。 |
| `ticket.task` | Analyzer 新增字段 | snapshot 可疑点验证任务。 |
| `ticket.priority_reasons` | Analyzer 新增字段 | 优先级原因列表。 |
| `ticket.resource_kind` | Analyzer 新增字段 | Candidate 资源类型。 |
| `ticket.source` | Analyzer 新增字段 | Candidate 生成器类型 `semantic_snapshot`。 |
| `ticket.evidence` | 字段名和位置不同 | 对应 Deep Worker 的 `Structured evidence`。 |
| `ticket.evidence.function` | 字段名相同、位置不同 | snapshot 所属函数 identity。 |
| `ticket.evidence.location` | 字段名相同、位置不同 | snapshot point 的逻辑位置。 |
| `ticket.evidence.snapshot_summary` | 位置不同且内容可能减少 | 函数摘要；超过限制时被截断。 |
| `ticket.evidence.suspicious_point` | 字段名相同、位置不同 | 可疑点对象。 |
| `ticket.evidence.suspicious_point.category` | 字段名相同、位置不同 | 可疑点类别。 |
| `ticket.evidence.suspicious_point.lines` | 字段名相同、位置不同 | 可疑点关联源码行。 |
| `ticket.evidence.suspicious_point.description` | 位置不同且内容可能减少 | 可疑点描述；过长时被截断。 |
| `ticket.evidence.suspicious_point.__compacted__` | Analyzer 新增字段 | 表示 suspicious point 对象经过压缩。 |
| `ticket.evidence.candidate_record` | 字段名相同、位置不同 | snapshot Candidate 的分类和去重记录。 |
| `ticket.evidence.candidate_record.defect_class` | 字段名相同、位置不同 | 统一缺陷分类。 |
| `ticket.evidence.candidate_record.root_cause_key` | 位置不同且内容可能减少 | 根因去重键；可能被截断。 |
| `ticket.evidence.candidate_record.canonical_source` | 字段名相同、位置不同 | 规范化 snapshot source。 |
| `ticket.evidence.candidate_record.canonical_sink` | 字段名相同、位置不同 | 规范化 snapshot sink。 |
| `ticket.evidence.candidate_record.__compacted__` | Analyzer 新增字段 | 表示 candidate record 经过压缩。 |
| `ticket.evidence.__compacted__` | Analyzer 新增字段 | 表示整个 evidence 经过压缩。 |

因此 `semantic_snapshot` 与 `source_rule` 类似：原 evidence 字段全部保留；差异主要是 `evidence` 的名称和位置、Analyzer 新增的 ledger/ticket 字段，以及字符串内容压缩。

### 2.3 `deep_worker` 新字段

```json
{
  "candidate_kind": "semantic_snapshot",
  "function":{
    "function_name": "_runtime_read_control_magic",
    "file_path": "src/lifecycle.c",
    "start_line": 1375,
    "end_line": 1385,
  },
  // "snapshot_summary": "该函数读取控制数据并复制预览内容。",
  "suspicious_point": {
    "category": "bounds",
    "lines": "1383",
    "description": "count 未经上限验证即作为 memcpy 长度。"
  },
}
```

新增或改名字段说明：

| 推荐字段 | 来源或取值方法 | 含义 |
|---|---|---|
| `candidate_kind` | 固定为 Candidate 生成器类型 `semantic_snapshot`。 | 标识推荐结构的证据家族。 |
| `function` | 将原字符串形式的 function identity 拆为结构化对象。 | 避免由大模型解析 `name@file:start-end`。 |
| `function.function_name` | 从原 `function` identity 中解析函数名。例如原值 `_runtime_read_control_magic@src/lifecycle.c:1375-1385` 应解析为 `_runtime_read_control_magic`。 | 供模型和工具直接使用的函数名。 |
| `function.file_path` | 从原 `function` identity 的 `@file` 部分解析，或由源码索引补全。 | 函数定义文件。 |
| `function.start_line` / `function.end_line` | 从原 `function` identity 的 `:start-end` 部分解析，解析失败时再查询源码索引。 | 函数定义范围，不是 suspicious point 的行号。 |

这些字段只是把原先编码在字符串中的 function identity 拆成可直接消费的结构化定位，不增加新的漏洞结论。

### 2.4 `vulnerability_analyzer` 新字段

```json
{
  "candidate_id": "CAND_1af794db95cc",
  "candidate_kind": "semantic_snapshot",
  "function":{
    "function_name": "_runtime_read_control_magic",
    "file_path": "src/lifecycle.c",
    "start_line": 1375,
    "end_line": 1385,
  },
  // "snapshot_summary": "该函数读取控制数据并复制预览内容。",
  "suspicious_point": {
    "category": "bounds",
    "lines": "1383",
    "description": "count 未经上限验证即作为 memcpy 长度。"
  },
  "priority_score": 18,
  "priority_reasons": [
      "semantic_snapshot_suspicious_point"
    ],
}
```
相比`deep_worker`，增加`candidate_id`，`priority_score`和`priority_reasons`。

## 第三章 `graph_rule`

本次运行中共有 104 个 `graph_rule` Ticket。它们来自调用图、资源协议、共享状态或生命周期配对规则，具有统一的 `candidate_evidence_v1` 外形。

### 3.1 `deep_worker` 原始字段

原始顶层字段：

```json
{
  "candidate_id": "GRAPH_...",
  "candidate_source": "graph_rule",
  "defect_class": "reader_state_race",
  "rule": "single_reader_field_under_shared_reader_count",
  "rule_confidence": 0.84,
  "source": {
    "expression": "shared reader field",
    "file": "src/lifecycle.c",
    "line": 2329
  },
  "sink": {
    "operation": "g_runtime_rwlock.reader_pid = reader_pid;",
    "file": "src/lifecycle.c",
    "line": 2329
  },
  "path": {
    "function": "_runtime_read_lock_owner",
    "complete_in_function": false
  },
  "object": {
    "id": "shared reader field",
    "aliases": []
  },
  "positive_evidence": [],
  "negative_evidence": [],
  "evidence_refs": [],
  "schema": "candidate_evidence_v1",
  "backend_profile": "unified",
  "checker": "unified_callgraph_svf_protocol_checker",
  "evidence_engines": [],
  "semantic_overlays": {},
  "semantic_overlay_evidence": {},
  "path_kind": "cross_function_protocol",
  "candidate_is_conclusion": false,
  "validation_required": true,
  "validation_notes": [],
  "candidate_record": {
    "defect_class": "reader_state_race",
    "canonical_source": "shared reader field",
    "canonical_sink": "g_runtime_rwlock.reader_pid = reader_pid;",
    "root_cause_key": "..."
  }
}
```

`semantic_overlays` 还可能包含整个运行加载的资源、锁、宏和函数语义模型名称列表；`semantic_overlay_evidence` 则用于保存当前 Candidate 实际命中的语义模型。

#### 3.1.1 Deep Worker 字段的重复和必要性分析

| 原始字段 | 必要性 | 分析 |
|---|---|---|
| `candidate_id` | 移出 Prompt | 用于追踪原始检查器结果，不参与验证。 |
| `candidate_source` | 移出 Prompt | 模型不需要知道是哪种检查器发现的，避免权威偏见。 |
| `defect_class` | 必须 | 应统一放入 `hypothesis.defect_class`。 |
| `rule` | 必须 | 是 Candidate 假设的精确名称。 |
| `rule_confidence` | 移出 Prompt | 用于优先级计算；发送给 Worker 会产生确认偏差。 |
| `source` | 必须 | 保留具体表达式和源码位置。 |
| `sink` | 必须 | 保留具体操作和源码位置。 |
| `path.function` | 必须 | 指明 source/sink 所在函数。 |
| `complete_in_function` | 条件保留 | 有助于决定是否需要查询 caller/callee，但应改名以避免被理解为路径已证明。 |
| `object` | 必须或条件保留 | race、ownership、lock、resource Candidate 需要；无明确对象时不发送空对象。 |
| `positive_evidence` | 必须 | 只保留具体源码事实，不保留结论性语句。 |
| `negative_evidence` | 必须 | 守卫和反证对拒绝 Candidate 至关重要。 |
| `evidence_refs` | 条件保留 | 仅当 Worker 有工具可以解析引用时保留；空数组删除。 |
| `schema` | 移出 Prompt | 序列化版本只用于程序解析。 |
| `backend_profile` / `checker` / `evidence_engines` | 移出 Prompt | 都是追踪元数据。 |
| `semantic_overlays` | 移出 Prompt | 是全局配置清单，重复且不针对当前 Candidate。 |
| `semantic_overlay_evidence` | 条件保留 | 只保留当前 Candidate 实际命中的非空语义。 |
| `path_kind` | 条件保留 | 可压缩成 `scope: cross_function`。 |
| `candidate_is_conclusion` | 删除 | system prompt 已声明 Candidate 不是结论。 |
| `validation_required` / `validation_notes` | 删除 | 与 Deep Worker 和 Validator 合约重复。 |
| `candidate_record` | 移出 Prompt | `defect_class/source/sink` 重复，`root_cause_key` 只用于去重。 |
| 外层 Origin / Sink | 删除 | 与结构化 `source/sink` 完全重复。 |
| 外层 Sources | 移出 Prompt | 只保留在审计元数据。 |

该类结构最有价值的部分是具体 source、sink、共享对象、局部路径完整性状态以及正反证据。后端名称、模型清单和调度置信度不应干扰 Worker 的独立验证。

固定值备注：以下字段在当前可读取的 `graph_rule` Ticket 中保持固定。备注区分了生成器/统一注解器常量和本次运行配置常量。

| 字段 | 固定值 | 备注 |
|---|---|---|
| `candidate_source` | `graph_rule` | 由 Candidate 家族决定，可由结构类型推导。 |
| `checker` | `unified_callgraph_svf_protocol_checker` | 当前 graph-rule 路由固定的 checker 标识，只用于追踪。 |
| `schema` | `candidate_evidence_v1` | 统一 evidence 注解器写入的序列化版本。 |
| `backend_profile` | `unified` | 本次运行配置固定，并非 Candidate 事实；其他运行可取不同 profile。 |
| `path_kind` | `cross_function_protocol` | 当前 graph-rule 路由统一传入的宽泛类别，不能区分具体调用链或协议类型。 |
| `candidate_is_conclusion` | `false` | 统一 evidence 注解器硬编码，system prompt 已表达相同约束。 |
| `validation_required` | `true` | 统一 evidence 注解器默认写入，且进入 Deep Worker 的 Ticket 已经过该条件过滤。 |
| `evidence_refs` | `[]` | 当前 Ticket 全为空，没有可供 Worker 解析的引用。 |
| `evidence_engines` | 固定为统一 profile 的四个 engine 名称 | 属于运行能力清单，不是当前 Candidate 实际使用了四种证据的证明。 |
| `semantic_overlays` | 固定为本次运行加载的全局模型摘要 | 其中资源模型数、锁模型数及名称列表在 Ticket 间重复；应保留在运行元数据。 |
| `object.aliases` | `[]` | 当前可读取 Ticket 均为空；这是当前样本固定，不是 graph-rule schema 保证。 |

固定的 `path_kind`、checker、engine 清单和 overlay 摘要没有 Ticket 级区分能力。`candidate_source/schema/validation` 等字段可以留在审计记录中，但没有必要发送给大模型。

### 3.2 `vulnerability_analyzer` 原始字段及与 `deep_worker` 的差异

Analyzer 对 `graph_rule` evidence 使用重对象压缩规则。由于 `evidence` 最多保留 8 个顶层键，典型原始结构为：

```json
{
  "candidate_id": "CAND_37ebfdfbd9bf",
  "status": "planned",
  "defect_class": "stack_overflow",
  "dedup_key": "...",
  "root_cause_key": "...",
  "sources": [
    "graph_rule:td_runtime_refresh_cache"
  ],
  "call_paths": [
    [
      "td_runtime_refresh_cache"
    ]
  ],
  "duplicate_count": 0,
  "canonical_source": "composed string",
  "canonical_sink": "memcpy(aux.name, composed, strlen(composed) + 1);",
  "worker_report_id": null,
  "ticket": {
    "id": "CAND_37ebfdfbd9bf",
    "skill": "bounds_and_integer",
    "line": 2377,
    "priority_score": 77,
    "trigger": "composed_string_copied_to_member_buffer_without_bound",
    "origin": "composed string",
    "sink": "memcpy(aux.name, composed, strlen(composed) + 1);",
    "dedup_key": "stack_overflow|memory|composed string|composed string|memcpy(aux.name, composed, strlen(composed) + 1);",
    "sources": [
      "graph_rule:td_runtime_refresh_cache"
    ],
    "call_paths": [
      [
        "td_runtime_refresh_cache"
      ]
    ],
    "task": "Verify regex/local-pattern stack_overflow candidate. Confirm concrete source, sink, path feasibility, and guard sufficiency; reject if any required proof is missing.",
    "priority_reasons": [
      "graph_rule",
      "stack_overflow",
      "rule_confidence=0.82"
    ],
    "resource_kind": "memory",
    "source": "graph_rule",
    "evidence": {
      "candidate_id": "GRAPH_STACK_OVERFLOW_d0c98324e6",
      "candidate_source": "graph_rule",
      "defect_class": "stack_overflow",
      "rule": "composed_string_copied_to_member_buffer_without_bound",
      "rule_confidence": 0.82,
      "source": {
        "expression": "composed string",
        "file": "src/lifecycle.c",
        "line": 2377,
        "__compacted__": true
      },
      "sink": {
        "operation": "memcpy(aux.name, composed, strlen(composed) + 1);",
        "file": "src/lifecycle.c",
        "line": 2377,
        "__compacted__": true
      },
      "path": {
        "function": "_runtime_prepare_worker_label",
        "complete_in_function": false,
        "__compacted__": true
      },
      "__omitted_keys__": {
        "count": 15,
        "keys": [
          "object",
          "positive_evidence",
          "negative_evidence",
          "evidence_refs",
          "schema",
          "backend_profile",
          "checker",
          "evidence_engines",
          "semantic_overlays",
          "semantic_overlay_evidence",
          "path_kind",
          "candidate_is_conclusion"
        ]
      },
      "__compacted__": true
    }
  }
}
```

与 Deep Worker 的差异：

| 字段 | 与 `deep_worker` 的差异 | 含义 |
|---|---|---|
| `candidate_id` | Analyzer 新增字段 | CandidateLedger 中 Ticket 的规范化 ID。 |
| `status` | Analyzer 新增字段 | Candidate 当前状态。 |
| `defect_class` | Analyzer 新增字段 | CandidateLedger 上移的缺陷分类。 |
| `dedup_key` | Analyzer 新增字段 | Candidate 去重键。 |
| `root_cause_key` | Analyzer 新增字段 | 根因去重键。 |
| `sources` | Analyzer 新增字段 | Candidate 来源标签列表。 |
| `call_paths` | Analyzer 新增字段 | CandidateLedger 调用路径摘要。 |
| `duplicate_count` | Analyzer 新增字段 | 合并的重复 Candidate 数量。 |
| `canonical_source` | 位置不同 | 对应 Deep Worker `candidate_record.canonical_source` 的 ledger 摘要副本。 |
| `canonical_sink` | 位置不同 | 对应 Deep Worker `candidate_record.canonical_sink` 的 ledger 摘要副本。 |
| `worker_report_id` | Analyzer 新增字段 | 关联的 Worker report ID。 |
| `ticket` | Analyzer 新增字段 | 原 Ticket 的包装对象。 |
| `ticket.id` | Analyzer 新增字段 | 原 Ticket ID。 |
| `ticket.skill` | Analyzer 新增字段 | 为 graph Candidate 选择的验证 Skill。 |
| `ticket.line` | Analyzer 新增字段 | Ticket 主定位行。 |
| `ticket.priority_score` | Analyzer 新增字段 | Ticket 调度分数。 |
| `ticket.trigger` | Analyzer 新增字段 | graph rule 名称。 |
| `ticket.origin` | Analyzer 新增字段 | Ticket 外层 origin。 |
| `ticket.sink` | Analyzer 新增字段 | Ticket 外层 sink。 |
| `ticket.dedup_key` | Analyzer 新增字段 | Ticket 内去重键。 |
| `ticket.sources` | Analyzer 新增字段 | Ticket 来源标签。 |
| `ticket.call_paths` | Analyzer 新增字段 | CandidateLedger 路径摘要，不是 evidence path。 |
| `ticket.task` | Analyzer 新增字段 | Candidate 验证任务。 |
| `ticket.priority_reasons` | Analyzer 新增字段 | 优先级原因列表。 |
| `ticket.resource_kind` | Analyzer 新增字段 | Candidate 涉及的资源类型。 |
| `ticket.source` | Analyzer 新增字段 | Candidate 生成器类型 `graph_rule`。 |
| `ticket.evidence` | 字段名和位置不同 | 对应 Deep Worker 的 `Structured evidence`。 |
| `ticket.evidence.candidate_id` | 字段名相同、位置不同 | graph 检查器内部 Candidate ID。 |
| `ticket.evidence.candidate_source` | 字段名相同、位置不同 | 固定为 `graph_rule`。 |
| `ticket.evidence.defect_class` | 字段名相同、位置不同 | graph Candidate 的缺陷类型。 |
| `ticket.evidence.rule` | 字段名相同、位置不同 | 产生 Candidate 的 graph rule。 |
| `ticket.evidence.rule_confidence` | 字段名相同、位置不同 | graph rule 的生成置信度。 |
| `ticket.evidence.source` | 字段名相同、位置不同 | graph Candidate 的 source 对象。 |
| `ticket.evidence.source.expression` | 字段名相同、位置不同 | source 表达式。 |
| `ticket.evidence.source.file` | 字段名相同、位置不同 | source 文件。 |
| `ticket.evidence.source.line` | 字段名相同、位置不同 | source 行号。 |
| `ticket.evidence.source.__compacted__` | Analyzer 新增字段 | source 对象已被 Prompt 压缩。 |
| `ticket.evidence.sink` | 字段名相同、位置不同 | graph Candidate 的 sink 对象。 |
| `ticket.evidence.sink.operation` | 字段名相同、位置不同 | sink 操作。 |
| `ticket.evidence.sink.file` | 字段名相同、位置不同 | sink 文件。 |
| `ticket.evidence.sink.line` | 字段名相同、位置不同 | sink 行号。 |
| `ticket.evidence.sink.__compacted__` | Analyzer 新增字段 | sink 对象已被 Prompt 压缩。 |
| `ticket.evidence.path` | 位置相同但内容减少 | Analyzer 仅保留未超过深度和键数限制的 path 字段。 |
| `ticket.evidence.path.function` | 字段名相同、位置不同 | 当前局部目标函数。 |
| `ticket.evidence.path.complete_in_function` | 字段名相同、位置不同 | 原局部完整性标志。 |
| `ticket.evidence.path.__compacted__` | Analyzer 新增字段 | path 对象已被 Prompt 压缩。 |
| `ticket.evidence.__omitted_keys__` | Analyzer 新增字段 | 记录被删除 evidence 顶层字段的数量和部分字段名。 |
| `ticket.evidence.__compacted__` | Analyzer 新增字段 | 整个 evidence 已被 Prompt 压缩。 |
| `ticket.evidence.object` | Analyzer 减少字段 | Deep Worker 中的共享对象和 alias 信息被删除。 |
| `ticket.evidence.positive_evidence` | Analyzer 减少字段 | Deep Worker 中的支持证据被删除。 |
| `ticket.evidence.negative_evidence` | Analyzer 减少字段 | Deep Worker 中的反证和待验证条件被删除。 |
| `ticket.evidence.evidence_refs` | Analyzer 减少字段 | Deep Worker 中的证据引用被删除。 |
| `ticket.evidence.schema` | Analyzer 减少字段 | evidence schema 版本被删除。 |
| `ticket.evidence.backend_profile` | Analyzer 减少字段 | 后端 profile 被删除。 |
| `ticket.evidence.checker` | Analyzer 减少字段 | graph checker 名称通常被 8 键限制删除。 |
| `ticket.evidence.evidence_engines` | Analyzer 减少字段 | engine 清单被删除。 |
| `ticket.evidence.semantic_overlays` | Analyzer 减少字段 | 全局 semantic overlay 摘要被删除。 |
| `ticket.evidence.semantic_overlay_evidence` | Analyzer 减少字段 | 当前 Candidate 命中的 overlay evidence 被删除。 |
| `ticket.evidence.path_kind` | Analyzer 减少字段 | graph path 的宽泛类型被删除。 |
| `ticket.evidence.candidate_is_conclusion` | Analyzer 减少字段 | Candidate 非结论标记被删除。 |
| `ticket.evidence.validation_required` | Analyzer 减少字段 | 验证要求标记被删除。 |
| `ticket.evidence.validation_notes` | Analyzer 减少字段 | 验证备注被删除。 |
| `ticket.evidence.candidate_record` | Analyzer 减少字段 | 完整去重记录被删除，仅 ledger 外层保留部分摘要。 |

Analyzer 中新增的 `ticket.call_paths` 是 CandidateLedger 路径摘要，不是从 Deep Worker `evidence.path` 改名得到的字段，也不能补回被删除的 caller/callee、回调或资源协议信息。

### 3.3 `deep_worker` 新字段

```json
{
  "candidate_kind": "graph_rule",
  "entry_function": {
    "function_name": "_runtime_accept_session_frame",
    "file_path": "src/lifecycle.c",
    "start_line": 2856,
    "end_line": 2884
  },
  "target_function": {
    "function_name": "_runtime_read_lock_owner",
    "file_path": "src/lifecycle.c",
    "start_line": 2323,
    "end_line": 2337,
  },
  "call_path":[
    "_runtime_accept_session_frame",
    "_runtime_read_lock_owner",
  ],
  "suspicious_point": {
    "defect_class": "reader_state_race",
    "rule": "single_reader_field_under_shared_reader_count",
    "line": 2329,
    "expression": "shared reader field",
    "operation": "g_runtime_rwlock.reader_pid = reader_pid;",
  },
  "relation_evidence":{
    "execution": {},
    "lifecycle_pair": {},
    "cascade_wait": {},
  },//仅在存在evidence时显示
  "positive_evidence": [
    "function increments/decrements a reader count atomically",
    "line 2329: reader identity state is assigned outside a lock"
  ],
  "negative_evidence": [],
  "semantic_evidence": {}
}
```
`relation_evidence` 仅在至少存在一种非空关系证据时出现，其中每个子字段也只在对应规则实际生成该类关系时出现。`semantic_evidence` 仅在非空时出现。

新增或改名字段说明：

| 推荐字段 | 来源或取值方法 | 含义 |
|---|---|---|
| `candidate_kind` | 固定为 Candidate 生成器类型 `graph_rule`；对应原 `candidate_source`，但不进入漏洞推理。 | 标识推荐结构的证据家族。 |
| `entry_function` | 由当前分析入口和源码索引组合。`function_name` 通常取外层 `Call paths` 的首节点；`file_path/start_line/end_line` 由源码索引补全。无法唯一定位时，相应定位字段应省略或置空，不能猜测。 | Deep Worker 开始验证该 Candidate 的入口函数及其源码范围。 |
| `target_function` | 由原 `path.function` 确定，再由源码索引补全文件和范围。 | 实际包含可疑操作、需要重点审计的目标函数。 |
| `entry_function.function_name` / `target_function.function_name` | 分别取入口和目标函数名；两者可以相同。 | 区分分析入口与可疑点所在函数。 |
| `file_path` / `start_line` / `end_line` | 由源码索引中的函数定义位置取得；行号表示整个函数范围，不是 suspicious point 行号。 | 使 Worker 无需解析复合 identity 即可定位函数代码。 |
| `call_path` | 由外层 `Call paths`、原图规则路径或 CodeIndex 调用图取得，按 entry 到 target 排列。相邻函数必须有调用图或 callsite 证据；entry 与 target 相同时可使用单节点数组。没有可靠链时应为空或省略。 | entry-to-target 的静态调用链，不代表运行时路径一定可行。 |
| `suspicious_point` | 由原 `defect_class`、`rule`、`source` 和 `sink` 重组。 | 集中保存本次需要验证的缺陷假设和具体代码操作。 |
| `suspicious_point.defect_class` / `rule` | 分别由原顶层同名字段迁入。 | Candidate 的统一缺陷类别和具体 graph rule。 |
| `suspicious_point.line` | 原 source/sink.line。 | 目标函数内的主要检查行。 |
| `suspicious_point.expression` | 由原 `source.expression` 迁入。| graph rule 关联的源表达式或前置状态。 |
| `suspicious_point.operation` | 由原 `sink.operation` 迁入。 | graph rule 要验证的目标操作。 |
| `relation_evidence` | 将 graph rule 通过 `_issue(..., evidence=...)` 提供、随后由 `pack.update(evidence)` 展开到顶层的专用关系重新收拢。当前来源仅包括原 `path`、`lifecycle_pair` 和 `cascade_wait`；默认的 `path: {function, complete_in_function: false}` 不视为专用关系证据。 | 保存规则提取出的事件顺序、函数角色、生命周期配对或锁等待关系。它们是待验证的支持关系，不表示路径可行、对象对应或缺陷已经得到证明。 |
| `relation_evidence.execution` | 由原专用 `path` 改名并归一化。按规则需要保存参与函数及其角色、`source_line`/`sink_line`、调用点、回调点、中间事件、`call_evidence` 和 `path_constraints` 等；只有原规则实际提供了专用 `path` 时才出现。 | 描述 Candidate 涉及的静态执行关系或事件顺序。它可能是单函数顺序、caller-callee 调用、回调返回后继续使用、分配到清理等关系，不应被解释为已经验证可行的动态执行路径。 |
| `relation_evidence.lifecycle_pair` | 由原同名字段迁入。当前生成器用于 `paired_global_registration_cleanup_omitted`，包含 `registration_function` 和 `cleanup_function`；未来扩展到其他生命周期规则时，应继续使用明确的角色名。 | 表示注册端与清理端被规则识别为一组候选生命周期关系；仅凭函数配对不能证明两端操作的是同一个对象，也不能证明清理路径一定可达。 |
| `relation_evidence.cascade_wait` | 由原同名字段迁入，仅用于规则构造出多参与方锁等待关系时。 | 描述 callback、资源持有方以及可选 scheduler 持有方之间的候选等待链；它不是已经闭合并可达的死锁环证明。 |
| `positive_evidence` / `negative_evidence` | 沿用原字段。 | 分别保存支持 Candidate 和削弱 Candidate 的事实。 |
| `semantic_evidence` | 由原 `semantic_overlay_evidence` 改名。 | 与当前 Candidate 直接相关的资源、锁、回调等补充语义。 |

当前 JSON 不再使用 `source.function`、`sink.function`、`path.scope`、`path.nodes`、`local_context_available` 或 `entry_chain_known`。入口、目标和静态链分别由 `entry_function`、`target_function` 和 `call_path` 表达；是否具备局部代码由对应函数对象的定位字段及随 Ticket 提供的 Focused Code Context 判断。

### 3.4 `vulnerability_analyzer` 新字段

```json
{
  "candidate_id": "CAND_37ebfdfbd9bf",
  "candidate_kind": "graph_rule",
  "entry_function": {
    "function_name": "_runtime_accept_session_frame",
    "file_path": "src/lifecycle.c",
    "start_line": 2856,
    "end_line": 2884
  },
  "target_function": {
    "function_name": "_runtime_read_lock_owner",
    "file_path": "src/lifecycle.c",
    "start_line": 2323,
    "end_line": 2337,
  },
  "call_path":[
    "_runtime_accept_session_frame",
    "_runtime_read_lock_owner",
  ],
  "suspicious_point": {
    "defect_class": "reader_state_race",
    "rule": "single_reader_field_under_shared_reader_count",
    "line": 2329,
    "expression": "shared reader field",
    "operation": "g_runtime_rwlock.reader_pid = reader_pid;",
  },
  "relation_evidence":{
    "execution": {},
    "lifecycle_pair": {},
    "cascade_wait": {},
  },//仅在存在evidence时显示
  "positive_evidence": [
    "function increments/decrements a reader count atomically",
    "line 2329: reader identity state is assigned outside a lock"
  ],
  "negative_evidence": [],
  "semantic_evidence": {},
  "priority_score": 77,
  "priority_reasons": [
    "graph_rule",
    "stack_overflow",
    "rule_confidence=0.82"
  ],
}
```
相比`deep_worker`，增加`candidate_id`，`priority_score`和`priority_reasons`。

## 第四章 `clang_ast_cfg`

本次运行中共有 143 个 `clang_ast_cfg` Ticket：普通单函数结构 38 个，入口到内部 Sink 结构 105 个。两种结构共享同一套局部 `ast_cfg`，入口到内部 Sink 结构额外携带跨函数调用路径。

### 4.1 `deep_worker` 原始字段

两种结构共同包含：

```json
{
  "candidate_id": "CLANG_CFG_...",
  "candidate_source": "clang_ast_cfg",
  "checker": "clang_ast_cfg_checker",
  "defect_class": "command_injection",
  "rule": "clang_cfg_system_with_nonliteral_command",
  "rule_confidence": 0.84,
  "source": {},
  "sink": {},
  "path": {},
  "ast_cfg": {},
  "positive_evidence": [],
  "negative_evidence": [],
  "evidence_refs": [],
  "validation_required": true,
  "proofs": {},
  "candidate_priority_group": "semantic_suspicious_point",
  "validation_budget_class": "...",
  "schema": "candidate_evidence_v1",
  "backend_profile": "unified",
  "evidence_engines": [],
  "semantic_overlays": {},
  "semantic_overlay_evidence": {},
  "path_kind": "local_memory_concurrency",
  "candidate_is_conclusion": false,
  "validation_notes": [],
  "candidate_record": {}
}
```

普通单函数 `path`：

```json
{
  "function": "_executor_execute_command",
  "complete_in_function": true,
  "backend": "Clang function body plus synthesized local CFG",
  "path_constraints": [],
  "cfg_path": [87]
}
```

入口到内部 Sink 结构额外包含：

```json
{
  "entry_function": "_executor_execute_task",
  "sink_function": "_executor_execute_command",
  "target_function": "_executor_execute_command",
  "call_path": [
    "_executor_execute_task",
    "_executor_execute_command"
  ],
  "complete_to_entry": true,
  "lifted_internal_sink": true,
  "path_kind": "entry_to_internal_sink",
  "call_edges": []
}
```

相同数据还会在 evidence 外层重复为：

```text
entry_function
sink_function
call_path
call_path_edges
internal_sink_lifted
```

`ast_cfg` 原始字段：

```json
{
  "checker_basis": "clangd-indexed function body with synthesized statement/CFG facts",
  "statement_count": 17,
  "approx_basic_block_count": 8,
  "declarations": [
    {
      "line": 82,
      "block": 6,
      "name": "full_command",
      "type": "char*",
      "pointer_depth": 1,
      "initialized": true
    }
  ],
  "condition_guards": [
    {
      "line": 83,
      "block": 7,
      "condition": "!full_command"
    }
  ],
  "scope_summary": {
    "block_count": 8,
    "return_lines": [72, 77, 84, 91],
    "branch_lines": [71, 75, 83]
  },
  "events": [
    {
      "kind": "system_call",
      "line": 87,
      "block": 9,
      "variable": "full_command",
      "api": "system",
      "expression": "system(full_command)"
    }
  ],
  "cfg_path": [87],
  "path_constraints": [],
  "clang_tooling": {
    "schema": "clang_tooling_evidence_v1",
    "function": "_executor_execute_command",
    "file": "src/executor.c",
    "range": {},
    "compile_commands_path": "...",
    "compile_command_found": true,
    "clang_path": "clang",
    "execution_enabled": false,
    "ast_dump_command": [],
    "cfg_dump_command": [],
    "status": "command_prepared_not_executed"
  }
}
```

`call_edges` 单条边：

```json
{
  "caller": "_executor_execute_task",
  "callee": "_executor_execute_command",
  "call_line": 48,
  "arguments": ["task->payload.command.command"],
  "parameter_mapping": [
    {
      "arg_index": 0,
      "actual": "task->payload.command.command",
      "formal": "command"
    }
  ],
  "caller_parameters": ["task"],
  "callee_parameters": ["command"],
  "guard_summary": {
    "caller_side": {},
    "callee_entry": {}
  },
  "evidence_source": "source_text_best_effort"
}
```

#### 4.1.1 Deep Worker 字段的重复和必要性分析

候选外层字段：

| 原始字段 | 必要性 | 分析 |
|---|---|---|
| `candidate_id` / `candidate_source` / `checker` | 移出 Prompt | 只用于追踪。 |
| `defect_class` / `rule` | 必须 | 合并为 `hypothesis`。 |
| `rule_confidence` | 移出 Prompt | 用于调度，不用于独立验证。 |
| `source` / `sink` | 必须 | 保留具体表达式、操作和位置。 |
| `positive_evidence` / `negative_evidence` | 必须 | 只保留具体事实和反证。 |
| `proofs` | 删除 | 当前 143 个 Ticket 全部为 `{}`，没有定义子 schema。 |
| `candidate_priority_group` / `validation_budget_class` | 移出 Prompt | 只影响排序和预算。 |
| schema/backend/engine/validation 字段 | 移出 Prompt | 不参与漏洞语义判断。 |
| `candidate_record` | 移出 Prompt | 与 source/sink/defect class 重复，根因键只用于去重。 |

`path` 字段：

| 原始字段 | 必要性 | 分析 |
|---|---|---|
| `function` | 必须 | sink 所在函数。 |
| `complete_in_function` | 条件保留并改名 | 只表示局部 Candidate 可在函数内描述，不代表路径可行性已证明。 |
| `backend` | 移出 Prompt | 固定说明字符串。 |
| `cfg_path` | 必须 | 是候选相关源码行，不是精确 CFG block path。 |
| `path_constraints` | 条件保留 | 是行号区间内的 `if` 文本扫描，不能作为路径证明。 |
| `entry_function` | 入口到内部 Sink 时必须 | 当前扫描根。 |
| `sink_function` | 入口到内部 Sink 时必须 | 实际包含 sink 的函数。 |
| `target_function` | 删除或合并 | 当前始终与 `sink_function` 相同。 |
| `call_path` | 必须 | CodeIndex 找到的函数调用链。 |
| `complete_to_entry` | 改名 | 当前只表示找到调用链，不表示路径运行时可行。 |
| `lifted_internal_sink` / `path_kind` | 合并 | 一个 `scope: entry_to_internal_sink` 即可表达。 |
| `call_edges` | 必须但应压缩 | 保留调用点、参数映射和有效守卫。 |
| 外层 `call_path_edges` | 删除 | 与 `path.call_edges` 重复。 |

`ast_cfg` 字段：

| 原始字段 | 必要性 | 分析 |
|---|---|---|
| `checker_basis` | 移出 Prompt | 固定生成方式说明。 |
| `statement_count` | 删除 | 对具体漏洞判断作用很小。 |
| `approx_basic_block_count` | 删除 | 与 `scope_summary.block_count` 重复，且只是启发式 block。 |
| `declarations` | 条件保留 | 只保留与 source/sink/guard 相关变量。正则类型解析可能不精确。 |
| `condition_guards` | 必须但应过滤 | 只保留与 Candidate 变量相关的条件。 |
| `scope_summary.return_lines` | 条件保留 | 生命周期、锁、错误路径 Candidate 有用。 |
| `scope_summary.branch_lines` | 条件保留 | 有代码上下文时价值有限。 |
| `events` | 必须 | 是规则生成器提取的主要语义事件。 |
| `cfg_path` / `path_constraints` | 必须或条件保留 | 与外层 path 重复，只保留一份。 |
| `clang_tooling` | 通常移出 Prompt | 本次 143 个 Candidate 的 `execution_enabled` 全为 false，没有真实 AST/CFG dump。只有执行成功且返回有效 summary 时才发送。 |

`call_edges.guard_summary` 由源码文本扫描产生，所有 `is_conclusive` 均为 false。由于 `->` 中的 `>` 可能被误识别为范围比较，`checks` 非空也不能证明存在有效 guard。它必须被标记为启发式线索。

固定值备注：`clang_ast_cfg` 同时包含全体 143 个 Ticket 的固定项，以及只在 105 个入口到内部 Sink 变体中出现的固定项。

| 适用范围 | 字段 | 固定值 | 备注 |
|---|---|---|---|
| 全部结构 | `candidate_source` | `clang_ast_cfg` | Candidate 家族标识，可由结构类型推导。 |
| 全部结构 | `checker` | `clang_ast_cfg_checker` | 生成器固定的追踪字段。 |
| 全部结构 | `schema` | `candidate_evidence_v1` | 统一 evidence 序列化版本。 |
| 全部结构 | `backend_profile` | `unified` | 本次运行配置固定，其他运行可能不同。 |
| 全部结构 | 顶层 `path_kind` | `local_memory_concurrency` | 当前 Clang 本地候选路由固定传入；覆盖 19 种 defect class，区分能力很低。 |
| 全部结构 | `candidate_is_conclusion` | `false` | 统一 evidence 注解器硬编码。 |
| 全部结构 | `validation_required` | `true` | 统一注解器默认值，进入 Worker 前还会按该字段过滤。 |
| 全部结构 | `evidence_refs` | `[]` | 143 个 Ticket 全为空。 |
| 全部结构 | `proofs` | `{}` | 143 个 Ticket 全为空，且当前没有定义 proof 子 schema。 |
| 全部结构 | `path.complete_in_function` | `true` | `_emit` 中硬编码，不是 CFG 分析结果；不能证明函数内路径可行。 |
| 全部结构 | `path.backend` | `Clang function body plus synthesized local CFG` | 固定说明字符串，不是 Candidate 证据。 |
| 全部结构 | `ast_cfg.checker_basis` | `clangd-indexed function body with synthesized statement/CFG facts` | 固定生成方式说明。 |
| 全部结构 | `ast_cfg.clang_tooling.schema` | `clang_tooling_evidence_v1` | tooling evidence 的固定版本号。 |
| 全部结构 | `ast_cfg.clang_tooling.clang_path` | `clang` | 本次运行配置值，不表示 clang 已实际执行。 |
| 全部结构 | `ast_cfg.clang_tooling.compile_commands_path` | 本次 benchmark 的固定 `compile_commands.json` 路径 | 运行环境元数据；不应发送绝对路径给模型。 |
| 全部结构 | `ast_cfg.clang_tooling.execution_enabled` | `false` | 143 个 Ticket 全部未执行真实 AST/CFG dump；`status` 仍有 `command_prepared_not_executed` 和 `compile_command_not_found` 两种，并非固定值。 |
| 入口变体中存在 `call_edges` 时 | `call_edges.guard_summary.is_conclusive` | `false` | 当前所有生成的 guard summary 都是 best-effort 文本线索；普通结构没有 `call_edges`。 |
| 全部结构 | `semantic_overlays` / `evidence_engines` | 本次 unified profile 的固定全局清单 | 运行级能力和模型配置，不是 Ticket 级命中证据。 |
| 入口变体 | `path.complete_to_entry` | `true` | 提升函数在找到非空调用链后直接写入；只表示静态调用链已找到。 |
| 入口变体 | `path.lifted_internal_sink` | `true` | 105 个入口变体全部如此；这是选择该变体的结构条件。 |
| 入口变体 | `path.path_kind` | `entry_to_internal_sink` | 提升逻辑硬编码，用于与普通单函数结构区分。 |
| 入口变体 | `path.target_function` | 固定等于 `path.sink_function` | 固定关系而非固定函数名，两个字段表达相同目标。 |

这些常量中，只有内层 `path.path_kind=entry_to_internal_sink` 对区分两种 Clang 结构有直接作用；其余大多可以由 Candidate 类型、运行配置或生成阶段推导。特别是 `complete_in_function=true` 和 `complete_to_entry=true` 不应被大模型解读为可行性证明。

### 4.2 `vulnerability_analyzer` 原始字段及与 `deep_worker` 的差异

`clang_ast_cfg` evidence 字段较多，因此在 Analyzer 中会稳定触发 8 键限制。典型结构为：

```json
{
  "candidate_id": "CAND_05508ff3c284",
  "status": "planned",
  "defect_class": "use_after_free",
  "canonical_source": "safe_free(g_runtime_pbuf_pool) at line 2350",
  "canonical_sink": "return g_runtime_pbuf_pool->buffer ? ...",
  "sources": [
    "local_rule:td_runtime_refresh_cache"
  ],
  "call_paths": [
    [
      "td_runtime_refresh_cache"
    ]
  ],
  "ticket": {
    "id": "CAND_05508ff3c284",
    "skill": "temporal_memory",
    "line": 2351,
    "priority_score": 1,
    "trigger": "clang_cfg_use_after_release",
    "origin": "SAFE_FREE(g_runtime_pbuf_pool) at line 2350",
    "sink": "return g_runtime_pbuf_pool->buffer ? ...",
    "source": "clang_ast_cfg",
    "evidence": {
      "candidate_id": "CLANG_CFG_USE_AFTER_FREE_6826a47ad9",
      "candidate_source": "clang_ast_cfg",
      "checker": "clang_ast_cfg_checker",
      "defect_class": "use_after_free",
      "rule": "clang_cfg_use_after_release",
      "rule_confidence": 0.86,
      "source": {
        "expression": "SAFE_FREE(g_runtime_pbuf_pool) at line 2350",
        "file": "src/lifecycle.c",
        "line": 2350,
        "__compacted__": true
      },
      "sink": {
        "operation": "return g_runtime_pbuf_pool->buffer ? ...",
        "file": "src/lifecycle.c",
        "line": 2351,
        "__compacted__": true
      },
      "__omitted_keys__": {
        "count": 23,
        "keys": [
          "path",
          "ast_cfg",
          "positive_evidence",
          "negative_evidence",
          "evidence_refs",
          "validation_required",
          "proofs",
          "candidate_priority_group",
          "validation_budget_class",
          "entry_function",
          "sink_function",
          "call_path"
        ]
      },
      "__compacted__": true
    }
  }
}
```

与 Deep Worker 的差异：

| 字段 | 与 `deep_worker` 的差异 | 含义 |
|---|---|---|
| `candidate_id` | Analyzer 新增字段 | CandidateLedger 中 Ticket 的规范化 ID。 |
| `status` | Analyzer 新增字段 | Candidate 当前状态。 |
| `defect_class` | Analyzer 新增字段 | CandidateLedger 上移的缺陷分类。 |
| `dedup_key` | Analyzer 新增字段 | Candidate 去重键。 |
| `root_cause_key` | Analyzer 新增字段 | 根因去重键。 |
| `sources` | Analyzer 新增字段 | Candidate 来源标签。 |
| `call_paths` | Analyzer 新增字段 | CandidateLedger 路径摘要。 |
| `duplicate_count` | Analyzer 新增字段 | 合并的重复 Candidate 数。 |
| `canonical_source` | 位置不同 | evidence 内 canonical source 的 ledger 摘要副本。 |
| `canonical_sink` | 位置不同 | evidence 内 canonical sink 的 ledger 摘要副本。 |
| `worker_report_id` | Analyzer 新增字段 | 关联的 Worker report ID。 |
| `ticket` | Analyzer 新增字段 | 原 Ticket 包装对象。 |
| `ticket.id` | Analyzer 新增字段 | 原 Ticket ID。 |
| `ticket.skill` | Analyzer 新增字段 | Clang Candidate 的验证 Skill。 |
| `ticket.line` | Analyzer 新增字段 | Ticket 主定位行。 |
| `ticket.priority_score` | Analyzer 新增字段 | Ticket 调度分数。 |
| `ticket.trigger` | Analyzer 新增字段 | Clang rule 名称。 |
| `ticket.origin` | Analyzer 新增字段 | Ticket 外层 origin。 |
| `ticket.sink` | Analyzer 新增字段 | Ticket 外层 sink。 |
| `ticket.dedup_key` | Analyzer 新增字段 | Ticket 内去重键。 |
| `ticket.sources` | Analyzer 新增字段 | Ticket 来源标签。 |
| `ticket.call_paths` | Analyzer 新增字段 | CandidateLedger 路径摘要，不等于 Clang `path.call_path`。 |
| `ticket.task` | Analyzer 新增字段 | Clang Candidate 验证任务。 |
| `ticket.priority_reasons` | Analyzer 新增字段 | 优先级原因列表。 |
| `ticket.resource_kind` | Analyzer 新增字段 | Candidate 资源类型。 |
| `ticket.source` | Analyzer 新增字段 | Candidate 生成器类型 `clang_ast_cfg`。 |
| `ticket.evidence` | 字段名和位置不同 | 对应 Deep Worker 的 `Structured evidence`。 |
| `ticket.evidence.candidate_id` | 字段名相同、位置不同 | Clang 检查器内部 Candidate ID。 |
| `ticket.evidence.candidate_source` | 字段名相同、位置不同 | 固定为 `clang_ast_cfg`。 |
| `ticket.evidence.checker` | 字段名相同、位置不同 | Clang checker 名称。 |
| `ticket.evidence.defect_class` | 字段名相同、位置不同 | Candidate 缺陷类型。 |
| `ticket.evidence.rule` | 字段名相同、位置不同 | Clang rule 名称。 |
| `ticket.evidence.rule_confidence` | 字段名相同、位置不同 | Clang rule 置信度。 |
| `ticket.evidence.source` | 字段名相同、位置不同 | Clang Candidate source。 |
| `ticket.evidence.source.expression` | 字段名相同、位置不同 | source 表达式。 |
| `ticket.evidence.source.file` | 字段名相同、位置不同 | source 文件。 |
| `ticket.evidence.source.line` | 字段名相同、位置不同 | source 行号。 |
| `ticket.evidence.source.__compacted__` | Analyzer 新增字段 | source 对象压缩标记。 |
| `ticket.evidence.sink` | 字段名相同、位置不同 | Clang Candidate sink。 |
| `ticket.evidence.sink.operation` | 字段名相同、位置不同 | sink 操作。 |
| `ticket.evidence.sink.file` | 字段名相同、位置不同 | sink 文件。 |
| `ticket.evidence.sink.line` | 字段名相同、位置不同 | sink 行号。 |
| `ticket.evidence.sink.__compacted__` | Analyzer 新增字段 | sink 对象压缩标记。 |
| `ticket.evidence.__omitted_keys__` | Analyzer 新增字段 | 记录被删除 evidence 字段的数量和部分字段名。 |
| `ticket.evidence.__compacted__` | Analyzer 新增字段 | evidence 压缩标记。 |
| `ticket.evidence.path` | Analyzer 减少字段 | Deep Worker 中完整的局部和跨函数 path 被整体删除。 |
| `ticket.evidence.ast_cfg` | Analyzer 减少字段 | Deep Worker 中完整的 AST/CFG 事实包被整体删除。 |
| `ticket.evidence.positive_evidence` | Analyzer 减少字段 | 支持证据被删除。 |
| `ticket.evidence.negative_evidence` | Analyzer 减少字段 | 反证和待验证项被删除。 |
| `ticket.evidence.evidence_refs` | Analyzer 减少字段 | 证据引用被删除。 |
| `ticket.evidence.validation_required` | Analyzer 减少字段 | 验证要求标记被删除。 |
| `ticket.evidence.proofs` | Analyzer 减少字段 | proofs 对象被删除。 |
| `ticket.evidence.candidate_priority_group` | Analyzer 减少字段 | Candidate 优先级组被删除。 |
| `ticket.evidence.validation_budget_class` | Analyzer 减少字段 | 验证预算类别被删除。 |
| `ticket.evidence.entry_function` | Analyzer 减少字段 | 入口变体的 evidence 外层入口函数被删除。 |
| `ticket.evidence.sink_function` | Analyzer 减少字段 | 入口变体的 evidence 外层 sink 函数被删除。 |
| `ticket.evidence.call_path` | Analyzer 减少字段 | 入口变体的 evidence 外层调用链被删除。 |
| `ticket.evidence.call_path_edges` | Analyzer 减少字段 | 入口变体的 evidence 外层调用边被删除。 |
| `ticket.evidence.internal_sink_lifted` | Analyzer 减少字段 | 内部 sink 提升标志被删除。 |
| `ticket.evidence.schema` | Analyzer 减少字段 | evidence schema 版本被删除。 |
| `ticket.evidence.backend_profile` | Analyzer 减少字段 | 后端 profile 被删除。 |
| `ticket.evidence.evidence_engines` | Analyzer 减少字段 | engine 清单被删除。 |
| `ticket.evidence.semantic_overlays` | Analyzer 减少字段 | 全局 semantic overlay 被删除。 |
| `ticket.evidence.semantic_overlay_evidence` | Analyzer 减少字段 | Candidate 命中的 overlay evidence 被删除。 |
| `ticket.evidence.path_kind` | Analyzer 减少字段 | 顶层 Clang path kind 被删除。 |
| `ticket.evidence.candidate_is_conclusion` | Analyzer 减少字段 | Candidate 非结论标记被删除。 |
| `ticket.evidence.validation_notes` | Analyzer 减少字段 | 验证备注被删除。 |
| `ticket.evidence.candidate_record` | Analyzer 减少字段 | 完整 Candidate 去重记录被删除。 |
| `ticket.evidence.path.function` | 随 `path` 减少 | 内部 sink 所在函数不可见。 |
| `ticket.evidence.path.complete_in_function` | 随 `path` 减少 | 固定局部完整性标志不可见。 |
| `ticket.evidence.path.cfg_path` | 随 `path` 减少 | Candidate 相关行列表不可见。 |
| `ticket.evidence.path.path_constraints` | 随 `path` 减少 | 局部路径约束不可见。 |
| `ticket.evidence.path.entry_function` | 随 `path` 减少 | 入口变体的入口函数不可见。 |
| `ticket.evidence.path.sink_function` | 随 `path` 减少 | 入口变体的 sink 函数不可见。 |
| `ticket.evidence.path.target_function` | 随 `path` 减少 | 入口变体的目标函数不可见。 |
| `ticket.evidence.path.call_path` | 随 `path` 减少 | entry-to-sink 调用链不可见。 |
| `ticket.evidence.path.complete_to_entry` | 随 `path` 减少 | 找到入口链的标志不可见。 |
| `ticket.evidence.path.lifted_internal_sink` | 随 `path` 减少 | 内部 sink 提升标志不可见。 |
| `ticket.evidence.path.path_kind` | 随 `path` 减少 | 普通结构与入口变体的区分字段不可见。 |
| `ticket.evidence.path.call_edges` | 随 `path` 减少 | 调用点、参数映射和 guard summary 不可见。 |
| `ticket.evidence.ast_cfg.checker_basis` | 随 `ast_cfg` 减少 | AST/CFG 生成基础说明不可见。 |
| `ticket.evidence.ast_cfg.statement_count` | 随 `ast_cfg` 减少 | 语句数量不可见。 |
| `ticket.evidence.ast_cfg.approx_basic_block_count` | 随 `ast_cfg` 减少 | 近似基本块数量不可见。 |
| `ticket.evidence.ast_cfg.declarations` | 随 `ast_cfg` 减少 | 变量声明事实不可见。 |
| `ticket.evidence.ast_cfg.condition_guards` | 随 `ast_cfg` 减少 | 条件 guard 不可见。 |
| `ticket.evidence.ast_cfg.scope_summary` | 随 `ast_cfg` 减少 | block、return 和 branch 摘要不可见。 |
| `ticket.evidence.ast_cfg.events` | 随 `ast_cfg` 减少 | Candidate 的局部语义事件不可见。 |
| `ticket.evidence.ast_cfg.cfg_path` | 随 `ast_cfg` 减少 | 重复的 Candidate 行列表不可见。 |
| `ticket.evidence.ast_cfg.path_constraints` | 随 `ast_cfg` 减少 | AST/CFG 路径约束不可见。 |
| `ticket.evidence.ast_cfg.clang_tooling` | 随 `ast_cfg` 减少 | Clang tooling 状态和命令信息不可见。 |

因此 Analyzer 实际只保留 Clang Candidate 的基本假设和两个端点，本文第一节分析的 AST/CFG、events、guards 及入口调用链均被减少。

### 4.3 `deep_worker` 新字段

普通单函数 Candidate：

```json
{
  "candidate_kind": "clang_ast_cfg",
  "defect_class": "command_injection",
  "rule": "clang_cfg_system_with_nonliteral_command",
  "function": {
    "function_name": "_executor_execute_command",
    "file_path": ,
    "start_line": ,
    "end_line": ,
  },
  "source": {
    "expression": "full_command",
    "file": "src/executor.c",
    "line": 87
  },
  "sink": {
    "operation": "int result = system(full_command);",
    "file": "src/executor.c",
    "line": 87
  },
  "events": [
  {
    "kind": "system_call",
    "line": 87,
    "variable": "full_command",
    "api": "system",
    "expression": "int result = system(full_command);"
  }
],
  "positive_evidence": [],
  "negative_evidence": [],
  "semantic_evidence": {}
}
```

入口到内部 Sink Candidate 结构：

```json
{
  "candidate_kind": "clang_ast_cfg",
  "defect_class": "command_injection",
  "rule": "clang_cfg_system_with_nonliteral_command",
  "entry_function": {
    "function_name": "_executor_execute_task",
    "file_path":,
    "start_line":,
    "end_line":,
  },
  "target_function": {
    "function_name": "_executor_execute_command",
    "file_path":,
    "start_line":,
    "end_line":,
  },
  "source": {
    "expression": "full_command",
    "file": "src/executor.c",
    "line": 87
  },
  "sink": {
    "operation": "int result = system(full_command);",
    "file": "src/executor.c",
    "line": 87
  },
  "events": [
  {
    "kind": "system_call",
    "line": 87,
    "variable": "full_command",
    "api": "system",
    "expression": "int result = system(full_command);"
  }
],
  "call_path": {
    "nodes": [
      "_executor_execute_task",
      "_executor_execute_command"
    ],
    "edges": [
      {
        "caller": "_executor_execute_task",
        "callee": "_executor_execute_command",
        "callsite_line": 48,
        "parameter_mapping": [
          {
            "index": 0,
            "actual": "task->payload.command.command",
            "formal": "command",
            "source_parameter": null
          }
        ],
        // "guard_at_caller_side": [
        //   {
        //     "line": 45,
        //     "text": "switch (task->type) {",
        //     "symbols": [
        //       "task"
        //     ],
        //     "guard_kind": "bounds_or_range_check"
        //   },
        //   {
        //     "line": 47,
        //     "text": "if (task->payload.command.command) {",
        //     "symbols": [
        //       "task",
        //       "payload",
        //       "command"
        //     ],
        //     "guard_kind": "bounds_or_range_check"
        //   }
        // ],
        // "guards_at_callee_entry": [
        //   {
        //     "line": 71,
        //     "text": "if (!command) {",
        //     "symbols": [
        //       "command"
        //     ],
        //     "guard_kind": "null_or_presence_check"
        //   },
        //   {
        //     "line": 75,
        //     "text": "if (_executor_validate_command(command) != 0) {",
        //     "symbols": [
        //       "command"
        //     ],
        //     "guard_kind": "bounds_or_range_check"
        //   }
        // ],
      }
    ]
  },
  "positive_evidence": [],
  "negative_evidence": [],
  "semantic_evidence": {}
}
```
当前 JSON 对照说明（以本节推荐 JSON 为准）：

| 推荐字段 | 来源或取值方法 | 含义 |
|---|---|---|
| `candidate_kind` | 固定为 `clang_ast_cfg`。 | 标识证据家族。 |
| `defect_class` / `rule` | 沿用原顶层字段。 | 待验证的缺陷类别和具体规则。 |
| `function` | 普通单函数结构的定位对象，由原 `path.function` 和源码索引组成。 | 当前 Candidate 所在函数及范围。 |
| `entry_function` / `target_function` | 入口变体分别由原 `path.entry_function`、`path.target_function`/`sink_function` 和源码索引组成。 | 调用链起点和内部 Sink 所在函数。 |
| `function_name` / `file_path` / `start_line` / `end_line` | 函数索引的结构化结果；当前 JSON 中空值只是待填定位占位。 | 供工具直接查询的函数名、文件和范围。 |
| `source` / `sink` | 沿用原端点字段，保留表达式/操作、文件和行。 | 规则命中的输入表达式与目标操作。 |
| `events` | 由原 `ast_cfg.events` 迁入。 | 当前 Candidate 的 AST/CFG 语义事件。 |
| `call_path.nodes` | 由原 `path.call_path` 迁入，首尾应与入口和目标一致。 | 静态调用链上的函数序列。 |
| `call_path.edges` | 由原 `path.call_edges` 迁入。 | 调用点、参数映射和可选 guard 证据。 |
| `edges[].callsite_line` | 原 `call_line` 的规范化名称。 | caller 中调用 callee 的源码行。 |
| `positive_evidence` / `negative_evidence` | 沿用原字段。 | 支持和削弱 Candidate 的证据。 |
| `semantic_evidence` | 由原 `semantic_overlay_evidence` 改名；为空时省略。 | 当前 Candidate 实际命中的语义补充。 |

因此，当前 JSON 不再要求 `local_scope_covered`、`feasibility_proven`、`entry_call_chain_found` 或 `runtime_feasibility_proven`。是否具备局部上下文由函数定位和代码上下文判断；入口调用链由 `call_path.nodes/edges` 判断；运行时可行性仍需 Deep Worker 独立验证。

### 4.4 `vulnerability_analyzer` 新字段

普通单函数 Candidate：

```json
{
  "candidate_id": "CAND_05508ff3c284",
  "candidate_kind": "clang_ast_cfg",
  "defect_class": "command_injection",
  "rule": "clang_cfg_system_with_nonliteral_command",
  "function": {
    "function_name": "_executor_execute_command",
    "file_path": ,
    "start_line": ,
    "end_line": ,
  },
  "source": {
    "expression": "full_command",
    "file": "src/executor.c",
    "line": 87
  },
  "sink": {
    "operation": "int result = system(full_command);",
    "file": "src/executor.c",
    "line": 87
  },
  "events": [
  {
    "kind": "system_call",
    "line": 87,
    "variable": "full_command",
    "api": "system",
    "expression": "int result = system(full_command);"
  }
],
  "positive_evidence": [],
  "negative_evidence": [],
  "semantic_evidence": {},
  "priority_score": 1,
  "priority_reasons": [],
}
```

入口到内部 Sink Candidate 结构：

```json
{
  "candidate_id": "CAND_05508ff3c284",
  "candidate_kind": "clang_ast_cfg",
  "defect_class": "command_injection",
  "rule": "clang_cfg_system_with_nonliteral_command",
  "entry_function": {
    "function_name": "_executor_execute_task",
    "file_path":,
    "start_line":,
    "end_line":,
  },
  "target_function": {
    "function_name": "_executor_execute_command",
    "file_path":,
    "start_line":,
    "end_line":,
  },
  "source": {
    "expression": "full_command",
    "file": "src/executor.c",
    "line": 87
  },
  "sink": {
    "operation": "int result = system(full_command);",
    "file": "src/executor.c",
    "line": 87
  },
  "events": [
  {
    "kind": "system_call",
    "line": 87,
    "variable": "full_command",
    "api": "system",
    "expression": "int result = system(full_command);"
  }
],
  "call_path": {
    "nodes": [
      "_executor_execute_task",
      "_executor_execute_command"
    ],
    "edges": [
      {
        "caller": "_executor_execute_task",
        "callee": "_executor_execute_command",
        "callsite_line": 48,
        "parameter_mapping": [
          {
            "index": 0,
            "actual": "task->payload.command.command",
            "formal": "command",
            "source_parameter": null
          }
        ],
      }
    ]
  },
  "positive_evidence": [],
  "negative_evidence": [],
  "semantic_evidence": {},
  "priority_score": 1,
  "priority_reasons": [],
}
```

## 第五章 `svf_value_flow`

本次运行中共有 21 个 `svf_value_flow` Ticket。它们由 SVF/Saber 后端内存信号标准化而来，并由 Z-Scope 使用 CodeIndex 和源码片段尝试进行源码级路径重建。

### 5.1 `deep_worker` 原始字段

原始 Candidate evidence 共同字段包括：

```text
candidate_id
candidate_source
checker
defect_class
rule
source
sink
path
value_flow
source_path
positive_evidence
negative_evidence
evidence_refs
schema
backend_profile
evidence_engines
semantic_overlays
semantic_overlay_evidence
path_kind
candidate_is_conclusion
validation_required
validation_notes
candidate_record
```

`value_flow` 原始结构：

```json
{
  "tool": "saber",
  "svf_group": "saber:default",
  "svf_groups": ["saber:default"],
  "bug_type": "Partial Memory Leak",
  "source_func": "_net_recv_string",
  "sink_func": "Partial Memory Leak",
  "function": "_net_recv_string",
  "file": "src/network.c",
  "line": 175,
  "function_start": 174,
  "function_end": 188,
  "signature": "char* _net_recv_string(int fd, size_t max_len)",
  "interprocedural": true,
  "backend_path": [],
  "raw_backend_row": {}
}
```

非空 `backend_path` 节点可能包含：

```json
{
  "index": 0,
  "function": "...",
  "file": "...",
  "line": 0,
  "code": "...",
  "ssa_node": "...",
  "llvm_value": "...",
  "points_to": [],
  "alias_set": [],
  "object_id": "..."
}
```

`source_path` 原始结构：

```json
{
  "entry_function": "_net_recv_string",
  "target_function": "_net_recv_string",
  "source_function": "",
  "sink_function": "",
  "call_path": ["_net_recv_string"],
  "complete_to_entry": true,
  "reported_location": {
    "file": "src/network.c",
    "line": 175
  },
  "reported_snippet": "...",
  "source_level_flow": {
    "schema": "svf_source_level_flow_v1",
    "source_symbol": "",
    "sink_symbol": "Partial Memory Leak",
    "object_symbols": ["buffer"],
    "events": [],
    "expression_edges": [],
    "complete_source_to_sink": false,
    "notes": []
  },
  "target_function_context": {
    "function": "...",
    "file": "...",
    "start_line": 0,
    "end_line": 0,
    "signature": "...",
    "code_excerpt": "...",
    "truncated": false
  },
  "source_function_context": {},
  "sink_function_context": {},
  "reconstruction_notes": []
}
```

`source_level_flow.events`：

```json
{
  "role": "reported_location",
  "symbol": "Partial Memory Leak",
  "function": "_net_recv_string",
  "file": "src/network.c",
  "line": 175,
  "code": "...",
  "match_kind": "reported_svf_location",
  "object_mentions": ["buffer"]
}
```

`expression_edges`：

```json
{
  "from_role": "source",
  "to_role": "sink",
  "shared_object_symbols": ["buffer"],
  "reason": "shared_object_symbol"
}
```

#### 5.1.1 Deep Worker 字段的重复和必要性分析

Candidate 通用元数据与 `graph_rule`、`clang_ast_cfg` 的结论相同：ID、checker、schema、backend、engine、validation flags、全局 overlays 和 candidate record 应移出 Prompt。以下重点分析 `value_flow` 和 `source_path`。

`value_flow`：

| 原始字段 | 必要性 | 分析 |
|---|---|---|
| `tool` | 条件保留 | 可用于理解信号类型，但不应增加结论权威性。 |
| `svf_group` / `svf_groups` | 移出 Prompt | 后端分组追踪元数据。 |
| `bug_type` | 必须 | 是后端报告的原始信号类型。 |
| `source_func` | 条件保留 | 当前有 fallback，可能只是 containing function，不一定是后端真实 source。 |
| `sink_func` | 条件保留 | 当前可能 fallback 为 `bug_type`，不能保证是函数名。 |
| `function/file/line/range/signature` | 必须但应合并 | 统一放入 `reported_location` 和 `containing_function`。 |
| `interprocedural` | 删除或重定义 | 当前只比较 source/sink 字符串是否不同，不能证明跨函数值流。 |
| `backend_path` | 条件保留且高价值 | 非空时是最接近后端原生值流的证据；本次 21 个全部为空。 |
| `raw_backend_row` | 移出 Prompt | 与标准化字段重复，只用于追踪 fallback 来源。 |

`source_path`：

| 原始字段 | 必要性 | 分析 |
|---|---|---|
| `entry_function` / `target_function` | 必须 | 表示当前入口和后端报告所在函数。 |
| `source_function` / `sink_function` | 条件保留 | 只在后端明确提供函数名时发送，不使用 bug type 占位。 |
| `call_path` | 必须 | 是 CodeIndex 调用链，不是 SVF value-flow path。 |
| `complete_to_entry` | 改名 | 只表示找到 entry-to-target 调用链，应改为 `entry_call_chain_found`。 |
| `reported_location` | 必须 | 后端信号的源码位置。 |
| `reported_snippet` | 删除或合并 | 与 `target_function_context.code_excerpt` 和 Focused Code Context 重复，只保留一份代码。 |
| `source_level_flow` | 必须 | 是源码重建状态，但必须显式区分 complete 和 unresolved。 |
| 三个 function context | 条件保留 | 只发送实际需要且非空的函数代码，避免重复。 |
| `reconstruction_notes` | 条件保留并结构化 | 固定说明移出 Prompt，仅保留具体缺失项。 |

`source_level_flow`：

| 原始字段 | 必要性 | 分析 |
|---|---|---|
| `schema` | 移出 Prompt | 版本元数据。 |
| `source_symbol` / `sink_symbol` | 条件保留 | 需要标记其来源，避免把 bug type 当源码符号。 |
| `object_symbols` | 必须 | 但只是文本/内存 API 参数推断，不是 points-to 证明。 |
| `events` | 必须 | 应区分 `source`、`sink`、`reported_location` 及匹配质量。 |
| `expression_edges` | 条件保留 | 是源码重建的启发式边，不是 SVF 原生边。 |
| `complete_source_to_sink` | 必须 | 是判断源码重建完整性的关键字段。 |
| `notes` | 必须但应改名 | 建议改为结构化 `unresolved`。 |

本次 21 个 Candidate 的实际质量状态：

```text
backend_path 非空：0
complete_source_to_sink=true：0
source_function_context 非空：0
sink_function_context 非空：0
每个 Candidate 的 source-level event 数：1
每个 Candidate 的 expression edge 数：0
```

因此这批 Candidate 表达的是“后端在某处发出内存泄漏信号”，不是“SVF 已提供完整 source-to-sink 证明”。

固定值备注：本次 21 个 `svf_value_flow` Ticket 来自同一 Saber 分组，因此存在较多运行固定值和当前样本固定值。

| 字段 | 固定值 | 备注 |
|---|---|---|
| `candidate_source` | `svf_value_flow` | Candidate 家族标识。 |
| `checker` | `svf_value_flow_checker` | 生成器固定的追踪字段。 |
| `schema` | `candidate_evidence_v1` | 统一 evidence 序列化版本。 |
| `backend_profile` | `unified` | 本次运行配置固定。 |
| 顶层 `path_kind` | `backend_signal` | 后端信号路由固定传入，只表示来源层级。 |
| `candidate_is_conclusion` | `false` | 统一 evidence 注解器硬编码。 |
| `validation_required` | `true` | 统一 evidence 注解器默认写入。 |
| `evidence_refs` | `[]` | 21 个 Ticket 全为空。 |
| `defect_class` / `candidate_record.defect_class` | `memory_leak` | 仅本次样本固定；`bug_type` 仍分为 `Memory Leak` 和 `Partial Memory Leak`。 |
| `path.backend` | `SVF/Saber value-flow` | 固定说明字符串。 |
| `path.complete_in_function` | `false` | 生成器硬编码，表示后端信号不能仅凭该字段视为函数内完整证明。 |
| `path.path_constraints` | 两条固定的后端验证说明 | 是通用验证模板，不是 Candidate 特有的路径约束。 |
| `value_flow.tool` | `saber` | 本次后端工具固定。 |
| `value_flow.svf_group` | `saber:default` | 本次后端分组固定。 |
| `value_flow.svf_groups` | `["saber:default"]` | 与单值 `svf_group` 重复。 |
| `value_flow.interprocedural` | `true` | 21 个 Ticket 均为 true，但它由 source/sink 字符串是否不同计算；当前 sink fallback 为 bug type，不能证明跨函数。 |
| `value_flow.backend_path` | `[]` | 21 个 Ticket 均未携带节点级后端路径。 |
| `source_path.complete_to_entry` | `true` | 当前样本均找到 entry-to-target 调用链；不表示 source-to-sink value flow 完整。 |
| `source_path.source_function` / `sink_function` | 空字符串 | 21 个 Ticket 均为空，说明源码重建没有确认真实端点函数。 |
| `source_path.source_function_context` / `sink_function_context` | `{}` | 21 个 Ticket 均为空。 |
| `source_level_flow.schema` | `svf_source_level_flow_v1` | 源码重建子结构的固定版本号。 |
| `source_level_flow.complete_source_to_sink` | `false` | 21 个 Ticket 全部未完成 source-to-sink 重建。 |
| `source_level_flow.expression_edges` | `[]` | 21 个 Ticket 均没有源码级表达式边。 |
| `negative_evidence` | 两条固定的 Validator 提醒 | 通用验证模板，不是从当前 Candidate 源码提取的反证。 |
| `semantic_overlays` / `evidence_engines` | 本次 unified profile 的固定全局清单 | 应作为运行元数据保存，不应被理解为每个 Ticket 都实际使用了所有 engine。 |

上述固定空值和固定说明会显著增加 Prompt 重复。对于大模型，保留 `bug_type`、报告位置和实际非空路径即可；固定 checker/schema/profile、空 backend path、空函数上下文及通用 Validator 模板均可移出 Prompt。

### 5.2 `vulnerability_analyzer` 原始字段及与 `deep_worker` 的差异

`svf_value_flow` 在 Analyzer 中也会触发 evidence 8 键限制。典型结构为：

```json
{
  "candidate_id": "CAND_9398dab24e7a",
  "status": "planned",
  "defect_class": "memory_leak",
  "canonical_source": "_runtime_query_peak_stats",
  "canonical_sink": "memory leak",
  "sources": [
    "static_backend_signal:_runtime_query_peak_stats"
  ],
  "call_paths": [
    [
      "_runtime_query_peak_stats"
    ]
  ],
  "ticket": {
    "id": "CAND_9398dab24e7a",
    "skill": "resource_lifecycle",
    "line": 1425,
    "priority_score": 66,
    "trigger": "svf_value_flow_memory_leak",
    "origin": "_runtime_query_peak_stats",
    "sink": "Memory Leak",
    "dedup_key": "memory_leak|memory|_runtime_get_thread_cache|_runtime_get_thread_cache|memory leak",
    "sources": [
      "static_backend_signal:td_runtime_refresh_cache"
    ],
    "call_paths": [
      [
        "td_runtime_refresh_cache"
      ]
    ],
    "task": "Verify regex/local-pattern memory_leak candidate. Confirm concrete source, sink, path feasibility, and guard sufficiency; reject if any required proof is missing.",
    "priority_reasons": [
      "svf_value_flow",
      "memory_leak",
      "rule_confidence=0.76"
    ],
    "resource_kind": "memory",
    "source": "svf_value_flow",
    "evidence": {
      "candidate_id": "SVF_VALUE_FLOW_19602bef19a9",
      "candidate_source": "svf_value_flow",
      "checker": "svf_value_flow_checker",
      "defect_class": "memory_leak",
      "rule": "svf_value_flow_memory_leak",
      "source": {
        "expression": "_runtime_query_peak_stats",
        "file": "src/lifecycle.c",
        "line": 1425,
        "__compacted__": true
      },
      "sink": {
        "operation": "Memory Leak",
        "file": "src/lifecycle.c",
        "line": 1425,
        "__compacted__": true
      },
      "path": {
        "function": "_runtime_query_peak_stats",
        "entry_function": "_runtime_query_peak_stats",
        "backend": "SVF/Saber value-flow",
        "complete_in_function": false,
        "path_constraints": {
          "__omitted__": "max_depth_reached; list_items=2"
        },
        "__compacted__": true
      },
      "__omitted_keys__": {
        "count": 15,
        "keys": [
          "value_flow",
          "source_path",
          "positive_evidence",
          "negative_evidence",
          "evidence_refs",
          "schema",
          "backend_profile",
          "evidence_engines",
          "semantic_overlays",
          "semantic_overlay_evidence",
          "path_kind",
          "candidate_is_conclusion"
        ]
      },
      "__compacted__": true
    }
  }
}
```

与 Deep Worker 的差异：

| 字段 | 与 `deep_worker` 的差异 | 含义 |
|---|---|---|
| `candidate_id` | Analyzer 新增字段 | CandidateLedger 中 Ticket 的规范化 ID。 |
| `status` | Analyzer 新增字段 | Candidate 当前状态。 |
| `defect_class` | Analyzer 新增字段 | CandidateLedger 上移的缺陷分类。 |
| `dedup_key` | Analyzer 新增字段 | Candidate 去重键。 |
| `root_cause_key` | Analyzer 新增字段 | 根因去重键。 |
| `sources` | Analyzer 新增字段 | Candidate 来源标签。 |
| `call_paths` | Analyzer 新增字段 | CandidateLedger 路径摘要。 |
| `duplicate_count` | Analyzer 新增字段 | 合并的重复 Candidate 数。 |
| `canonical_source` | 位置不同 | evidence 内 canonical source 的 ledger 摘要副本。 |
| `canonical_sink` | 位置不同 | evidence 内 canonical sink 的 ledger 摘要副本。 |
| `worker_report_id` | Analyzer 新增字段 | 关联的 Worker report ID。 |
| `ticket` | Analyzer 新增字段 | 原 Ticket 包装对象。 |
| `ticket.id` | Analyzer 新增字段 | 原 Ticket ID。 |
| `ticket.skill` | Analyzer 新增字段 | SVF Candidate 的验证 Skill。 |
| `ticket.line` | Analyzer 新增字段 | 后端报告行。 |
| `ticket.priority_score` | Analyzer 新增字段 | Ticket 调度分数。 |
| `ticket.trigger` | Analyzer 新增字段 | SVF rule 名称。 |
| `ticket.origin` | Analyzer 新增字段 | Ticket 外层 origin。 |
| `ticket.sink` | Analyzer 新增字段 | Ticket 外层 sink。 |
| `ticket.dedup_key` | Analyzer 新增字段 | Ticket 内去重键。 |
| `ticket.sources` | Analyzer 新增字段 | 静态后端信号来源标签。 |
| `ticket.call_paths` | Analyzer 新增字段 | CandidateLedger 路径摘要，不是 SVF value-flow path。 |
| `ticket.task` | Analyzer 新增字段 | SVF Candidate 验证任务。 |
| `ticket.priority_reasons` | Analyzer 新增字段 | 优先级原因列表。 |
| `ticket.resource_kind` | Analyzer 新增字段 | Candidate 资源类型。 |
| `ticket.source` | Analyzer 新增字段 | Candidate 生成器类型 `svf_value_flow`。 |
| `ticket.evidence` | 字段名和位置不同 | 对应 Deep Worker 的 `Structured evidence`。 |
| `ticket.evidence.candidate_id` | 字段名相同、位置不同 | SVF 检查器内部 Candidate ID。 |
| `ticket.evidence.candidate_source` | 字段名相同、位置不同 | 固定为 `svf_value_flow`。 |
| `ticket.evidence.checker` | 字段名相同、位置不同 | SVF checker 名称。 |
| `ticket.evidence.defect_class` | 字段名相同、位置不同 | Candidate 缺陷类型。 |
| `ticket.evidence.rule` | 字段名相同、位置不同 | SVF rule 名称。 |
| `ticket.evidence.source` | 字段名相同、位置不同 | 标准化 source 对象。 |
| `ticket.evidence.source.expression` | 字段名相同、位置不同 | source 函数或 fallback 字符串。 |
| `ticket.evidence.source.file` | 字段名相同、位置不同 | source 报告文件。 |
| `ticket.evidence.source.line` | 字段名相同、位置不同 | source 报告行。 |
| `ticket.evidence.source.__compacted__` | Analyzer 新增字段 | source 对象压缩标记。 |
| `ticket.evidence.sink` | 字段名相同、位置不同 | 标准化 sink 对象。 |
| `ticket.evidence.sink.operation` | 字段名相同、位置不同 | sink 函数或 bug type fallback。 |
| `ticket.evidence.sink.file` | 字段名相同、位置不同 | sink 报告文件。 |
| `ticket.evidence.sink.line` | 字段名相同、位置不同 | sink 报告行。 |
| `ticket.evidence.sink.__compacted__` | Analyzer 新增字段 | sink 对象压缩标记。 |
| `ticket.evidence.path` | 位置相同但内容减少 | Analyzer 只保留浅层 path 信息。 |
| `ticket.evidence.path.function` | 字段名相同、位置不同 | 后端报告所在函数。 |
| `ticket.evidence.path.entry_function` | 字段名相同、位置不同 | 当前分析入口。 |
| `ticket.evidence.path.backend` | 字段名相同、位置不同 | 固定后端说明。 |
| `ticket.evidence.path.complete_in_function` | 字段名相同、位置不同 | 固定为 false 的局部完整性标志。 |
| `ticket.evidence.path.path_constraints` | 内容减少 | Deep Worker 中的完整数组被替换为 `__omitted__`。 |
| `ticket.evidence.path.path_constraints.__omitted__` | Analyzer 新增字段 | 表示 path constraints 因最大深度限制被删除。 |
| `ticket.evidence.path.__compacted__` | Analyzer 新增字段 | path 对象压缩标记。 |
| `ticket.evidence.__omitted_keys__` | Analyzer 新增字段 | 记录被删除 evidence 字段的数量和部分字段名。 |
| `ticket.evidence.__compacted__` | Analyzer 新增字段 | evidence 压缩标记。 |
| `ticket.evidence.value_flow` | Analyzer 减少字段 | 完整后端 value-flow 对象被删除。 |
| `ticket.evidence.value_flow.tool` | 随 `value_flow` 减少 | 后端工具名不可见。 |
| `ticket.evidence.value_flow.svf_group` | 随 `value_flow` 减少 | SVF 分组不可见。 |
| `ticket.evidence.value_flow.svf_groups` | 随 `value_flow` 减少 | SVF 分组列表不可见。 |
| `ticket.evidence.value_flow.bug_type` | 随 `value_flow` 减少 | 后端原始 bug type 不可见。 |
| `ticket.evidence.value_flow.source_func` | 随 `value_flow` 减少 | 后端 source 函数不可见。 |
| `ticket.evidence.value_flow.sink_func` | 随 `value_flow` 减少 | 后端 sink 函数或 fallback 不可见。 |
| `ticket.evidence.value_flow.function` | 随 `value_flow` 减少 | 报告所在函数不可见。 |
| `ticket.evidence.value_flow.file` | 随 `value_flow` 减少 | 报告文件不可见。 |
| `ticket.evidence.value_flow.line` | 随 `value_flow` 减少 | 报告行不可见。 |
| `ticket.evidence.value_flow.function_start` | 随 `value_flow` 减少 | 函数起始行不可见。 |
| `ticket.evidence.value_flow.function_end` | 随 `value_flow` 减少 | 函数结束行不可见。 |
| `ticket.evidence.value_flow.signature` | 随 `value_flow` 减少 | 函数签名不可见。 |
| `ticket.evidence.value_flow.interprocedural` | 随 `value_flow` 减少 | 原跨函数布尔值不可见。 |
| `ticket.evidence.value_flow.backend_path` | 随 `value_flow` 减少 | 后端节点路径不可见。 |
| `ticket.evidence.value_flow.raw_backend_row` | 随 `value_flow` 减少 | 原始后端行不可见。 |
| `ticket.evidence.source_path` | Analyzer 减少字段 | 完整源码级重建对象被删除。 |
| `ticket.evidence.source_path.entry_function` | 随 `source_path` 减少 | 源码重建入口不可见。 |
| `ticket.evidence.source_path.target_function` | 随 `source_path` 减少 | 报告目标函数不可见。 |
| `ticket.evidence.source_path.source_function` | 随 `source_path` 减少 | 重建 source 函数不可见。 |
| `ticket.evidence.source_path.sink_function` | 随 `source_path` 减少 | 重建 sink 函数不可见。 |
| `ticket.evidence.source_path.call_path` | 随 `source_path` 减少 | entry-to-target 调用链不可见。 |
| `ticket.evidence.source_path.complete_to_entry` | 随 `source_path` 减少 | 入口调用链完整性标志不可见。 |
| `ticket.evidence.source_path.reported_location` | 随 `source_path` 减少 | 后端报告源码位置不可见。 |
| `ticket.evidence.source_path.reported_snippet` | 随 `source_path` 减少 | 报告附近代码不可见。 |
| `ticket.evidence.source_path.source_level_flow` | 随 `source_path` 减少 | 源码级 flow 重建对象不可见。 |
| `ticket.evidence.source_path.source_level_flow.source_symbol` | 随 `source_path` 减少 | source symbol 不可见。 |
| `ticket.evidence.source_path.source_level_flow.sink_symbol` | 随 `source_path` 减少 | sink symbol 不可见。 |
| `ticket.evidence.source_path.source_level_flow.object_symbols` | 随 `source_path` 减少 | 对象符号不可见。 |
| `ticket.evidence.source_path.source_level_flow.events` | 随 `source_path` 减少 | 源码级事件不可见。 |
| `ticket.evidence.source_path.source_level_flow.expression_edges` | 随 `source_path` 减少 | 源码级表达式边不可见。 |
| `ticket.evidence.source_path.source_level_flow.complete_source_to_sink` | 随 `source_path` 减少 | source-to-sink 重建完整性不可见。 |
| `ticket.evidence.source_path.source_level_flow.notes` | 随 `source_path` 减少 | 重建备注不可见。 |
| `ticket.evidence.source_path.target_function_context` | 随 `source_path` 减少 | 目标函数代码上下文不可见。 |
| `ticket.evidence.source_path.source_function_context` | 随 `source_path` 减少 | source 函数上下文不可见。 |
| `ticket.evidence.source_path.sink_function_context` | 随 `source_path` 减少 | sink 函数上下文不可见。 |
| `ticket.evidence.source_path.reconstruction_notes` | 随 `source_path` 减少 | 重建缺失项不可见。 |
| `ticket.evidence.positive_evidence` | Analyzer 减少字段 | 支持证据被删除。 |
| `ticket.evidence.negative_evidence` | Analyzer 减少字段 | 验证提醒被删除。 |
| `ticket.evidence.evidence_refs` | Analyzer 减少字段 | 证据引用被删除。 |
| `ticket.evidence.schema` | Analyzer 减少字段 | evidence schema 版本被删除。 |
| `ticket.evidence.backend_profile` | Analyzer 减少字段 | 后端 profile 被删除。 |
| `ticket.evidence.evidence_engines` | Analyzer 减少字段 | engine 清单被删除。 |
| `ticket.evidence.semantic_overlays` | Analyzer 减少字段 | 全局 semantic overlay 被删除。 |
| `ticket.evidence.semantic_overlay_evidence` | Analyzer 减少字段 | Candidate 命中的 overlay evidence 被删除。 |
| `ticket.evidence.path_kind` | Analyzer 减少字段 | 顶层 backend signal 类型被删除。 |
| `ticket.evidence.candidate_is_conclusion` | Analyzer 减少字段 | Candidate 非结论标记被删除。 |
| `ticket.evidence.validation_required` | Analyzer 减少字段 | 验证要求标记被删除。 |
| `ticket.evidence.validation_notes` | Analyzer 减少字段 | 验证备注被删除。 |
| `ticket.evidence.candidate_record` | Analyzer 减少字段 | 完整 Candidate 去重记录被删除。 |

Analyzer 新增的 `ticket.call_paths` 只是 CandidateLedger 路径摘要，不是从 `source_path.call_path` 改名或移动得到的字段，更不是 SVF value-flow path。

### 5.3 `deep_worker` 新字段

```json
{
  "candidate_kind": "svf_value_flow",
  "entry_function": {
    "function_name": "_net_recv_string",
    "file_path": ,
    "start_line": ,
    "end_line": ,
  },
  "target_function": {
    "function_name": "_net_recv_string",
    "file_path": "src/network.c",
    "start_line": 174,
    "end_line": 188,
  },
  "call_path": [
    "_net_recv_string"
    ],
  "suspicious_point":{
    "bug_type": "Partial Memory Leak",
    "line": 175,
  },
  "positive_evidence": [],
  "negative_evidence": [],
  "semantic_evidence": {}
}
```
当前 JSON 对照说明（以本节推荐 JSON 为准）：

| 推荐字段 | 来源或取值方法 | 含义 |
|---|---|---|
| `candidate_kind` | 固定为 `svf_value_flow`。 | 标识证据家族。 |
| `entry_function` | 由原 `source_path.entry_function` 和源码索引组成；空的文件/范围字段需要后续索引补全。 | 源码重建的分析入口。 |
| `target_function` | 由原 `source_path.target_function`、`value_flow.function` 和源码索引组成；不包含函数签名。 | 后端报告位置所在的目标函数。 |
| `function_name` / `file_path` / `start_line` / `end_line` | 分别表示函数名、定义文件和范围；空值只作为未解析占位。 | 结构化函数定位信息。 |
| `call_path` | 由原 `source_path.call_path` 迁入；它是 CodeIndex 调用链，不是 SVF 节点级 value-flow 路径。 | 从入口到目标的静态调用链。 |
| `suspicious_point` | 由原 `value_flow.bug_type` 和报告行号重组。 | 后端报告的待验证信号及其源码锚点。 |
| `suspicious_point.bug_type` | 原 `value_flow.bug_type` 原样迁入，例如 `Partial Memory Leak`。 | 后端使用的原始缺陷信号类型。 |
| `suspicious_point.line` | 原 `value_flow.line` 或 `source_path.reported_location.line`。 | 后端信号对应的报告行，不保证是 source 或 sink 事件。 |
| `positive_evidence` / `negative_evidence` | 沿用原字段。 | 支持和削弱后端信号的证据。 |
| `semantic_evidence` | 由原 `semantic_overlay_evidence` 改名；为空时省略。 | 当前 Candidate 实际命中的语义补充。 |

当前 JSON 没有 `backend_flow`、`source_reconstruction`、`backend_path_available`、`entry_call_chain_found` 或 `source_to_sink_complete` 字段；这些名称属于此前的扩展设计，不应继续作为本 JSON 的字段要求。若后续重新引入它们，必须在 JSON 中实际出现后再按对应后端事实填值，不能仅由 `call_path` 或报告行号推断。

### 5.4 `vulnerability_analyzer` 新字段

以下 JSON 暂复制自本章第三节“新字段”，作为后续设计占位：

```json
{
  "candidate_id": "CAND_9398dab24e7a",
  "candidate_kind": "svf_value_flow",
  "entry_function": {
    "function_name": "_net_recv_string",
    "file_path": ,
    "start_line": ,
    "end_line": ,
  },
  "target_function": {
    "function_name": "_net_recv_string",
    "file_path": "src/network.c",
    "start_line": 174,
    "end_line": 188,
  },
  "call_path": [
    "_net_recv_string"
    ],
  "suspicious_point":{
    "bug_type": "Partial Memory Leak",
    "line": 175,
  },
  "positive_evidence": [],
  "negative_evidence": [],
  "semantic_evidence": {},
  "priority_score": 66,
  "priority_reasons": [
      "svf_value_flow",
      "memory_leak",
      "rule_confidence=0.76"
    ],
}
```
相比`deep_worker`，增加`candidate_id`，`priority_score`和`priority_reasons`。