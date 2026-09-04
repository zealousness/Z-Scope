# ValidatorEvidenceSlice v3 设计建议

本文从大模型推理上下文的角度分析 `ValidatorEvidenceSlice v2`，不讨论 UID、hash、version 等字段对 CandidateLedger、缓存、报告关联和审计系统的内部价值。核心问题是：一个字段是否包含 LLM 可以直接消费、并会实际改变验证结论的程序语义。

分析样本为：

- 会话：`/home/jager/Z-Scope-benchmark/test/range/.zscope_conversations/run_20260810_113158_1355930/zscope-validator-0-validator_agent-0001`
- Candidate：`CAND_7929fabdcd425d114cd543ac`
- Candidate 来源：`clang_ast_cfg`
- 缺陷类型：`memory_leak`
- 目标函数：`_net_handle_error`
- 位置：`src/network.c:206`

该 Candidate 的核心假设是：`error_msg` 在 191 行由 `_safe_malloc` 分配，成功路径到达 206 行返回时未见释放。入口 `td_report_network_error` 通过调用路径 `td_report_network_error -> _net_handle_error` 到达该函数。

本文使用以下必要性标记：

| 标记 | 含义 |
|---|---|
| LLM 必须 | 直接提供程序事实、待验证假设、路径、代码或未解决反证，应发送给模型。 |
| 条件保留 | 只在非空且能改变当前 Candidate 结论时发送。 |
| 移出 Prompt | 系统内部有关联、缓存、去重或审计用途，但对模型推理没有语义价值。 |
| 删除或合并 | 与其他字段重复，或字段表达会造成错误暗示。 |

## 一、 原始字段

### 1.1 ValidatorEvidenceSlice v2 原始 JSON

以下是 `zscope-validator-0-validator_agent-0001` 中模型实际收到的 Slice。代码内容保持原样，长 UID 和 hash 也保留，以展示当前 Prompt 的真实组成。

```json
{
    "schema_version": "zscope.validator-evidence-slice.v2",
    "protocol_version": "zscope.validator-protocol.v2",
    "obligation": {
        "candidate_uid": "CAND_7929fabdcd425d114cd543ac",
        "validation_cluster_uid": "VAL_0073dc7a203e521e9d520fee879f369f",
        "obligation_uid": "OBL_c0c6024278ca04d1ff96d820c1bae13f",
        "defect_family": "memory_leak",
        "obligation_shape": "source_centric",
        "subject_uid": "{\"expression\":\"_safe_malloc(...)atline191\",\"file\":\"src/network.c\",\"line\":\"191\"}",
        "source_uid": "{\"expression\":\"_safe_malloc(...) at line 191\",\"file\":\"src/network.c\",\"line\":\"191\"}",
        "sink_uid": "{\"file\":\"src/network.c\",\"line\":\"206\",\"operation\":\"return error_code;\"}",
        "function": "_net_handle_error",
        "location": "src/network.c:206",
        "category": "memory_leak",
        "subcategory": "memory_leak",
        "cwe": "CWE-401"
    },
    "canonical_occurrence": {
        "occurrence_uid": "OCC_5ded503fcd1a11a47b22897e",
        "entry_identity": "src/main.c::int td_report_network_error(int error_code)",
        "reachable_from_entry": true,
        "representative_call_path": [
            "td_report_network_error",
            "_net_handle_error"
        ]
    },
    "decision_facts": {
        "version": "zscope.decision-facts.v1.2",
        "coverage": "complete",
        "fact_uids": [
            "FACT_0f2af7ff8f56252aa2f6931320c35888",
            "FACT_0f2f301708c0b857dd9a5a214f409863",
            "FACT_1d0b4945a535472fe343d4f14edd8ee7"
        ],
        "edge_uids": [],
        "dependency_code_hashes": [
            "SNAP_0a4a9bbbf2e1addad200adcfafbbb9ea1238c43c4fc0f4e312f27464fc0bd5e7"
        ],
        "missing_fact_kinds": [],
        "deterministic_proofs": []
    },
    "evidence": {
        "source": "_safe_malloc(...) at line 191",
        "sink": "return error_code;",
        "positive": [
            "line 191: `error_msg` acquired from `_safe_malloc` (return value)",
            "line 206: return edge without a matching release in this function",
            "Entry `td_report_network_error` reaches internal sink `_net_handle_error` through call path `td_report_network_error -> _net_handle_error`."
        ],
        "negative": [
            "Validator must confirm whether ownership is transferred outside this local body."
        ],
        "path_constraints": []
    },
    "code": {
        "function_context": "190 | int _net_handle_error(int error_code) {
        191 |     char* error_msg = (char*)_safe_malloc(256);
        192 |     if (!error_msg) {
        193 |         return -1;
        194 |     }
        195 |
        196 |     snprintf(error_msg, 256, \"Network error occurred: %d\", error_code);
        197 |     LOG_ERROR(\"%s\", error_msg);
        198 |
        199 |     if (error_code == ENOMEM) {
        200 |         char* recovery_buffer = (char*)_safe_malloc(1024);
        201 |         if (recovery_buffer) {
        202 |             strcpy(recovery_buffer, \"recovery\");
        203 |         }
        204 |     }
        205 |
        206 |     return error_code;
        207 | }
        ",
        "location_snippet": {
            "file": "src/network.c",
            "start_line": 194,
            "end_line": 207,
            "code": "194 |     }
            195 |
            196 |     snprintf(error_msg, 256, \"Network error occurred: %d\", error_code);
            197 |     LOG_ERROR(\"%s\", error_msg);
            198 |
            199 |     if (error_code == ENOMEM) {
            200 |         char* recovery_buffer = (char*)_safe_malloc(1024);
            201 |         if (recovery_buffer) {
            202 |             strcpy(recovery_buffer, \"recovery\");
            203 |         }
            204 |     }
            205 |
            206 |     return error_code;
            207 | }
            "
        }
    },
    "alias_summary": {
        "occurrence_count": 1,
        "alias_count": 0,
        "alias_uid_set_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    },
    "validation_requirements": [
        "Treat every candidate as evidence only; do not accept it solely because a regex, graph, or backend rule emitted it.",
        "Independently audit semantic overlay assumptions from user_config, including custom alloc/free/lock/macros and pointer target models.",
        "Return verdict=verified only if there is a concrete public/API or caller-controlled trigger path.",
        "Return verdict=rejected when local evidence or guards disprove the candidate.",
        "Return verdict=uncertain only when the candidate is plausible but decisive context is missing.",
        "Identify source, sink, source controllability, and the missing/insufficient guard.",
        "Reject hardening/style/theoretical findings without a source-to-sink path.",
        "For integer overflow, multiplication/addition must be checked before the operation or by a proven bounded operand.",
        "When this evidence pack names a current analysis entry, treat that configured/header-discovered entry as the public trigger for internal callee findings.",
        "The current_analysis_entry is the root selected for this scan. It is normal for a header/configured root to have zero repository callers, to be absent from main, or to have no separate worker/start wrapper; do not use those facts alone as dead-code evidence.",
        {
            "omitted_items": 9
        }
    ]
}
```

### 1.2 原始字段分组

当前 Slice 将三类信息放在同一个模型输入对象中：

1. 推理数据：缺陷假设、代码、调用路径、正反证据。
2. 控制面数据：Candidate、Occurrence、Validation Cluster、Fact 和 Snapshot 的内部身份。
3. 协议与策略数据：schema、protocol、通用验证规则、alias 摘要和截断元数据。

问题不只是字段多。控制面数据与推理数据混合后，模型可能把 `coverage=complete`、多个 `FACT_*` 和代码 hash 误解为漏洞证据已经闭合，即使 `deterministic_proofs=[]` 且 `negative` 仍要求确认 ownership transfer。

## 二、 重复与必要性分析

### 2.1 消融结果

使用项目当前 `LLMClient.estimate_tokens()` 对第一章 JSON 进行估算：

| 输入版本 | 字符数 | 估算 tokens | 相对原始 Slice 减少 |
|---|---:|---:|---:|
| 原始 Slice | 4,493 | 1,182 | 0% |
| 删除 UID、hash、version 和 alias | 3,429 | 902 | 23.7% |
| 再删除重复的 `validation_requirements` | 2,154 | 566 | 52.1% |
| 再删除本例重复字段 | 1,483 | 390 | 67.0% |

该轮共有 183 次 Validator 调用。如果其他会话具有相近结构，按本例外推，精简 Slice 可能减少约 14.5 万 prompt tokens。该数字是单样本估算，只用于判断字段优化量级。

### 2.2 顶层版本字段

| 原始字段 | 必要性 | 分析 |
|---|---|---|
| `schema_version` | 移出 Prompt | 由调用代码选择 v2/v3 构造器和解析器。模型不需要根据版本选择行为。 |
| `protocol_version` | 移出 Prompt | `_run_evidence_slice_protocol()` 已决定协议。应保留在请求 envelope、trace 和缓存键中。 |

### 2.3 `obligation`

| 原始字段 | 必要性 | 分析 |
|---|---|---|
| `candidate_uid` | 移出 Prompt | 只用于结果回写和 trace 关联。模型输出可由当前 session 自动绑定 Candidate。 |
| `validation_cluster_uid` | 移出 Prompt | 用于全局 validation group、缓存和重复调用合并。LLM 无法从 UID 获取语义。 |
| `obligation_uid` | 移出 Prompt | 用于结构化安全义务的内部身份，不参与当前漏洞推理。 |
| `defect_family` | LLM 必须 | 决定应验证 memory leak、race、bounds、UAF 等哪一种安全性质。 |
| `obligation_shape` | 删除或合并 | `source_centric` 是内部 grouping 术语。若需约束模型，应改写为自然语义的 `claim` 或 `decision_scope`。 |
| `subject_uid` | 移出 Prompt | 是 JSON 字符串化的资源 identity，与 `evidence.source` 和代码重复。当前值还存在空格规范化差异。 |
| `source_uid` | 移出 Prompt | 用于稳定 identity；对模型而言是 `source` 的冗长重复。 |
| `sink_uid` | 移出 Prompt | 用于稳定 identity；对模型而言是 `sink` 和 location 的冗长重复。 |
| `function` | LLM 必须 | 确定需要审计的函数。 |
| `location` | LLM 必须 | 提供主报告位置和代码锚点。 |
| `category` | 删除或合并 | 与 `defect_family` 相同，应只保留一个统一字段。 |
| `subcategory` | 条件保留 | 只有细分类能改变验证要求时保留；本例与 `defect_family` 完全相同。 |
| `cwe` | 移出 Prompt | 用于报告、SARIF 和标准分类。通常不帮助模型判断具体代码事实。 |

### 2.4 `canonical_occurrence`

| 原始字段 | 必要性 | 分析 |
|---|---|---|
| `occurrence_uid` | 移出 Prompt | 只用于 occurrence 审计和 primary/alias 关联。 |
| `entry_identity` | 删除或合并 | 与 `representative_call_path[0]` 重复。若签名用于消歧，应只保留一个紧凑 `entry` 对象。 |
| `reachable_from_entry` | 条件保留 | 只有该值来自可信调用图事实时有意义。若已有完整 `call_path`，布尔值可以由路径推导。 |
| `representative_call_path` | LLM 必须 | 支撑内部 Sink 的入口可达性，但不能自动证明攻击者控制或可重复触发。 |

本例中，调用路径只证明 `td_report_network_error` 可以调用 `_net_handle_error`。模型进一步声称攻击者可以制造网络错误并控制泄漏频率，但 Slice 未提供调用者代码或入口契约，因此该结论超出了输入证据。

### 2.5 `decision_facts`

| 原始字段 | 必要性 | 分析 |
|---|---|---|
| `version` | 移出 Prompt | 只影响事实缓存和兼容性。 |
| `coverage` | 删除或重构 | `complete` 只表示所要求的 fact kind 已收集，不表示漏洞 proof 完整。单独发送容易形成错误确定性。 |
| `fact_uids` | 移出 Prompt | UID 不包含事实内容。应向模型发送规范化 fact，而不是 fact handle。 |
| `edge_uids` | 移出 Prompt | 同上。若关系会改变结论，应发送具体 source/relation/target。 |
| `dependency_code_hashes` | 移出 Prompt | 仅用于代码版本、缓存失效和审计。 |
| `missing_fact_kinds` | 条件保留并改名 | 应改为具体、可执行的 `unresolved_facts`。空数组不必发送。 |
| `deterministic_proofs` | 条件保留并压缩 | 非空 proof 可能直接改变结论，但只需发送 outcome、proof kind、summary 和关键事实，不发送 proof version、fact IDs 或 code hash。 |

本例的 `coverage=complete`、`missing_fact_kinds=[]` 与以下事实不一致：

- `deterministic_proofs=[]`，没有可直接关闭 Candidate 的 proof。
- `negative` 明确要求确认 ownership transfer。
- Slice 没有 `LOG_ERROR` 的 ownership contract。

因此 v3 不应向模型发送抽象 completeness 标签，而应发送实际已知事实和实际未解决事实。

### 2.6 `evidence`

| 原始字段 | 必要性 | 分析 |
|---|---|---|
| `source` | LLM 必须 | 用自然语言标识分配、输入或状态来源。 |
| `sink` | LLM 必须 | 标识返回、写入、释放或危险调用。 |
| `positive` | LLM 必须但应结构化 | 当前三条内容有效，但 acquire、exit 和 call path 应转成结构化事实，减少自然语言重复。 |
| `negative` | LLM 必须 | 表示尚未关闭的反证风险。本例 ownership transfer 是决定 verdict 的关键。 |
| `path_constraints` | 条件保留 | 仅在非空且与 source-to-sink 可行性有关时发送。空数组删除。 |

### 2.7 `code`

| 原始字段 | 必要性 | 分析 |
|---|---|---|
| `function_context` | LLM 必须 | 是模型独立核验 acquire、use、branch 和 exit 的主要实体证据。 |
| `location_snippet` | 条件保留 | 本例与 `function_context` 大量重复。仅当函数被截断、位置跨函数，或 snippet 包含额外依赖代码时发送。 |

当前代码仍不足以严格关闭 ownership transfer：`LOG_ERROR` 的定义和 contract 不在 Slice 中。模型基于“日志宏通常不获取所有权”给出 `verified`，属于常识推断而不是输入中的程序事实。

### 2.8 `alias_summary`

| 原始字段 | 必要性 | 分析 |
|---|---|---|
| `occurrence_count` | 移出 Prompt | occurrence 数量不应改变漏洞真假。 |
| `alias_count` | 移出 Prompt | alias 数量可能形成“重复出现所以更可信”的锚定偏差。 |
| `alias_uid_set_hash` | 移出 Prompt | 只用于审计 commitment，模型无法消费。 |

整个 `alias_summary` 应保留在请求 envelope 和最终报告中，不发送给模型。

### 2.9 `validation_requirements`

`validation_requirements` 应从 Slice 中删除。通用三态判定规则、source/sink/guard 要求、入口可达性规则已经存在于 Validator system prompt，再发送一次只会重复上下文。

本例还包含与 memory leak 无关的 integer overflow 规则，并通过 `{"omitted_items": 9}` 告知模型还有九条未展示规则。该截断对象不提供可执行语义，反而会增加不确定性。

建议：

- 通用规则只保留在 system prompt。
- 类别专用规则按 `defect_family` 动态选择，只发送与当前 Candidate 有关的少量 delta。
- 规则截断和 omitted count 只写入 telemetry，不进入模型输入。

## 三、 validation_requirements

### 3.1 生成与发送路径

系统首先调用 _base_validation_requirements() 生成 14 条通用规则，再根据 Candidate 的 defect_class、subcategory 或 category 调用 category_validation_requirements() 追加类别专属规则：

~~~python
validation_requirements = _base_validation_requirements()
validation_requirements.extend(category_validation_requirements(issue))
~~~

类别匹配按 defect_class -> subcategory -> category 的顺序取第一个非空值，将连字符替换为下划线并转成小写，然后与规则表的 key 做精确匹配。没有继承、前缀匹配或 defect family 回退；未命中时不追加专属规则。

完整规则列表写入内部 evidence pack 后，ValidatorEvidenceSlice v2 又执行以下压缩：

~~~python
"validation_requirements": _compact_validation_value(
    pack.get("validation_requirements") or [],
    max_list_items=10,
    max_string_chars=1000,
)
~~~

因此只有列表前 10 项和一个 omitted_items 标记进入 LLM。

### 3.2 完整的通用 validation_requirements

通用规则共 14 条，原文如下：

1. Treat every candidate as evidence only; do not accept it solely because a regex, graph, or backend rule emitted it.
2. Independently audit semantic overlay assumptions from user_config, including custom alloc/free/lock/macros and pointer target models.
3. Return verdict=verified only if there is a concrete public/API or caller-controlled trigger path.
4. Return verdict=rejected when local evidence or guards disprove the candidate.
5. Return verdict=uncertain only when the candidate is plausible but decisive context is missing.
6. Identify source, sink, source controllability, and the missing/insufficient guard.
7. Reject hardening/style/theoretical findings without a source-to-sink path.
8. For integer overflow, multiplication/addition must be checked before the operation or by a proven bounded operand.
9. When this evidence pack names a current analysis entry, treat that configured/header-discovered entry as the public trigger for internal callee findings.
10. The current_analysis_entry is the root selected for this scan. It is normal for a header/configured root to have zero repository callers, to be absent from main, or to have no separate worker/start wrapper; do not use those facts alone as dead-code evidence.
11. When entry_is_external_root is true and reachable_from_entry/call_path evidence connects the entry to the sink, validate triggerability from an external invocation of the entry and its parameters, task payload, received bytes, or callback contract; do not require an additional repository-internal caller above the entry.
12. Do not reject an internal callee solely because its direct caller list is empty; rely on entry exposure and call-path evidence instead.
13. If reachable_from_entry, complete_to_entry, call_path, or entry_function evidence is present, reject reachability only when code evidence disproves that specific path.
14. If the only negative reachability evidence is zero callers for current_analysis_entry, absence from main, or absence of a worker creator, choose uncertain instead of rejected unless code disproves the entry-to-sink path.

第 8 条只适用于 integer overflow，却被放在通用规则中，导致所有 defect class 都接收无关约束。

### 3.3 完整的 defect-class 专属 validation_requirements

代码当前覆盖 38 个精确类别、共 55 条专属规则。

#### signed_unsigned

1. For signed/unsigned conversion, a negative signed return cast to size_t before a copy/IO length is a concrete sink when the pre-cast value is not checked.
2. A post-cast warning or truncation log is not a sufficient guard if the dangerous copy/IO still executes.

#### integer_overflow

1. For serialized/wire lengths, header-size addition and allocation/copy-size arithmetic require an explicit overflow or backing-buffer bound check.

#### object_publication

1. For object publication, a pointer stored in a global/list/callback slot or ready flag set before member initialization is security-relevant if readers can observe the partially initialized object.
2. Do not reject solely because the same function later initializes fields; compare publication order with reader visibility.

#### memory_leak

1. Freeing a wrapper object does not release nested owned members, child lists, duplicated strings, mutexes, or role-specific resources unless code shows that cleanup explicitly.
2. A role-specific release helper only proves cleanup for the role it actually receives; compare stored role and release argument.
3. If the candidate names a member/child allocation as the leaked resource, do not reject it merely because the parent container is freed.
4. If an insert/link helper can attach an object to a global structure and then return failure, an ignored return value can lose rollback and cleanup ownership; global reachability alone does not prove a valid cleanup protocol.
5. Do not reinterpret a negative helper return as success unless a documented or enforced contract proves that negative status is an expected non-failure mode.

#### infinite_loop

1. For poisoned/self-linked list nodes, evaluate concurrent or stale iterators that may already hold the node before unlink; a fresh traversal from the current head is not sufficient to disprove the loop.
2. A self-link used as a poison marker needs a visible traversal guard; otherwise any walker that follows next pointers can spin on the same node.

#### log_amplification

1. A self-referential or poisoned traversal with a loop-internal log/error emission can be a resource-exhaustion defect even without memory corruption.
2. For traversal findings, consider stale/current iterator state and concurrent mutation paths, not only whether a fresh traversal from the head reaches the node.

#### race

1. Macro-guarded locks must be evaluated under all configured compilation branches; a no-op lock branch does not protect shared state.

#### reader_state_race

1. For reader-state races, atomic reader-count operations do not protect side fields such as reader identity unless that side field is also atomic or protected by the rwlock protocol.

#### global_mode_race

1. For global-mode races, registration, mode selection, and callback dispatch must be protected by a common lock or immutable mode snapshot.

#### registration_race

1. For registration races, a pre-lock check of a global slot/list followed by a later locked update is still a race; validation must require one lock covering check and update.

#### key_generation_race

1. For ftok-style key generation, path existence/state checks and key derivation/registration must be atomic with respect to path changes or use a stable opened object.

#### slot_race

1. For slot-claim races, an ignored CAS/compare-exchange result is a concrete bug when field writes continue after a failed claim could leave the slot owned by another thread.

#### shared_memory_race

1. For create-if-absent shared resources, lookup and insertion must be atomic under the same lock; a pre-lock lookup is not sufficient.

#### callback_self_destroy_race

1. For callback self-destruction, validate whether the callback receives the current object as context and can release it before the caller resumes dereferencing it.

#### premature_destroy

1. For premature-destroy findings, freeing a shared pool/object while an active task/refcount branch says users remain is a concrete lifetime bug unless the code first waits, refcounts, or marks all users stopped.
2. Publishing a global/shared pointer and then freeing that same global object in the active-user branch leaves a dangling shared reference even if allocation happened in the same function.

#### alloc_free_mismatch

1. For allocator/free mismatch, allocation and release callbacks must be registered and selected as a validated pair; a no-op/free callback paired with a custom/header allocator is not safe by type compatibility alone.

#### sigpipe_unhandled

1. For peer writes, write/send paths to sockets or peer fds need SIGPIPE suppression or handling; checking the negative return value is insufficient if the process can receive SIGPIPE first.

#### lost_wakeup

1. For wakeup bugs, publishing an event/list node is not enough; require a signal, trigger, scheduler kick, or documented polling guarantee for the consumer.

#### signal_deadlock

1. For signal/exception handlers, locks, semaphores, formatting, and logging are unsafe when the path can run asynchronously or re-enter code holding the same primitive.

#### signal_race

1. For signal/exception handlers, allocation, logging, and writes to shared global state are unsafe unless the code uses an async-signal-safe handoff such as writing minimal data to a pipe or atomic flag.
2. Do not reject signal shared-state findings solely because writes are local to the handler; the handler can asynchronously interleave with normal code that owns or reads the same global state.

#### held_lock_callback

1. Calling a callback/function pointer while holding a non-recursive lock is a lock-order and reentrancy risk when the callback is externally supplied, stored globally, or can evolve independently of the current no-op sample.
2. Do not reject solely because the currently registered callback body is empty; validate the callback registration contract and whether callers control the callback.

#### alignment

1. Casting byte-buffer offsets such as packet + 1 to integer pointers is undefined behavior on strict-alignment targets and can be security-relevant when reachable from an external parsing API.
2. Do not reduce unaligned dereference to a style issue solely because one wrapper currently passes a local buffer; validate the exposed parser contract and callee signature.

#### unchecked_return

1. Returning success from a classifier/probe branch after a lower-level error or ambiguous status is a concrete contract bug when callers use zero as success.

#### state_inconsistency

1. For state restoration, saving `previous` is not a guard unless the changed state is restored on every failure path before return.
2. A later assignment like `previous = state` is not restoration; require `state = previous` before the failure return.

#### fd_type_mismatch

1. Reliable/encoded descriptors and raw file descriptors are distinct API contracts; passing one representation to the other validator is a concrete misuse even if both are integers.
2. A representation mismatch remains valid when the raw-fd helper fails closed or rejects the encoded value; the issue is the reachable API-contract break and lost descriptor operation, not only memory corruption.

#### protocol_mixup

1. Protocol mismatch accepted on a non-strict/auth fallback is a boundary validation issue, not a harmless style choice.

#### version_filtering

1. Parsing a protocol version and explicitly ignoring it means low/unsupported versions can reach state processing unless another guard proves otherwise.

#### size_limit_mismatch

1. When a byte cache limit and an element-count specification are both present, validate whether the computed byte limit can reject or mis-size values that the public count contract says are valid.

#### busy_loop

1. For receive/read retry loops, EAGAIN/EINTR handling needs a timeout, retry budget, blocking wait, or caller-visible failure; a bare continue can be a resource-exhaustion path.

#### dynamic_array_race

1. For global dynamic array resizing, the capacity check, new allocation, global pointer publish, capacity update, and old-array free must be protected by the same lock or atomic handoff.

#### fd_encoding_mismatch

1. Raw fd indexes must not be passed to validators expecting encoded/check-value fds unless code constructs the encoded representation first.
2. Do not reject solely because the mixed representation fails closed in one local branch; the finding is the reachable API-contract mismatch between raw fd indexes and encoded/check-value fd validators.

#### semantic_mismatch

1. For semantic-contract mismatches, type compatibility is not enough; compare the unit/domain promised by the caller with the callee's documented or inferred contract.
2. A callee parameter name, accumulator field, threshold, or downstream side effect can establish the expected unit even when the C type is only int.

#### byte_order_logic

1. For byte-order logic, copying wire bytes into host integers and using bit-index operations requires explicit endian normalization or a byte-order-independent scan.
2. If the computed byte/bit offset influences a later decision, index, copy, or status value, treat the host-order-dependent offset as a concrete semantic sink.

#### uninitialized_output

1. For output-parameter structs, require memset/zero initialization or assignments for all externally visible fields before copying the temporary object to the caller.

#### file_type_validation

1. For mapping/file validation, regular files, character devices, shared memory, and anonymous mappings can require different size/existence checks.

#### log_level_misuse

1. For log-level findings, verify that the branch represents a normal/idempotent state and returns success; ERROR logs in such paths can create alert pollution rather than a functional failure.

#### logic_error

1. For traversal logic errors, compare the index used to select a parent/group object with the index used to access the member; cached traversal state can go stale across loop iterations.

#### state_machine

1. For state-machine findings, every successful publication branch must transition the shared lifecycle state consistently with the identity/data fields it publishes.

### 3.4 发现的问题

#### 3.4.1 列表顺序与截断共同导致专属规则失效

内部列表先放 14 条通用规则，再追加专属规则，但 v2 只保留前 10 项。因此：

- 通用规则第 11～14 条始终不可见。
- 所有 defect-class 专属规则始终不可见。
- LLM 只看到 omitted_items 数量，无法知道被省略规则的内容。

样本 zscope-validator-0-validator_agent-0001 是 memory_leak，内部应有 14 条通用规则和 5 条专属规则，共 19 条；实际只发送前 10 条通用规则和 {"omitted_items": 9}。

对指定运行的 183 个 ValidatorEvidenceSlice v2 逐一检查，结果全部如此：

| 实际现象 | Slice 数 |
|---|---:|
| validation_requirements 长度为 11，即 10 条文本加一个 omitted marker | 183 |
| 第一项是固定通用规则 | 183 |
| omitted 4 项，即没有命中专属规则 | 69 |
| omitted 5 项，即内部有 1 条专属规则 | 52 |
| omitted 6 项，即内部有 2 条专属规则 | 14 |
| omitted 9 项，即内部有 5 条专属规则 | 48 |
| 实际看到任意专属规则 | 0 |

这不是单纯的 Prompt 压缩问题，而是功能性错误：代码维护了 55 条专属规则，但 v2 序列化路径使其全部成为死配置。

#### 3.4.2 通用规则与 system prompt 重复

通用规则中的三态 verdict、source/sink/guard、入口可达性和拒绝 hardening finding 等要求，已经存在于 Validator system prompt。相同策略在 system message 和 Slice user message 中重复，增加 token 成本，也使未来规则更新可能出现两个版本不一致。

#### 3.4.3 通用列表混入类别专属规则

通用规则第 8 条只讨论 integer overflow，却发送给 memory leak、race、lifetime、protocol 等所有 Candidate。它既制造无关噪声，又占用了仅有的 10 个可见位置，应移动到 integer_overflow 专属规则。

#### 3.4.4 omitted marker 对推理没有帮助

{"omitted_items": N} 只能说明存在未发送内容，不能告诉模型缺少什么约束。模型无法执行这些规则，却可能因为“有规则被省略”产生不必要的不确定性。该计数最多属于 telemetry，不应进入推理载荷。

#### 3.4.5 精确字符串匹配缺少类别继承

专属规则只按一个规范化字符串精确匹配。例如一个未列入表的 data_race 不会继承 race 规则；新的 memory/resource lifecycle 子类也不会自动继承 memory_leak 规则。规则适用关系隐藏在命名约定中，容易因 detector 新增类别而静默失效。

#### 3.4.6 部分规则预设结论而非提出核验问题

多条专属规则使用 “is a concrete bug”“remains valid” 等结论性措辞。这会给模型形成确认偏差。Validator policy 更适合描述必须核验的判定条件和反证条件，而不是预先宣布 Candidate 成立。

## 四、 建议的新字段

### 4.1 控制面与推理面分离

Validator 调用应拆成外层 `ValidatorRequestEnvelope` 与内层 `reasoning_payload`。外层不序列化进 LLM user message。

```json
{
  "schema_version": "zscope.validator-request.v3",
  "protocol_version": "zscope.validator-protocol.v3",
  "candidate_uid": "CAND_7929fabdcd425d114cd543ac",
  "validation_cluster_uid": "VAL_0073dc7a203e521e9d520fee879f369f",
  "obligation_uid": "OBL_c0c6024278ca04d1ff96d820c1bae13f",
  "occurrence_uid": "OCC_5ded503fcd1a11a47b22897e",
  "fact_uids": ["FACT_..."],
  "dependency_code_hashes": ["SNAP_..."],
  "alias_summary": {
    "occurrence_count": 1,
    "alias_count": 0,
    "alias_uid_set_hash": "e3b0c442..."
  },
  "policy_version": "zscope.validator-focus-policy.v1",
  "projection_telemetry": {
    "fact_count_total": 3,
    "fact_count_sent": 3,
    "fact_count_omitted": 0
  },
  "reasoning_payload": {}
}
```

外层字段继续服务：

- Candidate 和 occurrence 结果回写。
- validation group 合并和缓存。
- 代码版本与 fact graph 一致性检查。
- alias commitment 和报告审计。
- 协议版本选择与迁移。

### 4.2 建议发送给 LLM 的 v3 字段

```json
{
  "defect_class": "memory_leak",
  "validation_focus": [
    "Verify whether the acquired resource is released on every reachable exit.",
    "Verify whether ownership is transferred to a specific durable owner or callee.",
    "Treat parent cleanup as sufficient only when code or a contract shows that it releases the named child resource."
  ],
  "entry_function": {
    "function_name": "td_report_network_error"
  },
  "call_path": [
    "td_report_network_error",
    "_net_handle_error"
  ],
  "facts": [
    {
      "kind": "acquire",
      "subject": "error_msg",
      "api": "_safe_malloc",
      "line": 191
    },
    {
      "kind": "exit",
      "line": 206
    }
  ],
  "evidence": {
    "source": "_safe_malloc(...) at line 191",
    "sink": "return error_code;",
    "positive": [
      "line 191: `error_msg` acquired from `_safe_malloc` (return value)",
      "line 206: return edge without a matching release in this function",
      "Entry `td_report_network_error` reaches internal sink `_net_handle_error` through call path `td_report_network_error -> _net_handle_error`."
    ],
    "negative": [
      "Validator must confirm whether ownership is transferred outside this local body."
    ]
  },
  "target_function_metadata": {
    "func_name": "_net_handle_error",
    "index_name": "_net_handle_error@src/network.c:190-207",
    "file_path": "src/network.c",
    "start_line": 190,
    "end_line": 207,
    "signature": "int _net_handle_error(int error_code)",
    "is_static": true,
    "is_macro": false,
    "project_callees": [],
    "external_callees": [],
    "referenced_globals": [],
    "referenced_macros": [],
    "referenced_types": []
  },
  "target_function_code": "190 | int _net_handle_error(int error_code) {\n191 |     char* error_msg = (char*)_safe_malloc(256);\n...\n206 |     return error_code;\n207 | }"
}
```

### 4.3 新字段说明

| 推荐字段 | 来源 | 作用 |
|---|---|---|
| validation_focus | 从当前 defect policy 选择的语义增量 | 只发送当前缺陷类别需要额外核验的事实、充分条件和反证条件；通用三态规则仍只保留在 system prompt。 |
| `defect_class` | 原 `obligation.defect_family`，必要时回退到 `category` 或 `subcategory` | 指明当前需要验证的缺陷类别，使模型选择对应的安全判断标准。相同语义只保留一个字段。 |
| `target_function_metadata` | Semantic Modeler user content 中的 `Target function metadata` | 原样嵌套 Semantic Modeler 的目标函数 identity、callee、global、macro、type、unresolved 和 truncation 上下文；v3 删除原 `target_function`，不再维护第二套目标函数描述。 |
| `target_function_metadata.func_name`、`file_path`、`start_line`、`end_line`、`signature` | `build_semantic_model_input()` | 定位 Candidate 函数及其完整签名和源码范围。 |
| `target_function_metadata.index_name`、`is_static`、`is_macro` | Semantic Modeler metadata 投影 | 与 Semantic Modeler 保持同一结构；`index_name` 仅用于消歧，不能作为漏洞证据。 |
| `target_function_metadata.project_callees`、`external_callees`、`unresolved_callees` | canonical function info 与 callee snapshot hydration | 提供调用依赖和已知 callee 摘要；空数组不证明不存在间接行为。 |
| `target_function_metadata.referenced_globals`、`referenced_macros`、`referenced_types`、`unresolved_referenced_types` | canonical function info | 提供代码所引用的符号和类型上下文。 |
| `target_function_metadata.*_truncation` | Semantic Modeler metadata 投影 | 明确相应集合是否被截断；truncation marker 只描述上下文覆盖，不表达 verdict。 |
| `entry_function` | 原 `canonical_occurrence.entry_identity` | 描述当前扫描入口；仅保留可理解的函数与位置，不发送 occurrence UID。 |
| `entry_function.function_name` | 从 entry identity 提取的函数名 | 表示外部入口或当前分析根，用于理解 Candidate 的触发起点。 |
| `entry_function.file_path` | entry identity 或入口函数快照 | 定位入口函数所在文件；无法可靠确定时省略。 |
| `entry_function.start_line` | 入口函数定义或入口代码片段的起始行 | 条件字段，仅在提供入口代码或需要精确定位时发送。 |
| `entry_function.end_line` | 入口函数定义或入口代码片段的结束行 | 条件字段，与 `start_line` 一起限定入口函数范围。 |
| `call_path` | 原 `canonical_occurrence.representative_call_path` | 表示从 `entry_function` 到 `target_function_metadata.func_name` 的代表性调用路径，支撑入口可达性判断。 |
| `facts[]` | 从 DecisionFact 实体投影 | 向模型发送事实内容，不发送 fact UID。 |
| `facts[].kind` | DecisionFact kind | 表示 acquire、release、guard、exit、lockset、HB 等事实类型。 |
| `facts[].subject` | DecisionFact subject | 明确事实作用的变量、资源或状态对象，避免不同 field 或资源混淆。 |
| `facts[].api` | acquire/release/call fact | 标识相关 API；不适用时省略。 |
| `facts[].line` | fact source location | 让模型与代码逐行核对。 |
| `missing_fact_kinds` | 原 `decision_facts.missing_fact_kinds` 经 Validator fact-kind 归一化 | 列出当前结构化事实图未覆盖、且可能改变 verdict 的事实类型。无缺项时省略。 |
| `deterministic_proofs` | 原 `decision_facts.deterministic_proofs` | 携带尚需模型结合上下文审查的确定性 proof。已能在 prevalidation 阶段独立闭合结论的 proof 不应进入 LLM；无此类 proof 时省略。 |
| `evidence` | 原 `evidence` | 汇总 Candidate 生成器提供的可读证据，作为结构化 facts 与代码之外的补充说明。 |
| `evidence.source` | 原 `evidence.source` | 用可读文本描述缺陷源点。 |
| `evidence.sink` | 原 `evidence.sink` | 用可读文本描述缺陷汇点或终止操作。 |
| `evidence.positive` | 原 `evidence.positive` | 列出支持 Candidate 的具体行号、路径或行为证据。 |
| `evidence.negative` | 原 `evidence.negative` | 列出削弱 Candidate 或仍需确认的反向事实，不将缺失信息表述成已证伪。 |
| `evidence.path_constraints` | 原 `evidence.path_constraints` | 描述当前 source-to-sink 路径必须满足的分支和值域约束；没有约束时省略。 |
| `target_function_code` | 原 `code.function_context` | 提供目标函数的完整或有界代码上下文，使模型能够独立核验 facts、source、sink 和 guard。 |

`target_function_metadata` 必须位于 `target_function_code` 前，并由 Semantic Modeler 与 Validator 共同使用的投影函数生成。对象内部保留 Semantic Modeler 的空数组，不能再经过 v3 的空值清理。若 canonical metadata 无法解析，系统省略整个对象、在请求 envelope 的 `projection_telemetry` 记录稳定原因并继续验证；不得从 Candidate 字段拼装不完整 metadata。

### 4.4 validation_requirements 的 v3 处理

ValidatorEvidenceSlice v3 不应继续携带完整 validation_requirements 列表：

1. 14条通用规则合并进 system prompt。
2. 每次只选择当前 defect_class 对应的少量 policy delta；不发送其他类别规则。
3. 将结论性规则改写为中性的 validation_focus，描述需要核验的事实、充分条件和反证条件。
4. 不截断已选择的 policy delta；若超出预算，应在调用前报配置错误或采用确定性摘要，不向模型发送 omitted marker。
5. policy version、rule ID、完整选中集合和截断 telemetry 保留在 ValidatorRequestEnvelope，用于缓存、审计和回放，不进入 LLM Prompt。

当前 v3 实现继续采用 defect class 精确匹配，不做族继承、alias 或名称启发式；未知类别只使用 system prompt 的通用规则。

### 4.5 设计原则总结

ValidatorEvidenceSlice v3 应遵循以下边界：

1. 模型只接收可以直接理解的程序事实，不接收事实句柄。
2. UID、hash、version、alias 和缓存信息全部留在控制面；完整移植的 `target_function_metadata.index_name` 是用于函数消歧的明确例外。
3. 不发送与 system prompt 重复的通用验证规则。
4. 不发送空数组、空 proof 或无作用的字段占位。
5. 同一语义只表达一次，避免 defect class、source、sink、location 多层重复。
6. `complete` 等抽象标签不能替代具体事实或 proof。
7. 未解决事实必须显式列出，防止模型用常识猜测 ownership、caller contract 或并发协议。
8. Candidate 来源默认不发送，避免来源权威性影响 verdict；如需来源级遥测，保留在控制面。

## 五、 Validator 输出与关联

### 5.1 LLM 输出

ValidatorEvidenceSlice v3 的 Validator 输出不复述 Candidate identity，也不输出可由 verdict 唯一推导的兼容字段；`missing_fact_request` 使用多 subject 数组契约：

```json
{
  "verdict": "uncertain",
  "confidence_score": 0.55,
  "reasoning": "现有代码表明 LOG_ERROR 可能影响 error_msg 的所有权，但缺少双方对象的明确 ownership contract。",
  "positive_evidence": ["line/file/path evidence supporting the candidate"],
  "negative_evidence": ["guards or facts that weaken or disprove the candidate"],
  "blocking_negative_evidence": false,
  "exploit_scenario": "",
  "source": "Attacker/caller-controlled source, or empty if absent.",
  "sink": "Dangerous operation, or empty if absent.",
  "control_of_source": "Explain source controllability in Chinese, or empty.",
  "guard_analysis": "Explain whether relevant checks/locks/lifetime guards are sufficient.",
  "missing_fact_request": [
    {
      "fact_kind": "ownership_transfer",
      "subject": "LOG_ERROR",
      "reason": "需要 LOG_ERROR 对 error_msg 的明确 ownership contract。"
    },
    {
      "fact_kind": "ownership_transfer",
      "subject": "error_msg",
      "reason": "需要确认调用后 error_msg 的所有权是否仍由当前函数持有。"
    }
  ]
}
```

`missing_fact_request` 始终为数组；没有缺失事实时返回 `[]`，`verified` 和 `rejected` 结果也应返回空数组。每个元素必须包含非空的 `fact_kind`、`subject` 和 `reason`。`subject` 是 LLM 可从代码直接理解的对象或表达式，例如 `wire_len`、`ctx->buffer`、`LOG_ERROR`，不得使用 UID、hash 或版本号。

同一 `fact_kind` 可以针对不同 `subject` 出现多次。程序按 `(fact_kind, subject)` 保留首次请求，因此同一组合即使 reason 不同也只消费第一项；不同 subject 不会因为 fact kind 相同而合并。数组不设置长度上限。Runner 将完整有效数组写入 `validator_missing_fact_requests`，同时将 fact kind 合并进集合型的 `missing_fact_kinds`。Evidence Completion 接收完整请求数组，但仍只执行一次聚合式确定性 provider pass；空请求数组不会阻止符合既有资格条件的补全。

旧响应中的单对象会包装为单元素数组；旧 `subject_uid` 在缺少 `subject` 时映射为语义 subject，`function_uid` 不再传播。无效、未知、缺字段和重复 `(fact_kind, subject)` 的元素不会进入补全，而会记录到 `validator_missing_fact_requests_rejected` 供审计。

### 5.2 程序补充字段

Validator runtime 通过当前 worker 持有的 `raw_issue`、`candidate_uid` 和 `validation_cluster_uid` 关联结果。解析成功后，程序按 verdict 补充兼容字段：

```json
{
  "type": "validation_result",
  "finding_kind": "verified_vulnerability",
  "is_valid": true
}
```

其中 `verified` 映射为 `verified_vulnerability/true`，`rejected` 映射为 `rejected/false`，`uncertain` 映射为 `audit_observation/false`。`issue_id` 和 `missing_context` 不进入规范化结果。
