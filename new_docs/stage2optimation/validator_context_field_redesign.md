# Validator Agent 三类输入结构字段分析与重构建议

本文分析 `validator_agent` 对 `clang_ast_cfg`、`graph_rule`、`svf_value_flow` 三类 Candidate 来源组织的模型上下文。其中 `clang_ast_cfg` 进一步区分普通单函数和入口到内部 Sink 两个变体，因此全文覆盖三类来源、四种实际结构。前三章依次列出实际 `Suspected Finding` 与 `Compact Evidence Pack`、全字段逐字段分析、生成器到 Validator Prompt 之间的丢失字段说明，以及推荐的新字段。整个 Validator 上下文范围的跨来源重复性和统一重构集中在第四章。

本文所称“原始结构”是模型在对话中实际收到的 post-compaction JSON，不是 Candidate 生成器压缩前的内部对象。

分析基准为：

- 运行目录：`/home/jager/Z-Scope-benchmark/test/range/benchmark_runs/auto_unified_wsl_20260805_173639`
- 会话目录：`/home/jager/Z-Scope-benchmark/test/range/.zscope_conversations/run_20260805_173936_72536`
- 去重后终态 Candidate：305 个
- `clang_ast_cfg`：235 个终态 Candidate
- `graph_rule`：57 个终态 Candidate
- `svf_value_flow`：13 个终态 Candidate
- Validator 会话：333 个；其中 312 次 fast-path 尝试，21 个未接受 fast-path 的 Candidate 又进入完整对话

三类示例对话：

- `clang_ast_cfg`：[zscope-validator-3-validator_agent-0079.md](/home/jager/Z-Scope-benchmark/test/range/.zscope_conversations/run_20260805_173936_72536/zscope-validator-3-validator_agent-0079.md:119)
- `graph_rule`：[zscope-validator-3-validator_agent-0065.md](/home/jager/Z-Scope-benchmark/test/range/.zscope_conversations/run_20260805_173936_72536/zscope-validator-3-validator_agent-0065.md:119)
- `svf_value_flow`：[zscope-validator-3-validator_agent-0006.md](/home/jager/Z-Scope-benchmark/test/range/.zscope_conversations/run_20260805_173936_72536/zscope-validator-3-validator_agent-0006.md:120)

当前 Validator Prompt 的共同组织为：

```text
System Prompt
User Message
  Suspected Finding
  Compact Evidence Pack
  Relevant Code Context
Fast-path instruction
Final-iteration instruction
```

其中前三个用户内容块由 [`ValidatorAgent.run()`](/home/jager/Z-Scope-benchmark/zscope/agents/validator_agent/agent.py:31) 固定拼接：

```text
Suspected Finding:
<compact_validation_finding(raw_issue)>

Compact Evidence Pack:
<compact_validation_evidence_pack(validation_pack)>

Relevant Code Context:
<trim_code(issue_code, max_lines=180)>
```

本文使用以下必要性标记：

| 标记 | 含义 |
|---|---|
| 必须 | 直接参与 Candidate 验证，应发送给大模型 |
| 条件保留 | 仅在非空、可解析或对当前 Candidate 有实际作用时发送 |
| 移出 Prompt | 运行时、调度、去重、缓存或审计需要，但大模型不需要 |
| 删除或合并 | 与其他字段重复，或者当前字段会制造错误语义 |

三个示例的 Prompt 体积如下。Clang 行使用入口到内部 Sink 示例 `0079`；普通单函数示例结构更短。字符数仅用于说明重复规模，不等同于 tokenizer token 数：

| 来源 | System Prompt | Suspected Finding JSON | Compact Evidence Pack JSON | Relevant Code Context | 完全重复的 `evidence_summary`/`candidate_evidence` 两份合计 |
|---|---:|---:|---:|---:|---:|
| `clang_ast_cfg` | 4,833 | 10,452 | 21,124 | 1,708 | 12,534 |
| `graph_rule` | 4,833 | 4,528 | 9,673 | 490 | 3,158 |
| `svf_value_flow` | 4,833 | 6,146 | 15,954 | 4,395 | 5,564 |

在三个示例中，`Suspected Finding.evidence_summary` 与 `Compact Evidence Pack.candidate_evidence` 都逐值完全相等。仅这一项就占两段 JSON 总体积的约 39.7%、22.2% 和 25.2%。

## 第一章 `clang_ast_cfg`

本次运行中共有 235 个去重后的 `clang_ast_cfg` Candidate。按验证后的终态 canonical record 投影为 12 个普通结构和 223 个入口提升结构；按模型实际收到的首次 Prompt 外层结构则是 14 个和 221 个。终态合并可能重新选择 occurrence，因此原始字段与逐字段分析使用后一个口径：

| 结构 | 实际 Prompt 数 | 终态投影数 | 判定条件 |
|---|---:|---:|---|
| 普通单函数结构 | 14 | 12 | Validator 外层 `internal_sink_lifted=false` 且 `call_path=null`；其中 5 个 nested path 仍残留上游 entry-path 字段。 |
| 入口到内部 Sink 结构 | 221 | 223 | Validator 外层 `internal_sink_lifted=true` 且有 canonical `call_path`；由 `_lift_internal_sink_candidate()` 增加入口和调用链字段。 |

两种结构共享 Clang 局部 `path.function/complete_in_function/backend/path_constraints/cfg_path`。入口到内部 Sink 结构额外携带 `entry_function`、`sink_function`、`target_function`、`call_path`、`complete_to_entry`、`lifted_internal_sink`、`path_kind` 和 `call_edges`。原始 `ast_cfg.events`、声明、条件守卫和 tooling 状态在两种 Validator 输入中都已经被 compaction 删除。

本章使用两个实际示例：

| 结构 | Candidate | 函数和位置 | Suspected Finding | Compact Evidence Pack |
|---|---|---|---|---|
| 普通单函数 | `CLANG_CFG_USE_AFTER_FREE_9576ecb390` | `_lifecycle_unload_rules`，`src/lifecycle.c:417` | [对话位置](/home/jager/Z-Scope-benchmark/test/range/.zscope_conversations/run_20260805_173936_72536/zscope-validator-1-validator_agent-0061.md:119) | [对话位置](/home/jager/Z-Scope-benchmark/test/range/.zscope_conversations/run_20260805_173936_72536/zscope-validator-1-validator_agent-0061.md:254) |
| 入口到内部 Sink | `CLANG_CFG_MEMORY_LEAK_0c6426ef07` | `_serialize_task`，`src/parser.c:244` | [对话位置](/home/jager/Z-Scope-benchmark/test/range/.zscope_conversations/run_20260805_173936_72536/zscope-validator-3-validator_agent-0079.md:119) | [对话位置](/home/jager/Z-Scope-benchmark/test/range/.zscope_conversations/run_20260805_173936_72536/zscope-validator-3-validator_agent-0079.md:429) |

### 1.1 `Suspected Finding` + `Compact Evidence Pack` 原始字段

本节只列出模型实际收到的两类原始对象及两种 Clang 变体；全部逐字段结论统一放在 1.2。

#### 1.1.1 `Suspected Finding`：普通单函数结构

普通结构模型实际收到 40 个顶层字段。它不包含 Candidate 顶层的 `entry_function`、`reachable_from_entry`、`internal_sink_lifted` 和 `call_path`：

```json
{
  "id": "CLANG_CFG_USE_AFTER_FREE_9576ecb390",
  "candidate_id": "CLANG_CFG_USE_AFTER_FREE_9576ecb390",
  "function": "_lifecycle_unload_rules",
  "location": "src/lifecycle.c:417",
  "category": "use_after_free",
  "subcategory": "use_after_free",
  "defect_class": "use_after_free",
  "finding_kind": "clang_ast_cfg_candidate",
  "candidate_source": "clang_ast_cfg",
  "evidence_checker": "clang_ast_cfg_checker",
  "cwe": "CWE-416",
  "description": "Global mapping pointer `g_rules_map` is unmapped without nearby invalidation.",
  "root_cause": "Later readers can pass non-null guards and dereference an unmapped global mapping.",
  "suggested_fix": "Clear the global mapping pointer and length...",
  "confidence": 0.84,
  "rule_confidence": 0.84,
  "impact_level": "high",
  "reasoning": "Clang AST/CFG checker ... produced an evidence candidate...",
  "code_snippet": "415 | int _lifecycle_unload_rules...\n417 | munmap(...);",
  "source": "g_rules_map",
  "sink": "munmap(g_rules_map, g_rules_len);",
  "dedup_key": "use_after_free|src/lifecycle.c|417|munmap_g_rules_map_g_rules_len",
  "positive_evidence": ["line 417: `munmap` releases global mapping..."],
  "negative_evidence": ["Validator must confirm a reachable later reader..."],
  "evidence_refs": ["ir_path_slices:585", "ir_resource_events:162"],
  "validation_required": true,
  "backend_profile": "unified",
  "evidence_engines": ["..."],
  "candidate_role": "evidence_only",
  "candidate_schema_version": "zscope.candidate.v3",
  "candidate_uid": "CAND_...",
  "occurrence_uid": "OCC_...",
  "history_key": "HIST_...",
  "evidence_hash": "...",
  "decision_evidence_hash": "...",
  "provenance_hash": "...",
  "validation_cluster_uid": "VAL_...",
  "context_signature": "...",
  "evidence_models": {
    "value_flow": {
      "source": "g_rules_map",
      "sink": "munmap(g_rules_map, g_rules_len);"
    }
  },
  "evidence_summary": {
    "candidate_id": "CLANG_CFG_USE_AFTER_FREE_9576ecb390",
    "candidate_source": "clang_ast_cfg",
    "checker": "clang_ast_cfg_checker",
    "defect_class": "use_after_free",
    "source": {"expression": "g_rules_map", "file": "src/lifecycle.c", "line": 417},
    "sink": {"operation": "munmap(g_rules_map, g_rules_len);", "file": "src/lifecycle.c", "line": 417},
    "path": {
      "function": "_lifecycle_unload_rules",
      "complete_in_function": true,
      "backend": "Clang function body plus synthesized local CFG",
      "path_constraints": [],
      "cfg_path": [417]
    },
    "positive_evidence": ["..."],
    "negative_evidence": ["..."],
    "evidence_refs": ["..."],
    "validation_required": true,
    "proofs": {},
    "backend_profile": "unified",
    "semantic_overlays": {"...": "global run-level model list"},
    "semantic_overlay_evidence": {}
  }
}
```

#### 1.1.2 `Suspected Finding`：入口到内部 Sink 结构

入口到内部 Sink 结构模型实际收到 44 个顶层字段。它在普通结构上增加 Candidate 顶层 entry/call-path 字段，并在 `evidence_models` 中增加 cross-procedure contract：

```json
{
  "id": "CLANG_CFG_MEMORY_LEAK_0c6426ef07",
  "candidate_id": "CLANG_CFG_MEMORY_LEAK_0c6426ef07",
  "function": "_serialize_task",
  "location": "src/parser.c:244",
  "category": "memory_leak",
  "subcategory": "memory_leak",
  "defect_class": "memory_leak",
  "finding_kind": "clang_ast_cfg_candidate",
  "candidate_source": "clang_ast_cfg",
  "evidence_checker": "clang_ast_cfg_checker",
  "cwe": "CWE-401",
  "description": "`buffer` is acquired from `_safe_malloc` and reaches return edge unreleased.",
  "root_cause": "The local CFG state has an acquire event but no matching release or ownership transfer before the exit edge.",
  "suggested_fix": "Release the resource on all exit paths or explicitly transfer ownership...",
  "confidence": 0.76,
  "rule_confidence": 0.76,
  "impact_level": "medium",
  "reasoning": "Clang AST/CFG checker ... produced an evidence candidate...",
  "code_snippet": "239 | ...\n244 | return 0;",
  "source": "_safe_malloc(...) at line 224",
  "sink": "return 0;",
  "dedup_key": "memory_leak|src/parser.c|244|return_0",
  "positive_evidence": [
    "line 224: `buffer` acquired from `_safe_malloc`",
    "line 244: return edge without a matching release",
    "Entry `td_serialize_task_message` reaches `_serialize_task`..."
  ],
  "negative_evidence": [
    "Validator must confirm whether ownership is transferred outside this local body."
  ],
  "evidence_refs": ["ir_path_slices:...", "ir_resource_events:..."],
  "validation_required": true,
  "entry_function": "td_serialize_task_message",
  "reachable_from_entry": true,
  "internal_sink_lifted": true,
  "call_path": ["td_serialize_task_message", "_serialize_task"],
  "backend_profile": "unified",
  "evidence_engines": [
    "clang_ast_cfg_checker",
    "clang_knowledgedb_callgraph_checker",
    "svf_value_flow_checker",
    "saber_memory_signal_adapter"
  ],
  "candidate_role": "evidence_only",
  "candidate_schema_version": "zscope.candidate.v3",
  "candidate_uid": "CAND_...",
  "occurrence_uid": "OCC_...",
  "history_key": "HIST_...",
  "evidence_hash": "...",
  "decision_evidence_hash": "...",
  "provenance_hash": "...",
  "validation_cluster_uid": "VAL_...",
  "context_signature": "...",
  "evidence_models": {
    "value_flow": {
      "source": "_safe_malloc(...) at line 224",
      "sink": "return 0;"
    },
    "cross_procedure_contract": {
      "entry_function": "td_serialize_task_message",
      "target_function": "_serialize_task",
      "call_path": ["td_serialize_task_message", "_serialize_task"]
    }
  },
  "evidence_summary": {
    "candidate_id": "CLANG_CFG_MEMORY_LEAK_0c6426ef07",
    "candidate_source": "clang_ast_cfg",
    "checker": "clang_ast_cfg_checker",
    "defect_class": "memory_leak",
    "source": {
      "expression": "_safe_malloc(...) at line 224",
      "file": "src/parser.c",
      "line": 224
    },
    "sink": {
      "operation": "return 0;",
      "file": "src/parser.c",
      "line": 244
    },
    "path": {
      "function": "_serialize_task",
      "complete_in_function": true,
      "backend": "Clang function body plus synthesized local CFG",
      "path_constraints": ["..."],
      "cfg_path": [224, 244],
      "entry_function": "td_serialize_task_message",
      "sink_function": "_serialize_task",
      "target_function": "_serialize_task",
      "call_path": ["td_serialize_task_message", "_serialize_task"],
      "complete_to_entry": true,
      "lifted_internal_sink": true,
      "path_kind": "entry_to_internal_sink",
      "call_edges": ["..."]
    },
    "positive_evidence": ["..."],
    "negative_evidence": ["..."],
    "evidence_refs": ["..."],
    "validation_required": true,
    "proofs": {},
    "entry_function": "td_serialize_task_message",
    "sink_function": "_serialize_task",
    "call_path": ["td_serialize_task_message", "_serialize_task"],
    "backend_profile": "unified",
    "semantic_overlays": {"...": "global run-level model list"},
    "semantic_overlay_evidence": {"resource_models": ["..."]}
  }
}
```

两种 `Suspected Finding` 的结构差异：

| 字段位置 | 普通单函数结构 | 入口到内部 Sink 结构 |
|---|---|---|
| Finding 顶层 `entry_function` | 不存在 | 存在 |
| Finding 顶层 `reachable_from_entry` | 不存在 | `true` |
| Finding 顶层 `internal_sink_lifted` | 不存在 | `true` |
| Finding 顶层 `call_path` | 不存在 | entry 到内部 Sink 的函数序列 |
| `evidence_models` | 通常只有 source/sink 等局部模型 | 额外包含 `cross_procedure_contract` |
| `evidence_summary.path` | 5 个局部字段 | 13 个字段，增加 entry、target、call path 和 call edges |
| `evidence_summary` 顶层 entry/path 副本 | 不存在 | 增加 `entry_function/sink_function/call_path` |

#### 1.1.3 `Compact Evidence Pack` 普通单函数结构

三类来源的 Pack 都使用同一个 28 字段顶层模板。Clang 的普通和入口提升变体只在 `entry_context`、`candidate_evidence`、`evidence_models` 及正向证据 enrichment 上不同。

普通结构的 Pack 顶层仍有 28 个字段，但 entry context 的当前入口就是 Candidate 所在函数，`call_path=null`，`internal_sink_lifted=false`：

```json
{
  "mode": "tri_state_exploitability_validation",
  "candidate_id": "CLANG_CFG_USE_AFTER_FREE_9576ecb390",
  "candidate_role": "evidence_only",
  "candidate_is_conclusion": false,
  "validation_required": true,
  "backend_profile": "unified",
  "evidence_checker": "clang_ast_cfg_checker",
  "finding_kind": "clang_ast_cfg_candidate",
  "defect_class": "use_after_free",
  "finding_summary": {
    "function": "_lifecycle_unload_rules",
    "location": "src/lifecycle.c:417",
    "source": "g_rules_map",
    "sink": "munmap(g_rules_map, g_rules_len);"
  },
  "entry_context": {
    "current_analysis_entry": "_lifecycle_unload_rules",
    "entry_exposure": "communication",
    "entry_is_external_root": true,
    "entry_is_scan_root": true,
    "issue_entry_function": "",
    "reachable_from_entry": true,
    "internal_sink_lifted": false,
    "call_path": null,
    "candidate_path": {
      "function": "_lifecycle_unload_rules",
      "complete_in_function": true,
      "backend": "Clang function body plus synthesized local CFG",
      "path_constraints": [],
      "cfg_path": [417]
    }
  },
  "candidate_evidence": {
    "candidate_id": "CLANG_CFG_USE_AFTER_FREE_9576ecb390",
    "candidate_source": "clang_ast_cfg",
    "checker": "clang_ast_cfg_checker",
    "defect_class": "use_after_free",
    "source": {"expression": "g_rules_map", "file": "src/lifecycle.c", "line": 417},
    "sink": {"operation": "munmap(g_rules_map, g_rules_len);", "file": "src/lifecycle.c", "line": 417},
    "path": {
      "function": "_lifecycle_unload_rules",
      "complete_in_function": true,
      "backend": "Clang function body plus synthesized local CFG",
      "path_constraints": [],
      "cfg_path": [417]
    },
    "positive_evidence": ["..."],
    "negative_evidence": ["..."],
    "evidence_refs": ["..."],
    "validation_required": true,
    "proofs": {},
    "backend_profile": "unified",
    "semantic_overlays": {"...": "global model list"},
    "semantic_overlay_evidence": {}
  },
  "evidence_models": {
    "value_flow": {
      "source": "g_rules_map",
      "sink": "munmap(g_rules_map, g_rules_len);"
    }
  },
  "positive_evidence": ["..."],
  "negative_evidence": ["..."],
  "primary_location_snippet": {"...": "..."},
  "function_context": {"code": "...", "callers": [], "callees": ["munmap"]},
  "validation_requirements": ["..."],
  "dedup_key": "...",
  "proofs": {},
  "audit_observation_reason": null,
  "va_unreviewed": false,
  "evidence_engines": ["..."],
  "semantic_overlays": {"...": "..."},
  "semantic_overlay_evidence": {},
  "rule_confidence": 0.84,
  "score_components": {"...": "..."},
  "evidence_refs": ["..."]
}
```

#### 1.1.4 `Compact Evidence Pack` 入口到内部 Sink 结构

入口到内部 Sink Pack 在普通结构上增加 entry-to-target path 和边证据。该示例的实际结构为：

```json
{
  "mode": "tri_state_exploitability_validation",
  "dedup_key": "memory_leak|src/parser.c|244|return_0",
  "candidate_id": "CLANG_CFG_MEMORY_LEAK_0c6426ef07",
  "candidate_role": "evidence_only",
  "candidate_is_conclusion": false,
  "validation_required": true,
  "proofs": {},
  "audit_observation_reason": null,
  "va_unreviewed": false,
  "backend_profile": "unified",
  "evidence_checker": "clang_ast_cfg_checker",
  "evidence_engines": ["... four run-level engines ..."],
  "semantic_overlays": {"...": "global model counts and names"},
  "semantic_overlay_evidence": {
    "resource_models": [
      {
        "name": "_safe_malloc",
        "kind": "malloc",
        "carrier": "return_value",
        "source": "builtin_defaults"
      }
    ]
  },
  "finding_kind": "clang_ast_cfg_candidate",
  "defect_class": "memory_leak",
  "rule_confidence": 0.76,
  "score_components": {
    "rule_confidence": 0.76,
    "path_completeness": 1.0,
    "contract_consistency": 0.8,
    "validation_confidence": 0.76,
    "history_feedback": 0.5,
    "final_score": 0.777
  },
  "evidence_refs": ["..."],
  "finding_summary": {
    "id": "CLANG_CFG_MEMORY_LEAK_0c6426ef07",
    "function": "_serialize_task",
    "location": "src/parser.c:244",
    "category": "memory_leak",
    "subcategory": "memory_leak",
    "confidence": 0.76,
    "description": "`buffer` is acquired...",
    "source": "_safe_malloc(...) at line 224",
    "sink": "return 0;",
    "cwe": "CWE-401"
  },
  "entry_context": {
    "current_analysis_entry": "td_serialize_task_message",
    "entry_custom_prompt": "Public API declared in a header file...",
    "entry_exposure": "api",
    "entry_is_external_root": true,
    "entry_is_scan_root": true,
    "zero_callers_is_expected_for_entry": true,
    "public_trigger": "Header-declared/configured entry function is an external scan root...",
    "issue_entry_function": "td_serialize_task_message",
    "reachable_from_entry": true,
    "internal_sink_lifted": true,
    "call_path": ["td_serialize_task_message", "_serialize_task"],
    "candidate_path": {"...": "same path as candidate_evidence.path"}
  },
  "candidate_evidence": {
    "candidate_id": "CLANG_CFG_MEMORY_LEAK_0c6426ef07",
    "candidate_source": "clang_ast_cfg",
    "checker": "clang_ast_cfg_checker",
    "defect_class": "memory_leak",
    "source": {"expression": "...", "file": "src/parser.c", "line": 224},
    "sink": {"operation": "return 0;", "file": "src/parser.c", "line": 244},
    "path": {
      "function": "_serialize_task",
      "complete_in_function": true,
      "backend": "Clang function body plus synthesized local CFG",
      "path_constraints": ["..."],
      "cfg_path": [224, 244],
      "entry_function": "td_serialize_task_message",
      "sink_function": "_serialize_task",
      "target_function": "_serialize_task",
      "call_path": ["td_serialize_task_message", "_serialize_task"],
      "complete_to_entry": true,
      "lifted_internal_sink": true,
      "path_kind": "entry_to_internal_sink",
      "call_edges": [
        {
          "caller": "td_serialize_task_message",
          "callee": "_serialize_task",
          "call_line": 330,
          "arguments": ["task", "buffer", "len"],
          "parameter_mapping": ["..."],
          "caller_parameters": ["task", "buffer", "len"],
          "callee_parameters": ["task", "buffer", "len"],
          "guard_summary": {"caller_side": {}, "callee_entry": {}},
          "evidence_source": "source_text_best_effort"
        }
      ]
    },
    "positive_evidence": ["..."],
    "negative_evidence": ["..."],
    "evidence_refs": ["..."],
    "validation_required": true,
    "proofs": {},
    "entry_function": "td_serialize_task_message",
    "sink_function": "_serialize_task",
    "call_path": ["td_serialize_task_message", "_serialize_task"],
    "backend_profile": "unified",
    "semantic_overlays": {"...": "global model list"},
    "semantic_overlay_evidence": {"resource_models": ["..."]}
  },
  "evidence_models": {
    "value_flow": {"source": "...", "sink": "..."},
    "cross_procedure_contract": {"entry_function": "...", "call_path": ["..."]}
  },
  "positive_evidence": ["..."],
  "negative_evidence": ["..."],
  "primary_location_snippet": {
    "file": "src/parser.c",
    "start_line": 232,
    "end_line": 256,
    "code": "..."
  },
  "function_context": {
    "code": "... complete target function ...",
    "snapshot_summary": null,
    "callers": ["..."],
    "callees": ["..."]
  },
  "validation_requirements": [
    "Treat every candidate as evidence only...",
    "Independently audit semantic overlay assumptions...",
    "Return verdict=verified only if...",
    "... first 12 generic requirements ...",
    {"omitted_items": 7}
  ]
}
```

### 1.2 `Suspected Finding` + `Compact Evidence Pack` 全字段逐字段分析

固定值统计按 235 个实际 Clang Prompt 输入计算：普通外层结构 14 个、入口到内部 Sink 结构 221 个。表中的“固定”分别标明代码/生成器固定、运行配置固定或固定关系；未写固定的字段会随 Candidate 变化。

| 字段 | 建议操作 | 重复 / 必要性 / 固定值分析 |
|---|---|---|
| `Finding.id` | 保留并改为 `candidate.id` | 必须用于结果关联；与 `candidate_id`、Pack ID 和 nested ID 在 235/235 固定相等。 |
| `Finding.candidate_id` | 删除 | 与 `Finding.id` 代码级重复。 |
| `Finding.function` | 合并 | 必须定位目标函数；与 Pack summary、path function 和 function context 重复，统一为 `analysis_scope.target_function`。 |
| `Finding.location` | 重构 | 必须定位源码；复合字符串在 Pack summary 重复，改为 program point 的 file/line。 |
| `Finding.category` | 删除 | 与 `subcategory`、`defect_class` 在 235/235 固定相等。 |
| `Finding.subcategory` | 删除 | 与 `defect_class` 重复。 |
| `Finding.defect_class` | 保留一次 | 假设分类必需；在 Finding、Pack、summary 和 candidate evidence 多次复制。 |
| `Finding.finding_kind` | 移出 Prompt | 本次均为 `clang_ast_cfg_candidate`；默认来源固定但 audit 代码可覆盖，只用于阶段追踪。 |
| `Finding.candidate_source` | 合并为 `source_kind` | 解释 Clang 证据语义有用；固定为 `clang_ast_cfg`，只保留一次。 |
| `Finding.evidence_checker` | 删除 | 固定为 `clang_ast_cfg_checker`；与 Pack/nested checker 重复。 |
| `Finding.cwe` | 条件保留 | 分类标签可能有用，但可由 defect class 映射，不应代替具体 claim。 |
| `Finding.description` | 改名为 claim | 与 root cause、reasoning 和 Pack finding summary 重述同一假设。 |
| `Finding.root_cause` | 降级为假设 | Candidate 尚未验证；与 description/reasoning 重复。 |
| `Finding.suggested_fix` | 删除 | 验证前发送修复建议会造成确认偏差。 |
| `Finding.reasoning` | 删除 | 来源模板和候选结论重复，不是新的程序事实。可能误导llm。 |
| `Finding.confidence` | 移出 Prompt | 与 `rule_confidence` 及 Pack 评分链在 235/235 固定相等，会锚定模型。可能误导llm。 |
| `Finding.rule_confidence` | 移出 Prompt | 上游排序先验；在 Pack 顶层和 score components 重复。 |
| `Finding.impact_level` | 移出 Prompt | 报告/排序元数据，不参与证据验证。 |
| `Finding.code_snippet` | 合并到唯一 code unit | 与 primary snippet、function code、Relevant Code Context 重复。 |
| `Finding.source` | 重构为 program point | 必须表达资源/状态起点；在 evidence model、summary、Pack summary 和 candidate evidence 重复。 |
| `Finding.sink` | 重构为 program point | 必须表达局部危险点；同样多层重复，“sink”未必是调用。 |
| `Finding.dedup_key` | 移出 Prompt | 只用于去重，并在 Pack 顶层重复。 |
| `Finding.positive_evidence` | 合并去重 | 必须；与 Pack 顶层及 nested evidence 重复，入口提升还混入 reachability 文案，应拆为 local/reachability evidence。 |
| `Finding.negative_evidence` | 合并去重 | 必须保留真实反证；与 Pack 多层重复，空值不发送。 |
| `Finding.evidence_refs` | 条件保留 | 与 Pack/nested refs 重复；fast path 不能解析时移出 Prompt。 |
| `Finding.validation_required` | 删除 | 代码固定为 `true`；Validator 调用和 System Prompt 已表达。 |
| `Finding.entry_function` | 条件保留一次 | 仅入口提升结构出现；221/221 存在并在 path/model/Pack 重复。 |
| `Finding.reachable_from_entry` | 合并为三态 reachability | 入口提升 221/221 固定 `true`；普通 Finding 不出现。布尔值本身不携带依据。 |
| `Finding.internal_sink_lifted` | 合并到 scope kind | 入口提升 221/221 固定 `true`；与 `path_kind/lifted_internal_sink` 重复。 |
| `Finding.call_path` | 保留一份 | 入口提升必需；与 evidence model、summary path、Pack entry context/candidate evidence 重复。 |
| `Finding.backend_profile` | 移出 Prompt | 本次运行固定为 `unified`。 |
| `Finding.evidence_engines` | 移出 Prompt | 本次固定为 unified 的四引擎清单，不证明当前 Candidate 使用了全部引擎。 |
| `Finding.candidate_role` | 删除 | 注解器默认固定 `evidence_only`，与 System Prompt 重复。 |
| `Finding.candidate_schema_version` | 移出 Prompt | 代码固定 `zscope.candidate.v3`，仅传输/审计使用。 |
| `Finding.candidate_uid` | 移出 Prompt | 生命周期主键，不参与漏洞判断。 |
| `Finding.occurrence_uid` | 移出 Prompt | occurrence 跟踪字段。 |
| `Finding.history_key` | 移出 Prompt | 历史聚合字段。 |
| `Finding.evidence_hash` | 移出 Prompt | 缓存/变更检测摘要。 |
| `Finding.decision_evidence_hash` | 移出 Prompt | 决策缓存摘要。 |
| `Finding.provenance_hash` | 移出 Prompt | provenance 审计摘要。 |
| `Finding.validation_cluster_uid` | 移出 Prompt | 聚类/终态映射字段。 |
| `Finding.context_signature` | 移出 Prompt | 上下文去重摘要。 |
| `Finding.evidence_models.value_flow` | 删除或结构化合并 | 只复制 Finding source/sink，不提供独立 flow 证明。 |
| `Finding.evidence_models.cross_procedure_contract` | 合并到 reachability | 仅入口提升出现；复制 entry、target 和 call path。 |
| `Finding.evidence_summary` | 删除整个副本 | 与 `Pack.candidate_evidence` 在 235/235 整对象相等。其全部子字段应在唯一 evidence 主体中分析，而不是保留第二份包装。 |
| `Finding.evidence_summary.candidate_id` | 删除 | 与 Finding/Pack ID 固定相等。 |
| `Finding.evidence_summary.candidate_source` | 合并 | 固定 `clang_ast_cfg`，与 Finding source kind 重复。 |
| `Finding.evidence_summary.checker` | 合并到 producer | 固定 `clang_ast_cfg_checker`。 |
| `Finding.evidence_summary.defect_class` | 删除副本 | 与 Finding/Pack 分类重复。 |
| `Finding.evidence_summary.source` | 合并到 program point | 与 Finding 字符串 source 表达同一事实，结构化版本精度更高。 |
| `Finding.evidence_summary.sink` | 合并到 program point | 与 Finding 字符串 sink 重复。 |
| `Finding.evidence_summary.path.function` | 合并到 target function | 与 Finding function 和 Pack function context 重复。 |
| `Finding.evidence_summary.path.complete_in_function` | 条件保留并改名 | 235/235 代码固定 `true`；只表示生成器声明局部 CFG 完整，不证明路径可行。 |
| `Finding.evidence_summary.path.backend` | 合并到 producer | 固定字符串 `Clang function body plus synthesized local CFG`。 |
| `Finding.evidence_summary.path.path_constraints` | 保留并结构化 | 是局部判断的重要约束；与正向证据可能重述，应引用 program points。 |
| `Finding.evidence_summary.path.cfg_path` | 保留 | 是 Clang 局部路径核心证据，改为 program-point ID 序列。 |
| `Finding.evidence_summary.path.entry_function` | 合并到 analysis scope | 入口相关 Clang 中出现，与顶层 entry 重复。 |
| `Finding.evidence_summary.path.sink_function` | 合并 | 入口提升中与 target function 固定相等。 |
| `Finding.evidence_summary.path.target_function` | 保留一次 | 入口提升中与 sink function 221/221 相等。 |
| `Finding.evidence_summary.path.call_path` | 合并 | 与 Finding/Pack canonical call path 重复。 |
| `Finding.evidence_summary.path.complete_to_entry` | 改为 reachability status | 入口提升代码固定 `true`；表示静态链已找到，不证明运行时可行。 |
| `Finding.evidence_summary.path.lifted_internal_sink` | 删除 | 入口提升代码固定 `true`，由 scope kind 可推导。 |
| `Finding.evidence_summary.path.path_kind` | 合并到 scope kind | 入口提升固定 `entry_to_internal_sink`。 |
| `Finding.evidence_summary.path.call_edges` | 保留并去重 | 跨函数验证必需；空 parameter/guard 不发送，避免随整 evidence block 复制。 |
| `Finding.evidence_summary.positive_evidence` | 合并 | 与 Finding/Pack evidence 重复。 |
| `Finding.evidence_summary.negative_evidence` | 合并 | 与 Finding/Pack counterevidence 重复。 |
| `Finding.evidence_summary.evidence_refs` | 条件保留一次 | 多层复制；仅工具可解析时发送。 |
| `Finding.evidence_summary.validation_required` | 删除 | 固定 `true`。 |
| `Finding.evidence_summary.proofs` | 空时删除 | 本次固定 `{}`，没有已定义 proof 内容。 |
| `Finding.evidence_summary.entry_function` | 合并 | 入口提升中是 path/top-level entry 的副本。 |
| `Finding.evidence_summary.sink_function` | 合并 | 入口提升中与 target 重复。 |
| `Finding.evidence_summary.call_path` | 合并 | 入口提升中是 path call_path 的副本。 |
| `Finding.evidence_summary.backend_profile` | 移出 Prompt | 运行固定 `unified`。 |
| `Finding.evidence_summary.semantic_overlays` | 移出 Prompt | 235/235 为同一全局模型摘要。 |
| `Finding.evidence_summary.semantic_overlay_evidence` | 条件保留 | 只保留当前 Candidate 实际命中的模型并标明假设性质。 |
| `Pack.mode` | 移出 Prompt | builder 代码固定 `tri_state_exploitability_validation`。 |
| `Pack.dedup_key` | 移出 Prompt | 与 Finding dedup key 重复。 |
| `Pack.candidate_id` | 删除副本 | 与 Finding ID 固定相等。 |
| `Pack.candidate_role` | 删除 | 固定 `evidence_only`。 |
| `Pack.candidate_is_conclusion` | 删除 | 固定 `false`，System Prompt 已说明。 |
| `Pack.validation_required` | 删除 | 固定 `true`。 |
| `Pack.proofs` | 空时删除 | 本次固定 `{}`；非空时才按 proof 子 schema 保留。 |
| `Pack.audit_observation_reason` | 空时删除 | 本次固定 `null`。 |
| `Pack.va_unreviewed` | 移出 Prompt | 本次固定 `false`，属于审计状态。 |
| `Pack.backend_profile` | 移出 Prompt | 运行固定 `unified`。 |
| `Pack.evidence_checker` | 删除 | 固定 `clang_ast_cfg_checker`，与 Finding/nested checker 重复。 |
| `Pack.evidence_engines` | 移出 Prompt | 运行固定四引擎清单。 |
| `Pack.semantic_overlays` | 移出 Prompt | 运行固定全局摘要，在 candidate evidence 再次出现。 |
| `Pack.semantic_overlay_evidence` | 条件保留一次 | 与 nested overlay evidence 重复；仅保留当前实例命中。 |
| `Pack.finding_kind` | 移出 Prompt | 本次固定 `clang_ast_cfg_candidate`，阶段标签。 |
| `Pack.defect_class` | 删除副本 | 与 Finding 分类重复。 |
| `Pack.rule_confidence` | 移出 Prompt | 与 Finding confidence 链重复。 |
| `Pack.score_components` | 移出 Prompt | rule/path/contract/validation/history/final 均为上游评分；`history_feedback=0.5` 本次固定。 |
| `Pack.evidence_refs` | 删除 | 与 Finding/nested refs 重复。 |
| `Pack.finding_summary` | 删除整个对象 | `id/function/location/category/subcategory/confidence/description/source/sink/cwe` 均从 Finding 固定复制。 |
| `Pack.entry_context.current_analysis_entry` | 保留或合并 | 入口语义参与判断时必需；普通结构常与 target 重复。 |
| `Pack.entry_context.entry_custom_prompt` | 删除 | exposure 对应模板，与 System Prompt/requirements 重复。 |
| `Pack.entry_context.entry_exposure` | 条件保留 | 实例枚举有用；不要重复发送模板解释。 |
| `Pack.entry_context.entry_is_external_root` | 合并为 root kind | 本次 235/235 固定 `true`。 |
| `Pack.entry_context.entry_is_scan_root` | 删除或合并 | 本次固定 `true`，与 external root/root kind 重叠。 |
| `Pack.entry_context.zero_callers_is_expected_for_entry` | 删除 | 本次固定 `true`，规则属于 System Prompt。 |
| `Pack.entry_context.public_trigger` | 删除 | 本次固定同一 scan-root 长文本，与 System Prompt 重复。 |
| `Pack.entry_context.issue_entry_function` | 合并 | 普通 14/14 为 `""`；入口提升应与 canonical entry 合并。 |
| `Pack.entry_context.reachable_from_entry` | 改为三态 | 普通和入口提升均为 `true`，但前者来自 entry==function，后者来自提升链，生成依据不同。 |
| `Pack.entry_context.internal_sink_lifted` | 合并到 scope kind | 普通固定 `false`，入口提升固定 `true`。 |
| `Pack.entry_context.call_path` | 保留一份 | 普通固定 `null`；入口提升与 Finding/path 重复。 |
| `Pack.entry_context.candidate_path` | 删除 | 与 `Pack.candidate_evidence.path` 235/235 整对象相等。 |
| `Pack.candidate_evidence` | 保留并重构为唯一 evidence | 与 Finding `evidence_summary` 235/235 相等；删除 Finding 副本后再按上述 nested 字段取舍。 |
| `Pack.evidence_models` | 删除或合并 | value flow 复制 source/sink，cross-procedure contract 复制 entry/call path。 |
| `Pack.positive_evidence` | 合并去重 | 必须；入口提升可能比 nested local evidence多 reachability 文案，不能简单择一删除。 |
| `Pack.negative_evidence` | 合并为 counterevidence | 与 Finding/nested evidence 重复；空时省略。 |
| `Pack.primary_location_snippet` | 合并到 code context | 与 Finding snippet/function code/Relevant Code 有行级重叠。 |
| `Pack.function_context.code` | 删除副本 | 与 Relevant Code 同源；289/305 全来源样本完全相等，其余只是截断。 |
| `Pack.function_context.snapshot_summary` | 空时删除 | 本次固定 `null`。 |
| `Pack.function_context.callers` | 条件保留 | 只保留支持 reachability 的边，避免与 call path 重复。 |
| `Pack.function_context.callees` | 条件保留 | 只保留决定 ownership/helper 语义的 callee，并应提供必要代码。 |
| `Pack.validation_requirements` | 从 Pack 删除 | 前 12 条固定，11 条与 System Prompt 高度重复；类别规则全部被 list cap 截断，只留下变化的 `omitted_items`。 |

### 1.3 Clang 丢失字段说明

本节的“丢失”是指：Clang Candidate 生成器已经写入字段，但 `Suspected Finding.evidence_summary` 和 `Compact Evidence Pack.candidate_evidence` 在调用同一个 `_compact_candidate_evidence()` 后不再包含它。该函数只保留通用白名单字段；`ast_cfg`、`rule` 等未命中白名单的普通键会被静默跳过，而且不会写入 `compaction_metadata`。因此，第 1.1 节的“原始字段”是模型实际收到的已压缩结构，不是 Clang 生成器的完整 `evidence_pack`。

| 生成器原始字段 | 原始内容 | 丢失方式与信息影响 | 推荐处理 |
|---|---|---|---|
| `evidence_pack.rule` | 精确的 Clang 命中规则 | 不在 compact 白名单，两种 Clang 结构均固定丢失；模型只能从 description、dedup key 或自然语言证据反推规则。 | 恢复为实例级 rule 标识或 hypothesis basis，不从 `dedup_key` 解析。 |
| `evidence_pack.rule_confidence` | 规则生成器的先验置信度 | 不在白名单；数值与 Finding 置信度链重复，丢失不减少代码事实。 | 不恢复到模型 Prompt，只保留在排序/审计元数据。 |
| `evidence_pack.ast_cfg` | Clang 生成器合成的 AST/CFG 事实包 | 整个对象不在白名单，普通单函数和入口到内部 Sink 结构都固定丢失。 | 不原样恢复大对象；按当前 claim 过滤后拆入 `program_points`、`source_specific.cfg` 和 `resource_trace`。 |
| `ast_cfg.checker_basis` | `clangd` 索引函数体加合成 CFG 的证据来源 | 随 `ast_cfg` 丢失；不是运行路径证明，但对理解证据上限必要。 | 压缩为 source-specific provenance，明确 CFG 是 synthesized，不宣称为编译器完整 CFG。 |
| `ast_cfg.statement_count` / `approx_basic_block_count` | 函数语句数和近似基本块数 | 随 `ast_cfg` 丢失；它们是实例级可变值，但通常不直接支持漏洞 claim。 | 默认不进 Prompt；仅用于完整性诊断或审计。 |
| `ast_cfg.declarations` | 局部声明、类型和初始化信息 | 随 `ast_cfg` 丢失；可能删掉判断资源类型、别名和初始状态所需的事实。 | 只恢复与 source、sink、guard 或跟踪资源有关的声明，并尽量引用唯一 code unit。 |
| `ast_cfg.condition_guards` / `path_constraints` | 函数分支条件和候选路径约束 | `condition_guards` 随 `ast_cfg` 丢失；`path_constraints` 和 `cfg_path` 另外复制到白名单内的 `path`，因此只是部分保留，不是整体丢失。 | 合并去重为 `source_specific.cfg.constraints/path_points`，同时保留条件表达式、位置和 Candidate 选择的分支。 |
| `ast_cfg.scope_summary` | 局部作用域与控制流摘要 | 随 `ast_cfg` 丢失；其通用文本价值低，但个别退出/清理边界可能有用。 | 不整块恢复；只将与 claim 有关的 exit/scope 边界转为程序点或路径约束。 |
| `ast_cfg.events` | 规则识别到的 acquire、release、transfer、invalidation、sink 等事件 | 随 `ast_cfg` 丢失；这是最直接说明“为什么命中”的结构化证据，自然语言 `positive_evidence` 只能保留不完整摘要。 | 按当前资源过滤，恢复为 `program_points` 和 `resource_trace.events`。 |
| `ast_cfg.clang_tooling` | 声明、引用、类型或其他 Clang tooling 补充证据 | 仅在 provider 返回非空证据时生成，但一旦生成仍会随 `ast_cfg` 丢失；不是运行级固定值。 | 只保留当前 claim 引用的 tooling 事实及 provenance，不发送全量工具输出。 |
| `candidate_priority_group` / `validation_budget_class` | 候选排序组和验证预算类别 | 不在白名单；值随 defect class、finding kind 和 priority 而变，但只服务调度。 | 保留在运行控制元数据，不恢复到 Validator 证据。 |
| `call_path_edges` / `internal_sink_lifted` 顶层副本 | 入口到内部 Sink 提升时的调用边和提升标记 | 顶层键不在白名单，但同一信息已写入被保留的 `path.call_edges/lifted_internal_sink`；属于丢失重复副本，没有净语义损失。 | 不恢复副本；在推荐结构中只保留 `analysis_scope.kind` 和一份 `reachability.call_edges`。 |

结论：Clang compaction 的主要问题不是删除了整块 JSON wrapper，而是在保留 ID、分类、summary 和 overlay 等多份副本的同时，删掉了 `events`、guards 和相关声明。新结构应恢复这些信息的 claim-specific 投影，而不是将完整 `ast_cfg` 原样塞回 Prompt。

### 1.4 `clang_ast_cfg` 两种推荐新结构

推荐取消独立 `Suspected Finding` 与 `Compact Evidence Pack`，使用一个 Validator 输入对象，并用必填 `analysis_scope` 明确区分两种 Clang 结构。

#### 1.4.1 普通单函数结构

```json
{
  "candidate": {
    "id": "CLANG_CFG_USE_AFTER_FREE_9576ecb390",
    "source_kind": "clang_ast_cfg",
  },
  "hypothesis": {
    "defect_class": "use_after_free",
    "cwe": "CWE-416",
    "rule": "clang_cfg_global_mapping_unmapped_without_invalidation",
    "claim": "Global mapping pointer `g_rules_map` is unmapped without nearby invalidation.",
    "root_cause": "Later readers can pass non-null guards and dereference an unmapped global mapping.",
  },
  "analysis_scope": "single_function",
  "entry_function": {
    "function_name": "_lifecycle_unload_rules",
    "file_path": ,
    "start_line": ,
    "end_line": ,
    "entry_custom_prompt": "Communication or IPC entry. Treat bytes read from peers/shared channels as untrusted. Audit framing, length checks, return-value handling, and trust boundaries before parsing, dispatch, copies, indexing, or deserialization. If the received data or derived length is returned, written through an out-parameter, stored in shared/session state, or otherwise consumed by callers, use get_callers to inspect caller-side parsing and validation instead of stopping at the low-level read wrapper.",
    "entry_exposure": "communication",
    "root_kind": "external_scan_root",
  },
  "target_function": {
    "function_name": "_lifecycle_unload_rules",
    "file_path": ,
    "start_line": ,
    "end_line": ,
    "snapshot_summary": null,
    "callers": [
      {
        "name": "td_configure_rules",
        "filename": "src/main.c",
        "callee_filename": "src/lifecycle.c",
        "lineNumber": 385
      }
    ],
    "callees": [
      {
        "name": "munmap",
        "filename": "/usr/include/x86_64-linux-gnu/sys/mman.h",
        "lineNumber": 417,
        "call_type": "direct",
        "callee_kind": "function",
        "callee_signature": ""
      }
    ]
  },//普通单函数结构的entry_function和target_function的function_name，file_path，start_line，end_line相同
  "source": {
    "expression": "g_rules_map",
    "file": "src/lifecycle.c",
    "line": 417
  },
  "sink": {
    "operation": "munmap(g_rules_map, g_rules_len);",
    "file": "src/lifecycle.c",
    "line": 417
  },
  "call_path": {
    "nodes": ["_lifecycle_unload_rules"],
    "edges": []//普通单函数结构为空
  },
  "evidence": {
    "positive_evidence": [],
    "negative_evidence": [],
    "semantic_overlay_evidence": {},
  },
  "target_function_code": ""
}
```

普通结构不应生成空的跨函数字段，也不需要 `internal_sink_lifted=false`。`analysis_scope=single_function` 与单节点 `call_path` 已足够表达作用域。

#### 1.4.2 入口到内部 Sink 结构

入口到内部 Sink 结构 target function 与 entry function 不相同，且call_path.nodes有多个节点，call_path.edges不为空。

```json
{
  "candidate": {
    "id": "CLANG_CFG_MEMORY_LEAK_0c6426ef07",
    "source_kind": "clang_ast_cfg",
  },
  "hypothesis": {
    "defect_class": "memory_leak",
    "cwe": "CWE-401",
    "rule": "clang_cfg_acquire_without_release_on_exit",
    "claim": "`buffer` may reach the successful return without an observed release or ownership transfer.",
    "root_cause": ""
  },

  "analysis_scope": "entry_to_internal_sink",
  "entry_function": {
    "function_name": "td_serialize_task_message",
    "file_path": ,
    "start_line": ,
    "end_line": ,
    "entry_custom_prompt": "Public API declared in a header file. Audit caller-controlled arguments and API contract misuse. This header API is an external scan root: zero repository callers, absence from main, or absence of a separate worker/start wrapper is expected and must not be treated as dead code by itself. Treat this as an externally reachable facade: follow its callees and callback/worker paths to the actual internal source/sink operations, and report the concrete vulnerable callee location rather than stopping at the wrapper call site.",
    "entry_exposure": "api",
    "root_kind": "external_scan_root"
  },
  "target_function": {
    "function_name": "_serialize_task",
    "file_path": ,
    "start_line": ,
    "end_line": ,
    "snapshot_summary": null,
    "callers": [],
    "callees": []
  },
  "source": {
    "expression": "_safe_malloc(...) at line 224",
    "file": "src/parser.c",
    "line": 224
  },
  "sink": {
    "operation": "return 0;",
    "file": "src/parser.c",
    "line": 244
  },
  "call_path": {
    "nodes": ["td_serialize_task_message", "_serialize_task"],
    "edges": [
      {
        "caller": "td_serialize_task_message",
        "callee": "_serialize_task",
        "callsite_line": 330,
        "parameter_mapping": [
          {
            "arg_index": 0,
            "actual": "task",
            "formal": "task",
            "source_parameter": "task"
          },
        ]
      }
    ]
  },
  "evidence": {
    "positive_evidence": [],
    "negative_evidence": [],
    "semantic_overlay_evidence": {},
  },
  "target_function_code": ""
}
```

推荐字段说明：

| 推荐字段 | 来源或取值方法 | 含义 |
|---|---|---|
| `candidate` | 由原 Finding 的 Candidate 身份字段去重重组。 | 待 Validator 判断的单个 Clang Candidate 身份对象。 |
| `candidate.id` | 原 `Finding.id/candidate_id`；两者相等时只保留一份。 | 关联 Validator 输入、输出和运行记录的唯一标识。 |
| `candidate.source_kind` | 原 `candidate_source`，Clang 固定取 `clang_ast_cfg`。 | 标识本 Candidate 来自 Clang AST/CFG 规则，不能解释为缺陷已被证明。 |
| `hypothesis` | 原分类、CWE、规则和结论性文案去重、去结论化后重组。 | 集中描述 Validator 需要确认或反驳的缺陷假设。 |
| `hypothesis.defect_class` | 原 `defect_class`，删除 `category/subcategory` 副本。 | 规范化缺陷类别，例如 `use_after_free` 或 `memory_leak`。 |
| `hypothesis.cwe` | 原 `cwe`；没有可靠映射时省略。 | 对外分类标签，不替代具体缺陷主张。 |
| `hypothesis.rule` | 从 compaction 前 Clang `evidence_pack.rule` 恢复。 | 精确标识产生 Candidate 的 Clang 规则。 |
| `hypothesis.claim` | 对原 `description/reasoning` 去重并改写为中性、可证伪句。 | Validator 实际需要判断的核心主张。 |
| `hypothesis.root_cause` | 原 `root_cause` 去结论化；没有实例级依据时使用空字符串或省略。 | 候选根因假设，不是已验证事实。 |
| `analysis_scope` | 由原 `internal_sink_lifted/path_kind`、entry/target 是否相同及 canonical call path 联合判断。 | Clang 结构枚举：普通结构为 `single_function`，入口提升结构为 `entry_to_internal_sink`。 |
| `entry_function` | 原 `current_analysis_entry/entry_function` 与 CodeIndex 函数定义、入口上下文合并。 | 本轮扫描入口的定位和暴露信息。 |
| `entry_function.function_name` | 原 analysis entry 或 canonical `entry_function`。 | 入口函数名称；普通结构中与目标函数名称相同。 |
| `entry_function.file_path` | 通过 CodeIndex/Clang 函数定义解析入口函数文件。 | 入口函数所在源码文件。 |
| `entry_function.start_line` | 通过 CodeIndex/Clang 函数定义取得。 | 入口函数源码范围起始行。 |
| `entry_function.end_line` | 通过 CodeIndex/Clang 函数定义取得。 | 入口函数源码范围结束行。 |
| `entry_function.entry_custom_prompt` | 原 `Pack.entry_context.entry_custom_prompt`。 | EntryDiscovery 为该入口生成的审计提示；内容随入口发现类型变化。 |
| `entry_function.entry_exposure` | 原 `Pack.entry_context.entry_exposure`。 | 入口暴露类别，例如 `api`、`communication`、`thread` 或 `other_user_input`。 |
| `entry_function.root_kind` | 仅由原 `entry_is_external_root` 和 `entry_is_scan_root` 按四态真值表映射。 | 表示外部根与本轮扫描根的组合，不读取 exposure 或 prompt。 |
| `target_function` | 原 Finding function、candidate path target/sink function 与 CodeIndex 函数上下文合并。 | 实际承载 Clang 局部规则命中、需要检查的目标函数。 |
| `target_function.function_name` | 原 `Finding.function` 或 `path.target_function/sink_function`。 | 目标函数名称；普通结构中与入口函数名称相同。 |
| `target_function.file_path` | 通过 Finding location 或 CodeIndex/Clang 函数定义解析。 | 目标函数所在源码文件。 |
| `target_function.start_line` | 通过 CodeIndex/Clang 函数定义取得。 | 目标函数源码范围起始行。 |
| `target_function.end_line` | 通过 CodeIndex/Clang 函数定义取得。 | 目标函数源码范围结束行。 |
| `target_function.snapshot_summary` | 原 `Pack.function_context.snapshot_summary`；无快照时为 `null`。 | 目标函数可用的紧凑语义快照。 |
| `target_function.callers` | 原 `Pack.function_context.callers`，按名称、文件和调用行去重。 | CodeIndex 已知的直接调用者列表；空数组表示未提供调用者证据。 |
| `target_function.callers[].name` | 原 caller 记录的 `name`。 | 直接调用者函数名称。 |
| `target_function.callers[].filename` | 原 caller 记录的 `filename`。 | 调用者函数所在文件。 |
| `target_function.callers[].callee_filename` | 原 caller 记录的 `callee_filename`。 | 被调用目标函数所在文件，用于消除同名函数歧义。 |
| `target_function.callers[].lineNumber` | 原 caller 记录的 `lineNumber`。 | 调用发生的源码行。 |
| `target_function.callees` | 原 `Pack.function_context.callees`，按调用目标和调用点去重。 | 目标函数直接调用的函数列表。 |
| `target_function.callees[].name` | 原 callee 记录的 `name`。 | 被调函数名称。 |
| `target_function.callees[].filename` | 原 callee 记录的 `filename`。 | 被调函数声明或定义所在文件。 |
| `target_function.callees[].lineNumber` | 原 callee 记录的 `lineNumber`。 | 目标函数中的调用点行号。 |
| `target_function.callees[].call_type` | 原 CodeIndex call edge 的 `call_type`。 | 调用类型，例如 `direct` 或 `indirect`。 |
| `target_function.callees[].callee_kind` | 原 CodeIndex call edge 的 `callee_kind`。 | 被调目标类别，例如函数、函数指针或外部符号。 |
| `target_function.callees[].callee_signature` | 原 CodeIndex/Clang 解析出的 `callee_signature`；未知时为空。 | 被调目标签名，用于重载、同名或间接调用判别。 |
| `source` | 原 `candidate_evidence.source` 与 Finding source 去重。 | Clang 规则识别的候选起始表达式及定位，不自动等价于污点源。 |
| `source.expression` | 原结构化 source expression。 | 被规则跟踪的资源、指针、状态或关键表达式。 |
| `source.file` | 原 source location 的文件。 | source 所在源码文件。 |
| `source.line` | 原 source location 的行号。 | source 所在源码行。 |
| `sink` | 原 `candidate_evidence.sink` 与 Finding sink 去重。 | Clang 规则识别的关键操作或退出点。 |
| `sink.operation` | 原结构化 sink operation。 | 需要验证安全性的操作、调用或 return。 |
| `sink.file` | 原 sink location 的文件。 | sink 所在源码文件。 |
| `sink.line` | 原 sink location 的行号。 | sink 所在源码行。 |
| `call_path` | 原 canonical `call_path` 与 `path.call_edges/call_path_edges` 合并。 | 入口到目标函数的调用路径容器。 |
| `call_path.nodes` | 普通结构生成仅含当前函数的单节点数组；提升结构使用 canonical 函数序列。 | 按调用顺序排列的函数名称。 |
| `call_path.edges` | 原 call edge 证据去重；普通结构固定为空数组。 | `nodes` 中相邻函数之间的调用点与参数传播信息。 |
| `call_path.edges[].caller` | 原 call edge `caller`。 | 当前调用边的调用者。 |
| `call_path.edges[].callee` | 原 call edge `callee`。 | 当前调用边的被调函数。 |
| `call_path.edges[].callsite_line` | 由原 `call_line` 规范化命名。 | 调用发生的源码行。 |
| `call_path.edges[].parameter_mapping` | 原 call edge 参数映射结果；无可用映射时为空或省略。 | 描述实参如何传入目标函数形参。 |
| `call_path.edges[].parameter_mapping[].arg_index` | 原参数映射中的参数序号。 | 实参/形参在调用签名中的零基位置。 |
| `call_path.edges[].parameter_mapping[].actual` | 原调用点提取的实参表达式。 | 调用者传入的值或对象。 |
| `call_path.edges[].parameter_mapping[].formal` | 原 callee 声明中的形参名称。 | callee 内承接实参的变量。 |
| `call_path.edges[].parameter_mapping[].source_parameter` | 当实参直接来自 caller 形参时，由调用边重建逻辑填写。 | 标识跨调用边继续传播的入口参数；不适用时省略。 |
| `evidence` | 原 Finding/Pack 正反证据和候选级 overlay 命中去重合并。 | 除 source、sink、call path 和源码外的实例级证据容器。 |
| `evidence.positive_evidence` | 原多层 `positive_evidence` 合并去重。 | 支持当前假设、但尚未由其他结构化字段表达的实例事实。 |
| `evidence.negative_evidence` | 原多层 `negative_evidence` 合并去重，并删除固定政策模板。 | 与当前假设冲突或限制其成立条件的实例事实。 |
| `evidence.semantic_overlay_evidence` | 原 Candidate 实际命中的 `semantic_overlay_evidence`，删除全局 overlay 清单副本。 | 当前假设使用的 allocator、ownership、lock 等外部语义模型；空对象表示没有实例级命中。 |
| `target_function_code` | 原 issue code、`function_context.code` 与 Relevant Code Context 去重后保留目标函数的一份代码。 | Validator 直接阅读的目标函数源码；不再重复发送 snippet 和 function code 副本。 |
## 第二章 `graph_rule`

本次运行中共有 57 个去重后的 `graph_rule` Candidate。该来源的原始生成器可以提供对象、事件关系、生命周期配对和规则专属字段，但当前 Validator compaction 只保留通用 source、sink 和 `path`。因此示例中的 graph path 退化为两个字段，Validator 看不到具体 rule 名称、对象模型或协议关系。

本章示例：

- Candidate：`GRAPH_MEMORY_LEAK_821b1ec058`
- 函数：`_runtime_release_reader_channel`
- 位置：`src/lifecycle.c:1295`
- [Suspected Finding](/home/jager/Z-Scope-benchmark/test/range/.zscope_conversations/run_20260805_173936_72536/zscope-validator-3-validator_agent-0065.md:119)
- [Compact Evidence Pack](/home/jager/Z-Scope-benchmark/test/range/.zscope_conversations/run_20260805_173936_72536/zscope-validator-3-validator_agent-0065.md:245)

### 2.1 `Suspected Finding` + `Compact Evidence Pack` 原始字段

本节只列原始对象；两类对象的全部字段统一在 2.2 逐字段分析。

#### 2.1.1 `Suspected Finding`

模型实际收到的顶层结构共有 39 个字段：

```json
{
  "id": "GRAPH_MEMORY_LEAK_821b1ec058",
  "candidate_id": "GRAPH_MEMORY_LEAK_821b1ec058",
  "function": "_runtime_release_reader_channel",
  "location": "src/lifecycle.c:1295",
  "category": "memory_leak",
  "subcategory": "memory_leak",
  "defect_class": "memory_leak",
  "finding_kind": "graph_candidate",
  "candidate_source": "graph_rule",
  "cwe": "CWE-401",
  "description": "A role-specific release helper is called with a hardcoded role instead of the object's stored role.",
  "root_cause": "Cleanup only releases resources for one role and can leak role-specific members owned by other roles.",
  "suggested_fix": "Pass the stored role/member role to the release helper...",
  "confidence": 0.84,
  "rule_confidence": 0.84,
  "impact_level": "high",
  "reasoning": "Graph candidate generated from cross-function C protocol evidence.",
  "code_snippet": "1293 | node->role = role;\n1295 | _service_release_by_role(node, 0);",
  "source": "node->role = role;",
  "sink": "_service_release_by_role(node, 0);",
  "dedup_key": "memory_leak|src/lifecycle.c|1295|role_specific_release_uses_hardcoded_role|...",
  "positive_evidence": [
    "line 1293: object role is set from `role`",
    "line 1295: role-specific release is called with literal `0`"
  ],
  "evidence_refs": ["ir_path_slices:392", "ir_resource_events:101"],
  "backend_profile": "unified",
  "evidence_checker": "unified_callgraph_svf_protocol_checker",
  "evidence_engines": ["... four run-level engines ..."],
  "validation_required": true,
  "candidate_role": "evidence_only",
  "candidate_schema_version": "zscope.candidate.v3",
  "candidate_uid": "CAND_...",
  "occurrence_uid": "OCC_...",
  "history_key": "HIST_...",
  "evidence_hash": "...",
  "decision_evidence_hash": "...",
  "provenance_hash": "...",
  "validation_cluster_uid": "VAL_...",
  "context_signature": "...",
  "evidence_models": {
    "value_flow": {
      "source": "node->role = role;",
      "sink": "_service_release_by_role(node, 0);"
    }
  },
  "evidence_summary": {
    "candidate_id": "GRAPH_MEMORY_LEAK_821b1ec058",
    "candidate_source": "graph_rule",
    "defect_class": "memory_leak",
    "source": {
      "expression": "node->role = role;",
      "file": "src/lifecycle.c",
      "line": 1295
    },
    "sink": {
      "operation": "_service_release_by_role(node, 0);",
      "file": "src/lifecycle.c",
      "line": 1295
    },
    "path": {
      "function": "_runtime_release_reader_channel",
      "complete_in_function": false
    },
    "positive_evidence": ["..."],
    "negative_evidence": [],
    "evidence_refs": ["..."],
    "backend_profile": "unified",
    "checker": "unified_callgraph_svf_protocol_checker",
    "semantic_overlays": {"...": "global model list"},
    "semantic_overlay_evidence": {},
    "validation_required": true
  }
}
```

#### 2.1.2 `Compact Evidence Pack`

Graph Pack 使用与 Clang 完全相同的 28 字段顶层模板。来源差异主要在 `candidate_evidence.path`：

```json
{
  "mode": "tri_state_exploitability_validation",
  "dedup_key": "memory_leak|src/lifecycle.c|1295|role_specific_release_uses_hardcoded_role|...",
  "candidate_id": "GRAPH_MEMORY_LEAK_821b1ec058",
  "candidate_role": "evidence_only",
  "candidate_is_conclusion": false,
  "validation_required": true,
  "proofs": {},
  "audit_observation_reason": null,
  "va_unreviewed": false,
  "backend_profile": "unified",
  "evidence_checker": "unified_callgraph_svf_protocol_checker",
  "evidence_engines": ["..."],
  "semantic_overlays": {"...": "global model list"},
  "semantic_overlay_evidence": {},
  "finding_kind": "graph_candidate",
  "defect_class": "memory_leak",
  "rule_confidence": 0.84,
  "score_components": {
    "rule_confidence": 0.84,
    "path_completeness": 0.75,
    "contract_consistency": 0.8,
    "validation_confidence": 0.84,
    "history_feedback": 0.5,
    "final_score": 0.7755
  },
  "evidence_refs": ["ir_path_slices:392", "ir_resource_events:101"],
  "finding_summary": {
    "id": "GRAPH_MEMORY_LEAK_821b1ec058",
    "function": "_runtime_release_reader_channel",
    "location": "src/lifecycle.c:1295",
    "category": "memory_leak",
    "subcategory": "memory_leak",
    "confidence": 0.84,
    "description": "A role-specific release helper...",
    "source": "node->role = role;",
    "sink": "_service_release_by_role(node, 0);",
    "cwe": "CWE-401"
  },
  "entry_context": {
    "current_analysis_entry": "td_run_service_cleanup_cases",
    "entry_custom_prompt": "Public API declared in a header file...",
    "entry_exposure": "api",
    "entry_is_external_root": true,
    "entry_is_scan_root": true,
    "zero_callers_is_expected_for_entry": true,
    "public_trigger": "Header-declared/configured entry function is an external scan root...",
    "issue_entry_function": "",
    "reachable_from_entry": false,
    "internal_sink_lifted": false,
    "call_path": null,
    "candidate_path": {
      "function": "_runtime_release_reader_channel",
      "complete_in_function": false
    }
  },
  "candidate_evidence": {
    "candidate_id": "GRAPH_MEMORY_LEAK_821b1ec058",
    "candidate_source": "graph_rule",
    "defect_class": "memory_leak",
    "source": {
      "expression": "node->role = role;",
      "file": "src/lifecycle.c",
      "line": 1295
    },
    "sink": {
      "operation": "_service_release_by_role(node, 0);",
      "file": "src/lifecycle.c",
      "line": 1295
    },
    "path": {
      "function": "_runtime_release_reader_channel",
      "complete_in_function": false
    },
    "positive_evidence": ["..."],
    "negative_evidence": [],
    "evidence_refs": ["..."],
    "backend_profile": "unified",
    "checker": "unified_callgraph_svf_protocol_checker",
    "semantic_overlays": {"...": "global model list"},
    "semantic_overlay_evidence": {},
    "validation_required": true
  },
  "evidence_models": {
    "value_flow": {
      "source": "node->role = role;",
      "sink": "_service_release_by_role(node, 0);"
    }
  },
  "positive_evidence": ["..."],
  "negative_evidence": [],
  "primary_location_snippet": {"file": "src/lifecycle.c", "start_line": 1283, "end_line": 1307, "code": "..."},
  "function_context": {
    "code": "... _runtime_release_reader_channel ...",
    "snapshot_summary": null,
    "callers": [{"name": "td_run_service_cleanup_cases", "lineNumber": 500}],
    "callees": ["_service_alloc_node", "_service_release_by_role", "SAFE_FREE"]
  },
  "validation_requirements": [
    "... first 12 generic requirements ...",
    {"omitted_items": 7}
  ]
}
```

### 2.2 `Suspected Finding` + `Compact Evidence Pack` 全字段逐字段分析

以下覆盖 57 个 Graph 输入。Graph 的 `path` 是 rule-dependent 异构字典；固定值只能用于公共外壳和本次 profile，不能把示例的两个 path 键推广成来源 schema。

| 字段 | 建议操作 | 重复 / 必要性 / 固定值分析 |
|---|---|---|
| `Finding.id` | 保留并改为 `candidate.id` | 必须关联结果；与 `candidate_id`、Pack ID 和 nested ID 在 57/57 固定相等。 |
| `Finding.candidate_id` | 删除 | 与 `Finding.id` 代码级重复。 |
| `Finding.function` | 合并到 target function | 必须；与 Pack summary、path function 和 function context 重复。 |
| `Finding.location` | 重构为 program point | 必须；复合字符串在 Pack summary 重复。 |
| `Finding.category` | 删除 | 与 `subcategory/defect_class` 在 57/57 固定相等。 |
| `Finding.subcategory` | 删除 | 与 defect class 重复。 |
| `Finding.defect_class` | 保留一次 | 假设分类必需；在 Pack 多层复制。 |
| `Finding.finding_kind` | 移出 Prompt | 固定 `graph_candidate`，只表示来源阶段。 |
| `Finding.candidate_source` | 合并为 `source_kind` | 固定 `graph_rule`；解释证据语义有用，只保留一次。 |
| `Finding.evidence_checker` | 合并到 producer | 本次 unified profile 固定 `unified_callgraph_svf_protocol_checker`；其他 profile 可变。 |
| `Finding.cwe` | 条件保留 | 分类标签可能有用，可由 defect class 映射。 |
| `Finding.description` | 合并为 hypothesis claim | 承载规则主张，但与 root cause/summary 重复。 |
| `Finding.root_cause` | 降级为待验证假设 | 当前把 helper 协议当成事实；缺 helper 实现时不应确认。 |
| `Finding.suggested_fix` | 删除 | 验证前会引导模型接受 Candidate。 |
| `Finding.reasoning` | 删除 | 57/57 固定为 Graph 来源模板，没有实例事实。 |
| `Finding.confidence` | 移出 Prompt | 与 rule confidence 和 Pack 评分链在 57/57 固定相等。 |
| `Finding.rule_confidence` | 移出 Prompt | 上游规则先验，会锚定验证。 |
| `Finding.impact_level` | 移出 Prompt | 报告/排序元数据。 |
| `Finding.code_snippet` | 合并到唯一 code unit | 与 Pack 两份代码及 Relevant Code 重复。 |
| `Finding.source` | 重构为 typed event | 当前是对象字段赋值，不是污点 source；在 model/summary/Pack 重复。 |
| `Finding.sink` | 重构为 typed event | 当前是 release helper 调用，不是通用 sink；多层重复。 |
| `Finding.dedup_key` | 移出 Prompt | 只用于去重；精确 rule 目前被迫残留其中，应恢复正式 `rule_id` 后删除 key。 |
| `Finding.positive_evidence` | 结构化为 events/relations | 必须；与 Pack 顶层/nested evidence 在 Graph 57/57 重复。 |
| `Finding.negative_evidence` | 合并为 counterevidence | 空时不发送；非空时只保留一份。 |
| `Finding.evidence_refs` | 条件保留 | 多层重复；仅工具可解析时发送。 |
| `Finding.backend_profile` | 移出 Prompt | 本次运行固定 `unified`。 |
| `Finding.evidence_engines` | 移出 Prompt | 本次运行固定四引擎清单，不代表四种证明。 |
| `Finding.validation_required` | 删除 | 固定 `true`。 |
| `Finding.candidate_role` | 删除 | 固定 `evidence_only`，System Prompt 已说明。 |
| `Finding.candidate_schema_version` | 移出 Prompt | 固定 `zscope.candidate.v3`。 |
| `Finding.candidate_uid` | 移出 Prompt | 生命周期主键。 |
| `Finding.occurrence_uid` | 移出 Prompt | occurrence 跟踪。 |
| `Finding.history_key` | 移出 Prompt | 历史聚合。 |
| `Finding.evidence_hash` | 移出 Prompt | 缓存摘要。 |
| `Finding.decision_evidence_hash` | 移出 Prompt | 决策缓存摘要。 |
| `Finding.provenance_hash` | 移出 Prompt | provenance 审计摘要。 |
| `Finding.validation_cluster_uid` | 移出 Prompt | 聚类/终态映射。 |
| `Finding.context_signature` | 移出 Prompt | 上下文去重摘要。 |
| `Finding.evidence_models.value_flow` | 删除 | 仅把两个协议事件包装成 source/sink，制造已证明 data flow 的错觉。 |
| `Finding.evidence_summary` | 删除整个副本 | 与 `Pack.candidate_evidence` 57/57 整对象相等。 |
| `Finding.evidence_summary.candidate_id` | 删除 | 与外层 ID 固定相等。 |
| `Finding.evidence_summary.candidate_source` | 合并 | 固定 `graph_rule`。 |
| `Finding.evidence_summary.checker` | 合并到 producer | 本次 profile 固定 checker。 |
| `Finding.evidence_summary.defect_class` | 删除副本 | 与 Finding/Pack 分类重复。 |
| `Finding.evidence_summary.source` | 重构为 event | `expression/file/line` 有定位价值，但 line 与 sink line都由规则主行固定填充，不保证真实端点精度。 |
| `Finding.evidence_summary.sink` | 重构为 event | 与 Finding sink 重复；operation 需保留，定位 provenance 需标注。 |
| `Finding.evidence_summary.path` | 重构为 tagged source-specific evidence | 没有全体固定子 schema：40/57 仅 `function+complete_in_function`，其余 17 个分布为多种规则专属组合。 |
| `Finding.evidence_summary.path.function` | 合并到 target function | 存在时与 Finding function 重复。 |
| `Finding.evidence_summary.path.complete_in_function` | 改为三态 path status | 基础生成值为 `false`，但 rule evidence 可覆盖或省略；不能视为固定或“已证不可行”。 |
| `Finding.evidence_summary.path` 其他 rule-specific 键 | 按 rule 拆为 events/relations | caller/callee/callback/cleanup/source_line 等含义不同，当前缺 tag；不得塞入无类型通用 path。 |
| `Finding.evidence_summary.positive_evidence` | 合并 | 与 Finding/Pack 正向证据重复。 |
| `Finding.evidence_summary.negative_evidence` | 合并 | 与 Pack 反证重复。 |
| `Finding.evidence_summary.evidence_refs` | 条件保留一次 | 多层复制。 |
| `Finding.evidence_summary.backend_profile` | 移出 Prompt | 运行固定 `unified`。 |
| `Finding.evidence_summary.semantic_overlays` | 移出 Prompt | 57/57 同一全局摘要。 |
| `Finding.evidence_summary.semantic_overlay_evidence` | 条件保留 | 只保留当前规则实际命中的模型。 |
| `Finding.evidence_summary.validation_required` | 删除 | 固定 `true`。 |
| 原始 `rule` | 恢复并保留 | compact 后 57/57 缺失；它比 dedup key、UID 更能解释命中语义。 |
| 原始 `object` 及关系块 | 恢复并条件保留 | compact 固定删除；same-object、lifecycle、callback 等规则判断通常必需。 |
| `Pack.mode` | 移出 Prompt | 固定 `tri_state_exploitability_validation`。 |
| `Pack.dedup_key` | 移出 Prompt | 与 Finding 重复。 |
| `Pack.candidate_id` | 删除副本 | 与 Finding ID 固定相等。 |
| `Pack.candidate_role` | 删除 | 固定 `evidence_only`。 |
| `Pack.candidate_is_conclusion` | 删除 | 固定 `false`。 |
| `Pack.validation_required` | 删除 | 固定 `true`。 |
| `Pack.proofs` | 空时删除 | 57/57 为 `{}`。 |
| `Pack.audit_observation_reason` | 空时删除 | 57/57 为 `null`。 |
| `Pack.va_unreviewed` | 移出 Prompt | 57/57 为 `false`。 |
| `Pack.backend_profile` | 移出 Prompt | 运行固定 `unified`。 |
| `Pack.evidence_checker` | 合并到 producer | 本次 profile 固定 checker，与 Finding/nested 重复。 |
| `Pack.evidence_engines` | 移出 Prompt | 运行固定清单。 |
| `Pack.semantic_overlays` | 移出 Prompt | 运行固定摘要，在 nested evidence 重复。 |
| `Pack.semantic_overlay_evidence` | 条件保留一次 | 与 nested overlay evidence 重复。 |
| `Pack.finding_kind` | 移出 Prompt | 固定 `graph_candidate`。 |
| `Pack.defect_class` | 删除副本 | 与 Finding 分类重复。 |
| `Pack.rule_confidence` | 移出 Prompt | 与 Finding confidence 链重复。 |
| `Pack.score_components` | 移出 Prompt | 上游排序数据；`history_feedback=0.5` 本次固定。 |
| `Pack.evidence_refs` | 条件保留一次 | 多层重复。 |
| `Pack.finding_summary` | 删除整个对象 | ID、function、location、category、subcategory、confidence、description、source、sink、cwe 均从 Finding 固定复制。 |
| `Pack.entry_context.current_analysis_entry` | 条件保留 | 入口确实参与协议判断时有用。 |
| `Pack.entry_context.entry_custom_prompt` | 删除 | exposure 模板，与 System Prompt 重复。 |
| `Pack.entry_context.entry_exposure` | 条件保留 | 实例枚举有用。 |
| `Pack.entry_context.entry_is_external_root` | 合并为 root kind | 本次固定 `true`。 |
| `Pack.entry_context.entry_is_scan_root` | 删除或合并 | 本次固定 `true`。 |
| `Pack.entry_context.zero_callers_is_expected_for_entry` | 删除 | 本次固定 `true`，是 System Prompt 规则。 |
| `Pack.entry_context.public_trigger` | 删除 | 本次固定长文本。 |
| `Pack.entry_context.issue_entry_function` | 空时删除 | Graph 没有接入 canonical issue entry。 |
| `Pack.entry_context.reachable_from_entry` | 改为三态 | false 54、true 3；false 多表示 builder 未建立，不是已证不可达。 |
| `Pack.entry_context.internal_sink_lifted` | 删除 | 57/57 固定 `false`；Graph path 不使用 Clang lift 协议。 |
| `Pack.entry_context.call_path` | 空时删除 | 57/57 固定 `null`，即使 rule-specific path 含 caller/callee。 |
| `Pack.entry_context.candidate_path` | 删除 | 与 `candidate_evidence.path` 57/57 完全相等。 |
| `Pack.candidate_evidence` | 保留并重构为唯一 evidence | 与 Finding summary 57/57 相等；应恢复 rule/object，并改为 tagged union。 |
| `Pack.evidence_models` | 删除或合并 | value flow 只复制协议 source/sink。 |
| `Pack.positive_evidence` | 合并去重 | 与 nested positive evidence 57/57 相等。 |
| `Pack.negative_evidence` | 合并为 counterevidence | 与 nested/Finding 重复；空时省略。 |
| `Pack.primary_location_snippet` | 合并到 code unit | 与 Finding snippet、function code、Relevant Code 重叠。 |
| `Pack.function_context.code` | 删除副本 | 与 Relevant Code 同源；Graph 54/57 完全相等，其余是截断。 |
| `Pack.function_context.snapshot_summary` | 空时删除 | 57/57 为 `null`。 |
| `Pack.function_context.callers` | 条件保留 | 仅保留支持 reachability 的边。 |
| `Pack.function_context.callees` | 条件保留且补代码 | helper 语义常决定规则真假；只给名称不足，应提供决定性 helper code unit。 |
| `Pack.validation_requirements` | 从 Pack 删除 | 前 12 条固定；第 13 项 57/57 为 `omitted_items=3`，Graph 类别专属规则正文被截断。 |

### 2.3 Graph 丢失字段说明

Graph 与 Clang 使用同一 `_compact_candidate_evidence()` 白名单。Graph 生成器先写入公共 `evidence_pack`，再用 rule-specific `evidence` 对其扩展；其中 `path` 在白名单内，因而内部的 caller/callee、source/sink line 和 `path_constraints` 可以保留，但与 `path` 同级的任意 rule-specific 关系块都会被静默删除。

| 生成器原始字段 | 原始内容 | 丢失方式与信息影响 | 推荐处理 |
|---|---|---|---|
| `evidence_pack.rule` | 精确 Graph rule，例如错误 cleanup role、paired lifecycle 或 callback protocol | 不在白名单，57/57 Validator 输入的正式 evidence 均缺失；部分 rule 字符只偶然残留在 `dedup_key`。 | 恢复为 hypothesis 的实例级 rule/basis；`dedup_key` 仍留在运行元数据，不充当证据载体。 |
| `evidence_pack.rule_confidence` | 规则先验置信度 | 不在白名单；与 Finding confidence 链重复，丢失不影响代码事实。 | 不恢复到 Prompt，仅作排序/审计元数据。 |
| `evidence_pack.object` | 基础生成器记录的对象 ID 和 aliases | 不在白名单，固定丢失。当前基础值多由 source/sink/defect class 回填且 aliases 为空，所以原样恢复的价值有限；但 Graph 规则确实需要 same-object 身份。 | 不恢复这个弱 wrapper；从具体赋值、参数映射和生命周期事件构造有证据依据的 object ID 与 `relations`。 |
| rule-specific `path` 子字段 | `caller/callee/callback`、配对函数、关键行、路径约束等 | 因为父键 `path` 在白名单内，这些字段通常没有被顶层 compaction 删除；但通用嵌套压缩仍会对长列表、长字符串和超过 24 个键的字典截断。 | 拆成 tagged source-specific events/relations，并显式标注 path completeness；不将异构规则都塞进无类型 `path`。 |
| `lifecycle_pair` 等与 `path` 同级的关系块 | 注册/清理函数对、生命周期关系或其他 rule-specific 扩展 | 只要键不在通用白名单就固定丢失；不会出现在 `compaction_metadata`。这会把“两个事件为什么属于同一协议”压成零散文本。 | 恢复为有类型的 `events`、`relations` 或 `protocol_claim`，并保留关系的代码依据。 |
| 其他未入白名单的 rule-specific 顶层键 | `pack.update(evidence)` 允许各规则添加的任意字段 | 压缩器是封闭白名单，生成器却是开放扩展；两者的 schema 契约不对称，新 rule 即使生成了证据也可能无声丢失。 | 将 Graph evidence 改为显式 tagged union，并在测试中校验生成字段必须被消费、转换或记录为 omitted。 |

`_service_release_by_role` 等决定性 helper 的函数体不属于“被 compaction 删除的字段”：当前 Candidate pack 本来就只写入 helper 名称或调用关系，没有写入 helper 代码。这是上游 evidence assembly 不完整，需要在新 `code_context.units` 中按需补充，不能通过放宽 compact 白名单恢复。

### 2.4 `graph_rule` 推荐新字段

```json
{
  "candidate": {
    "id": "GRAPH_MEMORY_LEAK_821b1ec058",
    "source_kind": "graph_rule",
    },
  "hypothesis": {
    "defect_class": "memory_leak",
    "cwe": "CWE-401",
    "rule": "role_specific_release_uses_hardcoded_role",
    "claim": "The release call may use a role value inconsistent with the object's stored role.",
    "root_cause": ""
  },
  "entry_function": {
    "function_name": "td_run_service_cleanup_cases",
    "file_path": ,
    "start_line": ,
    "end_line": ,
    "entry_custom_prompt": "",
    "entry_exposure": "api",
    "root_kind": "external_scan_root"
  },
  "target_function": {
    "function_name": "_runtime_release_reader_channel",
    "file_path": ,
    "start_line": ,
    "end_line": ,
    "snapshot_summary": null,
    "callers": [],
    "callees": []
  },
  "source": {
    "expression": "node->role = role;",
    "file": "src/lifecycle.c",
    "line": 1295
    },
  "sink": {
    "operation": "_service_release_by_role(node, 0);",
    "file": "src/lifecycle.c",
    "line": 1295
  },
  "call_path": {
    "nodes": []
  },
  "evidence": {
    "source_evidence": {
      "relations": {},
      "lifecycle_pair": {},
      "cascade_wait": {},
    },
    "positive_evidence": [],
    "negative_evidence": [],
    "semantic_overlay_evidence": {},
  },
  "target_function_code": ""
}
```

推荐字段说明：

| 推荐字段 | 来源或取值方法 | 含义 |
|---|---|---|
| `candidate` | 由原 Finding 的 Candidate 身份字段去重重组。 | 待 Validator 判断的单个 Graph Candidate 身份对象。 |
| `candidate.id` | 原 `Finding.id/candidate_id`；两者相等时只保留一份。 | 关联 Validator 输入、输出和运行记录的唯一标识。 |
| `candidate.source_kind` | 原 `candidate_source`，Graph 固定取 `graph_rule`。 | 标识本 Candidate 来自 Graph rule，不能解释为协议缺陷已被证明。 |
| `hypothesis` | 原分类、Graph rule 和结论文案去重、去结论化后重组。 | 集中表达需要验证的协议假设。 |
| `hypothesis.defect_class` | 原 `defect_class`，删除 `category/subcategory` 副本。 | 规范化缺陷类别，例如 `memory_leak` 或 `race`。 |
| `hypothesis.cwe` | 原 `cwe`；没有可靠映射时省略。 | 对外分类标签，不替代协议事实。 |
| `hypothesis.rule` | 从 compaction 前 Graph `evidence_pack.rule` 恢复。 | 精确标识触发 Candidate 的 Graph 规则。 |
| `hypothesis.claim` | 原 `description/root_cause` 去结论化后合并。 | Validator 要确认或反驳的协议主张。 |
| `hypothesis.root_cause` | 原 `root_cause`；缺少 helper 代码依据时置空或省略。 | 候选根因假设，不能当作已验证事实。 |
| `entry_function` | 原 entry context、analysis entry 和入口定义信息合并。 | 当前扫描入口的定位和暴露信息。 |
| `entry_function.function_name` | 原 `current_analysis_entry` 或 entry function。 | 入口函数名称。 |
| `entry_function.file_path` | 通过 CodeIndex/Clang 函数定义解析。 | 入口函数所在源码文件。 |
| `entry_function.start_line` | 通过 CodeIndex/Clang 函数定义取得。 | 入口函数源码范围起始行。 |
| `entry_function.end_line` | 通过 CodeIndex/Clang 函数定义取得。 | 入口函数源码范围结束行。 |
| `entry_function.entry_custom_prompt` | 原 `Pack.entry_context.entry_custom_prompt`。 | EntryDiscovery 为入口生成的审计提示；内容随入口发现类型变化。 |
| `entry_function.entry_exposure` | 原 `Pack.entry_context.entry_exposure`。 | 入口暴露类别，例如 API、通信或线程入口。 |
| `entry_function.root_kind` | 仅由原 `entry_is_external_root` 和 `entry_is_scan_root` 按四态真值表映射。 | 表示外部根与本轮扫描根的组合；Graph rule、exposure 和 prompt 不参与取值。 |
| `target_function` | 原 Finding function 与 Graph evidence path/function 合并。 | Graph 事件、对象关系和规则主张所在的目标函数。 |
| `target_function.function_name` | 原 `Finding.function` 或 `candidate_evidence.path.function`。 | 目标函数名称。 |
| `target_function.file_path` | 通过 Finding location 或 CodeIndex 函数定义解析。 | 目标函数所在源码文件。 |
| `target_function.start_line` | 通过 CodeIndex/Clang 函数定义取得。 | 目标函数源码范围起始行。 |
| `target_function.end_line` | 通过 CodeIndex/Clang 函数定义取得。 | 目标函数源码范围结束行。 |
| `target_function.snapshot_summary` | 原 `Pack.function_context.snapshot_summary`；无快照时为 `null`。 | 目标函数可用的紧凑语义快照。 |
| `target_function.callers` | 原 `Pack.function_context.callers`，按调用者和调用行去重。 | CodeIndex 已知的直接调用者列表。 |
| `target_function.callers[].name` | 原 caller 记录的 `name`。 | 直接调用者函数名称。 |
| `target_function.callers[].filename` | 原 caller 记录的 `filename`。 | 调用者所在文件。 |
| `target_function.callers[].callee_filename` | 原 caller 记录的 `callee_filename`。 | 被调用目标所在文件，用于消除同名歧义。 |
| `target_function.callers[].lineNumber` | 原 caller 记录的 `lineNumber`。 | 调用发生的源码行。 |
| `target_function.callees` | 原 `Pack.function_context.callees`，按目标和调用点去重。 | 目标函数直接调用的函数列表。 |
| `target_function.callees[].name` | 原 callee 记录的 `name`。 | 被调函数名称。 |
| `target_function.callees[].filename` | 原 callee 记录的 `filename`。 | 被调函数声明或定义所在文件。 |
| `target_function.callees[].lineNumber` | 原 callee 记录的 `lineNumber`。 | 调用点源码行。 |
| `target_function.callees[].call_type` | 原 CodeIndex call edge 的 `call_type`。 | 调用类型，例如 direct 或 indirect。 |
| `target_function.callees[].callee_kind` | 原 CodeIndex call edge 的 `callee_kind`。 | 被调目标类别。 |
| `target_function.callees[].callee_signature` | 原 CodeIndex/Clang 解析的 callee signature；未知时为空。 | 被调目标签名，辅助核查协议边界。 |
| `source` | 原 Graph candidate evidence source 与 Finding source 去重。 | Graph 规则识别的源事件或对象表达式，不自动等价于污点源。 |
| `source.expression` | 原 source expression。 | 规则识别的赋值、对象或调用相关表达式。 |
| `source.file` | 原 source location 文件。 | source 事件所在源码文件。 |
| `source.line` | 原 source location 行号。 | source 事件所在源码行。 |
| `sink` | 原 Graph candidate evidence sink 与 Finding sink 去重。 | Graph 规则识别的目标操作或协议事件，不自动等价于数据流 sink。 |
| `sink.operation` | 原 sink operation。 | 规则关注的调用、释放、发布或其他操作。 |
| `sink.file` | 原 sink location 文件。 | sink 事件所在源码文件。 |
| `sink.line` | 原 sink location 行号。 | sink 事件所在源码行。 |
| `call_path` | 只从可验证的 canonical call path 生成；不把 rule-specific caller/callee 关系冒充完整调用链。 | 入口到目标函数的调用路径容器。 |
| `call_path.nodes` | 当前 Graph 示例没有标准调用链，因此为空数组；有独立调用图证据时填入函数序列。 | 按调用顺序排列的函数名称；空数组表示未提供 canonical path。 |
| `evidence` | 原 Graph source/sink、object、rule-specific evidence、正反证据和代码定位重组。 | Graph Candidate 的唯一证据主体。 |
| `evidence.source_evidence` | 从原 Graph `object`、关系块和规则专属 evidence 归一化；当前示例保留三个可扩展关系容器。 | 承载 Graph 来源独有的关系证据，不与通用 source/sink 混淆。 |
| `evidence.source_evidence.relations` | 原 same-object、callback/cleanup 等关系证据；无关系时为空对象。 | 连接事件或对象的结构化关系。 |
| `evidence.source_evidence.lifecycle_pair` | 原 `evidence_pack.lifecycle_pair`；无生命周期配对时为空对象。 | 注册/创建与清理/释放操作之间的配对依据。 |
| `evidence.source_evidence.cascade_wait` | 原 timer/callback cascade-wait rule 的专属 evidence；不适用时为空对象。 | 描述 callback、scheduler holder 和等待链之间的关系。 |
| `evidence.positive_evidence` | 原多层 `positive_evidence` 合并去重。 | 支持协议假设、但尚未结构化的实例事实。 |
| `evidence.negative_evidence` | 原多层 `negative_evidence` 合并去重，并删除固定政策模板。 | 与协议假设冲突或限制其成立的实例事实。 |
| `evidence.semantic_overlay_evidence` | 原 Candidate 实际命中的 overlay evidence，删除全局摘要副本。 | 当前规则使用的 allocator、lock、ownership 等外部模型；空对象表示没有实例级命中。 |
| `target_function_code` | 原 issue code、`function_context.code` 和 Relevant Code Context 去重后保留目标函数代码。 | Validator 直接阅读的目标函数源码；不重复发送 snippet 副本。 |
## 第三章 `svf_value_flow`

本次运行中共有 13 个去重后的 `svf_value_flow` Candidate。该来源是 SVF/Saber 后端信号与源码级 best-effort 重建的组合。当前 Validator 输入删除了原始 `value_flow` 和 `source_path`，只保留一个通用 path，并把 `td_init` 和 `Memory Leak` 包装成 source/sink。这个结构没有清楚区分“后端报告”“LLVM 节点级 flow”“源码映射”和“入口调用链”。

本章示例：

- Candidate：`SVF_VALUE_FLOW_bbbaa268e158`
- 函数：`td_init`
- 位置：`src/main.c:188`
- [Suspected Finding](/home/jager/Z-Scope-benchmark/test/range/.zscope_conversations/run_20260805_173936_72536/zscope-validator-3-validator_agent-0006.md:120)
- [Compact Evidence Pack](/home/jager/Z-Scope-benchmark/test/range/.zscope_conversations/run_20260805_173936_72536/zscope-validator-3-validator_agent-0006.md:282)

### 3.1 `Suspected Finding` + `Compact Evidence Pack` 原始字段

本节只列原始对象；两类对象的全部字段统一在 3.2 逐字段分析。

#### 3.1.1 `Suspected Finding`

模型实际收到的顶层结构共有 39 个字段：

```json
{
  "id": "SVF_VALUE_FLOW_bbbaa268e158",
  "candidate_id": "SVF_VALUE_FLOW_bbbaa268e158",
  "function": "td_init",
  "location": "src/main.c:188",
  "category": "memory_leak",
  "subcategory": "memory_leak",
  "defect_class": "memory_leak",
  "finding_kind": "svf_value_flow_candidate",
  "candidate_source": "svf_value_flow",
  "evidence_checker": "svf_value_flow_checker",
  "cwe": "CWE-401",
  "description": "SVF/Saber reported `Memory Leak` in `td_init`.",
  "root_cause": "SVF/Saber value-flow analysis produced a memory lifetime signal requiring source-level validation.",
  "suggested_fix": "Validate the reported flow, then fix the ownership, lifetime, or failure-path contract.",
  "confidence": 0.76,
  "rule_confidence": 0.76,
  "impact_level": "medium",
  "reasoning": "SVF/Saber value-flow checker reported `Memory Leak`... This is evidence only...",
  "source": "td_init",
  "sink": "Memory Leak",
  "dedup_key": "memory_leak|src/main.c|188|td_init|Memory Leak",
  "positive_evidence": [
    "saber reported `Memory Leak` at src/main.c:188",
    "SVF source `td_init` flows to sink `Memory Leak`",
    "Clang function signature: int td_init(const char* config_str)",
    "Containing function range: 128-210",
    "Source snippet near SVF location: ...",
    "Source-level flow events: reported_location `Memory Leak`...",
    "Source-level reconstruction found entry call path: main -> td_init"
  ],
  "negative_evidence": [
    "Validator must confirm source-to-sink feasibility on the concrete C path.",
    "LLVM-level signal must be reconciled with source-level ownership semantics."
  ],
  "evidence_refs": ["..."],
  "backend_profile": "unified",
  "evidence_engines": ["... four run-level engines ..."],
  "validation_required": true,
  "candidate_role": "evidence_only",
  "candidate_schema_version": "zscope.candidate.v3",
  "candidate_uid": "CAND_...",
  "occurrence_uid": "OCC_...",
  "history_key": "HIST_...",
  "evidence_hash": "...",
  "decision_evidence_hash": "...",
  "provenance_hash": "...",
  "validation_cluster_uid": "VAL_...",
  "context_signature": "...",
  "evidence_models": {
    "value_flow": {
      "source": "td_init",
      "sink": "Memory Leak"
    }
  },
  "evidence_summary": {
    "candidate_id": "SVF_VALUE_FLOW_bbbaa268e158",
    "candidate_source": "svf_value_flow",
    "checker": "svf_value_flow_checker",
    "defect_class": "memory_leak",
    "source": {
      "expression": "td_init",
      "file": "src/main.c",
      "line": 188
    },
    "sink": {
      "operation": "Memory Leak",
      "file": "src/main.c",
      "line": 188
    },
    "path": {
      "function": "td_init",
      "entry_function": "td_init",
      "backend": "SVF/Saber value-flow",
      "complete_in_function": false,
      "path_constraints": [
        "SVF/Saber produced a backend memory/value-flow signal",
        "validator must reconcile LLVM-level fact with source-level ownership semantics"
      ]
    },
    "positive_evidence": ["..."],
    "negative_evidence": ["..."],
    "evidence_refs": ["..."],
    "backend_profile": "unified",
    "semantic_overlays": {"...": "global model list"},
    "semantic_overlay_evidence": {"resource_models": ["..."]},
    "validation_required": true
  }
}
```

#### 3.1.2 `Compact Evidence Pack`

```json
{
  "mode": "tri_state_exploitability_validation",
  "dedup_key": "memory_leak|src/main.c|188|td_init|Memory Leak",
  "candidate_id": "SVF_VALUE_FLOW_bbbaa268e158",
  "candidate_role": "evidence_only",
  "candidate_is_conclusion": false,
  "validation_required": true,
  "proofs": {},
  "audit_observation_reason": null,
  "va_unreviewed": false,
  "backend_profile": "unified",
  "evidence_checker": "svf_value_flow_checker",
  "evidence_engines": ["..."],
  "semantic_overlays": {"...": "global model list"},
  "semantic_overlay_evidence": {
    "resource_models": [
      {"name": "_safe_calloc", "kind": "calloc", "carrier": "return_value"}
    ]
  },
  "finding_kind": "svf_value_flow_candidate",
  "defect_class": "memory_leak",
  "rule_confidence": 0.76,
  "score_components": {
    "rule_confidence": 0.76,
    "path_completeness": 0.75,
    "contract_consistency": 0.55,
    "validation_confidence": 0.76,
    "history_feedback": 0.5,
    "final_score": 0.6895
  },
  "evidence_refs": ["..."],
  "finding_summary": {
    "id": "SVF_VALUE_FLOW_bbbaa268e158",
    "function": "td_init",
    "location": "src/main.c:188",
    "category": "memory_leak",
    "subcategory": "memory_leak",
    "confidence": 0.76,
    "description": "SVF/Saber reported `Memory Leak` in `td_init`.",
    "source": "td_init",
    "sink": "Memory Leak",
    "cwe": "CWE-401"
  },
  "entry_context": {
    "current_analysis_entry": "td_init",
    "entry_custom_prompt": "Public API declared in a header file...",
    "entry_exposure": "api",
    "entry_is_external_root": true,
    "entry_is_scan_root": true,
    "zero_callers_is_expected_for_entry": true,
    "public_trigger": "Header-declared/configured entry function is an external scan root...",
    "issue_entry_function": "",
    "reachable_from_entry": true,
    "internal_sink_lifted": false,
    "call_path": null,
    "candidate_path": {
      "function": "td_init",
      "entry_function": "td_init",
      "backend": "SVF/Saber value-flow",
      "complete_in_function": false,
      "path_constraints": ["... two generic backend instructions ..."]
    }
  },
  "candidate_evidence": {
    "candidate_id": "SVF_VALUE_FLOW_bbbaa268e158",
    "candidate_source": "svf_value_flow",
    "checker": "svf_value_flow_checker",
    "defect_class": "memory_leak",
    "source": {"expression": "td_init", "file": "src/main.c", "line": 188},
    "sink": {"operation": "Memory Leak", "file": "src/main.c", "line": 188},
    "path": {
      "function": "td_init",
      "entry_function": "td_init",
      "backend": "SVF/Saber value-flow",
      "complete_in_function": false,
      "path_constraints": ["... two generic backend instructions ..."]
    },
    "positive_evidence": ["..."],
    "negative_evidence": ["..."],
    "evidence_refs": ["..."],
    "backend_profile": "unified",
    "semantic_overlays": {"...": "global model list"},
    "semantic_overlay_evidence": {"resource_models": ["..."]},
    "validation_required": true
  },
  "evidence_models": {
    "value_flow": {"source": "td_init", "sink": "Memory Leak"}
  },
  "positive_evidence": ["... includes embedded source snippet ..."],
  "negative_evidence": ["..."],
  "primary_location_snippet": {
    "file": "src/main.c",
    "start_line": 176,
    "end_line": 200,
    "code": "..."
  },
  "function_context": {
    "code": "... td_init truncated to the validation string limit ...",
    "snapshot_summary": null,
    "callers": ["..."],
    "callees": ["..."]
  },
  "validation_requirements": [
    "... first 12 generic requirements ...",
    {"omitted_items": 7}
  ]
}
```

### 3.2 `Suspected Finding` + `Compact Evidence Pack` 全字段逐字段分析

以下覆盖全部 13 个 SVF 输入。它们都来自同一 Saber memory-leak 信号族，因此表中特别区分生成器常量、运行配置固定值和仅当前样本固定值；后者不能上升为通用 SVF schema 约束。

| 字段 | 建议操作 | 重复 / 必要性 / 固定值分析 |
|---|---|---|
| `Finding.id` | 保留并改为 `candidate.id` | 必须关联结果；与 `candidate_id`、Pack ID 和 nested ID 在 13/13 固定相等。 |
| `Finding.candidate_id` | 删除 | 与 Finding ID 代码级重复。 |
| `Finding.function` | 重构为 mapped function | 必须说明源码映射范围；与 Pack summary/path/function context 重复，但不是已证 value-flow source。 |
| `Finding.location` | 重构为 reported point | 必须保留 backend row 定位；在 Pack summary/source/sink 重复。 |
| `Finding.category` | 删除 | 13/13 与 subcategory/defect class 相等且固定 `memory_leak`。 |
| `Finding.subcategory` | 删除 | 与 defect class 重复。 |
| `Finding.defect_class` | 保留一次 | 当前样本 13/13 固定 `memory_leak`；schema 不应限制为单一类别。 |
| `Finding.finding_kind` | 移出 Prompt | 生成器固定 `svf_value_flow_candidate`。 |
| `Finding.candidate_source` | 合并为 `source_kind` | 固定 `svf_value_flow`；解释 backend signal 语义有用。 |
| `Finding.evidence_checker` | 合并到 producer | 固定 `svf_value_flow_checker`，与 Pack/nested checker 重复。 |
| `Finding.cwe` | 条件保留 | 当前 13/13 固定 `CWE-401`，由 memory-leak 分类映射。 |
| `Finding.description` | 保留但改为中性 signal claim | 必须说明 Saber 报告了什么；不能声称 flow 已确认。 |
| `Finding.root_cause` | 删除或改为通用 caveat | 13/13 同一“需要源码验证”模板，不是实例根因。 |
| `Finding.suggested_fix` | 删除 | 13/13 同一 ownership/lifetime 模板，会造成确认偏差。 |
| `Finding.reasoning` | 合并 | 与 description、negative evidence、path constraints 重复说明“需要验证”。 |
| `Finding.confidence` | 移出 Prompt | 13/13 固定 `0.76`，与 rule confidence/Pack score 重复。 |
| `Finding.rule_confidence` | 移出 Prompt | 13/13 固定 `0.76`，是 adapter 先验。 |
| `Finding.impact_level` | 移出 Prompt | 13/13 固定 `medium`，报告元数据。 |
| `Finding.code_snippet` | 不生成；不要补文本副本 | 13/13 缺失，但 positive evidence 内嵌源码；应抽取到唯一 code unit。 |
| `Finding.source` | 改为 `source_mapping.mapped_function` | 当前是 `td_init` 一类 containing function，不是已证值流 source。 |
| `Finding.sink` | 改为 `backend_signal.signal` | 当前是 `Memory Leak` bug type，不是程序操作。 |
| `Finding.dedup_key` | 移出 Prompt | 只用于去重，在 Pack 重复。 |
| `Finding.positive_evidence` | 拆分为四层证据 | 必须；混合 backend report、源码映射、call path、代码片段和 reconstruction，且在 Pack 多层复制。 |
| `Finding.negative_evidence` | 改为 caveats/open questions | 13/13 为同两条固定 backend 说明，不是实例反证。 |
| `Finding.evidence_refs` | 条件保留 | 多层重复；仅可解析时发送。 |
| `Finding.backend_profile` | 移出 Prompt | 本次运行固定 `unified`。 |
| `Finding.evidence_engines` | 移出 Prompt | 运行固定四引擎清单。 |
| `Finding.validation_required` | 删除 | 固定 `true`。 |
| `Finding.candidate_role` | 删除 | 固定 `evidence_only`。 |
| `Finding.candidate_schema_version` | 移出 Prompt | 固定 `zscope.candidate.v3`。 |
| `Finding.candidate_uid` | 移出 Prompt | 生命周期主键。 |
| `Finding.occurrence_uid` | 移出 Prompt | occurrence 跟踪。 |
| `Finding.history_key` | 移出 Prompt | 历史聚合。 |
| `Finding.evidence_hash` | 移出 Prompt | 缓存摘要。 |
| `Finding.decision_evidence_hash` | 移出 Prompt | 决策缓存摘要。 |
| `Finding.provenance_hash` | 移出 Prompt | provenance 审计摘要。 |
| `Finding.validation_cluster_uid` | 移出 Prompt | 聚类/终态映射。 |
| `Finding.context_signature` | 移出 Prompt | 上下文去重摘要。 |
| `Finding.evidence_models.value_flow` | 删除 | 把 mapped function 与 bug type 包装成 source/sink，夸大后端证据。 |
| `Finding.evidence_summary` | 删除整个副本 | 与 `Pack.candidate_evidence` 13/13 整对象相等。 |
| `Finding.evidence_summary.candidate_id` | 删除 | 与外层 ID 固定相等。 |
| `Finding.evidence_summary.candidate_source` | 合并 | 固定 `svf_value_flow`。 |
| `Finding.evidence_summary.checker` | 合并到 producer | 固定 `svf_value_flow_checker`。 |
| `Finding.evidence_summary.defect_class` | 删除副本 | 当前固定 memory leak，与 Finding/Pack 重复。 |
| `Finding.evidence_summary.source` | 改为 source mapping | expression 是 mapped function；file/line 来自 backend row。 |
| `Finding.evidence_summary.sink` | 改为 backend signal | operation 是 bug type；与 source 使用同一 file/line 是固定构造关系，不是真实 sink 定位。 |
| `Finding.evidence_summary.path.function` | 合并到 mapped function | 与 Finding function 重复。 |
| `Finding.evidence_summary.path.entry_function` | 改为 mapping/reconstruction 字段 | 13/13 与 mapped function同类，不会让 Pack builder自动建立 canonical reachability。 |
| `Finding.evidence_summary.path.backend` | 合并到 producer/signal | 13/13 固定 `SVF/Saber value-flow`。 |
| `Finding.evidence_summary.path.complete_in_function` | 改为 backend-flow complete | 13/13 固定 `false`；不是已证不可达。 |
| `Finding.evidence_summary.path.path_constraints` | 移到 System Prompt | 13/13 同两条 backend 验证说明，不是程序路径约束。 |
| `Finding.evidence_summary.positive_evidence` | 拆分并合并 | 与 Finding/Pack evidence 重复。 |
| `Finding.evidence_summary.negative_evidence` | 删除固定副本 | 固定 caveat 与 Finding/Pack 重复。 |
| `Finding.evidence_summary.evidence_refs` | 条件保留一次 | 多层复制。 |
| `Finding.evidence_summary.backend_profile` | 移出 Prompt | 运行固定。 |
| `Finding.evidence_summary.semantic_overlays` | 移出 Prompt | 13/13 同一全局摘要。 |
| `Finding.evidence_summary.semantic_overlay_evidence` | 条件保留 | allocator 模型可能支持源码映射，但应标记为假设。 |
| `Finding.evidence_summary.validation_required` | 删除 | 固定 `true`。 |
| 原始 `rule` / `bug_type` | 恢复为 backend signal 元数据 | compact 后正式字段 13/13 缺失；当前只残留于 sink/description 文本。 |
| 原始 `value_flow` | 恢复并结构化 | compact 固定删除；应明确 nodes/edges 是否 available、complete。 |
| 原始 `source_path` | 恢复并标注 reconstruction | compact 固定删除；调用图/源码重建不能冒充 SVF flow。 |
| `Pack.mode` | 移出 Prompt | 固定 `tri_state_exploitability_validation`。 |
| `Pack.dedup_key` | 移出 Prompt | 与 Finding 重复。 |
| `Pack.candidate_id` | 删除副本 | 与 Finding ID 固定相等。 |
| `Pack.candidate_role` | 删除 | 固定 `evidence_only`。 |
| `Pack.candidate_is_conclusion` | 删除 | 固定 `false`。 |
| `Pack.validation_required` | 删除 | 固定 `true`。 |
| `Pack.proofs` | 空时删除 | 13/13 为 `{}`。 |
| `Pack.audit_observation_reason` | 空时删除 | 13/13 为 `null`。 |
| `Pack.va_unreviewed` | 移出 Prompt | 13/13 为 `false`。 |
| `Pack.backend_profile` | 移出 Prompt | 运行固定 `unified`。 |
| `Pack.evidence_checker` | 合并到 producer | 固定 `svf_value_flow_checker`。 |
| `Pack.evidence_engines` | 移出 Prompt | 运行固定清单。 |
| `Pack.semantic_overlays` | 移出 Prompt | 运行固定摘要。 |
| `Pack.semantic_overlay_evidence` | 条件保留一次 | 与 nested overlay evidence 重复；保留实例命中的 allocator model。 |
| `Pack.finding_kind` | 移出 Prompt | 固定 `svf_value_flow_candidate`。 |
| `Pack.defect_class` | 删除副本 | 当前固定 memory leak，与 Finding 重复。 |
| `Pack.rule_confidence` | 移出 Prompt | 13/13 固定 `0.76`。 |
| `Pack.score_components` | 移出 Prompt | 13/13 整组固定：rule `0.76`、path `0.75`、contract `0.55`、validation `0.76`、history `0.5`、final `0.6895`。 |
| `Pack.evidence_refs` | 条件保留一次 | 多层复制。 |
| `Pack.finding_summary` | 删除整个对象 | ID/function/location/category/subcategory/confidence/description/source/sink/cwe 均复制 Finding；类别、CWE、confidence 还在本样本固定。 |
| `Pack.entry_context.current_analysis_entry` | 条件保留 | 仅表示扫描入口，不是 SVF source。 |
| `Pack.entry_context.entry_custom_prompt` | 删除 | exposure 模板，与 System Prompt 重复。 |
| `Pack.entry_context.entry_exposure` | 条件保留 | 实例枚举有用。 |
| `Pack.entry_context.entry_is_external_root` | 合并为 root kind | 13/13 固定 `true`。 |
| `Pack.entry_context.entry_is_scan_root` | 删除或合并 | 13/13 固定 `true`。 |
| `Pack.entry_context.zero_callers_is_expected_for_entry` | 删除 | 13/13 固定 `true`，是 System Prompt 规则。 |
| `Pack.entry_context.public_trigger` | 删除 | 本次固定 scan-root 长文本。 |
| `Pack.entry_context.issue_entry_function` | 空时删除 | 当前未从 `path.entry_function` 建立 canonical issue entry。 |
| `Pack.entry_context.reachable_from_entry` | 改为三态 | false 12、true 1；反映 builder 命中情况，不是可达性反证。 |
| `Pack.entry_context.internal_sink_lifted` | 删除 | 13/13 固定 `false`。 |
| `Pack.entry_context.call_path` | 空时删除 | 13/13 固定 `null`；source reconstruction 的调用链已在 compaction 中丢失。 |
| `Pack.entry_context.candidate_path` | 删除 | 与 `candidate_evidence.path` 13/13 完全相等。 |
| `Pack.candidate_evidence` | 保留并重构为唯一 evidence | 与 Finding `evidence_summary` 13/13 相等，但当前缺失原始 value_flow/source_path。 |
| `Pack.evidence_models` | 删除 | value flow 只复制 mapped function 和 bug type。 |
| `Pack.positive_evidence` | 拆分并去重 | 与 nested evidence 13/13 相等，且内嵌源码形成额外代码副本。 |
| `Pack.negative_evidence` | 移到固定政策或 open questions | 与 nested evidence 13/13 相等，内容是固定 caveat。 |
| `Pack.primary_location_snippet` | 合并到 code unit | 与 positive evidence snippet、function code、Relevant Code 重叠。 |
| `Pack.function_context.code` | 删除副本 | 与 Relevant Code 同源；SVF 12/13 完全相等，另 1 个只是截断。 |
| `Pack.function_context.snapshot_summary` | 空时删除 | 13/13 为 `null`。 |
| `Pack.function_context.callers` | 条件保留 | 只用于明确调用图 reconstruction，不能当 value flow。 |
| `Pack.function_context.callees` | 条件保留 | 只保留决定 ownership 语义的 helper，并附必要代码。 |
| `Pack.validation_requirements` | 从 Pack 删除 | 前 12 条固定；第 13 项 13/13 为 `omitted_items=7`，SVF/memory-leak 专属正文全部被截断。 |

### 3.3 SVF 丢失字段说明

SVF Candidate 生成器明确构造 `value_flow` 和 `source_path`，然后将它们放入 `evidence_pack`。在 Validator 输入阶段，两个父键都不在 `_compact_candidate_evidence()` 白名单，因而不是“内部过长被截断”，而是整个对象被固定删除。`positive_evidence` 会事先抽取少量后端路径、snippet 和最多数个事件的自然语言摘要，但这不能代替节点身份、边、完整性和 provenance。

| 生成器原始字段 | 原始内容 | 丢失方式与信息影响 | 推荐处理 |
|---|---|---|---|
| `evidence_pack.rule` | `svf_value_flow_<bug_type>` 规则标识 | 不在白名单，13/13 正式 evidence 中丢失；规则只可能通过 description、sink 或 dedup key 间接推断。 | 与 `bug_type` 一起恢复为 backend signal 元数据，不将缺陷类型冒充程序 sink。 |
| `evidence_pack.value_flow` | SVF/Saber 后端信号、节点路径和原始行的结构化容器 | 父键不在白名单，整体固定丢失；Validator 无法区分“后端只报了一个 signal”和“后端提供了完整 value-flow path”。 | 拆分恢复为 `backend_signal`、`backend_flow` 和 source mapping，各自标注 available/complete/provenance。 |
| `value_flow.tool` / `svf_group(s)` | 后端工具与 bitcode/SVF 分组 | 随 `value_flow` 丢失；`tool` 在本次运行可表现为固定 Saber/SVF 来源，group 则是运行/分析分区元数据，不是漏洞证明。 | 在 `backend_signal.tool` 只保留一次工具来源；group 默认移出 Prompt，除非它影响证据完整性。 |
| `value_flow.bug_type` | 后端 diagnostic 类别，例如 `Memory Leak` | 随 `value_flow` 丢失；当前却以 `sink` 文本残留，容易被误读为 source-to-sink 终点。 | 恢复为 `backend_signal.signal`，明确它是报告类型而不是程序点。 |
| `value_flow.source_func` / `sink_func` | 后端输出中的 source/sink 名称 | 随 `value_flow` 丢失；名称可能是 LLVM 摘要、containing function 或 bug type fallback，不一定是源码级端点。 | 保留为带 provenance 的 backend label；只在存在节点与 debug-location 依据时映射为 program point。 |
| `value_flow.function/file/line/function_start/function_end/signature` | 后端报告位置和 Clang containing-function 范围 | 随 `value_flow` 丢失；部分 location 在外层字段重复，但“后端位置”与“源码映射结果”的来源区分消失。 | 去重为 backend reported point 和 `source_mapping.basis`，不重复发送 signature/范围。 |
| `value_flow.interprocedural` | 由 source/sink 名称是否不同计算的布尔值 | 随 `value_flow` 丢失；它是代码级派生值，不足以证明真实跨函数 flow。 | 不直接恢复；根据实际 backend nodes/edges 计算 `backend_flow.complete`。 |
| `value_flow.backend_path` | 后端 path/trace 规范化得到的节点列表 | 随 `value_flow` 整体丢失；有路径时 `positive_evidence` 只保留格式化文本，节点 ID、SSA/LLVM value、points-to、alias 和 object identity 可丢失或被截断。 | 恢复为 `backend_flow.nodes/edges`，保留 backend identity 和可用位置；不用调用图边代替。 |
| `value_flow.raw_backend_row` | 后端原始报告行的压缩副本 | 随 `value_flow` 丢失；即使父键放行，`raw_*` 规则也会将它标为 raw payload。全量原始行对模型不是必需。 | 原始行留在审计/工具层；Prompt 只恢复规范化后且可解释的 signal、node、edge 和 location。 |
| `evidence_pack.source_path` | CodeIndex 调用图、源码 snippet 和启发式 source-level flow 的重建容器 | 父键不在白名单，整体固定丢失；其中的调用可达性与 value-flow 证据无法再分层。 | 拆分为 `analysis_scope.reachability`、`source_mapping` 和 `source_reconstruction`，每层标注证据来源。 |
| `source_path.entry_function/target_function/call_path/complete_to_entry` | Entry 到 mapped target 的 CodeIndex 调用路径与完整标记 | 随 `source_path` 丢失；部分文本可残留在 positive evidence，但这只证明调用可达性，不证明 ownership/value flow。 | 恢复到 `analysis_scope.reachability`，与 `backend_flow` 严格分开。 |
| `source_path.source_function/sink_function` | 用于重建的后端符号 | 随 `source_path` 丢失；它们仍可能是 fallback 名称。 | 作为 reconstruction input/provenance 保留，不直接晋升为已验证程序点。 |
| `source_path.reported_location/reported_snippet` | 后端位置及其附近源码 | 随 `source_path` 丢失；snippet 又被编入 positive evidence，并与 primary snippet、function code 和 Relevant Code 重复。 | 定位映射为一个 program point，源码只在 `code_context.units` 保留一份。 |
| `source_path.source_level_flow` | schema、source/sink symbol、object symbols、events、expression edges、complete flag 和 notes | 随 `source_path` 丢失；`positive_evidence` 只格式化前几个 event/edge，无法保留完整性和对象关系。 | 恢复为显式标注 heuristic/best-effort 的 `source_reconstruction.events`、relations 和 `complete`。 |
| `source_path.target_function_context/source_function_context/sink_function_context` | 为源码重建读取的函数摘要和 code excerpt | 随 `source_path` 丢失；同时 Pack 又通过 `function_context.code` 和 Relevant Code 发送相同或相似代码。 | 去重为唯一 `code_context.units`，只补充决定 ownership 语义的 helper。 |
| `source_path.reconstruction_notes` | 固定 caveat 加上未找到 call path/snippet 时的实例级说明 | 随 `source_path` 丢失；前两条通用 caveat 是代码级固定文本，其余内容取决于实例。 | 固定 caveat 放 System Prompt；实例级缺失转为 `open_questions` 或结构化 status。 |

结论：SVF 的 `value_flow` 和 `source_path` 不应原样二选一地“全保留”或“全删除”。前者要保留后端真正报告的 signal/nodes/edges，后者要保留但降级标注调用图和源码启发式重建；两者不能再被合并成一个没有 provenance 的通用 source-to-sink 故事。

### 3.4 `svf_value_flow`

```json
{
  "candidate": {
    "id": "SVF_VALUE_FLOW_bbbaa268e158",
    "source_kind": "svf_value_flow",
  },
  "hypothesis": {
    "defect_class": "memory_leak",
    "cwe": "CWE-401",
    "bug_type": "",
    "claim": "Saber reported a memory-leak signal mapped near an allocation in `td_init`; source-level ownership remains unproven.",
    "root_cause": ""
  },
  "entry_function": {
    "function_name": "td_init",
    "file_path": ,
    "start_line": ,
    "end_line": ,
    "entry_custom_prompt": "",
    "entry_exposure": "api",
    "root_kind": "external_scan_root"
  },
  "target_function": {
    "function_name": "td_init",
    "file_path": ,
    "start_line": ,
    "end_line": ,
    "snapshot_summary": null,
    "callers": [],
    "callees": []
  },
  "source": {
      "expression": "td_init",
      "file": "src/main.c",
      "line": 188
  },
  "sink": {
    "operation": "Memory Leak",
    "file": "src/main.c",
    "line": 188
  },
  "call_path": {
    "nodes": ["td_init"]
  },
  "evidence": {
    "positive_evidence": [],
    "negative_evidence": [],
    "semantic_overlay_evidence": {}
  },
  "target_function_code": ""
}
```

推荐字段说明：

| 推荐字段 | 来源或取值方法 | 含义 |
|---|---|---|
| `candidate` | 由原 Finding 的 Candidate 身份字段去重重组。 | 待 Validator 判断的单个 SVF/Saber Candidate 身份对象。 |
| `candidate.id` | 原 `Finding.id/candidate_id`；两者相等时只保留一份。 | 关联 Validator 输入、输出和运行记录的唯一标识。 |
| `candidate.source_kind` | 原 `candidate_source`，SVF 固定取 `svf_value_flow`。 | 标识本 Candidate 来自 SVF/Saber 后端信号，不表示漏洞或完整 value flow 已被证明。 |
| `hypothesis` | 原缺陷分类、后端 bug type 和结论性文案去重、去结论化后重组。 | 集中表达需要通过源码确认或反驳的后端缺陷假设。 |
| `hypothesis.defect_class` | 原 `defect_class`，删除 `category/subcategory` 副本。 | 规范化缺陷类别；本次样本为 `memory_leak`，schema 不限于该类。 |
| `hypothesis.cwe` | 原 `cwe`；没有可靠映射时省略。 | 对外分类标签。 |
| `hypothesis.bug_type` | 从 compaction 前 `value_flow.bug_type` 或 backend diagnostic 恢复。 | 后端报告类型，例如 `Memory Leak`；不是程序中的 sink。 |
| `hypothesis.claim` | 由原 description/reasoning、backend signal 和源码映射状态生成中性句。 | 说明后端信号可能对应某源码缺陷，同时明确 ownership/source-level flow 尚待验证。 |
| `hypothesis.root_cause` | 原 `root_cause` 去结论化；没有实例级源码依据时置空或省略。 | 候选根因假设，不是 SVF 已证明的事实。 |
| `entry_function` | 原 entry context 与 `source_path.entry_function`、CodeIndex 函数定义合并。 | 当前扫描入口的定位和暴露信息。 |
| `entry_function.function_name` | 原 current analysis entry 或 source reconstruction entry。 | 入口函数名称。 |
| `entry_function.file_path` | 通过 CodeIndex/Clang 函数定义解析。 | 入口函数所在源码文件。 |
| `entry_function.start_line` | 通过 CodeIndex/Clang 函数定义取得。 | 入口函数源码范围起始行。 |
| `entry_function.end_line` | 通过 CodeIndex/Clang 函数定义取得。 | 入口函数源码范围结束行。 |
| `entry_function.entry_custom_prompt` | 原 `Pack.entry_context.entry_custom_prompt`。 | EntryDiscovery 为该入口生成的审计提示；空字符串表示没有附加提示。 |
| `entry_function.entry_exposure` | 原 `Pack.entry_context.entry_exposure`。 | API、线程、通信或其他用户输入入口类型。 |
| `entry_function.root_kind` | 仅由原 `entry_is_external_root` 和 `entry_is_scan_root` 按四态真值表映射。 | 表示外部根与本轮扫描根的组合；SVF backend、mapping、exposure 和 prompt 不参与取值。 |
| `target_function` | 原 backend mapped/containing function、Finding function 与 CodeIndex 函数上下文合并。 | Validator 应核查后端信号所映射源码语义的目标函数。 |
| `target_function.function_name` | 原 `Finding.function`、`value_flow.function` 或 `source_path.target_function` 对齐后的名称。 | 后端报告映射到的源码函数名称。 |
| `target_function.file_path` | 原 backend reported file 与 CodeIndex 函数定义对齐。 | 目标函数所在源码文件。 |
| `target_function.start_line` | 原 `value_flow.function_start` 或 CodeIndex/Clang 函数范围。 | 目标函数源码范围起始行。 |
| `target_function.end_line` | 原 `value_flow.function_end` 或 CodeIndex/Clang 函数范围。 | 目标函数源码范围结束行。 |
| `target_function.snapshot_summary` | 原 `Pack.function_context.snapshot_summary`；无快照时为 `null`。 | 目标函数可用的紧凑语义快照。 |
| `target_function.callers` | 原 `Pack.function_context.callers`，按调用者和调用行去重。 | CodeIndex 已知的直接调用者；只能支持调用可达性，不能作为 SVF value-flow edge。 |
| `target_function.callers[].name` | 原 caller 记录的 `name`。 | 直接调用者函数名称。 |
| `target_function.callers[].filename` | 原 caller 记录的 `filename`。 | 调用者所在文件。 |
| `target_function.callers[].callee_filename` | 原 caller 记录的 `callee_filename`。 | 目标函数所在文件，用于同名函数消歧。 |
| `target_function.callers[].lineNumber` | 原 caller 记录的 `lineNumber`。 | 调用发生的源码行。 |
| `target_function.callees` | 原 `Pack.function_context.callees`，按目标和调用点去重。 | 目标函数直接调用的函数列表；不代表后端 value flow。 |
| `target_function.callees[].name` | 原 callee 记录的 `name`。 | 被调函数名称。 |
| `target_function.callees[].filename` | 原 callee 记录的 `filename`。 | 被调函数声明或定义所在文件。 |
| `target_function.callees[].lineNumber` | 原 callee 记录的 `lineNumber`。 | 调用点源码行。 |
| `target_function.callees[].call_type` | 原 CodeIndex call edge 的 `call_type`。 | 调用类型，例如 direct 或 indirect。 |
| `target_function.callees[].callee_kind` | 原 CodeIndex call edge 的 `callee_kind`。 | 被调目标类别。 |
| `target_function.callees[].callee_signature` | 原 CodeIndex/Clang 解析的 callee signature；未知时为空。 | 被调目标签名，用于核查 wrapper 或 ownership helper。 |
| `source` | 原 Graph candidate evidence source 与 Finding source 去重。 | Graph 规则识别的源事件或对象表达式，不自动等价于污点源。 |
| `source.expression` | 原 source expression。 | 规则识别的赋值、对象或调用相关表达式。 |
| `source.file` | 原 source location 文件。 | source 事件所在源码文件。 |
| `source.line` | 原 source location 行号。 | source 事件所在源码行。 |
| `sink` | 原 Graph candidate evidence sink 与 Finding sink 去重。 | Graph 规则识别的目标操作或协议事件，不自动等价于数据流 sink。 |
| `sink.operation` | 原 sink operation。 | 规则关注的调用、释放、发布或其他操作。 |
| `sink.file` | 原 sink location 文件。 | sink 事件所在源码文件。 |
| `sink.line` | 原 sink location 行号。 | sink 事件所在源码行。 |
| `call_path` | 原 `source_path.call_path` 或独立 CodeIndex path；不读取 bug type 生成路径。 | 入口到 mapped target 的调用图路径容器，与 SVF value flow 分开。 |
| `call_path.nodes` | entry 与 target 相同时生成单节点；否则使用已建立的 CodeIndex 函数序列。 | 按调用顺序排列的函数名称，仅表达调用可达性。 |
| `evidence` | 原正反证据与 Candidate 实际命中的 semantic overlay evidence 去重合并。 | 当前简化结构中保留的实例级 SVF 验证证据容器。 |
| `evidence.positive_evidence` | 原 Finding/Pack positive evidence 合并去重，包括仍未拆成独立字段的 backend 和 reconstruction 摘要。 | 支持当前假设的实例事实；自然语言摘要不等价于完整 backend path。 |
| `evidence.negative_evidence` | 原 Finding/Pack negative evidence 合并去重，并删除固定 backend caveat。 | 与当前假设冲突或限制其成立条件的实例事实。 |
| `evidence.semantic_overlay_evidence` | 原 Candidate 实际命中的 allocator/ownership 等 overlay evidence，删除全局摘要副本。 | 源码映射或 ownership 判断使用的外部语义模型；空对象表示没有实例级命中。 |
| `target_function_code` | 原 source snippet、`function_context.code` 与 Relevant Code Context 去重后保留目标函数的一份代码。 | Validator 直接阅读的 mapped target 源码；不包含独立 backend nodes/edges。 |

## 第四章 System Prompt 重复性分析与整个 Validator 上下文的与统一重构

前三章分别分析了来源专属差异。本章包括 `validation_requirements` 与 system prompt 的重复、fast-path 附加消息，以及整个模型上下文的统一组织。

### 4.1 `validation_requirements` 与 System Prompt 的重复

System prompt 已经定义：

- 三态 verdict 的语义
- verified 需要 source、sink、controllability、feasible path 和 guard analysis
- missing context 不能证明漏洞
- hardening/style/theoretical Candidate 应拒绝
- configured/header entry 是扫描根，零 callers 不能单独证明 dead code
- entry-to-sink 路径只能被具体代码反证
- structured evidence 未完全证明时应优先 uncertain 而不是无证据 rejected
- integer overflow guard 的严格要求
- concurrency Candidate 的共享状态和锁协议要求

Pack 的 `_base_validation_requirements()` 又发送 14 条通用规则。对应关系如下：

| `validation_requirements` 内容 | System Prompt 中的对应内容 | 结论 |
|---|---|---|
| Candidate 只是 evidence，不可因 regex/graph/backend 来源直接接受 | system 开头的 strict validation bar 和 structured evidence 规则 | 重复，保留在 system。 |
| 独立审核 semantic overlay 假设 | system 的独立验证原则未显式列出 user config | 通用原则可补入 system；具体模型放 Candidate `model_assumptions`。 |
| verified 需要 public/API 或 caller-controlled trigger | verified 定义和 Validation bar 第一条 | 重复。 |
| rejected 需要 local evidence 或 guard 反证 | rejected 定义 | 重复。 |
| uncertain 用于缺少决定性上下文 | uncertain 定义和 missing-context 条款 | 重复。 |
| 识别 source、sink、controllability 和 guard | verified 定义和输出字段要求 | 重复。 |
| 拒绝 hardening/style/theoretical finding | system 开头和 Validation bar | 重复。 |
| integer overflow 的 pre-operation bound | system integer overflow 条款 | 重复。 |
| 当前 analysis entry 是 public trigger/root | system current-analysis-entry 条款 | 重复。 |
| zero callers、absence from main/worker 不能证明 dead code | system entry-root 条款 | 重复。 |
| external root + call path 不需要额外内部 caller | system entry-to-sink 条款 | 重复。 |
| internal callee 无 caller 不能单独拒绝 | system entry-root 条款 | 重复。 |
| 只有具体代码才能反证 reachable path | system call-path 条款 | 重复。 |
| 唯一负证据为零 caller 时应 uncertain | system structured evidence/entry-root 条款 | 语义重复。 |

当前实现还有一个比重复更严重的问题：

1. 先写入 14 条通用 requirements。
2. 再追加 defect-class 专属 requirements。
3. `compact_validation_evidence_pack()` 对普通 list 默认只保留前 12 项。
4. 三个示例都是 `memory_leak`，原始列表总计 19 项。
5. 模型实际收到前 12 条通用规则和 `{"omitted_items": 7}`。

因此，最后两条通用规则和 5 条真正有区分力的 memory-leak 专属规则全部被截掉。当前结构同时产生了“重复发送通用政策”和“删除 Candidate 专属政策”两个问题。

推荐处理：

```text
System Prompt
  stable tri-state policy
  stable entry-root policy
  stable output schema
  stable evidence-independence policy
  selected category policy block

Validator Input
  candidate-specific facts
  candidate-specific counterevidence
  candidate-specific open questions
```

类别规则有两种可行组织方式：

| 方案 | 处理方式 | 推荐度 |
|---|---|---|
| 动态 System block | 根据 `defect_class/rule` 选择少量类别规则，作为 system prompt 的一个独立段落 | 推荐；政策只有一个权威位置。 |
| `validation_focus` 字段 | Candidate 输入只携带与当前实例直接相关的 1-3 条检查重点 | 可接受；必须保证不与 system 重复且不受通用 list cap。 |

不推荐继续把固定通用规则和类别规则混在同一 `validation_requirements` 数组中。

### 4.2 Fast-path 附加消息的重复和矛盾

当前 fast-path 追加：

```text
Fast-path validation: use only the suspected finding and Compact Evidence Pack.
Do not ask for tools.
Return exactly one validation_result JSON block.
Use uncertain if a decisive fact requires code not present in the pack.
```

但 `Relevant Code Context` 已经在同一条初始用户消息中，因此“只使用 Finding 和 Pack”与实际上下文组织矛盾。该消息还重复 system prompt 的 JSON 输出要求和 uncertain 定义。最后一轮消息又再次说明工具禁用和必须输出 JSON。

推荐：

- 工具是否可用由运行时 tool policy 控制，不依赖模型遵守自然语言。
- fast-path 不再单独拼接 `Relevant Code Context`，因为唯一代码已在 `Validator Input.code_context`。
- system prompt 只保留一次输出 schema 和三态定义。
- fast-path 只需要一个短模式信号，或者完全不需要模型可见的模式字段。

若必须保留模式提示，可缩减为：

```text
This is a no-retrieval validation pass. Decide from the provided Validator Input.
```

### 4.3 推荐的最终 Prompt 组织

```text
System Prompt
  Agent role and tool policy
  Tri-state verdict definitions
  Stable exploitability bar
  Stable entry-root interpretation
  Selected defect/rule policy
  Output JSON schema

User Message
  Validator Input
```

不再单独发送：

```text
Suspected Finding
Compact Evidence Pack
Relevant Code Context
validation_requirements
entry_custom_prompt/public_trigger prose
```

该结构的核心原则不是单纯减少字段，而是：

1. 每个事实只保留一个权威位置。
2. 运行和生命周期元数据不进入模型证据。
3. 通用验证政策只存在于 system prompt。
4. 代码只发送一次，其他证据通过引用关联。
5. 三类来源共享统一外层，但保留来源专属证明结构。
6. 明确区分源码事实、生成器假设、后端信号、源码映射和已证明关系。

特别是 SVF 不能再把 bug type 包装成程序 Sink，Graph 不能删除 lifecycle_pair 和 cascade-wait，Clang 不能为了统一结构而继续删除 AST/CFG 事件。
重构后的 Validator 输入应减少 wrapper 重复，同时恢复对 verdict 真正有区分力的来源专属事实。
