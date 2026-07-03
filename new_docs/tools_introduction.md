# Tools introduction

本文列出 Z-SCOPE 中不同 Agent 可以使用的本地工具集合。口径以当前代码为准：

- Agent 的基础工具声明来自 `zscope/agents/*/AGENT.md`。
- Skill 的工具声明来自 `zscope/skills/*/SKILL.md` 的 `allowed_tools`。
- 运行时有效工具由 `zscope/orchestration/agent_policy.py` 中的 `tool_policy_for_agent` 决定：当 Agent tools 和 active Skill tools 都存在时，取二者交集。
- `zscope/core/analysis/analyzer.py::_get_tools` 还会按后端能力过滤工具；本次 baseline 使用 unified backend，因此 CPG/graph 类工具可用。
- `deny_sensitive_paths_hook` 对所有 Agent 生效，会拒绝明显敏感路径参数。

## 一、默认 Workflow 中的 Agent 工具集合

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

## 二、非默认 Workflow 中出现的 Agent

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

## 三、按 Skill 划分的 allowed_tools

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

## 四、工具可见性优化关注点

| 现象 | 说明 |
|---|---|
| Agent 声明了工具但默认运行时不可见 | 例如 `semantic_modeler.list_known_functions`、`validator_agent.get_callers`、`vulnerability_analyzer.get_deep_call_context`。原因是 active Skill allowed_tools 未包含这些工具。 |
| Skill 声明了工具但 Agent 未声明 | 例如 vulnerability skills 中的 `get_function_impl` 对 `vulnerability_analyzer` 不可见。原因是 Agent tools 与 Skill tools 取交集。 |
| `issue_reconciler_agent` 无工具 | 它是纯 LLM 语义合并/去重 Agent，当前实现没有向其传入工具列表。 |
| 后端能力会进一步过滤工具 | `get_call_graph`、`get_data_flow`、`find_function_pointers`、`query_pointer_alias`、`verify_taint_reachability`、`get_deep_call_context` 只在 joern/svf/unified 等 advanced backend 下加入工具池。 |
