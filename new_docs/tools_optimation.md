# 工具优化实施记录

## 2026-07-03

### 已完成

- 将原先集中在 `zscope/tools/utils.py` 中的 10 个工具拆分为一个工具一个文件：
  - `list_known_functions` -> `zscope/tools/list_functions.py`
  - `get_file_snippet` -> `zscope/tools/file_snippet.py`
  - `get_callers` -> `zscope/tools/callers.py`
  - `get_type_info` -> `zscope/tools/type_info.py`
  - `get_call_graph` -> `zscope/tools/call_graph.py`
  - `get_data_flow` -> `zscope/tools/data_flow.py`
  - `find_function_pointers` -> `zscope/tools/function_pointers.py`
  - `query_pointer_alias` -> `zscope/tools/pointer_alias.py`
  - `verify_taint_reachability` -> `zscope/tools/taint_reachability.py`
  - `get_deep_call_context` -> `zscope/tools/deep_call_context.py`
- 保留 `get_function_impl` 和 `get_function_snapshot` 的原有文件组织方式，未做迁移。
- 保留所有工具的原始逻辑、工具名、schema 和返回结构；本次只做文件级拆分。
- 将 `Analyzer._get_tools()` 中对 `zscope.tools.utils` 的集中导入改为从各工具模块直接导入，和 `get_function_impl` / `get_function_snapshot` 的导入方式保持一致。
- 将 `zscope/tools/utils.py` 改为兼容导出层，继续 re-export 原有 10 个工具类，避免潜在外部导入断裂。

### 测试

- `python -m py_compile zscope/tools/list_functions.py zscope/tools/file_snippet.py zscope/tools/callers.py zscope/tools/type_info.py zscope/tools/call_graph.py zscope/tools/data_flow.py zscope/tools/function_pointers.py zscope/tools/pointer_alias.py zscope/tools/taint_reachability.py zscope/tools/deep_call_context.py zscope/tools/utils.py zscope/core/analysis/analyzer.py` 通过。
- 兼容导出检查通过：`zscope.tools.utils` re-export 的 10 个类与新模块中的类对象一致。
- `python -m pytest tests/test_tool_policy.py tests/test_json_output_agents.py -q` 通过：16 个测试。

### 计划偏差 / 问题记录

- 非阻塞优化点：`GetFunctionImplTool` 的底层 `CodeIndex.get_function_impl()` 已支持 `file_path` 消歧，但当前工具 schema 和 `execute()` 没有暴露/传递 `file_path`。如果后续保留或合并 `get_function_impl`，建议补充 `file_path` 参数，降低同名函数歧义风险。
- 非阻塞优化点：`get_deep_call_context` 已有独立工具实现，但默认 workflow 下当前对实际运行 Agent 不可见，因此 baseline 调用次数为 0。后续需要决定是按 skill/candidate 条件暴露，还是继续保持隐藏。
- 本次未修改任何工具行为；已发现的工具设计问题先记录，留待重构完成后统一讨论。


## 2026-07-07

### 已完成

- 按 `tools_optimation_plan.md` 实现 `get_function_info`：
  - 新增 `CodeIndex.find_function_infos()`，按 `func_name` 和可选 `file_path` 返回所有匹配函数。
  - 返回 `match_count` 与 `matches`，不返回 `ambiguous`，由调用方通过 `match_count` 判断同名/重载歧义。
  - 每个 match 返回 `function_name`、`file_path`、`index_name`、`start_line`、`end_line`、`signature`、`callers`、`callees`。
  - 新增 `callers_limit` 和 `callees_limit` 输入字段，默认值均为 30。
  - `call_type` 在 `svf` / `unified` 后端保留 `direct` / `indirect`；在 `clang` / `clangd` 后端自动降级为 `direct`。
- 新增 `zscope/tools/function_info.py`，提供 `GetFunctionInfoTool`。
- 在 `Analyzer._get_tools()` 中注册 `GetFunctionInfoTool`；`get_function_impl` 的实现和注册均保留，未删除。
- 在 `ToolsRuntime` 中补齐 `get_function_info` 的 schema、参数校验和执行分支，保持 runtime 工具路径一致。
- 更新工具兼容导出层 `zscope/tools/utils.py`，加入 `GetFunctionInfoTool`。
- 将 `zscope/agents/semantic_modeler/AGENT.md` 和 `zscope/agents/validator_agent/AGENT.md` 中的 `get_function_impl` 替换为 `get_function_info`。
- 同步更新 `code_semantic_modeling` 与 `evidence_validation` 两个 Skill 的 `allowed_tools`，避免 Agent/Skill 工具交集策略把 `get_function_info` 过滤掉。
- 更新 `tools_introduction.md`，将本地工具总数改为 13，并补充 `get_function_info` 的输入、输出和 `call_type` 降级说明。

### 测试

- `python -m py_compile zscope/retrieval/code_index.py zscope/tools/function_info.py zscope/tools/runtime.py zscope/tools/utils.py zscope/core/analysis/analyzer.py` 通过。
- 新增 `tests/test_function_info_tool.py`，覆盖：
  - 同名函数无 `file_path` 时返回多个 match。
  - 传入 `file_path` 时能缩小到目标文件。
  - `callers_limit` / `callees_limit` 生效。
  - `svf` / `unified` 后端保留 `indirect` call_type。
  - `clang` / `clangd` 后端将 call_type 降级为 `direct`。
  - `GetFunctionInfoTool` 和 `ToolsRuntime.execute_tool("get_function_info", ...)` 均返回 `match_count`。
- `python -m pytest tests/test_function_info_tool.py tests/test_analyzer_tool_policy.py tests/test_tool_policy.py tests/test_json_output_agents.py -q` 通过：23 个测试。

### 注意事项

- 当前 `CodeIndex` 的唯一函数键生成策略不只使用 `函数名@文件:行号`。当同名函数可用签名键区分时，`index_name` 可能是 `Target(void)` 这类签名键；只有签名键也冲突时才会使用 `Target@src/a/shared.c:1` 形式。
- 本次没有删除 `get_function_impl`，也没有改变 `CodeIndex.get_function_impl()` 的返回结构。后续是否隐藏或删除旧工具，应基于小规模回归中的工具调用次数、token 成本和漏洞指标决定。
