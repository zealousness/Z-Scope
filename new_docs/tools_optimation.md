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
