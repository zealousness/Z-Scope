---
name: bounds_and_integer
languages: [c_cpp]
description: Audit buffer bounds, array indexing, and integer size conversions.
category: memory_safety
triggers:
  - memcpy/memmove/strcpy/strncpy/strcat/sprintf/snprintf
  - read/recv/fread into caller-provided buffers
  - array index or pointer arithmetic uses external input
  - allocation size is computed from multiplication/addition/cast
allowed_tools:
  - search_code
  - read_code
  - get_semantic_context
  - query_code_graph
  - trace_data_flow
  - query_static_findings
allowed_mcp_tools:
  - zscope.code.search
  - zscope.code.read
  - zscope.semantic.context
  - zscope.graph.query
  - zscope.flow.trace
  - zscope.findings.query
allowed_mcp_resources:
  - zscope://knowledge/functions
---

## 工具调用纪律

- 已有 `symbol_id` 时直接传给后续工具，不要重新搜索，也不要自行构造或修改 `symbol_id`。
- `partial`、`unsupported`、`unavailable` 不能解释为“没有漏洞”或“没有路径”。
- `may` 数据流路径和未验证 finding 只能作为调查线索，不能当作已证明结论。
- 分页只使用返回的 `page.next_offset`；不要用完全相同的参数重复调用工具。

Prove whether every write/read length is bounded by the destination/source
object. Track size_t/int signedness, truncation, multiplication/addition
overflow, sentinel bytes, NUL termination, and whether the bound is checked
before the sink. A finding needs the source of the size/index, the sink, and the
missing or incorrect guard.

Integer-overflow rule: a post-computation check such as `total < input` is not
sufficient when `total` was already computed by `input * k` or `a + b` and could
have wrapped. Treat it as valid only if there is a precondition before the
operation, for example `input <= SIZE_MAX / k`, `a <= SIZE_MAX - b`, or an
equivalent proven bound on each operand.
