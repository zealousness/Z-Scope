---
name: evidence_validation
languages: [c_cpp, java]
description: Validate a suspected defect against source evidence and available contracts.
category: validation
triggers:
  - candidate finding has been produced
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
---

## 工具调用纪律

- 已有 `symbol_id` 时直接传给后续工具，不要重新搜索，也不要自行构造或修改 `symbol_id`。
- `partial`、`unsupported`、`unavailable` 不能解释为“没有漏洞”或“没有路径”。
- `may` 数据流路径和未验证 finding 只能作为调查线索，不能当作已证明结论。
- 分页只使用返回的 `page.next_offset`；不要用完全相同的参数重复调用工具。

Compare the finding's path and assumptions with code evidence under a strict
exploitability bar. Validate only when the source, sink, source controllability,
and feasible trigger path are concrete. Reject hardening/style/theoretical
findings when they do not prove a source-to-sink path, even if the code could be
made more defensive. A missing guard matters only when the relevant input can
reach the sink in the shown path. For mitigations, cite the concrete guard,
range proof, ownership transfer, cleanup path, or synchronization rule.
