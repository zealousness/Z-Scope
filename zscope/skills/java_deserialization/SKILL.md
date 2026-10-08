---
name: java_deserialization
languages: [java]
description: Audit unsafe Java deserialization, polymorphic JSON typing, and XML parser XXE.
category: java_security
triggers:
  - ObjectInputStream.readObject
  - Jackson enableDefaultTyping/activateDefaultTyping
  - XML parser factories and SAXReader
  - Fastjson/SnakeYAML/XStream/Kryo/Hessian style object materialization
  - ZipInputStream/ZipFile archive extraction
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

Confirm whether untrusted bytes, text, request bodies, message payloads, files,
or cache entries are materialized into objects or XML documents.

For Java object deserialization, look for ObjectInputFilter, class allowlists,
signed/trusted sources, and constrained gadget surfaces. Missing context should
be `uncertain` unless the source and sink are concrete.

For XXE, require parser configuration evidence. Safe factories disable DOCTYPE,
external general entities, external parameter entities, external DTD loading, and
external entity support before parsing attacker-controlled XML.

For third-party parsers, check polymorphic typing, auto type support,
constructor/object materialization, and class allowlists. For YAML/XML/JSON
parsers, distinguish plain DTO binding from arbitrary type materialization. For
Zip Slip, prove archive entry names reach filesystem writes/creates and allowed
root checks do not dominate the sink.

For active audit, inspect request bodies, file uploads, message payloads, cache
entries, and helper methods reachable from parser entrypoints. Mark non-candidate
findings as `java_llm_active_audit`.
