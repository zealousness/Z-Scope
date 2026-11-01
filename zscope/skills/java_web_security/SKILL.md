---
name: java_web_security
languages: [java]
description: Audit Java web request boundaries, SSRF, path traversal, redirects, and file/URL construction.
category: java_security
triggers:
  - Spring MVC/JAX-RS/Servlet request parameters, headers, body, path variables
  - URL/URI/HttpClient/RestTemplate/WebClient construction
  - File/Path/Files APIs using request-derived values
  - redirects, forwards, downloads, uploads, response headers, cookies, CORS
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
- 列表分页使用返回的 `page.next_offset`，`search_code` 的 `scope=text/files` 续页保留返回的 `view_id`；`read_code` 源码续取使用 `data.source.next_start_line` 作为 `start_line`，同时省略或更新 `end_line`；不要用完全相同的参数重复调用工具。

Treat framework-bound request data as untrusted: path variables, query
parameters, headers, cookies, request bodies, multipart fields, session values,
and DTO fields populated from a request.

For SSRF, prove that an attacker-controlled URL/host reaches an outbound client
and that scheme, host, port, redirects, DNS rebinding, and private-network
targets are not sufficiently constrained.

For path traversal, prove that external input reaches File/Path/Files or archive
extraction and that normalization/canonicalization plus allowed-root checks do
not dominate the sink.

For uploads and downloads, check filename, extension, content type, archive
entry names, storage root, overwrite behavior, and whether later reads/deletes
reuse request-derived names. For redirects and headers, distinguish fixed safe
destinations from caller-controlled URLs or CRLF-capable header values. For
CORS/cookies, consider wildcard origins, credentials, HttpOnly, Secure, and
SameSite only when the endpoint or cookie has security impact.

For active audit, follow Controller -> Service -> helper/file/client flows.
Use framework annotations and DTO/request binding as source evidence, and mark
non-candidate findings as `java_llm_active_audit`.
