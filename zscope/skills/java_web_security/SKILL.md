---
name: java_web_security
description: Audit Java web request boundaries, SSRF, path traversal, redirects, and file/URL construction.
category: java_security
triggers:
  - Spring MVC/JAX-RS/Servlet request parameters, headers, body, path variables
  - URL/URI/HttpClient/RestTemplate/WebClient construction
  - File/Path/Files APIs using request-derived values
  - redirects, forwards, downloads, uploads, response headers, cookies, CORS
allowed_tools:
  - get_function_impl
  - get_function_snapshot
  - get_file_snippet
  - get_callers
  - get_type_info
  - get_data_flow
allowed_mcp_tools:
  - zscope.code.get_function_impl
  - zscope.get_function_snapshot
  - zscope.knowledge.query
---

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
