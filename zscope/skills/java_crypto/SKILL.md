---
name: java_crypto
languages: [java]
description: Audit weak Java cryptography, key handling, randomness, and password hashing.
category: java_security
triggers:
  - Cipher.getInstance with ECB/DES/RC4
  - MessageDigest MD5/SHA-1
  - hardcoded keys, IVs, salts, tokens, or passwords
  - Random used for security decisions
  - JWT signing or verification with hardcoded/weak secrets or decode-only APIs
  - trust-all HostnameVerifier/TrustManager or disabled certificate checks
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

Identify crypto choices that fail current security expectations: ECB, DES, RC4,
MD5, SHA-1 for signatures/passwords, deterministic IV/nonce reuse, hardcoded
keys, weak randomness, and homegrown encryption.

Validate the purpose before severity. Non-security checksums may be lower risk;
password hashing, token signing, credential storage, and transport encryption
require strong primitives, authenticated modes, proper key management, and
SecureRandom where randomness matters.

For JWT, check whether tokens are only decoded, whether issuer/audience/expiry
and signature are verified, and whether HMAC/RSA keys are hardcoded or derived
from weak configuration. For TLS, trust-all verifiers and permissive trust
managers are findings when they protect outbound security-sensitive calls.

For active audit, follow token/key creation helpers and security config methods
even when the entrypoint only calls a wrapper. Mark non-candidate findings as
`java_llm_active_audit`.
