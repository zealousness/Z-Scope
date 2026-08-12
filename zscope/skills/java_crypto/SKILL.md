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
  - get_function_impl
  - get_function_snapshot
  - get_file_snippet
  - get_callers
  - get_type_info
allowed_mcp_tools:
  - zscope.code.get_function_impl
  - zscope.get_function_snapshot
---

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
