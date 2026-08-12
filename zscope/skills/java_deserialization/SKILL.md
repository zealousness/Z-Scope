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
