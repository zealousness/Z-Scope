---
name: java_resource_lifecycle
languages: [java]
description: Audit Java Closeable/AutoCloseable resource lifecycle and transaction cleanup.
category: java_reliability_security
triggers:
  - FileInputStream/FileOutputStream/Reader/Writer/Socket
  - JDBC Connection/Statement/PreparedStatement/ResultSet
  - channels, streams, zip/archive handles
  - manual close without try-with-resources
  - readAllBytes/readString on unbounded request/file/archive content
  - temporary files/directories and cleanup-sensitive paths
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

Trace each resource acquisition through normal returns, exceptions, early exits,
and ownership transfer. Prefer issues when a resource is neither covered by
try-with-resources nor closed in a finally/error path.

For JDBC and transaction-like APIs, check nested ResultSet/Statement/Connection
ownership and rollback/commit behavior. If a framework clearly owns lifecycle
management, record that as negative evidence rather than reporting a leak.

For active audit, inspect normal returns, exceptions, early returns, and helper
ownership transfer. Also check resource exhaustion from unbounded reads or loops,
temporary files without cleanup or safe permissions, and archive/stream handles.
Framework-managed resources should be treated as negative evidence.

Mark non-candidate findings as `java_llm_active_audit` and keep source/sink or
acquire/release evidence explicit.
