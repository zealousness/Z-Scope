---
name: java_injection
description: Audit Java SQL, command, expression, and template injection paths.
category: java_security
triggers:
  - Statement.execute/executeQuery/executeUpdate with dynamic SQL
  - MyBatis ${} substitution
  - JPA/JPQL string concatenation and Criteria fallbacks
  - Mongo/NoSQL query documents built from text
  - LDAP/JNDI lookup or search filters
  - Runtime.exec or ProcessBuilder
  - expression/template/script evaluation with external input
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

Trace untrusted Java request, message, CLI, file, or database-derived data into
SQL, JPQL/JPA, NoSQL, LDAP/JNDI, process execution, expression evaluation,
template rendering, or scripting sinks. A valid finding needs the source, the
sink, the call path, and why the guard is missing or insufficient.

For SQL, distinguish true parameter binding from string concatenation. `#{}` or
PreparedStatement setters can be mitigating evidence; MyBatis `${}` and dynamic
table/order fields require a strict allowlist.

For command execution, prefer an issue only when user-controlled text can affect
the executable or arguments. Fixed executable plus allowlisted separate
arguments may be safe.

For active audit, inspect reachable service, mapper, repository, and helper
callees even when the controller itself only passes a DTO. Check DTO fields,
headers, path variables, message payloads, and environment/CLI values. Mark
non-candidate findings as `java_llm_active_audit` and include concrete source,
sink, entry path, and guard analysis.
