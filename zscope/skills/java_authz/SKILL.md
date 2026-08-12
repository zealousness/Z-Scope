---
name: java_authz
languages: [java]
description: Audit Java authentication, authorization, tenant, and object-level access control checks.
category: java_security
triggers:
  - controller/service methods changing or reading sensitive objects
  - missing @PreAuthorize/Secured/RolesAllowed or equivalent checks
  - userId/accountId/tenantId path or query parameters
  - repository lookups followed by updates/deletes/downloads
  - Servlet Filter, HandlerInterceptor, and Spring Security permitAll rules
allowed_tools:
  - get_function_impl
  - get_function_snapshot
  - get_file_snippet
  - get_callers
  - get_type_info
  - get_call_graph
allowed_mcp_tools:
  - zscope.code.get_function_impl
  - zscope.get_function_snapshot
  - zscope.knowledge.query
---

Check whether the current principal is authenticated and authorized for the
specific object, tenant, role, or operation. A valid finding needs an exposed
entry, a sensitive action or data read, attacker-controlled identity/object key,
and absence of an effective authorization check.

Do not treat naming alone as proof. Positive evidence includes missing or
bypassed annotations, service-layer checks that validate only existence, tenant
filters omitted from repository queries, or object IDs accepted from the caller
without ownership comparison.

For active audit, classify the action as read, state change, admin operation,
tenant-scoped operation, or object download/delete. Check annotations,
filter/interceptor behavior, SecurityFilterChain matchers, role checks, tenant
predicates in repository queries, and ownership comparison after lookup. A
Filter/Interceptor that observes credentials but still unconditionally
continues the chain is an authorization boundary concern.

Non-candidate findings must be marked `java_llm_active_audit` and should stay
review-only unless merged with a proof-carrying local/backend candidate.
