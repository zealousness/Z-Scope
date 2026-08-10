---
name: java_concurrency
description: Audit Java shared mutable state, unsafe publication, races, and lock/async hazards.
category: java_concurrency
triggers:
  - static mutable fields and singleton services
  - non-thread-safe collections accessed from controllers/listeners/schedulers
  - CompletableFuture, Executor, Thread, Timer, @Async
  - synchronized/Lock/volatile/Atomic misuse
  - mutable caches, SimpleDateFormat, parser instances, or shared DTO builders
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

Identify shared mutable state that can be accessed concurrently by request
threads, listeners, schedulers, async callbacks, or executor tasks. A valid
finding needs the shared object, at least two plausible concurrent paths or a
framework concurrency contract, and missing or inconsistent synchronization.

Check unsafe publication, double-checked locking without volatile, compound
operations on ConcurrentHashMap or Atomic values, lock ordering, callbacks under
locks, and non-thread-safe date/format/parser/cache objects stored in singletons.

For active audit, use the framework concurrency contract: Spring singleton
controllers/services, servlet filters, listeners, schedulers, and async tasks can
run concurrently. A finding needs shared mutable state plus a plausible
concurrent access path or framework-managed multi-threaded entry. Immutable
constants and request-scoped locals are negative evidence.

Mark non-candidate findings as `java_llm_active_audit`.
