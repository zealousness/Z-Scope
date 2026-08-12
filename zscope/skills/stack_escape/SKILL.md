---
name: stack_escape
languages: [c_cpp]
description: Audit escaping stack addresses and asynchronous lifetime bugs.
category: lifetime
triggers:
  - return address of local variable
  - store local address into global or heap object
  - pass local address to pthread_create/CreateThread/callback
allowed_tools:
  - get_function_impl
  - get_file_snippet
  - get_callers
  - get_call_graph
allowed_mcp_tools:
  - zscope.code.get_function_impl
---

Determine whether a local variable address outlives the stack frame. Treat
thread starts, callbacks, timers, async IO, and retained global/container fields
as lifetime-extending sinks. A finding needs the local object, the escape sink,
and why the consumer can outlive the creator.
