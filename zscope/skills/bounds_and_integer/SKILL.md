---
name: bounds_and_integer
description: Audit buffer bounds, array indexing, and integer size conversions.
category: memory_safety
triggers:
  - memcpy/memmove/strcpy/strncpy/strcat/sprintf/snprintf
  - read/recv/fread into caller-provided buffers
  - array index or pointer arithmetic uses external input
  - allocation size is computed from multiplication/addition/cast
allowed_tools:
  - get_function_impl
  - get_function_snapshot
  - get_file_snippet
  - get_type_info
  - get_data_flow
  - verify_taint_reachability
allowed_mcp_tools:
  - zscope.get_function_impl
  - zscope.query_knowledge
allowed_mcp_resources:
  - zscope://knowledge/functions
---

Prove whether every write/read length is bounded by the destination/source
object. Track size_t/int signedness, truncation, multiplication/addition
overflow, sentinel bytes, NUL termination, and whether the bound is checked
before the sink. A finding needs the source of the size/index, the sink, and the
missing or incorrect guard.
