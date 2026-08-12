---
name: null_and_failure
languages: [c_cpp]
description: Audit unchecked allocation/API failures and null dereferences.
category: reliability_memory_safety
triggers:
  - malloc/calloc/realloc/external API returns pointer or handle
  - function parameter can be NULL
  - initialization returns error but later fields/handles are used
allowed_tools:
  - get_function_impl
  - get_function_snapshot
  - get_file_snippet
  - get_type_info
  - get_callers
allowed_mcp_tools:
  - zscope.code.get_function_impl
  - zscope.get_function_snapshot
---

Check whether returned pointers, handles, and initialization status are validated
before use. Include negative error codes, sentinel handles, partially initialized
objects, and cleanup that assumes initialization succeeded. Do not report if a
prior contract or guard proves non-null/non-error.
