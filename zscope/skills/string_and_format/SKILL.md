---
name: string_and_format
languages: [c_cpp]
description: Audit C string termination, format strings, and text parsing hazards.
category: input_memory_safety
triggers:
  - strcpy/strncpy/strcat/strncat/sprintf/snprintf
  - printf/syslog/fprintf with nonliteral format
  - strlen/strcmp on buffers from IO
allowed_tools:
  - get_function_impl
  - get_file_snippet
  - get_data_flow
  - get_type_info
allowed_mcp_tools:
  - zscope.code.get_function_impl
  - zscope.knowledge.query
---

Check whether strings are NUL-terminated before string APIs, whether destination
capacity includes the terminator, whether strncpy leaves unterminated buffers,
and whether attacker-controlled text is used as a format string. Confirm the
input source and the missing guard before reporting.
