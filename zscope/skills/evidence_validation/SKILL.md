---
name: evidence_validation
description: Validate a suspected defect against source evidence and available contracts.
category: validation
triggers:
  - candidate finding has been produced
allowed_tools:
  - get_function_impl
  - get_function_snapshot
  - list_known_functions
  - get_file_snippet
  - get_call_graph
  - get_type_info
allowed_mcp_tools:
  - zscope.get_function_impl
  - zscope.get_function_snapshot
---

Compare the finding's path and assumptions with code evidence. Validate when the
path is plausible and no mitigation is visible. Reject only when a concrete
guard, range proof, ownership transfer, cleanup path, or synchronization rule
clearly eliminates the issue.
