---
name: evidence_validation
languages: [c_cpp, java]
description: Validate a suspected defect against source evidence and available contracts.
category: validation
triggers:
  - candidate finding has been produced
allowed_tools:
  - get_function_info
  - get_function_snapshot
  - list_known_functions
  - get_file_snippet
  - get_call_graph
  - get_type_info
allowed_mcp_tools:
  - zscope.code.get_function_info
  - zscope.get_function_snapshot
---

Compare the finding's path and assumptions with code evidence under a strict
exploitability bar. Validate only when the source, sink, source controllability,
and feasible trigger path are concrete. Reject hardening/style/theoretical
findings when they do not prove a source-to-sink path, even if the code could be
made more defensive. A missing guard matters only when the relevant input can
reach the sink in the shown path. For mitigations, cite the concrete guard,
range proof, ownership transfer, cleanup path, or synchronization rule.
