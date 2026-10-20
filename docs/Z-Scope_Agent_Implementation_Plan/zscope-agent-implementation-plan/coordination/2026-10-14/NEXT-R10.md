# R10 dependency and ownership plan

Prepared while R9 final verification is running. **No next task is dispatched by this document.** Dispatch requires a green current-byte six-command R9 receipt plus fresh public Bridge session checks.

| Work | Worker | Isolated workspace | Exclusive source ownership |
|---|---|---|---|
| S01-SYMBOL | Kimi K3 | s01-symbol-r10 | knowledge_db.py, code_index.py, instance_index.py, semantics/contracts.py, two new symbol/native tests |
| U01-MCP-JOBS | ZCode GLM5.3 | u01-mcp-r10 | mcp/provider.py, new mcp/jobs_adapter.py, four existing MCP tests, new test_mcp_jobs.py |
| ASTRA-UX-R10 | Astra | astra-ux-r10 | first-party static files, existing workbench browser test and fixture; vendor/license files read only |

All copies derive from the same accepted source snapshot; root integration and all shared documents/locks remain coordinator-owned. Prior workspaces and artifacts remain intact. No old S06-R02 session restoration, worker CLI driving, duplicate Bridge service, or DeepSeek complex work is authorized here.

Current integration gaps verified in source:

- `ScanSessionRunner.run` still calls `_ensure_semantic_phase`; batch execution still calls `analyze_function_entries(entries)` at scan_session.py:764. It does not call the new per-instance API.
- `ScanSessionRunner` does not construct `SessionWorkScheduler` or `JobWindowHook`; complete scanner queue/checkpoint/cooperative stop/remaining integration is pending. Standalone scheduler/owner tests do not close JOB04/JOB06.
- `ZScopeMcpProvider` still constructs the old `ScanRequestService` and calls its in-memory start/status. The Web service uses `ScanJobService`; the MCP migration has an independent dependency and ownership boundary.
- Scoped graph/type/macro/contract consumers still return declared gaps when no current member receipt can authorize them. S01-SYMBOL must supply actual precise data before broader semantic coverage is claimed.
- Full U01 profile/real tool and model readiness requires remaining business/conflict dependencies. Current editing/prepare evidence does not establish model connection or project scan effects.

Coordinator next shared integration is ScanSession/ParallelAnalyzer and CLI/Web/MCP same-source regression. S02/S03/S04, general links and full demand equivalence remain behind their original dependencies. Real project/LLM effect acceptance, formal benchmark, portable smoke and S10/Q conditional branches remain separate; absent process LLM settings or requested business materials are not replaced with synthetic success.
