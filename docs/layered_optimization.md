# Z-SCOPE Layered Optimization

This document records the new four-layer architecture.

## 1. Workflow

Workflow specs live in `zscope/workflows/*.yaml`.

- `default.yaml`: fresh scan. It discovers entries when requested, premodels callees, models the entry, plans focused worker tickets, mines vulnerabilities, validates findings, and persists reports.
- `resume.yaml`: skips completed entries by `snapshot.db` state, analyzes the rest, then merges skipped reports.
- `maintain.yaml`: compares fingerprints, reuses unchanged reports, reconciles changed historical findings, and rescans only changed entries.

The runtime loads workflow specs through `SpecRegistry` and injects the selected workflow contract into agent prompts only when that agent runs.

## 2. Agent

Agent contracts live beside each Python agent as `AGENT.md`.

- `semantic_modeler`: builds compact function snapshots.
- `vulnerability_analyzer`: manages C memory and concurrency vulnerability mining.
- `deep_worker`: performs one context-clean focused investigation.
- `validator_agent`: confirms or rejects findings with source evidence.
- `issue_reconciler_agent`: deduplicates and verifies historical issue state.

The vulnerability analyzer can plan focused subagent tickets for allocation,
release, copy, lock, thread, and stack-escape triggers. By default this is only
a plan injected into the manager context. Set `analysis.enable_subagent_workers:
true` or `can_spawn_subagents: true` for the agent to execute the deep workers.

## 3. Skill

Skill contracts live in `zscope/skills/*/SKILL.md`. Each declares triggers,
allowed tools, allowed MCP tools/resources/prompts, and the focused audit model.

Current C audit skills:

- `bounds_and_integer`
- `resource_lifecycle`
- `temporal_memory`
- `null_and_failure`
- `stack_escape`
- `concurrency_lock_order`
- `shared_state_race`
- `ownership_contract`
- `string_and_format`
- `code_semantic_modeling`
- `evidence_validation`

The goal is to avoid one giant prompt that asks the model to find everything at
once. The manager identifies concrete code events and dispatches the narrow
skill that can prove or disprove that class.

## 4. Tool And MCP

Existing `ToolsRuntime`, `CodeIndex`, `KnowledgeDB`, and `SnapshotStore` remain
the execution layer. The new `zscope/mcp` package exposes them as MCP-style
primitives:

- Resources: `zscope://config`, `zscope://knowledge/stats`,
  `zscope://knowledge/functions`, `zscope://snapshots/list`
- Prompts: `zscope.entry_discovery`, `zscope.resource_lifecycle_audit`,
  `zscope.concurrency_audit`
- Tools: all existing analysis tools plus `query_knowledge` and
  `discover_entries`

Run the local MCP server with:

```bash
python -m zscope.mcp.server -c zscope.yaml
```

or through CLI:

```bash
zscope -c zscope.yaml --mcp-stdio
```

## Entry Discovery

`EntryDiscovery` classifies scan entries into:

- `api`: functions declared in `.h`/`.hpp`
- `communication`: functions calling send/recv/read/write/socket/shared-memory APIs
- `thread`: functions creating threads or passing work to async execution
- `other_user_input`: scanf/getline/getenv/getopt/ioctl/fread/open-like inputs

Enable it with:

```yaml
project:
  entry_discovery:
    enabled: true
    max_candidates: 200
    max_functions: 10000
    header_files: []
```

or run:

```bash
zscope -c zscope.yaml --discover-entries
```
