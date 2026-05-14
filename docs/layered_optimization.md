# Z-SCOPE Layered Optimization

Z-SCOPE uses layered analysis so each stage has a narrow job and a reusable
artifact. This keeps prompt size down and makes benchmark results auditable.

## 1. Layer Overview

| Layer | Code | Responsibility |
| --- | --- | --- |
| workflow | `zscope/workflows/*.yaml`, `SpecRegistry` | choose runtime steps for default/resume/maintain |
| backend facts | `zscope/retrieval/*`, `KnowledgeDB` | extract functions, types, calls, globals, SVF facts |
| semantic/evidence | semantic snapshots, deterministic candidates | summarize behavior and create evidence-backed candidates |
| agent validation | vulnerability analyzer, deep worker, validator, reconciler | interpret, verify, deduplicate and persist findings |

## 2. Workflow Layer

Workflow specs are declarative execution plans:

- `default.yaml`: fresh scan, premodel callees, model entry, plan focused
  candidates, mine vulnerabilities, validate, persist.
- `resume.yaml`: skip completed entries by snapshot state, analyze the rest, and
  merge skipped reports.
- `maintain.yaml`: compare fingerprints, reuse unchanged reports, reconcile
  changed historical findings, and rescan changed entries.

The CLI, not YAML config, chooses the workflow. `--resume` and `--maintain` are
mutually exclusive.

## 3. Backend Fact Layer

`CodeIndex` hides backend differences behind one query surface. Unified mode is
the preferred C backend:

```text
UnifiedBackend
  |
  +-- ClangBackend -> KnowledgeDB: functions/types/globals/macros/calls
  |
  +-- SvfAnalyzer  -> KnowledgeDB: indirect_calls + taint_signatures
```

SVF is an enrichment path. A missing or failing SVF installation should not
erase Clang facts.

## 4. Semantic And Evidence Layer

Semantic modeling produces compact per-function JSON snapshots. Deterministic
candidate generation adds local, reproducible signals for high-value C bugs.

A candidate should include:

- stable `candidate_id`
- defect class and mapped skill
- source and sink location
- object, lock or resource identity when known
- positive and negative evidence
- rule confidence
- dedup key

Generic rules are allowed; benchmark-specific rules are not. For example,
matching `access/stat` followed by `open/fopen` is valid. Matching a fixture
helper name from `test/range` is not.

## 5. Agent Layer

The agent layer consumes facts rather than inventing them from a blank prompt:

- `semantic_modeler` builds snapshots.
- `vulnerability_analyzer` receives active skills, snapshots, candidates and
  worker summaries.
- `deep_worker` investigates focused source/sink/path questions.
- `validator_agent` confirms, rejects or downgrades findings.
- `issue_reconciler_agent` compares historical and current findings.

Worker budget is not a coverage boundary. Candidates that exceed
`max_subagent_tickets` are still passed to the main analyzer.

## 6. Skill Layer

Vulnerability skills:

- `bounds_and_integer`
- `resource_lifecycle`
- `temporal_memory`
- `null_and_failure`
- `stack_escape`
- `concurrency_lock_order`
- `shared_state_race`
- `ownership_contract`
- `string_and_format`

Support skills:

- `code_semantic_modeling`
- `evidence_validation`
- `snapshot_refresh_decision`
- `zscope-prompt-autofill`

`zscope-prompt-autofill` is a template-only skill. Users must fill project
vocabulary directly in its `SKILL.md`; Z-SCOPE does not load skill
`references/` files at runtime.

## 7. Benchmark Discipline

Benchmark runs must separate source fixture, config, runtime output and secrets:

- keep `test/range` tracked as source test code
- ignore build directories, snapshots, benchmark runs and reports
- store API keys in environment variables
- keep range entries free of `custom_prompt` for generic benchmark runs
- rerun entry coverage before full benchmark scans

This discipline lets recall, false-positive rate and scan speed reflect the
analyzer rather than hidden prompts or fixture-specific shortcuts.
