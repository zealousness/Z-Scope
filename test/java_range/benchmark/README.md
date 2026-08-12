# Java benchmark data

- `entries.json` contains runtime entry locations only and is copied to scans in
  answer-free form.
- `ground_truth.json` is the only scoring truth source and is visible only to
  the score phase.
- `structural_baseline.json` defines the offline structural regression baseline.
- `maintenance/entry_rule_coverage.json` maps entries to expected deterministic
  rules for maintainers and tests; it is never copied into scan input.

Use `zscope-benchmark`; no script in this directory is an execution entry point.
