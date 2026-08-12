# C/C++ benchmark data

- `ground_truth.json` is the only scoring truth source and is visible only to
  the score phase.
- `deterministic_entries.json` is a deterministic, no-LLM regression manifest;
  it is not a second formal benchmark protocol and is not copied into automatic
  entry-discovery scans.
- `check_entry_coverage.py` and `fp_audit_rules.py` are scorer maintenance tools.
- `maintenance/` contains benchmark-maintainer data, never scan input.

Use `zscope-benchmark`; no script in this directory is an execution entry point.
