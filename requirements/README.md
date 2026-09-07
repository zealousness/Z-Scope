# Python constraints

`constraints/py313.txt` is the hash-locked Linux release and CI resolution
generated from `dev.in`. Regenerate it with:

```bash
python scripts/compile_constraints.py
```

The generator invokes `uv pip compile` for the supported Python minor.
Workflows install the file with `--require-hashes`.

`release/py313.txt` is the hash-locked dependency inventory used by the offline
application bundle. Audit this exact inventory for known vulnerabilities
(`pip-audit --require-hashes --no-deps -r requirements/release/py313.txt`) and
check every installed distribution against `license-policy.json` via
`scripts/check_dependency_licenses.py`. Adding, removing, or relicensing a
release dependency therefore requires an explicit policy review in the same
change.
