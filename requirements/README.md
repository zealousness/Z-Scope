# Python constraints

`constraints/py39.txt` through `py314.txt` are hash-locked Linux release and CI
resolutions generated from `dev.in`. Regenerate all files with:

```bash
python scripts/compile_constraints.py
```

The generator invokes `uv pip compile` separately for every verified Python
minor. CI installs each matching file with `--require-hashes`, runs the full
test suite and `pip check`, and rejects an uncommitted regeneration diff.

`release/py313.txt` is the hash-locked dependency inventory used by the offline
application bundle. CI audits this exact inventory for known vulnerabilities
and checks every installed distribution against `license-policy.json`. Adding,
removing, or relicensing a release dependency therefore requires an explicit
policy review in the same pull request.
