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

## Security pins

`urllib3` and `certifi` are transitive (requests / httpx / openai) but they ship in
the release bundle and in both portable archives, so an advisory that names them
applies to every artifact. Fix them in all four locks in the same change;
`tests/test_release_contract.py::test_every_lock_pins_the_same_security_fixed_runtime_versions`
fails if the locks disagree or drop below the fixed floor.

Two `black` advisories are knowingly deferred, because both need `black>=26` and that
release reformats roughly 300 files that this repository keeps as reviewed debt in
`black-baseline.json`. Neither path is reachable here:

- GHSA-v53h-f6m7-xcgm (`CVE-2026-31900`) is in the `psf/black` GitHub Action with
  `use_pyproject: true`; this repository runs no black action (zero matches under
  `.github/workflows/`).
- GHSA-3936-cmfr-pm3m (`CVE-2026-32274`) needs attacker control of
  `--python-cell-magics`; the gate only runs `black --check` on repository paths.

Bump `black` together with the formatting migration, then delete this section.
