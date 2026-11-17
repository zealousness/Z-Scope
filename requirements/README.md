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

Project semantics YAML uses `ruamel.yaml` to preserve reviewed document structure.
Both `ruamel-yaml` and its Linux CPython dependency `ruamel-yaml-clib` must be
included in the constraints, release and two portable locks, with MIT licenses
recorded in `license-policy.json`. Keep these pins aligned when updating the YAML
runtime; a source install alone does not validate an offline bundle.

Symbol searches use `regex` in Version 0 mode to retain Python `re` behavior
while enforcing a shared timeout for a complete query. The dependency is
included in all four runtime locks. Its distribution declares
`Apache-2.0 AND CNRI-Python`; both licenses are recorded in the policy and
must be included by the existing dependency-license packaging step.

## Security pins

`urllib3` and `certifi` are transitive (requests / httpx / openai) but they ship in
the release bundle and in both portable archives, so an advisory that names them
applies to every artifact. Fix them in all four locks in the same change;
`tests/test_release_contract.py::test_every_lock_pins_the_same_security_fixed_runtime_versions`
fails if the locks disagree or drop below the fixed floor.

The development formatter is pinned to `black==26.10.1` in `pyproject.toml`,
`dev.in` and the hashed development constraints. This fixes
[GHSA-cg8m-r9f2-5wm2](https://github.com/advisories/GHSA-cg8m-r9f2-5wm2)
(`CVE-2026-114134`, bundled GitHub Action version validation) and
[GHSA-3936-cmfr-pm3m](https://github.com/advisories/GHSA-3936-cmfr-pm3m)
(`CVE-2026-32274`, cache filename path handling).
Black is not included in the release or portable runtime inventories.
Keep the existing formatting-debt baseline non-expanding when upgrading it;
the formatter upgrade is not permission to accept new formatting debt.

The Java Range fixture and the portable Maven cache use XStream 1.4.21 to fix
[CVE-2024-47072](https://x-stream.github.io/CVE-2024-47072.html). The cache lock is
refreshed from checksum-verified Maven Central artifacts; this does not change
the Java fixture's intentional source-level vulnerabilities or ground truth.
