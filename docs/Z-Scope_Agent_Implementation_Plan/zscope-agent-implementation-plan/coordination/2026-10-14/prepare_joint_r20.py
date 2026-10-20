"""Keep the whole passed R19 collection and add every R20 delivery/probe."""
from pathlib import Path
import hashlib

HERE = Path(__file__).resolve().parent
source = (HERE / "verify_current_root_r19.py").read_text(encoding="utf-8")
anchor = "R19_REVIEWS = {"
assert source.count(anchor) == 1
source = source.replace(anchor, '''R20_REVIEW = json.loads((ROOT / "artifacts/coordinator-job-cli-window-r20-final-acceptance-20261015/review.json").read_text(encoding="utf-8"))
assert R20_REVIEW["independent_acceptance_passed"] and R20_REVIEW["source_unchanged"]
assert len(R20_REVIEW["commands"]) == 4 and all(r["returncode"] == 0 for r in R20_REVIEW["commands"])
assert "U01-JOB-CLI-WINDOW-R20" in integrated
R20_INTAKE = json.loads((ROOT / "artifacts/intake-job-cli-window-r20-20261015/receipt.json").read_text(encoding="utf-8"))
R20_OVERRIDES = {r["path"]: r["after"] for r in R20_INTAKE["files"]}
assert set(R20_REVIEW["delivered_hashes"]) <= set(R20_OVERRIDES)
for p, sha in R20_REVIEW["delivered_hashes"].items():
    assert R20_OVERRIDES[p] == sha == hashlib.sha256((ROOT/p).read_bytes()).hexdigest()
R19_REVIEWS = {''')
anchor = 'assert hashlib.sha256((ROOT/p).read_bytes()).hexdigest() == sha\n        r19_source_paths.add(p)'
assert source.count(anchor) == 1
source = source.replace(anchor, 'assert hashlib.sha256((ROOT/p).read_bytes()).hexdigest() == R20_OVERRIDES.get(p, sha)\n        r19_source_paths.add(p)')
anchor = 'r19_black_paths.update({"tests/test_incremental_replay.py", "tests/test_config_v3_preparation.py"})'
assert source.count(anchor) == 1
addition = '''
r19_source_paths.update(R20_OVERRIDES)
r19_black_paths.update(p for p in R20_REVIEW["delivered_hashes"] if p.endswith(".py"))
for arg in R20_REVIEW["commands"][0]["command"]:
    if arg.startswith("tests/") and arg.endswith(".py"):
        TESTS.append(arg)
    elif Path(arg).is_absolute() and Path(arg).name.startswith("test_") and arg.endswith(".py"):
        original = HERE / "followups-r12" / Path(arg).name
        assert original.is_file()
        assert hashlib.sha256(original.read_bytes()).hexdigest() == hashlib.sha256(Path(arg).read_bytes()).hexdigest()
        TESTS.append(str(original.relative_to(ROOT)))
'''
source = source.replace(anchor, anchor + addition)
anchor = '"r19_all_independent_collections_preserved": True,'
assert source.count(anchor) == 1
source = source.replace(anchor, anchor + '\n    "r20_owner_cli_window_integrated": True,\n    "r20_all_independent_collections_preserved": True,')
launcher = HERE / "verify_current_root_r20.py"
assert not launcher.exists()
launcher.write_text(source, encoding="utf-8", newline="\n")
clock = (HERE / "verify_joint_with_clock_r20.py").read_text(encoding="utf-8")
clock = clock.replace('label.startswith("coordinator-r19-")', 'label.startswith("coordinator-r20-")').replace('"verify_current_root_r19.py"', '"verify_current_root_r20.py"')
(HERE / "verify_joint_with_clock_r21.py").write_text(clock, encoding="utf-8", newline="\n")
print(hashlib.sha256(launcher.read_bytes()).hexdigest())
