"""Prepare a strict union of R18 plus every R19 independent collection."""
from pathlib import Path

HERE=Path(__file__).resolve().parent
source=(HERE/"verify_current_root_r18.py").read_text(encoding="utf-8")
needle='TESTS = list(dict.fromkeys(TESTS))\nassert all((ROOT/name).is_file() for name in TESTS), "accepted current-root test missing"'
# The original wording is preserved verbatim; match its actual source text.
needle='TESTS = list(dict.fromkeys(TESTS))\nassert all((ROOT/name).is_file() for name in TESTS), "accepted current-root test missing"' if needle in source else 'TESTS = list(dict.fromkeys(TESTS))\nassert all((ROOT/name).is_file() for name in TESTS), "accepted current-root test missing"'
actual='TESTS = list(dict.fromkeys(TESTS))\nassert all((ROOT/name).is_file() for name in TESTS), "accepted current-root test missing"'
if actual not in source:
    actual='TESTS = list(dict.fromkeys(TESTS))\nassert all((ROOT/name).is_file() for name in TESTS), "accepted current-root test missing"'
# Use the stable assert line as the insertion point; its error text is data.
lines=source.splitlines(keepends=True)
positions=[i for i,line in enumerate(lines) if line.startswith('assert all((ROOT/name).is_file() for name in TESTS)')]
assert len(positions)==1
insertion='''R19_REVIEWS = {
    "VALIDATION-CONTEXT-R18": "coordinator-validation-context-r19-final-acceptance-20261015",
    "U01-STOP-AT-R18": "coordinator-stop-r19-final-acceptance-20261015",
    "S07-NATIVE-HOT-R19": "coordinator-native-hot-r19-final-acceptance-20261015",
}
assert set(R19_REVIEWS) <= integrated
r19_source_paths = set()
r19_black_paths = set()
for identity, label in R19_REVIEWS.items():
    review = json.loads((ROOT / "artifacts" / label / "review.json").read_text(encoding="utf-8"))
    assert review["independent_acceptance_passed"] and review["source_unchanged"]
    assert len(review["commands"]) == 4 and all(r["returncode"] == 0 for r in review["commands"])
    for p, sha in review["delivered_hashes"].items():
        assert hashlib.sha256((ROOT/p).read_bytes()).hexdigest() == sha
        r19_source_paths.add(p)
        if p.endswith(".py"): r19_black_paths.add(p)
    for arg in review["commands"][0]["command"]:
        if arg.startswith("tests/") and arg.endswith(".py"):
            TESTS.append(arg)
        elif Path(arg).is_absolute() and Path(arg).name.startswith("test_") and arg.endswith(".py"):
            original = HERE / "followups-r12" / Path(arg).name
            assert original.is_file()
            assert hashlib.sha256(original.read_bytes()).hexdigest() == hashlib.sha256(Path(arg).read_bytes()).hexdigest()
            TESTS.append(str(original.relative_to(ROOT)))
r19_black_paths.update({"tests/test_incremental_replay.py", "tests/test_config_v3_preparation.py"})
TESTS = list(dict.fromkeys(TESTS))
'''
lines.insert(positions[0],insertion)
source=''.join(lines)
anchor='before = capture()'
assert source.count(anchor)==1
source=source.replace(anchor,'SOURCES = sorted(set(SOURCES) | r19_source_paths)\n'+anchor)
anchor='    started = dt.datetime.now(dt.timezone.utc).isoformat()'
assert source.count(anchor)==1
source=source.replace(anchor,'    if "black" in command:\n        command += sorted(r19_black_paths)\n'+anchor)
source=source.replace('"test_file_count": len(TESTS),','"test_file_count": len(TESTS),\n    "r19_integrated_tasks": sorted(R19_REVIEWS),\n    "r19_all_independent_collections_preserved": True,')
target=HERE/"verify_current_root_r19.py"
assert not target.exists()
target.write_text(source,encoding="utf-8",newline="\n")
clock=(HERE/"verify_joint_with_clock_r19.py").read_text(encoding="utf-8").replace('label.startswith("coordinator-r18-")','label.startswith("coordinator-r19-")').replace('HERE / "verify_current_root_r18.py"','HERE / "verify_current_root_r19.py"')
target=HERE/"verify_joint_with_clock_r20.py"
assert not target.exists()
target.write_text(clock,encoding="utf-8",newline="\n")
print("R19 union launcher prepared; no root mutation or run yet",flush=True)
