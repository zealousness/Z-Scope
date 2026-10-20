"""Prepare three minimal shared test migrations, without changing workspaces."""
from pathlib import Path
import ast
import datetime as dt
import difflib
import hashlib
import json
import sys

if sys.platform != "linux" or sys.flags.optimize:
    raise RuntimeError("Use non-optimized Linux Python")
HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
OUT = ROOT / "artifacts/consumer-shared-fixtures-r26-20261016"

def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

root_inputs = json.loads((ROOT / "artifacts/coordinator-r23-ui-projection-union-20261016/source-evidence.json").read_text(encoding="utf-8"))["after"]
assert all(sha(ROOT / path) == digest for path, digest in root_inputs.items())
changes = {
    "tests/test_lock_modes.py": (
        "    assert descriptor.revision == 9 and not descriptor.default_enabled\n",
        "    assert descriptor.revision == 10 and not descriptor.default_enabled\n",
    ),
    "tests/test_rule_runtime_governance.py": (
        "    runner.tool_policy_for_agent = lambda _name: None\n\n    config_hash_before = analyzer._config_hash()\n",
        "    runner.tool_policy_for_agent = lambda _name: None\n    runner._instance_scope = None  # Match the unscoped constructor binding.\n\n    config_hash_before = analyzer._config_hash()\n",
    ),
    "tests/test_analyzer_semantics.py": (
        "        ),\n    )\n    analyzer.candidate_pipeline = SimpleNamespace(\n",
        "        ),\n        analysis=SimpleNamespace(semantic_snapshot_candidate_mode=\"off\"),\n    )\n    analyzer.candidate_pipeline = SimpleNamespace(\n",
    ),
}
OUT.mkdir(exist_ok=False)
proof = {}
for path, (old, new) in changes.items():
    source = (ROOT / path).read_text(encoding="utf-8")
    assert source.count(old) == 1
    modified = source.replace(old, new, 1)
    before_ast, after_ast = ast.parse(source), ast.parse(modified)
    names = lambda tree: [node.name for node in ast.walk(tree) if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name.startswith("test_")]
    assert names(before_ast) == names(after_ast)
    assertions = lambda tree: [ast.dump(node, include_attributes=False) for node in ast.walk(tree) if isinstance(node, ast.Assert)]
    expected_assertions = assertions(ast.parse(source.replace("descriptor.revision == 9", "descriptor.revision == 10", 1))) if path.endswith("test_lock_modes.py") else assertions(before_ast)
    assert assertions(after_ast) == expected_assertions
    target = OUT / path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(modified, encoding="utf-8", newline="\n")
    (OUT / (Path(path).name + ".diff")).write_text("".join(difflib.unified_diff(source.splitlines(True), modified.splitlines(True), fromfile=path, tofile=path)), encoding="utf-8", newline="\n")
    proof[path] = dict(before_sha256=sha(ROOT / path), after_sha256=sha(target), tests_names_preserved=True, assertions_preserved_except_exact_catalog_revision=path.endswith("test_lock_modes.py"), all_assertions_unchanged=not path.endswith("test_lock_modes.py"))
assert all(sha(ROOT / path) == digest for path, digest in root_inputs.items())
review = dict(recorded_at=dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat(), actual_task="/root", proposed_scope="Coordinator-owned shared tests; prepared artifact only, no Stage/worker/Root copy yet", migrations=proof, source_failure_evidence=".coordination/20261014/workspaces/astra-instance-consumers-r25/artifacts/instance-consumers-r25/regression-01.log", source_failure_evidence_sha256=sha(ROOT / ".coordination/20261014/workspaces/astra-instance-consumers-r25/artifacts/instance-consumers-r25/regression-01.log"), product_modified=False, workspace_files_modified=0, tests_executed=0, independent_acceptance=False, integrated=False, joint_verification=False, root_bound_inputs_unchanged=len(root_inputs), reason="Revision10 is required by changed API-role effects; preserve exact revision assertion and experimental default-off. Two __new__ fixtures now initialize the same unscoped/snapshot-off defaults as the constructors; original behavior assertions remain byte-identical.")
(OUT / "review.json").write_text(json.dumps(review, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
print(json.dumps(dict(receipt=(OUT / "review.json").relative_to(ROOT).as_posix(), prepared_files=3, workspace_files_modified=0, tests_executed=0)))
