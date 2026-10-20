"""Prepare explicit compatibility revisions; never generalize the whitelist."""
from pathlib import Path
import ast
import datetime as dt
import hashlib
import json

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
WORK = ROOT / ".coordination/20261014/workspaces/coordinator-contract-tests-r33"
OUT = ROOT / "artifacts/coordinator-review-revision-repair-r33-20261017"
SOURCE = WORK / "zscope/core/validation/review_checks.py"
sha = lambda path: hashlib.sha256(path.read_bytes()).hexdigest()
target = OUT / "candidate/zscope/core/validation/review_checks.py"
assert not target.exists()
target.parent.mkdir(parents=True)
source = SOURCE.read_text(encoding="utf-8")
tree = ast.parse(source)
assignment = next(node for node in tree.body if isinstance(node, ast.Assign) and any(isinstance(name, ast.Name) and name.id == "RULE_CONTRACT_REVISIONS" for name in node.targets))
before = ast.literal_eval(assignment.value)
current = {
    "unsynchronized_shared_flag_or_counter": 10,
    "clang_cfg_unsynchronized_shared_flag_or_counter": 10,
    "clang_cfg_parent_release_without_owned_member_cleanup": 8,
    "clang_cfg_acquire_without_release_on_exit": 11,
    "clang_cfg_unchecked_insert_after_ownership_handoff": 9,
    "clang_cfg_unbounded_count_indexes_fixed_array": 8,
    "clang_cfg_nonliteral_format_string": 8,
    "clang_cfg_narrowed_allocation_original_length_copy": 8,
    "clang_cfg_return_with_lock_held": 10,
    "clang_cfg_fd_open_return_without_close": 10,
    "clang_cfg_allocation_result_used_without_null_check": 7,
}
assert set(before) == set(current) and all(max(before[name]) + 1 == value for name, value in current.items())
for name, value in current.items():
    old = f'    "{name}": {{{", ".join(map(str, sorted(before[name])))}}},'
    new = f'    "{name}": {{{", ".join(map(str, sorted(before[name] | {value})))}}},'
    assert source.count(old) == 1
    source = source.replace(old, new)
target.write_text(source, encoding="utf-8", newline="\n")
extension = HERE / "followups-r12/coordinator-instance-integration-r24-ownership-extension-09.json"
assert not extension.exists()
ownership = dict(actual_task="/root", owner="coordinator", observed_at=dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat(), isolated_workspace=WORK.relative_to(ROOT).as_posix(), added_paths=["zscope/core/validation/review_checks.py", "tests/test_review_current_revisions_r33.py"], old_probe_must_finish_before_WORK_change=True, no_native_worker_ownership_overlap=True, stage_write=False, root_write=False, rule_catalog_changed=False, reason="R29 current rule revisions are unintentionally rejected by unchanged Review checker revision table; independent source audit and actual probe required")
extension.write_text(json.dumps(ownership, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
receipt = dict(actual_task="/root", prepared_at=ownership["observed_at"], source_path="zscope/core/validation/review_checks.py", before_sha256=sha(SOURCE), candidate_sha256=sha(target), explicit_current_additions=current, preserved_old_supported_revisions={name: sorted(values) for name, values in before.items()}, checker_schema_unchanged=True, algorithm_binding_receipt_logic_unchanged=True, native_tool_not_changed=True, candidate_test_sha256=sha(OUT / "test_review_current_revisions_r33.py"), source_review_pending=True, actual_red_pending=True, product_WORK_intake=False, stage_intake=False, root_intake=False)
(OUT / "candidate.json").write_text(json.dumps(receipt, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
print(json.dumps(dict(candidate_sha256=receipt["candidate_sha256"], additions=len(current))))
