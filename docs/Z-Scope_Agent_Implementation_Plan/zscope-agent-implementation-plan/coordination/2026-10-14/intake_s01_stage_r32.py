"""Accept the frozen bounded S01 module, then copy it into coordinator Stage."""
from pathlib import Path
import datetime as dt
import hashlib
import json
import shutil
import sys

assert sys.platform == "linux" and not sys.flags.optimize
HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
PRODUCER = ROOT / ".coordination/20261014/workspaces/s01-origin-repair-r31"
STAGE = ROOT / ".coordination/20261014/workspaces/coordinator-instance-integration-r24"
OUT = ROOT / "artifacts/s01-stage-intake-r32-20261017"


def read(path):
    return json.loads(path.read_text(encoding="utf-8"))


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write(path, value):
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")


def snapshot():
    return {path.relative_to(STAGE).as_posix(): sha(path) for directory in ("zscope", "scripts", "test", "tests", "docs/modules") for path in (STAGE / directory).rglob("*") if path.is_file() and "__pycache__" not in path.parts and path.suffix != ".pyc"}


review_path = ROOT / "artifacts/s01-source-review-r32-20261017/review.json"
source_review = read(review_path)
assert source_review["actual_reviewer_task"] == "/root/consumer_source_review_r28"
assert source_review["source_review_passed"] and source_review["blocking_findings"] == []
execution_path = ROOT / "artifacts/coordinator-s01-independent-r32-20261017/review.json"
execution = read(execution_path)
assert execution["execution_checks_passed"] and execution["returncode"] == 0
assert all(execution["exact_producer_case_counters_preserved"].values())
assert execution["independent_junit"] == {"results.xml": dict(tests=209, failures=0, errors=0, skipped=0), "authority-r24.xml": dict(tests=4, failures=0, errors=0, skipped=0)}
freeze_path = PRODUCER / "artifacts/s01-repair-r31/freeze.json"
freeze = read(freeze_path)
incoming = freeze["source_sha256"]
assert len(incoming) == 2 and incoming == execution["frozen_source_sha256"]
assert all(digest in json.dumps(source_review) for digest in incoming.values()), "Review must bind both exact frozen source hashes"
assert all(sha(PRODUCER / path) == digest for path, digest in (incoming | freeze["artifact_sha256"]).items())
prep = read(ROOT / "artifacts/coordinator-s01-replacement-r31-20261017/preparation.json")
assert all(sha(PRODUCER / path) == digest for path, digest in prep["readonly_sources"].items())
before = snapshot()
assert before == read(ROOT / "artifacts/stage-quality-repair-r30-20261017/repair-source.json")["full_stage_source_after"]
assert len(before) == 967 and all(not (STAGE / path).exists() for path in incoming)
root_inputs = prep["root_inputs"]
assert len(root_inputs) == 1065 and all(sha(ROOT / path) == digest for path, digest in root_inputs.items())
baseline = read(HERE / "followups-r12/coordinator-instance-integration-r24-baseline.json")
allowed = set(baseline["task"]["write_paths"])
for suffix in ("01", "02", "03", "04", "05", "06"):
    allowed.update(read(HERE / f"followups-r12/coordinator-instance-integration-r24-ownership-extension-{suffix}.json")["write_paths"])
assert not allowed & incoming.keys()
doc = "docs/modules/configuration-state.md"
assert doc in allowed
configuration_names = {"conftest.py", "pytest.ini", ".pytest.ini", "mypy.ini", ".mypy.ini", "tox.ini", "setup.cfg", "pyproject.toml"}
configs = {path.relative_to(STAGE).as_posix(): sha(path) for name in configuration_names for path in STAGE.rglob(name) if path.is_file()}
old_config_inputs = read(ROOT / "artifacts/consumer-stage-intake-r30-20261017/receipt.json")["stage_source_after"]
assert configs == {path: digest for path, digest in old_config_inputs.items() if Path(path).name in configuration_names}
at = dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat()
OUT.mkdir(exist_ok=False)
acceptance = dict(accepted_at=at, logical_task="S01-INSTANCE-SEMANTICS-MIN-R23", actual_producer_task=freeze["actual_task"], actual_source_reviewer_task=source_review["actual_reviewer_task"], source_review_sha256=sha(review_path), independent_execution_finished_at=execution["finished_at"], independent_execution_receipt=execution_path.relative_to(ROOT).as_posix(), independent_junit=execution["independent_junit"], six_commands_zero=True, frozen_source_sha256=incoming, previous_actual_failed_deliveries_preserved=3, consecutive_failures_after_this_slice_acceptance=0, independent_acceptance=True, accepted_scope="Frozen bounded instance-semantic module: exact current Linux glibc LP64 installed standard declarations, factory integrity/currentness/advisory/unknown denial; not wholeS01/S08/U01/native full scan/Root joint/real-project effects.", integrated_to_root=False, root_joint_verification=False, whole_package_complete=False)
write(OUT / "module-acceptance.json", acceptance)
extension = HERE / "followups-r12/coordinator-instance-integration-r24-ownership-extension-07.json"
assert not extension.exists()
write(extension, dict(coordinator_authorized=True, authorized_by="Existing user authorization: independently accept exact candidate, integrate into Stage and run current joint checks", write_paths=list(incoming), source_sha256=incoming, previous_owner=freeze["actual_task"], stage_owner="/root", previous_workspace_readonly=True, acceptance=(OUT / "module-acceptance.json").relative_to(ROOT).as_posix(), root_intake=False))
for path, digest in incoming.items():
    target = STAGE / path
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(PRODUCER / path, target)
    assert sha(target) == digest
(OUT / "configuration-state.before.md").write_bytes((STAGE / doc).read_bytes())
text = (STAGE / doc).read_text(encoding="utf-8")
if "  - tests/test_instance_semantics.py\n" not in text:
    anchor = "  - tests/test_semantic_contract_schema.py\n"
    assert anchor in text
    text = text.replace(anchor, anchor + "  - tests/test_instance_semantics.py\n", 1)
paragraph = "当前标准来源核验限定 Linux/glibc LP64 的 malloc/calloc/realloc/free：声明须绑定物理 `/usr/include/stdlib.h`，并具有当前精确构建实际读入的 stdlib/features 摘要、native include 解析、target/search 与工具身份；标准安装文件及父目录必须属于 root 且非 group/world 可写。名称、USR、ABI、system-header 位和未命中用户路径均不能单独授予权限。自定义 sysroot、其他安装布局/ABI、未知来源参数及缺失收据保持拒绝；只读核验不执行保存的命令。这是有界标准根来源契约，不代表完整实例扫描或真实项目效果已验收。\n"
anchor = "该策略不表示全项目建模或全部语义域已经覆盖。\n"
assert text.count(anchor) == 1
text = text.replace(anchor, anchor + "\n" + paragraph, 1)
(STAGE / doc).write_text(text, encoding="utf-8", newline="\n")
after = snapshot()
changed = sorted(path for path in before.keys() | after.keys() if before.get(path) != after.get(path))
assert set(changed) == set(incoming) | {doc} and len(after) == 969
assert all(after[path] == digest for path, digest in before.items() if path != doc)
assert all(sha(ROOT / path) == digest for path, digest in root_inputs.items())
changed_python = sorted(path for path, digest in after.items() if path.endswith(".py") and root_inputs.get(path) != digest)
receipt = dict(integrated_at=at, actual_task="/root", actual_producer_task=freeze["actual_task"], independent_module_acceptance=True, acceptance=(OUT / "module-acceptance.json").relative_to(ROOT).as_posix(), source_review=review_path.relative_to(ROOT).as_posix(), copied_source_sha256=incoming, changed_paths=changed, stage_changed_python_since_root=changed_python, stage_source_before=before, stage_source_after=after, configuration_baseline=configs, configurations_unchanged=True, old_stage_other_inputs_unchanged=True, root_bound_inputs_unchanged=True, producer_frozen_source_artifacts_unchanged=True, stage_intake=True, full_stage_quality_passed=False, selected_stage_joint_checks_passed=False, root_intake=False, root_joint_verification=False, whole_packages_complete=False)
write(OUT / "receipt.json", receipt)
ledger = read(HERE / "tasks.json")
row = next(row for row in ledger["tasks"] if row["id"] == "S01-INSTANCE-SEMANTICS-MIN-R23")
assert row["consecutive_failed_actual_deliveries"] == 3 and len(row["glm_delivery_rounds"]) == 3
row.update(status="fourth_native_delivery_independently_accepted_bounded_module_intaken_stage_r32_full_stage_validation_pending", artifact_available=True, independent_acceptance=True, prior_failed_actual_deliveries_before_acceptance=3, consecutive_failed_actual_deliveries=0, fourth_actual_development_delivery_complete=True, fourth_independent_acceptance=True, independent_execution_receipt=execution_path.relative_to(ROOT).as_posix(), independent_source_review=review_path.relative_to(ROOT).as_posix(), coordinator_stage_intake=True, coordinator_stage_intake_receipt=(OUT / "receipt.json").relative_to(ROOT).as_posix(), integrated=False, joint_verification=False, checked_at=at)
row.update(producer_status="completed_frozen_independently_accepted_bounded_module", producer_status_source="frozen_delivery_plus_independent_execution_and_source_review", worker_finished_at=freeze["frozen_at"])
row["sol_delivery_rounds"] = [dict(round=4, actual_task=freeze["actual_task"], source_sha256=incoming, independent_execution_finished_at=execution["finished_at"], independent_acceptance=True, evidence=(OUT / "module-acceptance.json").relative_to(ROOT).as_posix(), counted_development_failure=False)]
coordinator = next(item for item in ledger["tasks"] if item["id"] == "COORD-INSTANCE-INTEGRATION-R24")
coordinator.update(status="s01_exact_module_intaken_stage_r32_current_joint_and_full_quality_pending", bounded_current_stage_revalidation_complete=False, bounded_stage_regression_passed=False, current_stage_revalidation_required_after_intake=True, full_stage_quality_passed=False, full_stage_mypy_accepted=False, new_s01_intake=(OUT / "receipt.json").relative_to(ROOT).as_posix(), checked_at=at)
for item in ledger["tasks"]:
    if item["id"] in {"ASTRA-INSTANCE-CONSUMERS-R25", "CONSUMER-EXACT-REPAIR-R29"}:
        item["current_stage_joint_revalidation_pending"] = True
ledger.update(updated_at=at, latest_handoff=(OUT / "receipt.json").relative_to(ROOT).as_posix(), current_root_status="RootR23 unchanged; S01 fourth bounded module independently209+R24four accepted/source reviewpassed, exact2files+module doc intakenStage; current fullStage mypy/native context/recovery/joint pending; prior3failure records retained")
for entry in ledger["next_module_tasks"]:
    item = next(item for item in ledger["tasks"] if item["id"] == entry["id"])
    entry.update({key: item.get(key) for key in entry})
write(HERE / "tasks.json", ledger)
continuation = read(HERE / "continuation-r6.json")
continuation.update(updated_at=at, active_phase=ledger["current_root_status"], latest_handoff=ledger["latest_handoff"], next_module_tasks=ledger["next_module_tasks"], whole_packages_complete=False)
write(HERE / "continuation-r6.json", continuation)
print(json.dumps(dict(integrated_at=at, receipt=(OUT / "receipt.json").relative_to(ROOT).as_posix(), bounded_module_accepted=True, stage_files_copied=2, root_intake=False)))
