"""Freeze the rejected consumer delivery, prepare a distinct owned repair copy."""
from pathlib import Path
import datetime as dt
import hashlib
import json
import shutil
import sys

assert sys.platform == "linux" and not sys.flags.optimize
HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
ORIGINAL = ROOT / ".coordination/20261014/workspaces/astra-instance-consumers-r25"
ART = ORIGINAL / "artifacts/instance-consumers-r25"
NEW = ROOT / ".coordination/20261014/workspaces/consumer-exact-repair-r29"
OUT = ROOT / "artifacts/astra-consumer-failure-freeze-r28-20261017"


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def read(path):
    return json.loads(path.read_text(encoding="utf-8"))


def write(path, value):
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")


producer = read(ART / "review.json")
assert sha(ART / "review.json") == "5101d36e10090514e2b4dabb41536e8e555f4075701a0c9a0853fbf9ec544352"
effective = read(HERE / "followups-r12/astra-instance-consumers-r25-readonly-dependencies-r26.json")
inputs = {row["path"]: row["sha256"] for row in effective["files"]}
inputs.update(producer["source_after"])
assert len(inputs) == 1071 and all(sha(ORIGINAL / path) == digest for path, digest in inputs.items())
root_inputs = read(ROOT / "artifacts/coordinator-r23-ui-projection-union-20261016/source-evidence.json")["after"]
assert len(root_inputs) == 1065 and all(sha(ROOT / path) == digest for path, digest in root_inputs.items())
assert all(sha(ART / path) == digest for path, digest in producer["artifact_sha256"].items())
review_path = ROOT / "artifacts/astra-consumers-source-review-r28-20261017/review.json"
assert sha(review_path) == "e9fd688a9d712359d295c7f2e13fabd8dfa1b7917e72d9b1050b8a796bfaebbf"
source_review = read(review_path)
assert not source_review["source_review_passed"] and len(source_review["findings"]) == 2
execution = read(ROOT / "artifacts/coordinator-astra-consumers-r28-20261017/review.json")
probes = read(ROOT / "artifacts/coordinator-consumer-boundary-probes-r28-20261017/review.json")
assert execution["candidate_independent_execution_checks_passed"]
assert execution["junit"] == dict(tests=852, failures=0, errors=0, skipped=0)
assert probes["junit"] == dict(tests=3, failures=3, errors=0, skipped=0)
assert probes["sources_unchanged"] and probes["root_unchanged"] and probes["references_unchanged"]

OUT.mkdir(exist_ok=False)
NEW.mkdir(exist_ok=False)
copied = {}


def copy_file(source, destination):
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, destination)
    assert sha(destination) == sha(source)
    return sha(destination)


for path in producer["source_after"]:
    copied["failed-candidate/" + path] = copy_file(ORIGINAL / path, OUT / "failed-candidate" / path)
copied["producer/DELIVERY.md"] = copy_file(ORIGINAL / "DELIVERY.md", OUT / "producer/DELIVERY.md")
for path in sorted(set(producer["artifact_sha256"]) | {"review.json"}):
    copied["producer/artifacts/" + path] = copy_file(ART / path, OUT / "producer/artifacts" / path)
for name in (
    "astra-consumers-source-review-r28-20261017",
    "coordinator-astra-consumers-r28-20261017",
    "astra-consumer-boundary-probes-r28-20261017",
    "coordinator-consumer-boundary-probes-r28-20261017",
):
    for path in (ROOT / "artifacts" / name).rglob("*"):
        if path.is_file() and "__pycache__" not in path.parts and path.suffix != ".pyc":
            relative = path.relative_to(ROOT / "artifacts")
            copied["independent/" + relative.as_posix()] = copy_file(path, OUT / "independent" / relative)
for path, digest in inputs.items():
    assert copy_file(ORIGINAL / path, NEW / path) == digest
owned = [
    "zscope/core/candidates/cpp_domains/typed_resources.py",
    "zscope/core/candidates/cpp_domains/protocol_ownership_logic.py",
    "tests/test_instance_builtin_consumers.py",
]
at = dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat()
failure = dict(
    schema="zscope.consumer-delivery-failure.v1", recorded_at=at,
    logical_task="ASTRA-INSTANCE-CONSUMERS-R25", actual_producer_task="/root/astra_design_contract_r23",
    producer_app_thread="01a1427c-30d0-7e72-b837-a2c399ecb982", bridge_task_id=None,
    actual_failed_delivery_ordinal=1, consecutive_failed_actual_deliveries=1,
    rule="One actual frozen delivery rejected; three failing parametrized probes are not three development rounds.",
    independent_existing_suite=execution["junit"], independent_external_probes=probes["junit"],
    source_findings=source_review["findings"], candidate_accepted=False, stage_intake=False,
    root_intake=False, root_joint_pass=False, frozen_files=copied,
    original_input_manifest=inputs, original_remains_frozen=True,
    s01_consecutive_failures_unchanged=3, s01_fourth_dispatched=False,
    platform_restrictions_bypassed=False, bridge_or_service_actions=0,
)
write(OUT / "review.json", failure)
manifest = dict(
    schema="zscope.isolated-consumer-repair.v1", prepared_at=at,
    logical_task="CONSUMER-EXACT-REPAIR-R29", parent_logical_task="ASTRA-INSTANCE-CONSUMERS-R25",
    actual_task=None, status="prepared_not_dispatched", requested_model="gpt-6.1-sol",
    requested_reasoning_effort="xhigh", workspace=NEW.relative_to(ROOT).as_posix(),
    source_baseline=inputs, owned_paths=owned,
    readonly_paths={path: digest for path, digest in inputs.items() if path not in owned},
    frozen_failure_receipt=(OUT / "review.json").relative_to(ROOT).as_posix(),
    frozen_failure_sha256=sha(OUT / "review.json"),
    immutable_probe="artifacts/astra-consumer-boundary-probes-r28-20261017/test_consumer_boundaries.py",
    immutable_probe_sha256=sha(ROOT / "artifacts/astra-consumer-boundary-probes-r28-20261017/test_consumer_boundaries.py"),
    original_workspace_readonly=True, root_and_stage_readonly=True,
    tests_require_linux_single_outer_slot_default_fd_ext4=True,
    preserve_all_852_case_identities=True, zero_skips_required=True,
    no_bridge_calls=True, no_process_queries=True, no_services=True,
    no_credentials_or_provider_changes=True, no_archived_s06_operations=True,
    domain="Non-UI exact consumer boundary repair; existing Astra UI ownership is unchanged.",
    integrated=False, root_joint_verification=False,
)
manifest_path = HERE / "followups-r12/consumer-exact-repair-r29-ownership.json"
assert not manifest_path.exists()
write(manifest_path, manifest)
assert all(sha(ORIGINAL / path) == digest for path, digest in inputs.items())
assert all(sha(ROOT / path) == digest for path, digest in root_inputs.items())
print(json.dumps(dict(prepared_at=at, failure_receipt=(OUT / "review.json").relative_to(ROOT).as_posix(), copied_failure_files=len(copied), workspace=str(NEW), source_files=len(inputs), owned_files=len(owned), readonly_files=len(manifest["readonly_paths"]), ownership_manifest=manifest_path.relative_to(ROOT).as_posix())))
