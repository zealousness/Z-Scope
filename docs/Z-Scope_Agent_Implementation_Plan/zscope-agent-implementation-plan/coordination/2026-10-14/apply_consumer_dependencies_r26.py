"""Controlled shared-test copy during Astra's acknowledged safe window."""
from pathlib import Path
import datetime as dt
import hashlib
import json
import sys

if sys.platform != "linux" or sys.flags.optimize:
    raise RuntimeError("Use non-optimized Linux Python")
HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
WORKER = ROOT / ".coordination/20261014/workspaces/astra-instance-consumers-r25"
PROPOSALS = ROOT / "artifacts/consumer-shared-fixtures-r26-20261016"
OUT = ROOT / "artifacts/consumer-readonly-dependency-intake-r26-20261016"

def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def read(path):
    return json.loads(path.read_text(encoding="utf-8"))

def write(path, value):
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")

review_path = ROOT / "artifacts/consumer-fixture-source-review-r26-20261016/review.json"
assert sha(review_path) == "d73bc8d1e4c73ad2de8b21e48fa4de9a48a8ec66f00e02b670f50c67f819f320"
review = read(review_path)
assert review["source_review_passed"] and not review["blocking_findings"]
assert all(sha(ROOT / path) == digest for path, digest in review["source_hashes_after"].items())
proposal = read(PROPOSALS / "review.json")
baseline_path = HERE / "followups-r12/astra-instance-consumers-r25-baseline.json"
baseline = read(baseline_path)
extension01_path = HERE / "followups-r12/astra-instance-consumers-r25-ownership-extension-01.json"
extension01 = read(extension01_path)
original = {entry["path"]: entry["sha256"] for entry in baseline["files"]}
assert len(original) == 1070
ledger_bytes = (HERE / "tasks.json").read_bytes()
ledger = json.loads(ledger_bytes.decode("utf-8"))
row = next(row for row in ledger["tasks"] if row["id"] == "ASTRA-INSTANCE-CONSUMERS-R25")
assert row["actual_task"] == "/root/astra_design_contract_r23" and not row["artifact_available"]
owned = set(row["write_paths"]) | set(extension01["write_paths"])
assert len(owned) == 10
assert all(sha(WORKER / path) == digest for path, digest in original.items() if path not in owned)
owned_before = {path: sha(WORKER / path) for path in owned}
root_sources = read(ROOT / "artifacts/coordinator-r23-ui-projection-union-20261016/source-evidence.json")["after"]
assert all(sha(ROOT / path) == digest for path, digest in root_sources.items())
changes = {path: details["after_sha256"] for path, details in proposal["migrations"].items()}
assert len(changes) == 3 and not set(changes) & owned
for path in changes:
    assert original[path] == proposal["migrations"][path]["before_sha256"] == sha(WORKER / path)
    assert sha(PROPOSALS / path) == changes[path]
extension02_path = HERE / "followups-r12/astra-instance-consumers-r25-ownership-extension-02.json"
effective_path = HERE / "followups-r12/astra-instance-consumers-r25-readonly-dependencies-r26.json"
assert not extension02_path.exists() and not effective_path.exists()
references = {str(path): sha(path) for path in [Path(__file__), review_path, PROPOSALS / "review.json", baseline_path, extension01_path, *[PROPOSALS / path for path in changes]]}
at = dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat()
OUT.mkdir(exist_ok=False)
for path in changes:
    backup = OUT / "readonly-before" / path
    backup.parent.mkdir(parents=True, exist_ok=True)
    backup.write_bytes((WORKER / path).read_bytes())
    (WORKER / path).write_bytes((PROPOSALS / path).read_bytes())
new_owned = "zscope/core/candidates/cpp_domains/shared_access.py"
assert new_owned in original and new_owned not in owned
write(extension02_path, dict(coordinator_authorized=True, actual_task=row["actual_task"], logical_task=row["id"], write_paths=[new_owned], previous_sha256=original[new_owned], reason="Concrete exact-mode literal atomic suppression bypass in SharedAccessIndex.match; same Astra task exclusively owns this one additional seam and adds actual emit positive/negative tests. Default behavior and trusted native atomic facts remain; strings do not mint authority."))
owned.add(new_owned)
effective = dict(original)
effective.update(changes)
readonly = {path: digest for path, digest in effective.items() if path not in owned}
assert len(effective) == 1070 and len(readonly) == 1060
assert all(sha(WORKER / path) == digest for path, digest in readonly.items())
assert all(sha(WORKER / path) == digest for path, digest in owned_before.items())
assert all(sha(ROOT / path) == digest for path, digest in root_sources.items())
assert all(sha(Path(path)) == digest for path, digest in references.items())
assert (HERE / "tasks.json").read_bytes() == ledger_bytes, "Concurrent ledger write; do not overwrite it"
write(effective_path, dict(coordinator_owned=True, actual_task=row["actual_task"], logical_task=row["id"], recorded_at=at, root_intake=False, stage_intake=False, source_review=review_path.relative_to(ROOT).as_posix(), source_review_sha256=sha(review_path), original_baseline=baseline_path.relative_to(ROOT).as_posix(), original_baseline_sha256=sha(baseline_path), ownership_extension02=extension02_path.relative_to(ROOT).as_posix(), readonly_replacements=changes, owned_paths=sorted(owned), readonly_count=1060, files=[dict(path=path, sha256=digest) for path, digest in sorted(effective.items())], application_precondition="lock fixture revision10 is only for the matching consumer catalog; not applied to current Stage catalog9 or Root", safe_window_evidence="Same actual Astra agent explicitly paused all tests and ten owned edits at15:06:38+08; coordinator announced copy complete before resumption."))
row.update(write_paths=sorted(owned), owns=sorted(owned), readonly_inputs=1060, ownership_extension02=extension02_path.relative_to(HERE).as_posix(), effective_readonly_dependencies=effective_path.relative_to(HERE).as_posix(), effective_readonly_dependencies_sha256=sha(effective_path), checked_at=at)
ledger["updated_at"] = at
write(HERE / "tasks.json", ledger)
proof = dict(recorded_at=at, actual_task=row["actual_task"], actual_coordinator="/root", logical_task=row["id"], workspace=WORKER.relative_to(ROOT).as_posix(), readonly_replacements=changes, owned_files_unchanged=owned_before, effective_readonly_manifest=effective_path.relative_to(ROOT).as_posix(), effective_readonly_manifest_sha256=sha(effective_path), readonly_count=1060, original_manifest_retained=True, ownership_extension02=extension02_path.relative_to(ROOT).as_posix(), source_review=review_path.relative_to(ROOT).as_posix(), source_review_sha256=sha(review_path), references_sha256=references, root_bound_inputs_unchanged=len(root_sources), root_product_writes=0, stage_files_written=0, tests_executed=0, independent_functional_acceptance=False, integrated=False, root_joint_verification=False)
write(OUT / "receipt.json", proof)
(OUT / "launcher.py").write_bytes(Path(__file__).read_bytes())
print(json.dumps(dict(at=at, receipt=(OUT / "receipt.json").relative_to(ROOT).as_posix(), readonly_count=1060, owned_count=len(owned), copied_shared_tests=3, root_product_writes=0, stage_files_written=0)))
