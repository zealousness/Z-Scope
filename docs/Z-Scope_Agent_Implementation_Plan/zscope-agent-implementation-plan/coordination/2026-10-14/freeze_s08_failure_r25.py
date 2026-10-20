"""Reconcile exact probe namespaces and freeze the second S08 delivery."""
from collections import Counter
from pathlib import Path
import datetime as dt
import hashlib
import json
import shutil
import xml.etree.ElementTree as ET

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
BRANCH = ROOT / ".coordination/20261014/workspaces/s08-instance-recovery-min-r23"

def read(path):
    return json.loads(path.read_text(encoding="utf-8"))

def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def write(path, value):
    with path.open("x", encoding="utf-8", newline="\n") as stream:
        stream.write(json.dumps(value, ensure_ascii=False, indent=2) + "\n")

def cases(path):
    return Counter((case.get("classname"), case.get("name")) for case in ET.parse(path).getroot().iter("testcase"))

root_sources = read(ROOT / "artifacts/coordinator-r23-ui-projection-union-20261016/source-evidence.json")["after"]
assert all(sha(ROOT / path) == digest for path, digest in root_sources.items())
dependency_path = ROOT / "artifacts/coordinator-s08-module-dependency-r25-20261016/review.json"
dependency = read(dependency_path)
probe = read(ROOT / "artifacts/coordinator-s08-consumer-r25-20261016/review.json")
assert dependency["actual_producer_task_id"] == "task_8886dcf232"
assert dependency["junit"] == dict(tests=307, failures=0, errors=0, skipped=0)
assert all(command["returncode"] == 0 for command in dependency["commands"])
assert dependency["source_unchanged"] and dependency["root_unchanged"] and dependency["references_unchanged"]
assert probe["junit"] == dict(tests=2, failures=2, errors=0, skipped=0) and probe["sources_unchanged"] and probe["root_unchanged"]
assert all(sha(BRANCH / path) == digest for path, digest in dependency["source_after"].items())
assert all(sha(ROOT / path) == digest for path, digest in dependency["trusted_root_references"].items())
current = cases(dependency_path.parent / "results.xml")
aliases = {}
base = ROOT / "artifacts/s08-multipath-probe-r24-20261016"
for name, result_name in (("test_s08_multipath_probe", "results.xml"), ("test_s08_boundary_probe", "boundary-results.xml"), ("test_s08_schema_probe", "schema-results.xml")):
    for (classname, case_name), count in cases(base / result_name).items():
        assert classname == "" and count == 1
        aliases[("artifacts.s08-multipath-probe-r24-20261016." + name, case_name)] = ("", case_name)
assert len(aliases) == 7 and len(set(aliases.values())) == 7
producer_xmls = [BRANCH / path for path in dependency["source_after"] if path.endswith(".xml")]
assert producer_xmls
reconciled = []
observed_aliases = set()
for path in producer_xmls:
    original = cases(path)
    canonical = Counter()
    for identity, count in original.items():
        if identity in aliases:
            observed_aliases.add(identity)
            canonical[aliases[identity]] += count
            assert count == 1
        else:
            canonical[identity] += count
    assert canonical <= current, (str(path), canonical - current)
    reconciled.append(dict(path=path.relative_to(BRANCH).as_posix(), sha256=sha(path), original_tests=sum(original.values()), canonical_tests=sum(canonical.values()), all_case_multiplicities_preserved=True))
assert observed_aliases == set(aliases)
ledger = read(HERE / "tasks.json")
row = next(row for row in ledger["tasks"] if row["id"] == "S08-INSTANCE-RECOVERY-MIN-R23")
assert row["bridge_task_id"] == "task_8886dcf232" and row["producer_status"] == "completed"
assert row["consecutive_failed_actual_deliveries"] == 1 and len(row["glm_delivery_rounds"]) == 1
target = ROOT / "artifacts/s08-consumer-probe-r25-20261016/failed-candidate"
target.mkdir(exist_ok=False)
for path in row["write_paths"] + ["DELIVERY.md"]:
    (target / path).parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(BRANCH / path, target / path)
shutil.copytree(BRANCH / "artifacts/instance-recovery-r23", target / "artifacts/instance-recovery-r23")
frozen = {path.relative_to(target).as_posix(): sha(path) for path in target.rglob("*") if path.is_file()}
at = dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat()
identity_reconciliation = dict(at=at, original_dependency_review_sha256=sha(dependency_path), original_overall_false_preserved=True, reason="Only seven explicitly source-bound outside-workspace probes have rootdir-derived JUnit namespace aliases. Every test name and multiplicity remains exact; primary tests are not normalized.", aliases=[dict(producer_classname=key[0], name=key[1], coordinator_classname=value[0]) for key, value in sorted(aliases.items())], producer_junits=reconciled, all_commands_exit_zero=True, junit=dependency["junit"], command_and_identity_reconciliation_passed=True, worker_development_failure_from_namespace_mismatch=False, tests_rerun=0)
write(dependency_path.parent / "identity-reconciliation.json", identity_reconciliation)
round_two = dict(round=2, task_id="task_8886dcf232", producer_finished_at=row["worker_finished_at"], independent_result="307/0/0/0, four commands0; seven exact outside-workspace JUnit namespace aliases reconciled without rerunning or changing tests. Two additional valid cases failed: live shared-cluster contexts rejected and prepared boundary outcome not verifiable.", evidence="artifacts/coordinator-s08-consumer-r25-20261016/review.json", dependency_evidence=dependency_path.relative_to(ROOT).as_posix(), identity_reconciliation="artifacts/coordinator-s08-module-dependency-r25-20261016/identity-reconciliation.json", counted_development_failure=True, original_obligation="Lossless legal live-Ledger records and successfully prepared result roundtrip", coordinator_namespace_mismatch_excluded=True)
row["glm_delivery_rounds"].append(round_two)
row.update(consecutive_failed_actual_deliveries=2, status="second_actual_delivery_failed_live_cluster_and_publication_roundtrip", independent_acceptance=False, integrated=False, joint_verification=False, checked_at=at, module_dependency_review=round_two["dependency_evidence"], independent_roundtrip_failure_evidence=round_two["evidence"], frozen_failed_candidate_r25=target.relative_to(ROOT).as_posix())
ledger["updated_at"] = at
(HERE / "tasks.json").write_text(json.dumps(ledger, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
proof = dict(recorded_at=at, task_id="task_8886dcf232", logical_task=row["id"], source_after=dependency["source_after"], frozen_files=frozen, frozen_candidate=target.relative_to(ROOT).as_posix(), round=round_two, root_bound_inputs_unchanged=len(root_sources), independent_acceptance=False, integrated=False, joint_verification=False)
write(ROOT / "artifacts/s08-consumer-probe-r25-20261016/failure-review.json", proof)
assert all(sha(ROOT / path) == digest for path, digest in root_sources.items())
print(json.dumps(dict(at=at, task_id=row["bridge_task_id"], consecutive_failed_actual_deliveries=2, frozen_candidate=proof["frozen_candidate"], frozen_files=len(frozen), root_bound_inputs_unchanged=len(root_sources), exact_junit_namespace_aliases=7)))
