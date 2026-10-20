"""DRAFT ONLY. Root must review/install; every execution needs a real ready SHA.

Host/snapshot patterns are copied (not imported) from Store 932c5c2b and
joint draft53ab2171. No JSON argv or saved native commands are executed.
"""
from __future__ import annotations

from collections import Counter
import datetime as dt
import fcntl
import hashlib
import importlib
import json
import os
from pathlib import Path
import pwd
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET

ROOT = Path("/mnt/c/Users/10273/home/work/Z-Scope_1.31/Z-Scope")
D = ROOT / "docs/Z-Scope_Agent_Implementation_Plan/zscope-agent-implementation-plan/coordination/2026-10-14"
WORK = ROOT / ".coordination/20261014/workspaces/coordinator-native-job-independent-r35"
STAGE = ROOT / ".coordination/20261014/workspaces/coordinator-instance-integration-r24"
BASE = ROOT / "artifacts/coordinator-native-job-independent-r35-20261017"
READY = BASE / "final-ready.json"
OUT = BASE / "independent"
INSTALLED = D / "verify_native_job_independent_r35.py"
PYTHON = "/home/zeal/venv313/bin/python"
OLD_TOOL = Path("/home/zeal/.cache/zscope-build-context/install/bin/zscope-clang-indexer")
NEW_TOOL = Path("/home/zeal/.cache/zscope-job-runtime-footprint-r34/install/bin/zscope-clang-indexer")
OLD_SHA = "d39cbe72fafad1fbfa989a51346cdf4785101e32855c0ee0d11a1e2748263399"
NEW_SHA = "f4e2ff8aef71027447afe497b4c8872a4b2bc2f596166ff543492a623fdda860"
ORIGINAL = "tests/test_job_runtime_footprint_r34.py"
PREWRITE = "tests/test_job_runtime_prewrite_r35.py"
THIRD = "tests/test_job_indexed_input_prewrite_r35.py"
STORE_TEST = "tests/test_store_active_transactions_r35.py"
TRACE_TEST = "tests/test_trace_callback_generation_probe_r35.py"
LEGAL_FIXTURES = ("test_job_runtime_footprint_r34", "test_job_runtime_prewrite_r35",
                  "test_scan_session_instances", "test_scan_session_jobs")
ORIGINAL_SHA = "ac34d7a64e0998e052780fc1f23283875781fc784d2c1141b52e3b827cc09b57"
PREWRITE_SHA = "74cd68ba5a5c45afa25c2c3d48695c2c3f56b7252664ffc51f9060304f45c054"
JOB_ID = ("tests.test_scan_session_jobs", "test_job_scan_runs_exact_instances_on_the_queue")
DOCS = {"docs/modules/execution-orchestration.md", "docs/modules/configuration-state.md",
        "docs/modules/retrieval-backends.md"}
CONFIG_NAMES = {"conftest.py", "pytest.ini", ".pytest.ini", "mypy.ini", ".mypy.ini",
                "tox.ini", "setup.cfg", "pyproject.toml"}
SKIP_DIRS = {"__pycache__", ".pytest_cache", ".mypy_cache"}
SDK_ALIAS = Path("/usr/include/clang/18.1.3/include")
SDK_PHYSICAL = Path("/usr/lib/llvm-18/lib/clang/18/include")
S01_EXTERNAL = [
    "artifacts/s01-authority-probe-r25-20261016/test_s01_authority_probe.py",
    "artifacts/s01-origin-probe-r25-20261016/test_s01_origin_probe.py",
    "artifacts/s01-origin-forms-probe-r26-20261016/test_s01_origin_forms_probe.py",
]
AUTHORITY = "artifacts/s01-authority-probe-r24-20261016/test_s01_authority_probe.py"
GROUPS = {
    "original53": [ORIGINAL, "tests/test_scan_session_jobs.py::" + JOB_ID[1]],
    "prewrite7": [PREWRITE],
    "third2": [THIRD],
    "s01_209": ["tests/test_instance_semantics.py", "tests/test_contract_usr_scope.py",
                "tests/test_instance_analysis.py", "tests/test_candidate_build_identity.py",
                "tests/test_build_context.py", "tests/test_native_model_cache.py",
                "tests/test_agent_docs.py", "tests/test_semantics_defaults.py",
                "tests/test_validation_build_scope.py", "tests/test_semantics_shadow_overlay.py",
                *S01_EXTERNAL],
    "core150": ["tests/test_instance_currentness_revocation_r33.py",
                "tests/test_instance_recovery_cost_r33.py", "tests/test_review_current_revisions_r33.py",
                "tests/test_native_classifier_currentness_r33.py", "tests/test_session_preentry_cost_r33.py"],
    "checkpoint10": ["tests/test_scan_checkpoint_resume.py"],
    "native_related": ["tests/test_clang_incremental_extraction.py", "tests/test_native_model_cache.py",
                       "tests/test_native_replay_hot_cache.py", "tests/test_protocol_incremental_equivalence.py",
                       "tests/test_build_context.py", "tests/test_candidate_build_identity.py",
                       "tests/test_link_targets.py", "tests/test_linked_lifecycle_paths.py",
                       "tests/test_native_wrapper_inference.py", "tests/test_resource_inference_coverage.py"],
    "authority4": [AUTHORITY],
    "llvm1": ["tests/test_indexing_pipeline.py::test_real_direct_bitcode_dependency_cache_and_svf"],
    # The actual immutable external path/test SHA/Counter must come from Root's
    # concrete reviewed record. No filename or future execution is guessed.
    "legal_backup1": [],
}
HISTORICAL = {
    "s01_209": ("artifacts/coordinator-s01-repair-r31-r32-independent-20261017/results.xml",
                "3da922d16a544fb78aaeebaaaf6786a073a02b673a2e18c9e13bdf9aca8c8026", 209),
    "core150": ("artifacts/coordinator-shared-style-r34-20261017/independent/results.xml",
                "1a2a9a4180966c8cd5fa971daa2f5880f939e47c7ef17944ea181f4fbe2c03cc", 150),
    "checkpoint10": ("artifacts/coordinator-checkpoint-contract-r34-20261017/independent/results.xml",
                     "a07db060978ac83d3c09d0080a64a086f8becc85bdcffb5d3af36f0ee34d2539", 10),
    "authority4": ("artifacts/coordinator-s01-repair-r31-r32-independent-20261017/authority-r24.xml",
                   "1ac994956078f4051f35ea08d5073d738996c17ef89023dc5070c0dd0d2d3aa3", 4),
    "llvm1": ("artifacts/coordinator-real-llvm-case-r34-20261017/results.xml",
              "dccac73f5b3734214b8908003d8f55baf3bc867c3fd1558911e6ac96842a9d0a", 1),
}
FLOOR = "artifacts/stage-checkpoint-contract-intake-r34-20261017/receipt.json"
FLOOR_SHA = "b9d8cc7874d3f224f514ec43feebad99f75eb659a9aa194ec068545dc605a69f"
PINS = {
    FLOOR: FLOOR_SHA,
    "docs/Z-Scope_Agent_Implementation_Plan/zscope-agent-implementation-plan/coordination/2026-10-14/test_slot.py":
        "7fd4e683bb9e7523a3247eb5efd21ff5a130ebc83375933f32290f4007f9c158",
    "docs/Z-Scope_Agent_Implementation_Plan/zscope-agent-implementation-plan/coordination/2026-10-14/verify_store_independent_r35.py":
        "932c5c2b296b8f9e4f376adba3090d54cc9f89de7199e4a98160e9fd74955540",
    "artifacts/stage-joint-launcher-rev5-draft-r35-20261017/revision-2/verify_stage_joint_r35_rev5_v2.py":
        "53ab21715d5aac586344338360ff40892cf55a13dd1763551691651a229364db",
    "artifacts/coordinator-job-valid-red-audit-r35-20261017/review.json":
        "b261c371e692f6f6492df85ea1862d0a4d086f3388c57196089e69c5b7b4da3f",
    ".coordination/20261014/workspaces/job-runtime-footprint-repair-r34/artifacts/job_runtime_footprint_r34/runner-v7/red-lookup-v8/receipt.json":
        "e502fb5cc94337f26c8a3689ad84714906b8030234591e1802f877ad624ea30b",
    ".coordination/20261014/workspaces/job-runtime-footprint-repair-r34/artifacts/job_runtime_footprint_r34/runner-v7/red-lookup-v8/results.xml":
        "f94451dede6f3dc92e44e4ac1f6d3533a803a712132347776822cf42c19af92b",
    ".coordination/20261014/workspaces/job-runtime-footprint-repair-r34/artifacts/job_runtime_footprint_r34/native-build-v4/receipt.json":
        "28a43d030a44b220927f3c9dd484aaa0c47cf3d18c3471da655804f9fef0e948",
    "artifacts/coordinator-native-independent-launcher-draft-r35-20261017/receipt.json":
        "342642026c6be0679737b4b20cb14f8ac25218e4c85189871f0bc783c85348f1",
    "artifacts/coordinator-native-independent-launcher-source-review-r35-20261017/review.json":
        "376b52cf0b032d9192466c40194c394de0f219da54c004e099dbc705cec1e7f7",
    "artifacts/job-indexed-input-probe-r35-20261017/execution-tooling/revision-2/run_probe.py":
        "712e95ab334ad740f6d66b3d2ca4d0e54258847f3198ecbb58f1b236c3488562",
    "artifacts/coordinator-native-independent-launcher-draft-r35-20261017/revision-2/receipt.json":
        "9e750a223bbb2a6029647213d2f8527bd16e82cb9948a8d528114424205b1a85",
    "artifacts/coordinator-native-independent-launcher-source-review-r35-20261017/revision-2/review.json":
        "35bed3e96aafac97fbfaacf4c6055ce5813a4439f0904f1bcfefd71ffa6f0c00",
}
ENV_KEYS = ("PATH", "LD_LIBRARY_PATH", "LLVM_COMPILER", "LLVM_COMPILER_PATH", "CC", "CXX")
ACTUAL_TASK = "/root"


class Pending(RuntimeError):
    pass


def require(value, message):
    if not value:
        raise RuntimeError(message)


def now():
    return dt.datetime.now(dt.timezone.utc).isoformat()


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def read(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def write(path, value):
    Path(path).write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n",
                          encoding="utf-8", newline="\n")


def digest(value):
    require(isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value), "missing SHA")
    return value


def safe_relative(value):
    path = Path(value)
    require(isinstance(value, str) and value == path.as_posix() and not path.is_absolute()
            and ".." not in path.parts and "." not in path.parts, "unsafe relative path")
    return path


def merge_refs(target, extra):
    require(isinstance(extra, dict), "reference map missing")
    for name, expected in extra.items():
        path = Path(name)
        require(path.is_absolute() and ".." not in path.parts and path.is_relative_to(ROOT)
                and path.is_file(), "reference must be a preserved Root file: " + name)
        digest(expected)
        require(name not in target or target[name] == expected, "reference pin conflict: " + name)
        require(sha(path) == expected, "reference SHA drift: " + name)
        target[name] = expected


def bound(record, refs):
    require(isinstance(record, dict), "pending evidence record")
    path = Path(record["path"])
    merge_refs(refs, {str(path): digest(record["sha256"])})
    return path


def source_map(base):
    return {p.relative_to(base).as_posix(): sha(p) for p in base.rglob("*")
            if p.is_file() and p.suffix != ".pyc"
            and p.relative_to(base).parts[0] != "artifacts"
            and not any(part in SKIP_DIRS for part in p.relative_to(base).parts)}


def named_files(base, names):
    return {p.relative_to(base).as_posix(): sha(p) for p in base.rglob("*")
            if p.is_file() and p.name in names}


def mapped(base, values):
    require(isinstance(values, dict) and values, "empty source map")
    return {str(safe_relative(name)): sha(base / name) for name in values}


def case_rows(counter):
    return [list(key) + [count] for key, count in sorted(counter.items())]


def parse_rows(rows):
    require(isinstance(rows, list) and rows, "pending/empty Counter")
    result = Counter()
    for row in rows:
        require(isinstance(row, list) and len(row) == 3 and all(isinstance(v, str) for v in row[:2])
                and type(row[2]) is int and row[2] > 0 and tuple(row[:2]) not in result,
                "invalid/duplicate Counter row")
        result[tuple(row[:2])] = row[2]
    require(rows == case_rows(result), "Counter must retain sorted raw identities")
    return result


def xml_data(path):
    nodes = list(ET.parse(path).getroot().iter("testcase"))
    counter = Counter((n.get("classname", ""), n.get("name", "")) for n in nodes)
    counts = {"tests": len(nodes), "failures": sum(n.find("failure") is not None for n in nodes),
              "errors": sum(n.find("error") is not None for n in nodes),
              "skipped": sum(n.find("skipped") is not None for n in nodes)}
    return counter, counts


def green_xml(path):
    counter, counts = xml_data(path)
    require(counter and counts["failures"] == counts["errors"] == counts["skipped"] == 0,
            "actual XML not green: " + str(path))
    return counter


def prewrite_counter():
    names = {"test_prewrite_probe_native_job_positive_closes_queue[" + value + "]"
             for value in ("False", "True")}
    names |= {"test_batch_backup_link_to_actual_input_is_refused_before_copy[" + a + "-" + b + "]"
              for a in ("source", "header") for b in ("hardlink", "symlink")}
    names.add("test_revoked_real_tool_copy_is_refused_before_first_store_connection")
    return Counter(("tests.test_job_runtime_prewrite_r35", name) for name in names)


def third_counter():
    return Counter(("tests.test_job_indexed_input_prewrite_r35", name) for name in (
        "test_third_indexed_tu_normal_header_keeps_real_job_drained",
        "test_third_indexed_tu_runtime_header_is_refused_before_replace"))


def legal_backup_path(ready):
    value = ready["groups"]["legal_backup1"]["external_test"]
    path = Path(value["path"])
    owned = ROOT / ".coordination/20261014/workspaces/job-runtime-footprint-repair-r34/artifacts/job_runtime_footprint_r34"
    require(path.is_absolute() and ".." not in path.parts and path.is_relative_to(owned)
            and path.suffix == ".py" and path.name.startswith("test_")
            and path.resolve(strict=True) == path and path.is_file(),
            "real immutable Cost OWN external legal-backup test is pending")
    require(sha(path) == digest(value["sha256"]), "external legal-backup test drift")
    return path


def arguments(label, ready):
    return [str(legal_backup_path(ready))] if label == "legal_backup1" else GROUPS[label]


def selected(label, ready):
    paths, physical = [], set()
    for argument in arguments(label, ready):
        filename, separator, node = argument.partition("::")
        path = ROOT / filename if filename in S01_EXTERNAL + [AUTHORITY] else WORK / filename
        require(path.is_file() and path.resolve().is_relative_to(ROOT), "selected test missing")
        identity = (path.stat().st_dev, path.stat().st_ino)
        require(identity not in physical, "same-file aliases within one test group")
        physical.add(identity)
        paths.append(str(path) + (separator + node if separator else ""))
    return paths


def external_controls(ready):
    values = {}
    paths = [ROOT / filename for filename in S01_EXTERNAL + [AUTHORITY]] + [legal_backup_path(ready)]
    for path in paths:
        for parent in path.parents:
            for basename in CONFIG_NAMES:
                path = parent / basename
                if path.is_file():
                    values[str(path)] = sha(path)
    return values


def raw_sources(raw, side):
    value = raw.get("candidate_" + side, raw.get("source_" + side))
    require(isinstance(value, dict) and value and all(isinstance(v, str) for v in value.values()),
            "raw actual full-source map absent")
    return value


def valid_raw(raw, green, label="original53"):
    require(raw.get("test_started") is True and raw.get("evidence_guards_passed") is True,
            "actual test execution/guards absent")
    gates = raw.get("guards", raw.get("gates"))
    require(isinstance(gates, dict) and gates and all(v is True for v in gates.values()),
            "actual evidence guards failed")
    commands = raw.get("commands")
    require(isinstance(commands, list) and commands
            and all(row["returncode"] == (0 if green else 1) for row in commands),
            "actual command exit mismatch")
    if label == "third2":
        require(raw["phase"] == ("green" if green else "red")
                and raw["phase_completed_validly"] is True
                and raw["pytest_all_passed"] is green
                and raw["valid_causal_red"] is (not green),
                "actual third phase classification differs")
    else:
        require(raw["passed"] is green, "actual producer phase pass classification differs")
        if label == "legal_backup1":
            require(green is True and raw["phase"] == "green-legal"
                    and raw["fixed_test_sha256"] == PREWRITE_SHA,
                    "legal producer must be the actual green-legal execution; original seven SHA remains separate")


def raw_counter(label, raw):
    return raw["actual_counter"] if label == "third2" else raw["case_counter"]


def raw_test_sha(label, raw):
    if label == "third2":
        return raw["test_sha256"]
    if label == "legal_backup1":
        # The fixed producer921b reports the immutable seven-case test in
        # fixed_test_sha256, and the separately selected external file here.
        # Do not reinterpret or rewrite either recorded execution field.
        return raw["fixed_external_test_sha256"]
    return raw.get("fixed_test_sha256", raw.get("new_test_sha256"))


def producer_source(label, actual, final, ready):
    # Original53/7 are produced before the independent third test is added.
    # Every shared code/test byte remains exact; only three reviewed docs differ.
    allowed_sets = [set(final)] if label == "third2" else [set(final), set(final) - {THIRD}]
    require(set(actual) in allowed_sets and len(actual) in {1086, 1087}, "producer full source set differs")
    overrides = ready["coordinator_document_overrides"]
    require(set(overrides) == DOCS and all(final[name] == overrides[name] for name in DOCS),
            "all three actual reviewed final module docs are mandatory")
    require(all(actual[name] == final[name] for name in actual if name not in DOCS),
            "producer source differs beyond the third-test addition and three docs")


def green_imports(label, record, raw, values, refs, ready):
    raw_path = Path(record["producer_green_raw"]["path"])
    path = raw_path.parent / "imported-product-source.json"
    merge_refs(refs, {str(path): raw["artifact_sha256"]["imported-product-source.json"]})
    imported = read(path)
    producer = Path(record["producer_source_root"])
    expected_root = (ROOT / ".coordination/20261014/workspaces/coordinator-indexed-input-prewrite-r35"
                     if label == "third2" else ROOT / ".coordination/20261014/workspaces/job-runtime-footprint-repair-r34/artifacts/job_runtime_footprint_r34/candidate-src-v2")
    require(producer == expected_root and imported["valid"] is True and imported["modules"]
            and "zscope" in imported["modules"], "actual producer source root/import receipt missing")
    for name, item in imported["modules"].items():
        require(item["valid"] is True and (name == "zscope" or name.startswith("zscope.")), "invalid recorded producer import")
        if "path" in item:
            physical = Path(item["path"])
            require(physical.is_relative_to(producer)
                    and values.get(physical.relative_to(producer).as_posix()) == item["sha256"],
                    "actual recorded producer module SHA/path differs")
        else:
            directory = producer / name.replace(".", "/")
            require(item["namespace_paths"] and all(p == str(directory) for p in item["namespace_paths"])
                    and any(p.startswith(directory.relative_to(producer).as_posix() + "/") for p in values),
                    "actual recorded producer namespace differs")
    require(imported["modules"]["zscope"]["path"] == str(producer / "zscope/__init__.py"), "actual producer product root differs")
    if label == "legal_backup1":
        fixtures = imported["actual_fixture_sources"]
        required = set(LEGAL_FIXTURES) | {"test_job_runtime_legal_backup_r35"}
        require(set(fixtures) == required, "actual producer legal fixture set differs")
        for name in required:
            target = (legal_backup_path(ready) if name == "test_job_runtime_legal_backup_r35"
                      else producer / "tests" / (name + ".py"))
            expected_sha = (sha(target) if name == "test_job_runtime_legal_backup_r35"
                            else values["tests/" + name + ".py"])
            item = fixtures[name]
            require(item["valid"] is True and item["path"] == item["expected_path"] == str(target)
                    and item["sha256"] == expected_sha,
                    "actual producer legal fixture path/SHA differs: " + name)


def legal_backup_review(ready, refs):
    group = ready["groups"]["legal_backup1"]
    path = legal_backup_path(ready)
    merge_refs(refs, {str(path): group["external_test"]["sha256"]})
    review = read(bound(group["test_source_review"], refs))
    require(review["source_review_passed"] is True
            and review.get("actual_task", review.get("actual_reviewer_task")) == group["test_source_review"]["actual_task"],
            "actual independent external legal-backup test review pending")
    require(review["source_sha256"].get(path.relative_to(ROOT).as_posix()) == sha(path),
            "external legal-backup exact reviewed test SHA missing")
    merge_refs(refs, review["reference_sha256"])


def actual_prewrite_red_bundle(audit, expected, test_sha, refs):
    # Exact actual c6e129 execution bundle. Copied checks from fixed53ab's
    # raw_prewrite_execution; never import that launcher or override globals.
    execution = audit["execution"]
    raw_path = bound(execution["raw_receipt"], refs)
    freeze_path = bound(execution["phase_freeze"], refs)
    launcher_path = bound(execution["launcher"], refs)
    imported_path = bound(execution["imported_product_source"], refs)
    raw, frozen, imported = read(raw_path), read(freeze_path), read(imported_path)
    producer = ROOT / ".coordination/20261014/workspaces/job-runtime-footprint-repair-r34/artifacts/job_runtime_footprint_r34/candidate-src-v2"
    require(raw["phase"] == frozen["phase"] == "red" and raw["command_started"] is True
            and raw["test_started"] is True and raw["finished_at"], "actual prewrite red phase incomplete")
    require(raw["freeze_sha256"] == sha(freeze_path) and frozen["launcher_sha256"] == sha(launcher_path)
            and Path(frozen["candidate_source_root"]) == producer,
            "actual prewrite freeze/launcher/root differs")
    merge_refs(refs, frozen["references_sha256"])
    require(raw["fixed_test_sha256"] == frozen["candidate_source_sha256"][PREWRITE] == test_sha
            and frozen["candidate_source_sha256"][ORIGINAL] == ORIGINAL_SHA,
            "actual prewrite frozen test bytes differ")
    require(raw["candidate_before"] == raw["candidate_after"] == frozen["candidate_source_sha256"]
            and len(raw["candidate_before"]) == 1086
            and raw["case_counter"] == frozen["expected_case_counter"] == case_rows(expected),
            "actual prewrite source/raw/frozen Counter differs")
    require(raw["evidence_guards_passed"] is True and raw["guards"]
            and all(value is True for value in raw["guards"].values())
            and raw["passed"] is False and len(raw["commands"]) == 1
            and raw["commands"][0]["returncode"] == 1, "actual prewrite rc/guards mismatch")
    require(imported_path == raw_path.parent / "imported-product-source.json"
            and raw["artifact_sha256"]["imported-product-source.json"] == sha(imported_path)
            and imported["valid"] is True and imported["modules"] and "zscope" in imported["modules"],
            "actual prewrite import artifact binding absent")
    require(raw["artifact_sha256"], "actual prewrite artifacts missing")
    for name, value in raw["artifact_sha256"].items():
        relative = Path(name)
        require(not relative.is_absolute() and ".." not in relative.parts and name != "receipt.json", "unsafe actual prewrite artifact")
        merge_refs(refs, {str(raw_path.parent / relative): value})
    values = raw["candidate_before"]
    for name, module in imported["modules"].items():
        require(module["valid"] is True and (name == "zscope" or name.startswith("zscope.")), "actual prewrite imported module invalid")
        if "path" in module:
            physical = Path(module["path"])
            require(physical.is_relative_to(producer)
                    and values.get(physical.relative_to(producer).as_posix()) == module["sha256"],
                    "actual prewrite recorded module path/SHA differs")
        else:
            directory = producer / name.replace(".", "/")
            require(module["namespace_paths"] and all(path == str(directory) for path in module["namespace_paths"])
                    and any(path.startswith(directory.relative_to(producer).as_posix() + "/") for path in values),
                    "actual prewrite namespace membership differs")
    require(imported["modules"]["zscope"]["path"] == str(producer / "zscope/__init__.py"), "actual prewrite product root differs")
    xml_path = raw_path.parent / "results.xml"
    actual, counts = xml_data(xml_path)
    require(str(xml_path) == audit["results_xml"] and sha(xml_path) == raw["artifact_sha256"]["results.xml"]
            == audit["results_xml_sha256"] and actual == expected and raw["junit"] == counts == audit["junit"],
            "actual prewrite raw/XML/audit mismatch")
    return raw


def verify_review_coverage(ready, before, changed, refs):
    covered = {}
    require(isinstance(ready["source_reviews"], list) and ready["source_reviews"], "source review pending")
    for record in ready["source_reviews"]:
        raw = read(bound(record, refs))
        require(raw.get("source_review_passed") is True, "source slice is blocked")
        issuer = raw.get("actual_task", raw.get("actual_reviewer_task"))
        require(issuer == record["actual_task"] and isinstance(issuer, str) and issuer.startswith("/root"),
                "reviewer task identity differs")
        values = raw.get("source_sha256", raw.get("owned_sources_sha256"))
        require(isinstance(values, dict) and values, "actual source review SHA map absent")
        if "source_sha256" in raw and "owned_sources_sha256" in raw:
            require(raw["source_sha256"] == raw["owned_sources_sha256"], "review SHA maps conflict")
        for name, value in values.items():
            require(name in before and before[name] == value, "review not bound to final source: " + name)
            require(name not in covered or covered[name] == value, "review coverage conflict")
            covered[name] = value
        if "reference_sha256" in raw:
            merge_refs(refs, raw["reference_sha256"])
    require(set(changed) <= set(covered), "changed source/test/doc/native lacks actual positive review")
    require(DOCS <= set(covered), "all three final module docs require actual source review")


def third_observation(node, mode):
    # Copied contract from the independently reviewed third tooling712e95.
    # It is not imported or executed as a local helper.
    values = [p.get("value") for p in node.findall("properties/property") if p.get("name") == "indexed_input_observation"]
    require(len(values) == 1, "actual third observation missing/duplicated")
    observed = json.loads(values[0])
    proofs = observed["native_plans"]
    require(len(proofs) == 1 and proofs[0]["prerequisites_passed"] is True
            and proofs[0]["index_context_count"] == 3, "actual native3 proof missing")
    proof = proofs[0]
    require(proof["plan"]["boundary_coverage_complete"] is True and proof["plan"]["planned_instances"] == 2
            and len(proof["plan"]["instances"]) == len(proof["selected_build_context_ids"]) == 2,
            "actual exact EntryPlan2 proof missing")
    contexts = [item["context"] for item in proof["native_contexts"]]
    require(len(contexts) == len({item["build_context_id"] for item in contexts}) == 3,
            "actual native membership differs")
    selected = set(proof["selected_build_context_ids"])
    require(selected == {item["build_context_id"] for item in proof["plan"]["instances"]}
            == {item["build_context_id"] for item in contexts if item["source"] == "unit.c"},
            "actual two selected native identities differ")
    third = [item for item in contexts if item["source"] == "other.c"]
    require(len(third) == 1 and third[0]["build_context_id"] not in selected, "third TU is not unselected")
    header = observed["entered_header"]
    require(Path(header).is_absolute() and proof["header_identity_at_native_plan"] == observed["input_before"]
            and third[0]["dependencies"][header] == observed["input_before"]["sha256"]
            and all(header not in item["dependencies"] for item in contexts if item["build_context_id"] in selected),
            "actual third-only input identity/SHA binding missing")
    require(any(query["including_file"] == third[0]["command"]["source"] and query["target_file"] == header
                and query["found"] is True for query in third[0]["include_lookups"]["queries"]),
            "actual third ordinary absolute lookup missing")
    for item in proof["native_contexts"]:
        require(item["context_input_status"] == "current" and item["emitting_bytes_current"] is True
                and item["context"]["tool"]["binary"]["sha256"] == NEW_SHA
                and item["context"]["dependencies_complete"] is True and item["context"]["include_lookups"]["complete"] is True,
                "actual current native proof failed before risk point")
        footer = item["complete_footers"]
        require(len(footer) == 1 and footer[0]["success"] is True
                and footer[0]["include_lookups"] == item["context"]["include_lookups"]
                and footer[0]["include_probes"] == item["context"]["include_probes"], "actual native footer differs")
    if mode == "normal":
        require(observed["collision"] is False and header != observed["target"]
                and observed["input_before"] == observed["input_after"]
                and observed["original_command_outcome"]["returned"] is True
                and observed["original_command_outcome"]["exit_code"] == 0
                and any(row.get("returned") is True for row in observed["target_replace_calls"]),
                "third normal did not traverse actual intact publisher")
    elif mode == "red":
        require(observed["collision"] is True and header == observed["target"]
                and observed["actual_indexed_input_overwritten"] is True
                and observed["classification"] == "actual_indexed_input_overwritten", "third overwrite inconclusive")
        first, last = observed["input_before"], observed["input_after"]
        require(hashlib.sha256(bytes.fromhex(first["bytes_hex"])).hexdigest() == first["sha256"]
                and hashlib.sha256(bytes.fromhex(last["bytes_hex"])).hexdigest() == last["sha256"]
                and first["sha256"] != last["sha256"], "third actual input byte corruption missing")
        require(any(row.get("returned") is True and row["destination"] == header and row["source"] == header + ".tmp"
                    and row["target_before"] == first and row["target_after"] == last
                    and row["temporary_before"]["sha256"] == last["sha256"] for row in observed["target_replace_calls"]),
                "original exact replace did not return with changed entered bytes")
        failure = node.find("failure")
        require(failure is not None and "an actual indexed TU input reached original os.replace" in (failure.text or ""),
                "third red first assertion unrelated")
    else:
        require(observed["collision"] is True and observed["input_before"] == observed["input_after"]
                and observed["target_write_calls"] == observed["target_replace_calls"] == [],
                "third green changed input or reached original write")
        require(observed["risk_gate_reached"] is True
                and "job_runtime_output" in (observed["original_command_outcome"]["caught_exception_message"] or ""),
                "third green did not reach exact native-input refusal")
        require(any(row.get("rejected") is True and row["target"] == header and row["directory"] is False
                    and row["native_plan_verified"] is True and row["input_identity_before"] == observed["input_before"]
                    and "job_runtime_output" in row.get("exception_message", "") for row in observed["exact_target_declares"]),
                "third green lacks exact actual factory refusal")


def verify_causal_record(label, record, expected, test_sha, refs):
    audit = read(bound(record, refs))
    require(audit["actual_task"] == "/root" and audit["causal_review_passed"] is True
            and audit["evidence_guards_passed"] is True, "actual Root causal review pending")
    path = Path(audit["results_xml"])
    merge_refs(refs, {str(path): audit["results_xml_sha256"]})
    counter, counts = xml_data(path)
    require(counter == expected and audit["case_counter"] == case_rows(counter)
            and audit["test_sha256"] == test_sha and audit["junit"] == counts
            and counts["failures"] > 0 and counts["errors"] == counts["skipped"] == 0,
            "red audit XML/test/Counter mismatch")
    raw = (actual_prewrite_red_bundle(audit, expected, test_sha, refs) if label == "prewrite7"
           else read(bound(audit["raw_red_receipt"], refs)))
    valid_raw(raw, False, label)
    require(raw_sources(raw, "before") == raw_sources(raw, "after"), "red full source drift")
    require(raw_counter(label, raw) == case_rows(counter) and raw_test_sha(label, raw) == test_sha,
            "raw red actual Counter/test differs")
    merge_refs(refs, audit["reference_sha256"])
    projection = read(bound(audit["causal_projection"], refs))
    require(projection["actual_task"] == "/root" and projection["causal_review_passed"] is True,
            "actual first-cause projection missing")
    failed = {(n.get("classname", ""), n.get("name", "")) for n in ET.parse(path).getroot().iter("testcase")
              if n.find("failure") is not None}
    targets = audit["valid_target_failure_identities"]
    require(isinstance(targets, list) and targets and len({tuple(v) for v in targets}) == len(targets)
            and set(map(tuple, targets)) <= failed, "actual causal target failures absent")
    if label == "original53":
        require(audit["schema"] == "zscope.stage-native-job-valid-red.r35.v1", "original red audit schema")
        require(JOB_ID in set(map(tuple, targets)) and expected[JOB_ID] == 1,
                "original SessionJobs causal failure omitted")
    else:
        require(audit["evidence_kind"] == "actual-red-execution-causality",
                "static source review cannot substitute for risk red")
        cases = projection["cases"]
        require(isinstance(cases, list) and len(cases) == len(targets)
                and {tuple(v["identity"]) for v in cases} == set(map(tuple, targets)),
                "per-target projection missing")
        require(projection["red_xml_sha256"] == sha(path) and projection["test_sha256"] == test_sha
                and projection["case_counter"] == case_rows(counter), "projection input binding differs")
        if label == "prewrite7":
            positives = {identity for identity in expected
                         if identity[1].startswith("test_prewrite_probe_native_job_positive_closes_queue[")}
            negatives = set(expected) - positives
            require(audit["schema"] == "zscope.stage-prewrite-valid-red.r35.v1"
                    and projection["schema"] == "zscope.stage-prewrite-first-cause.r35.v1"
                    and counts == {"tests": 7, "failures": 5, "errors": 0, "skipped": 0}
                    and failed == negatives == set(map(tuple, targets)), "all five real risk reds required")
            for identity in positives:
                node = next(n for n in ET.parse(path).getroot().iter("testcase")
                            if (n.get("classname", ""), n.get("name", "")) == identity)
                values = [p.get("value") for p in node.findall("properties/property") if p.get("name") == "positive_job"]
                require(len(values) == 1 and json.loads(values[0]) == {
                    "batch": identity[1].endswith("[True]"), "analyzed": 2, "checkpointed": True},
                    "actual red-phase positive closure absent")
        else:
            require(audit["schema"] == "zscope.stage-indexed-input-valid-red.r35.v1"
                    and projection["schema"] == "zscope.stage-indexed-input-first-cause.r35.v1"
                    and counts == {"tests": 2, "failures": 1, "errors": 0, "skipped": 0}
                    and set(map(tuple, targets)) == {("tests.test_job_indexed_input_prewrite_r35",
                        "test_third_indexed_tu_runtime_header_is_refused_before_replace")},
                    "third-TU control/failure identities differ")
            normal_node = next(n for n in ET.parse(path).getroot().iter("testcase")
                               if n.get("name", "") == "test_third_indexed_tu_normal_header_keeps_real_job_drained")
            require(normal_node.find("failure") is None, "third original control failed")
            third_observation(normal_node, "normal")
        for item in cases:
            node = next(n for n in ET.parse(path).getroot().iter("testcase")
                        if (n.get("classname", ""), n.get("name", "")) == tuple(item["identity"]))
            prop_name = "prewrite_observation" if label == "prewrite7" else "indexed_input_observation"
            props = [p.get("value") for p in node.findall("properties/property") if p.get("name") == prop_name]
            require(len(props) == 1 and item["observation_value_sha256"] == hashlib.sha256(props[0].encode()).hexdigest(),
                    "causal projection not bound to actual observation bytes")
            require(item["failure_element_sha256"] == hashlib.sha256(ET.tostring(node.find("failure"), encoding="utf-8")).hexdigest(),
                    "first assertion projection not bound to raw failure")
            observation = json.loads(props[0])
            require(observation["risk_gate_reached"] is True, "unreached risk is inconclusive")
            if label == "third2":
                require(item["first_failed_gate"] == "target_replace_calls_empty", "third first-failure projection differs")
                third_observation(node, "red")
            else:
                plans = observation["native_plans"]
                require(len(plans) == 1 and plans[0]["instances"] == plans[0]["current_contexts"] == 2
                        and plans[0]["tool_sha256"] == [NEW_SHA], "actual two-variant f4 prerequisite absent")
                if item["identity"][1].startswith("test_batch_backup_"):
                    require(item["first_failed_gate"] == "dangerous_copy_calls_empty"
                            and observation["dangerous_copy_calls"]
                            and observation["actual_input_before"]["sha256"] != observation["actual_input_after"]["sha256"]
                            and "the real copy operation must never follow a link to an input" in (node.find("failure").text or ""),
                            "actual forwarded backup input damage not proved")
                else:
                    require(observation["store_connects"] and observation["store_connects"][0]["native_plan_finished"] is True
                            and observation["tool_before"]["sha256"] == NEW_SHA
                            and observation["tool_revoked"]["sha256"] != NEW_SHA
                            and observation["tool_revoked"]["mtime_ns"] == observation["tool_before"]["mtime_ns"],
                            "actual private-tool withdrawal or first Store connect missing")
                    revoked = [v for v in observation["native_tool_gates"]
                               if v["recorded_tool_sha256"] == NEW_SHA
                               and v["actual_tool_sha256"] == observation["tool_revoked"]["sha256"]
                               and v.get("actual_current_result") is False]
                    require(revoked, "original emitting-byte verifier did not return False")
                    if item["first_failed_gate"] == "native_tool_verifier_before_store":
                        require(all(v["store_connects_before_gate"] > 0 for v in revoked)
                                and "the real emitting-byte verifier must observe the revoked tool before any Store connection" in (node.find("failure").text or ""),
                                "actual late verifier not first failure")
                    else:
                        require(item["first_failed_gate"] == "store_connects_empty"
                                and any(v["store_connects_before_gate"] == 0 for v in revoked)
                                and "withdrawn native authority must precede even a WAL-capable Store connection" in (node.find("failure").text or ""),
                                "actual ignored preconnect verifier not first failure")
        merge_refs(refs, projection["reference_sha256"])


def validate_ready(ready_sha):
    digest(ready_sha)
    if not READY.is_file():
        raise Pending("real final ready file is absent")
    require(sha(READY) == ready_sha, "ready SHA mismatch")
    ready = read(READY)
    if ready.get("status") != "ready" or ready.get("pending_dependencies"):
        raise Pending("real final ready and every dependency are still pending")
    require(ready["schema"] == "zscope.native-job-independent-ready.r35.v1"
            and ready["actual_task"] == "/root" and ready["workspace"] == str(WORK)
            and ready["launcher_sha256"] == sha(INSTALLED)
            and ready["launcher_shell_sha256"] == sha(INSTALLED.with_suffix(".sh")),
            "ready identity/launcher differs")
    require(WORK.is_dir() and WORK.resolve() == WORK and not WORK.is_symlink(), "independent workspace unavailable")
    refs = {}
    merge_refs(refs, ready["reference_sha256"])
    merge_refs(refs, {str(ROOT / p): v for p, v in PINS.items()})
    merge_refs(refs, {str(READY): ready_sha, str(INSTALLED): sha(INSTALLED),
                      str(INSTALLED.with_suffix(".sh")): sha(INSTALLED.with_suffix(".sh"))})
    floor = read(ROOT / FLOOR)
    floor_source, root_inputs = floor["complete_inputs_after"], floor["root_inputs"]
    require(len(floor_source) == 1082 and len(root_inputs) == 1065
            and ready["stage_floor_sha256"] == floor_source and ready["root1065_sha256"] == root_inputs,
            "fixed Stage1082/Root1065 floor changed")
    before = source_map(WORK)
    additions = {ORIGINAL, PREWRITE, THIRD, STORE_TEST, TRACE_TEST}
    require(len(before) == 1087 and before == ready["complete_inputs_sha256"]
            and set(before) == set(floor_source) | additions, "final full1087 not ready")
    require(before[ORIGINAL] == ORIGINAL_SHA and before[PREWRITE] == PREWRITE_SHA, "immutable53/7 tests changed")
    changed = {p for p in before if floor_source.get(p) != before[p]}
    require(set(ready["changed_paths"]) == changed, "changed path declaration differs from real delta")
    verify_review_coverage(ready, before, changed, refs)
    require(named_files(WORK, CONFIG_NAMES) == {"pyproject.toml": before["pyproject.toml"]}
            and ready["configuration_baseline"] == {"pyproject.toml": before["pyproject.toml"]},
            "only actual workspace pyproject config allowed")
    require(named_files(WORK, {"AGENTS.md"}) == ready["agents_baseline"], "actual AGENTS set differs")
    require(source_map(STAGE) == floor_source and mapped(ROOT, root_inputs) == root_inputs,
            "Stage/Root inputs drifted")
    build = read(ROOT / next(k for k in PINS if k.endswith("native-build-v4/receipt.json")))
    require(build["passed"] is True and build["evidence_guards_passed"] is True
            and build["native_tool_sha256"] == NEW_SHA and all(v is True for v in build["guards"].values()),
            "real native build evidence invalid")
    require(build["commands"] and all(c["returncode"] == 0 for c in build["commands"]), "real build did not return0")
    for name, expected in build["native_build_sources"].items():
        require(before[name] == expected, "final native build source differs: " + name)
    expected = {}
    require(set(ready["groups"]) == set(GROUPS), "a required execution group is pending/missing")
    require(set(ready["coordinator_document_overrides"]) == DOCS
            and all(ready["coordinator_document_overrides"][p] == before[p] for p in DOCS),
            "all three final module docs and exact source reviews are mandatory")
    legal_backup_review(ready, refs)
    for label, record in ready["groups"].items():
        for argument in GROUPS[label]:
            filename = argument.partition("::")[0]
            path = ROOT / filename if filename in S01_EXTERNAL + [AUTHORITY] else WORK / filename
            if filename in S01_EXTERNAL + [AUTHORITY]:
                require(str(path) in refs, "external allowed test must be an immutable reference")
            else:
                require(record["test_sources_sha256"][filename] == before[filename], "group test source differs")
        selected(label, ready)
        if label in HISTORICAL:
            filename, value, count = HISTORICAL[label]
            merge_refs(refs, {str(ROOT / filename): value})
            expected[label] = green_xml(ROOT / filename)
            require(sum(expected[label].values()) == count, "historical exact Counter changed")
        elif label == "native_related":
            # Existing real XML provides identities without requiring a new executable
            # collection phase. Overlapping XML must agree on raw multiplicity.
            modules = {"tests." + Path(p).stem for p in GROUPS[label]}
            oracles = record["counter_oracles"]
            require(isinstance(oracles, list) and oracles, "actual native XML oracle missing")
            expected[label] = Counter()
            for oracle in oracles:
                actual, _counts = xml_data(bound(oracle, refs))
                subset = Counter({key: value for key, value in actual.items() if key[0] in modules})
                require(subset, "native oracle has no selected raw identities")
                for identity, multiplicity in subset.items():
                    require(identity not in expected[label] or expected[label][identity] == multiplicity,
                            "native oracle overlap multiplicity differs")
                    expected[label][identity] = multiplicity
        else:
            xml = bound(record["producer_green_xml"], refs)
            expected[label] = green_xml(xml)
            raw = read(bound(record["producer_green_raw"], refs))
            valid_raw(raw, True, label)
            first, last = raw_sources(raw, "before"), raw_sources(raw, "after")
            require(first == last, "producer final green full source drift")
            producer_source(label, first, before, ready)
            require(raw_counter(label, raw) == case_rows(expected[label]), "producer green actual Counter differs")
            green_imports(label, record, raw, first, refs, ready)
            for name, value in raw["artifact_sha256"].items():
                relative = Path(name)
                require(not relative.is_absolute() and ".." not in relative.parts and name != "receipt.json", "unsafe producer green artifact")
                merge_refs(refs, {str(Path(record["producer_green_raw"]["path"]).parent / relative): value})
            if label == "legal_backup1":
                phase_path = bound(record["producer_phase_freeze"], refs)
                launcher_path = bound(record["producer_launcher"], refs)
                frozen = read(phase_path)
                require(raw["freeze_sha256"] == sha(phase_path)
                        and frozen["phase"] == "green-legal"
                        and frozen["launcher_sha256"] == sha(launcher_path)
                        and frozen["candidate_source_sha256"] == first
                        and frozen["selected_test_sha256"] == PREWRITE_SHA
                        and frozen["external_test_sha256"] == raw_test_sha(label, raw)
                        and frozen["expected_case_counter"] == raw_counter(label, raw),
                        "actual legal producer phase/freeze/launcher/source/Counter binding differs")
                merge_refs(refs, frozen["references_sha256"])
                require(sum(expected[label].values()) == len(expected[label]) == 1
                        and raw_test_sha(label, raw) == sha(legal_backup_path(ready))
                        and raw["artifact_sha256"]["results.xml"] == sha(xml)
                        and record["case_counter"] == case_rows(expected[label]),
                        "actual one-case legal existing-report backup green/source binding pending")
                continue
            collection = read(bound(record["collection_receipt"], refs))
            require(collection["phase"] == "collect"
                    and (collection["phase_completed_validly"] if label == "third2" else collection["passed"]) is True
                    and collection["test_started"] is False and collection["evidence_guards_passed"] is True
                    and collection["guards"] and all(v is True for v in collection["guards"].values())
                    and raw_counter(label, collection) == case_rows(expected[label]), "actual collection not bound")
            test_name = ORIGINAL if label == "original53" else PREWRITE if label == "prewrite7" else THIRD
            require(raw_test_sha(label, collection) == before[test_name],
                    "actual collection test bytes differ")
            if label == "third2":
                for node in ET.parse(xml).getroot().iter("testcase"):
                    third_observation(node, "normal" if node.get("name", "") == "test_third_indexed_tu_normal_header_keeps_real_job_drained" else "green")
        require(record["case_counter"] == case_rows(expected[label]), "ready array is not actual XML Counter")
    original52 = Counter({k: v for k, v in expected["original53"].items() if k[0] == "tests.test_job_runtime_footprint_r34"})
    require(sum(expected["original53"].values()) == len(expected["original53"]) == 53
            and sum(original52.values()) == len(original52) == 52
            and expected["original53"][JOB_ID] == 1
            and set(expected["original53"]) == set(original52) | {JOB_ID}, "original53 is exactly52+1")
    require(expected["prewrite7"] == prewrite_counter() and expected["third2"] == third_counter(),
            "actual7/third2 identities changed")
    require(expected["native_related"] and all(k[0] in {"tests." + Path(p).stem for p in GROUPS["native_related"]}
            for k in expected["native_related"]), "related native oracle has foreign module identities")
    require({k[0] for k in expected["native_related"]} == {"tests." + Path(p).stem for p in GROUPS["native_related"]},
            "one related native file has no actual cases")
    for label, test in (("original53", ORIGINAL), ("prewrite7", PREWRITE), ("third2", THIRD)):
        verify_causal_record(label, ready["groups"][label]["valid_red_audit"], expected[label], before[test], refs)
    require(ready["expected_environment"] == {key: os.environ.get(key) for key in ENV_KEYS},
            "actual login/LLVM environment differs")
    external = external_controls(ready)
    allowed_projects = {str(ROOT / "pyproject.toml"),
                        str(ROOT / ".coordination/20261014/workspaces/job-runtime-footprint-repair-r34/pyproject.toml")}
    require(external == ready["external_configuration_baseline"] and set(external) <= allowed_projects
            and str(ROOT / "pyproject.toml") in external
            and all(value == before["pyproject.toml"] for value in external.values()),
            "external probe ancestors contain unreviewed config/conftest")
    require(isinstance(ready["expected_host"], dict) and ready["expected_host"], "frozen actual host pending")
    return ready, before, refs, expected


def chain(path):
    return {str(p): {"physical": str(p.resolve(strict=True)), "uid": p.lstat().st_uid,
                     "gid": p.lstat().st_gid, "mode": p.lstat().st_mode,
                     "device": p.lstat().st_dev, "inode": p.lstat().st_ino,
                     "links": p.lstat().st_nlink,
                     "symlink": os.readlink(p) if p.is_symlink() else None}
            for p in (path, *path.parents, path.resolve(strict=True), *path.resolve(strict=True).parents)}


def file_identity(path):
    require(path.is_file(), "host file absent: " + str(path))
    return {"sha256": sha(path), "physical": str(path.resolve(strict=True)), "chain": chain(path)}


def linked(path, env, raw_log):
    result = subprocess.run(["ldd", str(path)], env=env, capture_output=True, text=True, timeout=20)
    raw_log.write_text(result.stdout + result.stderr, encoding="utf-8")
    require(result.returncode == 0 and "not found" not in result.stdout + result.stderr, "actual ldd failed")
    libraries = sorted({Path(v) for v in re.findall(r"/[^\s()]+", result.stdout)})
    require(libraries and all(p.is_file() for p in libraries), "unresolved actual library/loader")
    return {"binary": file_identity(path), "libraries": {str(p): file_identity(p) for p in libraries}}


def host(ready, env, target, suffix):
    require(sha(OLD_TOOL) == OLD_SHA and sha(NEW_TOOL) == NEW_SHA, "fixed binary changed")
    version = subprocess.run([str(NEW_TOOL), "--version"], env=env, capture_output=True, text=True, timeout=20)
    require(version.returncode == 0, "actual native capability failed")
    capability = json.loads(version.stdout)
    native = ready["new_native_tool"]
    require(native["path"] == str(NEW_TOOL) and native["sha256"] == NEW_SHA
            and native["physical"] == str(NEW_TOOL.resolve(strict=True))
            and capability == native["capability"]
            and capability.get("protocol") == "zscope.clang-facts.v2"
            and capability.get("include_lookup_version") == 1
            and capability.get("clang_version") == "18.1.3"
            and hashlib.sha256(version.stdout.encode()).hexdigest() == native["version_stdout_sha256"],
            "actual current tool capability/build differs")
    sdk = chain(SDK_ALIAS)
    sdk.update(chain(SDK_PHYSICAL))
    require(SDK_ALIAS.is_symlink() and SDK_ALIAS.resolve(strict=True) == SDK_PHYSICAL
            and all(item["uid"] == 0 and (item["symlink"] is not None or not item["mode"] & 0o022)
                    for item in sdk.values())
            and {p for p, item in sdk.items() if item["symlink"] is not None} == {str(SDK_ALIAS)},
            "SDK installation alias/trust differs")
    resources = {}
    require(native["resource_header_roots"] == [str(SDK_PHYSICAL)], "actual supported SDK root pending")
    for root_name in native["resource_header_roots"]:
        root = Path(root_name)
        members = {".": {"chain": chain(root)}}
        for path in sorted(root.rglob("*")):
            value = path.lstat()
            require(not path.is_symlink() and value.st_uid == 0 and not value.st_mode & 0o022
                    and (stat.S_ISDIR(value.st_mode) or stat.S_ISREG(value.st_mode)),
                    "unknown nested SDK alias or writable/nonstandard member")
            members[path.relative_to(root).as_posix()] = file_identity(path) if path.is_file() else {"chain": chain(path)}
        require(len(members) > 1, "resource-header tree missing")
        resources[root_name] = members
    standard = {}
    for path in (Path("/usr/include/stdlib.h"), Path("/usr/include/features.h")):
        value = file_identity(path)
        require(all(v["uid"] == 0 and not v["mode"] & 0o022 and v["symlink"] is None for v in value["chain"].values()),
                "standard header installation trust changed")
        standard[str(path)] = value
    names = ("cmake", "gcc", "clang", "clang++", "clangd", "gclang", "get-bc", "llvm-link", "llvm-nm", "wpa", "saber")
    tools = {name: shutil.which(name, path=env.get("PATH")) for name in names}
    require(all(tools.values()), "actual login tool missing")
    require(Path(tools["llvm-link"]).resolve(strict=True) == Path("/usr/lib/llvm-18/bin/llvm-link").resolve(strict=True),
            "LLVM18 selection changed")
    result = {"old_native": linked(OLD_TOOL, env, target / ("old-ldd-" + suffix + ".log")),
              "new_native": linked(NEW_TOOL, env, target / ("new-ldd-" + suffix + ".log")),
              "capability": capability, "sdk_trust": sdk, "standard_headers": standard,
              "resource_headers": resources, "python": file_identity(Path(PYTHON)),
              "login_tools": {name: file_identity(Path(path)) for name, path in tools.items()},
              "svf": {name: linked(Path(tools[name]), env, target / (name + "-ldd-" + suffix + ".log"))
                      for name in ("wpa", "saber")}}
    return result


def runtime():
    token = os.environ.get("ZSCOPE_COORDINATOR_TEST_SLOT", "").split(":")
    require(len(token) == 2 and token[0].isdigit() and int(token[0]) > 0 and token[1] in {"0", "1"},
            "single outer slot token missing")
    lock_path = Path("/tmp/zscope-coordination-20261014-test-slots") / (token[1] + ".lock")
    with lock_path.open() as stream:
        try:
            fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            pass
        else:
            fcntl.flock(stream.fileno(), fcntl.LOCK_UN)
            raise RuntimeError("outer slot lock is not held")
    mounted = subprocess.run(["findmnt", "--json", "--output", "TARGET,FSTYPE", "--target", os.environ["TMPDIR"]],
                             capture_output=True, text=True, timeout=15)
    require(mounted.returncode == 0, "temporary mount unavailable")
    mount = json.loads(mounted.stdout)["filesystems"][0]
    require(mount["fstype"] == "ext4", "actual temp must be ext4")
    with tempfile.TemporaryFile(dir=os.environ["TMPDIR"]) as stream:
        stream.write(b"fd capture prerequisite")
        stream.flush()
        stream.truncate(0)
        require(os.fstat(stream.fileno()).st_size == 0, "unlinked fd truncate failed")
    return {"slot": ":".join(token), "lock": str(lock_path), "mount": mount,
            "ext4_unlinked_fd_truncate": True, "process_inspection": False}


def execution_env():
    env = dict(os.environ)
    env["PYTHONPATH"] = str(WORK)
    env["Z_SCOPE_TEST_CLANG_INDEXER"] = str(NEW_TOOL)
    env["Z_SCOPE_TEST_LLVM"] = "1"
    return env


def guard(ready, refs, target, suffix, env):
    return {"source": source_map(WORK), "configuration": named_files(WORK, CONFIG_NAMES),
            "agents": named_files(WORK, {"AGENTS.md"}), "stage": source_map(STAGE),
            "external_configuration": external_controls(ready),
            "root": mapped(ROOT, ready["root1065_sha256"]),
            "references": {name: sha(name) for name in refs},
            "host": host(ready, env, target, suffix), "runtime": runtime()}


def check_guard(snapshot, ready, before, refs):
    require(snapshot["source"] == before and snapshot["configuration"] == ready["configuration_baseline"]
            and snapshot["agents"] == ready["agents_baseline"] and snapshot["stage"] == ready["stage_floor_sha256"]
            and snapshot["external_configuration"] == ready["external_configuration_baseline"]
            and snapshot["root"] == ready["root1065_sha256"] and snapshot["references"] == refs
            and snapshot["host"] == ready["expected_host"], "complete execution guard mismatch")


def bootstrap():
    if sys.platform != "linux" or sys.flags.optimize or sys.executable != PYTHON or sys.version_info[:2] != (3, 13):
        raise RuntimeError("unoptimized Linux venv313 required")
    if pwd.getpwuid(os.geteuid()).pw_name != "zeal" or Path.cwd().resolve() != WORK:
        raise RuntimeError("zeal and exact independent working directory required")
    if any(os.environ.get(name) for name in ("PYTHONOPTIMIZE", "PYTEST_ADDOPTS", "PYTEST_PLUGINS")):
        raise RuntimeError("external optimization/pytest options/plugins forbidden")
    if Path(__file__).resolve() != INSTALLED:
        raise RuntimeError("draft execution forbidden; Root must install reviewed bytes first")


def child(ready_sha, label, output):
    bootstrap()
    require(label in GROUPS, "unknown child group")
    require(output == OUT / label and output.is_dir(), "child output must be its Root group directory")
    ready, before, child_refs, _expected = validate_ready(ready_sha)
    require(not any(name == "zscope" or name.startswith("zscope.") for name in sys.modules),
            "product imported before source selection")
    sys.path.insert(0, str(WORK))
    import zscope
    require(Path(zscope.__file__).resolve() == WORK / "zscope/__init__.py", "wrong product package")
    if label == "legal_backup1":
        require((WORK / "tests").is_dir() and not any(name.rsplit(".", 1)[-1] in LEGAL_FIXTURES for name in sys.modules),
                "fixture modules imported before fixed tests path selection")
        sys.path.insert(0, str(WORK / "tests"))
        # External test's four bare fixture imports must use these actual
        # immutable WORK files, never the producer, Root baseline or old main.
        for name in LEGAL_FIXTURES:
            module = importlib.import_module(name)
            path = Path(module.__file__).resolve(strict=True)
            relative = "tests/" + name + ".py"
            require(path == WORK / relative and sha(path) == before[relative],
                    "wrong actual external fixture file/SHA: " + name)
    import pytest

    class Provenance:
        def pytest_collection_finish(self, session):
            write(output / "collected.json", {"actual_nodeids": [item.nodeid for item in session.items]})

        def pytest_sessionfinish(self, session, exitstatus):
            modules = {}
            external_modules = {}
            fixture_modules = {}
            for name, module in sorted(sys.modules.items()):
                if label == "legal_backup1" and name.rsplit(".", 1)[-1] in LEGAL_FIXTURES:
                    relative = "tests/" + name.rsplit(".", 1)[-1] + ".py"
                    raw_fixture = getattr(module, "__file__", None)
                    fixture_path = Path(raw_fixture).resolve() if raw_fixture else None
                    value = sha(fixture_path) if fixture_path is not None and fixture_path.is_file() else None
                    fixture_modules[name] = {"path": str(fixture_path) if fixture_path else None, "sha256": value,
                                             "valid": fixture_path == WORK / relative and value == before[relative]}
                if name != "zscope" and not name.startswith("zscope."):
                    raw = getattr(module, "__file__", None)
                    if raw:
                        path = Path(raw).resolve()
                        if path.is_relative_to(ROOT) and not path.is_relative_to(WORK) and path.is_file():
                            value = sha(path)
                            external_modules[name] = {"path": str(path), "sha256": value,
                                                      "valid": child_refs.get(str(path)) == value}
                    continue
                raw = getattr(module, "__file__", None)
                if raw:
                    path = Path(raw).resolve()
                    relative = path.relative_to(WORK).as_posix() if path.is_relative_to(WORK) else None
                    value = sha(path) if path.is_file() else None
                    valid = relative in before and before.get(relative) == value
                    modules[name] = {"path": str(path), "sha256": value, "valid": valid}
                else:
                    paths = [Path(p).resolve() for p in getattr(module, "__path__", ())]
                    directory = WORK / name.replace(".", "/")
                    valid = bool(paths) and all(p == directory and p.is_dir() for p in paths)
                    valid = valid and any(p.startswith(directory.relative_to(WORK).as_posix() + "/") for p in before)
                    modules[name] = {"namespace_paths": list(map(str, paths)), "valid": valid}
            valid = bool(modules) and all(row["valid"] is True for row in modules.values()) \
                and all(row["valid"] is True for row in external_modules.values())
            if label == "legal_backup1":
                valid = valid and set(LEGAL_FIXTURES) <= set(fixture_modules) \
                    and all(row["valid"] is True for row in fixture_modules.values())
            write(output / "imported-product-source.json", {"actual_task": ACTUAL_TASK, "valid": valid,
                                                           "modules": modules, "external_local_modules": external_modules,
                                                           "fixture_modules": fixture_modules})
            if not valid:
                session.exitstatus = 2

    options = ["-q", "--rootdir=" + str(WORK), "--confcutdir=" + str(WORK), "--capture=fd",
               *selected(label, ready), "--junitxml=" + str(output / "results.xml")]
    write(output / "pytest-invocation.json", {"actual_task": ACTUAL_TASK, "argv": options,
                                             "workspace": str(WORK), "source_sha256": before})
    return pytest.main(options, plugins=[Provenance()])


def execute_test(label, ready_sha, ready, before, refs, expected, env):
    target = OUT / label
    target.mkdir(exist_ok=False)
    freeze = {"phase": "green", "group": label, "candidate_source_root": str(WORK),
              "candidate_source_sha256": before, "expected_case_counter": case_rows(expected),
              "launcher_sha256": sha(INSTALLED), "references_sha256": dict(refs)}
    freeze_path = target / "phase-freeze.json"
    write(freeze_path, freeze)
    merge_refs(refs, {str(freeze_path): sha(freeze_path)})
    raw = {"actual_task": ACTUAL_TASK, "actual_agent_id": ACTUAL_TASK, "phase": "green",
           "group": label, "test_started": False, "command_started": False, "commands": [],
           "freeze_sha256": sha(freeze_path), "candidate_before": before,
           "expected_case_counter": case_rows(expected),
           "fixed_test_sha256": before[PREWRITE if label in {"legal_backup1", "prewrite7"}
                                      else THIRD if label == "third2" else ORIGINAL],
           "passed": False, "evidence_guards_passed": False, "started_at": now()}
    errors = []
    if label == "legal_backup1":
        raw["fixed_external_test_sha256"] = sha(legal_backup_path(ready))
    try:
        first = guard(ready, refs, target, "before", env)
        write(target / "before.json", first)
        check_guard(first, ready, before, refs)
        argv = [PYTHON, str(INSTALLED), "--child", ready_sha, label, str(target)]
        raw.update(test_started=True, command_started=True)
        write(target / "receipt.json", raw)
        started = now()
        with (target / "command.log").open("w", encoding="utf-8") as stream:
            completed = subprocess.run(argv, cwd=WORK, env=env, stdout=stream, stderr=subprocess.STDOUT)
        raw["commands"].append({"argv": argv, "returncode": completed.returncode,
                                "started_at": started, "finished_at": now(), "log_sha256": sha(target / "command.log")})
        actual, counts = xml_data(target / "results.xml")
        imported = read(target / "imported-product-source.json")
        require(imported["valid"] is True, "actual imported product differs")
        raw.update(case_counter=case_rows(actual), junit=counts)
        if label == "third2":
            for node in ET.parse(target / "results.xml").getroot().iter("testcase"):
                third_observation(node, "normal" if node.get("name", "") == "test_third_indexed_tu_normal_header_keeps_real_job_drained" else "green")
        raw["guards"] = {"actual_counter_exact": actual == expected,
                         "actual_zero_failures_errors_skips": counts["failures"] == counts["errors"] == counts["skipped"] == 0,
                         "actual_product_import_provenance": imported["valid"] is True}
    except Exception as error:
        errors.append({"type": type(error).__name__, "message": str(error)})
    finally:
        try:
            last = guard(ready, refs, target, "after", env)
            write(target / "after.json", last)
            check_guard(last, ready, before, refs)
            raw["candidate_after"] = last["source"]
            raw.setdefault("guards", {})["complete_after_source_config_stage_root_refs_host"] = True
        except Exception as error:
            errors.append({"type": type(error).__name__, "message": str(error)})
            raw.setdefault("guards", {})["complete_after_source_config_stage_root_refs_host"] = False
        raw["evidence_guards_passed"] = not errors and bool(raw.get("guards")) and all(raw["guards"].values())
        raw["passed"] = raw["evidence_guards_passed"] and len(raw["commands"]) == 1 and raw["commands"][0]["returncode"] == 0
        raw.update(errors=errors, finished_at=now())
        raw["artifact_sha256"] = {p.relative_to(target).as_posix(): sha(p) for p in target.rglob("*")
                                  if p.is_file() and p.name != "receipt.json"}
        write(target / "receipt.json", raw)
    return raw


def main(ready_sha):
    bootstrap()
    OUT.mkdir(parents=True, exist_ok=False)
    report = {"schema": "zscope.coordinator-native-job-independent-run.r35.v1",
              "actual_task": ACTUAL_TASK, "started_at": now(), "status": "pending",
              "test_started": False, "commands": [], "groups": {}, "errors": [],
              "passed": False, "independent_native_job_passed": False,
              "stage_intake": False, "root_intake": False, "joint_passed": False}
    ready = before = refs = expected = None
    try:
        ready, before, refs, expected = validate_ready(ready_sha)
        env = execution_env()
        initial = guard(ready, refs, OUT, "initial", env)
        write(OUT / "before.json", initial)
        check_guard(initial, ready, before, refs)
        report["status"] = "running"
        for label in GROUPS:
            raw = execute_test(label, ready_sha, ready, before, refs, expected[label], env)
            report["groups"][label] = {"raw_receipt": str(OUT / label / "receipt.json"),
                                      "raw_receipt_sha256": sha(OUT / label / "receipt.json"),
                                      "passed": raw["passed"], "junit": raw.get("junit"),
                                      "case_counter": raw.get("case_counter")}
            report["commands"].extend(raw["commands"])
            report["test_started"] = report["test_started"] or raw["test_started"]
            write(OUT / "journal.json", report)
            require(raw["evidence_guards_passed"], "group evidence failed: " + label)
        black_paths = sorted(name for name in ready["changed_paths"] if name.endswith(".py"))
        require(black_paths, "actual changed Python Black scope missing")
        external_black = str(legal_backup_path(ready))
        require(external_black in refs and refs[external_black] == sha(external_black),
                "mandatory reviewed external Black input/reference changed")
        black_paths.append(external_black)
        quality = [
            ("compileall", [PYTHON, "-m", "compileall", "-f", "-q", "zscope", "scripts", "test", "tests"]),
            ("mypy", [PYTHON, "-m", "mypy", "zscope"]),
            ("mypy-fresh", [PYTHON, "-m", "mypy", "--no-incremental", "zscope"]),
            ("scripts-mypy", [PYTHON, "-m", "mypy", "scripts/agent_plan_evaluation.py"]),
            ("black", [PYTHON, "-m", "black", "--check", "--config", str(WORK / "pyproject.toml"), *black_paths]),
            ("web-assets", [PYTHON, "scripts/portable/web_assets.py"]),
        ]
        for label, argv in quality:
            first = guard(ready, refs, OUT, label + "-before", env)
            write(OUT / (label + "-before.json"), first)
            check_guard(first, ready, before, refs)
            started = now()
            with (OUT / (label + ".log")).open("w", encoding="utf-8") as stream:
                completed = subprocess.run(argv, cwd=WORK, env=env, stdout=stream, stderr=subprocess.STDOUT)
            report["commands"].append({"label": label, "argv": argv, "returncode": completed.returncode,
                                       "started_at": started, "finished_at": now(), "log_sha256": sha(OUT / (label + ".log"))})
            last = guard(ready, refs, OUT, label + "-after", env)
            write(OUT / (label + "-after.json"), last)
            check_guard(last, ready, before, refs)
            write(OUT / "journal.json", report)
    except Pending as error:
        report["status"] = "pending"
        report["errors"].append({"type": type(error).__name__, "message": str(error)})
    except Exception as error:
        report["status"] = "failed"
        report["errors"].append({"type": type(error).__name__, "message": str(error)})
    finally:
        if ready is not None and before is not None and refs is not None:
            try:
                last = guard(ready, refs, OUT, "final", execution_env())
                write(OUT / "after.json", last)
                check_guard(last, ready, before, refs)
                report["final_guard_passed"] = True
            except Exception as error:
                report["final_guard_passed"] = False
                report["errors"].append({"type": type(error).__name__, "message": str(error)})
        report["passed"] = bool(report["groups"]) and len(report["groups"]) == len(GROUPS) \
            and all(row["passed"] for row in report["groups"].values()) \
            and len(report["commands"]) == len(GROUPS) + 6 \
            and all(row["returncode"] == 0 for row in report["commands"]) \
            and report.get("final_guard_passed") is True and not report["errors"]
        report["independent_native_job_passed"] = report["passed"]
        report["finished_at"] = now()
        if report["status"] != "pending":
            report["status"] = "passed" if report["passed"] else "failed"
        if report["passed"]:
            try:
                artifacts = {str(p): sha(p) for p in OUT.rglob("*") if p.is_file() and p.name != "review.json"}
                adapter_refs = dict(refs)
                merge_refs(adapter_refs, artifacts)
                adapter_path = OUT / "stage-evidence-adapter.json"
                prewrite_raw = report["groups"]["prewrite7"]
                prewrite_directory = OUT / "prewrite7"
                prewrite_adapter_path = OUT / "prewrite-stage-evidence-adapter.json"
                write(prewrite_adapter_path, {
                    "schema": "zscope.stage-prewrite-evidence.r35.v1", "actual_task": ACTUAL_TASK,
                    "independent_prewrite_passed": True, "tool_sha256": NEW_SHA,
                    "complete_inputs_sha256": before, "test_sha256": before[PREWRITE],
                    "results_xml": str(prewrite_directory / "results.xml"),
                    "results_xml_sha256": sha(prewrite_directory / "results.xml"),
                    "case_counter": prewrite_raw["case_counter"], "junit": prewrite_raw["junit"],
                    "reference_sha256": dict(adapter_refs),
                    "execution": {"raw_receipt": {"path": prewrite_raw["raw_receipt"], "sha256": prewrite_raw["raw_receipt_sha256"]},
                                  "phase_freeze": {"path": str(prewrite_directory / "phase-freeze.json"), "sha256": sha(prewrite_directory / "phase-freeze.json")},
                                  "launcher": {"path": str(INSTALLED), "sha256": sha(INSTALLED)},
                                  "imported_product_source": {"path": str(prewrite_directory / "imported-product-source.json"), "sha256": sha(prewrite_directory / "imported-product-source.json")}},
                    "stage_intake": False, "root_intake": False, "joint_passed": False})
                merge_refs(adapter_refs, {str(prewrite_adapter_path): sha(prewrite_adapter_path)})
                write(adapter_path, {
                    "schema": "zscope.stage-native-job-evidence.r35.v1", "actual_task": ACTUAL_TASK,
                    "independent_native_job_passed": True, "tool_sha256": NEW_SHA,
                    "complete_inputs_sha256": before, "results_xml": str(OUT / "original53/results.xml"),
                    "results_xml_sha256": sha(OUT / "original53/results.xml"),
                    "case_counter": report["groups"]["original53"]["case_counter"],
                    "groups": report["groups"], "reference_sha256": adapter_refs,
                    "prerequisite_ready": {"path": str(READY), "sha256": ready_sha},
                    "independent_report_path": str(OUT / "review.json"),
                    "prewrite_evidence_adapter": {"path": str(prewrite_adapter_path), "sha256": sha(prewrite_adapter_path)},
                    "legal_backup_evidence_required": True,
                    "legal_backup_test": ready["groups"]["legal_backup1"]["external_test"],
                    "legal_backup_execution": report["groups"]["legal_backup1"],
                    "legal_backup_xml": str(OUT / "legal_backup1/results.xml"),
                    "legal_backup_xml_sha256": sha(OUT / "legal_backup1/results.xml"),
                    "stage_intake": False, "root_intake": False, "joint_passed": False})
                report["stage_evidence_adapter"] = {"path": str(adapter_path), "sha256": sha(adapter_path)}
            except Exception as exc:
                report["errors"].append("adapter: " + repr(exc))
                report["passed"] = report["independent_native_job_passed"] = False
                report["status"] = "failed"
        write(OUT / "review.json", report)
    return 0 if report["passed"] else 2


if __name__ == "__main__":
    if len(sys.argv) == 5 and sys.argv[1] == "--child":
        raise SystemExit(child(sys.argv[2], sys.argv[3], Path(sys.argv[4])))
    if len(sys.argv) != 2:
        raise SystemExit("Exactly one frozen ready SHA required; no saved commands are accepted.")
    raise SystemExit(main(sys.argv[1]))

