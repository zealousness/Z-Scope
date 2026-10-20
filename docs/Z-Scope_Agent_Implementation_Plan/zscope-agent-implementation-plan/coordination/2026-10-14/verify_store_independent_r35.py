"""Coordinator Store acceptance, gated by a concrete final candidate intake."""
from collections import Counter
from pathlib import Path
import datetime as dt
import hashlib
import json
import os
import re
import subprocess
import sys
import xml.etree.ElementTree as ET

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
WORK = ROOT / ".coordination/20261014/workspaces/coordinator-store-active-transactions-r35"
BASE = ROOT / "artifacts/coordinator-store-active-transactions-r35-20261017"
OUT = BASE / "independent"
INTAKE = BASE / "input-freeze.json"
STORE = "zscope/orchestration/jobs/store.py"
NEW = "tests/test_store_active_transactions_r35.py"
TRACE = "tests/test_trace_callback_generation_probe_r35.py"
OLD_XML = ROOT / "artifacts/coordinator-store-queue-r26-e0560b7b2e9d/results.xml"
LONG_XML = ROOT / "artifacts/coordinator-store-receipt-bounds-probe-r26-20261016/results.xml"
PREPARATION_SHA = "4ace4b50781645f4a9053ba991be8abc8e8760784a0f6b828376db4a96a12960"
FLOOR = ROOT / "artifacts/stage-checkpoint-contract-intake-r34-20261017/receipt.json"
FLOOR_SHA = "b9d8cc7874d3f224f514ec43feebad99f75eb659a9aa194ec068545dc605a69f"
TESTS = ["tests/test_job_bound_instance_results.py", "tests/test_job_bound_completion.py", "tests/test_job_session_scheduler.py", "tests/test_scan_job_work_queue.py", "tests/test_instance_result_recovery.py", "tests/test_scan_jobs.py", NEW, TRACE]
CONFIG_NAMES = ("conftest.py", "pytest.ini", ".pytest.ini", "mypy.ini", ".mypy.ini", "tox.ini", "setup.cfg", "pyproject.toml")


def require(value, message):
    if not value:
        raise RuntimeError(message)


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def read(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def write(path, value):
    require(not path.exists(), "Preserve evidence: " + str(path))
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")


def snapshot(base):
    return {p.relative_to(base).as_posix(): sha(p) for p in base.rglob("*") if p.is_file() and p.relative_to(base).parts[0] != "artifacts" and not any(v in {"__pycache__", ".pytest_cache", ".mypy_cache"} for v in p.parts) and p.suffix != ".pyc" and p.name != "DELIVERY.md"}


def cases(path):
    return Counter((n.get("classname", ""), n.get("name", "")) for n in ET.parse(path).getroot().iter("testcase"))


def counts(path):
    tree = ET.parse(path).getroot()
    return dict(tests=len(list(tree.iter("testcase"))), failures=len(list(tree.iter("failure"))), errors=len(list(tree.iter("error"))), skipped=len(list(tree.iter("skipped"))))


def rows(counter):
    return [list(key) + [count] for key, count in sorted(counter.items())]


def merge_equal(target, source):
    for name, digest in source.items():
        require(name not in target or target[name] == digest, "Conflicting reference: " + name)
        target[name] = digest


def host():
    tool = Path("/home/zeal/.cache/zscope-build-context/install/bin/zscope-clang-indexer")
    require(sha(tool) == "d39cbe72fafad1fbfa989a51346cdf4785101e32855c0ee0d11a1e2748263399", "old tool changed")
    result = subprocess.run(["ldd", str(tool)], capture_output=True, text=True, timeout=15)
    require(result.returncode == 0 and "not found" not in result.stdout + result.stderr, "unresolved native host library")
    libraries = {Path(p) for p in re.findall(r"/[^\s()]+", result.stdout)}
    require(libraries and all(p.is_file() for p in libraries), "actual ldd payload missing")
    files = libraries | {tool, Path("/usr/include/stdlib.h"), Path("/usr/include/features.h")}
    paths = set(files)
    for header in (Path("/usr/include/stdlib.h"), Path("/usr/include/features.h")):
        paths.update(header.parents)
    return dict(files={str(p): dict(sha256=sha(p), physical=str(p.resolve(strict=True))) for p in files}, installation={str(p): dict(uid=p.lstat().st_uid, gid=p.lstat().st_gid, mode=p.lstat().st_mode, physical=str(p.resolve(strict=True)), symlink=os.readlink(p) if p.is_symlink() else None) for p in paths})


def main():
    if sys.platform != "linux" or sys.flags.optimize or sys.executable != "/home/zeal/venv313/bin/python" or Path.cwd().resolve() != WORK:
        raise RuntimeError("Fixed unoptimized Linux Python and independent cwd required")
    if any(os.environ.get(name) for name in ("PYTHONOPTIMIZE", "PYTEST_ADDOPTS", "PYTEST_PLUGINS")):
        raise RuntimeError("External optimization and test plugins/options forbidden")
    sys.path.insert(0, str(HERE))
    from root_runtime_preflight_r23 import inspect_root_runtime
    runtime = inspect_root_runtime(require_slot=True)
    require(sha(BASE / "preparation.json") == PREPARATION_SHA and sha(FLOOR) == FLOOR_SHA, "original prepared Stage/Root floor receipt changed")
    prep, frozen = read(BASE / "preparation.json"), read(INTAKE)
    floor = read(FLOOR)
    require(prep["source_floor_receipt_sha256"] == FLOOR_SHA and prep["complete_stage_floor"] == floor["complete_inputs_after"] and prep["root_inputs"] == floor["root_inputs"], "prepared source floor differs from the fixed original intake")
    require(frozen["actual_task"] == "/root" and frozen["status"] == "ready" and frozen["source_review_passed"] is True, "concrete candidate intake/source review pending")
    require(frozen["launcher_sha256"] == sha(Path(__file__)), "unreviewed launcher bytes")
    before = snapshot(WORK)
    require(len(before) == 1084 and before == frozen["complete_inputs"], "full final independent input set/SHA mismatch")
    require(set(before) == set(prep["complete_stage_floor"]) | {NEW, TRACE}, "unexpected input additions/removals")
    require(all(before[name] == digest for name, digest in prep["complete_stage_floor"].items() if name != STORE), "readonly Stage floor changed")
    require(frozen["owned_sources_sha256"] == {name: before[name] for name in (STORE, NEW, TRACE)}, "reviewed owned source/test mismatch")
    refs = {}
    merge_equal(refs, frozen["reference_sha256"])
    merge_equal(refs, {str(BASE / "preparation.json"): PREPARATION_SHA, str(FLOOR): FLOOR_SHA})
    merge_equal(refs, {str(Path(__file__)): frozen["launcher_sha256"], str(INTAKE): sha(INTAKE), str(BASE / "preparation.json"): sha(BASE / "preparation.json"), str(HERE / "test_slot.py"): "7fd4e683bb9e7523a3247eb5efd21ff5a130ebc83375933f32290f4007f9c158", str(HERE / "root_runtime_preflight_r23.py"): "37bdbfe76401407280598d39f89424211bb418ff8469b1dc0b2bfe89ce10b4e3", str(OLD_XML): "e09593e32f8d472c3eea73da38b44e0b7e8b7b2460071925eef18ae0862f5770", str(LONG_XML): "1c16b0b44a1f26672c0cc1e6c19ec55aac42c58c68b392727dc4d3c6deb83710"})
    source_review = read(frozen["source_review_path"])
    require(str(Path(frozen["source_review_path"])) in refs and source_review["source_review_passed"] is True and source_review["owned_sources_sha256"] == frozen["owned_sources_sha256"], "missing concrete final three-source review")
    expected = Counter({(row[0], row[1]): row[2] for row in frozen["regression_case_counter"]})
    expected_trace = Counter({(row[0], row[1]): row[2] for row in frozen["trace_case_counter"]})
    expected_old, expected_long = cases(OLD_XML), cases(LONG_XML)
    require(sum(expected.values()) == len(expected) == 369, "actual producer regression Counter must contain 369 unique cases")
    require(sum(expected_trace.values()) == len(expected_trace) == 5 and all(expected[key] == value for key, value in expected_trace.items()), "permanent trace five absent from actual regression")
    require(sum(expected_old.values()) == 227 and all(expected[key] == value for key, value in expected_old.items()), "old227 original raw Counter omitted")
    require(sum(expected_long.values()) == 1, "original long-USR probe changed")
    producer_counters = {}
    for label in ("regression", "trace"):
        evidence = frozen["producer_" + label]
        paths = {}
        for name in ("results_xml", "before_snapshot", "after_snapshot", "receipt"):
            path = Path(evidence[name])
            merge_equal(refs, {str(path): evidence[name + "_sha256"]})
            require(sha(path) == evidence[name + "_sha256"], "producer actual evidence changed: " + label + "/" + name)
            paths[name] = path
        producer_counts = counts(paths["results_xml"])
        require(producer_counts["tests"] > 0 and producer_counts["failures"] == producer_counts["errors"] == producer_counts["skipped"] == 0, "producer actual XML is not green")
        producer_counters[label] = cases(paths["results_xml"])
        first, last = read(paths["before_snapshot"]), read(paths["after_snapshot"])
        require(first["source"] == last["source"], "producer full source changed during execution")
        checked_sources = (STORE, NEW, TRACE) if label == "trace" else (STORE, NEW)
        require(all(first["source"][name] == before[name] for name in checked_sources), "producer actual final source is not the independently selected source")
        raw = read(paths["receipt"])
        require(raw["actual_task"] == "/root/stage_currentness_repair_r33" and bool(raw["gates"]) and all(value is True for value in raw["gates"].values()), "producer raw receipt failed actual evidence guards")
        if "commands" in raw:
            require(raw["commands"] and all(row["returncode"] == 0 for row in raw["commands"]), "producer actual command failure")
        else:
            require(raw["pytest_returncode"] == 0, "producer actual trace pytest failure")
        raw_counter = raw.get("case_counters", {}).get("actual", raw.get("actual_counter"))
        require(raw_counter == rows(producer_counters[label]), "producer actual receipt/XML raw Counter differs")
    require(sum(producer_counters["regression"].values()) == 364 and sum(producer_counters["trace"].values()) == 5, "producer actual regression/trace totals differ")
    require(not (producer_counters["regression"].keys() & producer_counters["trace"].keys()), "producer final trace would duplicate regression identities")
    require(expected == producer_counters["regression"] + producer_counters["trace"] and expected_trace == producer_counters["trace"], "future freeze arrays differ from the actual producer XML Counters")
    stage = ROOT / ".coordination/20261014/workspaces/coordinator-instance-integration-r24"

    def guard():
        return dict(source=snapshot(WORK), configurations={p.relative_to(WORK).as_posix(): sha(p) for basename in CONFIG_NAMES for p in WORK.rglob(basename) if p.is_file()}, root={name: sha(ROOT / name) for name in prep["root_inputs"]}, stage=snapshot(stage), references={name: sha(name) for name in refs}, host=host())

    original = guard()
    require(original["source"] == before and original["configurations"] == {"pyproject.toml": before["pyproject.toml"]}, "source/config preflight changed")
    require(original["root"] == prep["root_inputs"] and len(original["root"]) == 1065 and original["stage"] == prep["complete_stage_floor"], "Root/Stage preflight changed")
    require(original["references"] == refs, "frozen references mismatch")
    commands = [
        [sys.executable, "-m", "pytest", "-q", f"--rootdir={WORK}", f"--confcutdir={WORK}", *TESTS, f"--junitxml={OUT / 'results.xml'}"],
        [sys.executable, "-m", "pytest", "-q", f"--rootdir={WORK}", f"--confcutdir={WORK}", TRACE, f"--junitxml={OUT / 'trace.xml'}"],
        [sys.executable, "-m", "pytest", "-q", f"--rootdir={WORK}", f"--confcutdir={WORK}", "tests/test_job_bound_instance_results.py::test_legal_long_usr_cannot_publish_a_truncated_sql_receipt", f"--junitxml={OUT / 'long-usr.xml'}"],
        [sys.executable, "-m", "compileall", "-f", "-q", "zscope", "scripts", "test", "tests"],
        [sys.executable, "-m", "mypy", "zscope"],
        [sys.executable, "-m", "mypy", "--no-incremental", "zscope"],
        [sys.executable, "-m", "mypy", "scripts/agent_plan_evaluation.py"],
        [sys.executable, "-m", "black", "--check", STORE, NEW, TRACE],
    ]
    OUT.mkdir(exist_ok=False)
    write(OUT / "preflight.json", dict(actual_task="/root", started_at=dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat(), inputs=original, runtime=runtime, commands=commands, scope="Real SQLite/queue Store acceptance only; not new native or full scan acceptance"))
    env = os.environ.copy()
    env["Z_SCOPE_TEST_CLANG_INDEXER"] = "/home/zeal/.cache/zscope-build-context/install/bin/zscope-clang-indexer"
    results = []
    for index, argv in enumerate(commands):
        started = dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat()
        with (OUT / f"command-{index}.log").open("w", encoding="utf-8") as stream:
            result = subprocess.run(argv, cwd=WORK, env=env, stdout=stream, stderr=subprocess.STDOUT)
        results.append(dict(argv=argv, returncode=result.returncode, started_at=started, finished_at=dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat()))
        write(OUT / f"command-{index}.json", results[-1])
        print(json.dumps(dict(command_index=index, returncode=result.returncode)), flush=True)
    after_error = None
    try:
        after = guard()
    except (OSError, RuntimeError, ValueError) as error:
        after_error = repr(error)
        after = {name: None for name in original}
    junit, actual, parse_errors = {}, {}, {}
    for name in ("results.xml", "trace.xml", "long-usr.xml"):
        try:
            junit[name], actual[name] = counts(OUT / name), cases(OUT / name)
        except (OSError, ET.ParseError, ValueError) as error:
            parse_errors[name] = repr(error)
            junit[name], actual[name] = dict(tests=0, failures=0, errors=0, skipped=0), Counter()
    gates = dict(full_source_guard=after["source"] == original["source"], config_guard=after["configurations"] == original["configurations"], root_guard=after["root"] == original["root"], stage_guard=after["stage"] == original["stage"], references_guard=after["references"] == refs, host_guard=after["host"] == original["host"], all_commands_zero=all(row["returncode"] == 0 for row in results), zero_fail_error_skip=all(row["tests"] > 0 and row["failures"] == row["errors"] == row["skipped"] == 0 for row in junit.values()), regression_counter_exact=actual["results.xml"] == expected, trace_counter_exact=actual["trace.xml"] == expected_trace, long_usr_counter_exact=actual["long-usr.xml"] == expected_long, old227_exact=all(actual["results.xml"][key] == value for key, value in expected_old.items()))
    gates["actual_xml_present_and_parseable"] = not parse_errors
    gates["after_guard_readable"] = after_error is None
    record = dict(actual_task="/root", finished_at=dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat(), commands=results, junit=junit, gates=gates, passed=all(gates.values()), source_before=before, source_after=after["source"], owned_sources_sha256={name: before[name] for name in (STORE, NEW, TRACE)}, reference_sha256=refs, inputs_before=original, inputs_after=after, case_counters={name: rows(counter) for name, counter in actual.items()}, junit_parse_errors=parse_errors, after_guard_error=after_error, stage_intake=False, root_intake=False, new_native_acceptance=False, full_scan_acceptance=False)
    write(OUT / "review.json", record)
    print(json.dumps(dict(passed=record["passed"], junit=junit, gates=gates)))
    return 0 if record["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
