"""Intake only final independently source-reviewed Store bytes and real producer evidence."""
import argparse
from collections import Counter
from pathlib import Path
import datetime as dt
import hashlib
import json
import shutil
import sys
import xml.etree.ElementTree as ET

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
PRODUCER = ROOT / ".coordination/20261014/workspaces/store-active-transactions-r35"
WORK = ROOT / ".coordination/20261014/workspaces/coordinator-store-active-transactions-r35"
BASE = ROOT / "artifacts/coordinator-store-active-transactions-r35-20261017"
NAMES = ("zscope/orchestration/jobs/store.py", "tests/test_store_active_transactions_r35.py", "tests/test_trace_callback_generation_probe_r35.py")
VERIFY = HERE / "verify_store_independent_r35.py"
VERIFY_SHA = "932c5c2b296b8f9e4f376adba3090d54cc9f89de7199e4a98160e9fd74955540"
sha = lambda p: hashlib.sha256(Path(p).read_bytes()).hexdigest()
read = lambda p: json.loads(Path(p).read_text(encoding="utf-8"))


def require(value, message):
    if not value:
        raise RuntimeError(message)


def snapshot(base):
    return {p.relative_to(base).as_posix(): sha(p) for p in base.rglob("*") if p.is_file() and p.relative_to(base).parts[0] != "artifacts" and not any(v in {"__pycache__", ".pytest_cache", ".mypy_cache"} for v in p.parts) and p.suffix != ".pyc" and p.name != "DELIVERY.md"}


def cases(path):
    return Counter((n.get("classname", ""), n.get("name", "")) for n in ET.parse(path).getroot().iter("testcase"))


def rows(counter):
    return [list(key) + [count] for key, count in sorted(counter.items())]


def evidence(run, label, owned):
    require(run.resolve(strict=True).is_relative_to(PRODUCER / "artifacts/store_active_transactions_r35"), "wrong producer phase directory")
    xmls = list(run.glob("*.xml"))
    require(len(xmls) == 1, "each actual phase must contain one original XML")
    paths = dict(results_xml=xmls[0], before_snapshot=run / "before.json", after_snapshot=run / "after.json", receipt=run / "receipt.json")
    raw = read(paths["receipt"])
    require(raw["actual_task"] == "/root/stage_currentness_repair_r33" and bool(raw["gates"]) and all(value is True for value in raw["gates"].values()), "producer actual task/guards failed")
    if "commands" in raw:
        require(raw["commands"] and all(row["returncode"] == 0 for row in raw["commands"]), "producer actual phase command failed")
    else:
        require(raw["pytest_returncode"] == 0, "producer actual trace pytest failed")
    tree = ET.parse(paths["results_xml"]).getroot()
    require(not list(tree.iter("failure")) and not list(tree.iter("error")) and not list(tree.iter("skipped")), "producer XML is not all green")
    counter = cases(paths["results_xml"])
    require(sum(counter.values()) == len(counter) == (364 if label == "regression" else 5), "actual producer Counter total differs")
    require(raw.get("case_counters", {}).get("actual", raw.get("actual_counter")) == rows(counter), "producer receipt/XML actual Counter mismatch")
    before, after = read(paths["before_snapshot"]), read(paths["after_snapshot"])
    require(before["source"] == after["source"] and len(before["source"]) == 1084, "final producer phase does not preserve the complete 1084 inputs")
    require(all(before["source"][name] == digest for name, digest in owned.items()), "producer phase source differs from reviewed final three files")
    result = {}
    for name, path in paths.items():
        result[name], result[name + "_sha256"] = str(path), sha(path)
    return result, counter, before["source"]


def main():
    parser = argparse.ArgumentParser(__doc__)
    parser.add_argument("--source-review", type=Path, required=True)
    parser.add_argument("--source-review-sha256", required=True)
    parser.add_argument("--regression", type=Path, required=True)
    parser.add_argument("--trace", type=Path, required=True)
    args = parser.parse_args()
    if sys.platform != "linux" or sys.flags.optimize:
        raise RuntimeError("Unoptimized Linux Python required")
    require(sha(BASE / "preparation.json") == "4ace4b50781645f4a9053ba991be8abc8e8760784a0f6b828376db4a96a12960", "prepared independent floor changed")
    require(sha(VERIFY) == VERIFY_SHA, "reviewed verifier changed")
    require(sha(args.source_review) == args.source_review_sha256, "source review changed")
    source_review = read(args.source_review)
    require(source_review["actual_task"] == "/root/consumer_source_review_r28" and source_review["source_review_passed"] is True, "final independent source review missing")
    owned = source_review["owned_sources_sha256"]
    require(set(owned) == set(NAMES) and all(sha(PRODUCER / name) == digest for name, digest in owned.items()), "final live producer three files differ from reviewed source")
    regression, counter, final_sources = evidence(args.regression, "regression", owned)
    trace, trace_counter, trace_sources = evidence(args.trace, "trace", owned)
    require(final_sources == trace_sources == snapshot(PRODUCER), "actual final producer inputs differ across phases or since validation")
    require(not (counter.keys() & trace_counter.keys()), "producer trace duplicates regression identities")
    prep = read(BASE / "preparation.json")
    require(snapshot(WORK) == prep["complete_stage_floor"], "independent prepared workspace was changed before intake")
    stage = ROOT / ".coordination/20261014/workspaces/coordinator-instance-integration-r24"
    require(snapshot(stage) == prep["complete_stage_floor"], "Stage changed")
    require(all(sha(ROOT / p) == v for p, v in prep["root_inputs"].items()), "Root changed")
    for name in NAMES:
        target = WORK / name
        require(not target.is_symlink() and target.parent.resolve(strict=True).is_relative_to(WORK), "unsafe independent target")
        if name != NAMES[0]:
            require(not target.exists(), "new independent test already exists")
    require(not (BASE / "input-freeze.json").exists() and not (BASE / "candidate-intake.json").exists(), "preserve previous intake")
    for name in NAMES:
        shutil.copyfile(PRODUCER / name, WORK / name)
    actual = snapshot(WORK)
    require(actual == final_sources and len(actual) == 1084, "actual independent copy differs from final tested producer")
    require(snapshot(stage) == prep["complete_stage_floor"] and all(sha(ROOT / p) == v for p, v in prep["root_inputs"].items()), "Root or Stage changed during independent copy")
    refs = {str(args.source_review): args.source_review_sha256, str(VERIFY): VERIFY_SHA,
        str(HERE / "test_slot.py"): "7fd4e683bb9e7523a3247eb5efd21ff5a130ebc83375933f32290f4007f9c158",
        str(HERE / "root_runtime_preflight_r23.py"): "37bdbfe76401407280598d39f89424211bb418ff8469b1dc0b2bfe89ce10b4e3",
        str(ROOT / "artifacts/coordinator-store-independent-launcher-source-review-r35-20261017/revised-review.json"): "f1f974e7deb5f359335238b5ee73f76cd2ead1e38ca1cf4665a8d68071689280"}
    require(all(sha(name) == digest for name, digest in refs.items()), "final evidence references changed")
    for item in (regression, trace):
        for key in ("results_xml", "before_snapshot", "after_snapshot", "receipt"):
            require(item[key] not in refs or refs[item[key]] == item[key + "_sha256"], "reference collision")
            refs[item[key]] = item[key + "_sha256"]
    freeze = dict(actual_task="/root", status="ready", prepared_at=dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat(),
        source_review_passed=True, source_review_path=str(args.source_review), owned_sources_sha256=owned,
        complete_inputs=actual, launcher_sha256=VERIFY_SHA, reference_sha256=refs,
        producer_regression=regression, producer_trace=trace,
        regression_case_counter=rows(counter + trace_counter), trace_case_counter=rows(trace_counter),
        stage_intake=False, root_intake=False, independent_acceptance=False)
    (BASE / "input-freeze.json").write_text(json.dumps(freeze, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
    intake = dict(actual_task="/root", prepared_at=freeze["prepared_at"], input_freeze_sha256=sha(BASE / "input-freeze.json"),
        owned_sources_sha256=owned, complete_inputs=actual, original364_and_permanent5_preserved=True,
        stage_root_unchanged=True, independent_tests_executed=False, independent_acceptance=False)
    (BASE / "candidate-intake.json").write_text(json.dumps(intake, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
    print(json.dumps(dict(prepared_at=freeze["prepared_at"], complete_inputs=1084, ready_for_independent=True, stage_root_unchanged=True)))


if __name__ == "__main__":
    main()
