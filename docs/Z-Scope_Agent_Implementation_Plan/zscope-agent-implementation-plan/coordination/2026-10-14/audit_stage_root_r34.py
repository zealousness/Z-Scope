"""Read-only reconciliation of the latest bounded Stage intake and Root floor."""
from pathlib import Path
import datetime as dt
import hashlib
import json
import sys

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
STAGE = ROOT / ".coordination/20261014/workspaces/coordinator-instance-integration-r24"
RECEIPT = ROOT / "artifacts/stage-checkpoint-contract-intake-r34-20261017/receipt.json"
OUT = ROOT / "artifacts/coordinator-stage-repairs-r33-20261017/stage-root-readonly-r34-1342.json"


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


if sys.platform != "linux" or sys.flags.optimize:
    raise RuntimeError("Use unoptimized Linux Python for this reconciliation")
receipt = json.loads(RECEIPT.read_text(encoding="utf-8"))
stage_expected, root_expected = receipt["complete_inputs_after"], receipt["root_inputs"]
stage_actual = {
    p.relative_to(STAGE).as_posix(): sha(p)
    for p in STAGE.rglob("*")
    if p.is_file()
    and p.relative_to(STAGE).parts[0] != "artifacts"
    and not any(v in {"__pycache__", ".pytest_cache", ".mypy_cache"} for v in p.parts)
    and p.suffix != ".pyc"
    and p.name != "DELIVERY.md"
}
root_mismatch = [p for p, v in root_expected.items() if not (ROOT / p).is_file() or sha(ROOT / p) != v]
gates = {
    "all_stage1082_inputs_exact": len(stage_expected) == 1082 and stage_actual == stage_expected,
    "all_root1065_inputs_exact": len(root_expected) == 1065 and not root_mismatch,
    "root_intake_not_claimed": receipt["root_intake"] is False,
}
value = {
    "actual_task": "/root",
    "checked_at": dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat(),
    "readonly_product_check": True,
    "source_receipt": str(RECEIPT),
    "source_receipt_sha256": sha(RECEIPT),
    "stage_inputs": len(stage_actual),
    "root_inputs": len(root_expected),
    "stage_missing": sorted(stage_expected.keys() - stage_actual.keys()),
    "stage_added": sorted(stage_actual.keys() - stage_expected.keys()),
    "stage_changed": sorted(p for p in stage_expected.keys() & stage_actual.keys() if stage_expected[p] != stage_actual[p]),
    "root_changed": root_mismatch,
    "gates": gates,
    "passed": all(gates.values()),
    "tests_executed": 0,
    "joint_acceptance": False,
}
if OUT.exists():
    raise RuntimeError("Preserve the existing audit receipt")
OUT.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
print(json.dumps(value, ensure_ascii=False))
raise SystemExit(0 if value["passed"] else 1)
