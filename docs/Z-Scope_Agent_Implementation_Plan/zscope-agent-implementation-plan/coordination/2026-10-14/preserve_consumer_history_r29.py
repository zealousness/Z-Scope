"""Supplement the failure freeze with all129 producer history files."""
from pathlib import Path
import datetime as dt
import hashlib
import json
import shutil

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
ART = ROOT / ".coordination/20261014/workspaces/astra-instance-consumers-r25/artifacts/instance-consumers-r25"
OUT = ROOT / "artifacts/astra-consumer-failure-freeze-r28-20261017"


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


before = {path.relative_to(ART).as_posix(): sha(path) for path in ART.rglob("*") if path.is_file() and "__pycache__" not in path.parts and path.suffix != ".pyc"}
assert len(before) == 129
review = json.loads((ROOT / "artifacts/astra-consumers-source-review-r28-20261017/review.json").read_text(encoding="utf-8"))
assert before == {row["path"]: row["sha256"] for row in review["hash_guard"]["artifacts"]["files"]}
DEST = OUT / "complete-producer-history"
DEST.mkdir(exist_ok=False)
for relative, digest in before.items():
    dest = DEST / relative
    dest.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(ART / relative, dest)
    assert sha(dest) == digest
after = {path.relative_to(ART).as_posix(): sha(path) for path in ART.rglob("*") if path.is_file() and "__pycache__" not in path.parts and path.suffix != ".pyc"}
assert before == after
proof = dict(recorded_at=dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat(), actual_task="/root", parent_failure_receipt="review.json", parent_failure_receipt_sha256=sha(OUT / "review.json"), original_artifacts_unchanged=True, all129_producer_artifacts_copied=True, copied_files=before, note="The initial39-file freeze retained the producer's12 declared release artifacts plus owned sources and independent evidence. This supplement also freezes all intermediate failures and interruption files; the original remains frozen. Neither receipt is overwritten.")
(OUT / "history-preservation.json").write_text(json.dumps(proof, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
print(json.dumps(dict(history_files=len(before),receipt=(OUT / "history-preservation.json").relative_to(ROOT).as_posix())))
