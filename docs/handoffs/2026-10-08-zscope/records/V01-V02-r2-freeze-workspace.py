"""Regenerate the V01/V02 frozen-input section of the author workspace record.

Run from the repository root in WSL. Only the author's own record is touched.
"""

import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[4]
RECORD = Path(__file__).resolve().parent / "V01-V02-final-workspace.json"

FROZEN = [
    "zscope/core/validation/dynamic_reproduction.py",
    "zscope/core/validation/runner.py",
    "zscope/core/validation/proofs.py",
    "zscope/config/config.py",
    "zscope/config/v2.py",
    "zscope/config/runtime_defaults.yaml",
    "tests/test_dynamic_reproduction.py",
    "tests/test_dynamic_reproduction_execution.py",
    "tests/test_investigation_runtime.py",
    "tests/fixtures/dynamic_reproduction/README.md",
    "tests/fixtures/dynamic_reproduction/allocation_oversize.c",
    "tests/fixtures/dynamic_reproduction/broken_build.c",
    "tests/fixtures/dynamic_reproduction/data_race_flaky.c",
    "tests/fixtures/dynamic_reproduction/data_race_negative.c",
    "tests/fixtures/dynamic_reproduction/data_race_positive.c",
    "tests/fixtures/dynamic_reproduction/heap_overflow_negative.c",
    "tests/fixtures/dynamic_reproduction/heap_overflow_positive.c",
    "tests/fixtures/dynamic_reproduction/unrelated_crash.c",
]

FORMULA = 'sha256(concat("<file sha256>  <path>\\n" for path in sorted(files)))'


def digests() -> dict[str, str]:
    return {name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest() for name in FROZEN}


def combined(files: dict[str, str]) -> str:
    payload = "".join(f"{files[name]}  {name}\n" for name in sorted(files))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> None:
    record = json.loads(RECORD.read_text(encoding="utf-8"))
    files = digests()
    record["review_round"] = (
        "2026-10-09 fix round after records/V01-V02-reacceptance-review.md (R01-R09 + resource/platform)"
    )
    record["frozen_inputs"]["files"] = files
    record["frozen_inputs"]["file_count"] = len(files)
    record["frozen_inputs"]["combined_sha256"] = combined(files)
    record["frozen_inputs"]["combined_sha256_formula"] = FORMULA
    records = Path(__file__).resolve().parent
    record["evidence"]["sha256"] = sha(records / "V01-V02-observed-execution.json")
    record["author_recheck"]["scripts"] = {
        "docs/handoffs/2026-10-08-zscope/records/V01-V02-r2-author-recheck.py": sha(
            records / "V01-V02-r2-author-recheck.py"
        ),
        "docs/handoffs/2026-10-08-zscope/records/V01-V02-r2-author-container-recheck.py": sha(
            records / "V01-V02-r2-author-container-recheck.py"
        ),
    }
    record["author_recheck"]["results"] = {
        "docs/handoffs/2026-10-08-zscope/records/V01-V02-r2-author-recheck-validation.json": sha(
            records / "V01-V02-r2-author-recheck-validation.json"
        ),
        "docs/handoffs/2026-10-08-zscope/records/V01-V02-r2-author-container-recheck-validation.json": sha(
            records / "V01-V02-r2-author-container-recheck-validation.json"
        ),
    }
    record["deliverables"]["records"] = [
        "docs/handoffs/2026-10-08-zscope/records/V01-dynamic-reproduction.md",
        "docs/handoffs/2026-10-08-zscope/records/V02-dynamic-reproduction.md",
        "docs/handoffs/2026-10-08-zscope/records/V01-V02-acceptance-response.md",
        "docs/handoffs/2026-10-08-zscope/records/V01-V02-R01-R09-response.md",
    ]
    RECORD.write_text(
        json.dumps(record, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    print(json.dumps({
        "file_count": len(files),
        "combined_sha256": record["frozen_inputs"]["combined_sha256"],
        "evidence": record["evidence"]["sha256"],
    }, indent=2))


if __name__ == "__main__":
    main()
