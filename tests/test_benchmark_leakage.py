from pathlib import Path
import re


PRODUCTION_ROOTS = (
    Path("zscope/agents"),
    Path("zscope/core"),
    Path("zscope/common"),
)

FORBIDDEN_PRODUCTION_TERMS = re.compile(
    r"benchmark|fixture|ground_truth|test/range|range\s+benchmark|"
    r"\btd_run\b|real_model|REAL_MODEL|"
    r"\bISSUE41\b|\bISSUE42\b|ISSUE41_|ISSUE42_|"
    r"\bRANGE-|\bREAL-",
    re.IGNORECASE,
)


def test_production_scan_paths_do_not_contain_benchmark_specific_terms() -> None:
    offenders: list[str] = []
    for root in PRODUCTION_ROOTS:
        for path in root.rglob("*"):
            if path.suffix not in {".py", ".md"} or "__pycache__" in path.parts:
                continue
            text = path.read_text(encoding="utf-8", errors="ignore")
            for line_number, line in enumerate(text.splitlines(), start=1):
                if FORBIDDEN_PRODUCTION_TERMS.search(line):
                    offenders.append(f"{path}:{line_number}: {line.strip()}")

    assert offenders == []
