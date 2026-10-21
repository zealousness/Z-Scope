from pathlib import Path
import json
import re


PRODUCTION_ROOTS = (
    Path("zscope/agents"),
    Path("zscope/core"),
    Path("zscope/common"),
)

FORBIDDEN_PRODUCTION_TERMS = re.compile(
    r"benchmark|fixture|ground_truth|test/range|range\s+benchmark|"
    r"\btd_run\b|real_model|REAL_MODEL|"
    r"\bISSUE41\b|\bISSUE42\b|\bISSUE43\b|ISSUE41_|ISSUE42_|ISSUE43_|"
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


def test_range_truth_function_identities_do_not_appear_in_product_scan_code() -> None:
    """Catch exact answer leakage beyond the older keyword-only guard.

    This test runs in the scorer/development environment.  The truth file is
    never imported by a product module or mounted into a formal scan.
    """

    truth = json.loads(Path("test/range/benchmark/ground_truth.json").read_text(encoding="utf-8"))
    function_names = {
        str(item.get("function") or "")
        for item in truth.get("vulnerabilities", [])
        if isinstance(item, dict) and str(item.get("function") or "")
    }
    product_roots = (
        Path("zscope/agents"),
        Path("zscope/common"),
        Path("zscope/core"),
        Path("zscope/retrieval"),
        Path("zscope/rules"),
        Path("zscope/orchestration"),
        Path("zscope/semantics"),
        Path("zscope/tools"),
    )
    offenders: list[str] = []
    if function_names:
        # One word-bounded alternation (longest names first) keeps the exact
        # match semantics of a per-name search while scanning each file once.
        pattern = re.compile(
            r"(?<![A-Za-z0-9_])(?:"
            + "|".join(
                re.escape(name) for name in sorted(function_names, key=len, reverse=True)
            )
            + r")(?![A-Za-z0-9_])"
        )
        seen: set[tuple[Path, str]] = set()
        for root in product_roots:
            for path in root.rglob("*"):
                if path.suffix not in {".py", ".md", ".yaml"} or "__pycache__" in path.parts:
                    continue
                text = path.read_text(encoding="utf-8", errors="ignore")
                for match in pattern.finditer(text):
                    if (path, match.group(0)) in seen:
                        continue
                    seen.add((path, match.group(0)))
                    offenders.append(
                        f"{path}: exact Range truth function {match.group(0)!r}"
                    )

    assert offenders == []
