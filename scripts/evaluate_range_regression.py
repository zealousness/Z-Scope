"""Evaluate Z-SCOPE range benchmark reports or deterministic candidate coverage."""

from __future__ import annotations

import argparse
import importlib.util
import json
from pathlib import Path
from typing import Any, Dict, List, Optional

from zscope.core.deterministic_candidates import DeterministicCandidateGenerator
from zscope.retrieval.code_index import CodeIndex


def _load_json(path: Path) -> Dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _load_scorer(benchmark_dir: Path):
    scorer_path = benchmark_dir / "evaluate_zscope_report.py"
    spec = importlib.util.spec_from_file_location("range_scorer", scorer_path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Unable to load benchmark scorer: {scorer_path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _deterministic_report(project_root: Path, entries_path: Path) -> Dict[str, Any]:
    entries = _load_json(entries_path).get("functions", [])
    compile_commands = project_root / "build" / "compile_commands.json"
    index = CodeIndex(
        project_root,
        compile_commands_path=compile_commands if compile_commands.exists() else None,
        source_root=project_root,
    )
    generator = DeterministicCandidateGenerator()
    issues: List[Dict[str, Any]] = []
    missing: List[str] = []
    for entry in entries:
        func = str(entry.get("function_name") or "")
        if not func:
            continue
        impl = index.get_function_impl(func)
        if not impl:
            missing.append(func)
            continue
        issues.extend(generator.generate_issues(func, impl["code"], impl["file"]))
    return {
        "entry_function": "range_deterministic_candidates",
        "overall_verdict": "issues_found" if issues else "no_issue_found",
        "issues": issues,
        "metadata": {
            "mode": "deterministic_candidate_coverage",
            "missing_entry_impls": missing,
        },
    }


def evaluate_range_regression(
    *,
    project_root: Path = Path("test/range"),
    benchmark_dir: Optional[Path] = None,
    truth_path: Optional[Path] = None,
    entries_path: Optional[Path] = None,
    report_path: Optional[Path] = None,
    deterministic_candidates: bool = False,
    line_tolerance: int = 5,
) -> Dict[str, Any]:
    benchmark_dir = benchmark_dir or project_root / "benchmark"
    truth_path = truth_path or benchmark_dir / "ground_truth.json"
    entries_path = entries_path or benchmark_dir / "entries.json"
    scorer = _load_scorer(benchmark_dir)

    if deterministic_candidates:
        report = _deterministic_report(project_root, entries_path)
    elif report_path:
        report = _load_json(report_path)
    else:
        raise ValueError("Pass report_path or deterministic_candidates=True")

    result = scorer.score(report, _load_json(truth_path), line_tolerance)
    if deterministic_candidates:
        result["candidate_coverage_mode"] = True
        result["missing_entry_impls"] = report.get("metadata", {}).get("missing_entry_impls", [])
    return result


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--project-root", type=Path, default=Path("test/range"))
    parser.add_argument("--benchmark-dir", type=Path, default=None)
    parser.add_argument("--truth", type=Path, default=None)
    parser.add_argument("--entries", type=Path, default=None)
    parser.add_argument("--report", type=Path, default=None)
    parser.add_argument("--deterministic-candidates", action="store_true")
    parser.add_argument("--line-tolerance", type=int, default=5)
    parser.add_argument("--output", type=Path, default=None)
    args = parser.parse_args()

    result = evaluate_range_regression(
        project_root=args.project_root,
        benchmark_dir=args.benchmark_dir,
        truth_path=args.truth,
        entries_path=args.entries,
        report_path=args.report,
        deterministic_candidates=args.deterministic_candidates,
        line_tolerance=args.line_tolerance,
    )

    output = json.dumps(result, ensure_ascii=False, indent=2)
    if args.output:
        args.output.write_text(output + "\n", encoding="utf-8")
    print(output)


if __name__ == "__main__":
    main()
