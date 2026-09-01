#!/usr/bin/env python3
"""Enforce Z-SCOPE 2.0 product/truth/scorer change separation."""

from __future__ import annotations

import argparse
import subprocess
import sys
from collections import defaultdict
from pathlib import PurePosixPath
from typing import Iterable, Mapping, Sequence


DOMAINS = ("product", "truth_fixture", "scorer")

# P6 owns a benchmark *control plane* alongside the product changes that it
# qualifies.  These files orchestrate isolated runs, provider/runtime binding,
# recovery, and evidence validation; they do not define Range answers or the
# frozen legacy/v16 matching semantics.  Keep this list deliberately narrow so
# adding another benchmark module requires an explicit governance decision.
#
# ``zscope/benchmarking/runner.py`` is shared with the legacy scorer wrapper,
# but P6 modifies only its producer/telemetry paths.  The byte-exact
# ``score_artifact`` function remains frozen by
# ``tests/test_p6_balanced_orchestrator.py`` while the canonical scorer engines
# below continue to classify as ``scorer``.
PRODUCT_COMPATIBLE_P6_CONTROL_PLANE_PATHS = frozenset(
    {
        "scripts/external_benchmark.py",
        "zscope/benchmarking/isolation.py",
        "zscope/benchmarking/provider_runtime.py",
        "zscope/benchmarking/runner.py",
    }
)
PRODUCT_COMPATIBLE_P6_CONTROL_PLANE_PREFIXES = (
    ".github/actions/classify-p6-job-failure/",
    ".github/actions/validate-p6-artifact/",
    ".github/workflows/p6-",
    "containers/p6/",
    "scripts/download_p6_",
    "scripts/p6_",
    "scripts/project_p6_",
    "scripts/qualify_p6_",
    "scripts/run_p6_",
    "scripts/validate_p6_",
    "zscope/benchmarking/p6_",
)


def _normalized(path: str) -> str:
    value = path.strip().replace("\\", "/")
    while value.startswith("./"):
        value = value[2:]
    return str(PurePosixPath(value)) if value else ""


def classify_path(path: str) -> str | None:
    """Return the governed domain for a repository-relative path."""

    value = _normalized(path)
    if not value:
        return None

    if value in PRODUCT_COMPATIBLE_P6_CONTROL_PLANE_PATHS or value.startswith(
        PRODUCT_COMPATIBLE_P6_CONTROL_PLANE_PREFIXES
    ):
        return "product"

    scorer_prefixes = (
        "zscope/benchmarking/",
        "scripts/analyze_range_",
        "scripts/build_postscore_",
        "scripts/compare_range_",
        "scripts/evaluate_range_",
        "scripts/evaluate_release_candidate.py",
        "scripts/range_fp_",
        "scripts/range_perf_",
        "scripts/score_",
    )
    scorer_paths = {
        # This entry point is exclusively the bundled benchmark control plane;
        # it never participates in a product scan. Classifying it with its
        # implementation preserves product/scorer separation for protocol work.
        "zscope/cli/benchmark.py",
    }
    if value in scorer_paths or value.startswith(scorer_prefixes):
        return "scorer"

    truth_paths = {
        "test/range/benchmark/ground_truth.json",
        "test/java_range/benchmark/ground_truth.json",
    }
    truth_prefixes = (
        "test/range/benchmark/v16/",
        "test/java_range/benchmark/v16/",
        "test/range/src/",
        "test/java_range/src/",
        "docs/benchmark-maintenance/range/",
        "docs/benchmark-maintenance/java-range/",
        "scripts/generate_range_v16_",
        "scripts/validate_range_v16_",
    )
    if value in truth_paths or value.startswith(truth_prefixes):
        return "truth_fixture"

    if value.startswith("zscope/"):
        return "product"
    return None


def classify_changes(paths: Iterable[str]) -> Mapping[str, tuple[str, ...]]:
    grouped: dict[str, list[str]] = defaultdict(list)
    for path in paths:
        domain = classify_path(path)
        if domain is not None:
            grouped[domain].append(_normalized(path))
    return {domain: tuple(sorted(set(grouped.get(domain, ())))) for domain in DOMAINS}


def scope_errors(paths: Iterable[str]) -> list[str]:
    grouped = classify_changes(paths)
    active = [domain for domain in DOMAINS if grouped[domain]]
    if len(active) <= 1:
        return []
    details = "; ".join(f"{domain}=[{', '.join(grouped[domain])}]" for domain in active)
    return [
        "Z-SCOPE 2.0 change-scope violation: product, truth/fixture, and scorer "
        f"changes must be split into separate changes; {details}"
    ]


def changed_paths(base: str, head: str) -> list[str]:
    if not base or set(base) == {"0"}:
        base = f"{head}^"
    completed = subprocess.run(
        ["git", "diff", "--name-only", "--diff-filter=ACMRTUXB", base, head, "--"],
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
    return [line for line in completed.stdout.splitlines() if line.strip()]


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base", help="base Git revision")
    parser.add_argument("--head", default="HEAD", help="head Git revision")
    parser.add_argument(
        "--path",
        action="append",
        default=[],
        help="explicit changed path; repeat to avoid invoking Git",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.path:
        paths = args.path
    elif args.base:
        paths = changed_paths(args.base, args.head)
    else:
        raise SystemExit("provide --base/--head or at least one --path")
    errors = scope_errors(paths)
    if errors:
        for error in errors:
            print(error, file=sys.stderr)
        return 2
    grouped = classify_changes(paths)
    active = [domain for domain in DOMAINS if grouped[domain]]
    print(f"Z-SCOPE 2.0 change scope: {active[0] if active else 'governance_or_docs'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
