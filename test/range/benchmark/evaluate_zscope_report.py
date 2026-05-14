#!/usr/bin/env python3
"""Score a Z-SCOPE JSON report against the range benchmark ground truth."""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any


def load_json(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as f:
        data = json.load(f)
    if not isinstance(data, dict):
        raise SystemExit(f"{path} must contain a JSON object")
    return data


def flatten_text(value: Any) -> str:
    if isinstance(value, dict):
        return " ".join(flatten_text(v) for v in value.values())
    if isinstance(value, list):
        return " ".join(flatten_text(v) for v in value)
    if value is None:
        return ""
    return str(value)


def report_issues(report: dict[str, Any]) -> list[dict[str, Any]]:
    if isinstance(report.get("issues"), list):
        return [x for x in report["issues"] if isinstance(x, dict)]
    results = report.get("results")
    if isinstance(results, dict):
        issues: list[dict[str, Any]] = []
        for result in results.values():
            if isinstance(result, dict) and isinstance(result.get("issues"), list):
                issues.extend(x for x in result["issues"] if isinstance(x, dict))
        return issues
    if isinstance(report.get("function_results"), list):
        issues = []
        for result in report["function_results"]:
            if isinstance(result, dict) and isinstance(result.get("issues"), list):
                issues.extend(x for x in result["issues"] if isinstance(x, dict))
        return issues
    return []


def normalize_path(text: str) -> str:
    return text.replace("\\", "/").lower()


def issue_file_and_line(issue: dict[str, Any]) -> tuple[str, int | None]:
    text = flatten_text(issue)
    norm = normalize_path(text)
    file_match = re.search(r"(src/[a-z0-9_./-]+\.c)", norm)
    line = None
    location = str(issue.get("location") or issue.get("file") or "")
    line_match = re.search(r":(\d+)(?:-\d+)?\b", location)
    if not line_match:
        line_match = re.search(r"\bline\s+(\d+)\b", text, flags=re.IGNORECASE)
    if line_match:
        line = int(line_match.group(1))
    return (file_match.group(1) if file_match else normalize_path(location), line)


def line_near(line: int | None, truth: dict[str, Any], tolerance: int) -> bool:
    if line is None:
        return False
    start = int(truth["line"])
    end = int(truth.get("end_line", start))
    if start - tolerance <= line <= end + tolerance:
        return True
    secondary = truth.get("secondary_line")
    if secondary is None:
        return False
    secondary_end = int(truth.get("secondary_end_line", secondary))
    return int(secondary) - tolerance <= line <= secondary_end + tolerance


def file_matches(issue_file: str, truth: dict[str, Any]) -> bool:
    issue_file = normalize_path(issue_file)
    primary = normalize_path(str(truth["file"]))
    secondary = normalize_path(str(truth.get("secondary_file", "")))
    return primary in issue_file or bool(secondary and secondary in issue_file)


def text_matches(issue: dict[str, Any], truth: dict[str, Any]) -> bool:
    text = flatten_text(issue).lower()
    cwe = str(truth.get("cwe", "")).lower()
    category = str(truth.get("category", "")).replace("_", " ").lower()
    keywords = [str(k).lower() for k in truth.get("keywords", [])]
    keyword_hits = sum(1 for k in keywords if k in text)
    return bool(cwe and cwe in text) or bool(category and category in text) or keyword_hits >= 2


def issue_function(issue: dict[str, Any]) -> str:
    return str(issue.get("function") or issue.get("func_name") or "").lower()


def function_matches(issue: dict[str, Any], truth: dict[str, Any]) -> bool:
    expected_values = [
        str(truth.get("function") or "").lower(),
        str(truth.get("secondary_function") or "").lower(),
    ]
    expected = [value for value in expected_values if value]
    if not expected:
        return True
    actual = issue_function(issue)
    if actual in expected:
        return True
    text = flatten_text(issue).lower()
    return any(value in text for value in expected)


def category_matches(issue: dict[str, Any], truth: dict[str, Any]) -> bool:
    text = flatten_text(issue).replace("_", " ").replace("-", " ").lower()
    cwe = str(truth.get("cwe", "")).lower()
    category = str(truth.get("category", "")).replace("_", " ").lower()
    aliases = {
        "integer overflow": ("integer overflow", "overflow", "wrap", "cwe-190"),
        "bounds": ("bounds", "out of bounds", "buffer overflow", "buffer overread", "overread", "over read", "cwe-125", "cwe-787"),
        "format string": ("format string", "cwe-134"),
        "deadlock": ("deadlock", "lock order", "cwe-833"),
        "infinite loop": ("infinite loop", "self loop", "self-referential", "cycle", "cwe-835"),
        "log amplification": ("log amplification", "log storm", "resource exhaustion", "cwe-400"),
        "key truncation": ("key truncation", "truncated key", "partial comparison", "cwe-187"),
        "double free": ("double free", "cwe-415"),
        "memory leak": ("memory leak", "resource leak", "leak", "cwe-401"),
        "race": ("race", "data race", "cwe-362"),
        "toctou": ("toctou", "check use", "cwe-367"),
        "command injection": ("command injection", "shell injection", "cwe-78"),
        "null pointer dereference": ("null pointer", "null dereference", "cwe-476"),
        "object publication": ("object publication", "half initialized", "published", "cwe-362"),
        "use after free": ("use after free", "use-after-free", "uaf", "dangling", "cwe-416"),
        "refcount race": ("refcount", "reference count", "ref count", "race", "cwe-362"),
        "held lock callback": ("callback", "under lock", "held lock", "deadlock", "cwe-667"),
        "stack escape": ("stack escape", "stack address", "pthread_create", "cwe-562"),
        "missing unlock": ("missing unlock", "forgot unlock", "held lock", "cwe-667"),
        "double checked locking": ("double checked", "lazy initialization", "race", "cwe-362"),
        "lost wakeup": ("lost wakeup", "condition variable", "pthread_cond_wait", "cwe-366"),
        "realloc misuse": ("realloc", "old pointer", "leak", "cwe-401"),
        "signed unsigned": ("signed", "unsigned", "negative", "cwe-195"),
        "off by one": ("off by one", "off-by-one", "one byte", "cwe-193"),
        "uninitialized read": ("uninitialized", "padding", "cwe-457"),
        "invalid free": ("invalid free", "non-heap", "cwe-590"),
        "stack overflow": ("stack overflow", "vla", "stack buffer", "cwe-121"),
        "alignment": ("unaligned", "alignment", "strict alias", "cwe-704"),
        "stale fd": ("stale fd", "file descriptor", "closed fd", "cwe-672"),
        "type confusion": (
            "type confusion",
            "wrong type",
            "invalid mutex",
            "pthread_mutex_destroy",
            "sharedresources",
            "cwe-843",
        ),
    }
    needles = aliases.get(category, (category, cwe))
    return any(needle and needle in text for needle in needles)


def match_issue(issue: dict[str, Any], truth: dict[str, Any], tolerance: int) -> bool:
    issue_file, issue_line = issue_file_and_line(issue)
    if not file_matches(issue_file, truth):
        return False
    if not category_matches(issue, truth):
        return False
    if not function_matches(issue, truth):
        return False
    return line_near(issue_line, truth, tolerance) and text_matches(issue, truth)


def score(report: dict[str, Any], truth: dict[str, Any], tolerance: int) -> dict[str, Any]:
    issues = report_issues(report)
    vulns = truth.get("vulnerabilities", [])
    matched_truth: dict[str, int] = {}
    matched_issues: set[int] = set()

    for tidx, vuln in enumerate(vulns):
        for iidx, issue in enumerate(issues):
            if iidx in matched_issues:
                continue
            if match_issue(issue, vuln, tolerance):
                matched_truth[vuln["id"]] = iidx
                matched_issues.add(iidx)
                break

    tp = len(matched_truth)
    fp = max(0, len(issues) - len(matched_issues))
    fn = max(0, len(vulns) - tp)
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / len(vulns) if vulns else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0

    missed = [v["id"] for v in vulns if v["id"] not in matched_truth]
    matched = sorted(matched_truth)
    return {
        "benchmark": truth.get("benchmark", "unknown"),
        "report_issue_count": len(issues),
        "ground_truth_count": len(vulns),
        "true_positives": tp,
        "false_positives": fp,
        "false_negatives": fn,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "matched": matched,
        "missed": missed,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--report", required=True, type=Path)
    parser.add_argument("--truth", required=True, type=Path)
    parser.add_argument("--line-tolerance", type=int, default=5)
    args = parser.parse_args()

    result = score(load_json(args.report), load_json(args.truth), args.line_tolerance)
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
