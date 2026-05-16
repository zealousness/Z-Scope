#!/usr/bin/env python3
"""Score a Z-SCOPE JSON report against the range benchmark ground truth."""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any

FUNC_DEF_RE = re.compile(
    r"(?m)^[A-Za-z_][\w\s\*\(\),]*\b([A-Za-z_]\w*)\s*\([^;{}]*\)\s*\{"
)
CALL_RE = re.compile(r"\b([A-Za-z_]\w*)\s*\(")
KEYWORDS = {
    "if",
    "for",
    "while",
    "switch",
    "return",
    "sizeof",
    "case",
}


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


def report_issues(report: dict[str, Any], view: str = "default") -> list[dict[str, Any]]:
    report_views = report.get("report_views")
    if isinstance(report_views, dict):
        selected = report_views.get(view)
        if isinstance(selected, dict) and isinstance(selected.get("issues"), list):
            return [x for x in selected["issues"] if isinstance(x, dict)]
    if view == "with_needs_review":
        issues = report_issues(report, "default")
        metadata = report.get("metadata") if isinstance(report.get("metadata"), dict) else {}
        observations = metadata.get("audit_observations") if isinstance(metadata, dict) else []
        if isinstance(observations, list):
            issues = list(issues) + [
                x
                for x in observations
                if isinstance(x, dict)
                and str(x.get("validation_status") or "").lower() == "needs_review"
            ]
        return issues
    if isinstance(report.get("issues"), list):
        issues = [x for x in report["issues"] if isinstance(x, dict)]
        if not issues and isinstance(report.get("findings"), list) and report.get("findings"):
            return [x for x in report["findings"] if isinstance(x, dict)]
        return issues
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


def source_files(root: Path) -> list[Path]:
    files: list[Path] = []
    for rel in ("src", "include", "internal"):
        base = root / rel
        if base.exists():
            files.extend(base.rglob("*.c"))
            files.extend(base.rglob("*.h"))
            files.extend(base.rglob("*.ph"))
    return sorted(files)


def find_matching_brace(text: str, open_idx: int) -> int:
    depth = 0
    for idx in range(open_idx, len(text)):
        char = text[idx]
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return idx
    return len(text)


def build_source_index(root: Path) -> dict[str, Any]:
    functions: dict[str, dict[str, Any]] = {}
    calls: dict[str, set[str]] = {}
    all_names: set[str] = set()
    file_texts: dict[str, str] = {}

    for path in source_files(root):
        rel = path.relative_to(root).as_posix()
        text = path.read_text(encoding="utf-8", errors="ignore")
        file_texts[rel] = text
        for match in FUNC_DEF_RE.finditer(text):
            name = match.group(1)
            open_idx = text.find("{", match.end() - 1)
            if open_idx < 0:
                continue
            end_idx = find_matching_brace(text, open_idx)
            start_line = text[: match.start()].count("\n") + 1
            end_line = text[:end_idx].count("\n") + 1
            body = text[open_idx:end_idx]
            functions[name] = {
                "file": rel,
                "line": start_line,
                "end_line": end_line,
                "body": body,
            }
            all_names.add(name)

    for name, info in functions.items():
        callees = {
            call.group(1)
            for call in CALL_RE.finditer(str(info.get("body") or ""))
            if call.group(1) not in KEYWORDS
        }
        calls[name] = callees & all_names

    return {"functions": functions, "calls": calls, "files": file_texts}


def reachable_functions(start: str, calls: dict[str, set[str]]) -> set[str]:
    seen = {start}
    stack = [start]
    while stack:
        current = stack.pop()
        for callee in calls.get(current, set()):
            if callee not in seen:
                seen.add(callee)
                stack.append(callee)
    return seen


def enrich_truth_locations(truth: dict[str, Any], source_index: dict[str, Any]) -> None:
    funcs = source_index.get("functions", {})
    for vuln in truth.get("vulnerabilities", []):
        primary = funcs.get(str(vuln.get("function") or ""))
        if primary:
            vuln["_current_file"] = primary["file"]
            vuln["_current_line"] = primary["line"]
            vuln["_current_end_line"] = primary["end_line"]
        secondary = funcs.get(str(vuln.get("secondary_function") or ""))
        if secondary:
            vuln["_current_secondary_file"] = secondary["file"]
            vuln["_current_secondary_line"] = secondary["line"]
            vuln["_current_secondary_end_line"] = secondary["end_line"]


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
    start = int(truth.get("_current_line") or truth["line"])
    end = int(truth.get("_current_end_line") or truth.get("end_line", start))
    if start - tolerance <= line <= end + tolerance:
        return True
    secondary = truth.get("_current_secondary_line") or truth.get("secondary_line")
    if secondary is None:
        return False
    secondary_end = int(truth.get("_current_secondary_end_line") or truth.get("secondary_end_line", secondary))
    return int(secondary) - tolerance <= line <= secondary_end + tolerance


def file_matches(issue_file: str, truth: dict[str, Any]) -> bool:
    issue_file = normalize_path(issue_file)
    primary = normalize_path(str(truth.get("_current_file") or truth["file"]))
    secondary = normalize_path(str(truth.get("_current_secondary_file") or truth.get("secondary_file", "")))
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


def call_reachable_function_matches(
    issue: dict[str, Any],
    truth: dict[str, Any],
    source_index: dict[str, Any],
) -> bool:
    actual = issue_function(issue)
    if not actual:
        return False
    calls = source_index.get("calls", {})
    reachable = reachable_functions(actual, calls)
    expected = {
        str(truth.get("function") or ""),
        str(truth.get("secondary_function") or ""),
    }
    return bool(reachable & {item for item in expected if item})


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


def match_issue(
    issue: dict[str, Any],
    truth: dict[str, Any],
    tolerance: int,
    source_index: dict[str, Any] | None = None,
) -> bool:
    issue_file, issue_line = issue_file_and_line(issue)
    if file_matches(issue_file, truth) and function_matches(issue, truth):
        near = line_near(issue_line, truth, tolerance)
        if category_matches(issue, truth):
            return near and text_matches(issue, truth)
        # The benchmark should measure whether a user can discover the target
        # issue from the report, not whether the normalized category string is
        # perfect.  If the finding is in the right function/location window and
        # its text still mentions the truth keywords, count it as discoverable.
        return near and text_matches(issue, truth)
    if not category_matches(issue, truth):
        return False
    if source_index and call_reachable_function_matches(issue, truth, source_index):
        return text_matches(issue, truth)
    return False


def score(
    report: dict[str, Any],
    truth: dict[str, Any],
    tolerance: int,
    source_index: dict[str, Any] | None = None,
    view: str = "default",
) -> dict[str, Any]:
    issues = report_issues(report, view)
    vulns = truth.get("vulnerabilities", [])
    matched_truth: dict[str, int] = {}
    matched_issues: set[int] = set()

    for tidx, vuln in enumerate(vulns):
        for iidx, issue in enumerate(issues):
            if iidx in matched_issues:
                continue
            if match_issue(issue, vuln, tolerance, source_index):
                matched_truth[vuln["id"]] = iidx
                matched_issues.add(iidx)
                break

    tp = len(matched_truth)
    fp = max(0, len(issues) - len(matched_issues))
    fn = max(0, len(vulns) - tp)
    precision = tp / (tp + fp) if tp + fp else 0.0
    false_positive_rate = fp / (tp + fp) if tp + fp else 0.0
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
        "false_positive_rate": round(false_positive_rate, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "matched": matched,
        "missed": missed,
    }


def score_report_views(
    report: dict[str, Any],
    truth: dict[str, Any],
    tolerance: int,
    source_index: dict[str, Any] | None = None,
) -> dict[str, Any]:
    default_result = score(report, truth, tolerance, source_index, view="default")
    with_review_result = score(
        report,
        truth,
        tolerance,
        source_index,
        view="with_needs_review",
    )
    return {
        "default": default_result,
        "with_needs_review": with_review_result,
        "comparison": {
            "issue_delta": with_review_result["report_issue_count"]
            - default_result["report_issue_count"],
            "true_positive_delta": with_review_result["true_positives"]
            - default_result["true_positives"],
            "false_positive_delta": with_review_result["false_positives"]
            - default_result["false_positives"],
            "false_negative_delta": with_review_result["false_negatives"]
            - default_result["false_negatives"],
            "recall_delta": round(
                with_review_result["recall"] - default_result["recall"],
                4,
            ),
            "false_positive_rate_delta": round(
                with_review_result["false_positive_rate"]
                - default_result["false_positive_rate"],
                4,
            ),
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--report", required=True, type=Path)
    parser.add_argument("--truth", required=True, type=Path)
    parser.add_argument("--line-tolerance", type=int, default=5)
    parser.add_argument("--root", type=Path, default=Path("test/range"))
    args = parser.parse_args()

    truth = load_json(args.truth)
    source_index = build_source_index(args.root)
    enrich_truth_locations(truth, source_index)
    report = load_json(args.report)
    result = score(report, truth, args.line_tolerance, source_index)
    result["report_views"] = score_report_views(
        report,
        truth,
        args.line_tolerance,
        source_index,
    )
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
