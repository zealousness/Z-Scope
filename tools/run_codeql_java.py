#!/usr/bin/env python3
"""Run CodeQL Java analysis and emit Z-SCOPE Java signal JSON.

This wrapper intentionally does not install CodeQL. Users must put `codeql` on
PATH or pass --codeql explicitly.
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any


def main() -> int:
    args = parse_args()
    codeql = args.codeql or shutil.which("codeql")
    if not codeql:
        sys.stderr.write(
            "CodeQL CLI not found. Install CodeQL and put `codeql` on PATH, or pass --codeql.\n"
        )
        return 2
    project_root = Path(args.project_root).resolve()
    source_root = Path(args.source_root or project_root).resolve()
    db = Path(args.database or project_root / ".zscope_knowledge" / "codeql-java-db").resolve()
    sarif = Path(args.sarif or project_root / ".zscope_knowledge" / "codeql-java.sarif").resolve()
    db.parent.mkdir(parents=True, exist_ok=True)
    sarif.parent.mkdir(parents=True, exist_ok=True)

    query_suite, query_reason = resolve_query_suite(codeql, args.query_suite)
    if not query_suite:
        payload = degraded_payload(query_reason)
        write_payload(payload, args.output_json)
        return 0

    if not db.exists():
        create_cmd = [
            codeql,
            "database",
            "create",
            str(db),
            "--language=java-kotlin",
            "--source-root",
            str(source_root),
            "--overwrite",
        ]
        if (project_root / "pom.xml").exists():
            create_cmd.extend(["--command", "mvn -q -DskipTests package"])
        else:
            create_cmd.append("--build-mode=none")
        proc = subprocess.run(
            create_cmd, cwd=str(project_root), text=True, capture_output=True, check=False
        )
        if proc.returncode != 0:
            sys.stderr.write(
                proc.stderr[-4000:] or f"CodeQL database create failed with {proc.returncode}\n"
            )
            return proc.returncode

    analyze_cmd = [
        codeql,
        "database",
        "analyze",
        str(db),
        query_suite,
        "--format=sarifv2.1.0",
        "--output",
        str(sarif),
        "--rerun",
    ]
    proc = subprocess.run(
        analyze_cmd, cwd=str(project_root), text=True, capture_output=True, check=False
    )
    if proc.returncode != 0:
        payload = degraded_payload(
            proc.stderr[-4000:] or f"CodeQL database analyze failed with {proc.returncode}"
        )
        write_payload(payload, args.output_json)
        return 0

    payload = sarif_to_payload(
        json.loads(sarif.read_text(encoding="utf-8")), project_root, source_root, args.entry
    )
    write_payload(payload, args.output_json)
    return 0


def write_payload(payload: dict[str, Any], output_json: str = "") -> None:
    if output_json:
        Path(output_json).write_text(
            json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8"
        )
    print(json.dumps(payload, ensure_ascii=False))


def degraded_payload(reason: str) -> dict[str, Any]:
    return {
        "provider": "codeql",
        "precision": "exact_flow",
        "call_edges": [],
        "signals": [],
        "metadata": {
            "signal_count": 0,
            "degraded_reason": str(reason or "CodeQL query suite unavailable"),
        },
    }


def resolve_query_suite(codeql: str, configured: str = "") -> tuple[str, str]:
    candidates = (
        [configured]
        if configured
        else [
            "codeql/java-queries:codeql-suites/java-security-and-quality.qls",
            "codeql/java-queries:codeql-suites/java-security-extended.qls",
            "java-security-and-quality.qls",
            "java-security-extended.qls",
        ]
    )
    reasons: list[str] = []
    for candidate in candidates:
        if not candidate:
            continue
        try:
            proc = subprocess.run(
                [codeql, "resolve", "queries", candidate],
                text=True,
                capture_output=True,
                check=False,
            )
        except OSError as exc:
            reasons.append(f"Unable to execute CodeQL CLI: {exc}")
            break
        if proc.returncode == 0:
            return candidate, ""
        reasons.append((proc.stderr or proc.stdout or f"{candidate} not resolved").strip())
    install_hint = (
        "CodeQL Java query pack is not visible to this CodeQL installation. "
        "Install/configure CodeQL Java queries or pass --query-suite / "
        "indexing.java_signal_provider_commands.codeql with an absolute suite path."
    )
    return "", "\n".join(reasons[-3:] + [install_hint])


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--codeql", default="")
    parser.add_argument("--project-root", required=True)
    parser.add_argument("--source-root", default="")
    parser.add_argument("--entry", default="")
    parser.add_argument("--classpath", default="")
    parser.add_argument("--database", default="")
    parser.add_argument("--sarif", default="")
    parser.add_argument("--query-suite", default="")
    parser.add_argument("--output-json", default="")
    return parser.parse_args()


def sarif_to_payload(
    data: dict[str, Any], project_root: Path, source_root: Path, entry: str = ""
) -> dict[str, Any]:
    rules = collect_rules(data)
    signals: list[dict[str, Any]] = []
    for run in data.get("runs", []) or []:
        for result in run.get("results", []) or []:
            if not isinstance(result, dict):
                continue
            rule_id = str(
                result.get("ruleId") or result.get("rule", {}).get("id") or "codeql_java_signal"
            )
            locations = flow_locations(result) or result_locations(result)
            if not locations:
                continue
            source = locations[0]
            sink = locations[-1]
            rule = rules.get(rule_id, {})
            category = category_for(rule_id, rule, result)
            message = message_text(result)
            signals.append(
                {
                    "provider": "codeql",
                    "rule_id": rule_id,
                    "category": category,
                    "precision": "exact_flow",
                    "score": score_for(result),
                    "source": {
                        "file": normalize_file(source.get("file", ""), project_root, source_root),
                        "line": source.get("line", 0),
                        "function": entry,
                        "kind": "codeql_source",
                        "expression": source.get("message") or message or rule_id,
                    },
                    "sink": {
                        "file": normalize_file(sink.get("file", ""), project_root, source_root),
                        "line": sink.get("line", 0),
                        "function": entry,
                        "kind": "codeql_sink",
                        "operation": sink.get("message") or message or rule_id,
                    },
                    "path": [
                        {
                            "method": entry,
                            "file": normalize_file(item.get("file", ""), project_root, source_root),
                            "line": item.get("line", 0),
                            "code": item.get("message", ""),
                        }
                        for item in locations
                    ],
                    "limitations": [
                        "CodeQL SARIF path-problem signal; Z-SCOPE Validator must confirm framework reachability and guards."
                    ],
                    "raw_evidence": {"message": message, "rule": rule, "result": result},
                }
            )
    return {
        "provider": "codeql",
        "precision": "exact_flow",
        "call_edges": [],
        "signals": signals,
        "metadata": {"signal_count": len(signals)},
    }


def collect_rules(data: dict[str, Any]) -> dict[str, dict[str, Any]]:
    rules: dict[str, dict[str, Any]] = {}
    for run in data.get("runs", []) or []:
        driver = (run.get("tool") or {}).get("driver") or {}
        for rule in driver.get("rules", []) or []:
            if isinstance(rule, dict) and rule.get("id"):
                rules[str(rule["id"])] = rule
    return rules


def result_locations(result: dict[str, Any]) -> list[dict[str, Any]]:
    rows = []
    for location in result.get("locations", []) or []:
        parsed = parse_location(location)
        if parsed:
            rows.append(parsed)
    return rows


def flow_locations(result: dict[str, Any]) -> list[dict[str, Any]]:
    rows = []
    for flow in result.get("codeFlows", []) or []:
        for thread in flow.get("threadFlows", []) or []:
            for location in thread.get("locations", []) or []:
                parsed = parse_location(location.get("location") or location)
                if parsed:
                    parsed["message"] = parsed.get("message") or message_text(location)
                    rows.append(parsed)
    return rows


def parse_location(location: dict[str, Any]) -> dict[str, Any]:
    physical = location.get("physicalLocation") or {}
    artifact = physical.get("artifactLocation") or {}
    region = physical.get("region") or {}
    uri = str(artifact.get("uri") or "")
    if not uri:
        return {}
    return {
        "file": uri,
        "line": int(region.get("startLine") or 0),
        "message": message_text(location),
    }


def message_text(value: dict[str, Any]) -> str:
    msg = value.get("message") if isinstance(value, dict) else {}
    if isinstance(msg, dict):
        return str(msg.get("text") or msg.get("markdown") or "")
    return ""


def normalize_file(uri: str, project_root: Path, source_root: Path) -> str:
    text = str(uri or "").replace("\\", "/")
    if text.startswith("file://"):
        text = text[7:]
    path = Path(text)
    if path.is_absolute():
        for root in (source_root, project_root):
            try:
                return path.resolve().relative_to(root.resolve()).as_posix()
            except Exception:
                pass
    return text


def category_for(rule_id: str, rule: dict[str, Any], result: dict[str, Any]) -> str:
    text = " ".join(
        [
            rule_id,
            json.dumps(rule.get("properties") or {}, ensure_ascii=False),
            message_text(result),
        ]
    ).lower()
    mapping = [
        ("sql", "sql_injection"),
        ("ldap", "ldap_injection"),
        ("jndi", "jndi_injection"),
        ("xxe", "xxe"),
        ("ssrf", "ssrf"),
        ("path", "path_traversal"),
        ("redirect", "open_redirect"),
        ("deserial", "unsafe_deserialization"),
        ("crypto", "weak_crypto"),
        ("random", "weak_random"),
        ("csrf", "authz_bypass"),
        ("auth", "authz_bypass"),
    ]
    for needle, category in mapping:
        if needle in text:
            return category
    return "java_signal"


def score_for(result: dict[str, Any]) -> float:
    level = str(result.get("level") or "").lower()
    if level == "error":
        return 8.5
    if level == "warning":
        return 7.5
    return 6.5


if __name__ == "__main__":
    raise SystemExit(main())
