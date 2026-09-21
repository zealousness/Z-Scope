"""Audit completed trial artifacts without loading multi-GB reports into memory."""

from __future__ import annotations

import argparse
import hashlib
from collections import Counter
import json
from pathlib import Path
import re

from zscope.reporting.json_io import read_json_streaming


SOURCE = re.compile(rb'"candidate_source"\s*:\s*"semantic_snapshot"')


def probe_report_json(path: Path) -> dict:
    """Count source envelopes and outline ordinary indent=2 report sections."""
    root_field = re.compile(rb'\n  "([A-Za-z_][A-Za-z_0-9]*)":')
    total, carry, consumed = 0, b"", 0
    checksum = hashlib.sha256()
    sections = []
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            checksum.update(chunk)
            data = carry + chunk
            origin = consumed - len(carry)
            end = max(0, len(data) - 1024)
            total += sum(m.start() < end for m in SOURCE.finditer(data))
            sections.extend((m.group(1).decode(), origin + m.start())
                            for m in root_field.finditer(data) if m.start() < end)
            carry = data[end:]
            consumed += len(chunk)
    total += len(SOURCE.findall(carry))
    sections.extend((m.group(1).decode(), consumed - len(carry) + m.start())
                    for m in root_field.finditer(carry))
    return {
        "snapshot_source_occurrences": total,
        "report_bytes": consumed,
        "sha256": checksum.hexdigest(),
        "serialized_sections": [
            {"field": name, "offset": offset, "span_bytes": (sections[i + 1][1] if i + 1 < len(sections) else consumed) - offset}
            for i, (name, offset) in enumerate(sections)
        ],
        "outline_note": "Sections are byte spans in indent=2 generated JSON, including field names and delimiters; empty for compact JSON. No evidence is decoded or removed.",
    }


def snapshot_source_occurrences(path: Path) -> int:
    return probe_report_json(path)["snapshot_source_occurrences"]


def audit(folder: Path, publication_path: Path) -> dict:
    if not (folder / "report.json").exists() or not (folder / "score.json").exists():
        raise RuntimeError("Audit requires a completed, independently scored report")
    publication = json.loads(publication_path.read_text(encoding="utf-8"))
    probe_path = folder / "report-json-probe.json"
    summary_path = folder / "summary.json"
    report_probe = None
    if probe_path.exists() and summary_path.exists():
        cached = json.loads(probe_path.read_text(encoding="utf-8"))
        summary = json.loads(summary_path.read_text(encoding="utf-8"))
        if (cached.get("sha256") == summary.get("artifact_hashes", {}).get("report.json")
                and cached.get("report_bytes") == (folder / "report.json").stat().st_size):
            report_probe = cached
    if report_probe is None:
        report_probe = probe_report_json(folder / "report.json")
    count = report_probe["snapshot_source_occurrences"]
    snapshot_candidates, snapshot_groups = set(), set()
    if count:
        # Candidate provenance lives in the envelope, not the usage event. Read
        # the full report only when a source-bearing envelope actually exists.
        pending = [read_json_streaming(folder / "report.json")]
        while pending:
            item = pending.pop()
            if isinstance(item, list):
                pending.extend(item)
            elif isinstance(item, dict):
                issue = item.get("issue") or {}
                if item.get("candidate_source") == "semantic_snapshot" or (
                    isinstance(issue, dict) and issue.get("candidate_source") == "semantic_snapshot"
                ):
                    for owner in (item, issue, item.get("candidate_envelope") or {}):
                        if isinstance(owner, dict):
                            if owner.get("candidate_uid"):
                                snapshot_candidates.add(owner["candidate_uid"])
                            if owner.get("validation_cluster_uid"):
                                snapshot_groups.add(owner["validation_cluster_uid"])
                pending.extend(v for v in item.values() if isinstance(v, (dict, list)))
    tokens, calls, snapshot_calls = Counter(), Counter(), 0
    snapshot_tokens = 0
    token_breakdown = {}
    usage = folder / "llm_usage_events.jsonl"
    if not usage.exists():
        raise RuntimeError("Missing per-call usage evidence")
    for line in usage.open(encoding="utf-8"):
        if not line.strip():
            continue
        event = json.loads(line)
        attribution = event.get("attribution") or {}
        agent = str(attribution.get("agent") or event.get("agent") or "unknown")
        kind = str(event.get("call_kind") or attribution.get("call_kind") or "unknown")
        key = agent + ":" + kind
        calls[key] += 1
        breakdown = token_breakdown.setdefault(key, Counter())
        for field in (
            "prompt_tokens",
            "completion_tokens",
            "cached_prompt_tokens",
            "reasoning_tokens",
        ):
            breakdown[field] += int((event.get("usage") or {}).get(field) or event.get(field) or 0)
        tokens[key] += int(
            (event.get("usage") or {}).get("total_tokens")
            or event.get("total_tokens")
            or event.get("tokens")
            or 0
        )
        candidate = event.get("candidate_uid") or attribution.get("candidate_uid")
        group = event.get("validation_cluster_uid") or attribution.get("validation_cluster_uid")
        if candidate in snapshot_candidates or group in snapshot_groups:
            snapshot_calls += 1
            snapshot_tokens += int(
                (event.get("usage") or {}).get("total_tokens") or event.get("total_tokens") or 0
            )
    proposal_errors = Counter(
        error
        for snapshot in publication.get("snapshots", [])
        for diagnostic in snapshot.get("diagnostics", [])
        for error in diagnostic.get("errors", [])
    )
    return {
        "release_eligible": False,
        "contract_version": publication["contract_version"],
        "modeling": publication["stats"],
        "call_site_counts": publication["call_site_counts"],
        "proposal_validation_errors": dict(proposal_errors),
        "published_contract_sources": dict(
            Counter(c.get("source", "unknown") for c in publication.get("api_contracts", []))
        ),
        "published_verification_methods": dict(
            Counter(
                c.get("verification", {}).get("method", "none")
                for c in publication.get("api_contracts", [])
            )
        ),
        "explicit_pair_count": len(publication.get("api_pairs", [])),
        "snapshot_candidate_source_occurrences": count,
        "report_json_outline": report_probe,
        "snapshot_attributed_usage_calls": snapshot_calls,
        "snapshot_linked_usage_tokens": snapshot_tokens,
        "snapshot_candidate_uids": sorted(snapshot_candidates),
        "snapshot_validation_cluster_uids": sorted(snapshot_groups),
        "snapshot_usage_attribution_basis": "candidate_source envelopes joined to usage by candidate_uid/validation_cluster_uid; shared groups can have more than one source",
        "snapshot_independent_tasks_absent": count == 0 and snapshot_calls == 0,
        "calls_by_agent_and_kind": dict(calls),
        "tokens_by_agent_and_kind": dict(tokens),
        "token_breakdown_by_agent_and_kind": {k: dict(v) for k, v in token_breakdown.items()},
        "measurement_note": "Repeated report envelopes are not deduplicated; zero means no snapshot-sourced envelope. Usage attribution is reported separately, including unknowns.",
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", type=Path, required=True)
    run = parser.parse_args().run.resolve()
    result = {
        "cold": audit(run, run / "semantic-publication/publication.json"),
        "hot": audit(run / "hot-rescan", run / "hot-rescan/publication.json"),
    }
    (run / "contract-audit.json").write_text(
        json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    assert all(r["snapshot_independent_tasks_absent"] for r in result.values())
    print(run / "contract-audit.json")


if __name__ == "__main__":
    main()
