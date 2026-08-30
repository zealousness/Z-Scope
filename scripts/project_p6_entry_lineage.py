#!/usr/bin/env python3
"""Project the protected P6 entry gate into answer-free reviewer evidence."""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any, Mapping, Optional, Sequence

from zscope.benchmarking.p6_protocol import (
    P6ProtocolError,
    canonical_sha256,
    load_json_strict,
    sha256_file,
    write_json_exclusive,
)


_ENTRY_FIELDS = frozenset(
    {
        "schema_version",
        "workflow_path",
        "control_plane_commit",
        "workflow_run_id",
        "workflow_run_attempt",
        "attempt_id",
        "candidate_git_sha",
        "candidate_git_tree",
        "candidate_sha256",
        "provider_contract_sha256",
        "p6_entry_gate_file_sha256",
        "p6_entry_gate_content_sha256",
        "e0_lineage",
        "trace_manifest_sha256",
        "canary_tree_sha256",
        "compile_commands_sha256",
        "qualification_harness_sha256",
        "hidden_bundle_sha256",
        "safe_pair_bundle_sha256",
        "formal_evidence",
        "release_eligible",
        "evidence_sha256",
    }
)
_LINEAGE_FIELDS = frozenset(
    {
        "schema_version",
        "entry_gate_file_sha256",
        "entry_gate_content_sha256",
        "review",
        "attestation",
        "review_packet_catalog_sha256",
        "review_packets_unchanged",
        "governance_is_ancestor_of_truth",
        "scorer_is_ancestor_of_truth",
        "projection_sha256",
    }
)
_ENTRY_GATE_FIELDS = frozenset(
    {
        "schema_version",
        "captured_at",
        "repository",
        "phase_transition",
        "e0_review",
        "e0_attestation",
        "ancestry",
        "review_packets",
        "historical_preflight",
        "entry_authorization",
        "content_sha256",
    }
)


def _require_exact(value: Any, fields: set[str] | frozenset[str], name: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) != set(fields):
        raise P6ProtocolError(f"P6 {name} fields are invalid")
    return value


def _require_artifact(value: Any, *, name: str) -> Mapping[str, Any]:
    artifact = _require_exact(value, {"name", "id", "digest", "expired"}, name)
    if (
        not isinstance(artifact["name"], str)
        or not artifact["name"]
        or not isinstance(artifact["id"], str)
        or not artifact["id"].isdigit()
        or int(artifact["id"]) < 1
        or not isinstance(artifact["digest"], str)
        or len(artifact["digest"]) != 71
        or not artifact["digest"].startswith("sha256:")
        or any(character not in "0123456789abcdef" for character in artifact["digest"][7:])
        or artifact["expired"] is not False
    ):
        raise P6ProtocolError(f"P6 {name} identity is invalid")
    return artifact


def validate_entry_gate(value: Mapping[str, Any]) -> None:
    gate = _require_exact(value, _ENTRY_GATE_FIELDS, "entry gate")
    if gate.get("schema_version") != "zscope.p6-entry-gate.v1":
        raise P6ProtocolError("P6 entry gate schema version is invalid")
    claimed = gate.get("content_sha256")
    if (
        not isinstance(claimed, str)
        or canonical_sha256({name: body for name, body in gate.items() if name != "content_sha256"})
        != claimed
    ):
        raise P6ProtocolError("P6 entry gate content hash is invalid")
    transition = _require_exact(
        gate["phase_transition"], {"previous", "current", "atomic"}, "phase transition"
    )
    if (
        transition["previous"] != {"E0": "pending", "P6": "pending"}
        or transition["current"] != {"E0": "complete", "P6": "in_progress"}
        or transition["atomic"] is not True
        or gate["repository"] != "zealousness/Z-Scope"
    ):
        raise P6ProtocolError("P6 phase transition is not authorized")

    review = _require_exact(
        gate["e0_review"],
        {
            "workflow_path",
            "event",
            "branch",
            "run_id",
            "source_sha",
            "status",
            "conclusion",
            "producer_job",
            "producer_job_conclusion",
            "artifacts",
        },
        "E0 review",
    )
    if (
        review["workflow_path"] != ".github/workflows/range-v16-review.yml"
        or review["event"] != "workflow_dispatch"
        or review["branch"] != "main"
        or review["status"] != "completed"
        or review["conclusion"] != "success"
        or review["producer_job_conclusion"] != "success"
        or not isinstance(review["run_id"], str)
        or not review["run_id"].isdigit()
        or not isinstance(review["source_sha"], str)
        or len(review["source_sha"]) != 40
    ):
        raise P6ProtocolError("P6 E0 review is not successful and frozen")
    artifacts = _require_exact(
        review["artifacts"], {"reviewed", "provenance", "pair"}, "E0 artifacts"
    )
    for artifact_name, artifact in artifacts.items():
        _require_artifact(artifact, name=f"E0 {artifact_name} artifact")

    attestation = _require_exact(
        gate["e0_attestation"],
        {
            "workflow_path",
            "event",
            "branch",
            "run_id",
            "head_sha",
            "status",
            "conclusion",
            "job",
            "job_conclusion",
            "environment",
            "artifact",
            "component_commits",
        },
        "E0 attestation",
    )
    if (
        attestation["workflow_path"] != ".github/workflows/range-v16-benchmark-v5-attestation.yml"
        or attestation["event"] != "workflow_dispatch"
        or attestation["branch"] != "main"
        or attestation["status"] != "completed"
        or attestation["conclusion"] != "success"
        or attestation["job_conclusion"] != "success"
        or attestation["environment"] != "sealed-benchmark"
        or not isinstance(attestation["run_id"], str)
        or not attestation["run_id"].isdigit()
        or not isinstance(attestation["head_sha"], str)
        or len(attestation["head_sha"]) != 40
    ):
        raise P6ProtocolError("P6 E0 attestation is not successful and frozen")
    _require_artifact(attestation["artifact"], name="E0 attestation artifact")
    commits = _require_exact(
        attestation["component_commits"],
        {"governance", "scorer", "truth"},
        "E0 component commits",
    )
    if (
        any(
            not isinstance(commit, str)
            or len(commit) != 40
            or any(character not in "0123456789abcdef" for character in commit)
            for commit in commits.values()
        )
        or commits["truth"] != attestation["head_sha"]
    ):
        raise P6ProtocolError("P6 E0 component commit binding is invalid")

    ancestry = _require_exact(
        gate["ancestry"],
        {"governance_is_ancestor_of_truth", "scorer_is_ancestor_of_truth"},
        "E0 ancestry",
    )
    packets = _require_exact(
        gate["review_packets"],
        {
            "review_source_sha",
            "truth_commit",
            "paths",
            "source_packet_tree_git_sha1",
            "truth_packet_tree_git_sha1",
            "source_catalog_blob_git_sha1",
            "truth_catalog_blob_git_sha1",
            "catalog_sha256",
            "unchanged",
        },
        "E0 review packets",
    )
    if (
        ancestry["governance_is_ancestor_of_truth"] is not True
        or ancestry["scorer_is_ancestor_of_truth"] is not True
        or packets["unchanged"] is not True
        or packets["review_source_sha"] != review["source_sha"]
        or packets["truth_commit"] != attestation["head_sha"]
        or packets["source_packet_tree_git_sha1"] != packets["truth_packet_tree_git_sha1"]
        or packets["source_catalog_blob_git_sha1"] != packets["truth_catalog_blob_git_sha1"]
        or not isinstance(packets["catalog_sha256"], str)
        or len(packets["catalog_sha256"]) != 64
    ):
        raise P6ProtocolError("P6 E0 packet or ancestry binding is invalid")
    historical = _require_exact(
        gate["historical_preflight"],
        {
            "path",
            "sha256",
            "provider_model",
            "entry_readiness",
            "preserved",
            "authorizes_current_entry",
        },
        "historical preflight",
    )
    authorization = _require_exact(
        gate["entry_authorization"],
        {
            "p1_p5_complete",
            "e0_complete",
            "p6_status",
            "cold_pilot_started",
            "formal_benchmark",
            "release_eligible",
        },
        "entry authorization",
    )
    if (
        historical["preserved"] is not True
        or historical["authorizes_current_entry"] is not False
        or authorization
        != {
            "p1_p5_complete": True,
            "e0_complete": True,
            "p6_status": "in_progress",
            "cold_pilot_started": False,
            "formal_benchmark": False,
            "release_eligible": False,
        }
    ):
        raise P6ProtocolError("P6 entry authorization is invalid")


def project_gate_lineage(value: Mapping[str, Any], *, gate_file_sha256: str) -> Mapping[str, Any]:
    validate_entry_gate(value)
    review = value["e0_review"]
    attestation = value["e0_attestation"]
    payload = {
        "schema_version": "zscope.p6-e0-lineage-projection.v1",
        "entry_gate_file_sha256": gate_file_sha256,
        "entry_gate_content_sha256": value["content_sha256"],
        "review": {
            "workflow_path": review["workflow_path"],
            "run_id": review["run_id"],
            "source_sha": review["source_sha"],
            "artifacts": {
                name: {
                    "id": artifact["id"],
                    "digest": artifact["digest"],
                    "expired": artifact["expired"],
                }
                for name, artifact in sorted(review["artifacts"].items())
            },
        },
        "attestation": {
            "workflow_path": attestation["workflow_path"],
            "run_id": attestation["run_id"],
            "head_sha": attestation["head_sha"],
            "artifact_id": attestation["artifact"]["id"],
            "artifact_digest": attestation["artifact"]["digest"],
        },
        "review_packet_catalog_sha256": value["review_packets"]["catalog_sha256"],
        "review_packets_unchanged": value["review_packets"]["unchanged"],
        "governance_is_ancestor_of_truth": value["ancestry"]["governance_is_ancestor_of_truth"],
        "scorer_is_ancestor_of_truth": value["ancestry"]["scorer_is_ancestor_of_truth"],
    }
    payload["projection_sha256"] = canonical_sha256(payload)
    return payload


def project_entry_lineage(value: Mapping[str, Any], *, artifact_sha256: str) -> Mapping[str, Any]:
    if (
        set(value) != _ENTRY_FIELDS
        or value.get("schema_version") != "zscope.p6-entry-evidence.v1"
        or value.get("formal_evidence") is not False
        or value.get("release_eligible") is not False
    ):
        raise P6ProtocolError("P6 entry evidence is invalid for independent review")
    claimed = value.get("evidence_sha256")
    if (
        not isinstance(claimed, str)
        or canonical_sha256(
            {name: body for name, body in value.items() if name != "evidence_sha256"}
        )
        != claimed
    ):
        raise P6ProtocolError("P6 entry evidence hash is invalid for independent review")
    lineage = value.get("e0_lineage")
    if not isinstance(lineage, Mapping) or set(lineage) != _LINEAGE_FIELDS:
        raise P6ProtocolError("P6 E0 lineage projection is invalid")
    projection_sha = lineage.get("projection_sha256")
    if (
        not isinstance(projection_sha, str)
        or canonical_sha256(
            {name: body for name, body in lineage.items() if name != "projection_sha256"}
        )
        != projection_sha
    ):
        raise P6ProtocolError("P6 E0 lineage projection hash is invalid")
    if (
        lineage.get("schema_version") != "zscope.p6-e0-lineage-projection.v1"
        or lineage.get("entry_gate_file_sha256") != value.get("p6_entry_gate_file_sha256")
        or lineage.get("entry_gate_content_sha256") != value.get("p6_entry_gate_content_sha256")
        or lineage.get("review_packets_unchanged") is not True
        or lineage.get("governance_is_ancestor_of_truth") is not True
        or lineage.get("scorer_is_ancestor_of_truth") is not True
    ):
        raise P6ProtocolError("P6 E0 lineage invariants are invalid")
    payload = {
        "schema_version": "zscope.p6-review-e0-lineage.v1",
        "control_plane_commit": value["control_plane_commit"],
        "candidate_sha256": value["candidate_sha256"],
        "entry_evidence_file_sha256": artifact_sha256,
        "entry_evidence_sha256": claimed,
        "e0_lineage": dict(lineage),
        "formal_evidence": False,
        "release_eligible": False,
    }
    payload["artifact_sha256"] = canonical_sha256(payload)
    return payload


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--entry-evidence", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _parser().parse_args(argv)
    value = load_json_strict(args.entry_evidence)
    if not isinstance(value, Mapping):
        raise P6ProtocolError("P6 entry evidence must be an object")
    projection = project_entry_lineage(value, artifact_sha256=sha256_file(args.entry_evidence))
    write_json_exclusive(args.output, projection)
    print(projection["artifact_sha256"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
