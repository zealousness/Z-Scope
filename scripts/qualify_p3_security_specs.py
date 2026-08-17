"""Run the answer-isolated, zero-network P3 SecuritySpec qualification corpus."""

from __future__ import annotations

import argparse
import json
import platform
import sys
import tempfile
from pathlib import Path
from typing import Any, Mapping, Sequence

from zscope.semantics.security_specs.canonical import canonical_json, content_sha256
from zscope.semantics.security_specs.compiler import SecuritySpecCompiler
from zscope.semantics.security_specs.miner import (
    SecuritySpecMiner,
    SecuritySpecProposalEngine,
)
from zscope.semantics.security_specs.models import (
    build_qualification,
    build_security_spec,
)
from zscope.semantics.security_specs.registry import registry_manifest


DEFAULT_CORPUS_ROOT = Path("tests/fixtures/p3_security_specs")


def _load_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"qualification_input_not_object:{path}")
    return value


def _slots(parameters: Mapping[str, Any]) -> list[str]:
    values: set[str] = set()
    for name, raw in parameters.items():
        if not (name.endswith("slot") or name.endswith("slots")):
            continue
        for value in raw if isinstance(raw, list) else [raw]:
            values.add(str(value))
    return sorted(values)


def _expand_source(source: Mapping[str, Any]) -> list[dict[str, Any]]:
    projects = list(source.get("projects") or [])
    variations = list(source.get("variations") or [])
    templates = list(source.get("predicate_templates") or [])
    if len(projects) < 3 or not variations or not templates:
        raise ValueError("p3_source_corpus_incomplete")
    cases: list[dict[str, Any]] = []
    for predicate_index, template in enumerate(templates):
        predicate = str(template.get("predicate") or "")
        parameters = dict(template.get("parameters") or {})
        for variation_index, variation in enumerate(variations):
            project = dict(projects[(predicate_index + variation_index) % len(projects)])
            variation_id = str(variation.get("variation_id") or "")
            function_uid = f"{project['project_id']}/{predicate}/{variation_id}"
            case_id = f"P3SPEC_{predicate}_{variation_id}"
            dependency_hashes = [
                content_sha256(
                    {
                        "case_id": case_id,
                        "transformation": variation.get("transformation"),
                        "dependency_revision": variation_index,
                    }
                ),
                content_sha256(
                    {
                        "project_id": project["project_id"],
                        "compiler": "frozen-corpus-backend-v1",
                    }
                ),
            ]
            cases.append(
                {
                    "fact_id": case_id,
                    "binding_complete": variation.get("binding_complete") is True,
                    "predicate": predicate,
                    "subject": {
                        "language": project["language"],
                        "function_uid": function_uid,
                        "signature": f"{predicate}_{variation_id}(slots)",
                        "slot_uids": _slots(parameters),
                    },
                    "scope": {
                        "kind": "callsite" if variation_id == "v07" else "function",
                        "target": (
                            f"{function_uid}:call:1" if variation_id == "v07" else function_uid
                        ),
                    },
                    "parameters": parameters,
                    "evidence_refs": [f"EVIDENCE_{case_id}"],
                    "dependency_hashes": dependency_hashes,
                    "origin": "program",
                    "confidence": 1.0,
                    "impact_preview": [function_uid],
                    "project_id": project["project_id"],
                    "variation_id": variation_id,
                }
            )
    return cases


def _cache_qualification(cases: Sequence[Mapping[str, Any]]) -> float:
    unknown = [dict(value) for value in cases if value.get("binding_complete") is not True][:12]
    calls: list[str] = []

    def proposal(request: Mapping[str, Any]) -> Mapping[str, Any]:
        calls.append(str(request.get("unit_id") or ""))
        return {"proposal_ids": []}

    with tempfile.TemporaryDirectory(prefix="zscope-p3-spec-cache-") as directory:
        engine = SecuritySpecProposalEngine(
            Path(directory), proposal, model_profile_hash=content_sha256({"profile": "fake"})
        )

        def run(values: Sequence[Mapping[str, Any]]) -> None:
            for case in values:
                engine.propose(
                    unit_id=str(case["fact_id"]),
                    unit_fingerprint=content_sha256(
                        {
                            "fact_id": case["fact_id"],
                            "dependencies": case["dependency_hashes"],
                            "scope": case["scope"],
                        }
                    ),
                    allowed_subjects=[case["subject"]],
                    allowed_scopes=[case["scope"]],
                    allowed_evidence_refs=case["evidence_refs"],
                    dependency_hashes=case["dependency_hashes"],
                    allowed_proposals=[],
                )

        run(unknown)
        first_calls = len(calls)
        run(unknown)
        second_calls = len(calls) - first_calls
        if first_calls == 0:
            raise AssertionError("counting_fake_client_received_no_first_scan_calls")

        changed_dependency = dict(unknown[0])
        changed_dependency["dependency_hashes"] = [
            *list(changed_dependency["dependency_hashes"][:-1]),
            content_sha256({"dependency": "changed"}),
        ]
        run([changed_dependency])
        if len(calls) != first_calls + second_calls + 1:
            raise AssertionError("dependency_change_did_not_recompute_exact_unit")

        changed_scope = dict(unknown[1])
        changed_scope["scope"] = {
            "kind": "callsite",
            "target": f"{changed_scope['subject']['function_uid']}:changed",
        }
        run([changed_scope])
        if len(calls) != first_calls + second_calls + 2:
            raise AssertionError("scope_change_did_not_recompute_exact_unit")
        return 1.0 - (second_calls / first_calls)


def qualify(corpus_root: Path = DEFAULT_CORPUS_ROOT) -> dict[str, Any]:
    source_path = Path(corpus_root) / "source-corpus.json"
    contracts_path = Path(corpus_root) / "expected-contracts.json"
    source = _load_json(source_path)
    contracts = _load_json(contracts_path)
    cases = _expand_source(source)

    # Only source-side program facts cross the product boundary.  The separate
    # contract file remains in this qualification scorer.
    result = SecuritySpecMiner().mine_program_facts(cases)
    specs = list(result["specs"])
    active_variations = set(map(str, contracts["active_variation_ids"]))
    inactive_variations = set(map(str, contracts["inactive_variation_ids"]))
    expected_active = [value for value in cases if str(value["variation_id"]) in active_variations]
    actual_keys = {(str(spec["predicate"]), str(spec["subject"]["function_uid"])) for spec in specs}
    expected_keys = {
        (str(value["predicate"]), str(value["subject"]["function_uid"]))
        for value in expected_active
    }
    safe_keys = {
        (str(value["predicate"]), str(value["subject"]["function_uid"]))
        for value in cases
        if str(value["variation_id"]) in inactive_variations
    }
    supported = len(actual_keys & expected_keys)
    unsupported = len(expected_keys - actual_keys)
    resolvable_evidence = {str(ref) for value in cases for ref in value.get("evidence_refs") or []}
    evidence_count = sum(len(spec["evidence_refs"]) for spec in specs)
    resolved_count = sum(
        1 for spec in specs for ref in spec["evidence_refs"] if ref in resolvable_evidence
    )
    metrics = {
        "case_count": len(cases),
        "key_contract_recall": round(supported / max(1, len(expected_keys)), 6),
        "positive_unsupported_rate": round(unsupported / max(1, len(expected_keys)), 6),
        "safe_false_activation_count": len(actual_keys & safe_keys),
        "evidence_resolution_rate": round(resolved_count / max(1, evidence_count), 6),
        "second_scan_llm_reduction": round(_cache_qualification(cases), 6),
    }
    corpus_sha256 = content_sha256({"source": source, "contracts": contracts})
    qualification = build_qualification(
        registry_sha256=content_sha256(registry_manifest()),
        compiler_sha256=content_sha256({"compiler_version": SecuritySpecCompiler.compiler_version}),
        corpus_sha256=corpus_sha256,
        qualified_predicates=list(contracts["required_predicates"]),
        source_projects=[str(value["project_id"]) for value in source["projects"]],
        metrics=metrics,
        environment={
            "python": sys.version.split()[0],
            "platform": platform.platform(),
            "network": False,
            "llm_client": "counting_fake",
        },
    )

    stable_specs = [
        build_security_spec(
            subject=spec["subject"],
            scope=spec["scope"],
            predicate=spec["predicate"],
            parameters=spec["parameters"],
            evidence_refs=spec["evidence_refs"],
            dependency_hashes=spec["dependency_hashes"],
            origin="qualification",
            confidence=1.0,
            status="stable",
            qualification_ref=qualification["content_sha256"],
            explanation="Qualified by the frozen P3 blind corpus.",
            impact_preview=spec["impact_preview"],
        )
        for spec in specs
    ]
    compilation = SecuritySpecCompiler().compile(
        stable_specs,
        qualification_hashes=[qualification["content_sha256"]],
        resolvable_evidence_refs=resolvable_evidence,
        current_dependency_hashes={
            value for spec in stable_specs for value in spec["dependency_hashes"]
        },
    )
    if len(compilation["compiled_specs"]) != len(expected_keys):
        raise AssertionError("qualification_compilation_count_mismatch")
    return {
        "schema_version": "zscope.p3-security-spec-qualification-result.v1",
        "qualification": qualification,
        "case_count": len(cases),
        "positive_case_count": len(expected_keys),
        "safe_case_count": len(safe_keys),
        "compiled_spec_count": len(compilation["compiled_specs"]),
        "compilation_mode": compilation["mode"],
        "source_corpus_sha256": content_sha256(source),
        "expected_contracts_sha256": content_sha256(contracts),
        "corpus_bundle_sha256": corpus_sha256,
    }


def main(argv: Sequence[str] = ()) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--corpus-root", type=Path, default=DEFAULT_CORPUS_ROOT)
    args = parser.parse_args(list(argv) or None)
    print(canonical_json(qualify(args.corpus_root)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
