"""Unified P3 shadow snapshot orchestration."""

from __future__ import annotations

from typing import Any, Iterable, Mapping, Sequence

from .compiler import SecuritySpecCompiler
from .lifecycle import SECURITY_SPEC_MODE
from .miner import SecuritySpecMiner
from .models import build_security_spec, validate_qualification
from .store import SecuritySpecStore


class SecuritySpecShadowRuntime:
    """Mine and compile specs without exposing an authority-bearing return value."""

    def __init__(self, store: SecuritySpecStore) -> None:
        self.store = store
        self.miner = SecuritySpecMiner()
        self.compiler = SecuritySpecCompiler()

    def run(
        self,
        semantic_map: Any,
        *,
        qualification_hashes: Iterable[str] = (),
        qualifications: Sequence[Mapping[str, Any]] = (),
        resolvable_evidence_refs: Iterable[str] = (),
        current_dependency_hashes: Iterable[str] = (),
        additional_specs: Sequence[Mapping[str, Any]] = (),
    ) -> dict[str, Any]:
        mining = self.miner.mine(semantic_map)
        qualification_values = []
        for qualification in qualifications:
            valid, reason = validate_qualification(qualification)
            if not valid:
                raise ValueError("security_spec_shadow_qualification_invalid:" + reason)
            qualification_values.append(dict(qualification))
            self.store.put_qualification(qualification)
        qualified_by_predicate = {
            str(predicate): str(qualification["content_sha256"])
            for qualification in qualification_values
            for predicate in qualification["qualified_predicates"]
        }
        existing_revisions: dict[str, list[Mapping[str, Any]]] = {}
        for value in additional_specs:
            existing_revisions.setdefault(str(value.get("spec_uid") or ""), []).append(value)
        promoted_specs = []
        for spec in mining["specs"]:
            qualification_ref = qualified_by_predicate.get(str(spec["predicate"]), "")
            if not qualification_ref or spec["origin"] == "llm":
                promoted_specs.append(spec)
                continue
            prior = existing_revisions.get(str(spec["spec_uid"]), [])
            equivalent_stable = next(
                (
                    value
                    for value in sorted(
                        prior, key=lambda item: int(item.get("revision", 0)), reverse=True
                    )
                    if value.get("status") == "stable"
                    and value.get("qualification_ref") == qualification_ref
                    and all(
                        value.get(key) == spec.get(key)
                        for key in (
                            "subject",
                            "scope",
                            "predicate",
                            "parameters",
                            "evidence_refs",
                            "dependency_hashes",
                            "origin",
                            "impact_preview",
                        )
                    )
                ),
                None,
            )
            if equivalent_stable is not None:
                continue
            revision = max([int(value.get("revision", 0)) for value in prior] or [0]) + 1
            promoted_specs.append(
                build_security_spec(
                    subject=spec["subject"],
                    scope=spec["scope"],
                    predicate=spec["predicate"],
                    parameters=spec["parameters"],
                    evidence_refs=spec["evidence_refs"],
                    dependency_hashes=spec["dependency_hashes"],
                    origin=spec["origin"],
                    confidence=spec["confidence"],
                    status="stable",
                    revision=max(1, revision),
                    spec_uid=spec["spec_uid"],
                    supersedes=[str(value["content_sha256"]) for value in prior],
                    qualification_ref=qualification_ref,
                    explanation=(
                        str(spec.get("explanation") or "")
                        + "; activated only in P3 shadow by qualification"
                    ),
                    impact_preview=spec["impact_preview"],
                )
            )
        indexed_specs = {
            (
                str(value.get("spec_uid") or ""),
                int(value.get("revision", 0) or 0),
                str(value.get("content_sha256") or ""),
            ): dict(value)
            for value in [*promoted_specs, *additional_specs]
        }
        specs = list(indexed_specs.values())
        for spec in specs:
            self.store.put_spec(spec)
        compilation = self.compiler.compile(
            specs,
            qualification_hashes=[
                *map(str, qualification_hashes),
                *(str(value["content_sha256"]) for value in qualification_values),
            ],
            resolvable_evidence_refs=resolvable_evidence_refs,
            current_dependency_hashes=current_dependency_hashes,
        )
        self.store.put_compilation(str(compilation["compilation_uid"]), compilation)
        references = self.store.artifact_refs()
        root = self.store.cas.write_root_manifest(references)
        return {
            "schema_version": "zscope.security-spec-shadow-result.v2",
            "security_spec_mode": SECURITY_SPEC_MODE,
            "mined_spec_count": len(mining["specs"]),
            "observation_count": len(mining["observations"]),
            "compiled_spec_count": len(compilation["compiled_specs"]),
            "compilation": compilation,
            "artifact_refs": references,
            "root_manifest_sha256": root["content_sha256"],
            "active_product_effect": "none",
        }
