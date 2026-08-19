"""Fail-closed SecuritySpec compiler and precise impact calculation."""

from __future__ import annotations

from typing import Any, Iterable, Mapping, Sequence

from .canonical import content_sha256, seal
from .lifecycle import SECURITY_SPEC_MODE, require_authoritative_mode
from .models import (
    COMPILATION_MANIFEST_VERSION,
    COMPILED_SPEC_VERSION,
    validate_security_spec,
)


_SCOPE_ORDER = {"project": 0, "module": 1, "file": 2, "function": 3, "callsite": 4}


def _scope_footprint(scope: Mapping[str, Any]) -> str:
    return f"{scope.get('kind')}:{scope.get('target')}"


def _scope_overlaps(left: Mapping[str, Any], right: Mapping[str, Any]) -> bool:
    left_kind, right_kind = str(left.get("kind")), str(right.get("kind"))
    left_target, right_target = str(left.get("target")), str(right.get("target"))
    if left_kind == "project" or right_kind == "project":
        return True
    if left_kind == right_kind:
        return left_target == right_target
    if _SCOPE_ORDER.get(left_kind, 99) < _SCOPE_ORDER.get(right_kind, 99):
        return right_target.startswith(left_target.rstrip("/") + "/")
    return left_target.startswith(right_target.rstrip("/") + "/")


def _specs_conflict(left: Mapping[str, Any], right: Mapping[str, Any]) -> bool:
    if left.get("spec_uid") == right.get("spec_uid"):
        return False
    explicit = set(map(str, left.get("conflicts") or [])) | set(
        map(str, right.get("conflicts") or [])
    )
    if str(left.get("spec_uid")) in explicit or str(right.get("spec_uid")) in explicit:
        return True
    if left.get("predicate") != right.get("predicate"):
        return False
    if left.get("subject") != right.get("subject"):
        return False
    return _scope_overlaps(left.get("scope") or {}, right.get("scope") or {}) and left.get(
        "parameters"
    ) != right.get("parameters")


class SecuritySpecCompiler:
    """Compile only fresh qualification-backed stable specs for live use."""

    compiler_version = "zscope.security-spec-compiler.v2"

    def __init__(self, *, mode: str = SECURITY_SPEC_MODE) -> None:
        require_authoritative_mode(mode)
        self.mode = mode

    def compile(
        self,
        specs: Sequence[Mapping[str, Any]],
        *,
        qualification_hashes: Iterable[str],
        resolvable_evidence_refs: Iterable[str],
        current_dependency_hashes: Iterable[str],
    ) -> dict[str, Any]:
        qualifications = set(map(str, qualification_hashes))
        evidence = set(map(str, resolvable_evidence_refs))
        dependencies = set(map(str, current_dependency_hashes))
        excluded: list[dict[str, str]] = []
        valid_by_uid: dict[str, list[Mapping[str, Any]]] = {}
        for spec in specs:
            valid, reason = validate_security_spec(spec)
            if not valid:
                excluded.append({"spec_uid": str(spec.get("spec_uid") or ""), "reason": reason})
                continue
            uid = str(spec["spec_uid"])
            if spec["status"] != "stable" or not spec["qualification_ref"]:
                excluded.append({"spec_uid": uid, "reason": "not_qualification_backed_stable"})
                continue
            if str(spec["qualification_ref"]) not in qualifications:
                excluded.append({"spec_uid": uid, "reason": "qualification_unresolved"})
                continue
            if not set(map(str, spec["evidence_refs"])).issubset(evidence):
                excluded.append({"spec_uid": uid, "reason": "evidence_unresolved"})
                continue
            if not set(map(str, spec["dependency_hashes"])).issubset(dependencies):
                excluded.append({"spec_uid": uid, "reason": "dependency_stale"})
                continue
            valid_by_uid.setdefault(uid, []).append(spec)

        candidates: list[Mapping[str, Any]] = []
        for uid, revisions in valid_by_uid.items():
            ordered = sorted(revisions, key=lambda value: int(value["revision"]), reverse=True)
            candidates.append(ordered[0])
            for superseded in ordered[1:]:
                excluded.append(
                    {
                        "spec_uid": uid,
                        "reason": "superseded_by_higher_valid_revision",
                    }
                )

        conflicted: set[str] = set()
        for index, left in enumerate(candidates):
            for right in candidates[index + 1 :]:
                if _specs_conflict(left, right):
                    conflicted.update({str(left["spec_uid"]), str(right["spec_uid"])})
        compiled = []
        for spec in candidates:
            uid = str(spec["spec_uid"])
            if uid in conflicted:
                excluded.append({"spec_uid": uid, "reason": "conflicting_active_specs"})
                continue
            body = {
                "schema_version": COMPILED_SPEC_VERSION,
                "protocol_revision": 2,
                "spec_uid": uid,
                "spec_revision": int(spec["revision"]),
                "source_spec_sha256": str(spec["content_sha256"]),
                "predicate": str(spec["predicate"]),
                "subject": dict(spec["subject"]),
                "scope": dict(spec["scope"]),
                "parameters": dict(spec["parameters"]),
                "qualification_ref": str(spec["qualification_ref"]),
                "effect_footprint": sorted(
                    {_scope_footprint(spec["scope"]), *map(str, spec["impact_preview"])}
                ),
                "mode": SECURITY_SPEC_MODE,
            }
            compiled.append(seal(body))
        compiled.sort(key=lambda value: (value["spec_uid"], value["spec_revision"]))
        excluded.sort(key=lambda value: (value["spec_uid"], value["reason"]))
        manifest_body = {
            "schema_version": COMPILATION_MANIFEST_VERSION,
            "protocol_revision": 2,
            "compiler_version": self.compiler_version,
            "mode": SECURITY_SPEC_MODE,
            "compiled_specs": compiled,
            "excluded_specs": excluded,
            "conflict_spec_uids": sorted(conflicted),
            "input_spec_sha256s": sorted(str(spec.get("content_sha256") or "") for spec in specs),
        }
        digest = content_sha256(manifest_body)
        return seal({**manifest_body, "compilation_uid": "SPECCOMP_" + digest[:32]})

    @staticmethod
    def impact_preview(
        before: Mapping[str, Any], after: Mapping[str, Any], *, dependents: Iterable[str] = ()
    ) -> dict[str, Any]:
        before_footprint = {
            _scope_footprint(before.get("scope") or {}),
            *map(str, before.get("impact_preview") or []),
        }
        after_footprint = {
            _scope_footprint(after.get("scope") or {}),
            *map(str, after.get("impact_preview") or []),
        }
        return {
            "invalidated": sorted((before_footprint - after_footprint) | set(dependents)),
            "added": sorted(after_footprint - before_footprint),
            "retained": sorted(before_footprint & after_footprint),
        }

    @staticmethod
    def semantic_overlay(compilation: Mapping[str, Any]) -> dict[str, Any]:
        """Project compiled DSL entries into deterministic candidate semantics.

        This adapter consumes only compiler output.  Candidate generators no
        longer query user workbooks or legacy semantic snapshots directly.
        """

        resources: list[dict[str, Any]] = []
        locks: list[dict[str, Any]] = []
        for value in compilation.get("compiled_specs") or []:
            if not isinstance(value, Mapping):
                continue
            predicate = str(value.get("predicate") or "")
            subject = value.get("subject")
            subject = subject if isinstance(subject, Mapping) else {}
            signature = str(subject.get("signature") or "")
            name = signature.split("(", 1)[0].strip().split()[-1] if signature else ""
            if not name:
                name = str(subject.get("function_uid") or "")
            if not name:
                continue
            base = {
                "name": name,
                "source": "security_spec_compiler",
                "spec_uid": str(value.get("spec_uid") or ""),
                "spec_revision": int(value.get("spec_revision", 0) or 0),
                "scope": dict(value.get("scope") or {}),
                "parameters": dict(value.get("parameters") or {}),
            }
            if predicate in {"acquire", "release", "transfer"}:
                resources.append(
                    {
                        **base,
                        "kind": {
                            "acquire": "resource_acquire",
                            "release": "resource_release",
                            "transfer": "resource",
                        }[predicate],
                    }
                )
            if predicate in {"lock", "unlock"}:
                locks.append({**base, "kind": predicate})
        return {
            "resource_models": resources,
            "lock_models": locks,
            "macro_models": [],
            "dispatcher_models": [],
            "lifecycle_models": [],
            "pointer_target_models": [],
            "function_intent_models": [],
            "engine_status": "complete",
            "engine_errors": [],
            "source": "security_spec_compiler",
        }
