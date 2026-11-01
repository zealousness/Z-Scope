"""Reviewed benchmark inputs and an independent, all-confirm discovery audit.

The reviewed YAML is user input for scans, never input to the discovery exam.
Build receipts are regenerated in each execution project; portable decisions
authorize only identical propositions over identical source bytes.
"""

from __future__ import annotations

import argparse
from copy import deepcopy
import json
from pathlib import Path
from typing import Any, Mapping

from ..config.project_semantics import (
    ProjectSemanticsError,
    ProjectSemanticsStore,
    canonical_digest,
    empty_project_semantics,
    file_sha256,
    validate_project_semantics,
    _yaml_round_trip_dump,
)

COLLECTIONS = ("interfaces", "dispatchers", "function_pointer_bindings")
REVIEW_SCHEMA = "zscope.benchmark-source-review.v2"


def source_hashes(root: Path) -> dict[str, str]:
    """Bind review to public sources, including newly added files, not answers."""
    files = [root / "CMakeLists.txt"]
    for directory in ("src", "include", "internal"):
        files.extend(path for path in (root / directory).rglob("*") if path.is_file())
    return {
        path.relative_to(root).as_posix(): file_sha256(path)
        for path in sorted(files)
        if path.is_file()
    }


def _relative(value: Any) -> str:
    text = str(value or "").replace("\\", "/")
    for prefix in ("src/", "include/", "internal/"):
        marker = "/" + prefix
        if marker in text:
            return prefix + text.rsplit(marker, 1)[1]
    return text


def proposition(collection: str, row: Mapping[str, Any]) -> dict[str, Any]:
    """Compare meaning across relocated builds, never reuse their evidence."""
    if collection == "interfaces":
        selector = row.get("selector") or {}
        result: dict[str, Any] = {
            key: deepcopy(row.get(key))
            for key in (
                "primitive",
                "basis",
                "cases",
                "effects",
                "otherwise",
                "pairs",
                "derived_from",
            )
        }
        result["selector"] = {
            key: selector.get(key, "") for key in ("kind", "name", "file", "signature", "usr")
        }
        result["selector"]["file"] = _relative(selector.get("file"))
        return result
    keys = (
        ("dispatcher", "usr", "handler_name", "handler_usr", "guard")
        if collection == "dispatchers"
        else (
            "caller_usr",
            "slot_usr",
            "slot_expression",
            "slot_signature",
            "target_usrs",
            "attribution",
        )
    )
    result = {key: deepcopy(row.get(key)) for key in keys}
    result["file"] = _relative(row.get("file"))
    if collection == "function_pointer_bindings":
        build = str(row.get("build_context_id") or "")
        callsite = str(row.get("callsite_id") or "")
        result["callsite"] = callsite.removeprefix(build + ":") if build else callsite
    return result


def reviewed_entries(document: Mapping[str, Any]) -> list[dict[str, Any]]:
    entries = []
    for collection in COLLECTIONS:
        for row in document.get(collection, []):
            if row.get("status") not in {"confirmed", "rejected"}:
                raise ProjectSemanticsError("Benchmark input contains an unreviewed proposition")
            entries.append(
                {
                    "collection": collection,
                    "proposition": proposition(collection, row),
                    "status": row["status"],
                    "reason": row.get("review_reason", ""),
                }
            )
    return entries


def seed_document() -> dict[str, Any]:
    document = empty_project_semantics()
    document["discovery_receipt"] = {"declaration": "none_known"}
    return document


def validate_reviewed(reviewed: Mapping[str, Any], root: Path) -> dict[str, Any]:
    """The source-authored YAML is the only scan/scoring authority."""
    validate_project_semantics(reviewed)
    authority = reviewed.get("discovery_receipt", {}).get("benchmark_review", {})
    if authority.get("schema") != REVIEW_SCHEMA or authority.get("sources") != source_hashes(root):
        raise ProjectSemanticsError(
            "Reviewed benchmark semantics has changed or unbound source inputs"
        )
    entries = reviewed_entries(reviewed)
    if authority.get("decisions_digest") != canonical_digest(entries):
        raise ProjectSemanticsError("Reviewed benchmark semantics decision digest mismatch")
    if authority.get("method") != "independent_source_review":
        raise ProjectSemanticsError("Benchmark semantics requires independent source review")
    if authority.get("scope_digest") != canonical_digest(
        {
            "scope": authority.get("scope", {}),
            "negative_contracts": authority.get("negative_contracts", []),
        }
    ):
        raise ProjectSemanticsError("Reviewed scope digest mismatch")
    if any(entry["status"] != "confirmed" for entry in entries):
        raise ProjectSemanticsError("Reference contracts must be reviewed positive contracts")
    return deepcopy(dict(reviewed))


def prepare_reviewed(config_path: Path) -> dict[str, Any]:
    """Bind source-authored contracts to native identities; never discover answers."""
    from ..config.config import ConfigLoader
    from ..config.semantics_workflow import (
        complete_review,
        project_activity,
        save_document,
        workflow_status,
        discovery_snapshot,
    )
    from ..config.project_semantics import rebind_project_semantics
    from ..retrieval.code_index import CodeIndex

    config = ConfigLoader.load(str(config_path))
    root = Path(config.project.project_root)
    if config.project.semantics_file is None:
        raise ProjectSemanticsError("Missing project.semantics_file")
    path = Path(config.project.semantics_file)
    with project_activity(root):
        reviewed = validate_reviewed(ProjectSemanticsStore(path).read(), root)
        before = file_sha256(path)
        if reviewed["dispatchers"] or reviewed["function_pointer_bindings"]:
            raise ProjectSemanticsError(
                "Reviewed callsite bindings require a dedicated native rebinder"
            )
        # Preserve the input authority even if a later stage fails.
        authority_path = root / ".zscope_snapshots" / "semantics" / "reviewed-input.yaml"
        _yaml_round_trip_dump(authority_path, reviewed)
        indexing = deepcopy(config.indexing)
        indexing.backend = "clang"
        # Non-built platform/demo files can use contextual fallback. The
        # snapshot and rebinder require current native compiled instances.
        indexing.clang_frontend = "auto"
        index = CodeIndex(
            root,
            config.project.compile_commands_path,
            source_root=root,
            indexing_config=indexing,
            wait_for_cpg=True,
            defer_svf=True,
        )
        try:
            snapshot = discovery_snapshot(config, index, reviewed)
            document, binding = rebind_project_semantics(
                reviewed, project_root=root, target_id=config.project.target_id, code_index=index
            )
            if not binding["ready"]:
                raise ProjectSemanticsError(
                    "Reviewed native binding failed: " + "; ".join(binding["unresolved"])
                )
            validate_reviewed(reviewed, root)
            if discovery_snapshot(config, index, reviewed) != snapshot:
                raise ProjectSemanticsError("Native inputs changed during reviewed binding")
            if canonical_digest(reviewed_entries(document)) != canonical_digest(
                reviewed_entries(reviewed)
            ):
                raise ProjectSemanticsError("Native binding changed a reviewed semantic decision")
            # This receipt attests actual native identity checks, not successful
            # rediscovery of the expected contracts. Missing detector support
            # must not remove a source-reviewed contract from the benchmark.
            receipt = {
                "schema": "zscope.reviewed-native-binding.v1",
                "operation": "bind_source_reviewed_contracts",
                "workflow": snapshot,
                "binding": binding,
                "blocking_coverage_gaps": [],
            }
            payload = {"schema": "zscope.reviewed-native-evidence.v1", "receipt": receipt}
            evidence = (
                root
                / ".zscope_snapshots"
                / "semantics"
                / ("discovery-" + canonical_digest(payload) + ".json")
            )
            evidence.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
            reference = evidence.relative_to(root).as_posix()
            for row in document["interfaces"]:
                row["evidence_ref"] = reference + "#" + row["id"]
            document["discovery_receipt"] = {
                "schema": receipt["schema"],
                "operation": receipt["operation"],
                "declaration": reviewed["discovery_receipt"]["declaration"],
                "benchmark_review": reviewed["discovery_receipt"]["benchmark_review"],
                "workflow_digest": canonical_digest(snapshot),
                "evidence_ref": reference,
                "blocking_coverage_gaps": [],
                "coverage_gap_count": 0,
            }
            version = save_document(path, document, root=root, expected_revision=before)
            complete_review(path, root=root, config_path=config_path, expected_revision=version)
            status = workflow_status(ProjectSemanticsStore(path).read(), root, config_path)
            if not status["ready"]:
                raise ProjectSemanticsError("Rebound benchmark semantics is not ready")
            _yaml_round_trip_dump(
                root / ".zscope_snapshots" / "semantics" / "effective.yaml",
                ProjectSemanticsStore(path).read(),
            )
            result = {
                "schema_version": "zscope.benchmark-semantics-preparation.v1",
                "ready": True,
                "llm_called": False,
                "input_sha256": before,
                "effective_sha256": file_sha256(path),
                "counts": {key: len(document[key]) for key in COLLECTIONS},
                "binding": binding,
                "workflow": status,
            }
            (root / ".zscope_snapshots" / "semantics" / "benchmark-preparation.json").write_text(
                json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8"
            )
            return result
        finally:
            index.close()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(prepare_reviewed(args.config.resolve()), ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
