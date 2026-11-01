"""Synthetic, content-bound onboarding for control-plane tests, NOT native evidence.

These fixtures do not assert discovery correctness. Real native coverage lives
in test_semantics_workflow and the existing native inference regressions.
"""

import json
from pathlib import Path

import yaml

from zscope.config.project_semantics import (
    ProjectSemanticsStore,
    empty_project_semantics,
    file_sha256,
)
from zscope.config.semantics_workflow import (
    WORKFLOW_SCHEMA,
    complete_review,
    project_inputs,
    revision,
    roots_digest,
)
from zscope.orchestration.primitive_discovery import (
    _write_discovery_evidence,
    _human_discovery_receipt,
)
from zscope.retrieval.build_context import BuildContext
from zscope.retrieval.indexing_identity import command_identity, search_directories_snapshot


def reviewed_control_plane_project(config_path: Path) -> None:
    raw = yaml.safe_load(config_path.read_text())
    if raw["project"]["language"] == "java":
        return
    if not raw["project"].get("semantics_file"):
        raw["project"]["semantics_file"] = "zscope.semantics.yaml"
        config_path.write_text(yaml.safe_dump(raw, sort_keys=False))
    root = config_path.parent
    path = root / raw["project"]["semantics_file"]
    directory = root / ".zscope_snapshots" / "semantics"
    directory.mkdir(parents=True, exist_ok=True)
    include = directory / "fixture-include"
    include.mkdir(exist_ok=True)
    source = next(iter(root.rglob("*.c")), None)
    if source is None:
        source = directory / "control.c"
        source.write_text("int fixture(void) { return 0; }\n")
    command = {"file": str(source), "directory": str(root), "arguments": ["cc", "-c", str(source)]}
    database = directory / "control-plane-compile.json"
    database.write_text(json.dumps([command]))
    tool = directory / "control-plane-tool"
    tool.write_text("Synthetic identity fixture; not executable native evidence.\n")
    context = BuildContext.create(
        command_identity(command, root),
        tool={
            "synthetic_control_plane": True,
            "capability": {"protocol": "zscope.clang-facts.v2", "target_origin_version": 1},
            "binary": {"path": str(tool), "sha256": file_sha256(tool), "shared_libraries": {}},
        },
        dependencies={str(source): file_sha256(source)},
        dependencies_complete=True,
    ).to_dict()
    context.update(
        status="indexed",
        compilation_database={"path": str(database), "sha256": file_sha256(database)},
        search_directories=search_directories_snapshot([include]),
    )
    document = empty_project_semantics()
    receipt = {
        "schema": "zscope.primitive-discovery.v1",
        "declaration": "none_known",
        "coverage_gaps": [],
        "workflow": {
            "schema": WORKFLOW_SCHEMA,
            "inputs": project_inputs(root, config_path),
            "contexts": [context],
            "roots_digest": roots_digest(document),
            "native_tool": {},
        },
        "test_fixture": "synthetic control-plane only",
    }
    receipt["evidence_ref"] = _write_discovery_evidence(
        root, receipt=receipt, interfaces=[], dispatchers=[], pointer_bindings=[]
    )
    document["discovery_receipt"] = _human_discovery_receipt(receipt)
    ProjectSemanticsStore(path).write(document)
    complete_review(path, root=root, config_path=config_path, expected_revision=revision(path))
