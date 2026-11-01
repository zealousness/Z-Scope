"""Onboarding and HTTP publication boundaries. Synthetic receipts are labelled."""

from copy import deepcopy
import json
import os
from pathlib import Path
import subprocess
import time

from click.testing import CliRunner
import pytest
import yaml

from zscope.cli.config_cli import main
from zscope.config.config import ConfigLoader
from zscope.config.project_semantics import (
    ProjectSemanticsStore,
    canonical_digest,
    file_sha256,
    validate_project_semantics,
)
from zscope.config.semantics_workflow import (
    WORKFLOW_SCHEMA,
    project_inputs,
    revision,
    roots_digest,
    workflow_status,
    require_workflow,
)
from zscope.orchestration.primitive_discovery import (
    _write_discovery_evidence,
    _human_discovery_receipt,
)
from zscope.web.projects import ProjectLibrary
from zscope.web.semantics_service import SemanticsService


@pytest.fixture
def project(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    (root / "unit.c").write_text(
        "#include <stdlib.h>\nvoid *allocate(unsigned long n) { return malloc(n); }\nvoid release(void *p) { free(p); }\n"
    )
    (root / "compile_commands.json").write_text(
        json.dumps(
            [{"directory": str(root), "file": "unit.c", "arguments": ["clang", "-c", "unit.c"]}]
        )
    )
    library = ProjectLibrary(tmp_path / "projects.json")
    library.create(
        {
            "directory": str(root),
            "filename": "custom.yaml",
            "language": "c_cpp",
            "compile_commands": "compile_commands.json",
            "base_url": "http://127.0.0.1:1/v1",
            "model": "synthetic",
            "api_key": "synthetic",
        }
    )
    return SemanticsService(root / "custom.yaml")


def base(service):
    data = service.status()
    return {"version": data["version"], "evidence_version": data["evidence_version"]}


def candidate(root, identifier="project:allocate", *, valid=True):
    digest = file_sha256(root / "unit.c")
    return {
        "id": identifier,
        "primitive": False,
        "basis": "derived_wrapper",
        "status": "pending",
        "selector": {
            "kind": "function",
            "name": "allocate",
            "usr": "c:@F@allocate",
            "signature": "void *(unsigned long)",
            "file": "unit.c",
        },
        "cases": [{"when": {"op": "true" if valid else "unknown"}, "effect": "applies"}],
        "otherwise": "unknown",
        "effects": [
            {
                "domain": "resource",
                "role": "allocator",
                "operation": "allocate",
                "carrier": {"root": "return", "phase": "post", "dereference": 0, "members": []},
                "strength": "must_under_guard",
                "resource_family": "heap",
            }
        ],
        "pairs": ["builtin:free"],
        "derived_from": ["builtin:malloc"],
        "evidence_digest": digest,
        "variants": [
            {
                "target_id": "main",
                "build_context_id": "synthetic-build",
                "usr": "c:@F@allocate",
                "signature": "void *(unsigned long)",
                "file": "unit.c",
                "source_sha256": digest,
                "evidence_sha256": digest,
                "native_input_hash": digest,
                "identity_status": "exact",
            }
        ],
    }


def synthetic_receipt(service, monkeypatch, rows=()):
    # This fixture exercises authority/version logic, not native inference.
    monkeypatch.setattr(
        "zscope.retrieval.build_context.context_input_status", lambda context: "current"
    )
    monkeypatch.setattr(
        "zscope.orchestration.instance_semantics_context._native_inputs_current",
        lambda context: True,
    )
    path, document = service.read()
    document["interfaces"] = list(deepcopy(rows))
    receipt = {
        "schema": "zscope.primitive-discovery.v1",
        "declaration": "none_known",
        "coverage_gaps": [],
        "workflow": {
            "schema": WORKFLOW_SCHEMA,
            "inputs": project_inputs(service.root, service.config_path),
            "contexts": [{"synthetic": True}],
            "roots_digest": roots_digest(document),
            "native_tool": {},
        },
        "analyzed_function_instances": 2,
        "interface_candidates": len(rows),
    }
    reference = _write_discovery_evidence(
        service.root, receipt=receipt, interfaces=list(rows), dispatchers=[], pointer_bindings=[]
    )
    receipt["evidence_ref"] = reference
    document["discovery_receipt"] = _human_discovery_receipt(receipt)
    for row in document["interfaces"]:
        row["evidence_ref"] = reference + "#" + row["id"]
    ProjectSemanticsStore(path).write(document)


def test_empty_project_requires_explicit_declaration_discovery_and_zero_result_review(
    project, monkeypatch
):
    assert project.status()["stage"] == "undeclared"
    config = ConfigLoader.load(str(project.config_path), read_only=True)
    with pytest.raises(ValueError, match="尚未就绪"):
        require_workflow(config)
    response = project.post(
        "/api/semantics/declare", {**base(project), "declaration": "none_known"}
    )
    assert response[0] == 200 and response[1]["stage"] == "needs_discovery"
    assert project.post("/api/semantics/complete", base(project))[0] == 400
    synthetic_receipt(project, monkeypatch)
    assert project.status()["stage"] == "needs_review"
    assert project.post("/api/semantics/complete", base(project))[0] == 200
    require_workflow(config)
    (project.root / "new.h").write_text("#define NEW_INTERFACE 1\n")
    assert not project.status()["ready"]
    with pytest.raises(ValueError, match="源码"):
        require_workflow(config)


def test_atomic_batch_rejects_invalid_branch_without_partial_decision(project, monkeypatch):
    rows = [candidate(project.root), candidate(project.root, "project:invalid", valid=False)]
    synthetic_receipt(project, monkeypatch, rows)
    original = project.location().read_bytes()
    queue = project.get("/api/semantics/entries")[1]["rows"]
    items = [{**row, "decision": "confirmed"} for row in queue]
    assert project.post("/api/semantics/review", {**base(project), "items": items})[0] == 400
    assert project.location().read_bytes() == original
    assert (
        project.post(
            "/api/semantics/review", {**base(project), "items": [items[0]], "preview": True}
        )[0]
        == 200
    )
    assert project.location().read_bytes() == original
    assert project.post("/api/semantics/review", {**base(project), "items": [items[0]]})[0] == 200
    second = {**items[1], "decision": "rejected", "reason": "条件未知，不授予执行效果"}
    assert project.post("/api/semantics/review", {**base(project), "items": [second]})[0] == 200
    assert project.status()["discovery_current"]
    assert project.post("/api/semantics/complete", base(project))[1]["ready"]


def test_yaml_comments_drafts_and_external_edit_conflicts(project):
    path = project.location()
    path.write_text("# keep this review comment\n" + path.read_text())
    before = base(project)
    content = path.read_text()
    assert (
        project.post("/api/semantics/save", {**before, "content": content + "# reviewer footer\n"})[
            0
        ]
        == 200
    )
    assert "# reviewer footer" in path.read_text()
    assert project.post("/api/semantics/save", {**before, "content": content})[0] == 409
    original = path.read_bytes()
    assert (
        project.post("/api/semantics/save", {**base(project), "content": "interfaces: [broken"})[0]
        == 400
    )
    assert path.read_bytes() == original


def test_receipt_cannot_be_forged_in_advanced_yaml(project):
    path, document = project.read()
    document["discovery_receipt"] = {"human_review": {"ready": True}}
    code, result = project.post(
        "/api/semantics/save", {**base(project), "content": yaml.safe_dump(document)}
    )
    assert code == 400 and "收据" in result["error"]
    assert not project.status()["ready"]


def test_entry_draft_preserves_evidence_and_comments(project, monkeypatch):
    synthetic_receipt(project, monkeypatch, [candidate(project.root)])
    entry = project.get("/api/semantics/entry", "id=project:allocate")[1]
    code, result = project.post(
        "/api/semantics/draft",
        {
            **entry,
            "id": entry["row"]["id"],
            "content": entry["content"] + "\nreview_note: retained draft\n",
        },
    )
    assert code == 200, result
    assert project.read()[1]["interfaces"][0]["review_note"] == "retained draft"


def test_cli_review_completion_and_read_only_status(project, monkeypatch):
    runner = CliRunner()
    result = runner.invoke(
        main, ["review-semantics", "--config", str(project.config_path), "--declare-none", "--json"]
    )
    assert result.exit_code == 0, result.output
    synthetic_receipt(project, monkeypatch)
    before = project.location().read_bytes()
    result = runner.invoke(
        main, ["review-semantics", "--config", str(project.config_path), "--json"]
    )
    assert result.exit_code == 0 and not json.loads(result.output)["ready"]
    assert project.location().read_bytes() == before
    result = runner.invoke(
        main, ["review-semantics", "--config", str(project.config_path), "--complete", "--json"]
    )
    assert result.exit_code == 0 and json.loads(result.output)["ready"]


def test_worker_lock_blocks_semantic_publication_and_job_creation(project):
    from zscope.orchestration.jobs.service import ScanJobService

    code = "from pathlib import Path; import time; from zscope.config.semantics_workflow import project_activity; import sys\nwith project_activity(Path(sys.argv[1])):\n print('locked',flush=True); time.sleep(10)"
    import sys

    process = subprocess.Popen(
        [sys.executable, "-c", code, str(project.root)], stdout=subprocess.PIPE, text=True
    )
    try:
        assert process.stdout.readline().strip() == "locked"
        assert (
            project.post("/api/semantics/declare", {**base(project), "declaration": "none_known"})[
                0
            ]
            == 409
        )
        response = ScanJobService(project.config_path, spawn_owner=False).start(
            request_id="semantics-gate-test"
        )
        assert (
            response.status_code == 409
            and response.payload["code"] == "project_semantics_not_ready"
        )
    finally:
        process.terminate()
        process.wait(timeout=10)


def test_legacy_scan_request_requires_same_onboarding(project):
    from zscope.orchestration.scan_request import ScanRequestService, ScanRequestError

    with pytest.raises(ScanRequestError, match="项目原语尚未就绪"):
        ScanRequestService(project.config_path).start()


def test_read_only_task_gate_does_not_create_state(project):
    from zscope.orchestration.primitive_tasks import PrimitiveTasks

    tasks = PrimitiveTasks(project.config_path)
    assert not tasks.db.exists()
    assert tasks.has_active() is False
    assert not tasks.db.exists()


def test_effective_semantics_path_and_business_answer_store(project):
    from zscope.orchestration.jobs.scan_work import _business_answers_digest
    from zscope.config.user_config_store import UserConfigStore

    config = ConfigLoader.load(str(project.config_path), read_only=True)
    assert Path(config.analysis.user_config_db) == project.location()
    before = project.location().read_bytes()
    empty_digest = _business_answers_digest(config)
    assert empty_digest is not None
    store = UserConfigStore(project.location())
    assert store.db_path == project.root / ".zscope_snapshots/user_config.state.db"
    assert _business_answers_digest(config) == empty_digest
    assert project.location().read_bytes() == before


def test_document_snapshot_rejects_invalid_yaml_and_racing_editor(project, monkeypatch):
    path = project.location()
    original = path.read_text()
    path.write_text(original + "\ninterfaces: []\n")
    assert project.get("/api/semantics/document")[0] == 400
    path.write_text("interfaces: [\n")
    assert project.get("/api/semantics/document")[0] == 400
    path.write_text(original)
    monkeypatch.setattr("zscope.web.semantics_service.revision", lambda _: "changed-during-read")
    assert project.get("/api/semantics/document")[0] == 409


def test_confirmed_unknown_or_false_applies_is_not_executable(project):
    path, document = project.read()
    row = candidate(project.root)
    row["status"] = "confirmed"
    document["interfaces"] = [row]
    for condition in ({"op": "unknown"}, {"op": "false"}, {"op": "not", "item": {"op": "true"}}):
        row["cases"] = [{"when": condition, "effect": "applies"}]
        with pytest.raises(ValueError, match="applies"):
            validate_project_semantics(document)


@pytest.mark.skipif(
    not os.environ.get("Z_SCOPE_TEST_CLANG_INDEXER"),
    reason="Requires actual matching Linux native tool",
)
def test_real_native_discovery_and_current_receipt(project, monkeypatch):
    from zscope.retrieval.code_index import CodeIndex
    from zscope.orchestration.primitive_discovery import discover_project_primitives
    from zscope.orchestration import primitive_discovery as discovery_module

    infer = discovery_module.infer_native_wrapper
    attempts = []

    def observe(context, registry):
        result = infer(context, registry)
        attempts.append((context["func_name"], result))
        return result

    monkeypatch.setattr(discovery_module, "infer_native_wrapper", observe)

    source = project.root / "unit.c"
    source.write_text(
        '#if __has_include("policy.runtime")\n#include "policy.runtime"\n#endif\n'
        + source.read_text()
        + "void *second_layer(unsigned long n) { void *p=allocate(n); return p; }\n"
    )
    project.post("/api/semantics/declare", {**base(project), "declaration": "none_known"})
    config = ConfigLoader.load(str(project.config_path), read_only=True)
    config.indexing.backend = "clang"
    config.indexing.clang_frontend = "batch"
    config.indexing.clang_indexer_path = os.environ["Z_SCOPE_TEST_CLANG_INDEXER"]
    index = CodeIndex(
        project.root,
        config.project.compile_commands_path,
        source_root=project.root,
        indexing_config=config.indexing,
        wait_for_cpg=True,
        defer_svf=True,
    )
    stages = []
    try:
        result = discover_project_primitives(
            config, index, progress=lambda stage, details: stages.append(stage)
        )
    finally:
        index.close()
    assert result["receipt"]["analyzed_function_instances"] >= 2
    assert "model_review" in stages and "merging" in stages
    assert project.status()["discovery_current"], project.status()
    assert not project.status()["ready"]
    assert any(
        row["selector"]["name"] == "second_layer" and row["derived_from"]
        for row in project.read()[1]["interfaces"]
    ), attempts
    assert all(row["status"] == "pending" for row in project.read()[1]["interfaces"])
    # A generated report is unrelated to the complete native lookup set.
    # An arbitrary-suffix previously absent include is a real input change.
    (project.root / "report.json").write_text("{}")
    assert project.status()["discovery_current"], project.status()
    (project.root / "policy.runtime").write_text("#define CHANGED_POLICY 1\n")
    assert not project.status()["discovery_current"]


@pytest.mark.skipif(
    not os.environ.get("Z_SCOPE_TEST_CLANG_INDEXER"), reason="Requires matching Linux native tool"
)
def test_detached_inventory_persists_and_replays_without_model(project, monkeypatch):
    native = Path(os.environ["Z_SCOPE_TEST_CLANG_INDEXER"])
    monkeypatch.setenv("PATH", str(native.parent) + os.pathsep + os.environ["PATH"])
    payload = {**base(project), "mode": "inventory", "request_id": "native-inventory-test"}
    code, result = project.post("/api/semantics/tasks", payload)
    assert code == 202, result
    task = result["task"]
    replay = project.post("/api/semantics/tasks", payload)
    assert replay[0] == 202 and replay[1]["task"]["id"] == task["id"]
    deadline = time.monotonic() + 45
    while time.monotonic() < deadline:
        state = project.tasks.get(task["id"])
        if state["task"]["status"] not in {"queued", "running", "publishing"}:
            break
        time.sleep(0.2)
    assert state["task"]["status"] == "completed", state
    rebuilt = SemanticsService(project.config_path)
    symbols = rebuilt.get("/api/semantics/symbols")[1]
    assert symbols["current"] and symbols["total"] >= 2, symbols
    assert "model_review" not in [event["stage"] for event in state["events"]]
    assert project.status()["stage"] == "undeclared"
    symbol = next(row for row in symbols["symbols"] if row["name"] == "allocate")
    response = project.post(
        "/api/semantics/primitive",
        {
            **base(project),
            "inventory_version": symbols["version"],
            "symbol_id": symbol["id"],
            "role": "allocator",
        },
    )
    assert response[0] == 200, response
    assert project.read()[1]["interfaces"][0]["selector"]["usr"] == symbol["usr"]
    assert project.read()[1]["interfaces"][0]["selector"]["build_context_id"] == symbol[
        "build_context_id"
    ]
    assert not project.status()["ready"]
    # Exercise the actual Web task path after guided declaration, not only the
    # in-process discovery core. The fixture's model endpoint is unavailable;
    # deterministic results remain pending and never gain model authority.
    code, result = project.post(
        "/api/semantics/tasks",
        {**base(project), "mode": "discovery", "request_id": "native-web-discovery-test"},
    )
    assert code == 202, result
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        state = rebuilt.tasks.get(result["task"]["id"])
        if state["task"]["status"] not in {"queued", "running", "publishing"}:
            break
        time.sleep(0.2)
    assert state["task"]["status"] == "completed", state
    assert rebuilt.status()["stage"] == "needs_review", rebuilt.status()
    assert "model_review" in [event["stage"] for event in state["events"]]
    assert all(row["status"] == "pending" for row in rebuilt.read()[1]["interfaces"])


def test_task_cancel_before_claim_and_request_conflict(project, monkeypatch):
    monkeypatch.setattr(
        "zscope.orchestration.primitive_tasks.subprocess.Popen", lambda *args, **kwargs: None
    )
    payload = {**base(project), "mode": "inventory", "request_id": "queued-task-test"}
    code, created = project.post("/api/semantics/tasks", payload)
    assert code == 202
    assert project.status()["stage"] == "discovering"
    assert project.post("/api/semantics/tasks", {**payload, "mode": "discovery"})[0] == 409
    task_id = created["task"]["id"]
    before = project.location().read_bytes()
    assert project.post("/api/semantics/cancel", {"id": task_id})[0] == 200
    # execute normally registers a signal handler; preserve pytest's handler.
    import signal

    handler = signal.getsignal(signal.SIGTERM)
    try:
        project.tasks.execute(task_id)
    finally:
        signal.signal(signal.SIGTERM, handler)
    assert project.tasks.get(task_id)["task"]["status"] == "cancelled"
    assert project.location().read_bytes() == before


@pytest.mark.parametrize("outcome", ["cancel", "crash"])
def test_live_preparation_owner_cancel_and_crash_preserve_yaml(project, monkeypatch, outcome):
    """Real detached owner/locks/signals; only slow preparation is controlled."""
    import sys

    before = project.location().read_bytes()
    with monkeypatch.context() as patch:
        patch.setattr("zscope.orchestration.primitive_tasks.subprocess.Popen", lambda *a, **k: None)
        code, result = project.post(
            "/api/semantics/tasks",
            {**base(project), "mode": "inventory", "request_id": "live-owner-" + outcome},
        )
    assert code == 202
    task_id = result["task"]["id"]
    script = """
import sys, time
from pathlib import Path
from zscope.orchestration import primitive_tasks
def controlled(config, *, mode, progress):
    progress('preparing_index', {'fixture': 'controlled slow preparation'})
    while True:
        time.sleep(0.1)
primitive_tasks.run_preparation = controlled
primitive_tasks.PrimitiveTasks(Path(sys.argv[1])).execute(sys.argv[2])
"""
    process = subprocess.Popen(
        [sys.executable, "-c", script, str(project.config_path), task_id],
        start_new_session=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            task = project.tasks.get(task_id)["task"]
            if task.get("stage") == "preparing_index":
                break
            if process.poll() is not None:
                pytest.fail(process.stderr.read())
            time.sleep(0.1)
        assert task["status"] == "running" and task["pid"] == process.pid
        if outcome == "cancel":
            assert project.post("/api/semantics/cancel", {"id": task_id})[0] == 200
        else:
            process.kill()
        process.wait(timeout=10)
        reopened = SemanticsService(project.config_path)
        task = reopened.tasks.get(task_id)["task"]
        assert task["status"] == ("cancelled" if outcome == "cancel" else "failed")
        assert not reopened.tasks.has_active()
        assert project.location().read_bytes() == before
        assert project.post(
            "/api/semantics/declare", {**base(project), "declaration": "none_known"}
        )[0] == 200
    finally:
        if process.poll() is None:
            process.kill()
        process.wait(timeout=10)


@pytest.mark.skipif(
    not os.environ.get("Z_SCOPE_TEST_CLANG_INDEXER"), reason="Requires matching Linux native tool"
)
def test_real_native_macro_and_overload_identity_in_two_builds(project, monkeypatch):
    from zscope.retrieval.code_index import CodeIndex
    from zscope.orchestration.primitive_discovery import (
        discover_project_primitives,
        _stream_function_work,
    )
    from zscope.orchestration import primitive_discovery as discovery_module

    infer = discovery_module.infer_native_wrapper
    attempts = []

    def observe(context, registry):
        result = infer(context, registry)
        attempts.append((context["func_name"], result))
        return result

    monkeypatch.setattr(discovery_module, "infer_native_wrapper", observe)

    root_declaration = candidate(project.root)
    (project.root / "unit.c").unlink()
    source = project.root / "chain.cpp"
    source.write_text(
        "#include <stdlib.h>\n"
        "void *project_acquire(unsigned long n) { return malloc(n); }\n"
        "void *layered(unsigned long n) { return project_acquire(n); }\n"
        "void *layered(unsigned n) { return project_acquire(n); }\n"
        "#define PROJECT_ALLOC(n) project_acquire(n)\n"
        "void *macro_caller(unsigned long n) { return PROJECT_ALLOC(n); }\n"
    )
    commands = [
        {
            "directory": str(project.root),
            "file": source.name,
            "arguments": ["clang++", "-c", source.name, f"-DMODE={mode}"],
        }
        for mode in (1, 2)
    ]
    (project.root / "compile_commands.json").write_text(json.dumps(commands))
    project.post("/api/semantics/declare", {**base(project), "declaration": "none_known"})
    config = ConfigLoader.load(str(project.config_path), read_only=True)
    config.indexing.backend = "clang"
    config.indexing.clang_frontend = "batch"
    config.indexing.clang_indexer_path = os.environ["Z_SCOPE_TEST_CLANG_INDEXER"]
    index = CodeIndex(
        project.root,
        config.project.compile_commands_path,
        source_root=project.root,
        indexing_config=config.indexing,
        wait_for_cpg=True,
        defer_svf=True,
    )
    try:
        # A known custom root is an explicit user specification, chosen from
        # real native identity; the overloaded wrappers must still be inferred.
        _, gaps, work, _ = _stream_function_work(index, project.root)
        assert not gaps, gaps
        overloaded_instances = [
            item for functions in work.values() for item in functions if item[3] == "layered"
        ]
        assert len(overloaded_instances) == 4
        assert len({item[0].usr for item in overloaded_instances}) == 2
        scope, _, _, name, signature = next(
            item
            for functions in work.values()
            for item in functions
            if item[3] == "project_acquire"
        )
        root = root_declaration
        root.update(primitive=True, basis="expected_contract", variants=[])
        root["selector"] = {
            "kind": "function",
            "name": name,
            "file": source.name,
            "signature": signature,
            "usr": scope.usr,
        }
        document = project.read()[1]
        document["interfaces"] = [root]
        document["discovery_receipt"]["declaration"] = "custom"
        ProjectSemanticsStore(project.location()).write(document)
        discover_project_primitives(config, index)
    finally:
        index.close()
    rows = project.read()[1]["interfaces"]
    assert all(len(row["variants"]) == 2 for row in rows)
    assert all(row["status"] == "pending" for row in rows)
    # The current resource-value interpreter explicitly excludes general C++
    # wrappers. Native overload identity is still retained in the inventory;
    # this Web integration must not manufacture executable candidates.
    assert any("native_value_receipt_unavailable" in result["reasons"] for _, result in attempts)
    assert any(row["selector"]["kind"] == "macro" for row in rows)
    assert project.status()["discovery_current"] and not project.status()["ready"]
