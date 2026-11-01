"""Project-picker isolation over real local HTTP; no scanner or model runs."""

from concurrent.futures import ThreadPoolExecutor
from http.client import HTTPConnection
from http.server import ThreadingHTTPServer
import json
from pathlib import Path
import threading
from types import SimpleNamespace

from click.testing import CliRunner
import pytest
import yaml

from zscope.web import projects, server
from zscope.reporting.json_io import read_report, write_report_atomic
from zscope.reporting.report import FinalReport, Issue
from zscope.reporting.views import build_report_views


@pytest.fixture
def library(tmp_path):
    return projects.ProjectLibrary(tmp_path / "registry" / "projects.json")


def create(library, root, label="demo"):
    root.mkdir(exist_ok=True)
    (root / "unit.c").write_text("void f(void) {}\n", encoding="utf-8")
    (root / "compile_commands.json").write_text("[]", encoding="utf-8")
    return library.create(
        {
            "directory": str(root),
            "language": "c_cpp",
            "compile_commands": "compile_commands.json",
            "preset": "fast",
            "base_url": "http://dummy.invalid/v1",
            "model": label,
            "api_key": "synthetic-secret-" + label,
        }
    )["project"]


@pytest.fixture
def http(library, monkeypatch):
    monkeypatch.setattr(server, "_project_library", library)
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), server.ZScopeHandler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()

    def request(path, *, project=None, payload=None, method="GET", headers=None, body=None):
        values = dict(headers or {})
        if project is not None:
            values["X-ZScope-Project"] = project
        if payload is not None:
            body = json.dumps(payload).encode()
            values.setdefault("Content-Type", "application/json")
        connection = HTTPConnection("127.0.0.1", httpd.server_port, timeout=10)
        try:
            connection.request(method, path, body=body, headers=values)
            response = connection.getresponse()
            raw = response.read()
            return response.status, json.loads(raw) if raw else {}
        finally:
            connection.close()

    request.port = httpd.server_port
    try:
        yield request
    finally:
        httpd.shutdown()
        httpd.server_close()
        thread.join(timeout=5)


def test_cli_web_without_yaml_does_not_load_analysis(tmp_path, monkeypatch):
    from zscope.cli import cli

    monkeypatch.chdir(tmp_path)
    seen = []
    monkeypatch.setattr(server, "run_server", lambda **kwargs: seen.append(kwargs))

    def forbidden(*args, **kwargs):
        pytest.fail("project picker must not load configuration or construct an analysis engine")

    monkeypatch.setattr(cli.ConfigLoader, "load", forbidden)
    monkeypatch.setattr(cli, "CodeIndex", forbidden)
    result = CliRunner().invoke(cli.main, ["--web"])
    assert result.exit_code == 0, result.output
    assert len(seen) == 1
    assert seen[0]["project_picker"] is True and seen[0]["config_path"] is None
    assert not list(tmp_path.iterdir())


def test_browse_lists_directories_and_yaml_only(library, tmp_path):
    root = tmp_path / "browse"
    root.mkdir()
    (root / "nested").mkdir()
    (root / "config.YML").write_text("dummy", encoding="utf-8")
    (root / "source.c").write_text("dummy", encoding="utf-8")
    result = library.browse(str(root))
    assert [(row["name"], row["kind"]) for row in result["entries"]] == [
        ("nested", "directory"),
        ("config.YML", "yaml"),
    ]
    assert result["path"] == str(root.resolve()) and result["has_yaml"] is True
    with pytest.raises(ValueError, match="绝对路径"):
        library.browse("relative")


def test_create_is_rootless_exclusive_and_registry_contains_paths_only(library, tmp_path):
    root = tmp_path / "project with spaces"
    opened = create(library, root, "private-model")
    document = yaml.safe_load((root / "zscope.yaml").read_text(encoding="utf-8"))
    assert "root" not in document["project"] and "source_root" not in document["project"]
    original = (root / "zscope.yaml").read_bytes()
    with pytest.raises((ValueError, FileExistsError)):
        create(library, root, "replacement")
    assert (root / "zscope.yaml").read_bytes() == original
    registry = library.registry.read_text(encoding="utf-8")
    assert "synthetic-secret" not in registry and "private-model" not in registry
    assert "dummy.invalid" not in registry
    restored = projects.ProjectLibrary(library.registry)
    assert restored.list()["projects"][0]["project_id"] == opened["project_id"]
    assert restored.context(opened["project_id"])._config_service.path == root / "zscope.yaml"
    assert library.registry.stat().st_mode & 0o077 == 0


@pytest.mark.parametrize(
    "filename", ["../escape.yaml", "nested/config.yaml", "nested\\config.yaml", "config.json"]
)
def test_create_refuses_filename_escape(library, tmp_path, filename):
    with pytest.raises(ValueError):
        library.create({"directory": str(tmp_path), "filename": filename})
    assert not (tmp_path.parent / "escape.yaml").exists()


def test_unconfigured_project_can_be_created_and_edited_but_not_scanned(
    http, tmp_path, monkeypatch
):
    for key in ("Z_SCOPE_LLM_BASE_URL", "Z_SCOPE_LLM_MODEL", "Z_SCOPE_API_KEY"):
        monkeypatch.delenv(key, raising=False)
    root = tmp_path / "setup later"
    root.mkdir()
    status, opened = http(
        "/api/projects/create",
        method="POST",
        payload={
            "directory": str(root),
            "language": "java",
            "preset": "fast",
        },
    )
    assert status == 200, opened
    identity = opened["project"]["project_id"]
    status, document = http("/api/config/structured", project=identity)
    assert status == 200, document
    assert document["config"]["llms"]["default"]["api_key"] == "${Z_SCOPE_API_KEY}"
    status, rejected = http(
        "/api/jobs",
        method="POST",
        project=identity,
        payload={"request_id": "unconfigured-must-not-scan"},
    )
    assert status >= 400, rejected


def test_http_browse_and_reopen_recent_project_after_library_restart(
    http, library, tmp_path, monkeypatch
):
    opened = create(library, tmp_path / "recent")
    status, directory = http("/api/projects/browse?path=" + str(tmp_path))
    assert status == 200 and any(row["name"] == "recent" for row in directory["entries"])
    monkeypatch.setattr(server, "_project_library", projects.ProjectLibrary(library.registry))
    status, recent = http("/api/projects")
    assert status == 200 and recent["projects"][0]["project_id"] == opened["project_id"]
    assert http("/api/config/structured", project=opened["project_id"])[0] == 200


def test_primitive_routes_bind_project_and_preserve_other_document(http, library, tmp_path):
    first = create(library, tmp_path / "first")
    second = create(library, tmp_path / "second")
    assert http("/api/semantics")[0] == 409
    assert http("/api/semantics", project="unknown-project")[0] == 409
    code, state = http("/api/semantics", project=first["project_id"])
    assert code == 200 and state["stage"] == "undeclared"
    untouched = (tmp_path / "second" / "zscope.semantics.yaml").read_bytes()
    code, result = http(
        "/api/semantics/declare", method="POST", project=first["project_id"],
        payload={"version": state["version"], "evidence_version": "", "declaration": "none_known"},
    )
    assert code == 200 and result["stage"] == "needs_discovery", result
    assert (tmp_path / "second" / "zscope.semantics.yaml").read_bytes() == untouched
    assert http("/api/semantics/task?id=foreign-task", project=second["project_id"])[0] == 400
    assert http("/api/semantics", project=second["project_id"])[1]["stage"] == "undeclared"


def test_invalid_registry_is_an_explained_error(library):
    library.registry.parent.mkdir()
    library.registry.write_text("[]", encoding="utf-8")
    with pytest.raises(ValueError, match="格式"):
        library.list()


def test_create_refuses_directory_retarget_before_writing(library, tmp_path, monkeypatch):
    from zscope.cli import init

    selected, other = tmp_path / "selected", tmp_path / "other"
    selected.mkdir()
    other.mkdir()
    original = init.render_project_config

    def retarget(directory, **kwargs):
        content = original(directory, **kwargs)
        directory.rename(tmp_path / "original-selected")
        directory.symlink_to(other, target_is_directory=True)
        return content

    monkeypatch.setattr(init, "render_project_config", retarget)
    with pytest.raises((ValueError, OSError)):
        library.create(
            {
                "directory": str(selected),
                "language": "java",
                "preset": "fast",
                "base_url": "http://dummy.invalid/v1",
                "model": "dummy",
                "api_key": "dummy",
            }
        )
    assert not (other / "zscope.yaml").exists()


def test_concurrent_create_cannot_replace_another_tab(library, tmp_path):
    root = tmp_path / "concurrent"
    root.mkdir()

    errors = []

    def attempt(label):
        try:
            library.create(
                {
                    "directory": str(root),
                    "language": "java",
                    "preset": "fast",
                    "model": label,
                    "base_url": "http://dummy.invalid/v1",
                    "api_key": "synthetic-secret",
                }
            )
            return label
        except (ValueError, FileExistsError) as exc:
            errors.append(str(exc))
            return None

    with ThreadPoolExecutor(2) as pool:
        results = list(pool.map(attempt, ["first", "second"]))
    assert sum(item is not None for item in results) == 1, errors
    document = yaml.safe_load((root / "zscope.yaml").read_text(encoding="utf-8"))
    assert document["llms"]["default"]["models"] == [next(item for item in results if item)]


def test_directory_open_resolves_yaml_symlink_to_one_project(library, tmp_path):
    actual = tmp_path / "actual"
    expected = create(library, actual)
    alias = tmp_path / "alias"
    alias.mkdir()
    (alias / "zscope.yaml").symlink_to(actual / "zscope.yaml")
    opened = library.open(str(alias))["project"]
    assert opened["project_id"] == expected["project_id"]
    assert Path(opened["root"]) == actual
    context = library.context(opened["project_id"])
    assert context._config_service.path.parent == actual
    assert Path(context._report_feedback_service.report_filename).parent == actual


def test_context_refuses_symlink_retarget_during_factory(library, tmp_path, monkeypatch):
    first = tmp_path / "first"
    second = tmp_path / "second"
    opened = create(library, first, "first")
    create(library, second, "second")
    original = projects.ProjectContext

    def retarget(path, scan_depth=None):
        path.unlink()
        path.symlink_to(second / "zscope.yaml")
        return original(path, scan_depth)

    monkeypatch.setattr(projects, "ProjectContext", retarget)
    with pytest.raises((ValueError, OSError)):
        library.context(opened["project_id"])


def test_multiple_targets_remain_editable_without_first_target_execution(
    library, tmp_path, monkeypatch
):
    root = tmp_path / "multiple"
    opened = create(library, root)
    path = Path(opened["config_path"])
    document = yaml.safe_load(path.read_text(encoding="utf-8"))
    document["project"]["targets"].append({"id": "second", "compile_commands": "second.json"})
    path.write_text(yaml.safe_dump(document), encoding="utf-8")

    def forbidden(*args, **kwargs):
        pytest.fail("multi-target picker must not compose a first-target execution config")

    monkeypatch.setattr(projects.ConfigLoader, "load", forbidden)
    context = library.context(opened["project_id"])
    payload = context._config_service.structured_payload()
    assert [target["id"] for target in payload["config"]["project"]["targets"]] == [
        "main",
        "second",
    ]
    assert context._report_feedback_service.project_config.project_root == root


def test_real_http_tabs_keep_config_and_report_read_write_isolated(http, library, tmp_path):
    a = create(library, tmp_path / "a", "A")
    b = create(library, tmp_path / "b", "B")
    for row, label in [(a, "A"), (b, "B")]:
        report = FinalReport(
            entry_function="f",
            overall_verdict="issue_found",
            issues=[
                Issue(
                    id="synthetic-" + label,
                    function="f",
                    location="unit.c:1",
                    category="reliability",
                    subcategory="memory",
                    defect_class="double_free",
                    description="synthetic report " + label,
                    root_cause="synthetic evidence",
                    suggested_fix="synthetic suggestion",
                    confidence=0.8,
                    impact_level="high",
                    validation_status="needs_review",
                )
            ],
        )
        report.report_views = build_report_views(
            [issue.to_dict() for issue in report.issues], [], canonical_projection=True
        )
        write_report_atomic(Path(row["root"]) / "zscope_batch_report.json", report.to_dict())
    with ThreadPoolExecutor(4) as pool:
        results = list(
            pool.map(
                lambda row: http("/api/findings?view=with_needs_review", project=row["project_id"]),
                [a, b, a, b],
            )
        )
    for (status, payload), label in zip(results, ["A", "B", "A", "B"]):
        assert (
            status == 200 and payload["findings"][0]["description"] == "synthetic report " + label
        )
    finding_a = results[0][1]["findings"][0]
    status, doc_a = http("/api/config/structured", project=a["project_id"])
    assert status == 200 and doc_a["config"]["llms"]["default"]["models"] == ["A"]
    changed = doc_a["config"]
    changed["llms"]["default"]["models"] = ["A-edited"]
    assert (
        http(
            "/api/config/structured",
            project=a["project_id"],
            method="POST",
            payload={"config": changed},
        )[0]
        == 200
    )
    assert http("/api/config/structured", project=b["project_id"])[1]["config"]["llms"]["default"][
        "models"
    ] == ["B"]
    update = {
        "issues": [
            {
                "issue_id": finding_a["issue_id"],
                "validation_status": "validated",
                "user_rebuttal": "A-only review",
            }
        ],
        "persist_snapshots": False,
    }
    untouched = (Path(b["root"]) / "zscope_batch_report.json").read_bytes()
    assert (
        http("/api/save_findings", project=b["project_id"], method="POST", payload=update)[0] >= 400
    )
    assert (Path(b["root"]) / "zscope_batch_report.json").read_bytes() == untouched
    assert (
        http("/api/save_findings", project=a["project_id"], method="POST", payload=update)[0] == 200
    )
    assert (
        read_report(Path(a["root"]) / "zscope_batch_report.json")["issues"][0]["user_rebuttal"]
        == "A-only review"
    )
    assert (
        read_report(Path(b["root"]) / "zscope_batch_report.json")["issues"][0]["validation_status"]
        == "needs_review"
    )


def test_http_missing_unknown_and_removed_project_never_fall_back(http, library, tmp_path):
    opened = create(library, tmp_path / "selected")
    for identity in [None, "unknown"]:
        status, payload = http("/api/config/structured", project=identity)
        assert status == 409 and payload["code"] in {"project_required", "project_unavailable"}
    Path(opened["config_path"]).unlink()
    status, payload = http("/api/config/structured", project=opened["project_id"])
    assert status == 409 and payload["code"] == "project_unavailable"


@pytest.mark.parametrize("origin", ["http://foreign.invalid", "null", "https://same-host"])
@pytest.mark.parametrize("method", ["POST", "DELETE"])
def test_project_writes_reject_foreign_origin(http, tmp_path, origin, method):
    if origin == "https://same-host":
        origin = f"https://127.0.0.1:{http.port}"
    status, payload = http(
        "/api/projects/create",
        method=method,
        payload={"directory": str(tmp_path)},
        headers={"Origin": origin},
    )
    assert status == 403 and payload["code"] == "invalid_origin"
    assert not (tmp_path / "zscope.yaml").exists()


def test_project_open_accepts_the_exact_server_origin(http, library, tmp_path):
    opened = create(library, tmp_path / "same-origin")
    status, result = http(
        "/api/projects/open",
        method="POST",
        payload={"path": opened["config_path"]},
        headers={"Origin": f"http://127.0.0.1:{http.port}"},
    )
    assert status == 200 and result["project"]["project_id"] == opened["project_id"]


@pytest.mark.parametrize(
    "body,headers,expected",
    [
        (b"[]", {"Content-Type": "application/json"}, 400),
        (b"{", {"Content-Type": "application/json"}, 400),
        (b"{}", {"Content-Type": "text/plain"}, 400),
        (b"{}", {"Content-Length": "-1", "Content-Type": "application/json"}, 400),
        (b"x" * 65537, {"Content-Type": "application/json"}, 413),
    ],
)
def test_project_http_rejects_malformed_requests(http, body, headers, expected):
    assert http("/api/projects/open", method="POST", body=body, headers=headers)[0] == expected


def test_cpg_factory_is_lazy_project_scoped_and_released_on_config_change(
    http, library, tmp_path, monkeypatch
):
    created, imported, closed = [], [], []

    class FakeIndex:
        def __init__(self, root, database, **kwargs):
            self.root = Path(root)
            created.append((self.root, Path(database), kwargs))
            self.backend = SimpleNamespace(
                status=lambda: "ready",
                joern_client=SimpleNamespace(
                    cpg_error=None,
                    import_cpg_async=lambda *args: imported.append(args),
                ),
            )

        def close(self):
            closed.append(self.root)

    monkeypatch.setattr("zscope.retrieval.code_index.CodeIndex", FakeIndex)
    a, b = create(library, tmp_path / "cpg-a"), create(library, tmp_path / "cpg-b")
    for item in (a, b):
        assert http("/api/cpg_status", project=item["project_id"])[1]["status"] == "unavailable"
    assert created == imported == []
    assert http("/api/build_cpg", project=a["project_id"], method="POST", payload={})[0] == 200
    assert len(created) == 1 and created[0][0] == Path(a["root"])
    assert created[0][2]["source_root"] == Path(a["root"])
    assert imported == [(a["root"], a["root"], str(Path(a["root"]) / "compile_commands.json"))]
    assert http("/api/cpg_status", project=b["project_id"])[1]["status"] == "unavailable"
    assert http("/api/build_cpg", project=a["project_id"], method="POST", payload={})[0] == 200
    assert len(created) == 1, "rebuilding uses the existing index for this unchanged context"
    assert http("/api/build_cpg", project=b["project_id"], method="POST", payload={})[0] == 200
    document = yaml.safe_load(Path(a["config_path"]).read_text())
    document["llms"]["default"]["models"] = ["updated-synthetic-model"]
    Path(a["config_path"]).write_text(yaml.safe_dump(document), encoding="utf-8")
    assert http("/api/cpg_status", project=a["project_id"])[1]["status"] == "unavailable"
    assert closed == [Path(a["root"])]
    assert http("/api/cpg_status", project=b["project_id"])[1]["status"] == "ready"
    assert http("/api/build_cpg", project=a["project_id"], method="POST", payload={})[0] == 200
    library.close()
    assert sorted(closed) == sorted([Path(a["root"]), Path(a["root"]), Path(b["root"])])


def test_review_memory_workers_activate_once_per_verified_context_and_close(
    library, tmp_path, monkeypatch
):
    from test_config_v2 import _config

    workers = []

    class FakeWorker:
        def __init__(self, store, *, llm_client_factory, llm_enabled):
            self.root, self.starts, self.stops = store.root, 0, 0
            assert llm_enabled is False
            workers.append(self)

        def start(self):
            self.starts += 1

        def stop(self):
            self.stops += 1

    monkeypatch.setattr(
        "zscope.web.services.ReviewMemoryStore",
        lambda root, state_dir: SimpleNamespace(root=Path(root)),
    )
    monkeypatch.setattr("zscope.review_memory.worker.ReviewMemoryWorker", FakeWorker)
    monkeypatch.setattr(
        "zscope.cli.review_memory._llm_client",
        lambda *args: pytest.fail("no real model is allowed"),
    )
    rows = [create(library, tmp_path / name) for name in ("worker-a", "worker-b")]
    for item in rows:
        document = _config(Path(item["root"]))
        document["project"]["review_memory"] = {
            "mode": "extract",
            "extraction": "auto_extract",
            "llm_enabled": False,
        }
        Path(item["config_path"]).write_text(yaml.safe_dump(document), encoding="utf-8")
    assert workers == [], "remembering a project must not activate a worker"
    first = library.context(rows[0]["project_id"])
    assert library.context(rows[0]["project_id"]) is first
    library.context(rows[1]["project_id"])
    assert [(worker.root, worker.starts, worker.stops) for worker in workers] == [
        (Path(row["root"]), 1, 0) for row in rows
    ]
    path = Path(rows[0]["config_path"])
    document = yaml.safe_load(path.read_text())
    document["project"]["review_memory"]["mode"] = "off"
    path.write_text(yaml.safe_dump(document), encoding="utf-8")
    assert library.context(rows[0]["project_id"]) is not first
    assert [worker.stops for worker in workers] == [1, 0]
    library.close()
    assert [worker.stops for worker in workers] == [1, 1]
    library.close()
    assert [worker.stops for worker in workers] == [1, 1]


def test_multiple_library_instances_remember_without_losing_registry_entries(tmp_path):
    registry = tmp_path / "registry.json"
    libraries = [projects.ProjectLibrary(registry) for _ in range(12)]
    try:
        with ThreadPoolExecutor(6) as pool:
            rows = list(
                pool.map(
                    lambda index: create(libraries[index], tmp_path / f"independent-{index}"),
                    range(len(libraries)),
                )
            )
        remembered = projects.ProjectLibrary(registry).list()["projects"]
        assert {item["project_id"] for item in remembered} == {item["project_id"] for item in rows}
        assert len(remembered) == len(rows)
    finally:
        for instance in libraries:
            instance.close()


def test_rejected_context_never_activates_a_worker(library, tmp_path, monkeypatch):
    item = create(library, tmp_path / "raced-context")
    events = []

    def raced_factory(path, scan_depth):
        candidate = SimpleNamespace(
            activate=lambda: events.append("activate"),
            close=lambda: events.append("close"),
        )
        path.write_text(
            path.read_text() + "\n# changed during context construction\n", encoding="utf-8"
        )
        return candidate

    monkeypatch.setattr(projects, "ProjectContext", raced_factory)
    with pytest.raises(ValueError, match="变化"):
        library.context(item["project_id"])
    assert events == ["close"]
    assert item["project_id"] not in library._contexts


@pytest.mark.parametrize("serve_error", [False, True])
def test_picker_server_closes_library_on_return_or_error(tmp_path, monkeypatch, serve_error):
    events = []
    fake_library = SimpleNamespace(
        initial_project_id="",
        open=lambda path: events.append(("open", path)) or {"project": {"project_id": "chosen"}},
        close=lambda: events.append("close"),
    )

    def serve():
        events.append("serve")
        if serve_error:
            raise RuntimeError("controlled server termination")

    monkeypatch.setattr(projects, "ProjectLibrary", lambda **kwargs: fake_library)
    monkeypatch.setattr(
        server, "DashboardHttpServer", lambda **kwargs: SimpleNamespace(serve_forever=serve)
    )
    monkeypatch.setattr(server, "_project_library", None)
    path = tmp_path / "zscope.yaml"
    if serve_error:
        with pytest.raises(RuntimeError, match="controlled server termination"):
            server.run_server(project_picker=True, config_path=path)
    else:
        server.run_server(project_picker=True, config_path=path)
    assert fake_library.initial_project_id == "chosen"
    assert events == [("open", str(path.resolve())), "serve", "close"]
