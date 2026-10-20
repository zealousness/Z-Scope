"""Real native ScanSession crash after SQL settlement, then a fresh owner/run.

The only model substitution is the existing deterministic native fixture
configuration with no external model clients. Scanner, index, Analyzer,
ledger, work queue, job service and owner execute product code.
"""

from pathlib import Path
import json
import os
import sys

from zscope.orchestration import scan_session as session_module
from zscope.orchestration.jobs.service import ScanJobService

sys.path.insert(0, str(Path(session_module.__file__).resolve().parents[2] / "tests"))
from test_scan_jobs import make_project as _base_project, start_job, store_for  # noqa: E402
from test_scan_job_execution import wait_terminal  # noqa: E402
from test_instance_analysis import RULE  # noqa: E402


def make_project(tmp_path):
    project = _base_project(tmp_path)
    # The owner fixture's unrelated main.c has no compile command. This native
    # project deliberately consists of the actual unit.c with two commands.
    (project / "src/main.c").unlink()
    return project


def wait_bound_report(service, job_id, *, timeout=90.0):
    """Wait for the per-attempt report binding of a terminal attempt.

    The terminal row and the attempt's bound report become visible in the same
    finalization, but a status read can still land between them; the artifact
    itself is written before it is registered. Waiting here keeps the assertion
    about *what* was published instead of *when* it became readable.
    """
    import time

    until = time.monotonic() + timeout
    while True:
        loaded = service.load_bound_report(job_id)
        if loaded is not None or time.monotonic() >= until:
            return loaded
        time.sleep(0.2)


def native_saved_config(project):
    import yaml

    # Keep real sources separate from generated scan reports and databases.
    # The service hashes the actual source root, never a test-made revision.
    for name in ("unit.c", "flags.h"):
        if (project / name).exists():
            (project / name).rename(project / "src" / name)
    database = project / "compile_commands.json"
    rows = json.loads(database.read_text(encoding="utf-8"))
    for row in rows:
        old = row["file"]
        row["file"] = str(project / "src/unit.c")
        row["arguments"] = [row["file"] if arg == old else arg for arg in row["arguments"]]
    database.write_text(json.dumps(rows), encoding="utf-8")
    # Perform the real compile-argument preparation before input binding.
    # A first scanner preparation may rewrite the database; that is a real
    # build-input change, not a valid same-input crash/resume comparison.
    from zscope.retrieval.compile_commands_prepare import prepare_compile_commands
    from zscope.retrieval.compile_preflight import discover_tools

    prepare_compile_commands(
        database,
        discover_tools(indexer=os.environ["Z_SCOPE_TEST_CLANG_INDEXER"], clangd="clangd"),
        workers=1,
    )
    saved = yaml.safe_load((project / "zscope.yaml").read_text(encoding="utf-8"))
    saved["project"].update(
        source_root="src",
        entry_function="f",
        entry_file_path="unit.c",
        compile_commands_path="compile_commands.json",
    )
    saved["rules"] = {"enabled_ids": [RULE]}
    return saved


SCANNER = r"""
import json, os, sys, time
from pathlib import Path
import zscope
sys.path.insert(0, str(Path(zscope.__file__).resolve().parent.parent / 'tests'))
from test_instance_analysis import _native_config
from zscope.orchestration.scan_session import ScanSessionRunner
from zscope.orchestration.jobs.work_queue import WorkQueue
from zscope.core.analysis.analyzer import Analyzer

root, mode, control = Path(sys.argv[1]), sys.argv[2], Path(sys.argv[3])
control.mkdir(parents=True, exist_ok=True)
config = _native_config(root, root / 'compile_commands.json', root / 'src')
config.project.entry_function = 'f'
config.project.entry_file_path = 'unit.c'
config.indexing.clang_frontend = 'batch'
config.indexing.clang_indexer_path = os.environ['Z_SCOPE_TEST_CLANG_INDEXER']
original_settle = WorkQueue.settle

def settle(self, item_id, **kwargs):
    row = next((row for row in self.snapshot()['remaining'] if row['item_id'] == item_id), {})
    result = original_settle(self, item_id, **kwargs)
    if mode == 'crash' and row.get('kind') == 'instance_analysis' and kwargs.get('action') == 'complete':
        (control / 'settled-before-crash.json').write_text(json.dumps({'scope':row['scope_key'], 'build':row['build']}))
        os._exit(7)
    return result

WorkQueue.settle = settle
if mode == 'blocking':
    original_run = Analyzer.run
    def cooperative_model_wait(self):
        # Control only the duration of an in-flight analysis/model boundary.
        # The actual Analyzer/token and native project execute otherwise.
        token = self.cancellation_token
        (control / 'inflight.json').write_text(json.dumps({'token_present':token is not None}))
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            if token is not None and token.is_cancelled():
                (control / 'cancel-observed.json').write_text(json.dumps({'reason':token.reason}))
                token.raise_if_cancelled()
            time.sleep(.05)
        (control / 'wait-expired.json').write_text('{}')
        return original_run(self)
    Analyzer.run = cooperative_model_wait
result = ScanSessionRunner(config).run()
# Force a resumable owner state in the source-edit counterexample. The actual
# scan report is left intact; this controls only the scanner wrapper's exit.
sys.exit(2 if mode == 'force_partial' else result.exit_code)
"""


def test_durable_analysis_without_checkpoint_is_not_lost_on_resume(tmp_path):
    assert os.environ.get("Z_SCOPE_TEST_CLANG_INDEXER"), "real native tool required"
    project = make_project(tmp_path)
    (project / "flags.h").write_text(
        "#include <stdlib.h>\n#ifdef ALT\n#define RELEASE(p) do { free(p); free(p); } while(0)\n#else\n#define RELEASE(p) free(p)\n#endif\n",
        encoding="utf-8",
    )
    (project / "unit.c").write_text(
        '#include "flags.h"\nvoid f(void){char *p=malloc(4); if(!p)return; RELEASE(p);}\n',
        encoding="utf-8",
    )
    rows = [
        {
            "directory": str(project),
            "file": str(project / "unit.c"),
            "arguments": ["clang", "-c", str(project / "unit.c"), *flags],
        }
        for flags in ([], ["-DALT=1"])
    ]
    (project / "compile_commands.json").write_text(json.dumps(rows), encoding="utf-8")
    import yaml

    config_path = project / "zscope.yaml"
    saved = native_saved_config(project)
    config_path.write_text(
        yaml.safe_dump(saved, allow_unicode=True, sort_keys=False), encoding="utf-8"
    )
    scanner = tmp_path / "actual_scan.py"
    scanner.write_text(SCANNER, encoding="utf-8")
    mode = ["crash"]
    control = tmp_path / "control"

    def builder(config_path, scan_depth, python_executable):
        return [python_executable, str(scanner), str(project), mode[0], str(control)]

    service = ScanJobService(
        project / "zscope.yaml", scan_command_builder=builder, terminate_grace=2.0
    )
    job = start_job(service, request_id="crash-after-analysis-settlement")
    first = wait_terminal(service, job["job_id"])
    assert (control / "settled-before-crash.json").is_file(), first
    assert first["status"] == "failed"
    first_revision = first["input_revision"]
    mode[0] = "normal"
    resumed = service.resume(
        job["job_id"], base_revision=first["revision"], request_id="resume-uncheckpointed-analysis"
    )
    assert resumed.status_code == 202, resumed.payload
    final = wait_terminal(service, job["job_id"])
    assert final["run_id"] != first["run_id"]
    assert final["input_revision"] == first_revision
    loaded = service.load_bound_report(job["job_id"])
    assert loaded is not None, final
    report, _ = loaded
    plan = report["metadata"]["entry_instances"]
    assert plan["planned_instances"] == 2
    analysis = plan["instance_analysis"]
    assert analysis["analyzed_instances"] == 2, analysis
    assert analysis["instance_scope_complete"] is True, analysis
    assert sorted(row["candidate_count"] for row in analysis["instances"]) == [0, 1], analysis
    assert any(
        c["defect_class"] == "double_free"
        for row in analysis["instances"]
        for c in row["candidates"]
    ), analysis


def test_real_header_edit_revokes_a_completed_instance_checkpoint(tmp_path):
    import yaml

    assert os.environ.get("Z_SCOPE_TEST_CLANG_INDEXER"), "real native tool required"
    project = make_project(tmp_path)
    header = project / "flags.h"
    header.write_text(
        "#include <stdlib.h>\n#ifdef ALT\n#define RELEASE(p) do { free(p); free(p); } while(0)\n#else\n#define RELEASE(p) free(p)\n#endif\n",
        encoding="utf-8",
    )
    (project / "unit.c").write_text(
        '#include "flags.h"\nvoid f(void){char *p=malloc(4); if(!p)return; RELEASE(p);}\n',
        encoding="utf-8",
    )
    (project / "compile_commands.json").write_text(
        json.dumps(
            [
                {
                    "directory": str(project),
                    "file": str(project / "unit.c"),
                    "arguments": ["clang", "-c", str(project / "unit.c"), *flags],
                }
                for flags in ([], ["-DALT=1"])
            ]
        ),
        encoding="utf-8",
    )
    config_path = project / "zscope.yaml"
    saved = native_saved_config(project)
    config_path.write_text(
        yaml.safe_dump(saved, allow_unicode=True, sort_keys=False), encoding="utf-8"
    )
    scanner = tmp_path / "actual_scan.py"
    scanner.write_text(SCANNER, encoding="utf-8")
    mode = ["force_partial"]

    def builder(config_path, scan_depth, python_executable):
        return [python_executable, str(scanner), str(project), mode[0], str(tmp_path / "control")]

    service = ScanJobService(config_path, scan_command_builder=builder, terminate_grace=2.0)
    job = start_job(service, request_id="actual-header-edit-start")
    first = wait_terminal(service, job["job_id"])
    assert first["status"] == "partial", first
    loaded = service.load_bound_report(job["job_id"])
    assert loaded is not None, first
    old_analysis = loaded[0]["metadata"]["entry_instances"]["instance_analysis"]
    assert sorted(row["candidate_count"] for row in old_analysis["instances"]) == [0, 1]
    old_builds = {row["build_context_id"] for row in old_analysis["instances"]}
    header = project / "src/flags.h"
    header.write_text("#include <stdlib.h>\n#define RELEASE(p) free(p)\n", encoding="utf-8")
    mode[0] = "normal"
    resumed = service.resume(
        job["job_id"], base_revision=first["revision"], request_id="actual-header-edit-resume"
    )
    assert resumed.status_code == 202, resumed.payload
    final = wait_terminal(service, job["job_id"])
    assert final["run_id"] != first["run_id"]
    assert final["input_revision"] != first["input_revision"]
    loaded = wait_bound_report(service, job["job_id"], timeout=90.0)
    if loaded is None:
        stored = store_for(project).get_job(job["job_id"])
        owner_log = Path(stored["run_dir"]) / "owner.log"
        raise AssertionError(
            {
                "status": stored.get("status"),
                "phase": stored.get("phase"),
                "report_json": stored.get("report_json"),
                "unbound_reason": service._read_bound_report(stored)[1],
                "run_dir": sorted(path.name for path in Path(stored["run_dir"]).iterdir()),
                "owner_log": (
                    owner_log.read_text(encoding="utf-8", errors="replace")[-4000:]
                    if owner_log.is_file()
                    else "<absent>"
                ),
                "events": [
                    (row["kind"], row.get("message"))
                    for row in service.events(job["job_id"], after_seq=0).payload["events"]
                ],
            }
        )
    report = loaded[0]
    analysis = report["metadata"]["entry_instances"]["instance_analysis"]
    assert analysis["analyzed_instances"] == 2, analysis
    assert analysis["instance_scope_complete"] is True, analysis
    assert sorted(row["candidate_count"] for row in analysis["instances"]) == [0, 0], analysis
    assert {row["build_context_id"] for row in analysis["instances"]}.isdisjoint(old_builds)
    assert not any(
        c["defect_class"] == "double_free"
        for row in analysis["instances"]
        for c in row["candidates"]
    )


def test_foreign_json_checkpoint_cannot_skip_an_empty_real_queue(tmp_path):
    import yaml
    from zscope.orchestration.jobs.scan_work import CHECKPOINT_SCHEMA, CHECKPOINT_FILENAME

    assert os.environ.get("Z_SCOPE_TEST_CLANG_INDEXER"), "real native tool required"
    project = make_project(tmp_path)
    (project / "flags.h").write_text(
        "#include <stdlib.h>\n#ifdef ALT\n#define RELEASE(p) do { free(p); free(p); } while(0)\n#else\n#define RELEASE(p) free(p)\n#endif\n",
        encoding="utf-8",
    )
    (project / "unit.c").write_text(
        '#include "flags.h"\nvoid f(void){char *p=malloc(4); if(!p)return; RELEASE(p);}\n',
        encoding="utf-8",
    )
    (project / "compile_commands.json").write_text(
        json.dumps(
            [
                {
                    "directory": str(project),
                    "file": str(project / "unit.c"),
                    "arguments": ["clang", "-c", str(project / "unit.c"), *flags],
                }
                for flags in ([], ["-DALT=1"])
            ]
        ),
        encoding="utf-8",
    )
    config_path = project / "zscope.yaml"
    saved = native_saved_config(project)
    config_path.write_text(
        yaml.safe_dump(saved, allow_unicode=True, sort_keys=False), encoding="utf-8"
    )
    scanner = tmp_path / "actual_scan.py"
    scanner.write_text(SCANNER, encoding="utf-8")

    def builder(config_path, scan_depth, python_executable):
        return [python_executable, str(scanner), str(project), "normal", str(tmp_path / "control")]

    # The ordinary service writes the real launch request. Delay only its
    # owner spawn so the untrusted JSON can be placed before the scanner starts.
    service = ScanJobService(
        config_path, scan_command_builder=builder, spawn_owner=False, terminate_grace=2.0
    )
    job = start_job(service, request_id="forged-checkpoint-start")
    store = store_for(project)
    row = store.get_job(job["job_id"])
    run_dir = Path(row["run_dir"])
    forged = {
        "schema": CHECKPOINT_SCHEMA,
        "job_id": "foreign-job",
        "run_id": "foreign-run",
        "input_revision": row["input_revision"],
        "report": {
            "completeness": "complete",
            "summary": {"total_issues": 0, "functions_analyzed": 0},
            "metadata": {
                "entry_instances": {
                    "planned_instances": 2,
                    "scheduled_instances": 2,
                    "instance_analysis": {
                        "planned_instances": 2,
                        "scheduled_instances": 2,
                        "analyzed_instances": 2,
                        "instance_scope_complete": True,
                        "consumer_scope_complete": True,
                        "scan_coverage_complete": True,
                        "instances": [],
                    },
                }
            },
        },
    }
    (run_dir.parent / CHECKPOINT_FILENAME).write_text(json.dumps(forged), encoding="utf-8")
    service._spawn_owner(store=store, job=row, run_dir=run_dir, launch_path=run_dir / "launch.json")
    final = wait_terminal(service, job["job_id"])
    loaded = service.load_bound_report(job["job_id"])
    assert loaded is not None, final
    analysis = loaded[0]["metadata"]["entry_instances"]["instance_analysis"]
    assert len(analysis["instances"]) == 2, "foreign JSON skipped real queued native analysis"
    assert sorted(item["candidate_count"] for item in analysis["instances"]) == [0, 1], analysis
    assert any(
        c["defect_class"] == "double_free"
        for item in analysis["instances"]
        for c in item["candidates"]
    ), analysis


def test_actual_inflight_analyzer_observes_cancel_before_owner_watchdog(tmp_path):
    import time
    import yaml

    assert os.environ.get("Z_SCOPE_TEST_CLANG_INDEXER"), "real native tool required"
    project = make_project(tmp_path)
    (project / "unit.c").write_text(
        "#include <stdlib.h>\nvoid f(void){char *p=malloc(4); if(!p)return; free(p);}\n",
        encoding="utf-8",
    )
    (project / "compile_commands.json").write_text(
        json.dumps(
            [
                {
                    "directory": str(project),
                    "file": str(project / "unit.c"),
                    "arguments": ["clang", "-c", str(project / "unit.c"), *flags],
                }
                for flags in ([], ["-DALT=1"])
            ]
        ),
        encoding="utf-8",
    )
    config_path = project / "zscope.yaml"
    saved = native_saved_config(project)
    config_path.write_text(
        yaml.safe_dump(saved, allow_unicode=True, sort_keys=False), encoding="utf-8"
    )
    scanner = tmp_path / "actual_scan.py"
    scanner.write_text(SCANNER, encoding="utf-8")
    control = tmp_path / "control"

    def builder(config_path, scan_depth, python_executable):
        return [python_executable, str(scanner), str(project), "blocking", str(control)]

    service = ScanJobService(config_path, scan_command_builder=builder, terminate_grace=2.0)
    job = start_job(service, request_id="actual-inflight-cancel")
    until = time.monotonic() + 60
    while not (control / "inflight.json").exists() and time.monotonic() < until:
        time.sleep(0.1)
    assert (control / "inflight.json").is_file(), service.detail(job["job_id"]).payload
    # The live owner bumps the job revision while the scanner runs, so a
    # read-then-cancel can lose the race with a 409. Re-reading the revision is
    # the documented client behaviour; the cancel itself must still be accepted.
    for attempt in range(50):
        current = service.detail(job["job_id"]).payload["job"]
        cancelled = service.cancel(
            job["job_id"],
            base_revision=current["revision"],
            request_id=f"cancel-real-inflight-{attempt}",
        )
        if cancelled.status_code != 409:
            break
        time.sleep(0.05)
    assert cancelled.status_code == 200, cancelled.payload
    final = wait_terminal(service, job["job_id"])
    assert final["status"] == "cancelled", final
    assert (
        control / "cancel-observed.json"
    ).is_file(), "real Analyzer retained a token disconnected from job cancellation"
    assert not (control / "wait-expired.json").exists()
    events = service.events(job["job_id"], after_seq=0).payload["events"]
    # The owner's ``cancel_finalize_grace`` (2 s) bounds how long it waits for
    # the scanner to unwind. A loaded machine can exceed that even though the
    # real Analyzer already observed the token, so the invariant to assert is
    # ordering — the observation happened before any watchdog teardown — plus
    # the fact that the analyzer never fell through to its own 30 s expiry.
    watchdog = [row for row in events if row["kind"] == "cancel_watchdog"]
    if watchdog:
        import datetime as dt

        observed = (control / "cancel-observed.json").stat().st_mtime
        teardown = min(dt.datetime.fromisoformat(row["at"]).timestamp() for row in watchdog)
        assert observed <= teardown, (observed, teardown, watchdog)
    teardown = [row for row in events if row["kind"] == "scan_terminated"]
    assert len(teardown) == 1, teardown
    outcome = teardown[0]["data"]["outcome"]
    if watchdog:
        # The owner's 2 s cooperative grace can expire before a loaded machine
        # unwinds the real scanner, so the documented backstop runs. Two outcomes
        # are then legitimate: the watchdog SIGTERMs a live scanner
        # (``terminated``) or finds it already gone (``already_exited``, see
        # ``runner.stop_process``). A SIGKILL (``killed``) still fails this test,
        # and the observation-before-teardown ordering above still holds.
        assert outcome in {"terminated", "already_exited"}, teardown
    else:
        assert outcome == "already_exited", teardown
    pending_path = Path(store_for(project).get_job(job["job_id"])["run_dir"]) / "pending.json"
    assert pending_path.is_file(), "cooperative session must persist its actual unfinished work"
    pending = json.loads(pending_path.read_text(encoding="utf-8"))
    assert pending["items"] and pending["count"] > 0, pending
