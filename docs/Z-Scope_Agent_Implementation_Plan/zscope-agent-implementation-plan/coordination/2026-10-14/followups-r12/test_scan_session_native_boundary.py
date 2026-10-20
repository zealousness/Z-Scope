"""Full ordinary ScanSession must consume precise native instances.

Only index construction is injected with the already initialized real native
index. The session, instance dispatcher, Analyzer, ledger and report execute.
"""
from pathlib import Path
import sys

import pytest

from zscope.orchestration import scan_session as session_module
from zscope.reporting.json_io import read_report

sys.path.insert(0, str(Path(session_module.__file__).resolve().parents[2] / "tests"))
from test_instance_analysis import native_variants, _native_index, _native_config  # noqa: E402


@pytest.mark.parametrize("resume,batch", [(False,False), (True,False), (True,True)])
def test_native_scan_session_never_borrows_global_semantics(native_variants, monkeypatch, resume, batch):
    backend, root, cdb = native_variants
    config = _native_config(root, cdb, root)
    config.project.entry_function = "f"
    config.project.entry_file_path = "unit.c"
    if batch:
        # The fixture already created ``entries.json`` inside the project root
        # (before the index snapshot), so pointing the config at it keeps the
        # stored include-search receipt current.
        config.project.entry_function = None
        config.project.entry_functions_list = root / "entries.json"
    index = _native_index(backend, root, cdb)
    if resume:
        config.analysis.workflow_name = "resume"
    runner = session_module.ScanSessionRunner(config, resume=resume, emit=lambda text: None)

    def native_index(state, **kwargs):
        state["code_index"] = index
        return index

    def forbidden_global(*args, **kwargs):
        pytest.fail("precise instance scan called the unscoped semantic phase")

    def forbidden_old_resume(*args, **kwargs):
        pytest.fail("precise instance resume used a name-only saved report")

    monkeypatch.setattr(runner, "_ensure_code_index", native_index)
    monkeypatch.setattr(runner, "_ensure_semantic_phase", forbidden_global)
    monkeypatch.setattr(runner, "_load_current_saved_report", forbidden_old_resume)
    contexts = index.get_build_contexts("unit.c")
    alt = next(row["build_context_id"] for row in contexts if "-DALT=1" in row["command"]["arguments"])
    result = runner.run()
    assert result.reports, result
    reports = [read_report(path) for path in result.reports if path.suffix == ".json"]
    assert reports
    coverage = reports[0]["metadata"]["entry_instances"]
    assert coverage["planned_instances"] == 2
    assert coverage["scheduled_instances"] == 2
    analysis = coverage["instance_analysis"]
    assert analysis["analyzed_instances"] == 2
    assert analysis["instance_scope_complete"] is True
    outcomes = analysis["instances"]
    assert len(outcomes) == 2
    assert any(candidate["defect_class"] == "double_free" for row in outcomes if row["build_context_id"] == alt for candidate in row["candidates"])
    assert not any(candidate["defect_class"] == "double_free" for row in outcomes if row["build_context_id"] != alt for candidate in row["candidates"])
    assert all(candidate["build_context_id"] == row["build_context_id"] for row in outcomes for candidate in row["candidates"])
