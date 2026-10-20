"""Real owner/resume at the result-envelope read boundary, identical bytes.

Only scanner contents and the precise interleaving are controlled. Provider,
adapter, service, SQLite, owner, resume and report projection execute product
code; the unused code index is the existing provider-construction fixture.
"""
from pathlib import Path
import sys

from zscope.mcp import provider as provider_module
from zscope.mcp.jobs_adapter import McpJobsAdapter
from zscope.config.config import ConfigLoader
from zscope.tools.policy import ToolPolicy
from zscope.orchestration.jobs.service import ScanJobService

sys.path.insert(0,str(Path(provider_module.__file__).resolve().parents[2] / "tests"))
from test_job_result_projection import SCANNER_SCRIPT, run_to_terminal  # noqa: E402
from test_scan_jobs import make_project  # noqa: E402
from test_scan_job_execution import wait_terminal  # noqa: E402
from test_mcp_jobs import _ControlledCodeIndex, _ControlledSnapshotStore  # noqa: E402


def test_resume_after_envelope_read_does_not_mix_old_artifacts_with_new_binding(tmp_path):
    project = make_project(tmp_path)
    scanner = tmp_path / "scanner.py"
    scanner.write_text(SCANNER_SCRIPT,encoding="utf-8")

    class SwitchingEnvelope(ScanJobService):
        switch_once = True
        switched_to = None

        def result(self, job_id):
            response = super().result(job_id)
            if self.switch_once:
                self.switch_once = False
                prior = self.detail(job_id).payload["job"]
                resumed = self.resume(job_id,base_revision=prior["revision"],request_id="resume-between-envelope-binding")
                assert resumed.status_code == 202, resumed.payload
                self.switched_to = wait_terminal(self,job_id)
                assert self.switched_to["run_id"] != prior["run_id"]
                assert self.switched_to["report"]["report_id"] == prior["report"]["report_id"], "test requires genuinely identical artifact bytes"
            return response

    def builder(config_path, scan_depth, python_executable):
        return [python_executable,str(scanner),"report_exit2",str(project)]

    service = SwitchingEnvelope(project / "zscope.yaml",scan_command_builder=builder,terminate_grace=2.0)
    job, first = run_to_terminal(service,request_id="envelope-race-start")
    provider = provider_module.ZScopeMcpProvider(
        ConfigLoader.load(str(project / "zscope.yaml")),
        code_index=_ControlledCodeIndex(),snapshot_store=_ControlledSnapshotStore(),
        config_path=project / "zscope.yaml",jobs_adapter=McpJobsAdapter(project / "zscope.yaml",service=service),
        profile="default",tool_policy=ToolPolicy.allow_all(),
    )
    result = provider.call_tool("zscope.jobs.result",{"job_id":job["job_id"]})
    assert result["success"], result
    payload = result["data"]
    assert service.switched_to is not None
    assert payload["binding"]["run_id"] == service.switched_to["run_id"]
    fresh = service.result(job["job_id"]).payload
    assert payload["artifacts"] == fresh["artifacts"], "old attempt artifacts were labelled with the new run binding"
    assert payload["coverage"] == fresh["coverage"]
    assert payload["questions"] == fresh["questions"]
    assert payload["findings"]["findings"][0]["id"] == "iss-1"
