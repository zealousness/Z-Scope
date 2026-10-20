"""MCP job schema rejection must precede real persistent-service side effects."""
from pathlib import Path
import sys
import pytest
import zscope

sys.path.insert(0,str(Path(zscope.__file__).resolve().parents[1]/"tests"))
from test_mcp_jobs import job_env, make_provider


@pytest.mark.parametrize("tool,arguments",[
    ("zscope.scan.status",{"job_id":None}),
    ("zscope.jobs.events",{"job_id":"j","after_seq":None}),
    ("zscope.scan.run",{"request_id":"null-stop","stop_at":None}),
    ("zscope.scan.run",{"request_id":"null-depth","scan_depth":None}),
])
def test_null_is_not_omission_under_the_published_job_schema(job_env,tool,arguments):
    project=job_env["project"]
    provider,_=make_provider(project,scanner=job_env["scanner"])
    result=provider.call_tool(tool,arguments)
    assert result.get("success") is False
    assert result.get("code")=="invalid_request",result
    assert result.get("status_code")==400,result
    assert not (project/".zscope_jobs").exists()
