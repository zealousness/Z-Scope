"""A real service reservation/SQL queue cannot be reset by a foreign token.

The owner launch is deliberately delayed. Native indexing, planning, service
nonce reservation and queue storage are real; the unauthorized scan must fail
before changing any of that queue's existing work.
"""
from pathlib import Path
import hashlib
import os
import sys

import pytest
import yaml

from zscope.orchestration import scan_session as session_module
from zscope.config.function_entry import FunctionEntry
from zscope.orchestration.entry_instances import plan_entry_instances
from zscope.orchestration.jobs.models import JobError
from zscope.orchestration.jobs.service import ScanJobService
from zscope.orchestration.jobs.work_queue import WorkQueue
from zscope.retrieval.code_index import CodeIndex

sys.path.insert(0,str(Path(session_module.__file__).resolve().parents[2]/"tests"))
from test_scan_session_instances import _write_project, _config  # noqa: E402
from test_scan_jobs import CONFIG_TEMPLATE, start_job, store_for  # noqa: E402


def test_foreign_owner_cannot_delete_an_existing_bound_instance_queue(tmp_path,monkeypatch):
    assert os.environ.get("Z_SCOPE_TEST_CLANG_INDEXER"), "actual native tool required"
    _write_project(tmp_path)
    config=_config(tmp_path)
    index=CodeIndex(tmp_path,tmp_path/"compile_commands.json",source_root=tmp_path,indexing_config=config.indexing,include_paths=[tmp_path])
    try:
        plan=plan_entry_instances(index,[FunctionEntry("f",file_path="unit.c")])
        assert len(plan.instances)==2
    finally:
        index.close()
    public=yaml.safe_load(CONFIG_TEMPLATE.replace("{root}",str(tmp_path)))
    public["project"].update(source_root=".",entry_function="f",entry_file_path="unit.c",compile_commands_path="compile_commands.json")
    path=tmp_path/"zscope.yaml"
    path.write_text(yaml.safe_dump(public,sort_keys=False),encoding="utf-8")
    service=ScanJobService(path,spawn_owner=False)
    job=start_job(service,request_id="foreign-owner-queue-fencing")
    store=store_for(tmp_path)
    row=store.get_job(job["job_id"])
    queue_path=Path(row["run_dir"]).parent/"work-queue.db"
    queue=WorkQueue(queue_path,job_id=job["job_id"],input_revision=row["input_revision"])
    instance=plan.instances[0]
    queue.enqueue([{"kind":"instance_analysis","scope_key":instance.identity,"build":instance.build_context_id}],batch_no=1)
    before=hashlib.sha256(queue_path.read_bytes()).hexdigest(),queue_path.stat().st_ino
    for key,value in {
        "ZSCOPE_JOB_STORE":str(store.db_path),"ZSCOPE_JOB_ID":job["job_id"],"ZSCOPE_JOB_RUN_ID":row["run_id"],
        "ZSCOPE_JOB_RUN_DIR":row["run_dir"],"ZSCOPE_JOB_OWNER_TOKEN":"foreign-token",
    }.items():
        monkeypatch.setenv(key,value)
    with pytest.raises(JobError):
        session_module.ScanSessionRunner(config,emit=lambda _:None).run()
    assert queue_path.is_file(), "foreign owner removed the legitimate queue before its binding was rejected"
    assert (hashlib.sha256(queue_path.read_bytes()).hexdigest(),queue_path.stat().st_ino)==before
    assert queue.snapshot()["counts"]["pending"]==1
