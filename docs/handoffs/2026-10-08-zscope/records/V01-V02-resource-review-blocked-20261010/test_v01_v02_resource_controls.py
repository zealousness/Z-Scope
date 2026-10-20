"""Small benign controls for the resource patch; no allocation pressure."""
import runpy
import sys
from pathlib import Path

from zscope.core.validation import dynamic_reproduction as d

ROOT=Path(d.__file__).resolve().parents[3]
H=runpy.run_path(str(ROOT/'tests/test_dynamic_reproduction.py'))


def test_real_build_uses_existing_watchdog_without_allocating_memory(tmp_path, monkeypatch):
    plan=H['_process_plan'](
        tmp_path,'true',memory_limit_mb=37,
        build=d.BuildSpec(argv=('/bin/sh','-c','sleep 0.2'),cwd=str(tmp_path)),
    )
    runner=d.SanitizerReproductionRunner('asan',policy=H['_policy']())
    checks=[]

    def synthetic_limit(pid,limit_mb):
        checks.append((pid,limit_mb))
        return True

    monkeypatch.setattr(runner,'_rss_exceeds',synthetic_limit)
    record=runner.execute(plan)
    assert checks and all(limit==37 for _,limit in checks)
    assert record.outcome=='engine_failed'
    assert 'resource_exhaustion' in record.detail
    assert record.build_exit_code is not None and record.build_exit_code!=0
    assert not record.runs and not record.findings


def test_pipe_capture_keeps_small_late_descendant_bytes(tmp_path):
    child='import os,time;time.sleep(0.1);os.write(1,b"A"*32);os.write(2,b"B"*32)'
    code='import subprocess,sys;subprocess.Popen([sys.executable,"-c",'+repr(child)+'])'
    runner=d.SanitizerReproductionRunner(
        'asan',policy=d.DynamicReproductionPolicy(enabled=True,output_capture_limit_bytes=128),
    )
    result=runner._run_once(
        argv=(sys.executable,'-c',code),cwd=str(tmp_path),env={'PATH':'/usr/bin:/bin'},
        timeout_seconds=5,address_space_limit_mb=0,tag='late',workdir=str(tmp_path),
    )
    assert result.exit_code==0
    assert result.stdout_excerpt==b'A'*32 and result.stderr_excerpt==b'B'*32
    assert not result.output_capped and not result.stdout_truncated and not result.stderr_truncated


def test_complete_exact_cap_output_is_not_falsely_truncated(tmp_path):
    runner=d.SanitizerReproductionRunner(
        'asan',policy=d.DynamicReproductionPolicy(enabled=True,output_capture_limit_bytes=32),
    )
    result=runner._run_once(
        argv=(sys.executable,'-c','import os;os.write(1,b"A"*32);os.write(2,b"B"*32)'),
        cwd=str(tmp_path),env={'PATH':'/usr/bin:/bin'},timeout_seconds=5,
        address_space_limit_mb=0,tag='exact',workdir=str(tmp_path),
    )
    assert result.exit_code==0 and result.stdout_bytes==result.stderr_bytes==32
    assert not result.output_capped and not result.stdout_truncated and not result.stderr_truncated
