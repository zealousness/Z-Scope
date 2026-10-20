"""Independent, bounded ordinary regressions; no sanitizer or pressure workload."""
import hashlib
import runpy
import sys
from pathlib import Path

import pytest

from zscope.core.validation import dynamic_reproduction as d

ROOT = Path(d.__file__).resolve().parents[3]
H = runpy.run_path(str(ROOT / 'tests/test_dynamic_reproduction.py'))


def test_build_receives_the_plan_memory_limit(tmp_path, monkeypatch):
    plan = H['_process_plan'](
        tmp_path, 'true', memory_limit_mb=37,
        build=d.BuildSpec(argv=('/bin/true',), cwd=str(tmp_path)),
    )
    calls = []
    runner = d.SanitizerReproductionRunner('asan', policy=H['_policy']())

    def once(**kwargs):
        calls.append(kwargs)
        return d._RunResult(0, '', b'', '', b'', False)

    monkeypatch.setattr(runner, '_run_once', once)
    runner.execute(plan)
    assert [c['tag'] for c in calls] == ['build', 'run-0']
    build = calls[0]
    assert build.get('rss_limit_mb', 0) == plan.memory_limit_mb or (
        build.get('address_space_limit_mb', 0) == plan.memory_limit_mb
    ), 'build must receive the declared product memory boundary'


def test_build_resource_failure_stops_before_run_and_stays_undecided(tmp_path, monkeypatch):
    plan = H['_process_plan'](
        tmp_path, 'true', memory_limit_mb=37,
        build=d.BuildSpec(argv=('/bin/true',), cwd=str(tmp_path)),
    )
    calls = []
    runner = d.SanitizerReproductionRunner('asan', policy=H['_policy']())

    def once(**kwargs):
        calls.append(kwargs['tag'])
        return d._RunResult(-9, '', b'', '', b'', False, rss_exceeded=True)

    monkeypatch.setattr(runner, '_run_once', once)
    record = runner.execute(plan)
    assert calls == ['build']
    assert record.outcome == 'engine_failed'
    assert 'resource_exhaustion' in record.detail
    assert record.build_exit_code == -9
    assert record.findings == ()
    assert any('memory' in x or 'rss' in x for x in record.limitations)


@pytest.mark.parametrize('pause', [0, 0.1], ids=['exit-immediately', 'briefly-live'])
def test_capture_never_exceeds_budget_even_before_hashing(tmp_path, monkeypatch, pause):
    # Only 64 bytes on each stream: a tiny deterministic over-cap fixture.
    original_hash = d.hash_file
    checked = []

    def bounded_hash(p):
        q = Path(p)
        if q.name.endswith(('.stdout', '.stderr')):
            checked.append(q.name)
            assert q.stat().st_size <= 16, 'capture must be bounded before digest work'
        return original_hash(p)

    monkeypatch.setattr(d, 'hash_file', bounded_hash)
    runner = d.SanitizerReproductionRunner(
        'asan', policy=d.DynamicReproductionPolicy(enabled=True, output_capture_limit_bytes=16),
    )
    code = f'import os,time;os.write(1,b"A"*64);os.write(2,b"B"*64);time.sleep({pause})'
    result = runner._run_once(
        argv=(sys.executable, '-c', code), cwd=str(tmp_path), env={'PATH':'/usr/bin:/bin'},
        timeout_seconds=5, address_space_limit_mb=0, tag='bounded', workdir=str(tmp_path),
    )
    assert len(checked) == 2
    assert result.stdout_bytes <= 16 and result.stderr_bytes <= 16
    assert (tmp_path/'bounded.stdout').stat().st_size <= 16
    assert (tmp_path/'bounded.stderr').stat().st_size <= 16
    assert result.output_capped or result.stdout_truncated or result.stderr_truncated
    assert result.stdout_digest == hashlib.sha256((tmp_path/'bounded.stdout').read_bytes()).hexdigest()
    assert result.stderr_digest == hashlib.sha256((tmp_path/'bounded.stderr').read_bytes()).hexdigest()


def test_below_cap_keeps_complete_bytes_and_nonzero_exit(tmp_path):
    runner = d.SanitizerReproductionRunner(
        'asan', policy=d.DynamicReproductionPolicy(enabled=True, output_capture_limit_bytes=128),
    )
    result = runner._run_once(
        argv=(sys.executable, '-c', 'import os;os.write(1,b"A"*32);os.write(2,b"B"*32);raise SystemExit(7)'),
        cwd=str(tmp_path), env={'PATH':'/usr/bin:/bin'}, timeout_seconds=5,
        address_space_limit_mb=0, tag='clean', workdir=str(tmp_path),
    )
    assert result.exit_code == 7
    assert result.stdout_bytes == result.stderr_bytes == 32
    assert result.stdout_excerpt == b'A'*32 and result.stderr_excerpt == b'B'*32
    assert not result.output_capped and not result.stdout_truncated and not result.stderr_truncated
