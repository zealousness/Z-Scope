"""Author re-check: run the sanitizer lane in the same offline review sandbox.

This is a copy of records/V01-V02-container-review.py with new work/output names
so the acceptance round's evidence is never overwritten. It is acceptance-style
infrastructure, not a product capability: the container's isolation must not be
credited to V01/V02.
"""
import json
import subprocess
import tempfile
import time
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT = Path(__file__).resolve().parents[4]
RECORDS = Path(__file__).resolve().parent
WORK = Path(tempfile.mkdtemp(prefix="zscope-v01-v02-author-container-20261009-"))
NAME = WORK.name
IMAGE = "docker.io/library/python@sha256:de8ba566572ebcb35cbd10e03f5f351cad00a0d0d50a11e084f1a0fd24a0c41a"
base = ["podman", "run", "--rm", "--name", NAME, "--pull=never", "--network=none",
        "--read-only", "--userns=keep-id", "--cap-drop=all",
        "--security-opt=no-new-privileges", "--pids-limit=256", "--memory=2g", "--cpus=2",
        "--tmpfs", "/tmp:rw,size=512m,exec", "-v", f"{ROOT}:/repo:ro",
        "-v", "/home/zeal/venv313:/venv:ro", "-v", f"{WORK}:/work:rw",
        "-e", "PYTHONPATH=/repo:/venv/lib/python3.13/site-packages",
        "-e", "PYTHONDONTWRITEBYTECODE=1", "-w", "/repo"]
probe = '''import os,sys,json,subprocess
from pathlib import Path
import pytest,zscope
status=Path('/proc/self/status').read_text()
data={'python':sys.version,'pytest':pytest.__version__,'zscope':zscope.__file__,
 'compiler':subprocess.run(['gcc','--version'],capture_output=True,text=True).stdout.splitlines()[0],
 'clang':subprocess.run(['sh','-c','command -v clang || true'],capture_output=True,text=True).stdout.strip(),
 'interfaces':os.listdir('/sys/class/net'),
 'repo_readonly':bool(os.statvfs('/repo').f_flag & os.ST_RDONLY),
 'status':[s for s in status.splitlines() if s.startswith(('CapEff:','NoNewPrivs:'))],
 'limits':{p:Path('/sys/fs/cgroup/'+p).read_text().strip() for p in ['memory.max','pids.max','cpu.max']}}
assert data['repo_readonly'] and data['interfaces']==['lo']
assert any(s.endswith('0000000000000000') for s in data['status'])
assert any(s.endswith('1') and s.startswith('NoNewPrivs:') for s in data['status'])
assert data['limits']['memory.max']=='2147483648'
assert data['limits']['pids.max']=='256'
print(json.dumps(data,indent=2))
'''
result = {'date': '2026-10-09', 'role': 'author re-check after the 2026-10-09 fix round',
          'scope': 'offline review container, not product isolation',
          'image': IMAGE, 'work': str(WORK), 'checks': [],
          'corrections': [
              'The first attempt ran the independent negatives with --basetemp=/work/pytest-neg; '
              'the reviewer harness builds its plan with the host default allowed_exec_roots '
              '(/bin, /usr/bin, /tmp, fixture dir), so /work is not authorized and the runner '
              'correctly refused to launch and returned "unsupported" for '
              'test_clean_execution_cannot_be_given_unqualified_positive_proof. That is the '
              'fail-closed working-directory check, not a product defect: re-run with the '
              'basetemp inside the container tmpfs, which is inside the plan allowed roots.'
          ]}
try:
    for name, command in [
        ('preflight', base + [IMAGE, 'python', '-c', probe]),
        ('sanitizer-tests', base + ['-e', 'ZSCOPE_DYNAMIC_REPRODUCTION_EVIDENCE=/work/observed.json',
            IMAGE, 'python', '-m', 'pytest', '-q', '-rs', '-p', 'no:cacheprovider',
            '--tb=short', '--basetemp=/work/pytest-san', '--junitxml=/work/junit-san.xml',
            'tests/test_dynamic_reproduction_execution.py']),
        ('independent-negative', base + [
            IMAGE, 'python', '-m', 'pytest', '-q', '-rs', '-p', 'no:cacheprovider',
            '--tb=short', '--basetemp=/tmp/pytest-neg', '--junitxml=/work/junit-neg.xml',
            'docs/handoffs/2026-10-08-zscope/records/V01-V02-acceptance-regressions.py']),
        ('deterministic-unit', base + [
            IMAGE, 'python', '-m', 'pytest', '-q', '-rs', '-p', 'no:cacheprovider',
            '--tb=short', '--basetemp=/tmp/pytest-det', '--junitxml=/work/junit-det.xml',
            'tests/test_dynamic_reproduction.py']),
    ]:
        started = time.monotonic()
        ran = subprocess.run(command, capture_output=True, text=True, timeout=600)
        (WORK / (name + '.log')).write_text(ran.stdout + ran.stderr, encoding='utf-8')
        result['checks'].append({'name': name, 'command': command, 'exit_code': ran.returncode,
            'duration_seconds': round(time.monotonic()-started, 3),
            'stdout': ran.stdout, 'stderr': ran.stderr})
        print(json.dumps({k: v for k, v in result['checks'][-1].items() if k not in {'command', 'stdout', 'stderr'}}), flush=True)
        if name == 'preflight' and ran.returncode:
            result['sanitizer_status'] = 'not_run'
            break
    counts = {}
    for label, xml in (('sanitizer-tests', WORK / 'junit-san.xml'),
                       ('independent-negative', WORK / 'junit-neg.xml'),
                       ('deterministic-unit', WORK / 'junit-det.xml')):
        if xml.exists():
            tally = {'passed': 0, 'failed': 0, 'errors': 0, 'skipped': 0}
            for case in ET.parse(xml).getroot().iter('testcase'):
                state = ('errors' if case.find('error') is not None else 'failed' if case.find('failure') is not None
                         else 'skipped' if case.find('skipped') is not None else 'passed')
                tally[state] += 1
            counts[label] = tally
    result['counts'] = counts
    if (WORK / 'observed.json').exists():
        result['observations'] = json.loads((WORK / 'observed.json').read_text())
finally:
    cleaned = subprocess.run(['podman', 'rm', '--force', '--ignore', NAME], capture_output=True, text=True)
    result['cleanup'] = {'exit_code': cleaned.returncode, 'stdout': cleaned.stdout, 'stderr': cleaned.stderr}
    (RECORDS / 'V01-V02-author-container-recheck-validation.json').write_text(
        json.dumps(result, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({'counts': result.get('counts'), 'cleanup': result['cleanup']}), flush=True)
