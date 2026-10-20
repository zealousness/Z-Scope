"""Run submitted sanitizer tests in an external, local, offline review sandbox.

This wrapper is acceptance infrastructure, not an implementation of the product
runner. Its isolation must not be credited to V01/V02 themselves.
"""
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import time
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT = Path(__file__).resolve().parents[4]
RECORDS = Path(__file__).resolve().parent
WORK = Path(tempfile.mkdtemp(prefix="zscope-v01-v02-reacceptance-container-20261009-"))
NAME = WORK.name
IMAGE = "docker.io/library/python@sha256:de8ba566572ebcb35cbd10e03f5f351cad00a0d0d50a11e084f1a0fd24a0c41a"
base = ["podman", "run", "--rm", "--name", NAME, "--pull=never", "--network=none",
        "--read-only", "--userns=keep-id", "--cap-drop=all",
        "--security-opt=no-new-privileges", "--pids-limit=256", "--memory=2g", "--cpus=2",
        "--tmpfs", "/tmp:rw,size=512m,exec", "-v", f"{ROOT}:/repo:ro",
        "-v", "/home/zeal/venv313:/venv:ro", "-v", f"{WORK}:/work:rw",
        "-e", "PYTHONPATH=/repo:/venv/lib/python3.13/site-packages",
        "-e", "PYTHONDONTWRITEBYTECODE=1", "-w", "/repo"]
probe = '''import os,sys,json,shutil,subprocess
from pathlib import Path
import pytest,zscope
status=Path('/proc/self/status').read_text()
data={'python':sys.version,'pytest':pytest.__version__,'zscope':zscope.__file__,
 'compiler':subprocess.run(['gcc','--version'],capture_output=True,text=True).stdout.splitlines()[0],
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
result = {'date': '2026-10-09', 'scope': 'independent review container, not product isolation',
          'image': IMAGE, 'work': str(WORK), 'checks': []}
declared = json.loads((RECORDS / 'V01-V02-final-workspace.json').read_text())['frozen_inputs']['files']
input_paths = [ROOT / name for name in declared] + [Path(__file__), RECORDS / 'V01-V02-reacceptance-integration.py']
result['input_hashes'] = {str(path.relative_to(ROOT)): hashlib.sha256(path.read_bytes()).hexdigest() for path in input_paths}
try:
    for name, command in [
        ('preflight', base + [IMAGE, 'python', '-c', probe]),
        ('sanitizer-tests', base + ['-e', 'ZSCOPE_DYNAMIC_REPRODUCTION_EVIDENCE=/work/observed.json', '-e', 'ZSCOPE_REVIEW_ISOLATED=1', '-e', 'ZSCOPE_REVIEW_BUILD_EVIDENCE=/work/build-evidence.json',
            IMAGE, 'python', '-m', 'pytest', '-q', '-rs', '-p', 'no:cacheprovider',
            '--tb=short', '--basetemp=/tmp/pytest', '--junitxml=/work/junit.xml',
            'tests/test_dynamic_reproduction_execution.py', 'docs/handoffs/2026-10-08-zscope/records/V01-V02-reacceptance-integration.py', '-k', 'not missing_optional']),
    ]:
        started = time.monotonic()
        ran = subprocess.run(command, capture_output=True, text=True, timeout=240)
        (WORK / (name + '.log')).write_text(ran.stdout + ran.stderr, encoding='utf-8')
        result['checks'].append({'name': name, 'command': command, 'exit_code': ran.returncode,
            'duration_seconds': round(time.monotonic()-started, 3),
            'stdout': ran.stdout, 'stderr': ran.stderr})
        print(json.dumps(result['checks'][-1]), flush=True)
        if name == 'preflight' and ran.returncode:
            result['sanitizer_status'] = 'not_run'
            break
    xml = WORK / 'junit.xml'
    if xml.exists():
        counts = {'passed':0,'failed':0,'errors':0,'skipped':0}
        for case in ET.parse(xml).getroot().iter('testcase'):
            state=('errors' if case.find('error') is not None else 'failed' if case.find('failure') is not None
                   else 'skipped' if case.find('skipped') is not None else 'passed')
            counts[state]+=1
        result['counts']=counts
    if (WORK / 'observed.json').exists():
        result['observations']=json.loads((WORK/'observed.json').read_text())
    if (WORK / 'build-evidence.json').exists():
        result['build_observations'] = json.loads((WORK / 'build-evidence.json').read_text())
finally:
    cleaned = subprocess.run(['podman','rm','--force','--ignore',NAME], capture_output=True,text=True)
    result['cleanup']={'exit_code':cleaned.returncode,'stdout':cleaned.stdout,'stderr':cleaned.stderr}
    result['changed_inputs'] = [name for name, digest in result['input_hashes'].items()
                               if hashlib.sha256((ROOT / name).read_bytes()).hexdigest() != digest]
    (RECORDS/'V01-V02-reacceptance-container-validation.json').write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    print(json.dumps({'counts':result.get('counts'),'cleanup':result['cleanup']}),flush=True)
