"""Rerun only the 34 ordinary clang checks skipped in independent acceptance."""
import hashlib, json, os, signal, subprocess, sys, time
from datetime import datetime, timezone
from pathlib import Path
import xml.etree.ElementTree as ET

ROOT = Path('/mnt/c/Users/10273/home/work/Z-Scope_1.31/Z-Scope')
LOCAL = Path('/mnt/c/Users/10273/Documents/Codex/2026-10-09/task-3')
BASE = json.loads((LOCAL/'V01-V02-independent-acceptance-20261010-ag7xwe18.json').read_text())
WORK = Path(BASE['work'])
XML = WORK/'compatibility-clang-supplement.xml'
OUT = WORK/'compatibility-clang-supplement.stdout.log'
ERR = WORK/'compatibility-clang-supplement.stderr.log'
TARGETS = [c.get('classname').replace('.', '/')+'.py::'+c.get('name')
           for c in ET.parse(WORK/'compatibility.xml').getroot().iter('testcase')
           if c.find('skipped') is not None]
assert len(TARGETS) == 34
assert all(t.startswith(('tests/test_review_fact_checks.py::',
                         'tests/test_review_runtime.py::')) for t in TARGETS)

def digest(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()

def snapshot():
    return {r: digest(ROOT/r) if (ROOT/r).is_file() else 'missing'
            for r in BASE['inputs_before']['files']}

before = snapshot()
assert before == BASE['inputs_after']['files'], 'inputs drifted before supplement'
env = {k: os.environ[k] for k in ('LANG','LC_ALL','LC_CTYPE','TZ') if k in os.environ}
env.update(PATH='/home/zeal/venv313/bin:/usr/lib/llvm-18/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin',
           PYTHONDONTWRITEBYTECODE='1', PYTEST_DISABLE_PLUGIN_AUTOLOAD='1',
           PYTHONPATH=str(ROOT), TMPDIR=str(WORK), XDG_CACHE_HOME=str(WORK/'cache'))
command = [sys.executable,'-m','pytest','-q','-p','no:cacheprovider','--tb=short',
           '--basetemp='+str(WORK/'compatibility-clang-supplement-tmp'),
           '--junitxml='+str(XML),*TARGETS]
result = {'role':'independent compatibility supplement; no sanitizer execution',
          'started_utc':datetime.now(timezone.utc).isoformat(),
          'command':command,'cwd':str(ROOT),'environment':env,
          'timeout_seconds':600,'max_output_bytes':8*1024*1024,
          'input_count':len(before),'inputs_before':before,
          'driver_sha256':digest(Path(__file__))}
print(json.dumps({'event':'start','targets':len(TARGETS),'timeout_seconds':600}),flush=True)
start = time.monotonic()
stopped = None
with OUT.open('wb') as out, ERR.open('wb') as err:
    p = subprocess.Popen(command,cwd=ROOT,env=env,stdout=out,stderr=err,start_new_session=True)
    while p.poll() is None:
        if time.monotonic()-start > 600:
            stopped = 'timeout'
        elif OUT.stat().st_size+ERR.stat().st_size > 8*1024*1024:
            stopped = 'output_limit'
        if stopped:
            os.killpg(p.pid,signal.SIGTERM)
            try:
                p.wait(timeout=5)
            except subprocess.TimeoutExpired:
                os.killpg(p.pid,signal.SIGKILL)
            break
        time.sleep(.1)
    result.update(exit_code=p.wait(),elapsed_seconds=round(time.monotonic()-start,3),stopped=stopped)
result['counts'] = {'passed':0,'failed':0,'errors':0,'skipped':0}
result['failures'] = []
if XML.is_file():
    for c in ET.parse(XML).getroot().iter('testcase'):
        tag = next((t for t in ('error','failure','skipped') if c.find(t) is not None),None)
        state = {None:'passed','error':'errors','failure':'failed','skipped':'skipped'}[tag]
        result['counts'][state] += 1
        if tag:
            result['failures'].append({'node':c.get('classname')+'::'+c.get('name'),
                                       'state':state,'message':c.find(tag).get('message','')})
result['files'] = {p.name:{'path':str(p),'sha256':digest(p)} for p in (OUT,ERR,XML) if p.is_file()}
after = snapshot()
result['inputs_after'] = after
result['changed_inputs'] = [r for r,h in before.items() if after.get(r)!=h]
result['finished_utc'] = datetime.now(timezone.utc).isoformat()
path = LOCAL/'V01-V02-compatibility-skips-20261010.json'
path.write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n')
print(json.dumps({k:result[k] for k in ('exit_code','counts','stopped','changed_inputs')},ensure_ascii=False),flush=True)
