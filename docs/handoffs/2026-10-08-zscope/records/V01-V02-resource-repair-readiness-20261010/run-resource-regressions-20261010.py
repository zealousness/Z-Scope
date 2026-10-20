import hashlib, json, os, pathlib, subprocess, sys, tempfile
from datetime import datetime, timezone
import xml.etree.ElementTree as ET
ROOT=pathlib.Path('/mnt/c/Users/10273/home/work/Z-Scope_1.31/Z-Scope')
LOCAL=pathlib.Path('/mnt/c/Users/10273/Documents/Codex/2026-10-09/task-3')
WORK=pathlib.Path(tempfile.mkdtemp(prefix='zscope-resource-regressions-20261010-'))
name='V01-V02-resource-regressions-'+sys.argv[1]+'-20261010'
env={k:os.environ[k] for k in ('LANG','LC_ALL','TZ') if k in os.environ}
env.update(PATH='/home/zeal/venv313/bin:/usr/bin:/bin',PYTHONPATH=str(ROOT),PYTHONDONTWRITEBYTECODE='1',PYTEST_DISABLE_PLUGIN_AUTOLOAD='1',TMPDIR=str(WORK))
digest=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
tracked=json.loads((LOCAL/'V01-V02-TSAN-minimal-20261010-xc9j8htj.json').read_text())['inputs_after']
before={p:digest(ROOT/p) for p in tracked}
xml=LOCAL/(name+'.xml');out=LOCAL/(name+'.stdout.log');err=LOCAL/(name+'.stderr.log')
cmd=[sys.executable,'-m','pytest','-q','-p','no:cacheprovider','--tb=short','--basetemp='+str(WORK/'tmp'),'--junitxml='+str(xml),str(LOCAL/'test_v01_v02_resource_bounds.py')]
with out.open('xb') as so,err.open('xb') as se:
    result=subprocess.run(cmd,cwd=ROOT,env=env,stdout=so,stderr=se,timeout=90,check=False)
counts={'passed':0,'failed':0,'errors':0,'skipped':0}; failures=[]
for c in ET.parse(xml).getroot().iter('testcase'):
    state='errors' if c.find('error') is not None else 'failed' if c.find('failure') is not None else 'skipped' if c.find('skipped') is not None else 'passed'
    counts[state]+=1
    if state!='passed': failures.append({'name':c.get('name'),'state':state,'detail':[(x.text or '') for x in c]})
after={p:digest(ROOT/p) for p in tracked}
r={'at':datetime.now(timezone.utc).isoformat(),'command':cmd,'exit_code':result.returncode,'counts':counts,'failures':failures,'source_digest':before['zscope/core/validation/dynamic_reproduction.py'],'inputs_before':before,'inputs_after':after,'changed_inputs':[p for p in before if before[p]!=after[p]],'pressure':False,'max_fixture_output_bytes_per_stream':64,'memory_pressure':False,'sanitizer_execution':False,'files':{p.name:{'bytes':p.stat().st_size,'sha256':digest(p)} for p in (out,err,xml)}}
(LOCAL/(name+'.json')).write_text(json.dumps(r,indent=2)+'\n')
print(json.dumps({k:r[k] for k in ('exit_code','counts','failures','source_digest','changed_inputs','pressure')}))
