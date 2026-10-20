"""One specific approved, offline, bounded ASAN acceptance container."""
import hashlib, json, os, pathlib, shutil, signal, subprocess, sys, tempfile, time
from datetime import datetime, timezone
import xml.etree.ElementTree as ET

ROOT = pathlib.Path('/mnt/c/Users/10273/home/work/Z-Scope_1.31/Z-Scope')
LOCAL = pathlib.Path('/mnt/c/Users/10273/Documents/Codex/2026-10-09/task-3')
DEPS = pathlib.Path('/home/zeal/venv313/lib/python3.13/site-packages')
IMAGE = 'docker.io/library/python@sha256:de8ba566572ebcb35cbd10e03f5f351cad00a0d0d50a11e084f1a0fd24a0c41a'
EXPECTED_IMAGE_ID = '1cbbca32768c3c2d7c0dfa6888790808c05672438f20718472f43f0ac8d9707c'
START = time.monotonic()
WORK = pathlib.Path(tempfile.mkdtemp(prefix='zscope-v01-v02-asan-postrepair-20261010-'))
STAGE = WORK/'inputs'
OUTPUT = WORK/'evidence'
STAGE.mkdir()
OUTPUT.mkdir()
NAME = 'zscope-v01-v02-asan-'+WORK.name.rsplit('-',1)[-1]
DEST = LOCAL/WORK.name
RESULT = {'role':'independent postrepair five-node ASAN acceptance','started_utc':datetime.now(timezone.utc).isoformat(),
          'work':str(WORK),'container_name':NAME,'image':IMAGE,'uid':os.getuid(),'gid':os.getgid(),
          'deadline_seconds':900,'max_output_bytes':8*1024*1024,'status':'preparing',
          'product_changes':False,'TSAN':'not_run','external_models':'not_started_or_messaged'}
HOST_ENV = {k:os.environ[k] for k in ('PATH','HOME','USER','LOGNAME','XDG_RUNTIME_DIR',
          'DBUS_SESSION_BUS_ADDRESS','LANG','LC_ALL','TZ') if k in os.environ}
RESULT_PATH = LOCAL/'V01-V02-ASAN-postrepair-20261010.json'

def digest(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()

baseline = json.loads((LOCAL/'V01-V02-independent-acceptance-current.json').read_text())
def current_inputs():
    return {r:digest(ROOT/r) if (ROOT/r).is_file() else 'missing'
            for r in baseline['inputs_before']['files']}

def save():
    RESULT_PATH.write_text(json.dumps(RESULT,ensure_ascii=False,indent=2)+'\n')

def output_size():
    return sum(p.stat().st_size for p in OUTPUT.rglob('*') if p.is_file()
               and p.name!='asan-inside.py' and p.name!='staging-manifest.json')

try:
    assert os.getuid()==1000 and os.getgid()==1000, 'nonroot expected identity unavailable'
    RESULT['inputs_before'] = current_inputs()
    assert RESULT['inputs_before']==baseline['inputs_after']['files'], 'product inputs drifted before ASAN'
    for p in DEPS.rglob('*'):
        if p.is_symlink():
            assert p.resolve().is_relative_to(DEPS.resolve()), 'dependency symlink escapes approved mount: '+str(p)
    inspect = subprocess.run(['podman','image','inspect',IMAGE],env=HOST_ENV,
                             capture_output=True,text=True,timeout=30)
    RESULT['image_inspect_exit']=inspect.returncode
    if inspect.returncode:
        RESULT['image_inspect_error']=inspect.stderr
        raise RuntimeError('fixed local image inspection failed')
    image = json.loads(inspect.stdout)[0]
    assert image['Id'].removeprefix('sha256:')==EXPECTED_IMAGE_ID, 'fixed image identity mismatch'
    RESULT['image_id']=image['Id']
    paths = [p for p in (ROOT/'zscope').rglob('*.py')
             if not any(s.startswith('.') for s in p.relative_to(ROOT).parts)]
    paths.extend(ROOT/r for r in (
        'zscope/config/runtime_defaults.yaml','tests/test_dynamic_reproduction_execution.py',
        'tests/fixtures/dynamic_reproduction/heap_overflow_positive.c',
        'tests/fixtures/dynamic_reproduction/heap_overflow_negative.c',
        'tests/fixtures/dynamic_reproduction/unrelated_crash.c',
        'tests/fixtures/dynamic_reproduction/broken_build.c'))
    manifest = {'files':{}}
    for source in sorted(paths):
        assert source.resolve().is_relative_to(ROOT.resolve()) and not source.is_symlink()
        rel = source.relative_to(ROOT).as_posix()
        target = STAGE/rel
        target.parent.mkdir(parents=True,exist_ok=True)
        shutil.copyfile(source,target)
        h = digest(source)
        assert digest(target)==h
        manifest['files'][rel]={'sha256':h,'bytes':target.stat().st_size}
    manifest['combined_sha256']=hashlib.sha256(''.join(f'{v["sha256"]}  {r}\n' for r,v in manifest['files'].items()).encode()).hexdigest()
    RESULT['staged_inputs']=manifest
    (OUTPUT/'staging-manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
    inside_source = LOCAL/'V01-V02-ASAN-inside-20261010.py'
    shutil.copyfile(inside_source,OUTPUT/'asan-inside.py')
    RESULT['inside_driver_sha256']=digest(inside_source)
    RESULT['outer_driver_sha256']=digest(pathlib.Path(__file__))
    command = ['podman','run','--rm','--name',NAME,'--pull=never','--network=none',
       '--read-only','--userns=keep-id','--user','1000:1000','--cap-drop=all',
       '--security-opt=no-new-privileges','--pids-limit=256','--memory=2g','--cpus=2',
       '--tmpfs','/tmp:rw,size=512m,exec',
       '-v',str(STAGE)+':/repo:ro',
       '-v',str(DEPS)+':/venv/lib/python3.13/site-packages:ro',
       '-v',str(OUTPUT)+':/work:rw',
       '-e','PYTHONPATH=/repo:/venv/lib/python3.13/site-packages',
       '-e','PYTHONDONTWRITEBYTECODE=1','-e','PYTEST_DISABLE_PLUGIN_AUTOLOAD=1',
       '-e','PATH=/usr/bin:/bin','-e','TMPDIR=/tmp',
       '-e','TZ=UTC','-w','/repo',IMAGE,'/usr/local/bin/python','/work/asan-inside.py']
    RESULT['command']=command
    RESULT['cwd']=str(ROOT)
    RESULT['status']='container_running'
    save()
    print(json.dumps({'event':'container_start','staged_inputs':len(paths),'command':command}),flush=True)
    out,err = OUTPUT/'container.stdout.log',OUTPUT/'container.stderr.log'
    stopped = None
    with out.open('wb') as stdout,err.open('wb') as stderr:
        process = subprocess.Popen(command,cwd=ROOT,env=HOST_ENV,stdout=stdout,stderr=stderr,start_new_session=True)
        while process.poll() is None:
            if time.monotonic()-START>900:
                stopped='total_deadline'
            elif output_size()>8*1024*1024:
                stopped='output_limit'
            if stopped:
                termination = subprocess.run(['podman','stop','--time','2',NAME],env=HOST_ENV,
                                             capture_output=True,text=True,timeout=20)
                RESULT['stop_exit']=termination.returncode
                if process.poll() is None:
                    os.killpg(process.pid,signal.SIGTERM)
                break
            time.sleep(.2)
        try:
            RESULT['exit_code']=process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid,signal.SIGKILL)
            RESULT['exit_code']=process.wait()
    RESULT['stopped']=stopped
    isolation_path=OUTPUT/'isolation-verification.json'
    RESULT['isolation']=json.loads(isolation_path.read_text()) if isolation_path.is_file() else None
    xml=OUTPUT/'asan.xml'
    if xml.is_file():
        cases=list(ET.parse(xml).getroot().iter('testcase'))
        counts={'passed':0,'failed':0,'errors':0,'skipped':0}
        RESULT['testcases']=[]
        for c in cases:
            state='errors' if c.find('error') is not None else 'failed' if c.find('failure') is not None else 'skipped' if c.find('skipped') is not None else 'passed'
            counts[state]+=1
            details=[{'type':v.tag,'message':v.get('message',''),'text':v.text or ''}
                     for v in c if v.tag in ('failure','error','skipped')]
            RESULT['testcases'].append({'name':c.get('name'),'state':state,'details':details})
        RESULT['counts']=counts
    else:
        RESULT['counts']=None
    RESULT['status']='asan_checks_passed' if RESULT['exit_code']==0 and RESULT.get('counts')=={'passed':5,'failed':0,'errors':0,'skipped':0} and RESULT['isolation'] and RESULT['isolation']['verified'] else 'blocked_or_failed'
except Exception as exc:
    RESULT['status']='blocked'
    RESULT['error']=type(exc).__name__+': '+str(exc)
finally:
    if 'command' in RESULT:
        cleanup=subprocess.run(['podman','rm','--force','--ignore',NAME],env=HOST_ENV,capture_output=True,text=True,timeout=30)
        RESULT['owned_container_cleanup']={'exit_code':cleanup.returncode,'stdout':cleanup.stdout,'stderr':cleanup.stderr}
    RESULT['inputs_after']=current_inputs()
    RESULT['changed_inputs']=[r for r,h in RESULT.get('inputs_before',{}).items() if RESULT['inputs_after'].get(r)!=h]
    RESULT['output_bytes']=output_size()
    RESULT['elapsed_seconds']=round(time.monotonic()-START,3)
    RESULT['finished_utc']=datetime.now(timezone.utc).isoformat()
    RESULT['evidence_files']={p.relative_to(OUTPUT).as_posix():{'bytes':p.stat().st_size,'sha256':digest(p)}
                              for p in OUTPUT.rglob('*') if p.is_file()}
    assert not DEST.exists()
    shutil.copytree(OUTPUT,DEST)
    RESULT['archived_evidence']=str(DEST)
    save()
    print(json.dumps({k:RESULT.get(k) for k in ('status','exit_code','counts','error','stopped','elapsed_seconds','changed_inputs','archived_evidence')}),flush=True)
