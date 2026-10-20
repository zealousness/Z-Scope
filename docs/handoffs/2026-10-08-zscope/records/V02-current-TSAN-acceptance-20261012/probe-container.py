"""PROPOSAL ONLY. Requires specific approval for the personality security exception and one new probe. Never runs fixtures."""
import hashlib, json, os, pathlib, shutil, signal, subprocess, sys, tempfile, time
from datetime import datetime, timezone

ROOT = pathlib.Path('/mnt/c/Users/10273/home/work/Z-Scope_1.31/Z-Scope')
LOCAL = pathlib.Path(__file__).resolve().parent
DEPS = pathlib.Path('/home/zeal/venv313/lib/python3.13/site-packages')
assert sys.argv[1:]==['--approved-tsan-personality-exception'], 'Requires direct approval; preparation is not permission'
IMAGE = '60e3b821beb946564925285acdc7c87b55bcdf587f4e3006321728dce2900fff'
assert len(IMAGE.removeprefix('sha256:')) == 64 and all(c in '0123456789abcdef' for c in IMAGE.removeprefix('sha256:')), 'Pass the reviewed derived image ID, not a moving tag'
EXPECTED_IMAGE_ID = IMAGE.removeprefix('sha256:')
START = time.monotonic()
WORK = pathlib.Path(tempfile.mkdtemp(prefix='zscope-v02-personality-proposal-20261012-'))
STAGE = WORK/'inputs'
OUTPUT = WORK/'evidence'
STAGE.mkdir()
OUTPUT.mkdir()
NAME = 'zscope-v02-common-'+WORK.name.rsplit('-',1)[-1]
DEST = LOCAL/WORK.name
RESULT = {'role':'PROPOSAL: one harmless TSAN compatibility probe in the common candidate image; zero fixtures','started_utc':datetime.now(timezone.utc).isoformat(),
          'work':str(WORK),'container_name':NAME,'image':IMAGE,'uid':os.getuid(),'gid':os.getgid(),
          'deadline_seconds':900,'max_output_bytes':8*1024*1024,'status':'preparing',
          'product_changes':False,'TSAN':'probe_only; thread_fixtures_not_run','external_models':'not_started_or_messaged'}
HOST_ENV = {k:os.environ[k] for k in ('PATH','HOME','USER','LOGNAME','XDG_RUNTIME_DIR',
          'DBUS_SESSION_BUS_ADDRESS','LANG','LC_ALL','TZ') if k in os.environ}
RESULT_PATH = LOCAL/'tsan-personality-probe-result.json'

def digest(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()

baseline = json.loads((ROOT/'docs/handoffs/2026-10-08-zscope/records/V01-V02-resource-repair-20261010/repo-format-validation.json').read_text())
def current_inputs():
    return {r:digest(ROOT/r) if (ROOT/r).is_file() else 'missing'
            for r in baseline['inputs_after']}

def save():
    RESULT_PATH.write_text(json.dumps(RESULT,ensure_ascii=False,indent=2)+'\n')

def output_size():
    return sum(p.stat().st_size for p in OUTPUT.rglob('*') if p.is_file()
               and p.name!='common-probe.py' and p.name!='staging-manifest.json')

try:
    assert os.getuid()==1000 and os.getgid()==1000, 'nonroot expected identity unavailable'
    RESULT['security_exception']='proposed narrowly allowed personality(0x40000); process ASLR may be disabled'
    default_profile=pathlib.Path('/usr/share/containers/seccomp.json')
    assert digest(default_profile)=='cc374cf23846ce1f62f4dc807a8e2b8673c783c6f56cb475467621035d281e6c', 'default policy drift'
    policy=LOCAL/'tsan-personality-seccomp.proposed.json'
    assert digest(policy)=='a56f617057f60b6b569678d7f8cf569a771aab7b721ca5e980199078e0a1a46b', 'reviewed policy drift'
    RESULT['policy_sha256']=digest(policy)
    RESULT['host_aslr_before']=pathlib.Path('/proc/sys/kernel/randomize_va_space').read_text().strip()
    assert RESULT['host_aslr_before']=='2'
    RESULT['inputs_before'] = current_inputs()
    assert RESULT['inputs_before']==baseline['inputs_after'], 'product inputs drifted before compatibility probe'
    assert RESULT['inputs_before']['zscope/core/validation/dynamic_reproduction.py']=='77fdcd1671849348bffcbff643e711b2c260d3ff73907f3d9ac4297b19f6aba7'
    RESULT['source_sha256']=RESULT['inputs_before']['zscope/core/validation/dynamic_reproduction.py']
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
    inside_source = LOCAL/'tsan-personality-probe.proposed.py'
    shutil.copyfile(inside_source,OUTPUT/'common-probe.py')
    RESULT['inside_driver_sha256']=digest(inside_source)
    RESULT['outer_driver_sha256']=digest(pathlib.Path(__file__))
    command = ['podman','run','--rm','--name',NAME,'--pull=never','--network=none',
       '--read-only','--userns=keep-id','--user','1000:1000','--cap-drop=all',
       '--security-opt=no-new-privileges','--security-opt=seccomp='+str(policy),'--pids-limit=256','--memory=2g','--cpus=2',
       '--tmpfs','/tmp:rw,size=512m,exec',
       '-v',str(STAGE)+':/repo:ro',
       '-v',str(DEPS)+':/venv/lib/python3.13/site-packages:ro',
       '-v',str(OUTPUT)+':/work:rw',
       '-e','PYTHONPATH=/repo:/venv/lib/python3.13/site-packages',
       '-e','PYTHONDONTWRITEBYTECODE=1','-e','PYTEST_DISABLE_PLUGIN_AUTOLOAD=1',
       '-e','PATH=/opt/zscope-test/bin:/usr/bin:/bin','-e','TMPDIR=/tmp',
       '-e','TZ=UTC','-w','/repo',IMAGE,'/usr/local/bin/python','/work/common-probe.py']
    RESULT['command']=command
    RESULT['cwd']=str(ROOT)
    with (LOCAL/'tsan-personality-probe.claimed.json').open('x') as claim:
        json.dump({'purpose':'one approved probe only','work':str(WORK),'image':IMAGE,'policy_sha256':digest(policy)},claim)
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
    RESULT['counts']=None
    probe_path=OUTPUT/'compat-probe.json'
    RESULT['probe']=json.loads(probe_path.read_text()) if probe_path.is_file() else None
    RESULT['fixture_executions']=0
    RESULT['status']='compatibility_probe_passed_only' if RESULT['exit_code']==0 and RESULT['probe'] and RESULT['probe']['exit_code']==0 and RESULT['isolation'] and RESULT['isolation']['verified'] else 'blocked_or_failed'
except Exception as exc:
    RESULT['status']='blocked'
    RESULT['error']=type(exc).__name__+': '+str(exc)
finally:
    if 'command' in RESULT:
        cleanup=subprocess.run(['podman','rm','--force','--ignore',NAME],env=HOST_ENV,capture_output=True,text=True,timeout=30)
        RESULT['owned_container_cleanup']={'exit_code':cleanup.returncode,'stdout':cleanup.stdout,'stderr':cleanup.stderr}
    RESULT['host_aslr_after']=pathlib.Path('/proc/sys/kernel/randomize_va_space').read_text().strip()
    RESULT['host_aslr_unchanged']=RESULT.get('host_aslr_before')==RESULT['host_aslr_after']=='2'
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
    if not RESULT.get('host_aslr_unchanged'):
        raise RuntimeError('ASLR verification failed; do not continue')
    print(json.dumps({k:RESULT.get(k) for k in ('status','exit_code','counts','error','stopped','elapsed_seconds','changed_inputs','archived_evidence')}),flush=True)

sys.exit(0 if RESULT.get('status')=='compatibility_probe_passed_only' and not RESULT.get('changed_inputs') and RESULT.get('host_aslr_unchanged') else 1)
