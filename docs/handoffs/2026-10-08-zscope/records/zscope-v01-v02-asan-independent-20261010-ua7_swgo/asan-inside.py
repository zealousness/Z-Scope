"""Verify the actual container boundary, then run only five approved ASAN nodes.

The profiler observes returned evidence and copies the runner's own raw logs
before normal cleanup. It does not patch product functions, policies, or tests.
"""
import hashlib, json, os, pathlib, shutil, subprocess, sys, time
from datetime import datetime, timezone
from fractions import Fraction

WORK = pathlib.Path('/work')
REPO = pathlib.Path('/repo')
DEPS = '/venv/lib/python3.13/site-packages'
NAMES = [
    'test_asan_positive_fixture_confirms_through_shared_adjudication',
    'test_asan_negative_fixture_is_not_reproduced_and_never_rejects',
    'test_asan_unrelated_crash_never_confirms_the_candidate',
    'test_asan_build_generated_binary_confirms_without_a_declared_digest',
    'test_asan_build_failure_stays_undecided',
]
NODES = ['tests/test_dynamic_reproduction_execution.py::'+n for n in NAMES]

def save(name, data):
    (WORK/name).write_text(json.dumps(data,ensure_ascii=False,indent=2)+'\n')

def hash_bytes(raw):
    return hashlib.sha256(raw).hexdigest()

mounts = {}
for line in pathlib.Path('/proc/self/mountinfo').read_text().splitlines():
    fields = line.split()
    separator = fields.index('-')
    mounts[fields[4]] = {'options':fields[5].split(','),
                         'type':fields[separator+1],
                         'super_options':fields[separator+3].split(',')}
status = dict(line.split(':',1) for line in pathlib.Path('/proc/self/status').read_text().splitlines() if ':' in line)
limits = {n:pathlib.Path('/sys/fs/cgroup',n).read_text().strip()
          for n in ('memory.max','pids.max','cpu.max')}
cpu_quota, cpu_period = limits['cpu.max'].split()
tmp = os.statvfs('/tmp')
isolation = {
    'checked_utc':datetime.now(timezone.utc).isoformat(),
    'uid':os.getuid(),'gid':os.getgid(),
    'mounts':{n:mounts.get(n) for n in ('/','/repo',DEPS,'/work','/tmp')},
    'limits':limits,'tmpfs_bytes':tmp.f_blocks*tmp.f_frsize,
    'network_interfaces':sorted(p.name for p in pathlib.Path('/sys/class/net').iterdir()),
    'ipv4_routes':pathlib.Path('/proc/net/route').read_text().splitlines()[1:],
    'no_new_privileges':status['NoNewPrivs'].strip(),
    'capabilities':{n:status[n].strip() for n in ('CapEff','CapPrm','CapBnd')},
    'seccomp':status['Seccomp'].strip(),
    'uid_map':pathlib.Path('/proc/self/uid_map').read_text().strip(),
}
checks = {
    'nonroot':isolation['uid']==1000 and isolation['gid']==1000,
    'readonly_root': 'ro' in mounts.get('/',{}).get('options',[]),
    'readonly_inputs':all('ro' in mounts.get(n,{}).get('options',[]) for n in ('/repo',DEPS)),
    'owned_evidence_writable':'rw' in mounts.get('/work',{}).get('options',[]),
    'tmpfs_512MiB':mounts.get('/tmp',{}).get('type')=='tmpfs' and isolation['tmpfs_bytes']==512*1024*1024,
    'tmpfs_executable':'noexec' not in mounts.get('/tmp',{}).get('options',[]),
    'network_none':isolation['network_interfaces']==['lo'] and not isolation['ipv4_routes'],
    'no_new_privileges':isolation['no_new_privileges']=='1',
    'all_capabilities_dropped':all(int(v,16)==0 for v in isolation['capabilities'].values()),
    'seccomp_filter':isolation['seccomp']=='2',
    'memory_2GiB':limits['memory.max']=='2147483648',
    'pids_256':limits['pids.max']=='256',
    'cpu_2':cpu_quota!='max' and Fraction(int(cpu_quota),int(cpu_period))==2,
}
isolation['checks'] = checks
isolation['verified'] = all(checks.values())
save('isolation-verification.json',isolation)
print(json.dumps({'event':'isolation_checked','verified':isolation['verified'],'checks':checks}),flush=True)
if not isolation['verified']:
    sys.exit(80)

manifest = json.loads((WORK/'staging-manifest.json').read_text())
for rel, info in manifest['files'].items():
    p = REPO/rel
    assert p.resolve().is_relative_to(REPO) and not p.is_symlink()
    assert hash_bytes(p.read_bytes()) == info['sha256'], 'staged input mismatch: '+rel
compiler = shutil.which('clang') or shutil.which('cc') or shutil.which('gcc')
if not compiler:
    save('toolchain-preflight.json',{'available':False,'reason':'no compiler on approved PATH'})
    sys.exit(81)
version = subprocess.run([compiler,'--version'],capture_output=True,text=True,timeout=15)
toolchain = {'compiler':compiler,'resolved_compiler':os.path.realpath(compiler),
             'compiler_sha256':hash_bytes(pathlib.Path(compiler).read_bytes()),
             'version_exit':version.returncode,'version':version.stdout,'stderr':version.stderr,
             'python':sys.version,'PATH':os.environ.get('PATH')}
save('toolchain-preflight.json',toolchain)
if version.returncode:
    sys.exit(81)

import pytest

events, observer_errors = [], []
current_node = None
raw_count = 0
raw_bytes = 0
raw_dir = WORK/'raw'
raw_dir.mkdir(exist_ok=False)
RAW_LIMIT = 8*1024*1024

def archive_raw(raw, label):
    global raw_count, raw_bytes
    if isinstance(raw,str):
        raw = raw.encode()
    if raw is None:
        return None
    assert isinstance(raw,bytes)
    if raw_bytes+len(raw)>RAW_LIMIT:
        raise RuntimeError('observer raw output budget exceeded')
    raw_count += 1
    raw_bytes += len(raw)
    p = raw_dir/f'{raw_count:03d}-{label}'
    p.write_bytes(raw)
    return {'path':str(p),'bytes':len(raw),'sha256':hash_bytes(raw)}

def observe(frame,event,value):
    if event!='return':
        return
    try:
        filename, name = frame.f_code.co_filename, frame.f_code.co_name
        if filename.endswith('/zscope/core/validation/dynamic_reproduction.py'):
            if name in ('execute','replay_witness','availability','build_execution_plan') and hasattr(value,'to_dict'):
                events.append({'node':current_node,'event':name,'type':type(value).__name__,'evidence':value.to_dict()})
            if name=='_run_once':
                loc = frame.f_locals
                streams = {}
                for key in ('out_path','err_path'):
                    p = pathlib.Path(loc[key])
                    assert p.resolve().is_relative_to(pathlib.Path('/tmp'))
                    streams[key] = archive_raw(p.read_bytes(),loc['tag']+('-stdout.log' if key=='out_path' else '-stderr.log'))
                events.append({'node':current_node,'event':'raw_runner_process',
                               'argv':list(loc['argv']),'cwd':loc['cwd'],'tag':loc['tag'],
                               'timeout_seconds':loc['timeout_seconds'],
                               'environment':dict(loc['env']),'streams':streams,
                               'exit_code':value.exit_code if value is not None else None})
        if filename==subprocess.__file__ and name=='run' and isinstance(value,subprocess.CompletedProcess):
            kwargs = frame.f_locals.get('kwargs',{})
            events.append({'node':current_node,'event':'compiler_or_probe_process',
                           'argv':value.args,'cwd':str(kwargs.get('cwd','/repo')),
                           'exit_code':value.returncode,
                           'stdout':archive_raw(value.stdout,'direct-stdout.log'),
                           'stderr':archive_raw(value.stderr,'direct-stderr.log')})
    except Exception as exc:
        if len(observer_errors)<10:
            observer_errors.append(type(exc).__name__+': '+str(exc))

class Observer:
    def pytest_collection_modifyitems(self,session,config,items):
        assert [i.nodeid for i in items]==NODES, 'collection escaped approved five nodes'

    @pytest.hookimpl(hookwrapper=True)
    def pytest_runtest_call(self,item):
        global current_node
        current_node = item.nodeid
        previous = sys.getprofile()
        assert previous is None
        sys.setprofile(observe)
        try:
            yield
        finally:
            sys.setprofile(previous)

    def pytest_sessionfinish(self,session,exitstatus):
        observed = {}
        for module in list(sys.modules.values()):
            if getattr(module,'__file__',None)==str(REPO/'tests/test_dynamic_reproduction_execution.py'):
                observed.update(getattr(module,'_OBSERVED',{}))
        save('observed-executions.json',{'events':events,'test_observed':observed,
             'observer_errors':observer_errors,'raw_files':raw_count,'raw_bytes':raw_bytes})

args = ['-q','-s','-p','no:cacheprovider','--tb=short',
        '--basetemp=/tmp/pytest-asan','--junitxml=/work/asan.xml',*NODES]
save('pytest-request.json',{'args':args,'nodes':NODES,'observer':'read-only sys.setprofile; no monkeypatch',
                          'started_utc':datetime.now(timezone.utc).isoformat()})
print(json.dumps({'event':'pytest_start','nodes':NODES}),flush=True)
code = pytest.main(args,plugins=[Observer()])
save('pytest-return.json',{'exit_code':code,'observer_errors':observer_errors,
                         'finished_utc':datetime.now(timezone.utc).isoformat()})
sys.exit(82 if observer_errors and not code else int(code))
