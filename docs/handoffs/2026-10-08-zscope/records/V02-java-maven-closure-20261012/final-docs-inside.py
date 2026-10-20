"""Verify the existing isolation boundary, then run documentation checks only.
"""
import hashlib, json, os, pathlib, shutil, subprocess, sys, time
from datetime import datetime, timezone
from fractions import Fraction

WORK = pathlib.Path('/work')
REPO = pathlib.Path('/repo')
DEPS = '/venv/lib/python3.13/site-packages'

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
    assert not p.is_symlink() and p.resolve().is_relative_to(REPO)
    assert hash_bytes(p.read_bytes()) == info['sha256']
for rel in ('docs/handoffs/2026-10-08-zscope/TASKS.yaml',
            'docs/handoffs/2026-10-08-zscope/PROGRESS.md',
            'docs/handoffs/2026-10-08-zscope/records/V02-java-maven-closure-20261012.md'):
    data=(REPO/rel).read_bytes()
    assert not data.startswith(b'\xef\xbb\xbf') and b'\r' not in data and data.endswith(b'\n')
    data.decode('utf-8',errors='strict')
import yaml
tasks=yaml.safe_load((REPO/'docs/handoffs/2026-10-08-zscope/TASKS.yaml').read_text())
items=tasks['tasks']
assert next(t for t in items if t['id']=='V01')['status']=='done'
v02=next(t for t in items if t['id']=='V02')
assert v02['status']=='done'
assert v02['result_record']=='records/V02-java-maven-closure-20261012.md'
summary=json.loads((REPO/'docs/handoffs/2026-10-08-zscope/records/V02-java-maven-closure-20261012/closure-summary.json').read_text())
assert summary['V01']=='done' and summary['V02']=='done_pending_handoff_validation'
assert summary['ordinary']=={'passed':1736,'failed':0,'errors':0,'skipped':0}
assert summary['TSAN']==summary['ASAN']=={'passed':5,'failed':0,'errors':0,'skipped':0}
assert summary['compileall_mypy']=={'compileall-final':0,'mypy':0}
assert summary['source_frozen_count']==403 and not summary['product_or_test_changes']
command=[sys.executable,'-m','pytest','-q','-p','no:cacheprovider',
         'tests/test_agent_docs.py','--junitxml=/work/docs.xml']
run=subprocess.run(command,cwd=REPO,capture_output=True,timeout=120,check=False)
(WORK/'pytest.stdout.log').write_bytes(run.stdout)
(WORK/'pytest.stderr.log').write_bytes(run.stderr)
save('docs-inside-result.json',{'command':command,'exit_code':run.returncode,
  'image_scope':'existing common candidate; documentation subset only',
  'TSAN':'not_run','ASAN':'not_run','full_regression':'not_run',
  'handoff_encoding_and_task_state_valid':True,
  'python':sys.version,'python_executable':sys.executable})
print(run.stdout.decode('utf-8','replace'),end='')
print(run.stderr.decode('utf-8','replace'),end='',file=sys.stderr)
sys.exit(run.returncode)
