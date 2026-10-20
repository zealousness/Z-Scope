"""Verify the existing isolation boundary, then run documentation checks only.
"""
import hashlib, json, os, pathlib, shutil, subprocess, sys, time
from datetime import datetime, timezone
from fractions import Fraction

WORK = pathlib.Path('/work')
REPO = pathlib.Path('/mnt/c/Users/10273/home/work/Z-Scope_1.31/Z-Scope')
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
    'mounts':{n:mounts.get(n) for n in ('/','/mnt/c/Users/10273/home/work/Z-Scope_1.31/Z-Scope',DEPS,'/work','/tmp')},
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
    'readonly_inputs':all('ro' in mounts.get(n,{}).get('options',[]) for n in ('/mnt/c/Users/10273/home/work/Z-Scope_1.31/Z-Scope',DEPS)),
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


import signal,xml.etree.ElementTree as ET
manifest=json.loads((WORK/'staging-manifest.json').read_text())
for rel,info in manifest['files'].items():
 assert hash_bytes((REPO/rel).read_bytes())==info['sha256'],rel
for name,info in manifest['external_tests'].items():
 assert hash_bytes(pathlib.Path('/review-tests',name).read_bytes())==info['sha256'],name
plan=json.loads((WORK/'ordinary-plan.json').read_text())
result={'status':'running','checks':[],'image_scope':'same common image; default seccomp and original ASLR','TSAN':'not_run_in_this_container','ASAN':'not_run_in_this_container','python':sys.version}
start=time.monotonic()
def persist():save('ordinary-inside-result.json',result)
try:
 for item in plan:
  label=item['label'];args=item['args'];command=[sys.executable,*args]
  env=dict(os.environ,HOME='/tmp',XDG_CACHE_HOME='/tmp/cache',PYTHONPYCACHEPREFIX='/tmp/compile-cache')
  with (WORK/(label+'.stdout.log')).open('wb') as out,(WORK/(label+'.stderr.log')).open('wb') as err:
   p=subprocess.Popen(command,cwd=REPO,env=env,stdout=out,stderr=err,start_new_session=True)
   try:code=p.wait(timeout=min(600,max(1,880-(time.monotonic()-start))))
   except subprocess.TimeoutExpired:
    os.killpg(p.pid,signal.SIGTERM)
    try:p.wait(timeout=3)
    except subprocess.TimeoutExpired:os.killpg(p.pid,signal.SIGKILL);p.wait()
    raise RuntimeError(label+' timed out')
  entry={'label':label,'command':command,'exit_code':code,'counts':None}
  xml=WORK/(label+'.xml')
  if item.get('expected_passed') is not None and xml.is_file():
   cases=list(ET.parse(xml).getroot().iter('testcase'));counts={'passed':0,'failed':0,'errors':0,'skipped':0}
   for c in cases:
    key='errors' if c.find('error') is not None else 'failed' if c.find('failure') is not None else 'skipped' if c.find('skipped') is not None else 'passed'
    counts[key]+=1
   entry['counts']=counts
   entry['expected_passed']=item['expected_passed']
  result['checks'].append(entry);persist()
  print(json.dumps({'event':'ordinary_check_finished',**entry}),flush=True)
  assert code==0,label+' failed; stop'
  if item.get('expected_passed') is not None:
   assert entry['counts']=={'passed':item['expected_passed'],'failed':0,'errors':0,'skipped':0},label+' count/skip mismatch; stop'
 result['total_passed']=sum(x['counts']['passed'] for x in result['checks'] if x['counts'])
 assert result['total_passed']==1736
 assert pathlib.Path('/proc/sys/kernel/randomize_va_space').read_text().strip()=='2'
 assert int(pathlib.Path('/proc/self/personality').read_text().strip(),16)==0
 result['status']='passed'
except Exception as exc:
 result['status']='failed_or_blocked';result['error']=type(exc).__name__+': '+str(exc)
finally:
 result['elapsed_seconds']=round(time.monotonic()-start,3);persist()
sys.exit(0 if result['status']=='passed' else 1)
