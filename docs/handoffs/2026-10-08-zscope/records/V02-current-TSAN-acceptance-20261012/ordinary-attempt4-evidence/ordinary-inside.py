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
git_snapshot=manifest['git_snapshot']
for rel,info in git_snapshot['files'].items():
 assert hash_bytes((REPO/rel).read_bytes())==info['sha256'],rel
for expression,key in [('HEAD','head'),('HEAD^{tree}','tree')]:
 assert subprocess.run(['git','rev-parse',expression],cwd=REPO,capture_output=True,text=True,check=True).stdout.strip()==git_snapshot[key]
for name,info in manifest['external_tests'].items():
 assert hash_bytes(pathlib.Path('/review-tests',name).read_bytes())==info['sha256'],name

plan=json.loads((WORK/'ordinary-plan.json').read_text())
assert len(plan)==1 and plan[0]['label']=='compatibility'
result={'status':'running','checks':[],'image_scope':'same image/default profile; interrupted original matrix continuation','python':sys.version}
start=time.monotonic()
def persist():save('ordinary-inside-result.json',result)
def run_nodes(label,nodes,path=None):
 command=[sys.executable,'-m','pytest','-q','-x','-p','no:cacheprovider','--tb=short','--basetemp=/tmp/'+label,'--junitxml=/work/'+label+'.xml',*nodes]
 env=dict(os.environ,HOME='/tmp',XDG_CACHE_HOME='/tmp/cache',PYTHONPYCACHEPREFIX='/tmp/compile-cache')
 if path is not None:env['PATH']=path
 with (WORK/(label+'.stdout.log')).open('wb') as out,(WORK/(label+'.stderr.log')).open('wb') as err:
  p=subprocess.Popen(command,cwd=REPO,env=env,stdout=out,stderr=err,start_new_session=True)
  try:code=p.wait(timeout=min(600,max(1,880-(time.monotonic()-start))))
  except subprocess.TimeoutExpired:
   os.killpg(p.pid,signal.SIGTERM)
   try:p.wait(timeout=3)
   except subprocess.TimeoutExpired:os.killpg(p.pid,signal.SIGKILL);p.wait()
   raise RuntimeError(label+' timed out')
 cases=list(ET.parse(WORK/(label+'.xml')).getroot().iter('testcase'))
 counts={'passed':0,'failed':0,'errors':0,'skipped':0}
 for c in cases:
  key='errors' if c.find('error') is not None else 'failed' if c.find('failure') is not None else 'skipped' if c.find('skipped') is not None else 'passed'
  counts[key]+=1
 entry={'label':label,'command':command,'exit_code':code,'counts':counts,'expected_passed':len(nodes),'PATH':env['PATH']}
 result['checks'].append(entry);persist();print(json.dumps({'event':'ordinary_check_finished',**entry}),flush=True)
 assert code==0 and counts=={'passed':len(nodes),'failed':0,'errors':0,'skipped':0},label+' failed or skipped; stop'
try:
 import pytest
 class Collector:
  nodes=[]
  def pytest_collection_finish(self,session):self.nodes=[item.nodeid for item in session.items]
 collector=Collector()
 args=plan[0]['args'];index=next(i for i,x in enumerate(args) if x.startswith('--junitxml='))
 collection=['--collect-only','-q','-p','no:cacheprovider',*args[index+1:]]
 assert pytest.main(collection,plugins=[collector])==0
 all_nodes=collector.nodes
 assert len(all_nodes)==1543 and len(set(all_nodes))==1543
 prior_cases=list(ET.parse(WORK/'prior-compatibility.xml').getroot().iter('testcase'))
 def node_id(case):
  pieces=case.attrib['classname'].split('.')
  for i in range(len(pieces),0,-1):
   rel='/'.join(pieces[:i])+'.py'
   if (REPO/rel).is_file():
    return rel+'::'+'::'.join([*pieces[i:],case.attrib['name']])
  raise AssertionError(case.attrib)
 passed=[];skipped=[];failed=[]
 for c in prior_cases:
  node=node_id(c);assert node in all_nodes
  if c.find('skipped') is not None:skipped.append({'node':node,'reason':c.find('skipped').attrib.get('message','')})
  elif c.find('failure') is not None or c.find('error') is not None:failed.append(node)
  else:passed.append(node)
 assert len(passed)==1259 and len(skipped)==5 and len(failed)==1
 clang_nodes=[x['node'] for x in skipped if x['reason']=='compiler integration requires clang']
 java_blocked=[x for x in skipped if x['reason']=='real Java sidecar contract requires Maven and Java']
 assert len(clang_nodes)==3 and len(java_blocked)==2
 accounted=set(passed)|{x['node'] for x in skipped}
 remaining=[x for x in all_nodes if x not in accounted]
 assert len(remaining)==279 and set(failed).issubset(remaining)
 result.update({'original_selected_nodes':all_nodes,'prior_compatibility_passed_reused':passed,'prior_skip_evidence':skipped,
  'remaining_nodes':remaining,'clang_repair_nodes':clang_nodes,'blocked_java_nodes':java_blocked,'original_heavy_deselections':3})
 persist()
 run_nodes('compatibility-remaining',remaining)
 tools={'/opt/zscope-test/bin/clang18':'421998f342ddaa8595790e45b14a0902e0d55fb7e7ab7440d4bb1094cd8a031b',
  '/opt/zscope-test/llvm18/bin/clang':'8ef402d453d1ba4902e4ee0f0f847f6cfa01400c95aa43c24e97818b9c0e3f45'}
 for name,h in tools.items():assert hash_bytes(pathlib.Path(name).read_bytes())==h
 tool_dir=pathlib.Path('/tmp/zscope-ordinary-clang');tool_dir.mkdir()
 alias=tool_dir/'clang';alias.write_text('#!/bin/sh\nexec /opt/zscope-test/bin/clang18 "$@"\n');alias.chmod(0o755)
 version=subprocess.run([str(alias),'--version'],capture_output=True,text=True,check=True,timeout=30)
 assert '18.1.3' in version.stdout
 save('ordinary-clang-route.json',{'path':str(alias),'sha256':hash_bytes(alias.read_bytes()),'wrapper':alias.read_text(),'underlying_tool_sha256':tools,'version':version.stdout,
  'scope':'Only these three original compiler integration nodes; no global tool replacement or TSAN exception'})
 run_nodes('compatibility-clang-repair',clang_nodes,str(tool_dir)+':/usr/local/bin:/usr/bin:/bin')
 result['total_fresh_passed']=sum(x['counts']['passed'] for x in result['checks'])
 result['compatibility_accounting']={'passed':len(passed)+result['total_fresh_passed'],'failed':0,'errors':0,'skipped':len(java_blocked)}
 assert result['total_fresh_passed']==282 and result['compatibility_accounting']['passed']==1541
 assert pathlib.Path('/proc/sys/kernel/randomize_va_space').read_text().strip()=='2'
 assert int(pathlib.Path('/proc/self/personality').read_text().strip(),16)==0
 result['status']='blocked_missing_original_prerequisites'
 result['error']='Two original Java sidecar nodes remain blocked; the original 1543-pass/zero-skip gate is not satisfied'
except Exception as exc:
 result['status']='failed_or_blocked';result['error']=type(exc).__name__+': '+str(exc)
finally:
 result['elapsed_seconds']=round(time.monotonic()-start,3);persist()
sys.exit(1)
