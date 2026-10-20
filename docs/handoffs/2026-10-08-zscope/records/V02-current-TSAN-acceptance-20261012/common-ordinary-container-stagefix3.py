"""One bounded original ordinary matrix and quality run, default security profile."""
import hashlib,json,os,pathlib,shutil,signal,subprocess,sys,tempfile,time
from datetime import datetime,timezone
ROOT=pathlib.Path('/mnt/c/Users/10273/home/work/Z-Scope_1.31/Z-Scope')
LOCAL=pathlib.Path(__file__).resolve().parent
DEST=LOCAL/'common-ordinary-stagefix3-20261012'
DEPS=pathlib.Path('/home/zeal/venv313/lib/python3.13/site-packages')
IMAGE='60e3b821beb946564925285acdc7c87b55bcdf587f4e3006321728dce2900fff'
assert not (DEST/'ordinary.claimed.json').exists() and not (DEST/'ordinary-container-result.json').exists(),'Already attempted; read existing result only'
for mode in ('tsan','asan'):
 r=json.loads((LOCAL/'post-probe-acceptance-symbolizer-route'/(mode+'-acceptance-result.json')).read_text())
 assert r['status']==mode+'_checks_passed' and r['counts']=={'passed':5,'failed':0,'errors':0,'skipped':0} and not r['changed_inputs']
assert json.loads((LOCAL/'post-probe-acceptance-symbolizer-route/tsan-independent-review.json').read_text())['passed']
START=time.monotonic();WORK=pathlib.Path(tempfile.mkdtemp(prefix='zscope-common-ordinary-20261012-'))
STAGE=WORK/'inputs';OUTPUT=WORK/'evidence';EXTERNAL=WORK/'review-tests'
for p in (STAGE,OUTPUT,EXTERNAL):p.mkdir()
NAME='zscope-common-ordinary-'+WORK.name.rsplit('-',1)[-1]
HOST_ENV={k:os.environ[k] for k in ('PATH','HOME','USER','LOGNAME','XDG_RUNTIME_DIR','DBUS_SESSION_BUS_ADDRESS','LANG','LC_ALL','TZ') if k in os.environ}
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
base=json.loads((ROOT/'docs/handoffs/2026-10-08-zscope/records/V01-V02-resource-repair-20261010/repo-format-validation.json').read_text())
manifest={'files':{},'external_tests':{}}
RESULT={'role':'same-image original 1736 ordinary executions plus compileall/mypy','image_id':IMAGE,'started_utc':datetime.now(timezone.utc).isoformat(),'work':str(WORK),'status':'preparing','deadline_seconds':900,'max_output_bytes':8388608,'seccomp_profile':'default','TSAN':'not_run_in_this_container','ASAN':'not_run_in_this_container'}
def save():(DEST/'ordinary-container-result.json').write_text(json.dumps(RESULT,indent=2)+'\n')
def size():return sum(p.stat().st_size for p in OUTPUT.rglob('*') if p.is_file())
try:
 assert os.getuid()==1000 and os.getgid()==1000
 assert sha(pathlib.Path('/usr/share/containers/seccomp.json'))=='cc374cf23846ce1f62f4dc807a8e2b8673c783c6f56cb475467621035d281e6c'
 assert all(sha(ROOT/rel)==h for rel,h in base['inputs_after'].items()),'frozen inputs drifted'
 info=json.loads(subprocess.run(['podman','image','inspect',IMAGE],env=HOST_ENV,capture_output=True,text=True,timeout=30,check=True).stdout)[0]
 assert info['Id'].removeprefix('sha256:')==IMAGE
 for p in DEPS.rglob('*'):
  if p.is_symlink():assert p.resolve().is_relative_to(DEPS.resolve())
 tracked=subprocess.run(['git','ls-files','-z'],cwd=ROOT,capture_output=True,check=True).stdout.decode().split('\0')
 roots={'zscope','scripts','tests','test','requirements','native','tools','.github','docs'}
 top={'install.sh','MANIFEST.in','AGENTS.md','README.md','pyproject.toml','LICENSE','.editorconfig','.gitattributes','.gitignore','zscope.c_cpp.yaml','zscope.java.yaml'}
 paths={rel for rel in tracked if rel and (rel.split('/')[0] in roots or rel in top)}
 paths.update(base['inputs_after'])
 for name in ('zscope','scripts','tests','test','tools'):
  paths.update(p.relative_to(ROOT).as_posix() for p in (ROOT/name).rglob('*.py') if '__pycache__' not in p.parts and not any(x.startswith('.') for x in p.relative_to(ROOT).parts))
 for rel in sorted(paths):
  source=ROOT/rel
  if not source.is_file():continue
  assert not source.is_symlink() and source.resolve().is_relative_to(ROOT.resolve())
  target=STAGE/rel;target.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(source,target)
  assert sha(source)==sha(target)
  manifest['files'][rel]={'sha256':sha(source),'bytes':source.stat().st_size}
 import zlib
 def git_bytes(*args):
  return subprocess.run(['git',*args],cwd=ROOT,capture_output=True,check=True,timeout=30).stdout
 head=git_bytes('rev-parse','HEAD').decode().strip()
 tree=git_bytes('rev-parse','HEAD^{tree}').decode().strip()
 assert len(head)==40 and all(c in '0123456789abcdef' for c in head)
 gitdir=STAGE/'.git';(gitdir/'objects').mkdir(parents=True);(gitdir/'refs').mkdir()
 (gitdir/'HEAD').write_text(head+'\n')
 (gitdir/'config').write_text('[core]\nrepositoryformatversion = 0\nbare = false\n')
 for kind,oid in [('commit',head),('tree',tree)]:
  raw=git_bytes('cat-file',kind,oid)
  object_bytes=(kind+' '+str(len(raw))).encode()+b'\0'+raw
  assert hashlib.sha1(object_bytes).hexdigest()==oid
  target=gitdir/'objects'/oid[:2]/oid[2:];target.parent.mkdir(exist_ok=True)
  target.write_bytes(zlib.compress(object_bytes))
 manifest['git_snapshot']={'head':head,'tree':tree,'scope':'exact actual commit/tree objects, detached snapshot HEAD; no remote/auth config',
  'files':{p.relative_to(STAGE).as_posix():{'sha256':sha(p),'bytes':p.stat().st_size} for p in gitdir.rglob('*') if p.is_file()}}
 assert subprocess.run(['git','rev-parse','HEAD'],cwd=STAGE,capture_output=True,text=True,check=True).stdout.strip()==head
 assert subprocess.run(['git','rev-parse','HEAD^{tree}'],cwd=STAGE,capture_output=True,text=True,check=True).stdout.strip()==tree
 RESULT['git_snapshot']=manifest['git_snapshot']
 external_names=['test_v01_v02_resource_bounds.py','test_v01_v02_resource_controls.py','test_v01_v02_independent_drift.py']
 for name in external_names:
  source=pathlib.Path('/mnt/c/Users/10273/Documents/Codex/2026-10-09/task-3')/name
  shutil.copyfile(source,EXTERNAL/name)
  manifest['external_tests'][name]={'sha256':sha(source),'bytes':source.stat().st_size}
 old=json.loads((ROOT/'docs/handoffs/2026-10-08-zscope/records/V01-V02-resource-repair-20261010/ordinary-final-validation.json').read_text())
 plan=[]
 for check in old['checks']:
  label=check['label'];command=check['command'][1:]
  if check.get('counts'):
   pos=command.index('--tb=short')+1
   targets=[x for x in command[pos:] if not x.startswith(('--basetemp=','--junitxml='))]
   targets=[('/review-tests/'+pathlib.PurePosixPath(x).name) if x.startswith('/mnt/c/Users/10273/Documents/Codex/2026-10-09/task-3/') else x for x in targets]
   args=['-m','pytest','-q','-x','-p','no:cacheprovider','--tb=short','--basetemp=/tmp/'+label,'--junitxml=/work/'+label+'.xml',*targets]
   plan.append({'label':label,'args':args,'expected_passed':check['counts']['passed']})
  elif '-m' in command and command[command.index('-m')+1]=='compileall':
   plan.append({'label':label,'args':['-m','compileall','-f','-q','zscope','scripts','test','tests']})
  elif '-m' in command and command[command.index('-m')+1]=='mypy':
   plan.append({'label':label,'args':['-m','mypy','zscope','--cache-dir','/tmp/mypy-cache']})
 assert sum(x.get('expected_passed',0) for x in plan)==1736 and len(plan)==9
 previous=json.loads((LOCAL/'common-ordinary-20261012/ordinary-container-result.json').read_text())
 accepted=previous['ordinary']['checks'][:6]
 assert sum(x['counts']['passed'] for x in accepted)==193 and not previous['changed_inputs']
 assert all(x['exit_code']==0 and all(x['counts'][k]==0 for k in ('failed','errors','skipped')) for x in accepted)
 RESULT['reused_prior_successful_checks']=accepted
 RESULT['prior_successful_evidence_sha256']=sha(LOCAL/'common-ordinary-20261012/ordinary-container-result.json')
 plan=plan[6:]
 assert [x['label'] for x in plan]==['compatibility','compileall-final','mypy']
 quality_result=json.loads((LOCAL/'common-ordinary-stagefix2-20261012/ordinary-container-result.json').read_text())
 quality_checks=quality_result['ordinary']['checks'][:2]
 assert [x['label'] for x in quality_checks]==['compileall-final','mypy'] and all(x['exit_code']==0 for x in quality_checks)
 assert not quality_result['changed_inputs']
 RESULT['reused_quality_checks']=quality_checks
 RESULT['prior_quality_evidence_sha256']=sha(LOCAL/'common-ordinary-stagefix2-20261012/ordinary-container-result.json')
 plan=plan[:1]
 assert plan[0]['label']=='compatibility'
 RESULT['check_order_note']='Quality reused from unchanged preceding snapshot; strict compatibility gate retained'

 prior_stage=json.loads((LOCAL/'common-ordinary-stagefix2-20261012/evidence/staging-manifest.json').read_text())
 assert all(sha(ROOT/rel)==info['sha256'] for rel,info in prior_stage['files'].items())
 shutil.copyfile(LOCAL/'common-ordinary-stagefix2-20261012/evidence/compatibility.xml',OUTPUT/'prior-compatibility.xml')
 RESULT['prior_compatibility_xml_sha256']=sha(OUTPUT/'prior-compatibility.xml')
 (OUTPUT/'ordinary-plan.json').write_text(json.dumps(plan,indent=2)+'\n')
 (OUTPUT/'staging-manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
 shutil.copyfile(DEST/'ordinary-inside.py',OUTPUT/'ordinary-inside.py')
 RESULT['driver_sha256']=sha(pathlib.Path(__file__));RESULT['inside_driver_sha256']=sha(DEST/'ordinary-inside.py')
 RESULT['staged_file_count']=len(manifest['files']);RESULT['external_tests']=manifest['external_tests']
 command=['podman','run','--rm','--name',NAME,'--pull=never','--network=none','--read-only','--userns=keep-id','--user','1000:1000','--cap-drop=all','--security-opt=no-new-privileges','--pids-limit=256','--memory=2g','--cpus=2','--tmpfs','/tmp:rw,size=512m,exec',
  '-v',str(STAGE)+':'+str(ROOT)+':ro','-v',str(EXTERNAL)+':/review-tests:ro','-v',str(DEPS)+':/venv/lib/python3.13/site-packages:ro','-v',str(OUTPUT)+':/work:rw',
  '-e','PYTHONPATH='+str(ROOT)+':/venv/lib/python3.13/site-packages','-e','PYTHONDONTWRITEBYTECODE=1','-e','PYTEST_DISABLE_PLUGIN_AUTOLOAD=1','-e','PATH=/usr/local/bin:/usr/bin:/bin','-e','TMPDIR=/tmp','-e','TZ=UTC','-w',str(ROOT),IMAGE,'/usr/local/bin/python','/work/ordinary-inside.py']
 RESULT['command']=command;RESULT['status']='running'
 with (DEST/'ordinary.claimed.json').open('x') as f:json.dump({'work':str(WORK),'image':IMAGE,'seccomp':'default'},f)
 save()
 with (OUTPUT/'container.stdout.log').open('wb') as out,(OUTPUT/'container.stderr.log').open('wb') as err:
  p=subprocess.Popen(command,cwd=ROOT,env=HOST_ENV,stdout=out,stderr=err,start_new_session=True)
  while p.poll() is None:
   if time.monotonic()-START>900 or size()>8388608:
    RESULT['stopped']='deadline_or_output_limit';subprocess.run(['podman','stop','--time','2',NAME],env=HOST_ENV,capture_output=True,timeout=20)
    if p.poll() is None:os.killpg(p.pid,signal.SIGTERM)
    break
   time.sleep(.2)
  try:RESULT['exit_code']=p.wait(timeout=10)
  except subprocess.TimeoutExpired:os.killpg(p.pid,signal.SIGKILL);RESULT['exit_code']=p.wait()
 inner=OUTPUT/'ordinary-inside-result.json';iso=OUTPUT/'isolation-verification.json'
 RESULT['ordinary']=json.loads(inner.read_text()) if inner.exists() else None
 RESULT['isolation']=json.loads(iso.read_text()) if iso.exists() else None
 RESULT['status']='passed' if RESULT['exit_code']==0 and RESULT['ordinary'] and RESULT['ordinary']['status']=='passed' and RESULT['isolation'] and RESULT['isolation']['verified'] else 'failed_or_blocked'
except Exception as e:
 RESULT['status']='blocked';RESULT['error']=type(e).__name__+': '+str(e)
finally:
 if 'command' in RESULT:
  clean=subprocess.run(['podman','rm','--force','--ignore',NAME],env=HOST_ENV,capture_output=True,text=True,timeout=30)
  RESULT['owned_container_cleanup']={'exit_code':clean.returncode,'stderr':clean.stderr}
 RESULT['changed_inputs']=[rel for rel,h in manifest['files'].items() if not (ROOT/rel).is_file() or sha(ROOT/rel)!=h['sha256']]
 RESULT['host_aslr_after']=pathlib.Path('/proc/sys/kernel/randomize_va_space').read_text().strip()
 RESULT['elapsed_seconds']=round(time.monotonic()-START,3);RESULT['output_bytes']=size()
 dest=DEST/'evidence';assert not dest.exists();shutil.copytree(OUTPUT,dest)
 RESULT['evidence_files']={p.relative_to(dest).as_posix():{'sha256':sha(p),'bytes':p.stat().st_size} for p in dest.rglob('*') if p.is_file()}
 save();print(json.dumps({k:RESULT.get(k) for k in ('status','exit_code','error','changed_inputs','elapsed_seconds','output_bytes')}))
 sys.exit(0 if RESULT['status']=='passed' and not RESULT['changed_inputs'] and RESULT['host_aslr_after']=='2' else 1)
