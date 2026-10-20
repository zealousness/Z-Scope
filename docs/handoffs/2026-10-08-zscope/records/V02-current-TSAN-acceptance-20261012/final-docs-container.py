"""One bounded documentation-only check in the existing common candidate."""
import datetime,hashlib,json,os,pathlib,shutil,signal,subprocess,sys,tempfile,time
import xml.etree.ElementTree as ET
import yaml
ROOT=pathlib.Path('/mnt/c/Users/10273/home/work/Z-Scope_1.31/Z-Scope')
LOCAL=pathlib.Path(__file__).resolve().parent
DEPS=pathlib.Path('/home/zeal/venv313/lib/python3.13/site-packages')
IMAGE='60e3b821beb946564925285acdc7c87b55bcdf587f4e3006321728dce2900fff'
START=time.monotonic()
WORK=pathlib.Path(tempfile.mkdtemp(prefix='zscope-v02-docs-20261012-'))
STAGE=WORK/'inputs'; OUTPUT=WORK/'evidence'
STAGE.mkdir(); OUTPUT.mkdir()
NAME='zscope-v02-docs-'+WORK.name.rsplit('-',1)[-1]
HOST_ENV={k:os.environ[k] for k in ('PATH','HOME','USER','LOGNAME','XDG_RUNTIME_DIR','DBUS_SESSION_BUS_ADDRESS','LANG','LC_ALL','TZ') if k in os.environ}
RESULT={'role':'documentation-only verification','image_id':IMAGE,'work':str(WORK),'status':'preparing',
  'deadline_seconds':900,'max_output_bytes':8*1024*1024,'TSAN':'not_run','ASAN':'not_run',
  'full_regression':'not_run','started_utc':datetime.datetime.now(datetime.timezone.utc).isoformat()}
manifest={'files':{}}
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
def save():
 (LOCAL/'docs-container-result.json').write_text(json.dumps(RESULT,indent=2)+'\n')
def size():
 return sum(p.stat().st_size for p in OUTPUT.rglob('*') if p.is_file())
try:
 assert os.getuid()==1000 and os.getgid()==1000
 image=subprocess.run(['podman','image','inspect',IMAGE],env=HOST_ENV,capture_output=True,text=True,timeout=30,check=True)
 info=json.loads(image.stdout)[0]
 assert info['Id'].removeprefix('sha256:')==IMAGE
 RESULT['image_layer_ids']=info.get('RootFS',{}).get('Layers',[])
 for p in DEPS.rglob('*'):
  if p.is_symlink(): assert p.resolve().is_relative_to(DEPS.resolve())
 RESULT['dependency_manifest_sha256']=hashlib.sha256(''.join(str(p.relative_to(DEPS))+':'+sha(p)+'\n' for p in sorted(DEPS.rglob('*')) if p.is_file()).encode()).hexdigest()
 names=['execution-orchestration.md','analysis-pipeline.md','retrieval-backends.md','agent-runtime.md','configuration-state.md','review-memory.md','wiki.md','interfaces-reporting.md','benchmarking.md']
 paths={'docs/handoffs/2026-10-08-zscope/records/V02-current-TSAN-acceptance-20261012/acceptance-summary.json','docs/handoffs/2026-10-08-zscope/records/V02-current-TSAN-acceptance-20261012/JAVA-MAVEN-SAME-IMAGE-SUPPLEMENT.md','AGENTS.md','.editorconfig','.gitattributes','docs/modules/README.md','docs/range-benchmark.md','tests/test_agent_docs.py',
  'docs/handoffs/2026-10-08-zscope/TASKS.yaml','docs/handoffs/2026-10-08-zscope/PROGRESS.md',
  'docs/handoffs/2026-10-08-zscope/records/V02-current-TSAN-acceptance-20261012.md'}
 if (ROOT/'AGENT.md').exists(): paths.add('AGENT.md')
 for n in names:
  rel='docs/modules/'+n; paths.add(rel)
  text=(ROOT/rel).read_text()
  meta=yaml.safe_load(text.split('---\n',2)[1])
  paths.update(meta['sources']); paths.update(meta['tests']); paths.update(meta['covers'])
 packages=sorted(p.name for p in (ROOT/'zscope').iterdir() if p.is_dir() and p.name!='__pycache__')
 RESULT['top_level_packages']=packages
 for n in packages:(STAGE/'zscope'/n).mkdir(parents=True,exist_ok=True)
 for rel in sorted(paths):
  source=ROOT/rel; target=STAGE/rel
  assert not source.is_symlink() and source.resolve().is_relative_to(ROOT.resolve())
  if source.is_dir():target.mkdir(parents=True,exist_ok=True);continue
  assert source.is_file(),rel
  target.parent.mkdir(parents=True,exist_ok=True); shutil.copyfile(source,target)
  h=sha(source); assert sha(target)==h
  manifest['files'][rel]={'sha256':h,'bytes':source.stat().st_size}
 (OUTPUT/'staging-manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
 shutil.copyfile(LOCAL/'docs-inside.py',OUTPUT/'docs-inside.py')
 RESULT['driver_sha256']=sha(pathlib.Path(__file__))
 RESULT['inside_driver_sha256']=sha(LOCAL/'docs-inside.py')
 command=['podman','run','--rm','--name',NAME,'--pull=never','--network=none','--read-only',
  '--userns=keep-id','--user','1000:1000','--cap-drop=all','--security-opt=no-new-privileges',
  '--pids-limit=256','--memory=2g','--cpus=2','--tmpfs','/tmp:rw,size=512m,exec',
  '-v',str(STAGE)+':/repo:ro','-v',str(DEPS)+':/venv/lib/python3.13/site-packages:ro',
  '-v',str(OUTPUT)+':/work:rw','-e','PYTHONPATH=/repo:/venv/lib/python3.13/site-packages',
  '-e','PYTHONDONTWRITEBYTECODE=1','-e','PYTEST_DISABLE_PLUGIN_AUTOLOAD=1','-e','PATH=/usr/bin:/bin',
  '-e','TMPDIR=/tmp','-e','TZ=UTC','-w','/repo',IMAGE,'/usr/local/bin/python','/work/docs-inside.py']
 RESULT['command']=command; RESULT['status']='running'; save()
 with (OUTPUT/'container.stdout.log').open('wb') as out,(OUTPUT/'container.stderr.log').open('wb') as err:
  process=subprocess.Popen(command,cwd=ROOT,env=HOST_ENV,stdout=out,stderr=err,start_new_session=True)
  while process.poll() is None:
   if time.monotonic()-START>900 or size()>8*1024*1024:
    RESULT['stopped']='deadline_or_output_limit'
    subprocess.run(['podman','stop','--time','2',NAME],env=HOST_ENV,capture_output=True,timeout=20)
    if process.poll() is None:os.killpg(process.pid,signal.SIGTERM)
    break
   time.sleep(.2)
  try:RESULT['exit_code']=process.wait(timeout=10)
  except subprocess.TimeoutExpired:
   os.killpg(process.pid,signal.SIGKILL);RESULT['exit_code']=process.wait()
 isolation=OUTPUT/'isolation-verification.json'
 RESULT['isolation']=json.loads(isolation.read_text()) if isolation.is_file() else None
 xml=OUTPUT/'docs.xml'
 if xml.is_file():
  cases=list(ET.parse(xml).getroot().iter('testcase')); counts={'passed':0,'failed':0,'errors':0,'skipped':0}
  for c in cases:
   key='errors' if c.find('error') is not None else 'failed' if c.find('failure') is not None else 'skipped' if c.find('skipped') is not None else 'passed'
   counts[key]+=1
  RESULT['counts']=counts
 RESULT['status']='passed' if RESULT.get('exit_code')==0 and RESULT.get('counts')=={'passed':6,'failed':0,'errors':0,'skipped':0} and RESULT['isolation'] and RESULT['isolation']['verified'] else 'failed_or_blocked'
except Exception as exc:
 RESULT['status']='blocked'; RESULT['error']=type(exc).__name__+': '+str(exc)
finally:
 if 'command' in RESULT:
  clean=subprocess.run(['podman','rm','--force','--ignore',NAME],env=HOST_ENV,capture_output=True,text=True,timeout=30)
  RESULT['owned_container_cleanup']={'exit_code':clean.returncode,'stderr':clean.stderr}
 RESULT['changed_inputs']=[rel for rel,h in manifest['files'].items() if not (ROOT/rel).is_file() or sha(ROOT/rel)!=h['sha256']]
 RESULT['elapsed_seconds']=round(time.monotonic()-START,3); RESULT['output_bytes']=size()
 RESULT['finished_utc']=datetime.datetime.now(datetime.timezone.utc).isoformat()
 RESULT['staged_inputs']=manifest
 dest=LOCAL/'docs-container-evidence'
 assert not dest.exists(); shutil.copytree(OUTPUT,dest)
 RESULT['evidence_files']={p.relative_to(dest).as_posix():{'sha256':sha(p),'bytes':p.stat().st_size} for p in dest.rglob('*') if p.is_file()}
 save()
 print(json.dumps({k:RESULT.get(k) for k in ('status','exit_code','counts','error','changed_inputs','elapsed_seconds','output_bytes')}))
 sys.exit(0 if RESULT['status']=='passed' and not RESULT['changed_inputs'] else 1)
