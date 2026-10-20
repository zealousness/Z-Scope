"""Source-bound syntax check only; admitted modules remain stage-only."""
from pathlib import Path
import datetime as dt
import hashlib,json,os,subprocess,sys,uuid
from root_runtime_preflight_r23 import inspect_root_runtime
if sys.flags.optimize or os.environ.get('PYTHONOPTIMIZE'):
    raise RuntimeError('Optimized Python cannot run verification guards')
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[4]
STAGE=ROOT/'.coordination/20261014/workspaces/coordinator-instance-integration-r24'
if Path.cwd().resolve()!=STAGE.resolve():raise RuntimeError('Wrong outer slot workspace')
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def read(p):return json.loads(p.read_text(encoding='utf-8'))
def snapshot():
    return {p.relative_to(STAGE).as_posix():sha(p) for name in ('zscope','scripts','test','tests') for p in (STAGE/name).rglob('*') if p.is_file() and '__pycache__' not in p.parts and p.suffix!='.pyc'}
runtime=inspect_root_runtime(require_slot=True)
root_hashes=read(ROOT/'artifacts/coordinator-r23-ui-projection-union-20261016/source-evidence.json')['after']
if not all(sha(ROOT/p)==h for p,h in root_hashes.items()):raise RuntimeError('Root drift')
before=snapshot();out=ROOT/'artifacts'/('coordinator-syntax-r24-'+uuid.uuid4().hex[:12]);out.mkdir()
start=dt.datetime.now(dt.timezone.utc).isoformat()
command=[sys.executable,'-m','compileall','-f','-q','zscope','scripts','test','tests']
with (out/'compileall.log').open('w',encoding='utf-8') as stream:
    result=subprocess.run(command,cwd=STAGE,stdout=stream,stderr=subprocess.STDOUT)
after=snapshot();root_unchanged=all(sha(ROOT/p)==h for p,h in root_hashes.items())
proof=dict(actual_task='/root',logical_task='COORD-INSTANCE-INTEGRATION-R24',started_at=start,finished_at=dt.datetime.now(dt.timezone.utc).isoformat(),command=command,returncode=result.returncode,source_before=before,source_after=after,source_unchanged=before==after,root_unchanged=root_unchanged,runtime_preflight=runtime,tests_executed=0,quality_scope='Preliminary syntax only; S01 and full functional consumer checks pending',worker_candidates_copied=True,admitted_worker_scope='S08 MIN codec only, stage-only; S01 absent',independent_acceptance=False,integrated=False,joint_verification=False)
(out/'review.json').write_text(json.dumps(proof,ensure_ascii=False,indent=2)+'\n',encoding='utf-8',newline='\n')
print(json.dumps(dict(receipt=(out/'review.json').relative_to(ROOT).as_posix(),returncode=result.returncode,source_unchanged=before==after,root_unchanged=root_unchanged,tests_executed=0)),flush=True)
sys.exit(0 if result.returncode==0 and before==after and root_unchanged else 1)
