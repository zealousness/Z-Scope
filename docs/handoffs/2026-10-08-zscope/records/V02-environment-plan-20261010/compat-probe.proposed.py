"""PROPOSAL ONLY: verify the original boundary, then run one harmless TSAN probe."""
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

if 'clang version 18.1.3' not in version.stdout:
    save('version-rejected.json', {'expected': 'clang version 18.1.3', 'actual': version.stdout})
    sys.exit(81)
expected_tools = {
    '/usr/lib/llvm-18/bin/clang': '8ef402d453d1ba4902e4ee0f0f847f6cfa01400c95aa43c24e97818b9c0e3f45',
    '/usr/lib/llvm-18/bin/llvm-symbolizer': '1f93f7c4930615a121903afa61c0544b99f3e1da18d7ed4fb9fb3a2056924dd1',
    '/usr/lib/llvm-18/lib/clang/18/lib/linux/libclang_rt.tsan-x86_64.a': '2252b875dd1f3bdcf67417a43497f8b0e418b9218e33031bf332c63f679917d4',
    '/usr/lib/llvm-18/lib/clang/18/lib/linux/libclang_rt.tsan-x86_64.so': 'dfb5ab5d511f84a08fbb380b04b2d3d30db69ee8817c427e73c131ff7e7c596b',
}
for name, expected in expected_tools.items():
    assert hash_bytes(pathlib.Path(name).read_bytes()) == expected, name
for name in ('/usr/lib/llvm-18/bin/clang', '/usr/lib/llvm-18/lib/clang/18/lib/linux/libclang_rt.tsan-x86_64.so'):
    metadata_env = dict(os.environ, LD_LIBRARY_PATH='/opt/v02-host-libs:/usr/lib/llvm-18/lib')
    deps = subprocess.run(['ldd', name], capture_output=True, text=True, timeout=15, env=metadata_env)
    save('ldd-' + pathlib.Path(name).name + '.json', {'argv': ['ldd', name], 'library_path': metadata_env['LD_LIBRARY_PATH'], 'exit_code': deps.returncode, 'stdout': deps.stdout, 'stderr': deps.stderr})
    if deps.returncode or 'not found' in deps.stdout:
        sys.exit(81)


# PROPOSAL ONLY; do not run before environment/probe approval. No thread fixture.
source = pathlib.Path('/tmp/v02-compat-main.c')
binary = pathlib.Path('/tmp/v02-compat-main')
source.write_text('int main(void){return 0;}\n', encoding='utf-8')
argv = ['/usr/bin/clang','-fsanitize=thread','-g','-O0','-pthread','-o',str(binary),str(source)]
built = subprocess.run(argv,capture_output=True,timeout=180,check=False)
save('compat-build.json',{'argv':argv,'exit_code':built.returncode,'stdout':built.stdout.decode('utf-8','replace'),'stderr':built.stderr.decode('utf-8','replace')})
if built.returncode:
    sys.exit(81)
ran = subprocess.run([str(binary)],capture_output=True,timeout=30,check=False)
save('compat-probe.json',{'argv':[str(binary)],'binary_sha256':hash_bytes(binary.read_bytes()),'exit_code':ran.returncode,'stdout':ran.stdout.decode('utf-8','replace'),'stderr':ran.stderr.decode('utf-8','replace'),'probe_count':1,'thread_fixture_executions':0})
sys.exit(0 if ran.returncode==0 else 82)
