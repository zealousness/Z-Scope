"""Create a file manifest and proposed scripts; do not copy tools or run a container."""
import hashlib
import json
import pathlib
import re

HERE = pathlib.Path(__file__).resolve().parent

def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def write(path, text):
    with path.open('x', encoding='utf-8', newline='\n') as file:
        file.write(text)

entries = {}
def add(source, destination):
    source = pathlib.Path(source)
    assert source.is_file(), str(source)
    if destination in entries:
        assert entries[destination]['sha256'] == digest(source)
        return
    entries[destination] = {'source': str(source), 'resolved_source': str(source.resolve()), 'destination': destination, 'bytes': source.stat().st_size, 'sha256': digest(source), 'mode': source.stat().st_mode & 0o777}

for name in ('clang', 'llvm-symbolizer'):
    add('/usr/lib/llvm-18/bin/' + name, 'usr/lib/llvm-18/bin/' + name)
for name in ('libLLVM.so.18.1', 'libclang-cpp.so.18.1'):
    add('/usr/lib/llvm-18/lib/' + name, 'usr/lib/llvm-18/lib/' + name)
resources = pathlib.Path('/usr/lib/llvm-18/lib/clang/18')
for source in resources.rglob('*'):
    if source.is_file():
        add(source, source.relative_to('/').as_posix())

core = {'libc.so.6', 'libm.so.6', 'libstdc++.so.6', 'libgcc_s.so.1', 'libpthread.so.0', 'libdl.so.2', 'librt.so.1'}
for name in ('ldd-0.json', 'ldd-1.json'):
    record = json.loads((HERE / name).read_text())
    assert record['exit_code'] == 0 and 'not found' not in record['stdout']
    for soname, filename in re.findall(r'\s*(\S+)\s+=>\s+(\S+)\s+\(', record['stdout']):
        if soname in core or soname.startswith(('libLLVM', 'libclang-cpp')):
            continue
        assert pathlib.Path(filename).is_absolute()
        add(filename, 'opt/v02-host-libs/' + soname)
manifest = {'role': 'proposed offline tool bundle, not staged or installed', 'compiler_version': 'Ubuntu Clang 18.1.3, package 1:18.1.3-1ubuntu1', 'files': entries, 'file_count': len(entries), 'total_file_bytes': sum(x['bytes'] for x in entries.values()), 'base_core_libraries_not_copied': sorted(core), 'copy_executed': False, 'new_image_built': False}
write(HERE / 'proposed-bundle-manifest.json', json.dumps(manifest, indent=2) + '\n')

stage_script = '''"""PROPOSAL ONLY: stage the approved manifest after explicit implementation approval."""
import hashlib, json, pathlib, shutil, sys
manifest = json.loads(pathlib.Path(sys.argv[1]).read_text())
target = pathlib.Path(sys.argv[2]).resolve()
assert not target.exists(), 'Use a fresh context; do not overwrite old files'
for item in manifest['files'].values():
    source = pathlib.Path(item['source'])
    assert hashlib.sha256(source.read_bytes()).hexdigest() == item['sha256'], str(source)
target.mkdir(parents=True)
for item in manifest['files'].values():
    source = pathlib.Path(item['source'])
    destination = target / 'rootfs' / item['destination']
    assert destination.resolve().is_relative_to(target)
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, destination)
    destination.chmod(item['mode'])
    assert hashlib.sha256(destination.read_bytes()).hexdigest() == item['sha256']
for name in ('clang', 'llvm-symbolizer'):
    wrapper = target / 'rootfs/usr/bin' / name
    wrapper.parent.mkdir(parents=True, exist_ok=True)
    wrapper.write_text('#!/bin/sh\\nexport LD_LIBRARY_PATH=/opt/v02-host-libs:/usr/lib/llvm-18/lib\\nexec /usr/lib/llvm-18/bin/' + name + ' "$@"\\n', encoding='utf-8')
    wrapper.chmod(0o755)
containerfile = pathlib.Path(__file__).with_name('Containerfile.clang18.proposed')
shutil.copyfile(containerfile, target / 'Containerfile')
print(json.dumps({'context':str(target), 'files':manifest['file_count'], 'tool_bytes':manifest['total_file_bytes'], 'image_built':False}))
'''
write(HERE / 'stage_bundle.proposed.py', stage_script)
write(HERE / 'Containerfile.clang18.proposed', 'FROM docker.io/library/python@sha256:de8ba566572ebcb35cbd10e03f5f351cad00a0d0d50a11e084f1a0fd24a0c41a\nCOPY rootfs/ /\n')

# Reuse exactly the approved boundary checks, but make this a single harmless probe.
inside = pathlib.Path('/mnt/c/Users/10273/Documents/Codex/2026-10-10/task-3/v01-v02-current-acceptance-20261010/current-asan-inside.py').read_text()
prefix = inside[:inside.index('import pytest')]
prefix = prefix[:prefix.index('NAMES = [')] + prefix[prefix.index('def save'):]
prefix = '"""PROPOSAL ONLY: verify the original boundary, then run one harmless TSAN probe."""\n' + prefix[prefix.index('import hashlib'):]
probe = prefix + '''
# PROPOSAL ONLY; do not run before environment/probe approval. No thread fixture.
source = pathlib.Path('/tmp/v02-compat-main.c')
binary = pathlib.Path('/tmp/v02-compat-main')
source.write_text('int main(void){return 0;}\\n', encoding='utf-8')
argv = ['/usr/bin/clang','-fsanitize=thread','-g','-O0','-pthread','-o',str(binary),str(source)]
built = subprocess.run(argv,capture_output=True,timeout=180,check=False)
save('compat-build.json',{'argv':argv,'exit_code':built.returncode,'stdout':built.stdout.decode('utf-8','replace'),'stderr':built.stderr.decode('utf-8','replace')})
if built.returncode:
    sys.exit(81)
ran = subprocess.run([str(binary)],capture_output=True,timeout=30,check=False)
save('compat-probe.json',{'argv':[str(binary)],'binary_sha256':hash_bytes(binary.read_bytes()),'exit_code':ran.returncode,'stdout':ran.stdout.decode('utf-8','replace'),'stderr':ran.stderr.decode('utf-8','replace'),'probe_count':1,'thread_fixture_executions':0})
sys.exit(0 if ran.returncode==0 else 82)
'''
write(HERE / 'compat-probe.proposed.py', probe)

portable = pathlib.Path('/home/zeal/.cache/zscope-portable/x86_64/prefix/llvm18/bin/clang')
extra = {'portable_clang': {'path':str(portable),'exists':portable.is_file(),'sha256':digest(portable) if portable.is_file() else None}, 'portable_tsan_runtime_matches': [str(path) for path in pathlib.Path('/home/zeal/.cache/zscope-portable/x86_64/prefix').glob('*/lib/clang/*/lib/*/*tsan*')], 'gcc_cc1_actual_path':'/usr/libexec/gcc/x86_64-linux-gnu/13/cc1', 'rg_unavailable':"FileNotFoundError: [Errno 2] No such file or directory: 'rg'", 'fallback_search':'targeted pathlib glob; no installation'}
write(HERE / 'additional-paths.json', json.dumps(extra, indent=2)+'\n')
print(json.dumps({'proposed_bundle_files':manifest['file_count'],'proposed_bundle_bytes':manifest['total_file_bytes'],'proposed_scripts_only':True,'new_container_or_probe':False}))
