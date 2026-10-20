"""Read installed tools and image metadata; never compile, run probes or containers."""
import hashlib
import json
import os
import pathlib
import subprocess
import sys
from datetime import datetime, timezone

OUT = pathlib.Path(__file__).resolve().parent
ROOT = pathlib.Path('/mnt/c/Users/10273/home/work/Z-Scope_1.31/Z-Scope')

def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def run(label, argv):
    result = subprocess.run(argv, capture_output=True, text=True, timeout=40)
    record = {'argv': argv, 'exit_code': result.returncode, 'stdout': result.stdout, 'stderr': result.stderr}
    path = OUT / (label + '.json')
    with path.open('x', encoding='utf-8', newline='\n') as file:
        json.dump(record, file, indent=2)
        file.write('\n')
    return record

assert sys.platform == 'linux'
data = {'at': datetime.now(timezone.utc).isoformat(), 'kernel': os.uname().release, 'machine': os.uname().machine, 'os_release': pathlib.Path('/etc/os-release').read_text(), 'tools': [], 'containers_started': 0, 'TSAN_executions': 0}
paths = [
    '/usr/lib/llvm-18/bin/clang', '/usr/lib/llvm-18/bin/llvm-symbolizer',
    '/usr/bin/x86_64-linux-gnu-gcc-13', '/usr/lib/gcc/x86_64-linux-gnu/13/cc1',
    '/usr/lib/llvm-18/lib/clang/18/lib/linux/libclang_rt.tsan-x86_64.so',
    '/usr/lib/llvm-18/lib/clang/18/lib/linux/libclang_rt.tsan-x86_64.a',
    '/usr/lib/gcc/x86_64-linux-gnu/13/libtsan.so',
]
for index, name in enumerate(paths):
    path = pathlib.Path(name)
    item = {'path': name, 'exists': path.is_file()}
    if path.is_file():
        item.update(resolved=str(path.resolve()), bytes=path.stat().st_size, sha256=sha(path))
        item['elf'] = run('elf-' + str(index), ['readelf', '-h', str(path)])['stdout'][:1800]
        if path.suffix != '.a':
            item['ldd'] = run('ldd-' + str(index), ['ldd', str(path)])
            item['needed'] = run('needed-' + str(index), ['readelf', '-d', str(path)])['stdout']
    data['tools'].append(item)
run('installed-packages', ['dpkg-query', '-W', '-f=${Package}\t${Version}\t${Architecture}\n', 'clang-18', 'llvm-18', 'libllvm18', 'libclang-cpp18', 'libclang-rt-18-dev', 'gcc-13', 'libtsan2', 'libc6', 'libstdc++6', 'podman', 'containers-common'])
images = run('images', ['podman', 'images', '--no-trunc', '--format', 'json'])
data['images'] = []
for index, item in enumerate(json.loads(images['stdout'])):
    inspected = subprocess.run(['podman', 'image', 'inspect', item['Id']], capture_output=True, text=True, timeout=30)
    if inspected.returncode:
        data['images'].append({'id': item['Id'], 'error': inspected.stderr})
        continue
    info = json.loads(inspected.stdout)[0]
    record = {key: info.get(key) for key in ('Id', 'Digest', 'RepoDigests', 'Architecture', 'Os', 'Size', 'Created', 'RootFS', 'GraphDriver')}
    record['names'] = item.get('Names')
    # Read package records directly from immutable layers, without mounting or running.
    dirs = []
    graph = info.get('GraphDriver', {}).get('Data', {})
    if graph.get('UpperDir'):
        dirs.append(graph['UpperDir'])
    dirs.extend(graph.get('LowerDir', '').split(':'))
    record['layer_package_records'] = []
    for directory in dirs:
        if not directory:
            continue
        path = pathlib.Path(directory) / 'var/lib/dpkg/status'
        try:
            if not path.is_file():
                continue
            text = path.read_text(encoding='utf-8')
            wanted = []
            for block in text.split('\n\n'):
                package = next((line.split(': ', 1)[1] for line in block.splitlines() if line.startswith('Package: ')), '')
                if package in ('gcc', 'gcc-13', 'gcc-14', 'libtsan2', 'clang', 'clang-18', 'clang-19', 'clang-22', 'clang-23', 'libc6', 'libstdc++6'):
                    wanted.append({line.split(': ', 1)[0]: line.split(': ', 1)[1] for line in block.splitlines() if line.startswith(('Package: ', 'Version: ', 'Architecture: ', 'Status: '))})
            record['layer_package_records'].append({'path': str(path), 'sha256': sha(path), 'packages': wanted})
        except OSError as exc:
            record['layer_package_records'].append({'path': str(path), 'error': type(exc).__name__ + ': ' + str(exc), 'retried_or_bypassed': False})
    data['images'].append(record)

profile = pathlib.Path('/usr/share/containers/seccomp.json')
if profile.is_file():
    content = json.loads(profile.read_text())
    data['seccomp_profile'] = {'path': str(profile), 'sha256': sha(profile), 'defaultAction': content.get('defaultAction'), 'personality_rules': [item for item in content.get('syscalls', []) if 'personality' in item.get('names', [])]}
else:
    data['seccomp_profile'] = {'path': str(profile), 'exists': False}
data['denied_read_preserved'] = {'path': '/proc/sys/vm/mmap_rnd_bits', 'error': "PermissionError: [Errno 13] Permission denied: '/proc/sys/vm/mmap_rnd_bits'", 'entropy_value': 'unknown', 'alternative_read_or_elevation': False}
data['product_sha256'] = sha(ROOT / 'zscope/core/validation/dynamic_reproduction.py')
with (OUT / 'inventory.json').open('x', encoding='utf-8', newline='\n') as file:
    json.dump(data, file, indent=2)
    file.write('\n')
print(json.dumps({'tools': len(data['tools']), 'images': len(data['images']), 'missing_host_dependencies': [item['path'] for item in data['tools'] if 'not found' in item.get('ldd', {}).get('stdout', '')], 'seccomp_profile': data['seccomp_profile'], 'product_sha256': data['product_sha256'], 'TSAN_executions': 0}))
