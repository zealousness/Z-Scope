"""Prepared container entry point. Execute only after the additional inputs are approved."""
import hashlib
import json
import os
import pathlib
import shutil
import subprocess
import sys
import time
import xml.etree.ElementTree as ET
from fractions import Fraction

CONTROL = pathlib.Path('/control')
OUTPUT = pathlib.Path('/work')
REPO = pathlib.Path('/repo')
TOOLS = pathlib.Path('/java-inputs')
DEPS = pathlib.Path('/venv/lib/python3.13/site-packages')
LIMIT = 8 * 1024 * 1024
NODES = [
    'tests/test_java_source_backend.py::test_spoon_structure_frontend_lombok_processor_real_cli_contract',
    'tests/test_java_source_backend.py::test_javaparser_structure_frontend_real_cli_contract',
]
sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()


def output_size():
    return sum(p.stat().st_size for p in OUTPUT.rglob('*') if p.is_file())


def save(name, value):
    raw = (json.dumps(value, indent=2) + '\n').encode()
    assert output_size() + len(raw) < LIMIT - 65536, 'Evidence budget exhausted'
    (OUTPUT / name).write_bytes(raw)


mounts = {}
for line in pathlib.Path('/proc/self/mountinfo').read_text().splitlines():
    fields = line.split()
    sep = fields.index('-')
    mounts[fields[4]] = {'options': fields[5].split(','), 'type': fields[sep + 1],
                         'super_options': fields[sep + 3].split(',')}
status = dict(x.split(':', 1) for x in pathlib.Path('/proc/self/status').read_text().splitlines() if ':' in x)
limits = {n: pathlib.Path('/sys/fs/cgroup', n).read_text().strip() for n in ('memory.max', 'pids.max', 'cpu.max')}
quota, period = limits['cpu.max'].split()
tmp = os.statvfs('/tmp')
checks = {
    'nonroot': os.getuid() == os.getgid() == 1000,
    'readonly_root': 'ro' in mounts['/']['options'],
    'readonly_inputs': all('ro' in mounts[p]['options'] for p in ('/repo', '/java-inputs', '/control', str(DEPS))),
    'owned_output_writable': 'rw' in mounts['/work']['options'],
    'tmpfs_512MiB': mounts['/tmp']['type'] == 'tmpfs' and tmp.f_blocks * tmp.f_frsize == 536870912,
    'tmpfs_executable': 'noexec' not in mounts['/tmp']['options'],
    'network_none': sorted(p.name for p in pathlib.Path('/sys/class/net').iterdir()) == ['lo'] and not pathlib.Path('/proc/net/route').read_text().splitlines()[1:],
    'no_new_privileges': status['NoNewPrivs'].strip() == '1',
    'all_capabilities_dropped': all(int(status[n].strip(), 16) == 0 for n in ('CapEff', 'CapPrm', 'CapBnd')),
    'seccomp_filter': status['Seccomp'].strip() == '2',
    'memory_2GiB': limits['memory.max'] == '2147483648',
    'pids_256': limits['pids.max'] == '256',
    'cpu_2': quota != 'max' and Fraction(int(quota), int(period)) == 2,
    'aslr_original': pathlib.Path('/proc/sys/kernel/randomize_va_space').read_text().strip() == '2' and int(pathlib.Path('/proc/self/personality').read_text().strip(), 16) == 0,
}
save('isolation.json', {'verified': all(checks.values()), 'checks': checks, 'limits': limits, 'mounts': mounts})
assert all(checks.values()), 'Isolation mismatch; no Java/Maven started'
manifest = json.loads((CONTROL / 'input-manifest.json').read_text())
for entry in manifest['files']:
    p = TOOLS / entry['destination']
    assert not p.is_symlink() and sha(p) == entry['sha256'], entry['destination']
for entry in manifest['project_files']:
    assert sha(REPO / entry['destination']) == entry['sha256'], entry['destination']
deps = json.loads((CONTROL / 'python-dependencies.json').read_text())
for entry in deps['files']:
    assert sha(DEPS / entry['relative']) == entry['sha256'], entry['relative']
for entry in json.loads((CONTROL / 'control-manifest.json').read_text())['generated_files']:
    p = pathlib.Path(entry['container_path'])
    assert sha(p) == entry['sha256'], str(p)
assert shutil.which('java') == '/java-inputs/jdk/bin/java'
assert shutil.which('mvn') == '/java-inputs/maven/bin/mvn'
home = pathlib.Path('/tmp/worker-home')
(home / '.m2').mkdir(parents=True)
(home / '.m2/settings.xml').symlink_to('/control/settings.xml')
(home / '.m2/repository').symlink_to('/java-inputs/cache')
pathlib.Path('/tmp/java').mkdir()
for name in ('spoon', 'javaparser'):
    target = pathlib.Path('/tmp/java-targets') / name
    target.mkdir(parents=True)
    source_link = REPO / ('tools/java-structure-' + name) / 'target'
    assert source_link.is_symlink() and str(source_link.readlink()) == str(target)
save('execution-inputs.json', {'image_id': manifest['image_id'], 'nodes': NODES,
     'JAVA_HOME': os.environ['JAVA_HOME'], 'MAVEN_HOME': os.environ['MAVEN_HOME'],
     'PATH': os.environ['PATH'], 'JAVA_TOOL_OPTIONS': os.environ['JAVA_TOOL_OPTIONS'],
     'MAVEN_OPTS': os.environ['MAVEN_OPTS'], 'settings_sha256': sha(CONTROL / 'settings.xml'),
     'cache': '/java-inputs/cache', 'target_outputs': '/tmp/java-targets',
     'source_inputs_verified': True, 'python': sys.version})

original_run = subprocess.run
calls = []
audit_error = []


def audited_run(*args, **kwargs):
    command = args[0] if args else kwargs.get('args')
    tracked = isinstance(command, (list, tuple)) and command and pathlib.Path(str(command[0])).name in ('java', 'mvn')
    if not tracked:
        return original_run(*args, **kwargs)
    assert not audit_error and output_size() < LIMIT - 262144, 'Output budget exhausted; do not launch next command'
    event = {'command': [str(x) for x in command], 'cwd': str(kwargs.get('cwd', REPO)), 'started_monotonic': time.monotonic()}
    if '-jar' in command:
        jar = pathlib.Path(command[command.index('-jar') + 1])
        event['jar_before_execution'] = {'path': str(jar), 'sha256': sha(jar), 'bytes': jar.stat().st_size}
    index = len(calls)
    try:
        result = original_run(*args, **kwargs)
        event['exit_code'] = result.returncode
        streams = {'stdout': result.stdout, 'stderr': result.stderr}
        return result
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as error:
        event['exception'] = type(error).__name__
        event['exit_code'] = getattr(error, 'returncode', None)
        streams = {'stdout': error.stdout, 'stderr': error.stderr}
        raise
    finally:
        for label, value in locals().get('streams', {}).items():
            raw = value.encode() if isinstance(value, str) else value or b''
            available = max(0, LIMIT - output_size() - 262144)
            if len(raw) > available:
                audit_error.append('Output budget exhausted; stream truncated; acceptance fails')
                raw = raw[:available]
            filename = 'command-' + str(index) + '.' + label + '.log'
            (OUTPUT / filename).write_bytes(raw)
            event[label] = {'path': filename, 'sha256': hashlib.sha256(raw).hexdigest(), 'bytes': len(raw)}
        event['elapsed_seconds'] = round(time.monotonic() - event['started_monotonic'], 3)
        calls.append(event)
        save('subprocess-audit.json', {'calls': calls, 'errors': audit_error})


import pytest
subprocess.run = audited_run
started = time.monotonic()
code = pytest.main(['-q', '-x', '-p', 'no:cacheprovider', '--tb=short', '--basetemp=/tmp/pytest-java', '--junitxml=/work/two-nodes.xml', *NODES])
subprocess.run = original_run
counts = {'passed': 0, 'failed': 0, 'errors': 0, 'skipped': 0}
xml = OUTPUT / 'two-nodes.xml'
if xml.is_file():
    for case in ET.parse(xml).getroot().iter('testcase'):
        key = 'errors' if case.find('error') is not None else 'failed' if case.find('failure') is not None else 'skipped' if case.find('skipped') is not None else 'passed'
        counts[key] += 1
jars = []
for jar in pathlib.Path('/tmp/java-targets').rglob('*.jar'):
    jars.append({'path': str(jar), 'bytes': jar.stat().st_size, 'sha256': sha(jar)})
good = code == 0 and counts == {'passed': 2, 'failed': 0, 'errors': 0, 'skipped': 0} and not audit_error
save('two-nodes-result.json', {'status': 'passed' if good else 'failed_or_blocked', 'pytest_exit_code': code,
     'counts': counts, 'audit_errors': audit_error, 'generated_jars': jars,
     'elapsed_seconds': round(time.monotonic() - started, 3), 'old_results_not_reexecuted': True})
sys.exit(0 if good else 1)
