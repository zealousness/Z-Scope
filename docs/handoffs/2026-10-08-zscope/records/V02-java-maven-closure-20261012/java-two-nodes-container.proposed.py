"""Reviewed draft only. A flag is not authorization; obtain approval of its sealed identity first."""
import argparse
import hashlib
import json
import os
import pathlib
import shutil
import signal
import subprocess
import sys
import time
from datetime import datetime, timezone

PREP = pathlib.Path(__file__).resolve().parent
WORK = pathlib.Path('/home/zeal/.cache/zscope-common-java-20261012')
NAME = 'zscope-common-java-20261012-two-nodes'
IMAGE = '60e3b821beb946564925285acdc7c87b55bcdf587f4e3006321728dce2900fff'
DEFAULT_PROFILE_SHA = 'cc374cf23846ce1f62f4dc807a8e2b8673c783c6f56cb475467621035d281e6c'
sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--approved-java-maven-inputs-20261012', action='store_true', required=True)
    parser.add_argument('--prepared-manifest-sha256', required=True)
    args = parser.parse_args()
    identity = PREP / 'prepared-artifact-manifest.json'
    assert sha(identity) == args.prepared_manifest_sha256
    sealed = json.loads(identity.read_text())
    for rel, info in sealed['files'].items():
        assert sha(PREP / rel) == info['sha256'], rel
    manifest = json.loads((PREP / 'input-manifest.json').read_text())
    deps = json.loads((PREP / 'python-dependencies.json').read_text())
    control_plan = json.loads((PREP / 'control-manifest.json').read_text())
    budget = manifest['budget']
    assert manifest['image_id'] == IMAGE and os.getuid() == os.getgid() == 1000
    assert WORK.parent.resolve() == pathlib.Path('/home/zeal/.cache') and not WORK.exists()
    assert not (PREP / 'java-two-nodes.claimed.json').exists()
    assert not (PREP / 'java-two-nodes-result.json').exists()
    assert not (PREP / 'java-two-nodes-evidence').exists()
    host_env = {k: os.environ[k] for k in ('PATH', 'HOME', 'USER', 'LOGNAME', 'XDG_RUNTIME_DIR', 'DBUS_SESSION_BUS_ADDRESS', 'LANG', 'LC_ALL', 'TZ') if k in os.environ}
    def host_run(command, **kwargs):
        return subprocess.run(command, env=host_env, capture_output=True, text=True, timeout=30, **kwargs)
    assert host_run(['podman', 'container', 'exists', NAME]).returncode == 1, 'Do not touch an existing same-name container'
    image = json.loads(host_run(['podman', 'image', 'inspect', IMAGE], check=True).stdout)[0]
    assert image['Id'].removeprefix('sha256:') == IMAGE
    assert sha(pathlib.Path('/usr/share/containers/seccomp.json')) == DEFAULT_PROFILE_SHA
    assert pathlib.Path('/proc/sys/kernel/randomize_va_space').read_text().strip() == '2'
    assert int(pathlib.Path('/proc/self/personality').read_text().strip(), 16) == 0
    with (PREP / 'java-two-nodes.claimed.json').open('x') as file:
        json.dump({'work': str(WORK), 'container_name': NAME, 'image_id': IMAGE, 'prepared_manifest_sha256': args.prepared_manifest_sha256}, file)
    started = time.monotonic()
    result = {'status': 'preparing', 'started_utc': datetime.now(timezone.utc).isoformat(), 'image_id': IMAGE,
              'prepared_manifest_sha256': args.prepared_manifest_sha256, 'work': str(WORK), 'container_name': NAME,
              'budget': budget, 'seccomp': 'default', 'old_tests_probes_and_models_not_reexecuted': True}
    started_container = False
    output = WORK / 'evidence'

    def persist():
        (PREP / 'java-two-nodes-result.json').write_text(json.dumps(result, indent=2) + '\n')

    def file_bytes(root):
        return sum(p.stat().st_size for p in root.rglob('*') if p.is_file()) if root.exists() else 0

    def allocated(root):
        return sum(p.lstat().st_blocks * 512 for p in root.rglob('*')) if root.exists() else 0

    def check_budget():
        assert time.monotonic() - started < 900, '900s whole-attempt deadline'
        assert file_bytes(output) <= budget['evidence_output_max_bytes'], '8MiB evidence limit'
        assert file_bytes(WORK) <= budget['host_regular_file_content_max_bytes'], 'Regular-file content budget'
        assert allocated(WORK) <= budget['host_owned_allocated_blocks_stop_threshold_bytes'], '640MiB observed allocated-block threshold'

    try:
        WORK.mkdir()
        bundle = WORK / 'tool-inputs'
        repo = WORK / 'project'
        control = WORK / 'control'
        for p in (bundle, repo, control, output):
            p.mkdir()
        assert shutil.disk_usage(WORK).free >= budget['host_owned_allocated_blocks_stop_threshold_bytes']
        for link in manifest['symlink_normalization']:
            p = pathlib.Path(link['source'])
            assert p.is_symlink() and str(p.readlink()) == link['link_text'], link['source']
            actual = str(p.resolve(strict=True)) if p.exists() else None
            assert actual == link['resolved'], link['source']
        copied = 0
        for index, entry in enumerate(manifest['files'], 1):
            physical = pathlib.Path(entry['physical_source'])
            logical = pathlib.Path(entry['logical_source'])
            assert str(logical.resolve(strict=True)) == str(physical)
            assert sha(physical) == entry['sha256'] and physical.stat().st_size == entry['bytes']
            rel = pathlib.PurePosixPath(entry['destination'])
            assert not rel.is_absolute() and '..' not in rel.parts
            target = bundle / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(physical, target)
            target.chmod(entry['mode'])
            assert sha(target) == entry['sha256']
            copied += entry['bytes']
            assert copied <= budget['normalized_tool_cache_copy_bytes']
            if index % 256 == 0:
                check_budget()
        assert copied == budget['normalized_tool_cache_copy_bytes']
        copied_project = 0
        for entry in manifest['project_files']:
            source = pathlib.Path(entry['source'])
            assert sha(source) == entry['sha256']
            target = repo / entry['destination']
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, target)
            target.chmod(0o444)
            copied_project += entry['bytes']
        assert copied_project == budget['project_snapshot_copy_bytes']
        for entry in deps['files']:
            assert sha(pathlib.Path(deps['root']) / entry['relative']) == entry['sha256']
        for name in ('spoon', 'javaparser'):
            (repo / ('tools/java-structure-' + name) / 'target').symlink_to('/tmp/java-targets/' + name)
        control_copied = 0
        for entry in control_plan['copies']:
            source = PREP / entry['source']
            assert sha(source) == entry['sha256']
            base = bundle if entry['area'] == 'bundle' else control
            target = base / entry['destination']
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, target)
            target.chmod(entry['mode'])
            control_copied += source.stat().st_size
        shutil.copyfile(PREP / 'control-manifest.json', control / 'control-manifest.json')
        (control / 'control-manifest.json').chmod(0o444)
        control_copied += (PREP / 'control-manifest.json').stat().st_size
        assert control_copied <= budget['control_files_max_bytes']
        check_budget()
        result['actual_copy_bytes'] = {'normalized_tools_cache': copied, 'project': copied_project, 'control': control_copied}
        command = ['podman', 'run', '--rm', '--name', NAME, '--pull=never', '--network=none', '--read-only',
                   '--userns=keep-id', '--user', '1000:1000', '--cap-drop=all', '--security-opt=no-new-privileges',
                   '--pids-limit=256', '--memory=2g', '--cpus=2', '--tmpfs', '/tmp:rw,size=512m,exec',
                   '-v', str(bundle) + ':/java-inputs:ro', '-v', str(repo) + ':/repo:ro',
                   '-v', str(control) + ':/control:ro', '-v', deps['root'] + ':/venv/lib/python3.13/site-packages:ro',
                   '-v', str(output) + ':/work:rw',
                   '-e', 'PATH=/java-inputs/maven/bin:/java-inputs/jdk/bin:/usr/local/bin:/usr/bin:/bin',
                   '-e', 'JAVA_HOME=/java-inputs/jdk', '-e', 'MAVEN_HOME=/java-inputs/maven', '-e', 'M2_HOME=/java-inputs/maven',
                   '-e', 'MAVEN_SKIP_RC=1', '-e', 'MAVEN_CONFIG=', '-e', 'MAVEN_ARGS=',
                   '-e', 'JAVA_TOOL_OPTIONS=-Xms32m -Xmx512m -XX:MaxMetaspaceSize=256m -Djava.io.tmpdir=/tmp/java -Duser.home=/tmp/worker-home',
                   '-e', 'MAVEN_OPTS=-Xms32m -Xmx512m -XX:MaxMetaspaceSize=256m -Djansi.mode=strip -Djansi.passthrough=true',
                   '-e', 'HOME=/tmp/worker-home', '-e', 'TMPDIR=/tmp', '-e', 'TZ=UTC',
                   '-e', 'PYTHONPATH=/repo:/venv/lib/python3.13/site-packages', '-e', 'PYTHONDONTWRITEBYTECODE=1',
                   '-e', 'PYTEST_DISABLE_PLUGIN_AUTOLOAD=1', '-e', 'PYTHONPYCACHEPREFIX=/tmp/python-cache',
                   '-w', '/repo', IMAGE, '/usr/local/bin/python', '/control/java-two-nodes-inside.proposed.py']
        result['command'] = command
        result['status'] = 'running'
        persist()
        started_container = True
        with (output / 'container.stdout.log').open('wb') as stdout, (output / 'container.stderr.log').open('wb') as stderr:
            process = subprocess.Popen(command, env=host_env, stdout=stdout, stderr=stderr, start_new_session=True)
            try:
                while process.poll() is None:
                    check_budget()
                    assert time.monotonic() - started < 860, 'Reserve 40 seconds for cleanup/final hashing within 900s'
                    time.sleep(0.2)
                result['exit_code'] = process.wait(timeout=5)
            except BaseException:
                host_run(['podman', 'stop', '--time', '2', NAME])
                if process.poll() is None:
                    os.killpg(process.pid, signal.SIGTERM)
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    os.killpg(process.pid, signal.SIGKILL)
                    process.wait()
                raise
        check_budget()
        receipt = output / 'two-nodes-result.json'
        result['two_nodes'] = json.loads(receipt.read_text()) if receipt.is_file() else None
        result['status'] = 'two_nodes_passed_pending_independent_review' if result['exit_code'] == 0 and result['two_nodes'] and result['two_nodes']['status'] == 'passed' else 'failed_or_blocked'
    except Exception as error:
        result['status'] = 'failed_or_blocked'
        result['error'] = type(error).__name__ + ': ' + str(error)
    finally:
        if started_container:
            cleanup = host_run(['podman', 'rm', '--force', '--ignore', NAME])
            result['owned_container_cleanup'] = {'exit_code': cleanup.returncode, 'stderr': cleanup.stderr}
            if cleanup.returncode:
                result['status'] = 'failed_or_blocked'
        result['host_aslr_after'] = pathlib.Path('/proc/sys/kernel/randomize_va_space').read_text().strip()
        result['default_seccomp_unchanged'] = sha(pathlib.Path('/usr/share/containers/seccomp.json')) == DEFAULT_PROFILE_SHA
        result['source_drift'] = [e['logical_source'] for e in manifest['files'] if sha(pathlib.Path(e['physical_source'])) != e['sha256']]
        result['project_drift'] = [e['source'] for e in manifest['project_files'] if sha(pathlib.Path(e['source'])) != e['sha256']]
        result['python_dependency_drift'] = [e['relative'] for e in deps['files'] if sha(pathlib.Path(deps['root']) / e['relative']) != e['sha256']]
        if result['source_drift'] or result['project_drift'] or result['python_dependency_drift'] or result['host_aslr_after'] != '2' or not result['default_seccomp_unchanged']:
            result['status'] = 'failed_or_blocked'
        result['elapsed_seconds'] = round(time.monotonic() - started, 3)
        result['evidence_bytes'] = file_bytes(output)
        result['owned_work_allocated_bytes'] = allocated(WORK)
        if result['elapsed_seconds'] >= 900 or result['evidence_bytes'] > budget['evidence_output_max_bytes']:
            result['status'] = 'failed_or_blocked'
        if output.exists() and file_bytes(output) <= budget['archive_max_bytes']:
            shutil.copytree(output, PREP / 'java-two-nodes-evidence')
        result['owned_work_preserved_for_review'] = True
        persist()
        print(json.dumps({k: result.get(k) for k in ('status', 'error', 'exit_code', 'elapsed_seconds', 'evidence_bytes', 'owned_container_cleanup')}))
    return 0 if result['status'] == 'two_nodes_passed_pending_independent_review' else 1


if __name__ == '__main__':
    sys.exit(main())
