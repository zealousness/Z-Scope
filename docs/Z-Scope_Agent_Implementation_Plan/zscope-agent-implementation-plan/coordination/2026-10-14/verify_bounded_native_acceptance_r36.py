"""Artifact-only concrete-build draft. Ready/actual collection remain required.

Four native-repair test groups and six quality commands only. This result is
never the full independent, Stage, Root, or joint acceptance result. Pure guard
patterns were copied from fixed sources documented in REUSE.json; no old
launcher is imported or has its globals changed. JSON never supplies commands.
"""
from __future__ import annotations

from collections import Counter
import ast
import datetime as dt
import fcntl
import hashlib
import importlib
import json
import os
from pathlib import Path
import pwd
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET

ROOT = Path('/mnt/c/Users/10273/home/work/Z-Scope_1.31/Z-Scope')
D = ROOT / 'docs/Z-Scope_Agent_Implementation_Plan/zscope-agent-implementation-plan/coordination/2026-10-14'
WORK = ROOT / '.coordination/20261014/workspaces/coordinator-bounded-native-acceptance-r36'
STAGE = ROOT / '.coordination/20261014/workspaces/coordinator-instance-integration-r24'
PRODUCER = ROOT / '.coordination/20261014/workspaces/job-runtime-footprint-repair-r34'
OWN = PRODUCER / 'artifacts/job_runtime_footprint_r34'
CANDIDATE = OWN / 'candidate-src-v2'
BASE = ROOT / 'artifacts/coordinator-bounded-native-acceptance-r36-20261019'
READY = BASE / 'ready.json'
OUT = BASE / 'independent'
INSTALLED = D / 'verify_bounded_native_acceptance_r36.py'
SHELL = D / 'verify_bounded_native_acceptance_r36.sh'
PYTHON = '/home/zeal/venv313/bin/python'
NEW_TOOL = Path('/home/zeal/.cache/zscope-job-runtime-footprint-r36-final-native-v1/install/bin/zscope-clang-indexer')
OLD_TOOL = Path('/home/zeal/.cache/zscope-build-context/install/bin/zscope-clang-indexer')
F4_TOOL = Path('/home/zeal/.cache/zscope-job-runtime-footprint-r34/install/bin/zscope-clang-indexer')
OLD_SHA = 'd39cbe72fafad1fbfa989a51346cdf4785101e32855c0ee0d11a1e2748263399'
F4_SHA = 'f4e2ff8aef71027447afe497b4c8872a4b2bc2f596166ff543492a623fdda860'

# Immutable real v9 build pins. JSON cannot override any of these. These pins
# prove a build only: no test/collector, source review of this runner or ready
# is claimed by their presence. Prior failed v7/v8 evidence stays historical.
FINAL_NATIVE_SHA = '2f71ea9417c9d3d06a2a57d113b1414e7400bc4cefb77b87b578039df6238fe9'
SUCCESSFUL_BUILD_RECEIPT = str(OWN / 'native-build-r36-v9/receipt.json')
SUCCESSFUL_BUILD_RECEIPT_SHA = '6e05586999c536da82ef1c7e4fa4613afc6d83637d861a4eab6e399396d2f84d'
SUCCESSFUL_BUILD_LAUNCHER = str(OWN / 'build-native-r36-v9.py')
SUCCESSFUL_BUILD_LAUNCHER_SHA = '8c9ffe2c5542a60c848ee8d1d3e1cafa5245d1122561f537ac727a81527e6978'
SUCCESSFUL_BUILD_SHELL = str(OWN / 'build-native-r36-v9.sh')
SUCCESSFUL_BUILD_SHELL_SHA = 'd3a96afddb68dd3a4df4a1bd9fb9e895529696712a762b689d2fce9b26d0601b'
SUCCESSFUL_BUILD_REVIEW = str(ROOT / 'artifacts/native-builder-env-independent-review-r36-20261019/revision-9/review.json')
SUCCESSFUL_BUILD_REVIEW_SHA = 'e6f9d4e66ace98df78790879c077c6d7aee5321fbb706c11cfc84ba5715a7c04'
SUCCESSFUL_BUILD_PHASE = 'native-build-r36-v9'
SUCCESSFUL_BUILD_ACTOR = '/root/job_producer_resume_r36'
SUCCESSFUL_BUILD_FREEZE = OWN / 'native-build-r36-v9-freeze.json'
SUCCESSFUL_BUILD_FREEZE_SHA = '90fd150cd1daaca94099c520c39411d3a087ff5ec84bcafed3f7c214201e339c'
ROOT_BUILD_MATERIALS = ROOT / 'artifacts/coordinator-resume-r36-20261019/native-build-v9-result-review-v2.json'
ROOT_BUILD_MATERIALS_SHA = '556f369a134a543edca5f12f7a82f10cc53ef47a5a049ac4266733a5c8272650'
ROOT_ELF_REVIEW = ROOT / 'artifacts/coordinator-resume-r36-20261019/native-install-elf-review.json'
ROOT_ELF_REVIEW_SHA = 'db3fe6d83df5328ecc82108bb0a34cb9f4228d51e329daca8a544390d8ce6821'
ROOT_PREPARATION = BASE / 'preparation/receipt.json'
ROOT_PREPARATION_SHA = '75d1f129e0f98262bccaa8ff93eb80cf6c0fc825f1b33da919954abc157718f2'
ENV_PROLOGUE = OWN / 'native-build-env-r36-v9.sh'
ENV_PROLOGUE_SHA = '969cddf552a7180eebf115f35a0351c55a7c902750800af686e359e64ce1b266'
CANONICAL_PATH = '/home/zeal/venv313/bin:/home/zeal/go/bin:/usr/lib/llvm-18/bin:/home/zeal/.local/svf/SVF-linux-x86_64/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/usr/lib/wsl/lib'
CANONICAL_LD_LIBRARY_PATH = '/home/zeal/.local/svf/SVF-linux-x86_64/lib:/home/zeal/.local/svf/llvm-18.1.0.obj/lib:'
BUILD_ENV_KEYS = ('PATH', 'CC', 'CXX', 'CFLAGS', 'CXXFLAGS', 'CPPFLAGS', 'LDFLAGS',
    'CMAKE_PREFIX_PATH', 'CMAKE_TOOLCHAIN_FILE', 'CMAKE_GENERATOR', 'MAKEFLAGS',
    'LD_LIBRARY_PATH', 'LIBRARY_PATH', 'CPATH', 'C_INCLUDE_PATH', 'CPLUS_INCLUDE_PATH')

ACTUAL_TASK = '/root'
RESULT_SCHEMA = 'zscope.coordinator-bounded-native-acceptance.r36.v1'
GROUPS = ('original53', 'prewrite7', 'legal_backup1', 'native14')
ORIGINAL = 'tests/test_job_runtime_footprint_r34.py'
PREWRITE = 'tests/test_job_runtime_prewrite_r35.py'
ORIGINAL_SHA = 'ac34d7a64e0998e052780fc1f23283875781fc784d2c1141b52e3b827cc09b57'
PREWRITE_SHA = '74cd68ba5a5c45afa25c2c3d48695c2c3f56b7252664ffc51f9060304f45c054'
JOB_NAME = 'test_job_scan_runs_exact_instances_on_the_queue'
JOB_ID = ('tests.test_scan_session_jobs', JOB_NAME)
LEGAL_FIXTURES = ('test_job_runtime_footprint_r34', 'test_job_runtime_prewrite_r35',
                  'test_scan_session_instances', 'test_scan_session_jobs')
EXTERNALS = {
    'legal': (OWN / 'extra-regressions-r35/test_job_runtime_legal_backup_r35.py',
              '11a56c4920470b4f3be4c0ffd39d804b1488ede3e55ccf7d6d708e94e57f8ded'),
    'operator': (OWN / 'test_native_hasinclude_operator_r36_draft_v1.py',
                 'f706aed45f39801599a1d86ecc166d3176e6edc2bbb88cdf1ef3e8920be06826'),
    'vfs': (OWN / 'test_native_vfs_mapping_r36_draft_v1.py',
            '1ccac96d5d2543d796a0e15e7e563455dbc4351c9d5b4e7c89592d5108459f3d'),
}
EXTERNAL_FORMAT_RECEIPT = BASE / 'external-format-v1/receipt.json'
EXTERNAL_FORMAT_SHA = 'f65d7fa71b9de4d1cc69c208dd84646650878a97a755628f7e333bc254df4a09'
FORMATTED_EXTERNALS = {
    'legal': (BASE / 'external-format-v1/legal/test_job_runtime_legal_backup_r35.py',
              '11a56c4920470b4f3be4c0ffd39d804b1488ede3e55ccf7d6d708e94e57f8ded'),
    'operator': (BASE / 'external-format-v1/operator/test_native_hasinclude_operator_r36_draft_v1.py',
                 'efe239319c99fc96e51b2c89d15cec7af57bebfa9a04d9bbd358e70b0b542e58'),
    'vfs': (BASE / 'external-format-v1/vfs/test_native_vfs_mapping_r36_draft_v1.py',
            'fe3e0894b77d23e3b222bcb9672ec58245ac5c702d2f74acf6c4dc360186ac93'),
}
NATIVE_MAIN = 'native/clang-indexer/main.cpp'
MAIN_OLD = '514597bad7c1da9c77c2a8c057a4a8864f36290f732563cd8099d23879bbe244'
MAIN_NEW = '0891353b6660b8fb1890aefb552ca41fb3195f9bd14c3df4a96840b97161eae3'
NATIVE_INPUTS = {'native/clang-indexer/ArgumentCheck.h', 'native/clang-indexer/ArgumentPolicy.h',
    'native/clang-indexer/CMakeLists.txt', 'native/clang-indexer/FunctionOwnership.h', NATIVE_MAIN,
    'native/clang-indexer/ProgramEvents.h', 'native/clang-indexer/PthreadCleanup.h',
    'scripts/build_clang_indexer.py', 'zscope/retrieval/compiler_argument_policy.json'}
CONFIG_NAMES = {'conftest.py', 'pytest.ini', '.pytest.ini', 'mypy.ini', '.mypy.ini',
                'tox.ini', 'setup.cfg', 'pyproject.toml'}
SKIP_DIRS = {'__pycache__', '.pytest_cache', '.mypy_cache'}
SDK_ALIAS = Path('/usr/include/clang/18.1.3/include')
SDK_PHYSICAL = Path('/usr/lib/llvm-18/lib/clang/18/include')
NODE_PROPERTY = 'zscope_bounded_actual_nodeid'
BUILD_GUARDS = {
    'candidate1086_complete_set_and_sha_unchanged', 'native_seven_script_policy_unchanged',
    'main1083_complete_set_and_sha_unchanged', 'root1065_unchanged',
    'stage1082_complete_set_and_sha_unchanged', 'stage_all_auxiliary_files_unchanged',
    'actual_config_and_AGENTS_sets_unchanged', 'all_references_unchanged',
    'old_d39_libraries_headers_physical_unchanged', 'old_f4_libraries_headers_physical_unchanged',
    'complete_SDK_compiler_headers_link_inputs_unchanged', 'manifest_and_runner_unchanged',
    'build_environment_unchanged', 'new_binary_actual_host_and_capability'}
ROOT_MATERIAL_CHECKS = {
    'actual_producer_build_passed_exact_phase_and_actor', 'fourteen_exact_guards_all_true',
    'one_actual_fixed_command_rc0', 'actual_configure_compile_link_install_evidence',
    'all23_actual_raw_artifacts_current', 'all525_immutable_refs_current',
    'candidate_exact1086_before_after_current', 'native_nine_provenance_exact',
    'Root_native_update_and_ENV_semantic_chain_passed', 'actual16_ENV_entry_precompile_final_equal',
    'actual_shared_shell_boundary_only_two_explicit_values', 'actual_single_outer_ext4_runtime_passed',
    'main1083_current', 'Root1065_current', 'Stage1082_and_auxiliary_current',
    'all63_build_and_one_install_outputs_current',
    'installed_tool_actual_SHA_and_exact_CMake_install_transform',
    'complete_SDK_baseline_before_after_and_current_bytes', 'complete_actual_SDK_member_set_current',
    'old_d39_and_f4_hosts_current', 'new_host_before_after_same_and_current21_files',
    'new_host_all_actual_physical_identities_current', 'new_capability_from_actual_raw_versions',
    'new_actual_ldd_library_binding_raws'}
PREPARATION_GUARDS = {'source1086_before_after_unchanged', 'target1086_exact_current_source',
    'nested_fixture_artifact_preserved', 'root1065_unchanged', 'stage1082_and_auxiliary_unchanged',
    'main1083_unchanged', 'all_exact_references_unchanged'}
UPDATE = 'artifacts/coordinator-resume-r36-20261019/native-source-update-01/receipt.json'
FLOOR = 'artifacts/stage-checkpoint-contract-intake-r34-20261017/receipt.json'
FIXED_PINS = {
    UPDATE: 'c27298857159e165e9a1e9634bc6fb632514c1bc5182bb714be8883073d2c2af',
    FLOOR: 'b9d8cc7874d3f224f514ec43feebad99f75eb659a9aa194ec068545dc605a69f',
    'artifacts/native-combined-source-review-r36-20261019/review.json':
        '25863e6bc526a2edefa15cf00f76104d76533f6e9c4b78f983e322a06060180a',
    'artifacts/native-root-apply-source-review-r36-20261019/revision-3/review.json':
        '9d4fad047715d0cf29147120ab63fdfa3a8bb15b9fbd08cc8d4a0aa0b1069fea',
    'docs/Z-Scope_Agent_Implementation_Plan/zscope-agent-implementation-plan/coordination/2026-10-14/test_slot.py':
        '7fd4e683bb9e7523a3247eb5efd21ff5a130ebc83375933f32290f4007f9c158',
}
ENV_KEYS = ('PATH', 'LD_LIBRARY_PATH', 'CC', 'CXX', 'LLVM_COMPILER', 'LLVM_COMPILER_PATH',
            'CFLAGS', 'CXXFLAGS', 'CPPFLAGS', 'LDFLAGS', 'CMAKE_PREFIX_PATH',
            'CMAKE_TOOLCHAIN_FILE', 'CMAKE_GENERATOR', 'MAKEFLAGS', 'LIBRARY_PATH',
            'CPATH', 'C_INCLUDE_PATH', 'CPLUS_INCLUDE_PATH')


def require(value, message):
    if not value:
        raise RuntimeError(message)


def now():
    return dt.datetime.now(dt.timezone.utc).isoformat()


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def read(path):
    return json.loads(Path(path).read_text(encoding='utf-8'))


def write(path, value):
    Path(path).write_text(json.dumps(value, ensure_ascii=False, indent=2) + '\n',
                          encoding='utf-8', newline='\n')


def digest(value):
    require(isinstance(value, str) and re.fullmatch('[0-9a-f]{64}', value), 'missing SHA')
    return value


def pending_build_gate():
    """Both entries require immutable code pins; real evidence is also checked."""
    digest(FINAL_NATIVE_SHA)
    require(FINAL_NATIVE_SHA not in {OLD_SHA, F4_SHA}, 'new native is an old installation')
    for path, value in ((SUCCESSFUL_BUILD_RECEIPT, SUCCESSFUL_BUILD_RECEIPT_SHA),
                        (SUCCESSFUL_BUILD_LAUNCHER, SUCCESSFUL_BUILD_LAUNCHER_SHA),
                        (SUCCESSFUL_BUILD_SHELL, SUCCESSFUL_BUILD_SHELL_SHA),
                        (SUCCESSFUL_BUILD_REVIEW, SUCCESSFUL_BUILD_REVIEW_SHA)):
        digest(value)
        require(isinstance(path, str) and Path(path).is_absolute(), 'successful build pin pending')
    require(isinstance(SUCCESSFUL_BUILD_PHASE, str) and SUCCESSFUL_BUILD_PHASE
            and isinstance(SUCCESSFUL_BUILD_ACTOR, str) and SUCCESSFUL_BUILD_ACTOR.startswith('/root/'),
            'successful build identity pending')


def canonical_environment_gate():
    """Same actual v9 prologue for metadata, collection and both run entries."""
    require(sha(ENV_PROLOGUE) == ENV_PROLOGUE_SHA, 'fixed shared ENV prologue drift')
    require(os.environ.get('ZSCOPE_R36_NATIVE_ENV_BOUNDARY') == 'r36-v9'
            and os.environ.get('PATH') == CANONICAL_PATH
            and os.environ.get('LD_LIBRARY_PATH') == CANONICAL_LD_LIBRARY_PATH,
            'canonical PATH/LD actual shell boundary missing')
    for key in BUILD_ENV_KEYS:
        incoming = 'ZSCOPE_R36_NATIVE_INCOMING_' + key
        require(incoming in os.environ, 'actual incoming environment evidence missing: ' + key)
        if key not in {'PATH', 'LD_LIBRARY_PATH'}:
            require(os.environ.get(key, '') == os.environ[incoming], 'unapproved ENV change: ' + key)


def safe_relative(name):
    require(isinstance(name, str), 'non-string relative path')
    path = Path(name)
    require(name and name == path.as_posix() and not path.is_absolute()
            and '..' not in path.parts and '.' not in path.parts, 'unsafe relative path')
    return path


def merge_refs(target, extra):
    require(isinstance(extra, dict), 'missing reference map')
    for name, expected in extra.items():
        digest(expected)
        path = Path(name)
        require(path.is_absolute() and '..' not in path.parts and path.is_relative_to(ROOT)
                and path.is_file() and path.resolve(strict=True) == path, 'invalid/aliased Root reference')
        require(name not in target or target[name] == expected, 'conflicting old reference: ' + name)
        require(sha(path) == expected, 'reference drift: ' + name)
        target[name] = expected


def bound(record, refs):
    require(isinstance(record, dict) and set(record) == {'path', 'sha256'}, 'pending evidence record')
    path = Path(record['path'])
    merge_refs(refs, {str(path): digest(record['sha256'])})
    return path


def all_true(values, count=None):
    return isinstance(values, dict) and bool(values) and (count is None or len(values) == count) \
        and all(value is True for value in values.values())


def source_map(base, *, delivery=True):
    require(base.is_dir(), 'source root missing')
    result = {}
    for directory, directories, names in os.walk(base):
        directories[:] = sorted(name for name in directories if name not in SKIP_DIRS
            and not (Path(directory) == base and name == 'artifacts'))
        require(not any((Path(directory) / name).is_symlink() for name in directories),
                'unreviewed source directory alias')
        for name in sorted(names):
            path = Path(directory) / name
            if path.suffix == '.pyc' or (not delivery and name == 'DELIVERY.md'):
                continue
            require(path.is_file() and not path.is_symlink(), 'nonregular/aliased source')
            result[path.relative_to(base).as_posix()] = sha(path)
    return result


def mapped(base, values):
    require(isinstance(values, dict) and values, 'source map missing')
    return {safe_relative(name).as_posix(): sha(base / name) for name in values}


def named_files(base, names):
    return {path.relative_to(base).as_posix(): sha(path) for path in base.rglob('*')
            if path.is_file() and path.name in names}


def rows(counter):
    return [list(key) + [count] for key, count in sorted(counter.items())]


def parse_rows(value):
    require(isinstance(value, list) and value, 'empty/missing Counter')
    counter = Counter()
    for row in value:
        require(isinstance(row, list) and len(row) == 3 and all(isinstance(s, str) for s in row[:2])
                and type(row[2]) is int and row[2] > 0 and tuple(row[:2]) not in counter,
                'duplicate/invalid raw Counter')
        counter[tuple(row[:2])] = row[2]
    require(rows(counter) == value, 'Counter must be sorted without identity normalization')
    return counter


def xml_data(path):
    nodes = list(ET.parse(path).getroot().iter('testcase'))
    counter = Counter((node.get('classname', ''), node.get('name', '')) for node in nodes)
    return counter, {'tests': len(nodes), 'failures': sum(n.find('failure') is not None for n in nodes),
        'errors': sum(n.find('error') is not None for n in nodes),
        'skipped': sum(n.find('skipped') is not None for n in nodes)}


def artifact_refs(raw, directory, refs):
    values = raw.get('artifact_sha256')
    require(isinstance(values, dict) and values, 'raw artifacts missing')
    for relative, value in values.items():
        path = directory / safe_relative(relative)
        require(path.resolve(strict=True) == path and path.name not in {'receipt.json', 'review.json'},
                'unsafe recursive raw reference')
        merge_refs(refs, {str(path): value})


def historical_refs(values, update, refs):
    """Only the actual Root-recorded native change may replace a live old pin."""
    extra = dict(values)
    mutable = str(CANDIDATE / NATIVE_MAIN)
    if mutable in extra and extra[mutable] == MAIN_OLD:
        require(update['source_before_sha256'][NATIVE_MAIN] == MAIN_OLD
                and update['source_after_sha256'][NATIVE_MAIN] == MAIN_NEW,
                'native history transition not proved')
        extra.pop(mutable)
        merge_refs(refs, {mutable: MAIN_NEW})
    merge_refs(refs, extra)


def validate_update(refs):
    update = read(ROOT / UPDATE)
    require(update['schema'] == 'zscope.root-native-source-update.r36.v1'
            and update['actual_task'] == ACTUAL_TASK and update['applied_and_source_reviewed'] is True
            and update['source_root'] == str(CANDIDATE) and update['allowed_changed_paths'] == [NATIVE_MAIN]
            and all_true(update['guards'], 6) and update['atomic_replacement'] is True,
            'actual Root native-only update invalid')
    before, after = update['source_before_sha256'], update['source_after_sha256']
    require(len(before) == len(after) == 1086 and set(before) == set(after)
            and {name for name in before if before[name] != after[name]} == {NATIVE_MAIN}
            and before[NATIVE_MAIN] == MAIN_OLD and after[NATIVE_MAIN] == MAIN_NEW,
            'Root native transition is not exactly the reviewed source1086')
    require(update['stage_intake'] is False and update['root_intake'] is False
            and update['test_started'] is False and update['native_build_started'] is False,
            'source update is not a native-only copy receipt')
    archive = bound(update['immutable_before_native'], refs)
    require(sha(archive) == MAIN_OLD, 'immutable old native missing')
    merge_refs(refs, update['reference_sha256'])
    require(len(update['reference_sha256']) == 437, 'Root source proof graph incomplete')
    return update


def validate_root_build_materials(raw, refs):
    """Consume real Root build-only review, never promote it to a test pass."""
    merge_refs(refs, {str(ROOT_BUILD_MATERIALS): ROOT_BUILD_MATERIALS_SHA,
                     str(ROOT_ELF_REVIEW): ROOT_ELF_REVIEW_SHA})
    review = read(ROOT_BUILD_MATERIALS)
    require(review['actual_task'] == ACTUAL_TASK and review['native_build_materials_independently_verified'] is True
            and set(review['checks']) == ROOT_MATERIAL_CHECKS and all_true(review['checks'], 24)
            and review['actual_build_receipt'] == {'path': SUCCESSFUL_BUILD_RECEIPT,
                'sha256': SUCCESSFUL_BUILD_RECEIPT_SHA}
            and review['actual_tool'] == {'path': str(NEW_TOOL), 'sha256': FINAL_NATIVE_SHA}
            and review['source_count'] == 1086 and review['build_finished_at'] == raw['finished_at'],
            'actual Root24 build material review differs')
    require(review['build_only'] is True and review['native_behavior_verified'] is False
            and all(review[name] is False for name in ('test_started', 'collector_started',
                'stage_intake', 'root_intake', 'joint_passed')), 'Root build review grants no test/acceptance authority')
    merge_refs(refs, review['evidence_sha256'])
    elf = read(ROOT_ELF_REVIEW)
    built = NEW_TOOL.parents[2] / 'build/zscope-clang-indexer'
    cmake = NEW_TOOL.parents[2] / 'build/cmake_install.cmake'
    require(elf['actual_task'] == ACTUAL_TASK and elf['exact_install_RUNPATH_removal_verified'] is True
            and all_true(elf['checks'], 6) and elf['changed_byte_count'] == 113
            and elf['old_RUNPATH'] == '/usr/lib/llvm-18/lib:'
            and elf['build_receipt'] == review['actual_build_receipt']
            and elf['built'] == {'path': str(built), 'sha256': raw['build_output_sha256']['zscope-clang-indexer']}
            and elf['installed'] == review['actual_tool']
            and elf['cmake_install_script'] == {'path': str(cmake),
                'sha256': raw['build_output_sha256']['cmake_install.cmake']}
            and sha(built) == elf['built']['sha256'] and sha(cmake) == elf['cmake_install_script']['sha256'],
            'actual CMake installed ELF provenance differs; built and installed bytes need not be equal')
    require(elf['installed']['sha256'] == raw['installed_output_sha256']['bin/zscope-clang-indexer']
            and all(elf[name] is False for name in ('test_started', 'native_tool_executed',
                'product_modified', 'stage_intake', 'root_intake', 'joint_passed')),
            'actual ELF review is not immutable build-only evidence')


def validate_build(ready, update, refs):
    for path, value in ((SUCCESSFUL_BUILD_RECEIPT, SUCCESSFUL_BUILD_RECEIPT_SHA),
                        (SUCCESSFUL_BUILD_LAUNCHER, SUCCESSFUL_BUILD_LAUNCHER_SHA),
                        (SUCCESSFUL_BUILD_SHELL, SUCCESSFUL_BUILD_SHELL_SHA),
                        (SUCCESSFUL_BUILD_REVIEW, SUCCESSFUL_BUILD_REVIEW_SHA)):
        merge_refs(refs, {path: value})
    require(ready['successful_build'] == {'path': SUCCESSFUL_BUILD_RECEIPT,
            'sha256': SUCCESSFUL_BUILD_RECEIPT_SHA}, 'ready changed the code-pinned successful build')
    raw_path = Path(SUCCESSFUL_BUILD_RECEIPT)
    raw = read(raw_path)
    require(raw['phase'] == SUCCESSFUL_BUILD_PHASE and raw['actual_agent_id'] == SUCCESSFUL_BUILD_ACTOR
            and raw['passed'] is True and raw['evidence_guards_passed'] is True
            and raw['native_build_started'] is True and raw['build_started'] is True
            and raw['test_started'] is False and raw['collection_started'] is False
            and set(raw['guards']) == BUILD_GUARDS and all_true(raw['guards'], 14),
            'successful real build/14 named guards missing')
    after = update['source_after_sha256']
    require(raw['candidate_before'] == raw['candidate_after'] == after
            and raw['native_build_sources_sha256'] == {name: after[name] for name in NATIVE_INPUTS}
            and raw['native_tool_path'] == str(NEW_TOOL) and raw['native_tool_sha256'] == FINAL_NATIVE_SHA
            and raw['new_native_host'] == raw['new_native_host_after']
            and raw['dedicated_prefix'] == str(NEW_TOOL.parents[2]), 'build source/output binding differs')
    require(len(raw['commands']) == 1 and raw['commands'][0]['returncode'] == 0
            and raw['commands'][0]['argv'] == [PYTHON, str(CANDIDATE / 'scripts/build_clang_indexer.py'),
                '--llvm-prefix', '/usr/lib/llvm-18', '--build-dir', str(NEW_TOOL.parents[2] / 'build'),
                '--prefix', str(NEW_TOOL.parents[1]), '--jobs', '2']
            and raw['commands'][0]['log_sha256'] == sha(raw_path.parent / 'build.log'),
            'actual compile/install command or raw log missing')
    artifact_refs(raw, raw_path.parent, refs)
    freeze = bound(ready['build_freeze'], refs)
    require(freeze == SUCCESSFUL_BUILD_FREEZE and sha(freeze) == raw['freeze_sha256'] == SUCCESSFUL_BUILD_FREEZE_SHA,
            'build freeze SHA differs from actual fixed v9 execution')
    frozen = read(freeze)
    require(frozen['phase'] == SUCCESSFUL_BUILD_PHASE and frozen['actual_agent_id'] == SUCCESSFUL_BUILD_ACTOR
            and frozen['candidate_source_root'] == str(CANDIDATE) and frozen['candidate_source_sha256'] == after
            and frozen['build_launcher_sha256'] == SUCCESSFUL_BUILD_LAUNCHER_SHA
            and frozen['shell_sha256'] == SUCCESSFUL_BUILD_SHELL_SHA
            and frozen['native_build_sources_sha256'] == raw['native_build_sources_sha256'],
            'successful build freeze is not bound to actual source and launcher')
    require(len(frozen['references_sha256']) == 525 and len(raw['artifact_sha256']) == 23
            and len(raw['build_output_sha256']) == 63 and len(raw['installed_output_sha256']) == 1,
            'actual successful v9 proof/input/output graph incomplete')
    historical_refs(frozen['references_sha256'], update, refs)
    merge_refs(refs, {str(ENV_PROLOGUE): ENV_PROLOGUE_SHA})
    expected_env = frozen['build_environment']
    require(set(expected_env) == set(BUILD_ENV_KEYS) and expected_env['PATH'] == CANONICAL_PATH
            and expected_env['LD_LIBRARY_PATH'] == CANONICAL_LD_LIBRARY_PATH
            and raw['actual_build_environment_on_entry'] == raw['actual_build_environment_before_compile']
                == raw['actual_build_environment_final'] == raw['build_environment']
                == raw['expected_build_environment'] == expected_env
            and raw['environment_difference_on_entry'] == raw['environment_difference_before_compile']
                == raw['environment_difference_final'] == {}
            and raw['selected_environment_key_count'] == 16
            and raw['explicitly_fixed_environment_keys'] == ['PATH', 'LD_LIBRARY_PATH']
            and raw['other_environment_values_preserved_exactly'] == 14,
            'actual successful v9 ENV entry/precompile/final differs')
    boundary = raw['actual_shell_environment_boundary_on_entry']
    require(boundary['marker'] == 'r36-v9' and boundary['selected'] == expected_env
            and set(boundary['incoming']) == set(BUILD_ENV_KEYS)
            and all(boundary['incoming'][key] == expected_env[key]
                for key in BUILD_ENV_KEYS if key not in {'PATH', 'LD_LIBRARY_PATH'})
            and frozen['environment_prologue_sha256'] == ENV_PROLOGUE_SHA
            and raw['shell_environment_boundary_validation']['validated'] is True
            and raw['shell_environment_boundary_validation']['prologue_sha256'] == ENV_PROLOGUE_SHA
            and raw['runtime']['passed'] is True and raw['runtime']['temporary_mount'][1] == 'ext4'
            and raw['runtime']['ext4_unlinked_fd_truncate'] is True,
            'actual shared v9 boundary or held-slot/ext4 runtime proof missing')
    validate_root_build_materials(raw, refs)
    sdk_before = raw_path.parent / 'sdk-before.json'
    sdk_after = raw_path.parent / 'sdk-after.json'
    require(sha(sdk_before) == raw['sdk_before_sha256'] and sha(sdk_after) == raw['sdk_after_sha256']
            and read(sdk_before) == read(sdk_after), 'actual build SDK before/after missing')
    require(ready['installed_native_tree_sha256'] == raw['installed_output_sha256']
            and ready['installed_native_tree_sha256'], 'actual complete new installed tree pending')
    review = read(SUCCESSFUL_BUILD_REVIEW)
    require(review['source_review_passed'] is True
            and review['source_sha256'].get(str(Path(SUCCESSFUL_BUILD_LAUNCHER).relative_to(ROOT)))
                == SUCCESSFUL_BUILD_LAUNCHER_SHA, 'successful builder independently reviewed source missing')
    require(sha(NEW_TOOL) == FINAL_NATIVE_SHA, 'actual newly built binary differs')
    return raw, frozen, read(sdk_before)


def validate_oracle(label, record, update, refs):
    path = bound(record, refs)
    oracle = read(path)
    require(oracle['schema'] == 'zscope.bounded-native-group-oracle.r36.v1'
            and oracle['actual_task'] == ACTUAL_TASK and oracle['group'] == label,
            'Root raw oracle record identity differs')
    raw_path = bound(oracle['raw_receipt'], refs)
    raw = read(raw_path)
    require(raw['test_started'] is True and raw['command_started'] is True
            and raw['evidence_guards_passed'] is True and all_true(raw['guards'])
            and raw['candidate_before'] == raw['candidate_after']
            and raw['candidate_after'] in (update['source_before_sha256'], update['source_after_sha256'])
            and raw['phase'] == {'original53': 'green-original53', 'prewrite7': 'green-seven',
                                 'legal_backup1': 'green-legal'}[label], 'historical raw source/phase/guards differ')
    require(raw['actual_agent_id'].startswith('/root/') and len(raw['commands']) == 1
            and raw['commands'][0]['returncode'] in {0, 1}, 'not an actual producer pytest run')
    require(label == 'original53' or (raw['passed'] is True and raw['commands'][0]['returncode'] == 0),
            'unchanged 7/1 oracle was not genuinely green')
    artifact_refs(raw, raw_path.parent, refs)
    historical_refs(raw['references_before'], update, refs)
    freeze = bound(oracle['phase_freeze'], refs)
    require(sha(freeze) == raw['freeze_sha256'], 'raw original phase freeze differs')
    frozen = read(freeze)
    require(frozen['phase'] == raw['phase'] and frozen['candidate_source_root'] == str(CANDIDATE)
            and frozen['candidate_source_sha256'] == raw['candidate_before']
            and frozen['expected_case_counter'] == raw['expected_case_counter'],
            'actual historical freeze/source/Counter differs')
    historical_launcher = Path(raw['commands'][0]['argv'][1])
    merge_refs(refs, {str(historical_launcher): frozen['launcher_sha256']})
    require(raw['commands'][0]['argv'] == [PYTHON, str(historical_launcher), '--child', raw['phase'],
                raw['freeze_sha256'], str(raw_path.parent)]
            and raw['commands'][0]['log_sha256'] == sha(raw_path.parent / 'command.log'),
            'actual historical launcher/freeze/command log differs')
    imported_path = raw_path.parent / 'imported-product-source.json'
    require(raw['artifact_sha256'].get(imported_path.name) == sha(imported_path),
            'actual historical import proof not raw-artifact-bound')
    imported = read(imported_path)
    require(imported['valid'] is True and imported['modules']
            and all(row['valid'] is True for row in imported['modules'].values()),
            'actual historical product imports invalid')
    xml = bound(oracle['results_xml'], refs)
    require(xml.parent == raw_path.parent and raw['artifact_sha256'].get(xml.name) == sha(xml),
            'raw original XML not an actual artifact')
    counter, counts = xml_data(xml)
    expected_count = {'original53': 53, 'prewrite7': 7, 'legal_backup1': 1}[label]
    require(counts['tests'] == expected_count and counts['errors'] == counts['skipped'] == 0
            and raw['junit'] == counts and parse_rows(raw['case_counter']) == counter
            and parse_rows(raw['expected_case_counter']) == counter, 'raw original Counter differs')
    if label == 'original53':
        require(counter[JOB_ID] == 1 and sum(n for (module, _name), n in counter.items()
                if module == 'tests.test_job_runtime_footprint_r34') == 52, 'original SessionJobs case missing')
    require(raw['fixed_test_sha256'] == PREWRITE_SHA, 'typed raw original7 source pin differs')
    require(raw['candidate_after'][ORIGINAL] == ORIGINAL_SHA and raw['candidate_after'][PREWRITE] == PREWRITE_SHA,
            'original 53/7 bytes changed')
    if label == 'legal_backup1':
        require(raw['fixed_external_test_sha256'] == EXTERNALS['legal'][1], 'typed external legal test pin differs')
        fixtures = imported['actual_fixture_sources']
        require(set(LEGAL_FIXTURES) <= set(fixtures), 'actual historical legal fixture proof missing')
        for name in LEGAL_FIXTURES:
            relative = 'tests/' + name + '.py'
            require(fixtures[name]['valid'] is True and fixtures[name]['path'] == str(CANDIDATE / relative)
                    and fixtures[name]['sha256'] == raw['candidate_before'][relative],
                    'actual historical legal fixture source differs')
    return counter


def validate_native_collection(record, ready, source, refs):
    collection_path = bound(record, refs)
    actual = read(collection_path)
    require(actual['schema'] == 'zscope.bounded-native-actual-collection.r36.v1'
            and actual['actual_task'] == ACTUAL_TASK and actual['group'] == 'native14'
            and actual['collection_started'] is True and actual['test_started'] is False
            and actual['returncode'] == 0 and all_true(actual['guards'])
            and actual['before_source_sha256'] == actual['after_source_sha256'] == source,
            'native14 requires real final-source collection, not static test estimates')
    require(actual['tool_sha256'] == FINAL_NATIVE_SHA and actual['external_sha256']
            == {str(EXTERNALS[name][0]): EXTERNALS[name][1] for name in ('operator', 'vfs')},
            'native14 collection tool/source mismatch')
    items = actual['items']
    require(isinstance(items, list) and len(items) == 14 and len({row['nodeid'] for row in items}) == 14,
            'native14 actual nodeids missing/duplicate')
    for key, count in (('operator', 12), ('vfs', 2)):
        external_path, value = EXTERNALS[key]
        require(sum(item['path'] == str(external_path) and item['sha256'] == value for item in items) == count,
                'actual operator12/VFS2 identities missing')
    require(all(set(item) == {'nodeid', 'module', 'name', 'path', 'sha256'}
                and all(isinstance(value, str) and value for value in item.values()) for item in items),
            'actual collection identity fields incomplete')
    require(parse_rows(actual['module_counter']) == Counter((row['module'], row['name']) for row in items),
            'actual module Counter differs from collected items')
    artifact_refs(actual, collection_path.parent, refs)
    historical_refs(actual['reference_sha256'], read(ROOT / UPDATE), refs)
    if ready['native14_xml_oracle'] is not None:
        oracle = bound(ready['native14_xml_oracle'], refs)
        counter, counts = xml_data(oracle)
        require(counts['tests'] == 14 and counts['errors'] == counts['skipped'] == 0,
                'native14 historical raw XML invalid')
        return items, counter
    return items, None


def external_controls():
    result = {}
    for path, _value in EXTERNALS.values():
        for directory in path.parents:
            if not directory.is_relative_to(ROOT):
                break
            for name in CONFIG_NAMES:
                control = directory / name
                if control.is_file():
                    result[str(control)] = sha(control)
    return result


def formatted_external_controls(refs):
    """Original execution/oracle bytes stay immutable; only Black uses copies."""
    merge_refs(refs, {str(EXTERNAL_FORMAT_RECEIPT): EXTERNAL_FORMAT_SHA})
    proof = read(EXTERNAL_FORMAT_RECEIPT)
    require(proof['actual_task'] == ACTUAL_TASK and proof['passed'] is True
            and proof['original_bytes_unchanged'] is True and proof['formatting_required'] is True
            and proof['original_black_check']['returncode'] == 1
            and proof['copy_format']['returncode'] == 0 and proof['errors'] == []
            and set(proof['copies']) == set(EXTERNALS)
            and all(proof[name] is False for name in ('test_started', 'product_modified',
                'stage_intake', 'root_intake', 'joint_passed')), 'actual external format proof missing')
    artifact_refs(proof, EXTERNAL_FORMAT_RECEIPT.parent, refs)
    for key, (path, value) in FORMATTED_EXTERNALS.items():
        original, original_sha = EXTERNALS[key]
        row = proof['copies'][key]
        require(row['original'] == {'path': str(original), 'sha256': original_sha}
                and row['formatted'] == {'path': str(path), 'sha256': value}
                and row['whole_AST_equal'] is True and path.name == original.name,
                'formatted external source binding differs')
        before = ast.dump(ast.parse(original.read_text(encoding='utf-8')), include_attributes=False)
        after = ast.dump(ast.parse(path.read_text(encoding='utf-8')), include_attributes=False)
        require(before == after and hashlib.sha256(before.encode()).hexdigest() == row['whole_AST_sha256'],
                'formatted external whole AST differs from original test')
        merge_refs(refs, {str(original): original_sha, str(path): value})


def validate_ready(ready_sha):
    pending_build_gate()
    require(sha(READY) == digest(ready_sha), 'ready SHA differs')
    ready = read(READY)
    require(ready['schema'] == 'zscope.bounded-native-ready.r36.v1' and ready['status'] == 'ready'
            and ready['actual_task'] == ACTUAL_TASK and ready['scope'] == 'independent-native-repair-only'
            and ready['launcher_sha256'] == sha(INSTALLED) and ready['shell_sha256'] == sha(SHELL),
            'bounded Root ready/installed bytes missing')
    refs = {}
    merge_refs(refs, {str(ROOT / name): value for name, value in FIXED_PINS.items()})
    merge_refs(refs, {str(READY): ready_sha, str(INSTALLED): sha(INSTALLED), str(SHELL): sha(SHELL)})
    merge_refs(refs, ready['reference_sha256'])
    update = validate_update(refs)
    source = update['source_after_sha256']
    require(ready['source_sha256'] == source and source_map(WORK) == source and len(source) == 1086,
            'independent WORK must equal exact actual Root update1086')
    require(source[ORIGINAL] == ORIGINAL_SHA and source[PREWRITE] == PREWRITE_SHA, 'original test bytes changed')
    review = read(bound(ready['independent_runner_review'], refs))
    require(review['actual_task'] == ACTUAL_TASK and review['source_review_passed'] is True
            and review['source_sha256'].get(str(INSTALLED.relative_to(ROOT))) == sha(INSTALLED),
            'Root independent launcher review missing')
    for path, value in EXTERNALS.values():
        merge_refs(refs, {str(path): value})
    formatted_external_controls(refs)
    raw_build, frozen_build, sdk = validate_build(ready, update, refs)
    floor = read(ROOT / FLOOR)
    require(ready['root1065_sha256'] == floor['root_inputs'] and len(floor['root_inputs']) == 1065
            and ready['stage1082_sha256'] == floor['complete_inputs_after']
            and len(floor['complete_inputs_after']) == 1082, 'actual Root/Stage floors differ')
    preparation_path = bound(ready['preparation'], refs)
    require(preparation_path == ROOT_PREPARATION and sha(preparation_path) == ROOT_PREPARATION_SHA,
            'actual fixed Root preparation record missing')
    preparation = read(preparation_path)
    require(preparation['schema'] == 'zscope.bounded-native-root-copy.r36.v1'
            and preparation['actual_task'] == ACTUAL_TASK and preparation['copy_completed'] is True
            and preparation['source_root'] == str(CANDIDATE) and preparation['target_root'] == str(WORK)
            and preparation['source_before_sha256'] == preparation['source_after_sha256']
                == preparation['target_sha256'] == source
            and set(preparation['guards']) == PREPARATION_GUARDS and all_true(preparation['guards'], 7)
            and preparation['root_native_update'] == {'path': str(ROOT / UPDATE), 'sha256': FIXED_PINS[UPDATE]},
            'actual Root-only source copy proof missing')
    require(ready['producer_main1083_sha256'] == frozen_build['main_source_sha256']
            and len(ready['producer_main1083_sha256']) == 1083
            and ready['stage_delivery_sha256'] == frozen_build['stage_delivery_files_sha256'],
            'producer main1083/Stage auxiliary binding differs')
    require(all(preparation[name] is False for name in ('test_started', 'collector_started',
                'ready_created', 'stage_intake', 'root_intake', 'joint_passed'))
            and len(preparation['reference_sha256']) == 552, 'actual copy proof graph or scope differs')
    require(not set(ready['stage_delivery_sha256']) & set(ready['stage1082_sha256'])
            and all(Path(name).name == 'DELIVERY.md' for name in ready['stage_delivery_sha256']),
            'Stage auxiliary map may not overwrite product/floor pins')
    require(ready['producer_configuration'] == frozen_build['configuration_baseline']
            and ready['producer_agents'] == frozen_build['agents_baseline'], 'build config/AGENTS baseline missing')
    historical_refs(preparation['reference_sha256'], update, refs)
    require(ready['configuration_baseline'] == named_files(WORK, CONFIG_NAMES)
            and set(ready['configuration_baseline']) == {'pyproject.toml'}
            and ready['agents_baseline'] == named_files(WORK, {'AGENTS.md'})
            and ready['external_configuration'] == external_controls(), 'actual complete config/AGENTS differs')
    require(set(ready['groups']) == {'original53', 'prewrite7', 'legal_backup1'}, 'oracle group selection differs')
    expected = {label: validate_oracle(label, ready['groups'][label], update, refs)
                for label in ('original53', 'prewrite7', 'legal_backup1')}
    items, native_xml = validate_native_collection(ready['native14_collection'], ready, source, refs)
    expected['native14'] = native_xml
    ready['_native_items'] = items
    ready['_build_sdk'] = sdk
    ready['_build_host'] = raw_build['new_native_host']
    ready['_build_outputs'] = raw_build['build_output_sha256']
    ready['_build_environment'] = frozen_build['build_environment']
    changed = sorted(name for name in source if floor['root_inputs'].get(name) != source[name])
    require(ready['changed_paths'] == changed, 'Black source delta is not the exact Root-floor difference')
    require(ready['environment'] == {name: os.environ.get(name, '') for name in ENV_KEYS}
            and {name: ready['environment'][name] for name in BUILD_ENV_KEYS} == ready['_build_environment'],
            'actual metadata/run ENV must equal the fixed successful v9 boundary')
    return ready, source, refs, expected


def chain(path):
    return {str(item): {'physical': str(item.resolve(strict=True)), 'uid': item.lstat().st_uid,
        'gid': item.lstat().st_gid, 'mode': item.lstat().st_mode, 'device': item.lstat().st_dev,
        'inode': item.lstat().st_ino, 'links': item.lstat().st_nlink,
        'symlink': os.readlink(item) if item.is_symlink() else None}
        for item in (path, *path.parents, path.resolve(strict=True), *path.resolve(strict=True).parents)}


def file_identity(path):
    require(path.is_file(), 'host file absent: ' + str(path))
    return {'sha256': sha(path), 'physical': str(path.resolve(strict=True)), 'chain': chain(path)}


def linked(path, env, log):
    result = subprocess.run(['ldd', str(path)], env=env, capture_output=True, text=True, timeout=20)
    log.write_text(result.stdout + result.stderr, encoding='utf-8')
    require(result.returncode == 0 and 'not found' not in result.stdout + result.stderr, 'actual ldd failed')
    bindings = {}
    for line in result.stdout.splitlines():
        matches = re.findall(r'/[^\s()]+', line)
        if matches:
            name = line.split('=>', 1)[0].strip() if '=>' in line else Path(matches[-1]).name
            require(name not in bindings, 'duplicate ldd binding')
            bindings[name] = matches[-1]
        else:
            require(line.strip().startswith('linux-vdso.so.'), 'unknown actual ldd row')
            bindings[line.strip().split()[0]] = 'kernel-virtual'
    libraries = {Path(value) for value in bindings.values() if value != 'kernel-virtual'}
    require(libraries and all(path.is_file() for path in libraries), 'actual library/loader absent')
    return {'binary': file_identity(path), 'bindings': bindings,
            'libraries': {str(path): file_identity(path) for path in sorted(libraries)}}


def sdk_inputs(env, target, phase):
    """Copy of fixed SDK input enumeration; no import of build/helper modules."""
    tops = [Path('/usr/include'), Path('/usr/lib/llvm-18/include/clang'),
            Path('/usr/lib/llvm-18/include/clang-c'), Path('/usr/lib/llvm-18/include/llvm'),
            Path('/usr/lib/llvm-18/include/llvm-c'), Path('/usr/lib/llvm-18/lib/cmake')]
    tops.extend(Path('/usr/lib/gcc').glob('*/*/include'))
    tops.extend(Path('/usr/lib/llvm-18/lib/clang').glob('*/include'))
    paths = set()
    for top in tops:
        require(top.is_dir(), 'SDK header root absent')
        paths.update(path for path in top.resolve(strict=True).rglob('*') if path.is_file())
    for pattern in ('libclang-cpp.so*', 'libLLVM.so*', 'libLLVM-*.so*'):
        paths.update(path for path in Path('/usr/lib/llvm-18/lib').glob(pattern) if path.is_file())
    commands = {}
    for command in ('cmake', 'gcc', 'cc', 'make', '/usr/lib/llvm-18/bin/clang', '/usr/lib/llvm-18/bin/clang++'):
        resolved = shutil.which(command, path=env.get('PATH'))
        require(resolved is not None, 'build SDK command absent')
        path = Path(resolved)
        paths.add(path)
        version = subprocess.run([resolved, '--version'], env=env, text=True, capture_output=True, timeout=10)
        require(version.returncode == 0, 'SDK command version failed')
        library = linked(path, env, target / ('sdk-' + phase + '-ldd-' + str(len(commands) + 1) + '.log'))
        paths.update(Path(value) for value in library['libraries'])
        commands[command] = {'invocation': resolved, 'version': version.stdout + version.stderr,
                             'ldd_bindings': library['bindings']}
    values = {}
    for path in sorted(paths):
        observed = path.stat()
        values[str(path)] = {'sha256': sha(path), 'physical': str(path.resolve(strict=True)),
            'device': observed.st_dev, 'inode': observed.st_ino, 'uid': observed.st_uid, 'mode': observed.st_mode}
    return {'files': values, 'commands': commands}


def host(ready, env, target, phase):
    require(sha(OLD_TOOL) == OLD_SHA and sha(F4_TOOL) == F4_SHA and sha(NEW_TOOL) == FINAL_NATIVE_SHA,
            'one of the three native installations changed')
    version = subprocess.run([str(NEW_TOOL), '--version'], env=env, capture_output=True, timeout=20)
    (target / ('version-' + phase + '.stdout')).write_bytes(version.stdout)
    (target / ('version-' + phase + '.stderr')).write_bytes(version.stderr)
    require(version.returncode == 0, 'actual new native capability failed')
    capability = json.loads(version.stdout)
    require(capability == ready['_build_host']['capability'] == ready['new_capability']
            and capability.get('protocol') == 'zscope.clang-facts.v2'
            and capability.get('include_lookup_version') == 1 and capability.get('clang_version') == '18.1.3'
            and hashlib.sha256(version.stdout).hexdigest() == ready['version_stdout_sha256'],
            'new binary actual capability/build mismatch')
    sdk_chain = chain(SDK_ALIAS)
    sdk_chain.update(chain(SDK_PHYSICAL))
    require(SDK_ALIAS.is_symlink() and SDK_ALIAS.resolve(strict=True) == SDK_PHYSICAL
            and all(item['uid'] == 0 and (item['symlink'] is not None or not item['mode'] & 0o022)
                    for item in sdk_chain.values())
            and {name for name, value in sdk_chain.items() if value['symlink'] is not None} == {str(SDK_ALIAS)},
            'bounded actual system SDK alias/trust changed')
    resources = {}
    for path in (SDK_PHYSICAL, *sorted(SDK_PHYSICAL.rglob('*'))):
        value = path.lstat()
        require(not path.is_symlink() and value.st_uid == 0 and not value.st_mode & 0o022
                and (stat.S_ISDIR(value.st_mode) or stat.S_ISREG(value.st_mode)), 'SDK member trust changed')
        resources[str(path)] = file_identity(path) if path.is_file() else {'chain': chain(path)}
    standard = {}
    for path in (Path('/usr/include/stdlib.h'), Path('/usr/include/features.h')):
        standard[str(path)] = file_identity(path)
        require(all(value['uid'] == 0 and not value['mode'] & 0o022 and value['symlink'] is None
                    for value in standard[str(path)]['chain'].values()), 'standard header trust changed')
    sdk = sdk_inputs(env, target, phase)
    require(sdk == ready['_build_sdk'], 'actual entire SDK/compiler/link inputs differ from successful build')
    # Real installed libraries AND resource headers belong to the successful
    # build; an SDK check of host /usr/include alone does not cover this tree.
    install = NEW_TOOL.parents[1]
    installed_files = {path.relative_to(install).as_posix(): sha(path) for path in install.rglob('*')
                       if path.is_file() and path.suffix != '.pyc'
                       and not any(part in SKIP_DIRS for part in path.relative_to(install).parts)}
    require(installed_files == ready['installed_native_tree_sha256'], 'complete installed binary/lib/resource tree drift')
    install_members = {str(path): file_identity(path) if path.is_file() else {'chain': chain(path)}
                       for path in (install, *sorted(install.rglob('*')))}
    build_root = NEW_TOOL.parents[2] / 'build'
    build_files = {path.relative_to(build_root).as_posix(): sha(path) for path in build_root.rglob('*')
                   if path.is_file() and path.suffix != '.pyc'
                   and not any(part in SKIP_DIRS for part in path.relative_to(build_root).parts)}
    require(build_files == ready['_build_outputs'], 'actual successful63 build-output artifacts changed')
    names = ('cmake', 'gcc', 'clang', 'clang++', 'clangd', 'gclang', 'get-bc',
             'llvm-link', 'llvm-nm', 'wpa', 'saber')
    tools = {name: shutil.which(name, path=env.get('PATH')) for name in names}
    require(all(tools.values()) and Path(tools['llvm-link']).resolve(strict=True)
            == Path('/usr/lib/llvm-18/bin/llvm-link').resolve(strict=True), 'actual Linux login/LLVM18 tools differ')
    native = {key: linked(path, env, target / (key + '-ldd-' + phase + '.log'))
              for key, path in (('old_d39', OLD_TOOL), ('old_f4', F4_TOOL), ('new', NEW_TOOL))}
    actual_files = {str(NEW_TOOL): native['new']['binary'], **native['new']['libraries'], **standard}
    for name, value in actual_files.items():
        built = ready['_build_host']['files'].get(name)
        require(built is not None and built['sha256'] == value['sha256']
                and built['physical'] == value['physical'], 'actual binary/loader/header not build-bound')
    return {'native': native, 'capability': capability, 'sdk_trust': sdk_chain,
        'installed_tree_sha256': installed_files, 'installed_member_states': install_members,
        'successful_build_output_sha256': build_files,
        'resource_headers': resources, 'standard_headers': standard, 'sdk': sdk,
        'python': file_identity(Path(PYTHON)),
        'login_tools': {name: file_identity(Path(path)) for name, path in tools.items()},
        'svf': {name: linked(Path(tools[name]), env, target / (name + '-ldd-' + phase + '.log'))
                for name in ('wpa', 'saber')}}


def runtime():
    token = os.environ.get('ZSCOPE_COORDINATOR_TEST_SLOT', '').split(':')
    require(len(token) == 2 and token[0].isdigit() and int(token[0]) > 0 and token[1] in {'0', '1'},
            'one held outer slot missing')
    lock = Path('/tmp/zscope-coordination-20261014-test-slots') / (token[1] + '.lock')
    with lock.open() as stream:
        try:
            fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            pass
        else:
            fcntl.flock(stream.fileno(), fcntl.LOCK_UN)
            raise RuntimeError('slot token has no actual held lock')
    mounted = subprocess.run(['findmnt', '--json', '--output', 'TARGET,FSTYPE', '--target', os.environ['TMPDIR']],
                             capture_output=True, text=True, timeout=15)
    require(mounted.returncode == 0, 'temporary mount unavailable')
    mount = json.loads(mounted.stdout)['filesystems'][0]
    require(mount['fstype'] == 'ext4', 'temporary filesystem must be actual ext4')
    with tempfile.TemporaryFile(dir=os.environ['TMPDIR']) as stream:
        stream.write(b'fd capture prerequisite')
        stream.flush()
        stream.truncate(0)
        require(os.fstat(stream.fileno()).st_size == 0, 'unlinked fd truncate failed')
    return {'slot': ':'.join(token), 'lock': str(lock), 'mount': mount, 'ext4_unlinked_fd_truncate': True}


def execution_env():
    env = dict(os.environ)
    env['PYTHONPATH'] = str(WORK) + os.pathsep + str(WORK / 'tests')
    env['PYTHONDONTWRITEBYTECODE'] = '1'
    env['Z_SCOPE_TEST_CLANG_INDEXER'] = str(NEW_TOOL)
    env['Z_SCOPE_TEST_LLVM'] = '1'
    return env


def bootstrap():
    if sys.platform != 'linux' or sys.flags.optimize or sys.executable != PYTHON or sys.version_info[:2] != (3, 13):
        raise RuntimeError('unoptimized Linux venv313 required')
    if any(os.environ.get(name) for name in ('PYTHONOPTIMIZE', 'PYTEST_ADDOPTS', 'PYTEST_PLUGINS')):
        raise RuntimeError('external optimization/pytest controls forbidden')
    pending_build_gate()
    canonical_environment_gate()
    if pwd.getpwuid(os.geteuid()).pw_name != 'zeal' or Path.cwd().resolve() != WORK:
        raise RuntimeError('exact independent WORK under zeal required')
    if Path(__file__).resolve() != INSTALLED:
        raise RuntimeError('artifact draft cannot execute; Root review/install required')


def guard(ready, source, refs, target, phase):
    canonical_environment_gate()
    value = {'source': source_map(WORK), 'candidate': source_map(CANDIDATE),
        'producer_main': source_map(PRODUCER), 'root': mapped(ROOT, ready['root1065_sha256']),
        'stage': source_map(STAGE, delivery=False), 'stage_all': source_map(STAGE),
        'configuration': named_files(WORK, CONFIG_NAMES), 'agents': named_files(WORK, {'AGENTS.md'}),
        'producer_configuration': named_files(PRODUCER, CONFIG_NAMES),
        'producer_agents': named_files(PRODUCER, {'AGENTS.md'}),
        'external_configuration': external_controls(), 'references': {name: sha(name) for name in refs},
        'host': host(ready, execution_env(), target, phase), 'runtime': runtime(),
        'environment': {name: os.environ.get(name, '') for name in ENV_KEYS}}
    write(target / (phase + '-guard.json'), value)
    require(value['source'] == value['candidate'] == source
            and value['producer_main'] == ready['producer_main1083_sha256']
            and value['root'] == ready['root1065_sha256'] and value['stage'] == ready['stage1082_sha256']
            and value['stage_all'] == {**ready['stage1082_sha256'], **ready['stage_delivery_sha256']}
            and value['configuration'] == ready['configuration_baseline']
            and value['agents'] == ready['agents_baseline']
            and value['producer_configuration'] == ready['producer_configuration']
            and value['producer_agents'] == ready['producer_agents']
            and value['external_configuration'] == ready['external_configuration']
            and value['references'] == refs and value['host'] == ready['expected_host']
            and value['environment'] == ready['environment'], 'complete source/host/control guard failed')
    return value


def selected(label):
    return {'original53': [ORIGINAL, 'tests/test_scan_session_jobs.py::' + JOB_NAME],
            'prewrite7': [PREWRITE], 'legal_backup1': [str(EXTERNALS['legal'][0])],
            'native14': [str(EXTERNALS['operator'][0]), str(EXTERNALS['vfs'][0])]}[label]


def item_rows(items):
    return [{'nodeid': item.nodeid, 'module': item.module.__name__, 'name': item.name,
             'path': str(Path(item.path).resolve(strict=True)), 'sha256': sha(item.path)} for item in items]


def import_provenance(source, refs, label):
    products, fixtures, local = {}, {}, {}
    external_allowed = {path for path, _value in EXTERNALS.values()}
    for name, module in sorted(sys.modules.items()):
        raw = getattr(module, '__file__', None)
        is_product = name == 'zscope' or name.startswith('zscope.')
        if not raw:
            if is_product:
                paths = [Path(value).resolve(strict=True) for value in getattr(module, '__path__', ())]
                target = WORK / name.replace('.', '/')
                valid = bool(paths) and all(path == target and path.is_dir() for path in paths)
                valid = valid and any(key.startswith(target.relative_to(WORK).as_posix() + '/') for key in source)
                products[name] = {'namespace_paths': list(map(str, paths)), 'valid': valid}
            continue
        path = Path(raw).resolve()
        if is_product or path.is_relative_to(ROOT):
            relative = path.relative_to(WORK).as_posix() if path.is_relative_to(WORK) else None
            value = sha(path) if path.is_file() else None
            member = relative in source and source.get(relative) == value
            control = path == INSTALLED and refs.get(str(path)) == value
            external = path in external_allowed and refs.get(str(path)) == value
            row = {'path': str(path), 'sha256': value,
                   'valid': bool(member if is_product else member or control or external)}
            if is_product:
                products[name] = row
            else:
                local[name] = row
        short = name.rsplit('.', 1)[-1]
        if short in LEGAL_FIXTURES:
            relative = 'tests/' + short + '.py'
            fixtures[name] = {'path': str(path), 'sha256': sha(path),
                'valid': path == WORK / relative and sha(path) == source[relative]}
    valid = bool(products) and all(row['valid'] is True for row in (*products.values(), *local.values(), *fixtures.values()))
    if label == 'legal_backup1':
        valid = valid and set(LEGAL_FIXTURES) <= set(fixtures)
    return {'actual_task': ACTUAL_TASK, 'valid': bool(valid), 'modules': products,
            'fixture_modules': fixtures, 'external_local_modules': local}


def child(ready_sha, label):
    bootstrap()
    require(label in GROUPS and (OUT / label).is_dir(), 'unknown/unprepared bounded child')
    ready, source, refs, _expected = validate_ready(ready_sha)
    target = OUT / label
    guard(ready, source, refs, target, 'child-before')
    require(not any(name == 'zscope' or name.startswith('zscope.') for name in sys.modules),
            'product imported before source selection')
    require(not any(name.rsplit('.', 1)[-1] in LEGAL_FIXTURES for name in sys.modules),
            'fixture imported before source selection')
    sys.path[:] = [str(WORK), str(WORK / 'tests')] + [value for value in sys.path
        if not Path(value or '.').resolve().is_relative_to(ROOT)]
    import zscope
    require(Path(zscope.__file__).resolve(strict=True) == WORK / 'zscope/__init__.py', 'wrong actual product')
    if label == 'legal_backup1':
        for name in LEGAL_FIXTURES:
            module = importlib.import_module(name)
            path = Path(module.__file__).resolve(strict=True)
            require(path == WORK / ('tests/' + name + '.py') and sha(path) == source['tests/' + name + '.py'],
                    'external legal fixture borrowed outside actual WORK')
    import pytest

    class Observation:
        def pytest_collection_finish(self, session):
            actual = item_rows(session.items)
            write(target / 'collected.json', {'actual_task': ACTUAL_TASK, 'items': actual,
                'actual_nodeids': [item['nodeid'] for item in actual],
                'module_counter': rows(Counter((item['module'], item['name']) for item in actual))})
            allowed = {WORK / ORIGINAL, WORK / 'tests/test_scan_session_jobs.py'} if label == 'original53' else \
                {WORK / PREWRITE} if label == 'prewrite7' else \
                {EXTERNALS['legal'][0]} if label == 'legal_backup1' else \
                {EXTERNALS['operator'][0], EXTERNALS['vfs'][0]}
            require(len(actual) == {'original53': 53, 'prewrite7': 7, 'legal_backup1': 1, 'native14': 14}[label]
                    and len({row['nodeid'] for row in actual}) == len(actual)
                    and all(Path(row['path']) in allowed for row in actual), 'actual collection scope changed')
            if label == 'original53':
                require(sum(row['path'] == str(WORK / ORIGINAL) for row in actual) == 52
                        and sum(row['name'] == JOB_NAME and row['path'] == str(WORK / 'tests/test_scan_session_jobs.py')
                                for row in actual) == 1, 'original 52+SessionJobs identity changed')
            if label == 'native14':
                require(actual == ready['_native_items'], 'native14 differs from actual frozen collection')
                for item in session.items:
                    require(not any(key == NODE_PROPERTY for key, _value in item.user_properties), 'nodeid property collision')
                    item.user_properties.append((NODE_PROPERTY, item.nodeid))

        def pytest_sessionfinish(self, session, exitstatus):
            proof = import_provenance(source, refs, label)
            write(target / 'imported-product-source.json', proof)
            if not proof['valid']:
                session.exitstatus = 2

    options = ['-q', '--rootdir=' + str(WORK), '--confcutdir=' + str(WORK), '--capture=fd',
               '-o', 'junit_family=xunit2', *selected(label), '--junitxml=' + str(target / 'results.xml')]
    write(target / 'pytest-invocation.json', {'actual_task': ACTUAL_TASK, 'argv': options,
        'workspace': str(WORK), 'source_sha256': source, 'external_sha256': {str(p): v for p, v in EXTERNALS.values()}})
    try:
        return pytest.main(options, plugins=[Observation()])
    finally:
        guard(ready, source, refs, target, 'child-after')


def native_xml_mapping(path, items):
    expected = {row['nodeid']: row for row in items}
    actual = {}
    for node in ET.parse(path).getroot().iter('testcase'):
        values = [row.get('value', '') for row in node.findall('./properties/property') if row.get('name') == NODE_PROPERTY]
        require(len(values) == 1 and values[0] in expected and values[0] not in actual,
                'real native XML lacks a unique actual nodeid property')
        item = expected[values[0]]
        require(node.get('name', '') == item['name'], 'real XML parameter/name differs from actual collection')
        actual[values[0]] = {'classname': node.get('classname', ''), 'name': node.get('name', '')}
    require(set(actual) == set(expected), 'real native14 XML/collection is not bijective')
    return actual


def execute_group(label, ready_sha, ready, source, refs, expected):
    target = OUT / label
    target.mkdir(exist_ok=False)
    freeze = {'schema': 'zscope.bounded-native-group-freeze.r36.v1', 'actual_task': ACTUAL_TASK,
        'phase': 'green', 'group': label, 'candidate_source_root': str(WORK),
        'candidate_source_sha256': source, 'tool_sha256': FINAL_NATIVE_SHA,
        'expected_case_counter': rows(expected) if expected is not None else None,
        'launcher_sha256': sha(INSTALLED), 'references_sha256': dict(refs)}
    write(target / 'phase-freeze.json', freeze)
    merge_refs(refs, {str(target / 'phase-freeze.json'): sha(target / 'phase-freeze.json')})
    raw = {'schema': 'zscope.bounded-native-raw-execution.r36.v1', 'actual_task': ACTUAL_TASK,
        'actual_agent_id': ACTUAL_TASK, 'phase': 'green', 'group': label, 'test_started': False,
        'command_started': False, 'commands': [], 'freeze_sha256': sha(target / 'phase-freeze.json'),
        'candidate_source_root': str(WORK), 'candidate_before': source,
        'expected_case_counter': rows(expected) if expected is not None else None,
        'tool_sha256': FINAL_NATIVE_SHA, 'references_before': dict(refs),
        'passed': False, 'evidence_guards_passed': False,
        'guards': {}, 'started_at': now(), 'full_independent_passed': False, 'joint_passed': False}
    if label in {'prewrite7', 'legal_backup1'}:
        raw['fixed_test_sha256'] = PREWRITE_SHA
    elif label == 'original53':
        raw['fixed_test_sha256'] = ORIGINAL_SHA
    if label == 'legal_backup1':
        raw['fixed_external_test_sha256'] = EXTERNALS['legal'][1]
    errors = []
    try:
        guard(ready, source, refs, target, 'before')
        raw['guards']['complete_before_source_config_root_stage_refs_host'] = True
        argv = [PYTHON, str(INSTALLED), '--child', ready_sha, label]
        raw.update(test_started=True, command_started=True)
        write(target / 'receipt.json', raw)
        start = now()
        with (target / 'command.log').open('wb') as stream:
            command = subprocess.run(argv, cwd=WORK, env=execution_env(), stdout=stream, stderr=subprocess.STDOUT)
        raw['commands'].append({'argv': argv, 'returncode': command.returncode, 'started_at': start,
            'finished_at': now(), 'log_sha256': sha(target / 'command.log')})
        actual, counts = xml_data(target / 'results.xml')
        raw.update(case_counter=rows(actual), actual_counter=rows(actual), junit=counts)
        collection = read(target / 'collected.json')
        raw['module_counter'] = collection['module_counter']
        require(counts['tests'] == {'original53': 53, 'prewrite7': 7, 'legal_backup1': 1, 'native14': 14}[label],
                'actual XML test count differs')
        if expected is not None:
            require(actual == expected, 'raw actual XML Counter differs from immutable original oracle')
        if label == 'native14':
            require(collection['items'] == ready['_native_items'], 'actual native14 collection changed')
            raw['xml_nodeid_mapping'] = native_xml_mapping(target / 'results.xml', collection['items'])
        raw['guards']['actual_counter_exact_or_native_actual_nodeid_bijection'] = True
        raw['guards']['zero_failures_errors_skips'] = counts['failures'] == counts['errors'] == counts['skipped'] == 0
        proof = read(target / 'imported-product-source.json')
        raw['guards']['actual_product_and_fixture_imports'] = proof['valid'] is True
        raw['imported_product_source'] = {'path': str(target / 'imported-product-source.json'),
                                         'sha256': sha(target / 'imported-product-source.json')}
    except BaseException as error:
        errors.append({'type': type(error).__name__, 'message': str(error)})
    finally:
        try:
            last = guard(ready, source, refs, target, 'after')
            raw['candidate_after'] = last['source']
            raw['guards']['complete_after_source_config_root_stage_refs_host'] = True
        except BaseException as error:
            errors.append({'type': type(error).__name__, 'message': str(error)})
            raw['guards']['complete_after_source_config_root_stage_refs_host'] = False
        raw['evidence_guards_passed'] = not errors and all_true(raw['guards'])
        raw['passed'] = raw['evidence_guards_passed'] and len(raw['commands']) == 1 and raw['commands'][0]['returncode'] == 0
        raw.update(errors=errors, finished_at=now())
        raw['artifact_sha256'] = {path.relative_to(target).as_posix(): sha(path) for path in target.rglob('*')
                                  if path.is_file() and path.name != 'receipt.json'}
        write(target / 'receipt.json', raw)
    return raw


def quality_commands(ready, source):
    paths = sorted(name for name in ready['changed_paths'] if name.endswith('.py'))
    require(paths and all(name in source for name in paths), 'actual changed Python Black scope missing')
    paths.extend(str(path) for path, _value in FORMATTED_EXTERNALS.values())
    return [
        ('compileall', [PYTHON, '-m', 'compileall', '-f', '-q', 'zscope', 'scripts', 'test', 'tests']),
        ('mypy', [PYTHON, '-m', 'mypy', 'zscope']),
        ('mypy-fresh', [PYTHON, '-m', 'mypy', '--no-incremental', 'zscope']),
        ('scripts-mypy', [PYTHON, '-m', 'mypy', 'scripts/agent_plan_evaluation.py']),
        ('black', [PYTHON, '-m', 'black', '--check', '--config', str(WORK / 'pyproject.toml'), *paths]),
        ('web-assets', [PYTHON, 'scripts/portable/web_assets.py']),
    ]


def execute_quality(label, argv, ready, source, refs):
    target = OUT / label
    target.mkdir(exist_ok=False)
    raw = {'label': label, 'argv': argv, 'started_at': now(), 'command_started': False,
           'returncode': None, 'guards': {}, 'passed': False, 'errors': []}
    try:
        guard(ready, source, refs, target, 'before')
        raw['guards']['complete_before'] = True
        raw['command_started'] = True
        write(target / 'receipt.json', raw)
        with (target / 'command.log').open('wb') as stream:
            command = subprocess.run(argv, cwd=WORK, env=execution_env(), stdout=stream, stderr=subprocess.STDOUT)
        raw.update(returncode=command.returncode, log_sha256=sha(target / 'command.log'))
    except BaseException as error:
        raw['errors'].append({'type': type(error).__name__, 'message': str(error)})
    finally:
        try:
            guard(ready, source, refs, target, 'after')
            raw['guards']['complete_after'] = True
        except BaseException as error:
            raw['errors'].append({'type': type(error).__name__, 'message': str(error)})
            raw['guards']['complete_after'] = False
        raw['passed'] = raw['returncode'] == 0 and all_true(raw['guards']) and not raw['errors']
        raw['finished_at'] = now()
        write(target / 'receipt.json', raw)
    return raw


def main(ready_sha):
    bootstrap()
    # Concrete build provenance does not supply ready/actual collection/test
    # results. validate_ready must succeed before any product/test subprocess.
    OUT.mkdir(parents=True, exist_ok=False)
    report = {'schema': RESULT_SCHEMA, 'actual_task': ACTUAL_TASK, 'started_at': now(),
        'scope': 'independent-native-repair-only', 'test_started': False, 'groups': {}, 'quality': [],
        'commands': [], 'errors': [], 'bounded_native_acceptance_passed': False,
        'independent_native_job_passed': False, 'full_independent_passed': False,
        'stage_intake': False, 'root_intake': False, 'joint_passed': False}
    write(OUT / 'review.json', report)
    ready = source = refs = None
    try:
        ready, source, refs, expected = validate_ready(ready_sha)
        guard(ready, source, refs, OUT, 'initial')
        for label in GROUPS:
            raw = execute_group(label, ready_sha, ready, source, refs, expected[label])
            report['groups'][label] = {'raw_receipt': str(OUT / label / 'receipt.json'),
                'raw_receipt_sha256': sha(OUT / label / 'receipt.json'), 'passed': raw['passed'],
                'junit': raw.get('junit'), 'case_counter': raw.get('case_counter')}
            report['commands'].extend(raw['commands'])
            report['test_started'] = report['test_started'] or raw['test_started']
            write(OUT / 'journal.json', report)
            require(raw['evidence_guards_passed'], 'bounded group evidence invalid: ' + label)
        for label, argv in quality_commands(ready, source):
            raw = execute_quality(label, argv, ready, source, refs)
            report['quality'].append(raw)
            report['commands'].append(raw)
            write(OUT / 'journal.json', report)
            require(all_true(raw['guards']), 'quality evidence invalid: ' + label)
    except BaseException as error:
        report['errors'].append({'type': type(error).__name__, 'message': str(error)})
    finally:
        try:
            require(ready is not None and source is not None and refs is not None,
                    'ready validation failed; no final complete guard can be claimed')
            guard(ready, source, refs, OUT, 'final')
            report['final_guard_passed'] = True
        except BaseException as error:
            report['errors'].append({'type': type(error).__name__, 'message': str(error)})
            report['final_guard_passed'] = False
        report['bounded_native_acceptance_passed'] = set(report['groups']) == set(GROUPS) \
            and all(value['passed'] is True for value in report['groups'].values()) \
            and len(report['quality']) == 6 and all(value['passed'] is True for value in report['quality']) \
            and len(report['commands']) == 10 and report['final_guard_passed'] and not report['errors']
        report['finished_at'] = now()
        report['reference_sha256'] = refs
        report['source_sha256'] = source
        if ready is None:
            # A bad real invocation still leaves an explicit failure receipt;
            # this observation cannot upgrade missing proof to a passing guard.
            try:
                report['observed_after_source_sha256'] = source_map(WORK)
            except BaseException as error:
                report['observed_after_error'] = {'type': type(error).__name__, 'message': str(error)}
        report['tool_sha256'] = FINAL_NATIVE_SHA
        report['artifact_sha256'] = {path.relative_to(OUT).as_posix(): sha(path) for path in OUT.rglob('*')
                                     if path.is_file() and path.name != 'review.json'}
        write(OUT / 'review.json', report)
    return 0 if report['bounded_native_acceptance_passed'] else 1


if __name__ == '__main__':
    # No --collect, --format, arbitrary paths, test argv, build or install mode.
    if len(sys.argv) == 4 and sys.argv[1] == '--child':
        raise SystemExit(child(sys.argv[2], sys.argv[3]))
    if len(sys.argv) != 2:
        raise RuntimeError('exact concrete bounded-ready SHA required')
    raise SystemExit(main(sys.argv[1]))
