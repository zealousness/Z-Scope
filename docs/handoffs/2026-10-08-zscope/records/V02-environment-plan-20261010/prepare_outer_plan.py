"""Generate a reviewable outer driver proposal without executing it."""
import ast
import pathlib

HERE = pathlib.Path(__file__).resolve().parent
old = pathlib.Path('/mnt/c/Users/10273/Documents/Codex/2026-10-10/task-3/v01-v02-current-acceptance-20261010/current-asan-container.py').read_text()
changes = [
    ("IMAGE = 'docker.io/library/python@sha256:de8ba566572ebcb35cbd10e03f5f351cad00a0d0d50a11e084f1a0fd24a0c41a'", "IMAGE = sys.argv[1]\nassert len(IMAGE.removeprefix('sha256:')) == 64 and all(c in '0123456789abcdef' for c in IMAGE.removeprefix('sha256:')), 'Pass the reviewed derived image ID, not a moving tag'"),
    ("EXPECTED_IMAGE_ID = '1cbbca32768c3c2d7c0dfa6888790808c05672438f20718472f43f0ac8d9707c'", "EXPECTED_IMAGE_ID = IMAGE.removeprefix('sha256:')"),
    ('zscope-v01-current-asan-20261010-', 'zscope-v02-compat-proposal-20261010-'),
    ('zscope-v01-v02-asan-', 'zscope-v02-compat-'),
    ('independent current-resource-repair five-node ASAN acceptance', 'PROPOSAL: one harmless TSAN compatibility probe, zero fixtures'),
    ('current-asan-result.json', 'compatibility-result.json'),
    ("'TSAN':'not_run'", "'TSAN':'probe_only; thread_fixtures_not_run'"),
    ('current-asan-inside.py', 'compat-probe.proposed.py'),
    ('asan-inside.py', 'compat-probe.py'),
    ("RESULT['status']='asan_checks_passed' if RESULT['exit_code']==0 and RESULT.get('counts')=={'passed':5,'failed':0,'errors':0,'skipped':0} and RESULT['isolation'] and RESULT['isolation']['verified'] else 'blocked_or_failed'", "probe_path=OUTPUT/'compat-probe.json'\n    RESULT['probe']=json.loads(probe_path.read_text()) if probe_path.is_file() else None\n    RESULT['fixture_executions']=0\n    RESULT['status']='compatibility_probe_passed_only' if RESULT['exit_code']==0 and RESULT['probe'] and RESULT['probe']['exit_code']==0 and RESULT['isolation'] and RESULT['isolation']['verified'] else 'blocked_or_failed'"),
]
for before, after in changes:
    assert before in old, before
    old = old.replace(before, after)
old = old.replace('"""One specific approved, offline, bounded ASAN acceptance container."""', '"""PROPOSAL ONLY. Requires approval for the derived image and one probe. Never runs fixtures."""')
path = HERE / 'compat-container.proposed.py'
with path.open('x', encoding='utf-8', newline='\n') as file:
    file.write(old)
for path in HERE.glob('*.py'):
    ast.parse(path.read_text(encoding='utf-8'), filename=str(path))
print('Proposed drivers parse; none executed.')
