"""Reuse the reviewed five-node container lane with the current frozen baseline."""
import hashlib
import json
import pathlib
import shutil

ROOT = pathlib.Path('/mnt/c/Users/10273/home/work/Z-Scope_1.31/Z-Scope')
OLD = pathlib.Path('/mnt/c/Users/10273/Documents/Codex/2026-10-09/task-3')
LOCAL = pathlib.Path(__file__).resolve().parent
old_path = OLD / 'V01-V02-ASAN-postrepair-container-20261010.py'
source = old_path.read_text(encoding='utf-8')
replacements = [
    ("LOCAL = pathlib.Path('/mnt/c/Users/10273/Documents/Codex/2026-10-09/task-3')", 'LOCAL = pathlib.Path(__file__).resolve().parent'),
    ('zscope-v01-v02-asan-postrepair-20261010-', 'zscope-v01-current-asan-20261010-'),
    ('independent postrepair five-node ASAN acceptance', 'independent current-resource-repair five-node ASAN acceptance'),
    ("RESULT_PATH = LOCAL/'V01-V02-ASAN-postrepair-20261010.json'", "RESULT_PATH = LOCAL/'current-asan-result.json'"),
    ("baseline = json.loads((LOCAL/'V01-V02-independent-acceptance-current.json').read_text())", "baseline = json.loads((ROOT/'docs/handoffs/2026-10-08-zscope/records/V01-V02-resource-repair-20261010/repo-format-validation.json').read_text())"),
    ("baseline['inputs_before']['files']", "baseline['inputs_after']"),
    ("baseline['inputs_after']['files']", "baseline['inputs_after']"),
    ("inside_source = LOCAL/'V01-V02-ASAN-inside-20261010.py'", "inside_source = LOCAL/'current-asan-inside.py'"),
    ("'zscope/config/runtime_defaults.yaml','tests/test_dynamic_reproduction_execution.py',", "'zscope/config/runtime_defaults.yaml','tests/test_dynamic_reproduction_execution.py',"),
]
for before, after in replacements:
    assert source.count(before) == 1, repr(before)
    source = source.replace(before, after)
needle = "    assert RESULT['inputs_before']==baseline['inputs_after'], 'product inputs drifted before ASAN'"
assert source.count(needle) == 1
source = source.replace(needle, needle + "\n    assert RESULT['inputs_before']['zscope/core/validation/dynamic_reproduction.py']=='77fdcd1671849348bffcbff643e711b2c260d3ff73907f3d9ac4297b19f6aba7'\n    RESULT['source_sha256']=RESULT['inputs_before']['zscope/core/validation/dynamic_reproduction.py']")
driver = LOCAL / 'current-asan-container.py'
inside = LOCAL / 'current-asan-inside.py'
with driver.open('x', encoding='utf-8', newline='\n') as file:
    file.write(source)
with inside.open('xb') as file:
    file.write((OLD / 'V01-V02-ASAN-inside-20261010.py').read_bytes())
manifest = {
    'old_outer_sha256': hashlib.sha256(old_path.read_bytes()).hexdigest(),
    'new_outer_sha256': hashlib.sha256(driver.read_bytes()).hexdigest(),
    'inside_driver_sha256': hashlib.sha256(inside.read_bytes()).hexdigest(),
    'approved_boundary_changed': False,
    'test_nodes_changed': False,
    'changes': 'New result directory and name; current 403-input baseline and explicit product hash; unchanged inner driver, image, limits, mounts and five nodes.',
}
with (LOCAL / 'driver-preparation.json').open('x', encoding='utf-8', newline='\n') as file:
    json.dump(manifest, file, indent=2)
    file.write('\n')
print(json.dumps(manifest))
