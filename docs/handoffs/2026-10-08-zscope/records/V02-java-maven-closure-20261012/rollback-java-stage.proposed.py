"""Optional approved cleanup after evidence review. Never run in preparation."""
import argparse
import json
import pathlib
import shutil
import subprocess

parser = argparse.ArgumentParser()
parser.add_argument('--remove-owned-stage-after-review', action='store_true', required=True)
parser.parse_args()
prep = pathlib.Path(__file__).resolve().parent
claim = json.loads((prep / 'java-two-nodes.claimed.json').read_text())
root = pathlib.Path('/home/zeal/.cache/zscope-common-java-20261012')
assert claim['work'] == str(root) and root.resolve() == root
assert root.parent.resolve() == pathlib.Path('/home/zeal/.cache') and not root.is_symlink()
assert claim['container_name'] == 'zscope-common-java-20261012-two-nodes'
assert claim['image_id'] == '60e3b821beb946564925285acdc7c87b55bcdf587f4e3006321728dce2900fff'
assert (prep / 'java-two-nodes-result.json').is_file() and (prep / 'java-two-nodes-evidence').is_dir()
subprocess.run(['podman', 'rm', '--force', '--ignore', claim['container_name']], check=True, capture_output=True)
shutil.rmtree(root)
print('Removed only the fixed claimed stage; sealed preparation and evidence are retained.')
