"""Append the independent regressions without changing existing assertions."""
import ast
import hashlib
import json
import re
from pathlib import Path

base = Path(__file__).resolve().parent
local = base.parent
root = Path("/mnt/c/Users/10273/home/work/Z-Scope_1.31/Z-Scope")
target = root / "tests/test_dynamic_reproduction.py"
baseline = json.loads((base / "reviewed-regressions.json").read_text())
frozen = json.loads((local / "V01-V02-TSAN-minimal-20261010-xc9j8htj.json").read_text())["inputs_after"]
before = target.read_bytes()
assert hashlib.sha256(before).hexdigest() == frozen["tests/test_dynamic_reproduction.py"]
text = before.decode("utf-8")
parts = []
for name, first in (("test_v01_v02_resource_bounds.py", "def test_build_receives"),
                    ("test_v01_v02_resource_controls.py", "def test_real_build")):
    part = (local / name).read_text()
    part = part[part.index(first):]
    part = part.replace("H['_process_plan']", "_process_plan").replace("H['_policy']", "_policy")
    parts.append(part)
part = (base / "test_resource_lifecycle.py").read_text()
part = part[part.index("def _command"):]
for old, new in (("_command", "_resource_child_command"), ("_alive", "_resource_child_alive"),
                 ("_cleanup", "_cleanup_resource_child"), ("_assert_stopped", "_assert_resource_child_stopped"),
                 ("_run", "_run_resource_process")):
    part = re.sub(r"\b" + old + r"\b", new, part)
parts.append(part)
addition = "\n\n# Bounded build/capture regressions (RG01/RG02), including owned descendants.\n\n" + "\n\n".join(parts)
added_names = {n.name for n in ast.parse(addition).body if isinstance(n, ast.FunctionDef) and n.name.startswith("test_")}
old_names = {n.name for n in ast.parse(text).body if isinstance(n, ast.FunctionDef)}
assert len(added_names) == 12 and not (added_names & old_names)  # 13 parametrized cases
ending = "\r\n" if "\r\n" in text else "\n"
text = text.replace("import os" + ending, "import os" + ending + "import signal" + ending, 1)
anchor = "from zscope.config.config import AnalysisConfig" + ending
assert anchor in text
text = text.replace(anchor, anchor + "from zscope.core.validation import dynamic_reproduction as d" + ending, 1)
with (base / "test_dynamic_reproduction.before.py").open("xb") as stream:
    stream.write(before)
target.write_bytes((text + addition).encode("utf-8"))
record = {"original_sha256": hashlib.sha256(before).hexdigest(),
          "added_test_names": sorted(added_names), "old_assertions_modified": False,
          "format_start_line": len(text.splitlines()) + 1}
(base / "test-integration.json").write_text(json.dumps(record, indent=2) + "\n")
print(json.dumps(record))
