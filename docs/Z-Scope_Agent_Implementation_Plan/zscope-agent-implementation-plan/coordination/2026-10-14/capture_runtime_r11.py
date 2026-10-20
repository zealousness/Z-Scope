"""Read-only Linux runtime receipt, never print credential values."""
from pathlib import Path
import datetime as dt
import hashlib
import importlib.metadata
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import zscope

assert sys.platform=="linux"
root=Path(__file__).resolve().parents[5]
tools={name:shutil.which(name) for name in ("cmake","gcc","clang","clangd","gclang","get-bc","llvm-link","llvm-nm","wpa","saber")}
libraries={}
for name in ("wpa","saber"):
    result=subprocess.run(["ldd",tools[name]],capture_output=True,text=True) if tools[name] else None
    libraries[name]={"returncode":result.returncode if result else None,"missing":[line.strip() for line in result.stdout.splitlines() if "not found" in line] if result else None}
native=Path("/home/zeal/.cache/zscope-build-context/install/bin/zscope-clang-indexer")
proof={"at":dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat(),"python":sys.version,"executable":sys.executable,
       "pytest":importlib.metadata.version("pytest"),"zscope_source":zscope.__file__,"cwd":os.getcwd(),"tools":tools,
       "dynamic_libraries":libraries,"native_sha256":hashlib.sha256(native.read_bytes()).hexdigest(),
       "llm_variables_present":{key:bool(os.environ.get(key)) for key in ("Z_SCOPE_LLM_BASE_URL","Z_SCOPE_LLM_MODEL","Z_SCOPE_API_KEY")},
       "ijson_present":importlib.util.find_spec("ijson") is not None,
       "scope":"Availability/dependency inventory only; not a real-project scan, model connectivity, formal benchmark or portable smoke."}
(root/"artifacts/coordinator-runtime-r11-20261015.json").write_text(json.dumps(proof,indent=2)+"\n",encoding="utf-8",newline="\n")
print(json.dumps(proof))
