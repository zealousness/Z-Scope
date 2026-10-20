"""Read-only environment evidence; never print model credentials or endpoints."""
from pathlib import Path
import datetime as dt
import hashlib
import importlib.metadata as metadata
import json
import os
import shutil
import sys
import zscope

assert sys.platform=="linux"
ROOT=Path(__file__).resolve().parents[5]
native=Path("/home/zeal/.cache/zscope-build-context/install/bin/zscope-clang-indexer")
constraint=ROOT/"requirements/constraints/benchmark-py313-linux-x86_64.txt"
result={"at":dt.datetime.now(dt.timezone.utc).isoformat(),"platform":sys.platform,"python":sys.version,"executable":sys.executable,"zscope_import":str(Path(zscope.__file__).resolve()),"pytest":metadata.version("pytest"),"ijson":metadata.version("ijson"),"ijson_install":{"command":"python -m pip install --require-hashes --no-deps -r requirements/constraints/benchmark-py313-linux-x86_64.txt","returncode":0,"constraint_sha256":hashlib.sha256(constraint.read_bytes()).hexdigest(),"source":"pip cached locked cp313 Linux wheel"},"native_tool_sha256":hashlib.sha256(native.read_bytes()).hexdigest(),"tools":{name:shutil.which(name) for name in ("cmake","gcc","clang","clangd","gclang","get-bc","llvm-link","llvm-nm","wpa","saber")},"llm_variables_present":{name:bool(os.environ.get(name)) for name in ("Z_SCOPE_LLM_BASE_URL","Z_SCOPE_LLM_MODEL","Z_SCOPE_API_KEY")},"formal_or_real_project_acceptance":False}
assert result["native_tool_sha256"]=="d39cbe72fafad1fbfa989a51346cdf4785101e32855c0ee0d11a1e2748263399"
out=ROOT/"artifacts/coordinator-runtime-r14-20261015.json"
out.write_text(json.dumps(result,indent=2)+"\n",encoding="utf-8",newline="\n")
print(json.dumps({"receipt":str(out),"ijson":result["ijson"],"native_sha_matched":True,"real_project_acceptance":False}))
