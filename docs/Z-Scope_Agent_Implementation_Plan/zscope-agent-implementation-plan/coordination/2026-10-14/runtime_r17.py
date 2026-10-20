"""Read-only runtime identity; never print credentials or rebuild native tools."""
from pathlib import Path
import datetime as dt
import hashlib
import json
import os
import sys

assert sys.platform=="linux"
HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[4]
tool=Path("/home/zeal/.cache/zscope-build-context/install/bin/zscope-clang-indexer")
value={"at":dt.datetime.now(dt.timezone.utc).isoformat(),"executable":sys.executable,"platform":sys.platform,"native_tool_sha256":hashlib.sha256(tool.read_bytes()).hexdigest(),"llm_variables_present":{name:bool(os.environ.get(name)) for name in ("Z_SCOPE_LLM_BASE_URL","Z_SCOPE_LLM_MODEL","Z_SCOPE_API_KEY")},"formal_or_real_project_acceptance":False}
assert value["native_tool_sha256"]=="d39cbe72fafad1fbfa989a51346cdf4785101e32855c0ee0d11a1e2748263399"
p=ROOT/"artifacts/coordinator-runtime-r17-20261015.json"
assert not p.exists();p.write_text(json.dumps(value,indent=2)+"\n",encoding="utf-8",newline="\n")
print(json.dumps(value))
