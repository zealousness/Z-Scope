"""Check the new method with Black without reformatting old unrelated regions."""
from pathlib import Path
import ast
import datetime as dt
import hashlib
import json
import sys
import black

assert sys.platform=="linux"
root=Path.cwd()
path=root/"zscope/retrieval/code_index.py"
source=path.read_text(encoding="utf-8")
tree=ast.parse(source)
node=next(node for cls in tree.body if isinstance(cls,ast.ClassDef) and cls.name=="CodeIndex"
          for node in cls.body if isinstance(node,ast.FunctionDef) and node.name=="get_compilation_facts")
snippet="class CodeIndex:\n"+"\n".join(source.splitlines()[node.lineno-1:node.end_lineno])+"\n"
formatted=black.format_str(snippet,mode=black.Mode(target_versions={black.TargetVersion.PY313},line_length=88))
assert snippet==formatted
out=root/"artifacts/coordinator-s01-code-index-style-r11-20261015"
out.mkdir(exist_ok=False)
(out/"checked-method.py").write_text(snippet,encoding="utf-8",newline="\n")
proof={"at":dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat(),"file":"zscope/retrieval/code_index.py",
       "source_sha256":hashlib.sha256(path.read_bytes()).hexdigest(),"method":"CodeIndex.get_compilation_facts",
       "black_version":black.__version__,"line_length":88,"target":"py313","passed":True,
       "scope":"New method only. Existing unrelated full-file formatting is preserved; no source mutation."}
(out/"review.json").write_text(json.dumps(proof,indent=2)+"\n",encoding="utf-8",newline="\n")
print(json.dumps(proof))
