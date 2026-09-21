import json, sys
from pathlib import Path
sys.path.insert(0, "/mnt/c/Users/10273/home/work/Z-Scope_1.31/Z-Scope")
from zscope.retrieval.code_index import CodeIndex
from zscope.config.config import ConfigLoader
ws = Path("/home/zeal/zscope_dash_ws/scan-input")
cfg = ConfigLoader.load(str(ws.parent / "zscope.yaml"))
idx = CodeIndex(
    cfg.project.project_root, cfg.project.compile_commands_path,
    source_root=cfg.project.source_root, indexing_config=cfg.indexing,
    include_paths=cfg.project.include_paths, exclude_paths=cfg.project.exclude_paths,
    wait_for_cpg=False,
)
for fn, fp in (("_lifecycle_wait_for_work", "src/lifecycle.c"),
               ("_executor_cleanup_resources", "src/executor.c")):
    facts = idx.get_function_program_facts(fn, fp)
    print(f"{fn}: type={type(facts).__name__}")
    if isinstance(facts, dict):
        print("  keys:", list(facts.keys())[:10])
        print("  complete:", facts.get("complete"), " functions:", len(facts.get("functions", [])))
        cc = facts.get("compiler_cfg")
        if isinstance(cc, dict):
            print("  compiler_cfg functions:", len(cc.get("functions", [])),
                  " complete:", cc.get("complete"))
        else:
            print("  compiler_cfg:", str(cc)[:80])
    else:
        print("  raw:", str(facts)[:200])
