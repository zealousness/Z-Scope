"""Read only controlled native probe reports and recorded input changes."""
from pathlib import Path
import json
import sqlite3
import sys
from zscope.reporting.json_io import read_report

for path in Path(sys.argv[1]).glob("pytest-of-*/pytest-0/test_*/project/report.json"):
    report=read_report(path)
    plan=report.get("metadata",{}).get("entry_instances",{})
    output={"test":path.parents[1].name,"completeness":report.get("completeness"),"plan":{k:plan.get(k) for k in ("status","planned_instances","gaps","entry_records")},"analysis":plan.get("instance_analysis")}
    database=path.parent/".zscope_jobs/jobs.db"
    knowledge=path.parent/".zscope_knowledge/code_knowledge.db"
    if knowledge.exists():
        with sqlite3.connect(knowledge.as_uri()+"?mode=ro",uri=True) as connection:
            output["native_sources"]=[r[0] for r in connection.execute("SELECT DISTINCT source FROM compilation_instances")]
    if database.exists():
        with sqlite3.connect(database.as_uri()+"?mode=ro",uri=True) as connection:
            output["input_changes"]=[json.loads(r[0]) for r in connection.execute("SELECT data_json FROM events WHERE kind='input_revoked'")]
    print(json.dumps(output,ensure_ascii=False))
