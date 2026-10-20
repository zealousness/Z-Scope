"""Read retained fixture timeline without printing owner/claim tokens."""
from pathlib import Path
import datetime as dt
import json
import sqlite3
import sys

assert sys.platform=="linux"
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[4]
base=Path("/tmp/zscope-branch-check-urt_py7y/pytest-of-zeal/pytest-0/test_claimed_work_finishes_bou0")
databases=list(base.glob("project/.zscope_jobs/*.db"))+list(base.glob("project/.zscope_jobs/*.sqlite3"))
assert len(databases)==1, [p.name for p in databases]
with sqlite3.connect(databases[0].as_uri()+"?mode=ro",uri=True) as connection:
    connection.row_factory=sqlite3.Row
    jobs=[dict(row) for row in connection.execute("SELECT job_id,run_id,status,stop_at_epoch,revision FROM jobs")]
    events=[]
    for row in connection.execute("SELECT seq,at,kind,data_json FROM events ORDER BY seq"):
        try:data=json.loads(row["data_json"])
        except (TypeError,ValueError):data={}
        events.append({"seq":row["seq"],"at":row["at"],"epoch":dt.datetime.fromisoformat(row["at"]).timestamp(),"kind":row["kind"],"data":{key:data[key] for key in ("status","counts","pending_count","completed_this_run","stop_cause","stop_at_epoch","item_id","batch_no","worker_count") if isinstance(data,dict) and key in data}})
value={"inspected_at":dt.datetime.now(dt.timezone.utc).isoformat(),"artifact":"artifacts/coordinator-bound-events-r17-20261015","fixture":str(base),"jobs":jobs,"events":events,"read_only":True,"focused_same_bytes_probe":"artifacts/coordinator-bound-events-r17-deadline-probe-20261015.xml"}
p=ROOT/"artifacts/coordinator-bound-events-r17-20261015/deadline-timeline.json"
assert not p.exists();p.write_text(json.dumps(value,indent=2)+"\n",encoding="utf-8",newline="\n")
print(json.dumps(value))
