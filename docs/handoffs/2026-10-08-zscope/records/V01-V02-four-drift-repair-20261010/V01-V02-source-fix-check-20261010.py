"""Independent ordinary source snapshot checks; no real sanitizer execution."""
import hashlib,json,os,signal,subprocess,sys,tempfile,time
from datetime import datetime,timezone
from pathlib import Path
import xml.etree.ElementTree as ET

ROOT=Path("/mnt/c/Users/10273/home/work/Z-Scope_1.31/Z-Scope")
LOCAL=Path("/mnt/c/Users/10273/Documents/Codex/2026-10-09/task-3")
RECORDS=ROOT/"docs/handoffs/2026-10-08-zscope/records"
WORK=Path(tempfile.mkdtemp(prefix="zscope-source-fix-20261010-"))
digest=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
tracked=[ROOT/"zscope/core/validation/dynamic_reproduction.py",ROOT/"tests/test_dynamic_reproduction.py",LOCAL/"test_v01_v02_independent_drift.py",RECORDS/"V01-V02-acceptance-regressions.py",RECORDS/"V01-V02-reacceptance-regressions.py"]
before={str(p):digest(p) for p in tracked}
report={"startedAt":datetime.now(timezone.utc).isoformat(),"python":sys.executable,"scope":"ordinary source snapshot and related proof regressions; fake binary never launched","checks":[],"before":before,"work":str(WORK)}
env={k:os.environ[k] for k in ("PATH","LANG","LC_ALL","LC_CTYPE","TZ","LD_LIBRARY_PATH") if k in os.environ}
env.update(PYTHONDONTWRITEBYTECODE="1",PYTEST_DISABLE_PLUGIN_AUTOLOAD="1",PYTHONPATH=str(ROOT),TMPDIR=str(WORK),XDG_CACHE_HOME=str(WORK/"cache"))
cases=[("source-drift",[str(LOCAL/"test_v01_v02_independent_drift.py"),"-k","drift_between_last_execution_and_registration"]),("related-proof",["tests/test_dynamic_reproduction.py",str(RECORDS/"V01-V02-acceptance-regressions.py"),str(RECORDS/"V01-V02-reacceptance-regressions.py")])]
for label,targets in cases:
    xml=WORK/(label+".xml");out=WORK/(label+".stdout.log");err=WORK/(label+".stderr.log")
    command=[sys.executable,"-m","pytest","-q","-p","no:cacheprovider","--tb=short","--basetemp="+str(WORK/(label+"-tmp")),"--junitxml="+str(xml),*targets]
    start=time.monotonic();stopped=None
    print(json.dumps({"start":label,"command":command}),flush=True)
    with out.open("wb") as stdout,err.open("wb") as stderr:
        proc=subprocess.Popen(command,cwd=ROOT,env=env,stdout=stdout,stderr=stderr,start_new_session=True)
        while proc.poll() is None:
            if time.monotonic()-start>300:stopped="timeout"
            elif out.stat().st_size+err.stat().st_size>8*1024*1024:stopped="output-cap"
            if stopped:
                os.killpg(proc.pid,signal.SIGTERM)
                try:proc.wait(timeout=5)
                except subprocess.TimeoutExpired:os.killpg(proc.pid,signal.SIGKILL)
                break
            time.sleep(.1)
        code=proc.wait()
    entry={"label":label,"command":command,"exitCode":code,"stopped":stopped,"elapsed":round(time.monotonic()-start,3),"stdout":str(out),"stderr":str(err)}
    if xml.is_file():
        d=ET.parse(xml).getroot();suites=[d] if d.tag=="testsuite" else list(d.findall("testsuite"));counts={k:sum(int(s.get(k,0)) for s in suites) for k in ("tests","failures","errors","skipped")};entry["counts"]={"passed":counts["tests"]-counts["failures"]-counts["errors"]-counts["skipped"],"failed":counts["failures"],"errors":counts["errors"],"skipped":counts["skipped"]};entry["junit"]=str(xml);entry["failures"]=[{"node":c.get("name"),"message":f.get("message")} for c in d.iter("testcase") for f in c if f.tag in ("failure","error")]
    report["checks"].append(entry);print(json.dumps(entry),flush=True)
report["after"]={str(p):digest(p) for p in tracked};report["changed"]=[p for p in before if before[p]!=report["after"][p]];report["completedAt"]=datetime.now(timezone.utc).isoformat()
result=LOCAL/("V01-V02-source-fix-check-20261010-"+WORK.name.rsplit("-",1)[-1]+".json")
result.write_text(json.dumps(report,indent=2)+"\n");print(json.dumps({"result":str(result),"changed":report["changed"]}),flush=True)
sys.exit(0 if not report["changed"] and all(c["exitCode"]==0 for c in report["checks"]) else 1)
