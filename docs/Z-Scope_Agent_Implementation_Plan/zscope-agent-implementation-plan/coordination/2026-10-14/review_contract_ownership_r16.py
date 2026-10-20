"""Record the actual ownership deviation, then authorize its narrowly reviewed continuation."""
from pathlib import Path
import datetime as dt
import hashlib
import json
from audit_followup_r12 import audit, ROOT, HERE

name="zscope/semantics/retention_protocols.py"
branch=ROOT/".coordination/20261014/workspaces/contract-validation-r12"
observed=audit("contract-validation-r12")
assert len(observed["nonowned_changes"])==1 and observed["nonowned_changes"][0]["path"]==name
delta=observed["nonowned_changes"][0]
assert hashlib.sha256((ROOT/name).read_bytes()).hexdigest()==delta["before"]
old=(ROOT/name).read_text(encoding="utf-8")
addition='                # The checked body\'s native owner identity when the receipt\n                # carries one; consumers pin this exact symbol and reject\n                # publications whose USR was blanked or forged.\n                usr=str(body.get("owner", {}).get("usr") or ""),\n'
new=old.replace('                build_context_id=context_build_id(context),\n','                build_context_id=context_build_id(context),\n'+addition)
assert new==(branch/name).read_text(encoding="utf-8")
at=dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat()
out=ROOT/"artifacts/coordinator-contract-r16-ownership-review-20261015"
out.mkdir(exist_ok=False)
(out/"original-audit.json").write_text(json.dumps(observed,indent=2)+"\n",encoding="utf-8",newline="\n")
decision={"at":at,"coordinator_reviewed":True,"prior_ownership_violation_retained":True,"path":name,"before":delta["before"],"after":delta["after"],"scope":"Only publish native owner USR from the already-read current body; unchanged runtime and native extraction. Original task did not authorize this write. Original audit retained. Prospective ownership extended to permit required repair and independent verification; this is not retrospective compliance or acceptance.","independent_acceptance":False,"integrated":False,"human_extra_approval_required":False,"authorization":"Existing user authorization for plan development, repair, shared integration and file ownership coordination; no platform or review restriction bypass."}
(out/"decision.json").write_text(json.dumps(decision,indent=2)+"\n",encoding="utf-8",newline="\n")
extension=HERE/"followups-r12/contract-validation-r12-ownership-extension-r4.json"
assert not extension.exists()
extension.write_text(json.dumps({"at":at,"coordinator_authorized":True,"write_paths":[name],"previous_sha256":{name:delta["before"]},"decision":(out/"decision.json").relative_to(ROOT).as_posix(),"original_ownership_violation_retained":True},indent=2)+"\n",encoding="utf-8",newline="\n")
p=HERE/"tasks.json";d=json.loads(p.read_text(encoding="utf-8"));r=next(r for r in d["tasks"] if r["id"]=="CONTRACT-VALIDATION-R12")
r["write_paths"]=list(dict.fromkeys(r["write_paths"]+[name]));r["owns"]=r["write_paths"];r["ownership_deviation_review"]=(out/"decision.json").relative_to(ROOT).as_posix();d["updated_at"]=at
p.write_text(json.dumps(d,ensure_ascii=False,indent=2)+"\n",encoding="utf-8",newline="\n")
print(json.dumps(decision))
