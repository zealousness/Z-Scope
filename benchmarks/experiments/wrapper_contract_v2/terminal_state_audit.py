"""Join frozen terminal candidates with usage without loading the full report."""
from __future__ import annotations
import argparse
from collections import Counter
import json
from pathlib import Path
import re
import ijson

def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--run',type=Path,required=True)
    run=parser.parse_args().run
    outline=json.loads((run/'report-json-probe.json').read_text())
    report=run/'report.json'
    assert report.stat().st_size==outline['report_bytes']
    section=next(v for v in outline['serialized_sections'] if v['field']=='candidate_terminal_states')
    rows=[]
    fields=('candidate_uid','validation_cluster_uid','id','candidate_id','candidate_source','function','location','category','rule','finding_kind','candidate_disposition','validation_status','validator_verdict','model_verdict','validator_stop_reason','validation_reasoning','policy_disposition','confirmed_via','entry_identity','entry_function','reachable_from_entry','validation_soft_budget_seconds','validation_duration_seconds','engine','engine_status','reason','record_role')
    with report.open('rb') as f:
        f.seek(section['offset']);header=f.read(256)
        match=re.match(rb'\s*"candidate_terminal_states"\s*:\s*',header);assert match
        start=section['offset']+match.end();end=section['offset']+section['span_bytes']
        f.seek(end-64);tail=f.read(64);trimmed=tail.rstrip();assert trimmed.endswith(b',')
        trimmed=trimmed[:-1].rstrip();end-=len(tail)-len(trimmed);f.seek(start)
        class Slice:
            def read(self,n=-1):
                left=end-f.tell();return f.read(left if n<0 else min(n,left))
        for candidate in ijson.items(Slice(),'item'):
            row={k:candidate.get(k) for k in fields}
            row['validator_policy_outcome']=candidate.get('validator_policy_outcome')
            latest=candidate.get('review_latest_result') or {}
            row['latest_model_verdict']=latest.get('verdict');row['latest_model_reasoning']=latest.get('reasoning')
            row['entry_context']=(candidate.get('review_validation_evidence') or {}).get('entry_context')
            rows.append(row)
    groups={r['validation_cluster_uid']:r for r in rows if r.get('validation_cluster_uid')}
    candidates={r['candidate_uid']:r for r in rows if r.get('candidate_uid')}
    calls=Counter();tokens=Counter();missing=[];physical=0
    for line in (run/'llm_usage_events.jsonl').read_text().splitlines():
        event=json.loads(line);attribution=event.get('attribution') or {}
        if (attribution.get('agent') or event.get('agent'))!='validator_agent':continue
        physical+=1
        group=event.get('validation_cluster_uid') or attribution.get('validation_cluster_uid')
        candidate=event.get('candidate_uid') or attribution.get('candidate_uid')
        owner=groups.get(group) or candidates.get(candidate)
        if owner is None:missing.append({'candidate_uid':candidate,'validation_cluster_uid':group,'call_id':event.get('call_id')})
        source=(owner or {}).get('candidate_source') or 'unattributed'
        calls[source]+=1;tokens[source]+=int((event.get('usage') or {}).get('total_tokens') or event.get('total_tokens') or 0)
    result={'source_report_sha256':outline['sha256'],'terminal_count':len(rows),'sources':dict(Counter(r.get('candidate_source') or 'unknown' for r in rows)),'dispositions':dict(Counter(r.get('candidate_disposition') or 'unknown' for r in rows)),'validator_physical_calls':physical,'validator_calls_by_source':dict(calls),'validator_tokens_by_source':dict(tokens),'unmatched_usage':missing,'candidates':rows}
    marker_counts=Counter((v.get('engine'),v.get('engine_status'),v.get('reason')) for v in rows if v.get('record_role')=='operational_obligation')
    result['operational_markers']=[{'engine':key[0],'engine_status':key[1],'reason':key[2],'count':value} for key,value in marker_counts.items()]
    result['validation_terminal_groups']=len(groups)
    (run/'terminal-state-audit.json').write_text(json.dumps(result,ensure_ascii=False,indent=2,default=str)+'\n',encoding='utf-8')
    print(json.dumps({k:v for k,v in result.items() if k!='candidates'},ensure_ascii=False))
if __name__=='__main__':main()
