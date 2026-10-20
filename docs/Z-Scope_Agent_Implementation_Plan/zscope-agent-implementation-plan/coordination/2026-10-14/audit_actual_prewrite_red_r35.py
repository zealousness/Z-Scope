"""Read original raw executions; never synthesize or rewrite test results."""
from collections import Counter
from pathlib import Path
import datetime as dt
import hashlib
import json
import sys
import xml.etree.ElementTree as ET

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
JOB = ROOT / '.coordination/20261014/workspaces/job-runtime-footprint-repair-r34/artifacts/job_runtime_footprint_r34'
RED = JOB / 'prewrite-red-v3'
FREEZE = JOB / 'prewrite-red-v3-freeze.json'
OUT = ROOT / 'artifacts/coordinator-prewrite-red-audit-r35-20261017'
TEST = 'tests/test_job_runtime_prewrite_r35.py'
TEST_SHA = '74cd68ba5a5c45afa25c2c3d48695c2c3f56b7252664ffc51f9060304f45c054'
TOOL_SHA = 'f4e2ff8aef71027447afe497b4c8872a4b2bc2f596166ff543492a623fdda860'
sha = lambda p: hashlib.sha256(Path(p).read_bytes()).hexdigest()
read = lambda p: json.loads(Path(p).read_text(encoding='utf-8'))
record = lambda p: dict(path=str(p), sha256=sha(p))
rows = lambda c: [list(k) + [v] for k, v in sorted(c.items())]
def require(value, message):
    if not value:
        raise RuntimeError(message)

if sys.platform != 'linux' or sys.flags.optimize:
    raise RuntimeError('Unoptimized Linux required')
require(len(sys.argv) == 2, 'Actual completed red receipt SHA is required')
require(sha(RED / 'receipt.json') == sys.argv[1], 'Red receipt changed')
require(sha(FREEZE) == 'c2f85326d03f078db91aa7b81c199c22b92db349207a645470101a081983e359', 'Unfixed red freeze changed')
raw, frozen = read(RED / 'receipt.json'), read(FREEZE)
require(raw['phase'] == 'red' and raw['command_started'] and raw['test_started'] and raw['finished_at'], 'Actual red incomplete')
require(raw['evidence_guards_passed'] and raw['guards'] and all(v is True for v in raw['guards'].values()), 'Actual source/runtime guards failed')
require(raw['candidate_before'] == raw['candidate_after'] == frozen['candidate_source_sha256'] and len(raw['candidate_after']) == 1086, 'Actual unfixed source drift')
require(raw['fixed_test_sha256'] == frozen['candidate_source_sha256'][TEST] == TEST_SHA, 'Original seven test changed')
require(raw['freeze_sha256'] == sha(FREEZE), 'Wrong red freeze')
refs = {str(FREEZE): sha(FREEZE), str(RED / 'receipt.json'): sys.argv[1], str(Path(__file__)): sha(Path(__file__))}
for name, digest in frozen['references_sha256'].items():
    require(sha(name) == digest and (name not in refs or refs[name] == digest), 'Frozen reference drift: ' + name)
    refs[name] = digest
for name, digest in raw['artifact_sha256'].items():
    relative = Path(name)
    require(not relative.is_absolute() and '..' not in relative.parts and name != 'receipt.json', 'Unsafe raw artifact')
    path = RED / relative
    require(sha(path) == digest, 'Raw artifact drift: ' + name)
    refs[str(path)] = digest
launcher = JOB / 'prewrite-probe-runner-v3.py'
require(sha(launcher) == frozen['launcher_sha256'], 'Actual launcher changed')
refs[str(launcher)] = sha(launcher)
imported_path = RED / 'imported-product-source.json'
imported = read(imported_path)
require(imported['valid'] and imported['modules'] and all(v['valid'] is True for v in imported['modules'].values()), 'Actual import provenance failed')
collection_path = JOB / 'prewrite-collect-v2/receipt.json'
require(sha(collection_path) == '7ad263288301b3e51bea24efc996e2b82ac20879834003fbb36fe12f47301578', 'Original collection changed')
collected = read(collection_path)
require(collected['passed'] and collected['evidence_guards_passed'], 'Original collection was not valid')
refs[str(collection_path)] = sha(collection_path)
nodes = list(ET.parse(RED / 'results.xml').getroot().iter('testcase'))
counter = Counter((n.get('classname', ''), n.get('name', '')) for n in nodes)
require(len(nodes) == len(counter) == 7 and rows(counter) == raw['case_counter'] == frozen['expected_case_counter'] == collected['case_counter'], 'Actual raw Counter differs')
counts = dict(tests=len(nodes), failures=sum(n.find('failure') is not None for n in nodes), errors=sum(n.find('error') is not None for n in nodes), skipped=sum(n.find('skipped') is not None for n in nodes))
require(counts == raw['junit'] and counts['errors'] == counts['skipped'] == 0, 'Actual JUnit differs or setup failed')
require(len(raw['commands']) == 1 and raw['commands'][0]['returncode'] == 1, 'Actual red command did not fail normally')
positives = {('tests.test_job_runtime_prewrite_r35', f'test_prewrite_probe_native_job_positive_closes_queue[{v}]') for v in ('False', 'True')}
cases, errors, valid = [], [], []
for node in nodes:
    identity = (node.get('classname', ''), node.get('name', ''))
    failure = node.find('failure')
    if identity in positives:
        require(failure is None and node.find('error') is None and node.find('skipped') is None, 'Actual positive control did not pass')
        values = [p.get('value') for p in node.findall('properties/property') if p.get('name') == 'positive_job']
        require(len(values) == 1 and json.loads(values[0]) == dict(batch=identity[1].endswith('[True]'), analyzed=2, checkpointed=True), 'Actual queue closure evidence differs')
        continue
    row = dict(identity=list(identity), observation_property='prewrite_observation', causal_review_passed=False)
    try:
        require(failure is not None, 'Intended risk did not fail')
        values = [p.get('value') for p in node.findall('properties/property') if p.get('name') == 'prewrite_observation']
        require(len(values) == 1, 'Actual observation missing or duplicated')
        observed = json.loads(values[0])
        row['observation_value_sha256'] = hashlib.sha256(values[0].encode()).hexdigest()
        row['failure_element_sha256'] = hashlib.sha256(ET.tostring(failure, encoding='utf-8')).hexdigest()
        plans = observed['native_plans']
        require(len(plans) == 1 and plans[0]['instances'] == plans[0]['current_contexts'] == 2 and plans[0]['tool_sha256'] == [TOOL_SHA], 'Failure occurred before the real two-variant plan')
        require(observed['risk_gate_reached'] is True, 'Inconclusive: risk gate not reached')
        if identity[1].startswith('test_batch_backup_link_to_actual_input_is_refused_before_copy['):
            require(observed['causal_classification'] == 'actual_copy_or_exact_target_gate_reached', 'Backup target was not reached')
            require(observed['dangerous_copy_calls'] and observed['actual_input_before']['sha256'] != observed['actual_input_after']['sha256'], 'No actual forwarded copy damage')
            require(all(c['actual_input_identity_before'] == observed['actual_input_before'] for c in observed['dangerous_copy_calls']), 'Copy did not target the proven input')
            require('the real copy operation must never follow a link to an input' in (failure.text or ''), 'First failed assertion is unrelated')
            row['first_failed_gate'] = 'dangerous_copy_calls_empty'
        else:
            require(identity[1] == 'test_revoked_real_tool_copy_is_refused_before_first_store_connection', 'Unknown original risk identity')
            require(observed['causal_classification'] == 'actual_revoked_tool_verifier_reached', 'Actual tool verifier was not reached')
            require(observed['store_connects'] and observed['store_connects'][0]['native_plan_finished'] is True and observed['store_connects'][0]['connect_returned'] is True, 'No real first Store connection')
            before, revoked = observed['tool_before'], observed['tool_revoked']
            require(before['sha256'] == TOOL_SHA and before['sha256'] != revoked['sha256'] and before['mtime_ns'] == revoked['mtime_ns'], 'Tool revocation was not real same-mtime bytes')
            gates = [g for g in observed['native_tool_gates'] if g['recorded_tool_sha256'] == before['sha256'] and g['actual_tool_sha256'] == revoked['sha256'] and g.get('actual_current_result') is False]
            require(gates, 'No actual emitting-byte verifier failure')
            if 'the real emitting-byte verifier must observe the revoked tool before any Store connection' in (failure.text or ''):
                require(not any(g['store_connects_before_gate'] == 0 for g in gates) and any(g['store_connects_before_gate'] > 0 for g in gates), 'Actual verifier did not follow Store')
                row['first_failed_gate'] = 'native_tool_verifier_before_store'
            else:
                require('withdrawn native authority must precede even a WAL-capable Store connection' in (failure.text or '') and any(g['store_connects_before_gate'] == 0 for g in gates), 'First failed tool assertion is unrelated')
                row['first_failed_gate'] = 'store_connects_empty'
        row['causal_review_passed'] = True
        valid.append(list(identity))
    except (RuntimeError, KeyError, TypeError, ValueError) as error:
        row['inconclusive_reason'] = str(error)
        errors.append(dict(identity=list(identity), reason=str(error)))
    cases.append(row)
passed = counts == dict(tests=7, failures=5, errors=0, skipped=0) and len(valid) == 5 and not errors
when = dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat()
require(not OUT.exists(), 'Preserve previous causal audit')
OUT.mkdir()
projection = dict(schema='zscope.stage-prewrite-first-cause.r35.v1', actual_task='/root', checked_at=when,
    causal_review_passed=passed, red_xml_sha256=sha(RED / 'results.xml'), test_sha256=TEST_SHA,
    case_counter=rows(counter), cases=sorted(cases, key=lambda c: c['identity']), errors=errors, reference_sha256=refs)
path = OUT / 'causal-projection.json'
path.write_text(json.dumps(projection, ensure_ascii=False, indent=2) + '\n', encoding='utf-8', newline='\n')
audit = dict(schema='zscope.stage-prewrite-valid-red.r35.v1', actual_task='/root', checked_at=when,
    evidence_kind='actual-red-execution-causality', causal_review_passed=passed, evidence_guards_passed=True,
    results_xml=str(RED / 'results.xml'), results_xml_sha256=sha(RED / 'results.xml'), test_sha256=TEST_SHA,
    case_counter=rows(counter), junit=counts, positive_pass_identities=[list(k) for k in sorted(positives)],
    valid_target_failure_identities=sorted(valid), causal_projection=record(path),
    execution=dict(raw_receipt=record(RED / 'receipt.json'), phase_freeze=record(FREEZE), launcher=record(launcher), imported_product_source=record(imported_path)),
    reference_sha256=dict(refs, **{str(path): sha(path)}), stage_intake=False, root_intake=False,
    independent_prewrite_passed=False, errors=errors)
(OUT / 'review.json').write_text(json.dumps(audit, ensure_ascii=False, indent=2) + '\n', encoding='utf-8', newline='\n')
print(json.dumps(dict(checked_at=when, actual_junit=counts, actual_causal_review_passed=passed, confirmed_risk_cases=len(valid), errors=errors)))
raise SystemExit(0 if passed else 1)
