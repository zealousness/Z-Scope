"""Review actual ASAN evidence without rerunning any accepted node."""
import hashlib,json,pathlib
LOCAL=pathlib.Path(__file__).resolve().parent
result=json.loads((LOCAL/'asan-acceptance-result.json').read_text());E=pathlib.Path(result['archived_evidence'])
saved=json.loads((E/'observed-executions.json').read_text());o=saved['test_observed'];events=saved['events']
positive=o['asan_positive'];negative=o['asan_negative'];broken=o['asan_build_failure']
replays=[e['evidence'] for e in events if e['event']=='replay_witness' and e['node'].endswith('::test_asan_positive_fixture_confirms_through_shared_adjudication')]
checks={
 'original_five_nodes_zero_skips':result['counts']=={'passed':5,'failed':0,'errors':0,'skipped':0} and result['exit_code']==0,
 'same_image':result['image_id'].removeprefix('sha256:')=='60e3b821beb946564925285acdc7c87b55bcdf587f4e3006321728dce2900fff',
 'default_profile':result['seccomp_profile']=='default' and result['seccomp_profile_sha256']=='cc374cf23846ce1f62f4dc807a8e2b8673c783c6f56cb475467621035d281e6c',
 'isolation_verified':result['isolation']['verified'],'inputs_unchanged':not result['changed_inputs'],
 'host_aslr_unchanged':result['host_aslr_unchanged'],'container_cleaned':result['owned_container_cleanup']['exit_code']==0,
 'observer_error_free':not saved['observer_errors'],
 'positive_source_site':positive['outcome']=='witness_observed' and positive['inputs_verified'] and positive['findings'][0]['site']=='/repo/tests/fixtures/dynamic_reproduction/heap_overflow_positive.c:19',
 'positive_two_independent_replays':len(replays)==1 and len(replays[0]['runs'])==2 and replays[0]['consistent'] and replays[0]['binary_digest']==positive['binary_digest'],
 'negative_no_finding':negative['outcome']=='not_reproduced' and not negative['findings'],
 'broken_build_no_run':broken['outcome']=='engine_failed' and broken['build_exit_code']!=0 and not broken['runs'],
 'original_test_hash':result['inputs_after']['tests/test_dynamic_reproduction_execution.py']=='3205acd925075b04dff129f8876b30da3509d6e717856df4f352f3eb7327fa3b',
 'raw_log_hashes':all(hashlib.sha256((E/pathlib.PurePosixPath(v['path']).relative_to('/work')).read_bytes()).hexdigest()==v['sha256'] for e in events for v in ([e.get('stdout'),e.get('stderr')] if e['event']=='compiler_or_probe_process' else list(e.get('streams',{}).values())) if v)}
report={'passed':all(checks.values()),'checks':checks,'raw_files':saved['raw_files'],'raw_bytes':saved['raw_bytes'],'source_evidence':str(E)}
(LOCAL/'asan-independent-review.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report))
assert report['passed']
