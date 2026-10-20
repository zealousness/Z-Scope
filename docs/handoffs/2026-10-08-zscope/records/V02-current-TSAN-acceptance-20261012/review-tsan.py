"""Independently verify actual saved TSAN evidence before later acceptance lanes."""
import hashlib,json,pathlib
LOCAL=pathlib.Path(__file__).resolve().parent
result=json.loads((LOCAL/'tsan-acceptance-result.json').read_text())
EVIDENCE=pathlib.Path(result['archived_evidence'])
saved=json.loads((EVIDENCE/'observed-executions.json').read_text())
observed=saved['test_observed']; events=saved['events']
checks={}
checks['five_actual_nodes_no_skips']=result['counts']=={'passed':5,'failed':0,'errors':0,'skipped':0} and result['exit_code']==0
checks['isolation_verified']=result['isolation']['verified']
checks['same_image']=result['image_id'].removeprefix('sha256:')=='60e3b821beb946564925285acdc7c87b55bcdf587f4e3006321728dce2900fff'
checks['inputs_unchanged']=not result['changed_inputs']
checks['host_aslr_unchanged']=result['host_aslr_unchanged']
checks['owned_container_cleaned']=result['owned_container_cleanup']['exit_code']==0
checks['approved_exact_policy']=result['seccomp_profile_sha256']=='a56f617057f60b6b569678d7f8cf569a771aab7b721ca5e980199078e0a1a46b'
checks['symbolizer_route_is_frozen_readonly_wrapper']=result['symbolizer_route']['readonly'] and result['symbolizer_route']['sha256']=='e658766da63d258579dc5f1a8eb9ebb28f17b9d30fe18e4e5e51bcc7f04e83b8'
checks['observer_readonly_and_error_free']=not saved['observer_errors']
positive=observed['tsan_positive']
replays=[e['evidence'] for e in events if e['event']=='replay_witness' and e['node'].endswith('::test_tsan_positive_fixture_confirms_through_shared_adjudication')]
assert len(replays)==1
replay=replays[0]
checks['two_independent_replays']=len(replay['runs'])==2 and replay['consistent'] and replay['classifications']==['data-race','data-race']
checks['replay_identity_bound']=replay['binary_digest']==positive['binary_digest'] and replay['plan_digest']==positive['plan_digest']
positive_records=[e['evidence'] for e in events if e['event']=='execute' and e['node'].endswith('::test_tsan_positive_fixture_confirms_through_shared_adjudication')]
checks['positive_primary_and_replay_records']=len(positive_records)==3 and all(r['outcome']=='witness_observed' and r['inputs_verified'] for r in positive_records)
checks['replay_records_match_observed_executions']=all(r['record_id'] in {e['record_id'] for e in positive_records} and r['input_verification_digest'] for r in replay['runs'])
all_findings=[r['findings'][0] for r in [positive,*replay['runs']]]
checks['positive_evidence_object_site_thread_source']=all(f['kind']=='data-race' and f['object_ref']=='shared_counter' and f['frames'] and f['thread'] and f['source_mapping'] and f['site']=='/repo/tests/fixtures/dynamic_reproduction/data_race_positive.c:17' and all('<null>' not in x for x in f['frames']) for f in all_findings)
negative=observed['tsan_negative']
checks['negative_no_finding']=negative['outcome']=='not_reproduced' and not negative['findings']
memory=observed['tsan_memory_limit'];unset=observed['tsan_memory_limit_unset']
checks['memory_actual_sampled_bound']=memory['memory_limit_mode']=='rss_watchdog' and 'rss_watchdog_is_sampled_not_a_kernel_limit' in memory['limitations'] and 'memory_limit_enforced_by_rss_watchdog' in memory['limitations']
checks['unset_memory_truthful']=unset['memory_limit_mode']=='none' and 'memory_limit_not_enforced_for_tsan' in unset['limitations']
flaky=observed['tsan_flaky'];mixed=observed['tsan_flaky_multi_replay']
checks['flaky_ten_samples']=len(flaky['classifications'])==10 and set(flaky['classifications'])<={'none','data-race','engine_failed:timeout'}
checks['flaky_consistency_truthful']=mixed['consistent']==(len(set(mixed['classifications']))==1) and len(mixed['runs'])==7
checks['raw_logs_hashes']=all(hashlib.sha256((EVIDENCE/pathlib.PurePosixPath(v['path']).relative_to('/work')).read_bytes()).hexdigest()==v['sha256'] for e in events for v in ([e.get('stdout'),e.get('stderr')] if e['event']=='compiler_or_probe_process' else list(e.get('streams',{}).values())) if v)
checks['original_test_file_unchanged']=result['inputs_after']['tests/test_dynamic_reproduction_execution.py']=='3205acd925075b04dff129f8876b30da3509d6e717856df4f352f3eb7327fa3b'
report={'passed':all(checks.values()),'checks':checks,'flaky_distribution':flaky,
 'mixed_real_replay_observed':observed['tsan_flaky_mixed_observed'],
 'actual_runner_executions':sum(e['event']=='execute' for e in events),
 'raw_files':saved['raw_files'],'raw_bytes':saved['raw_bytes'],
 'source_result':str(LOCAL/'tsan-acceptance-result.json'),'source_evidence':str(EVIDENCE),
 'first_failed_attempt_preserved':str(LOCAL.parent/'post-probe-acceptance/tsan-acceptance-result.json'),
 'scope':'bounded micro-fixture real TSAN acceptance with approved process-ASLR exception; not arbitrary-project safety'}
(LOCAL/'tsan-independent-review.json').write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps(report))
assert report['passed']
