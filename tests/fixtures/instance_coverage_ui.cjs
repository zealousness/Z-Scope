const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const {randomUUID} = require('node:crypto');
const context = vm.createContext({window: {}, console});
vm.runInContext(fs.readFileSync('zscope/web/static/dashboard_workbench.js', 'utf8'), context);
const app = () => ({...context.window.ZScopeWorkbench});
const payload = () => ({report_id: 'r1', findings: [], report: {metadata: {
  entry_instances: {schema:'zscope.entry-instances.v1', planned_instances: 2, scheduled_instances: 2, scan_coverage_complete: false,
    instances: [{build_context_id:'BASE', usr:'c:@F@f', function_names:['f']}, {build_context_id:'ALT', usr:'c:@F@f', function_names:['f']}],
    instance_analysis: {schema:'zscope.instance-analysis.v1', scheduled_instances:2, analyzed_instances:2, instance_scope_complete:true,
      instances:[{build_context_id:'BASE', usr:'c:@F@f', function_name:'f', status:'analyzed', candidate_count:0},
        {build_context_id:'ALT', usr:'c:@F@f', function_name:'f', status:'analyzed', candidate_count:1, candidates:[{defect_class:'double_free'}]}]}},
  job:{schema:'zscope.scan-session-job.v1', executed_instances:1, cached_instances:1}}}});

async function contract() {
  const state = app(); state.applyAcceptance(payload());
  assert.equal(state.instanceRows().length, 2);
  assert.equal(state.instanceRows()[0].candidate_count, 0);
  assert.match(state.instanceCandidateLabels(state.instanceRows()[1]), /double_free/);
  assert.equal(state.instanceCount(state.instanceJob.executed_instances), '1');
  assert.equal(state.instanceCompleteness(state.instancePlan.scan_coverage_complete), '不完整');
  for (const value of [undefined, null, -1, '2', true, NaN, Infinity, 0.5]) assert.equal(state.instanceCount(value), '未测量');
  assert.equal(state.instanceCount(0), '0');
  state.instanceSearch = 'ALT'; assert.equal(state.instanceFiltered().length, 1);
  const missing = payload(); delete missing.report.metadata.job;
  state.applyAcceptance(missing); assert.equal(state.instanceCount(state.instanceJob?.executed_instances), '未测量');
  assert.equal(state.instanceSearch, '');
  const unknown = payload(); unknown.report.metadata.entry_instances.instance_analysis.instances[0].usr = '';
  state.applyAcceptance(unknown); assert.equal(state.instanceRows().length, 3, 'missing USR must not match the planned instance');
  state.applyAcceptance({report_id:'legacy',findings:[]}); assert.equal(state.instancePlan, null);
  const future=payload(); future.report.metadata.entry_instances.schema='future';
  state.applyAcceptance(future); assert.equal(state.instancePlan, null);
  state.applyAcceptance(payload()); state.invalidateJobAcceptance(); assert.equal(state.instancePlan, null); assert.equal(state.instanceJob, null);
  const live = {job_id:'job',run_id:'run',revision:1,input_revision:'input',report:{available:true,report_id:'bytes'}};
  const pending = app(); pending.job = live; let release;
  pending.workbenchFetch = () => new Promise(resolve => {release=resolve;});
  const read = pending.openJobResult(); pending.job = {...live,run_id:'new-run'};
  release({job_id:'job',report_available:true,report_id:'bytes',binding:{job_id:'job',run_id:'run',input_revision:'input',report_id:'bytes'},findings:payload()});
  await read; assert.equal(pending.instancePlan, null, 'late result cannot restore instances');
  const bound=app(); bound.job=live;
  const result={job_id:'job',report_available:true,report_id:'bytes',binding:{job_id:'job',run_id:'run',input_revision:'input',report_id:'bytes'},findings:payload()};
  bound.workbenchFetch=async()=>result;
  await bound.openJobResult(); assert.equal(bound.instanceJob,null,'unbound historical counters are unknown');
  result.findings.report.metadata.job.job_id='job'; result.findings.report.metadata.job.run_id='run';
  await bound.openJobResult(); assert.equal(bound.instanceJob.executed_instances,1);
  bound.applyJob({...live,run_id:'next-run'}); assert.equal(bound.instancePlan,null,'a new run invalidates all instance data');
  console.log('Instance UI state contracts passed');
}

async function browser() {
  const {chromium} = require(process.env.ZSCOPE_UI_PLAYWRIGHT_MODULE);
  const output = process.env.ZSCOPE_INSTANCE_EVIDENCE, base = process.env.ZSCOPE_UI_BASE_URL;
  const browser = await chromium.launch({headless:true, executablePath:process.env.ZSCOPE_UI_CHROMIUM});
  const page = await browser.newPage({viewport:{width:1440,height:1100},locale:'zh-CN'});
  const errors=[]; page.on('pageerror',error => errors.push(error.message));
  try {
    const created = await page.request.post(`${base}/api/jobs`,{data:{request_id:randomUUID()}});
    assert.equal(created.status(),202,await created.text());
    const id = (await created.json()).job.job_id;
    let job;
    // Real native receipt revalidation includes tool/dependency digests at
    // checkpoint boundaries; allow it to finish rather than inspecting an
    // active checkpoint as though it were a terminal report failure.
    for (let i=0;i<360;i++) {
      job=(await (await page.request.get(`${base}/api/jobs/detail?job_id=${id}`)).json()).job;
      if (!['queued','running','stopping'].includes(job.status)) break;
      await new Promise(resolve=>setTimeout(resolve,500));
    }
    assert.ok(!['queued','running','stopping'].includes(job.status),JSON.stringify(job));
    assert.ok(job.report.available, JSON.stringify(job));
    const envelope=await (await page.request.get(`${base}/api/jobs/result?job_id=${id}`)).json();
    assert.equal(envelope.binding.run_id,job.run_id);
    const plan=envelope.findings.report.metadata.entry_instances;
    assert.ok(plan, 'Bound lightweight report must expose instance metadata');
    assert.equal(plan.instance_analysis.analyzed_instances,2);
    assert.equal(plan.scan_coverage_complete,true);
    assert.equal(plan.instance_analysis.instance_scope_complete,true);
    assert.equal(plan.instance_analysis.consumer_scope_complete,true);
    // Selected-instance execution can complete while whole-build/link coverage
    // remains explicitly incomplete. Never conflate those two measurements.
    assert.equal(envelope.findings.coverage.build_coverage.scan_complete,false);
    const gaps=envelope.findings.coverage.gaps;
    assert.ok(!gaps.some(gap=>gap.kind==='entry_instance_coverage_incomplete'));
    assert.ok(!gaps.some(gap=>gap.kind==='entry_instance_analysis_unwired')); 
    assert.deepEqual(plan.instance_analysis.instances.map(row=>row.candidate_count).sort(),[0,1]);
    fs.writeFileSync(`${output}/http-result.json`,JSON.stringify(envelope,null,2));
    await page.goto(base,{waitUntil:'networkidle'});
    await page.evaluate(async id => {const state=Alpine.$data(document.querySelector('[x-data]')); await state.loadJob(id); await state.openJobResult();},id);
    await page.getByRole('navigation',{name:'主导航',exact:true}).getByRole('button',{name:'覆盖与诊断',exact:true}).click();
    const panel=page.locator('section[aria-labelledby="wb-instance-title"]');
    await panel.waitFor({state:'visible'});
    assert.match(await panel.innerText(),/本实例未产生候选/);
    assert.match(await panel.innerText(),/double_free/);
    assert.match(await panel.innerText(),/完整/);
    assert.match(await page.locator('body').innerText(),/构建扫描覆盖\s*覆盖不完整/);
    assert.doesNotMatch(await page.locator('body').innerText(),/逐编译实例的分析与验证尚未接入/);
    for (const [label,field] of [['本轮实际执行','executed_instances'],['本轮复用结果','cached_instances']]) {
      const value=envelope.findings.report.metadata.job?.[field];
      const expected=Number.isSafeInteger(value) && value>=0 ? String(value) : '未测量';
      assert.equal(await panel.locator('dl').first().locator('div').filter({hasText:label}).locator('dd').innerText(),expected);
    }
    assert.equal(await panel.locator('article').count(),2);
    assert.equal(await panel.locator('details[open]').count(),0);
    await panel.screenshot({path:`${output}/desktop.png`});
    await page.setViewportSize({width:390,height:844});
    await page.evaluate(()=>scrollTo(0,0));
    await page.screenshot({path:`${output}/mobile.png`,fullPage:true});
    assert.ok(await page.evaluate(()=>document.documentElement.scrollWidth <= innerWidth+1),'mobile horizontal overflow');
    await panel.getByText('查看编译身份与范围记录',{exact:true}).first().click();
    assert.match(await panel.innerText(),/c:@F@f/);
    await panel.getByLabel('查找编译实例').fill(plan.instance_analysis.instances[1].build_context_id);
    assert.equal(await panel.locator('article').count(),1);
    await panel.getByLabel('查找编译实例').fill('');
    assert.equal(await panel.locator('article').count(),2);
    assert.deepEqual(errors,[]);
    console.log('Real native ScanSession / detached owner / SQLite / HTTP desktop and mobile passed');
  } finally { await browser.close(); }
}
(async()=>{await contract(); if(process.argv.includes('--browser')) await browser();})().catch(error=>{console.error(error);process.exit(1);});
