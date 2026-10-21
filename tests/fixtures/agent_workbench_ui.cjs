// Explicit fake transport: tests frontend transitions, never a real job execution.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const {randomUUID} = require('node:crypto');
let transport;
const stored = new Map();
const context = vm.createContext({window: {}, document: {hidden: false},
  fetch: (...args) => transport(...args), setTimeout, clearTimeout, AbortController,
  sessionStorage: {getItem: key => stored.get(key), setItem: (key, value) => stored.set(key, value), removeItem: key => stored.delete(key)},
  crypto: {randomUUID}, confirm: () => true, console});
vm.runInContext(fs.readFileSync('zscope/web/static/dashboard_workbench.js', 'utf8'), context);
vm.runInContext(fs.readFileSync('zscope/web/static/dashboard_config.js', 'utf8'), context);
context.ZScopeDashboardReports = {};
context.ZScopeWorkbench = context.window.ZScopeWorkbench;
context.ZScopeConfigEditor = context.window.ZScopeConfigEditor;
vm.runInContext(fs.readFileSync('zscope/web/static/index.html', 'utf8').split('<script>\n        function zscopeApp()')[1].split('</script>')[0].replace(/^/, 'function zscopeApp()'), context);
const notices = [];
function app() { return {...context.window.ZScopeWorkbench, jobs: [], jobEvents: [],
  dispositionDrafts: {}, acceptanceIssues: [], showToast: (...args) => notices.push(args)}; }
function reply(value, status = 200) { return {ok: status < 400, status, json: async () => value}; }
function job(id, revision = 1, extra = {}) { return {job_id: id, run_id: `run-${id}`, revision,
  status: 'running', progress: {completed: 2, total: null}, capabilities: {cancel: true, resume: false}, ...extra}; }
const schema = 'zscope.scan-jobs.v1';
function state(report, issue, revision = 0, disposition = null) {
  return {schema: 'zscope.acceptance-dispositions.v1', report_id: report, issue_id: issue,
    revision, context_revision: 'scope-current', build_context_id: 'build', writable: true, disposition};
}
function delay() { let resolve; const promise = new Promise(r => {resolve = r;}); return {promise, resolve}; }
// The real-owner browser uses UTC. Chromium canonicalizes zero seconds away;
// Playwright fill rejects a noncanonical string even when the date itself is valid.
function utcDeadlineInputValue(date) { return date.toISOString().slice(0,19).replace(/:00$/, ''); }

if (process.argv.includes('--browser-config')) (async () => {
  const {chromium} = require(process.env.ZSCOPE_UI_PLAYWRIGHT_MODULE);
  const output = process.env.ZSCOPE_UI_CONFIG_EVIDENCE, base = process.env.ZSCOPE_UI_BASE_URL;
  fs.mkdirSync(output,{recursive:true});
  const browser = await chromium.launch({headless:true,executablePath:process.env.ZSCOPE_UI_CHROMIUM});
  const browserContext = await browser.newContext({viewport:{width:1440,height:1100},locale:'zh-CN'});
  const page = await browserContext.newPage(); page.setDefaultTimeout(15000);
  const errors=[], external=[], receipts=[];
  let multiTargetEvidence=null;
  page.on('pageerror',error=>errors.push(error.message));
  page.on('request',request=>{if(!request.url().startsWith(base)) external.push(request.url());});
  const saved = async () => (await (await browserContext.request.get(`${base}/api/config/structured`)).json()).config;
  async function save(expected=200) {
    const responsePromise=page.waitForResponse(response=>response.url()===`${base}/api/config/structured` && response.request().method()==='POST');
    await page.getByRole('button',{name:'保存项目配置',exact:true}).click();
    const response=await responsePromise;
    const body=await response.json(); assert.equal(response.status(),expected,JSON.stringify(body));
    receipts.push({transport:expected===409?'contract-fixture':'real-http',path:'/api/config/structured',status:response.status(),success:body.success});
    await page.waitForFunction(()=>!Alpine.$data(document.querySelector('[x-data]')).configSaving);
    return body;
  }
  try {
    await page.goto(base,{waitUntil:'networkidle'});
    await page.getByRole('button',{name:'编辑项目配置',exact:true}).click();
    await page.locator('#wb-v3-editor').waitFor();
    const original=await saved();
    assert.equal(await page.getByLabel('项目根目录 root',{exact:true}).inputValue(),'.');
    assert.equal(await page.getByLabel('目标 1 编译数据库',{exact:true}).inputValue(),'build/compile_commands.json');
    await page.screenshot({path:`${output}/01-editor-desktop.png`,fullPage:true});
    // Actual service validation errors retain typed values and disable scan starts.
    await page.getByLabel('最大工作数 max_workers',{exact:true}).fill('0');
    await save(400);
    assert.equal(await page.getByLabel('最大工作数 max_workers',{exact:true}).inputValue(),'0');
    await page.getByRole('button',{name:'01项目准备'}).click();
    assert.equal(await page.getByRole('button',{name:'开始夜间扫描',exact:true}).isDisabled(),true);
    await page.getByRole('button',{name:'编辑项目配置',exact:true}).click();
    // Cancel reload must preserve draft and never make its stale preparation startable.
    page.once('dialog',dialog=>dialog.dismiss());
    await page.getByRole('button',{name:'重新载入',exact:true}).click();
    assert.equal(await page.getByLabel('最大工作数 max_workers',{exact:true}).inputValue(),'0');
    await page.getByLabel('最大工作数 max_workers',{exact:true}).fill('5');
    await page.getByLabel('配置停止时间 stop_at',{exact:true}).fill('09:15');
    await page.getByLabel('扫描预设',{exact:true}).selectOption('quick');
    await page.getByLabel('扫描重点 focus',{exact:true}).fill('resources\nmemory');
    await page.getByText('模型 profile：default',{exact:true}).click();
    const profile=page.locator('.wb-config-profile').filter({has:page.getByText('模型 profile：default',{exact:true})});
    assert.equal(await profile.getByLabel('替换 API 密钥',{exact:true}).inputValue(),'');
    assert.equal(await profile.getByLabel('模型 models',{exact:true}).inputValue(),'${ZSCOPE_UI_DUMMY_MODEL}');
    await profile.getByLabel('模型 models',{exact:true}).fill('${ZSCOPE_UI_DUMMY_MODEL}\nfallback-model');
    await save();
    const changed=await saved();
    assert.equal(changed.config_version,3); assert.equal(changed.project.root,'.');
    assert.equal(changed.project.targets[0].compile_commands,'build/compile_commands.json');
    assert.equal(changed.llms.default.api_key,'${ZSCOPE_UI_DUMMY_KEY}');
    assert.deepEqual(changed.llms.wiki_compiler,original.llms.wiki_compiler);
    assert.deepEqual(changed.llms.default.models,['${ZSCOPE_UI_DUMMY_MODEL}','fallback-model']);
    assert.equal(changed.execution.max_workers,5); assert.equal(changed.execution.stop_at,'09:15');
    assert.equal(changed.scan.preset,'quick'); assert.deepEqual(changed.scan.focus,['resources','memory']);
    await page.getByRole('button',{name:'01项目准备'}).click();
    await page.locator('#wb-v3-preparation').waitFor();
    await page.locator('#wb-v3-preparation').getByText('快速检查 · 当前映射为 快速',{exact:true}).waitFor();
    await page.getByRole('button',{name:'编辑项目配置',exact:true}).click();
    await page.setViewportSize({width:390,height:844});
    await page.screenshot({path:`${output}/02-editor-mobile.png`,fullPage:true});
    assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),true);
    await page.getByLabel('运行时区 timezone',{exact:true}).focus(); await page.keyboard.press('Tab');
    assert.equal(await page.getByLabel('配置停止时间 stop_at',{exact:true}).evaluate(element=>element===document.activeElement),true);
    await page.setViewportSize({width:1440,height:1100});
    // Multi-target request uses every row. Until parser-only service lands this is a real 400, never a mocked pass.
    await page.getByRole('button',{name:'添加目标',exact:true}).click();
    await page.getByLabel('目标 2 标识',{exact:true}).fill('second');
    await page.getByLabel('目标 2 编译数据库',{exact:true}).fill('build/second.json');
    const multiReady=process.env.ZSCOPE_UI_MULTI_TARGET_EDITING==='1';
    await save(multiReady?200:400);
    await page.screenshot({path:`${output}/03-multiple-targets-${multiReady?'saved':'pending-service'}.png`,fullPage:true});
    if(multiReady) {
      const targets=(await saved()).project.targets;
      assert.deepEqual(targets,[{id:'service',compile_commands:'build/compile_commands.json'},{id:'second',compile_commands:'build/second.json'}]);
      const prepared=await (await browserContext.request.get(`${base}/api/scan/prepare`)).json();
      assert.equal(prepared.version3.start_capability.startable,false);
      assert.deepEqual(prepared.version3.targets.map(target=>target.id),['service','second']);
      multiTargetEvidence={post_status:200,readback_targets:targets,prepare_startable:prepared.version3.start_capability.startable,prepare_target_ids:prepared.version3.targets.map(target=>target.id)};
      await page.getByRole('button',{name:'01项目准备'}).click();
      await page.locator('#wb-v3-preparation').getByRole('heading',{name:'second',exact:true}).waitFor();
      assert.equal(await page.getByRole('button',{name:'开始夜间扫描',exact:true}).isDisabled(),true);
      await page.getByRole('button',{name:'编辑项目配置',exact:true}).click();
    } else assert.equal((await saved()).project.targets.length,1);
    await page.getByRole('button',{name:'删除目标 2',exact:true}).click(); await save();
    // Labelled transport fixture: a real successful write whose response arrives after a new edit.
    const waiting=delay(), release=delay();
    await page.route('**/api/config/structured',async route=>{
      if(route.request().method()!=='POST') return route.continue();
      const response=await route.fetch(); waiting.resolve(); await release.promise; await route.fulfill({response});
    });
    await page.getByLabel('最大工作数 max_workers',{exact:true}).fill('6');
    await page.getByRole('button',{name:'保存项目配置',exact:true}).click(); await waiting.promise;
    await page.getByLabel('最大工作数 max_workers',{exact:true}).fill('7'); release.resolve();
    await page.getByText('已保存提交版本，后续修改仍未保存',{exact:true}).waitFor();
    assert.equal((await saved()).execution.max_workers,6);
    assert.equal(await page.getByLabel('最大工作数 max_workers',{exact:true}).inputValue(),'7');
    await page.unroute('**/api/config/structured'); await save();
    assert.equal((await saved()).execution.max_workers,7);
    // Contract-only 409 and failed/empty GET. No claim of backend configuration CAS.
    await page.route('**/api/config/structured',route=>route.fulfill({status:409,contentType:'application/json',body:JSON.stringify({error:'fixture config conflict'})}));
    await page.getByLabel('最大工作数 max_workers',{exact:true}).fill('8'); await save(409);
    await page.getByText('配置已发生冲突，草稿已保留。请核对文件后重试或重新载入。',{exact:true}).waitFor();
    await page.screenshot({path:`${output}/04-contract-conflict.png`,fullPage:true});
    await page.unroute('**/api/config/structured');
    await browserContext.setOffline(true);
    await page.getByRole('button',{name:'保存项目配置',exact:true}).click();
    await page.waitForFunction(()=>!Alpine.$data(document.querySelector('[x-data]')).configSaving);
    await page.getByText('保存未确认，草稿已保留',{exact:true}).waitFor();
    assert.equal(await page.getByLabel('最大工作数 max_workers',{exact:true}).inputValue(),'8');
    await browserContext.setOffline(false); await save();
    assert.equal((await saved()).execution.max_workers,8);
    await page.route('**/api/config/structured',route=>route.fulfill({status:200,contentType:'application/json',body:'{"config":{}}'}));
    await page.getByRole('button',{name:'重新载入',exact:true}).click();
    await page.getByText('未找到配置文件',{exact:true}).waitFor();
    assert.equal(await page.getByRole('button',{name:'保存项目配置',exact:true}).isDisabled(),true);
    await page.screenshot({path:`${output}/05-contract-empty.png`,fullPage:true});
    await page.unroute('**/api/config/structured');
    await page.getByRole('button',{name:'重新载入',exact:true}).click(); await page.locator('#wb-v3-editor').waitFor();
    // Language changes use the current public model, including Java's forbidden database field.
    await page.getByLabel('项目语言',{exact:true}).selectOption('java'); await save();
    assert.equal((await saved()).project.language,'java');
    assert.equal('compile_commands' in (await saved()).project.targets[0],false);
    await page.getByLabel('项目语言',{exact:true}).selectOption('c_cpp');
    await page.getByLabel('目标 1 编译数据库',{exact:true}).fill('build/compile_commands.json');
    await page.getByLabel('项目根目录 root',{exact:true}).fill('./');
    await page.getByLabel('运行时区 timezone',{exact:true}).fill('UTC'); await save();
    assert.equal((await saved()).project.root,'./'); assert.equal((await saved()).execution.timezone,'UTC');
    await page.reload({waitUntil:'networkidle'});
    await page.getByRole('button',{name:'编辑项目配置',exact:true}).click(); await page.locator('#wb-v3-editor').waitFor();
    assert.equal(await page.getByLabel('最大工作数 max_workers',{exact:true}).inputValue(),'8');
    assert.deepEqual(errors,[]); assert.deepEqual(external,[]);
    fs.writeFileSync(`${output}/acceptance.json`,JSON.stringify({actual_http:receipts.filter(item=>item.transport==='real-http'),contract_http:receipts.filter(item=>item.transport==='contract-fixture'),real:['v3 single-target load/save/reload','invalid max_workers rejected','relative paths and environment references preserved','untouched named profiles and blank password preserved','save reparses preparation','language and timezone edits','mobile and keyboard','offline retry'],multi_target_service:multiReady?'real save + execution blocked':'pending parser-only service; real rejection observed',multi_target_evidence:multiTargetEvidence,contract_only:['409 response','empty document response','delayed response after real committed write'],external_requests:external,browser_errors:errors,scans_started:0,limitations:['No backend configuration CAS','No real model connection or analysis']},null,2));
    console.log('V3 editor real HTTP acceptance and explicitly labelled fault fixtures passed.');
  } finally { await browser.close(); }
})().catch(error=>{console.error(error);process.exitCode=1;});

if (!process.argv.some(value => value.startsWith('--browser'))) (async () => {
  assert.equal(utcDeadlineInputValue(new Date('2026-10-14T13:31:00Z')),'2026-10-14T13:31');
  assert.equal(utcDeadlineInputValue(new Date('2026-10-14T13:31:01Z')),'2026-10-14T13:31:01');
  // Contract fixture: exact shipped v3 editor and legacy builder, fake HTTP only.
  const editor = context.zscopeApp();
  editor.showToast = () => {};
  editor.loadJobs = async () => {};
  const original = {config_version:3, project:{root:'../relative project',language:'c_cpp',platform:'linux_user',targets:[
    {id:'one',compile_commands:'build/one.json'},{id:'two',compile_commands:'${OTHER_DATABASE}'}]},
    llms:{default:{base_urls:['${MODEL_URL}'],models:['${MODEL_NAME}'],api_key:'${MODEL_KEY}',timeout:null},
      wiki_compiler:{base_urls:['http://dummy.invalid'],models:['wiki'],api_key:'untouched-secret',retry_until_available:true}},
    scan:{preset:'quick',focus:['memory']},execution:{max_workers:'${WORKERS}'}};
  transport = async url => reply(url.includes('/structured') ? {config:original} : {config_path:'/project/zscope.yaml',project:{root:'/project'}});
  await editor.loadStructuredConfig();
  assert.equal(editor.configLoading,false);
  assert.equal(JSON.stringify(editor.buildStructuredConfig()),JSON.stringify(original),'unedited v3 must survive byte-value projection, including omitted fields and profiles');
  editor.v3Form.project.root = './edited'; editor.markConfigDirty();
  assert.equal(editor.preparation,null); assert.equal(editor.canStartJob(),false);
  editor.addV3Target(); editor.v3Form.targets[2].id='three'; editor.v3Form.targets[2].compile_commands='third.json';
  const changed = editor.buildStructuredConfig();
  assert.equal(changed.config_version,3); assert.equal(changed.project.targets.length,3);
  assert.equal(changed.llms.default.api_key,'${MODEL_KEY}');
  assert.equal(JSON.stringify(changed.llms),JSON.stringify(original.llms));
  editor.v3Form.project.language='java';
  assert.equal(editor.buildStructuredConfig().project.targets.some(target => 'compile_commands' in target),false);
  editor.v3Form.project.language='c_cpp';
  assert.equal(editor.buildStructuredConfig().project.targets[1].compile_commands,'${OTHER_DATABASE}');
  transport=async()=>reply({error:'conflict'},409);
  await editor.saveStructuredConfig(); assert.equal(editor.configDirty,true); assert.match(editor.configError,/冲突/);
  assert.equal(editor.v3Form.project.root,'./edited');
  context.confirm=()=>false;
  await editor.reloadStructuredConfig(); assert.equal(editor.v3Form.project.root,'./edited');
  context.confirm=()=>true;
  transport=async()=>{throw new TypeError('offline');};
  await editor.reloadStructuredConfig(); assert.equal(editor.configDirty,true); assert.equal(editor.v3Form.project.root,'./edited');
  transport=async()=>reply({config:{}});
  await editor.reloadStructuredConfig();
  assert.equal(editor.structuredConfigAvailable,true); assert.equal(editor.v3Form.project.root,'./edited');
  assert.equal(editor.configDirty,true); assert.match(editor.configError,/草稿已保留/);
  // New edits while saving survive; rebasing handles returning to the original value.
  const lateSave=delay(); let submitted;
  transport=async(_url,options)=>{submitted=JSON.parse(options.body);return lateSave.promise;};
  const saveConfig=editor.saveStructuredConfig();
  editor.v3Form.project.root=original.project.root; editor.markConfigDirty();
  lateSave.resolve(reply({success:true,config:submitted.config})); await saveConfig;
  assert.equal(editor.configDirty,true); assert.equal(editor.buildStructuredConfig().project.root,original.project.root);
  // A slower read cannot replace a newer selection; edits also invalidate in-flight reads.
  const oldRead=delay(); transport=async()=>oldRead.promise;
  const loading=editor.loadStructuredConfig({discard:true});
  editor.v3Form.project.root='new input'; editor.markConfigDirty();
  oldRead.resolve(reply({config:original})); await loading;
  assert.equal(editor.v3Form.project.root,'new input'); assert.equal(editor.configDirty,true);
  const older=delay(); transport=async()=>older.promise;
  const firstLoad=editor.loadStructuredConfig({discard:true});
  const replacement=JSON.parse(JSON.stringify(original)); replacement.project.root='replacement';
  transport=async url=>reply(url.includes('/structured')?{config:replacement}:{project:{root:'replacement'}});
  await editor.loadStructuredConfig({discard:true});
  older.resolve(reply({config:original})); await firstLoad;
  assert.equal(editor.v3Form.project.root,'replacement');
  transport=async()=>reply({error:'config missing'},400);
  await editor.loadStructuredConfig(); assert.equal(editor.structuredConfigAvailable,false);
  const javaDocument=JSON.parse(JSON.stringify(original)); javaDocument.project.language='java';
  javaDocument.project.targets=[{id:'java',compile_commands:null}];
  editor.structuredConfig=javaDocument; editor.populateConfigForm(javaDocument);
  assert.equal(JSON.stringify(editor.buildStructuredConfig()),JSON.stringify(javaDocument));
  const legacy={config_version:2,project:{root:'.',language:'java'},llms:original.llms};
  editor.structuredConfig=legacy; editor.populateConfigForm(legacy);
  assert.equal(editor.v3Form,null); assert.equal(editor.buildStructuredConfig().config_version,2);

  const ui = app();
  transport = async () => reply({error: 'Owner service unavailable'}, 503);
  await ui.loadJobs();
  assert.equal(ui.jobsReady, false);
  ui.preparation = {scan: {depth: 'balanced'}};
  assert.equal(ui.canStartJob(), false, 'unavailable owner must never fall back to the in-memory scan endpoint');
  assert.match(ui.jobsError, /unavailable/);

  // Honest denominators, including malformed or unknown data.
  ui.applyJob(job('A'));
  assert.equal(ui.jobProgressPercent(), null);
  ui.job.progress = {completed: 2, total: 4};
  assert.equal(ui.jobProgressPercent(), 50);
  for (const progress of [{completed: 1, total: 0}, {completed: 9, total: 2}, {completed: null, total: 4}]) {
    ui.job.progress = progress; assert.equal(ui.jobProgressPercent(), null);
  }
  assert.equal(ui.numberText(null), '未测量');
  assert.equal(ui.numberText(0), '0');

  // A late GET cannot change selection, even if another job's response arrives first.
  const old = delay();
  transport = async url => url.includes('job_id=old') ? old.promise : url.includes('/events')
    ? reply({job_id: 'new', events: [], next_seq: 0}) : reply({schema, job: job('new')});
  const loadingOld = ui.loadJob('old');
  await ui.loadJob('new');
  old.resolve(reply({schema, job: job('old', 99)})); await loadingOld;
  assert.equal(ui.job.job_id, 'new');
  ui.applyJob(job('new', 4)); ui.applyJob(job('new', 2));
  assert.equal(ui.job.revision, 4, 'older revisions must not replace state');

  // Failed POSTs may have executed. Retry the exact request id, payload and endpoint.
  ui.jobsReady = true; ui.jobCapabilities = {create: true}; ui.jobsError = '';
  const commands = [];
  transport = async (url, options) => {commands.push({url, body: options.body}); throw new Error('connection lost');};
  await ui.startWorkbenchJob();
  assert.equal(commands.length, 1); assert.ok(ui.jobCommand);
  ui.preparation.config_path = '/project/zscope.yaml'; ui.preparation.project = {root: '/project'};
  ui.persistJobCommand();
  const reopened = app(); reopened.preparation = ui.preparation; reopened.restoreJobCommand();
  assert.equal(reopened.jobCommand.payload.request_id, ui.jobCommand.payload.request_id, 'reload keeps the exact uncertain request');
  const elsewhere = app(); elsewhere.preparation = {config_path: '/project/zscope.yaml', project: {root: '/other'}};
  elsewhere.restoreJobCommand(); assert.equal(elsewhere.jobCommand, null, 'other project must not reuse the command');
  await ui.startWorkbenchJob(); assert.equal(commands.length, 1);
  transport = async (url, options) => {
    if (options?.method !== 'POST') return reply({schema, jobs: [ui.job], capabilities: {create: true}});
    commands.push({url, body: options.body}); return reply({schema, job: job('created')});
  };
  await ui.sendJobCommand();
  assert.deepEqual(commands[0], commands[1]); assert.equal(ui.jobCommand, null);
  assert.equal(ui.job.job_id, 'created');
  assert.equal(JSON.parse(commands[0].body).scan_depth, undefined, 'default must preserve the saved preset');
  ui.workbenchStopAt = '2000-01-01T10:00'; await ui.startWorkbenchJob();
  assert.match(ui.jobActionError, /未来/); assert.equal(commands.length, 2);
  ui.preparation.version3 = {start_capability: {startable: false}};
  assert.equal(ui.canStartJob(), false, 'multi-target or invalid preparation must block create');
  ui.preparation.version3 = {start_capability: {startable: true}};
  assert.equal(ui.canStartJob(), true);
  delete ui.preparation.version3;

  // Polling a previous selection while POST is pending must not steal navigation
  // from a newly created job. Explicit selection is tested separately below.
  ui.workbenchStopAt = '';
  const creatingResponse = delay();
  transport = async (_url, options) => options?.method === 'POST' ? creatingResponse.promise
    : reply({schema, jobs: [job('fresh')], capabilities: {create:true}});
  const creating = ui.startWorkbenchJob();
  const commandRequest = ui.jobRequest;
  await ui.loadJobs({quiet:true}); await ui.loadJob('created',{quiet:true});
  assert.equal(ui.jobRequest,commandRequest);
  creatingResponse.resolve(reply({schema,job:job('fresh')})); await creating;
  assert.equal(ui.job.job_id,'fresh'); assert.equal(ui.activeTab,'jobs');

  // Switching selection during a command does not navigate back on its late result.
  const command = delay();
  transport = async () => command.promise;
  const stopping = ui.controlJob('cancel');
  ui.jobRequest++; ui.applyJob(job('other'));
  command.resolve(reply({schema, job: job('fresh', 2, {status: 'stopping'})})); await stopping;
  assert.equal(ui.job.job_id, 'other');
  assert.equal(ui.jobs.find(item => item.job_id === 'fresh').status, 'stopping');

  // Only explicit service projections affect acceptance classification.
  assert.equal(ui.acceptanceState({validation_status: 'validated', confidence: 1}), 'pending');
  assert.equal(ui.acceptanceState({validation_status: 'rejected'}), 'pending');
  ui.applyAcceptance({report_id: 'report', findings: [
    {issue_id: '1', location: 'a.c:1', acceptance: {state: 'confirmed', build_context_id: 'one'}},
    {issue_id: '2', location: 'a.c:1', acceptance: {state: 'business_conditional', build_context_id: 'two'}},
    {issue_id: '3', acceptance: {state: 'pending'}},
    {issue_id: '4', acceptance: {state: 'ruled_out'}},
  ], coverage: {completeness: 'partial', gaps: [{message: 'Unknown link target'}], deferred_count: null}});
  for (const bucket of ['confirmed','business_conditional','pending','ruled_out','gaps']) assert.equal(ui.acceptanceCount(bucket), 1);
  ui.setAcceptanceFilter('business_conditional'); ui.acceptanceSearch = 'two';
  assert.equal(ui.acceptanceFiltered()[0].issue_id, '2', 'same line/different build must remain distinct');
  assert.equal(ui.acceptanceIssues.length, 4);
  transport = async () => reply({report_id: 'new report', findings: []});
  await ui.openAcceptanceIssue(ui.acceptanceIssues[0]); assert.match(ui.acceptanceError, /报告已变化/);

  // Switching from historic result to current report invalidates a late historic read.
  const historic = delay(); ui.applyJob(job('history', 1, {report: {available: true}}));
  transport = async url => url.startsWith('/api/jobs/result') ? historic.promise : reply({report_id: 'current', findings: []});
  const historicLoading = ui.openJobResult(); await ui.loadAcceptance();
  historic.resolve(reply({job_id: 'history', report_available: true, findings: {report_id: 'old', findings: []}}));
  await historicLoading; assert.equal(ui.acceptanceReportId, 'current');

  // A late failure from an earlier attempt must not mark a resumed run as failed.
  ui.applyJob(job('history', 2, {report:{available:true}}));
  const oldResultFailure=delay(); transport=async()=>oldResultFailure.promise;
  const oldResultRead=ui.openJobResult();
  ui.applyJob(job('history', 3, {run_id:'new-attempt',report:{available:false}}));
  oldResultFailure.resolve(reply({error:'old attempt report unavailable'},404));
  await oldResultRead;
  assert.equal(ui.jobResultError,'','late result failure belongs only to its original run');
  ui.jobResultError='previous run error';
  ui.applyJob(job('other-history',1,{report:{available:false}}));
  assert.equal(ui.jobResultError,'','selecting another job clears the old result error');

  // Explicit binding contract negatives complement the real owner/resume scenario.
  const boundJob=job('bound',1,{input_revision:'input-a',report:{available:true,report_id:'bytes-a'}});
  const binding={job_id:'bound',run_id:boundJob.run_id,input_revision:'input-a',report_id:'bytes-a'};
  ui.applyJob(boundJob);
  for(const changed of [{run_id:'old-run'},{input_revision:'old-input'},{report_id:'old-bytes'},null]) {
    transport=async()=>reply({job_id:'bound',report_available:true,report_id:'bytes-a',
      binding:changed===null?null:{...binding,...changed},findings:{report_id:'wrong-scope',findings:[]}});
    await ui.openJobResult(); assert.notEqual(ui.acceptanceReportId,'wrong-scope');
    assert.match(ui.jobResultError,/范围已变化/);
  }
  transport=async()=>reply({job_id:'bound',report_available:true,report_id:'bytes-a',binding,
    findings:{report_id:'bound-scope',findings:[]}});
  await ui.openJobResult(); assert.equal(ui.acceptanceReportId,'bound-scope');
  ui.applyJob({...boundJob,revision:2,input_revision:'input-b'});
  assert.equal(ui.acceptanceLoaded,false); assert.equal(ui.acceptanceReportId,'');
  assert.match(ui.acceptanceError,/输入范围已变化/);
  transport=async()=>reply({report_id:'current',findings:[]}); await ui.loadAcceptance();
  ui.applyJob({...boundJob,revision:3,run_id:'yet-another-run'});
  assert.equal(ui.acceptanceReportId,'current','explicit current report view is independent of job selection');

  // Entering detail from the acceptance page must not discard unsaved legacy review.
  const localDraft = {issue_id: 'draft', user_rebuttal: 'Local unsaved note', _validation_dirty: true};
  ui.currentReportId = 'current'; ui.dirtyValidationFindings = () => [localDraft];
  ui.ingestFindingsPayload = data => {ui.reportViewCache = {with_needs_review: data.findings};};
  ui.selectFinding = finding => {ui.selectedFinding = finding;};
  transport = async () => reply({report_id: 'current', findings: [{issue_id: 'draft', user_rebuttal: 'Server note'}]});
  await ui.openAcceptanceIssue({issue_id: 'draft'});
  assert.equal(ui.selectedFinding.user_rebuttal, 'Local unsaved note');
  ui.currentReportId = 'older';
  await ui.openAcceptanceIssue({issue_id: 'draft'});
  assert.match(ui.acceptanceError, /复核草稿尚未保存/);

  // Independent disposition drafts survive switches and conflict; no verdict is posted.
  ui.currentReportId = 'report';
  transport = async url => reply(state('report', url.includes('issue_id=A') ? 'A' : 'B'));
  await ui.loadDisposition({issue_id: 'A'}); ui.disposition.reason = 'Acknowledged for this release';
  await ui.loadDisposition({issue_id: 'B'}); await ui.loadDisposition({issue_id: 'A'});
  assert.equal(ui.disposition.reason, 'Acknowledged for this release');
  const saving = delay(); let savedPayload;
  transport = async (_url, options) => {savedPayload = JSON.parse(options.body); return saving.promise;};
  const save = ui.saveDisposition();
  transport = async () => reply(state('report', 'B'));
  await ui.loadDisposition({issue_id: 'B'});
  saving.resolve(reply({...state('report', 'A', 1, {type: 'risk_accept', reason: savedPayload.reason}), success: true}));
  await save;
  assert.equal(ui.disposition.issue_id, 'B');
  assert.deepEqual(Object.keys(savedPayload).sort(), ['base_context_revision','base_revision','build_context_id','issue_id','reason','report_id','request_id','type']);
  assert.equal(savedPayload.base_context_revision, 'scope-current');
  assert.equal(ui.dispositionDrafts[ui.dispositionKey('report','A')].revision, 1);
  transport = async () => reply(state('report', 'A', 1));
  await ui.loadDisposition({issue_id: 'A'}); ui.disposition.reason = 'Changed';
  transport = async () => reply({error: 'Concurrent update'}, 409);
  await ui.saveDisposition(); assert.equal(ui.disposition.stale, true); assert.equal(ui.disposition.reason, 'Changed');
  transport = () => {throw new Error('stale draft must not post');};
  await ui.saveDisposition();
  transport = async () => reply(state('report', 'C'));
  await ui.loadDisposition({issue_id: 'C'}); ui.disposition.reason = 'Unsent evidence-specific note';
  ui.persistDispositionDraft();
  const fresh = app(); fresh.currentReportId = 'report';
  transport = async () => reply({...state('report', 'C'), context_revision: 'scope-changed'});
  await fresh.loadDisposition({issue_id: 'C'});
  assert.equal(fresh.disposition.reason, 'Unsent evidence-specific note');
  assert.equal(fresh.disposition.revision, 0);
  assert.equal(fresh.disposition.context_revision, 'scope-current');
  assert.equal(fresh.disposition.stale, true, 'even a revision-zero draft is bound to its evidence context');
  transport = async () => reply({...state('report', 'D'), context_revision: null});
  await fresh.loadDisposition({issue_id: 'D'}); assert.equal(fresh.disposition, null);
  assert.match(fresh.dispositionError, /证据版本/);
  assert.equal(ui.gapText({kind: 'validation_not_completed', detail: 'count=2'}), '验证尚未完成（2 项）');
  console.log('Workbench contract behavior: passed (explicit fake transport; no backend acceptance claim).');
})().catch(error => {console.error(error); process.exitCode = 1;});

if (process.argv.includes('--browser-jobs')) (async () => {
  const {spawn, execFileSync} = require('node:child_process');
  const {chromium} = require(process.env.ZSCOPE_UI_PLAYWRIGHT_MODULE);
  const output = process.env.ZSCOPE_UI_JOB_EVIDENCE;
  const project = process.env.ZSCOPE_UI_JOB_PROJECT;
  const configPath = process.env.ZSCOPE_UI_JOB_CONFIG;
  const portfile = `${project}/web-port.txt`;
  fs.mkdirSync(output, {recursive: true});
  const browser = await chromium.launch({headless: true, executablePath: process.env.ZSCOPE_UI_CHROMIUM});
  let serverChild; let page; let base; let port = 0;
  const errors = []; const externalRequests = []; const evidence = [];
  const testContext = await browser.newContext({viewport: {width:1440,height:1100}, locale:'zh-CN', timezoneId:'UTC'});
  async function until(probe, description, timeout = 30000) {
    const deadline = Date.now() + timeout; let value;
    while (Date.now() < deadline) {
      value = await probe(); if (value) return value;
      await new Promise(resolve => setTimeout(resolve, 150));
    }
    throw new Error(`Timed out: ${description}; last=${JSON.stringify(value)}`);
  }
  async function launchWeb() {
    serverChild = spawn(process.env.ZSCOPE_UI_PYTHON, [process.env.ZSCOPE_UI_SERVER_HELPER,
      '--serve-jobs-fixture', configPath, process.env.ZSCOPE_UI_JOB_SCANNER, String(port), portfile], {env: process.env});
    let logs = '';
    serverChild.stderr.on('data', value => {logs += value.toString();});
    serverChild.on('error', error => {logs += error.message;});
    await until(async () => {
      if (serverChild.exitCode !== null) throw new Error(`Web helper exited: ${logs}`);
      if (!fs.existsSync(portfile)) return false;
      port = Number(fs.readFileSync(portfile, 'utf8')); base = `http://127.0.0.1:${port}`;
      try {return (await testContext.request.get(`${base}/api/version`, {timeout:1000})).ok();} catch (_) {return false;}
    }, 'actual Web process startup');
  }
  async function stopWeb() {
    if (!serverChild || serverChild.exitCode !== null) return;
    const child = serverChild;
    await new Promise(resolve => {child.once('exit', resolve); child.kill('SIGTERM');});
  }
  async function newPage() {
    page = await testContext.newPage(); page.setDefaultTimeout(15000);
    page.on('pageerror', error => errors.push(error.message));
    page.on('request', request => {if (!request.url().startsWith(base)) externalRequests.push(request.url());});
    await page.addInitScript(() => document.addEventListener('DOMContentLoaded', () => {
      const label=document.createElement('div'); label.textContent='真实 HTTP / SQLite / 独立 owner · 受控扫描器输出合成证据 · 非真实扫描';
      label.style='padding:10px;background:#e0f2fe;color:#164e63;text-align:center;font-weight:bold'; document.body.prepend(label);
    }));
    await page.goto(base, {waitUntil:'networkidle'});
  }
  async function api(path, data) {
    const response = data ? await testContext.request.post(`${base}${path}`, {data}) : await testContext.request.get(`${base}${path}`);
    const body = await response.json(); return {status:response.status(), body};
  }
  async function getJob(id) { const response=await api(`/api/jobs/detail?job_id=${id}`); assert.equal(response.status,200); return response.body.job; }
  async function terminal(id, status) { return until(async () => {const item=await getJob(id);return item.status===status && item;}, `job ${status}`); }
  async function uiPost(name, path, expected = 202) {
    const pending = page.waitForResponse(response => response.url()===`${base}${path}` && response.request().method()==='POST');
    await page.getByRole('button',{name,exact:true}).click();
    const response=await pending; const body=await response.json(); assert.equal(response.status(),expected,JSON.stringify(body));
    evidence.push({path,status:response.status(),job_id:body.job?.job_id,run_id:body.job?.run_id,code:body.code});
    return body;
  }
  async function verifyProjection() {
    // Actual HTTP responses are delayed, never replaced with invented job bindings.
    await page.evaluate(()=>Alpine.$data(document.querySelector('[x-data]')).destroy());
    const ui = expression => page.evaluate(expression);
    const select = id => page.evaluate(id=>Alpine.$data(document.querySelector('[x-data]')).loadJob(id),id);
    const open = () => ui(()=>Alpine.$data(document.querySelector('[x-data]')).openJobResult());
    const state = () => ui(()=>{const s=Alpine.$data(document.querySelector('[x-data]'));return {
      job:s.job,loaded:s.acceptanceLoaded,issues:s.acceptanceIssues.length,report:s.acceptanceReportId,
      source:s.acceptanceSource,binding:s.acceptanceBinding,error:s.jobResultError,notice:s.acceptanceError,tab:s.activeTab};});
    fs.writeFileSync(`${project}/scanner-mode.txt`,'partial');
    const created=await api('/api/jobs',{request_id:crypto.randomUUID()}); assert.equal(created.status,202);
    const id=created.body.job.job_id;
    const first=await terminal(id,'partial'); await select(id); await open();
    const firstResult=(await api(`/api/jobs/result?job_id=${id}`)).body;
    assert.equal(firstResult.binding.run_id,first.run_id);
    assert.equal(firstResult.binding.input_revision,first.input_revision);
    assert.equal(firstResult.review_scope.filename,`${project}/report.json`);
    assert.equal(firstResult.review_scope.shared_with_current,true);
    assert.equal(firstResult.findings.report_id,(await api('/api/findings?view=with_needs_review')).body.report_id);
    assert.equal((await state()).loaded,true);
    await page.getByRole('button',{name:/待验证.*证据/}).click();
    await page.screenshot({path:`${output}/01-bound-partial-report.png`,fullPage:true});
    async function resume(previous, changeInput=false) {
      if(changeInput) fs.appendFileSync(`${project}/unit.c`,'\n/* real projection input change */\n');
      const response=await api('/api/jobs/resume',{job_id:id,base_revision:previous.revision,request_id:crypto.randomUUID()});
      assert.equal(response.status,202,JSON.stringify(response.body));
      const next=await terminal(id,'partial'); assert.notEqual(next.run_id,previous.run_id);
      assert.equal(next.report.report_id,previous.report.report_id,'identical synthetic bytes do not identify a run');
      if(changeInput) assert.notEqual(next.input_revision,previous.input_revision);
      evidence.push({check:'actual same-hash resume',previous:previous.run_id,current:next.run_id,
        previous_input:previous.input_revision,current_input:next.input_revision,report_hash:next.report.report_id});
      return next;
    }
    const second=await resume(first);
    await ui(()=>{Alpine.$data(document.querySelector('[x-data]')).activeTab='jobs';});
    await open(); // Server has advanced while this page still holds the earlier run.
    const mismatched=await state();
    await select(id);
    const invalidated=await state();
    fs.writeFileSync(`${output}/projection-reproduction.json`,JSON.stringify({first:firstResult.binding,
      actual_current:second,mismatched_response_state:mismatched,after_refresh:invalidated},null,2));
    await page.screenshot({path:`${output}/02-resumed-scope.png`,fullPage:true});
    assert.equal(mismatched.tab,'jobs','a response from a different server attempt must not navigate to old local scope');
    assert.match(mismatched.error,/运行|范围|报告/);
    assert.equal(invalidated.loaded,false,'a displayed previous-run result must be invalidated after real resume');
    assert.equal(invalidated.issues,0); assert.equal(invalidated.report,'');
    assert.match(invalidated.notice,/运行|输入|报告/);
    let current=second;
    for(const kind of ['success','unavailable']) {
      await open(); assert.equal((await state()).loaded,true);
      if(kind==='unavailable') fs.unlinkSync(current.report.path);
      const fetched=delay(), release=delay(); let actualResponse;
      const handler=async route=>{
        const response=await route.fetch(); actualResponse=await response.json();
        fetched.resolve(); await release.promise; await route.fulfill({response});
      };
      await page.route('**/api/jobs/result?*',handler);
      await ui(()=>{const s=Alpine.$data(document.querySelector('[x-data]'));s.activeTab='jobs';window.projectionRead=s.openJobResult();});
      await fetched.promise;
      assert.equal(actualResponse.report_available,kind==='success');
      const next=await resume(current,kind==='unavailable');
      await select(id);
      release.resolve(); await ui(()=>window.projectionRead);
      await page.unroute('**/api/jobs/result?*',handler);
      const after=await state();
      assert.equal(after.loaded,false); assert.equal(after.issues,0); assert.equal(after.tab,'jobs');
      assert.equal(after.error,'','old actual success/unavailable response must not pollute resumed run');
      evidence.push({check:`late actual ${kind} response rejected`,response_binding:actualResponse.binding,
        response_reason:actualResponse.reason,new_run:next.run_id,new_input:next.input_revision,state:after});
      current=next;
    }
    await open(); const last=await state();
    assert.equal(last.loaded,true); assert.equal(last.binding.run_id,current.run_id);
    assert.equal(last.binding.input_revision,current.input_revision);
    assert.equal((await api(`/api/jobs/result?job_id=${id}`)).body.questions.length,1);
    assert.equal(current.pending_count,null);
    await page.getByRole('button',{name:/待验证.*证据/}).click();
    await page.screenshot({path:`${output}/03-current-run-report.png`,fullPage:true});
    await page.setViewportSize({width:390,height:844});
    await page.screenshot({path:`${output}/04-current-run-mobile.png`,fullPage:true});
    assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),true);
    assert.equal((await api('/api/jobs')).body.jobs.length,1);
    assert.equal(fs.readFileSync(`${project}/scanner-starts.txt`,'utf8').trim().split('\n').length,4);
    assert.deepEqual(errors,[]); assert.deepEqual(externalRequests,[]);
    fs.writeFileSync(`${output}/browser-evidence.json`,JSON.stringify({platform:process.platform,
      actual_backend:['HTTP','SQLite','detached owner','shared projection','four real attempts'],checks:evidence,
      final_state:last,review_scope:firstResult.review_scope,page_errors:errors,external_requests:externalRequests,
      limitation:'Synthetic scanner/report, actual service bindings. HTTP responses delayed without replacing payloads; no full scan or queue claim.'},null,2));
  }
  try {
    await launchWeb(); await newPage();
    if(process.env.ZSCOPE_UI_JOB_SCENARIO==='projection') {await verifyProjection(); return;}
    await page.locator('#wb-v3-preparation').waitFor();
    await page.getByRole('heading',{name:'service',exact:true}).waitFor();
    await page.getByRole('heading',{name:'second',exact:true}).waitFor();
    assert.equal(await page.getByRole('button',{name:'开始夜间扫描',exact:true}).isDisabled(),true);
    await page.getByText('扫描重点：已声明，尚未参与执行。',{exact:true}).waitFor();
    await page.locator('#wb-v3-preparation').getByText(/多目标执行尚未接入/).waitFor();
    assert.equal((await page.locator('body').innerText()).includes('dummy-api-key-material'),false);
    assert.equal((await page.locator('body').innerText()).includes('dummy-endpoint.invalid'),false);
    await page.screenshot({path:`${output}/01-v3-multiple-targets.png`,fullPage:true});
    await page.getByRole('button',{name:'编辑项目配置',exact:true}).click();
    if (process.env.ZSCOPE_UI_MULTI_TARGET_EDITING === '1') {
      await page.locator('#wb-v3-editor').waitFor();
      assert.equal(await page.getByRole('button',{name:'保存项目配置',exact:true}).isEnabled(),true);
    } else {
      assert.equal(await page.getByRole('button',{name:'保存项目配置',exact:true}).isDisabled(),true);
      await page.getByText('配置加载失败，可重新载入',{exact:true}).waitFor();
    }
    await page.getByRole('button',{name:'01项目准备'}).click();
    await page.setViewportSize({width:390,height:844});
    await page.screenshot({path:`${output}/02-v3-mobile.png`,fullPage:true});
    assert.equal(await page.evaluate(() => document.documentElement.scrollWidth<=innerWidth),true);
    await page.setViewportSize({width:1440,height:1100});

    // Edit only the disposable saved input; no HTTP backend response is fabricated.
    const document = JSON.parse(fs.readFileSync(configPath,'utf8'));
    document.project.targets = document.project.targets.slice(0,1);
    fs.writeFileSync(configPath,JSON.stringify(document));
    await page.getByRole('button',{name:'重新检查',exact:true}).click();
    await page.getByRole('button',{name:'重试连接',exact:true}).click();
    await until(() => page.getByRole('button',{name:'开始夜间扫描',exact:true}).isEnabled(),'single target start');
    await page.screenshot({path:`${output}/03-v3-single-target.png`,fullPage:true});

    // Commit a real job, then discard its HTTP response. Reload retains the command.
    const requests=[]; let drop=true;
    await page.route('**/api/jobs',async route => {
      if(route.request().method()!=='POST') return route.continue();
      requests.push(JSON.parse(route.request().postData()));
      if(!drop) return route.continue();
      drop=false; const committed=await route.fetch(); assert.equal(committed.status(),202);
      await route.abort('connectionfailed');
    });
    await page.getByRole('button',{name:'开始夜间扫描',exact:true}).click();
    await page.getByText(/上次请求结果尚未确认/).waitFor();
    await page.reload({waitUntil:'networkidle'});
    const retry=await uiPost('核对并重试原请求','/api/jobs');
    assert.deepEqual(requests[0],requests[1]); assert.equal(requests[0].scan_depth,undefined);
    assert.equal(requests[0].stop_at,undefined);
    assert.ok(retry.job.resolved_stop_time,'blank explicit input must use saved v3 window');
    assert.equal(new Intl.DateTimeFormat('en-GB',{timeZone:document.execution.timezone,hour:'2-digit',minute:'2-digit',hourCycle:'h23'}).format(new Date(retry.job.resolved_stop_time)),document.execution.stop_at);
    evidence.push({check:'blank request uses saved config stop window',configured:document.execution.stop_at,timezone:document.execution.timezone,resolved:retry.job.resolved_stop_time});
    await page.unroute('**/api/jobs');
    const id=retry.job.job_id; const firstRun=retry.job.run_id;
    const running=await until(async()=>{const item=await getJob(id);return item.status==='running' && item.owner.state==='alive' && fs.existsSync(`${project}/scanner-starts.txt`) && item;},'real owner and scanner');
    assert.equal((await api('/api/jobs')).body.jobs.length,1);
    assert.equal(fs.readFileSync(`${project}/scanner-starts.txt`,'utf8').trim().split('\n').length,1);
    await page.getByRole('button',{name:'02夜间作业'}).click(); await page.getByRole('button',{name:'刷新作业',exact:true}).click();
    await page.getByText('执行进程在线',{exact:true}).waitFor();
    assert.equal(await page.locator('progress.wb-progress').isVisible(),false);
    await page.screenshot({path:`${output}/04-real-owner-running.png`,fullPage:true});
    evidence.push({check:'real owner running',pid:running.owner.process_id,job_id:id,run_id:firstRun,input_revision:running.input_revision});

    // Both the browser tab and the Web process are independent of the detached owner.
    await page.close(); await stopWeb(); await launchWeb(); await newPage();
    const afterRestart=await getJob(id);
    assert.equal(afterRestart.owner.process_id,running.owner.process_id);
    assert.equal(afterRestart.run_id,firstRun); assert.equal(afterRestart.status,'running');
    await page.getByRole('button',{name:'02夜间作业'}).click();
    await page.getByText('执行进程在线',{exact:true}).waitFor();
    await testContext.setOffline(true); await page.getByRole('button',{name:'刷新作业',exact:true}).click();
    await page.getByText(/最近状态可能已过期/).waitFor();
    assert.equal(await page.getByRole('button',{name:'停止并保留已有结果',exact:true}).isDisabled(),true);
    await page.screenshot({path:`${output}/05-real-disconnected.png`,fullPage:true});
    await testContext.setOffline(false); await page.getByRole('button',{name:'刷新作业',exact:true}).click();
    await until(()=>page.getByRole('button',{name:'停止并保留已有结果',exact:true}).isEnabled(),'control restored');

    // Hold the UI request while a second actual client finishes cancellation.
    // An already-stopping job accepts another stop idempotently; only the stale
    // request delivered after the terminal transition should receive HTTP 409.
    await page.route('**/api/jobs/cancel',async route => {
      const current=await getJob(id);
      const cancel=await api('/api/jobs/cancel',{job_id:id,base_revision:current.revision,request_id:randomUUID()});
      assert.equal(cancel.status,200);
      await terminal(id,'cancelled');
      await route.continue();
    });
    await uiPost('停止并保留已有结果','/api/jobs/cancel',409);
    await page.unroute('**/api/jobs/cancel');
    await terminal(id,'cancelled'); await page.getByRole('button',{name:'刷新作业',exact:true}).click();
    await page.getByText('已停止',{exact:true}).first().waitFor();
    await page.screenshot({path:`${output}/06-real-cancel-conflict.png`,fullPage:true});

    // A new attempt must bind changed inputs, not reuse the earlier fingerprint.
    fs.appendFileSync(`${project}/unit.c`,'\n/* changed input for real resume verification */\n');
    fs.writeFileSync(`${project}/scanner-mode.txt`,'complete');
    const resumed=await uiPost('重新尝试此作业','/api/jobs/resume');
    assert.notEqual(resumed.job.run_id,firstRun); assert.notEqual(resumed.job.input_revision,running.input_revision);
    assert.equal(resumed.job.resolved_stop_time,null);
    await terminal(id,'completed'); await page.getByRole('button',{name:'刷新作业',exact:true}).click();
    await page.getByText('作业完成',{exact:true}).first().waitFor();
    await page.getByText('合成问题：谁负责释放此对象？',{exact:true}).waitFor();
    const events=(await api(`/api/jobs/events?job_id=${id}&after_seq=0`)).body;
    assert.ok(events.events.some(event=>event.kind==='input_revoked'));
    const result=(await api(`/api/jobs/result?job_id=${id}`)).body;
    assert.equal(result.report_available,true); assert.equal(result.findings.findings[0].acceptance.state,'pending');
    const completedJob=await getJob(id);
    assert.equal(completedJob.status,'completed');
    assert.equal(completedJob.owner.state,'exited');
    const completedTitle=await page.locator('#wb-jobs-title').innerText();
    assert.equal(completedTitle,'作业状态与进展，有据可查。','completed jobs must not claim execution is continuing');
    evidence.push({check:'completed job uses neutral heading',status:completedJob.status,owner_state:completedJob.owner.state,heading:completedTitle});
    await page.screenshot({path:`${output}/07-real-result-ready.png`,fullPage:true});
    fs.writeFileSync(`${output}/remaining-semantics.json`,JSON.stringify({
      actual_backend:'HTTP/SQLite/detached owner; controlled scanner with no queue receipt',
      pending_count:completedJob.pending_count,questions:completedJob.questions,
      progress:completedJob.progress,rendered_remaining:await page.locator('dt').filter({hasText:/^剩余工作$/}).locator('..').locator('dd').innerText(),
    },null,2));
    assert.equal(completedJob.pending_count,null,'business questions must not become a measured remaining queue');
    assert.equal(await page.locator('dt').filter({hasText:/^剩余工作$/}).locator('..').locator('dd').innerText(),'未测量');
    await page.getByText('已记录业务问题：1',{exact:true}).waitFor();
    await page.getByRole('button',{name:'查看本轮结果',exact:true}).click();
    await page.getByRole('button',{name:/待验证.*证据/}).click();
    await page.getByRole('heading',{name:'合成扫描器结果 · 不代表真实分析',exact:true}).waitFor();
    await page.screenshot({path:`${output}/08-real-job-acceptance.png`,fullPage:true});
    await page.getByRole('button',{name:/覆盖缺口.*未覆盖/}).click();
    await page.getByText(/编译实例扫描覆盖仍不完整/).waitFor();

    // Historical result stays bound to its own snapshot, and cannot edit a newer report.
    execFileSync(process.env.ZSCOPE_UI_PYTHON,['-c',
      "from pathlib import Path; import sys; from zscope.reporting.json_io import read_report, write_report_atomic; path=Path(sys.argv[1]); report=read_report(path); report['issues']=[]; write_report_atomic(path,report)",
      `${project}/report.json`],{env:process.env});
    const historic=(await api(`/api/jobs/result?job_id=${id}`)).body;
    const currentReport=(await api('/api/findings?view=with_needs_review')).body;
    assert.equal(currentReport.findings.length,0);
    assert.notEqual(historic.findings.report_id,currentReport.report_id);
    await page.getByRole('button',{name:'02夜间作业'}).click(); await page.getByRole('button',{name:'查看本轮结果',exact:true}).click();
    await page.getByRole('button',{name:/待验证.*证据/}).click();
    await page.getByRole('button',{name:'查看证据与反馈',exact:true}).click();
    await page.getByText(/当前报告已变化/).waitFor();
    await page.screenshot({path:`${output}/09-real-historic-boundary.png`,fullPage:true});

    // This verifies only the actual process deadline, explicitly not JOB04/JOB06.
    // A real network failure for an old report must not remain on a new job.
    await page.getByRole('button',{name:'02夜间作业'}).click();
    await testContext.setOffline(true);
    await page.getByRole('button',{name:'查看本轮结果',exact:true}).click();
    await page.waitForFunction(()=>!!Alpine.$data(document.querySelector('[x-data]')).jobResultError);
    const previousResultError=await page.evaluate(()=>Alpine.$data(document.querySelector('[x-data]')).jobResultError);
    await testContext.setOffline(false);
    await page.getByRole('button',{name:'刷新作业',exact:true}).click();
    fs.writeFileSync(`${project}/scanner-mode.txt`,'wait');
    await page.getByRole('button',{name:'01项目准备'}).click();
    const stopInput=page.getByLabel('本轮停止时间（可选）',{exact:true});
    await stopInput.waitFor({state:'visible'});
    await until(()=>page.getByRole('button',{name:'开始夜间扫描',exact:true}).isEnabled(),'ready to create deadline job');
    // Deterministic zero/nonzero-second checks use the actual product control.
    // Neither probe submits a job; the live 12-second window is computed afterward.
    for (const iso of ['2026-10-14T13:31:00.000Z','2026-10-14T13:31:01.000Z']) {
      const value=utcDeadlineInputValue(new Date(iso));
      await stopInput.fill(value);
      assert.equal(await stopInput.inputValue(),value);
      assert.equal(await stopInput.evaluate(input=>new Date(input.value).toISOString()),iso);
    }
    const requestedStop=new Date(Math.floor((Date.now()+12000)/1000)*1000);
    const stopTime=utcDeadlineInputValue(requestedStop);
    await stopInput.fill(stopTime);
    assert.equal(await stopInput.inputValue(),stopTime);
    assert.equal(await stopInput.evaluate(input=>new Date(input.value).toISOString()),requestedStop.toISOString());
    const deadlineJob=await uiPost('开始夜间扫描','/api/jobs');
    assert.equal(await page.evaluate(()=>Alpine.$data(document.querySelector('[x-data]')).jobResultError),'');
    evidence.push({check:'old result error cleared on new job',old_job:id,new_job:deadlineJob.job.job_id,old_error:previousResultError});
    assert.equal(Date.parse(deadlineJob.job.resolved_stop_time),requestedStop.getTime());
    evidence.push({check:'native deadline value preserved',requested_local:stopTime,requested_utc:requestedStop.toISOString(),accepted_stop_time:deadlineJob.job.resolved_stop_time,window_ms:12000});
    await terminal(deadlineJob.job.job_id,'partial');
    await page.getByRole('button',{name:'刷新作业',exact:true}).click();
    await page.getByText('部分完成，可重新尝试',{exact:true}).first().waitFor();
    await page.screenshot({path:`${output}/10-real-process-deadline.png`,fullPage:true});
    fs.writeFileSync(`${project}/scanner-mode.txt`,'complete');
    const retryDeadline=await uiPost('重新尝试此作业','/api/jobs/resume');
    assert.equal(retryDeadline.job.resolved_stop_time,null);
    await terminal(deadlineJob.job.job_id,'completed'); await page.getByRole('button',{name:'刷新作业',exact:true}).click();
    await page.getByRole('heading',{name:'作业完成',exact:true}).waitFor();
    await page.setViewportSize({width:390,height:844});
    await page.screenshot({path:`${output}/11-real-jobs-mobile.png`,fullPage:true});
    assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),true);
    const finalList=(await api('/api/jobs')).body.jobs;
    assert.equal(finalList.length,2); assert.ok(finalList.every(item=>item.status==='completed'));
    assert.deepEqual(errors,[]); assert.deepEqual(externalRequests,[]);
    fs.writeFileSync(`${output}/browser-evidence.json`,JSON.stringify({platform:process.platform,browser:await browser.version(),
      actual_backend:['saved v3 preparation','HTTP','SQLite','detached owner','scanner subprocess','Web process restart'],
      verified:['multi-target start blocked','single-target preserves saved preset','committed create with lost response and exact idempotent retry',
        'one scanner for repeated request','same owner and run after Web process restart','offline controls disabled and reconnect',
        'real concurrent-client terminal conflict','changed source causes new input revision and input_revoked event',
        'bound job report projects pending and independent coverage gaps','historical report cannot edit current report',
        'process deadline becomes partial','resume does not inherit expired deadline','390px mobile without horizontal overflow'],
      checks:evidence,first_owner_pid:running.owner.process_id,final_jobs:finalList,
      page_errors:errors,external_requests:externalRequests,
      limitation:'Controlled scanner outputs synthetic reports. No LLM/full scan. This controlled scanner checks process deadline behavior only; cooperative queue draining and fine-grained recovery are not measured by this fixture.'},null,2));
    console.log('Actual v3 + HTTP + SQLite + owner browser checks passed; scanner evidence is synthetic.');
  } catch(error) {
    if(page && !page.isClosed()) await page.screenshot({path:`${output}/failure.png`,fullPage:true});
    throw error;
  } finally { await stopWeb(); await browser.close(); }
})().catch(error=>{console.error(error);process.exitCode=1;});

if (process.argv.includes('--browser')) (async () => {
  const {chromium} = require(process.env.ZSCOPE_UI_PLAYWRIGHT_MODULE);
  const output = process.env.ZSCOPE_UI_EVIDENCE || 'artifacts/ui-workbench-20261014';
  fs.mkdirSync(output, {recursive: true});
  const browser = await chromium.launch({headless: true, executablePath: process.env.ZSCOPE_UI_CHROMIUM});
  let page;
  try {
    const browserContext = await browser.newContext({viewport: {width: 1440, height: 1050}, locale: 'zh-CN'});
    page = await browserContext.newPage();
    page.setDefaultTimeout(10000);
    const errors = []; const externalRequests = [];
    page.on('pageerror', error => errors.push(error.message));
    page.on('request', request => {if (!request.url().startsWith(process.env.ZSCOPE_UI_BASE_URL)) externalRequests.push(request.url());});
    await page.addInitScript(() => document.addEventListener('DOMContentLoaded', () => {
      const label = document.createElement('div'); label.textContent = '合成验收证据 · 真实 HTTP / SQLite 服务 · 非扫描结果';
      label.style = 'padding:10px;background:#e0f2fe;color:#164e63;text-align:center;font-weight:bold'; document.body.prepend(label);
    }));
    const base = process.env.ZSCOPE_UI_BASE_URL;
    const httpEvidence = [];
    async function findings() { return (await page.request.get(`${base}/api/findings?view=with_needs_review`)).json(); }
    const actual = await findings();
    const states = actual.findings.map(item => item.acceptance.state);
    assert.equal(states.filter(value => value === 'confirmed').length, 1);
    assert.equal(states.filter(value => value === 'business_conditional').length, 1);
    assert.equal(states.filter(value => value === 'pending').length, 3);
    assert.equal(states.filter(value => value === 'ruled_out').length, 1);
    const pendingA = actual.findings.find(item => item.description === '合成证据：构建 A 待验证');
    const pendingB = actual.findings.find(item => item.description === '合成证据：构建 B 待验证');
    const duplicateA = actual.findings.find(item => item.description === '合成证据：构建 A 重复目标');
    assert.equal(pendingA.location, pendingB.location);
    assert.notEqual(pendingA.issue_id, pendingB.issue_id);
    function query(issue) { return new URLSearchParams({report_id: actual.report_id, issue_id: issue.issue_id}).toString(); }
    async function receipt(issue) {
      const response = await page.request.get(`${base}/api/acceptance/dispositions?${query(issue)}`);
      assert.equal(response.status(), 200); return response.json();
    }
    async function openIssue(issue) {
      await page.getByRole('button', {name: '03集中验收'}).click();
      await page.getByRole('button', {name: /待验证.*证据/}).click();
      await page.getByLabel('查找问题', {exact: true}).fill(issue.description);
      await page.locator('.wb-result').filter({hasText: issue.description}).getByRole('button', {name: '查看证据与反馈'}).click();
      await page.locator('.markdown-report').first().waitFor({state: 'visible'});
      const details = page.locator('details.wb-disposition');
      if (await details.getAttribute('open') === null) await details.locator('summary').click();
      await page.getByLabel('原因与依据', {exact: true}).waitFor();
    }
    async function save(status = 200) {
      const response = page.waitForResponse(response => response.url().endsWith('/api/acceptance/dispositions') && response.request().method() === 'POST');
      await page.getByRole('button', {name: '保存处置', exact: true}).click();
      const result = await response;
      assert.equal(result.status(), status, await result.text());
      const data = await result.json();
      httpEvidence.push({status, code: data.code || null, revision: data.revision ?? null});
      await page.getByRole('button', {name: '保存处置', exact: true}).waitFor();
      return data;
    }
    async function reloadDraft() {
      page.once('dialog', dialog => dialog.accept());
      await page.getByRole('button', {name: '重新载入', exact: true}).click();
      await page.getByLabel('原因与依据', {exact: true}).waitFor();
    }
    await page.goto(process.env.ZSCOPE_UI_BASE_URL, {waitUntil: 'networkidle'});
    await page.locator('#wb-prepare-title').waitFor();
    await page.getByText(process.env.ZSCOPE_UI_PROJECT_ROOT, {exact: true}).first().waitFor();
    assert.equal(await page.getByRole('button', {name: '开始夜间扫描', exact: true}).isDisabled(), true);
    await page.screenshot({path: `${output}/01-real-prepare.png`, fullPage: true});
    await page.getByRole('button', {name: '03集中验收'}).click();
    await page.locator('#wb-acceptance-title').waitFor();
    for (const [label, count] of [['已确认', 1], ['条件性', 1], ['待验证', 3]]) {
      assert.equal(await page.locator('.wb-stat').filter({hasText: label}).locator('strong').textContent(), String(count));
    }
    await page.screenshot({path: `${output}/02-real-report.png`, fullPage: true});
    await page.getByRole('button', {name: /^已排除（1）$/}).click();
    await page.getByRole('heading', {name: '合成证据：守卫已排除路径'}).waitFor();
    await page.screenshot({path: `${output}/02b-real-ruled-out.png`, fullPage: true});
    await page.getByRole('button', {name: /条件性.*业务/}).click();
    await page.locator('.wb-result').filter({hasText: 'pool-slot-0-gen-3'}).waitFor();
    await page.screenshot({path: `${output}/02c-real-conditional.png`, fullPage: true});
    // R10: actual business-answer HTTP/SQLite over explicitly synthetic assumptions.
    // No synthetic response grants a successful save or a scan conclusion here.
    const conditional = actual.findings.find(item => item.acceptance.state === 'business_conditional');
    const readBusiness = async () => (await (await page.request.get(`${base}/api/issue_report?issue_id=${encodeURIComponent(conditional.issue_id)}`)).json()).business_review;
    const businessReceipts=[];
    await page.locator('.wb-result').filter({hasText:'pool-slot-0-gen-3'}).getByRole('button',{name:'查看证据与反馈'}).click();
    const answerInput=page.getByLabel('业务前提回答',{exact:true});
    const sourceInput=page.getByLabel('业务约定来源或说明',{exact:true});
    await answerInput.waitFor();
    assert.equal((await readBusiness()).available,true);
    fs.writeFileSync(`${output}/business-control-state.json`,JSON.stringify(await page.evaluate(()=>{
      const app=Alpine.$data(document.querySelector('[x-data]')), input=document.querySelector('[aria-label="业务前提回答"]');
      return {available:app.businessReview?.available,stale:app.businessReview?.stale ?? null,loading:app.reportLoading,saving:app.savingBusinessReview,
        expression:app.savingBusinessReview || app.reportLoading || !app.businessReview?.available || app.businessReview?.stale,
        fieldset:input.closest('fieldset').outerHTML,disabled:input.matches(':disabled')};
    }),null,2));
    assert.equal(await answerInput.isEnabled(),true,'a fresh editable business review must enable its native controls');
    async function saveBusiness(status=200) {
      const waiting=page.waitForResponse(response=>response.url()===`${base}/api/business_review` && response.request().method()==='POST');
      await page.getByRole('button',{name:'保存业务前提',exact:true}).click();
      const response=await waiting, body=await response.json();
      assert.equal(response.status(),status,JSON.stringify(body));
      await page.waitForFunction(()=>!Alpine.$data(document.querySelector('[x-data]')).savingBusinessReview);
      businessReceipts.push({status,revision:body.business_review?.questions[0].expected_revision ?? null});
      return body;
    }
    await answerInput.selectOption('yes'); await sourceInput.fill('合成验收约定第 1 节');
    await saveBusiness();
    assert.equal((await readBusiness()).questions[0].answer,'yes');
    await page.getByText('业务回答与扫描时不同，下次扫描将重新核验受影响结论。',{exact:true}).waitFor();
    await answerInput.selectOption('unknown'); await sourceInput.fill('撤回先前声明，需重新核实');
    await saveBusiness();
    assert.equal((await readBusiness()).questions[0].expected_revision,2);
    assert.equal((await readBusiness()).questions[0].answer,'unknown');
    await page.screenshot({path:`${output}/02d-business-withdrawal.png`,fullPage:true});
    await page.setViewportSize({width:390,height:844});
    await sourceInput.focus(); await page.keyboard.press('Shift+Tab');
    assert.equal(await answerInput.evaluate(input=>input===document.activeElement),true);
    await page.screenshot({path:`${output}/02d-business-mobile.png`,fullPage:true});
    assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),true);
    await page.setViewportSize({width:1440,height:1050});
    await answerInput.selectOption('no'); await sourceInput.fill('并发失败后保留的业务草稿');
    const concurrentReview=await readBusiness(), question=concurrentReview.questions[0];
    const concurrentAnswer=await page.request.post(`${base}/api/business_review`,{data:{report_id:concurrentReview.report_id,issue_id:concurrentReview.issue_id,base_revision:concurrentReview.base_revision,
      answers:[{id:question.id,answer:'yes',source_note:'另一个真实客户端的声明',expected_revision:question.expected_revision}]}});
    assert.equal(concurrentAnswer.status(),200);
    await saveBusiness(409);
    assert.equal(await answerInput.inputValue(),'no');
    assert.equal(await sourceInput.inputValue(),'并发失败后保留的业务草稿');
    await page.screenshot({path:`${output}/02e-business-real-conflict.png`,fullPage:true});
    await openIssue(pendingA);
    await page.getByRole('button',{name:'03集中验收'}).click();
    await page.getByLabel('查找问题',{exact:true}).fill('');
    await page.getByRole('button',{name:/条件性.*业务/}).click();
    await page.locator('.wb-result').filter({hasText:'pool-slot-0-gen-3'}).getByRole('button',{name:'查看证据与反馈'}).click();
    await sourceInput.waitFor();
    assert.equal(await sourceInput.inputValue(),'并发失败后保留的业务草稿','switching issue must retain the failed answer draft');
    await page.getByRole('button',{name:'舍弃前提草稿并重新载入',exact:true}).click();
    await page.waitForFunction(()=>Alpine.$data(document.querySelector('[x-data]')).businessReview?.questions[0].expected_revision===3);
    await answerInput.selectOption('unknown'); await sourceInput.fill('重新核对后撤回声明');
    await browserContext.setOffline(true);
    await page.getByRole('button',{name:'保存业务前提',exact:true}).click();
    await page.waitForFunction(()=>!Alpine.$data(document.querySelector('[x-data]')).savingBusinessReview);
    assert.equal(await sourceInput.inputValue(),'重新核对后撤回声明');
    await browserContext.setOffline(false); await saveBusiness();
    const finalBusiness=await readBusiness();
    assert.equal(finalBusiness.questions[0].answer,'unknown');
    assert.equal(finalBusiness.questions[0].expected_revision,4);
    assert.deepEqual((await findings()).findings.map(item=>item.acceptance),actual.findings.map(item=>item.acceptance));
    fs.writeFileSync(`${output}/business-answers.json`,JSON.stringify({transport:'actual HTTP + SQLite; synthetic assumption evidence',subject_key:question.subject_key,
      responses:businessReceipts,final_answer:'unknown',final_revision:4,checks:['fresh native controls enabled','yes saved','unknown withdraws declaration','real concurrent-client 409 retains draft','issue switch retains failed draft','offline failure retains draft','reconnected save','acceptance states unchanged','390px mobile and keyboard']},null,2));
    await page.getByRole('button',{name:'03集中验收'}).click();
    await page.getByRole('button', {name: /覆盖缺口.*未覆盖/}).click();
    await page.getByText('部分编译实例未完成（2 项）', {exact: true}).waitFor();
    await page.getByText('链接目标尚未核验', {exact: true}).waitFor();
    await page.screenshot({path: `${output}/02d-real-coverage.png`, fullPage: true});
    await page.getByRole('button', {name: /待验证.*证据/}).click();
    await page.locator('.wb-result').filter({hasText: '构建：build-a'}).first().waitFor();
    await page.locator('.wb-result').filter({hasText: '构建：build-b'}).waitFor();
    await page.screenshot({path: `${output}/02e-real-build-identity.png`, fullPage: true});
    await openIssue(pendingA);
    const initial = await receipt(pendingA);
    assert.equal(initial.revision, 0); assert.ok(initial.context_revision);
    await page.getByLabel('原因与依据', {exact: true}).fill('真实服务测试：暂时接受本构建风险，待验证状态保留。');
    const first = await save(); assert.equal(first.revision, 1);
    assert.equal(first.context_revision, initial.context_revision);
    await page.getByText(/当前记录：暂时接受风险/).waitFor();
    await page.screenshot({path: `${output}/03-real-detail.png`, fullPage: true});
    await page.reload({waitUntil: 'networkidle'}); await openIssue(pendingA);
    assert.equal(await page.getByLabel('原因与依据', {exact: true}).inputValue(), first.disposition.reason);

    // Unsent drafts survive page reload and an actual offline browser transition.
    const offlineReason = '刷新与断线后保留的本构建草稿';
    await page.getByLabel('原因与依据', {exact: true}).fill(offlineReason);
    await page.reload({waitUntil: 'networkidle'}); await openIssue(pendingA);
    assert.equal(await page.getByLabel('原因与依据', {exact: true}).inputValue(), offlineReason);
    await browserContext.setOffline(true);
    await page.getByRole('button', {name: '保存处置', exact: true}).click();
    await page.locator('.wb-disposition [role="alert"]').waitFor({state: 'visible'});
    assert.equal(await page.getByLabel('原因与依据', {exact: true}).inputValue(), offlineReason);
    await browserContext.setOffline(false);
    const second = await save(); assert.equal(second.revision, 2);

    // Lose the response *after* the genuine POST commits; retry must not commit twice.
    const sent = []; let loseResponse = true;
    await page.route('**/api/acceptance/dispositions', async route => {
      if (route.request().method() !== 'POST') return route.continue();
      sent.push(JSON.parse(route.request().postData()));
      if (!loseResponse) return route.continue();
      loseResponse = false;
      const committed = await route.fetch(); assert.equal(committed.status(), 200);
      return route.abort('connectionfailed');
    });
    await page.getByLabel('原因与依据', {exact: true}).fill('已提交但回包丢失后的幂等重试');
    await page.getByRole('button', {name: '保存处置', exact: true}).click();
    await page.locator('.wb-disposition [role="alert"]').waitFor({state: 'visible'});
    assert.equal((await receipt(pendingA)).revision, 3);
    const third = await save(); assert.equal(third.revision, 3);
    assert.deepEqual(sent[0], sent[1]);
    await page.unroute('**/api/acceptance/dispositions');
    await page.screenshot({path: `${output}/03b-real-retry.png`, fullPage: true});

    // A second real client commits while the first holds a draft: real HTTP 409.
    await page.getByLabel('原因与依据', {exact: true}).fill('并发冲突后保留的人工草稿');
    const concurrent = await page.request.post(`${base}/api/acceptance/dispositions`, {data: {
      report_id: third.report_id, issue_id: third.issue_id, build_context_id: third.build_context_id,
      base_revision: third.revision, base_context_revision: third.context_revision,
      request_id: randomUUID(), type: 'risk_accept', reason: '第二客户端的真实保存',
    }});
    assert.equal(concurrent.status(), 200);
    await save(409);
    await page.getByText('线上记录、证据或适用构建已变化，草稿已保留。请核对当前版本后重新载入。', {exact: true}).waitFor();
    assert.equal(await page.getByLabel('原因与依据', {exact: true}).inputValue(), '并发冲突后保留的人工草稿');
    await page.screenshot({path: `${output}/03c-real-conflict.png`, fullPage: true});
    await reloadDraft();
    await page.getByLabel('本次处置', {exact: true}).selectOption('followup');
    await page.getByLabel('任务标题（可选）', {exact: true}).fill('补足本构建验证证据');
    await page.getByLabel('原因与依据', {exact: true}).fill('后续修复不代替当前验证结论');
    const followup = await save(); assert.equal(followup.disposition.type, 'followup');
    await page.getByLabel('本次处置', {exact: true}).selectOption('duplicate');
    await page.getByLabel('重复的问题 ID', {exact: true}).fill(pendingB.issue_id);
    await page.getByLabel('原因与依据', {exact: true}).fill('拒绝跨构建重复关联，保留草稿');
    await save(400);
    assert.equal(await page.getByLabel('重复的问题 ID', {exact: true}).inputValue(), pendingB.issue_id);
    await page.getByLabel('重复的问题 ID', {exact: true}).fill(duplicateA.issue_id);
    const duplicate = await save(); assert.equal(duplicate.disposition.type, 'duplicate');
    await page.getByLabel('本次处置', {exact: true}).selectOption('clear');
    const cleared = await save(); assert.equal(cleared.disposition, null);

    // Revision-zero drafts also become stale when the report's evidence changes.
    await openIssue(pendingB);
    const beforeEvidence = await receipt(pendingB); assert.equal(beforeEvidence.revision, 0);
    await page.getByLabel('原因与依据', {exact: true}).fill('尚未保存、绑定旧证据的草稿');
    const reportBytes = fs.readFileSync(process.env.ZSCOPE_UI_REPORT_PATH);
    const changed = JSON.parse(reportBytes);
    changed.issues.find(item => item.id === 'synthetic-pending-b').description = '合成证据：此上下文已变化';
    fs.writeFileSync(process.env.ZSCOPE_UI_REPORT_PATH, JSON.stringify(changed));
    try {
      const afterEvidence = await receipt(pendingB);
      assert.equal(afterEvidence.revision, 0); assert.notEqual(afterEvidence.context_revision, beforeEvidence.context_revision);
      await save(409);
      assert.equal(await page.getByLabel('原因与依据', {exact: true}).inputValue(), '尚未保存、绑定旧证据的草稿');
      await page.screenshot({path: `${output}/03d-real-evidence-conflict.png`, fullPage: true});
    } finally { fs.writeFileSync(process.env.ZSCOPE_UI_REPORT_PATH, reportBytes); }
    await reloadDraft();
    const persistedReason = '重新核对证据后保存；用于 SQLite 重新打开验证';
    await page.getByLabel('原因与依据', {exact: true}).fill(persistedReason);
    const persisted = await save(); assert.equal(persisted.revision, 1);
    fs.writeFileSync(`${output}/u02-persistence.json`, JSON.stringify({query: query(pendingB), revision: persisted.revision, reason: persistedReason}, null, 2));
    const after = await findings();
    assert.deepEqual(after.findings.map(item => item.acceptance), actual.findings.map(item => item.acceptance), 'human dispositions do not promote or hide any acceptance state');
    assert.deepEqual(after.coverage, actual.coverage);
    await page.setViewportSize({width: 390, height: 844});
    await page.getByRole('button', {name: '03集中验收'}).focus(); await page.keyboard.press('Enter');
    await page.locator('#wb-acceptance-title').waitFor({state: 'visible'});
    await page.getByLabel('查找问题', {exact: true}).fill('');
    await page.getByText('处置已保存，验证结论与待验证风险保持独立', {exact: true}).waitFor({state: 'hidden'});
    await page.screenshot({path: `${output}/03e-real-mobile.png`, fullPage: true});
    assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth), true);
    await page.setViewportSize({width: 1440, height: 1050});
    assert.equal(errors.length, 0, errors.join('\n'));
    assert.equal(externalRequests.length, 0, 'No external frontend assets or remote content');

    // The remaining screenshots are visibly labelled simulated contracts. They test
    // rendering/interactions while the real persisted owner is developed separately.
    let currentJob = job('contract-job', 1, {started_at: '2026-10-14T08:00:00Z', updated_at: '2026-10-14T08:20:00Z',
      phase: 'validating', owner: {state: 'alive'}, progress: {completed: 18, total: null, active: 2, deferred: 3},
      pending_count: 6, coverage: {completeness: 'partial', gaps: [{message: '部分链接目标尚未核验'}]},
      questions: [{id: 'q1', question: '注销接口是否等待已开始的回调结束？', affected_scope: 'queue_shutdown',
        impact: '影响回调对象的释放责任', current_assumption: '保留未知，其他工作继续'}], report: {available: false}});
    let disconnected = false; let createCount = 0;
    await page.route('**/api/jobs**', async route => {
      if (disconnected) return route.abort('connectionfailed');
      const url = new URL(route.request().url());
      let payload;
      if (url.pathname === '/api/jobs' && route.request().method() === 'POST') {
        createCount++; payload = {schema, job: currentJob};
      } else if (url.pathname === '/api/jobs/cancel') {
        currentJob = {...currentJob, revision: 2, status: 'partial', owner: {state: 'exited'}, capabilities: {cancel: false, resume: true}};
        payload = {schema, job: currentJob};
      } else if (url.pathname === '/api/jobs/resume') {
        currentJob = {...currentJob, revision: 3, run_id: 'second-run', status: 'running', owner: {state: 'alive'}, capabilities: {cancel: true, resume: false}};
        payload = {schema, job: currentJob};
      } else if (url.pathname === '/api/jobs/events') {
        payload = {schema, job_id: currentJob.job_id, events: [{seq: 1, job_id: currentJob.job_id, run_id: currentJob.run_id,
          at: currentJob.updated_at, message: '正在核对回调释放路径的当前证据'}], next_seq: 1, has_more: false};
      } else if (url.pathname === '/api/jobs/detail') payload = {schema, job: currentJob};
      else payload = {schema, jobs: createCount ? [currentJob] : [], latest_job_id: createCount ? currentJob.job_id : null, capabilities: {create: true, reasons: []}};
      return route.fulfill({json: payload});
    });
    await page.addInitScript(() => document.addEventListener('DOMContentLoaded', () => {
      const label = document.createElement('div'); label.id = 'fixture-label'; label.textContent = '契约数据演示 · 仅验证前端交互，不是后台扫描结果';
      label.style = 'padding:10px;background:#fff0bd;color:#6b4b00;text-align:center;font-weight:bold'; document.body.prepend(label);
    }));
    await page.reload({waitUntil: 'networkidle'});
    await page.getByRole('button', {name: '开始夜间扫描', exact: true}).click();
    await page.getByText('正在运行', {exact: true}).first().waitFor();
    assert.equal(createCount, 1);
    assert.equal(await page.locator('progress.wb-progress').count(), 1);
    assert.equal(await page.locator('progress.wb-progress').isVisible(), false, 'unknown totals render no percentage');
    await page.screenshot({path: `${output}/04-contract-running.png`, fullPage: true});
    await page.getByRole('button', {name: '停止并保留已有结果'}).click();
    await page.getByText('部分完成，可重新尝试', {exact: true}).first().waitFor();
    await page.getByRole('button', {name: '重新尝试此作业'}).click();
    await page.getByText('正在运行', {exact: true}).first().waitFor();
    disconnected = true;
    await page.getByRole('button', {name: '刷新作业'}).click();
    await page.getByText(/最近状态可能已过期/).waitFor();
    assert.equal(await page.getByRole('button', {name: '停止并保留已有结果'}).isDisabled(), true);
    disconnected = false;
    await page.getByRole('button', {name: '刷新作业'}).click();
    await page.getByRole('button', {name: '停止并保留已有结果'}).waitFor();
    await page.reload({waitUntil: 'networkidle'});
    await page.getByRole('button', {name: '02夜间作业'}).click();
    await page.getByText('正在运行', {exact: true}).first().waitFor();
    assert.equal(createCount, 1, 'reloading the UI only reads jobs');
    await page.setViewportSize({width: 390, height: 844});
    await page.getByRole('button', {name: '01项目准备'}).click();
    await page.screenshot({path: `${output}/05-mobile.png`, fullPage: true});
    assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth), true, 'mobile horizontal overflow');
    await page.getByRole('button', {name: '03集中验收'}).focus();
    await page.keyboard.press('Enter');
    await page.locator('#wb-acceptance-title').waitFor({state: 'visible'});
    await page.screenshot({path: `${output}/06-mobile-acceptance.png`, fullPage: true});
    assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth), true);
    await page.setViewportSize({width: 1440, height: 1050});
    assert.equal(errors.length, 0, errors.join('\n'));
    fs.writeFileSync(`${output}/browser-evidence.json`, JSON.stringify({
      platform: process.platform, browser: await browser.version(), viewport: [1440,1050], mobile: [390,844],
      real_http: ['saved config preparation', 'server-projected four states and coverage over synthetic evidence',
        'risk_accept/followup/same-build duplicate/clear', 'cross-build rejection retains draft',
        'SQLite save and reload', 'draft reload', 'offline/reconnect', 'committed POST lost-response idempotency',
        'real concurrent-client 409 retains draft', 'real changed-evidence revision-zero 409 retains draft',
        'unchanged pending states and coverage', '390px mobile and keyboard navigation'],
      real_u02_responses: httpEvidence,
      acceptance_states: states, coverage: actual.coverage,
      contract_only: ['job create','unknown denominator','cancel','resume','disconnect','reconnect','reload'],
      page_errors: errors, external_requests: externalRequests,
      limitation: 'Synthetic inputs and job transport fixture do not verify a real scan, owner, or model.'
    }, null, 2));
    console.log('Browser real HTTP + explicitly labelled contract UI checks: passed.');
  } catch (error) {
    if (page) await page.screenshot({path: `${output}/failure.png`, fullPage: true});
    throw error;
  } finally { await browser.close(); }
})().catch(error => {console.error(error); process.exitCode = 1;});
