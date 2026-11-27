// Synthetic state/transport: these checks never execute an analysis job.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const location = {hash:''};
const listeners={};
const context = vm.createContext({window:{location, history:{pushState(_a,_b,hash){location.hash=hash;}},addEventListener(type,listener){(listeners[type] ||= []).push(listener);}},URLSearchParams,Date});
for (const name of ['dashboard_workbench.js','dashboard_navigation.js']) vm.runInContext(fs.readFileSync('zscope/web/static/'+name,'utf8'),context);
function app() { return {...context.window.ZScopeWorkbench,...context.window.ZScopeNavigation, findings:[],findingFilters:[],filterQuery:'',currentReportId:'report-1',
  findingSearchText:item=>String(item.description||'').toLowerCase(),selectFinding(item){this.selectedFinding=item;},loadRules(){},loadJobs(){},
  loadJob:async function(id){this.job={job_id:id,run_id:'run-1',report:{report_id:'report-1'}};}}; }
(async()=>{
  const current=app(); assert.equal(current.activeTab,'overview');
  assert.equal(current.coverageGapCount(),'未测量');current.acceptanceCoverage={gaps:[]};assert.equal(current.coverageGapCount(),0);
  current.findings=[{issue_id:'a',description:'buffer',acceptance:{state:'confirmed'},location:'a.c',build_context_id:'one'}, {issue_id:'b',acceptance:{state:'ruled_out'}}];
  assert.equal(current.filteredFindings().length,1); current.findingFileFilter='b.c';assert.equal(current.filteredFindings().length,0);current.findingFileFilter='';
  location.hash='#tab=findings&report=report-1&issue=a&q=buffer&build=one';await current.restoreNavigationRoute();
  assert.equal(current.selectedFinding.issue_id,'a');assert.equal(current.findingBuildFilter,'one');assert.equal(current.filterQuery,'buffer');
  current.writeNavigationRoute();assert.match(location.hash,/report=report-1/);
  location.hash='#tab=findings&report=old&issue=a';await current.restoreNavigationRoute();assert.equal(current.selectedFinding,null);assert.match(current.routeError,/另一份报告/);
  location.hash='#tab=findings&issue=a';await current.restoreNavigationRoute();assert.match(current.routeError,/缺少报告身份/);
  location.hash='#tab=acceptance&job=job-1&run=old&report=report-1';await current.restoreNavigationRoute();assert.match(current.routeError,/运行已变化/);
  location.hash='#tab=acceptance&job=job-1&run=run-1&report=old';await current.restoreNavigationRoute();assert.match(current.routeError,/报告已失效/);
  current.loadJob=async function(id){this.job={job_id:id,run_id:'run-1',input_revision:'input-1',report:{report_id:'outer-artifact'}};};
  current.openJobResult=async function(){this.acceptanceReportId='inner-report';this.acceptanceSource='job-1';this.acceptanceBinding={job_id:'job-1',run_id:'run-1',input_revision:'input-1',report_id:'outer-artifact'};this.activeTab='acceptance';};
  location.hash='#tab=coverage&job=job-1&run=run-1&input=input-1&artifact=outer-artifact&report=inner-report';await current.restoreNavigationRoute();assert.equal(current.routeError,'');assert.equal(current.activeTab,'coverage');assert.equal(current.acceptanceReportId,'inner-report');
  current.writeNavigationRoute();assert.match(location.hash,/artifact=outer-artifact/);assert.match(location.hash,/report=inner-report/);
  let refreshedCurrent=false;current.loadAcceptance=()=>{refreshedCurrent=true;};current.navigate('findings');assert.equal(refreshedCurrent,true);
  const drafts=app();const draft={issue_id:'same',build_context_id:'build-1',validation_status:'rejected',user_rebuttal:'typed while loading',_validation_dirty:true};
  drafts.findingIdentity=item=>item.issue_id;drafts.dirtyValidationFindings=()=>[draft];
  drafts.ingestFindingsPayload=function(data){this.currentReportId=data.report_id;return {findings:data.findings};};
  location.hash='';drafts.initNavigation();
  const unload=listeners.beforeunload.at(-1);
  let prevented=false;let event={preventDefault(){prevented=true;}};unload(event);assert.equal(prevented,true);assert.equal(event.returnValue,'');
  drafts.dirtyValidationFindings=()=>[];drafts.businessAnswersChanged=()=>false;drafts.dispositionDrafts={inactive:{type:'risk_accept',reason:'edited',original:'[]'}};
  prevented=false;event={preventDefault(){prevented=true;}};unload(event);assert.equal(prevented,true);
  drafts.dispositionDrafts={};drafts.businessDrafts={inactive:{changed:true}};drafts.businessAnswersChanged=value=>!!value?.changed;
  prevented=false;event={preventDefault(){prevented=true;}};unload(event);assert.equal(prevented,true);
  drafts.businessDrafts={};prevented=false;event={preventDefault(){prevented=true;}};unload(event);assert.equal(prevented,false);
  drafts.dirtyValidationFindings=()=>[draft];
  let result=drafts.ingestFindingsPayload({report_id:'report-1',findings:[{issue_id:'same',build_context_id:'build-1',user_rebuttal:''},{issue_id:'same',build_context_id:'other-build',user_rebuttal:''}]});
  assert.equal(result.findings[0].user_rebuttal,'typed while loading');assert.equal(result.findings[1].user_rebuttal,'');
  result=drafts.ingestFindingsPayload({report_id:'other-report',findings:[{issue_id:'same',build_context_id:'build-1',user_rebuttal:''}]});assert.equal(result.findings[0].user_rebuttal,'');
  let release;current.loadJob=()=>new Promise(resolve=>{release=resolve;});
  location.hash='#tab=acceptance&job=job-1&run=run-1&report=report-1';const pending=current.restoreNavigationRoute();current.navigate('overview');release();await pending;assert.equal(current.activeTab,'overview');assert.equal(current.routeError,'');
  const deadline=app();deadline.canStartJob=()=>true;deadline.workbenchId=()=> 'request';deadline.preparation={project:{root:'.'}};deadline.persistJobCommand=()=>{};deadline.sendJobCommand=async()=>{};
  deadline.workbenchStopAt=new Date(Date.now()+3600000).toISOString();await deadline.startWorkbenchJob(true);assert.equal(deadline.jobCommand.payload.scan_depth,'fast');assert.equal(deadline.jobCommand.payload.stop_at,deadline.workbenchStopAt);
  deadline.jobCommand=null;deadline.workbenchStopAt='2000-01-01T12:00';await deadline.startWorkbenchJob(true);assert.equal(deadline.jobCommand,null);assert.match(deadline.jobActionError,/未来/);
  console.log('Navigation, identity, filter, late route and quick deadline contracts passed.');
  if (process.argv.includes('--browser')) await browserRoutes();
})().catch(error=>{console.error(error);process.exitCode=1;});

async function browserRoutes() {
  const http=require('node:http'),path=require('node:path');
  const report='inner-report',outer='artifact-bytes';
  const finding={issue_id:'issue-a',function:'demo',location:'src/demo.c:3',description:'合成测试问题',impact_level:'high',validation_status:'needs_review',acceptance:{state:'pending',build_context_id:'build-a'}};
  const payload={report_id:report,findings:[finding],coverage:null,report:{metadata:{},summary:{}},views:{default:{issue_count:1},with_needs_review:{issue_count:1}}};
  const job={job_id:'job-a',run_id:'run-a',input_revision:'input-a',revision:1,status:'completed',report:{available:true,report_id:outer},capabilities:{}};
  const config={config_version:3,llms:{default:{base_urls:['http://invalid.example/v1'],models:['synthetic'],api_key:''}},project:{language:'c_cpp',root:'/demo',platform:'linux_user',targets:[{id:'debug',compile_commands:'compile_commands.json'}]},scan:{preset:'quick'},execution:{timezone:'UTC'}};
  const staticRoot=path.resolve('zscope/web/static');
  const server=http.createServer((req,res)=>{
    const url=new URL(req.url,'http://localhost');
    if(url.pathname.startsWith('/api/')) {
      const data=({'/api/findings':{...payload,view:url.searchParams.get('view')||'with_needs_review'},'/api/jobs':{schema:'zscope.scan-jobs.v1',jobs:[job],capabilities:{}},'/api/jobs/detail':{schema:'zscope.scan-jobs.v1',job},'/api/jobs/events':{job_id:job.job_id,events:[],next_seq:0},'/api/jobs/result':{job_id:job.job_id,report_available:true,report_id:outer,binding:{job_id:job.job_id,run_id:job.run_id,input_revision:job.input_revision,report_id:outer},findings:payload},'/api/config/structured':{config},'/api/scan/prepare':{config_path:'/demo/zscope.yaml',project:{root:'/demo',language:'c_cpp'},scan:{},build:{},tools:[],models:[],messages:[]},'/api/user_config/workbook':{sheets:[],sheet_names:[],rows:{},headers:{}},'/api/user_config/warnings':{warnings:[]},'/api/config':{content:'# synthetic'},'/api/rules':{rules:[]},'/api/issue_report':{markdown:'# 合成测试报告',review:{},business_review:null},'/api/acceptance/dispositions':{disposition:null},'/api/cpg_status':{status:'ready'}})[url.pathname]||{};
      res.setHeader('Content-Type','application/json');return res.end(JSON.stringify(data));
    }
    const file=path.resolve(staticRoot,url.pathname==='/'?'index.html':url.pathname.replace(/^\//,''));
    if(!file.startsWith(staticRoot+path.sep)||!fs.existsSync(file)){res.writeHead(404);return res.end();}
    res.setHeader('Content-Type',({'.html':'text/html','.css':'text/css','.js':'text/javascript'})[path.extname(file)]||'application/octet-stream');res.end(fs.readFileSync(file));
  });
  await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
  const {chromium}=require(process.env.ZSCOPE_UI_PLAYWRIGHT_MODULE||'playwright');
  let browser;
  try {
    browser=await chromium.launch({headless:true,executablePath:process.env.ZSCOPE_UI_CHROMIUM||undefined});
    const page=await browser.newPage(),errors=[];page.on('pageerror',error=>errors.push(error.message));
    const base='http://127.0.0.1:'+server.address().port;
    await page.goto(base+'/#tab=findings&report=inner-report&issue=issue-a&view=with_needs_review');
    await page.waitForFunction(()=>window.Alpine&&Alpine.$data(document.querySelector('[x-data]')).selectedFinding?.issue_id==='issue-a'&&!Alpine.$data(document.querySelector('[x-data]')).navigationRestoring);
    assert.equal(await page.evaluate(()=>Alpine.$data(document.querySelector('[x-data]')).routeError),'');
    await page.goto(base+'/#tab=findings&report=stale-report&issue=issue-a');
    await page.waitForFunction(()=>!!Alpine.$data(document.querySelector('[x-data]')).routeError);
    assert.equal(await page.locator('.findings-shell').isVisible(),false);
    assert.match(page.url(),/report=stale-report/);
    await page.goto(base+'/#tab=coverage&job=job-a&run=run-a&input=input-a&artifact=artifact-bytes&report=inner-report');
    await page.waitForFunction(()=>{const s=Alpine.$data(document.querySelector('[x-data]'));return !s.navigationRestoring&&s.acceptanceSource==='job-a';});
    assert.equal(await page.evaluate(()=>Alpine.$data(document.querySelector('[x-data]')).routeError),'');
    await page.reload();await page.waitForFunction(()=>{const s=Alpine.$data(document.querySelector('[x-data]'));return !s.navigationRestoring&&s.acceptanceSource==='job-a';});
    assert.equal(await page.evaluate(()=>Alpine.$data(document.querySelector('[x-data]')).activeTab),'coverage');
    assert.deepEqual(errors,[]);console.log('Real shipped page browser routes: current issue, stale report refusal, exact snapshot scope and reload passed.');
  } finally {if(browser) await browser.close();await new Promise(resolve=>server.close(resolve));}
}
