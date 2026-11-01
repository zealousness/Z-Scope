// Config/report HTTP is real; report content and isolated request contracts are controlled.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');

async function requestContracts() {
  const context = vm.createContext({window:{}, console});
  vm.runInContext(fs.readFileSync('zscope/web/static/dashboard_workbench.js','utf8'),context);
  const state = {...context.window.ZScopeWorkbench, canStartJob:()=>true, workbenchId:()=> 'request',
    preparation:{project:{root:'controlled'}}, persistJobCommand(){}, async sendJobCommand(){}};
  state.workbenchStopAt=''; await state.startWorkbenchJob();
  assert.ok(!Object.hasOwn(state.jobCommand.payload,'stop_at'),'blank must allow saved-config fallback');
  state.workbenchStopAt='2099-01-02T12:34:56'; await state.startWorkbenchJob();
  assert.equal(state.jobCommand.payload.stop_at,new Date(state.workbenchStopAt).toISOString());
  state.jobCommand=null; state.job={job_id:'job',revision:2,capabilities:{resume:true},stop_at:'old'};
  state.jobsError=''; state.jobBusy=false; await state.controlJob('resume');
  assert.equal(state.jobCommand.url,'/api/jobs/resume');
  assert.ok(!Object.hasOwn(state.jobCommand.payload,'stop_at'),'resume cannot carry old or form deadline');
  assert.match(state.gapText({kind:'entry_instance_coverage_incomplete'}),/覆盖仍不完整/);
  assert.match(state.gapText({kind:'entry_instance_analysis_unwired'}),/尚未接入/);
  for (const flag of [undefined,null,'false',0]) assert.equal(state.instanceCompleteness(flag),'未测量');
  assert.equal(state.instanceCompleteness(false),'不完整');
}

(async()=>{
  await requestContracts();
  const {chromium}=require(process.env.ZSCOPE_UI_PLAYWRIGHT_MODULE);
  const base=process.env.ZSCOPE_UI_BASE_URL, output=process.env.ZSCOPE_UX_BOUNDARY_EVIDENCE;
  const scenario=process.env.ZSCOPE_UX_BOUNDARY_CASE;
  const browser=await chromium.launch({headless:true,executablePath:process.env.ZSCOPE_UI_CHROMIUM});
  const page=await browser.newPage({viewport:{width:1440,height:1100},locale:'zh-CN'});
  const errors=[]; page.on('pageerror',error=>errors.push(error.message));
  try {
    const response=await page.request.get(`${base}/api/findings?view=with_needs_review`);
    assert.equal(response.status(),200); const projected=await response.json();
    const kinds=projected.coverage.gaps.map(gap=>gap.kind);
    assert.equal(kinds.includes('entry_instance_coverage_incomplete'),scenario!=='unknown');
    assert.equal(kinds.includes('entry_instance_analysis_unwired'),scenario==='explicit-unwired');
    await page.goto(base,{waitUntil:'networkidle'});
    await page.getByRole('navigation',{name:'主导航',exact:true}).getByRole('button',{name:'扫描任务',exact:true}).click();
    await page.locator('#wb-v3-preparation').waitFor();
    const preparation=await page.evaluate(()=>Alpine.$data(document.querySelector('[x-data]')).preparation);
    assert.equal(preparation.version3.execution.scheduler_consumer_wired,true);
    const prepText=await page.locator('body').innerText();
    assert.match(prepText,/直到扫描完成/);
    assert.match(prepText,/不会套用 YAML 中旧的停止时间/);
    assert.match(prepText,/到点后后台停止并保存可恢复状态/);
    assert.match(prepText,/不保证只运行剩余项/);
    const modeOptions=await page.getByLabel('本轮分析深度',{exact:true}).locator('option').evaluateAll(items=>items.map(item=>item.value));
    assert.deepEqual(modeOptions,['','fast','balanced','deep']);
    await page.getByLabel('执行方式',{exact:true}).selectOption('daily');
    await page.getByLabel('每天开始时间',{exact:true}).fill('23:00');
    await page.getByLabel('每天停止时间',{exact:true}).fill('07:00');
    assert.equal(await page.getByRole('button',{name:'保存扫描计划',exact:true}).isVisible(),true);
    assert.match(await page.locator('.ui-launch-summary').innerText(),/23:00—07:00/);
    await page.getByLabel('执行方式',{exact:true}).selectOption('once');
    await page.getByLabel('结束方式',{exact:true}).selectOption('deadline');
    await page.getByLabel('本轮停止时间（可选）',{exact:true}).waitFor({state:'visible'});
    await page.getByLabel('结束方式',{exact:true}).selectOption('complete');
    await page.getByLabel('本轮停止时间（可选）',{exact:true}).waitFor({state:'hidden'});
    await page.getByRole('navigation',{name:'主导航',exact:true}).getByRole('button',{name:'项目设置',exact:true}).click();
    await page.locator('#wb-v3-editor').waitFor();
    await page.locator('details.ui-planned-settings > summary').click();
    const editor=await page.locator('#wb-v3-editor').innerText();
    assert.match(editor,/配置窗口已用于扫描停止令牌与持久作业/);
    assert.match(editor,/max_workers 仍仅声明/);
    assert.match(editor,/平台仅声明/);
    assert.doesNotMatch(editor,/时区、配置停止时间和最大工作数目前仅解析声明/);
    await page.screenshot({path:`${output}/config-desktop.png`,fullPage:true});
    await page.getByRole('navigation',{name:'主导航',exact:true}).getByRole('button',{name:'覆盖与诊断',exact:true}).click();
    await page.evaluate(async()=>{const state=Alpine.$data(document.querySelector('[x-data]')); await state.loadAcceptance(); state.setAcceptanceFilter('gaps');});
    await page.getByRole('heading',{name:'覆盖范围与剩余工作',exact:true}).waitFor();
    const body=await page.locator('body').innerText();
    assert.equal(body.includes('编译实例扫描覆盖仍不完整'),scenario!=='unknown');
    assert.equal(body.includes('逐编译实例的分析与验证尚未接入'),scenario==='explicit-unwired');
    assert.match(body,/零问题不代表安全/);
    if(scenario==='unknown') assert.match(body,/未测量/);
    await page.screenshot({path:`${output}/coverage-desktop.png`,fullPage:true});
    await page.setViewportSize({width:390,height:844});
    await page.screenshot({path:`${output}/coverage-mobile.png`,fullPage:true});
    assert.ok(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth+1));
    assert.deepEqual(errors,[]);
    fs.writeFileSync(`${output}/receipt.json`,JSON.stringify({scenario,scope:'Controlled config/report real HTTP rendering; no scan/model execution',projected,preparation,errors},null,2));
  } finally {await browser.close();}
})().catch(error=>{console.error(error);process.exit(1);});
