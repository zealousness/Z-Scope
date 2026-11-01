// Actual local HTTP and persisted schedules. Project content is synthetic.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const {chromium} = require(process.env.ZSCOPE_UI_PLAYWRIGHT_MODULE);

(async()=>{
  const base=process.env.ZSCOPE_UI_BASE_URL, output=process.env.ZSCOPE_PICKER_EVIDENCE;
  const browser=await chromium.launch({headless:true,executablePath:process.env.ZSCOPE_UI_CHROMIUM});
  const context=await browser.newContext({viewport:{width:1440,height:1000},locale:'zh-CN',timezoneId:'Asia/Taipei',reducedMotion:'reduce'});
  const page=await context.newPage(); page.setDefaultTimeout(15000);
  const errors=[], external=[], captures=[], checks=[];
  page.on('pageerror',error=>errors.push(error.message));
  page.on('request',request=>{if(!request.url().startsWith(base)) external.push(request.url());});
  await page.addInitScript(()=>document.addEventListener('DOMContentLoaded',()=>{
    const label=document.createElement('div');
    label.textContent='真实页面 / 本地 HTTP · 合成工程 · 计划仅保存 · 未执行扫描或模型请求';
    label.style='position:relative;z-index:1000;text-align:center;padding:8px;background:#dff3ff;color:#145075;font:12px sans-serif';
    document.body.prepend(label);
  }));
  async function capture(name){
    await page.addStyleTag({content:'*,*::before,*::after{transition:none!important;animation:none!important}'});
    await page.evaluate(()=>document.activeElement?.blur());
    for(const width of [1440,390,1280,1920]){
      await page.setViewportSize({width,height:width===390?844:1000});
      await page.evaluate(()=>new Promise(resolve=>requestAnimationFrame(()=>requestAnimationFrame(resolve))));
      const overflow=await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth+1);
      assert.equal(overflow,false,`${name}: horizontal overflow at ${width}`);
      if(width===1440||width===390){
        const file=`${name}-${width}.png`; await page.screenshot({path:`${output}/${file}`,fullPage:true});captures.push(file);
      }
    }
    await page.setViewportSize({width:1440,height:1000});
  }
  async function nav(name){
    const toggle=page.getByRole('button',{name:'展开导航',exact:true});
    if(await toggle.isVisible() && await toggle.getAttribute('aria-expanded')!=='true') await toggle.click();
    await page.getByRole('navigation',{name:'主导航',exact:true}).getByRole('button',{name,exact:true}).click();
  }
  try{
    await page.goto(base,{waitUntil:'networkidle'});
    await page.getByRole('heading',{name:'先选择要分析的工程',exact:true}).waitFor();
    assert.equal(await page.locator('.project-recent').count(),0);
    await page.getByLabel('工程目录或 YAML 路径',{exact:true}).fill(process.env.ZSCOPE_PICKER_FIRST);
    await page.getByRole('button',{name:'浏览目录',exact:true}).click();
    await page.getByText('这个目录还没有 YAML 配置，可以按下面的向导创建。',{exact:true}).waitFor();
    await capture('picker');
    await page.getByRole('button',{name:'在此目录创建项目配置',exact:true}).click();
    await page.getByLabel('新项目语言',{exact:true}).selectOption('java');
    assert.equal(await page.getByLabel('新项目默认模式',{exact:true}).inputValue(),'fast');
    checks.push('Java language switches the wizard to fast');
    await page.getByRole('button',{name:'下一步',exact:true}).click();
    assert.equal(await page.getByLabel('新项目模型名称',{exact:true}).inputValue(),'');
    await capture('wizard');
    await page.getByRole('button',{name:'下一步',exact:true}).click();
    const createResponse=page.waitForResponse(r=>r.url().endsWith('/api/projects/create')&&r.request().method()==='POST');
    await page.getByRole('button',{name:'创建并进入项目设置',exact:true}).click();
    const created=await createResponse; assert.equal(created.status(),200);
    await page.waitForURL(url=>url.searchParams.has('project'));
    const identity=new URL(page.url()).searchParams.get('project');
    const library=await (await page.request.get(`${base}/api/projects`)).json();
    assert.equal(library.initial_project_id,identity);
    const project=library.projects.find(item=>item.project_id===identity);
    assert.ok(project);assert.equal(project.root,process.env.ZSCOPE_PICKER_FIRST);
    await page.locator('#wb-v3-editor').waitFor();
    assert.equal(await page.getByLabel('项目语言',{exact:true}).inputValue(),'java');
    const profile=page.locator('.wb-config-profile').filter({has:page.locator('summary').getByText('模型 profile：default',{exact:true})});
    await profile.locator('summary').first().click();
    await profile.getByLabel('服务地址 base_urls',{exact:true}).fill('http://synthetic-model.invalid/v1');
    await profile.getByLabel('模型 models',{exact:true}).fill('synthetic-only-model');
    await profile.getByLabel('替换 API 密钥',{exact:true}).fill('synthetic-only-key');
    const saveResponse=page.waitForResponse(r=>r.url().endsWith('/api/config/structured')&&r.request().method()==='POST');
    await page.getByRole('button',{name:'保存项目配置',exact:true}).click();
    const saved=await saveResponse; assert.equal(saved.status(),200,await saved.text());
    await page.waitForFunction(()=>!Alpine.$data(document.querySelector('[x-data]')).configDirty);
    assert.equal(await page.evaluate(()=>Alpine.$data(document.querySelector('[x-data]')).configExecutionError),'');
    assert.equal(await page.getByText(/unset environment variable/).isVisible(),false);
    await capture('settings');
    await nav('扫描任务');
    await page.getByLabel('开始方式',{exact:true}).selectOption('later');
    const future=await page.evaluate(()=>{const d=new Date(Date.now()+7200000);d.setSeconds(31,0);return new Date(d.getTime()-d.getTimezoneOffset()*60000).toISOString().slice(0,19);});
    await page.getByLabel('扫描开始时间',{exact:true}).fill(future);
    await page.getByRole('button',{name:'保存扫描计划',exact:true}).waitFor();
    await page.waitForFunction(()=>Alpine.$data(document.querySelector('[x-data]')).canCreateSchedule());
    await page.waitForFunction(()=>Alpine.$data(document.querySelector('[x-data]')).preparation?.project.language==='java');
    assert.equal(await page.getByLabel('本轮分析深度',{exact:true}).locator('option[value="balanced"]').evaluate(option=>option.disabled),true);
    await capture('scans');
    const plannedResponse=page.waitForResponse(r=>r.url().endsWith('/api/schedules')&&r.request().method()==='POST');
    await page.getByRole('button',{name:'保存扫描计划',exact:true}).click();
    const planned=await plannedResponse; assert.equal(planned.status(),202,await planned.text());
    const schedule=(await planned.json()).schedule;
    assert.equal(schedule.status,'waiting');assert.equal(schedule.job_id,null);
    await page.locator('.schedule-history-row').getByText('等待开始',{exact:true}).waitFor();
    await capture('jobs');
    await page.reload({waitUntil:'networkidle'});
    await page.locator('.schedule-history-row').getByText('等待开始',{exact:true}).waitFor();
    const cancelledResponse=page.waitForResponse(r=>r.url().endsWith('/api/schedules/cancel')&&r.request().method()==='POST');
    await page.getByRole('button',{name:'取消计划并停止当前运行',exact:true}).click();
    const cancelled=await cancelledResponse; assert.equal(cancelled.status(),200,await cancelled.text());
    await page.locator('.schedule-history-row').getByText('已取消计划',{exact:true}).waitFor();
    checks.push('Future SQLite schedule survives refresh and cancels without creating a job');
    await page.getByRole('button',{name:'切换项目',exact:true}).click();
    await page.getByRole('heading',{name:'先选择要分析的工程',exact:true}).waitFor();
    await page.getByLabel('工程目录或 YAML 路径',{exact:true}).fill(process.env.ZSCOPE_PICKER_SECOND+'/zscope.yaml');
    await page.getByRole('button',{name:'打开 YAML',exact:true}).click();
    await page.waitForURL(url=>url.searchParams.has('project')&&url.searchParams.get('project')!==project.project_id);
    const secondIdentity=new URL(page.url()).searchParams.get('project');
    await page.getByRole('button',{name:'切换项目',exact:true}).waitFor();
    await page.reload({waitUntil:'networkidle'});
    assert.equal(new URL(page.url()).searchParams.get('project'),secondIdentity);
    await page.getByRole('button',{name:'切换项目',exact:true}).waitFor();
    checks.push('Explicit picker bypasses the -c initial project; selected B survives refresh');
    await page.getByRole('button',{name:'切换项目',exact:true}).click();
    await page.locator('.project-recent').filter({hasText:'synthetic-java-project'}).click();
    await page.waitForURL(url=>url.searchParams.get('project')===project.project_id);
    checks.push('Switch to a second project then reopen the first from recent projects');
    assert.deepEqual(errors,[]);assert.deepEqual(external,[]);
    fs.writeFileSync(`${output}/browser-receipt.json`,JSON.stringify({scope:'Actual shipped pages and real HTTP/SQLite over synthetic projects; no scanner/model execution',browser:await browser.version(),captured_at:new Date().toISOString(),project_id:project.project_id,schedule_id:schedule.schedule_id,captures,widths_checked:[390,1280,1440,1920],checks,page_errors:errors,external_requests:external},null,2));
  }catch(error){await page.screenshot({path:`${output}/failure.png`,fullPage:true}).catch(()=>{});throw error;}
  finally{await browser.close();}
})().catch(error=>{console.error(error);process.exit(1);});
