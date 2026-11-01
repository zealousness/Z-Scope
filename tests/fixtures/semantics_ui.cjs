const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');
const crypto=require('node:crypto');
const {chromium}=require(process.env.ZSCOPE_UI_PLAYWRIGHT_MODULE);
(async()=>{
 const base=process.env.ZSCOPE_SEM_BASE, output=process.env.ZSCOPE_SEM_OUTPUT;
 const browser=await chromium.launch({headless:true,executablePath:process.env.ZSCOPE_UI_CHROMIUM});
 const context=await browser.newContext({viewport:{width:1440,height:1000},locale:'zh-CN',recordVideo:{dir:output,size:{width:1440,height:1000}}});
 const page=await context.newPage();page.setDefaultTimeout(12000);
 const errors=[],external=[],captures=[];
 page.on('pageerror',error=>errors.push(error.message));
 page.on('response',async response=>{if(response.status()>=400 && response.url().includes('/api/semantics')) console.log(response.status(),await response.text());});
 await context.route('**/*',route=>{if(!route.request().url().startsWith(base)){external.push(route.request().url());return route.abort();}return route.continue();});
 const app=page.locator('.sem-shell').first();
 async function capture(name){
  await page.addStyleTag({content:'*,*::before,*::after{transition:none!important;animation:none!important}'});
  await page.evaluate(()=>{if(!document.getElementById('capture-label')){const label=document.createElement('div');label.id='capture-label';label.textContent='演示数据 · 实际产品界面';label.style='position:fixed;bottom:5px;right:7px;z-index:9999;background:#e9effc;color:#415579;font:10px sans-serif;padding:4px 7px;border-radius:4px';document.body.append(label);}});
  for(const width of [1440,390,1280,1920]){
   await page.setViewportSize({width,height:width===390?844:1000});
   await page.evaluate(()=>new Promise(resolve=>requestAnimationFrame(()=>requestAnimationFrame(resolve))));
   assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth+1),false,name+' overflow '+width);
   if(width===390) assert.ok(await page.locator('.ui-sidebar').evaluate(el=>el.getBoundingClientRect().right<=1),'mobile sidebar must be closed');
   if(width===1440||width===390){const file=name+'-'+width+'.png';await page.screenshot({path:output+'/'+file});captures.push(file);}
  }
  await page.setViewportSize({width:1440,height:1000});
 }
 try{
  await page.goto(base+'/?project='+process.env.ZSCOPE_SEM_FRESH+'#tab=semantics',{waitUntil:'networkidle'});
  await page.getByRole('heading',{name:'让分析理解你的项目接口。'}).waitFor();
  await capture('first-primitives');
  await page.getByRole('button',{name:'没有已知自定义原语',exact:true}).click();
  await page.getByText('已声明：没有已知自定义原语。仍将基于内置原语发现包装接口。',{exact:true}).waitFor();
  await page.goto(base+'/?project='+process.env.ZSCOPE_SEM_PROJECT+'#tab=semantics',{waitUntil:'networkidle'});
  await page.locator('.sem-row').first().waitFor();
  assert.equal(await page.locator('.sem-row').count(),30);
  await page.locator('.sem-row button').first().focus();await page.keyboard.press('Enter');
  await page.getByRole('heading',{name:'buffer_allocate_000',exact:true}).waitFor();
  await page.evaluate(()=>window.scrollTo(0,0));await capture('discover-review');
  await page.reload({waitUntil:'networkidle'});
  await page.getByRole('heading',{name:'buffer_allocate_000',exact:true}).waitFor();
  await page.locator('.sem-row button').nth(1).click();await page.getByRole('heading',{name:'buffer_allocate_001',exact:true}).waitFor();
  await page.goBack();await page.getByRole('heading',{name:'buffer_allocate_000',exact:true}).waitFor();
  await page.getByText('编辑条目 YAML / 待审草稿',{exact:true}).click();
  const editor=page.getByLabel('原语条目 YAML',{exact:true});
  const initial=await editor.inputValue();await editor.fill(initial+'\nreview_note: browser draft\n');
  page.once('dialog',dialog=>dialog.accept());await page.reload({waitUntil:'networkidle'});
  await page.getByText('编辑条目 YAML / 待审草稿',{exact:true}).click();
  assert.match(await editor.inputValue(),/browser draft/);
  await page.getByRole('button',{name:'保存待审草稿',exact:true}).click();
  await page.getByText('待审稿已保存。确认或拒绝仍需单独提交。',{exact:true}).waitFor();
  await page.getByRole('button',{name:'预检确认',exact:true}).click();
  await page.getByRole('button',{name:'提交本批审阅决定',exact:true}).waitFor();
  await page.getByRole('button',{name:'提交本批审阅决定',exact:true}).click();
  await page.getByText('审阅决定已保存。完成全部条目后，请确认本轮审阅摘要。',{exact:true}).waitFor();
  // Select one legal and one unknown-condition candidate: whole batch must fail.
  await page.getByRole('checkbox',{name:'选择 project:allocate_001',exact:true}).check();
  await page.getByRole('checkbox',{name:'选择 project:allocate_002',exact:true}).check();
  await page.getByRole('button',{name:'预检勾选项确认',exact:true}).click();
  await page.locator('.sem-error:visible').filter({hasText:'applies'}).waitFor();
  assert.equal(await page.getByRole('button',{name:'提交本批审阅决定',exact:true}).isVisible(),false);
  await page.getByLabel('搜索原语候选',{exact:true}).fill('buffer_allocate_094');
  await page.waitForFunction(()=>document.querySelectorAll('.sem-row').length===1);
  await page.locator('.sem-row button').click();
  await page.getByRole('heading',{name:'buffer_allocate_094',exact:true}).waitFor();
  await page.getByRole('button',{name:'接口更新 / 重新发现',exact:true}).click();
  await page.evaluate(()=>window.scrollTo(0,0));await capture('interface-update');
  await page.getByRole('button',{name:'高级 YAML',exact:true}).click();
  const yamlEditor=page.getByLabel('项目语义 YAML',{exact:true});await yamlEditor.waitFor();
  await page.waitForFunction(()=>!document.querySelector('[aria-label="项目语义 YAML"]').disabled);
  await yamlEditor.press('Control+End');await page.keyboard.insertText('\n# preserved browser comment\n');
  // A second tab writes a different declaration/version while this draft stays local.
  const other=await context.newPage();await other.goto(page.url(),{waitUntil:'networkidle'});
  await other.getByRole('button',{name:'高级 YAML',exact:true}).click();
  const otherEditor=other.getByLabel('项目语义 YAML',{exact:true});
  await other.waitForFunction(()=>!document.querySelector('[aria-label="项目语义 YAML"]').disabled);
  await otherEditor.press('Control+End');await other.keyboard.insertText('\n# other tab edit\n');
  await Promise.all([other.waitForResponse(r=>r.url().endsWith('/api/semantics/save')),other.getByRole('button',{name:'保存语义文档',exact:true}).click()]);
  await page.getByRole('button',{name:'保存语义文档',exact:true}).click();
  await page.locator('.sem-error:visible').filter({hasText:'文档已更新'}).waitFor();
  assert.match(await yamlEditor.inputValue(),/preserved browser comment/);
  await other.close();
  assert.deepEqual(errors,[]);assert.deepEqual(external,[]);
  const hash=file=>crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex');
  const sources=Object.fromEntries(['index.html','dashboard_semantics.js','dashboard_semantics.css','dashboard_navigation.js'].map(file=>[file,hash(path.resolve(__dirname,'../../zscope/web/static',file))]));
  fs.writeFileSync(output+'/browser-receipt.json',JSON.stringify({captured_at:new Date().toISOString(),sources,images:Object.fromEntries(captures.map(file=>[file,hash(path.join(output,file))])),scope:'Real HTML/CSS/JS and HTTP; synthetic 95-candidate evidence; no scanner or model',widths:[390,1280,1440,1920],captures,checks:['explicit none declaration','pagination','keyboard entry selection','refresh and back navigation','draft survives reload','individual review','invalid batch atomic rejection','search','project isolation','two-tab conflict preserves draft','offline local resources'],errors,external},null,2));
 }finally{
  await context.close();const video=await page.video()?.path();if(video)fs.renameSync(video,output+'/primitives-flow.webm');await browser.close();
 }
})().catch(error=>{console.error(error);process.exitCode=1;});
