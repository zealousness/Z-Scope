// Launch the exact official bundled CLI command in a packet-only workspace.
const fs=require('fs'),path=require('path'),crypto=require('crypto'),cp=require('child_process');
const base=__dirname;
const exe='C:/Users/10273/AppData/Local/Programs/DeepSeek Harness/DeepSeek Harness.exe';
const entry='C:/Users/10273/AppData/Local/Programs/DeepSeek Harness/resources/app.asar/dsh/node_modules/@deepseek-ai/dsh-desktop-host/lib/cli.js';
const args=['--expose-internals',entry,'--profile','headless','--patch',path.join(base,'limited-repair.patch.yml'),'--session-id','session-6345b6e2-1245-440c-ae91-f953c08b9655','--json','-'];
const scope=JSON.parse(fs.readFileSync(path.join(base,'submission-scope.json'),'utf8'));
const prompt=fs.readFileSync(path.join(base,'repair-followup1.txt'));
const digest=crypto.createHash('sha256').update(prompt).digest('hex');
if(digest!==scope.followup1_sha256)throw new Error('approved prompt changed');
const original='C:/Users/10273/home/work/Z-Scope_1.31/Z-Scope/zscope/core/validation/dynamic_reproduction.py';
if(crypto.createHash('sha256').update(fs.readFileSync(original)).digest('hex')!==scope.source_sha256)throw new Error('product changed before submission');
const record={started_utc:new Date().toISOString(),executable:exe,args,cwd:base,
  approved_prompt_sha256:digest,prompt_bytes:prompt.length,new_session:false,attempt:2,
  original_session_unchanged:true,tool_execution:'disabled by temporary overlay and monotonic guard',
  timeout_seconds:900,output_limit_bytes:2*1024*1024,session_id:null};
const recordFile=path.join(base,'submission-result-attempt2.json');
const save=()=>fs.writeFileSync(recordFile,JSON.stringify(record,null,2)+'\n');
save();
const out=fs.createWriteStream(path.join(base,'headless-attempt2.stdout.jsonl'),{flags:'wx'});
const err=fs.createWriteStream(path.join(base,'headless-attempt2.stderr.log'),{flags:'wx'});
const proc=cp.spawn(exe,args,{cwd:base,env:{...process.env,ELECTRON_RUN_AS_NODE:'1'},windowsHide:true,
  stdio:['pipe','pipe','pipe']});
let bytes=0,buffer='',stopped=null;
const stop=reason=>{if(stopped)return;stopped=reason;proc.kill();};
const timeout=setTimeout(()=>stop('timeout'),900000);
proc.stdout.on('data',chunk=>{
  bytes+=chunk.length;out.write(chunk);buffer+=chunk.toString('utf8');
  let end;
  while((end=buffer.indexOf('\n'))>=0){
    const line=buffer.slice(0,end);buffer=buffer.slice(end+1);
    try{
      const event=JSON.parse(line);
      const id=event.sessionId??event.session_id;
      if(typeof id==='string'&&record.session_id===null){record.session_id=id;save();console.log(JSON.stringify({event:'session_identified',session_id:id}));}
      if(event.type==='error')record.last_error_event={type:event.type,message:String(event.message??'').slice(0,1500)};
    }catch{}
  }
  if(bytes>2*1024*1024)stop('output_limit');
});
proc.stderr.on('data',chunk=>{bytes+=chunk.length;err.write(chunk);if(bytes>2*1024*1024)stop('output_limit');});
proc.on('error',error=>{record.startup_error=error.message;save();});
proc.on('close',(code,signal)=>{
  clearTimeout(timeout);out.end();err.end();
  Object.assign(record,{exit_code:code,signal,stopped,output_bytes:bytes,finished_utc:new Date().toISOString()});
  save();console.log(JSON.stringify({event:'headless_finished',session_id:record.session_id,exit_code:code,stopped,output_bytes:bytes,
    error:record.last_error_event??record.startup_error??null}));
  process.exitCode=code===0?0:1;
});
proc.stdin.end(prompt);
