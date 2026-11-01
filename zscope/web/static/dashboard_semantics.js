/* Project semantics is server-authoritative. Drafts never grant scan readiness. */
window.ZScopeSemantics = {
  semStatus: null, semError: '', semNotice: '', semBusy: false, semLoading: false,
  semRows: [], semTotal: 0, semPage: 1, semQuery: '', semFilter: 'todo', semSelected: {},
  semEntry: null, semEntryContent: '', semEntryDirty: false, semEntrySequence: 0, semQueueSequence: 0,
  semId: '', semCollection: 'interfaces', semMobileDetail: false, semReason: '', semCondition: 'always',
  semAdvanced: false, semAdvancedContent: '', semAdvancedBase: null, semAdvancedDirty: false, semAdvancedLoading: false, semAdvancedRequest: 0,
  semDrafts: {}, semTask: null, semEvents: [], semCursor: 0, semTimer: null, semBatch: null,
  semAdding: false, semSymbols: [], semSymbolQuery: '', semSymbolPage: 1, semSymbolTotal: 0, semInventory: null,
  semPrimitive: {symbol_id:'', role:'allocator', carrier:'return', argument:0, dereference:0, members:'', resource_family:'malloc', pairs:'', condition:'always'},
  semWorkbook: 'user_config.xlsx', semMigrationReport: null,
  semStageLabel(stage) { return ({missing:'创建语义文档',undeclared:'声明项目原语',needs_discovery:'需要自动发现',needs_rediscovery:'输入已变化 · 需要重新发现',discovering:'原语准备正在执行',needs_review:'等待人工审阅',ready:'扫描就绪',not_applicable:'Java · 不适用'})[stage] || '读取状态'; },
  semTaskLabel(stage) { return ({queued:'等待执行',preparing_index:'准备 native 索引',native_inventory:'整理接口目录',binding_primitives:'绑定项目原语',discovering_wrappers:'发现包装接口',macros_pointers_dispatchers:'核对宏、指针和 dispatcher',model_review:'模型初审（仅建议）',model_unavailable:'模型不可用，保留确定性候选',merging:'校验并合并结果',completed:'已完成',failed:'执行失败',cancelled:'已取消',cancelling:'正在取消',publishing:'发布结果'})[stage] || stage; },
  semStatusLabel(status) { return ({pending:'待确认',stale:'已失效',confirmed:'已确认',rejected:'已拒绝'})[status] || status; },
  semRole(role) { return ({allocator:'申请资源',deallocator:'释放资源',reallocator:'重新分配',lock:'加锁',unlock:'解锁',copy:'拷贝'})[role] || role; },
  semPredicate(value) {
    if(!value) return '条件待明确';
    if(value.op==='true') return '每次调用';if(value.op==='false') return '不可发生';if(value.op==='unknown') return '条件未知';
    if(value.op==='all'||value.op==='any') return (value.items||[]).map(item=>this.semPredicate(item)).join(value.op==='all'?'，并且 ':'，或者 ');
    if(value.op==='not') return '不满足：'+this.semPredicate(value.item);
    const operand=v=>v?.kind==='return'?'返回值':v?.kind==='argument'?'参数 '+v.index:v?.kind==='literal'?(v.value===null?'空值':String(v.value)):JSON.stringify(v);
    return operand(value.left)+' '+value.operator+' '+operand(value.right);
  },
  semSummary(row) {
    return (row?.effects || []).map(effect => {
      const c = effect.carrier || {};
      return this.semRole(effect.role) + ' · ' + (c.root === 'return' ? '返回值' : c.root === 'argument' ? `参数 ${c.index}（从 0 计数）` : c.root) + (c.members?.length ? ' → '+c.members.join('.') : '') + (effect.resource_family ? ' · '+effect.resource_family : '');
    }).join('；') || '请审视精确目标和生效条件';
  },
  semStepDone(index) { const s=this.semStatus; return index===0 ? !!s?.configuration_ready : index===1 ? !!s?.declaration || ['needs_review','ready'].includes(s?.stage) : index===2 ? !!s?.discovery_current : index===3 ? !!s?.review_complete : !!s?.ready && !!s?.configuration_ready; },
  semDraftKey() { return 'zscope:semantics:drafts:' + window.location.origin + window.location.search; },
  semPersistDraft() {
    if (this.semEntry && this.semEntryDirty) this.semDrafts[this.semEntry.collection+':'+this.semEntry.row.id] = {base:this.semEntry,content:this.semEntryContent};
    try { sessionStorage.setItem(this.semDraftKey(), JSON.stringify({entries:this.semDrafts,advanced:this.semAdvancedDirty ? {content:this.semAdvancedContent,base:this.semAdvancedBase} : null})); }
    catch { this.semNotice='浏览器未能保存本地草稿，请导出后再关闭页面。'; }
  },
  semExport(value, filename='zscope-semantics-draft.yaml') {
    const url=URL.createObjectURL(new Blob([typeof value === 'string' ? value : JSON.stringify(value,null,2)],{type:'text/plain;charset=utf-8'}));
    const a=document.createElement('a'); a.href=url; a.download=filename; a.click(); URL.revokeObjectURL(url);
  },
  async semFetch(path, payload) {
    const response=await fetch('/api/semantics'+path, payload === undefined ? {} : {method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(payload)});
    const data=await response.json(); if(!response.ok) throw new Error(data.error || `HTTP ${response.status}`); return data;
  },
  async initSemantics() {
    try { const saved=JSON.parse(sessionStorage.getItem(this.semDraftKey()) || '{}'); this.semDrafts=saved.entries || {}; if(saved.advanced) {this.semAdvancedContent=saved.advanced.content;this.semAdvancedBase=saved.advanced.base;this.semAdvancedDirty=true;} } catch {}
    window.addEventListener('beforeunload', event=>{ if(this.semEntryDirty || this.semAdvancedDirty || Object.keys(this.semDrafts).length) { this.semPersistDraft(); event.preventDefault(); event.returnValue=''; } });
    await this.loadSemantics();
  },
  async loadSemantics() {
    this.semLoading=true;
    try { this.semStatus=await this.semFetch(''); if(this.semStatus.active_task) this.semWatchTask(this.semStatus.active_task.id); }
    catch(error) { this.semError=error.message; }
    finally {this.semLoading=false;}
  },
  async semAction(path, extra={}) {
    this.semBusy=true; this.semError=''; this.semNotice='';
    try { const data=await this.semFetch('/'+path,{version:this.semStatus?.version,evidence_version:this.semStatus?.evidence_version || '',...extra});
      if(data.applicable !== undefined) this.semStatus=data;
      if(data.migration_report) this.semMigrationReport=data.migration_report;
      if(data.task) this.semWatchTask(data.task.id);
      await this.semLoadQueue(); this.loadPreparation?.(); return data;
    } catch(error) {this.semError=error.message;return null;}
    finally {this.semBusy=false;}
  },
  async semLoadQueue(restore=false) {
    if(!this.semStatus?.applicable || this.semStatus.stage==='missing') return;
    const sequence=++this.semQueueSequence;
    try { const data=await this.semFetch('/entries?'+new URLSearchParams({page:this.semPage,state:this.semFilter,q:this.semQuery}));
      if(sequence!==this.semQueueSequence) return;
      this.semRows=data.rows;this.semTotal=data.total;this.semSelected={};this.semBatch=null;
      if(!restore) this.writeNavigationRoute?.();
    } catch(error){this.semError=error.message;}
  },
  async semOpenEntry(row, restore=false) {
    this.semPersistDraft(); const sequence=++this.semEntrySequence; this.semError='';
    this.semId=row.id;this.semCollection=row.collection;this.semMobileDetail=true;
    try { const data=await this.semFetch('/entry?'+new URLSearchParams({id:row.id,collection:row.collection}));
      if(sequence!==this.semEntrySequence) return;
      const draft=this.semDrafts[row.collection+':'+row.id];
      this.semEntry=draft?.base || data;this.semEntryContent=draft?.content || data.content;this.semEntryDirty=!!draft;
      this.semReason='';
      if(draft && draft.base.version!==data.version) this.semError='本地草稿基于旧版本。请导出草稿，载入当前条目后比较；不会自动覆盖。';
      if(!restore) this.writeNavigationRoute?.();
    }catch(error){this.semError=error.message;}
  },
  async semReloadEntry() {
    if(!this.semEntry) return;
    // The old draft remains downloadable until the user explicitly chooses
    // this action, and unrelated entry drafts remain untouched.
    delete this.semDrafts[this.semCollection+':'+this.semId];this.semEntryDirty=false;this.semPersistDraft();
    await this.semOpenEntry({id:this.semId,collection:this.semCollection});
  },
  semApplyCondition() {
    if(!this.semEntry || this.semEntry.collection!=='interfaces') return;
    if(this.semEntryDirty) {this.semError='请先保存或载入当前条目，再使用条件表单，避免覆盖 YAML 草稿。';return;}
    const row=JSON.parse(JSON.stringify(this.semEntry.row));
    const when=this.semCondition==='always' ? {op:'true'} : {op:'compare',left:{kind:'return'},operator:this.semCondition==='return_zero' ? '==' : '!=',right:{kind:'literal',value:this.semCondition==='return_zero' ? 0 : null}};
    row.cases=[{when,effect:'applies'}];row.status='pending';this.semEntryContent=JSON.stringify(row,null,2);this.semEntryDirty=true;this.semPersistDraft();
  },
  async semSaveEntry() {
    const entry=this.semEntry;if(!entry) return;
    const data=await this.semAction('draft',{version:entry.version,evidence_version:entry.evidence_version,row_version:entry.row_version,collection:entry.collection,id:entry.row.id,content:this.semEntryContent});
    if(data) {this.semEntryDirty=false;delete this.semDrafts[entry.collection+':'+entry.row.id];this.semPersistDraft();await this.semOpenEntry({id:entry.row.id,collection:entry.collection});this.semNotice='待审稿已保存。确认或拒绝仍需单独提交。';}
  },
  semReviewItems(decision, single=false) {
    const rows=single && this.semEntry ? [{...this.semEntry.row,collection:this.semEntry.collection,row_version:this.semEntry.row_version}] : this.semRows.filter(row=>this.semSelected[row.collection+':'+row.id]);
    return rows.map(row=>({collection:row.collection,id:row.id,row_version:row.row_version,decision,reason:this.semReason}));
  },
  async semPreviewReview(decision, single=false) {
    if(this.semEntryDirty || this.semAdvancedDirty) {this.semError='请先保存待审草稿，再预检确认。';return;}
    this.semBusy=true;this.semError='';this.semBatch=null;
    const items=this.semReviewItems(decision,single);
    const base=single ? this.semEntry : this.semStatus;
    try { const payload={version:base.version,evidence_version:base.evidence_version || '',items};
      const result=await this.semFetch('/review',{...payload,preview:true});this.semBatch={...result,payload};
    }catch(error){this.semError=error.message;}finally{this.semBusy=false;}
  },
  async semCommitReview() {
    if(!this.semBatch) return;
    const data=await this.semAction('review',this.semBatch.payload);
    if(data) {this.semBatch=null;if(this.semEntry) await this.semOpenEntry({id:this.semId,collection:this.semCollection});this.semNotice='审阅决定已保存。完成全部条目后，请确认本轮审阅摘要。';}
  },
  async semNextEntry() { const index=this.semRows.findIndex(row=>row.id===this.semId && row.collection===this.semCollection);const next=this.semRows[index+1] || this.semRows[0];if(next) await this.semOpenEntry(next); },
  async semOpenAdvanced() {
    this.semAdvanced=true;if(this.semAdvancedDirty) return;
    const sequence=++this.semAdvancedRequest;this.semAdvancedLoading=true;
    try{const data=await this.semFetch('/document');if(sequence!==this.semAdvancedRequest || this.semAdvancedDirty) return;this.semAdvancedBase=data;this.semAdvancedContent=data.content;}catch(error){this.semError=error.message;}
    finally{if(sequence===this.semAdvancedRequest)this.semAdvancedLoading=false;}
  },
  async semSaveAdvanced(validate=false) {
    if(!this.semAdvancedBase) return;
    const data=await this.semAction(validate?'validate':'save',{...this.semAdvancedBase,content:this.semAdvancedContent});
    if(data) {if(!validate){this.semAdvancedDirty=false;this.semPersistDraft();await this.semOpenAdvanced();}this.semNotice=validate?'正式契约校验通过，尚未保存。':'语义文档已保存；受影响条目仍需发现或审阅。';}
  },
  async semFindSymbols() {
    this.semError='';try{const data=await this.semFetch('/symbols?'+new URLSearchParams({q:this.semSymbolQuery,page:this.semSymbolPage}));this.semInventory=data;this.semSymbols=data.symbols;this.semSymbolTotal=data.total;}catch(error){this.semError=error.message;}
  },
  async semAddPrimitive() {
    const data=await this.semAction('primitive',{...this.semPrimitive,inventory_version:this.semInventory?.version});
    if(data){this.semAdding=false;this.semFilter='all';await this.semLoadQueue();this.semNotice='原语声明已保存。请执行自动发现以绑定 native 身份。';}
  },
  async semStartTask(mode) {
    if(this.semEntryDirty || this.semAdvancedDirty) {this.semError='有未发布的草稿。请先保存，再按已保存的声明执行任务。';return;}
    await this.semAction('tasks',{mode,request_id:crypto.randomUUID()});
  },
  async semWatchTask(id) {
    if(this.semTask?.id!==id){this.semCursor=0;this.semEvents=[];}
    clearTimeout(this.semTimer);
    try{const data=await this.semFetch('/task?'+new URLSearchParams({id,cursor:this.semCursor}));this.semTask=data.task;this.semCursor=data.cursor;this.semEvents=[...this.semEvents,...data.events].slice(-100);
      if(['queued','running','publishing','cancelling'].includes(data.task.status)) this.semTimer=setTimeout(()=>this.semWatchTask(id),2000);
      else {this.semStatus=await this.semFetch('');await this.semLoadQueue();if(data.task.mode==='inventory') await this.semFindSymbols();}
    }catch(error){this.semError=error.message;}
  },
  async semRestoreRoute(params) {
    this.semQuery=params.get('sq') || '';this.semFilter=params.get('ss') || 'todo';this.semPage=Math.max(1,Number(params.get('sp'))||1);
    if(!this.semStatus) await this.loadSemantics();
    await this.semLoadQueue(true);
    if(params.get('sid')) await this.semOpenEntry({id:params.get('sid'),collection:params.get('sc') || 'interfaces'},true);
    if(params.get('st')) await this.semWatchTask(params.get('st'));
  },
};
