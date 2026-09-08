(function () {
  'use strict';
  const R = window.ZScopeReport, $ = id => document.getElementById(id);
  const manifest = JSON.parse($('zscope-manifest').textContent);
  const documents = new Map(); let selected = '', busy = false;
  function message(text) { $('message').textContent = text; }
  function dirty(doc) { return doc.status !== doc.savedStatus || doc.note !== doc.savedNote; }
  function anyDirty() { return [...documents.values()].some(dirty); }
  function draftKey(doc) { return JSON.stringify([doc.status, doc.note]); }
  function unprotectedDrafts() { return [...documents.values()].some(doc => dirty(doc) && doc.downloadedDraft !== draftKey(doc)); }
  function draft(doc) { return R.serialize(doc.original, doc.status, doc.note); }
  function current() { return documents.get(selected); }
  function renderList() {
    const query = $('search').value.toLowerCase(), status = $('status-filter').value;
    const view = new Set(manifest.views[$('view').value] || []);
    $('issue-list').replaceChildren(); let count = 0;
    for (const [key, doc] of documents) {
      if (!view.has(key) || (status && status !== doc.status) || (query && !(doc.original + doc.note).toLowerCase().includes(query))) continue;
      count++;
      const button = document.createElement('button'); button.type = 'button'; button.classList.toggle('active', key === selected);
      const title = doc.parsed.body.match(/^# (.+)$/m)?.[1] || key;
      button.textContent = `${dirty(doc) ? '● ' : ''}${title}`;
      const detail = document.createElement('small'); detail.textContent = `${doc.status} · ${doc.path}`; button.append(detail);
      button.onclick = () => select(key); $('issue-list').append(button);
    }
    $('count').textContent = `${count} 条显示 / ${documents.size} 条已读取 / ${manifest.issues.length} 条报告`;
    $('dirty-label').textContent = current() && dirty(current()) ? '未保存' : '';
  }
  function select(key) {
    selected = key; const doc = current(); if (!doc) return;
    // Incomplete Markdown can exist while typing; switching issues must retain that draft.
    let content = doc.original;
    try { content = draft(doc); } catch (_) { message('人工说明包含未闭合代码围栏或无效边界；草稿已保留，请修正后保存。'); }
    const result = R.mount($('report'), content);
    $('toc').replaceChildren();
    for (const item of result.toc) {
      const button = document.createElement('button'); button.textContent = item.label;
      button.onclick = () => R.jump($('report'), item.id); $('toc').append(button);
    }
    $('reading').scrollTop = 0; $('editor').hidden = false;
    $('review-status').value = doc.status; $('review-note').value = doc.note;
    $('review-preview').hidden = true; renderList();
  }
  async function load(entries) {
    if (busy) { message('正在保存，请完成后再打开文件。'); return; }
    if (unprotectedDrafts()) { message('请先保存或下载当前修改，再重新打开文件。'); return; }
    const next = new Map(), expected = new Set(manifest.issues.map(item => item.issue_id));
    for (const entry of entries) {
      const parsed = R.parse(entry.content), meta = parsed.metadata;
      if (meta.report_id !== manifest.report_id || !expected.has(meta.issue_id)) throw new Error('所选目录包含其他报告的 Markdown');
      if (next.has(meta.issue_id)) throw new Error('所选文件包含重复 issue');
      if (!parsed.region) throw new Error('Markdown 缺少本次复核区域，请重新导出');
      next.set(meta.issue_id, {...entry, original: entry.content, parsed, status: meta.validation_status, note: parsed.user_rebuttal,
        savedStatus: meta.validation_status, savedNote: parsed.user_rebuttal});
    }
    if (!next.size) throw new Error('未找到此报告的 Markdown 文件');
    documents.clear(); for (const [key, doc] of next) documents.set(key, doc);
    select(documents.has(selected) ? selected : documents.keys().next().value);
    message(`已读取 ${documents.size} 条报告${next.size < manifest.issues.length ? '；部分文件缺失，当前只展示已读取条目' : ''}。本次说明留空的条目不会回写。`);
  }
  async function openDirectory() {
    if (busy) { message('正在保存，请完成后再打开目录。'); return; }
    if (unprotectedDrafts()) { message('请先保存或下载当前修改，再打开其他目录。'); return; }
    if (!window.showDirectoryPicker) { $('directory-files').value = ''; $('directory-files').click(); return; }
    try {
      const root = await window.showDirectoryPicker({mode: 'readwrite'});
      const entries = [];
      let totalBytes = 0;
      for (const item of manifest.issues) {
        if (!R.safePath(item.path)) throw new Error('报告目录索引路径无效');
        let folder = root; const parts = item.path.split('/');
        try {
          for (const part of parts.slice(0, -1)) folder = await folder.getDirectoryHandle(part);
          const handle = await folder.getFileHandle(parts.at(-1));
          const file = await handle.getFile();
          if (file.size > 16 * 1024 * 1024) throw new Error('Markdown 文件超过 16 MiB');
          totalBytes += file.size;
          if (totalBytes > 128 * 1024 * 1024 || entries.length >= 10000) throw new Error('报告数量或总大小超限');
          entries.push({path: item.path, content: new TextDecoder('utf-8', {fatal:true}).decode(await file.arrayBuffer()), handle});
        } catch (error) { if (error.name !== 'NotFoundError') throw error; }
      }
      await load(entries);
    } catch (error) {
      if (error.name === 'AbortError') { message('已取消目录选择；原有草稿保留。'); return; }
      message(`目录访问失败：${error.message}。可使用“选择 Markdown / ZIP”，编辑后下载修改包。`);
    }
  }
  async function save(keys) {
    if (busy) return; busy = true;
    try {
      const changed = keys.map(key => documents.get(key)).filter(doc => doc && dirty(doc));
      if (!changed.length) { message('没有需要保存的修改。'); return; }
      if (changed.some(doc => !doc.handle)) {
        R.downloadReviews(changed.map(doc => ({content: draft(doc)})));
        changed.forEach(doc => { doc.downloadedDraft = draftKey(doc); });
        message('已下载修改包；请保留下载文件用于导入。当前草稿仍保留。'); return;
      }
      let saved = 0;
      for (const doc of changed) {
        const onDisk = new TextDecoder('utf-8', {fatal:true}).decode(await (await doc.handle.getFile()).arrayBuffer());
        if (onDisk !== doc.original) throw new Error(`文件已被外部修改：${doc.path}。已保存 ${saved} 条；剩余草稿保留，可下载修改包。`);
        const savedStatus = doc.status, savedNote = doc.note;
        const output = draft(doc);
        let writer;
        try { writer = await doc.handle.createWritable(); await writer.write(output); await writer.close(); }
        catch (error) { if (writer) { try { await writer.abort(); } catch (_) {} } throw error; }
        doc.original = output; doc.savedStatus = savedStatus; doc.savedNote = savedNote; doc.parsed = R.parse(output); saved++;
      }
      message(`已保存 ${saved} 个 Markdown 文件。`);
    } catch (error) { message(`保存失败：${error.message}；未成功保存的草稿仍保留。`); }
    finally { busy = false; renderList(); }
  }
  for (const state of R.STATES) {
    for (const id of ['review-status','status-filter']) { const option = document.createElement('option'); option.value = state; option.textContent = state; $(id).append(option); }
  }
  $('open-directory').onclick = openDirectory;
  $('open-files').onclick = () => { $('files').value = ''; $('files').click(); };
  for (const id of ['files','directory-files']) $(id).onchange = async event => {
    try { await load(await R.readFiles(event.target.files)); } catch (error) { message(`读取失败：${error.message}`); }
  };
  for (const id of ['search','view','status-filter']) $(id).oninput = renderList;
  $('review-note').oninput = () => { if (current()) { current().note = $('review-note').value; renderList(); if (!$('review-preview').hidden) $('review-preview').innerHTML = R.markdown(current().note); } };
  $('review-status').onchange = () => { if (current()) { current().status = $('review-status').value; renderList(); } };
  $('preview').onclick = () => { $('review-preview').hidden = !$('review-preview').hidden; $('review-preview').innerHTML = R.markdown(current()?.note || '*尚未填写*'); };
  $('save-current').onclick = () => save([selected]); $('save-all').onclick = () => save([...documents.keys()]);
  $('download-changes').onclick = () => {
    try {
      const changed = [...documents.values()].filter(doc => dirty(doc) || doc.note.trim());
      if (!changed.length) { message('没有可下载的复核修改。'); return; }
      R.downloadReviews(changed.map(doc => ({content: draft(doc)})));
      changed.forEach(doc => { doc.downloadedDraft = draftKey(doc); });
      message('已下载复核修改包，可在线导入。');
    } catch (error) { message(error.message); }
  };
  window.addEventListener('beforeunload', event => { if (anyDirty()) { event.preventDefault(); event.returnValue = ''; } });
})();
