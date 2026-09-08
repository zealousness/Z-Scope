/* Shared, offline-capable Markdown renderer and review document codec. */
(function (global) {
  'use strict';
  const START = '<!-- zscope-review:start -->';
  const END = '<!-- zscope-review:end -->';
  const STATES = ['pending', 'needs_review', 'validated', 'rejected', 'uncertain', 'unvalidated'];
  const MAX_FILE = 16 * 1024 * 1024, MAX_TOTAL = 128 * 1024 * 1024, MAX_COUNT = 10000;
  const esc = value => String(value ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;', '<':'&lt;', '>':'&gt;', '"':'&quot;', "'":'&#39;'}[c]));
  const bytes = text => new TextEncoder().encode(text);
  const decode = value => new TextDecoder('utf-8', {fatal: true}).decode(value);
  function region(body) {
    const markers = []; let fence = '', offset = 0;
    for (const line of body.match(/[^\n]*\n|[^\n]+$/g) || []) {
      const stripped = line.replace(/\r?\n$/, '');
      const match = stripped.match(/^ {0,3}(`{3,}|~{3,})(.*)$/);
      if (match) {
        if (!fence) fence = match[1];
        else if (fence[0] === match[1][0] && match[1].length >= fence.length && !match[2].trim()) fence = '';
      } else if (!fence && [START, END].includes(stripped)) markers.push([stripped, offset, offset + line.length]);
      offset += line.length;
    }
    if (!markers.length) return null;
    if (markers.length !== 2 || markers[0][0] !== START || markers[1][0] !== END) throw new Error('人工说明边界损坏或重复');
    return {start: markers[0][2], end: markers[1][1], markerStart: markers[0][1], markerEnd: markers[1][2]};
  }
  function parse(content) {
    if (bytes(content).length > MAX_FILE) throw new Error('Markdown 文件超过 16 MiB');
    content = content.replace(/^\uFEFF/, '').replace(/\r\n/g, '\n');
    const match = content.match(/^---\n([\s\S]*?)\n---(?:\n|$)/);
    if (!match || match[1].length > 256 * 1024) throw new Error('缺少 Markdown 元数据；旧 HTML 请重新导出');
    const meta = jsyaml.load(match[1], {schema: jsyaml.JSON_SCHEMA});
    const keys = ['schema_version','report_id','issue_id','base_revision','base_context','base_status','base_user_rebuttal','validation_status'];
    if (!meta || typeof meta !== 'object' || Object.keys(meta).length !== keys.length || keys.some(key => typeof meta[key] !== 'string')) throw new Error('Markdown 元数据字段无效');
    if (meta.schema_version !== 'zscope.issue-markdown.v1' || !STATES.includes(meta.validation_status)) throw new Error('不支持的报告版本或验证状态');
    if (['report_id','issue_id','base_revision','base_context'].some(key => !/^[a-f0-9]{64}$/.test(meta[key]))) throw new Error('报告身份无效');
    const body = content.slice(match[0].length), bounds = region(body);
    return {metadata: meta, body, region: bounds, user_rebuttal: bounds ? body.slice(bounds.start, bounds.end).trim() : ''};
  }
  function serialize(content, status, note) {
    const parsed = parse(content);
    if (!STATES.includes(status)) throw new Error('非法验证状态');
    if (!parsed.region) throw new Error('缺少本次复核区域，请重新导出报告');
    parsed.metadata.validation_status = status;
    const body = parsed.body.slice(0, parsed.region.start) + '\n' + String(note).trim() + '\n\n' + parsed.body.slice(parsed.region.end);
    region(body); // Reject injected or broken control markers before saving anything.
    const result = '---\n' + jsyaml.dump(parsed.metadata, {schema: jsyaml.JSON_SCHEMA, lineWidth: -1, noRefs: true}) + '---\n' + body;
    parse(result);
    return result;
  }
  const md = global.markdownit({html: false, linkify: false, breaks: false});
  // Reports must remain passive even when the source or review contains hostile Markdown.
  md.renderer.rules.image = (tokens, index) => `<span class="report-image-placeholder">[图片：${esc(tokens[index].content)}]</span>`;
  const defaultLink = md.renderer.rules.link_open || ((tokens, index, options, env, self) => self.renderToken(tokens, index, options));
  md.renderer.rules.link_open = (tokens, index, options, env, self) => {
    const href = tokens[index].attrGet('href') || '';
    if (!href.startsWith('#') && !/^https?:\/\//i.test(href)) tokens[index].attrSet('href', '#');
    tokens[index].attrSet('rel', 'noopener noreferrer');
    if (/^https?:\/\//i.test(href)) tokens[index].attrSet('target', '_blank');
    return defaultLink(tokens, index, options, env, self);
  };
  function evidenceValue(value, key, labels, depth = 0) {
    if (value === null) return '<span class="evidence-empty">未提供（null）</span>';
    if (value === false && key === 'is_conclusive') return '<strong class="evidence-limitation">不具决定性（false）</strong>';
    if (value === false && key === 'execution_enabled') return '<strong class="evidence-limitation">未启用执行（false）</strong>';
    if (typeof value === 'boolean') return value ? '是（true）' : '否（false）';
    if (typeof value !== 'object') return value === '' ? '<span class="evidence-empty">未提供（空文本）</span>' : `<span class="evidence-value">${esc(value)}</span>`;
    if (!Object.keys(value).length) {
      const hint = key === 'checks' ? '；不代表不存在保护' : (key === 'proofs' ? '；未提供证明' : '；不构成安全结论');
      return `<span class="evidence-empty">未记录（${Array.isArray(value) ? '空列表' : '空对象'}）${hint}</span>`;
    }
    if (depth >= 12) return `<pre class="evidence-data">${esc(JSON.stringify(value, null, 2))}</pre>`;
    if (Array.isArray(value)) return `<ol class="evidence-items">${value.map(item => `<li>${evidenceValue(item, key, labels, depth + 1)}</li>`).join('')}</ol>`;
    return `<dl class="evidence-fields">${Object.entries(value).map(([name, item]) => `<div><dt>${esc(labels[name] || name)}<small>${esc(name)}</small></dt><dd>${evidenceValue(item, name, labels, depth + 1)}</dd></div>`).join('')}</dl>`;
  }
  function evidenceAppendix(content) {
    let data;
    try { data = JSON.parse(content); } catch (_) { return dataBlock(content, '证据附录格式无效；保留原文'); }
    if (data?.schema_version !== 'zscope.evidence-presentation.v1' || !Array.isArray(data.groups) || !Object.hasOwn(data, 'raw')) return dataBlock(content, '不支持的证据附录；保留原文');
    const labels = data.labels && typeof data.labels === 'object' ? data.labels : {};
    const groups = data.groups.filter(group => group && typeof group.title === 'string' && Array.isArray(group.fields));
    const details = groups.map(group => {
      const fields = group.fields.filter(field => field && typeof field.key === 'string');
      return `<details class="evidence-detail"><summary>${esc(group.title)}<small>${fields.length} 项</small></summary><dl class="evidence-fields">${fields.map(field => `<div><dt>${esc(field.label || field.key)}<small>${esc(Array.isArray(field.paths) ? field.paths.join(' / ') : field.key)}</small></dt><dd>${evidenceValue(field.value, field.key, labels)}</dd></div>`).join('')}</dl></details>`;
    }).join('');
    return `<section class="evidence-appendix" aria-label="结构化证据详情">${details}<details class="evidence-detail evidence-raw"><summary>完整原始 JSON<small>全部字段</small></summary><button type="button" class="evidence-copy" data-copy-evidence>复制完整 JSON</button><pre class="evidence-data">${esc(JSON.stringify(data.raw, null, 2))}</pre></details></section>`;
  }
  function dataBlock(content, label = 'JSON 数据') {
    return `<section class="report-data"><header><span>${esc(label)}</span><button type="button" data-copy-code>复制数据</button></header><pre class="evidence-data">${esc(content)}</pre><pre class="report-code-raw" hidden>${esc(content)}</pre></section>`;
  }
  md.renderer.rules.fence = (tokens, index) => {
    const token = tokens[index]; const split = token.info.indexOf(' zscope:');
    const language = (split < 0 ? token.info : token.info.slice(0, split)).trim().split(/\s/)[0];
    let meta = {};
    if (split >= 0) { try { meta = JSON.parse(token.info.slice(split + 8)); } catch (_) { /* render as unlocated code */ } }
    if (!meta || typeof meta !== 'object' || Array.isArray(meta)) meta = {};
    if (meta.kind === 'evidence-appendix') return meta.version === 1 ? evidenceAppendix(token.content) : dataBlock(token.content, '不支持的证据附录版本；保留原文');
    if (language === 'json' && meta.located !== true) return dataBlock(token.content);
    const lines = token.content.replace(/\n$/, '').split('\n');
    const located = meta.located === true && Array.isArray(meta.numbers) && meta.numbers.length === lines.length && meta.numbers.every(n => Number.isSafeInteger(n) && n > 0);
    const path = typeof meta.path === 'string' ? meta.path : '片段';
    const id = typeof meta.id === 'string' && /^code-\d+$/.test(meta.id) ? meta.id : '';
    const highlights = Array.isArray(meta.highlight) ? new Set(meta.highlight) : new Set();
    const grammar = global.Prism?.languages[language];
    const code = grammar ? Prism.highlight(token.content.replace(/\n$/, ''), grammar, language) : esc(token.content.replace(/\n$/, ''));
    // Highlight the complete block first, then balance multiline Prism spans per row.
    let spans = [];
    const highlighted = code.split('\n').map(line => {
      const prefix = spans.join('');
      for (const tag of line.match(/<span\b[^>]*>|<\/span>/g) || []) {
        if (tag.startsWith('</')) spans.pop(); else spans.push(tag);
      }
      return prefix + line + '</span>'.repeat(spans.length);
    });
    const label = located ? `${path}:${meta.numbers[0]}-${meta.numbers.at(-1)}` : `${path} · 片段内行号（非源码行号）`;
    const rows = lines.map((line, i) => {
      const n = located ? meta.numbers[i] : i + 1;
      return `<tr${id && located ? ` id="${id}-L${n}"` : ''}${highlights.has(n) && located ? ' class="report-code-focus"' : ''}><td class="report-line"><button type="button" data-copy-location="${esc(located ? `${path}:${n}` : `片段第 ${n} 行`)}" title="复制位置">${n}</button></td><td class="report-code-text">${highlighted[i] || ' '}</td></tr>`;
    }).join('');
    return `<section class="report-code"${id ? ` id="${id}"` : ''}><header><span>${esc(label)}</span><button type="button" data-copy-code>复制代码</button></header><div class="report-code-scroll"><table><tbody>${rows}</tbody></table></div><pre class="report-code-raw" hidden>${esc(token.content.replace(/\n$/, ''))}</pre></section>`;
  };
  function render(content) {
    const parsed = parse(content);
    let body = parsed.body;
    if (parsed.region) body = body.slice(0, parsed.region.markerStart) + (parsed.user_rebuttal || '*本次尚未填写*') + '\n' + body.slice(parsed.region.markerEnd);
    return md.render(body);
  }
  function mount(element, content) {
    const parsed = parse(content);
    element.innerHTML = render(content);
    const toc = [], seen = new Set();
    const sectionIds = {'代码证据与路径':'report-code-evidence', '正反证据':'report-positive-negative', 'Validator 验证结果':'report-validator', '结构化证据解读':'report-evidence'};
    element.querySelectorAll('h2').forEach((heading, index) => {
      const id = sectionIds[heading.textContent];
      heading.id = id && !seen.has(id) ? id : `section-${index}`; seen.add(heading.id);
      toc.push({id: heading.id, label: heading.textContent});
    });
    element.querySelectorAll('a[href^="#code-"]').forEach(link => {
      if (!/:[1-9]\d*(?:-[1-9]\d*)?$/.test(link.textContent)) return;
      const button = document.createElement('button'); button.type = 'button'; button.className = 'evidence-copy-location';
      button.dataset.copyLocation = link.textContent; button.textContent = '复制位置'; link.after(button);
    });
    element.onclick = async event => {
      const codeButton = event.target.closest('[data-copy-code]');
      const location = event.target.closest('[data-copy-location]');
      const evidence = event.target.closest('[data-copy-evidence]');
      if (codeButton || location || evidence) {
        try {
          await copy(location ? location.dataset.copyLocation : (evidence ? evidence.closest('.evidence-raw').querySelector('.evidence-data').textContent : codeButton.closest('.report-code,.report-data').querySelector('.report-code-raw').textContent));
          const button = location || codeButton || evidence, label = button.textContent;
          button.textContent = '已复制'; setTimeout(() => { button.textContent = label; }, 1100);
        } catch (_) { (location || codeButton || evidence).title = '复制失败，请手动选择文本'; }
      }
      const link = event.target.closest('a[href^="#"]');
      if (link) { event.preventDefault(); jump(element, link.getAttribute('href').slice(1)); }
    };
    return {toc, parsed};
  }
  function jump(element, id) {
    const target = [...element.querySelectorAll('[id]')].find(node => node.id === id);
    if (target) {
      for (let parent = target.parentElement; parent && parent !== element; parent = parent.parentElement) if (parent.tagName === 'DETAILS') parent.open = true;
      target.scrollIntoView({block: 'start', behavior: 'smooth'});
    }
  }
  async function copy(value) {
    if (navigator.clipboard?.writeText) { try { await navigator.clipboard.writeText(value); return; } catch (_) {} }
    const area = document.createElement('textarea'); area.value = value; area.style.cssText = 'position:fixed;left:-9999px'; document.body.append(area);
    area.select(); const ok = document.execCommand('copy'); area.remove(); if (!ok) throw new Error('复制失败');
  }
  function safePath(path) {
    return typeof path === 'string' && !path.includes('\\') && !path.startsWith('/') && path.split('/').every(part => part && !['.', '..'].includes(part) && !/[:\0]/.test(part));
  }
  function unzipDocuments(data) {
    const documents = []; let total = 0, count = 0; const paths = new Set();
    const unzip = new fflate.Unzip(file => {
      const path = file.name;
      if (!safePath(path.replace(/\/$/, ''))) throw new Error('ZIP 包含不安全路径');
      if (path.endsWith('/') || /(^|\/)index\.html$/i.test(path)) return;
      if (!path.toLowerCase().endsWith('.md')) throw new Error('ZIP 包含不支持的文件');
      if (paths.has(path) || ++count > MAX_COUNT) throw new Error('ZIP 包含重复路径或过多文件');
      paths.add(path);
      if (file.originalSize > MAX_FILE) throw new Error('ZIP 中的 Markdown 超过 16 MiB');
      let size = 0; const chunks = [];
      file.ondata = (error, chunk, final) => {
        if (error) throw error;
        size += chunk.length; total += chunk.length;
        if (size > MAX_FILE || total > MAX_TOTAL) { file.terminate(); throw new Error('ZIP 解压大小超限'); }
        chunks.push(chunk);
        if (final) {
          const output = new Uint8Array(size); let at = 0;
          for (const item of chunks) { output.set(item, at); at += item.length; }
          documents.push({path, content: decode(output)});
        }
      };
      file.start();
    });
    unzip.register(fflate.UnzipInflate);
    for (let at = 0; at < data.length; at += 65536) unzip.push(data.subarray(at, at + 65536), at + 65536 >= data.length);
    return documents;
  }
  async function readFiles(files) {
    const documents = []; let total = 0;
    for (const file of files) {
      if (file.size > MAX_TOTAL) throw new Error('文件超过 128 MiB');
      const path = file.webkitRelativePath || file.name;
      if (!safePath(path)) throw new Error('不安全的文件路径');
      if (file.name.toLowerCase().endsWith('.zip')) documents.push(...unzipDocuments(new Uint8Array(await file.arrayBuffer())));
      else if (file.name.toLowerCase().endsWith('.md')) documents.push({path, content: decode(await file.arrayBuffer())});
      else if (file.webkitRelativePath && file.name === 'index.html') continue;
      else throw new Error('仅支持新 Markdown 包；旧版单 HTML 请重新导出');
    }
    for (const doc of documents) { const size = bytes(doc.content).length; total += size; if (size > MAX_FILE) throw new Error('Markdown 超过 16 MiB'); }
    if (!documents.length || documents.length > MAX_COUNT || total > MAX_TOTAL) throw new Error('导入文件数量或总大小超限');
    return documents;
  }
  function download(data, name, type) {
    const url = URL.createObjectURL(new Blob([data], {type}));
    const link = document.createElement('a'); link.href = url; link.download = name; link.click(); setTimeout(() => URL.revokeObjectURL(url), 1000);
  }
  function downloadReviews(documents) {
    const entries = {};
    for (const doc of documents) {
      const parsed = parse(doc.content); entries[`issues/${parsed.metadata.issue_id}.md`] = bytes(doc.content);
    }
    download(fflate.zipSync(entries), 'zscope-review-changes.zip', 'application/zip');
  }
  global.ZScopeReport = {parse, serialize, render, mount, jump, copy, readFiles, safePath, download, downloadReviews, STATES, markdown: text => md.render(text)};
})(window);
