/* Alpine mixin: server-owned reports and incremental Markdown review import. */
window.ZScopeDashboardReports = {
  reportLoading: false, reportError: '', reportToc: [], reportRequest: 0,
  reportMarkdown: '', reviewPreview: false, importingReviews: false, exportingReport: false,
  async loadMarkdownReport(finding) {
    const request = ++this.reportRequest;
    this.reportLoading = true; this.reportError = ''; this.reportToc = []; this.reportMarkdown = ''; this.reviewPreview = false;
    try {
      if (!finding?.issue_id) throw new Error('报告身份缺失，请刷新页面后重试');
      const response = await fetch(`/api/issue_report?issue_id=${encodeURIComponent(finding.issue_id)}`);
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || `HTTP ${response.status}`);
      if (request !== this.reportRequest) return;
      this.reportMarkdown = data.markdown;
      // Full text is authoritative. Keep an existing local review draft across issue switches.
      if (!finding._validation_dirty) {
        finding.validation_status = data.review.validation_status;
        finding.user_rebuttal = data.review.user_rebuttal;
        this.resetFindingValidationBaseline(finding, {snapshotPending: finding._snapshot_sync_pending});
      }
      await this.$nextTick();
      if (request !== this.reportRequest || !this.$refs.markdownReport) return;
      this.reportToc = ZScopeReport.mount(this.$refs.markdownReport, data.markdown).toc;
      this.$refs.reportScroll.scrollTop = 0;
    } catch (error) { if (request === this.reportRequest) this.reportError = error.message; }
    finally { if (request === this.reportRequest) this.reportLoading = false; }
  },
  jumpReport(id) { if (this.$refs.markdownReport) ZScopeReport.jump(this.$refs.markdownReport, id); },
  renderReviewPreview() { return ZScopeReport.markdown(this.selectedFinding?.user_rebuttal || '*尚未填写*'); },
  reportExchangeReady() {
    if (this.importingReviews || this.exportingReport || this.savingFindings || this.savingSingleFinding) return false;
    if (this.dirtyValidationFindings().length) { this.showToast('请先回写当前验证改动，再导入或导出；草稿已保留', 'warning'); return false; }
    return true;
  },
  async exportOfflinePage() {
    if (!this.reportExchangeReady()) return;
    this.exportingReport = true;
    try {
      const response = await fetch('/api/offline_report');
      if (!response.ok) { const error = await response.json(); throw new Error(error.error || '导出失败'); }
      ZScopeReport.download(await response.arrayBuffer(), 'zscope-report.zip', 'application/zip');
      this.showToast('已导出 Markdown 报告包，解压后打开 index.html', 'success');
    } catch (error) { this.showToast(error.message, 'error'); }
    finally { this.exportingReport = false; }
  },
  triggerOfflineImport() {
    if (!this.reportExchangeReady()) return;
    this.$refs.offlineImportInput.value = ''; this.$refs.offlineImportInput.click();
  },
  triggerDirectoryImport() {
    if (!this.reportExchangeReady()) return;
    this.$refs.reviewDirectoryInput.value = ''; this.$refs.reviewDirectoryInput.click();
  },
  async importOfflinePage(event) {
    if (!event.target.files?.length || !this.reportExchangeReady()) return;
    this.importingReviews = true;
    try {
      const documents = await ZScopeReport.readFiles(event.target.files);
      const response = await fetch('/api/import_reviews', {method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({documents})});
      const result = await response.json(); if (!response.ok || !result.success) throw new Error(result.error || '导入失败');
      this.showImportResults(result, documents);
      if (result.counts.updated) await this.refreshImportedReviews();
    } catch (error) { this.showToast(error.message, 'error'); }
    finally { this.importingReviews = false; }
  },
  async refreshImportedReviews() {
    const previousFinding = this.selectedFinding; this.reportViewCache = {}; this.reportViewRequests = {};
    await this.fetchFindingsForView(this.reportView, {activate: true, force: true, previousFinding});
  },
  showImportResults(result, documents) {
    document.getElementById('review-import-dialog')?.remove();
    const dialog = document.createElement('dialog'); dialog.id = 'review-import-dialog'; dialog.className = 'review-dialog';
    const title = document.createElement('h2'); title.textContent = '人工复核导入结果'; dialog.append(title);
    const counts = document.createElement('p');
    const labels = {updated:'已更新', skipped_empty:'空说明跳过', unchanged:'无变更', conflict:'冲突', invalid:'格式错误', unmatched:'未匹配'};
    counts.textContent = Object.entries(result.counts).map(([key, n]) => `${labels[key] || key} ${n} 条`).join(' · '); dialog.append(counts);
    for (const item of result.results) {
      if (!['conflict','invalid','unmatched'].includes(item.status)) continue;
      const row = document.createElement('article'); const name = document.createElement('strong');
      name.textContent = `${documents[item.index].path}：${item.message}`; row.append(name);
      if (item.status === 'conflict') this.appendReviewConflict(row, item, documents[item.index]);
      dialog.append(row);
    }
    const close = document.createElement('button'); close.className = 'btn btn-sm'; close.textContent = '关闭'; close.onclick = () => dialog.close(); dialog.append(close);
    document.body.append(dialog); dialog.showModal();
  },
  appendReviewConflict(row, item, documentValue) {
    const diff = document.createElement('div'); diff.className = 'review-diff';
    for (const [key, label] of [['baseline','导出时'],['current','线上当前'],['incoming','本次离线复核']]) {
      const column = document.createElement('div'); const title = document.createElement('strong'); title.textContent = `${label} · ${item[key].validation_status}`;
      const note = document.createElement('pre'); note.textContent = item[key].user_rebuttal || '（无人工说明）'; column.append(title, note); diff.append(column);
    }
    row.append(diff);
    if (item.context_changed) {
      const details = document.createElement('details'); const summary = document.createElement('summary'); summary.textContent = '证据或 Validator 上下文已变化，查看当前验证说明';
      const text = document.createElement('pre'); text.style.whiteSpace = 'pre-wrap'; text.textContent = item.validation_reasoning;
      details.append(summary, text); row.append(details);
    }
    const keep = document.createElement('button'); keep.className = 'btn btn-sm'; keep.textContent = '保留线上';
    keep.onclick = () => { row.textContent = '已保留线上结果'; };
    const apply = document.createElement('button'); apply.className = 'btn btn-primary btn-sm'; apply.textContent = '采用离线复核';
    apply.onclick = async () => {
      apply.disabled = true; keep.disabled = true;
      try {
        const response = await fetch('/api/import_reviews/resolve', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({documents:[{...documentValue, expected_revision:item.expected_revision}]})});
        const result = await response.json(); if (!response.ok || !result.success) throw new Error(result.error || '冲突处理失败');
        const next = result.results[0]; row.replaceChildren();
        if (next.status === 'conflict') {
          const changed = document.createElement('p'); changed.textContent = '线上结果再次变化，请重新比较。'; row.append(changed); this.appendReviewConflict(row, next, documentValue);
        } else { row.textContent = next.message; if (next.status === 'updated') await this.refreshImportedReviews(); }
      } catch (error) { this.showToast(error.message, 'error'); apply.disabled = false; keep.disabled = false; }
    };
    row.append(keep, apply);
  },
};
