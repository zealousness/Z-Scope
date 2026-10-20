/* Alpine mixin: server-owned reports and incremental Markdown review import. */
window.ZScopeDashboardReports = {
  reportLoading: false, reportError: '', reportToc: [], reportRequest: 0,
  reportMarkdown: '', reviewPreview: false, importingReviews: false, exportingReport: false,
  businessReview: null, businessDrafts: {}, savingBusinessReview: false,
  async loadMarkdownReport(finding) {
    const request = ++this.reportRequest;
    this.reportLoading = true; this.reportError = ''; this.reportToc = []; this.reportMarkdown = ''; this.reviewPreview = false; this.businessReview = null;
    try {
      if (!finding?.issue_id) throw new Error('报告身份缺失，请刷新页面后重试');
      const response = await fetch(`/api/issue_report?issue_id=${encodeURIComponent(finding.issue_id)}`);
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || `HTTP ${response.status}`);
      if (request !== this.reportRequest) return;
      this.reportMarkdown = data.markdown;
      if (data.business_review?.questions?.length) {
        const review = data.business_review;
        const key = `${review.report_id}:${review.issue_id}`;
        const draft = this.businessDrafts[key];
        if (draft && this.businessAnswersChanged(draft)) {
          draft.stale = draft.base_revision !== review.base_revision;
          this.businessReview = draft;
        } else {
          review.questions.forEach(q => { q.original_answer = q.answer; q.original_source_note = q.source_note; });
          review.draft_key = key;
          this.businessDrafts[key] = review;
          this.businessReview = review;
        }
      }
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
  businessAnswersChanged(review = this.businessReview) {
    return !!review?.questions?.some(q => q.answer !== q.original_answer || q.source_note !== q.original_source_note);
  },
  reloadBusinessReview() {
    if (this.businessReview) delete this.businessDrafts[this.businessReview.draft_key];
    return this.loadMarkdownReport(this.selectedFinding);
  },
  async saveBusinessReview() {
    const review = this.businessReview;
    if (!review?.available || review.stale || this.savingBusinessReview || !this.businessAnswersChanged(review)) return;
    const answers = review.questions.filter(q => q.answer !== q.original_answer || q.source_note !== q.original_source_note)
      .map(({id, answer, source_note, expected_revision}) => ({id, answer, source_note, expected_revision}));
    if (answers.some(a => !a.source_note.trim())) { this.showToast('请填写每条回答的业务约定来源或说明', 'warning'); return; }
    this.savingBusinessReview = true;
    try {
      const response = await fetch('/api/business_review', {method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({
        report_id: review.report_id, issue_id: review.issue_id, base_revision: review.base_revision, answers,
      })});
      const data = await response.json();
      if (!response.ok || !data.success) throw new Error(data.error || '业务前提保存失败');
      const saved = data.business_review;
      saved.draft_key = review.draft_key;
      saved.questions.forEach(q => { q.original_answer = q.answer; q.original_source_note = q.source_note; });
      this.businessDrafts[review.draft_key] = saved;
      if (this.businessReview?.draft_key === review.draft_key) this.businessReview = saved;
      this.showToast('业务前提已保存；下次扫描将重新核验受影响结论，历史报告保持原样', 'success');
    } catch (error) { this.showToast(error.message, 'error'); }
    finally { this.savingBusinessReview = false; }
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
