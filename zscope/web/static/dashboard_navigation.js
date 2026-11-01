/* URL state is a locator only. Existing report/job loaders retain authority. */
window.ZScopeNavigation = {
  activeTab: 'overview', mobileNavigationOpen: false, detailSection: 'report', routeError: '',
  reportView: 'with_needs_review',
  findingAcceptanceFilter: 'active', findingFileFilter: '', findingBuildFilter: '',
  navigationRestoring: false, navigationSequence: 0,
  pageTitle() { return ({semantics:'项目原语',overview:'项目概览',prepare:'扫描任务',jobs:'扫描任务',findings:'问题工作台',acceptance:'问题工作台',coverage:'覆盖与诊断',project:'项目设置',rules:'规则目录',config:'业务模型',warnings:'诊断记录',stats:'统计'})[this.activeTab] || '项目概览'; },
  projectName() { const root = this.preparation?.project?.root || this.configForm?.project?.root || ''; return root.split(/[\\/]/).filter(Boolean).pop() || '当前工程'; },
  navigationGroup() { return ({prepare:'jobs',acceptance:'findings',config:'project',rules:'project',warnings:'coverage',stats:'coverage'})[this.activeTab] || this.activeTab; },
  severityLabel(value) { return ({critical:'严重',high:'高危',medium:'中危',low:'低危'})[String(value || '').toLowerCase()] || '严重度待定'; },
  validationLabel(value) { return ({validated:'人工确认',rejected:'判为误报',needs_review:'待人工复核',pending:'待处理',uncertain:'人工判断不确定',unvalidated:'尚未人工复核'})[value] || '状态待核实'; },
  coverageGapCount() { return Array.isArray(this.acceptanceCoverage?.gaps) ? this.acceptanceCoverage.gaps.length : '未测量'; },
  filteredFindings() {
    const query = String(this.filterQuery || '').trim().toLowerCase();
    return (this.findings || []).filter(finding => {
      const state = this.acceptanceState(finding);
      return (this.findingAcceptanceFilter === 'all' || (this.findingAcceptanceFilter === 'active' ? state !== 'ruled_out' : state === this.findingAcceptanceFilter))
        && (!this.findingFileFilter || String(finding.location || finding.file_path || '').includes(this.findingFileFilter))
        && (!this.findingBuildFilter || String(finding.build_context_id || finding.acceptance?.build_context_id || '').includes(this.findingBuildFilter))
        && (this.findingFilters || []).every(rule => this.matchesFindingRule(finding, rule))
        && (!query || this.findingSearchText(finding).includes(query));
    });
  },
  navigate(tab) {
    if (this.navigationRestoring) { this.navigationSequence++; this.jobRequest++; this.acceptanceRequest++; this.navigationRestoring = false; }
    if (!['overview','prepare','jobs','findings','acceptance','coverage','project','rules','config','stats','warnings','semantics'].includes(tab)) tab = 'overview';
    if (tab === 'config' && this.semStatus?.applicable) tab = 'semantics';
    this.activeTab = tab; this.mobileNavigationOpen = false; this.routeError = '';
    if (tab === 'semantics') { this.loadSemantics(); this.semLoadQueue(); }
    if (tab === 'jobs') this.loadJobs();
    if (tab === 'rules') this.loadRules();
    if (tab === 'findings' && this.acceptanceSource !== 'current') {
      this.loadAcceptance();
      const hasDrafts = this.dirtyValidationFindings?.().length || this.businessAnswersChanged?.() || (this.disposition && this.dispositionChanged?.());
      if (!hasDrafts) this.refreshData?.();
      else this.showToast?.('当前报告的未保存草稿已保留。保存后可刷新读取最新报告。','info');
    }
    if (tab === 'findings' && this.reportView !== 'with_needs_review' && this.setReportView) {
      if (this.dirtyValidationFindings?.().length) this.showToast?.('已保留当前视图的复核草稿。保存后重新进入，可查看全部待验证问题。','info');
      else this.setReportView('with_needs_review');
    }
    this.writeNavigationRoute();
  },
  navigationParams() {
    const params = new URLSearchParams({tab:this.activeTab});
    const snapshot = ['acceptance','overview','coverage'].includes(this.activeTab) && this.acceptanceSource !== 'current' ? this.acceptanceBinding : null;
    const job = snapshot || (this.activeTab === 'jobs' ? this.job : null);
    if (job?.job_id) {
      params.set('job', job.job_id); if (job.run_id) params.set('run',job.run_id);
      if (snapshot?.input_revision) params.set('input',snapshot.input_revision);
      if (snapshot?.report_id) params.set('artifact',snapshot.report_id);
    }
    const report = snapshot ? this.acceptanceReportId : this.currentReportId;
    if (report && (snapshot || this.activeTab === 'findings')) params.set('report',report);
    if (this.activeTab === 'findings') {
      if (this.reportView) params.set('view',this.reportView);
      if (this.selectedFinding?.issue_id) params.set('issue',this.selectedFinding.issue_id);
      for (const [key,value] of [['q',this.filterQuery],['status',this.findingAcceptanceFilter],['file',this.findingFileFilter],['build',this.findingBuildFilter]]) if (value && value !== 'active') params.set(key,value);
    }
    if (this.activeTab === 'semantics') { for (const [key,value] of [['sid',this.semId],['sc',this.semCollection],['sq',this.semQuery],['ss',this.semFilter],['sp',this.semPage]]) if(value) params.set(key,value); }
    return params;
  },
  writeNavigationRoute() {
    if (this.navigationRestoring || this.routeError || typeof window === 'undefined' || !window.history) return;
    const hash = '#' + this.navigationParams();
    if (window.location.hash !== hash) window.history.pushState(null,'',hash);
  },
  async restoreNavigationRoute() {
    const sequence = ++this.navigationSequence;
    const params = new URLSearchParams(window.location.hash.replace(/^#/,''));
    const tab = params.get('tab') || 'overview';
    this.navigationRestoring = true; this.routeError = '';
    try {
      this.activeTab = ['overview','prepare','jobs','findings','acceptance','coverage','project','rules','config','stats','warnings','semantics'].includes(tab) ? tab : 'overview';
      if (tab === 'semantics') await this.semRestoreRoute(params);
      if (tab === 'config' && this.semStatus?.applicable) { this.activeTab='semantics'; await this.semRestoreRoute(params); }
      this.filterQuery = params.get('q') || '';
      this.findingAcceptanceFilter = ['all','confirmed','pending','business_conditional','ruled_out'].includes(params.get('status')) ? params.get('status') : 'active';
      this.findingFileFilter = params.get('file') || ''; this.findingBuildFilter = params.get('build') || '';
      if (params.has('job')) {
        await this.loadJob(params.get('job'));
        if (sequence !== this.navigationSequence) return;
        if (this.job?.job_id !== params.get('job') || (params.has('run') && this.job.run_id !== params.get('run'))) throw new Error('链接中的作业运行已变化，请重新选择本轮结果。');
        if (['acceptance','overview','coverage'].includes(tab)) {
          // Persisted artifact identity and inner findings report identity differ.
          if (!params.get('report') || !params.get('input') || !params.get('artifact')
            || this.job?.input_revision !== params.get('input') || this.job?.report?.report_id !== params.get('artifact')) throw new Error('链接中的报告已失效或缺少完整输入身份，请重新选择作业结果。');
          await this.openJobResult();
          if (sequence !== this.navigationSequence) return;
          if (this.acceptanceReportId !== params.get('report') || this.acceptanceSource !== params.get('job')) throw new Error(this.jobResultError || '未能恢复链接指定的报告，请重新选择结果。');
          if (tab === 'config' && this.semStatus?.applicable) tab = 'semantics';
    this.activeTab = tab;
        }
      } else if (tab === 'acceptance' && params.has('report')) {
        throw new Error('历史报告链接缺少作业与运行身份，请重新选择报告。');
      }
      if (sequence !== this.navigationSequence) return;
      if (tab === 'findings' && params.has('report')) {
        const view = ['default','with_needs_review'].includes(params.get('view')) ? params.get('view') : (this.reportView || 'with_needs_review');
        if (view !== this.reportView && this.dirtyValidationFindings?.().length) throw new Error('当前视图有未保存复核草稿。请保存后再打开另一视图。');
        if ((!this.currentReportId || view !== this.reportView) && this.fetchFindingsForView) await this.fetchFindingsForView(view);
        if (sequence !== this.navigationSequence) return;
        if (this.currentReportId !== params.get('report')) { this.selectedFinding = null; throw new Error('链接属于另一份报告，请重新选择问题；不会自动绑定当前报告。'); }
        if (params.has('issue')) {
          const finding = this.findings.find(item => item.issue_id === params.get('issue'));
          if (!finding) { this.selectedFinding = null; throw new Error('该报告中未找到链接指定的问题。'); }
          this.selectFinding(finding);
        }
      } else if (tab === 'findings' && params.has('issue')) {
        this.selectedFinding = null; throw new Error('问题链接缺少报告身份，请重新选择问题。');
      }
    } catch (error) { if (sequence === this.navigationSequence) this.routeError = error.message; }
    finally { if (sequence === this.navigationSequence) this.navigationRestoring = false; }
  },
  initNavigation() {
    if (typeof window === 'undefined' || !window.location) return;
    window.addEventListener('beforeunload', event => {
      const dirty = this.dirtyValidationFindings?.().length || this.businessAnswersChanged?.()
        || Object.values(this.businessDrafts || {}).some(draft => this.businessAnswersChanged?.(draft))
        || this.dispositionChanged?.()
        || Object.values(this.dispositionDrafts || {}).some(draft => this.dispositionChanged?.(draft));
      if (dirty) { event.preventDefault(); event.returnValue = ''; }
    });
    const originalSelectFinding = this.selectFinding;
    if (originalSelectFinding) this.selectFinding = function(finding, options = {}) {
      originalSelectFinding.call(this,finding,options);
      if (!options.keepContextMode) this.detailSection = 'report';
      if (!options.keepMobileView && (this.viewportWidth || window.innerWidth) <= 1099) this.mobileFindingView = 'detail';
    };
    // A refresh can finish after an editor input. Preserve only drafts belonging
    // to the exact same report, issue and compilation variant.
    const originalIngest = this.ingestFindingsPayload;
    if (originalIngest) this.ingestFindingsPayload = function(data, requestedView) {
      const previousReport = this.currentReportId;
      const key = item => JSON.stringify([this.findingIdentity(item),item.build_context_id || item.acceptance?.build_context_id || '']);
      const drafts = new Map((this.dirtyValidationFindings?.() || []).map(item => [key(item),item]));
      const result = originalIngest.call(this,data,requestedView);
      if (previousReport && previousReport === data.report_id) {
        for (const item of result.findings) {
          const draft = drafts.get(key(item));
          if (!draft) continue;
          for (const field of ['validation_status','validation_reasoning','user_rebuttal','_validation_original_status','_validation_original_reasoning','_validation_original_rebuttal','_validation_dirty']) item[field] = draft[field];
        }
      }
      return result;
    };
    window.addEventListener('hashchange', () => this.restoreNavigationRoute());
    if (typeof this.$watch === 'function') {
      for (const key of ['activeTab','reportView','filterQuery','findingAcceptanceFilter','findingFileFilter','findingBuildFilter','selectedFinding','job','acceptanceReportId','acceptanceBinding']) this.$watch(key, () => this.writeNavigationRoute());
    }
    this.restoreNavigationRoute();
  }
};
