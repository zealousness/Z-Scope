/* Preparation, persisted jobs and acceptance. All authority stays on the server. */
window.ZScopeWorkbench = {
  jobs: [], job: null, jobsReady: false, jobsLoading: false, jobsError: '',
  jobCapabilities: {}, jobRequest: 0, jobListRequest: 0, jobBusy: false,
  jobEvents: [], jobEventSeq: 0, jobEventsError: '', jobResultError: '',
  jobActionError: '', jobCommand: null, jobTimer: null, jobDestroyed: false,
  workbenchDepth: '', workbenchStopAt: '',
  acceptanceReportId: '', acceptanceCoverage: null, acceptanceLoaded: false,
  acceptanceLoading: false, acceptanceError: '', acceptanceRequest: 0,
  acceptanceFilter: 'confirmed', acceptanceSearch: '', acceptanceLimit: 30,
  acceptanceIssues: [], acceptanceSource: 'current', acceptanceBinding: null,
  instancePlan: null, instanceJob: null, instanceSearch: '', instanceLimit: 12,
  disposition: null, dispositionDrafts: {}, dispositionLoading: false,
  dispositionError: '', dispositionRequest: 0, dispositionSaving: false,
  structuredConfigAvailable: false,

  initWorkbench() {
    this.loadJobs();
    this.loadAcceptance();
    this.scheduleJobPoll();
  },
  destroy() {
    this.jobDestroyed = true;
    clearTimeout(this.jobTimer);
    clearInterval(this.scheduleTimer);
    this.jobRequest++; this.jobListRequest++; this.acceptanceRequest++; this.dispositionRequest++;
  },
  scheduleJobPoll() {
    clearTimeout(this.jobTimer);
    if (this.jobDestroyed) return;
    this.jobTimer = setTimeout(async () => {
      if (!document.hidden && !this.jobBusy) {
        if (this.jobsReady || this.job) await this.loadJobs({quiet: true});
        if (this.job) await this.loadJob(this.job.job_id, {quiet: true});
      }
      this.scheduleJobPoll();
    }, this.jobsError ? 15000 : 5000);
  },
  async workbenchFetch(url, options) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 20000);
    try {
      const response = await fetch(url, {...options, signal: controller.signal});
      let data;
      try { data = await response.json(); } catch (_) {
        const error = new Error(response.status === 404 ? '此服务尚未提供该功能。请使用已有报告，或更新后端后重试。' : '服务返回了无法识别的响应，请重试。');
        error.status = response.status; throw error;
      }
      if (!response.ok) {
        const message = typeof data.error === 'string' && !/Traceback|api[_-]?key|Bearer\s/i.test(data.error)
          ? data.error : '请求未完成，请检查服务状态后重试。';
        const error = new Error(message); error.status = response.status; error.code = data.code; throw error;
      }
      return data;
    } catch (error) {
      if (error.name === 'AbortError') throw new Error('连接超时，尚未确认操作结果。请恢复连接后使用同一请求重试。');
      if (error.name === 'TypeError') throw new Error('连接中断，草稿已保留。恢复连接后可重试。');
      throw error;
    } finally { clearTimeout(timer); }
  },
  workbenchId() { return crypto.randomUUID(); },
  jobCommandStorageKey() { return this.preparation?.config_path ? `zscope.job-command:${this.preparation.config_path}` : null; },
  persistJobCommand() {
    const key = this.jobCommandStorageKey();
    if (!key) return;
    try {
      if (this.jobCommand) sessionStorage.setItem(key, JSON.stringify({root: this.preparation.project.root, command: this.jobCommand}));
      else sessionStorage.removeItem(key);
    } catch (_) { /* Private/limited storage keeps the in-memory retry available. */ }
  },
  restoreJobCommand() {
    if (this.jobCommand) return;
    const key = this.jobCommandStorageKey();
    if (!key) return;
    try {
      const saved = JSON.parse(sessionStorage.getItem(key) || 'null');
      if (saved?.root !== this.preparation.project.root) return;
      const command = saved.command;
      if (!['/api/jobs', '/api/jobs/cancel', '/api/jobs/resume'].includes(command?.url) || !command.payload?.request_id) return;
      this.jobCommand = command;
    } catch (_) { /* Broken local retry data never authorizes an operation. */ }
  },
  numberText(value) { return Number.isInteger(value) && value >= 0 ? String(value) : '未测量'; },
  timeText(value) {
    if (!value) return '未记录';
    const date = new Date(value);
    return Number.isNaN(date.getTime()) ? '时间不可用' : date.toLocaleString('zh-CN', {hour12: false});
  },
  localTimezone() { return Intl.DateTimeFormat().resolvedOptions().timeZone; },
  jobStatusText(status) {
    return ({queued: '等待开始', running: '正在运行', stopping: '正在停止', completed: '作业完成',
      partial: '部分完成，可重新尝试', cancelled: '已停止', failed: '执行失败', lost: '执行进程中断'})[status] || '状态待核实';
  },
  jobPhaseText(phase) {
    return ({preparing: '检查工程与构建', indexing: '建立代码索引', modeling: '理解接口与资源',
      analyzing: '分析候选问题', validating: '验证证据与条件', reporting: '整理报告',
      launching: '正在启动扫描进程', scanning: '扫描进程运行中，细分阶段尚未测量', finalizing: '正在保存本次运行记录', stopping: '正在停止扫描进程',
      queued: '等待执行', finished: '本轮执行结束'})[phase] || (phase ? `当前阶段：${phase}` : '当前没有细分阶段记录');
  },
  jobProgressPercent() {
    const progress = this.job?.progress;
    if (!Number.isInteger(progress?.total) || progress.total <= 0 || !Number.isInteger(progress.completed)
      || progress.completed < 0 || progress.completed > progress.total) return null;
    return Math.round(progress.completed * 100 / progress.total);
  },
  async loadJobs({quiet = false} = {}) {
    if (quiet && this.jobBusy) return;
    const request = ++this.jobListRequest;
    if (!quiet) this.jobsLoading = true;
    try {
      const data = await this.workbenchFetch('/api/jobs');
      if (request !== this.jobListRequest) return;
      if (data.schema !== 'zscope.scan-jobs.v1' || !Array.isArray(data.jobs)) throw new Error('作业服务版本不匹配，请更新后端。');
      this.jobs = data.jobs; this.jobCapabilities = data.capabilities || {}; this.jobsReady = true; this.jobsError = '';
      if (this.job) {
        const latest = data.jobs.find(item => item.job_id === this.job.job_id);
        if (latest) this.applyJob(latest);
      }
      if (!this.job && data.latest_job_id) await this.loadJob(data.latest_job_id);
    } catch (error) {
      if (request !== this.jobListRequest) return;
      this.jobsReady = false; this.jobCapabilities = {}; this.jobsError = error.code === 'config_unavailable' ? '已保存配置暂不支持启动，请核对准备页的目标与诊断。' : error.message;
    } finally { if (request === this.jobListRequest) this.jobsLoading = false; }
  },
  applyJob(job) {
    if (!job?.job_id || !Number.isInteger(job.revision)) throw new Error('作业状态缺少身份或版本，请刷新后重试。');
    if (this.job?.job_id === job.job_id && this.job.revision > job.revision) return;
    const changedRun = this.job?.job_id !== job.job_id || this.job?.run_id !== job.run_id;
    if (this.acceptanceBinding && !this.jobResultMatches(job, this.acceptanceBinding)) {
      this.acceptanceRequest++;
      this.invalidateJobAcceptance();
    }
    this.job = job;
    if (changedRun) { this.jobEvents = []; this.jobEventSeq = 0; this.jobEventsError = ''; this.jobResultError = ''; }
    this.jobs = [job, ...this.jobs.filter(item => item.job_id !== job.job_id)];
  },
  async loadJob(id, {quiet = false} = {}) {
    // Background refresh must not supersede a pending command's navigation.
    // An explicit selection still wins over a late command response.
    if (quiet && this.jobBusy) return;
    const request = ++this.jobRequest;
    if (!quiet) { this.jobsLoading = true; this.jobActionError = ''; }
    try {
      const data = await this.workbenchFetch(`/api/jobs/detail?job_id=${encodeURIComponent(id)}`);
      if (request !== this.jobRequest) return;
      if (data.schema !== 'zscope.scan-jobs.v1' || data.job?.job_id !== id) throw new Error('作业响应身份不匹配，请刷新后重试。');
      this.applyJob(data.job); this.jobsError = '';
      await this.loadJobEvents(id, request);
    } catch (error) { if (request === this.jobRequest) this.jobsError = error.message; }
    finally { if (request === this.jobRequest) this.jobsLoading = false; }
  },
  async loadJobEvents(id, request) {
    try {
      const data = await this.workbenchFetch(`/api/jobs/events?job_id=${encodeURIComponent(id)}&after_seq=${this.jobEventSeq}`);
      if (request !== this.jobRequest || this.job?.job_id !== id) return;
      if (data.job_id !== id || !Array.isArray(data.events)) throw new Error('活动记录身份不匹配');
      const known = new Set(this.jobEvents.map(item => item.seq));
      this.jobEvents = [...this.jobEvents, ...data.events.filter(item => item.job_id === id && !known.has(item.seq))]
        .sort((a, b) => a.seq - b.seq).slice(-80);
      if (Number.isInteger(data.next_seq)) this.jobEventSeq = Math.max(this.jobEventSeq, data.next_seq);
      this.jobEventsError = '';
    } catch (error) { if (request === this.jobRequest) this.jobEventsError = error.message; }
  },
  isV3Config() { return !!this.preparation?.version3 || this.structuredConfig?.config_version === 3; },
  preparationStartAllowed() { return this.preparation?.project_semantics?.ready !== false && (!this.preparation?.version3 || this.preparation.version3.start_capability?.startable === true); },
  canStartJob() { return this.jobsReady && this.jobCapabilities.create === true && !!this.preparation && this.preparationStartAllowed() && !this.configDirty && !this.configSaving && !this.configLoading && !this.preparationLoading && !this.jobBusy && !this.jobCommand; },
  presetLabel(value) { return ({fast: '快速', balanced: '均衡', deep: '深度'})[value] || value || '未指定'; },
  declaredFieldLabel(field) { return ({'project.platform': '目标运行平台', 'project.targets': '多个构建目标', 'scan.focus': '扫描重点', 'scan.reproduction': '自动复现', 'execution.max_workers': '最大工作数', 'execution.timezone': '运行时区', 'execution.stop_at': '配置停止时间'})[field] || field; },
  capabilityReason(reason) { return ({multi_target_execution_unwired: '多目标执行尚未接入。请在配置文件中明确选择一个目标，再重新检查。', project_scan_active: '本工程已有活动作业，可在运行与历史中查看。', cancel_in_progress: '停止请求正在处理。', terminal_state: '本次运行已结束。', job_active: '本次运行尚未结束。', already_completed: '本次运行已完成，可查看结果或新建作业。', invalid_state: '当前作业状态不支持此操作。'})[reason?.code] || reason?.message || '当前操作不可用'; },
  jobErrorText(error) { return ({cancelled: '已按请求停止；请核对保留的结果与未完成范围。', stop_window_reached: '已到本轮停止时间，扫描未完成。', scan_incomplete: '扫描已退出，仍有未完成范围。', scan_failed: '扫描进程执行失败，请查看本次运行产物中的日志。', owner_lost: '执行进程失联，不能认定作业已完成。'})[error?.code] || error?.message || ''; },
  jobEventText(event) {
    if (event.kind === 'job_terminal') return `运行记录已保存：${this.jobStatusText(event.data?.status)}`;
    return ({job_created:'已创建作业', attempt_started:'已创建本次运行', owner_spawned:'已启动独立执行进程', owner_started:'执行进程已接管作业', input_fingerprint:'已核对本次输入版本', input_revoked:'输入已变化，旧输入的证据不再复用', scan_launched:'已启动扫描进程', cancel_requested:'已记录停止请求', cancel_observed:'执行进程正在处理停止请求', scan_terminated:'扫描进程已停止', stop_window_reached:'已到本轮停止时间，保留部分结果和未完成标记', owner_lost:'执行进程失联', report_bound:'已保存并绑定本次运行的报告', report_missing:'本次运行尚无可绑定的新报告', report_unreadable:'本次运行的报告无法读取，请核对产物'})[event.kind] || event.message;
  },
  targetBuildText(target) {
    const build = target?.build || {};
    const status = ({available:'已读取',partial:'部分有效',missing:'缺少编译数据库',invalid:'编译数据库无效',not_applicable:'无需编译数据库'})[build.status] || '未测量';
    return status + (Number.isInteger(build.compilation_instances) ? ` · ${build.sources} 个源文件 / ${build.compilation_instances} 个编译实例` : '');
  },
  async startWorkbenchJob(quick = false) {
    if (!this.canStartJob()) return;
    const payload = {request_id: this.workbenchId()};
    if (quick || this.workbenchDepth) payload.scan_depth = quick ? 'fast' : this.workbenchDepth;
    if (this.workbenchStopAt) {
      const stop = new Date(this.workbenchStopAt);
      if (Number.isNaN(stop.getTime()) || stop.getTime() <= Date.now()) { this.jobActionError = '请选择未来的本轮停止时间。'; return; }
      payload.stop_at = stop.toISOString();
    }
    this.jobCommand = {url: '/api/jobs', payload, projectRoot: this.preparation.project?.root}; this.persistJobCommand();
    await this.sendJobCommand();
  },
  async controlJob(action) {
    if (!['cancel', 'resume'].includes(action) || !this.job?.capabilities?.[action] || this.jobBusy || this.jobCommand || this.jobsError) return;
    this.jobCommand = {url: `/api/jobs/${action}`, payload: {job_id: this.job.job_id, base_revision: this.job.revision, request_id: this.workbenchId()}};
    this.persistJobCommand();
    await this.sendJobCommand();
  },
  async sendJobCommand() {
    if (!this.jobCommand || this.jobBusy) return;
    const command = this.jobCommand;
    if (command.url === '/api/jobs' && (this.configDirty || this.configSaving || this.configLoading || !this.preparation || !this.preparationStartAllowed()
      || (command.projectRoot && command.projectRoot !== this.preparation.project?.root))) {
      this.jobActionError = '工程或配置已变化，请恢复并核对原工程后重试该请求；不会在另一个工程重复启动。';
      return;
    }
    this.jobBusy = true; this.jobActionError = '';
    const request = ++this.jobRequest;
    this.jobListRequest++;
    try {
      const data = await this.workbenchFetch(command.url, {method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(command.payload)});
      if (data.schema !== 'zscope.scan-jobs.v1') throw new Error('作业服务响应版本不匹配；操作结果尚未确认。');
      if (!data.job?.job_id || !Number.isInteger(data.job.revision)) throw new Error('作业响应缺少身份或版本；操作结果尚未确认。');
      if (request === this.jobRequest) { this.applyJob(data.job); this.jobsError = ''; this.activeTab = 'jobs'; }
      else this.jobs = [data.job, ...this.jobs.filter(item => item.job_id !== data.job.job_id)];
      this.jobCommand = null; this.persistJobCommand();
    } catch (error) {
      // A transport failure may follow a successful POST. Preserve its idempotency key.
      if ([400, 404, 409, 422, 503].includes(error.status)) { this.jobCommand = null; this.persistJobCommand(); }
      this.jobActionError = ({revision_conflict: '作业版本已变化，已保留当前选择。请核对最新状态后再操作。', invalid_state: '作业状态已变化，此操作未执行。请核对最新状态。', project_scan_active: '本工程已有活动作业，请在作业列表中查看。'})[error.code] || error.message;
      if (error.status === 409) await this.loadJobs({quiet: true});
    } finally { this.jobBusy = false; }
    if (!this.jobCommand) await this.loadJobs({quiet: true});
  },
  jobResultMatches(job, binding) {
    return !!binding?.job_id && !!binding?.run_id && !!binding?.input_revision && !!binding?.report_id
      && job?.job_id === binding.job_id && job?.run_id === binding.run_id
      && job?.input_revision === binding.input_revision && job?.report?.report_id === binding.report_id;
  },
  invalidateJobAcceptance() {
    this.acceptanceBinding = null; this.acceptanceSource = 'current';
    this.acceptanceLoaded = false; this.acceptanceIssues = []; this.acceptanceReportId = '';
    this.acceptanceCoverage = null; this.acceptanceLoading = false;
    this.instancePlan = null; this.instanceJob = null; this.instanceSearch = ''; this.instanceLimit = 12;
    this.acceptanceError = '所选作业的运行或输入范围已变化，旧报告已移出当前验收。请刷新作业并查看本轮结果。';
  },
  async openJobResult() {
    if (!this.job?.report?.available) return;
    const id = this.job.job_id;
    const run = this.job.run_id;
    const input = this.job.input_revision;
    const report = this.job.report.report_id;
    const request = ++this.acceptanceRequest;
    this.jobResultError = '';
    try {
      const data = await this.workbenchFetch(`/api/jobs/result?job_id=${encodeURIComponent(id)}`);
      if (this.job?.job_id !== id || this.job?.run_id !== run || this.job?.input_revision !== input
        || this.job?.report?.report_id !== report || request !== this.acceptanceRequest) return;
      if (data.job_id !== id || !data.report_available || !data.findings) throw new Error(data.reason || '本轮报告尚未可用，已完成范围仍保留在作业状态。');
      if (!this.jobResultMatches(this.job, data.binding) || data.report_id !== data.binding.report_id) {
        if (this.acceptanceBinding) this.invalidateJobAcceptance();
        throw new Error('报告对应的运行或输入范围已变化。请刷新作业，再查看本轮结果。');
      }
      this.applyAcceptance(data.findings); this.acceptanceSource = id;
      if (this.instanceJob?.job_id !== id || this.instanceJob?.run_id !== run) this.instanceJob = null;
      this.acceptanceBinding = {...data.binding}; this.activeTab = 'acceptance';
    } catch (error) { if (this.job?.job_id === id && this.job?.run_id === run && this.job?.input_revision === input
      && this.job?.report?.report_id === report && request === this.acceptanceRequest) this.jobResultError = error.message; }
  },
  applyAcceptance(data) {
    if (!Array.isArray(data.findings) || !data.report_id) throw new Error('报告尚未生成，或缺少可核对的报告身份。');
    this.acceptanceReportId = data.report_id;
    this.acceptanceBinding = null;
    this.acceptanceIssues = data.findings;
    this.acceptanceCoverage = data.coverage || null;
    const plan = data.report?.metadata?.entry_instances;
    this.instancePlan = plan?.schema === 'zscope.entry-instances.v1' ? {...plan,
      instance_analysis: plan.instance_analysis?.schema === 'zscope.instance-analysis.v1' ? plan.instance_analysis : null} : null;
    const job = data.report?.metadata?.job;
    this.instanceJob = job?.schema === 'zscope.scan-session-job.v1' ? job : null;
    this.instanceSearch = ''; this.instanceLimit = 12;
    this.acceptanceLoaded = true; this.acceptanceError = '';
  },
  async loadAcceptance() {
    const request = ++this.acceptanceRequest;
    this.acceptanceLoading = true; this.acceptanceError = '';
    try {
      const data = await this.workbenchFetch('/api/findings?view=with_needs_review');
      if (request !== this.acceptanceRequest) return;
      this.applyAcceptance(data); this.acceptanceSource = 'current';
    } catch (error) { if (request === this.acceptanceRequest) this.acceptanceError = error.message; }
    finally { if (request === this.acceptanceRequest) this.acceptanceLoading = false; }
  },
  acceptanceState(issue) {
    const state = issue?.acceptance?.state;
    return ['confirmed', 'business_conditional', 'pending', 'ruled_out'].includes(state) ? state : 'pending';
  },
  acceptanceLabel(state) { return ({confirmed: '已确认', business_conditional: '条件性', pending: '待验证', ruled_out: '已排除', gaps: '覆盖缺口'})[state] || '待验证'; },
  acceptanceCount(state) {
    if (!this.acceptanceLoaded) return '—';
    if (state === 'gaps') return Array.isArray(this.acceptanceCoverage?.gaps) ? this.acceptanceCoverage.gaps.length : '未测';
    return this.acceptanceIssues.filter(issue => this.acceptanceState(issue) === state).length;
  },
  acceptanceFiltered() {
    const search = this.acceptanceSearch.trim().toLocaleLowerCase();
    return this.acceptanceIssues.filter(issue => this.acceptanceState(issue) === this.acceptanceFilter
      && (!search || [issue.function, issue.location, issue.description, issue.category, issue.acceptance?.resource_label,
        issue.acceptance?.trigger_summary, issue.acceptance?.build_context_id].join(' ').toLocaleLowerCase().includes(search)));
  },
  coverageGaps(coverage) { return Array.isArray(coverage?.gaps) ? coverage.gaps : []; },
  instanceCount(value) { return Number.isSafeInteger(value) && value >= 0 ? String(value) : '未测量'; },
  instanceCompleteness(value) { return value === true ? '已完成' : value === false ? '不完整' : '未测量'; },
  instanceRows() {
    const planned = Array.isArray(this.instancePlan?.instances) ? this.instancePlan.instances : [];
    const outcomes = Array.isArray(this.instancePlan?.instance_analysis?.instances) ? this.instancePlan.instance_analysis.instances : [];
    // Only the exact build and native symbol can associate a plan with an outcome.
    // Missing identity is never a wildcard, and same-name variants stay separate.
    const identity = item => typeof item?.build_context_id === 'string' && item.build_context_id
      && typeof item?.usr === 'string' && item.usr ? JSON.stringify([item.build_context_id, item.usr]) : null;
    const analyzed = new Set(outcomes.map(identity).filter(Boolean));
    const rows = outcomes.filter(item => item && typeof item === 'object').map(item => ({...item}));
    for (const item of planned) {
      if (item && typeof item === 'object' && (!identity(item) || !analyzed.has(identity(item)))) {
        rows.push({...item, status: 'planned'});
      }
    }
    return rows.map((item, index) => ({...item, rowKey: index,
      displayName: item.function_name || (Array.isArray(item.function_names) ? item.function_names.join(' / ') : '') || '入口名称未记录'}));
  },
  instanceFiltered() {
    const search = this.instanceSearch.trim().toLocaleLowerCase();
    return this.instanceRows().filter(item => !search || [item.displayName, item.source, item.build_context_id, item.usr]
      .join(' ').toLocaleLowerCase().includes(search));
  },
  instanceStatus(item) {
    return ({planned: '已规划，尚无分析结果', analyzed: '已分析', failed: '分析失败', skipped: '未分析', deferred: '已延期'})[item?.status] || '分析状态未测量';
  },
  instanceCandidateText(item) {
    const count = this.instanceCount(item?.candidate_count);
    if (count === '未测量') return '候选数量未测量';
    if (item.candidate_count === 0) return '本实例未产生候选；不代表安全';
    return `${count} 个候选；确认程度以问题验收为准`;
  },
  instanceCandidateLabels(item) {
    if (!Array.isArray(item?.candidates)) return '';
    return [...new Set(item.candidates.map(candidate => ({double_free: '重复释放（double_free）'})[candidate?.defect_class]
      || candidate?.defect_class || candidate?.category || '类别未记录'))].join('、');
  },
  gapText(gap) {
    if (typeof gap === 'string') return gap;
    if (gap?.message || gap?.reason) return gap.message || gap.reason;
    if (gap?.kind === 'scan_completeness') return this.coverageText({completeness: gap.detail});
    const label = ({incomplete_compilation_instances: '部分编译实例未完成', link_targets_unverified: '链接目标尚未核验',
      validation_not_completed: '验证尚未完成', pending_validation: '等待验证', additional_gaps_omitted: '还有未展开的覆盖缺口',
      entry_instance_coverage_incomplete: '编译实例扫描覆盖仍不完整', entry_instance_analysis_unwired: '逐编译实例的分析与验证尚未接入', entry_absent_in_variant: '部分构建变体中未找到入口'})[gap?.kind];
    const count = /^count=(\d+)$/.exec(gap?.detail || '');
    return (label || gap?.kind || gap?.code || '存在未说明的覆盖缺口') + (count ? `（${count[1]} 项）` : gap?.detail ? ` · ${String(gap.detail).slice(0, 500)}` : '');
  },
  coverageText(coverage) {
    return ({complete: '本轮已完成约定范围', partial: '部分完成，仍有未完成范围', degraded: '部分能力不可用',
      failed: '执行失败，结果不完整', interrupted: '已中断，需继续剩余工作'})[coverage?.completeness] || '尚无覆盖测量，不能据此判断安全';
  },
  setAcceptanceFilter(state) { this.acceptanceFilter = state; this.acceptanceLimit = 30; },
  async openAcceptanceIssue(issue) {
    // Detail and review endpoints are bound to the current report. Never silently open
    // an old job's issue against a newer report with the same issue id.
    const expectedReport = this.acceptanceReportId;
    try {
      const data = await this.workbenchFetch('/api/findings?view=with_needs_review');
      if (this.acceptanceReportId !== expectedReport) return;
      if (data.report_id !== expectedReport) throw new Error('当前报告已变化。请加载当前报告后验收；历史作业结果仍可查看。');
      const current = data.findings.find(item => item.issue_id === issue.issue_id);
      if (!current) throw new Error('此问题不在当前报告中，请刷新验收列表。');
      const drafts = new Map((this.dirtyValidationFindings?.() || []).map(item => [item.issue_id, item]));
      if (drafts.size && (this.currentReportId !== expectedReport || [...drafts.keys()].some(id => !data.findings.some(item => item.issue_id === id)))) {
        throw new Error('有复核草稿尚未保存，且报告范围已变化。请先回到问题详情处理草稿；当前输入已保留。');
      }
      this.ingestFindingsPayload(data, 'with_needs_review');
      this.reportViewCache.with_needs_review = this.reportViewCache.with_needs_review.map(item => drafts.get(item.issue_id) || item);
      this.reportView = 'with_needs_review'; this.findings = this.reportViewCache.with_needs_review;
      this.activeTab = 'findings';
      this.selectFinding(this.findings.find(item => item.issue_id === current.issue_id));
    } catch (error) { this.acceptanceError = error.message; }
  },
  dispositionKey(report, issue) { return JSON.stringify([report, issue]); },
  persistDispositionDraft(draft = this.disposition) {
    if (!draft?.key) return;
    try {
      const key = `zscope.disposition-draft:${draft.key}`;
      if (this.dispositionChanged(draft)) sessionStorage.setItem(key, JSON.stringify(draft));
      else sessionStorage.removeItem(key);
    } catch (_) { /* Limited browser storage leaves the current draft in memory. */ }
  },
  dispositionChanged(draft = this.disposition) {
    return !!draft && JSON.stringify([draft.type, draft.reason, draft.duplicate_of, draft.title]) !== draft.original;
  },
  async loadDisposition(finding) {
    const request = ++this.dispositionRequest;
    this.disposition = null; this.dispositionError = ''; this.dispositionLoading = true;
    const reportId = finding?.report_id || this.currentReportId;
    if (!reportId || !finding?.issue_id) { this.dispositionLoading = false; return; }
    const key = this.dispositionKey(reportId, finding.issue_id);
    try {
      const data = await this.workbenchFetch(`/api/acceptance/dispositions?report_id=${encodeURIComponent(reportId)}&issue_id=${encodeURIComponent(finding.issue_id)}`);
      if (request !== this.dispositionRequest) return;
      if (data.schema !== 'zscope.acceptance-dispositions.v1' || data.report_id !== reportId || data.issue_id !== finding.issue_id
        || !data.context_revision || !Number.isInteger(data.revision)) throw new Error('处置记录缺少身份或证据版本，草稿未提交。');
      let previous = this.dispositionDrafts[key];
      if (!previous) {
        try { previous = JSON.parse(sessionStorage.getItem(`zscope.disposition-draft:${key}`) || 'null'); } catch (_) {}
        if (previous?.report_id !== reportId || previous?.issue_id !== finding.issue_id || previous?.key !== key) previous = null;
      }
      if (previous && this.dispositionChanged(previous)) {
        previous.stale = previous.revision !== data.revision || previous.build_context_id !== data.build_context_id
          || previous.context_revision !== data.context_revision;
        previous.writable = data.writable; this.dispositionDrafts[key] = previous; this.disposition = previous;
      } else {
        const value = data.disposition || {};
        const draft = {...data, key, type: value.type || 'risk_accept', reason: value.reason || '', duplicate_of: value.duplicate_of || '', title: value.title || '', stale: false};
        draft.original = JSON.stringify([draft.type, draft.reason, draft.duplicate_of, draft.title]);
        this.dispositionDrafts[key] = draft; this.disposition = draft;
      }
    } catch (error) { if (request === this.dispositionRequest) this.dispositionError = error.message; }
    finally { if (request === this.dispositionRequest) this.dispositionLoading = false; }
  },
  async reloadDisposition() {
    if (this.disposition && this.dispositionChanged() && !confirm('重新载入将丢弃这条处置草稿，是否继续？')) return;
    if (this.disposition) {
      try { sessionStorage.removeItem(`zscope.disposition-draft:${this.disposition.key}`); } catch (_) {}
      delete this.dispositionDrafts[this.disposition.key];
    }
    await this.loadDisposition(this.selectedFinding);
  },
  async saveDisposition() {
    const draft = this.disposition;
    if (!draft?.writable || !draft.context_revision || draft.stale || this.dispositionSaving || !this.dispositionChanged(draft)) return;
    if (draft.type !== 'clear' && !draft.reason.trim()) { this.dispositionError = '请填写本次处置的原因。'; return; }
    if (draft.type === 'duplicate' && !draft.duplicate_of.trim()) { this.dispositionError = '请指定同一报告、同一构建中的重复问题 ID。'; return; }
    const payload = {report_id: draft.report_id, issue_id: draft.issue_id, build_context_id: draft.build_context_id,
      base_revision: draft.revision, base_context_revision: draft.context_revision, type: draft.type, reason: draft.reason};
    if (draft.type === 'duplicate') payload.duplicate_of = draft.duplicate_of.trim();
    if (draft.type === 'followup' && draft.title.trim()) payload.title = draft.title.trim();
    const fingerprint = JSON.stringify(payload);
    if (draft.pendingFingerprint !== fingerprint) { draft.pendingFingerprint = fingerprint; draft.requestId = this.workbenchId(); }
    payload.request_id = draft.requestId;
    this.persistDispositionDraft(draft);
    this.dispositionSaving = true; this.dispositionError = ''; this.toastMessage = '';
    try {
      const data = await this.workbenchFetch('/api/acceptance/dispositions', {method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(payload)});
      if (!data.success || data.report_id !== draft.report_id || data.issue_id !== draft.issue_id
        || !data.context_revision || !Number.isInteger(data.revision)) throw new Error('尚未确认处置是否保存，请使用同一请求重试。');
      // Do not overwrite edits made while this request was in flight, or another issue.
      const unchanged = fingerprint === JSON.stringify({report_id: draft.report_id, issue_id: draft.issue_id, build_context_id: draft.build_context_id,
        base_revision: draft.revision, base_context_revision: draft.context_revision, type: draft.type, reason: draft.reason,
        ...(draft.type === 'duplicate' ? {duplicate_of: draft.duplicate_of.trim()} : {}),
        ...(draft.type === 'followup' && draft.title.trim() ? {title: draft.title.trim()} : {})});
      draft.revision = data.revision; draft.context_revision = data.context_revision;
      draft.disposition = data.disposition; draft.writable = data.writable;
      if (unchanged) draft.original = JSON.stringify([draft.type, draft.reason, draft.duplicate_of, draft.title]);
      draft.requestId = null; draft.pendingFingerprint = null;
      this.showToast('处置已保存，验证结论与待验证风险保持独立', 'success');
    } catch (error) {
      if (error.status === 409) draft.stale = true;
      if (this.disposition?.key === draft.key) this.dispositionError = error.message;
      else this.showToast(`处置保存未完成：${error.message}`, 'error');
    } finally { this.persistDispositionDraft(draft); this.dispositionSaving = false; }
  },
};
