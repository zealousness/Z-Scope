/* Persistent scan plans: all timers and resume decisions live on the server. */
window.ZScopeSchedules = {
  scheduleKind:'once', scheduleStart:'now', scheduleStartAt:'', scheduleEnd:'complete',
  scheduleTimezone:Intl.DateTimeFormat().resolvedOptions().timeZone || 'UTC',
  scheduleDailyStart:'23:00', scheduleDailyEnd:'07:00', schedules:[], schedulesError:'',
  schedulesBusy:false, scheduleCommand:null, schedulesReady:false,
  initSchedules() {
    try { this.scheduleCommand = JSON.parse(sessionStorage.getItem(this.scheduleStorageKey()) || 'null'); } catch {}
    this.loadSchedules();
    this.scheduleTimer = setInterval(() => { if (this.activeTab === 'jobs' || this.activeTab === 'prepare') this.loadSchedules(); }, 5000);
  },
  scheduleStorageKey() { return 'zscope.schedule-command.' + (new URLSearchParams(window.location.search).get('project') || 'legacy'); },
  saveScheduleCommand() { try { if (this.scheduleCommand) sessionStorage.setItem(this.scheduleStorageKey(),JSON.stringify(this.scheduleCommand)); else sessionStorage.removeItem(this.scheduleStorageKey()); } catch {} },
  async loadSchedules() {
    try {
      const data = await this.workbenchFetch('/api/schedules');
      if (data.schema !== 'zscope.scan-schedules.v1') throw new Error('扫描计划服务响应无效');
      this.schedules = data.schedules || []; this.schedulesReady = true; this.schedulesError = '';
    } catch (error) { this.schedulesReady = false; this.schedulesError = error.message; }
  },
  scheduleStatus(value) { return ({waiting:'等待开始',running:'扫描中',completed:'已完成',cancelled:'已取消计划',blocked:'需要处理',failed:'执行失败',expired:'截止已到'})[value] || '状态未知'; },
  canCreateSchedule() { return this.canStartJob() && this.schedulesReady && !this.schedulesBusy && !this.scheduleCommand; },
  scheduleSummary() {
    if (this.scheduleKind === 'daily') return `每天 ${this.scheduleDailyStart}—${this.scheduleDailyEnd}（${this.scheduleTimezone}），窗口内续扫，完成后结束计划。`;
    return (this.scheduleStart === 'now' ? '立即开始' : `${this.scheduleStartAt.replace('T',' ')} 开始`) + (this.scheduleEnd === 'complete' ? '，扫描完成后结束。' : `，${this.workbenchStopAt.replace('T',' ')} 停止。`) + ` 时区：${this.localTimezone()}。`;
  },
  async submitSchedule() {
    if (!this.canCreateSchedule()) return;
    this.jobActionError = '';
    const payload = {request_id:this.workbenchId(),scan_depth:this.workbenchDepth || this.preparation?.scan.depth || 'balanced',start_at:null,end_mode:'complete',stop_at:null,daily_window:null};
    if (this.scheduleKind === 'daily') {
      if (!this.scheduleDailyStart || !this.scheduleDailyEnd || this.scheduleDailyStart === this.scheduleDailyEnd) { this.jobActionError = '每日窗口的开始与结束时间必须不同。'; return; }
      payload.daily_window = {timezone:this.scheduleTimezone,start:this.scheduleDailyStart,end:this.scheduleDailyEnd};
    } else {
      if (this.scheduleStart === 'later') {
        const start = new Date(this.scheduleStartAt);
        if (!this.scheduleStartAt || !Number.isFinite(start.getTime()) || start.getTime() <= Date.now()) { this.jobActionError = '请选择未来的开始时间。'; return; }
        payload.start_at = start.toISOString();
      }
      payload.end_mode = this.scheduleEnd;
      if (this.scheduleEnd === 'deadline') {
        const end = new Date(this.workbenchStopAt), start = payload.start_at ? new Date(payload.start_at).getTime() : Date.now();
        if (!this.workbenchStopAt || !Number.isFinite(end.getTime()) || end.getTime() <= start) { this.jobActionError = '停止时间必须晚于开始时间。'; return; }
        payload.stop_at = end.toISOString();
      }
    }
    this.scheduleCommand = {url:'/api/schedules',payload,configPath:this.preparation.config_path}; this.saveScheduleCommand();
    await this.sendScheduleCommand();
  },
  async cancelSchedule(schedule) {
    if (this.schedulesBusy || this.scheduleCommand) return;
    this.scheduleCommand = {url:'/api/schedules/cancel',payload:{schedule_id:schedule.schedule_id,base_revision:schedule.revision,request_id:this.workbenchId(),stop_running:true},configPath:this.preparation?.config_path};
    this.saveScheduleCommand(); await this.sendScheduleCommand();
  },
  async sendScheduleCommand() {
    if (!this.scheduleCommand || this.schedulesBusy) return;
    const command = this.scheduleCommand;
    if (command.configPath !== this.preparation?.config_path || (command.url === '/api/schedules' && (this.configDirty || this.configSaving || !this.preparationStartAllowed()))) { this.jobActionError = '请先读取原项目已保存配置，再核对原请求。'; return; }
    this.schedulesBusy = true; this.jobActionError = '';
    try {
      const data = await this.workbenchFetch(command.url,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(command.payload)});
      if (data.schema !== 'zscope.scan-schedules.v1' || !data.schedule?.schedule_id) throw new Error('计划响应缺少身份，请核对并重试原请求。');
      this.scheduleCommand = null; this.saveScheduleCommand(); this.navigate('jobs');
      await this.loadSchedules(); await this.loadJobs();
    } catch (error) {
      this.jobActionError = error.message;
      if ([400,404,409,422,503].includes(error.status)) { this.scheduleCommand = null; this.saveScheduleCommand(); }
    } finally { this.schedulesBusy = false; }
  },
};
