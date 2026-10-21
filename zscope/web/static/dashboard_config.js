/* Public v3 document editing. Keep original values until a field is edited. */
window.ZScopeConfigEditor = {
  configRequest: 0, configEditRevision: 0, configLoading: false, configSaving: false,
  configError: '', v3Form: null, v3InitialForm: null,
  modelNumberFields: ['max_tokens', 'timeout', 'max_retries', 'base_url_rate_limit_per_minute', 'base_url_max_concurrent_requests'],
  modelBooleanFields: ['retry_until_available', 'supports_structured_output'],
  cloneConfig(value) { return JSON.parse(JSON.stringify(value)); },
  configLines(value) { return Array.isArray(value) ? value.join('\n') : String(value ?? ''); },
  parseConfigLines(value) { return String(value).split(/\r?\n/).map(item => item.trim()).filter(Boolean); },
  markConfigDirty() {
    this.configDirty = true; this.configEditRevision++;
    this.clearPreparation();
  },
  clearPreparation() {
    this.preparationRequest++; this.preparation = null;
    this.preparationLoading = false; this.preparationError = '';
  },
  async loadPreparation() {
    if (this.configDirty || this.configSaving || this.configLoading) return;
    const request = ++this.preparationRequest;
    this.preparationLoading = true; this.preparationError = ''; this.preparation = null;
    try {
      const data = await this.workbenchFetch('/api/scan/prepare');
      if (request === this.preparationRequest && !this.configDirty) {
        this.preparation = data; this.restoreJobCommand();
      }
    } catch (error) {
      if (request === this.preparationRequest) this.preparationError = error.message || '准备检查失败，请检查配置。';
    } finally { if (request === this.preparationRequest) this.preparationLoading = false; }
  },
  async loadStructuredConfig({discard = false} = {}) {
    if (this.configSaving || (this.configDirty && !discard)) return;
    const request = ++this.configRequest;
    const revision = this.configEditRevision;
    this.clearPreparation(); this.configLoading = true; this.configError = '';
    this.structuredConfigStatus = '加载中…';
    try {
      const data = await this.workbenchFetch('/api/config/structured');
      if (request !== this.configRequest || revision !== this.configEditRevision) return;
      const cfg = data.config;
      if (!cfg || typeof cfg !== 'object' || Array.isArray(cfg) || !Object.keys(cfg).length) {
        if (this.configDirty) throw new Error('未找到配置文件，当前草稿已保留。请检查配置文件后重新载入。');
        this.structuredConfigAvailable = false; this.structuredConfigStatus = '未找到配置文件';
        return;
      }
      if (![2, 3].includes(cfg.config_version)) throw new Error('此配置版本尚不支持编辑，请检查配置文件。');
      this.structuredConfig = this.cloneConfig(cfg);
      this.populateConfigForm(cfg); this.structuredConfigAvailable = true;
      this.configDirty = false; this.structuredConfigStatus = '配置已载入';
    } catch (error) {
      if (request === this.configRequest) {
        if (!this.configDirty) this.structuredConfigAvailable = false;
        this.configError = error.message;
        this.structuredConfigStatus = this.configDirty ? '加载失败，草稿已保留' : '配置加载失败，可重新载入';
      }
    } finally {
      if (request === this.configRequest) {
        this.configLoading = false;
        if (revision === this.configEditRevision && !this.configDirty) await this.loadPreparation();
      }
    }
  },
  reloadStructuredConfig() {
    if (this.configSaving) return;
    if (this.configDirty && !confirm('当前项目配置有未保存修改，确定重新载入并丢弃这些修改？')) return;
    return this.loadStructuredConfig({discard: true});
  },
  populateV3Form(cfg) {
    const project = cfg.project || {}, scan = cfg.scan || {}, execution = cfg.execution || {};
    this.v3Form = {
      project: {root: project.root ?? '.', language: project.language, platform: project.platform ?? 'linux_user'},
      targets: (project.targets || []).map(target => ({...target, _key: this.workbenchId()})),
      scan: {preset: scan.preset ?? 'overnight', focus: this.configLines(scan.focus ?? ['memory', 'resources', 'async_lifecycle']), reproduction: scan.reproduction ?? 'auto'},
      execution: {timezone: execution.timezone ?? '', stop_at: execution.stop_at ?? '', max_workers: String(execution.max_workers ?? '')},
      profiles: Object.entries(cfg.llms || {}).map(([name, profile]) => {
        const row = {name, base_urls: this.configLines(profile.base_urls), models: this.configLines(profile.models), api_key: ''};
        for (const field of [...this.modelNumberFields, ...this.modelBooleanFields]) row[field] = profile[field] == null ? '' : String(profile[field]);
        return row;
      }),
    };
    this.v3InitialForm = this.cloneConfig(this.v3Form);
  },
  addV3Target() {
    this.v3Form.targets.push({_key: this.workbenchId(), id: '', compile_commands: ''});
    this.markConfigDirty();
  },
  removeV3Target(key) {
    if (this.v3Form.targets.length <= 1) return;
    this.v3Form.targets = this.v3Form.targets.filter(target => target._key !== key);
    this.markConfigDirty();
  },
  buildV3Config() {
    const cfg = this.cloneConfig(this.structuredConfig), form = this.v3Form, initial = this.v3InitialForm;
    // Comparing with the displayed baseline preserves omitted defaults, nulls and ${VAR} references.
    const patch = (section, name, value, before, convert = value => value, optional = false) => {
      if (value === before) return;
      if (!cfg[section]) cfg[section] = {};
      if (optional && value === '') delete cfg[section][name];
      else cfg[section][name] = convert(value);
    };
    for (const name of ['root', 'language', 'platform']) patch('project', name, form.project[name], initial.project[name]);
    cfg.project.targets = form.targets.map(target => {
      const {_key, ...raw} = target;
      if (form.project.language === 'java' && raw.compile_commands !== null) delete raw.compile_commands;
      return raw;
    });
    for (const name of ['preset', 'reproduction']) patch('scan', name, form.scan[name], initial.scan[name]);
    patch('scan', 'focus', form.scan.focus, initial.scan.focus, this.parseConfigLines);
    for (const name of ['timezone', 'stop_at']) patch('execution', name, form.execution[name], initial.execution[name], undefined, true);
    patch('execution', 'max_workers', form.execution.max_workers, initial.execution.max_workers, value => this.configNumber(value), true);
    for (const profile of form.profiles) {
      const before = initial.profiles.find(item => item.name === profile.name);
      const output = cfg.llms[profile.name];
      for (const name of ['base_urls', 'models']) if (profile[name] !== before[name]) output[name] = this.parseConfigLines(profile[name]);
      // Blank passwords always mean keep the saved secret/reference.
      if (profile.api_key.trim()) output.api_key = profile.api_key;
      for (const name of this.modelNumberFields) if (profile[name] !== before[name]) {
        if (profile[name] === '') delete output[name]; else output[name] = this.configNumber(profile[name]);
      }
      for (const name of this.modelBooleanFields) if (profile[name] !== before[name]) {
        if (profile[name] === '') delete output[name];
        else output[name] = profile[name] === 'true' ? true : profile[name] === 'false' ? false : profile[name];
      }
    }
    return cfg;
  },
  configNumber(value) {
    if (/\$\{[^}]+\}/.test(value)) return value;
    const number = Number(value);
    if (!Number.isFinite(number)) throw new Error('数字设置无效，请输入数值或 ${环境变量}。');
    return number;
  },
  async saveStructuredConfig() {
    if (!this.structuredConfigAvailable || this.configLoading || this.configSaving) return;
    this.configError = '';
    let config;
    try { config = this.buildStructuredConfig(); }
    catch (error) { this.configError = error.message; return; }
    const request = this.configRequest, revision = this.configEditRevision;
    const submittedForm = this.v3Form ? this.cloneConfig(this.v3Form) : null;
    this.configSaving = true; this.clearPreparation(); this.structuredConfigStatus = '保存中…';
    try {
      const data = await this.workbenchFetch('/api/config/structured', {
        method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({config}),
      });
      if (request !== this.configRequest) return;
      if (!data.success) throw new Error(data.error || '保存失败');
      this.structuredConfig = this.cloneConfig(data.config || config);
      if (revision === this.configEditRevision) {
        this.populateConfigForm(this.structuredConfig); this.configDirty = false;
        this.structuredConfigStatus = '项目配置已保存';
      } else {
        // Newer input remains a draft; compare it against the submitted version.
        if (submittedForm) {
          this.v3InitialForm = submittedForm;
          for (const profile of this.v3Form.profiles) {
            if (profile.api_key === submittedForm.profiles.find(item => item.name === profile.name)?.api_key) profile.api_key = '';
          }
        }
        this.configDirty = true; this.structuredConfigStatus = '已保存提交版本，后续修改仍未保存';
      }
    } catch (error) {
      if (request === this.configRequest) {
        this.configDirty = true;
        this.configError = error.status === 409 ? '配置已发生冲突，草稿已保留。请核对文件后重试或重新载入。' : error.message;
        this.structuredConfigStatus = '保存未确认，草稿已保留';
      }
    } finally {
      this.configSaving = false;
      if (request === this.configRequest && !this.configDirty) {
        await this.loadPreparation(); await this.loadJobs({quiet: true});
      }
    }
  },
};
