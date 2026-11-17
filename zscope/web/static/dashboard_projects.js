/* Project selection pins every request to a YAML, including concurrent tabs. */
(() => {
  const originalFetch = window.fetch.bind(window);
  window.fetch = (input, options = {}) => {
    const url = new URL(typeof input === 'string' ? input : input instanceof URL ? input.href : input.url, window.location.href);
    const project = new URLSearchParams(window.location.search).get('project');
    if (project && url.origin === window.location.origin && url.pathname.startsWith('/api/') && !url.pathname.startsWith('/api/projects')) {
      const headers = new Headers(options.headers || (typeof input !== 'string' ? input.headers : undefined));
      headers.set('X-ZScope-Project', project); options = {...options, headers};
    }
    return originalFetch(input, options);
  };
})();

window.ZScopeProjects = {
  projectReady: false, projectPickerEnabled: false, projectLoading: true,
  projectFailure: '', recentProjects: [], currentProject: null,
  projectDirectory: '', projectBrowse: null, projectBusy: false,
  projectWizard: false, projectWizardStep: 1, showSetupGuide: true,
  newProject: {filename:'zscope.yaml',language:'c_cpp',target_id:'main',compile_commands:'build/compile_commands.json',preset:'fast',base_url:'',model:'',api_key:''},
  async projectFetch(url, options = {}) {
    const response = await fetch(url, options); let data;
    try { data = await response.json(); } catch { throw new Error('项目服务返回了无法读取的响应。'); }
    if (!response.ok) throw new Error(data.error || `HTTP ${response.status}`);
    return data;
  },
  async initProjects() {
    try {
      const response = await fetch('/api/projects');
      if (response.status === 404) { this.projectReady = true; return true; }
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || '项目列表读取失败');
      if (!data.enabled) { this.projectReady = true; return true; }
      this.projectPickerEnabled = true; this.recentProjects = data.projects || [];
      this.projectDirectory = data.home || '';
      const params = new URLSearchParams(window.location.search);
      const selected = params.get('project');
      if (!selected && params.get('choose') !== '1' && data.initial_project_id) {
        window.location.replace('/?project=' + encodeURIComponent(data.initial_project_id)); return false;
      }
      if (selected) {
        this.currentProject = this.recentProjects.find(p => p.project_id === selected);
        if (!this.currentProject?.available) throw new Error('项目配置已移动或不可用，请重新选择 YAML 文件。');
        this.projectReady = true; return true;
      }
      await this.browseProjectDirectory(); return false;
    } catch (error) { this.projectFailure = error.message; return false; }
    finally { this.projectLoading = false; }
  },
  projectDownloadURL(path) {
    const identity = new URLSearchParams(window.location.search).get('project');
    return identity ? path + '?project=' + encodeURIComponent(identity) : path;
  },
  leaveProject() {
    // Existing beforeunload guards preserve the user's chance to save drafts.
    window.location.assign('/?choose=1');
  },
  async browseProjectDirectory(path = this.projectDirectory) {
    this.projectBusy = true; this.projectFailure = '';
    try {
      this.projectBrowse = await this.projectFetch('/api/projects/browse?path=' + encodeURIComponent(path));
      this.projectDirectory = this.projectBrowse.path; this.projectWizard = false;
    } catch (error) { this.projectFailure = error.message; }
    finally { this.projectBusy = false; }
  },
  async openProjectPath(path = this.projectDirectory) {
    this.projectBusy = true; this.projectFailure = '';
    try {
      const data = await this.projectFetch('/api/projects/open', {method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({path})});
      window.location.assign('/?project=' + encodeURIComponent(data.project.project_id));
    } catch (error) { this.projectFailure = error.message; }
    finally { this.projectBusy = false; }
  },
  startProjectWizard() {
    this.projectFailure = ''; this.projectWizard = true; this.projectWizardStep = 1;
    this.newProject.api_key = '';
  },
  wizardLanguageChanged() {
    if (this.newProject.language === 'java') this.newProject.preset = 'fast';
  },
  async createProject() {
    this.projectBusy = true; this.projectFailure = '';
    try {
      const payload = {...this.newProject, directory:this.projectBrowse.path};
      if (payload.language === 'java') delete payload.compile_commands;
      const data = await this.projectFetch('/api/projects/create',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(payload)});
      this.newProject.api_key = '';
      window.location.assign('/?project=' + encodeURIComponent(data.project.project_id) + '#tab=project');
    } catch (error) { this.projectFailure = error.message; }
    finally { this.projectBusy = false; }
  },
};
