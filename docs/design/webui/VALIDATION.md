# Z-SCOPE WebUI 改版交付与验证记录（首轮历史）

**2026-10-24 更新入口：** 本页保留 2026-10-23 的原始验证结果与失败证据。工程选择、单根配置与时间计划的本轮结果见 [FOLLOWUP-VALIDATION](FOLLOWUP-VALIDATION.md)。此前未通过的真实 native → ScanSession → owner → SQLite → HTTP → 页面链路现已在受限双宏 fixture 上复验通过，证据为 native-current/browser.log（原始产物定位：`../../../artifacts/ui-redesign-validation/py313/native-current/browser.log`） 与 native-evidence.json（原始产物定位：`../../../artifacts/ui-redesign-validation/py313/native-current/native-evidence.json`）。这不代表全工程扫描；下面的原始失败和日志不删除、不改写为通过。

新版已接入现有 Python HTTP 服务与 Alpine.js 页面。默认首页为项目概览，五个主要入口覆盖准备、扫描、问题复核、覆盖诊断和项目设置。[新旧对照](index.html)展示实际产品页面的匹配截图，并提供独立原型、流程录屏和可导出的取舍清单。

本次相关界面与接口检查通过；真实 native 扫描到 WebUI 的完整链路未通过，失败发生在扫描器生成报告之前。下文分别记录证据范围，不能以合成截图代替真实扫描验收。

## 已实现的变化与取舍

| 旧版问题 | 实际调整 | 收益与取舍 | 类型 |
|---|---|---|---|
| 准备、配置与启动入口重复 | 概览提示下一步；扫描任务统一准备、本轮参数和开始扫描 | 入口更清晰；需要熟悉新的导航名称 | 交互 |
| 首页优先呈现操作细节 | 新增工程、任务、问题和覆盖摘要 | 更易判断下一步；详细技术信息需进入对应页面 | 视觉与交互 |
| 集中验收与问题详情分开 | 统一问题队列，支持系统结论、严重度、文件、构建和关键词筛选 | 减少重复定位；历史结果仍保留独立身份约束 | 交互 |
| 多栏信息挤压报告正文 | 列表与详情两栏，详情分为报告与证据、复核与处置、技术详情 | 正文更宽；辅助指标需切换查看 | 视觉与交互 |
| 系统结论与人工操作含义不清 | 系统结论只读，复核、业务回答、处置分别编辑与保存 | 保存范围明确；多个接口不承诺一次原子保存 | 交互 |
| 编译实例与覆盖占据问题首屏 | 独立覆盖与诊断页面，问题工作台优先展示证据 | 减少干扰；需另开诊断页查看完整范围 | 视觉与交互 |
| 缺口数量易被当作完整性结论 | 测量状态与已记录缺口分开，未测量不显示为零或完成 | 避免错误理解“没有问题”；状态需要结合说明阅读 | 正确性 |
| 快速检查忽略本轮停止时间 | 所有启动模式都提交显式停止时间 | 参数与启动请求一致；仍遵循现有后台进程级停止语义 | 正确性 |
| 未消费配置与执行选项混在一起 | v3 未参与执行字段放入有明确说明的高级区域 | 避免误认生效；保留保存能力 | 交互与正确性 |
| 刷新或返回后丢失定位 | URL 保存页面、任务、报告身份、问题与筛选；失效链接显示错误 | 可恢复工作位置；链接不能绕过服务端身份校验 | 交互与正确性 |
| 窄屏阅读、导航和键盘操作困难 | 小于 1100px 切换列表与详情；手机抽屉导航；可聚焦问题卡片与跳至正文 | 手机可完成主要操作；列表与详情不能同时展开 | 视觉与交互 |

以上是当前工作区采用的初版方案，尚未记录用户对每项布局的最终偏好。在对照页选择“采用新版／保留旧版／继续调整”并导出 JSON 或 Markdown，可作为后续调整依据；选择只记录偏好，不修改产品。停止时间、报告身份、未知覆盖等正确性修复应保留，即使选择旧版布局。

保留离线报告导入导出、业务模型工作簿、规则目录、v2/v3 配置、任务恢复以及原有报告身份和构建隔离。没有扩展账号权限、多项目管理、HTTP API、报告 schema 或扫描引擎能力。多目标禁启、Java 模式限制、配置草稿与准备状态约束继续生效；重新尝试不承诺只运行剩余项，也不继承旧停止窗口。

## 对照材料

- [逐页对照与取舍清单](index.html)：6 组页面映射，1440px 与 390px，合计 24 张截图和 2 段录屏，支持查看原尺寸。
- [独立可点击原型](prototype.html)：五个页面与首次使用、准备受阻、运行中、部分完成、结果复核、连接失败六个状态。
- [采集清单](assets/capture-manifest.json)：基线版本、实际源码与媒体 SHA-256、模拟数据摘要、浏览器错误和网络记录。

旧版基线来自改造前冻结的工作区静态文件，记录的 Git HEAD 为 `2693b74665991508affec2d71a181077324ff677`；以文件摘要为准确基线，不将已有工作区修改误称为提交内容。旧版没有独立概览与诊断页，对照左侧分别展示原项目准备与集中验收中的对应信息。

截图和录屏使用真实产品 HTML、CSS、JavaScript 配合相同合成 API。采集没有执行真实扫描或 API 写入，外部网络请求与页面异常均为零。录屏演示导航与阅读，不执行启动、保存或后台控制。

## 验证结果

2026 年 10 月 23 日在 WSL Ubuntu 中执行。有效 Python 环境为 `/home/zeal/.venvs/zscope-fix-validation-20261022/bin/python`，版本 3.13.15；从仓库外确认 editable 安装指向当前 checkout。早期 Python 3.12 环境不满足项目版本要求，其结果不作为本次验收依据。

| 检查 | 结果 | 能证明的范围 |
|---|---|---|
| 工作台及能力边界检查 | 8 passed | 含真实 HTTP 浏览器检查与状态契约；配置保存、任务控制、报告与业务回答冲突、构建隔离、未知覆盖；扫描器为受控 fixture |
| 导航、配置、报告绑定、业务复核、准备与编译实例状态回归 | 28 passed，2 skipped | 两个跳过项为未启用环境变量的导航浏览器与 native 浏览器用例；导航浏览器后来单独覆盖 |
| Web 服务、规则、业务工作簿、Wiki、portable 与导航检查 | 54 passed | 含启用的导航浏览器检查及离线静态资源完整性；与前组存在重叠，不累计为独立用例数 |
| 原型与对照展示 | 通过 | 60 个页面、状态与窗口组合，图片加载、偏好刷新恢复及 JSON / Markdown 导出 |
| 实际页面四种宽度 | 通过 | 390、1280、1440、1920px；无横向溢出，键盘选择、跳至正文、筛选与返回恢复、失效链接阻止显示可写结果 |
| `python -m mypy zscope` | 通过 | 360 个源文件无类型错误 |
| `python -m compileall -f -q zscope scripts test tests` | 通过 | Python 编译检查 |
| 真实 native 编译实例到 WebUI | 1 failed | 扫描器在生成报告前失败，尚未进入产品页面渲染 |

真实 HTTP 浏览器检查的证据保存在 `artifacts/ui-redesign-validation/py313/` 下的 `config`、`workbench`、`jobs`、`jobs-projection`、`ux` 目录。实际页面截图与导航检查采用合成 API；两类证据用途不同，均不构成真实工程完整扫描、LLM 或正式 benchmark 验收。

主要命令在 WSL 项目根目录执行：

```bash
export ZSCOPE_UI_PLAYWRIGHT_MODULE=/mnt/c/Users/10273/.cache/codex-runtimes/codex-primary-runtime/dependencies/node/node_modules/playwright
export ZSCOPE_UI_CHROMIUM=/home/zeal/.cache/ms-playwright/chromium-1234/chrome-linux64/chrome
export ZSCOPE_UI_MULTI_TARGET_EDITING=1
export ZSCOPE_UI_CONFIG_EVIDENCE=artifacts/ui-redesign-validation/py313/config
export ZSCOPE_UI_EVIDENCE=artifacts/ui-redesign-validation/py313/workbench
export ZSCOPE_UI_JOB_EVIDENCE=artifacts/ui-redesign-validation/py313/jobs
export ZSCOPE_UX_BOUNDARY_EVIDENCE=artifacts/ui-redesign-validation/py313/ux
validation_python=/home/zeal/.venvs/zscope-fix-validation-20261022/bin/python

"$validation_python" -m pytest -q tests/test_agent_workbench_ui.py tests/test_ux_capability_boundaries_ui.py --tb=short
"$validation_python" -m pytest -q tests/test_web_dashboard_server.py tests/test_web_rules_api.py tests/test_web_user_config_workbook_api.py tests/test_web_wiki_api.py tests/test_portable_release.py tests/test_dashboard_navigation.py
"$validation_python" -m mypy zscope
"$validation_python" -m compileall -f -q zscope scripts test tests
```

28 passed / 2 skipped 的回归组未设置浏览器与 native 环境变量，文件列表为 `test_dashboard_navigation.py`、`test_config_editor_http.py`、`test_job_result_http_binding.py`、`test_protocol_review_ui.py`、`test_project_preparation.py`、`test_web_request_boundaries.py`、`test_instance_coverage_ui.py`，均位于 `tests/`。截图及原型复现命令见 [交付说明](README.md)。

## 已知限制

`test_instance_coverage_native_owner_http` 启用现有真实 native 工具后失败。扫描器在 `zscope/retrieval/indexing_identity.py` 的运行时输出路径核验处抛出 `ValueError("job_runtime_output_lookup_unverifiable")`，未生成报告；fixture 在 `page.goto()` 之前的报告可用性断言失败。因此不能将这条链路标记为通过，也不能据此判断新版页面渲染失败。

日志保存在 scanner.log（原始产物定位：`../../../artifacts/ui-redesign-validation/py313/native/scanner.log`） 与 browser.log（原始产物定位：`../../../artifacts/ui-redesign-validation/py313/native/browser.log`）。本次没有修改扫描器或 native 工具来规避校验；这条扫描链路需要独立排查并重新验收。

导航恢复页面位置与筛选，不持久化未保存的复核正文。草稿在当前页面会话内保护，离开前提示保存；刷新或关闭前仍应保存。对照页的偏好保存使用浏览器本地存储，存储不可用时应导出文件保留。

长列表采用现有渲染方式，本次未加入分页或虚拟列表；未形成万级问题量的性能基准。浏览器验收以 Linux Chromium 为准，未形成 Safari 或 Firefox 的兼容性结论。
