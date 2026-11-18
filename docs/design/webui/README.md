# WebUI 新旧对照交付

## 项目原语本轮交付

[项目原语实际对照](primitives.html)覆盖“首次配置原语、发现并审阅、接口更新后复核”三个流程，提供 1440/390px 截图、操作录屏和可导出的偏好清单。旧版没有等价原语页面，因此使用保留的旧配置页说明入口差异，不将新增功能伪装为旧版已有页面。新截图来自实际 Web/HTTP 与明确标注的合成证据；真实 native 验收另见 [本轮验证记录](PRIMITIVES-VALIDATION.md)。问题工作台布局仍待用户决策。

## 本轮实际展示与追加原型

[本轮实际实现画廊](index.html#current-implementation)展示五页 1440/390px 共 10 张实际页面截图，支持桌面／手机切换、并排与单独打开；真实 HTTP/SQLite 使用合成工程，采集不执行协调器、扫描器或模型。`assets/followup/manifest.json` 记录来源与媒体摘要。它和下方首轮历史对照、独立原型分别标注，不混用截图。

`followup.html` 独立演示工程选择、四步创建向导、YAML 父目录作为唯一根、快速/均衡/深度三种模式，以及单次开始/截止与每日运行时段。`prototype.html` 顶部和对照首页均提供入口。问题工作台标记为待决并链接回上一轮原型；不将其列为本轮已完成修改。此追加页的工程和计划仅保存在浏览器，不调用接口或写入真实配置，也没有替换旧截图冒充实际实施结果。

运行 `/usr/local/bin/node docs/design/webui/verify-followup.cjs` 可验证向导、Java 模式限制、时间计划保存/刷新/取消、工程隔离与四种窗口的布局；此检查不改原有截图或 capture manifest。

直接打开 `index.html` 查看逐页对照与偏好选择，打开 `prototype.html` 查看独立可点击原型。两者均不需要联网或构建；原型所有数据明确为合成演示，不调用 API。浏览器本地存储受限时，使用 JSON / Markdown 导出保留选择。

`assets/` 中截图由真实旧版和新版产品 HTML、CSS、JavaScript 配合完全合成的模拟 API 生成，展示相同任务与问题。旧版概览截图使用项目准备，覆盖截图使用原集中验收区域；旧版没有这两个独立页面。媒体只证明页面展示与演示交互，不能代替真实服务端、工具执行或扫描验收。

截图脚本：`tests/fixtures/webui_redesign_capture.cjs`。截图清单包含静态源码 SHA-256、模拟数据 SHA-256、浏览器错误及采集时间；可据此判断截图是否对应当前源码。原型设计和实际产品截图明确分开，不用原型替代实施结果。

选择清单只记录偏好，不能改变产品。报告绑定、构建身份、未知覆盖和停止时间正确性应与视觉偏好分别评估。

[首轮变化、验证结果与已知限制](VALIDATION.md)保留当时接入内容及 native 扫描失败记录。后续修复与真实扫描验收见 [工程与时间计划记录](FOLLOWUP-VALIDATION.md) 和 [项目原语验证记录](PRIMITIVES-VALIDATION.md)，不将首轮的历史失败当作当前实现状态。

## 验证与复现

在 WSL Linux 项目目录运行：

```bash
/usr/local/bin/node tests/fixtures/webui_redesign_capture.cjs
/usr/local/bin/node docs/design/webui/verify.cjs
```

可通过 `ZSCOPE_UI_PLAYWRIGHT_MODULE` 与 `ZSCOPE_UI_CHROMIUM` 指定 Playwright 模块与 Chromium 可执行文件；默认路径匹配当前 WSL 开发环境。截图脚本支持 `--before-only` / `--after-only` 更新单边；两侧使用同一个内置合成 fixture，不能传入真实工程数据。

已在 WSL Chromium 验证：原型 6 个状态 × 5 页 × 2 个窗口共 60 个组合、24 张匹配截图的加载、桌面与手机对照布局、偏好刷新恢复、JSON / Markdown 导出；无页面异常或外部网络请求。实际页面采集未执行 API 写入，报告 Markdown 正常渲染。截图与录屏摘要见 `assets/capture-manifest.json`。产品后端回归结果见 [验证记录](VALIDATION.md)，模拟 API 检查不作为后端通过依据。

产品浏览器检查使用同一合成 API，在 390、1280、1440、1920px 四种窗口验证六页无横向溢出、Enter 键选择问题、复核处置正常加载、结论/文件/构建/关键词筛选与问题定位刷新恢复、返回恢复，以及失效报告链接隐藏写入界面。历史快照演示区分外层 artifact 与内层 review report，并核对 job/run/input/artifact/report 全部身份。这些检查只验证前端对所给响应的行为，不证明服务器授权或完整扫描能力。

当前录屏展示准备页、任务、问题、覆盖与复核入口的真实按钮导航；为了避免创建演示扫描，不点击启动、保存或后台控制按钮。原型使用精简数据演示意图，细节不完全等同于产品。旧版没有独立概览与诊断页，这两张旧版截图因此分别来自原准备和集中验收页面。
