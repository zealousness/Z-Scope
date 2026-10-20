# Astra U01/U02 前端交付记录

17:08 UTC+8 当前交付覆盖下文旧 pending/fixture 描述：Astra已亲自接线真实jobs与v3只读准备，最终同根定向97passed/92.82s、0skip/0fail，artifacts/ui-jobs-real-20261014/ui-final-results.xml。真实HTTP/SQLite/detached owner，只有scanner/报告明确合成；关闭页面与重启Web保持原owner、丢回包同键唯一scanner、断网重连、并发终态409、源码变化resume/input_revoked、绑定历史快照、进程deadline partial与不继承旧窗口、390px均有证据。真实U02回归保留，旧契约分支在u02-regression内明确标记；不与旧86/7/79相加。

index.html=c739a7976281ef9ab1dc9f747f48f7415466f9fee7622dd12dca700f87215e91；workbench.js=caa7ab961963cfc46781010dc1fa941c4341a2a9bd9ef807c959da29f82e1ff6；workbench.css=c57bd0ca61d564b3cb05b7ddc27aca5043b93762a48ad0dc34d4a11d55b898c0。前端/UI测试均已由Astra冻结，20直接文件/16U02文件前后同字节；11张真实作业/v3和14张U02/契约截图、页面异常与外部请求均0。协调者仅绑定FIRST_PARTY摘要并做最终联合验证。

v3只读展示所有targets/preset映射和未消费声明，multi-target禁启、不经旧v2表单回写，完整v3编辑未开发。当前窗口为owner进程级停止，resume标明新attempt重核输入、不保证仅remaining、不沿用旧窗口；JOB04任务级收尾/JOB06公平remaining、完整实例分析、真实模型全扫描与整个U01/U02/S08计划未验收。此前独立静态/协议/fixture历史记录保留如下。

本记录只说明本轮 Astra 亲自实现的前端。U01/U02 主包、S08 后台作业和完整实施计划未因本记录关闭。未转交前端开发，未修改后端、native、协议核验、规则或被隔离的 caller-wake 分支；保留原工作区修改，未 commit/push。

## 用户路径与实际范围

1. **项目准备**：启动后自动读取已有结构化配置和只读准备接口，显示实际工程、配置文件、执行目录、编译范围、扫描入口与重点、模型配置/连接实测区别、工具存在性、复现模式和独立产物目录。配置有未保存修改时禁止启动；保留明确的构建缺失提示。选择分析深度和可选本轮截止时间，然后开始扫描。截止时间按浏览器显示的时区转为带时区 ISO 时间。
2. **夜间作业**：只连接持久作业合同，不把旧内存 scan 接口冒充后台 owner。列表、选定作业、阶段、真实工作量、未决和延期数、覆盖缺口、集中业务问题、最近活动、停止/继续及结果入口均接入合同。未知分母不显示百分比；停止请求和停止完成分开。服务缺失、断连、错误和加载状态可见，能力不支持时禁用操作。
3. **集中验收**：读取含待复核项的轻量报告，按服务端 `acceptance.state` 展示已确认、条件性、待验证和已排除；覆盖缺口单独显示。缺投影保守列待验证，不从 confidence、模型文本或旧 validation_status 伪造确认。相同位置的不同问题/构建不在前端合并。列表展示触发条件、资源、来源数、构建和复现状态，详情复用完整 Markdown、源码证据与业务前提反馈。
4. **反馈与处置**：确认问题/误报继续使用原反馈路径；业务回答继续使用原带版本的原子保存。重复、暂时接受风险、本地后续修复任务和撤回单独消费 disposition API，不改验证结论、不隐藏 pending。冲突和失败保留草稿，迟到响应不覆盖另一个问题；切换验收详情保留已有复核草稿。后续修复只记录本地任务，不发外部消息或修改业务工程。

## 所有权与文件

- `zscope/web/static/dashboard_workbench.js`：独立 Alpine mixin，合同消费、异步序号/版本、幂等重试、报告身份核对和处置草稿。
- `zscope/web/static/dashboard_workbench.css`：本地响应式样式，1440px 桌面及 390px 手机验证，可见键盘焦点，不增加 Tailwind utility。
- `zscope/web/static/index.html`：在已有页面上增加三步导航/页面及详情处置区；复用配置和证据组件，保留原有修改。
- `tests/test_agent_workbench_ui.py`、`tests/fixtures/agent_workbench_ui.cjs`：Linux 状态转换与真实浏览器回归。契约 transport 明确是 fixture。

共享接口以同目录 `API_CONTRACT.md` 为准。`server.py`、`services.py`、`review_reports.py`、reporting、README/模块文档/21，以及发布脚本/静态锁由后端集成任务维护。新增 JS/CSS 已被现有 package_data 通配包含；FIRST_PARTY 与静态资源锁待集成任务按最终字节更新。

## 恢复与身份边界

- 创建/停止/续跑使用独立 `request_id`；传输失败保留原请求。当前标签页重载通过按配置路径/工程绑定的 sessionStorage 恢复不确定请求，不保存密钥。重试不会自动另造请求标识。
- 轮询返回较旧 revision、切换作业后的迟到请求、旧运行的迟到结果和旧报告详情均不能覆盖当前选择。
- 读取历史作业报告后，进入会写反馈的详情前重新核对当前报告身份；不向新报告误写同名 issue。
- 处置绑定 report/issue/build/revision，未知构建不作为通配。风险接受、重复和 followup 不改变 confirmed/pending。

## 实际验证

执行环境：WSL Ubuntu `/home/zeal/venv313/bin/python` 3.13.15、Linux Node、Chromium 151.0.7922.34。普通沙箱最初返回 `Wsl/E_ACCESSDENIED`，随后在已有用户授权下通过正式 `require_escalated` 工具路径成功；未替换为 Windows Python 结论。

- UI 状态机、真实浏览器、原业务草稿和项目准备：**7 passed**。JUnit：`artifacts/ui-workbench-20261014/ui-results.xml`。
- 报告/接口/交接文档回归：`test_agent_docs`、`test_web_dashboard_server`、`test_issue_markdown`、`test_report_views`，**44 passed**。JUnit：同目录 `report-regression.xml`。集合不累加为独立覆盖。
- `python -m compileall -f -q zscope scripts test tests`：通过。
- `python -m mypy zscope`：330 个源文件通过。
- 新增 Python 测试 Black：通过。没有大范围格式化。

浏览器证据在 `artifacts/ui-workbench-20261014/`：

| 文件 | 实际证据 |
|---|---|
| `01-real-prepare.png` | 真实配置准备 HTTP、含空格工程路径、作业 API 未提供时的禁用状态 |
| `02-real-report.png`、`03-real-detail.png` | 真实报告/详情服务，输入报告明确为合成 UI fixture，不是扫描发现 |
| `04-contract-running.png` | 可见标注的作业合同 fixture，未知分母和问题队列 |
| `05-mobile.png`、`06-mobile-acceptance.png` | 390×844 视口，准备/验收响应式布局，无水平溢出；键盘 Enter 导航 |
| `07-contract-disposition.png` | 可见标注的处置合同 fixture，保存后再制造 409，草稿保留 |
| `browser-evidence.json` | 浏览器版本、真实 HTTP 与 fixture 范围、0 页面脚本异常、0 外部请求 |

首次浏览器测试因测试产物父目录未创建而 setup error；随后两次分别因测试 locator 匹配隐藏详情中的相同文本、可访问性查询默认忽略隐藏 progress 而失败。均修正测试定位并完整复跑通过，没有放宽产品断言。真实页面测试也检查停止/继续、断线禁用、重连、重载不重复启动及处置冲突；这些新 API 操作仍是明确标注的契约模拟。

## 首轮待集成记录（处置状态已由下文真实联调更新）

**真实作业/处置端到端联调为 pending**：本轮浏览器运行时 `/api/jobs` 和 `/api/acceptance/dispositions` 尚未落地；准备、报告和详情使用真实服务，新接口只以 fixture 验证前端行为。需在持久 owner、轻量验收投影和处置服务集成后重新验收真实创建、关闭页面、取消、恢复、时窗截止、进程身份、反馈持久化及冲突。当前结果不证明 JOB01–JOB06 或 U02 整包完成。

U01 全量自动导入/检测平台、源码实际版本摘要、目标选择、完整业务模型问卷/试编译仍由后续配置/服务实现；本界面只消费已有准备字段。跨问题合并批量业务回答、回答后的选择性重算、复现材料的真实执行/复跑同样没有由 UI 自行补造。未运行真实 LLM 扫描、正式准确率评测或 portable 实物 smoke。

## U02 真实 HTTP / SQLite 联调更新

2026-10-14 后端接线后，Astra 在相同工作区亲自完成真实 Chromium 验收。此段取代上面的“处置接口 pending”；**S08 作业接口仍为契约 fixture，未通过真实 owner 联调**。报告证据是明确标注的合成输入，不是扫描器实测发现。

前端补齐 `context_revision` / `base_context_revision`：读取草稿、比较 stale、构造 POST、在途指纹与成功返回全部绑定服务端证据上下文。数值 revision 为 0 的首次未保存草稿也不能套用到变化后的证据。处置草稿和不确定请求标识按 report/issue 保存在当前标签页 sessionStorage；刷新恢复后重新核对构建及上下文。人工处置仍不修改验证结论或业务回答。覆盖缺口现在消费真实 `{kind, detail}`，显示编译实例、链接目标和待完成验证的中文原因及数量；处置下拉框补可访问名称。

执行环境仍为 WSL Ubuntu、Linux Node 与 Chromium 151.0.7922.34。最终定向集合 `test_agent_workbench_ui`、`test_protocol_review_ui`、`test_project_preparation`、`test_acceptance_projection`、`test_acceptance_feedback`、`test_acceptance_http_api`：**86 passed，48.74 秒**，无 skip。该集合包含后端 79 项，不与后端此前的 79 passed 累加。

真实浏览器使用 `ZScopeHandler`、`ConfigService`、`ReportFeedbackService` 和按已保存配置初始化的 `AcceptanceReviewService`；处置持久化到临时测试工程的 `.zscope_acceptance/dispositions.sqlite3`。未替换 U02 成功或冲突响应；只有传输故障注入会让真实 POST 提交后的回包丢失。已经实际验证：

- 服务端投影四态：1 已确认、1 条件性、3 待验证、1 已排除；覆盖缺口独立为 4 项。相同源码位置、不同构建的两项独立显示；资源/来源/复现未测量不填零。
- 风险接受、后续修复、同构建重复关联和撤回经过真实 HTTP 写 SQLite。跨构建重复关联返回 400，输入保留。
- 已保存记录刷新可读；未提交草稿刷新仍在；浏览器离线保存失败后重连成功。
- 真实 POST 已提交但回包丢失，再用完全相同请求重试：revision 保持 3，不重复提交。
- 第二真实客户端抢先保存导致 409 `revision_conflict`，本地草稿保留；合成报告证据改变但 revision 仍为 0 时，旧草稿收到 409 `stale_scope`。
- 重新核对证据后成功保存；新建独立服务实例可读取同一 SQLite 处置。报告原始字节不变，六项验收状态与 coverage 不受处置影响。
- 390×844 手机布局、键盘 Enter 导航、无水平溢出；页面脚本异常 0，外部资源请求 0。

最终证据目录：`artifacts/ui-u02-real-20261014/`。

| 文件 | 证据 |
|---|---|
| `ui-results.xml` | 同次 86 项定向回归 |
| `source-sha256.json` | 浏览器开始与结束均核对一致的 16 个直接 UI/服务/测试文件摘要 |
| `browser-evidence.json` | 浏览器版本、真实响应状态/版本、四态及覆盖、mock 范围 |
| `u02-persistence.json` | 独立服务实例重新打开状态库的核对输入 |
| `02-real-report.png`、`02b-real-ruled-out.png`、`02c-real-conditional.png` | 四态实际页面 |
| `02d-real-coverage.png`、`02e-real-build-identity.png` | 真实覆盖原因、同位置跨构建区分 |
| `03-real-detail.png`、`03b-real-retry.png`、`03c-real-conflict.png`、`03d-real-evidence-conflict.png` | 保存、幂等重试、并发冲突与证据变化冲突 |
| `03e-real-mobile.png` | 真实 U02 移动端页面 |
| `04-contract-running.png`、`05-mobile.png`、`06-mobile-acceptance.png` | 仍明确标注的 S08 作业契约 fixture，不作为 owner 证据 |

测试修正记录：最初合成重复目标/排除目标与另一问题具有同一构建、位置和类别，被现有语义去重合并；改为独立位置后真实四态完整，不修改后端、不手造 acceptance 投影。另修正测试中条件性标签的定位，并给处置下拉框补明确可访问名称。最后一次完整集合通过后保存上述同版本证据。

剩余范围：U01 的未接线准备能力、S08 真实作业生命周期、批量业务问卷/选择性重算、真实复现与完整扫描仍不在本次通过范围。整体 U01/U02 包与实施计划最终验收由父任务负责。首次向原父线程发送本轮进度时正式会话工具返回 `thread not found`；仅进度消息未送达，已向可达的后端协调线程报告，开发与测试未受阻。
