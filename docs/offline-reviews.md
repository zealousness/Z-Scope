# Markdown 报告与离线复核

Dashboard 的“离线导出”下载服务端已保存的结果。存在未保存编辑时，先回写；导出不会清除本地草稿。ZIP 解压后包含 `zscope-report/index.html` 和 `zscope-report/issues/<issue-id>.md`。默认视图与含复核视图共享 issue 文件，原视图归属保存在 HTML 目录索引中。HTML 内嵌阅读器、样式、第三方依赖和许可证，正文及复核数据始终来自 `.md`。

## 离线操作

1. 双击 `index.html`，点击“打开报告目录”，选择包含 `issues/` 的解压目录。Chrome/Edge 支持时会请求目录读写授权。
2. 不支持目录写入、授权被拒绝或取消时，可以使用“选择 Markdown / ZIP”。此模式通过下载修改包保存副本，不会声称已写入原文件。
3. 选择 issue，编辑验证状态和本次说明；说明支持 Markdown 预览。切换 issue 保留草稿，关闭页面时提示未保存修改。
4. 直接保存会先比较文件当前内容与读取时的内容。发现外部修改或写入失败时保留草稿，可以下载修改包；成功关闭文件写入流后才显示“已保存”。
5. 线上使用“导入”选择一个或多个 `.md` / ZIP，或者“导入目录”。只合并有效复核；冲突需逐条选择保留线上或采用离线。

**本次说明缺失、为空或只有空白时，整条跳过，即使状态不同或历史说明非空，也不会修改报告、snapshot、baseline 或 suppression。** 已经应用的相同复核不重复写入。旧版单 HTML 导入已停止，请重新导出 Markdown 包。

单 `.md` 上限 16 MiB，导入及导出总 Markdown 上限 128 MiB、最多 10000 条。目录、ZIP 中的不安全路径和重复 issue 不会自动应用。无需启动本地服务器或连接外网。

## Markdown 契约

`schema_version: zscope.issue-markdown.v1` 使用 YAML frontmatter。以下字段均为字符串：

| 字段 | 含义 |
| --- | --- |
| `schema_version` | Markdown 协议版本，与分析结果主 schema 独立 |
| `report_id` | 服务端报告作用域身份的 SHA-256 |
| `issue_id` | 根据完整稳定身份与发生位置生成的 SHA-256；不依赖文件名或列表序号 |
| `base_revision` | 导出时状态、历史人工说明与上下文摘要的版本 |
| `base_context` | Validator、证据及分析上下文摘要 |
| `base_status` | 导出时验证状态，只读 |
| `base_user_rebuttal` | 导出时人工说明，只读 |
| `validation_status` | 本次验证状态，可编辑 |

保留现有状态枚举：`pending`、`needs_review`、`validated`、`rejected`、`uncertain`、`unvalidated`。未知元数据字段、重复 YAML 键、身份歧义、基线不一致或非法状态不会自动回写。

报告正文顺序为问题概述、代码证据与路径、正反证据、分析说明、根因与影响、修复建议、Validator 验证结果，随后附结构化证据及历史人工说明。缺失字段明确标注。源码补充读取复用 Dashboard 的目录限制，并标记为查看/导出时的当前源码摘录；原始报告片段单独保留。

代码围栏的 `zscope:` JSON 附带文件位置、真实行号、关键行及来源。无法可靠定位的片段使用片段内行号；`ir_path_slices:149` 之类的记录编号显示未定位。

### 结构化证据解读

默认展开关键事实、调用与参数路径、证据完整度及限制。服务端根据明确字段生成普通 Markdown 表格和条目，不调用 LLM 改写证据，不将候选事件、规则置信度或已配置引擎列表当作 Validator 结论。保护条件扫描不具决定性、事实覆盖不足和工具命令尚未执行等限制随证据展示。

技术附录默认折叠为“路径与保护条件”“AST/CFG 与语义模型”“规则与工具信息”“身份与追踪数据”，未知字段归入“其他字段”。重复调用边、规则描述和事实切片合并呈现，并保留字段来源路径。完整原始 JSON 单独展开、复制；JSON 不显示源码行号，也没有独立的纵向滚动框。

附录通过 `json zscope:{"kind":"evidence-appendix","version":1}` 围栏标识，内容为 `zscope.evidence-presentation.v1` 展示数据（`groups`、中文 `labels` 和完整 `raw`）。这只扩展只读正文；报告 frontmatter、复核版本及导入行为保持不变。未知附录版本或损坏的附录会显示原文，不阻断其他章节。旧 Markdown 仍能读取、导入，重新导出获得优化后的离线页面。

AST 事件仅在所属文件和函数范围内使用记录行号；调用位置必须有对应调用者文件。入口的明确文件/函数签名可用于匹配调用者，但不会从其他函数位置、IR 编号、哈希或不透明 UID 推断源码行号。缺少范围或存在坐标冲突时明确标注未定位/冲突，不生成误导性跳转。位置链接可跳到现有代码摘录并复制 `文件:行号`。

本次说明具有固定边界，初始为空。提示文字必须放在边界之外：

```markdown
## 本次人工反驳 / 复核说明

<!-- zscope-review:start -->

<!-- zscope-review:end -->
```

只有围栏之外的独立边界行具有协议含义；代码示例内的同名注释不是边界。不要删除边界或留下未闭合的人工说明代码围栏。服务端重新解析 Markdown，只使用状态和本次说明，忽略正文编辑；Validator 原文取线上报告。

## HTTP 接口

- `GET /api/findings`：每条 finding 增加 `report_id`、`issue_id`；压缩列表不用于完整正文。
- `GET /api/issue_report?issue_id=<id>`：返回 `report_id`、`issue_id`、`base_revision`、`markdown` 和 `review`（当前 `validation_status` / `user_rebuttal`）。
- `GET /api/offline_report`：返回 `application/zip`，下载名称 `zscope-report.zip`。
- `POST /api/import_reviews`：接收下面的 JSON；浏览器将目录或 ZIP 解包为文档，服务端独立校验路径、元数据、当前说明及线上版本。

```json
{"documents":[{"path":"issues/<issue-id>.md","content":"完整 Markdown 文本"}]}
```

响应包含 `success`、`results`、`counts` 和 `persistence`。逐条结果含输入 `index`、可解析时的 `issue_id`、`status` 和说明 `message`：

| `status` | 行为 |
| --- | --- |
| `updated` | 已通过既有反馈链路回写 |
| `skipped_empty` | 本次说明为空，零持久化副作用 |
| `unchanged` | 相同状态与本次说明已存在，不重复写入 |
| `conflict` | 基线与当前不同，线上保持不变 |
| `invalid` | 格式、路径、状态或重复身份无效 |
| `unmatched` | 报告或 issue 身份不符/歧义 |

冲突返回 `baseline`、`current`、`incoming` 三组状态/说明，以及 `expected_revision`、`context_changed`、当前 `validation_reasoning`。选择“保留线上”无需写入；“采用离线复核”提交：

```text
POST /api/import_reviews/resolve
{"documents":[{"path":"issues/<issue-id>.md","content":"原离线 Markdown","expected_revision":"冲突响应中的最新版本"}]}
```

确认接口重新读取线上报告并检查版本；变化后继续返回冲突。空说明在确认接口同样跳过。普通在线保存仍使用 `/api/save_findings`；新 UI 的保存只采用状态和人工说明，避免压缩字段覆盖完整报告。

## 开发验证

Linux/WSL 中安装 `.[dev,browser-test]` 和 Playwright Chromium 后执行：

```bash
python -m pytest -q tests/test_issue_markdown.py tests/test_markdown_report_browser.py
python -m pytest -q tests/test_evidence_presentation.py
python -m pytest -q tests/test_web_user_config_workbook_api.py tests/test_portable_release.py tests/test_agent_docs.py
python scripts/portable/web_assets.py
```

浏览器测试覆盖真实 `file://` 断网加载、编辑/下载/重开及线上导入；目录系统权限窗口采用句柄替身，验证读写顺序、写入失败和外部文件冲突。操作系统权限窗口需在目标浏览器上手动授权。
