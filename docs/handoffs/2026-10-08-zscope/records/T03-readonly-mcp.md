# T03：只读 MCP 与 Codex smoke

日期：2026-10-08，Asia/Taipei。开始/结束 HEAD：010f40210b54ba0f79a088312ce5d8be3a82ace0；分支 v1.3.1_feat/llm-wiki。原有文件保留；未提交/推送，没有修改用户 Codex 配置。

implementation_status: complete

verification_status: passed_protocol_and_local_codex_client

## 变更与权限

原 provider/stdio/HTTP 增加 default/read_only/candidate_blind 启动 profile；CLI `--mcp-profile` 在正常加载/建模/索引之前分流。ConfigLoader 的内部只读路径仍严格校验 Config v2，跳过 rollout 状态、usage 注册和扩展 provider 执行。只读工厂不允许注入可能启动后端的自定义索引/runtime，不建 SnapshotStore、UserConfigStore 或 ScanRequestService。

CachedCodeIndex 仅打开项目内已有 KnowledgeDB，函数符号作为 partial 导航提示，数据库无效时 unavailable，不自动重建。旧图/流输入身份无法验证，因此工具可列出但返回 unavailable；当前只读索引不载入 backend findings。candidate_blind 在列举与执行双端拒绝 findings、报告、任意 SQL、prompts 和控制面，且不能绕过调用方 ToolPolicy。人工复核 read_only 可在 ToolPolicy 允许后读 config/reports/latest 资源。详细权限表与无密钥项目级配置见 [只读 MCP](../../../mcp-read-only.md)。

stdio 输出换行 JSON，兼容旧 Content-Length；格式错误可恢复，stdout 无 banner/日志。只读按序 worker 的请求队列有界，并接入现有 CancellationToken；运行中的搜索/SQLite 接受 notifications/cancelled，取消后 ping/后续请求仍有效。退出关闭自己持有的资源，默认注入的借用 CodeIndex 不误关闭。HTTP 原 token/IP/绑定安全条件保留。

## 协议与安全验收

最终组合命令见 [批次验证](batch-validation.md)，356 passed、0 failed、0 skipped，exit 0。

| 验收 | 实际检查 | 结果 |
|---|---|---|
| AC05 | WSL 实际 Python 子进程，两个 profile、两个协议版本，initialize/tools/list/search/read/semantic/越权/错误恢复/退出；旧 framing | passed；test_mcp_read_only 14 项 |
| AC05/AC18 | 活动请求 cancellation、队列单所有者、取消后 ping；客户端进程终止与目标文件状态不变 | passed |
| AC05 | HTTP 临时 loopback server：无 token 401，有 token 仍不能调用 scan.run | passed；HTTP/MCP 安全共回归 |
| AC07 | profile 与 ToolPolicy 取交集、raw alias/任意参数拒绝、报告/SQL/resources/prompts 隔离 | passed |
| AC18 | default 原 MCP、配置、Java、Ledger 与 active discovery | passed |
| 真实 Windows Codex→WSL | 见下一节 | passed |
| 真实模型、正式 Range、长期并发/公网 HTTP、UI 截图 | 未执行 | not_run；没有相应结论 |

开发首轮 21 passed/9 failed，原因是新增 C/C++ 测试 YAML 漏写必填 svf_workers；仅修 fixture 后同组 30 passed。随后 45 项 MCP 安全/取消回归通过。最终全组包含这些用例；没有放宽 Config v2。

## 真实客户端联调

- 客户端：Windows `codex-cli 0.144.4`（实际 `codex --version`）；核对 `codex mcp --help`、`codex app-server --help`、`generate-json-schema --help`，从客户端生成的 schema 核实协议方法。
- server：WSL Ubuntu `/home/zeal/venv313/bin/python`，当前 editable Z-Scope，candidate_blind profile；不是 Windows Python 测试结论。
- 新建临时合成项目，只有单行 demo.c 与最小严格 Config v2；客户端使用独立临时 CODEX_HOME、ephemeral thread，模型 provider 指向未服务的本机端口，未发 turn/start 或模型请求。未触碰用户配置/凭据，未发送仓库源码。
- 用 `codex app-server --strict-config` 的真实 MCP client，initialize→thread/start(ephemeral)→mcpServerStatus/list→mcpServer/tool/call。wsl.exe 参数为 `-d Ubuntu --cd <临时项目WSL路径> -- /home/zeal/venv313/bin/python -m zscope.mcp.server --config <临时项目WSL路径>/zscope.yaml --profile candidate_blind`。
- 真实工具：zscope.code.read、zscope.code.search、zscope.semantic.context、zscope.graph.query、zscope.flow.trace。资源为空，search/read=ok，缺少 semantic map=unavailable，scan.run=forbidden。独立断言检查这些结果，退出码 0。
- 关闭客户端 stdin 并等待退出；检查 /proc，无属于该临时项目的 zscope.mcp.server 遗留进程。
- 持久摘要与完整原始 transcript 的 SHA-256：[T03-codex-smoke.json](T03-codex-smoke.json)。原始本地 transcript 位于本机 `%TEMP%/zscope-client-8f30030e51494064a609097e30923c67/transcript.json`，只含合成项目。实际调用脚本同目录 smoke.ps1；测试不依赖该临时目录继续存在。

Codex 项目级配置依据官方 MCP 文档并经上述真实命令/协议核对；用户自行选择放入目标项目，不自动添加或启用连接。非该客户端版本、Linux 原生 Codex、真实 read_only 人工报告 UI 联调未执行。

## 续接

本批没有改变默认扫描深度，也没有开启新发现 worker。下一批 D01 可复用搜索/源码 revision 与只读 profile，但仍需实现证据登记与资格约束。真正新鲜的图/流和快照依赖完整缓存身份，不能把当前 unavailable/partial 改成通过来扩大能力。模型/正式 benchmark 需用户自行提供显式环境并按 Range 协议执行。
