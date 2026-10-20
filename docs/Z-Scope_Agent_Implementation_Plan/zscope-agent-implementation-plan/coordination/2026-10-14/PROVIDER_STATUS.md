# 本轮 provider 与失败分类核对

仅提取非秘密配置字段；没有输出密钥/请求头/完整环境，没有修改凭据、provider 或持久访问配置。证据：[provider-audit.json](provider-audit.json)、[installed-entry-audit.json](installed-entry-audit.json) 和公开 MCP 回执。

| 对象 | 本轮事实 | 失败类别与提示 |
|---|---|---|
| Agent-Bridge | 正式入口 `C:\Users\10273\.local\bin\agent-bridge.exe`，0.1.0；官方 stdio + 标准 SDK `ClientSession.list_tools/call_tool` | 普通沙箱启动器路径错误经正式权限升级后 help/version 正常；不是已证明的安装损坏 |
| DeepSeek Harness | `task_0de1f64677`，请求 `deepseek-v4.1-flash`；未传 provider/base_url 覆写；Bridge 发现的是旧 CLI **0.1.2-rc.1** | `session/configure` 的 native ACP 模型 ID 不匹配，`prompt_may_have_been_sent=false`；不是内容/认证/权限拒绝，未发生模型提示调用 |
| DeepSeek 当前 ACP | 公开会话只公布 `deepseek-official/deepseek-v4-flash`、`...v4-pro`、`...v4-flash-vision-exp` | 没有约定的 `deepseek/deepseek-v4.1-flash`，未设置其它模型替代；**没有成功选定 provider，实际 HTTP base_url 未发生/未核实**，不能说已经向官方端点发送 |
| DeepSeek 约定配置 | `.dsh/settings.yaml.imported` 与 `profiles/desktop/cordis.patch.yml` 均保存 `provider=deepseek`、`model=deepseek-v4.1-flash`、`baseURL=https://st8tp3ajl0df3n8b8l8qu.apigateway-cn-beijing.volceapi.com/v1` | 约定本身得到配置证据；`settings.yaml` 当前不存在，当前 ACP 两个 profile 文件未含上述 whitelisted 路由字段；本轮**未证明走了约定 provider** |
| DeepSeek 正确安装入口 | 已找到 `C:\Users\10273\AppData\Local\Programs\DeepSeek Harness\resources\runtime\cli\bin\dsh.cmd`；静态 ASAR package `@deepseek-ai/dsh-desktop-host` **0.2.0-rc.2** | 与本轮 Bridge 实际发现的旧 0.1.2-rc.1 不同；未直接启动 worker CLI 或替换持久 Bridge 配置 |
| ZCode | 本轮公开 `list_agents available=false`：`zcode-acp-server not found; zcode-acp not found` | **没有 dispatch、没有任务 ID、没有 glm-5.3 提示/HTTP 请求**；是本地 ACP 命令发现失败，不能称模型拒绝或 provider 认证失败 |
| ZCode 配置证据 | `.zcode/v2/config.json` 有自定义 provider `97ad75c3-e785-4369-9730-55a5ee47c71c`，名称 **hw**；模型键 `glm-5.3`、`glm-5.3-flash`，baseURL 同上火山网关 | 可以确认该路由在现配置存在；尚未通过正式 ACP 会话核实其实际选择，不假定 built-in BigModel/Z.ai 是约定路由 |
| ZCode 安装 | `@zcode/desktop` 3.11.2；当前已查安装目录没有独立 ACP wrapper，包 metadata无 bin | 历史 0.67.0 ACP adapter 与 model.options 补丁仍需定位；桌面app版本不能当作ACP版本 |

修复范围应先对齐**已安装正式入口、ACP 会话实际可见的既有 provider/model 路由**：DeepSeek Bridge command 应指向已有 bundled dsh.cmd，并让 ACP 读取已约定的 deepseek 自定义模型；ZCode 需找回既有 0.67.0 adapter/正式 wrapper 并核实 hw/glm-5.3。若必须改项目外 Bridge command/profile、修补 adapter 或重新安装，先由父任务取得该精确变更授权。本轮没有换 provider/model 后重试上述两项，没有新建凭据。

两个独立 Kimi 请求完整 advertised ID `volceapi/kimi-k3`，曾公开 running/no warnings，但随后因 Unified exec transport 丢失，公开恢复查询已将 `task_6b7b3fc3cf`、`task_1198b0d674` 标记 **failed / bridge_restarted**，native 会话 `idle_unloaded`。原隔离目录未新增 jobs 模块/全变体测试；S01 的四个允许修改文件仍匹配捕获基线。当前机器另有两个 Kimi 进程，父链属于其他 Bridge/进程，不归本轮当前后台客户端；不终止或操作它们。当前后台标准客户端 PID 95496，公开工具链仍保持连接；旧请求已持久标记 consumed，禁止重启自动重放。此故障是任务生命周期/传输问题，不能当平台内容拒绝，也不能继续报告旧 running 为实时状态。
