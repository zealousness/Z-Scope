# DeepSeek 续接方式只读核实

本次只读检查安装包源码；没有启动、恢复或发送 prompt。

会话：`bc51fb3a-c9e7-445e-b6e3-855461b3179c`，preset=standard；cwd `C:\Users\10273\home\work\Z-Scope_1.31\Z-Scope`。
Desktop 安装版本 0.2.0.0，内置 CLI 0.2.0-rc.2；PATH 旧 CLI 0.1.2-rc.1。
安装包：`C:\Users\10273\AppData\Local\Programs\DeepSeek Harness\resources\app.asar`。

源码：
- `dsh/node_modules/@deepseek-ai/dsh-api-session-controller/lib/index.js:399–410`：resumeObserved 验证持久 header.id/cwd、subagent ownership，以 presetForObservation 组装原 setup，调用 `ctx.agents.resume({resumeSessionId: sessionId, agentOptions: this.agentOptions(), setup: composition.setup})`。
- 同文件 850–896：prompt(request) 调 resolveAgent(request.sessionId)，requestId 已被接收则返回 accepted；mode=steer 调 agent.steer，其它合法 mode（queue）调 agent.followup。
- `.../typert.host.js:783–800`：请求字段 requestId/sessionId、mode=queue|steer、content=[{type:text,text:…}]，可选 clientTimeZone。
- 同文件 1229–1253：公开服务契约 ID `@deepseek-ai/dsh-api-session-controller#session/prompt`，service=sessionController、namespace=session、method=prompt。
- writer-held、subagent ownership、preset/cwd conflict 均为明确拒绝条件，不能改 session header、解除 writer lock 或去掉 preset 来重试。

父端决定续接后，可在既有 Desktop 的该 session 输入已保存请求，或使用 Desktop 的既有受支持客户端 session/prompt 入口；提交必须保持上面 exact sessionId，并选 queue，使用稳定 requestId。收到 accepted 只代表接收，仍须观察真实 turn/end 和结果记录。

当前没有可调用的 DeepSeek MCP 工具；只验证了安装包的服务契约，没有验证已运行的 Desktop 传输端点或认证连接。不能据此凭猜测组装 HTTP/WS 地址、读取密钥或伪造内部认证。若父端选择自动提交，须先确认可用的官方 Desktop 客户端/正常连接入口；若没有，只能报告这个具体连接条件，不能谎称已发起。

headless 已核实会拒绝包含 agentPreset 的既有会话，因此不能用 headless 接管 standard session。profile 范围 init/config/help 可能写 cordis.yml，不是只读探测。session-log 默认上传设置与 telemetry 分开；本次没有读取凭据/配置值，也没有发送模型请求。

可直接审核并发送的文本：[V01-V02-DeepSeek-repair-request-20261010.txt](V01-V02-DeepSeek-repair-request-20261010.txt)。内容限定为普通证据生命周期修复和已授权普通回归，不包含真实 sanitizer、容器启动或绕过网络安全策略。

