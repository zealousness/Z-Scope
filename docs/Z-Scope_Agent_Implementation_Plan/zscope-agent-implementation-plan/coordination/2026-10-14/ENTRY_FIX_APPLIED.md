# 用户级入口修改已执行

用户在父任务明确批准 User PATH 与用户 Bridge 启动配置两处修改后，于 **2026-10-14 11:17:22 UTC+8** 执行。没有修改系统PATH、凭据、安全设置或第三方包，没有重启持有当前Kimi作业的实例。

## 修改与验证

- User `Path`：将 `C:\Users\10273\AppData\Local\Programs\DeepSeek Harness\resources\runtime\cli\bin` 插入 `C:\Users\10273\home\tool\npm-global` 前；其它条目保留，共享目录及其Claude/Codex/Gemini/OpenCode/pnpm未删除。原注册表值类型保留，Machine Path写前/写后完全一致。
- `C:\Users\10273\.agent-bridge\agents.toml`：只更新 `agents.dsh/zcode.command` 与对应重复相同绝对command的 `fallback_commands`。DeepSeek使用 `cmd.exe /d /c call <bundled dsh.cmd> --profile acp`；ZCode使用现有0.67.0 wrapper。其它TOML键与原解析数据逐项相等；原编码/BOM/换行保留。
- 新进程使用最新注册表环境执行 `Get-Command dsh`，实际得到上述 bundled dsh.cmd。已发送标准Environment更新通知；现有shell/Bridge不会因此重新读startup配置，需要其任务结束后受控重连，当前Kimi不受重启影响。
- 独立无开发任务的只读标准MCP实例从持久配置**只复制已修改的非秘密入口字段**进行预检：DSH实际解析到cmd启动链、ZCode `available=true/version=0.67.0`；没有复制env/密钥/其它私有偏好到项目。实例禁止所有写操作。
- DeepSeek的安装ASAR package元数据为 **@deepseek-ai/dsh-desktop-host 0.2.0-rc.2**，wrapper摘要匹配。Bridge使用cmd启动时version字段显示Windows版本，不能用它当DSH版本，未伪称已完成native ACP/模型调用验收。

证据：[entry-fix-receipt.json](entry-fix-receipt.json)、[entry-fix-verification.json](entry-fix-verification.json)、`persistent-preflight.stdout.jsonl`。用户配置完整备份保持在私有用户目录，没有把配置正文或凭据复制进项目。

## 回退

- 配置原件：`C:\Users\10273\.agent-bridge\agents.toml.backup-20261014T031722Z`。
- User Path原值/注册表类型：项目内 `user-path-backup-20261014T031722Z.json`（不在聊天输出完整PATH）。
- 回退时先核对当前值仍为本轮写入版本；如用户又修改过，先合并而不整文件覆盖。按备份原类型恢复User Path、按备份原始字节恢复agents.toml。不要动Machine Path/凭据/第三方包，重连只限相关空闲客户端。

## 尚未覆盖的范围

完整DSH native ACP约定provider仍未核实；任何额外 `profiles/acp/cordis.patch.yml` 提供方/模型注册或凭据调整不在此次授权中。ZCode新任务 `task_f531d6882c` 在 `session/prompt` 协议错误、提示可能已发送，已停止且未重发；该结果不能当内容/认证拒绝或模型成功调用。

[ENTRY_BINDINGS.json](ENTRY_BINDINGS.json) 保持DSH/ZCode `dispatch_ready=false`。新增正常派发使用 [bridge_submit.py](bridge_submit.py)、[dispatch_safety.py](dispatch_safety.py) 及持久journal；实际入口/版本/完整model/provider/baseURL不匹配就停，未知结果和重启不重放。Linux定向防复发回归最终 **19 passed / 0 failed / 0 skipped，1.95s**，包含正常路由正例、旧入口/版本/endpoint/模型拒绝、非秘密输出、跨分支ID冲突、连接丢失/已接受提示后未知结果、队列发送权只转交一次。[JUnit](dispatch-safety-tests.xml)。这些是协调可靠性测试，不是模型/扫描准确率验收。

当前四个Kimi任务仍由独立持久主实例持有：S08 `task_914e1ba719`、S01 `task_fed6debc7d`、U02投影 `task_ab2f74e4fd`、U02处置 `task_d248900b18`。读取到真实交付后再按隔离文件所有权集成；当前未将缺少产物标为完成。
