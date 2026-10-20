# 已核实入口修正与防复发

本文件只授权项目内维护与进程级绝对入口选择；**没有修改用户/系统 PATH、项目外 Bridge 配置、第三方包、权限或凭据**。不得停止当前四个 Kimi 作业来修入口。

## 现有事实

| 对象 | 已核实位置/版本/路由 |
|---|---|
| 旧 dsh 解析 | 当前 PowerShell `Get-Command dsh` 为 `C:\Users\10273\home\tool\npm-global\dsh.ps1`；本轮 Bridge 列表版本0.1.2-rc.1 |
| 正式 desktop-host | `C:\Users\10273\AppData\Local\Programs\DeepSeek Harness\resources\runtime\cli\bin\dsh.cmd`；静态 ASAR 包 `@deepseek-ai/dsh-desktop-host` 0.2.0-rc.2；wrapper SHA `c6c38be7f9f66a7bfb96d5ac9490618f9713df5ffb552cb7e66b831affb20ab9` |
| DeepSeek 目标 | provider `deepseek`；完整模型 `deepseek/deepseek-v4.1-flash`；baseURL `https://st8tp3ajl0df3n8b8l8qu.apigateway-cn-beijing.volceapi.com/v1`；desktop patch/旧 imported settings得到配置证据，native ACP尚未公布此路由 |
| ZCode ACP | `C:\Users\10273\.agent-bridge\adapters\zcode-acp-0.67.0\node_modules\.bin\zcode-acp-server.cmd`，package0.67.0；SHA `d494fa23bcb31a4b208a553eb2f13a5765ac3538c2e79759ea9541b44fe90ef2` |
| ZCode 目标 | user provider ID `97ad75c3-e785-4369-9730-55a5ee47c71c`，name `hw`，完整模型 `97ad75c3-e785-4369-9730-55a5ee47c71c/glm-5.3`；baseURL同上；来自现 `.zcode/v2/config.json`，不是内置BigModel/Z.ai推断 |
| ZCode消费实现 | 已安装 `dist/config/provider-registry.js` SHA `43261f0a286b47d8c4130ad21c0cd13580745ae3aa0a9997569a330946b89011`；当前代码将model options/baseURL交给backend。未修改第三方包 |

## 项目内先做

使用独立项目内 `AGENT_BRIDGE_HOME` 和临时 `agents.toml`，只设绝对 command、空 fallback_commands；保留实际worker/coordinator上下文，不覆盖鉴权、proxy或permission_policy。以现有正式MCP stdio服务和标准SDK列出实际版本，再用实际ACP选择核对完整provider/model；未公布目标、资料不足或不匹配停止。此诊断实例不重启持有Kimi作业的主Bridge，不操作旧caller-wake。

`dispatch_safety.py` 与 `tests/test_bridge_dispatch_safety.py` 是协调辅助，不进入 Z-Scope 产品工具目录：不自行查PATH回退、不默认provider、不按近似模型猜测；只输出非秘密路由字段；入口不存在/摘要或版本变化提示检查安装/升级后正常更新绑定。持久SQLite请求journal在发送前登记，未知结果/重启仍占用该分支；同request_id不同参数拒绝，新request_id也不能绕过未决占用。公开当前终态核对后才释放。

## 需要父任务一次确认的项目外修改

1. **用户环境变量 `Path`（User scope）**：将正式 bundled `...\runtime\cli\bin` 放在现 `C:\Users\10273\home\tool\npm-global` 前面，保留全部其它项。不删除/移除共享npm-global，不改Machine Path，不卸载旧软件。该共享目录已有Claude/Codex/Gemini/OpenCode/pnpm等wrapper。新顺序仅影响新启动进程，既有shell/Bridge保留旧环境；不能杀当前Kimi使它刷新。
2. **`C:\Users\10273\.agent-bridge\agents.toml`**：`[agents.dsh].command` 使用 `C:\Windows\System32\cmd.exe /d /c call <正式 bundled dsh.cmd> --profile acp` 的参数数组（不是直接执行Windows .cmd）；`[agents.zcode].command` 指向上述0.67.0 wrapper。不改其它agent、凭据、proxy、权限。**当前Bridge0.1.0的解析器把自动发现候选放在配置command前，空fallback数组在merge时也被忽略；仅写绝对command不能宣称禁用了旧路径。**项目内诊断进程暂时排除旧npm-global后已实际选中cmd入口；用户PATH先放新入口、新实例再检查实际resolved command。若仍回退，停止并正常修复Bridge版本，不改第三方代码或伪装新agent名称。
3. **仅在正确 bundled ACP仍不公布约定DeepSeek时**：核对 `C:\Users\10273\.dsh\profiles\acp\cordis.patch.yml` 的模型/提供方注册，与既有desktop中 `provider/model/baseURL` 路由一致。应引用现有凭据配置，不生成、复制到项目或替换密钥；具体注册节点需以当前official schema确认后提供补丁，再申请该项许可，不能提前批准未知patch。

持久Bridge命令读取于实例启动；等其全部任务真实终态后，仅受控重连对应已空闲实例并重新检查。当前正常Kimi实例无需马上改或重启。没有内容/权限拒绝的provider换线重试；本轮DeepSeek是模型配置前失败、ZCode是未发现命令。

## 后续实际结果（保留前述初始失败）

项目内临时配置已使ZCode公开 `list_agents available=true/version=0.67.0`，没有安装/修改第三方包。通过已核实 hw 的完整模型ID派发独立S09准备：`task_f531d6882c`；其后在 **session/prompt** 返回 **protocol_error/Internal error**，`prompt_may_have_been_sent=true`、result为空。它已不是最初命令发现失败；目前不能判成内容拒绝、认证拒绝或成功调用了模型。**停止S09该分支，不重复任务、不换provider，不把它当完成。**只有工具元数据与项目侧 `.zcode/acp/sandbox.json` 被列为变化，尚无S09源码产物。

DSH正式bundle入口的静态版本0.2.0-rc.2已证实；Bridge使用cmd启动时其version字段会显示Windows版本，不能拿该字段当DSH版本。当前native ACP provider仍未核实，因此ENTRY_BINDINGS.json中DSH/ZCode均 `dispatch_ready=false`，禁止后续误用。新请求通过 `bridge_submit.py` 前检查与持久journal，未知结果不重发；现四Kimi在独立主实例继续。新脚本不会自动重启持有作业的旧客户端，也不宣称已更新用户PATH或全部其它会话。
