# DSH / ZCode 剩余路由与协议诊断

记录时间：2026-10-14 03:43 UTC。范围为只读诊断；本轮仅新增本文件。未派发开发、重发提示、启动 Bridge/ACP 服务、重启现有进程、恢复清理任务或修改项目外配置/第三方包。未读取凭据值、请求头或完整环境；`DEEPSEEK_API_KEY` 在下文仅为已有配置中的凭据引用名。

已通过正式线程工具向主协调 `01a13810-7741-723a-bfc5-a351552420da` 发送两次中间证据。既有四个 Kimi 作业不由本诊断操作。[入口绑定](ENTRY_BINDINGS.json) 的 `dispatch_ready=false` 保持原样。

## 结论与确定性

| 对象 | 确定事实 | 尚不能作出的结论 |
|---|---|---|
| DSH 0.2.0-rc.2 | ACP 与 desktop 是独立 profile；当前 ACP 用户 patch 只有注释和空列表，未注册约定 `deepseek` 路由。安装包的 ACP bundle 默认明确配置 `deepseek-official/deepseek-v4-flash`。修入口没有补齐这一配置差异。 | 未运行新的 native ACP 会话，不能宣称当前 ACP 已公布或成功调用 `deepseek/deepseek-v4.1-flash`，也不能宣称已向任何端点发送模型请求。 |
| ZCode 0.67.0 | 当前 Windows 执行环境存在可复现的安装目录和 Node 发现失败。目标旧会话仍是未物化占位，且目标时段没有原生 backend 日志。Bridge 丢弃了 SDK 原始错误的 `data` 详情。 | 历史 `Internal error` 的底层异常已不在现存回执中，启动失败是高度吻合的解释，不能把当前探测当成历史调用栈证明；没有内容/认证拒绝、provider HTTP 成功或业务执行成功的证据。 |

两者都不需要改换约定 provider。公开模型选项或 `available=true` 仅证明控制面可用，不能替代原生 backend 和模型请求验收。

## DSH：已定位的配置根因

直接只读读取已安装 `resources/app.asar` 内官方文档、CLI 与 schema，未启动 Harness：

- `dsh/node_modules/@deepseek-ai/dsh-acp-app/cordis.patch.yml` 的 `id: acp` 完整 config 是 `provider: deepseek-official`、`model: deepseek-v4-flash`。
- `dsh/node_modules/@deepseek-ai/dsh-base/cordis.patch.yml:127` 挂载 `id: llm-pi-ai`，没有配置自定义 providers。安装 schema `@deepseek-ai/dsh-llm-pi-ai/lib/index.js:1051` 的 `providers` 默认 `{}`。
- `C:\Users\10273\.dsh\profiles\acp\package.json` 的 bundles 为 `dsh-base`、`dsh-acp-app`，`patchReload: startup`；该 profile 的 `cordis.patch.yml` 为 217 字节，只有注释与空列表。`cordis.yml` 也是空 entry list。
- desktop profile 的独立 patch 在 `id: llm-pi-ai` 下注册 `providers.deepseek`，第 18 行为约定网关，第 24 行为 `deepseek-v4.1-flash`，第 26 行为 `apiKeyEnv: DEEPSEEK_API_KEY`。只读取并输出了引用名，未打开其凭据源。
- 安装 CLI `@deepseek-ai/dsh/lib/bin.js:105` 支持 `--patch <path>`（profile layer 之后的进程级覆盖）、`--dump-config` 与不挂载插件的 `--dump-config-schema`。本轮没有运行配置 dump，避免把完整配置带入日志。

官方 ACP 文档说明默认路由及 startup-only 行为；官方 provider 文档说明 `apiKeyEnv` 引用与 `providers` 配置。[ACP profile](https://github.com/deepseek-ai/deepseek-harness/blob/master/packages/bundle/acp-app/README.md)、[pi-ai provider 配置](https://github.com/deepseek-ai/deepseek-harness/blob/master/packages/llm/llm-pi-ai/README.md)。以本机 0.2.0-rc.2 安装内容为此次版本事实，公开 master 仅作交叉核对。

### 最小受支持修复（待批准，未执行）

准确目标为 `C:\Users\10273\.dsh\profiles\acp\cordis.patch.yml`。保留其现有内容，增加下面两条按 id 覆盖；引用现有凭据，不创建、读取、复制或替换密钥：

```yaml
- id: acp
  name: '@deepseek-ai/dsh-acp'
  config:
    provider: deepseek
    model: deepseek-v4.1-flash

- id: llm-pi-ai
  name: '@deepseek-ai/dsh-llm-pi-ai'
  config:
    providers:
      deepseek:
        apiKeyEnv: DEEPSEEK_API_KEY
        baseURL: https://st8tp3ajl0df3n8b8l8qu.apigateway-cn-beijing.volceapi.com/v1
        models:
          - id: deepseek-v4.1-flash
            name: deepseek-v4.1-flash
```

本机 Cordis composition reference 技能明确 `config` 是整项替换，不是深合并。执行前必须确认 ACP patch 仍为空或合并用户后续变动；只修改 `agent-default-model` 不足以覆盖 ACP row 自己的 provider/model。模型未显式提供的容量等字段按安装 schema/catalog 默认；本轮未验证网关能力或令牌上限。

风险与边界：新增路由影响后续使用该 ACP profile 的进程；ACP 不热重载。不能为了加载此补丁重启持有其它任务的 Bridge/Agent。等相关实例空闲后由协调者受控验证，先核对 native advertised 完整路由，选定精确模型，再决定是否进行另行授权的简单任务。若引用不能解析，正常报告 `MISSING_CREDENTIAL`，不新增凭据或换线。

另一种官方支持方式是仅为新进程传 `--patch <独立非秘密覆盖文件>`，而不改共享 ACP profile；本轮受限于只允许新增本诊断文件，未创建该覆盖文件，也未修改 Bridge command。不能把整个 desktop patch 直接套入 ACP，其中包含界面插件配置。

## ZCode：启动缺口与错误详情丢失

目标失败仍是 [task_f531d6882c 回执](route-check/bridge-response-zcode-result.json)：`session/prompt`、`protocol_error`、`Internal error`、`prompt_may_have_been_sent=true`。不能因为以下诊断把该标志改为 false，也不能重放此任务。

### 本轮可复现事实

只运行已安装 adapter 导出的 `resolveZcodeCommand()`，未构造 server/backend。变量调整仅存在于该独立 Node 探测子进程：

| 输入 | 解析结果 |
|---|---|
| 当前继承环境，无显式 CLI/Node pin | `['zcode', 'app-server', '--stdio', ...]` |
| 只设 `ZCODE_BIN=...\ZCode\resources\glm\zcode.cjs` | `['...zcode.cjs', 'app-server', '--stdio', ...]`，没有 Node 启动器 |
| 同时设真实 `ZCODE_BIN`、`ZCODE_NODE=C:\Program Files\nodejs\node.exe` | `[node.exe, '--no-network-family-autoselection', '--dns-result-order=ipv4first', zcode.cjs, 'app-server', '--stdio', ...]` |

当前 Node 为 **v24.13.0**，导出函数对该 Node 的内存 `node:sqlite` 检查通过。版本探测参数 `--version` 的单次 `spawnSync` 验证：裸 `zcode` 为 **ENOENT**，直接 `.cjs` 为 **EFTYPE**；两次均没有成功创建目标进程，没有执行 Agent。

原因来自已安装 `dist/backend/resolve.js`：

- 第 86–88 行通过 `process.env.LOCALAPPDATA` 拼桌面安装路径；本执行环境该变量被 Windows 沙箱重定向至 `...\Packages\sandbox.{...}\AC`，不是真实安装的 `C:\Users\10273\AppData\Local`。
- 第 15–25 行的 PATH 发现使用 `which`；本环境不存在 `which`。Node 候选只有显式 `ZCODE_NODE`、Mac 常见路径和 Zed Mac 路径，未使用 Windows 上已存在的 `C:\Program Files\nodejs\node.exe`。
- 末尾无法发现 Node 时退回直接执行 CLI `.cjs`，Windows 无法按 Node shebang 执行它。

这些发现规则与上游当前源码一致；README 明文支持上述 bootstrap 参数以及 `ZCODE_PROVIDER`/`ZCODE_MODEL` 精确选择。[上游启动器源码](https://github.com/william0wang/zcode-acp/blob/main/src/backend/resolve.ts)、[参数文档](https://github.com/william0wang/zcode-acp#environment-variables)。这是社区 ACP 适配器，底层驱动官方 ZCode app-server；其 npm 版本不能称为官方 ZCode 桌面版本。

### 历史任务的证据边界

- Bridge state 中目标 `native_session_id` 为 `1aa6ce16-ba93-46a5-b15d-9361d9a7c93b`。该 ID 在 `C:\Users\10273\.zcode\v2\acp-lazy-sessions.json` 中只有 `cwd`、`createdAt`，没有物化后的 `zcodeSid`。adapter 的 `session/new` 是延迟启动；模型/模式控制面能够先于原生 session/create 返回。
- `C:\Users\10273\.zcode\cli\log\zcode-2026-10-14.jsonl` 共 181 条，最后一条为 `01:32:43.854Z`；目标调用为 `02:53:38–40Z`，无对应 backend 日志。ACP diary 同时段只有 PowerShell 被当作 POSIX login shell 使用 `-l -c env -0` 的警告，代码随即退回继承环境；该警告本身不是致命错误证明。
- 安装 SDK `@agentclientprotocol/sdk/dist/jsonrpc.js:180` 把普通异常转成 `-32603 / Internal error`，底层 message 放在 `error.data.details`。Bridge `agent_bridge/adapters/acp.py:734` 的 `_failure` 仅保留 `str(exc)` 与分类，不保存该 data；现有 transcript 也只有 prompt_sent 与三条 AvailableCommandsUpdate。因此历史底层异常无法从现有回执恢复。

所以，启动发现错误是已复现缺陷；它与该历史故障高度吻合。缺少原始 `error.data` / 当时实际 argv，不能将其升级为历史唯一根因。现有证据没有进入真实 backend session 的记录，但仍不把“无记录”当成绝对未发 HTTP 的证明。

公开 [issue #202](https://github.com/william0wang/zcode-acp/issues/202) 涉及 3.12+ provider registry 和配置路径问题，本机安装 CLI 中 `workspace/updateProviderRegistry` 字符串有 5 处，不能因相似报错直接套用那一历史根因；字符串存在本身也不证明 RPC 成功。CAPTCHA/账户 runtime headers 的公开问题没有本轮对应证据，不做绕过或改 provider 尝试。

### 最小受支持修复（仅报告协调者，未执行）

可在下一次获准的独立启动环境中固定以下非秘密参数，不修改 User/Machine 环境、不改 provider 或凭据：

```text
ZCODE_BIN=C:\Users\10273\AppData\Local\Programs\ZCode\resources\glm\zcode.cjs
ZCODE_NODE=C:\Program Files\nodejs\node.exe
ZCODE_PROVIDER=97ad75c3-e785-4369-9730-55a5ee47c71c
ZCODE_MODEL=glm-5.3
```

Bridge 默认继承名单包含这四项，`AgentConfig.env` 也支持逐 agent 配置。前两项修正发现缺口，后两项防止 first-enabled-provider 或默认模型误用。仍须通过公开 ACP 选项确认完整 `97ad75c3-e785-4369-9730-55a5ee47c71c/glm-5.3`。**不要设置 `ZCODE_BASE_URL`**：适配器将其解释为服务 origin 并主动移除；约定模型 endpoint 应来自现有 hw provider registry。

若要求持久化，需要额外批准准确目标 `C:\Users\10273\.agent-bridge\agents.toml` 的 `[agents.zcode.env]` 四个键，合并保留现有字段；不改其 command、其它 agent、代理、权限策略或凭据。风险是只影响后续新实例，既有实例不会刷新；不得为此重启当前 Kimi/Bridge。现 task_f531d6882c 保持停止，不以新 request_id 绕开未决执行边界。是否进行一个全新简单验收请求，仍由协调者依用户授权与原任务处置单独决定。

## 证据指纹与交付状态

- DSH wrapper SHA-256：`c6c38be7f9f66a7bfb96d5ac9490618f9713df5ffb552cb7e66b831affb20ab9`，与 [ENTRY_BINDINGS.json](ENTRY_BINDINGS.json) 相符；版本来自安装 ASAR metadata，不使用 cmd.exe 的 Windows 版本。
- ZCode wrapper SHA-256：`d494fa23bcb31a4b208a553eb2f13a5765ac3538c2e79759ea9541b44fe90ef2`，与既有绑定相符。
- ZCode adapter `dist/backend/resolve.js` SHA-256：`9ee7133a5241bd6482562aa02d025d3cdf24e1d67d8240c1ebee88001a6f1b51`。
- 官方 ZCode `resources/glm/zcode.cjs` SHA-256：`e9f1868c0fdb863537ed910ee3828b9be96b8c2fd805473f63b439e1113266b8`。

诊断已完成；修复未执行，状态是**范围限制下待批准/待协调者受控启动**，没有操作被拒绝或结果不明的新请求。现有旧任务的提示结果不确定性继续保留。没有运行 Z-SCOPE 产品测试，也没有形成扫描/benchmark 结论。本次只读探测不能作为既定 provider 已成功工作的验收。

## 后续只读诊断：Kimi 消息可见性与 8000 字节分页

本节是后续独立诊断，前文状态保留为当时快照。仅追加本文件；未向任何开发任务发送提示、权限答复或取消请求，没有启动/重启 Bridge、读取原生 wire 请求或凭据、修改配置/权限策略。主协调提供了现有公开回执路径，并确认界面交付依赖其 commentary 与仓库进度文件；本节没有直接观察用户的网页画面。

### 8000 字节究竟限制什么

**它只限制 `get_transcript` 一页返回多少日志事件，不是 Kimi 的输出总量、上下文长度或日志存储上限。** 已安装 Agent-Bridge 0.1.0 的 `agent_bridge/transcript.py:17` 定义 `PAGE_BYTE_BUDGET = 8000`，`page_events` 位于第 255 行。

分页器先按 `kinds` 过滤事件，再按 `offset` 取位置。逐条计算 `json.dumps(event, ensure_ascii=False)` 的 UTF-8 字节数，累计到页预算就把后续事件留给下一页。中文通常每字 3 字节，JSON 字段名、标点和转义也占字节，所以不是“8000 个字”。它不切开一条事件；若第一页的首条事件本身超过 8000 字节，该条仍完整返回。外层元数据也有开销，因此这是事件页的软预算，不是 HTTP/MCP 响应硬上限，也不会由这一步产生半个 UTF-8 字符。

公开入口 `server.py:182` 为 `get_transcript(session_id, offset=0, limit=50, kinds=None)`，没有 `max_bytes` 参数。8000 是源码常量，没有公开配置字段；调大 `limit` 只增加条数上限，仍受字节预算。正确续读方式是保持同一 `session_id` 和 `kinds`，把下一次 `offset` 设成返回的 `next_offset`，直到 `has_more=false`；不能因为一页少于 50 条就认为结束。`total_matching` 是当前过滤集合的总条数，换 `kinds` 后旧 offset 不再表示同一个位置。会话日志包含该会话多轮任务，不能把第一页当作当前任务尾部。

主协调提供的四份公开回执都停在第一页，直接解释了工具日志时间为何明显早于 `check_task.recent_activity`：

| 回执 | offset / next_offset | 本页 / total_matching | has_more |
|---|---|---|---|
| [tools-s08](bridge-response-tools-s08.json) | 0 / 45 | 45 / 8136 | true |
| [tools-s01](bridge-response-tools-s01.json) | 0 / 45 | 45 / 2431 | true |
| [tools-projection](bridge-response-tools-projection.json) | 0 / 42 | 42 / 4458 | true |
| [tools-disposition](bridge-response-tools-disposition.json) | 0 / 42 | 42 / 4637 | true |

`bridge-response-raw-s01.json`、`...raw-s08.json` 也都是 offset 0、limit 1、next_offset 1、has_more true。没有证据表明这几个旧时间是“读错日志 segment”；已经证实的是没有续读。它们不能证明最近无工具错误、无权限请求或无问题。

### 几种不同的裁剪不能混为一谈

| 层级 | 已安装实现与单位 | 能否续读 / 完整性 |
|---|---|---|
| `get_transcript` | 默认 50 事件、8000 UTF-8 字节软预算，`transcript.py:255` | `next_offset/has_more`；完整事件继续保留在日志中，但仅限映射器已经保存的字段。 |
| `check_task` 的 `recent_activity` | 尾部 16 KiB 日志窗口中的最近 5 条，每条正文/标题最多 160 Python 字符，`registry.py:1314`、`transcript.py:293` | 只是摘要；很多工具更新只有状态，旧问题很快被挤出摘要。公开工具名为 `check_task`，没有 `get_task`。 |
| 终态 `wait_task` / state 的 `result_text` | 末尾 6000 UTF-8 字节，`registry.py:84,139,1350` | 截取后的开头若落在多字节字符中，用 `decode(errors='ignore')` 丢弃残缺字节；看 `result_truncated` 并改用 `get_result`。 |
| `get_result` | 每页最多 60000 Python 字符，参数可设 1–60000，`registry.py:1417` | 完整 result artifact 以 `cursor/next_cursor/has_more` 续读，按字符切片不会切坏 UTF-8。若 `result_complete=false/result_source=legacy_state`，只能读现有尾部，不等于完整结果。 |
| artifact 写入失败的 state 兜底 | 末尾 30000 UTF-8 字节，`registry.py:88,860` | 会有持久化失败 warning；没有 artifact 时分页不能找回丢失前缀。 |
| ACP 工具输入/失败输出摘要 | `_tool_io_summary` 最多 500 Python 字符加省略号，`adapters/acp.py:91–98` | 在保存日志之前已经裁剪，分页不能恢复。这一层没有长度/截断标志或完整输出 artifact。 |

`get_result` 收集的是助手 message 文本，不是全部工具输出。`task.result_text` 在 `run_turn` 返回后才赋值（`registry.py:848–860`），因此运行中 `get_result` 不是实时助手对话；运行中的自然语言问题应从 `message_chunk` 日志读取。当前已存在的 S08/S01/处置结果文件均小于 6000 字节，未发现它们被结果尾部预览裁剪；这不能抵消工具摘要确实被裁剪的事实。

### 确定存在的映射缺口

`adapters/acp.py:558–610` 的 `session_update` 不保存完整 ACP 更新：

- `AgentMessageChunk` 的文本被完整加入当前轮 `text_parts` 并写入 `message_chunk`；自然语言问题没有专门通知或等待状态，只是这些文本的一部分。
- 工具只保存 id、标题、kind、status、最多 20 个位置；开始调用时保存输入摘要，只有 status 为 failed 时才保存 `rawOutput` 摘要。ACP 工具 `content` 字段完全没有写入日志；成功工具的输出也没有进入结果。若错误仅在 content 中，Bridge 日志可能只剩 failed 状态而没有原因。此行为由代码确定，本轮未抓取原始 ACP 原文，不能逐条证明哪些 content 曾被收到后丢弃。
- `ext_notification` 在第 660 行直接返回；未知扩展通知不写日志。`UserMessageChunk` 等未专门处理的更新大多只留下 update_type。
- stderr 只保留进程内尾部；失败摘要仅提取若干固定错误关键词，不是原始 stderr 全文。不能因 `stderr_summary=null` 推断没有工具/启动异常。

只读采样四个目标 Bridge 持久日志（`C:\Users\10273\.agent-bridge\transcripts\<session>.jsonl`，不读 Kimi wire 请求）得到代表性证据：

| 会话 / 时间 UTC | 保存下来的错误 |
|---|---|
| S08 `sess_66640fd67a`，03:57:11 | `Write_58` failed：Write 缺必需 `path` 和 `content`。 |
| S01 `sess_9669ed4555`，03:52:45 | `Read_57` failed：不接受额外参数 `limit`。 |
| 处置 `sess_8fa76506e8`，03:55:15 | `Write_55` failed：Write 缺必需 `path` 和 `content`。 |

当时四份完整持久日志分别有 2、4、1、1 条 failed 工具更新，其中 S01 两条、投影一条输出恰为 500 字符加省略号，证明存在实际的保存前裁剪。S08 的较早 Bash 错误还记录了 `/mnt/c/.../.coordination/20261014/` 不存在。工具失败后 worker 可能修正并继续，不必然等于整个任务失败；但公开 task `warnings=[]/error=null` 也不等于未发生这些执行问题。协调者需要看到它们并核对修正结果。

### Kimi 提问时谁处理，用户能否看见

| 消息类别 | 当前实现 | 用户在网页是否可答 |
|---|---|---|
| ACP `session/request_permission` | `_BridgeClient.request_permission` 第 531 行立即按既有 policy 选项应答并写 permission 事件；默认 `allow_once`。第 475 行注释明确 Bridge 是此链路的批准方。Kimi `_sync_kimi_selection` 第 1203 行还固定切换 `yolo`。 | 本 Bridge 没有待决人类审批队列或 respond-permission MCP 工具，不能声称网页会弹出该请求。没有修改这一既有策略。 |
| 助手自然语言问题，例如“请确认……” | 保存为 `message_chunk`；若该轮结束，可能照常被标为 completed，TaskStatus 没有 waiting_user。 | 协调者必须先完整读到文本，再转达父网页对话，由用户回答；Bridge 不自动把文本变成输入框，也不替用户回答。 |
| ACP elicitation 澄清请求 | 第 649 行 `create_elicitation` 无条件返回 `DeclineElicitationResponse(action='decline')`，没有记录原问题；初始化也没有声明 elicitation 支持。 | 不是转给用户等待回答。没有日志不代表没发生；若原生 agent 遵守能力协商，它应避免使用此接口，但本轮未证明具体行为。 |
| 自定义扩展通知/方法 | 通知忽略，方法返回空对象。 | 不存在可依赖的网页转发保障。 |

本轮已保存四会话日志中的 permission 事件均为 0；拼接所有已保存助手正文后，没有发现明确请求用户确认/等待回复的问题。S01 唯一问号所在句以 “Let me investigate” 继续，是工作说明，不是待用户回答的请求。**这只说明已保存文本中没有找到待答问题**；磁盘读取不含 owner 进程尚未刷盘的缓冲，且 elicitation/扩展消息可能无日志，因此不能升级成“本轮绝无被丢弃的提问”。

日志缓冲另有 64 KiB/30 秒条件（`transcript.py:18–19`），其中年龄检查发生在下一次 append；owner 的公开读取能合并进程内 pending 文本，而外部只读磁盘可能落后。不能把磁盘暂未出现最后 prompt 或更新当作丢失的最终证明。

### 本地 Codex 到父网页的边界与最小建议

当前 Bridge 是标准 stdio MCP 服务，公开 10 个工具里没有网页推送、待决问题列表或提交审批答复接口。项目 `bridge_mcp_client.py` 只把公开回执保存 JSON、输出到后台 stdout；保存仓库文件本身不保证出现在父网页对话。主协调也确认其当前通过自身 commentary 与仓库进度文件交付，未证明父网页完整镜像其工具输出。Codex 自身工具审批/auto-review 与 Kimi ACP 权限是不同链路；网页上即使出现 Codex 审批，也不代表 Kimi 问题已经转接。

官方文档说明 Codex 的 sandbox/approval 和同一聊天内的工作交互，但没有承诺第三方 ACP 子进程的全部消息自动镜像到另一网页对话。[Agent approvals & security](https://learn.chatgpt.com/docs/agent-approvals-security)、[Long-running work](https://learn.chatgpt.com/docs/long-running-work)。本节关于 Bridge 的结论来自本机源码与本轮证据，不把一般产品文档当作这条集成已验收的证明。

最小操作修正无需改配置：由当前 owner 客户端按固定 kinds 和 next_offset 增量续读，拼接助手消息，同时审阅 failed 工具输出与 permission 事件；把需要用户决定的问题、反复工具错误及未决状态明确转到用户正在看的父对话。终态结果按 next_cursor 读完，并检查 result_complete。不要仅轮询 recent_activity 或把 warnings 为空当成无故障。

若要修 Bridge，需另行授权第三方代码开发：保留脱敏后的工具 content/完整输出 artifact 及截断元数据；对不支持的 elicitation/扩展请求留可见事件；若需要人类审批，实现关联请求 id 的 pending/response 链和前端呈现，而不是改成自动批准或默认答复。仅调大 8000 常量不能解决映射丢失或网页不可答问题。当前 busy 会话不能靠另发 dispatch 注入答案（`registry.py:752` 会拒绝），也不能为了应答未知问题取消或重启任务。本诊断没有实施这些变更。

关键结果已正式发送主协调。向源线程 `01a11e1c-b0bf-731c-a0a7-551a6447700f` 的直接通知返回 `thread not found`，未确认送达且未重试；已向主协调更正并请求转述，完整结果由本次最终回执交回父任务。这是通知目标不可寻址，不影响上述只读诊断结果。

## 后续新会话停滞诊断：2026-10-14 05:12 UTC 快照

本节仅核查主协调已经创建的新 S01/S08，会话分别为 `task_f709895aa3` / `sess_0dfdf879d4` 与 `task_24c156da37` / `sess_4b386346c6`。时间统一写 UTC；当日桌面显示时间为 UTC+8。没有派发开发、重发 prompt、取消任务、修改权限或配置、重启 Bridge/Agent，也没有读取或输出凭据。公开查询均由既有 owner 客户端执行；本诊断曾经提交 38 项只读 `check_task` / `get_transcript` 查询到其文件队列，均已完成，并已向主协调披露。收到“查询继续由本协调持有”的最新指令后，停止写查询队列，只读取主协调保存的回执。

### 结论与当前状态

长时间静默的直接证据是 Kimi 原生日志中的 `APITimeoutError: Request timed out.` 及原生重试。超时一轮约 307 秒，重试日志标明 `maxAttempts=10`。这不是从 TCP 连接或 Bridge 的 `running` 推测出来的。两个会话随后均有恢复：S01 在 05:08:48 完成一次 Read，S08 在 05:11:32 前持续完成多项工具调用，主协调也确认 S08 两个新代码文件在 05:10:35 落盘。此前“首个 ls 后一直无动作”的结论只适用于较早快照，不能继续当成现状。

当前证据没有定位到人类权限等待、未完成工具调用或自然语言问题等待。公开 `permission` 过滤已完整读取，两个会话都是零事件；已完成的 assistant `message_chunk` 中没有明确要求用户作答的文本。这个判断仅限已观测区间，不能把 Bridge 对 elicitation/扩展消息的可见性缺口解释为其永远不存在。

### 完整公开游标核对

主协调回执目录为本目录下 `current-public/956cbd4046f4/`。已核对固定过滤类型下的全部续页、起止游标和 `has_more`，没有将第一页或 `recent_activity` 当完整日志。

| 项目 | S01 | S08 |
| --- | --- | --- |
| 工具过滤 | `tool_call,tool_call_update` | 同左 |
| 已有完整前段 | 0→48 | 0→48 |
| 本次完整续段 | 48→77，1 页、29 事件 | 48→1274，29 页、1226 事件 |
| 末页 | `has_more=false` | `has_more=false` |
| 最后工具完成 | 05:08:48.314Z，Read | 05:11:32.726Z，Bash |
| assistant 消息 | 0→20，1 页，完整 | 0→91，2 页，完整 |
| `permission` | offset 0、total 0、无后页 | offset 0、total 0、无后页 |

工具事件数量包含同一工具的连续进度更新，不是独立工具调用次数。状态回执两者仍为 `running`；`get_result` 为 `legacy_state`、不完整、空结果及 `usage={}`，只能说明尚未形成终态结果，不能据此判定健康或失败。原生 raw 完整段仅含 AvailableCommands/CurrentMode/ConfigOption/SessionInfo，不能用它代替工具或消息过滤。

### 原生日志提供的等待点

只读取正常 Kimi 日志的时间、类型、模型别名、计数和脱敏错误，不输出请求正文、工具参数、工具结果内容或推理内容。日志位置：`~/.kimi-code/sessions/wd_z-scope_dd6e09233af9/<native_session>/agents/main/wire.jsonl`。

- S01 native session 为 `session_a93496aa-91c6-4878-a223-97fe37c05e20`。初次工具前在 04:24:34、04:29:41、04:34:48 发生三次请求超时；首个 ls 于 04:38:54 完成。随后 04:44:00、04:49:07、04:54:14、04:59:23、05:04:35 又发生五次请求超时，之后于 05:08:48 完成 Read。下一个 `llm.request` 为 05:08:48.317Z。截至本节快照共有 11 个请求记录、8 个超时重试、2 组完整 tool.call/tool.result，没有未配对工具。
- S08 native session 为 `session_c219a6de-4ffa-438d-b2d7-32f398cf6698`。初次工具前三次超时与 S01 时间接近，首个 ls 于 04:38:57 完成；随后 04:44:03 和 04:49:10 又有两次请求超时，之后恢复多轮响应及工具调用。最近 Bash 在 05:11:32 完成，下一个 `llm.request` 为 05:11:32.729Z。共有 33 个请求记录、5 个超时重试、41 组完整 tool.call/tool.result，没有未配对工具。

记录的模型别名一直为 `volceapi/kimi-k3`、thinking off。日志中的 provider 类型字段不能单独证明网关实际上游选择；本节没有另行切换或验证新的 provider。请求记录证明客户端进入了模型调用路径，不能单独证明每次请求已被网关接收。

原生权限事件还显示两个会话在 04:19:27 左右从 `auto` 切到 `yolo`，与已安装 Bridge `_sync_kimi_selection` 的既有行为相符。因此用户更改的启动默认值不能直接当作当前原生权限模式。这个发现不能解释 `APITimeoutError`，本诊断没有修改权限模式。

### Bridge 表象与尚缺证据

当前 owner 的公开读请求正常返回；现有 Bridge 日志只有对应 `task_dispatched` 等记录，没有发现这两个会话的连接断开错误。Kimi 在内部进行的请求超时/重试不一定形成 ACP 活动，Bridge 的模型结束观察与部分 warning 汇总又发生在 turn 结束后，所以 `running`、空 warnings 和较长 silent 可以同时出现。不能将这种状态概括为权限拒绝，也不能把空 warnings 当无错误的证明。

既有默认 `stall_timeout=1800` 按 ACP 可见活动计时。本次曾提示 S01 可能接近此阈值，随后已即时更正：05:08:47 起恢复消息、05:08:48 完成 Read，没有证据表明本轮触发了 stalled 终止。未据此执行取消、重派或重启。

已确定的是模型调用发生约五分钟超时并重试；尚不能区分 DNS/TLS、代理、连接池、网关排队、首 token 等待或上游服务原因。最小追加证据是这些既有请求对应的连接/首字节/超时阶段指标，以及网关侧脱敏 request id、HTTP 状态和排队/上游延迟；不需要重新发送开发内容。当前日志没有这些信息，不能凭超时文本给出更深层确定根因。S08 代码落盘只作为恢复活动证据，产品交付与验收继续由主协调负责。

无需为本节诊断更改配置或批准开发。若未来要让 Bridge 将原生重试、等待阶段与未映射 ACP 事件及时呈现，属于前节所述第三方实现改动，需另行明确范围和授权；本节未实施。
