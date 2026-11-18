# 只读 MCP 与 Codex 接入

Z-Scope 使用原有 MCP server，通过启动参数选择权限。profile 不属于 public Config v3；不要在 `zscope.yaml` 中添加它。默认仍是 `default`，正常扫描、Clang AST+SVF、六工具词汇和语义刷新策略保持原样。

## 选择权限与启动方式

| 能力 | default | read_only | candidate_blind |
|---|---|---|---|
| 搜索、源码读取 | 原行为，新增 text/files | 获准语料 | 获准语料 |
| 语义查询 | 函数默认 ensure_current | 强制 cache_only | 强制 cache_only，类型化投影 |
| 图、数据流 | 原行为 | 缺可验证身份时 unavailable | 同左 |
| findings 工具 | 原行为 | 可列出，但当前只读索引不载入后端信号 | 列举及执行均禁止 |
| config、reports/latest 资源 | 原行为 | 经 ToolPolicy 允许后可读 | 禁止 |
| 扫描、任意 SQL、Wiki 控制面、entry discovery、prompts | 原行为 | 禁止 | 禁止 |

服务端 profile 与调用方 ToolPolicy 取交集；客户端工具白名单不能扩大权限。仅在强制 cache_only 的语义工具注册中标记 `readOnlyHint=true`；混合注册的语义工具仍是 false。工具参数不接受 cwd、env、project root 或输出路径。

在已安装当前 Z-Scope 的 Linux/WSL 虚拟环境执行：

```bash
cd /path/to/target
/path/to/venv/bin/python -m zscope.mcp.server \
  --config /path/to/target/zscope.yaml --profile candidate_blind
# 等价 CLI 入口：
zscope -c /path/to/target/zscope.yaml --mcp-stdio --mcp-profile candidate_blind
```

YAML 所在目录是唯一工程根；源码和缓存路径锁定该配置的工程，跨工作目录执行不会改根。公共配置不接受独立 root/source_root，显式 `--config` 建议使用绝对 YAML 路径，工程内路径保持相对。服务器必须使用已安装 Z-Scope 的 Linux Python，不使用 Windows Python；依赖未安装时由用户准备，不由服务自动安装。

HTTP 入口同样支持 `--mcp-profile`，原有 token、客户端 allowlist 和非 loopback 绑定限制仍然生效。本地使用优先 stdio。stdout 只输出 JSON-RPC，日志走 stderr；新客户端使用换行 JSON，兼容旧 Content-Length 输入。只读 stdio 按序处理请求，最多排队 32 个，支持 `notifications/cancelled` 协作取消正在进行的搜索及 SQLite 查询；取消只属于当前请求。

## 搜索后读取

MCP 名称与内部工具对应：

| MCP 名称 | 内部工具 |
|---|---|
| `zscope.code.search` | `search_code` |
| `zscope.code.read` | `read_code` |
| `zscope.semantic.context` | `get_semantic_context` |
| `zscope.graph.query` | `query_code_graph` |
| `zscope.flow.trace` | `trace_data_flow` |
| `zscope.findings.query` | `query_static_findings`（盲调查不列出） |

```json
{"scope":"text","query":"connection refused","path_prefix":"src","limit":20}
```

`data.matches` 提供 `file`、一基 `line` / Unicode 字符 `column`、有界 `text` 和原始文件 SHA-256 `revision`。按路径、行号排序，每个匹配行返回一个片段。用 `zscope.code.read` 续读：

```json
{"file_path":"src/session.c","start_line":42,"end_line":55}
```

`scope=files` 按相对路径字面子串匹配，line/column 为 null，从第 1 行读取。text/files 不启动 SymbolCatalog、AST、SVF 或模型；只支持字面子串，regex/glob、符号 kinds 和非 substring 的 match_mode 均拒绝。省略 scope 完全保留 symbols 的原有四种匹配模式及 ID。

后续结果页同时传入原查询、`page.next_offset` 与 `data.view_id`。视图最多缓存 4 个，300 秒失效；目录、文件版本或许可发生变化时返回 `search_view_expired`，从 offset=0 且不带 view_id 重启。`page.total` 仅是该视图已收集结果总数；`coverage.details.corpus_complete` 单独说明语料扫描是否完成。partial 时分页不会恢复尚未扫描的语料，应缩小 path_prefix 后重新查询。

当前内部上限：20000 个目录项、10000 个文件、每文件 2 MiB、总字节预算 64 MiB、5000 个命中行、5 秒扫描时间。超限或不可读文件、非法 UTF-8、链接导致的未覆盖会说明原因；预算字节计入尝试读取的文件大小。片段最多 512 字符；read_code 继续受行数和输出大小上限约束。

search/read 共用项目根、exclude_paths 和语料许可，拒绝路径逃逸和链接遍历。密钥/凭据、truth、报告、运行时 Agent/Skill 指令、交接目录及生成缓存不能被这些入口读取。结构化结论字段不作为盲调查语料；普通源码中的 candidate/rule 词汇和提示注入文本仍是待分析数据，工具不会执行其中指令。此隔离不是通用密钥识别器；项目应通过 exclude_paths 排除额外私密目录。

read_code 缓存每次检查当前许可、文件身份与摘要；不能把先前获准的内容在撤权或文件变化后重新返回。返回的 revision 是源码身份，不是漏洞结论或数据流证明。

## 只读缓存的准确边界

```json
{"kind":"function","symbol_id":"从符号搜索原样取得","refresh_policy":"cache_only"}
```

普通函数查询省略 refresh_policy 仍走原路径；非函数 kind 不接受 ensure_current。只读 profile 拒绝显式 ensure_current。cache_only 独立读取已提交状态，不调用 resolver、build_semantic_model_input、建模任务、模型或后端补全，也不建目录、迁移 DB。

| snapshot.status | 含义 |
|---|---|
| missing | 缺少快照登记 |
| stale | 可核验的函数源码摘要已变化 |
| corrupt | 存储或快照身份损坏、登记的 payload 丢失 |
| unverifiable | 旧缓存缺完整输入身份，无法核验源码/头文件/构建/契约等全部依赖 |
| unavailable | 权限、链接、活动 WAL 或其他安全读取限制 |

旧存储没有独立可核验的完整输入收据，因此即使函数体未变，本增量也不会把它标成 current。只读函数查询的 contract 为空；普通 cache_only 可返回标明历史/advisory 的旧 payload，candidate_blind 不返回 payload。盲调查的语义 map 仅投影程序/用户来源的 claim 身份、证据引用及 audit unit 成员等类型化字段，去掉 value、怀疑点、候选、review hint 与结论 metadata；map 同样标明 freshness 未核验。

只读符号索引仅从已有 KnowledgeDB 取函数导航信息，标 partial；它不建立类型、宏或外部契约上下文。当前无法建立旧图/流事实的独立新鲜度身份，两个工具返回 unavailable，不能以空列表推断无调用或无流。需要最新完整事实时，在单独授权的正常会话建立索引；只读服务不会代为刷新。

SQLite 以 immutable、mode=ro、query_only 打开 checkpoint 后状态，拒绝存在 WAL 的文件，不创建 journal/shm 或迁移表。正在写入的工程可能暂不可读，应由写入方结束并 checkpoint 后重新启动只读服务。没有迁移或删除旧缓存的要求。普通审计日志仍按调用方 ToolPolicy 执行。

## 项目级 Codex 配置

以下片段供用户审查后放入**目标项目** `.codex/config.toml`，不会自动修改用户配置。配置语法依据 [Codex 官方 MCP 文档](https://developers.openai.com/codex/mcp/)。目标项目需要由客户端按其信任设置加载；client 和 server 的 home、解释器和路径不可互换。

Linux/WSL 客户端示例：

```toml
[mcp_servers.zscope]
command = "/home/you/venv313/bin/python"
args = ["-m", "zscope.mcp.server", "--config", "/home/you/target/zscope.yaml", "--profile", "candidate_blind"]
cwd = "/home/you/target"
startup_timeout_sec = 30
tool_timeout_sec = 30
```

Windows 客户端 → WSL Ubuntu server 示例（替换用户、项目路径与发行版）：

```toml
[mcp_servers.zscope]
command = "wsl.exe"
args = ["-d", "Ubuntu", "--cd", "/mnt/c/Users/you/work/target", "--", "/home/you/venv313/bin/python", "-m", "zscope.mcp.server", "--config", "/mnt/c/Users/you/work/target/zscope.yaml", "--profile", "candidate_blind"]
cwd = 'C:\Users\you\work\target'
startup_timeout_sec = 30
tool_timeout_sec = 30
```

Windows `cwd` 是客户端启动 wsl.exe 的目录；`--cd` 与 `--config` 是 WSL 路径。只读模式不需要模型密钥，不配置 env_vars，也不假设 Windows 环境变量会自动转发给 WSL。项目 YAML 仍需符合严格 Config v3；模型字段可以沿用现有项目配置，但不会调用模型。人工复核需要报告资源时可显式选 read_only。

检查客户端 `codex --version`、`codex mcp --help` 与服务器 `python -m zscope.mcp.server --help`。连接后应看到上述五个盲调查工具，先执行 text 搜索→read，然后请求 cache_only 并确认扫描被拒绝。无索引的临时项目也能搜索读取。当前批次的真实客户端、协议与未执行项见 [T03 记录](../handoffs/2026-10-08-zscope/records/T03-readonly-mcp.md)。
