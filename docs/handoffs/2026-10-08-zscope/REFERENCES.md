# 来源、版本与可信边界

本包不依赖 ChatGPT 内部引用编号。以下提供可在本地源码或浏览器中核对的持久路径。仓库源码优先于概述文档；本地 HEAD 不同应重新核对。

## 仓库基线

参考分支 `v1.3.1_feat/llm-wiki`；本轮再次读取分支提交 API，仍为 `010f40210b54ba0f79a088312ce5d8be3a82ace0`，提交时间 2026-10-08T03:22:52Z。提交自述测试不作为本次运行证据。

<a id="r01"></a>
### R01 — 仓库开发与交接规范

路径：`AGENTS.md`  
[固定提交源码](https://github.com/zealousness/Z-Scope/blob/010f40210b54ba0f79a088312ce5d8be3a82ace0/AGENTS.md)  
核对范围：本轮读取 1–160 行。开发路线、WSL/Linux、Config v2、RuntimeSpec 和 benchmark 隔离。

<a id="r02"></a>
### R02 — 构建与运行要求

路径：`pyproject.toml`  
[固定提交源码](https://github.com/zealousness/Z-Scope/blob/010f40210b54ba0f79a088312ce5d8be3a82ace0/pyproject.toml)  
核对范围：本轮读取 1–150 行。Python、依赖、console scripts、mypy/Black、包数据。

<a id="r03"></a>
### R03 — 现有符号搜索

路径：`zscope/tools/search_code.py`  
[固定提交源码](https://github.com/zealousness/Z-Scope/blob/010f40210b54ba0f79a088312ce5d8be3a82ace0/zscope/tools/search_code.py)  
核对范围：上一轮同一提交已读 1–200 行。当前 scope 是符号检索。

<a id="r04"></a>
### R04 — 现有源码／行区间读取

路径：`zscope/tools/read_code.py`  
[固定提交源码](https://github.com/zealousness/Z-Scope/blob/010f40210b54ba0f79a088312ce5d8be3a82ace0/zscope/tools/read_code.py)  
核对范围：本轮读取 1–205 行。已有 symbol_id 与 file_path 二选一读取。

<a id="r05"></a>
### R05 — 现有语义查询

路径：`zscope/tools/semantic_context.py`  
[固定提交源码](https://github.com/zealousness/Z-Scope/blob/010f40210b54ba0f79a088312ce5d8be3a82ace0/zscope/tools/semantic_context.py)  
核对范围：本轮读取 1–235 行。resolver 与持久快照、副作用标注。

<a id="r06"></a>
### R06 — 主动发现实现

路径：`zscope/orchestration/active_discovery.py`  
[固定提交源码](https://github.com/zealousness/Z-Scope/blob/010f40210b54ba0f79a088312ce5d8be3a82ace0/zscope/orchestration/active_discovery.py)  
核对范围：上一轮同一提交分段读取：profile、单次 tool-free Agent、投影、报告校验、缓存与候选映射。

<a id="r07"></a>
### R07 — C/C++ 参考配置

路径：`zscope.c_cpp.yaml`  
[固定提交源码](https://github.com/zealousness/Z-Scope/blob/010f40210b54ba0f79a088312ce5d8be3a82ace0/zscope.c_cpp.yaml)  
核对范围：上一轮同一提交已读。参考默认 scan.depth=fast，不表示用户本地配置。

<a id="r08"></a>
### R08 — 批量索引与 SVF 输入验收

路径：`docs/clang-batch-indexing.md`  
[固定提交源码](https://github.com/zealousness/Z-Scope/blob/010f40210b54ba0f79a088312ce5d8be3a82ace0/docs/clang-batch-indexing.md)  
核对范围：上一轮同一提交已读前 180 行。LibTooling、首个编译命令、缓存与完整性。

<a id="r09"></a>
### R09 — 检索与后端模块契约

路径：`docs/modules/retrieval-backends.md`  
[固定提交源码](https://github.com/zealousness/Z-Scope/blob/010f40210b54ba0f79a088312ce5d8be3a82ace0/docs/modules/retrieval-backends.md)  
核对范围：上一轮同一提交已读前 150 行。事实层、作用域、缓存、CompleteFactStore 边界。

<a id="r10"></a>
### R10 — 编排与建模模块契约

路径：`docs/modules/execution-orchestration.md`  
[固定提交源码](https://github.com/zealousness/Z-Scope/blob/010f40210b54ba0f79a088312ce5d8be3a82ace0/docs/modules/execution-orchestration.md)  
核对范围：上一轮同一提交已读前 145 行。建模并集、SCC、freeze、回调和共享任务。

<a id="r11"></a>
### R11 — 入口发现实现位置

路径：`zscope/orchestration/entry_discovery.py`  
[固定提交源码](https://github.com/zealousness/Z-Scope/blob/010f40210b54ba0f79a088312ce5d8be3a82ace0/zscope/orchestration/entry_discovery.py)  
核对范围：已由仓库 tree/模块文档定位；本次未读完整实现。入口行为以 R10 与本地核对为准。

<a id="r12"></a>
### R12 — Wiki 契约

路径：`docs/modules/wiki.md`  
[固定提交源码](https://github.com/zealousness/Z-Scope/blob/010f40210b54ba0f79a088312ce5d8be3a82ace0/docs/modules/wiki.md)  
核对范围：上一轮同一提交已读前 150 行。来源约束、revision pin、只读控制面与原文回退。

<a id="r13"></a>
### R13 — 候选与验证契约

路径：`docs/modules/analysis-pipeline.md`  
[固定提交源码](https://github.com/zealousness/Z-Scope/blob/010f40210b54ba0f79a088312ce5d8be3a82ace0/docs/modules/analysis-pipeline.md)  
核对范围：上一轮同一提交已读前 210 行。V0～V3、freeze/append、proof 资格、怀疑点暂停。

<a id="r14"></a>
### R14 — 怀疑点适配实现

路径：`zscope/orchestration/snapshot_candidates.py`  
[固定提交源码](https://github.com/zealousness/Z-Scope/blob/010f40210b54ba0f79a088312ce5d8be3a82ace0/zscope/orchestration/snapshot_candidates.py)  
核对范围：上一轮同一提交已读前 170 行。存在适配实现不等于独立通道当前启用。

<a id="r15"></a>
### R15 — 报告与 MCP 契约

路径：`docs/modules/interfaces-reporting.md`  
[固定提交源码](https://github.com/zealousness/Z-Scope/blob/010f40210b54ba0f79a088312ce5d8be3a82ace0/docs/modules/interfaces-reporting.md)  
核对范围：上一轮同一提交已读前 115 行。MCP 控制面、共享报告、证据和终态。

<a id="r16"></a>
### R16 — Agent/工具运行时契约

路径：`docs/modules/agent-runtime.md`  
[固定提交源码](https://github.com/zealousness/Z-Scope/blob/010f40210b54ba0f79a088312ce5d8be3a82ace0/docs/modules/agent-runtime.md)  
核对范围：上一轮同一提交已读前 170 行。六工具、schema、角色策略、账本仅计量。

<a id="r17"></a>
### R17 — 运行时默认值

路径：`zscope/config/runtime_defaults.yaml`  
[固定提交源码](https://github.com/zealousness/Z-Scope/blob/010f40210b54ba0f79a088312ce5d8be3a82ace0/zscope/config/runtime_defaults.yaml)  
核对范围：本轮读取 1–195 行。内部 flags、deep worker 默认关闭、observe 预算策略等。

<a id="r18"></a>
### R18 — 六工具 registry

路径：`zscope/tools/registry.py`  
[固定提交源码](https://github.com/zealousness/Z-Scope/blob/010f40210b54ba0f79a088312ce5d8be3a82ace0/zscope/tools/registry.py)  
核对范围：上一轮同一提交已读。六工具原子注册、共享 SymbolCatalog。


## 外部官方接口：本轮核对

<a id="e01"></a>
### E01 — Codex AGENTS.md

[官方文档](https://developers.openai.com/codex/guides/agents-md)；当前重定向到 [ChatGPT Learn](https://learn.chatgpt.com/docs/agent-configuration/agents-md)。核对日期 2026-10-08。

用于确认项目指令的发现、目录范围与大小边界。因此本包采用短入口＋按任务读取，不覆盖根 AGENTS.md，不宣称把整个目录放进仓库就会被自动完整读取。

<a id="e02"></a>
### E02 — Codex MCP

[官方文档](https://developers.openai.com/codex/mcp)；当前重定向到 [ChatGPT Learn](https://learn.chatgpt.com/docs/extend/mcp?surface=cli)。核对日期 2026-10-08。

用于确认本地 stdio／HTTP MCP、同一 host 的配置、工具 allowlist 与执行标注。具体 UI、配置键和版本仍需本地核对。服务器工具名称必须来自 tools/list，不能从 Agent 工具名推测 namespace。

<a id="e03"></a>
### E03 — Codex Security TypeScript/CLI

[官方 SDK README](https://github.com/openai/codex-security/blob/main/sdk/typescript/README.md)。本轮通过 GitHub connector 读取 1–110 行；返回文件 blob SHA 为 `c14e25f770f845bfd73efebf1b43fc86aa564bd5`。这是文件内容身份，不是已锁定的软件发行版本。

README 描述扫描／验证与导出，并明确 1.0 前 minor 版本可改变公开 API，部分请求可能需要额外访问资格。A02 必须在本地锁定实际版本、访问权限和数据流；本包不自动安装、不提供未经核对的完整调用脚本。

## 研究资料：保留线索，不作为当前产品能力或收益保证

下表延续上一轮调研的技术线索。本轮重点复核代码与交接落点，**未重新验证每项论文的完整正文、开源实现、最新版本或许可证**。实施对应研究任务前必须重新获取一手来源；链接失效或无法复现实验时记录，不猜接口、不照抄性能数值。

| 线索 | 一手资料入口 | 对应任务／用途 |
|---|---|---|
| clangd 分层索引 | https://clangd.llvm.org/design/indexing | P01，索引层与查询就绪边界 |
| Infer Pulse | https://fbinfer.com/docs/checker-pulse/ | K01，条件性／latent 问题摘要 |
| RepoAudit | https://arxiv.org/abs/2501.18160 | D02，按需调查与缓存思路 |
| IRIS | https://arxiv.org/abs/2405.17238 | K02，可消费规格，不能照搬其他语言实验收益 |
| IncSFS | https://arxiv.org/abs/2608.24391 | R01，增量指针分析；核对适用前提与版本 |
| CodeNib | https://arxiv.org/abs/2607.25431 | P01，多视图与增量正确性；核对原始论文范围 |
| KNighter | https://arxiv.org/abs/2503.09002 | R02，修复模式到检查器 |
| OSS-CRS | https://oss-crs.openssf.org/ | V01/A01，后续执行组件参考，不是现成私有仓适配 |
| CBMC | https://www.cprover.org/cbmc/ | V02，有界模型检查与假设边界 |
| Clang ASAN | https://clang.llvm.org/docs/AddressSanitizer.html | V01，按固定工具链核对支持与构建 |
| Clang TSAN | https://clang.llvm.org/docs/ThreadSanitizer.html | V02，按目标平台核对能力 |
| Claude Agent SDK | https://platform.claude.com/docs/en/agent-sdk/overview | A01，实施前核对接口／权限／认证 |
| CodeQL C/C++ data flow | https://codeql.github.com/docs/codeql-language-guides/analyzing-data-flow-in-cpp/ | 可选外部候选源，不列首轮必需依赖 |
| Semgrep 语言矩阵 | https://docs.semgrep.dev/supported-languages | 可选对照，必须明确版本／引擎／许可证 |

## 未验证事项

用户本地仓库当前 HEAD、未提交变更、模型 endpoint、工具链、样例工程、外部服务资格以及性能／召回均未知。本包没有访问本地 Codex App 或自动配置其插件。所有计划性参数是设计输入，不是已完成的测试结论。
