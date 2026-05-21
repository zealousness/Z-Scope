# Z-SCOPE Next Optimization Implementation Plan

本文档用于跟踪 Z-SCOPE 下一阶段优化落地。依据包括：

- `Z-SCOPE 深度研究报告.pdf` 对架构、Anthropic 风格实践、业界工具对照和短板的分析。
- 当前仓库实现：workflow、candidate/evidence layer、Deep Worker、Validator、MCP stdio 雏形、SARIF 导入/导出、external benchmark harness。
- 现有工程目标：保持 Z-SCOPE 作为 C/C++ 内存安全与并发风险的证据优先专用扫描器，而不是泛化 AI code review bot。

## 0. 当前判断

Z-SCOPE 的路线是正确的：先由 Clang/SVF/Saber/Joern/规则候选生成可审计证据，再由 LLM 做语义建模、聚焦扩展和验证。下一步优化不应优先扩大漏洞类型广度，而应先强化工程闭环：

1. 工具权限和 MCP 治理从 prompt 元数据变成运行时硬约束。
2. Deep Worker 从顺序 ticket loop 变成可观测、可限流、可失败隔离的并行子任务。
3. benchmark 从 smoke/self-report 变成可重复、可对比、可持续回归的评测协议。
4. SARIF/CI 从基础导出变成稳定集成面。
5. 长期继续加深 C/C++ 内存与并发证据链。

需要修正报告中的一个现状判断：当前仓库已经具备 MCP 和 SARIF 的初步实现，不再是纯预留字段。

- MCP stdio server/client 已在 `zscope/mcp/` 下起步。
- CLI 已支持 `--mcp-stdio`，并新增实验性 `--mcp-http` Streamable HTTP 入口用于 IP+端口远程访问。
- SARIF adapter/exporter 已在 `zscope/core/sarif_adapter.py` 和 `zscope/core/sarif_exporter.py` 中起步。
- 仍缺少 production-grade MCP scoping、approval、policy enforcement、审计日志和生态集成模板。

## 1. 北极星目标

把 Z-SCOPE 打造成可接入工程流水线的 C/C++ 内存与并发高风险专审器：

- 面向 C/C++ 代码库，聚焦 memory lifecycle、temporal memory、bounds/integer、ownership contract、lock/race/thread handoff。
- 默认输出 evidence-backed findings，而非单纯 LLM 推断。
- 可在 CI 中运行，并输出 SARIF、JSON、Markdown。
- 可通过 MCP 暴露只读项目事实、快照、候选和工具，但所有 tool/resource 调用受最小权限控制。
- 可用公开 benchmark 和真实项目 patch-level 数据证明效果。

## 2. 阶段目标

### Anthropic 对齐复查

本节用于记录计划与 Anthropic/Claude Code/MCP 官方实践的对齐情况。复查日期：2026-05-18。

参考口径：

- Anthropic `Building effective agents`：优先简单、可组合模式；workflow 适合预定义路径，agent 适合开放式、多步、需模型动态决策的问题；agent 需要环境反馈、停止条件、人类 checkpoint、sandbox 和 guardrails。
- Claude Code subagents：subagent 应有单一明确职责、详细 `description`、独立 context window、独立工具权限；默认继承工具风险较高，生产场景应显式 allowlist；可配置 `model`、`maxTurns`、`permissionMode`、`mcpServers`、`hooks`、`isolation`。
- Claude Code settings/hooks：权限应支持 allow/ask/deny，敏感文件应可 deny；PreToolUse/PostToolUse hooks 可用于审批、审计、校验和后置格式化。
- Anthropic MCP connector：MCP toolset 应支持 server name、per-tool enable/disable、defer loading、OAuth token、多个 server。
- Claude Code MCP：MCP resource 应可 list/read/reference；MCP 大输出应有 token/size limit、分页或 `_meta["anthropic/maxResultSizeChars"]`。
- MCP security/authorization：远程 HTTP MCP 应遵循 OAuth 2.1、HTTPS、audience/resource validation、least-privilege scopes、禁止 token passthrough、不要记录 credential/session secret；本地 stdio MCP 也要有环境凭据和最小暴露面。
- Anthropic tool-writing guidance：工具应有清晰、独立、非重叠职责；少量高价值工具优于大量碎片工具；工具描述和参数名需要像新人 onboarding 文档一样明确；输入输出 schema 应严格，错误信息应可帮助 agent 修正行为。
- Anthropic eval guidance：agent eval 需要任务、trial、grader、trace/transcript、final outcome；多轮 agent 的评测应记录完整 tool-call trajectory，并多 trial 度量稳定性。

对齐结论：

| 领域 | 当前计划状态 | 结论 | 需补强 |
| --- | --- | --- | --- |
| Workflow vs Agent 边界 | default/resume/maintain 和 P2 benchmark 已覆盖 | 基本符合 | 增加“确定性步骤优先 workflow，开放式判断才交给 agent”的设计约束 |
| Agent 合约 | AGENT.md + workflow step 已覆盖 | 基本符合 | 增加 `maxTurns`、model/effort、停止条件和人类 checkpoint 的验收项 |
| Subagent | P1 已覆盖并行、隔离、trace | 部分符合 | 增加 spawn allowlist、nested spawn 禁止、worktree/file isolation、per-ticket model/turn budget |
| Tool 权限 | P0 已覆盖 allowlist 和审计 | 基本符合 | 增加 allow/ask/deny 三态、PreToolUse/PostToolUse hooks、敏感文件 deny |
| Tool 设计 | 计划已有 cost/tool-call 指标 | 部分符合 | 增加 strict schema、工具命名空间、去重合并、错误响应规范 |
| MCP | P0 已覆盖 policy gate | 部分符合 | 增加 output limit、pagination、resource templates、remote OAuth/audience validation |
| Skill | P4 已覆盖 lazy loading | 基本符合 | 增加 skill 描述触发质量、supporting files 审计、默认 summary-only |
| Evals | P2 已覆盖 benchmark | 基本符合 | 增加 transcript/trajectory、multi-trial、grader rubric、final outcome 与 tool behavior 评分 |

新增决策：

- DECISION: Z-SCOPE 的主扫描流水线保持 workflow-first，不把每一步都改成 autonomous agent。只有漏洞解释、路径验证、反证判断等开放式任务交给 agent。
- DECISION: 所有工具和 MCP 能力默认 deny-by-default；显式 workflow/agent/skill policy 才能开放。
- DECISION: Deep Worker 并行化必须先保证隔离、停止条件和稳定汇总，再追求吞吐。

### P0: 权限治理与 MCP 硬化

目标：把 `allowed_tools`、`allowed_mcp_tools`、`allowed_mcp_resources` 从说明性字段变成运行时强制策略。

当前证据：

- `zscope/orchestration/specs.py` 已能读取 skill/agent frontmatter 中的 allowed fields。
- `zscope/core/tools_runtime.py` 当前执行工具时主要按 tool name dispatch，缺少 per-agent/per-skill policy gate。
- `zscope/mcp/provider.py` 已暴露 resources/prompts/tools，但缺少 scoped provider 和 approval policy。

任务清单：

- [x] 新增 `ToolPolicy` 或等价策略对象。
- [x] 在 agent 执行工具前强制检查 agent-level allowlist。
- [x] 在加载 skill contract 时合并 skill-level allowlist，并记录 effective policy。
- [x] 为 MCP tools/resources/prompts 增加 allow/deny gate。
- [x] 为 `query_knowledge` 增加更严格只读 SQL 校验：拒绝多语句、注释绕过、危险 pragma、attach/detach、write-like CTE。
- [x] 为工具调用输出审计事件：agent、skill、tool、args summary、allow/deny、duration、error。
- [x] 增加 prompt-injection 权限测试：模型要求调用未授权工具时必须被 runtime 拒绝。
- [x] 增加 MCP resource scoping 测试：未授权 resource/read 必须失败。
- [x] 支持 allow/ask/deny 三态权限：高风险工具进入 ask，显式危险工具进入 deny。
- [x] 增加 PreToolUse/PostToolUse hook 机制，用于审批、审计、schema 校验、敏感路径阻断和后置验证。
- [x] 增加敏感文件 deny 规则，例如 `.env`、secret、credential、API key、本地私有配置和 benchmark local env。
- [x] 为每个工具 schema 增加 strict validation，拒绝多余字段、模糊参数名和类型漂移。
- [x] 增加 tool namespace 约定，例如 `zscope.code.*`、`zscope.knowledge.*`、`zscope.report.*`，减少跨 MCP server 命名冲突。
- [x] 复查工具集，合并高度重叠工具，优先提供高价值聚合工具而不是碎片化底层 API。
- [x] 规范工具错误响应：错误应说明可修正输入格式、范围限制和下一步可尝试工具。
- [x] 对 MCP 大输出增加分页、摘要和 hard limit；在 `tools/list` 中为大输出工具提供 `_meta["anthropic/maxResultSizeChars"]`。
- [x] 为未来 remote HTTP MCP 模式预留 OAuth 2.1、audience/resource validation、least-privilege scopes 和 token redaction。

验收标准：

- 未授权 tool/resource 即使被 LLM 请求也不会执行。
- 审计日志可追溯每次工具调用的来源和策略决策。
- 现有 agent 流程不因默认策略缺失而静默扩大权限。
- 工具调用 schema 错误可被稳定拒绝并返回可行动错误。
- MCP 输出不会因单次大 payload 污染 agent 上下文。
- 审计日志不记录 token、API key、authorization header 或 session secret。

建议测试：

```bash
python -m pytest tests/test_tool_policy.py tests/test_mcp_policy.py tests/test_analyzer_tool_policy.py
python -m pytest tests/test_sarif_exporter.py
```

### P1: Deep Worker 并行化与可观测性

目标：把 focused subagent ticket 从顺序执行升级为并行执行，同时保留上下文隔离和失败隔离。

当前证据：

- `zscope/orchestration/subagents.py::run_tickets` 已升级为受控 `ThreadPoolExecutor` 并行执行，按 ticket 原始顺序稳定汇总。
- `parallel_workers`、`subagent_max_turns`、`subagent_ticket_timeout`、`subagent_spawn_allowlist`、`subagent_skill_llm_refs`、`subagent_skill_efforts` 已进入配置。
- `AGENT.md` 中已有 `can_spawn_subagents` 和 `max_subagents` 元数据；`deep_worker` 显式 `can_spawn_subagents: false`。

任务清单：

- [x] 为 `SubAgentOrchestrator.run_tickets` 增加 `max_workers` 参数。
- [x] 使用 `ThreadPoolExecutor` 或受控 async worker pool 并行执行 ticket。
- [x] 每个 ticket 创建独立 DeepWorkerAgent 或隔离工具上下文，避免共享可变状态污染。
- [x] 增加 per-ticket timeout。
- [x] 增加 per-ticket trace：ticket id、skill、priority、input tokens、tool calls、duration、status。
- [x] 支持部分失败：单个 ticket failed/timeout 不影响其他 ticket 和主分析。
- [x] 将 unassigned candidates 和 worker reports 一起写入 report metadata。
- [x] 增加 run-to-run stability 检查，防止并行化改变确定性去重。
- [x] 增加 per-ticket `max_turns`，避免 worker 无限循环。
- [x] 增加 spawn allowlist，只允许规划出的 `deep_worker` 类型执行 focused tickets。
- [x] 明确禁止 Deep Worker 再派生子代理，除非后续引入专门的 agent team 模式。
- [x] 支持 per-ticket model/effort 选择：低风险用便宜模型，高风险路径验证用强模型。
- [x] 支持可选 worktree/file isolation，避免并行 worker 共享可变文件状态。
- [x] 增加人工 checkpoint：worker 对证据不足或高影响结论输出 `needs_human_review`，而不是硬判。

验收标准：

- 同一批 tickets 可并发执行，输出顺序稳定或在汇总时按 ticket priority/id 稳定排序。
- 单 ticket 超时不拖垮 entry scan。
- 主分析器仍能看到未分配候选，worker budget 不再成为 coverage boundary。
- 每个 worker 都有独立 context、独立 trace、明确 turn budget 和停止原因。
- 未在 spawn allowlist 中的子代理类型无法被启动。

建议测试：

```bash
python -m pytest tests/test_subagents_parallel.py tests/test_candidate_evidence.py
python -m pytest tests/test_parallel_custom_prompt.py
```

### P2: Benchmark 产品化

目标：把现有 test/range、Juliet、SV-COMP、Magma 评测变成持续回归协议，而不是一次性 smoke 文档。

当前证据：

- `docs/external_benchmark_first_run.md` 已记录 Juliet/SV-COMP/Magma smoke。
- `scripts/external_benchmark.py` 已作为三层外部 benchmark harness 起步，并接入统一 `zscope.benchmark.v3` summary schema。
- `zscope/benchmarking/protocol.py` 已提供三条件评测、双视图评分、cost、trajectory、grader 和 multi-trial stability 聚合；v3 评分已支持 secondary/sink/call_path 归因、custom category alias、placeholder line，并输出 `matched_pairs` 解释匹配原因。
- `docs/c_memory_concurrency_optimization_plan.md` 已定义 range benchmark discipline 和 no-custom-prompt 结果。

任务清单：

- [x] 固化三条件评测模式：
  - pure LLM on entry source only
  - pure LLM with repository context and no Z-SCOPE candidates
  - full Z-SCOPE pipeline
- [x] 为三条件模式输出统一 JSON schema。
- [x] 为每个 benchmark run 写入 environment metadata：backend、model、prompt_autofill、commit、OS、wall time。
- [x] 把 smoke/sample/formal run 明确区分。
- [x] 为 Juliet、SV-COMP、Magma 分别建立最小可重复命令。
- [x] 为 formal run 增加 `--max-cases 0` / `--max-bugs 0` 明确语义。
- [x] 输出 with/without needs_review 两套指标。
- [x] 增加 run-to-run stability 指标：issue Jaccard、TP overlap、FP overlap。
- [x] 增加 cost 指标：tokens per verified issue、tool calls per verified issue。
- [x] 增加 transcript/trajectory 记录：完整 messages、tool calls、tool results、worker reports、validator verdict。
- [x] 增加 multi-trial 评测模式，同一任务运行多次并统计均值、方差和稳定性。
- [x] 增加 grader rubric：不仅评估最终 issue，也评估 tool use 是否遵守权限、是否过度调用、是否遗漏关键证据。
- [x] 区分 final answer 和 final outcome：报告声称的问题必须能映射到 ground truth 或 patch-level outcome。

验收标准：

- 一条命令可复现实验并生成 machine-readable report。
- 同一 ground truth 下可比较 pure LLM 与 full Z-SCOPE。
- benchmark 结果不依赖 range-specific custom prompt 或 fixture 名称硬编码。
- 每次 eval 都能回放 agent trajectory，支持定位错误来自候选层、工具层、worker 还是 validator。

建议命令：

```bash
python scripts/external_benchmark.py prepare-juliet --source /path/to/Juliet/C --name juliet_memory_formal --max-cases 0
python scripts/external_benchmark.py prepare-svcomp --source /path/to/sv-benchmarks/c --name svcomp_memsafety_formal --max-cases 0
python scripts/external_benchmark.py prepare-magma --magma-root /path/to/magma --target libpng --target-source /path/to/magma_full/libpng/repo --name magma_libpng_formal --max-bugs 0 --copy-full-source
python scripts/external_benchmark.py run-matrix --suite-root benchmarks/external/workspace/juliet_memory_formal --conditions pure_llm_entry_source pure_llm_repo_context full_zscope_pipeline --trials 3 --run-kind formal
```

### P3: SARIF/CI 集成面

目标：让 Z-SCOPE 可作为 C/C++ 高风险模块二级专审 job 接入工程流水线。

当前证据：

- `zscope/core/sarif_exporter.py` 已支持 Z-SCOPE report 到 SARIF v2.1.0。
- `zscope/core/sarif_adapter.py` 已支持外部 SARIF alert verify。
- CLI 已支持 `--export-sarif` 和 `alert-verify --sarif`。

任务清单：

- [ ] 为 GitHub Actions 增加最小工作流模板。
- [ ] 为 GitLab CI 增加最小 job 模板。
- [ ] 为 Jenkins 增加 shell pipeline 示例。
- [ ] 对 SARIF 输出增加 schema validation 测试。
- [ ] 改进 SARIF fingerprint：结合 dedup_key、canonical source/sink、normalized location。
- [ ] 输出 codeFlows 时优先使用 evidence_pack 中的 call_path/source/sink。
- [ ] 支持 severity mapping 配置。
- [ ] 支持 baseline/suppression 在 SARIF properties 中落地。
- [ ] 增加 CI exit code policy：仅 verified high/critical 失败，needs_review 可配置。

验收标准：

- Z-SCOPE scan 可在 CI 中生成 SARIF artifact。
- GitHub code scanning 或其他 SARIF consumer 可识别规则、位置、fingerprint 和 codeFlows。
- baseline/suppression 不会破坏历史 issue tracking。

建议测试：

```bash
python -m pytest tests/test_sarif_exporter.py tests/test_sarif_adapter.py
python -m compileall -q zscope tests scripts
```

### P4: Skill Lazy Loading 与上下文经济性

目标：减少 prompt 冗余，让 skill 更接近按需加载的能力包，而不是全部内联说明。

当前证据：

- `SkillSpec` 已包含 `references`、`context`、`allowed_tools` 等字段。
- 当前 `to_prompt_block` 主要把 body 截断后内联，supporting files 未形成动态载入策略。

任务清单：

- [ ] 增加 skill trigger matcher，区分 always-loaded skill summary 和 on-demand full body。
- [ ] 支持 `context: inline` / `context: fork` / `context: reference-only`。
- [ ] 支持按需读取 `references` 中的 supporting files。
- [ ] 给每个 skill 增加 compact summary，默认只放 summary 和 allowed tools。
- [ ] 只有被 ticket 或 workflow step 激活时加载 full skill body。
- [ ] 记录每次 agent run 的 loaded skills 和 loaded references。
- [ ] 为每个 skill 增加 action-oriented description，用于准确触发和避免误加载。
- [ ] 为 skill supporting files 增加路径作用域、最大大小和审计记录。
- [ ] 增加 skill eval：验证同一候选只加载相关 skill，不加载无关漏洞族。

验收标准：

- 常规 entry 分析的 system prompt 规模下降。
- 激活单个 skill 时不会把无关漏洞族完整塞进上下文。
- skill references 可审计、可复现。
- Skill 触发结果可用测试样例稳定复现。

### P5: C/C++ 并发与跨函数证据链深化

目标：建立 Z-SCOPE 的长期护城河，专注通用工具做不深的 C/C++ 语义风险。

任务清单：

- [ ] 增强 SVF/Saber source-level path reconstruction。
- [ ] 为 Clang AST/CFG 候选增加更真实的 CFG path constraints。
- [ ] 扩展 Joern CPG 跨函数 data-flow 和 semantic operator query。
- [ ] 建立 thread start、thread handoff、join/detach 的统一 evidence model。
- [ ] 建立 shared global / alias / lockset evidence model。
- [ ] 建立 lock hierarchy 和 potential deadlock 证据模型。
- [ ] 建立 happens-before 近似证明：lock、condvar、atomic、thread lifecycle。
- [ ] 增加 patch-level benchmark：漏洞修复前应报出，修复后应消失。

验收标准：

- 并发类 finding 不只说明“存在锁/线程”，还要有可审计 path、shared object、lockset 或 handoff 证据。
- Patch-level evaluation 可证明 finding 与真实 bug fix 对齐。

## 3. 建议落地顺序

### Sprint 1: 权限策略和 MCP policy gate

时间：1 周左右。

交付：

- `ToolPolicy` runtime。
- agent/skill effective allowlist。
- MCP tools/resources allow/deny。
- 审计日志。
- 权限测试。

优先原因：这是 Anthropic-style least privilege 的基础，也能降低 prompt injection 和误调用风险。

### Sprint 2: Deep Worker 并行化

时间：1 周左右。

交付：

- 并行 `run_tickets`。
- per-ticket timeout/trace/cost。
- 稳定排序和部分失败处理。
- 并行测试。

优先原因：subagent 已经有规划模型，吞吐和可观测性是最短路径收益。

### Sprint 3: Benchmark runner 固化

时间：1 到 2 周。

交付：

- 三条件 benchmark schema。
- external benchmark 命令固化。
- metrics JSON/Markdown。
- run-to-run stability 和 cost metrics。

优先原因：只有稳定评测，后续规则增强和 LLM 调整才不会凭感觉推进。

### Sprint 4: CI/SARIF 集成模板

时间：1 周左右。

交付：

- GitHub Actions/GitLab/Jenkins examples。
- SARIF schema validation。
- fingerprint/codeFlows 改进。
- exit-code policy。

优先原因：把工具从研究态推向工程使用态。

### Sprint 5+: C/C++ 深层分析增强

时间：持续。

交付：

- 并发证据模型。
- SVF source path reconstruction。
- Joern 跨函数 query。
- patch-level benchmark。

优先原因：这是 Z-SCOPE 区别于通用 SAST 和普通 AI review 的长期价值。

## 4. 统一指标

每次正式 run 都应输出以下指标：

| 指标 | 用途 |
| --- | --- |
| Precision / Recall / F1 | 基础准确性 |
| False positives per entry | 审查噪音 |
| Verified rate | Validator 后真正坐实的比例 |
| Candidate-to-issue conversion | 候选层质量 |
| Seconds per entry / wall time | CI 可用性 |
| Tokens per verified issue | LLM 成本效率 |
| Tool calls per verified issue | 工具效率 |
| Resume reuse rate | 断点续扫收益 |
| Maintain reuse rate | 增量扫描收益 |
| Run-to-run stability | 非确定性风险 |
| Needs-review ratio | 人工复核负担 |
| Denied tool/resource calls | 权限治理效果 |

## 5. 风险与约束

- 不要为了提升 benchmark 指标写 fixture-specific 规则。
- 不要让并行化改变 issue dedup 的稳定性。
- 不要把 MCP 暴露面扩大为任意文件/命令执行入口。
- 不要让 `needs_review` 成为“默认报出一切可疑点”的逃生门。
- 不要在没有独立 ground truth 的情况下声称优于 CodeQL/Semgrep/Snyk。

## 6. 跟踪看板

| ID | 事项 | 优先级 | 状态 | 备注 |
| --- | --- | --- | --- | --- |
| OPT-001 | ToolPolicy runtime | P0 | DONE | allow/ask/deny、strict schema、pre/post hooks、敏感路径 hook、agent/skill effective allowlist 已落地：`zscope/core/tool_policy.py`; `zscope/core/analyzer.py`; `tests/test_tool_policy.py`; `tests/test_analyzer_tool_policy.py` |
| OPT-002 | MCP resource/tool policy gate | P0 | DONE | resource/tool/prompt gate、namespaced aliases、resource pagination 已接入 MCP provider; `zscope/mcp/provider.py`; `tests/test_mcp_policy.py` |
| OPT-003 | Tool audit log | P0 | DONE | JSONL audit sink + args/result redaction + duration/source 已落地；`analysis.tool_audit_log`; `tests/test_tool_policy.py`; `tests/test_mcp_policy.py` |
| OPT-004 | Prompt-injection permission tests | P0 | DONE | 模拟 LLM 请求未授权工具会被 runtime 拒绝；`tests/test_tool_policy.py` |
| OPT-005 | Parallel Deep Worker tickets | P1 | DONE | ThreadPool 并行 + 稳定顺序汇总 + spawn allowlist 已落地；`zscope/orchestration/subagents.py`; `tests/test_subagents_parallel.py` |
| OPT-006 | Per-ticket trace/cost/evidence | P1 | DONE | ticket_id/skill/priority/source/context_tokens/tool_call_count/iterations/duration/stop_reason/needs_human_review 已写入 metadata |
| OPT-007 | Ticket timeout and partial failure | P1 | DONE | `subagent_ticket_timeout` 超时标记 + 部分失败隔离已落地；单 ticket timeout 不阻塞主流程 |
| OPT-008 | Three-condition benchmark schema | P2 | DONE | `zscope.benchmark.v3` summary schema covers pure entry LLM, pure repo-context LLM, full Z-SCOPE, plus candidate-layer smoke; scorer accepts secondary/sink/call_path attribution and records `matched_pairs`; `zscope/benchmarking/protocol.py`; `scripts/external_benchmark.py` |
| OPT-009 | External benchmark formal commands | P2 | DONE | Juliet/SV-COMP/Magma `prepare-* --max-cases 0/--max-bugs 0` formal commands documented in `docs/external_benchmark_protocol.md` |
| OPT-010 | Run-to-run stability metric | P2 | DONE | `run-matrix`/`aggregate-trials` report issue Jaccard、TP overlap、FP overlap、mean/stdev |
| OPT-011 | GitHub Actions SARIF template | P3 | TODO | code scanning artifact |
| OPT-012 | GitLab/Jenkins examples | P3 | TODO | minimal CI jobs |
| OPT-013 | SARIF fingerprint/codeFlows upgrade | P3 | TODO | stable issue tracking |
| OPT-014 | Skill lazy loading | P4 | TODO | summary first, full body on demand |
| OPT-015 | Skill supporting references loading | P4 | TODO | scoped reference reads |
| OPT-016 | SVF source-level path reconstruction | P5 | TODO | source/sink/call path |
| OPT-017 | Thread handoff evidence model | P5 | TODO | pthread/thread lifecycle |
| OPT-018 | Lockset/happens-before evidence | P5 | TODO | race/deadlock proof |
| OPT-019 | Patch-level benchmark | P5 | TODO | pre-fix reports, post-fix disappears |
| OPT-020 | Tool strict schema and namespace | P0 | DONE | strict schema opt-in + `zscope.code.*`/`zscope.graph.*`/`zscope.knowledge.*`/`zscope.entries.*` MCP aliases + skill metadata migration 已落地；`tests/test_tool_policy.py`; `tests/test_mcp_policy.py` |
| OPT-021 | Tool hooks and ask/deny modes | P0 | DONE | ask/deny + Pre/Post hook runtime + sensitive path deny hook 已落地；`tests/test_tool_policy.py`; `tests/test_mcp_policy.py` |
| OPT-022 | MCP output limit and pagination | P0 | DONE | resource pagination + hard result limit + `_meta["anthropic/maxResultSizeChars"]` 已落地；`tests/test_mcp_policy.py` |
| OPT-023 | Remote MCP auth hardening | P0 | DONE | 已有实验性 Streamable HTTP runtime（无内置认证，仅可信网络早期集成）；HTTPS/OAuth audience/resource/scope validation 和 token redaction 基础保留在 `zscope/mcp/security.py`; `tests/test_mcp_policy.py`; `tests/test_mcp_http_server.py` |
| OPT-024 | Subagent maxTurns/model/isolation | P1 | DONE | `subagent_max_turns`、`subagent_skill_llm_refs`、`subagent_skill_efforts`、read-only worker isolation 已接入 |
| OPT-025 | Eval trajectory recording | P2 | DONE | `summary.json` stores trajectory references, workflow progress, worker reports, validator presence, final_answer/final_outcome |
| OPT-026 | Multi-trial agent stability eval | P2 | DONE | `run-matrix --trials N` and `aggregate-trials` produce per-condition stability summaries |
| OPT-027 | Range public API/task entry modeling | P2 | DONE | `test/range/include/task_dispatcher.h` now exposes real-model/Issue41 public `td_*` wrappers and `VOS_TaskCreate`; `test/range/src/main.c` routes wrappers to internal sinks and models task workers discoverable from `*.h` + thread discovery |
| OPT-028 | Range miss-reduction rules and scorer fixes | P2 | DONE | Dispatcher sibling-branch expansion, protocol/system contract regex candidates, narrower `needs_review` attachment, and best-match benchmark scoring landed in `zscope/core/analyzer.py`, `zscope/core/graph_candidates.py`, `zscope/core/regex_candidates.py`, `zscope/core/report_views.py`, `zscope/benchmarking/protocol.py` |
| OPT-029 | Range unified FN closure 2026-05-20 | P2 | DONE | WSL/unified/auto-discovery/`*.h` run `test/range/benchmark_runs/auto_unified_wsl_fix_20260520_3` exposed residual FNs. Landed clang/unified candidates for heap thread arg owner leaks, log-error allocation leaks, unchecked insert handoff, protocol-derived copy lengths, probe branches returning success, and refcount-free protocol gaps; updated scorer multi-anchor support and RANGE-001/RANGE-013/RANGE-016 anchors. Old report rescored from default recall 0.7586 to 0.7931, with-needs-review recall 0.9080 to 0.9425 before rerun. Tests: `tests/test_clang_ast_cfg_candidates.py`, `tests/test_analyzer_semantics.py`, `tests/test_benchmark_protocol.py`, `tests/test_range_benchmark_regression.py`, `tests/test_regex_candidates.py`, `tests/test_graph_candidates.py`, `tests/test_issue_dedup.py` |
| OPT-031 | Range structured FN closure after 2026-05-20 rerun | P2 | IN_PROGRESS | User decision: do not use regex rules as the unified optimization path. WSL/unified/auto-discovery/`*.h` run `test/range/benchmark_runs/auto_unified_wsl_structured_20260520_2` completed with SVF/Saber imported: default TP/FP/FN 69/68/18, recall 0.7931; with-needs-review TP/FP/FN 78/124/9, recall 0.8966. Landed clang/CFG candidates for unchecked `strchr`, registry unlink/free-after-unlock races, role-specific release literal mismatch, raw-fd-to-encoded-validator mismatch, global state not restored on syscall/validation failure, parsed protocol version ignored, wide count read without magic guard, fixed byte-limit/spec-count mismatch, recv retry without timeout/budget, and global dynamic-array resize without lock; fixed CFG member-release/allocation identity so `node->payload`/`node->name`/`node->children` stay distinct from parent `node`; stopped persisting validator `rejected` as a broad future baseline; structured candidates now win dedup ties over long free-form duplicates; validator over-narrow entry-root/model-name/current-callback rejections are retained as needs_review instead of discarded; narrowed pipe lock-order dedup by sink function; refreshed all REAL-* and ISSUE41-* source/secondary line anchors after public-header and wrapper entry refactors. Tests: `python -m pytest -q` -> 232 passed. Pending: WSL unified + auto-discovery + `*.h` benchmark rerun after these non-regex structured fixes. |
| OPT-032 | Range duplicate-report collapse | P2 | DONE | Targeted the 32 default FP bucket where one GT already matched and duplicate reports remained. Added semantic root-cause keys for Issue41 refcount/resource protocol, partial retry cleanup, ignored protocol version, raw-fd/encoded-fd validation, unchecked control-message `strchr`, real-model stack job, protocol length, alignment, signed recv, busy loop, rule-map globals, lifecycle locks, and dispatcher queue resources. Rebuilt prior run issue lists with the new dedup: default issues 137 -> 104, with-needs-review issues 202 -> 163; v9-like same-function/same-category duplicate bucket 32 -> 1. The remaining item is `td_init` `g_dispatcher.queue.tasks` failure-path leak, intentionally kept distinct from `RANGE-013` `thread_ids`. Tests: `python -m pytest -q` -> 236 passed. |
| OPT-030 | Skill trigger evals | P4 | TODO | action-oriented descriptions |

## 7. P0 落地自查（2026-05-18）

结论：P0 已完成。当前实现覆盖 Anthropic/Claude Code/MCP 最优实践中和 P0 相关的 least privilege、runtime policy、tool hooks、auditability、MCP scoping、output bounding、prompt-injection resistance、token redaction 和 remote HTTP MCP 安全预留。

| 验收项 | 状态 | 落地点 |
| --- | --- | --- |
| 未授权 tool/resource 即使被 LLM 请求也不会执行 | PASS | `ToolPolicy.enforce_tool/enforce_resource`; agent/tool runtime/MCP provider 强制调用；`tests/test_tool_policy.py`; `tests/test_mcp_policy.py` |
| 审计日志可追溯每次工具调用来源和策略决策 | PASS | `ToolAuditEvent` 记录 actor、action、reason、args/result summary、duration；`analysis.tool_audit_log` JSONL |
| 现有 agent 流程不因默认策略缺失而静默扩大权限 | PASS | `Analyzer._tool_policy_for_agent` 合并 AGENT.md 与 active SKILL.md allowlist；默认附加敏感路径 hook |
| 工具调用 schema 错误可被稳定拒绝并返回可行动错误 | PASS | `strict_schema` + runtime 参数校验；`tests/test_tool_policy.py` |
| MCP 输出不会因单次大 payload 污染 agent 上下文 | PASS | resource pagination、hard result limit、`_meta["anthropic/maxResultSizeChars"]` |
| 审计日志不记录 token/API key/authorization/session secret | PASS | args/result summary redaction；`tests/test_tool_policy.py` |
| 敏感文件路径不能通过工具读取 | PASS | `deny_sensitive_paths_hook` 覆盖 `.env`、secret、credential、token、本地 env 等路径；agent/MCP 默认启用 |
| MCP 工具命名空间减少跨 server 冲突 | PASS | 暴露 `zscope.code.*`、`zscope.graph.*`、`zscope.knowledge.*`、`zscope.entries.*` aliases；旧 raw tool name 保留兼容 |
| remote HTTP MCP OAuth/audience/scopes/token redaction | PASS/N-A | 当前只有本地 stdio MCP；已新增 `zscope/mcp/security.py` 作为未来 remote runtime 的 HTTPS、OAuth audience/resource、least-privilege scopes、禁止 token passthrough 校验基础 |

## 8. P1 落地自查（2026-05-18）

结论：P1 已完成。Deep Worker tickets 已从顺序执行升级为受控并行执行，并且保留上下文隔离、失败隔离、稳定汇总、显式 spawn policy、turn budget、per-ticket execution policy 和可追踪 metadata。

| 验收项 | 状态 | 落地点 |
| --- | --- | --- |
| 同一批 tickets 可并发执行且汇总顺序稳定 | PASS | `SubAgentOrchestrator.run_tickets(max_workers=...)`；按输入 ticket 顺序返回 reports；`tests/test_subagents_parallel.py` |
| 单 ticket 超时不拖垮 entry scan | PASS | `subagent_ticket_timeout` 产生 `status=killed`/`failure_kind=timeout` report；其他 ticket 保留结果 |
| 主分析器仍能看到未分配候选和 worker reports | PASS | `subagent_unassigned_candidates`、`subagent_reports`、`subagent_report_summary` 写入 state、agent_context 和最终 metadata |
| 每个 worker 独立 context、trace、turn budget、停止原因 | PASS | 每个 ticket 创建独立 `DeepWorkerAgent`；metadata 记录 ticket_id、worker_index、duration、max_turns、iterations、tool_call_count、stop_reason |
| 未在 spawn allowlist 中的子代理类型无法启动 | PASS | `agent_type` + `subagent_spawn_allowlist` runtime gate；拒绝时返回 `failure_kind=spawn_denied` |
| 禁止 Deep Worker nested spawn | PASS | `deep_worker/AGENT.md` 显式 `can_spawn_subagents: false`；runtime metadata `subagent_can_spawn=false` |
| per-ticket model/effort 选择 | PASS | `analysis.subagent_skill_llm_refs` 选择 ticket LLM client；`analysis.subagent_skill_efforts` 写入 execution policy |
| read-only worktree/file isolation | PASS | Deep Worker 工具禁用 on-demand snapshot writes；runtime 传入 `worktree_isolation={mode: read_only, snapshot_writes: false}` |
| 人工 checkpoint | PASS | worker schema 和 prompt 支持 `needs_human_review`；失败、超时、无效报告默认标记需要复核 |

## 9. P2 落地自查（2026-05-18）

结论：P2 已完成。benchmark 已从单次 smoke 脚本升级为统一协议：同一 ground truth 下可跑 pure LLM、repo-context LLM、full Z-SCOPE 三条件；每个 trial 产出 machine-readable `summary.json`，并可用 multi-trial 聚合衡量稳定性。

| 验收项 | 状态 | 落地点 |
| --- | --- | --- |
| 一条命令可复现实验并生成 machine-readable report | PASS | `scripts/external_benchmark.py run-prepared` 写入 `summary.json`、`evaluation.json`、`evaluation_views.json` |
| 同一 ground truth 下可比较 pure LLM 与 full Z-SCOPE | PASS | `run-matrix --conditions pure_llm_entry_source pure_llm_repo_context full_zscope_pipeline` |
| benchmark 结果不依赖 fixture-specific custom prompt | PASS | prepare/run 协议只读取 generated entries/truth；Z-SCOPE config 关闭 prompt_autofill；pure LLM prompt 禁止 answer-key |
| 每次 eval 都能回放 trajectory | PASS | `summary.json.trajectory` 引用 pure LLM transcript 或 verbose conversation recorder 文件，并记录 workflow/worker/validator 摘要 |
| with/without needs_review 双指标 | PASS | `evaluation_views.default` 与 `evaluation_views.with_needs_review` |
| run-to-run stability | PASS | `aggregate-trials` 输出 issue Jaccard、TP overlap、FP overlap、precision/recall/F1 mean/stdev |
| cost metrics | PASS | `cost.tokens_per_verified_issue`、`cost.tool_calls_per_verified_issue`、wall time |
| grader rubric | PASS | `grader.final_outcome`、`grader.tool_behavior`、`grader.evidence_traceability`、`grader.cost_efficiency` |
| final answer vs final outcome | PASS | `summary.final_answer` 记录报告声称，`summary.final_outcome` 记录 matched/missed/FP ground-truth outcome |

## 10. 每次落地后的更新规则

每完成一个事项，应更新本文件：

- 将状态从 `TODO` 改为 `IN_PROGRESS`、`DONE` 或 `BLOCKED`。
- 在备注中写明关键代码路径和测试命令。
- 如果指标发生变化，补充 benchmark run 路径和结果摘要。
- 如果发现计划偏差，新增一条 `DECISION:` 说明为什么调整优先级。

推荐提交粒度：

- 权限治理单独提交。
- subagent 并行单独提交。
- benchmark schema 单独提交。
- CI/SARIF 模板单独提交。
- 分析规则增强按漏洞族或 evidence model 单独提交。
