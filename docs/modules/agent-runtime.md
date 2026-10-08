---
doc_contract: zscope-module-v1
covers:
  - zscope/framework
  - zscope/agents
  - zscope/skills
  - zscope/tools
sources:
  - zscope/framework/base.py
  - zscope/framework/llm_client.py
  - zscope/framework/llm_usage.py
  - zscope/common/validator_protocol.py
  - zscope/agents/vulnerability_analyzer/AGENT.md
  - zscope/skills/evidence_validation/SKILL.md
  - zscope/tools/runtime.py
  - zscope/tools/policy.py
  - zscope/tools/registry.py
  - zscope/tools/contracts.py
  - zscope/tools/symbols.py
  - zscope/tools/flow_query.py
tests:
  - tests/test_spec_registry.py
  - tests/test_json_output_agents.py
  - tests/test_tool_policy.py
  - tests/test_tool_registry.py
  - tests/test_evidence_tools.py
  - tests/test_tool_use_eval.py
  - tests/test_tool_schema_strict.py
  - tests/test_llm_client_tokens.py
  - tests/test_validator_v3_protocol.py
---

# Agent 运行时

## 职责与非职责

本子系统负责 LLM 请求、Agent 生命周期、运行时 prompt 规范、Skill 知识包、工具 schema/执行和 ToolPolicy。它定义模型能接收哪些上下文、调用哪些工具，以及结构化结果如何解析和审计。

它不负责源码索引实现、候选真值判断的全部业务逻辑，也不负责把最终 finding 写成报告文件。

## 主入口和数据流

- framework 基类定义 Agent 运行协议，`LLMClient` 处理 OpenAI 兼容 endpoint、重试、容量和 call 级 token 结算。一次扫描的所有 profile 共享同一个 `ScanTokenUsageLedger`；它只计量，不限流。
- `zscope/agents/*/AGENT.md` 是产品运行时系统 prompt，由 spec registry 加载。
- `zscope/skills/*/SKILL.md` 提供按风险领域激活的审计知识和检查策略。
- Tool registry 只暴露 `search_code`、`read_code`、`get_semantic_context`、`query_code_graph`、`trace_data_flow`、`query_static_findings`。六者共享 `ToolContract`，Agent function schema 与 MCP schema 都由同一个 input/output contract 生成，runtime 再执行本地递归校验和 ToolPolicy。工具结果按条数或完整源码行截断，统一通过 `page.next_offset` 或 `source.next_start_line` 续取，不得产生无效 JSON。
- Agent 输出回到分析/验证流水线，不能绕过统一 schema 和 issue identity 直接持久化最终报告。
- Validator v3 的 V1/V2 使用无状态、严格 schema 的直接 chat completion；V1 不进入通用工具循环，V2 只携带原候选摘要和新增证据。V3 才能按档位使用有界只读工具轨迹。
- 流式响应未携带任何内容、工具调用与 finish_reason 块时按被截断的流处理并进入传输重试；通用工具循环任何退出路径都返回全部 assistant 文本的拼接内容，不得把循环内追加的用户提示词当作模型输出。
- 每个真实 HTTP attempt 在发出前原子预留估算 prompt 与最大 completion，返回后按 provider usage 结算。usage event 只保存计量和归因，不保存 prompt、源码正文或模型思维正文。

## 必须保持的不变量

- 运行时 `AGENT.md` 和仓库根 `AGENTS.md` 必须严格区分。
- 运行时必须默认完整加载 `AGENT.md` 与 `SKILL.md` 契约，不得静默截断规范性 system prompt；上下文压缩应作用于动态证据，只有显式调用限长接口时才允许截断契约。
- Agent/Skill 声明的工具必须在 registry 中存在，并通过 ToolPolicy 和后端能力 gate。
- 六工具输入必须拒绝未知字段；数组、嵌套对象、枚举、长度与数值边界均在本地递归校验。跨字段错误必须返回精确路径，不能依赖 provider 的 strict schema 支持。
- 工具返回固定信封 `success/status/data/coverage/page/warnings/next_actions/error`。`not_found`、`unsupported`、`unavailable` 是成功执行后的不同事实状态；只有参数、策略或执行错误令 `success=false`。
- `symbol_id` 只能来自 `search_code` 且原样传递。模型不得构造 ID，不得在已有 ID 时重新按名称搜索；旧 ID 失效必须重新搜索，不能退化为同名匹配。
- `partial`、`unsupported`、`unavailable` 不是反证；`may` flow 与未验证 candidate/backend signal 不能冒充已证明 finding。
- 模型输出解析失败必须可观测并受重试/回退边界控制，不能把任意文本当作已验证 finding。
- 结构化终结结果校验失败后，格式修复须保留实际字段错误。仅在响应确实包含声明的包装字段时校验嵌套结果；不存在的包装字段不能用空值校验覆盖根对象的缺失字段诊断。
- `finish_reason=length` 只允许一次无历史紧凑重试（validator v3 直连完成同样适用：重试携带加倍的输出上限并计入 `validator_length_retry_count`）；malformed 输出只允许一次小型格式修复。repair、retry、fallback 和连接中断都必须各自计费。
- cached prompt token 是 prompt 子集，reasoning token 是 completion 子集，不得重复加入总 token；provider 不报告 usage 时必须标记 estimated，已发出但用量未知的调用保守扣除全部预留。
- usage 账本不得拒绝新的 HTTP attempt，也不得缩短模型的 completion allowance；连接中断时仅做保守计量。token 成本是否超出预期由 Benchmark 在扫描完成后判定。
- 多轮 provider reasoning metadata 只在请求链内原样传递，不得写入普通日志、usage event 或报告。
- API key、Authorization header 和私有 endpoint 响应不得进入日志、prompt 快照或测试 fixture。
- endpoint 负载、重试和取消必须维护请求所有权，避免超时后泄漏后台工作。
- 工具只能读取策略允许的目标项目范围，MCP 暴露不应扩大单个 Agent 的默认权限。

## 常见变更应落到哪里

- Agent 角色、任务约束和工具白名单：对应 `zscope/agents/<name>/AGENT.md` 与 spec 测试。
- 领域知识：对应 Skill；不要把通用规则复制到所有 Agent prompt。
- LLM endpoint、结构化输出、重试和 token：`framework/llm_client.py`。
- 新工具能力：优先扩展六工具之一及其 `ToolContract`，并补 ToolPolicy、coverage、参数和 output-schema 测试；不要新增同义的 LLM 工具。
- Agent/Skill/Workflow 元数据加载：`zscope/orchestration/specs.py`，同时保持包数据声明有效。

## 对应测试与验证命令

```bash
python -m pytest -q tests/test_spec_registry.py tests/test_json_output_agents.py
python -m pytest -q tests/test_tool_policy.py tests/test_tool_registry.py
python -m pytest -q tests/test_evidence_tools.py tests/test_tool_use_eval.py tests/test_tool_schema_strict.py
python -m pytest -q tests/test_llm_client_tokens.py tests/test_llm_owner_cleanup.py
python -m pytest -q tests/test_validator_v3_protocol.py
```

## 权威源码和关联文档

- 稳定入口见本文 frontmatter 的 `sources`。
- Agent、Skill 和 Tool 的架构关系见 `docs/architecture.md` 的“智能体平面”。
- 用户可见工具矩阵见 `README.md` 的“分析工具清单”。

## ToolContract 与角色可见性

`ToolContract` 是工具名、给 LLM 的短描述、input schema、output schema 和 MCP annotations 的唯一来源。OpenAI-compatible endpoint 默认接收 portable schema；profile 声明 structured output 时，运行时把可选字段转换成 nullable-required 并发送 `strict:true`。若 endpoint 首次以 schema 相关 HTTP 400 拒绝，当前 run 只降级一次并记录 `tool_schema_strict_fallback`。

角色白名单固定为：Semantic Modeler 使用 search/read/semantic/graph；Validator、Vulnerability Analyzer、Deep Worker 和 Alert Verifier 可使用六个工具。后端不再改变工具词汇，只通过 `coverage.level/providers/missing/details` 表达能力差异。函数语义查询在 Analyzer 中可能调用外部 LLM 并持久化快照，因此 MCP annotation 保守标记为非只读且 open-world；其余五个分析工具是只读、幂等和 closed-world。

单次结构化结果硬限制约 60,000 字符。列表裁剪只删除完整 item，源码裁剪只删除完整行；高成本 snapshot 正文可以省略，但 provenance、状态和恢复提示必须保留。结果在离开 runtime 前按 output schema 再校验，工具实现违反契约时转为可观测的 `internal_error`，不能把畸形 payload 交给模型。

`tests/fixtures/tool_use_eval_v1.json` 固定至少 40 个跨 C、C++、Java 的工具选择场景；`scripts/evaluate_tool_use.py` 既可对已有 JSONL 调用轨迹评分，也可通过 `--run-llm` 使用生产 `LLMClient` 和 Registry 当前六工具 schema，独立发起每个场景的首次 tool call。真实运行从标准 LLM 环境变量取连接参数，强制每个场景只产生一个首调用，并同时保存原始场景 prompt、实际注入上下文后的 `presented_prompt`、模型、finish reason、usage、规范化参数或执行错误，便于复算并识别不可由当前 schema 表达的用例；`--first-tool-only` 只门禁首次选择、首次参数合法性和旧工具调用率。完整轨迹评分继续覆盖错误后恢复、coverage/may 语义和两调用发现-读取上限，并保留证据引用。schema token 门槛使用同一稳定估算器和冻结的旧 14 工具基线，防止六工具描述随迭代重新膨胀。

## LLM 客户端生命周期

进程共享额度按存活客户端所有者计算最严格的正上限，关闭客户端注销其约束并唤醒等待者。配置上限与 AIMD 过载降速分开维护，注销不会清空其他请求的在途计数和有效 RPM 历史。客户端关闭后停止接收新请求，已取得额度的请求保留 HTTP session，最后一个请求释放后完成清理。借入客户端的所有权留在调用方，Facade 只能关闭自身创建的客户端。
