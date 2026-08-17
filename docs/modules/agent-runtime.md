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
  - zscope/agents/active_discovery/AGENT.md
  - zscope/agents/history_maintenance/AGENT.md
  - zscope/skills/evidence_validation/SKILL.md
  - zscope/tools/runtime.py
  - zscope/tools/policy.py
  - zscope/tools/registry.py
tests:
  - tests/test_spec_registry.py
  - tests/test_json_output_agents.py
  - tests/test_history_maintenance_agent.py
  - tests/test_tool_policy.py
  - tests/test_tool_registry.py
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
- Tool registry 暴露 schema，runtime 执行查询，ToolPolicy 根据 Agent 白名单、后端能力和敏感路径规则过滤。
- Agent 输出回到分析/验证流水线，不能绕过统一 schema 和 issue identity 直接持久化最终报告。
- `active_discovery` 只对运行时预先界定的 candidate-blind 语义单元提出候选；`history_maintenance_agent` 只执行 `verify_fix` 历史复核。二者都没有 proof、promotion 或稳定终态权限。
- P3 `SecuritySpecProposalEngine` 不是自由语义写入器：仅对 unknown audit unit 调用供应的模型适配器，输入只含系统提供的 exact subject/scope/evidence/predicate/slot ID；输出必须是 `origin=llm,status=proposed` 的严格对象。cache key 绑定 unit、registry/compiler/prompt、model profile 与依赖 hashes，模型不能声明 coverage、qualification、review 或 terminal disposition。
- Validator v3 的 V1/V2 使用无状态、严格 schema 的直接 chat completion；V1 不进入通用工具循环，V2 只携带原候选摘要和新增证据。V3 才能按档位使用有界只读工具轨迹。
- 每个真实 HTTP attempt 在发出前原子预留估算 prompt 与最大 completion，返回后按 provider usage 结算。usage event 只保存计量和归因，不保存 prompt、源码正文或模型思维正文。

## 必须保持的不变量

- 运行时 `AGENT.md` 和仓库根 `AGENTS.md` 必须严格区分。
- 运行时必须默认完整加载 `AGENT.md` 与 `SKILL.md` 契约，不得静默截断规范性 system prompt；上下文压缩应作用于动态证据，只有显式调用限长接口时才允许截断契约。
- Agent/Skill 声明的工具必须在 registry 中存在，并通过 ToolPolicy 和后端能力 gate。
- 模型输出解析失败必须可观测并受重试/回退边界控制，不能把任意文本当作已验证 finding。
- `finish_reason=length` 只允许一次无历史紧凑重试；malformed 输出只允许一次小型格式修复。repair、retry、fallback 和连接中断都必须各自计费。
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
- 新工具：实现工具模块，注册 schema，并补 ToolPolicy、后端 gate 和参数测试。
- Agent/Skill/Workflow 元数据加载：`zscope/orchestration/specs.py`，同时保持包数据声明有效。

## 对应测试与验证命令

```bash
python -m pytest -q tests/test_spec_registry.py tests/test_json_output_agents.py
python -m pytest -q tests/test_tool_policy.py tests/test_tool_registry.py
python -m pytest -q tests/test_llm_client_tokens.py tests/test_llm_owner_cleanup.py
python -m pytest -q tests/test_validator_v3_protocol.py
```

## 权威源码和关联文档

- 稳定入口见本文 frontmatter 的 `sources`。
- Agent、Skill 和 Tool 的架构关系见 `docs/architecture.md` 的“智能体平面”。
- 用户可见工具矩阵见 `README.md` 的“分析工具清单”。
