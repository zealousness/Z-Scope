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
  - zscope/framework/chat_protocol.py
  - zscope/framework/cancellable_http.py
  - zscope/framework/conversation_recorder.py
  - zscope/framework/llm_usage.py
  - zscope/framework/context_window.py
  - zscope/common/validator_protocol.py
  - zscope/agents/validator_agent/agent.py
  - zscope/agents/validator_agent/investigation.py
  - zscope/agents/validator_agent/legacy.py
  - zscope/agents/validator_agent/output.py
  - zscope/agents/validator_agent/AGENT.md
  - zscope/agents/vulnerability_analyzer/AGENT.md
  - zscope/skills/evidence_validation/SKILL.md
  - zscope/tools/runtime.py
  - zscope/tools/policy.py
  - zscope/tools/registry.py
  - zscope/tools/contracts.py
  - zscope/tools/symbols.py
  - zscope/tools/flow_query.py
  - zscope/tools/source_access.py
  - zscope/tools/semantic_context.py
tests:
  - tests/test_spec_registry.py
  - tests/test_json_output_agents.py
  - tests/test_tool_policy.py
  - tests/test_tool_registry.py
  - tests/test_evidence_tools.py
  - tests/test_tool_use_eval.py
  - tests/test_tool_schema_strict.py
  - tests/test_source_search.py
  - tests/test_semantic_cache_only.py
  - tests/test_build_context.py
  - tests/test_llm_client_tokens.py
  - tests/test_llm_context_window.py
  - tests/test_agent_runtime_regressions.py
  - tests/test_validator_v3_protocol.py
  - tests/test_validator_investigation_session.py
  - tests/test_validator_review_boundaries.py
  - tests/test_validator_contract_review.py
  - tests/test_validator_decision_protocol.py
  - tests/test_validator_compact_runtime.py
---

# Agent 运行时

## 职责与非职责

balanced/deep 的 Validator 在同一候选内维护缺陷解释与反驳解释，使用只读工具及 `record_validator_investigation_fact` 积累当前证据。自主调查可以记录 provider 清单之外的受支持事实；`counterexample` 必须绑定精确 subject UID、BuildContext 和此前工具引用，并声明 `claim_scope`。只有 `candidate_premise` 的具体反驳可进入独立的有证据 LLM 拒绝路径；`all_paths`/`all_accessors` 仍需已有范围覆盖/证明路径。模型分数、失败查询和未发现问题都不授权结论。

普通 V3 调查将原始 `TOOLFACT` 与已登记 `FACT_V3` 分开：终态只能引用当前已登记事实或输入目录中的证据，直接提交原始工具引用会收到登记指引，历史响应提取同样不接纳这些引用。Review envelope 保留其原有证据协议。调查按具体候选条件读取、及时登记，再补查未决条件；允许的事实类型是词汇范围，不要求逐项填满，事实登记也不授予程序证明权限。搜索契约明确区分文本／文件与符号参数，文本搜索的空 `kinds` 表示无过滤；非空过滤、不适用的匹配模式和无效分页标识仍返回错误。

普通 V3 的成立条件表来自当前规则义务。事实登记可附加 `condition_ids` 与 `condition_outcome`，把当前证据关联到具体条件；查询范围订阅生成成员增删和覆盖补齐任务。历史条件只作为提案进入本轮模型输入，已执行的当前查询与任务输入匹配时提供 `CONDITION_R*` 确认引用。模型复核后可在终态引用这些提案，程序完成当前事实登记并将引用转换为当前 `FACT_V3`；新条件继续调查和登记，稳定条件在终态一并确认。终态先校验裁决及整批事实，全部准入后才登记，避免后项失败留下部分确认。相同证据支持新条件或新结果计入进展，重复表述不计入。条件状态描述模型验证进展，最终程序证明及 Finding 分流保持原有职责。

当前编译实例尚无可供公共工具使用的完整符号目录；`search_code(scope=symbols)` 在该范围返回 `unavailable/build_scoped_symbol_catalog`，不访问已被隔离的全项目导航存储，也不将能力缺口报告为空集合。模型可以按已知文件位置读取或用文本搜索导航；这些文本命中不自动成为当前构建调用关系。

deep 的 `ContractDiscoveryAgent` 使用同一 LLM 客户端、取消令牌和 RuntimeSpec 时间/迭代边界。它只读项目静态 pass 准入的函数源代码及 native facts；调用边按 native owner USR 解析，跨 TU 必须有真实链接组。函数、功能、模块逐层组合，未知边和未经确认业务前提保留在摘要中；摘要及责任转移永远不自行取得证明权限。旧单轮 finder 仅供显式离线对照。

本子系统负责 LLM 请求、Agent 生命周期、运行时 prompt 规范、Skill 知识包、工具 schema/执行和 ToolPolicy。它定义模型能接收哪些上下文、调用哪些工具，以及结构化结果如何解析和审计。

它不负责源码索引实现、候选真值判断的全部业务逻辑，也不负责把最终 finding 写成报告文件。

## 主入口和数据流

- framework 基类定义 Agent 运行协议，`LLMClient` 处理 OpenAI 兼容 endpoint、重试、容量和 call 级 token 结算。一次扫描的所有 profile 共享同一个 `ScanTokenUsageLedger`；它只计量，不限流。
- `zscope/agents/*/AGENT.md` 是产品运行时系统 prompt，由 spec registry 加载。
- `zscope/skills/*/SKILL.md` 提供按风险领域激活的审计知识和检查策略。
- Tool registry 只暴露 `search_code`、`read_code`、`get_semantic_context`、`query_code_graph`、`trace_data_flow`、`query_static_findings`。六者共享 `ToolContract`，Agent function schema 与 MCP schema 都由同一个 input/output contract 生成，runtime 再执行本地递归校验和 ToolPolicy。工具结果按条数或完整源码行截断，统一通过 `page.next_offset` 或 `source.next_start_line` 续取，不得产生无效 JSON。
- Agent 输出回到分析/验证流水线，不能绕过统一 schema 和 issue identity 直接持久化最终报告。
- `JsonOutputSpec.schema` 在本地终态、文本提取和兼容 fallback 三条路径共同执行；领域 validator 追加语义约束，不能替代公开 schema。修复提示携带实际字段错误，不向没有 `type` 字段的 schema 添加类型标签。Java 建模也校验其语言专属完整 schema。
- `search_code` 的 text/files scope 与 `read_code` 共用 `ProjectSourceAccess`；符号搜索默认不变。字面检索独立于索引，以有界固定视图分页，文件版本变化要求重启；扫描覆盖与结果分页分开报告。源码读取缓存需重新核验文件身份、摘要及当前许可。
- `get_semantic_context(refresh_policy=cache_only)` 独立读已提交状态，不经过建模 helper 或 resolver。服务端 read_only/candidate_blind profile 强制此路径；后者还隔离 findings、结论资源和语义 payload，类型化投影保留程序身份。完整输入身份不足时不能声明 current。参数、限制及消费方式见 [只读 MCP](../guides/mcp-read-only.md)。
- Validator v3 的 V1/V2 使用无状态、严格 schema 的直接 chat completion；V1 不进入通用工具循环，V2 只携带原候选摘要和新增证据。V3 才能按档位使用有界只读工具轨迹。
- Validator 的 `AGENT.md` 只维护共通裁决、证据和领域约束；闭合裁决、调查、V2b 与 Review 的差异由各自入口提供。旧格式指令只进入 legacy/V2 及其快速路径和格式修复，不进入 V3 请求。
- 模型只生成 `verdict/reasoning/positive_evidence/negative_evidence/evidence_refs/blocking_negative_evidence/missing_fact_request`，补事实请求只含 `fact_kind/reason`。程序绑定版本、候选/簇、阶段和请求目标，按裁决与请求派生停止状态；运行失败状态仍由运行时产生。完整 `ValidatorResultV3` 和历史回放协议保持原形，完整旧响应校验其原始身份，拒绝新旧字段混搭。Review 同样由程序补版本和内层裁决身份，再经过既有反驳与正面案例验收。
- 普通 V3 每轮按当前目录、已登记事实及就绪条件提案刷新终态 `evidence_refs` 的可选引用，让模型直接选择本轮合法引用；原始工具观测仍通过事实登记或条件确认后参与最终裁决。
- 一次 V3 响应的当前公开 JSON/DSML 只解码一次，裁决与审计共用 `DecisionOutput`。调查终态复用 handler 已验收的结果，保留 Review 裁决后的状态；结束时仍拒收截断、终态失败或会话异常。未调用 handler 的兼容客户端必须通过当前公开回复验收，不能仅凭其声称的 `terminal_tool_payload` 恢复结果。
- `ValidatorAgent` 负责模型请求、有界格式修复及响应归并；`InvestigationSession` 按候选隔离查询重放、事实登记、进展计数和终态验收。事实登记执行本地 schema 校验，反例须绑定当前对象、构建与声明范围；事实去重使用集合，登记记录保持顺序。工具的成功执行不等于获得证据：只有 ok/partial 的有效数据体可贡献证据，失败、不可用、未找到、空数据、陈旧快照及信封诊断均不授权事实登记。共享工具策略和最终 proof 检查仍由原有运行时与验证流水线负责。
- 事实记录与调查进展分开：不同摘要保留供审计，同一事实类型、对象、声明范围和工具引用的改写或重新组合不增加进展；新证据或新的条件支持才重置无增益计数。工具观测按实际返回的位置和结构化内容去重，保留数值、源码空白及记录内字段关系，记录换序不算新证据。失败查询允许以相同参数重试，仍受无增益上限约束。`LegacyResult` 独立维护旧协议的 envelope 白名单及别名，识别字段从其 schema 派生；这些兼容规则不进入 V3 严格解析器。
- `output.py` 统一接纳当前公开回复的完整 JSON 对象或单个终态工具参数，支持完整 Markdown JSON 围栏；拒绝混合工具、多个终态及残缺结构，不从历史正文或模型推理中恢复裁决。公开 JSON 与 provider DSML 片段共用严格解码，拒绝重复键、非有限数值和解码溢出；DSML 按当前位置匹配，避免在畸形尾部反复搜索。超大审计正文只保留摘要与大小，诊断字段也限长，完整轨迹由会话记录器管理。
- 结果对象、完整 JSON schema 和解析器共用停止状态表：完成的 verified/rejected 使用 `decision_complete` 或既有 `investigation_complete`；带补事实请求的 uncertain 使用 `missing_fact`；`malformed_output`、`output_truncated`、`investigation_exhausted` 等未完成结果保持 uncertain。身份、枚举和引用严格校验，结果中的补事实请求不可变，序列化时返回独立副本。
- Validator 的执行约定是：V1/V2 每次正常裁决一次逻辑请求、最多一次修复；直接请求的尝试次数包含失败请求，独立于完成轮次。V3 最多 50 个模型轮次，连续两轮无新增证据/条件支持后请求终结。轮次不等于物理 HTTP 次数或工具调用数；传输重试仍单独计量。600 秒验证预算为观测阈值，硬截止时间与取消继承扫描/入口令牌。调查异常保留错误类别和已采集证据，旧入口及其格式修复同样不传播异常正文；取消继续向调用方传播，查询返回后若已取消，不再发布本次观测。
- V3 工具会话因窗口不足结束时保留已收集事实，明确标记未完成并返回 uncertain；不得从此前 assistant 文本提取终态裁决。通用 JSON Agent 同样停止格式修复，返回可观测失败。
- 流式响应必须包含明确的 finish_reason；已有部分正文、完整 JSON 或 [DONE] 均不能替代结束帧。流内 error、损坏数据帧和未完成响应进入失败/有界重试，不执行其中工具或接受终态；通用工具循环任何退出路径都返回全部 assistant 文本的拼接内容，不得把循环内追加的用户提示词当作模型输出。
- 流式工具调用按数值 index 归并 id、名称和参数碎片；index 不进入下一轮请求。执行前核对非空且唯一的调用 ID、函数名称、类型与参数字符串；正文/XML 示例不转换为可执行调用。`length` 截断了工具调用时立即返回截断状态，由所属 Agent 处理有界修复；不执行半截参数，也不把未配对的调用历史发回 provider。
- 每个真实 HTTP attempt 在发出前原子预留估算 prompt 与最大 completion，返回后按 provider usage 结算。usage event 只保存计量和归因，不保存 prompt、源码正文或模型思维正文。

## 必须保持的不变量

- 运行时 `AGENT.md` 和仓库根 `AGENTS.md` 必须严格区分。
- 运行时必须默认完整加载 `AGENT.md` 与 `SKILL.md` 契约，不得静默截断规范性 system prompt；上下文压缩应作用于动态证据，只有显式调用限长接口时才允许截断契约。
- Agent/Skill 声明的工具必须在 registry 中存在，并通过 ToolPolicy 和后端能力 gate。
- 六工具输入必须拒绝未知字段；数组、嵌套对象、枚举、长度与数值边界均在本地递归校验。跨字段错误必须返回精确路径，不能依赖 provider 的 strict schema 支持。
- 工具参数的兼容修复只调整引号、键名和尾逗号等语法，保留字符串及全部字段；不能从损坏根对象提取子对象、补齐截断调用或猜测行号。非对象和非有限数值被拒绝；终态工具也须恢复 strict 转换引入的可选 null 后再执行原始契约校验。
- 模型参数边界另处理已观测到的缺省 ID 字符串 `"null"`：仅在 `read_code` 已指定文件位置时恢复空 `symbol_id`，或 `search_code` 首屏请求时恢复空 `view_id`。不改搜索正文、文件名、有效 ID 或后续分页标识；MCP／工具本身仍按原契约校验。V3 输出 schema 将缺失事实请求表示为独立 null／object 分支，避免生成占位对象；完成裁决不得携带补事实请求的解析条件不变。
- 工具循环不缓存重放历史证据。相同参数仍经过工具及策略层重新核验当前源码、构建和权限；只有连续相同参数、相同结果达到阈值才关闭该工具。结果变化重置该重复计数，旧会话保留供审计，不成为当前证据授权。
- 直接请求与工具会话都有统一生命周期收尾；成功、失败、取消和窗口不足均记录恰好一次 session_end 与索引行。异常不伪装成正常结束，计量与已记录的证据事件保留。
- provider 返回 context length 拒绝时，当前模型最多进行一次更小输入容量的重新投影；仍失败则显式报告 context_window_exceeded 或尝试后续模型。重投影不缩小输出 allowance，不删除身份、证据引用或覆盖缺口，也不改变原始历史。
- 工具返回固定信封 `success/status/data/coverage/page/warnings/next_actions/error`。`not_found`、`unsupported`、`unavailable` 是成功执行后的不同事实状态；只有参数、策略或执行错误令 `success=false`。
- 上下文压缩在每次 HTTP attempt 前按所选模型窗口触发，计入实际 wire 消息、strict/portable 工具 schema、输出 schema、请求输出上限及 5%（至少 256 token）估算余量；不按固定工具轮数触发。`llms.*.context_window` 默认 192000，`max_tokens` 默认 8192，默认输入压缩目标为 174208。兼容 endpoint 没有统一 tokenizer，完整序列化输入采用区分 CJK/其他字符的启发式估算，仅用于投影与缺少 provider usage 时的估计计量；不将 UTF-8 字节上界当成真实 token，也不因估算超标拒绝请求。provider usage 仍按真实计数结算。这些是配置值，不是 endpoint 自动探测结果；`model_context_windows` 按请求模型名精确覆盖，回退模型重新投影原始历史。窗口属于单次请求容量，不是 scan-wide token 预算。
- 压缩保留完整原始会话，只对工具结果中明确的长源码/文本字段生成带摘要校验值的 `context_omitted` 标记。嵌套记录与列表不按深度、条数或键数裁剪；构建身份、USR、证据引用、来源版本及依赖、coverage、warnings、分页和恢复提示保持原值及对应关系。未知字段保守保留，无法解析的结果不猜测压缩。省略文本不授权反证或安全结论，依赖原文时仍需窄范围重读。
- 压缩优先处理旧工具结果；窗口仍不足时允许压缩最新结果，但不删除 system/user 契约、调用配对或 provider 必需的 reasoning metadata。启发式投影后仍超标时保留必需信息并发送，由 provider 判断实际容量；仅配置的输出预留和余量已占满整个窗口时可提前拒绝。provider 明确返回超限后，最多一次缩小输入重投影；无法进一步投影或再次被拒绝时记录 `context_window_exceeded` 与 `provider_rejected=true`，尝试后续模型，全部失败则明确未完成。不缩短输出 allowance，不修改原会话。源码缓存复用仍遵守本次 `max_lines`；首条内容无法容纳时保留原 provider/覆盖缺口并追加 `result_size_limit`，不提供无法推进的续页。
- `symbol_id` 只能来自 `search_code` 且原样传递。模型不得构造 ID，不得在已有 ID 时重新按名称搜索；旧 ID 失效必须重新搜索，不能退化为同名匹配。
- `partial`、`unsupported`、`unavailable` 不是反证；`may` flow 与未验证 candidate/backend signal 不能冒充已证明 finding。
- 模型输出解析失败必须可观测并受重试/回退边界控制，不能把任意文本当作已验证 finding。
- 结构化终结结果校验失败后，格式修复须保留实际字段错误。仅在响应确实包含声明的包装字段时校验嵌套结果；不存在的包装字段不能用空值校验覆盖根对象的缺失字段诊断。
- `finish_reason=length` 只允许一次无历史紧凑重试（validator v3 直连完成同样适用：重试携带加倍的输出上限并计入 `validator_length_retry_count`）；malformed 输出只允许一次小型格式修复。repair、retry、fallback 和连接中断都必须各自计费。
- cached prompt token 是 prompt 子集，reasoning token 是 completion 子集，不得重复加入总 token；provider 不报告 usage 时必须标记 estimated，已发出但用量未知的调用保守扣除全部预留。
- 缺失 usage 的 prompt 估算包含实际工具/输出 schema 和消息开销；部分 usage 的缺项以估算补齐并标记 estimated，完整 provider 计数同步用于 usage 与对话记录。
- usage 账本不得拒绝新的 HTTP attempt，也不得缩短模型的 completion allowance；连接中断时仅做保守计量。token 成本是否超出预期由 Benchmark 在扫描完成后判定。
- 通用 Agent 默认保留多轮 provider reasoning metadata，不依赖单个 Agent 手动开启；该元数据仅在请求链内原样传递，不得写入普通日志、usage event 或报告。
- API key、Authorization header 和私有 endpoint 响应不得进入日志、prompt 快照或测试 fixture。
- provider 错误正文只用于当前请求的分类，不写入日志、记录器或最终异常；诊断保留 HTTP 状态及 schema/context/auth/rate 等固定类别。记录器按 UTF-8 字节边界裁剪，首字符放不下时直接返回空串。
- endpoint 负载、重试和取消必须维护请求所有权，避免超时后泄漏后台工作。绑定取消令牌的 HTTP attempt 由 HTTPX 异步 I/O 执行，取消/动态 deadline 后等待请求与连接清理完成再释放槽位；普通未绑定调用保持 requests 路径。工具批次每次执行前后检查取消，CancellationError 在 runtime、Agent 与终态 handler 中原样传播。
- 流式空闲保护按最近有效 JSON 块计时；SSE 注释、keepalive 和损坏块不能持续延长请求。重试等待须重新观察父令牌取消及等待期间收紧的 deadline。
- 本地 schema 的 `anyOf` / `oneOf` 与同级字段约束共同生效；可空类型仍须满足枚举约束。
- 工具只能读取策略允许的目标项目范围，MCP 暴露不应扩大单个 Agent 的默认权限。
- Joern 便利查询对模型可控的名称、regex 和文件过滤值统一编码为 Scala 字符串字面量，不能直接插入查询源码；location selector 指定列时同时核对行与列。

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
python -m pytest -q tests/test_llm_context_window.py tests/test_agent_runtime_regressions.py
python -m pytest -q tests/test_validator_v3_protocol.py
```

窗口回归中的 `real_http` 用例通过本地 HTTP 接收端实际接收 requests/curl 请求，使用完整 Validator/Skill 契约和通过 `read_code` schema 校验的分页结果；检查默认 192000/8192、窗口内原样发送、最少旧正文省略、SHA-256 标记以及其余字段和原始会话完整保留。`python -m pytest -q -s tests/test_llm_context_window.py -k real_http` 输出估算前后 token 数和接收字节数。这是客户端协议验收，不代替实际 endpoint 的 tokenizer 和模型行为验收。

## 权威源码和关联文档

- 稳定入口见本文 frontmatter 的 `sources`。
- Agent、Skill 和 Tool 的架构关系见 `docs/architecture.md` 的“智能体平面”。
- 用户可见工具矩阵见 `README.md` 的“分析工具清单”。

## ToolContract 与角色可见性

`ToolContract` 是工具名、给 LLM 的短描述、input schema、output schema 和 MCP annotations 的唯一来源。OpenAI-compatible endpoint 默认接收 portable schema；profile 声明 structured output 时，运行时把可选字段转换成 nullable-required 并发送 `strict:true`。转换须保留联合分支与 `const` 约束，并处理 `$defs` 内的对象；返回参数按原始 schema 及其本地引用恢复，保留原本合法的 null，不猜测存在歧义的联合分支。若 endpoint 首次以 schema 相关 HTTP 400 拒绝，当前 run 只降级一次并记录 `tool_schema_strict_fallback`。

角色白名单固定为：Semantic Modeler 使用 search/read/semantic/graph；Validator、Vulnerability Analyzer、Deep Worker 和 Alert Verifier 可使用六个工具。后端不再改变工具词汇，只通过 `coverage.level/providers/missing/details` 表达能力差异。函数语义查询在 Analyzer 中可能调用外部 LLM 并持久化快照，因此 MCP annotation 保守标记为非只读且 open-world；其余五个分析工具是只读、幂等和 closed-world。

单次结构化结果硬限制约 60,000 字符，包含截断说明和分页信息。列表裁剪只删除完整 item，源码裁剪只删除完整行，通过二分查找确定可保留的前缀，不修改后端持有的原始结果；高成本 snapshot 正文可以省略，但来源、状态和恢复提示必须保留。Agent、runtime 与缓存命中共用同一结果限制和 output schema 校验，工具实现违反契约时返回 `internal_error`。后端异常只公开异常类别，审计中的结构化错误和 hook 原因同样脱敏。

符号查询与源码读取共用工程目录和排除规则；默认分析模式另保留用户配置的无源码 external 契约。工程目录被替换后拒绝读取，缓存符号仍须按当前排除规则复核可见性。正则符号匹配使用 `regex.VERSION0` 和整次匹配的 1 秒预算，超时明确报错，不当作无匹配。文本搜索沿用独立的文件数、字节数和时间预算；这些是查询资源边界，不代表后端建模或远程调用的端到端耗时承诺。

函数定位中的文件、签名和 USR 是约束，冲突时不能退回同名函数。跨函数查询必须向上传递子查询的覆盖缺口；部分源码和缓存续页不能标为完整定义。安全语义函数记录只有在当前源码摘要和构建范围匹配后才可称为 current；无法验证整体时效的全局语义记录保留为 partial。静态发现同样按当前构建范围筛选，后端缺失、查询失败和真正未发现结果分别表达。

数据流路径采用反向可达剪枝和惰性深度优先遍历；整次查询及递归子查询共享 100,000 次展开预算，单条路径最多 200 个节点，触顶分别报告 `path_search_bound` 和 `path_node_bound`，不保证首条路径最短。sink 正则匹配共享时间预算；Joern 先在本地限时匹配调用名称，再向服务端传入精确名称集合。静态发现的后端结果达到容量上限时也必须报告 partial，不能把被截断的查询当作完整结果。

`tests/fixtures/tool_use_eval_v1.json` 固定至少 40 个跨 C、C++、Java 的工具选择场景；`scripts/evaluate_tool_use.py` 既可对已有 JSONL 调用轨迹评分，也可通过 `--run-llm` 使用生产 `LLMClient` 和 Registry 当前六工具 schema，独立发起每个场景的首次 tool call。真实运行从标准 LLM 环境变量取连接参数，强制每个场景只产生一个首调用，并同时保存原始场景 prompt、实际注入上下文后的 `presented_prompt`、模型、finish reason、usage、规范化参数或执行错误，便于复算并识别不可由当前 schema 表达的用例；`--first-tool-only` 只门禁首次选择、首次参数合法性和旧工具调用率。完整轨迹评分继续覆盖错误后恢复、coverage/may 语义和两调用发现-读取上限，并保留证据引用。schema token 门槛使用同一稳定估算器和冻结的旧 14 工具基线，防止六工具描述随迭代重新膨胀。

## 编译实例事实查询

`get_semantic_context` 另支持 `kind=build_contexts` 和 `kind=program_facts`。先枚举实例，再携带其 `build_context_id` 和精确函数名 `query` 读取 native 程序事件；沿用分页和结果体积限制。两种查询不调用语义 resolver，不生成模型快照。读取旧输入、缺实例存储或未初始化后端时返回缺口；只读缓存前端尚不支持的查询保持 unavailable。实例内函数事实完整不等于跨 TU 链接路径完整。

## LLM 客户端生命周期

进程共享额度按存活客户端所有者计算最严格的正上限，关闭客户端注销其约束并唤醒等待者。配置上限与 AIMD 过载降速分开维护，注销不会清空其他请求的在途计数和有效 RPM 历史。客户端关闭后停止接收新请求，已取得额度的请求保留 HTTP session，最后一个请求释放后完成清理。借入客户端的所有权留在调用方，Facade 只能关闭自身创建的客户端。

curl 传输等待期间以有界间隔重读取消令牌和动态 deadline，中止时终止并回收进程、移除临时配置；取消异常不进入普通重试。绑定令牌的 requests adapter 使用 HTTPX 的可取消请求任务，覆盖响应头与流读取；同步入口须在同步 worker 中调用，不在已有 asyncio loop 内另起脱管线程。
