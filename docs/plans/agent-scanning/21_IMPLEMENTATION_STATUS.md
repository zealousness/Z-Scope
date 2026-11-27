# 21 · 实施记录

本文件记录用户授权“JUST YOLO，按照该实施计划落地”后的真实开发状态。计划目标不等于完成声明；本轮保留已有未提交修改，未创建提交、推送或正式 benchmark 结果。

## 2026-10-12 · S01 第一切片：编译实例事实与查询

状态：**该切片已实现；S01 整包仍在进行，整份计划尚未完成。**

原先 native batch 对同一源文件只提取第一条命令，KnowledgeDB 按文件的查询投影无法表达多个宏/ABI 变体。现在枚举所有符合扫描范围的不同命令身份，仅折叠完全相同命令。每个实例的 native 记录独立保存，CodeIndex 和现有语义工具可以按构建身份读取实际函数事件。

实际改动：

- `retrieval/build_context.py` 定义内容绑定的 BuildContext，包含命令、环境、响应文件、工具、依赖与已观察 ABI；无链接证据时明确 `link_target=null`。
- KnowledgeDB schema 17 新增 `compilation_instances/compilation_facts`。与导航投影同代次原子提交；删除 TU、失效变体或切换 LSP 撤销相应实例。自动事实库不迁移为虚假的多变体历史证据，下次 native 索引重新生成。
- batch producer v3 分别缓存和提取编译实例；区分 `extraction_complete`、`projection_complete` 和查询就绪。新增变体不会被文件去重静默吞掉，失败以实例计数。
- `CodeIndex.get_build_contexts()` 与 `get_function_program_facts(..., build_context_id=...)` 提供实际查询。未选择的歧义返回空证明事实和上下文列表；无效身份不回退到其他实例。
- `get_semantic_context` / `zscope.semantic.context` 新增 `build_contexts`、`program_facts` 查询。后者要求精确函数名和构建身份，分页返回函数描述、事件、CFG 边与访问。仅消费已初始化后端，不调用 LLM，不触发建模。源码、头文件、响应文件、环境、编译数据库或 include 搜索成员变化时，交互查询返回过期原因，不返回当前证明。
- 语义输入缓存继续比较规范化代码/事实、命令、工具和 ABI；注释变化撤销旧字节凭证，但可复用语义结果。对象内部构建身份不被归一化删除。
- 增量事实 replay 现在比较全部符合范围的编译实例及导航投影，单独保留投影缺口；仍不是候选、验证终态或召回等价性证明。

实现落点：`retrieval/{build_context,clang_batch,clang_backend,knowledge_db,code_index,incremental_replay}.py`、`semantics/compiler_fingerprint.py`、`tools/semantic_context.py`。同步了 README、AGENTS、architecture 和相关模块文档。

## 验证

所有质量检查在 WSL Ubuntu 的 `<venv>` 执行。初次发现已安装 native 工具仍输出旧程序事件版本，已使用当前 checkout 的 native 源码和系统 LLVM/Clang 18.1.3 重新构建测试工具：

```bash
python scripts/build_clang_indexer.py \
  --llvm-prefix /usr/lib/llvm-18 \
  --build-dir $HOME/.cache/zscope-build-context/build \
  --prefix $HOME/.cache/zscope-build-context/install --jobs 2
export Z_SCOPE_TEST_CLANG_INDEXER=$HOME/.cache/zscope-build-context/install/bin/zscope-clang-indexer
```

这是开发机真实 native 验证工具，不是 portable 发布包，不替代锁定发行工具链。没有运行客户项目扫描、真实 LLM 分析、Sanitizer 自动复现、正式准确率 benchmark 或 portable smoke。

测试包含同源两组宏、真实 native 事件差异、热缓存、头文件修改、变体删除/重排、TU 删除、命令/响应文件/环境/include 搜索失效、分页语义工具与八类真实增量变更。

最终验证记录：

| 检查 | 实际结果 |
|---|---|
| 主回归：build_context、clang_batch/logging、KnowledgeDB、indexing_pipeline、incremental_replay、evidence_tools、semantic_cache_only、mcp_read_only、incremental_semantic_modeling、source_contract_boundaries、tool_schema_strict/registry/use_eval、conditional_ownership_contracts、wrapper_contract_compiler | 298 passed、2 failed、1 skipped；两个失败均为工具定义长度预算，随后修复并定向复验 |
| 修复后：tool_use_eval、tool_schema_strict、evidence_tools、semantic_cache_only、mcp_read_only | 64 passed；包含上述两个失败用例。缩短说明而未放宽约束，schema 估算为 1516/2168（69.93%） |
| agent_docs、config_v2、reference_configs、portable_runtime、portable_release | 77 passed |
| `python -m compileall -f -q zscope scripts test tests` | 通过 |
| `python -m mypy zscope` | 308 个源码文件通过 |
| 本轮 Markdown 编码、计划本地链接、代码块及 `git diff --check` | 通过 |

截至最后修复，以上测试集合的失败均已消除；重复执行的用例不叠加为额外覆盖。唯一跳过项是 `test_real_direct_bitcode_dependency_cache_and_svf`，需要显式 `Z_SCOPE_TEST_LLVM`，本轮未启用该 LLVM/SVF 执行链。真实 native Clang 的八类增量对照已经执行并通过，不能把这一结果扩大为完整扫描、模型或 SVF 等价性。

## 2026-10-12 · 契约作用域与自动复现接续

构建身份继续传入源码契约与池协议、快照、工作簿及调用点。ApiContract schema 升为 v5、compiler 升为 v17，旧自动证明失效；ContextVar 隔离并行消费者，未指定或不匹配的实例不能使用实例契约。未展开条件编译源码及歧义/过期事实不能推导确定效果。报告新增 `metadata.build_coverage`，分别说明提取结果、多变体消费者缺口与未知链接归属。语义缓存记录现绑定内容构建身份，跨内容复用和重新签发尚待完成。

该节点在 WSL 执行 contract_build_scope、conditional_ownership_contracts、wrapper_contract_compiler、source_contract_boundaries、incremental_semantic_modeling，共 **100 passed**。节点时点 `mypy zscope` 为 **309 个源码文件通过**；这不是后续尚未验收代码的验证结果。

后续构建身份、契约 schema/链路/发布、并行语义、恢复、Markdown/报告装配与文档回归 **101 passed**。修正 regex 与 Clang 候选生成器的事件收集顺序，使其先取得程序事实、再按实例生成语义调用事件；相关契约/发布/边界回归 **56 passed**，包含两个实际候选生成器的实例正反例。透明配对发现也读取对应程序事实，不另走无作用域的源码证明。

自动复现会话服务、原程序入口计划和 native 对象见证正在开发。真实 ASan 已产生正例报告，并匹配候选对象/分配点/访问点；集成测试揭示独立重放重复消耗构建预算，当前尚未通过验收，默认运行模式仍为 off。用户指定通过 agent-bridge 交由 Kimi 完成自动复现/Sanitizer 修复，再由主协调者独立检查 diff 和运行 WSL 验收。此处不把库级执行器、首次见证或未完成的服务声明为 S05 交付。

## 2026-10-12 · 协调者接续：精确函数事实身份

跟踪 Kimi 的 `task_ed2762ccfa` 期间，独立检查发现单个 BuildContext 内的 C++ 重载仍混合返回事件，只有 `complete=false` 提醒，且调用方不能选择一个重载。已在既有实例存储和查询上补齐 native USR 选择，不另建符号库：

- `CodeIndex` 保留 USR 中的 `@`；KnowledgeDB 和 ClangBackend 在指定实例内按 owner USR 查询函数与访问。未知 USR 返回缺失，不回退到同名函数或其他实例。
- 同名歧义返回 `ambiguous_function_identity` 与 owner 选项，事件/访问/函数证明体为空；语义工具把选项作为 `function_choice` 分页返回，选择后的结果附带 BuildContext + USR 的 `function_identity`。
- 同一头文件的 static 函数即使 USR 相同，也因 TU 构建实例不同而保持独立。交互查询继续检查当前输入；没有宣称链接目标或完整扫描调度迁移完成。
- 建模调用和发布快照的 `semantic_model_unit_uid` 绑定构建实例。语义指纹去掉函数身份的字节收据字段但保留 USR，不因仅注释变化额外破坏语义复用；重新签发当前源码契约仍是必要条件。

本切片在同一 WSL Python/native 工具下验证：编译实例/精确符号、Clang batch、KnowledgeDB、条件契约/作用域/透明包装、增量建模、证据工具、cache-only/MCP 和 schema/use-eval 共 **249 passed**。随后增加缓存收据分离修正，精确符号、快照 observation、契约作用域与增量建模 **93 passed**。文档/配置/模板 **51 passed**，交接文档/portable runtime/release **32 passed**（这些集合含重复项，不累加覆盖数）。该节点 mypy **311 个源码文件通过**，compileall 和修改 Markdown 的 UTF-8/LF 检查通过。

自动复现仍待 Kimi 最终交付后独立验收；上述 S01 成绩不替代其最终测试。协调者初步运行的真实 ASan/TSan 执行测试为 **16 passed**，证据在 `/tmp/zscope-coordinator-sanitizer-20261012.json`；这一结果不代表自动 TSan 对象映射、完整 S05 或正式准确率 benchmark 通过。

截至协调者本轮检查，Kimi 任务仍在运行。待收敛的实际失败：

- `test_reproduction_planner.py` 新增用例的检查为 **23 passed、1 failed**，失败是重复 native 分配事件的合成反例；Kimi 正在核对真实 v5 事件，不允许把真正二次分配一起去重。
- 动态复现/Validator/扫描会话回归为 **268 passed、1 failed**，旧 `test_scan_hook_is_inert_by_default_and_executes_when_enabled` 仍依赖全局 provider，需迁移到会话服务并保留不串用 provider 的反例。
- 协调者新增 `test_reproduction_arguments.py` 为 **1 passed、5 failed**：自动计划不应保留 `-objcmt-*` 源码迁移参数，优化记录、模块输出也不能写到业务工程目录；本机 Clang 帮助已核对这些选项含义。修复前这些用例明确保持失败，不能记为验收完成；`-ObjC`、`-object-file-name` 等真实语义选项应保留。

此前保存过每 10 分钟的自动续接，但后续检查其状态已为 PAUSED；不能根据本段历史记录声称它正在运行。主协调者仍在当前任务中跟进 Kimi，读取结果、自行检查差异并在 WSL 修复/复验，通过后继续计划；无需用户再次确认。S01 查询切片与尚未通过的自动复现分开记录。

## 尚未完成与接续点

S01 契约消费继续修正重载歧义：原先按角色筛选后才检查同名身份，可能在多个重载中误选唯一的释放/获取角色。新增 `find_for_call` 先核对完整符号，再筛选角色；包装源码组合、资源域、分配大小和协议转换采用相同约束。显式文件/签名仍可消歧，同一符号的多个效果仍可共存。compiler v18 与注册表指纹撤销旧效果解释；native callee USR 到所有契约调用者的自动选择尚未完成，歧义保持未知。

该节点 WSL 契约、构建作用域、包装、源码边界/schema/链路 **108 passed**；加入指纹版本和转换选择后的 schema/链路/defaults/发布、增量建模及交接文档 **73 passed**，mypy **312 个源码文件通过**。

S00 新增独立 `tests/fixtures/resource_protocols/pool_queue.c`：成功转移后重复归还、失败遗漏归还、取消后完成再次归还及对应安全路径。业务计数避免未定义行为，明确只验证顺序协议，不作为 Sanitizer 见证。WSL 真实 Clang 构建、六条执行路径与 native 候选采集 **7 passed**。仅将 C 源码/编译数据库交给索引与现有 Regex/Clang 生成器，标注不进入分析。

当前未建模基线中，三个 submit 函数没有生命周期候选；cancel/complete 得到泛化 race 候选，安全 cancel 同样如此。记录在 pytest 临时目录 `protocol-baseline.json`。这说明需要 S02 的条件责任与 S03 的跨阶段对象协议；未运行 LLM/Validator/SVF，不把候选数当最终召回/误报，也不据此直接禁用现有规则。测试允许后续候选改进，不冻结漏检为期望输出。

U01 已完成首个只读启动准备切片：`zscope-config prepare` 与本地 Web 项目配置页共用 `config/preparation.py`，列出实际配置/工程/产物路径、去重编译实例、多变体提示、工具存在性和配置中的扫描/复现模式。准备不调用模型、子进程或扩展 provider，不加载历史 rollout；缺失/无效数据库给出处理提示。前端编辑/重载配置后撤销旧视图和迟到响应。尚未实现完整业务模型问卷、准备方案修改/试编译、夜间时窗配置或整包 U01。

本切片 WSL 验证：project_preparation、config_v2、web_rules_api、agent_docs **57 passed**；Node 直接执行 Dashboard 脚本，验证迟到响应撤销、错误提示和成功视图状态；`mypy zscope` **312 个源码文件通过**。另外交接文档/portable runtime/release **32 passed**，compileall 通过。在本地浏览器连接临时测试工程，检查卡片布局、编译变体与复现模式显示；没有将工具存在性检查等同于工具链/模型运行验收。

本轮独立复现验收为 **259 passed、1 failed、1 skipped**：仍失败的是旧扫描钩子依赖全局 provider 的测试。新增 `test_reproduction_identity_acceptance.py` 的两个真实 native 反例也失败：指针取地址后经二级别名改写，仍被签发最初分配的对象见证；同一行多分配时运行时文件/行号不能修复这一错误。自动复现仍未验收通过。

Bridge 不支持在运行会话中追加消息；协调者保留全部已写改动，主动结束原轮 `task_ed2762ccfa`（cancelled，不记为完成），读取其结果并在同一会话 `sess_9bec0aa89e` 成功派发 `task_e3542f6ec9`，让 Kimi 专注上述三项剩余验收。后续应等待新任务、读取 `get_result`、独立复验；旧任务不再运行。Bridge 的文件列表包含协调者并行改动，不能全部归因于 Kimi。

| 工作包 | 实际状态 |
|---|---|
| S00 | 真实 queue/pool 正反例与 native/现有候选基线已建立；完整模型/Validator/SVF 对照仍未运行 |
| S01 | 实例存储和查询切片完成；旧函数/类型/图导航投影仍按文件组织，不能宣称整包完成 |
| U01 | 只读启动准备切片已完成；完整准备交互与夜间时窗配置待完成 |
| S02–S09、U02 | 尚未整体按新版计划交付；原有能力与自动复现进行中部分依上文及 02 区分 |
| S10、Q01/Q02 | 保持原计划的条件和后置顺序 |

继续 S01 时优先完成真实链接目标/构建分组与实例作用域向函数调度、SymbolIdentity、契约、图边、候选、缓存和见证的传播，替换旧消费者，而非再建第二套实例库。当前 scoped program facts 不能授权另一 TU/目标的路径；完整扫描仍可能经旧投影分析部分变体，因此需要把实例覆盖缺口进一步传播到最终报告，并保留未完成工作。

身份传播切片需要成组处理：Regex/Clang 候选顶层的构建身份、CandidateEnvelope/义务/缓存键、普通去重、finding roots 与 same-site aggregation，以及人工 baseline 的范围。该切片已于 2026-10-13 完成下述验收；不能将其扩大解释为全部变体的函数调度或真实链接目标归属已经完成。

接着用 S00 的 pool 获取 → queue 成功转移/失败保留 → complete/cancel 正反例推进 S02/S03/S04。ObjectRef 的区域、实例和代际、自动复现生成器、夜间持久作业及集中验收尚未因本轮新增存储而自动实现。

## 2026-10-13 · Kimi 交付与独立复现验收

`task_e3542f6ec9` 已正常结束（completed/end_turn，无 warnings）。协调者取回完整结果并审查实际代码，随后在 WSL 使用真实 native Clang 工具，运行 reproduction_planner、reproduction_arguments、reproduction_identity_acceptance、dynamic_reproduction、dynamic_reproduction_execution、validation_runner、scan_session_resume_svf：**265 passed，无失败、无跳过**。启用执行证据转储，真实 ASan/TSan 记录在开发机 `/tmp/zscope-reproduction-acceptance-20261013.json`。

本次通过的是 S05 的单 TU 原程序入口切片：共享执行预算记录 plan/binary 摘要，独立重放复用已核验的构建，篡改二进制后拒绝复用；自动计划精确绑定构建、对象与站点，指针地址逃逸和同行多次分配保持未决。扫描会话使用显式服务，既有全局 provider 不影响产品执行。扫描钩子、编译参数及两个真实别名反例均已通过独立验收。

RuntimeSpec 默认仍为 off；多 TU 链接、内部函数 harness、业务输入生成与自动 TSan 对象映射尚未完成。这不是完整 S05、正式 benchmark 或 portable 验收。接续开发按上文 S01 候选—义务—事实缓存—去重—报告—人工 baseline 的身份传播切片推进。

## 2026-10-13 · S01 候选到人工反馈的构建隔离

候选协议升级为 v3.5，decision facts v1.4、security obligation v1.3。完整且当前的无歧义程序事实将构建身份传入 Regex/Clang 候选和 ticket；该身份进入 CandidateEnvelope、义务/region、事实图、Validator 缓存、Ledger 与终态。重注解已改变构建身份的候选会重新生成身份，不复用旧 cluster。混合事实图按构建切片，不从另一实例补齐缺失事实。

普通和语义去重、finding roots、exact-sink roots、同站点聚合及 baseline 均分隔不同构建和未知构建。同构建的重复证据仍可合并。Web 对已知构建的人工误报决定仅保存到 baseline；无构建收据的位置 suppression 不再绕过这一范围。原有报告复用检查通过 v3.5 撤销旧候选协议直接复用。

WSL 验证：主链路与存储/恢复/文档回归 **274 passed、2 failed**，两个失败均为新增测试对 Ledger 终态 API 的使用错误，已修正为真实登记、终态回填和生命周期快照；修正后的新增测试及普通/语义去重回归 **68 passed**。其中两个真实 native 测试从同源两组编译命令，经 Regex/Clang 到 Registrar、Ledger 和终态，验证身份分离。动态复现、规则目录/治理/扩展与交接文档 **217 passed，无跳过**；mypy **312 个源码文件通过**，compileall、修改范围 diff 检查通过。重复集合不叠加为额外覆盖。

稳定模块文档及 AGENTS 已同步。尚未将旧导航调度替换为全编译实例调度，链接目标仍未知；没有运行正式准确率 benchmark、真实模型或 portable smoke。下一切片以单构建中的 queue/pool 协议为范围，区分“保存了对象引用”的源码事实与“接管释放责任”的业务契约，避免仅凭入队赋值推导所有权转移。

## 2026-10-13 · S02 单槽引用留存与 S01 发布修复

新增 `reference_retention` 角色和 `single_slot_retention` 提案格式，模型 schema/prompt 与工作簿枚举同步。源码校验重用 ApiContract/条件谓词/编译实例，不另建第二个模型库：仅接受有完整 native v5 存储/返回事件、无宏或调用副作用的 C 单槽实现。成功保存、失败未保存各有动作，载体和接收方槽分开绑定；未检查返回值保持未知，释放责任仍为 unresolved。将保存引用误写为 ownership_transfer 的提案只能发布留存事实，不能凭此排除泄漏或批准提前释放。编译器 v19 撤销旧自动契约复用。

真实池协议链路暴露并修复一项 S01 发布遗漏：`LocalPatternSemantics.add_api` 曾用实例作用域查询做全局名称登记，从而为已发布的实例契约额外制造无作用域同名契约，导致实际调用歧义与漏检。现在登记检查全部声明，效果消费仍按实例查询。native 池回归分别编译正确域和错误域源码，并让候选生成器消费实际索引源码及程序事实，验证工作簿/透明包装/候选的同一链路，另锁定发布与合并不得制造无作用域别名。

WSL 节点回归（留存、池、条件契约、schema、包装、作用域、发布、工作簿、候选身份、文档和工具 schema/use-eval）**227 passed，无失败、无跳过**。native 队列测试使用独立 S00 fixture 的源码/编译数据库，不向索引提供标注；建模工具交互回归使用受控响应，不宣称调用了真实模型服务。跨 complete/cancel 的对象责任、别名/代际和最终生命周期裁决尚未交付，本切片不等于完整 S02/S03。

## 2026-10-13 · S02 内嵌单槽池、主动调查消费与缓存修复

新增有界 `single_slot_pool` 源码核验，使用 ApiContract 的既有获取/归还角色与条件转换，不新增候选规则。协议区分返回的资源、池实例和内嵌槽地址；获取成功、失败空返回以及归还时同槽成员/live 条件分别保留。可选代际自增仅记录实际动作，不声称永不回绕或异步代际正确。逻辑归还不能替代 free，也不能仅凭 API 配对消除条件未知的候选。

native `ProgramEvents.h` 在原 TU 解析中增加 `zscope.resource-protocol-facts.v1` 能力收据：参数所指 record 的种类与 USR、嵌套宏标记、Clang 空指针常量判定。使用当前源码在 WSL 重建开发工具后验证；没有替换 portable 锁定工具链或宣称发行验收。单槽池/留存核验拒绝缺失新能力的事实、union、宏改写及未知副作用；NULL 只在 Clang 确认为空指针常量时放行。即便同一 TU 的类型都拼写为 Pool，不同 native record 也不得建立配对。条件 `address_of` 保留成员地址与成员值的区别，包装组合和分支事实同步；契约编译器升级至 v20。

S00 原始源码/编译数据库经 native → 提案核验 → 工作簿 → 现有 Regex/Clang，失败遗漏归还路径已产生带构建身份的泄漏候选。零 LLM 安全语义图也已消费该池和引用留存：修复新角色遗漏以及调用未传入构建事实的问题；函数/audit 输入身份分隔构建，过期/歧义事实和另一构建的 overlay 不获得当前作用域。留存作为 resource_transition 观察，不提升为所有权或确认结论。尚未闭合成功转交、complete/cancel 和跨阶段代际，不把候选计数当最终召回/误报。

扩大回归曾为 **332 passed、2 failed**，定位到此前构建身份迁移使建模缓存路径随源码字节变化：编译语义未变也找不到旧记录，且失效原因误记为 spec。现有 sidecar 改为每个导航符号保存最近一份输入/结果，完整语义输入仍逐项比较；候选、Validator 与证据身份不变。无接口契约的快照可在纯字节收据变化时复用分析；有契约时保守重建为 build_receipt，不重绑旧证明。真实 native 测试验证新收据重新核验、随后相同收据缓存命中。多编译变体缓存容量和普遍的无 LLM 契约重签仍未完成。

本节点最终 WSL 跨模块回归 **499 passed，无失败、无跳过**，覆盖单槽协议/真实 native 反例、条件/包装、模型发布、候选身份、主动调查、Clang、增量/缓存、规则目录/治理和交接文档。另有修复后定向 **70 passed**、缓存/快照 **103 passed**、实际链路与文档 **52 passed**，这些集合重叠，不累加。mypy **314 个源码文件通过**，compileall、修改范围 diff 检查和文档 UTF-8/LF 检查通过。

使用本节点重建的 native 工具，重新执行 Kimi 交付对应的 reproduction_planner、reproduction_arguments、reproduction_identity_acceptance、dynamic_reproduction、dynamic_reproduction_execution、validation_runner、scan_session_resume_svf：**265 passed，无失败、无跳过**。真实运行证据保存在开发机 `/tmp/zscope-reproduction-post-protocol-20261013.json`，未改变自动复现默认 off 的边界。下一节点继续 S03 的成功留存/失败保留，以及 complete/cancel 跨阶段对象责任与生命周期路径；本次仍非全实施计划、正式准确率 benchmark 或 portable 发布完成。

## 2026-10-13 · S03 单槽清理候选与 S04 缺失义务保留

新增受限 C 单槽清理摘要 `retained_slots.py`，消费现有 native v5/资源事实收据和已核验的同 TU 单槽池契约。摘要分别绑定接收方参数、槽位字段、池参数、局部副本与真实调用身份，支持直接槽位和单个直线局部别名、非空分支、摘除后归还及归还后清空。函数名不参与场景猜测；额外调用、条件清空、重赋值、错字段、union、非空 NULL 宏、字段宏改写和失效构建不能取得摘要。使用已有 native 开发工具，本节点没有改动 native 实现或重新制作 portable。

新规则 `zscope.c_cpp.cpp_clang_cfg.retained_slot_release` revision 1 通过 Clang 资源域调度和公共 emitter 登记，已核验正常摘除路径不产生本规则候选。内嵌池仍有存储，逻辑归还不等于堆内存 free，因此规则归入 `state_inconsistency / CWE-672 / ownership_contract`。缺陷成立仍需归还条件、同分配代次、接收方存活、后续访问和共同可行路径；摘要保留 generation/allocation_site unknown，不授予证明权限。规则保持 experimental/default-disabled，显式启用可做开发验证，disabled 优先并且 Skill 过滤正常。

端到端反例发现并修复两项裁决风险：缺失事实归一化曾丢弃固定 provider 词表之外的义务，一般补证随后会把切片变成 complete；高分 verified 的旧晋升分支未检查显式缺失义务。现在未知义务保持未决，补证只选择既有 caller/cleanup/reachability provider，一般结果不能冒充专门协议事实。模型晋升同时检查顶层和事实切片缺口，高置信 uncertain 也遵循该规则；空顶层列表不能遮蔽切片，报告说明未闭合原因。独立完整的确定性证明仍走既有证明裁决。本节点只修复已知缺口绕过，不声称已完成 S04 的全部证据语义和 provider。

Validator 缓存协议升级 v10；运行 manifest 新增 `zscope.validation-policy.v1`，缺失或不匹配策略的历史报告不再跳过重扫。旧报告保留可读，已有产物不被改写。AGENTS、分析/接口模块文档、验收场景和规则资格说明同步；本节点不修改产品 Agent prompt、不增加 web 访问、不引入新的用户审批步骤。

最终 WSL 回归 **546 passed，无失败、无跳过**，包括真实 native 正反例、S00 六条实际执行路径、单槽池/留存、Clang 规则、目录/资格/禁用策略、候选身份和事实、补证、Validator、报告恢复与交接文档。自动复现/计划器及 CWE/Validator wire 回归另有 **185 passed，无失败、无跳过**；本轮没有重跑完整 Sanitizer 执行矩阵，前一节点 265 项执行验收不冒充本轮成绩。mypy **315 个源码文件通过**，compileall 和修改范围 diff 检查通过。过程中的补证顺序断言已纠正，实际义务丢失和评分绕过均由新增反例锁定并修复。

当前交付是 S03 的单槽清理候选切片，不是完整跨阶段生命周期求解。成功留存后的业务责任、失败路径的责任终点、跨函数/跨回调同代路径，以及相应专门事实 provider 仍待推进。下一切片应把这些对象义务连接到实际调用路径，优先覆盖 S00 成功留存/失败保留与 cancel→complete 的因果链；不得用当前局部摘要直接确认重复归还或 UAF。未运行真实模型、正式准确率 benchmark 或 portable smoke。

## 2026-10-13 · S03 具体对象调用路径与 S04 定向缺口

新增 `LifecyclePaths`，在一个当前 BuildContext 内按 native USR 精确读取同 TU 被调函数，解释有界、输入可确定的 C CFG 路径。局部变量按调用帧隔离，真实参数传播到字段和池实例；获取创建带分配站点、调用帧和独立获取代次的 `ObjectRef`。同一站点重复导出的 call 事件只执行一次；不同站点和再次获取保持独立身份。被调事实在本次分析内复用，不为每个调用重启 Clang；输出只保存路径边和事实输入摘要，不重复铺开每条边的完整 native 值元数据。

成功留存、失败未转交、摘除、实际归还、重复归还尝试、错池和旧指针命中新代对象已连接到具体因果路径。C 指针地址比较与获取代次分开：旧指针在槽地址复用后可能实际归还新对象，不能把它算作同代 double free。归还条件不成立时明确记录 no-effect。失败后正常归还、成功后正常 complete、cancel 摘除后 complete、再次获取后正常使用、失败后重试留存，以及常量分支排除 cancel 均有反例。引用留存与实际执行清理仍不证明业务上承担释放责任；入口结束不自动构成长期对象的责任终点。

native 增加 CFG 入口/出口及 `zscope.lifecycle-value-facts.v1` 附加收据，包含值的重叠存储、volatile/atomic、整数宽度/符号、聚合值和返回类型。具体路径不猜测缺失收据、外部/间接调用、未知入口参数、循环、union、聚合复制或未支持的转换。采用实际 WSL 开发工具重编译和安装；最终执行干净重编译，未更换 portable 锁定 SDK，也未制作或验收发行包。

新规则 `zscope.c_cpp.cpp_clang_cfg.object_protocol_path` revision 1 已进入 Clang 资源域、目录、Skill 过滤和显式启停测试，保持 experimental/default-disabled。候选保存完整调用路径和 ObjectRef，不授予证明权限。S04 已接入已闭合的获取/对象代次/可行路径事实，业务释放规范、责任终点或后续访问仍作为精确缺失义务；一般补证及模型高分不能伪造这些事实。验收发现补证队列曾把全部 required 再当作 missing，现在有缺口清单时只按真实缺口选择 provider，旧候选缺少清单才回退 required，避免重复查询已闭合路径。

验收使用 S00 原始池/队列实现的源码副本，并增加普通 C 调用入口显式组成测试场景；期望结果只留在测试断言，扫描器不读取答案。当前未自动为用户工程生成这些入口，也未求解原始 `main(argc, argv)` 的参数、任意 switch/外部调用、跨 TU 链接或线程交错；这不是完整 S03/S04 或 S06 的完成声明。详细开发证据保存于 WSL `/tmp/zscope-object-protocol-paths-20261013.json`，包含 12 个场景的对象路径、候选和义务；不是正式准确率数据。

下一切片继续 S04 的业务责任来源绑定和条件性结论，再按缺口推进调用上下文/输入与 S06 异步协议；现有具体路径作为可复用事实源，不能将计数器、单线程顺序或未复现结果直接升格为缺陷/安全证明。AGENTS、分析与后端模块文档及 RES08/RES09/VAL08 验收规格已同步，无新增用户配置、审批步骤或 web 访问能力。

验收结果：WSL 第一组协议/候选/治理/补证回归 **241 passed**，跨模块（含 Validator、报告、配置、后端、发布代码单元测试和交接文档）**513 passed**。最终重编译工具后的对象协议、native 构建身份与动态复现回归 **351 passed、1 skipped**；唯一跳过项为未设置可选执行证据导出路径，实际 ASan/TSan 正反例、资源边界与不稳定复现测试均已运行通过。随后显式配置导出路径重跑实际执行组，**16 passed、无跳过**，证据保存于 WSL `/tmp/zscope-reproduction-object-path-20261013.json`。这些测试集有交叉，不累计为不重复用例数。mypy **316 个源码文件通过**，compileall、修改范围/新文件 diff 检查及 UTF-8/LF 检查通过；交接文档另有 **6 passed**。未执行真实模型、正式准确率 benchmark 或 portable smoke。

## 2026-10-13 · S04 当前源码核验与条件性验收

新增 `protocol_assessment.py`，复用 CodeIndex、运行时 ContractRegistry 和有界 LifecyclePaths 重放当前具体路径。路径 v2 记录实际消费契约的完整摘要、符号、来源、源码核验收据和事件依据；Validator 要求当前构建/被调事实/对象/原观察全部匹配，并独立核对编译契约使用的源码 token 摘要。候选包中的契约不能被重新注册成可信来源。源文件、契约内容或其依据变化，旧路径收据、缺 provider、错误对象或技术缺口均保留 pending，不作为安全反证。

重复归还、错池、旧代次归还、失败未归还分别产生具体业务前提。失败未归还另列“入口退出是否为责任终点”；仍有留存槽位但缺少后续访问时继续待补证。前提明确标记 `analysis_requirement / unconfirmed`，绑定 BuildContext、入口、ObjectRef、依赖摘要和观察，而非伪装为已确认用户规范。源码契约仅说明实际效果，不授予业务释放责任。

统一 ValidationPipeline 新增 `business_conditional` 与 `protocol_pending` 两个 needs_review 子状态：只有本次完整重放且只剩业务前提时才呈现条件性风险；技术缺口或冲突仍待补证。模型高分/三态判定、删除缺口清单不能使该规则自动确认或拒绝，独立完整证明仍按原渠道处理。程序收据在 JSON 中不携带授权，新扫描必须重放；关闭模型也执行核验。验证结果缓存纳入本次核验身份，缓存协议升至 v11，报告复用策略升至 v2；旧报告保持可读。

JSON、汇总 Markdown 和 WebUI 共用的单条 Markdown 保留前提、来源、适用范围与技术缺口，问题集中在验收，不增加夜间扫描中途交互。规则 `object_protocol_path` revision 2 仍为 experimental/default-disabled；没有增加公共配置或 web 访问能力。AGENTS、分析/接口模块、数据契约与 VAL09–VAL11 验收规格同步。

本切片没有交付业务回答的结构化写回/依赖重算、任意规范文本的权威解析、所有规则的统一四态、通用输入求解、跨 TU 或异步并发路径；也不把条件性风险计为 confirmed。后续沿 S04 补齐前提反馈与专门义务 provider，再推进输入/调用上下文和 S06 异步协议。当前 native 工具及接口无需修改，本节点使用前一节点真实构建的开发工具验收。

最终 WSL 协议、候选/规则、补证、完整 Validator 编排、报告/Markdown、Web 服务及交接文档回归 **449 passed，无失败、无跳过**；新增专项与交接文档另有 **32 passed**（包含在上述集合中）。测试覆盖当前源码、契约内容/来源变化、构建失配、JSON 重载、收据/候选篡改、未知技术缺口、模型三态和禁用模型。复现库/计划器/身份验收、配置、扫描恢复和 portable 代码单元回归另有 **262 passed，无失败、无跳过**。mypy **317 个源码文件通过**，compileall、修改范围 diff 及 Markdown UTF-8/无 BOM/LF 检查通过。真实 LLM、正式准确率 benchmark、portable smoke 和本节点完整 Sanitizer 执行矩阵未运行。

## 2026-10-13 · S04 业务前提反馈与依赖重验

WebUI 单条报告新增业务前提验收：集中填写成立、不成立或尚不确定及业务约定来源，复用项目现有状态库，不增加用户 YAML。服务端从报告取得前提和适用范围，客户端不能指定另一对象的范围；回答键绑定前提、构建、入口、ObjectRef 和源码/契约依赖，显示 ID 变化不改变含义。批量回答按预期版本原子追加历史，相同内容重试不产生多余版本，冲突保留草稿。页面切换、迟到响应和报告证据变化均不覆盖未保存输入，重新载入会明确丢弃当前草稿。

当前 native 路径重放与全部必要用户声明共同成立、没有技术缺口或冲突时，专门检查器签发限定对象和调用路径的 `checked_object_protocol_with_business_declarations`，继续由统一 ValidationPipeline 确认。失败保留仍需单独确认责任终点；用户回答不能替代后续访问、其他对象或路径事实。该规则不接受序列化通用 proof 绕过专门核验。否定或撤销前提仍保留待审，不能直接排除缺陷；关闭模型也执行当前程序核验。

回答版本进入核验收据和缓存身份；扫描中修改回答会重新读取和重放。每次核验先撤回旧业务事实和对应裁决信息，再按当前回答发布事实。历史复用和 resume 按实际依赖检查版本，维护扫描把受影响结论重新登记到候选台账；无关回答不使该结论失效。保存回答本身不改写历史报告、不立即启动扫描、不写 suppression/baseline；下次扫描生成新结论。报告保留作出判断时的用户声明、来源、版本和范围。

协议核验升至 v2，Validator 缓存 v12，报告验证策略 v3；`object_protocol_path` 规则 revision 3 仍为 experimental/default-disabled。AGENTS、README、架构、配置/分析/接口模块文档和 VAL12/VAL13/UX09 同步。没有修改 native 工具或产品运行时 Agent prompt，没有新增产品 web 访问能力。

WSL 核心跨模块回归 **523 passed，无失败、无跳过**；补充旧裁决撤回检查后的协议反馈/核验/前端脚本、Validator、复现库/计划器/身份、配置、portable 代码与交接文档回归 **383 passed，无失败、无跳过**。两组有重叠，不累计为不重复用例数。真实 native 工具参与对象路径验收；前端使用 Node 执行实际 Dashboard 脚本验证草稿、冲突及迟到响应，HTTP 处理器另验证 409 冲突。mypy **319 个源码文件通过**，compileall、静态资源摘要、修改范围 diff 和 UTF-8/无 BOM/LF 校验通过；最终文档检查另有 **6 passed**。

本节点完成精确对象范围的前提写回与重验切片，尚未完成任意业务规范解析、跨对象规则推广、离线文件业务回答导入、通用输入求解、跨 TU 或异步并发路径。下一步仍按 S04 的专门义务及输入/调用上下文推进，再进入 S06 异步协议。未运行真实 LLM、正式准确率 benchmark、portable smoke 或本节点完整 Sanitizer 执行矩阵，不宣称完整 S04 或全计划完成。

## 2026-10-13 · 资源接口识别优化纳入统一计划（仅规划）

用户授权把 [独立能力评估](../../research/resource-api-2026-10-13/ASSESSMENT.md) 的优化计划纳入本包统一跟踪。已新增 [22 资源接口识别子计划](22_RESOURCE_API_INFERENCE.md)，并补充 README、11 路线图、16 验收索引及 19 专业扫描入口；独立报告和取证清单保留原样。**规划整合已完成；以下新增代码实施任务均待办／未启动，不计为 S02/S03/S04/S06/S07 已完成。**

| 统一任务 ID | 对应阶段／范围 | 实施状态 |
|---|---|---|
| S02-R01、S02-R02 | P0：当前接缝核对、发现/核验覆盖 | 待办／未启动 |
| S02-R03、S02-R04、S02-R05、S02-R06 | P1：native 值流、条件包装器、发布/消费一致性、定向验证 | 待办／未启动 |
| S03-R01 | P2：单一真实链接目标内跨 TU 与有限函数指针 | 待办／未启动 |
| S02-R07 | P3：非并发 refcount、池扩展及后续句柄 | 待办／未启动 |
| S06-R01、S02-R08 | P4：锁模式、有限 C++ RAII | 待办／未启动 |
| S06-R02 | P5：有界异步清理协议 | 待办／未启动 |
| S07-R01 | P5：新增访问者/回调/否定性依赖与完整增量对照 | 待办／未启动 |

首批只建议 P0/P1 的单构建、同 TU、直接调用子集，估算 10–19 有效人日，条件和任务验收 `RAPI01–RAPI10` 见 22。S01 身份、S02 条件契约/单槽池、S03 具体路径，以及本文件上条 S04 业务回答写回/依赖重验均作为已有切片复用；不重复登记为未实现。跨 TU 必须补足 S01 真实链接证据，异步归 S06，完整依赖失效归 S07；不另建裁决或反馈链，不改变正在推进的 S04 工作。两个对象协议实验规则继续 default-disabled。

本次仅编辑计划文档，未修改产品代码/配置、未 commit/push、未生成或执行缺陷注入评测集，也未派发外部 Agent。验证范围限文档增量、编号/链接与 UTF-8/无 BOM/LF；不是产品测试成绩。此前 WSL 命令返回 `Wsl/E_ACCESSDENIED`，失败后记录时间 `2026-10-13T02:34:29.0787732Z`；本次没有重试或绕过，因此 `tests/test_agent_docs.py`、compileall/mypy 及 native/扫描验证均未运行。前述各开发节点的历史测试记录保持原样，不挪作本次结果。

## 2026-10-13 · 首批资源接口实施接续与 S04 验收

用户已在规划登记之后明确授权先验收当前 S04，再实施 S02-R01–R06；22、11 中“仅规划／未启动”指登记时状态，当前进度以本节及后续记录为准。跨 TU、refcount、锁/RAII、异步及完整增量专项仍待办，实验规则不改变默认开关。

开始时保存六份计划原文及独立评估文件摘要到 WSL `/tmp/zscope-rapi-start-20261013`。本轮检查计划的 82 个本地链接（含锚点）、12 个唯一专项任务和 10 个验收 ID：通过；UTF-8/无 BOM/LF 通过。任务明细表再次引用相同任务是预期关联，首次检查脚本曾将其误判为重复定义，已限于编号登记表核对。原评估不修改。没有此前编辑前副本，不能补造“之前原文未删改”的证明；本轮可核对保存副本之后的增量。

当前 WSL 正常可用，未提权或更换入口。S04 当前业务前提/重放切片的核验、反馈、前端实际脚本、needs_review、ValidationPipeline/Runner、扫描恢复及交接文档回归 **175 passed，0 failed，0 skipped**。据此完成当前 S04 切片的接续验收，不把任意规范解析或所有规则四态等整包工作关闭。首批专项复用这一接口及原有静态包装器、工作簿发布屏障和 Registry；不重建反馈页、对象库或裁决链。

## 2026-10-13 · S02-R01–R06 首批受限实现与验收

本节接续上条实施记录：当前 S04 切片验收后完成首批专项，范围为**单 BuildContext、同 TU 的 C 堆资源直接包装器及覆盖诊断**。下面的完成状态不扩张到所有 C/C++ 资源协议。后续跨 TU、refcount、锁/RAII、异步和完整增量专项仍待办；没有更改 `retained_slot_release` / `object_protocol_path` 的 experimental/default-disabled 状态，没有新增 public YAML、第二套对象库、调度器或裁决链。

| 任务 | 本批状态与实际交付 | 验收边界 |
|---|---|---|
| S02-R01 | 完成。重新核对六份新增计划、现有 S04 业务回答 revision/重验链及生产调用方，先运行当前 S04 的 175 项回归 | 复用现有反馈页和专门 proof；不是 S04 整包关闭 |
| S02-R02 | 完成。`resource_coverage.py` 使用有效发布 Registry，接口区分 not_seen/proposed/schema_only/source_verified/manual_assumption/unsupported/stale/conflict；记录构建、USR、来源、核验器、拒绝原因、消费者限制及调用条件 | 复用 `.semantic-modeling/publication.json`、GlobalModelStats 和报告 metadata；未知调用有可取得的 token 站点，缺位置显式标记。分母是已调度图，入口外 cleanup 为 not_measured；consumer capability 不冒充实际执行，实际启用/执行仍查已有 rule catalog/engine coverage |
| S02-R03 | 完成。`native_wrappers.py` 消费既有 program-events.v5 / lifecycle-value-facts.v1，核对函数/参数/局部 USR、站点、源码与 CFG guard、构建及文件身份 | 受限 CFG 行走；循环、深度/事件预算耗尽、复杂转换、跨帧、宏/值事实不闭合为 unsupported。本轮没有改 native C++ 或补造新收据，复用已有真实工具 |
| S02-R04 | 完成。直接可信根、局部别名、两层调用及参数换位、return/out-param/字段、显式成功码、失败清理与条件 input release | 混合借用返回、已释放后返回、外部保存、额外资源、未知调用/函数指针和未检查状态不授权；native 失败不回退 token 强授权。fresh_no_alias 与漏洞 proof_authority 均为 false，清理根及人工假设也进入依赖 |
| S02-R05 | 完成。沿 compile_snapshot → 工作簿 → Registry 的原屏障发布；实测 Regex/Clang/Graph/SecurityMap 的输出对象为指针而非状态码，复用 KnowledgeDB、候选/Validator 的原有守卫、协议与权威性回归 | 已知契约不等于所有消费者支持。非 return pattern 的 out/字段保留语义事件及消费限制；transition、锁模式和最终义务仍需专门消费者/provider。schema-only 和错误池不授予解除义务权限 |
| S02-R06 | 完成。扩展现有构建/增量测试，新增实际 native 包装器和覆盖诊断测试；更新 AGENTS、用户说明、配置/编排/分析模块及计划索引 | 本轮直接相关 Linux 验证通过；未形成正式准确率、召回、运行性能或发行结论 |

RAPI01–RAPI05 的本批观察结果：

- **RAPI01 pass**：未知调用、模型无结果、schema-only、人工假设、失效身份及项目同名标准接口分别可见；真实 native 的项目 `malloc` 实现不能继承标准库效果。缺函数收据不授权，未调度 cleanup 不视为已扫描或安全。
- **RAPI02 pass**：真实 C fixture 覆盖 `NULL`、状态码输出、`p/&p/*pp`、字段、别名重赋值、参数换位和两层包装；工作簿重载保持载体与条件。未检查 `posix_memalign` 状态不能把未定义输出当获取成功。
- **RAPI03 pass**：错误分支释放不污染成功返回；成功出口已经释放、混合借用、全局/额外字段保存、两个内部资源、未知副作用及间接调用保持 unsupported。LLM 高置信度或“logging 无害”声明不能解除 native 拒绝。
- **RAPI04 pass（受限消费范围）**：共享消费者观察同一个输出指针和未知/已满足条件；复用错误池、schema-only、构建隔离、协议重放和规则 disabled/backend signal 回归。KnowledgeDB 和 SecurityMap 只传递契约/上下文，不能作为生命周期安全证明。未支持载体/模式/转换在覆盖诊断中显示。
- **RAPI05 pass**：实际 native → GlobalModeler 冷建模只核验一次，同输入热命中不再调用包装器核验器；源码/guard、头文件及编译参数变化使缓存失效并绑定新 BuildContext。根契约降为 schema-only 不能继续派生可信外层契约；既有 incremental/contract-chain 测试覆盖根变化传播。契约编译器升级为 v21，使旧自动证明失效。

实际运行环境为 WSL Ubuntu 的 `<venv>/bin/python`。native 测试显式设置 `Z_SCOPE_TEST_CLANG_INDEXER=$HOME/.cache/zscope-build-context/install/bin/zscope-clang-indexer`；工具报告 Clang **18.1.3**、clang-facts.v2，二进制 SHA-256 为 `88a1df53454d29732cdbe297a18959b4f25dfd7a648f9b3e5a2e2cc0321951e9`。这是已有本地开发工具，不是锁定 Clang 18.1.0 的 portable 发布验收。新 native 用例实际编译提取 C 函数，没有把合成事实当提取结果；模型缓存测试中的 RecordingAgent 是受控响应，不是真实 LLM。

| 验证集合 | 实际结果 | 说明 |
|---|---|---|
| 当前 S04 接续验收 | 175 pass / 0 fail / 0 skip | protocol assessment/feedback/UI、needs_review、validation pipeline/runner、scan resume、agent docs |
| 首批资源、包装器、构建、池/留存、路径、协议与规则治理 | 447 pass / 0 fail / 0 skip | native wrapper/coverage/cache、incremental modeling、wrapper compiler/error/failure/cast、carrier/chain/build/symbol/conditional contracts、pool/retention/lifecycle、protocol、pair/security map、catalog/runtime/extensions、candidate identity、source lifecycle、agent docs |
| 发布、工作簿、报告及验证消费者 | 263 pass / 0 fail / 0 skip | 最新 coverage、global modeler/coordinator、KnowledgeDB、workbook/readme、report assembler/schema、protocol UI、needs_review、validation pipeline/runner、scan resume、agent docs |
| `python -m mypy zscope` | pass，321 个源文件 | 无错误 |
| `python -m compileall -f -q zscope scripts test tests` | pass，exit 0 | Linux 执行 |
| 最终 `tests/test_agent_docs.py` | 6 pass / 0 fail / 0 skip | 文档更新后重新运行 |

各回归集合有交叉，不相加为独立用例总数。开发中 native 正反例曾暴露 NULL、未初始化声明和状态组合适配缺口，已修复；扩大回归曾有 **436 pass / 6 fail**，六项均为旧构建隔离 fixture 只有构建 ID、缺 native 函数收据。保留生产侧拒绝缺收据的行为，将隔离测试补为明确标注的合成 frame；缺收据反例与真实 native 用例分开保留，最终集合 447 全通过。未运行真实 LLM、正式 benchmark、portable smoke 或完整 Sanitizer 矩阵，均为 **未运行/skip（非 pytest 跳过）**；没有将其写为通过。

最终文档检查覆盖 **86 个本地链接（含锚点）、12 个唯一专项任务、10 个 RAPI ID**，UTF-8/无 BOM/LF、文件末尾换行及本轮相关 `git diff --check` 通过。独立 `ASSESSMENT.md` / `EVIDENCE.json` 的 SHA-256 与开工副本一致，21 的原历史正文保持完整前缀；其余五份计划仅调整授权/状态及先前验证限制，详细 diff 保存在 WSL `/tmp/zscope-rapi-start-20261013/*.diff`。本地机器记录在 `/tmp/zscope-rapi-acceptance-20261013.json`。原登记时受阻的最终检查不能追认通过，本轮重新核对不证明本轮之前不存在原文删改。保留工作树其他并行修改，未 commit/push。

剩余边界：当前适配只组合 malloc 家族直接根，字段输出可发布但字段根的进一步任意组合尚未支持；没有 fresh/no-alias 推导、一般 C++/RAII、realloc 或自定义池/锁/refcount 的新模型。CFG 支持刻意受限，复杂算术/转换、路径预算超限及副作用不明均保留 unknown。覆盖诊断尚不测量入口外 cleanup，也不提供逐接口的全项目实际消费者覆盖率；消费者是否运行仍依赖原报告。后续按用户限定保留 S03-R01、S02-R07/R08、S06-R01/R02、S07-R01 待办，不在本批扩张。

## 2026-10-13 · S03-R01 已观察链接目标与受限跨 TU 验收

用户在首批验收后明确授权继续 S03-R01。本轮先核对实际调用方：BuildContext 已有每 TU 身份与 `link_target` 占位，编译数据库、导航调用图及 LLVM 分组均不能证明对象属于同一真实链接目标；此前也没有生产者提供这种证明。沿用现有 CodeIndex/实例库、契约 Registry、LifecyclePaths 和 S04 重放，只补充真实链接记录与受限消费，不创建第二套分析图或裁决链。开工副本保存于 WSL `/tmp/zscope-s03r01-start-20261013`，保留工作树并行修改。

| 节点 | 实际交付及验证范围 | 状态 |
|---|---|---|
| S01 链接前置 | 显式 `python -m zscope.cli.link_record` 从编译数据库精确选择对象命令，实际重编译并链接，记录源码/头文件、命令、工具、对象、ELF 符号及最终产物摘要；失败重建撤销旧收据。普通扫描只读 `.zscope-link-targets/`，不启动构建进程 | 受限 Linux C 直接对象链接通过 |
| S03-R01 直接跨 TU | 按共同真实链接目标、各 TU 的 BuildContextID 和 C USR 解析唯一强符号定义；核对 Clang 版本、编译配置、目标 ABI、函数签名及参数/返回涉及的 record 布局。调用帧、契约、ObjectRef、路径边和依赖分别保留所属构建身份 | 已有单槽池/留存具体路径通过 |
| S03-R01 有限间接调用 | native 在原 AST 提取中为内部链接、不可变的小型函数数组/struct ops 提供封闭初始化收据，最多 8 个目标；路径只消费可确定的实际选择。可变表、未知选择、递归/预算不闭合保留缺口 | 受限 const ops 正反例通过 |
| S04 消费与失效 | 复用当前协议重放和业务前提反馈；路径 v3 绑定链接目标及实际成员事实，输出/对象/源码/目标集合变化拒绝旧路径，业务假设不因跨 TU 而变成已确认规范 | 当前条件性裁决回归通过 |

RAPI06 在上述切片内 **pass**：真实 TU-A 获取、TU-B 失败清理与遗漏清理可追溯；成功留存、cancel→complete、实际归还及未释放分支保留对象身份。两 executable 共用调用者、同名 static、宏变体、缺失实例、变更头文件/对象/输出不能串线。const 表中的释放与不释放目标分别按具体选择解释；选择未知时不把部分目标的释放效果推广到全体。重写表后实际重新链接会改变目标身份并撤销旧消费者。新增 `#pragma pack` 反例验证同名参数类型和相同签名仍须匹配真实布局；位域、布局预算耗尽或不完整类型不授予闭合证据。const 初始化即使经编译器诊断降级接受，也必须核对精确函数指针类型；不兼容的隐式转换不生成封闭目标收据。损坏或类型错误的链接 JSON 只产生覆盖缺口，不中断整个扫描。

native 新增 `zscope.c-linkage.v1` 与 `zscope.const-call-targets.v1` 附加收据，保留原 program-events.v5 等协议。最终源码在 WSL 使用 Clang SDK **18.1.3** 真实重编译、安装并重跑回归；工具为 `$HOME/.cache/zscope-build-context/install/bin/zscope-clang-indexer`，SHA-256 为 `e7e97e5c3cadfdfb083e358586df53b4ab5ed087b236a11b27b20e72b19b7624`。这是本地开发工具，不能冒充 portable 锁定 SDK 18.1.0 的发布产物。新增脚本入口为 `zscope-link-record`；本轮实际验收模块命令，包括含空格路径，安装后才有新控制台入口。

| 验证集合 | 最终实际结果 | 说明 |
|---|---|---|
| 最终 native 构建后的跨 TU、协议、构建、包装器及验证消费者 | **373 pass / 0 fail / 0 skip** | link targets/linked lifecycle、lifecycle、protocol assessment/feedback/UI、build context/compilation symbols、catalog/runtime governance、native wrappers/cache/anonymous types、Clang batch、incremental modeling、contract scope、coverage、validation pipeline/runner、scan resume |
| 链接及发布代码/配置/交接兼容回归 | **111 pass / 0 fail / 0 skip** | link targets/linked lifecycle、build context、agent docs、portable release/runtime 单元测试、public config v2；最后的布局及函数指针类型补充由上面的 373 项覆盖 |
| 链接记录健壮性补充与文档 | **46 pass / 0 fail / 0 skip** | 无效 JSON 保留诊断；link targets/linked lifecycle、build context、agent docs；在最后的函数指针类型补充之前运行，不冒充该反例验收 |
| `python -m mypy zscope` | **pass，323 个源文件** | Linux 虚拟环境 |
| `python -m compileall -f -q zscope scripts test tests` | **pass，exit 0** | Linux 虚拟环境 |

本节收尾另运行 `tests/test_agent_docs.py`：**6 pass / 0 fail / 0 skip**；四个本轮新 Python 文件的 Black 检查通过。

测试均使用 WSL `<venv>/bin/python`，native 用例显式设置 `Z_SCOPE_TEST_CLANG_INDEXER` 并执行真实编译、链接和事实提取。各集合有交集，不累计为独立用例总数。开发中首轮 **11 pass / 51 fail** 暴露缺少 native 被调函数签名收据，补齐真实提取并重建；随后 **64 pass / 1 fail** 为旧缺口原因断言，更新为精确的链接目标缺失原因。扩展反例的 **8 pass / 2 fail** 分别是缺失编译命令导致严格索引提前拒绝、fixture 使用未支持算术；改为真实索引后移除成员实例，以及可解释的局部变量路径，未放宽生产守卫。最终各集合失败已归零。此前 85、139、232 项阶段回归不另外累计。

能力边界：仅 Linux ELF、C 直接对象组成的一个可核验 executable；成员编译器须与 native SDK 的 Clang 版本匹配，并有兼容目录/参数、ABI 和依赖。GCC 可记录构建，但尚不能为此 native 跨 TU 消费授权。静态/共享库、复杂链接脚本、LTO、weak/common/ifunc、动态可变目标、任意函数指针、跨目标及完整变体调度仍未支持；不能把 BuildContext 中任意 `link_target` 字典视作授权。路径只扩展已有单槽池/引用留存解释，不包含一般堆资源路径求解、跨 TU 自动包装器契约推导、refcount、锁/RAII 或异步调度。扫描覆盖报告区分已观察目标及无收据/不兼容成员，不声称已扫描全部变体或入口外清理。路径输入核验仅在一次解析内复用摘要，重放时重新核验。

规则 `zscope.c_cpp.cpp_clang_cfg.object_protocol_path` revision **4**，仍为 **experimental / default-disabled**；显式禁用优先，新测试分别验证默认、显式开启和禁用。`retained_slot_release` 默认开关不变。AGENTS、README、架构、后端/分析/编排模块及计划索引同步；无新增 public YAML、web 访问或夜间交互。未运行真实 LLM、正式准确率/性能 benchmark、完整 Sanitizer 执行矩阵及 portable 实物 smoke，均为 **未运行/skip（非 pytest 跳过）**，不是通过或安全结论。S02-R07/R08、S06-R01/R02、S07-R01 仍保留待办。

本轮文档检查通过：计划内 **86 个本地链接（含锚点）、12 个唯一专项任务和 10 个 RAPI ID**，另检查新增模块/README 链接。编号按登记表核对，后文详细任务表的重复引用不算重复定义。修改的 Markdown 保持 UTF-8/无 BOM/LF 及末尾换行；新增行及本轮相关 diff 检查通过，原文既有 Markdown 换行空格不重写。21 的原历史正文保持完整前缀，独立评估两文件摘要未变；详细增量及机器记录保存于 WSL `/tmp/zscope-s03r01-acceptance-20261013/`。未 commit/push。

## 2026-10-13 · S02-R07 非并发引用计数与单槽池归还状态

用户授权从非并发引用计数和已有池的小扩展开始。本轮先核对并复用 ApiContract 发布屏障、工作簿/Registry、池 ObjectRef 与获取代次、S03-R01 的真实链接和 const ops、S04 当前重放及业务前提反馈；没有另建模型库、路径图或裁决入口。开工副本保存于 WSL `/tmp/zscope-s02r07-start-20261013/`，保留原工作树修改。**S02-R07 首个子域已验收，整项仍有待办；RAPI07 仅下表范围通过。**

| 节点 | 实际交付与观察结果 | 状态 |
|---|---|---|
| 源码契约与池扩展 | 新增受限 C 非原子 signed 32-bit 字段计数核验：init=1、带非正值/上界失败保护的 retain、带非正值失败保护的 drop，以及可选的归零 callback；既有单槽池增加成功 1/失败 0 的归还状态 | 已验收 |
| 对象路径与专门义务 | 2→1 保持对象存活；1→0 实际执行 callback，只有匹配对象的真实池归还才记录 logical_pool_return。多个别名、借用、失败 retain、饱和/下溢保护、错池、旧代指针及同地址再次获取分别核对 | 已验收 |
| 发布、跨 TU 与 S04 | 工作簿重载保持 standard_operation，不把 drop 放入 deallocator 或 allocator 配对；复用已观察链接及 const ops 路径，保留各 TU 身份。非并发执行与业务释放约定分别验收，撤回声明重开缺口；头文件变化拒绝旧路径 | 已验收 |

引用计数契约仅描述当前源码效果，`terminal_effect` 保持 unresolved，实际释放证据由当前路径提供；不以函数名、计数归零或调用 callback 推断物理 free。新增观察包括正计数提前归还、归零未归还、归还后计数操作和旧代指针修改新代计数，仍需相应业务约定。纯借用不增加计数或清理责任。带状态的池归还按真实成员/live 条件与返回值交叉核对，失败分支不能冒充释放。

native 在已有值元数据中补充字段写入的位宽/符号/限定信息和位域标记，源码核验拒绝缺失事实、atomic/volatile、unsigned、位域、union、其他位宽、宏改写、额外副作用和属性不明等形态。路径增减按当前 native 类型的整数边界执行；计数或业务 generation 发生溢出时保留技术缺口，不使用 Python 无界整数模拟 C 回绕，也不使用溢出前的部分路径签发结论。现阶段不实现 unsigned 回绕语义。

实际在 WSL 重编译并安装 native 开发工具，Clang SDK 为 **18.1.3**，二进制 `$HOME/.cache/zscope-build-context/install/bin/zscope-clang-indexer` 的 SHA-256 为 `b9b4d3d8297a8e487538cd6f5dcdc925c809b714925c8d1c9faf765140901cd6`。这不是 portable 锁定 SDK 18.1.0 的发布产物。契约编译器 **v22**、对象路径 **v4**、协议核验 **v3** 撤销旧语义收据的复用；`object_protocol_path` 规则 revision **5** 增加 CWE-911，仍为 **experimental / default-disabled**，显式 disabled 优先。`retained_slot_release` 默认开关不变。

| 验证集合 | 最终实际结果 | 说明 |
|---|---|---|
| 开工既有池/路径/S04/链接回归 | **137 pass / 0 fail / 0 skip** | 用于接续与复用核对，不作为新增能力成绩 |
| 节点一：源码契约、池与 schema | **62 pass / 0 fail / 0 skip** | 真实 native 正反例与发布角色 |
| 节点二：具体路径、S04 与规则治理 | **123 pass / 0 fail / 0 skip** | 含 const ops、别名/代次及整数边界 |
| 节点三：发布、反馈、跨 TU 与拒绝形态 | **66 pass / 0 fail / 0 skip** | 工作簿独立读回、真实编译链接、业务撤回和覆盖诊断 |
| 最终跨模块回归 | **638 pass / 0 fail / 0 skip** | refcount/pool/retention/lifecycle/link、协议反馈/UI、目录/资格/禁用、native/cache/Clang、契约与工作簿、Validator/resume、构建和交接文档 |
| `python -m mypy zscope` | **pass，324 个源文件** | Linux 虚拟环境 |
| `python -m compileall -f -q zscope scripts test tests` | **pass，exit 0** | Linux 虚拟环境 |

各测试集合有交集，不累加为独立用例总数。所有质量命令使用 WSL `<venv>/bin/python`；native 用例显式设置真实工具路径。最终 pytest JUnit 为 `/tmp/zscope-s02r07-final-20261013.xml`。开发中节点一曾 **56 pass / 5 fail**：四项暴露 native 字段写入缺少整数类型事实，补齐真实提取并重建；另一个发布 fixture 改用当前函数行号。节点二曾 **120 pass / 1 fail**，溢出 fixture 原用了尚未支持的嵌套字段赋值，改为已有指针字段路径，不放宽生产守卫。节点三曾 **25 pass / 1 fail**，发现撤销非并发声明后缺口清单丢失新义务，已修复并保留撤回反例。最终失败均归零。

能力边界：源码核验只接受明确列出的有界 C 语句形态，计数为单个 signed 32-bit 成员；具体对象消费只覆盖已有内嵌单槽池，callback 须由当前同 TU 或受支持真实链接路径解释。没有通用堆析构证明、任意引用计数形态、原子/并发/重入计数证明、任意 C++、句柄 close/dup/同值重开或 arena/reset。序列化路径本身不证明线程安全，非并发前提仍需验收；未知调用、输入、算术、递归或预算超限保留技术缺口。剩余 S02-R07 子域、S06-R01、S02-R08、S06-R02 和 S07-R01 保留待办。

AGENTS、README、架构、配置/分析/后端模块及计划索引同步；Modeler schema/prompt 仅补充新的协议提案和证据约束。复用已有验收界面和状态库，无新增 public YAML 或夜间问答。未运行真实 LLM、正式准确率/性能 benchmark、完整 Sanitizer 执行矩阵和 portable 实物 smoke，均为 **未运行/skip（非 pytest 跳过）**，不能记为通过或准确率/性能结论。

最终交接文档回归另有 **6 pass / 0 fail / 0 skip**。计划内 **86 个本地链接（含锚点）、12 个唯一专项任务、10 个 RAPI ID** 校验通过；修改 Markdown 的 UTF-8/无 BOM/LF/末尾换行、本轮新增行空白及相关 diff 检查通过。以开工保存的 397 个文件逐项比较，本轮修改 24 个已有文件并新增 3 个文件，21 历史正文保持完整字节前缀，独立评估两文件摘要未变。详细增量、native 摘要、JUnit 和机器记录保存于 WSL `/tmp/zscope-s02r07-acceptance-20261013/`。未 commit/push。

## 2026-10-13 · S02-R07 有界整数句柄、dup 与同值重开

用户授权继续句柄子域。本轮先核对现有标准 open/close/dup 角色、ApiContract、具体 CFG 路径、ObjectRef、真实链接和 S04 反馈，发现整数尚无描述符代次与共享底层对象的路径表示；沿原链补充，未新增规则 ID、配置入口或裁决库。开工保存 399 个相关文件至 WSL `/tmp/zscope-handles-start-20261013/`，保留其他工作树修改。**已交付受限自定义句柄表；不代表 S02-R07 通用句柄或平台语义全部完成。**

| 节点 | 实际交付 | RAPI07 范围 |
|---|---|---|
| 源码核验与发布 | `bounded_handle_table` 校验 2–4 个固定非负 signed 32-bit 句柄值、独立 live/object 字段、open 序号保护、close 明确失败参数和 dup 复制实际底层标识；发布为 standard_operation，沿工作簿/Registry 重载 | close 消费前失败与消费后报错分别保留，不加入普通 allocator/deallocator 配对 |
| 具体对象与代次 | `HandleValue` 保存数值、命名空间及获取时的描述符 ObjectRef；dup 新建描述符并共享底层对象，普通赋值只复制原代次；同值 open/dup 重新获取产生新代次 | handle=0、失败 dup/open、旧别名、错误命名空间和非连续数值分别核对；旧句柄实际关闭新代次时记录两者身份 |
| 消费与验收 | 复用 S03-R01 跨 TU/const ops 和 S04 当前重放；句柄观察独立要求命名空间顺序独占，仍存活句柄另需清理责任及责任终点；撤回任何前提均重开缺口 | 工作簿重载、真实编译链接、头文件失效、默认关闭/显式开启/disabled 优先通过 |

两个 dup 描述符有各自关闭义务，关闭一个不消费另一个；底层对象列出仍存活的描述符，最后一个关闭仍标记物理析构 unproven。每次 API 前后均核对当前表和已观察对象图，未知非负整数、表字段的未跟踪修改、序号重用、转换或缺 native 事实都保留缺口；不从整数相等、返回失败或业务声明补造技术事实。标准 API 目录既有 close 行已声明错误效果依赖平台，本轮将其通用失败 no_effect 改为 **unknown**，保留成功效果；没有据此宣称已支持 OS close/errno 或 dup2。

新增反例暴露表本身的寿命缺口：返回局部表地址后旧解释器仍会读存留的分析内存。现由 native 的 `function_scope_local` 确认 VarDecl 直接属于函数体，具体路径再要求已零初始化且所属调用帧仍活跃。过期函数表、内层块表，以及内部函数退出时从其局部表导出活句柄都保留 `handle_namespace_lifetime_unclosed`；未知技术寿命不能用顺序独占声明代替。当前支持函数作用域局部表传给被调函数；堆、全局、成员/数组表和任意块作用域寿命仍未支持。

native 同时补齐调用结果目标与局部写入的类型事实，未再读取的变量也能核对载体位宽；不是由返回类型猜测变量类型。最终实际在 WSL 重编译、安装的工具为 `$HOME/.cache/zscope-build-context/install/bin/zscope-clang-indexer`，SDK **Clang 18.1.3**，SHA-256 为 `2366e041e48b2ced67ffdb4fe6cc384131e2af372d3706d28f3d626d3f173e55`。这不是 portable 锁定 SDK 18.1.0 的发行验收。契约编译器 **v23**、标准 API **v4**、对象路径 **v5**、协议核验 **v4** 使旧相关语义收据失效；`object_protocol_path` revision **6** 继续 **experimental / default-disabled**，其他实验规则默认值不变。

| 验证集合 | 实际结果 | 说明 |
|---|---|---|
| 开工已有计数/池、路径、协议反馈和跨 TU | **129 pass / 0 fail / 0 skip** | 复用接续基线 |
| 节点一源码核验 | **13 pass / 0 fail / 0 skip** | native 与发布；不冒充完整节点二/三 |
| 节点二及既有资源/规则回归 | **141 pass / 0 fail / 0 skip** | 重建类型事实后的句柄路径、引用计数、池、目录和 schema |
| 节点三发布/反馈/覆盖 | **66 pass / 0 fail / 0 skip** | 在表寿命追加之前执行 |
| 最终表寿命与句柄专项 | **64 pass / 0 fail / 0 skip** | 含实际 native 拒绝形态、3–4 槽非连续值、工作簿、跨 TU、回答撤销和三个表寿命反例 |
| 最终跨模块回归 | **777 pass / 0 fail / 0 skip** | 最终 native 与全部修改；句柄/计数/池、真实链接、契约/发布/消费、反馈/UI、规则治理、native 缓存、Validator、扫描恢复与交接文档 |
| `python -m mypy zscope` | **pass，326 个源文件** | 最终 Linux 虚拟环境检查 |
| `python -m compileall -f -q zscope scripts test tests` | **pass，exit 0** | 最终 Linux 虚拟环境检查 |

各集合有交集，不累计为独立用例总数。全部产品质量命令在 WSL `<venv>/bin/python` 执行；native 测试显式指定真实工具。表寿命修正前的一次跨模块回归为 **774 pass / 0 fail / 0 skip**，保存在 `/tmp/zscope-handles-pre-lifetime-20261013.xml`，不能代替最终版本验收。开发中首轮 13 errors 来自 fixture 重复定义，随后修复；路径首轮 **36 pass / 6 fail** 暴露未读取结果变量缺类型，修复 native 并真实重建。扩展 **59 pass / 2 fail** 来自 fixture 同一行混合函数正文，分行后通过而不放宽生产守卫；另一个真实过期表反例曾 **1 fail**，完成上述寿命修正后专项失败归零。mypy 中两处 Value 联合类型适配也已修正。

边界与后续：仅有明确源码形态的 C 自定义表、已知具体输入和当前可核验的直接/有限 const ops 路径；没有 OS fd 行为重放、dup2/dup3 的目标替换、errno/平台变体、动态/数组/堆/全局句柄表、并发关闭/重开、外部进程干预、通用 C++ 或物理析构证明。S02-R07 的通用/平台子域及其他原待办保持开放。AGENTS、README、架构、模块及计划索引同步，提案 schema/prompt 只增加该协议证据合同。未运行真实 LLM、正式准确率/性能 benchmark、完整 Sanitizer 矩阵或 portable 实物 smoke，均为 **未运行/skip（非 pytest 跳过）**；无新增 public YAML、web 访问或夜间交互。

收尾交接文档另有 **6 pass / 0 fail / 0 skip**；四个新 Python 文件的 Black 检查通过。计划内 **86 个本地链接（含锚点）、12 个唯一任务 ID、10 个 RAPI ID** 校验通过；修改的 Markdown 保持 UTF-8/无 BOM/LF/末尾换行，新增行空白与本轮相关 diff 检查通过。对开工 399 文件逐项核对，本轮仅修改 25 个已有文件并新增 4 文件；21 的历史正文保持完整字节前缀，独立评估两文件摘要未变。最终 JUnit 为 `/tmp/zscope-handles-final-20261013.xml`，详细增量、工具/源码摘要和机器检查记录位于 WSL `/tmp/zscope-handles-acceptance-20261013/`。未 commit/push。

## 2026-10-13 · S06-R01 锁模式与当前静态锁覆盖

用户授权继续后续推进。本轮按 P4 顺序接续 S06-R01，先复用标准返回条件、透明包装器、工作簿/Registry、共享访问候选和 ReviewClaimChecker，再补模式及实例消费；**交付受限锁模式切片，不关闭完整 S06 或 RAPI08 的 RAII/通用锁协议范围。** 开工保存 403 个相关文件，另在修改前保存共享测试 fixture，合计 404 文件基线位于 WSL `/tmp/zscope-locks-start-20261013/`；保留原工作树修改。

| 节点 | 实际交付 | RAPI08 边界 |
|---|---|---|
| 契约与发布 | 标准 API、透明包装链、工作簿重载、转换动作及 CallSemanticMatch 保留 shared/exclusive/unknown、成功条件、载体和构建身份；缺模式或未核验效果保持 unknown | try 失败不持锁；EOWNERDEAD 获取与 cond_wait 的释放/重获分开，部分恢复分支不能从继承转换重新取得权限 |
| 候选与旧消费者 | Regex/Clang 共享访问过滤仅接受确定 exclusive；未知解锁、锁状态中断和等待清空旧前缀。旧的无条件 pthread 文本前缀改走契约条件；调用方词法摘要只保留调查上下文 | 读锁不能遮蔽写入；仅记录的调用者/首个文本调用点不能冒充全部调用和真实实例证明 |
| 当前编译验证 | 复用 CompleteFactStore 的 AST/CFG、依赖摘要和签名收据，核对非逃逸 TU-static 锁、静态标量、全部访问及所有引用相关锁的函数；一个指针参数的直接 return 包装链重新核对当前 AST | 同一真实声明、相容模式和明确成功分支才支持原 race 义务反证；指针本身的读取不能证明 pointee 写入受保护，也不能用 race 收据排除 UAF |

核验 coverage 保存访问节点、锁声明身份、模式、检查的状态值和共同锁集合；预算上限为 10000 步、128 分支状态、12 轮透明包装器。未知或失败分支不增加锁集合；递归第二次获取、升级/降级、cond_wait、任意 helper、成员/动态锁、复杂别名和 C++ 生命周期效果保留 unknown。EOWNERDEAD 的强证据要求当前预处理事实中的唯一系统头定义及对应依赖摘要，项目/命令行重定义不充当库 ABI；真实 POSIX 头文件正例和重定义反例均已执行。标准多参数 timed/clock 操作可以传播契约，但尚不进入本次单参数实例覆盖证明。

标准 API **v5**、契约编译器 **v24** 和 ReviewClaimChecker **v3** 更新相关语义/收据边界；两条既有共享访问规则 `unsynchronized_shared_flag_or_counter`、`clang_cfg_unsynchronized_shared_flag_or_counter` revision **9** 继续 **experimental / default-disabled**，无新规则 ID 或正式资格提升；两个对象协议实验规则的开关也未改变。没有新增 public YAML、Web 访问或夜间交互，未改运行时 Agent prompt。

| 验证集合 | 实际结果 | 说明 |
|---|---|---|
| 接续标准/包装器/旧消费者基线 | **69 pass / 0 fail / 0 skip** | WSL 开工对照 |
| 节点一模式与编译覆盖 | **108 pass / 0 fail / 0 skip** | 原静态锁消费者扩展、发布、当前包装器及模式正反例 |
| 指针/外部锁操作边界追加 | **69 pass / 0 fail / 0 skip** | 包含旧 review fact 及转换回归 |
| 系统 errno 来源与锁专项 | **31 pass / 0 fail / 0 skip** | 真实系统头、项目重定义、模式/实例/未知边界 |
| 补充消费者/文档集合 | **182 pass / 0 fail / 1 skip** | 本次补充命令未设置 native 工具变量，native 包装器项真实 skip；不能以此替代下面的最终 native 验收 |
| 跨模块回归（52 文件） | **1064 pass / 0 fail / 0 skip** | 显式设置真实批量工具；原计数/池/句柄/跨 TU、契约/发布/缓存、锁/候选快照/规则治理、Validator/反馈/UI、扫描恢复与交接文档 |
| 最终收尾模式/编译/发布/文档回归 | **98 pass / 0 fail / 0 skip** | 再补非法非字符串模式（列表/字典/整数）输入，统一保持 unknown，防止解析异常；包含真实 native 包装器。其后 mypy/compileall 再次通过 |
| `python -m mypy zscope` | **pass，327 个源文件** | 最终 Linux 源码检查 |
| `python -m compileall -f -q zscope scripts test tests` | **pass，exit 0** | Linux 虚拟环境 |
| 新增三个 Python 文件 Black 检查 | **pass** | 已有文件只格式化本轮变更范围 |

各集合有交集，不累加为独立用例总数。全部质量命令在 WSL `<venv>/bin/python` 执行。开发中一次节点集合为 **208 pass / 9 fail**：六项为新测试误用目录构造 API，三项暴露旧 provider 调用源码解析时遗漏函数身份，均修复；定向复验 **54 pass**。随后 **225 pass / 1 fail** 为 cond_wait 转换增加模式后旧精确快照断言未更新，已同步。首次大集合 **1059 pass / 1 fail** 的唯一失败是旧测试仍要求未检查 mutex 返回值授予文本强反证，已改为应保留未决，并在最终完整集合归零。旧结果单独保留，不覆盖成通过记录。

本轮未修改 native 提取代码，复用并实际执行已有批量工具，SHA-256 `2366e041e48b2ced67ffdb4fe6cc384131e2af372d3706d28f3d626d3f173e55`；批量 SDK 和本次 CompleteFactStore 使用的 WSL Clang 均为 **18.1.3**。没有冒充 portable 锁定 SDK 18.1.0 的发行验收。最终 JUnit 为 `/tmp/zscope-locks-final-20261013.xml`，逐轮 JUnit、增量 diff、工具/源码摘要及实际 pass/fail/skip 记录位于 `/tmp/zscope-locks-acceptance-20261013/`。

AGENTS、README、架构、配置/分析模块及计划索引同步。计划 **86 个本地链接（含锚点）、12 个唯一专项任务、10 个 RAPI ID** 校验通过；修改 Markdown 的 UTF-8/无 BOM/LF/末尾换行和本轮相关 diff 空白检查通过。21 历史正文保持完整字节前缀，独立评估两文件摘要未变；本轮修改 24 个已有文件、新增 3 个文件。未 commit/push。真实 LLM、正式准确率/性能 benchmark、完整 Sanitizer 矩阵和 portable 实物 smoke 均为 **未运行/skip（非 pytest 跳过）**，不形成准确率/性能或完整 CON 验收声明。

后续进入 **S02-R08 有限 RAII**。已核对 native 的 CFG 开启 `AddImplicitDtors/AddTemporaryDtors/AddEHEdges`，并已有 automatic/temporary `implicit_release` 事件；下一步复用这些事实核对析构函数身份、管理器→资源映射及实际分支，不重复建设，也不把事件标签直接当 free/unlock。通用锁协议、S02-R07 平台子域、S06-R02 和 S07-R01 保持待办。

## 2026-10-13 · S02-R08 单指针 scoped heap guard

保存 1282 个已有源码/测试/文档文件的字节基线，开工检查 86 个本地链接、12 个专项任务和 10 个 RAPI ID；未回退并行修改。复用 native 隐式析构、CompleteFactStore、LifecycleAnalysis、ReviewClaimChecker 和候选治理，不新增全局 deallocator 配对。

native `cxx-lifetime-facts.v1` 补充管理器、构造/析构 USR、定义位置和自动存储/完整对象属性。局部单指针 guard 的 noexcept 空体构造直接保存参数，析构直接 free 或经最多八层当前源码核验的单参数 noexcept deleter 清理。管理器保存获取对象身份，原指针后续改值不替换其责任；空 guard 不清理其他对象。支持正常/提前退出、嵌套作用域和函数内明确字面量 throw→catch(...)。Clang 异常 CFG 不总列出展开析构；后者依据受限结构化 AST 语义，不伪造 native CFG 清理边。

仅同 TU、唯一编译命令，核对精确 BuildContext、当前命令/依赖、构造/析构位置及同版本 Clang SDK。收据绑定构建、对象选择、工具/共享库和源码依赖；重核验先撤销旧收据。真实候选使用结构化 acquire 事件定位义务，不依赖英文描述。生命周期事实 v3、review checker v4；`clang_cfg_acquire_without_release_on_exit` revision 10 继续 experimental/default-disabled。未知异常、未捕获 throw、构造/析构异常、复制/move、adopt/defer/release/reset、逃逸、成员改写、模板/继承、new/delete 智能指针和锁 guard 仍留缺口。该反证只作用于泄漏义务，不证明 UAF/并发安全；原 C 协议路径与其他模式消费者尚未支持通用 C++。RES06/RAPI08 是本切片验收，不代表完整 C++ 或 CON 矩阵完成。

| 验证 | 实际结果 |
|---|---|
| 34 文件跨模块回归（真实 native，含原池/计数/句柄/链接路径/反馈/锁/规则） | **839 pass / 0 fail / 0 skip** |
| 结构化候选消费、RAII、review、覆盖、规则与交接文档收尾 | **154 pass / 0 fail / 0 skip** |
| Linux mypy / compileall | **pass（328 源文件）/ pass（exit 0）** |
| 本轮变更行及两个新增 Python 文件 Black | **pass** |

开发中保留真实失败记录：新测试 proof API 参数错误，catch(...) 空参数占位和 PointerToBoolean 处理遗漏；native 对尚无析构声明的普通结构体空目标解引用（107 pass / 1 fail）；真实候选未走目录 enrichment 的测试错误及中文对象选择未衔接。均修复并包含于上述收尾回归。一次命令测试文件名错误、exit 4、零用例，未计通过。集合有交集，不累加独立用例数。

批量工具实际重编译两次，最终 SHA-256 `7cd43795443358cd2d6501c296da4b48292644fc5fa9955d909ef98d50ae78c2`，开发 SDK 18.1.3，不冒充 portable SDK 18.1.0 验收。全部测试/质量命令使用 WSL `<venv>/bin/python`；JUnit `/tmp/zscope-raii-final-20261013.xml`、`/tmp/zscope-raii-closeout-20261013.xml`。未运行真实 LLM、正式准确率/性能 benchmark、完整 Sanitizer 或 portable 实物 smoke；这些不是通过。AGENTS、用户指南、架构、模块与计划索引同步，无新 public YAML、Web 能力、运行时 prompt 或默认实验开关变更。

本切片验收后继续 **S07-R01 当前协议增量证据与否定性依赖**。S04 回答 revision 失效、native 输入/链接清单和语义建模缓存直接复用。S06-R02 实际异步清理协议、复杂 RAII/锁 guard 和平台子域仍待办。

## 2026-10-13 · S07-R01 当前协议增量与否定性依赖

S02-R08 切片通过后继续依赖已满足的 S07-R01，阶段基线另存 774 个文件于 `/tmp/zscope-incremental-start-20261013/`。复用 S04 回答 revision、native 输入/链接清单、语义建模与 demand/cache-only 路径；不重建调度器或答案库。本阶段交付当前支持协议的失效修正和局部全量/增量对照，不关闭完整 RAPI10/INC01–INC05。

- CompleteFactStore **v4** 在冷收集前后和热载入时核对真实预处理输出，覆盖可选头文件出现/消失、较高优先级头文件及预处理条件；内容 depfile 不是“未找到文件”的完整依赖。磁盘事实必须当前收集后才可执行绑定的预处理命令，序列化字段不能恢复执行/证明资格。准备阶段发生查找变更返回未完成，不因缺 source 字段异常退出。
- ReviewClaimChecker **v5** 将 live Registry 版本纳入进程内签名收据；重放中和签发后契约变化均撤回授权。旧 lifecycle 缓存不能绕过当前 native 实例检查。新增 TU-static 访问者后重新检查全部访问，沿现有统一裁决链比较候选、报告桶、状态、未决义务与覆盖。
- 实际重编译 native，新增 **include-probes.v1**：存在性查询与真正读取的内容分开记录，查询结果和搜索根进入 BuildContext。发布、热复用和交互消费前重验；绝对路径、缓存目录中的查询也不能被目录排除规则漏掉。负向 include-next 搜索集合有歧义时保持不完整，header map/framework 不在支持范围。
- 标准 C++ 头文件追加验收促成 RAII 绑定修正：SDK 符号链接按解析后的实际路径和摘要匹配，接受当前类型事实中明确的 noexcept(true)/throw()。custom deleter 匹配实际声明 ID，不能借用其他命名空间同名函数的实现；标准 free/malloc 被当前项目定义遮蔽时不借用内置效果。两个同名指针的不同获取继续保留独立义务。

| 验证集合 | 实际结果 | 范围 |
|---|---|---|
| 否定性依赖基线复现 | **0 pass / 2 fail / 0 skip** | 先复现旧预处理查询未失效与全量/增量不同，保留原失败 |
| 增量/RAII/native 构建定向集合 | **63 pass / 0 fail / 0 skip** | 标准 C++ 头文件、存在性查询身份及热复用、受限统一裁决对照 |
| 44 文件跨模块回归 | **1036 pass / 0 fail / 0 skip** | 真实 native；池/计数/句柄/链接、锁/RAII、契约/发布/反馈、规则、索引参数和独立增量重放 |
| 准备阶段输入变化与 review/交接文档收尾 | **53 pass / 0 fail / 0 skip** | 包含收集后头文件变化；该小修正由收尾集合验证 |
| Linux mypy / compileall | **pass（328 源文件）/ pass（exit 0）** | 最终源码，未使用 Windows Python 形成结论 |

各集合有交集，不累加独立用例总数。增量测试走实际 ValidationPipeline，模型未启用；默认实验规则未改变。单个小 fixture 的热核验耗时 **0.152s**，预处理 **4** 次、AST/CFG **0** 次；独立冷核验 **0.220s**，预处理 **5** 次、AST/CFG **2** 次。仅证明本 fixture 的事实复用和等价性，不外推扫描性能、内存峰值、LLM 节省或召回。

开发中另有 **989 pass / 1 fail / 0 skip** 的跨模块结果，失败为新增 TU 刷新 fixture 的自有事实目录进入搜索清单，改用产品 `.zscope_review_facts` 目录并补 CDB 后定向通过。标准头文件用例先失败，定位到旧 native 的 __has_include 不完整、SDK 路径拼写差异和 noexcept(true) 未识别后修正。查询测试首轮 **1 pass / 2 fail**、次轮 **2 pass / 1 fail**；一项是测试扩展名被当作源码收集，改为存在性查询专用文件名；其余是上述标准头绑定缺口。最终集合包含真实工具与拒绝边界，没有把失败改记为 skip。

最终 native SHA-256 `f17b876f92c82508994475c6796d0513adb2c98ef2f69d2c7d8c6eff9cd97246`；WSL 开发 SDK/Clang **18.1.3**，不冒充 portable 锁定 SDK **18.1.0** 验收。JUnit 为 `/tmp/zscope-raii-incremental-final-20261013.xml` 和 `/tmp/zscope-incremental-prepare-closeout-20261013.xml`；逐轮 JUnit、实际热/冷测量、diff 与源码/工具摘要归档于 `/tmp/zscope-raii-incremental-acceptance-20261013/`。

未运行真实 LLM、正式准确率/性能 benchmark、完整 Sanitizer 或 portable 实物 smoke，均为未运行而非通过。S06-R02 实际异步调度/回调/drain、复杂 RAII/锁 guard、平台子域，以及完整扫描多变体等价性和 INC05 调度替换仍待办；旧 cancel/complete 顺序路径和同锁证明不能替代这些事实。没有新增 public YAML、Web 能力、扫描中途交互或重审批流程。

每阶段同步 AGENTS、用户指南、架构、模块和计划索引；最终 86 个本地链接/锚点、12 个唯一任务、10 个 RAPI ID 及状态索引核对通过。与开工 1282 文件逐项核对，本轮修改 24 个已有文件、新增 3 文件；21 的开工历史和 RAII 阶段历史均保持完整字节前缀，独立评估两文件摘要不变。Markdown 为 UTF-8 无 BOM、LF、末尾换行，本轮新增行空白与相关 diff 校验通过；只格式化改动行和新增 Python 文件。未 commit/push，保留既有并行修改。

## 2026-10-13 · S06-R02 单工作者 pthread 延迟回调见证

按依赖从 S03/S04、既有锁/RAII 和当前协议增量进入 S06-R02。开工保存 1295 个源码/测试/文档文件于 `/tmp/zscope-async-start-20261013/`；核对既有修改，复用 native 调用/参数身份、CFG、ObjectRef、契约发布、实验规则和 S04 验收反馈，不重建异步调度平台。本轮只验收单工作者见证切片，不关闭 S06、RAPI09 或整体实施计划。

- 标准 API **v6**、契约编译器 **v25** 分开 start_callback、wait_callback_completion、release_join_handle 和 request_cancellation；线程载体与 callback/context 经包装器映射及工作簿重载保留。成功条件或效果未核验时，不从继承转换恢复强效果。join/detach 的线程资源配对不等于上下文释放或 drain。
- 新解释器复用原具体路径引擎的调用钩子与事实检查。仅支持 Linux LP64、同 TU、直接系统声明、默认线程属性、一个工作者、malloc/calloc 堆上下文与受限成员访问。系统 API 被项目定义遮蔽、根契约变化或构建范围不匹配时不借用硬编码效果。回调、线程句柄、对象与获取身份分开；调用方指针重新分配不会替换已保存的旧上下文。
- `zscope.pthread-delayed-path.v1` 显式选择分配/创建成功，工作者已启动后延迟至调用方 join 等待期间执行。free 后的实际回调成员访问生成见证，并在首个非法访问停止；不伪造回调完成、join 成功或 UB 后的效果。成功 join 后释放、未实际访问上下文、释放其他对象和不可达释放分支均有反例。cancel 请求、detach 与完成分开；无 drain、取消点、任意 helper、循环、未知输入、动态目标或多工作者保留缺口。
- 复用 `object_protocol_path`（revision **7**，附加 CWE-416，主 CWE-664）、S04 assessment **v5** 和原答案库。Validator 重新读取当前入口/回调事实与 Registry 后才进入条件性验收；具体业务路径/外部协调前提未经确认不能被模型分数补齐，回答撤回重新打开义务。默认 experimental/default-disabled，不新增 public YAML、Web 能力、运行时 prompt 或扫描中途交互。

| 验证集合 | 实际结果 | 范围 |
|---|---|---|
| 开工路径/反馈/锁基线 | **101 pass / 0 fail / 0 skip** | WSL，真实 native |
| 首轮路径与原路径/锁 | **85 pass / 0 fail / 0 skip** | 同一具体调度的正反例与默认关闭 |
| 契约/包装器/发布/覆盖 | **71 pass / 0 fail / 0 skip** | callback/context、返回条件与根效果传播 |
| 31 文件跨模块回归 | **679 pass / 0 fail / 0 skip** | 原池/计数/句柄/链接、反馈/UI、锁/RAII、native/构建、规则与 Validator；最终作用域/缺失参数防御追加另在收尾集合验证 |
| Linux mypy（阶段检查） | **pass，329 个源文件** | 最终质量结果另记收尾 |

开发中首轮 **6 pass / 18 fail**，主要暴露解释器拒绝未初始化 pthread_t 声明与函数指针纯衰变；按真实 native 类型/事件补齐后通过，没有用合成事实替代 native。一次错误测试文件名导致零用例，未计通过。后续增量首轮 **54 pass / 2 fail**：一项测试误期望另一构建的手工覆盖可恢复 builtin（原 Registry 按设计保守屏蔽），另一项复用 fixture 的 shared.h 未被任何 TU 包含导致严格 batch 拒绝；修正测试保留原生产守卫。各测试集合有交集，不累加独立用例数；失败 JUnit 保留。

真实 native 工具未改动、未重编译，复用并执行 SDK 18.1.3 工具，SHA-256 `f17b876f92c82508994475c6796d0513adb2c98ef2f69d2c7d8c6eff9cd97246`。不是 portable SDK 18.1.0 的发行验收。全部质量命令使用 WSL `<venv>/bin/python`；阶段 JUnit `/tmp/zscope-async-stage1-20261013.xml`。本轮没有执行真实 pthread 程序、ASan/TSan、LLM 或正式准确率/性能 benchmark，不将静态 native 重放称为动态复现。

覆盖边界：`complete` 只表示所选路径或首个非法访问见证闭合，全部交错/失败分支/无观察安全证明三个标记均为 false。完整 queue/unregister/drain、锁保护下串行 UAF、多个工作者、并发引用计数、动态回调集合和跨 TU 异步均未完成。S07-R01 可继续消费本切片已有事实开展失效与独立冷/热对照，不重做原缓存/业务答案链。

## 2026-10-13 · S07-R01 直接 pthread 回调失效与冷/热对照

S06-R02 的受限见证可用后继续依赖满足的回调增量切片。复用现有 BuildContext、context_input_status、native 工具依赖摘要、Clang batch 缓存和统一 ValidationPipeline，不新增缓存库或需求调度器。

对照发现实际缺口：CodeIndex 可以返回尚未重建的旧 native 存储事实，异步消费者最初只检查实例 ID，没有检查当前磁盘输入；直接回调目标修改后仍可能重放旧见证。现已在解释前后核对源码/头文件、编译数据库、命令环境、搜索根/include probes 和真实工具/共享库摘要；缺失、失效或中途改变均保持缺口。进程内 assessment 收据还绑定 live Registry 版本与这些输入，签发后的源码/根契约变化立即撤回资格；JSON 不恢复收据。

`test_async_incremental.py` 使用两个真实 native TU，同一路径下单独冷数据库与批量缓存，逐阶段比较完整路径事实、候选身份、统一裁决/报告桶、未决和覆盖：首次无访问、增加回调成员访问、相同源码及已有说明文件内容变化、直接目标切换、移除访问、恢复访问、改变 free 根契约。新增/移除目标访问重新生成候选；旧见证在重新索引前已拒绝，根契约变化复用 native 事实但不复用效果。热轮实际 **compiled_tus=0 / reused_tus=2**，独立冷轮 **compiled_tus=2**，不将此指标外推为完整扫描性能。

最终当前输入/路径定向集合为 **32 pass / 0 fail / 0 skip**（`/tmp/zscope-async-current-inputs-20261013.xml`）；随后追加当前工具/平台与签发后源码/Registry 失效反例，纳入最终收尾集合。开发中另有 **31 pass / 1 fail**，原因是测试向头文件搜索目录新增文件仍期待零重编译；保留否定性查找的失效守卫，将“已有说明文件内容变化”与“文件新增”分开。后续两次单例失败复现上述旧 native 事实真实缺口，修正消费者后通过；不删掉失败记录冒充首次通过。

支持目标明确限制为 Linux **glibc LP64**，在 BuildContext 的 target triple、指针位宽和 libc 事实中核验，其他目标不按相同 API 名字推断 ABI。RAPI09 的完整 queue/unregister/drain、同锁串行 UAF、多工作者和跨 TU 异步，以及 RAPI10/INC 的动态回调集合、全扫描多变体和需求调度替换仍待办。本次切片验收不等于这些任务或整体计划完成。

最终收尾：**199 pass / 0 fail / 0 skip**，覆盖新增 ABI/工具缺收据与签发后依赖变化、回调冷/热对照、原路径/S04/反馈/UI、构建/覆盖/规则/发布及交接文档，JUnit `/tmp/zscope-async-final-20261013.xml`。其后将异步候选的修复说明改为等待真实完成再释放，避免显示句柄 close 的无关建议；两项真实 native 候选/默认开关回归 **2 pass / 0 fail / 0 skip**（39 deselected，不记为 skip），JUnit `/tmp/zscope-async-report-closeout-20261013.xml`。各集合有交集，不累加独立用例总数。最终 mypy（329 源文件）、compileall 与变更行/新增文件 Black 通过；交接文档单独复验另存 `/tmp/zscope-async-docs-closeout-20261013.xml`。

AGENTS、用户指南、架构、分析/配置模块与计划 11/16/21/22/README 同步。计划 **86 个本地链接/锚点、12 个唯一专项任务、10 个 RAPI ID** 和状态索引校验通过；Markdown 为 UTF-8 无 BOM、LF、末尾换行，当前增量空白检查通过。与开工 1295 文件逐项核对，本轮修改 **18 个已有文件、新增 4 个文件**；21 开工历史保持完整字节前缀，独立评估两文件摘要未变，native 文件未修改。diff、JUnit 和源码/工具摘要归档于 `/tmp/zscope-async-acceptance-20261013/`。保留已有并行修改，未 commit/push。

未运行真实 LLM、pthread 动态执行、完整 ASan/TSan 矩阵、正式准确率/性能 benchmark 或 portable 实物 smoke，均为未运行而非通过。下一项领域工作仍是 S06-R02 的实际单工作者队列/停止接收与 drain、取消点/清理及同锁 UAF；动态目标、多工作者、复杂 RAII/锁 guard、平台子域与完整 S07 调度继续开放。**本次两个受限切片完成，整体实施计划未完成。**

## 2026-10-14 · S06-R02 pthread 单工作者队列：取走、取消、停止与 join

用户确认首个协议采用 Linux pthread 单工作者队列。本轮从已验收的直接延迟回调路径继续，复用 native CFG、当前 BuildContext、ObjectRef、标准根契约、原调用方 helper 路径和 S04 回答/撤回链。没有新建队列配置、命名驱动的 drain 契约、全局 deallocator 配对或新的裁决库。

`LifecyclePaths._execution` 将原解释过程保留为可暂停帧；普通路径由原入口同步耗尽，循环边界不变。异步路径 v2 在创建后调用方首次 mutex unlock 推进工作者到其首次 unlock，保留实际取走的任务指针和对象代次，之后在 join 等待期间继续；仅该工作者允许每个 CFG 块最多 8 次访问，并共用总步数预算。具体字段写入与返回分支决定 submit/cancel/stop 的效果，active 清零、槽位摘除和调用方指针重新获取不能改写已保存的局部引用。成功 join 必须在回调实际退出后才记录；首个非法访问立即停止，不制造后续完成。

新增 native `pthread-storage.v1`，只给当前系统声明的 opaque pthread mutex/cond 记录类型，不透视/复制 libc union。队列路径限于创建前以默认属性初始化的存活堆上下文字段，按对象/字段身份维护锁所有者；不同实例或无共同锁的已执行共享访问保留缺口（未证明只读的访问也保守处理）。同一 mutex 下先 free 再访问仍产生 UAF 候选。只有当前标准根及精确签名才消费同步，signal/broadcast 不代表任务完成。

真实 native 正反例覆盖：活动任务取消后 free→join、仅 stop 后提前释放、同锁串行 UAF、调用方重新分配、释放不同对象、先 join 再 free、开始前摘除、待处理任务 drain、停止后拒绝提交、pthread_cancel 请求后正常完成；反例包括执行到 cond_wait、持锁 join、错误 mutex 实例/无锁共享访问、opaque 复制、销毁未 join 的同步对象、循环/总步数预算、缺类型收据和错误 allocation extent。任务对象与队列上下文、线程句柄分开，源码效果不证明业务释放责任。

阶段结果：首轮 **35 pass / 17 fail / 0 skip**（新同步根的 canonical signature 预期错误）；依据真实 native 签名修正后，队列/直接回调/旧路径 **83 pass / 0 fail / 0 skip**。后续队列/增量/目录/coverage **46 pass / 1 fail / 0 skip**：反例期待检查首次 UAF 之后才会执行的 stop 访问，调整为先让回调继续读取该字段再释放，以验证真正的未同步访问；没有放松生产守卫。包括回答撤回、JSON 无授权、根契约改变和 native 缺收据的接续回归 **93 pass / 0 fail / 0 skip**。JUnit 保存在 `/tmp/zscope-queue-node1-20261013.xml` 至 `node4`（文件名沿用开工日期）。集合有交集，不累加独立用例数。

修改 `ProgramEvents.h` 后已执行真实 CMake build/install，工具 SHA-256 为 `aee71c55fb55cd206c0bd0ef31bd6638781ab7d85c2bf1a0a43d328391994ab7`，SDK 18.1.3；这不是 portable 18.1.0 发行验收。测试与质量命令均在 WSL `<venv>/bin/python` 中执行，并指向该实际工具。mypy 初次发现 generator 返回 Any 的一处类型问题，以明确 Value 类型修复后 **329 个源文件通过**；compileall 通过。范围回归与文档/diff 收尾见后续记录。

S04 assessment v6 和 `object_protocol_path` revision 8 保留原规则 ID、主/附加 CWE、业务问题与撤回机制，仍 experimental/default-disabled。当前只是 Linux glibc LP64、同 TU、默认属性、堆上下文/单槽队列和成功分配/创建/同步结果的选定调度；实际条件等待/唤醒、取消点/cleanup、工作者 helper、通用 unregister/drain、多工作者、跨 TU 异步、失败结果和完整调度均未完成。complete 不等于所有交错覆盖，无观察不证明安全。

## 2026-10-14 · S07-R01 受限队列依赖失效与冷/热对照

S06-R02 事实可用后继续依赖满足的增量节点。复用原当前输入检查、batch 缓存、live Registry、S04 收据和统一 ValidationPipeline；`test_async_queue_incremental.py` 比较同路径独立冷数据库与热缓存的完整路径、候选 ID、裁决/报告桶、缺口及覆盖投影。阶段包括初始 UAF、相同源码/已有无关说明文件内容变化、取消 helper 写 active=0（不等于完成）、删除回调访问、恢复、将释放移到 join 后和改变 mutex_unlock 根契约。

旧 helper/回调/释放顺序变化在重建前已撤销当前收据，新的 native 事实再生成对应结果；业务前提回答撤回和 JSON 不授权沿原链验证。无关已有文件内容变化实际热提取为 **0 compiled / 2 reused TU**；独立冷提取重新执行，两侧结果一致。此局部对照已纳入上述 **93 pass**，不外推完整扫描、全部编译变体、动态目标集合或需求调度性能。RAPI10/INC 完整目标仍待办。

最终范围回归 **730 pass / 0 fail / 0 skip**（462.71 秒），包含队列/直接回调、旧路径/链接、池/引用计数/句柄、锁/RAII、S04/反馈/UI、native 包装器/批量提取、构建身份/缓存、契约/覆盖/候选/规则与统一验证。唯一 warning 是已有 `record_property` 与 JUnit xunit2 格式兼容提示。JUnit：`/tmp/zscope-queue-stage1-20261013.xml`。另外冷/热对照（增加真实冷轮 2 TU 重编译与当前收据断言）、规则运行时治理和交接文档 **22 pass / 0 fail / 0 skip**，见 `/tmp/zscope-queue-closeout-20261014.xml`；集合交叉，不累加独立测试数。最终任务对象/队列上下文修复说明、真实 native 候选/回答撤回及文档定向复验 **8 pass / 0 fail / 0 skip**，见 `/tmp/zscope-queue-docs-final-20261014.xml`。

实际 CMake source 指向当前仓库 `native/clang-indexer`，工具版本输出确认 Clang 18.1.3；不是旧二进制或合成事件验收。最终 mypy、compileall 和变更行/新增 Python 的 Black 通过。计划状态更新前及收尾均核对 **86 个本地链接/锚点、12 个唯一专项任务、10 个 RAPI ID**；本轮从 1299 文件快照核对，修改 **17 个已有文件、新增 2 个测试文件**，21 开工历史保持完整字节前缀，独立评估文件摘要不变，既有并行修改保留。Markdown UTF-8 无 BOM/LF/末尾换行及新增行空白校验通过。diff、工具/文件摘要和全部成功/失败 JUnit 归档在 `/tmp/zscope-queue-acceptance-20261014/`，未 commit/push。

本轮未运行真实 pthread 程序、ASan/TSan、真实 LLM、正式准确率/性能 benchmark 或 portable 实物 smoke，均为未运行，不计通过；上述 pytest skip=0 只描述实际执行集合。下一领域节点仍为 S06-R02 的条件等待/唤醒与取消点/cleanup 路径，其后按依赖处理通用 drain/unregister；S07-R01 动态目标集合与完整扫描/调度继续开放。**本次队列与对应增量切片完成，S06/S07 整包和整体实施计划均未完成。**

## 2026-10-14 · S06-R02 单等待者条件等待与匹配通知

依赖核对：已交付的单工作者队列、opaque mutex/cond native 身份、可暂停 CFG 帧、标准 wait/notify 根契约和 S04 重放/回答撤回均可直接复用，下一节点选为条件等待/唤醒；取消 cleanup 尚需独立 native 事实，不以语义名称猜测。计划链接和任务索引重新核对，保留原开工历史，不新增任务号或公共配置。

原解释器在调用完成后才能暂停，不能表示 cond_wait 尚未返回。现将同步调用保留为默认行为，异步消费者可在调用内部暂停；仅匹配当前条件实例的通知且重新取得指定 mutex 后，才向真实调用帧写入返回值。每次 wait_id 分开，提前通知不留额度，第一次等待收到的通知不能供下一轮使用。signal/broadcast 只标记当前单等待者，不证明任务完成或谓词成立；实际 CFG 返回后继续执行 while/返回值检查，空通知可再次进入等待。

沿用默认属性、已初始化 opaque 堆字段、当前系统 API/根契约、真实 mutex 所有者与共享访问检查。调用方解锁后只在等待 mutex 可重获时恢复工作者；解锁其他仍被持有的锁不抢先假定目标 mutex 已可用。持锁 join、无匹配通知、错误条件实例、未持锁等待、已释放等待存储、调用方等待及取消前/取消中的 cleanup 都保留缺口，未匹配通知不标为死锁或代码安全。虚假唤醒、timed/clock wait 与一般失败结果不在本切片中。

异步路径 schema v3、assessment v7、对象协议规则 revision 9 同步保留 canonical ID/CWE 和 experimental/default-disabled。恢复位置可以是通知后的解锁或 join，见证与业务验收问题使用真实边；首个 UAF 后不伪造尚未发生的 join。任务引用、等待对象、mutex、线程句柄仍分开，既有精确业务回答/撤回和 JSON 无程序授权的约束不变。

初轮 **78 pass / 1 fail / 0 skip**：新增时序断言误选了队列上下文的局部引用，按实际任务 ObjectRef 修正。随后定向等待/旧队列/直接回调、通知失效/冷热、契约/覆盖/目录 **107 pass / 0 fail / 0 skip**，见 `/tmp/zscope-wait-node2-20261014.xml`。扩展返回值样例时入口与回调同名，真实 native 编译拒绝该 fixture；独立诊断保存为 `/tmp/zscope-wait-fixture-diagnostic-20261014.xml`，已改入口名并继续验收，没有放松 strict batch 或退回 LSP。范围及修复后的结果在收尾补记，失败证据保留。

native 没有新增事实，本轮复用前轮实际重建的 SDK 18.1.3 工具，SHA-256 仍为 `aee71c55fb55cd206c0bd0ef31bd6638781ab7d85c2bf1a0a43d328391994ab7`；所有 native 用例在 WSL 通过显式 Z_SCOPE_TEST_CLANG_INDEXER 执行。mypy **329 个源文件通过**、compileall 通过；不是 Windows 解释器、动态 pthread 执行或 portable 发行结论。取消点/cleanup、工作者 helper、多工作者、跨 TU 异步与完整 RAPI09 保持开放。

## 2026-10-14 · S07-R01 等待通知依赖的冷/热对照

对应 S06 等待事实就绪后继续依赖满足的增量节点。复用 batch 缓存、当前源码/构建/native 检查、live Registry 收据和统一 ValidationPipeline；不创建新的缓存或调度器。实际两个 TU 的对照覆盖初始等待后 UAF、原样与已有无关文档内容变化、删除全部通知、通知到另一个条件字段、恢复、wait 根契约变化和修复 drain 顺序。

旧源码/通知实例变化在重新索引前已拒绝，根契约以当前 Registry 重放；同一 live Registry 的版本撤销沿既有回归核验，不能把另一个新 Registry 的构造误说成旧实例已被修改。独立冷轮确认为 **2 compiled TU**，原样与仅根契约变化的热轮为 **0 compiled / 2 reused TU**；完整路径、候选身份、统一裁决/报告桶、未决及覆盖一致。无通知/错误通知为待补证，不能从无候选推导安全。此项已纳入上述定向结果，完整扫描、动态目标集合和需求调度仍待办。

范围与修复验收：在修复 fixture 前已启动的跨模块集合记录 **711 pass / 0 fail / 22 error / 0 skip**（480.74 秒），22 个 error 全部来自同一个 `checked_wait` 入口/回调同名导致的 native setup 失败，不能把该轮标为全通过；唯一 warning 为既有 record_property/xunit2 提示。JUnit 保存在 `/tmp/zscope-wait-stage1-20261014.xml`。其余对象路径/链接、池/refcount/句柄、锁/RAII、native/构建/缓存、协议/反馈/UI、契约/规则/候选/统一验证均通过。

重命名测试入口后，包含所有等待病例及新增“通知恢复阶段 UAF、尚未进入 join”正例的定向修复集合 **123 pass / 0 fail / 0 skip**（`/tmp/zscope-wait-repair-20261014.xml`）。同时验证等待返回状态、空通知后重等、通知不跨等待轮次、持有目标 mutex 时释放无关锁不错误恢复、S04 业务回答撤回和序列化不授权，以及队列/等待的冷热对照与规则治理。修复只改测试名，生产证据额外修正恢复位置描述；没有绕过真实编译或将模型输出当作 native 事实。集合重叠，不累加独立测试数。

最终等待、直接回调、规则运行时治理及交接文档定向复验 **79 pass / 0 fail / 0 skip**（50.92 秒），见 `/tmp/zscope-wait-final-20261014.xml`；包含最终恢复位置描述与测试修复，和上述集合重叠，不累加独立测试数。

最终 mypy（329 源文件）、compileall、变更行/新增 Python 的 Black 通过，交接文档单独 **6 pass**。计划 86 个本地链接/锚点、12 个唯一任务号、10 个 RAPI ID 及当前状态索引通过；从本轮 1301 文件快照核对，修改 17 个已有文件、新增 2 个测试文件，原 21 历史保持完整字节前缀，独立评估文件和 native 源码均未修改。Markdown UTF-8 无 BOM/LF/末尾换行及新增行空白检查通过；diff、源码/工具摘要、成功与失败 JUnit 归档在 `/tmp/zscope-wait-acceptance-20261014/`。保留已有修改，未 commit/push。

未执行真实 pthread 程序、ASan/TSan、真实 LLM、正式准确率/性能 benchmark 或 portable 实物 smoke；这些未运行项不计通过。下一项仍是 S06-R02 的取消点/cleanup 事实与重放；虚假唤醒/超时、工作者 helper、多工作者/跨 TU、通用 unregister/drain 与 S07 完整扫描/需求调度继续待办。**当前条件等待与对应增量切片完成，不代表完整异步能力或整体实施计划完成。**

## 2026-10-14 · S06-R02 默认延迟取消与受限 cleanup

依赖核对后从已验收的单等待者 cond_wait 与 S04 重放进入取消点/cleanup。复用原 CFG 暂停帧、ObjectRef、同步实例、标准根和集中反馈，没有新增调度器或用户配置。开工保存 1303 个源码/测试/native/文档文件；另补保存开工时干净的 portable 批量构建脚本原文，共 1304 个基线文件。计划修改前核对 86 个本地链接/锚点、12 个唯一任务与 10 个 RAPI ID。原 21 的全部历史按字节前缀保留，包括 checked_wait 重名的扩大回归 **711 pass / 22 error** 及修复后的 **123/79 pass**；这些旧失败不改写为通过。

native 新增 `pthread-cleanup.v1`：在当前 C/glibc 无异常宏变体中核对系统 push/pop replacement tokens、直接简单参数、展开 AST 的真实回调/参数声明、内部 runtime 调用和分支、配对及控制跳出。原始 CFG/事件不删除；`pthread_cleanup.py` 仅供异步消费者投影经核验的 setjmp 脚手架，其输入仍绑定原始事实摘要。无相关宏时不额外遍历 AST；`PthreadCleanup.h` 同步进入 portable 批量组件构建指纹。

当前仅默认 enabled/deferred 取消：testcancel 无待处理请求时返回，有请求时执行 cleanup 并结束工作者；cond_wait 的取消不要求通知，但必须先重获原 mutex，然后 LIFO 执行最多四层同 TU void(void*) handler。push 保存注册当时的对象及代次，后续指针重赋值不改清理目标；pop(0) 仅移除，pop(1) 按真实回调执行。请求、取消投递、cleanup 完成、工作者结束及成功 join 分开。handler 中实际 free 与 unlock 使用原标准根及对象/锁状态，不能凭名字配成全局 deallocator；首次 UAF 立即停止，不虚构其后的清理、完成或 join。

旧无 handler 的 testcancel 现闭合选定取消路径；无 unlock cleanup 的 cond_wait 则在重获后保留锁残留缺口。提前请求、等待中请求、通知后请求、通知/解锁期间 cleanup UAF、原对象捕获、嵌套顺序、物理 free、正常 pop、当前 native 收据/根契约、集中验收与回答撤回均有真实提取验证。持锁 join、失效等待存储、未 drain、改写宏/内部 likely 宏、异常宏变体、控制跳出、未知 helper 和取消模式切换不取得完成或安全权限。首批不含 pthread_exit、任意取消点、cleanup 内取消点/嵌套注册、工作者 helper、C++/异常 cleanup、TSD 析构、跨 TU 或多工作者；未观察到缺陷不证明安全。

版本同步：异步路径 v4、assessment v8、标准 API v7（新增 testcancel 的 standard_operation）、object_protocol_path revision 10。canonical ID、主 CWE-664/附加 CWE 与默认 experimental/default-disabled 不变；普通同 TU 对象路径仍为 v5，未混淆二者。当前源码/构建/根契约和 S04 回答版本继续控制收据，序列化路径和模型文本不授权确认。

节点记录（均 WSL，实际工具通过 Z_SCOPE_TEST_CLANG_INDEXER 指定）：

| 集合 | 实际结果 | 说明 |
|---|---|---|
| node1 | **8 pass / 1 fail / 0 skip** | normal pop(1) 的常量 CFG 分支已被裁剪，强选 false 导致歧义；修复为保留实际常量分支，handler 仍显式执行 |
| node2 | **79 pass / 4 fail / 0 skip** | 新模式反例的更早拒绝点与旧取消用例预期未更新；按新能力核对后保留模式/锁残留缺口，单独验证无 handler 的 testcancel 不返回 |
| node3 | **91 pass / 1 fail / 0 skip** | helper 反例替换误命中旧 spins fixture，真实编译报未声明调用；改为精确替换 handler，不放松 strict batch |
| node4 | **92 pass / 0 fail / 0 skip** | cleanup、等待、直接回调及标准契约；包括宏改写/控制跳出/模式/未知 helper 拒绝与业务回答撤回 |
| 发布脚本与交接文档 | **32 pass / 0 fail / 0 skip** | portable Python 单元验证及 agent docs，不是发布实物 smoke |

JUnit 保存为 `/tmp/zscope-cancel-node1-20261014.xml` 至 `node4`，发布/文档为 `/tmp/zscope-cancel-release-docs-20261014.xml`，失败证据保留。扩大回归前 native 在当前仓库实际重编译，SDK 18.1.3，该轮工具 SHA-256 `43f700cc3f4f432e8e369ee04bb1280ec555076f42c646c3dc9ee5cef4570e18`；早期节点工具亦来自本轮真实构建。收尾另补内部宏二次展开的拒绝检查，使用独立安装目录重建，避免改变尚在运行的扩大回归工具；该补充的最终工具与验证结果另记。mypy **330 个源文件通过**，compileall 通过，变更 Python 按变更行或新增文件 Black。范围复验结果在收尾追加，不预先记为通过。

## 2026-10-14 · S07-R01 cleanup 依赖失效与冷/热对照

S06 事实可用后继续依赖满足的局部增量节点，复用既有 batch cache、BuildContext/工具/源码依赖、live Registry 与统一 ValidationPipeline。真实两 TU 对照初始 cleanup UAF、原样热复用、清理体移除访问、直接 handler 改为 noop、恢复、testcancel 根契约改变及成功 join 后释放。源码变化在索引重建前就会使旧收据失效；独立新 Registry 在当前重放时拒绝旧契约，不能误报旧 live Registry 自身发生了修改。

热轮原样/仅根契约变化为 **0 compiled / 2 reused TU**；每个独立冷轮真实 **2 compiled TU**，完整路径、候选身份、统一裁决/报告桶、未决及覆盖投影一致。该对照连同已有队列/等待增量与规则治理 **34 pass / 0 fail / 0 skip**（130.75 秒，`/tmp/zscope-cancel-incremental-20261014.xml`）。本地切片不代表完整扫描、动态目标集合、全部编译变体或需求调度已验收。

后续领域节点为工作者普通 helper 的受限调用帧，随后按事实依赖处理虚假唤醒/超时与更一般的 drain/unregister。取消模式切换、任意取消点、跨 TU/多工作者和完整 S07 保持待办。未运行真实 pthread、ASan/TSan、真实 LLM、正式准确率/性能 benchmark 或 portable 实物 smoke；未运行不计通过。**本轮默认延迟取消/cleanup 与对应增量切片完成，S06/S07 整体及完整实施计划均未完成。**

扩大范围复验 **801 pass / 0 fail / 0 error / 0 skip**（675.98 秒，`/tmp/zscope-cancel-stage1-20261014.xml`）。该轮使用 SHA-256 `43f700cc…4570e18` 的本轮真实工具，包含异步/队列/等待/cleanup 及冷热、native 包装器/批量提取/构建身份/缓存、链接/对象路径、池/refcount/句柄、锁/RAII、S04/反馈/UI、契约/覆盖/候选/规则与统一验证。唯一 warning 为既有 record_property 与 JUnit xunit2 兼容提示。与节点及局部增量集合重叠，不累加独立测试数；不能据此改写上一轮失败记录。

收尾限制补充：即使外层 push/pop 仍是标准模板，项目也可能通过内部宏替换缓冲类型或 runtime 名称。native 现拒绝这些二次展开，只接受当前系统定义的受支持内部宏；新反例另覆盖内部类型宏、项目定义的注册函数、非字面量 pop 和栈深度上限。为保持扩大回归工具不变，在独立目录真实编译/安装该补充版后进行专项复验；扩大回归结束才安装回常用工具路径。最终两个安装路径的工具 SHA-256 均为 `2bdb69e77b6b8d339f0a85e39039e12d48b075c996415c6d690feac1e1fb3629`，SDK 18.1.3；补充版专项结果在收尾追加。

补强版专项复验 **241 pass / 0 fail / 0 error / 0 skip**（211.02 秒，`/tmp/zscope-cancel-final-20261014.xml`），使用最终 SHA-256 `2bdb69e7…fb3629` 的独立安装工具。覆盖新增二次宏/内部函数/非字面量 pop/深度反例、cleanup/直接回调/等待及 cleanup 冷热、native 包装器/覆盖/缓存/构建身份、S04/反馈和规则治理；其余跨域范围由上述 801 项实测记录，不将两轮视为同一二进制的一次全集验收。常用目录已安装同摘要二进制。当前所有新增及受影响测试均完成复验，无未处理失败；各集合重叠，不累加独立数。

收尾 mypy **330 源文件通过**、compileall 和 Python Black 通过，更新交接文档后单独 **6 pass**。从 1304 文件基线核对本轮修改 22 个已有文件、新增 4 个文件；86 个本地链接/锚点、12 个专项任务号、10 个 RAPI ID、UTF-8 无 BOM/LF/末尾换行及新增行空白校验通过。原 21 历史完整字节前缀、独立评估文件及既有并行修改保留。阶段 diff、输入/工具摘要和全部成功/失败 JUnit 存于 `/tmp/zscope-cancel-acceptance-20261014/`。未 commit/push，实验默认开关不变；下一节点仍为工作者普通 helper 的受限调用帧，完整计划保持进行中。

## 2026-10-14 · S06-R02 工作者普通 helper 的有界调用帧

按依赖从已验收的默认延迟取消/cleanup 进入工作者 helper。开工保存 1307 个文件的当前原文，核对计划 86 个本地链接/锚点、12 个唯一任务号、10 个 RAPI ID；保留既有并行修改和 21 全部历史。现有 native 已提供当前直接调用 USR、签名、参数、返回值、CFG 与构建收据，本轮不增加提取事实、不修改 native 源码。所有 native 验证在 WSL 指向前轮实际重建的 SDK 18.1.3 工具，SHA-256 为 `2bdb69e77b6b8d339f0a85e39039e12d48b075c996415c6d690feac1e1fb3629`。前轮 801 项扩大回归与 241 项补强版专项的两个二进制及验收范围保持分别记录，不合并为同版本全集结论。

普通工作者 helper 首批仅同一 C 源文件、同一精确 BuildContext、当前无属性直接目标；实际重放函数体，不发布名称驱动的释放摘要。参数和返回限已知堆根 Pointer/ObjectRef、空值与 signed 32-bit 范围整数，并核对 native 类型和转换限制；释放对象仍保留原获取代次。独立工作者调用栈跨 unlock/cond_wait 暂停，恢复只更新调度根边，保留所有活动 helper 帧；正常返回才发布值，重复调用使用独立 invocation。普通工作者的 free 复用标准根和真实对象状态核验。

取消点可以位于普通 helper；cleanup 仍使用受限真实 C/glibc handler。各 handler 保存注册帧和注册时参数，LIFO 清理在对应活动帧路径执行，另存实际取消点，不能误归到最内层 helper；取消后的父子帧不生成返回事件。首个 UAF 即停止，不能补造后续清理/完成/join。递归/深度、步骤和循环继续有界；局部/字段地址传参或返回、未知/间接目标、cleanup 内普通 helper、worker 分配、跨 TU 和多工作者保持缺口，无观察不证明安全。

异步路径升级 v5、assessment v9、object_protocol_path revision 11；普通同 TU 路径版本及标准 API v7 不变。canonical ID/CWE 和 experimental/default-disabled 保持，coverage 区分受限 helper 能力与规则实际运行，不加 public YAML、第二套反馈库或全局 deallocator 配对。AGENTS、用户指南、架构/模块与计划任务/验收边界同步维护。

节点实测：首轮真实 native helper **17 pass / 0 fail / 0 error / 0 skip**（16.04 秒，`/tmp/zscope-helper-node1-20261014.xml`）；补充集中验收回答撤回、JSON 不授权及两 TU 冷热对照后 **19 pass / 0 fail / 0 error / 0 skip**（81.79 秒，`/tmp/zscope-helper-node2-20261014.xml`）。覆盖嵌套返回、暂停后发布、重复调用、原对象别名、实际 free、正常 drain、helper 中 testcancel、跨层注册 cleanup 及受限拒绝边界。规则目录/运行时治理和契约 **71 pass / 0 fail / 0 skip**（13.25 秒，`/tmp/zscope-helper-governance-20261014.xml`）。集合重叠时不累加独立测试数；扩大相关回归结果收尾追加。

## 2026-10-14 · S07-R01 工作者 helper 依赖与冷/热对照

S06 helper 事实就绪后继续对应增量节点，复用现有 batch cache、当前源码/构建/native 输入核验、live Registry、S04 回答版本和统一 ValidationPipeline。真实两 TU 对照初始 UAF、原样复用、helper 体移除访问、直接目标改变、返回空值、恢复、根契约变化、helper 加入 testcancel 与修复 drain 顺序。源码变化在重新索引前撤回旧进程内收据，旧事实也不能重新签发确认；当前契约改变必须重新核验，不将另建 Registry 误说成旧 live Registry 自身修改。

每个独立冷轮实际 **2 compiled TU**；原样与仅根契约变化的热轮为 **0 compiled / 2 reused TU**。完整路径、候选身份、统一裁决/报告桶、未决和覆盖投影一致；新增取消点后实际结束工作者，只有此前已返回的 take_one 保留返回事件。该项包含在上述 19 项节点集合中，不另累加。业务前提确认/撤回及序列化失权已定向验收，不新增夜间中途交互。

后续领域节点为虚假唤醒/超时及更一般的 drain/unregister；一般 helper、取消模式切换、任意取消点、跨 TU/多工作者与完整扫描/需求调度仍待办。未运行真实 pthread 程序、ASan/TSan、真实 LLM、正式准确率/性能 benchmark 或 portable 实物 smoke，不计通过。**当前 helper 与对应局部增量切片不代表完整 S06/S07、RAPI09/RAPI10 或整体实施计划完成。**

收尾工作者 helper 跨模块复验 **342 pass / 0 fail / 0 error / 0 skip**（JUnit 499.96 秒，`/tmp/zscope-helper-stage1-20261014.xml`），使用上述同一 SHA-256 的实际 native 工具。覆盖全部已支持异步/队列/等待/cleanup/helper 与局部冷热、对象路径与实际链接、S04/反馈/UI、构建身份/缓存/覆盖、候选及统一验证。候选台账快照、Clang 候选引擎与规则治理补充 **126 pass / 0 fail / 0 skip**（21.97 秒，`/tmp/zscope-helper-candidate-20261014.xml`），交接文档单独 **6 pass**（`/tmp/zscope-helper-docs-20261014.xml`）。各集合存在重叠，不累加独立测试数；本轮无未处理测试失败，不能以此覆盖历史失败或晋级实验规则。

最终 mypy **330 源文件通过**、compileall 和变更行/新增 Python Black 通过。从 1307 文件基线核对修改 15 个已有文件、新增 2 个测试；native 源码未改，portable 批量构建脚本与前轮归档摘要一致。计划 86 个本地链接/锚点、12 个唯一任务号、10 个 RAPI ID、UTF-8 无 BOM/LF/末尾换行和新增行空白检查通过，原 21 历史完整字节前缀及独立评估文件保留。首次归档检查误将未纳入本轮基线的 portable 脚本当作已登记文件而产生 KeyError；修正检查脚本为对照前轮已归档摘要后通过，产品源码和基线未改写。阶段 diff、工具/输入摘要、质量结果及 JUnit 存于 `/tmp/zscope-helper-acceptance-20261014/`。未 commit/push；当前同文件直接 helper 与对应增量切片完成，下一领域节点仍为虚假唤醒/超时，完整计划保持进行中。

## 2026-10-14 · S06-R02 一次无通知唤醒与受限 timedwait

依赖已有同文件 worker/helper、单等待者 cond_wait、默认延迟取消/cleanup 和 S04 当前路径重放，继续虚假唤醒/超时节点。开工保存 1309 个文件原文，并核对 86 个计划本地链接/锚点、12 个唯一任务号和 10 个 RAPI ID。现有标准 API v7 已有 timedwait 的 lock_wait/ETIMEDOUT 语义，本轮复用，不重建契约、缓存、业务回答库或用户配置。

原通知路径优先；仅当其停在未匹配通知的等待点时，从相同当前事实额外重放 `spurious_once`，对核验过的 timedwait 再尝试独立的 `timeout_once`。最多三条路径，单条替代路径最多一次无通知返回，继续使用现有步骤/循环/调用深度上限。先选实际非法访问见证，次选完整路径；均未闭合时保留原缺口及各次尝试的原因。匹配通知和取消优先，返回前仍必须重获原 mutex，实际 CFG 决定谓词/返回值分支。重等不取得第二次无通知返回额度；探索结束再次检查源码/工具和 Registry 版本。未穷举所有唤醒点、次数或通知/超时竞争，无观察不证明安全。

native 新增 `pthread-wait.v1` / `pthread-deadline.v1`：只接受当前系统定义、两字段 signed 64-bit timespec、函数局部对象和直接取地址调用参数；系统 ETIMEDOUT 要有实际单数值宏定义出处。只有直接系统常量展开可投影为当前 AST 表达式，项目/包装宏不授权，原始输入摘要仍绑定。消费者核验已初始化的非负秒数和合法纳秒范围；默认 cond 属性对应 CLOCK_REALTIME。超时发布实际 ETIMEDOUT，普通返回发布 0，两者分别携带时钟不早于/早于截止时间的约束，不读取宿主时钟、不执行等待程序。取消先重获锁并沿注册帧 cleanup，不生成普通返回。

截止时间未知/非法、负秒、显式指针转换、非局部时间来源、缺收据、项目宏/包装宏、clockwait/自定义时钟保持缺口；锁重获阻塞、等待对象失效及 cleanup/helper 旧边界继续保留。场景包含超时分支 UAF、无通知 if 与 while 重检对照、成功 join 后释放、helper 和 cleanup 注册范围、取消优先、当前根契约、见证篡改及集中业务回答撤回。时钟/截止条件进入已有验收前提，源码效果不代表业务规范。

中间节点均使用本轮第一次实际重建的 SDK 18.1.3 工具，SHA-256 `606890e6dba13820dbd3c8e5c63c65c5b0b2f5612fdca89e71b8ae69996c4d13`：首轮 **13 pass / 0 fail / 0 error / 0 skip**（29.58 秒，`/tmp/zscope-wake-node1-20261014.xml`）；补充边界、反馈及旧等待/helper 后 **63 pass / 0 fail / 0 error / 0 skip**（89.90 秒，`/tmp/zscope-wake-node2-20261014.xml`）。这是中间实现及工具的定向结果，不当作最终版本全集验收。

随后去除非相关 AST 事件的额外 pretty-print 成本，再次实际重建，主回归版工具 SHA-256 `30fe2b47946d23b47c765ea211a72c5b6c3d4c9bc5f0ad163c17b2d1907df55c`；该集合结束前没有改写工具。异步路径 v6、assessment v10、object_protocol_path revision 12 同步，canonical ID/CWE、experimental/default-disabled 和标准 API v7 保持。mypy **330 源文件通过**、compileall/变更 Python Black 通过，交接文档单独 **6 pass**（`/tmp/zscope-wake-docs-20261014.xml`）。最终相关回归与增量结果在收尾追加；不合并前轮或本轮不同二进制/范围为一次全集通过。

## 2026-10-14 · S07-R01 等待结果与截止时间依赖

新增两 TU 局部对照沿用 batch cache、当前 native 输入、Registry 与 ValidationPipeline，覆盖原样热复用、截止时间变化、返回码谓词改变、非法纳秒、ETIMEDOUT 项目宏重定义、恢复、根契约变化和 drain 顺序修复。应比较完整路径与各次调度尝试、候选身份、统一裁决/报告桶、未决及覆盖；修改源码前后的旧进程内收据必须失效。测试已接入最终工具上的相关集合，实际 pass/fail/skip 和冷/热编译数收尾记录，未完成运行前不预记通过。

clockwait、自定义时钟和一般时间来源、多次唤醒/通知竞争、一般错误结果、通用 drain/unregister、跨 TU/多工作者与完整扫描/需求调度继续待办。未运行真实 pthread 程序、Sanitizer、真实 LLM、正式准确率/性能 benchmark 或 portable 实物 smoke，不计通过。**本切片不关闭完整 S06/S07、RAPI09/RAPI10 或整体计划。**

收尾额外核对 ABI 边界时，以 `-fpack-struct=1` 真实重提取复现旧 v1 收据仍允许超时见证，定向记录 **0 pass / 1 fail / 0 error / 0 skip**（22 deselected，`/tmp/zscope-wake-layout-before-20261014.xml`）。已收紧为 `pthread-wait.v2` / `pthread-deadline.v2`：检查 timespec 大小 16 字节、对齐 8 字节、两个字段位移 0/64 bit 和局部对象属性；Python 再核验布局收据并拒绝旧 v1。工具再次实际重建，新增真实布局反例及缺失/旧版本/篡改布局隔离检查，补强版验证另行记录，不冒称前一二进制的结果覆盖该补充。

收尾等待结果主回归 **377 pass / 1 fail / 0 error / 0 skip**（682.69 秒，`/tmp/zscope-wake-stage1-20261014.xml`），全部使用主回归版 `30fe2b47…df55c` 工具。唯一失败是旧等待增量测试将删除/错发通知视为必然未闭合：此 fixture 仍在锁内提交任务，因此一次无通知唤醒重检真实谓词后可以访问已 free 的任务。修正这项旧预期，额外断言主通知路径仍缺通知、选中路径确为 spurious_once；没有放松 native/CFG/锁或业务验收。完整七阶段修复对照 **1 pass / 0 fail / 0 error / 0 skip**（60.67 秒，`/tmp/zscope-wake-repair-20261014.xml`）。该修复仅改测试，生产代码和该轮工具未变；原失败 JUnit 保留，主回归不改写为一次全通过。

上述主集合中新的等待结果增量对照已经通过：原样与仅根契约变化实际 **0 compiled / 2 reused TU**，每个独立冷轮 **2 compiled TU**；完整路径/尝试范围、候选身份、裁决、未决及覆盖投影一致。源码/截止时间/宏改变在重索引前撤回旧收据，谓词改成 rc==0 时选中 spurious_once，timeout 分支使用核验系统常量与时钟约束。S07-R01 对应局部切片验收完成；完整扫描、动态调度集合和需求调度未关闭。

同一主回归版工具的批量提取、Clang 候选引擎和统一 Validator 补充回归 **148 pass / 0 fail / 0 error / 0 skip**（57.99 秒，`/tmp/zscope-wake-native-consumers-20261014.xml`）。主集合还覆盖全部现有异步/helper/cleanup 与局部冷热、native 包装器/覆盖/缓存、构建身份、对象路径/链接、S04/反馈/UI、规则与候选台账。集合重叠，不累加独立测试数；先前工具的 13/63 项、上一阶段工具及历史失败保留各自版本和范围，不混作同一二进制的一次全集结论；随后布局补强的结果另记。

最终 mypy **330 源文件通过**，修复测试后 compileall 与相关 Python Black 通过；交接文档 **6 pass**。从 1309 文件基线核对修改 17 个已有文件、新增 2 个测试；native 的两个改动文件均已实际重编译，portable 构建脚本保持前轮归档摘要。86 个本地链接/锚点、12 个唯一任务号、10 个 RAPI ID、Markdown UTF-8 无 BOM/LF/末尾换行和新增行空白检查通过；原 21 历史完整字节前缀、独立评估材料和并行修改保留。阶段 diff、最终输入/工具摘要、两次构建日志和成功/失败 JUnit 存于 `/tmp/zscope-wake-acceptance-20261014/`。实验规则仍默认关闭，未 commit/push。下一领域工作仍有通用 drain/unregister，以及 clockwait/一般时间来源和更广唤醒序列；本轮有限等待结果与局部增量完成，不代表整体计划完成。

布局补强版最终专项 **160 pass / 0 fail / 0 error / 0 skip**（JUnit 325.44 秒，`/tmp/zscope-wake-layout-final-20261014.xml`），使用第三次实际重建工具，SHA-256 `7083c2e9ff1cfdcab26c8f097fa45969e3ca592f7cbd927af47aad979dcbe66d`，SDK 18.1.3。覆盖真实 packed timespec 反例、v1/缺失/布局篡改拒绝、全部新等待结果与业务撤回、截止时间及旧通知两组完整冷热对照、native 包装器/覆盖/缓存/构建身份/批量提取、规则与 S04/反馈。前轮 377/1 与 148 项范围继续独立保留，不能视为第三版工具的一次全集；当前新增及受影响项目均已复验，无未处理失败。补强后 mypy 330 源文件、compileall、Black 通过，交接文档另 **6 pass**（`/tmp/zscope-wake-docs-final-20261014.xml`）。原 packed 失败证据保留，不把旧工具的布局收据重新授权。

## 2026-10-14 · S06-R02 直接系统时钟 clockwait

依赖已经验收的单工作者队列、helper、等待结果、取消 cleanup 和当前 timespec ABI 收据，继续直接 pthread_cond_clockwait 切片。开工保存 1311 个文件基线，重新核对 86 个本地链接/锚点、12 个唯一任务号和 10 个 RAPI ID；保留上一轮 v2 工具 160 项专项与更早 377/1、148 项等各自版本和范围，不合并为一次全集通过。

标准 API v7 已有 clockwait 的 lock_wait/返回条件，本轮复用；不新增契约根、用户配置、回答库或全局释放器配对。native `pthread-wait.v3` / `pthread-deadline.v3` 为显式时钟参数检查当前系统 CLOCK_REALTIME/CLOCK_MONOTONIC 单数值宏的直接展开、当前定义和值，连同已核验的局部 timespec 布局发布收据。消费者再次检查当前系统标记、时钟参数及值，使用相应时钟的绝对截止条件；数字字面量、变量别名、显式转换、包装宏、同值项目重定义、不支持的时钟及旧 v1/v2 收据保持缺口。真实 packed 布局反例继续拒绝。

复用既有通知优先、一次无通知返回、最多三条路径的受限探索：超时前释放、返回前重获原 mutex，随后按实际 0/ETIMEDOUT 分支解释；取消仍先清理、不产生普通返回，同文件 helper 保留真实调用栈与对象代次。同步纠正旧 timedwait 成功分支的过强时间约束：返回 0 不证明返回时早于截止时间，仅 timeout 分支记录时钟不早于截止的条件。见证使用异步 v7、assessment v11、object_protocol_path revision 13；canonical ID/CWE 和 experimental/default-disabled 不变。

native 已在 WSL Linux 用 SDK 18.1.3 实际重建，SHA-256 `d39cbe72fafad1fbfa989a51346cdf4785101e32855c0ee0d11a1e2748263399`；当前相关测试运行期间工具不改写。首轮真实 native clockwait 与既有 wake 专项 **57 pass / 0 fail / 0 error / 0 skip**（151.57 秒，`/tmp/zscope-clock-node1-20261014.xml`）。该轮后补充消费者 coverage 断言及 timedwait 零返回无时间先后约束断言，最终集合另记。Black 仅处理变更行与新增测试；compileall、mypy **330 源文件通过**。扩大消费者集合首个命令误用了不存在的两个测试文件名，未收集测试；保留原日志并按实际测试文件重新执行，不计 pass 或 skip。

## 2026-10-14 · S07-R01 显式时钟依赖与冷/热对照

继续依赖已满足的局部增量节点，新增真实两 TU 对照：初始 monotonic、原样复用、realtime 选择、返回码谓词、同值宏重定义、不支持的时钟、恢复、当前根契约与 drain 顺序。沿原 batch cache、native 输入当前性、live Registry、统一 ValidationPipeline 与业务回答撤回链比较完整路径、尝试范围、候选身份、裁决/未决/覆盖；源变更在重索引前撤回旧进程内收据。测试已接入扩大集合，实际结果和冷热编译数在运行结束后追加。

此轮不读取宿主时钟、不执行真实 pthread 程序；Sanitizer、真实 LLM、正式准确率/性能 benchmark 和 portable 实物 smoke 未运行，不计通过。一般时间来源、自定义时钟、重复唤醒/通知竞争、通用 drain/unregister、跨 TU/多工作者与完整扫描/需求调度仍待办。**受限 clockwait 与对应局部增量不代表完整 S06/S07、RAPI09/RAPI10 或整体计划完成。**

本轮 clockwait 收尾：异步协议与对应局部增量、对象路径/实际链接、S04/反馈/UI 和协议缓存回归 **316 pass / 0 fail / 0 error / 0 skip**（JUnit 930.31 秒，`/tmp/zscope-clock-protocols-20261014.xml`）。native 包装器/覆盖/缓存/构建身份/批量工具、Clang 候选/策略、规则治理、统一 Validator 与交接文档 **269 pass / 0 fail / 0 error / 0 skip**（JUnit 148.10 秒，`/tmp/zscope-clock-consumers-final-20261014.xml`）。这两组和首轮 57 项均使用上文 SHA-256 `d39cbe72…263399` 实际工具；集合重叠，不累加独立测试数。最初文件名错误的命令为 **0 tests collected**，原日志及空 JUnit 保留，不计通过；没有未处理的测试失败。

显式时钟的九阶段两 TU 冷/热对照完成：原样与仅根契约变化热轮实际 **0 compiled / 2 reused TU**，每个独立冷轮 **2 compiled TU**；完整路径/尝试、候选身份和统一裁决/未决/覆盖相同。源码或时钟定义/选择变化在重索引前撤回旧收据，谓词改变选中 spurious_once，超时选中对应时钟的 timeout_once。当前 contract 修改重放失效，成功 join 后再 free 不产生该 UAF 见证；业务回答撤回与 JSON 不授权均通过。此项已包含在协议集合中，不另累加。

最终 mypy 330 源文件、compileall、变更行及新增 Python Black 通过。阶段 diff、工具/输入摘要、真实 native 构建日志及各范围 JUnit 存于 `/tmp/zscope-clock-acceptance-20261014/`。从 1311 文件原文基线核对修改 18 个已有文件、新增 2 个测试；两个 native 文件已实际重建，portable 构建脚本与前轮归档摘要一致。86 个本地链接/锚点、12 个唯一任务号、10 个 RAPI ID、UTF-8 无 BOM/LF/末尾换行及新增行空白检查通过；原 21 历史完整字节前缀、独立评估材料和并行修改保留。未 commit/push，实验规则仍默认关闭。本轮受限 clockwait 和对应 S07 局部增量完成，通用 drain/unregister、一般时间来源及更广调度继续待办，整体实施计划保持进行中。

协议集合另有一项既有 `record_property` 与 JUnit xunit2 格式兼容提示，来自 `test_protocol_incremental_equivalence.py::test_hot_reuses_ast_cfg_with_measured_preprocessing`；该测试及其实际预处理/缓存断言通过。原提示保留在日志，不计测试失败，也不据此扩大性能结论。

状态收尾后的交接文档单独复验 **6 pass / 0 fail / 0 error / 0 skip**（`/tmp/zscope-clock-docs-final-20261014.xml`）；最后再次核对计划链接、编号、历史原文及工具摘要通过，结果与本轮 diff 一并归档。

## 2026-10-14 · S06-R02 调用方条件等待与受限 drain

核对剩余依赖后继续同一 pthread 单工作者队列的调用方等待切片。开工保存 1313 个文件基线并校验 86 个计划本地链接/锚点、12 个唯一任务号与 10 个 RAPI ID；前轮 clockwait 的 316 项协议、269 项消费者和 6 项文档结果按原工具版本、范围保留，不累加独立用例或覆盖历史失败。现有 native mutex/cond、实际 CFG、worker/helper、取消 cleanup、S04 和局部增量足够，本轮不改 native 源码/事实 schema，不引入 drain 名称契约、配置或第二套状态库。

调用方只新增当前标准 pthread_cond_wait 的匹配通知路径：核对精确条件变量、mutex、当前持锁者以及并行等待的动态锁绑定，释放原锁后推进工作者，通知到达且原 mutex 释放后才重获锁并返回。无关锁的 unlock 不满足重获条件；同一条件变量同时绑定不同 mutex 保持缺口。实际 if/while 负责重检 active 等业务谓词；提前通知不保留额度，通知/标志清零/等待返回不设置 worker complete/joined，也不授权队列存储销毁。最多四次调用方等待，仅实际发生等待的帧可按八次块访问上限重检，整体步骤/调用深度沿用现有界限。

调度路径保留入口到调用方 helper 的全部边，再接实际 worker 恢复边及其活动 helper 帧。恢复时只替换调度前缀，取消 cleanup 的根注册帧按该前缀真实深度展开。首次非法访问在等待期间发生时立即停止，既不补造调用方等待返回，也不补造未来 join；入口候选仍能定位原调用点。异步 v8、assessment v12、object_protocol_path revision 14 同步；主/附加 CWE、canonical ID 与实验默认关闭保持。coverage 对 cond_wait 明确标记调用方条件重检，timedwait/clockwait 保留 caller_wait_unsupported。

全部本轮 native 提取使用前轮真实构建、SDK 18.1.3 的同一工具 SHA-256 `d39cbe72fafad1fbfa989a51346cdf4785101e32855c0ee0d11a1e2748263399`；未以重写完成标记冒充重建，当前 native 源码与已验收输入一致。首轮 **32 pass / 4 fail / 0 error / 0 skip**（49.40 秒，`/tmp/zscope-drain-node1-20261014.xml`）：两项失败来自等待 helper 的入口调用边丢失，导致真实 UAF 见证未生成候选；已修正调度前缀。另两项为不可达 CFG exit 的无限循环 fixture 与旧“调用方完全不支持”预期，分别改为有原生出口的已知真谓词循环，以及保留实际双等待/无通知缺口，未放松 CFG 完整性。修复后连同既有等待/helper/cleanup **86 pass / 0 fail / 0 error / 0 skip**（126.28 秒，`/tmp/zscope-drain-node2-20261014.xml`）。

随后补充不同 mutex 绑定拒绝、通知后先解无关锁、消费者诊断及九阶段局部冷热对照，专项 **17 pass / 0 fail / 0 error / 0 skip**（95.79 秒，`/tmp/zscope-drain-node3-20261014.xml`）。再核对 caller helper 内取消投递时的 cleanup 根展开，补齐实际调度前缀深度并加入取消后完成与 cleanup UAF 正反例，当前 drain 专项 **18 pass / 0 fail / 0 error / 0 skip**（32.67 秒，`/tmp/zscope-drain-cancel-20261014.xml`）。这些中间集合保留各自代码范围，最终扩大回归另记，不能相加或代替最终版本全集。Black 仅处理变更行及新增测试，compileall 与 mypy 330 源文件通过。

## 2026-10-14 · S07-R01 调用方等待依赖与冷/热对照

依赖有限 caller cond_wait 实现，继续原 batch cache、native 当前输入、live Registry、统一 ValidationPipeline 与回答撤回链。九阶段实际两 TU 对照覆盖初始提前清零、原样、helper 谓词、通知删除、回调目标改成真实完成、恢复、先 free 后等待、当前根契约与 join 先于 free 修复；比较完整调度路径、候选身份、统一裁决/报告桶、未决和覆盖。源码变化在重新索引前撤回旧进程内收据；等待发生在 helper 内时同样要产生对应入口候选。上述节点对照已通过，收尾扩大集合会对最终代码再次复验并记录编译/复用数。

调用方 timedwait/clockwait、无通知返回及取消仍不支持；多工作者、跨 TU 异步、通用 unregister/drain、完整扫描/需求调度继续待办。未执行真实 pthread 程序、Sanitizer、真实 LLM、正式准确率/性能 benchmark 或 portable 实物 smoke，不计通过。**当前受限调用方等待及局部增量不代表完整 S06/S07、RAPI09/RAPI10 或整体实施计划完成。**

本轮 caller drain 收尾：最终异步协议/所有局部增量、对象路径/实际链接、S04/反馈/UI 与协议缓存集合 **335 pass / 0 fail / 0 error / 0 skip**（JUnit 977.28 秒，`/tmp/zscope-drain-protocols-20261014.xml`）。native 包装器/覆盖/缓存/构建身份/批量工具、Clang 候选/策略、规则治理、统一 Validator、引用计数/句柄集成与交接文档集合 **280 pass / 0 fail / 0 error / 0 skip**（JUnit 157.66 秒，`/tmp/zscope-drain-consumers-20261014.xml`）。均使用上文相同 `d39cbe72…263399` 工具和最终代码；集合有重叠，不累加独立用例。前轮 clockwait 的 316/269 项及本轮中间 32/4、86、17、18 项范围继续分别保留；原始失败未改写为通过，当前无未处理失败。

最终九阶段 caller drain 冷/热对照通过：原样及仅根契约变化热轮实际 **0 compiled / 2 reused TU**，每个独立冷轮 **2 compiled TU**；完整路径/候选身份/裁决/未决/覆盖相同。helper 谓词跳过等待后仍保留后续 UAF，删除通知不闭合 caller 等待，真实完成或 join 先于 free 修复不产生此见证；先 free 后在 helper 中等待仍能生成准确入口候选。旧收据在源码变化后重索引前撤回，当前根契约及业务回答改变必须重核验，JSON 不恢复确认权限。该对照已含在最终协议集合，不另累加。

质量检查：mypy 330 源文件、compileall、变更行/新增 Python Black 通过。1313 文件原文基线的阶段 diff 为 16 个已有文件修改、2 个新增测试；native 源码未改，工具与前轮实际构建输入一致，portable 构建脚本保持前轮摘要。86 个计划本地链接/锚点、12 个唯一任务号、10 个 RAPI ID、Markdown UTF-8 无 BOM/LF/末尾换行及新增行空白检查通过，21 原历史完整字节前缀与独立评估材料保留。各范围 JUnit、首轮失败、质量日志、工具/输入摘要和 diff 归档于 `/tmp/zscope-drain-acceptance-20261014/`。未 commit/push，实验规则默认关闭。当前匹配通知的受限 caller cond_wait 及对应局部增量验收完成；调用方超时/无通知/取消、通用 unregister/drain 和更广调度仍待办，完整实施计划保持进行中。

协议集合保留既有 record_property/JUnit xunit2 兼容提示；相应实际预处理和缓存测试已通过，不计失败，也不扩张为正式性能验收。

最终交接文档单独复验 **6 pass / 0 fail / 0 error / 0 skip**（`/tmp/zscope-drain-docs-final-20261014.xml`）；计划链接、编号、历史原文与工具/输入摘要再次核对通过，并同步归档最终 diff。

## 2026-10-14 并行实施增量：U02 子系统与 S09 开发准备

本节点保留上文全部历史，并以当前 dirty 工作树内容为集成输入，不把旧 HEAD 或历史重叠集合当作最终验收。协调记录与可执行 DAG 在 `coordination/2026-10-14/`：42 节点、11 层，保留 S00–S10/U01–U02/Q01–Q02 范围和既定启用条件。用户保留的 caller 无通知/超时分支没有由本轮重派、恢复、实现或绕过；对应代码/native/规则文件持续隔离。所有前端由 Astra 开发，后端和发布接线由协调者统一持有。

U02 轻量验收投影与独立处置由 Kimi 两个隔离分支交付，终态 observed model 均为 `volceapi/kimi-k3`；集成保留完整 finding 证据再投影 confirmed、business_conditional、pending、ruled_out。模型分数、缺复现、人工风险接受不授予确认/排除权限。覆盖缺口独立显示，未知计数为 null。项目内独立 SQLite 处置支持 duplicate/risk_accept/followup/clear；原子 revision、request_id 幂等和 context_revision 防止证据变化后数字版本0的旧草稿套用新范围。处置不修改报告证明、业务回答、suppression 或 Review Memory。

Astra 已亲自完成真实 Chromium/U02 HTTP 联调，输入报告明确为合成 fixture；四态、同位置跨构建、真实 SQLite、并发409、证据变化409、丢回包后的幂等重试与手机布局均有证据。新增静态字节已加入 FIRST_PARTY 和 SHA 锁，无新增 Tailwind utility 或网络重编。持久作业 Web adapter 复用同一轻量投影，核验本轮报告快照并区分工件摘要与复核 scope；其六例目前为明确契约 fixture，S08 owner 尚未接入，不将旧内存 scan 或 fixture 算 JOB01–JOB06 完成。

S09 的 `scripts/agent_plan_evaluation.py` 与测试由原 hw provider 的 ZCode `glm-5.3` 交付，实际 observed model 匹配。它只准备无答案矩阵、冻结既有报告/usage、比较同版本身份，不启动扫描/模型、不读 truth、不评分，不具备 formal/release 资格。协调审查曾复现编辑冻结 run 的 identity/counts 并保留旧 record_id 可绕过比较；原会话修复后加载重新核对内容摘要，report-manifest 绑定重新锚定报告，declared-only 不冒称实测。独立 Linux 修复集合 **33 passed/2.19s**，两新文件导入前核对931个继承输入均未改变。

最新根目录同次 Linux 集合 **147 pass / 0 fail / 0 error / 0 skip**（48.05秒，`artifacts/coordinator-u02-integration-20261014/results.xml`），覆盖 U02 真实浏览器/HTTP、配置准备、处置/投影、作业 adapter、S09 准备、文档与静态包装；不与此前79、86、118或其他集合累加。浏览器直接文件摘要与截图在同目录。compileall、mypy334文件、新增接线/测试 Black 已通过；mypy 首轮因尚未交付的 jobs 直接导入失败，改为明确可选加载后复验通过，原失败记录仍在协调 PROGRESS。

DeepSeek 简单只读文档与环境审计已交付，实际 observed `deepseek/deepseek-v4.1-flash`：旧导语七处落后于后续21记录，历史测试数保持不累加；WSL 中十项工具可解析、wpa/saber 无缺失共享库、editable 安装指向本仓库，既有 native SHA `d39cbe72…263399` 匹配。仅程序存在性/版本/ldd，不计真实扫描或 formal-ready。S01 与 S08 新会话曾有约307秒的模型请求超时和自动重试，后来恢复工具输入；running/thinking 不算交付，具体时刻以公开完整分页回执为准。

剩余范围明确未完成：S01全变体/符号/链接闭环、S08实际owner/时窗/续跑与作业浏览器联调、S07完整需求调度、S09真实准确率/性能和正式评测，以及其他DAG节点；S10/Q01/Q02仍按原条件。未运行真实 LLM扫描、完整Range/formal、真实自动复现、native重建或portable实物smoke。本节点不代表完整U01/U02/S09、主包或整体实施计划完成。未commit/push，已有修改保留，默认实验规则不变。

### 2026-10-14 15:00 UTC+8 增量复核

此记录覆盖上段旧阶段计数，不改历史：同一当前 root 源码集合 **370 pass / 0 fail / 0 error / 0 skip**，107.84秒（`artifacts/coordinator-u01-integration-20261014/results.xml`），直接源码摘要前后相同；包含真实 Astra U02 Chromium/SQLite、v2/v3 配置、S07 受控模型 shadow、S09 开发准备与作业 adapter。compileall、mypy335文件及 S09 脚本、新增文件 Black、静态锁默认只读核验通过。先前静态命令误写不存在的 `--verify` 的失败日志保留，已改正确默认入口复验；不与旧232/147/142/39/77集合累加，jobs仍为契约 fixture。

U01 v3 核心由原 hw/glm-5.3 的 ZCode 实现，四项 parser/schema 约束差异经原会话修复、独立142用例复核后受控导入；两个已有配置文件更新前逐字节匹配原 dirty 基线并备份。v3 根目录相对配置文件目录，保留 target 身份、多 target 执行明确拒绝，时窗解析为单次绝对边界；focus/reproduction/max_workers/platform 尚未消费，时窗未接 S08。完整 CLI/init/MCP/模板/prepare 与 UX 迁移仍未完成，不能从核心模型通过推导完整 U01。

S09 已用正式 read_report 解码当前 shared-json 对象图，缺引用/错误摘要/编码禁用 marker 拒绝；原始工件 SHA 保留。大报告依赖 ijson 本轮缺失，16MiB 合成输入实际 fail-closed，流式分支与正式评测未测。S01 原 Kimi 任务因 stalled 终态停止且无实现交付；用户明确授权普通 API 故障转交后，931文件未改的隔离分支由既定路由 ZCode 接续，当前仅实例边界开发，不冒称逐实例 Analyzer/Validator 贯穿。S08 首轮交付的 F1–F4 未修及降级断言未获验收；后续修复出现两次 APIEmptyResponseError（与旧 APITimeoutError 分开），13文件保全、正式取消终态和停止后字节/mtime稳定核实后转同一既定 ZCode 路由修复，未导入 owner。JOB04/JOB06、真实作业 HTTP/浏览器与整体 Kita 验收仍待完成。

### 2026-10-14 17:00 UTC+8 后端集成边界

S01 实例边界、U01 v3只读准备与 S08 owner/store/input/report 修复已受控导入。S01 拒绝 foreign BuildContext 与绕过显式文件；U01 多目标完整保留并禁止启动；S08 lost/spawn失败不丢 input_revision、PID重用/zombie与新attempt fresh fingerprint已核对，当前shared-json对象图正式解码。独立66/87/69集合不相加，真实HTTP/SQLite/detached owner控制样本3pass。同根后端集合493passed/174.03s、0skip，compileall/mypy347+S09/Black通过，直接源码前后同字节，证据 artifacts/coordinator-jobs-backend-20261014。UI正在变化的字节未进入此集合，旧370/86不能相加为当前整体验收。

Astra实际恢复工具与真实owner浏览器联调，使用明确受控scanner/合成报告、真实HTTP/SQLite/进程；其最终UI与全版本联合回归尚待固定字节。独立 CDB覆盖与公平队列 producer 各在965文件项目内隔离开发，暂未验收；不修改公共scan_session、不代做此前被拦caller任务。用户已确认旧S06-R02观察线程完成并归档，不作为待用户处理阻塞；本轮没有独立验收该交付或获准重试旧被拦实施。

本阶段不关闭完整S01、U01或S08：逐实例Analyzer/Validator/CDB全覆盖、完整配置入口迁移与实际协作窗口/公平remaining接线仍缺；真实模型扫描、完整增量质量/成本、formal Range/sealed/attestation、portable实物smoke与Kita整体最终验收未运行。S10/Q01/Q02原条件保留。应用更新后新的只读MCP快照显示两项新producer原进程丢失、failed/bridge_restarted；原产物保全、终态和输入字节核实后的原会话普通传输续接单独记录，不能把accepted当完成或实际模型证明。

## 2026-10-15 · R11 受限符号消费、MCP 持久作业与 UX 修复

S01 `task_0afb819799` 的受限符号消费者与 MCP `task_feb229984d` 已经协调者独立验收，分别 461 与 262 项通过、零跳过，源码冻结后按所有权导入；Astra UX r10 独立88项通过，3文件于01:29:51导入。各集合不相加。最终合并字节的联合结果独立记录在 `artifacts/coordinator-r11-all-intaken-20261015`，本段不代替该收据。

S01 首交付五项身份/失效反例失败、MCP 首交付四项 null 边界及一项 mypy 失败均保留；修复后重新独立验收。工具描述断言在派发基线及首交付完整36项文件中同样失败，协调者同步当前搜索契约并加强默认符号结果无正文检查，完整文件进入联合集合。Astra 修复首次可编辑业务前提仍被原生 fieldset 禁用的问题，真实 HTTP/SQLite 回答、撤回、第二客户端409、断网草稿和重连验证保留。

这些是明确边界的交付：完整 ScanSession/队列/checkpoint/公平剩余工作、契约 USR 传递及更广图/链接仍待接入。共享验证直接调用 ValidationRunner.run，单补 Analyzer 构造参数不足以绑定契约上下文。MCP result 尚无 findings 投影；受控 scanner/report/assumption 数据不代表真实项目扫描效果，formal/portable 与 S10/Q 条件扩展单列。未恢复旧 S06-R02、未提交或推送。

### 2026-10-15 R12：剩余工作计数修复与下一批执行

协调者修复 owner 将业务问题数写成 pending_count 的问题。收尾只读当前 job/input 的真实队列计数，缺失/损坏/异构绑定保留 null；pending、active、deferred 与业务 questions 分开，仍有剩余或 failed 项不发布 completed。真实 Linux owner/SQLite/合作截止及既有作业、MCP、HTTP 共190项通过，compileall/mypy/Black通过；证据为 artifacts/coordinator-shared-r12-acceptance-20261015/review.json。此计数修复不代表完整 ScanSession、checkpoint 或真实项目效果通过。

同源隔离副本已派发并实际执行 Kimi `task_1cee9c8e9d`（ScanSession/队列）与 ZCode `task_315195c1a1`（契约USR/验证上下文）；Astra `/root/astra_v3_editor_r6` 继续前端。尚无本批后端独立验收或整体完成结论，当前状态与集成后联合收据见 coordination/2026-10-14。未操作旧 S06-R02。

Astra R12 的剩余未知/业务问题独立呈现和新 run 迟到结果错误修复，经标题视觉返修后独验88项及质量通过，三文件受控导入；静态锁仅更新HTML/JS两项摘要。证据 artifacts/coordinator-astra-r12-title-acceptance-20261015/review.json，旧失败、初次独验与视觉hold均保留。真实HTTP/SQLite/owner/浏览器仍使用受控scanner/report，完整扫描效果与队列接线未因此关闭。
