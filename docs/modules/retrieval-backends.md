---
doc_contract: zscope-module-v1
covers:
  - zscope/retrieval
sources:
  - zscope/retrieval/code_index.py
  - zscope/retrieval/validation_facts.py
  - zscope/retrieval/lifecycle_analysis.py
  - zscope/retrieval/claim_paths.py
  - zscope/retrieval/knowledge_db.py
  - zscope/retrieval/clang_backend.py
  - zscope/retrieval/clang_batch.py
  - zscope/retrieval/indexing_identity.py
  - zscope/retrieval/indexing_inventory.py
  - zscope/retrieval/indexing_runtime.py
  - zscope/retrieval/bitcode_compile.py
  - zscope/retrieval/llvm_toolchain.py
  - zscope/retrieval/clang_extractor.py
  - zscope/retrieval/clang_resolution.py
  - zscope/retrieval/clang_derived_cache.py
  - zscope/retrieval/clang_source_snapshot.py
  - zscope/retrieval/compiler_compat.py
  - zscope/retrieval/compile_commands_prepare.py
  - zscope/retrieval/compile_preflight.py
  - zscope/retrieval/clang_extractor_pool.py
  - zscope/retrieval/joern_backend.py
  - zscope/retrieval/unified_backend.py
  - zscope/retrieval/java_source_backend.py
  - zscope/retrieval/java_unified_backend.py
  - zscope/retrieval/java_signal_providers.py
  - zscope/retrieval/svf_analyzer.py
  - zscope/retrieval/build_llvm.py
  - zscope/retrieval/bitcode_scope.py
tests:
  - tests/test_portable_runtime.py
  - tests/test_code_index_cache.py
  - tests/test_function_lookup_index.py
  - tests/test_review_fact_checks.py
  - tests/test_lifecycle_obligations.py
  - tests/test_clang_incremental_extraction.py
  - tests/test_clang_batch.py
  - tests/test_clang_batch_arguments.py
  - tests/test_compiler_compat.py
  - tests/test_compile_commands_prepare.py
  - tests/test_clang_source_snapshot.py
  - tests/test_clang_identity_validation.py
  - tests/test_clang_cache_pressure.py
  - tests/test_indexing_pipeline.py
  - tests/test_indexing_performance_audit.py
  - tests/test_clang_derived_reference_resolution.py
  - tests/test_clang_usr_resolution.py
  - tests/test_clang_lsp_transport.py
  - tests/test_knowledge_db_ir_and_config.py
  - tests/test_svf_cache.py
  - tests/test_joern_client.py
  - tests/test_java_source_backend.py
  - tests/test_svf_saber_parallel.py
  - tests/test_svf_memory_budget.py
  - tests/test_clang_extractor_pool.py
  - tests/test_build_llvm_lazy_plan.py
  - tests/test_partial_derived_rebuild.py
---

# 代码检索与后端

## 职责与非职责

本子系统负责把 C/C++ 或 Java 源码、编译数据库和外部分析器转换为可查询事实：函数、类型、调用边、AST/CFG、间接调用、指针/值流、结构/信号 provider 和缓存状态。`CodeIndex` 为上层提供统一门面；C/C++ 使用 regex、Clang、Unified，Java 使用 java_source 或 java_unified。

它不负责决定候选是否成为最终漏洞，不负责模型提示词，也不负责报告视图。

`lifecycle_analysis.py` 将编译器 AST 和路径分支转换为逐次获取的对象义务，复用扫描级事实缓存。义务绑定获取位置、编译上下文、对象赋值版本、资源族、池身份和契约版本；合法释放必须匹配同一对象与资源域。返回和未改写的输出参数可转移本函数义务，赋给全局/成员或传入不透明容器仍保留所有者清理缺口。循环、异常、汇编、未解析偏移和条件效果不完整时不得签发全路径反证。

生命周期事实 v2 的路径约束使用 `branch_taken` 布尔值记录条件成立或不成立，并保留表达式和源码行号。该版本参与事实缓存身份，旧版派生事实重新计算，不重做底层编译事实或语义建模。候选及完整事实通过检查点保存与共享引用重读时不得丢失分支信息；检查点仍拒绝 `truth`、评分标签等离线答案字段，不通过放宽隔离校验来兼容旧字段。

KnowledgeDB 的调用边查询枚举全部获取站点，不以同函数出现释放函数名过滤。名称查询仍可供检索使用；泄漏判断交由共享对象事实和 Validator。`claim_paths.py` 独立检查报告的操作是否能到达报告的观察点，不从互斥分支拼接锁状态，也不推断隐藏的加锁返回值。

## 主入口和数据流

- `CodeIndex` 负责源码发现、缓存、后端创建和统一查询接口。
- 函数查询的名称、限定名、模板变体和签名在内存索引构建时建立倒排索引；未命中及同名歧义查询只访问对应候选，不重新遍历全部函数。插入、替换、重建与关闭同步维护该索引；完整身份、候选排序、文件约束和歧义语义保持一致。该索引不属于可淘汰的查询缓存。
- 头文件 API 枚举按名称检查是否存在实现，保留歧义候选；类作用域每文件计算一次，跨行声明通过行偏移查找坐标，重叠文件模式不重复扫描。函数名称索引构建及头文件发现阶段每 30 秒输出独立心跳，头文件进度包含当前文件、行和已检查声明数。
- Clang extractor/backend 分阶段写入基础 TU 事实和可重建的函数 symbol/type 派生引用。
- `indexing.clang.frontend` 支持 auto/batch/lsp。独立 LibTooling 工具按选定 TU 同次解析生成基础与派生事实；原始事实包保留编译上下文，公共文件视图不混合不同宏环境。成功批量 TU 不再通过 LSP 查询派生引用，失败/未覆盖文件在 auto 中显式回退。部署与验收见 [批量索引指南](../clang-batch-indexing.md)。
- 批量 Clang 在 INFO 按 30 秒汇总进度并保留阶段结束日志；逐 TU 和逐进程指标在 DEBUG 查看。同类失败每轮仅展示前 3 个 WARNING 样例，全部失败和资源指标仍保存在缓存报告/清单中，回退前报告即落盘。编译工作目录允许位于源码范围外，但必须完整可达，不得替换 cwd 改变相对编译参数的含义。
- 批量参数策略固定忽略 `-Werror` 的警告提升，并按 Clang 结构化诊断剔除未知选项后最多重试一次；原始参数和响应文件保持不变。成功必须通过驱动及前端的错误诊断校验，失败首轮事实不得混入重试结果。调整参数、尝试次数和失败原因随 TU 清单保存，缓存包含策略版本，旧能力工具不能绕过校验。详见批量索引指南。
- auto 的 batch 回退只提前补齐基础事实及 symbol context；type refs 由统一后台调度器逐函数补齐，消费者提升同一个任务的优先级，不另开扫描。显式 lsp 保持提前构建；没有新增 YAML 配置。
- `KnowledgeDB` 持久化代码事实和后端 IR，并维护版本化查询缓存。
- Java source backend 提供方法、注解和框架结构；java_unified 叠加 SootUp、WALA、Joern provider evidence。Java source、java_unified 与 Joern 同时提供可枚举的类型记录，保留完整限定名和定义起止行，供 `SymbolCatalog` 建立可读取的 type `symbol_id`。
- C/C++ Joern 在 1.x 中仅为弃用兼容入口，不属于默认或离线 C 工具链。
- Unified backend 组合 Clang 与 SVF；bitcode scope、LLVM 构建和 SVF runner 负责入口裁剪、链接与分析。
- SVF 执行受三项性能机制约束：按组堆预算预检（超预算组跳过并保留降级语义）、saber 分组并行的堆上界 worker 池，以及可选的 scope-first 惰性位码构建（先按 KnowledgeDB 规划所需 TU，再只编译这些 TU）。
- Clang 基础抽取可通过 Z_SCOPE_CLANGD_SHARDS 选择多实例 clangd 分片池；派生索引部分重建按 include 闭包把重建范围缩小到受影响的函数文件。
- 上层候选和 Tool runtime 只消费统一查询结果，不应依赖某个后端的私有输出文本。

## 必须保持的不变量

- 实验性 `CompleteFactStore` 补存完整 Clang AST、按函数隔离的 CFG、预处理输出和宏分支树。事实身份绑定 TU、依赖文件、编译命令、编译器与影响头文件／宏的环境；未绑定的响应文件或插件配置返回 unknown。旧摘要存储仍保持兼容，不反向冒充完整事实。
- 首版只为与事实编译器绑定的 Clang driver 签发证明；GCC、编译包装器、预编译头和模块尚无等价性适配时返回 unknown，不能把替换编译器后的宏或 ABI 当作当前构建。CFG 身份同时隔离编译单元和函数；无法解释的边保留不完整状态。
- 模型通过 `ast_nodes`、函数、类型、CFG 和宏分页查询；`display_truncated` 与底层 `complete` 分开。页读完只表示当前查询耗尽，不能推断全程序路径完整。程序检查器直接读完整载荷并校验依赖，磁盘文件自带正确摘要也不等于编译器来源。
- 宏记录保留嵌套条件、重定义、undef、别名与空操作；编译器预处理结果确认实际执行的定义，使用点语义以 AST 的展开位置为准，不能以文件末尾定义替代。非当前分支只作条件风险。调用覆盖表核对实际参数；当前常量区间可确认单个调用点，间接调用、公开入口和符号关系未闭合时仍为 unknown。

- 后端能力不足必须返回明确的空结果、告警或降级状态，不能伪造完整能力。
- Java provider 信号只能进入 Java 分析路径；CodeQL 为 BYO，不得进入官方依赖包。
- Java Spoon 默认复用已准备的本地 Maven 缓存，不隐式强制联网刷新；显式刷新只允许发生在联网准备阶段，sidecar 不得在目标项目遗留 `spoon.classpath.tmp`。
- 日常 Joern WebSocket 查询必须有总量可控的超时和重试边界；CPG import 可以使用独立的长时限，不能把一小时等待传播到普通入口查询。
- 基础增量索引只以文件哈希、TU 状态、删除影响和基础 extractor 版本为依据；`indexed + hash unchanged` 的 TU 不得因为派生索引版本或生命周期变化而重新执行 `extract_tu()`/`documentSymbol`。
- `function_symbol_context` 与 `function_type_refs` 的整体生命周期保存在 metadata JSON 中；schema v15 增加 `function_type_ref_state`，区分单函数 pending/in_progress/current/failed。后台未完成时后端可以 ready，但整体 type refs 不能标记 current。函数事实与状态在同一事务按代次及尝试标识发布，旧任务不得覆盖新代次。
- 提前构建沿用调用方写 TEMP staging；后台类型引用由进程内同一 KnowledgeDB 的唯一协调线程拥有连接并发布，worker 只收集结果。前后台共用一个解析执行槽位；最多保留有界数量的挂起函数栈，在 RPC 成功进入缓存后、每批本地候选处让出执行权。辅助缓存不能持有一个挂起任务拥有、另一任务等待的 Future。
- 消费者各自最多等待 300 秒；某个等待者超时不取消其他等待者的任务，全部离开后降回后台。函数信息枚举不触发类型收集；快照先定位唯一函数再取上下文，执行失败通过 `TypeContextUnavailable` 转成快照输入失败，不能当作空类型列表。
- 函数检查点与文件检查点隔离，坐标及 semantic tokens 的成功 RPC 结果有界缓存并落盘；完整输入身份与类型目录按会话共享。依赖证明不足禁止跨进程恢复，源文件、头文件、编译参数或基础代次变化拒绝旧结果。可重试的临时 RPC 错误在新尝试前清除，不成为永久负缓存；clangd 进程故障暂停整条队列，后续消费可触发合并重试。
- 基础重建及 SVF 阶段先暂停调度并释放 clangd，结束后恢复；单纯等待者超时不停止进程。无可运行任务时空闲 60 秒释放，退出保存已完成证据与待办，不等待全量补齐；先结束协调/收集线程，再关闭数据库。心跳按 30 秒汇总，停止时输出 `clang_type_refs_report.json`。
- clangd JSON-RPC 必须使用单调时钟硬超时和事件唤醒，正确回复 server request，并以 work-done token 跟踪 background indexing；索引等待超时不得继续标记后端 ready。
- symbol/type 引用采用逐文件 semantic tokens 过滤、使用位置 symbolInfo/USR 与精确声明坐标、definition/declaration 回退。仍未闭合时，优先从使用位置按 USR 查询包含声明的 references，并精确匹配库内声明；最后才按候选声明补证，且只给实际命中的声明查询 USR。禁止在补证前预取整个同名组的声明 USR。完整 symbolInfo 多结果不得取第一项；USR 缺少库内映射不代表外部符号；include closure 不能作为硬排除依据。仅 C 文件自身拥有的唯一全局定义与实际全局作用域 token 可走局部快路径。
- 基础 TU 刷新应把 clangd/源码收集与 SQLite 发布分开：跨文件查询使用有界并发，KnowledgeDB 由单写者按 TU SAVEPOINT、按批次单次提交；收集或发布失败不得先清空旧事实。
- 派生引用必须使用有界、线程安全的缓存：两类派生索引同时失效时按文件合并 semantic pass；同一使用坐标及声明补证使用 single-flight，锁不得跨越 clangd RPC。热缓存按序列化字节预算淘汰，冷结果落到独立 SQLite sidecar；worker 通过有界请求队列访问缓存，只有调度线程读写 SQLite，等待必须由事件唤醒。解析中的歧义集合不能依赖 LRU 是否仍保留某个结果。
- 声明坐标的 symbolInfo/references 必须持有 document lease，按文件有界复用。RPC 错误、成功空结果、超时和截断分别计量；references 达到显式返回上限或索引未就绪时不能用未命中消除歧义。逐位置 RPC 保留行列及协商的位置编码，不使用任意放宽的行号窗口绑定，也不把同名成员误匹配到外层声明范围。
- 已确定单一 USR 的使用位置 references 可提供同一身份的正向声明证据，即使返回量触顶；只接受准确声明选择位置，不能从普通使用位置推断声明，也不能从空或截断结果否决其余候选。使用文件的 lease 从首次解析 RPC 保留到补证和事实收集结束，候选文档不能淘汰它。`declarationProvider` 与 MethodNotFound 按 clangd 进程代次适配。
- 派生会话每 30 秒独立输出 `derived-heartbeat`：已完成/总文件数、活跃文件及阶段、候选补证进度、当前 RPC/文档及耗时、请求增量、缓存队列和 RSS。心跳覆盖收集后的源码校验、构建身份校验及缓存关闭；文件全部完成不代表已完成发布校验。SQLite 执行时间与 worker 排队时间分别累计，排队时间不能直接加作墙钟耗时。心跳不能依赖文件完成或 SQLite 调度线程，也不得自行发送 RPC；单 worker 和所有 worker 等待请求时同样有效。
- `clang_derived_cache.sqlite3` 位于实际 KnowledgeDB 同目录，拥有独立 schema，不改变主库版本。坐标、USR 身份映射、references 和分索引的文件检查点按完整构建身份隔离。检查点保存事实和完成状态；旧已发布事实保持可读，恢复结果仍经 TEMP staging 原子发布。
- 持久恢复必须证明输入一致：构建身份覆盖源码/依赖内容、编译数据库、clangd 身份、位置编码、基础事实和分析范围。首版仅对带 `arguments`、完整 `-MD` 依赖文件且依赖未过期的编译数据库启用跨进程恢复；`command` 字符串、`-MMD`、缺少/过期依赖或覆盖不全时保守禁用跨进程复用，仍保留本轮磁盘缓存。错误结果只存在会话 TEMP 表。发布前重新核对输入摘要，变化时停止发布。
- 构建输入清单与惰性的头文件查找目录分离：只由分析选定文件、编译命令、依赖清单、基础事实及已知 include 路径构成，不把查找目录中的日志、数据库或其他扫描生成物自动当作输入。batch 回退在基础抽取前复用既有源码清单，分片同步预置，避免再次全目录遍历。真实依赖不按后缀或缓存目录名排除；保留符号链接目标校验。身份校验按文件、编译数据库、基础表和运行上下文记录摘要；失败日志报告变化总数及至多八个具体项目，不输出源文件或编译参数内容。身份算法升级仅使派生缓存失效，不重抽未变化的基础 TU。
- LSP transport 的读写、排队和等待都受同一 monotonic deadline 约束；死进程 generation、document lease、UTF position encoding 和 source-lines 缓存必须保持线程安全。
- KnowledgeDB 写入新事实后必须使相关查询缓存失效。
- Unified 的 Clang 与 SVF 结果必须通过稳定的文件、函数和位置坐标缝合。
- bitcode 裁剪、符号闭包、共享/互斥 pool 和回退原因必须保留 manifest 供审计。
- WPA/Saber worker 只执行工具并返回结果；协调线程负责检查点、状态及 KnowledgeDB 导入。并发同时受 CPU、容器限制与当前可用内存 75% 的总预算约束；每进程预留完整 `heap_limit_mb`，不能把单进程堆预算当作所有 worker 共享额度。
- bitcode 缓存必须校验源文件、实际头文件、搜索目录、编译参数及工具身份；无依赖证明不得持久复用，禁止仅按时间戳判断有效。普通 TU 由匹配 llvm-link 主版本的 Clang 直接生成 bitcode，包装器保留 gllvm 路径。WPA/Saber 成功产物按内容、工具、模型和分析参数复用，worker 数变化不使成功结果失效；每个组仍有独立的导入状态。
- 创建 TU/bitcode 任务及启动 clangd 前，`compile_commands_prepare` 在真实数据库路径的进程间锁内备份并原子改写原始 `compile_commands.json`；三条后端共用有效命令及同代准备凭据。`directory/file/output`、条目顺序和变体不变，改写条目使用 `arguments`。同目录 `.zscope-compile-commands/` 保存按摘要寻址的不可覆盖备份、报告、预检缓存及兼容响应文件；原始响应文件不改动且继续参与失效校验。无变化不更新时间戳，策略、工具或响应文件变化从原始备份重新处理。
- 参数策略 v3 消除命令行 warning 提升（含 pedantic、旧式 implicit-function 及汇编器/链接器转发），保留普通 warning。Linux x86_64 上下文移除选项位置的遗留 `-m32` 并补 `-m64`；显式冲突 target/x32 在改写前失败，其他架构不套用此修正。参数操作数、项目宏、sysroot 和真实源码错误不能当作不兼容选项删除。
- `compile_preflight` 按实际工具、语言、目标、目录、环境和参数上下文合并检查，并发不超过 4。批量工具 `--check-arguments` 使用绑定 SDK 的 driver/CompilerInvocation/诊断选项解析，独立 SVF 使用配套 Clang 的 driver dry-run 和 cc1 help 参数检查；两者均不解析真实 TU、不生成 AST/对象/bitcode。每组每工具最多两轮，共享 10 秒；只能持久复用已验证的未知参数修正。扩展参数、超时及缺少检查能力记录 unverified；clangd 身份单独记录，不声称 Clang 18 的预检覆盖 clangd 22。
- 当前扫描代次不再改写公共数据库；后台类型任务复用准备凭据，原始/兼容响应文件加入会话输入监测，禁止逐函数重新哈希整个数据库。显式基础刷新先停止旧任务，再准备新代次。运行阶段 batch、直接 Clang 和 gllvm 仍保留一次真实诊断重试，调整仅限本任务；优化、调试及输出参数仍属于各自阶段。gllvm 子编译器诊断独立落盘，失败首轮产物不发布，第二轮失败仍进入 failed_tus。
- 派生位置解析复用会话路径与源码快照，文件系统校验放在任务/发布边界；路径、文件版本和符号链接目标变化拒绝旧结果。快照与现有缓存共用字节预算，路径/版本元数据与源码正文分别保留容量；坐标直接从当前快照转换，不为每个坐标建立缓存项而挤掉源码工作集。冷快照只在会话 TEMP 表保存，任务校验和检查点按批读取轻量版本凭据，不为校验反复载入正文。文件检查点仅在完成校验成功后保存，发布前仍重新校验。symbol context 完成后才交接后台类型收集，交接日志与消费者等待日志明确区分。
- 派生缓存使用同一预算内的固定大小存在性过滤器，跳过已证明不存在的新键的 SQLite 查询；过滤器命中仅表示可能存在，必须继续查真实缓存。恢复时先装载全部已持久化键，过滤器误判或饱和不能改变绑定及失效结果。JSON 解码不得持有共享登记锁；统计分别报告 SQL 查询数、读取/写入字节及被跳过的空查询。
- 输入目录校验只排除分析器拥有的缓存和数据库文件；同一目录中的真实头文件、其他缓存目录里的构建输入仍参与失效判断。
- 输入校验按校验轮次合并同键读取；哈希和目录 IO 不持有全局登记锁，不同输入可并行校验。新一轮及发布前仍使用新的校验器，不跨轮次复用内容或目录状态。
- batch 导入的路径和 USR 绑定结论在有界缓存中复用，溢出落到会话临时 SQLite；类型绑定键包含定义布局摘要，不按名称跨宏环境复用。宏引用不查询类型身份表；发布前重新检查已用路径的符号链接目标。
- 原生批量工具按文件预计算函数归属区间，引用位置通过区间索引查找，不逐引用扫描全部函数；嵌套范围选最小包含区间，同跨度保持原声明顺序。
- 派生缓存协调线程等待 worker 的共享计算时必须继续泵送 SQLite 请求，避免 worker 等待 SQLite、协调线程等待 worker 的循环等待。
- TU、链接与分析产物原子保存。失败、超时、内存不足和缺失 TU 均不得标为完整成功；校验、编译、链接、求解、等待和导入由独立心跳报告。盘点输出区分编译上下文、源文件和 bitcode/分析任务，不用文件大小或源码行数推断求解时间。
- WPA 内存预算预检按合并后 .bc 体积估算 Andersen 内存；被跳过的超预算组必须记录 `skipped_memory_budget` 工具状态并维持降级（had_timeout）语义，不得伪装成完整成功；`Z_SCOPE_SVF_BC_MEMORY_FACTOR`（<=0 关闭预检）只调缩放系数。
- 惰性位码构建（`Z_SCOPE_SVF_LAZY_BITCODE`，默认关闭）的规划只能使用 KnowledgeDB 事实与预期 bc 路径：规划失败、空计划或 full 模式必须回退全量编译；编译后的符号闭包只能在已编译集合内补链，选择、闭包与链接仍以真实编译产物为准。
- 派生索引部分重建仅在所有脏索引的 `dirty_reason` 均为 `base_facts_changed`、存在真实基础变更且受影响函数文件不超过候选一半时启用；merge 发布必须完整替换受影响文件的行且不触碰其他文件行；extractor 版本升级、purge/清理与失败重试保持全量重建。
- clangd 分片池只扇出基础抽取与延迟调用边；SQLite 发布保持调用方单写者事务，派生索引重建固定路由到主分片。
- 遍历目标项目时要容忍权限错误和无效链接，但不能越过配置的源码范围读取敏感路径。

## 常见变更应落到哪里

- 新索引查询或缓存：`code_index.py`、`knowledge_db.py`，同时更新调用工具测试。
- Clang AST/CFG 或增量行为：`clang_extractor.py`、`clang_backend.py`。
- Joern CPG 查询：`joern_backend.py` 和公共 Joern client。
- SVF/Saber、bitcode 或工具发现：`svf_*`、`build_llvm.py`、`bitcode_scope.py`。
- 多后端合并和能力 gate：`unified_backend.py`、`backend_base.py`。

## 对应测试与验证命令

```bash
python -m pytest -q tests/test_code_index_cache.py tests/test_clang_incremental_extraction.py tests/test_clang_derived_reference_resolution.py tests/test_clang_lsp_transport.py
python -m pytest -q tests/test_clang_usr_resolution.py
python -m pytest -q tests/test_clang_cache_pressure.py tests/test_clang_source_snapshot.py tests/test_indexing_performance_audit.py
python -m pytest -q tests/test_knowledge_db_ir_and_config.py tests/test_svf_cache.py
python -m pytest -q tests/test_joern_client.py tests/test_bitcode_scope.py
python -m pytest -q tests/test_svf_saber_parallel.py tests/test_svf_memory_budget.py tests/test_clang_extractor_pool.py
python -m pytest -q tests/test_build_llvm_lazy_plan.py tests/test_partial_derived_rebuild.py
```

`scripts/profile_clang_derived.py` 在基础 KnowledgeDB 的独立副本上运行固定文件集合与不同 worker 数，保存方法请求量/错误/延迟、缓存、进程 RSS、恢复情况及稳定事实摘要；不运行 LLM、不删除 clangd 缓存。`--file-limit 0` 选择全部函数文件，`--files` 可重放固定 JSON 文件列表。对比时区分 clangd 缓存状态、派生冷重建和检查点恢复，不能将样本结果或本机线程扩展效率宣称为目标大项目的提速倍数。

`scripts/profile_clang_cache_pressure.py` 重放小内存预算、多文件和多 worker 的源码坐标及缓存负载，可通过 `PYTHONPATH` 对比两个源码快照。它核对结果摘要并记录 SQLite 请求、等待和缓存淘汰，不执行 clangd；结果仅说明 Python/缓存路径的开销，不能替代客户范围的完整索引性能验证。

## 权威源码和关联文档

函数调用的声明位置和定义身份需要分开处理。Clang 调用边指向头文件（包括 `.ph`）时，函数元数据可解析到唯一、签名兼容的非静态项目定义，供入口可达图和语义建模共用；源码文件约束、静态同名函数与重载歧义不能通过名称回退消除。原生跨文件调用测试覆盖这一边界。

- 稳定入口见本文 frontmatter 的 `sources`。
- 后端定位与能力矩阵见 `README.md` 和 `docs/architecture.md` 的“事实平面”。
- WSL 特有问题见 `.agents/workflows/wsl-pitfalls.md`；原生 Linux 不应套用 WSL/NTFS 假设。

## Portable 后端资源

C/C++ Portable 包内的 `zscope-clang-indexer` 使用锁定的 LLVM 18 SDK 构建，默认 `auto` 前端直接定位包内启动器；严格 `batch` 模式失败不降级。显式选定的批量工具缺失或协议不兼容时直接报错，不静默启动 LSP。批量组件的原生库和 resource headers 随包安装，客户端无需开发 SDK。发布验收同时检查批量引用、宏/类型/调用边和成功 TU 的零 LSP 请求及缓存复用。

Portable 的 clangd 22.1.7 索引环境与 LLVM 18.1.0 / SVF 3.2 bitcode 环境分开，启动器为 gllvm 明确指定 LLVM 18 工具。Java 结构与信号后端优先加载包内预编译 JAR；portable 中外部结构提取失败不回退 builtin，显式自定义命令失败也不回退。Spoon 仍遵守 Maven 项目前提。Java Maven 缓存位于用户可写目录，工程依赖导入与离线分析共用该缓存。

工具调用保留启动器的命令名（包括 `clang++`）；ELF 依赖、工具摘要和缓存身份检查通过 bundle manifest 定位其实际二进制，同时记录启动器摘要。不能把共享启动器解析后的文件名用作编译命令，也不能对 shell 启动器执行 `ldd` 来推断 SVF 的 LLVM 版本。

## 程序事件与共享分析缓存

批量 Clang 协议 `zscope.clang-facts.v2` 在原有 TU 解析中提取函数 CFG、语句/表达式位置、new/delete 家族及带 USR 的全局/字段访问，不为每个候选另启编译器。内部 `zscope.program-events.v5` 记录形式参数身份、稳定 event/value identity、逐事件 defs/uses、逐实参 uses、声明初始化、赋值/复合赋值/增减、嵌套调用、调用结果、return 和 CFG condition/guard。`function_program_facts` 随同其他事实表事务发布；CFG 构建失败或函数身份不唯一时显式返回不完整。v4 及更早事实不得用于 source-to-sink 推断；`ProgramEvents.h` 纳入 portable batch 组件指纹，协议变化必须真实重建二进制。

六工具的符号入口由 revision-aware `SymbolCatalog` 统一生成 `zs1:<kind>:<24-hex>` ID，摘要绑定 kind、限定名、项目相对文件、定义范围和签名。函数重载、静态同名函数和 Java 方法不能通过名称清洗合并。宏搜索优先读 KnowledgeDB，缺失时按项目 include/exclude 与敏感路径策略扫描源码；函数式宏和 object-like 宏均可检索。object-like 直接字面量只规范化括号、正负号、整数进制/suffix、浮点、字符串、字符和布尔值，不递归展开或计算表达式。

`FlowQueryService` 直接在 v5 facts 上做 reaching-definition 和有界路径搜索，并以 direct argument→parameter、callee return→caller result 以及真实存在的 SVF resolved callsite 连接跨函数证据。唯一 reaching definition、直接身份、无未知 guard/间接分派/may-alias 时才可标记 `must`；否则为 `may`。当前 SVF 数据库没有通用完整 alias 查询时必须报告 `coverage.details.alias=unavailable`，不能合成别名结论。Java 只有 Joern parameter→sink 路径映射为 flow；source/java_unified 明确返回 `unsupported`。

KnowledgeDB 的 IR 语句身份包含列号和事件序号，升级保留既有语句 ID 及边引用。同一扫描的 Graph 函数事实和锁边通过有容量上限的共享缓存复用，同一键的并发请求只运行一个生产者。缓存身份包含源码/索引版本和语义上下文；入口可达性单独计算，锁顺序反转使用反向锁对索引，模糊别名仍需核验。

语义建模阶段通过线程隔离的 `semantic_modeling_context` 读取完整 callee、宏、全局对象和类型定义，绕过工具展示用的数量与定义字节限制。作用域退出后恢复原查询预算；真实后端缺失或截断仍作为 partial 覆盖记录。

宏体中的标识符只是检索线索；全局载体由索引中的声明或定义绑定，排除其他翻译单元的静态对象，歧义保持未知。无参锁宏因此携带实际全局对象进入建模及工作簿发布，不能从宏名称或描述推断锁身份。

契约源码组合包含条件表达式中的接口调用，并区分每次调用的结果。内部锁配对按成功路径检查，失败即返回的路径不等于对外持锁；无法解析的短路副作用不视为完整覆盖。声明左值、成员左值和输出参数分别解析，防止返回状态别名或载体路径丢失。

原生类型身份将匿名 typedef 的成员引用绑定到其真实 typedef 声明，并单独登记嵌套或局部匿名类型。保留原始引用 USR；布局哈希包含 typedef 底层展开定义，不把不同编译宏下的布局相互投影。类型缺口不能靠同名搜索或人工接口确认消除。

- 批量投影以当前编译单元代次替换程序事件，源码位于项目根目录时也使用统一的 TU 相对路径；迁移旧绝对路径登记后撤销旧调用位置和已删除函数。重新发布原子提交，失败仍保留上一完整代次。
