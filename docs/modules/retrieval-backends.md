---
doc_contract: zscope-module-v1
covers:
  - zscope/retrieval
sources:
  - zscope/retrieval/code_index.py
  - zscope/retrieval/instance_index.py
  - zscope/retrieval/cached_index.py
  - zscope/retrieval/validation_facts.py
  - zscope/retrieval/lifecycle_analysis.py
  - zscope/retrieval/raii_lifecycle.py
  - zscope/retrieval/claim_paths.py
  - zscope/retrieval/knowledge_db.py
  - zscope/retrieval/clang_backend.py
  - zscope/retrieval/clang_batch.py
  - zscope/retrieval/indexing_identity.py
  - zscope/retrieval/build_context.py
  - zscope/retrieval/link_targets.py
  - zscope/retrieval/indexing_inventory.py
  - zscope/retrieval/incremental_replay.py
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
  - tests/test_native_source_roots.py
  - tests/test_mcp_read_only.py
  - tests/test_portable_runtime.py
  - tests/test_code_index_cache.py
  - tests/test_function_lookup_index.py
  - tests/test_review_fact_checks.py
  - tests/test_lifecycle_obligations.py
  - tests/test_raii_lifecycle.py
  - tests/test_clang_incremental_extraction.py
  - tests/test_clang_batch.py
  - tests/test_build_context.py
  - tests/test_instance_analysis.py
  - tests/test_full_symbol_build_scope.py
  - tests/test_instance_symbol_native.py
  - tests/test_link_targets.py
  - tests/test_linked_lifecycle_paths.py
  - tests/test_compilation_symbols.py
  - tests/test_handle_protocols.py
  - tests/test_clang_batch_arguments.py
  - tests/test_compiler_compat.py
  - tests/test_compile_commands_prepare.py
  - tests/test_clang_source_snapshot.py
  - tests/test_clang_identity_validation.py
  - tests/test_clang_cache_pressure.py
  - tests/test_indexing_pipeline.py
  - tests/test_incremental_replay.py
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

批量 native 工具记录依赖和 include 查询路径时先解析实际符号链接，再处理父目录语义；不能词法消去 `/lib` 等符号链接后的 `..`。usr-merged Linux 上 GCC 的 C++ 系统头搜索路径否则会被错误登记成 `/include/...`，使真实依赖摘要无法核验。尚不存在的配置搜索根按当前存在的前缀解析，收据另保留原拼写，不伪造已存在文件。此修复须实际重建工具，旧二进制不包含修复。

## 职责与非职责

本子系统负责把 C/C++ 或 Java 源码、编译数据库和外部分析器转换为可查询事实：函数、类型、调用边、AST/CFG、间接调用、指针/值流、结构/信号 provider 和缓存状态。`CodeIndex` 为上层提供统一门面；C/C++ 使用 regex、Clang、Unified，Java 使用 java_source 或 java_unified。

它不负责决定候选是否成为最终漏洞，不负责模型提示词，也不负责报告视图。

只读 MCP 通过 `CachedCodeIndex` 打开项目内已有 KnowledgeDB，只提供标明未核验新鲜度的函数导航信息，不初始化 CodeIndex/Clang/SVF/Joern。缺少完整输入身份的旧图与数据流缓存返回 unavailable，不自动补全；文本/文件检索由独立源码读取内核提供。正常后端选择和索引流程保持不变。

`lifecycle_analysis.py` 将编译器 AST 和路径分支转换为逐次获取的对象义务，复用扫描级事实缓存。义务绑定获取位置、编译上下文、对象赋值版本、资源族、池身份和契约版本；合法释放必须匹配同一对象与资源域。返回和未改写的输出参数可转移本函数义务，赋给全局/成员或传入不透明容器仍保留所有者清理缺口。循环、异常、汇编、未解析偏移和条件效果不完整时不得签发全路径反证。

生命周期事实 v2 的路径约束使用 `branch_taken` 布尔值记录条件成立或不成立，并保留表达式和源码行号。该版本参与事实缓存身份，旧版派生事实重新计算，不重做底层编译事实或语义建模。候选及完整事实通过检查点保存与共享引用重读时不得丢失分支信息；检查点仍拒绝 `truth`、评分标签等离线答案字段，不通过放宽隔离校验来兼容旧字段。

KnowledgeDB 的调用边查询枚举全部获取站点，不以同函数出现释放函数名过滤。名称查询仍可供检索使用；泄漏判断交由共享对象事实和 Validator。`claim_paths.py` 独立检查报告的操作是否能到达报告的观察点，不从互斥分支拼接锁状态，也不推断隐藏的加锁返回值。

## 主入口和数据流

KnowledgeDB 的大规模可达函数过滤与编译命令归属查询保持 SQLite 3.8.10.2 兼容，不依赖 JSON1。查询不写临时表，可在 query-only 连接使用；大量命令标识按参数上限分批处理，仍返回每条命令的全部构建上下文。

bitcode 编译以源码编译前后的文件身份、修改/变更时间及摘要核对当前性，允许原先已在未来的源码时间戳，但同内容改写并恢复 mtime 仍失效。该校验版本进入产物指纹；编译后才发现的头文件继续使用保守时间检查。同一源码因多个最终目标产生多条编译命令、且所得 bitcode 字节完全相同时，SVF 合并只向 `llvm-link` 传一份物理内容，但 link receipt 保留全部逻辑输入和 command identity，相关信号按多变体归属；不同源码或不同 bitcode 的重名定义仍失败，不能靠去重隐藏真实链接冲突。合并前若发现仍有强外部符号重复，则直接记录 `observed_link_target_required` 并拒绝构造跨最终目标的虚假链接；fast 仍执行本地/TU 静态分析，但 SVF/backend degraded 与 link coverage gap 会阻止 formal qualification。balanced/deep 不因此放宽后端要求。

- `CodeIndex` 负责源码发现、缓存、后端创建和统一查询接口。
- 函数查询的名称、限定名、模板变体和签名在内存索引构建时建立倒排索引；未命中及同名歧义查询只访问对应候选，不重新遍历全部函数。插入、替换、重建与关闭同步维护该索引；完整身份、候选排序、文件约束和歧义语义保持一致。该索引不属于可淘汰的查询缓存。
- 头文件 API 枚举按名称检查是否存在实现，保留歧义候选；类作用域每文件计算一次，跨行声明通过行偏移查找坐标，重叠文件模式不重复扫描。函数名称索引构建及头文件发现阶段每 30 秒输出独立心跳，头文件进度包含当前文件、行和已检查声明数。
- Clang extractor/backend 分阶段写入基础 TU 事实和可重建的函数 symbol/type 派生引用。
- `indexing.clang.frontend` 支持 auto/batch/lsp。独立 LibTooling 工具按选定 TU 同次解析生成基础与派生事实；原始事实包保留编译上下文，公共文件视图不混合不同宏环境。成功批量 TU 不再通过 LSP 查询派生引用，失败/未覆盖文件在 auto 中显式回退。部署与验收见 [批量索引指南](../development/clang-batch-indexing.md)。
- 批量 Clang 在 INFO 按 30 秒汇总进度并保留阶段结束日志；逐 TU 和逐进程指标在 DEBUG 查看。同类失败每轮仅展示前 3 个 WARNING 样例，全部失败和资源指标仍保存在缓存报告/清单中，回退前报告即落盘。编译工作目录允许位于源码范围外，但必须完整可达，不得替换 cwd 改变相对编译参数的含义。
- 批量参数策略固定忽略 `-Werror` 的警告提升，并按 Clang 结构化诊断剔除未知选项后最多重试一次；原始参数和响应文件保持不变。成功必须通过驱动及前端的错误诊断校验，失败首轮事实不得混入重试结果。调整参数、尝试次数和失败原因随 TU 清单保存，缓存包含策略版本，旧能力工具不能绕过校验。详见批量索引指南。
- auto 的 batch 回退只提前补齐基础事实及 symbol context；type refs 由统一后台调度器逐函数补齐，消费者提升同一个任务的优先级，不另开扫描。显式 lsp 保持提前构建；没有新增 YAML 配置。
- `KnowledgeDB` 持久化代码事实和后端 IR，并维护版本化查询缓存。
- Java source backend 提供方法、注解和框架结构；java_unified 叠加 SootUp、WALA、Joern provider evidence。Java source、java_unified 与 Joern 同时提供可枚举的类型记录，保留完整限定名和定义起止行，供 `SymbolCatalog` 建立可读取的 type `symbol_id`。
- C/C++ Joern 在 1.x 中仅为弃用兼容入口，不属于默认或离线 C 工具链。
- Unified backend 组合 Clang 与 SVF；bitcode scope、LLVM 构建和 SVF runner 负责入口裁剪、链接与分析。
- SVF 执行受三项性能机制约束：按组堆预算预检（超预算组跳过并保留降级语义）、saber 分组并行的堆上界 worker 池，以及可选的 scope-first 惰性位码构建（先按 KnowledgeDB 规划所需 TU，再只编译这些 TU）。
- Clang 基础抽取可通过 Z_SCOPE_CLANGD_SHARDS 选择多实例 clangd 分片池；派生索引部分重建按 include 闭包把重建范围缩小到受影响的函数文件。
- LSP 基础抽取也在替换旧事实前检查已有非系统 include 闭包：已扫描头文件修改或删除时，将传递依赖的当前 TU 标为 pending，重新抽取函数和调用边等基础事实；无关 TU 保留热缓存。此机制依赖已记录的 include 边，不等同于 native 的完整依赖与否定查找收据。
- 上层候选和 Tool runtime 只消费统一查询结果，不应依赖某个后端的私有输出文本。

## 必须保持的不变量

- native 程序事件的 `cfg_entry`/`cfg_exit` 显式标识 CFG 边界，不能以最大 block 或入度猜测被常量剪枝后的入口。`zscope.lifecycle-value-facts.v1` 为具体对象路径消费者提供 union 重叠、volatile/atomic、整数宽度/符号和返回类型信息；未覆盖的 C 值转换保持未知。字段为 v5 事件的附加能力收据，缺少收据的旧事实不获得新路径分析资格。此变更仍在已有 TU 解析中完成，不逐候选重启编译器。

- 实验性 `CompleteFactStore` 补存完整 Clang AST、按函数隔离的 CFG、预处理输出和宏分支树。事实身份绑定 TU、依赖文件、编译命令、编译器与影响头文件／宏的环境；未绑定的响应文件或插件配置返回 unknown。旧摘要存储仍保持兼容，不反向冒充完整事实。
- 完整事实的热载入用当前编译器重新预处理，覆盖 `__has_include`、include-next 和较高优先级头文件出现等旧 depfile 无法证明的否定前提；结果不变才复用 AST/CFG。冷收集前后核对预处理结果，变化时不发布完整证据。磁盘事实不能直接恢复执行其保存命令的资格，必须在当前进程重新收集；这有预处理成本，不是零进程热命中。
- native `include-probes.v1` 保存实际头文件存在性查询及搜索目录，已查询但未读取的文件不冒充内容依赖。查询结果参与 BuildContext，发布、缓存复用及交互消费时重验；绝对路径或被缓存目录排除的查询仍逐项核对。负向 include-next 的搜索集合有歧义时保守不完整，header map/framework 仍不授予完整性。与独立 AST 核对 SDK 头文件时使用解析后的实际路径和字节摘要，不能按文件名或版本号推定等价。
- 首版只为与事实编译器绑定的 Clang driver 签发证明；GCC、编译包装器、预编译头和模块尚无等价性适配时返回 unknown，不能把替换编译器后的宏或 ABI 当作当前构建。CFG 身份同时隔离编译单元和函数；无法解释的边保留不完整状态。
- 模型通过 `ast_nodes`、函数、类型、CFG 和宏分页查询；`display_truncated` 与底层 `complete` 分开。页读完只表示当前查询耗尽，不能推断全程序路径完整。程序检查器直接读完整载荷并校验依赖，磁盘文件自带正确摘要也不等于编译器来源。
- 宏记录保留嵌套条件、重定义、undef、别名与空操作；编译器预处理结果确认实际执行的定义，使用点语义以 AST 的展开位置为准，不能以文件末尾定义替代。非当前分支只作条件风险。调用覆盖表核对实际参数；当前常量区间可确认单个调用点，间接调用、公开入口和符号关系未闭合时仍为 unknown。

- 后端能力不足必须返回明确的空结果、告警或降级状态，不能伪造完整能力。
- Java provider 信号只能进入 Java 分析路径；CodeQL 为 BYO，不得进入官方依赖包。
- Java Spoon 默认复用已准备的本地 Maven 缓存，不隐式强制联网刷新；显式刷新只允许发生在联网准备阶段，sidecar 不得在目标项目遗留 `spoon.classpath.tmp`。
- 日常 Joern WebSocket 查询必须有总量可控的超时和重试边界；CPG import 可以使用独立的长时限，不能把一小时等待传播到普通入口查询。
- 基础增量索引只以文件哈希、TU 状态、删除影响和基础 extractor 版本为依据；`indexed + hash unchanged` 的 TU 不得因为派生索引版本或生命周期变化而重新执行 `extract_tu()`/`documentSymbol`。
- `index-audit` 的编译清单复用 `command_identity`，逐条保留命令、选中/等价/未覆盖上下文及原因；只有完全相同的命令身份归为等价，宏、include 顺序和 ABI 差异不能折叠。缺少可核验选择记录或存在未知 context 时不声明覆盖已验证。
- `index-audit --replay-fixture --work-directory <新目录> --clang-indexer <工具>` 仅创建内置 C fixture，不读取项目配置或执行构建脚本。增量与干净路径使用独立数据库、TU 缓存和参数预检缓存，比较全部符合范围的编译实例、规范化发布事实、原始事实及覆盖；保留删除/重命名、回调和 negative-include 差分。提取完整度与旧导航投影的多变体缺口分别记录，不用投影缺口跳过实例对照。只忽略已列出的存储身份、时间和运行统计，不能忽略语义差异；完整扫描的变体消费者、链接目标、SVF 和任意 C/C++ 工程不在该等价性结论内。已有工作目录拒绝复用，不清理用户缓存。
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

Maven 启动器先按命令行 `-Dmaven.repo.local`（含分开的 `-D` 写法）、`Z_SCOPE_MAVEN_REPO`、默认用户目录的顺序选择仓库，再仅向该仓库补充包内种子；同一属性重复时最后一个值生效，不覆盖已有文件。显式仓库不要求默认用户缓存可写。

Java 信号 provider 的执行异常、非零退出、无效 JSON/容器形状和显式 degraded 响应必须传递为收集失败，不缓存为成功的空结果；后续调用可以重试。合法空结果仍允许缓存，Joern 收集异常同样不写入结果缓存。统一后端不吞掉这些异常，候选消费者据此记录失败状态。

工具调用保留启动器的命令名（包括 `clang++`）；ELF 依赖、工具摘要和缓存身份检查通过 bundle manifest 定位其实际二进制，同时记录启动器摘要。不能把共享启动器解析后的文件名用作编译命令，也不能对 shell 启动器执行 `ldd` 来推断 SVF 的 LLVM 版本。

## 程序事件与共享分析缓存

批量 Clang 协议 `zscope.clang-facts.v2` 在原有 TU 解析中提取函数 CFG、语句/表达式位置、new/delete 家族及带 USR 的全局/字段访问，不为每个候选另启编译器。内部 `zscope.program-events.v5` 记录形式参数身份、稳定 event/value identity、逐事件 defs/uses、逐实参 uses、声明初始化、赋值/复合赋值/增减、嵌套调用、调用结果、return 和 CFG condition/guard。`function_program_facts` 随同其他事实表事务发布；CFG 构建失败或函数身份不唯一时显式返回不完整。v4 及更早事实不得用于 source-to-sink 推断；`ProgramEvents.h` 纳入 portable batch 组件指纹，协议变化必须真实重建二进制。

六工具的符号入口由 revision-aware `SymbolCatalog` 统一生成 `zs1:<kind>:<24-hex>` ID，摘要绑定 kind、限定名、项目相对文件、定义范围和签名。函数重载、静态同名函数和 Java 方法不能通过名称清洗合并。宏搜索优先读 KnowledgeDB，缺失时按项目 include/exclude 与敏感路径策略扫描源码；函数式宏和 object-like 宏均可检索。object-like 直接字面量只规范化括号、正负号、整数进制/suffix、浮点、字符串、字符和布尔值，不递归展开或计算表达式。

`FlowQueryService` 直接在 v5 facts 上做 reaching-definition 和有界路径搜索，并以 direct argument→parameter、callee return→caller result 以及真实存在的 SVF resolved callsite 连接跨函数证据。唯一 reaching definition、直接身份、无未知 guard/间接分派/may-alias 时才可标记 `must`；否则为 `may`。当前 SVF 数据库没有通用完整 alias 查询时必须报告 `coverage.details.alias=unavailable`，不能合成别名结论。Java 只有 Joern parameter→sink 路径映射为 flow；source/java_unified 明确返回 `unsupported`。

KnowledgeDB 的 IR 语句身份包含列号和事件序号，升级保留既有语句 ID 及边引用。同一扫描的 Graph 函数事实和锁边通过有容量上限的共享缓存复用，同一键的并发请求只运行一个生产者。缓存身份包含源码/索引版本和语义上下文；入口可达性单独计算，锁顺序反转使用反向锁对索引，模糊别名仍需核验。

语义建模阶段通过线程隔离的 `semantic_modeling_context` 读取完整 callee、宏、全局对象和类型定义，绕过工具展示用的数量与定义字节限制。作用域退出后恢复原查询预算；真实后端缺失或截断仍作为 partial 覆盖记录。

宏体中的标识符只是检索线索；discovery 只有取得当前 native `macro_reference` 的精确定义位置、USR 与 BuildContext 后才生成候选。全局载体由索引中的声明或定义绑定，排除其他翻译单元的静态对象，歧义保持未知。函数指针同样要求 exact slot/callsite/type/USR 与当前 SVF command attribution；源码子串中的 pointer name 不能授权目标。确认结果进入项目语义 YAML，不能从宏名称或描述推断锁身份。

项目原语 discovery 枚举所有精确函数实例，不限入口可达范围，并复用项目级 `FunctionFactSummary`。直接/多层 wrapper 在真实 link group 调用图的 SCC 上传播；各 TU 仍保留自身 BuildContext，unknown build 不作通配。Dispatcher 候选记录精确 selector、分支 guard/key、handler USR 与 CFG 证据，必须人工确认后才能供 balanced/deep 扩展既有检索。

契约源码组合包含条件表达式中的接口调用，并区分每次调用的结果。内部锁配对按成功路径检查，失败即返回的路径不等于对外持锁；无法解析的短路副作用不视为完整覆盖。声明左值、成员左值和输出参数分别解析，防止返回状态别名或载体路径丢失。

原生类型身份将匿名 typedef 的成员引用绑定到其真实 typedef 声明，并单独登记嵌套或局部匿名类型。保留原始引用 USR；布局哈希包含 typedef 底层展开定义，不把不同编译宏下的布局相互投影。类型缺口不能靠同名搜索或人工接口确认消除。

- 批量投影以当前编译单元代次替换程序事件，源码位于项目根目录时也使用统一的 TU 相对路径；迁移旧绝对路径登记后撤销旧调用位置和已删除函数。重新发布原子提交，失败仍保留上一完整代次。

## 编译实例事实与导航投影

native v5 的附加能力 `zscope.resource-protocol-facts.v1` 提供参数所指 record 的种类/USR、事件子表达式中的宏标记及 Clang 空指针常量判定。单槽池和引用留存核验要求该收据；旧 native 仍可服务既有事实消费者，但不因此获得新协议的源码证明。嵌套宏检查按 AST 节点缓存，不为协议重复解析 TU。它不能证明池并发正确、代际唯一或整个调用路径无缺陷。变更后必须重建 native 工具，工具二进制身份参与 TU 缓存失效。

字段写入与读事件共用 `valueIdentity` 类型事实，保留整数位宽/符号、volatile/atomic、重叠存储和位域标记。非原子引用计数核验同时检查资源参数限定符与计数字段，缺失类型收据、位域及不支持的整数表示不能回退为普通 int；只用旧写入字段身份的缓存不足以核验新协议。仍在原 TU 提取中完成，不为每个计数调用重新解析源码。

Native batch 对每个不同命令身份执行提取，仅合并完全相同的命令、环境和响应文件身份。`BuildContext` 另外绑定工具、源码/头文件内容及已观察目标 ABI；编译数据库不提供真实链接归属时，`link_target` 明确为空。

KnowledgeDB 的 `compilation_instances`、`compilation_facts` 按构建实例和记录序号持久化完整 native 记录，与旧查询投影在同一代次原子发布。旧 `translation_units/functions` 仍是按文件组织的导航投影，不能代表全部实例。批量统计单列 `variant_sources`、`projection_complete`；导航可查询不等于变体覆盖完成。TU 删除/替换或切换到 LSP 时撤销相应实例事实。

`CodeIndex.get_build_contexts()` 枚举实例，`get_function_program_facts(..., build_context_id=...)` 精确读取相应函数/事件；未指定身份且存在多个实例时返回 `ambiguous_build_context` 和空证据，不任意选取第一条。未知/已失效身份不回退到别的 TU。交互工具在读取证明事实前复核依赖、响应文件、关键环境与编译数据库，不写状态或启动编译器。

单个实例内的名称仍可能对应多个 C++ 重载或命名空间成员。此时返回 `ambiguous_function_identity` 及函数 owner 选项，事件、访问和 CFG 不合并。调用者可把返回的 native USR 原样用作函数查询；USR 中的 `@` 不按导航后缀截断。精确结果附带由 BuildContext 和 USR 共同确定的 `function_identity`，因此同一头文件的 static 函数在不同 TU 内具有不同身份。工具把歧义选项作为 `function_choice` 分页返回；未知 USR 保持缺失，不按函数名称回退。这是实例事实查询合同，尚不替代旧导航符号及其余未迁移的扫描消费者。

当前完整扫描的函数调度与契约选择已按精确实例解析，但 SVF 链接分组、全建模、全部候选消费者与逐实例 durable 尚未迁移到实例级；多变体覆盖仍是显式缺口。静态同名符号、不同链接目标与跨 TU 证明不能仅凭这一存储切片宣称全部解决。

### SVF/Saber 信号的构建身份

SVF 仍是**每个项目一次**的整程序运行，产物按链接组（一个组合并多个 TU）落地，所以“这个污点信号属于哪个编译变体”必须由生产者显式给出，不能靠文件名猜。现在这条链路是：

信号消费还要求当前进程的 SVF 运行成功，并重新核对已导入结果的 generation、逐组工具状态和产物摘要。缺少编译数据库、构建失败、工具不可用或结果失效时，旧行可保留供诊断，但逐实例查询、非实例候选收集和 unified 污点工具不能将其当作本轮有效信号。仅 `command_id` 相等不证明结果仍然有效。

- `BitcodeBuilder.group_tu_identities(group)` 按组发布每个 TU 的 `command_id`（= `digest_json(command_identity(...))`，与 `BuildContext.command_id` 同一键），并把同一源码出现多条命令的记入 `variant_sources`；`bitcode_manifest.json` 的 `analysis_tasks[].input_command_ids`/`variant_sources` 与 `linked[group].command_ids` 携带它。缺失字段一律读作“无归属”，不回退猜测，也不提升 manifest 版本（避免强制重建全部 bitcode）。
- `SvfOutputMapper.attribution(path)` 只给判定，不给猜测：仅当该位置是本组某个 TU 源文件、且该源在本组只有一条命令时为 `exact`；头文件/内联位置（被多个 TU 包含）、同源多变体、组外路径分别为 `ambiguous`/`unattributed`。`taint_signatures`、`indirect_calls` 新增 `command_id`/`attribution` 并进入 UNIQUE 键（否则 `INSERT OR IGNORE` 会把第二个变体的信号静默丢弃），schema 升到 v18；旧行保持空 `command_id` + `unattributed`，并清空 SVF 哈希/工具状态，使缓存必须重新导入。
- `ScopedCodeIndex.get_instance_backend_signals()` 是实例侧唯一入口：只接受 `attribution='exact'`、`command_id` 属于被钉住的实例、且该命令在 `compilation_instances` 中只对应这一个上下文；否则返回 `stale`/`unavailable`/`foreign_build_context`/`ambiguous_command` 的空结果，绝不退化成“SVF 没发现问题”。Analyzer 在实例分支据此记录 `svf_taint_query`：拿到 `complete` 时记 `status=complete` 并带 exact/ambiguous/unattributed 计数；被拒绝时记 `status=excluded`、`reason=scoped_raw_knowledge_db_unavailable`（可比较的声明式排除，集合闭合检查按它比对），精确判定与原因放在 `detail` 字段。查询真的抛异常则记 `failed`，让实例集合不闭合而不是被当成“已排除”。候选同时写入 `build_context_id`；候选 id 与 dedup key 在带构建身份时包含它，两个变体的同一条 Saber 行不会被去重掉。
- 仍未迁移：`clang_knowledge_db`/`find_acquisition_calls` 读的是单变体导航投影 `call_edges`；裸 `_backend`/`_db`/`db` 仍被 `ScopedCodeIndex` 拒绝；`GlobalModeler` 保持项目级；跨 TU 流向只证明“报告位置所属 TU”，不证明调用者变体之外的路径。真正的逐变体 SVF 需要每个 `command_id` 一个链接组，本切片没有做，也不声称做到。

## 已观察链接目标与受限跨 TU

`zscope-link-record` 显式按编译数据库重建指定 C 对象，再实际执行对象文件链接，将源码/头文件内容、编译命令/环境、对象与可执行文件摘要、ELF ABI 和符号表写入项目 `.zscope-link-targets/`。它不从编译数据库或目录猜测链接归属；失败的重新构建撤销该输出的旧记录。此准备命令需由用户显式运行，普通索引/扫描只读记录，不启动编译器或链接器，不新增 public YAML。

`LinkedTargets` 将记录中的每个对象命令绑定到唯一、当前的 BuildContext；保留各 TU 自身身份，不把 target ID 当作共享 BuildContext。当前仅接受对象直接链接的 Linux ELF executable、与 native SDK 版本一致的 Clang 编译、相同编译目录/有效参数（除源码和输出）、相容 native/ELF ABI。GCC 记录、混合配置、archive/shared library/LTO、链接脚本、弱符号/别名及无记录依赖都不取得本切片跨 TU 权限。未索引成员、过期产物或缺收据明确报 gap；同一入口实例属于多个有效 executable 时不自动选取。显式按目标查询只在该目标成员内按 native USR、强 ELF 函数定义和签名核对调用。

native v5 的附加 `zscope.c-linkage.v1` 提供函数 canonical signature、外部链接、属性边界及参数/返回值可达 record 的字段、偏移、尺寸和对齐；布局相同才可跨 TU 连接，不能只比较同名类型。布局收集按函数缓存且有深度/数量界限，位域、未完成类型或超限保持未闭合。`zscope.const-call-targets.v1` 只提供具有内部链接、const、完整函数初始化的小型数组/结构体 ops 表（最多八个槽）；槽位指针的函数类型必须与初始化目标精确匹配，不接受隐式不兼容转换。可变表、未知对象、空/不完整初值、volatile 或未支持属性不生成封闭目标集。此能力由实际 AST 提取，不从文本或接口名称推断。新增事实必须真实重编译工具；工具摘要照常使 native 缓存失效。

链接目标绑定复用现有输入校验器，在单次校验内共享公共头文件和目录哈希；不同扫描/路径收尾重新检查当前输入。链接摘要包含所有成员，因此未执行的表目标重写、头文件/宏变体或产物改变也撤销旧路径依据。构建覆盖报告同时列出已观察链接与未核验原因；这些记录只支持相应查询/协议路径，不声称导航调度覆盖全部变体，也不自动扩展 SVF 分组或 S02 跨 TU 契约组合。

调用结果目标和局部变量写入也通过原 AST 的 `valueIdentity` 保留整数位宽、符号及限定事实，包含后续从未读取的结果变量。句柄路径只能在明确的 signed 32-bit 载体间保存代次，不依据函数返回类型猜测目标变量类型。缺少这些字段的旧 native 事实不能绕过转换检查；变更提取器需真实重编译并由工具摘要使缓存失效。

`function_scope_local` 由 VarDecl 的真实 AST 父节点确认是否直接处于函数体 CompoundStmt；不是按行号或变量名猜测。句柄表路径用它与当前调用帧、实际零初始化共同限定命名空间寿命，内层块和缺收据的局部表不取得该子域权限。它不声称提供任意 C/C++ 对象寿命求解。

`PthreadCleanup.h` 提供 `pthread-cleanup.v1` 附加收据：C/glibc 默认 push/pop 宏的当前系统定义、直接调用参数、展开 AST 函数/变量身份、配对位置和控制跳出限制。只标注受支持脚手架，保留原始 program-events/CFG；异步消费者单独投影，普通消费者不能从标签授权清理。无相关宏的函数不额外遍历 AST；改动后真实重编译，工具摘要使旧 native 缓存失效。portable 批量组件指纹包含此头文件，不能复用未更新的发行工具；本地回归不替代 portable 实物验收。

`pthread-wait.v3`/`pthread-deadline.v3` 沿用当前系统 timespec 布局核验，并为直接 pthread_cond_clockwait 提供 CLOCK_REALTIME/CLOCK_MONOTONIC 宏定义/展开及当前值收据。参数必须是直接系统数值常量；项目重定义、包装宏、变量或显式转换不产生授权收据。native 工具摘要、预处理依赖和 BuildContext 继续参与缓存及消费者当前性；旧 v1/v2 收据不授权新版路径。

## 2026-10-15 受限逐实例符号消费者

`CodeIndex.get_compilation_facts` 按精确 BuildContext 读取 native 成员收据；`ScopedCodeIndex` 逐次核对当前构建依赖和完整 native 入口身份，再解析 callee/caller 的唯一 USR、文件与位置。宏调用的 AST callee 是展开后的 wrapper，因此 scoped program facts 还携带同一 owner 的精确 `macro_reference` 名称、USR 和 BuildContext；规则用该收据把源码中 `LOCK(x)`/`SAFE_FREE(x)` 绑定到 confirmed macro contract，不从名称猜测。缺少 owner 文件、导航别名不符、歧义重载、外来 callee_file 或不完整事实均返回空与缺口。真实头文件变化会撤回已有调用、宏和类型缓存。默认索引的其他导航 API 不因此获得逐实例证明权限。

当前只提供已有收据能核验的引用；类型完整定义、复杂图/链接与其余消费端的共享调用链尚未闭合。精确调用边、函数清单以及同 TU 唯一 native owner 的完整正文记入 `served_consumers`，不再仅因消费成功而保留 blocked 标签；Graph 缓存以 BuildContext 为实例身份，外部/系统调用无项目正文时直接停止项目函数遍历。歧义、跨 TU 无链接依据、陈旧或缺失收据仍明确 blocked/incomplete。真实 native C/C++ fixture 与受控模型回归不能代替真实项目效果验收。

普通 C/C++ `ScanSessionRunner` 已按实际 `EntryInstancePlan` 执行这些实例：索引就绪后枚举精确 `(BuildContext, USR)`，可解析时逐实例运行真实 Analyzer，并在冻结台账上集中运行一次扫描级验证；实例间共用候选台账、验证缓存和裁决队列，验证按唯一精确实例选择 scoped index，且不构建项目级语义模型。Java 与无实例场景保留各自 `legacy` 路径；C/C++ 若枚举不到可核验实例，报告 `instance_execution.mode=gap` 并保持 incomplete，不退回按名称分析未知构建。全建模、SVF、链接、全部消费端和逐实例 durable 仍未完成，本切片不代表全项目扫描覆盖。

C/C++ fast 在冻结实例语义时额外为 compile database 中每个未被入口计划覆盖的当前 BuildContext 选择一个精确 `program_function` owner，因而入口外 TU 也进入静态发现。函数清单来自该上下文的 native owner 收据，执行去重只使用 `(BuildContext, USR)`，不能使用展示 identity、路径拼写或裸函数名。标准 API 效果按本构建真实 call receipt、系统头物理文件与摘要、USR、ABI 签名、target、native 工具及共享库收据授权；项目同名 shadow、用户头、过期头/工具和未知身份均拒绝。当前跨 TU 图仍只由真实 link record 授权，缺失记录会使 fast formal qualification 为 false。

fast 缓存不另造事实：函数命中身份包含完整当前 program facts 与 BuildContext 收据、有效规则/实现摘要、RuntimeSpec 和实例语义摘要；TU 图键再包含本构建全部函数键和真实 link receipt，因此变化函数只直接重算自身、本 TU 图摘要随依赖前沿失效。候选取出后仍重新绑定本轮 `analysis_unit_id`、可达性、BuildContext 和 Validator 生命周期。缓存目录必须留在工程根内且路径组件不能是符号链接；读取失败、内容不匹配或无法原子写入均退回本轮分析。跨 TU SCC 和 backend/SVF 的持久增量边界尚未闭合，不能借函数/TU 图缓存宣称这些能力热命中。

报告对计划与执行分开计量：`entry_instances` 的 `planned_instances` 是枚举出的实例数，`scheduled_instances`（未接入实例分析时为 null）是已提交调度的实例数，`instance_analysis` 的 `analyzed_instances` 才是状态为 analyzed 的实例数，另有 `instance_scope_complete`、`consumer_scope_complete`、`scan_coverage_complete`。本次实际分析和经作业队列从可信 checkpoint 复用而非重新分析是不同事实，计划枚举不等于已调度，已调度不等于已分析，复用也不等于本轮执行。`metadata.build_coverage` 记录实际提取覆盖与仍存缺口，其 `extraction_complete` 不能解释为 `scan_complete`，后者保持 false，不能据此承诺全项目扫描完成。按实例固定的 `ScopedCodeIndex` 只把 `get_build_contexts` 固定到一个上下文，覆盖统计改走 `coverage_index()` 读取未包裹索引，并标注 `view="instance"` 与 `pinned_build_context_id`；实例枚举保持不变是实例语义“恰好一个当前构建”的前提，因此不能靠放宽枚举来修覆盖统计。被计数的每个实例还会按 `context_input_status` 复核当前性：`status="indexed"` 只说明提取成功，输入已陈旧时记入 `uncurrent_instances` 并追加 `stale_compilation_instance_inputs`，没有收据的摘要记 `instance_input_status[build]="unmeasured"`，都不再冒充 current。覆盖检查会按各 BuildContext 自己的 `search_excludes` 分组复用 `InputValidator`：同组公共头文件只摘要一次，但不能用另一个上下文不同的排除集去判定当前实例过期。

### Native 源码根与导航路径

Clang 精确构建事实使用提取器的 `source_root` 相对路径；`CodeIndex` 的构建列表、函数构建归属、program facts 和 compilation facts 查询先解析真实文件，再转换到该命名空间。导航输出仍按项目根目录表示。源码根是项目子目录时，项目相对路径、源码相对路径与绝对路径可查询同一真实实例；另一个同名文件和源码根外路径不能退化为 basename 匹配。`tests/test_native_source_roots.py` 使用真实 native 双编译变体与 ALT 独有 double_free 候选核对此边界，不代表完整 ScanSession、全消费者或真实项目效果验收。

### 原生热复用的观测范围

逐实例语义与结果恢复同时核对当前 CDB、依赖、include 查询及精确 native 入口事实，不能复用 scoped facade 早前缓存的成功探针来授权新消费。文件字节变化即使保持原 mtime/大小也使快照失效；同名文件、另一 BuildContext 或保存的结果不能补造当前 USR。索引提取覆盖、候选消费者覆盖和扫描完成保持独立统计。

当前 include-probes.v1 对存在性前提重新核验：仍缺失的头文件可热复用，目标出现、消失或更高优先级候选变化必须失效。rebuilt_tus 计量 AST 提取；热轮零提取、零参数检查不表示零进程，工具版本及 ldd 依赖来源核验仍可能运行。缓存工件摘要只证明工件稳定，提取进程由独立执行计数核对。extraction_complete、projection_complete 与全扫描 coverage 分开；当前受限 replay 的 projection_complete=false 不可提升为导航或全项目完成。

逐实例入口保留真实 native 完整签名、USR、BuildContext、源码与定义字节位置。入口的私有查询适配器只把这些坐标共同核实的完整签名映射到当前物理函数，不清空签名或借用同名函数。外部标准调用分类同时要求当前 native caller/target 调用事实、同一进程工厂签发且仍有效的实例快照，以及已核验标准来源和可执行契约；项目同名函数、缺少当前事实或冲突提示保留 source_unavailable。调用记录只能收紧权限，分类前后重新检查精确快照，不委托未限定实例的全局分类器。此有界接线不表示所有函数调度、语义域或真实项目效果已覆盖。
