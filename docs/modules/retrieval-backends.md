---
doc_contract: zscope-module-v1
covers:
  - zscope/retrieval
sources:
  - zscope/retrieval/code_index.py
  - zscope/retrieval/knowledge_db.py
  - zscope/retrieval/clang_backend.py
  - zscope/retrieval/clang_extractor.py
  - zscope/retrieval/clang_resolution.py
  - zscope/retrieval/clang_derived_cache.py
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
  - tests/test_code_index_cache.py
  - tests/test_clang_incremental_extraction.py
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

## 主入口和数据流

- `CodeIndex` 负责源码发现、缓存、后端创建和统一查询接口。
- Clang extractor/backend 分阶段写入基础 TU 事实和可重建的函数 symbol/type 派生引用。
- `KnowledgeDB` 持久化代码事实和后端 IR，并维护版本化查询缓存。
- Java source backend 提供方法、注解和框架结构；java_unified 叠加 SootUp、WALA、Joern provider evidence。
- C/C++ Joern 在 1.x 中仅为弃用兼容入口，不属于默认或离线 C 工具链。
- Unified backend 组合 Clang 与 SVF；bitcode scope、LLVM 构建和 SVF runner 负责入口裁剪、链接与分析。
- SVF 执行受三项性能机制约束：按组堆预算预检（超预算组跳过并保留降级语义）、saber 分组并行的堆上界 worker 池，以及可选的 scope-first 惰性位码构建（先按 KnowledgeDB 规划所需 TU，再只编译这些 TU）。
- Clang 基础抽取可通过 Z_SCOPE_CLANGD_SHARDS 选择多实例 clangd 分片池；派生索引部分重建按 include 闭包把重建范围缩小到受影响的函数文件。
- 上层候选和 Tool runtime 只消费统一查询结果，不应依赖某个后端的私有输出文本。

## 必须保持的不变量

- 后端能力不足必须返回明确的空结果、告警或降级状态，不能伪造完整能力。
- Java provider 信号只能进入 Java 分析路径；CodeQL 为 BYO，不得进入官方依赖包。
- Java Spoon 默认复用已准备的本地 Maven 缓存，不隐式强制联网刷新；显式刷新只允许发生在联网准备阶段，sidecar 不得在目标项目遗留 `spoon.classpath.tmp`。
- 日常 Joern WebSocket 查询必须有总量可控的超时和重试边界；CPG import 可以使用独立的长时限，不能把一小时等待传播到普通入口查询。
- 基础增量索引只以文件哈希、TU 状态、删除影响和基础 extractor 版本为依据；`indexed + hash unchanged` 的 TU 不得因为派生索引版本或生命周期变化而重新执行 `extract_tu()`/`documentSymbol`。
- `function_symbol_context` 与 `function_type_refs` 的 `dirty/in_progress/current/failed` 生命周期保存在 schema v14 的 metadata JSON 中。派生扫描按文件有界并发，worker 不得写 SQLite；只有调用线程可以分批写 TEMP staging，派生事实与 `current` 状态必须在同一事务发布；中断恢复只重建非 current 的派生层。
- clangd JSON-RPC 必须使用单调时钟硬超时和事件唤醒，正确回复 server request，并以 work-done token 跟踪 background indexing；索引等待超时不得继续标记后端 ready。
- symbol/type 引用采用逐文件 semantic tokens 过滤、使用位置 symbolInfo/USR 与精确声明坐标、definition/declaration 回退。仍未闭合时，优先从使用位置按 USR 查询包含声明的 references，并精确匹配库内声明；最后才按候选声明补证，且只给实际命中的声明查询 USR。禁止在补证前预取整个同名组的声明 USR。完整 symbolInfo 多结果不得取第一项；USR 缺少库内映射不代表外部符号；include closure 不能作为硬排除依据。仅 C 文件自身拥有的唯一全局定义与实际全局作用域 token 可走局部快路径。
- 基础 TU 刷新应把 clangd/源码收集与 SQLite 发布分开：跨文件查询使用有界并发，KnowledgeDB 由单写者按 TU SAVEPOINT、按批次单次提交；收集或发布失败不得先清空旧事实。
- 派生引用必须使用有界、线程安全的缓存：两类派生索引同时失效时按文件合并 semantic pass；同一使用坐标及声明补证使用 single-flight，锁不得跨越 clangd RPC。热缓存按序列化字节预算淘汰，冷结果落到独立 SQLite sidecar；worker 通过有界请求队列访问缓存，只有调度线程读写 SQLite，等待必须由事件唤醒。解析中的歧义集合不能依赖 LRU 是否仍保留某个结果。
- 声明坐标的 symbolInfo/references 必须持有 document lease，按文件有界复用。RPC 错误、成功空结果、超时和截断分别计量；references 达到显式返回上限或索引未就绪时不能用未命中消除歧义。逐位置 RPC 保留行列及协商的位置编码，不使用任意放宽的行号窗口绑定，也不把同名成员误匹配到外层声明范围。
- 已确定单一 USR 的使用位置 references 可提供同一身份的正向声明证据，即使返回量触顶；只接受准确声明选择位置，不能从普通使用位置推断声明，也不能从空或截断结果否决其余候选。使用文件的 lease 从首次解析 RPC 保留到补证和事实收集结束，候选文档不能淘汰它。`declarationProvider` 与 MethodNotFound 按 clangd 进程代次适配。
- 派生会话每 30 秒独立输出 `derived-heartbeat`：已完成/总文件数、活跃文件及阶段、候选补证进度、当前 RPC/文档及耗时、请求增量、缓存队列和 RSS。心跳不能依赖文件完成或 SQLite 调度线程，也不得自行发送 RPC；单 worker 和所有 worker 等待请求时同样有效。
- `clang_derived_cache.sqlite3` 位于实际 KnowledgeDB 同目录，拥有独立 schema，不改变主库版本。坐标、USR 身份映射、references 和分索引的文件检查点按完整构建身份隔离。检查点保存事实和完成状态；旧已发布事实保持可读，恢复结果仍经 TEMP staging 原子发布。
- 持久恢复必须证明输入一致：构建身份覆盖源码/依赖内容、编译数据库、clangd 身份、位置编码、基础事实和分析范围。首版仅对带 `arguments`、完整 `-MD` 依赖文件且依赖未过期的编译数据库启用跨进程恢复；`command` 字符串、`-MMD`、缺少/过期依赖或覆盖不全时保守禁用跨进程复用，仍保留本轮磁盘缓存。错误结果只存在会话 TEMP 表。发布前重新核对输入摘要，变化时停止发布。
- LSP transport 的读写、排队和等待都受同一 monotonic deadline 约束；死进程 generation、document lease、UTF position encoding 和 source-lines 缓存必须保持线程安全。
- KnowledgeDB 写入新事实后必须使相关查询缓存失效。
- Unified 的 Clang 与 SVF 结果必须通过稳定的文件、函数和位置坐标缝合。
- bitcode 裁剪、符号闭包、共享/互斥 pool 和回退原因必须保留 manifest 供审计。
- SVF/saber 组并行执行（串行 resume 阶段 + 执行阶段线程池）必须保持与串行逐组执行完全一致的每组 status 与 artifact 语义；worker 并发同时受 `svf_workers` 与堆预算上界约束。
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
python -m pytest -q tests/test_knowledge_db_ir_and_config.py tests/test_svf_cache.py
python -m pytest -q tests/test_joern_client.py tests/test_bitcode_scope.py
python -m pytest -q tests/test_svf_saber_parallel.py tests/test_svf_memory_budget.py tests/test_clang_extractor_pool.py
python -m pytest -q tests/test_build_llvm_lazy_plan.py tests/test_partial_derived_rebuild.py
```

`scripts/profile_clang_derived.py` 在基础 KnowledgeDB 的独立副本上运行固定文件集合与不同 worker 数，保存方法请求量/错误/延迟、缓存、进程 RSS、恢复情况及稳定事实摘要；不运行 LLM、不删除 clangd 缓存。`--file-limit 0` 选择全部函数文件，`--files` 可重放固定 JSON 文件列表。对比时区分 clangd 缓存状态、派生冷重建和检查点恢复，不能将样本结果或本机线程扩展效率宣称为目标大项目的提速倍数。

## 权威源码和关联文档

- 稳定入口见本文 frontmatter 的 `sources`。
- 后端定位与能力矩阵见 `README.md` 和 `docs/architecture.md` 的“事实平面”。
- WSL 特有问题见 `.agents/workflows/wsl-pitfalls.md`；原生 Linux 不应套用 WSL/NTFS 假设。
