# clangd 千万行项目派生引用索引优化

日期：2026-09-06。状态：核心实现、持久缓存、恢复、诊断和性能测量工具已落地；目标千万行项目的完整性能验收尚未运行。

## 最终方案与实现入口

采用用户确认的“使用位置 USR 优先 → 精确坐标回退 → 按声明批量补证”。保留 symbol/type、全局变量和宏的分析范围，派生流程继续使用现有主 clangd 分片。

| 内容 | 实现 |
| --- | --- |
| 文件调度、semantic tokens、LSP transport、派生发布 | zscope/retrieval/clang_extractor.py |
| 使用位置解析、USR 映射、补证、输入身份 | zscope/retrieval/clang_resolution.py |
| 字节预算、SQLite broker、single-flight、缓存恢复 | zscope/retrieval/clang_derived_cache.py |
| 两类派生版本升级到 5，基础 extractor 版本不变 | zscope/retrieval/clang_backend.py |
| 固定文件集合、worker 对比和事实摘要 | scripts/profile_clang_derived.py |
| 规模、歧义、恢复和真实 clangd 回归 | tests/test_clang_usr_resolution.py |

## 解析与正确性

1. 当前文件复用 semantic tokens，保留局部遮蔽、字段和函数式宏过滤。仅 C 文件自身拥有的唯一全局定义与可靠全局作用域 token 可走本地快路径。
2. symbol/type 共享使用坐标的完整 symbolInfo 和 definition 结果，按当前 TU 上下文与构建身份隔离。正常稳定坐标只发送一次各类请求。
3. symbolInfo 保留全部候选，优先使用 USR 及 declarationRange / definitionRange 映射记录。USR 映射保存稳定声明身份集合，不能用 SQLite 自增 ID 或 (file, name) 表示绑定。
4. 只有身份、类别和编译器目标坐标能唯一对应时才绑定，否则调用 definition。匹配保留规范路径、列与 UTF-8/16/32 位置编码；已有准确标识符位置时，不用外层声明区间匹配同名成员。
5. MethodNotFound 只禁用当前 clangd 进程代次的 symbolInfo；其他错误独立统计。缺少 USR 映射、基础事实未收录、范围外定义分别记录。
6. include closure 不完整时仍解析使用位置，不按名字判定外部符号，也不依据可见候选数量确认身份。
7. 未闭合的位置先在文件内分组，再按声明查询补证。声明身份能通过 USR 闭合时直接绑定；否则复用有 lease 的声明文档查询 references，并将结果与这一组全部待判坐标相交。
8. references 明确限制为 1000 个结果。达到上限、请求失败、未就绪或多个命中都不能形成唯一绑定；当前匹配集合与 LRU 生命周期无关。跨宏/全局变量类别的补证同样不能用另一类别的失败推导唯一性。

声明文档 lease 每个 worker 最多保留 4 个，退出文件时释放。没有请求超时、错误或未就绪结果的文件才可写入可恢复检查点。

## 缓存和恢复边界

- 独立 sidecar clang_derived_cache.sqlite3 放在实际 KnowledgeDB 同目录，不改变主库 schema。没有持久库路径时使用临时 SQLite。
- 热缓存默认预算为 32 MiB 的序列化数据；超出预算的条目仍可由磁盘读取。SQLite 读写、提交均在调用方协调线程执行，worker 通过有界队列与事件请求服务。
- 坐标原始结果、按类别的 USR 映射、声明 references 和分索引文件检查点使用独立命名空间。错误只进入会话 TEMP 表，不能作为跨进程负结论。
- 检查点保存完整可重放事实。中断后可恢复已完成文件；单独 symbol/type 与合并重建可以互相复用对应索引的检查点。
- 身份覆盖源码、依赖、编译数据库、clangd 身份和配置、位置编码、基础事实及当前分析范围。基础记录 ID 也参加身份校验，避免恢复最终事实时引用被重用的 ID。
- 首版跨进程恢复要求 compile_commands.json 使用 arguments，且存在完整 -MD 依赖文件，依赖和编译数据库均不晚于依赖文件。command 字符串、-MMD、依赖缺失或过期、覆盖不完整时保守禁用跨进程复用，继续使用本轮磁盘缓存。日志给出 resumable 与 identity_reason。
- 源码、头文件或编译参数变化会更换构建身份。发布前重新校验输入摘要；输入变化或已索引源码不可读时终止发布，旧事实保持可读。
- 主库仍通过现有 TEMP staging，将新事实和 current 状态在同一事务发布。两类派生版本升级不会单独触发未变化 TU 的基础抽取。

## 诊断和性能验收

rpc_methods 记录物理发送量、成功空/非空、错误码、超时和平均延迟。p95 使用最近至多 256 个完成请求，并公开样本量。日志同时记录候选组规模、RPC 缓存命中、磁盘命中、淘汰、SQLite 时间、身份校验时间、未解析原因、文件恢复数及 Python/clangd RSS。RSS 峰值是周期采样值。

测量脚本在 KnowledgeDB 的独立副本上运行，不修改原始事实，不启动 LLM，也不清除 clangd 自身缓存：

    python -m scripts.profile_clang_derived --project-root /path/to/project --knowledge-db /path/to/project/.zscope_knowledge/code_knowledge.db --compile-commands-dir /path/to/project/build --workers 1 2 4 8 --repeats 3 --file-limit 200 --output /path/to/results/derived-profile.json

--file-limit 0 选择全部函数文件。--files 读取固定文件列表 JSON；输出也保存所选文件集合。每组 worker 使用相同基础库副本，首次运行创建新的派生缓存，后续运行请求恢复。只有 resumable=true 且实际出现 files_reused 才能把后续运行称为检查点恢复。

摘要比较全部已发布引用字段和可用稳定身份，包括宏/类型索引名、函数位置/签名、类型引用类别和读写属性，排除数据库自增 ID。公共全局引用表原本只保存名称、文件与引用行，不能从该表独自恢复声明列；精确列绑定另由 resolver 回归用例验证。

真实 clangd 的小样本验证涵盖宏重定义、尖括号项目头和强制包含头；规模回归覆盖 255/256/257/512/4096 个同名声明、候选顺序变化、小缓存和多 worker。另有部分补证失败、截断、早期命中被淘汰、同名作用域、UTF 坐标、文件恢复和发布保护测试。

目标千万行项目仍需执行：固定约 100–300 文件分层样本、相同基础索引上的完整派生重建、冷缓存/恢复、旧实现与新实现的绑定差异审计。references 请求下降至少 90%、派生墙钟降至原来的 1/3 以下是验收目标，并非已证明的收益。完整项目、硬件和历史全程基线未提供，不能把本机小样本结果外推为该目标项目的提速倍数。

## 本机验证记录

- 263 项相关测试通过，包含 transport、derived、incremental、partial rebuild、pool、KnowledgeDB、查询契约和文档检查。compileall 与本次修改的 diff 空白检查通过。
- 全库 mypy 仍有 136 条诊断，分布于 31 个文件。使用改动前的 extractor/backend 作为 shadow-file 基线核对，没有新增诊断；不能将全库类型检查标记为通过。
- Windows / clangd 22.1.7 的合成样本包含 100 个 C++ 文件、100 个同名 static 全局声明，每个函数引用三次。1/2/4/8 worker 共八次运行的事实摘要一致；每次首次构建发送 300 次 symbolInfo、100 次 semantic tokens，definition/references 均为 0；恢复运行复用全部文件，没有解析 RPC。

| worker | 首次派生构建（秒） | 检查点恢复（秒） |
| --- | ---: | ---: |
| 1 | 5.109 | 0.500 |
| 2 | 3.750 | 0.516 |
| 4 | 2.797 | 0.578 |
| 8 | 2.578 | 0.453 |

以上耗时包含派生输入校验与发布，不含 clangd 启动等待。运行时保留 clangd 缓存，部分回归测试同机并行执行，因此这些数值仅作功能/性能冒烟记录，不构成受控的新旧实现性能对比，也不用于选择目标机器的最优 worker 数。

后续是否扩展派生 shard 或引入 Clang 批量提取后端，由完整测量中的剩余瓶颈决定。
