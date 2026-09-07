# Clang 批量索引与 SVF 输入验收

本流程保持配置中既有的源码范围、编译上下文选择和 SVF 分组。文件数、编译数据库条目数、独立 TU 数和 bitcode 数分别统计，不能互相替代。约 17 MiB 的客户 bitcode 集合尚不能证明覆盖了千万行源码。

## 安装与切换

Linux C/C++ Portable 包已集成 `bin/zscope-clang-indexer`，与配套 LLVM/Clang 18.1.0 库和头文件一起发布。解压后无需安装开发包，默认 `frontend: auto` 自动使用包内工具；模板无需增加 `tools` 路径。可运行 `bin/zscope-clang-indexer --version` 检查协议和编译版本，严格验收时将 `frontend` 设为 `batch`。下面的手工构建及路径配置仅适用于源码安装或显式替换工具。

`zscope-clang-indexer` 是独立的 LibTooling 程序，需要 LLVM 和 Clang 开发包及 CMake。当前集成验证使用 Linux LLVM/Clang 18.1.3；它与 clangd 的版本独立。现有 clangd 20.1.0 继续用于 LSP 回退，不要求升级到 clangd 22。

在 Linux 中从源码构建（以已安装 `/usr/lib/llvm-18` 为例）：

```bash
python scripts/build_clang_indexer.py --llvm-prefix /usr/lib/llvm-18 --prefix "$HOME/.local" --jobs 2
"$HOME/.local/bin/zscope-clang-indexer" --version
```

开发包、运行时库与工具必须属于同一 LLVM 安装。复制单个可执行文件到另一台机器前，需要在目标机用 `ldd` 验证依赖；本构建脚本不把系统动态库打包成离线发布包。

在客户实际使用的 YAML 中增加以下字段，保留其他配置：

```yaml
indexing:
  backend: unified
  clang:
    frontend: auto
  tools:
    clang_indexer: /opt/zscope/bin/zscope-clang-indexer
```

- `auto`：工具可用时按选定 TU 批量解析；工具不可用时走现有 LSP。失败 TU、无法证明模块/PCH 来源的 TU，以及当前扫描范围中未被 TU 覆盖的文件走 LSP，数量、原因和 RPC 单独统计。
- `batch`：严格批量模式；任何需要回退的文件都会使本次索引失败，保留原已发布事实。
- `lsp`：使用原解析流程。从批量前端切回时，在暂存库中重建；失败仍保留原已发布事实。

批量工具在首次解析前移除 `-Werror`，将 `-Werror=<group>` 改为对应的普通警告选项；warning 保留诊断但不阻断索引。参数处理覆盖嵌套响应文件与 `-Xclang`、`-Xpreprocessor`、`-Wp,...` 转发，区分选项和路径等参数值，原始编译数据库和响应文件不改写。只有 Clang 的未知参数诊断会触发兼容重试：一次移除本次诊断明确指出的未知选项，最多重试一次；不猜测未知选项后面独立值的含义，也不按错误消息中的源码文本删参数。语法、缺头文件、目标不支持等其他错误仍使 TU 失败。

重试使用独立抽取状态，首轮产生的事实被丢弃；最终成功同时要求工具返回成功且驱动、前端均没有 Error/Fatal 诊断。重试仍失败的 TU 写入 `failed_tus`，之后遵循既有 auto 回退或严格 batch 失败规则。每个成功 TU 的清单及失败记录包含 `argument_adjustments`，记录忽略的警告提升选项、剔除的未知选项、最终参数及各次诊断计数；完整两轮 stderr 保留在同一日志中。汇总 `argument_retries` 只统计本轮实际执行的重试，热缓存复用不增加该计数。

参数规则由 `compiler_argument_policy.json` 统一定义，批量工具在构建时嵌入，Python bitcode 适配器加载同一份规则。需要重新编译批量工具，`--version` 返回 `argument_policy_version: 2` 和 `argument_policy_digest`；协调器同时检查版本与摘要。缓存身份包含策略、工具和原始输入，兼容后的成功结果可复用，策略变化会失效。已有 Portable 安装不会被源码修改自动更新。

直接 Clang 与 gllvm 编译也采用同一警告提升处理及一次未知选项重试，保持各自原有分析参数。gllvm 的两个 Clang 子进程分别记录诊断，避免并发 stderr 交错造成错误识别；配套 Python 适配器仅补充 `-v` 诊断以记录每个子进程的实际头文件搜索目录，不改变分析参数或工具版本，也不依赖 batch 工具。`bitcode_manifest.json` 的 `argument_adjustments` 保存原始/实际命令、策略摘要、尝试记录和独立诊断路径。两次尝试共享原 TU 超时与取消预算，超时、OOM、取消和真实源码错误不被兼容策略吞掉。

auto 回退文件的 `function_type_refs` 固定采用后台补齐与按需优先收集，不需要增加配置。基础事实及 `function_symbol_context` 完成后即可继续扫描；batch 成功产出的类型引用照常导入。类型上下文消费者只等待目标函数，默认最多 300 秒；同一函数的前后台请求合并，单个消费者超时不会取消其他消费者的等待。单函数收集仍可能使 clangd 解析其整个 TU。

`symbol-context` 仍是初始化阶段的一部分；主线程处于 `rebuild_function_symbol_refs` 时，后台类型交接尚未发生。派生会话共享规范路径、源码快照和 UTF 坐标转换，热坐标不逐次调用 realpath/stat。文件快照与序列化缓存共享字节预算，冷快照仅落到当前会话的 SQLite TEMP 表；文件任务边界、最终发布和后台恢复重新验证原始路径、符号链接目标与文件版本。修改、删除或链接改向使旧计算失效，不降低绑定和覆盖要求。心跳的 `sources` 提供路径/源码命中、resolve/stat 次数与时间，`sqlite_queue_wait_seconds` 区分缓存排队等待。

开发者可以运行 `python -m scripts.profile_clang_locations --output /tmp/clang-locations.json` 对比旧路径转换与新快照的固定合成引用样本；报告比较结果摘要、墙钟、文件系统调用和缓存指标。该回放不发送 clangd RPC，不能作为完整项目索引耗时或加速倍数的承诺。

函数枚举和不返回类型引用的 `get_function_info` 工具不会触发收集。语义快照先消解函数身份，再补齐该函数的类型上下文；失败或超时明确报告不可用，不能把未完成误当作没有类型引用。

并发沿用 `concurrency.index_workers`（配置默认 4），没有增加编译变体。每个源文件选取编译数据库中的首个命令；其他命令不会因为更换前端被额外展开。所有事实包保留各自的 TU 上下文。公共文件视图使用该文件自身的命令或首个包含它的 TU；不同宏环境中的类型定义不相符时，保留引用和 `type_context_not_projected` 原因，不把它绑定到另一个上下文的类型内容。C++ 命名空间中的实体使用限定名，修正原来同文件同名实体可能相互覆盖的问题。

## 产物、恢复和完整性

批量事实包、依赖清单、文件检查点位于**实际 KnowledgeDB 所在目录**的 `clang_batch_cache/`。每个包保留 USR、声明/使用的 UTF-8 字节坐标、调用、宏展开、类型类别和读写角色。成功批量 TU 的派生引用不发送 symbolInfo、definition 或 references 请求。

导入后保留完整 TU 事实包及依赖 manifest，用于热缓存和发布中断后的恢复；不能用已投影到当前文件视图的临时表替代完整事实包。清理只删除该成功任务的临时作业、标准输出及残留 partial 文件，stderr 与失败任务的诊断材料保留。

缓存身份包含工具内容及协议、源码、编译参数、响应文件、相关环境、依赖内容及头文件搜索目录状态。文件内容每轮校验共享，发布前重新校验；不使用仅时间戳复用。未绑定的依赖、模块/PCH、负向 include 探测等信息不足时保守禁用持久复用或回退。缓存目录不计入源码头文件搜索状态。

协调线程将事实包流式导入独立暂存库；新基础事实、派生事实与 `current` 状态在主库同一事务发布。失败或中断不会先清空主库。`latest_run.json` 记录本次尝试，单 TU 成功包可用于中断恢复；已有有效包只做校验和必要导入。

报告中的 `ready_for_queries` 与 `type_refs_complete` 分开：存在待处理回退函数时可以进入分析，但 `complete` 不会因此变为 true。当前函数完成度以 KnowledgeDB 的 `function_type_ref_state` 为准。后台通过一个执行槽位按函数推进，前台在 RPC 边界优先，函数结果与状态原子发布；缓存与函数检查点在同目录的 `clang_type_refs_cache.sqlite3`，不会当成整文件检查点。

`[function-type-refs]` 每 30 秒汇总前后台状态、当前函数、等待、准备耗时、函数吞吐、RPC、缓存和内存。退出时 `clang_type_refs_report.json` 保存函数状态、等待平均值/p95、累计 RPC 及有界的会话指标。扫描结束保存进度后退出，常驻 WebUI/MCP 可继续补齐；输入身份有完整依赖证明时跨进程恢复，否则保守重做未被证明有效的结果。成功的 semantic tokens 和坐标查询证据也可在暂停恢复后复用。基础重建和 SVF 阶段暂停此后台并释放 clangd，避免重型进程竞争。

默认 INFO 日志仅打印阶段开始、结束和每 30 秒一次的批量心跳，包含完成、剩余、编译、复用和失败数量；即使没有 TU 完成，心跳也继续输出。逐 TU 完成进度、子进程心跳及完整资源指标在 DEBUG 查看，资源指标仍写入事实包清单，不因降低日志级别丢失。同一错误类别每轮仅将前 3 个失败样例打到 WARNING，后续样例进入 DEBUG；心跳及结束汇总显示累计失败和省略的打屏数量。

`[clang-batch-failed]` 显示源码、错误类别、退出码、超时/内存/取消状态、编译工作目录及诊断文件路径。主日志仅展示有界的错误摘要，完整编译器输出保存在 `<key>.stderr.log`；全部 TU 失败详情、分类计数保存在 `latest_run.json`，该报告在进入 LSP 回退前即写入。批量工具尚未启动时可能没有 stderr 文件，此时查看报告中的 `reason`、`directory` 和 `<key>.job.json`。

`compile_directory_missing` 表示编译数据库记录的**完整工作目录**在运行环境中不可达，上层目录存在不足以满足要求。工作目录可以位于 `project.root` 或源码扫描范围之外，无需加入扫描范围。应恢复构建目录和生成输入，或在当前环境重新生成编译数据库；不要自动改成源码目录，也不要把创建空目录当作恢复生成头文件或响应文件的替代方法，否则会改变或破坏相对 `-I`、`-include`、`@response` 的含义。

bitcode 普通编译命令使用与 `llvm-link` **同一 LLVM 主版本**的 Clang 直接生成 `.bc`，保留原分析编译参数；包装器保留 gllvm 路径。不会从 PATH 挑选最高版本。SVF 通过版本输出、动态库或随构建提供的 `llvm-version.txt` 核实 LLVM 主版本；无法核实时明确失败。

`bitcode_manifest.json` 记录每个上下文的计划、成功、复用、失败或范围排除，以及链接组输入、内容哈希和指标。输出与检查点先写临时文件，再原子替换。WPA/Saber 缓存按输入内容、工具、模型、库及分析参数区分；同一成功输入可以跨组名复用，但保留每组独立的导入和状态。改变 worker 数或超时预算不使完整成功结果失效。失败组不写成功标记，也不发布缺少 TU 的分析结果。

每个 TU 的完整 bitcode 检查点独立写入 `tu-checkpoints/`，避免逐 TU 重写全项目依赖清单。`svf_run_report.json` 区分 WPA/Saber 本次实际执行、去重、缓存复用和导入时间；盘点命令会检查报告是否仍对应当前 manifest。

## 16 核 / 64 GB 的资源起点

- Clang 从 4 worker 开始，原生 TU 默认每进程预留 8 GiB；可用 `Z_SCOPE_CLANG_BATCH_MEMORY_MB` 调整单进程预算后重新测量。
- bitcode 编译默认最多 4 worker、每进程 4 GiB，分别通过 `Z_SCOPE_BITCODE_WORKERS`、`Z_SCOPE_BITCODE_MEMORY_MB` 调整。
- SVF 沿用 `concurrency.svf_workers` 和 `indexing.svf.heap_limit_mb`。总准入预算最多为当前可用内存的 75%，同时考虑 CPU 和容器限制。48 GiB 预算、32 GiB/进程只能准入 1 个 SVF 任务；空间不足时记录 `insufficient_memory`，不能当作成功。
- Clang 与 SVF 重型阶段串行，Clang 完成后释放抽取进程。批量 Clang 在 INFO 使用单个 30 秒汇总心跳，覆盖校验、等待和导入；逐进程心跳及完成指标在 DEBUG 查看。其他编译及 SVF 子进程保留原心跳。Linux 记录单进程墙钟、CPU 时间、峰值 RSS、退出状态；RSS 防护采用采样，不能等同于内核硬限额。

## 客户验证命令

先盘点实际配置与现有 bitcode，不启动 LLM：

```bash
zscope-index-audit -c /path/to/zscope_v2.yaml --bitcode-dir /path/to/bitcode --output /tmp/indexing-audit.json
```

旧 manifest 无法证明角色和编译覆盖时显示 `unverified`。新构建自动写入分析任务清单；手工产物可通过 `--tasks` 提供经过核对的 JSON 数组，每项包含 `group`、`tool`（`wpa` 或 `saber`）、`bitcode`、`inputs`。相同大小不代表相同内容；相同字节也不代表两个不同工具可以共享求解。

确认任务清单后测量已有产物：

```bash
zscope-index-audit -c /path/to/zscope_v2.yaml --bitcode-dir /path/to/bitcode --measure-svf --window-seconds 1800 --output /tmp/svf-timing.json
```

30 分钟是验证窗口：超出窗口后不启动新任务，已经启动的任务仍遵守 YAML 中自身的超时。这里报告的是现有 bitcode 集合的耗时；完整扫描日志另行报告编译、链接和主库导入时间。

批量 Clang 的固定分层 TU 样本及 1/2/4/8 worker 校准：

```bash
python -m scripts.profile_clang_batch -c /path/to/zscope_v2.yaml --sample-tus 200 --workers 1 2 4 8 --output /tmp/clang-batch-profile.json
```

不足样本数时纳入全部选定 TU；`--sample-tus 0` 测量完整 TU 集合。报告保存精确源文件列表、事实摘要、失败/回退信息、冷/热缓存与资源指标。该脚本测量 TU 抽取，不包括主库发布；不能把它的时间当作端到端时间。LSP 派生基线继续使用 `scripts/profile_clang_derived.py` 的独立数据库副本，并固定相同函数文件。

最后在相同基础输入上运行完整 `zscope -c ...`，分别保存冷缓存、热缓存和中断恢复日志，比较声明身份、引用坐标、类型类别、读写属性与调用边。任何范围变化或未解释的绑定缺失均不计作提速。千万行项目的 1–3 小时仅为待校准的优化预算，样本达到原墙钟 1/3 也需要实测；本地小型集成测试不证明客户项目已达到目标。
