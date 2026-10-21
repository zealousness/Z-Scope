# Z-SCOPE 项目交接指南

本文件是仓库级协作说明，帮助后续模型先识别用户诉求，再进入正确的代码、文档和验证路径。具体实现以源码和测试为最终事实来源；端到端架构以 [`docs/architecture.md`](docs/architecture.md) 为准。

## 项目速览

Z-SCOPE 是面向 Java 与 C/C++ 项目的 AI 静态分析平台。典型数据流为：

`CLI / WebUI / MCP` → 配置加载与入口规划 → 代码索引和后端事实 → 候选生成 → Agent 分析与 Validator 验证 → 去重、报告和反馈持久化。

关键位置：

- `zscope/`：产品代码、运行时 Agent/Skill、Workflow 和内置语义。
- `tests/`：Python 自动化测试。
- `test/range/`：故意植入缺陷的 Range Benchmark fixture，不是普通示例项目。
- `scripts/`：回归评测、外部 benchmark、发布聚合和维护脚本。
- `docs/modules/`：按稳定子系统组织的开发导航。
- `README.md`：安装、配置、CLI、WebUI、MCP 和常用开发命令。

根目录的 `AGENTS.md` 是仓库交接说明；`zscope/agents/*/AGENT.md` 是 Z-SCOPE 产品运行时加载的 Agent prompt。二者用途不同，不要把运行时 prompt 当作仓库说明，也不要为更新开发文档而改写它们。

## 先路由用户诉求

### 使用者路线

适用于安装、配置目标项目、执行扫描、选择后端、启动 WebUI/MCP、解释报告和排查运行问题。

1. 先读 `README.md` 的安装、端到端使用指南和后端对比。
2. 确认实际执行目录和实际配置文件，不要默认使用本仓库的配置。
3. 只在用户明确要求开发或修复产品时进入源码修改；普通使用问题优先给出配置、命令和环境诊断。
4. 涉及输出时区分单入口报告、批量报告、SARIF、快照目录和 KnowledgeDB，不把生成物当作源码。

### 开发者路线

适用于功能开发、缺陷修复、架构调整，以及 Agent、Skill、Workflow、后端、候选、验证、报告或测试变更。

1. 先读 `docs/architecture.md`，再按 [`docs/modules/README.md`](docs/modules/README.md) 进入对应子系统。
2. 修改前搜索调用方、配置模型和现有测试；不要仅凭文件名推断所有权。
3. 保持用户已有修改，不重写无关文件，不提交密钥、私有 endpoint 或本地 benchmark 配置。
   涉及候选、证明、缓存、报告聚合或人工反馈时，同时检查 `build_context_id` 是否贯穿；未知构建不是通配符，不能将另一编译变体的证据或误报决定复用过来。身份链路回归见 `tests/test_candidate_build_identity.py`，全变体扫描覆盖仍以报告中的 `metadata.build_coverage` 为准；该覆盖逐实例复核当前输入，`status="indexed"` 不再等于输入仍 current（陈旧实例进 `uncurrent_instances`，无收据记 `unmeasured`）。SVF/Saber 信号同样按编译命令归属：生产者给 `command_id` 与 `exact/ambiguous/unattributed` 判定，实例侧只经 `ScopedCodeIndex.get_instance_backend_signals()` 读，回归见 `tests/test_svf_build_identity.py`；链接组仍是多变体合并分析，不因此变成逐变体 SVF。
4. 优先运行与变更直接相关的测试，再按风险补充：

   ```bash
   python -m pytest -q <相关测试>
   python -m compileall -f -q zscope scripts test tests
   python -m mypy zscope
   ```

   测试与质量命令一律在 Linux 环境执行；Windows 上必须在 WSL Linux 用户态中运行（在 WSL 虚拟环境安装并执行），不要用原生 Windows 解释器形成测试结论。

5. 仅对需要格式化的 Python 变更运行 Black，避免无关的大范围格式化。

6. 资源包装器 native 核验改动运行 `tests/test_native_wrapper_inference.py`、`tests/test_resource_inference_coverage.py` 和 `tests/test_native_model_cache.py`；真实提取测试需在 Linux 设置 `Z_SCOPE_TEST_CLANG_INDEXER` 指向实际构建的批量工具。合成事实只验证隔离逻辑，不能代替 native 验收；缺收据或源码/CFG 冲突不能回退弱路径授权。覆盖诊断区分契约核验、消费者能力和规则实际执行，不能将入口外未测量 cleanup 或实验规则关闭解释为安全。

7. 跨 TU 对象路径修改运行 `tests/test_link_targets.py`、`tests/test_linked_lifecycle_paths.py` 及现有 lifecycle/protocol 回归。链接归属来自 `zscope-link-record` 实际重建并链接的记录，不来自 compile_commands、文件名或相同 BuildContext。native 签名/const ops 收据改动必须重编译真实工具后验收；各 TU 保留自身身份，未知目标/选择不可推广为全部清理，实验规则仍默认关闭。准备命令会重建所列对象，普通扫描只读记录。

8. 引用计数及池状态扩展运行 `tests/test_refcount_protocols.py`、`tests/test_refcount_integration.py` 和现有单槽池/路径/反馈回归。首批是 signed 32-bit 非原子计数，发布为 `standard_operation`，不能加入 deallocator 配对；零计数的 callback 必须实际重放到对应对象，逻辑归还不是物理 free。非并发执行前提独立进入验收及回答撤回链，默认实验开关不变；位宽、位域或 volatile/atomic 写入事实变化需实际重建 native 工具。

9. 句柄子域修改运行 `tests/test_handle_protocols.py`、`tests/test_handle_integration.py` 及现有 native/路径/反馈回归。当前为源码核验的 2–4 槽 signed 32-bit 自定义表；描述符代次、整数值和 dup 共享的底层对象分开，close 错误的状态不替代实际消费效果。标准 close 错误保持 unknown；此子域不模拟 OS fd/dup2。命名空间顺序独占与业务责任在验收阶段核实，回答撤销必须重开缺口；实验规则默认关闭。调用结果和局部写入的 native 类型事实改动须实际重建工具。

10. 锁模式或锁反证修改运行 `tests/test_lock_modes.py`、`tests/test_lock_coverage.py`、现有 review fact/契约/候选及规则治理测试。shared/exclusive/unknown 和成功条件必须随契约、转换及调用事件保留；读锁不能过滤写入候选，未知解锁及 cond_wait 不能遗留旧保护。强反证仅限当前编译事实中非逃逸 TU-static 锁与受限访问，透明 return 包装器需重新核对当前 AST；递归计数、升级、成员锁、任意辅助调用及 RAII 未支持时保持 unknown。调用方词法摘要只作上下文，不能授予强反证；实验规则默认关闭。

11. 有限 RAII 改动运行 `tests/test_raii_lifecycle.py` 及现有 lifecycle/review/native/构建身份回归。当前只核验单指针成员的局部 scoped heap guard：构造映射、真实析构与受限 custom deleter 都重新读取当前 AST，并与 native 构造/析构 USR、源码位置及精确 BuildContext 核对。正常退出与函数内明确 throw→catch(...) 的展开分别解释；未知异常、move/adopt/defer/release/reset、逃逸和锁 guard 保留缺口。`implicit_release` 标签和源码注解不授权 free/unlock；不把 guard 加入全局 deallocator 配对。native 生命周期事实变化必须实际重编译；实验规则默认关闭。

12. 当前协议增量修改运行 `tests/test_protocol_incremental_equivalence.py`、`tests/test_native_model_cache.py`、`tests/test_build_context.py` 及既有链接/协议反馈回归。头文件不存在、较高优先级查找及新增静态访问者也属于依赖；旧 depfile 不能证明这些否定前提仍成立。Review 热路径复核实际预处理输出后复用 AST/CFG，进程内收据同时检查当前契约版本；磁盘 JSON 不授权执行保存的命令。native `include-probes.v1` 记录存在性查询，独立于真正读取文件的摘要；查询结果进入 BuildContext，在发布/复用/消费前核对，新增或消失的文件必须失效。真实 native 改动先重建；本地受限对照不代表完整扫描、异步回调或需求调度已验收。

13. pthread 回调寿命改动运行 `tests/test_async_contracts.py`、`tests/test_async_paths.py`、`tests/test_async_incremental.py`、`tests/test_async_queue.py`、`tests/test_async_queue_incremental.py`、`tests/test_async_wait.py`、`tests/test_async_wait_incremental.py`、`tests/test_async_cleanup.py`、`tests/test_async_cleanup_incremental.py`、`tests/test_async_helpers.py`、`tests/test_async_helpers_incremental.py`、`tests/test_async_wake.py`、`tests/test_async_wake_incremental.py`、`tests/test_async_clock.py`、`tests/test_async_clock_incremental.py`、`tests/test_async_drain.py`、`tests/test_async_drain_incremental.py` 及现有对象路径/反馈/构建回归。当前解释 Linux glibc LP64、同 TU、直接系统 API、默认属性的一个工作者与 malloc/calloc 对象；单槽队列可在调用方首次 unlock 后推进工作者到其首次 unlock，保留局部任务引用，随后在 join 期间继续。实际同 TU 调用方 helper 的字段写入/返回守卫决定提交、取消和停止接收效果，不按名称授予 drain。只有成功 join 与真实回调退出才闭合该等待；同锁不能消除 UAF，清空槽位不撤销已取走的对象代次。`pthread-storage.v1` 限定当前系统声明的 opaque mutex/cond 字段，不解释 libc union，改 native 后先实际重建。单等待者 cond_wait 先释放精确 mutex，匹配当前条件变量实例的通知后才重获锁并发布返回值，再由实际 CFG 重检条件。提前通知不存额度，通知不等于完成，UAF 记录实际解锁/通知/join 恢复位置。默认延迟取消仅支持 cond_wait/testcancel 和最多四层的同 TU C/glibc cleanup，重获等待锁后才 LIFO 执行注册时保存的对象；取消不返回到被中断调用，pop(0)/pop(1) 分开。`pthread-cleanup.v1` 同时核对当前系统宏和展开 AST，保持原始 CFG；原样工具也不能用缺失收据授权。改写宏、异常/C++ 变体、控制跳出和 cleanup 内任意 helper/取消点保持缺口。新增 `PthreadCleanup.h` 参与 portable 批量组件指纹。同一 C 源文件和精确构建中的工作者直接 helper 可保留有界调用帧，参数/返回值只接受已知堆根指针、空值和受限整数；unlock/cond_wait 暂停期间不发布返回值，重复调用隔离局部帧，取消按注册帧归属执行清理且不伪造 helper 返回。递归、局部/字段地址传递或返回、间接目标、cleanup 内 helper 保留缺口；物理 free 仍核对实际标准根与对象代次。未覆盖唤醒序列、一般超时/时钟、调用方超时/无通知等待、取消模式切换/任意取消点、一般工作者 helper、未知锁属性、不同锁下共享访问、多工作者、动态目标和跨 TU 异步保留缺口。默认通知路径未闭合时可额外尝试一次无通知唤醒与一次独立的 timedwait 超时路径，单条路径最多一次无通知返回。`pthread-wait.v3` 核对当前系统 timespec 的 64-bit 字段、16-byte 大小/8-byte 对齐/0 与 64-bit 字段偏移、本地截止时间和直接系统 ETIMEDOUT 宏；timedwait 使用默认 CLOCK_REALTIME，clockwait 只接受直接系统 CLOCK_REALTIME/CLOCK_MONOTONIC 常量并核对宏出处及当前数值；返回 0 不证明时间早于截止，返回前必须重获原 mutex，普通返回发布 0、超时发布核验常量并执行当前 CFG。取消优先且不伪造返回；完整探索后再次核验源码和 Registry 当前性。修改 native 后实际重建，旧工具不能授权此切片。循环与调度有界，只覆盖成功分配/创建/同步及上述有界等待结果的选定路径，首次非法访问即停止，无观察不证明安全。默认关闭的 `object_protocol_path` 复用 S04 重放和集中业务验收；helper/回调/根契约/构建/回答变化撤回旧见证，局部冷/热对照不代表全扫描或完整 RAPI09/RAPI10 完成。

### 规则开发路线

适用于新增、修改或禁用 Java/C/C++ 确定性规则，以及 YAML rule pack 或 Python provider 开发。

1. 先读 [`docs/rule-development.md`](docs/rule-development.md) 和 [`docs/modules/analysis-pipeline.md`](docs/modules/analysis-pipeline.md)，区分确定性规则、backend signal、Skill trigger 与 finding suppression；不要用一类机制替代另一类。
2. 修改内置检测逻辑时，同一变更必须同步 `zscope/rules/builtin_catalog.yaml`：保持 canonical ID，并在规则语义、CWE（含 `additional_cwes` 附加 CWE）、Skill 或验证要求变化时递增 `revision`；`cwe` 仍是唯一治理主值，类别级兜底 CWE 集合集中在 `zscope/common/defect_cwe_map.py`，新增类别时同步该映射及其不变量测试。
3. 每条规则至少增加一个正例和一个反例，并运行目录一致性、候选快照和相关引擎测试；不得让实现产生未登记 ID。
4. 验证 `rules.disabled_ids` 只停止指定确定性检测器，不得意外抑制 SVF/Saber、Joern 等 backend signal、LLM 独立发现或已持久化的 finding suppression。
5. 规则治理变更不要改写 `zscope/agents/*/AGENT.md`。`SKILL.md` 只在 Skill 语言归属或证据契约本身变化时同步。

### Range Benchmark 路线

只要诉求涉及 `test/range`、recall、precision、F1、ground truth、发布门禁、正式扫描或回归比较，就必须同时遵循本路线。

1. 先读 [`docs/range-benchmark.md`](docs/range-benchmark.md) 和 [`docs/modules/benchmarking.md`](docs/modules/benchmarking.md)。
2. 正式 unified benchmark 需要 Linux 用户态和完整的 gcc、cmake、clangd、gllvm、LLVM、SVF/Saber 工具链：
   - 原生 Linux 运行 `zscope-benchmark`；Windows 上的 C/C++ 命令由该前端自动重启到 WSL。
   - 不得用原生 Windows Python 或 Windows 构建工具形成正式结果。
   - 执行 trial/formal 前先在实际运行的 Linux/WSL 用户态确认 `cmake`、`gcc`、`clang`、`clangd`、`gclang`、`get-bc`、`llvm-link`、`llvm-nm`、`wpa`、`saber` 均可由 `PATH` 解析，并用 `ldd` 确认 `wpa`/`saber` 没有缺失共享库。
   - trial/formal 必须显式提供 `Z_SCOPE_LLM_BASE_URL`、`Z_SCOPE_LLM_MODEL`、`Z_SCOPE_API_KEY`；benchmark 不会自动读取 `test/range/zscope.local.env`。Windows 前端只转发当前 Windows 进程中已经设置的变量。
   - WSL 中的 Python 环境必须已经安装当前 Z-SCOPE（推荐在 WSL 虚拟环境中执行 `python3 -m pip install -e .`），不能依赖 Windows Python 或仅依赖源码 checkout 恰好位于当前目录。
   - 完整安装、环境变量和 preflight 命令以 [`docs/range-benchmark.md`](docs/range-benchmark.md) 的“环境与门禁”为准；不要在工具缺失、SVF 动态库加载失败或 backend 降级后继续形成正式结论。
3. 扫描阶段不得把 `GROUND_TRUTH.md` 或 `benchmark/ground_truth.json` 放入 Z-SCOPE/LLM 分析上下文；ground truth 只能用于入口覆盖预检和扫描完成后的独立评分。
4. 不把 SVF/Saber 不可用后自动降级的结果标为正式 unified 结果。
5. `test/range` 含故意危险的 C 代码。除非任务明确要求演进 fixture 和 truth，否则不要“修复”其中植入的漏洞。

混合诉求采用叠加规则。例如修复 Range 漏检时，代码和测试修改遵循开发者路线；执行环境、答案隔离、评分和结论遵循 Range Benchmark 路线。

## 配置文件定位

- 启动前可用 `zscope-config prepare --config <path>` 或 Web 项目配置页的“检查已保存配置”核对实际路径、编译变体与工具存在性；共用只读准备接口，不执行模型、索引、扩展 provider 或历史 rollout。准备视图不代表工具运行、模型连接或扫描完整性已验证。
- 命令显式传入 `zscope -c <path>/zscope.yaml` 或 `--config` 时，以该文件为准。
- CLI 未显式传入配置时，使用进程执行目录中的 `./zscope.yaml`；找不到时应报错，而不是回退到本仓库配置。
- 仓库根目录的 `zscope.c_cpp.yaml` 与 `zscope.java.yaml` 只是按语言划分的参考配置，不是其他目标项目的全局配置入口；复制到目标项目后通常命名为 `zscope.yaml`。
- 操作配置前必须确认：当前工作目录、命令中的 `-c/--config`、配置内的 `project.root`。
- v2 的 `project.root` 的相对路径按进程工作目录解析；`source_root`、`compile_commands_path`、`entry_functions_list` 等项目相对路径再依据 `project.root` 解析。v3 的 `project.root` 相对配置文件目录解析，target 的 `compile_commands` 再相对工程 root。跨目录运行时核对版本及实际路径，避免把缓存和报告写到错误项目。

### 当前 public config v3

`zscope-init` 与两语言模板生成严格 v3。顶层仅允许 `config_version`、`llms`、`project`、`scan`、可选 `execution`；project 使用 `language/root/platform/targets`，各 target 使用 `id/compile_commands`。Java 不填写编译数据库且只接受 quick；C/C++ 使用 quick 或 overnight。llms 保留全部命名 profile，scan 使用 preset/focus/reproduction，execution 使用 timezone/stop_at/max_workers。

CLI prepare 与默认 Web saved-config 准备共用只读接口；validate 区分文档有效与当前执行组合。结构化编辑复用正式 parser，多目标可保存和检查，执行仍禁启，不能偷偷选择首目标。focus/reproduction/max_workers/platform 尚未消费；配置 execution.stop_at 已由 CLI 和新建持久作业消费，显式作业窗口优先，同 request_id 重放不重解析窗口；resume 不重新套用配置窗口。解析出的配置窗口若已过期，新建持久作业（Web `/api/jobs`、MCP `zscope.scan.run`）在创建时以 `stop_window_closed` 拒绝，不接受开局即停的作业；显式请求窗口不受该检查影响。owner 启动的 CLI 仅消费当前 job/run/owner/input 与运行目录绑定核实后的持久窗口；合法空窗口不回退配置，部分或失效绑定拒绝启动。其余消费端（停止新调度后的公平批次、完整 resume 语义）仍有剩余，不把此切片视为完整 U01/S08。v2 仍严格加载，下节字段表仅用于已有 v2 文档，不可混入 v3。

### public config v2 字段清单

顶层只允许 `config_version`、`llms`、`project`、`scan`、`indexing`、`concurrency` 和可选 `rules`，未知键严格报错。两份语言模板只展示常用子集，下列字段均合法；默认值、取值约束与相对路径基准以 `README.md` 的“配置字段参考”为准，本节只列字段与作用。

- `llms`：profile 表，`default` 必需，可新增命名 profile。字段：`base_urls`（多 endpoint 最闲优先分流）、`models`（按序回退）、`api_key`、`max_tokens`、`timeout`、`max_retries`、`retry_until_available`（瞬态错误无限重试）、`base_url_rate_limit_per_minute`、`base_url_max_concurrent_requests`、`supports_structured_output`（JSON 输出走 response_format）。`scan.llm_profiles` 把 modeling/analysis/validation 三角色绑定到命名 profile；Wiki 编译器读取 `wiki_compiler` profile。
- `project`：`language`、`root`、`source_root`、`id`（持久化标识）、单入口 `entry_function`（配 `entry_file_path`/`entry_signature` 消歧）、批量 `entry_functions_list`、`entry_discovery`（`enabled`/`search_root`/`interface_files`/`max_entries`/`max_functions`）、`include_paths`（源码扫描根，非空即替换）、`exclude_paths`、`compile_commands_path`（仅 C/C++）、`user_config_file`（语义工作簿）、`wiki`（`mode`/`auto_maintain`/`state_dir`/`compiler_enabled`/`documents.exclude`/`documents.classify.explanatory`/`documents.classify.generated`/`max_file_bytes`/`max_files`/`max_total_bytes`/`compiler_max_tokens`/`max_wall_seconds`/`max_constraints`）、`review_memory`（项目级人工误报模式归档和 advisory hint 配置）。
- `scan`：`depth`（fast/balanced/deep，Java 仅 fast）、`task`（空串启用全部 Skill）、`llm_profiles`。
- `indexing`：`backend`（C/C++：unified/clang/regex；Java：java_unified/java_source/joern）；`clang.frontend`（auto/batch/lsp，仅 C/C++）；`svf`（仅 C/C++：`scope`/`entry_depth`/`max_selected_tus`/`fallback`/`groups_file`/`always_include`/`exclusive_pools`/`shared_pools`/`heap_limit_mb`/`timeout_seconds`）；`java`（仅 Java：`structure_frontend`/`signals`/`extractor_command`/`provider_commands`）；`tools`（C/C++：`clangd`/`clang_indexer`/`gclang`/`get_bc`/`llvm_link`/`svf_bin_dir`；Java：`joern.command`/`joern.host`/`joern.port`/`joern.heap`）。
- `concurrency`：`entry_workers`、`validator_workers`、`investigator_workers`、`evidence_completion_workers`、`index_workers`、`wiki_compiler_workers`（可省略）、`svf_workers`（仅 C/C++）、`llm_max_inflight`，全部正整数。
- `rules`：`packs`（YAML 规则包）、`providers`（Python provider 入口）、`enabled_ids`、`disabled_ids`（优先于 enabled_ids，不抑制 backend signal）。

Agent 启停、分析预算、deadline、缓存与报告策略属于 RuntimeSpec（`zscope/config/runtime_defaults.yaml`），不进入用户 YAML；仅在 `Z_SCOPE_DEVELOPER_MODE=1` 时可用 `Z_SCOPE_RUNTIME_SPEC` 覆盖。

## 模块导航

- [执行与编排](docs/modules/execution-orchestration.md)
- [分析流水线](docs/modules/analysis-pipeline.md)
- [代码检索与后端](docs/modules/retrieval-backends.md)
- [Agent 运行时](docs/modules/agent-runtime.md)
- [配置、语义与状态](docs/modules/configuration-state.md)
- [Validator Review Memory](docs/modules/review-memory.md)
- [LLM Wiki](docs/modules/wiki.md)
- [接口与报告](docs/modules/interfaces-reporting.md)
- [Benchmark](docs/modules/benchmarking.md)

当子系统职责、公共行为、关键不变量或所有权发生变化时，同一变更中更新对应模块文档。纯内部重构不应复制大量实现细节到文档。

## Linux Portable 发布路线

发布入口为 `python3 scripts/portable_release.py`，在 Linux 或 WSL Ubuntu 中执行。构建基线是锁定的 Ubuntu 23.10 / glibc 2.38；不能直接拿 WSL 宿主 Ubuntu 24.04 的二进制拼包。运行时使用宿主 glibc，最低要求由逐包 ABI 报告和实际 smoke 结果决定，不能把构建版本或符号下限直接写成实测下限。

1. 首次准备 WSL（普通用户运行 Podman，只有安装系统前置软件需要 sudo）：

   ```bash
   sudo apt-get update
   sudo apt-get install -y podman uidmap slirp4netns fuse-overlayfs qemu-user-static binfmt-support python3-venv
   podman info --format '{{.Host.Security.Rootless}}'
   cat /proc/sys/fs/binfmt_misc/qemu-aarch64
   build_work="$HOME/.cache/zscope-portable"
   python3 scripts/portable_release.py bootstrap --work "$build_work"
   ```

   `--work` 必须位于 WSL Linux 文件系统，不能放在 `/mnt/c`；源码和最终 `--output` 可以在 Windows 挂载目录。x86_64 原生构建，aarch64 使用 QEMU 容器构建和运行测试。构建下载可使用宿主代理；验收容器固定 `--network=none`，不可为了通过验收改成 host 网络。

2. 仅在主动更新依赖时运行下面的维护命令，审查并保存锁文件变更；常规 `fetch/build` 不解析 latest、不改写锁：

   ```bash
   python3 scripts/portable/lock_sources.py --published-digests \
     --cache "$build_work/downloads" --output requirements/portable/toolchain.lock.json
   python3 scripts/portable/lock_runtime_images.py \
     --toolchain-lock requirements/portable/toolchain.lock.json \
     --output requirements/portable/runtime-images.lock.json
   python3 scripts/portable/lock_redistribution.py \
     --toolchain-lock requirements/portable/toolchain.lock.json \
     --output requirements/portable/redistribution.lock.json
   python3 scripts/portable/lock_system_sources.py \
     --toolchain-lock requirements/portable/toolchain.lock.json \
     --cache "$build_work/source-indices" \
     --output requirements/portable/system-sources.lock.json
   python3 scripts/portable/web_assets.py --update
   # 新版本的 JDK/Maven 下载到锁指定的 downloads 文件后，在容器中准备缓存。
   # 只有此维护步骤使用网络；普通 build 必须使用已经冻结的缓存。
   podman run --rm --network host --userns keep-id \
     -v "$PWD:/inputs:ro" -v "$build_work/x86_64:/work:rw" \
     -v "$build_work/downloads:/downloads:ro" \
     localhost/zscope-portable-builder:x86_64 \
     python3 /inputs/scripts/portable/native.py \
     --lock /inputs/requirements/portable/toolchain.lock.json \
     --source /inputs --downloads /downloads --work /work \
     --arch x86_64 --profile java --component java --refresh-maven-lock
   python3 scripts/portable/freeze_maven.py \
     --repository "$build_work/x86_64/prefix/maven-repository" \
     --output requirements/portable/maven.lock.json
   ```

   `toolchain.lock.json` 固定源码、下载来源、SHA-256、两架构基础镜像和 apt 签名索引摘要；`runtime-images.lock.json` 固定兼容性测试镜像。Python 两个 profile 的完整带哈希依赖分别在 `requirements/portable/py313-cpp.txt` 和 `py313-java.txt`。Maven 构建缓存由 `maven.lock.json` 校验，常规构建强制 offline；gllvm 1.3.0 仅使用自身代码和 Go 标准库，不需要在线解析 Go 模块。

3. 下载、构建、逐包验收：

   ```bash
   python3 scripts/portable_release.py fetch --work "$build_work"
   python3 scripts/portable_release.py build --work "$build_work" --output dist/portable --arm-compiler-helper
   python3 scripts/portable_release.py verify --run-smoke --work "$build_work" --output dist/portable
   ```

   `--arm-compiler-helper` 在 x86_64 的 LLVM 已构建后创建包外辅助编译器；ARM 容器中的配置探针、目标 sysroot、生成的工具和验收仍使用 ARM/QEMU，辅助工具清单记录于构建证据。省略该参数则连编译器也在 QEMU 中执行。单独构建 ARM C/C++ 并启用此参数时，先构建 x86_64 C/C++。辅助工具、Go 和 Rust 不进入发布包。

   不要同时对同一 `--work` 的同一架构执行多个 `build`。Python 构建会在编译参数改变时清理旧对象；ARM CMake 构建会在辅助编译器指纹改变时清理旧构建目录。不能仅更新完成标记来跳过重建，否则 manifest 中的工具与真实对象来源会不一致。

   分架构执行时，后续 `build` 用 `--source-snapshot "$build_work/snapshots/<首次构建的摘要>"` 复用首次捕获的源码，避免工作区后续变化进入部分发布包。入口逐文件验证快照摘要，四包必须来自同一快照；调整产品或发布代码后重新捕获并重建四包。重建会删除对应旧 smoke 证据，必须重新验收。

   下载必须完成后再启动构建，不要同时更新锁与运行构建。大文件代理截断时可在能直连官方来源的环境设置 `ZSCOPE_DOWNLOAD_DIRECT=1` 后运行 `fetch`，使用分段重试并核对最终完整 SHA-256；不得接受截断文件或跳过摘要检查。

   每包验收最多同时运行两个 glibc 容器，各自使用独立的 HOME、工程目录、网络命名空间和日志；不要再对同一个归档重复启动验收。

   `fetch` 在 WSL 宿主预先解压已经校验的源码，避免 QEMU 文件解压成为瓶颈；目标编译及执行仍在对应架构容器中。WebUI 的本地资源及许可证随 Python 包发布，`web-assets.lock.json` 校验其摘要；新增 Tailwind 类或升级前端依赖后显式运行 `web_assets.py --update`，审查生成的静态 CSS 与锁。Tailwind 制作程序不进入发布件，WebUI 不依赖外部 CDN、在线字体或 Node.js。

   `--profile cpp|java|all`、`--arch x86_64|aarch64|all` 可用于单包定位问题；完整发布必须齐备四个 `zscope-{version}-linux-{arch}-{profile}-portable.tar.gz` 及各自 ABI JSON/Markdown、SPDX SBOM、smoke 证据和校验和。`verify` 不因选择了单 profile 而放宽完整发布矩阵。最高 GLIBC/GLIBCXX/CXXABI 需求、对应文件与符号见 ABI JSON；编译 sysroot 单列。测试包含 glibc 2.38、2.39、推导下限及 2.34 尝试，2.34 失败必须记录真实原因，ARM 结果注明 QEMU。

   用户明确要求单独的 Linux x86 C/C++ 本地验证包时，架构为 `x86_64`，使用独立输出目录，执行下面的单包路线。`verify-package` 检查真实归档、源码材料、校验和、ABI、SBOM 及离线运行证据，只接受 `unsigned-local`，不会生成正式四包发布通过报告；正式发布仍执行上面的完整 `verify`。

   ```bash
   python3 scripts/portable_release.py build --arch x86_64 --profile cpp \
     --jobs 4 --work "$build_work" --output dist/portable-cpp-x86_64
   python3 scripts/portable_release.py verify-package --arch x86_64 --profile cpp \
     --run-smoke --work "$build_work" --output dist/portable-cpp-x86_64
   ```

   C/C++ 构建在锁定容器内自动执行 `scripts/portable/clang_indexer.py`：使用 LLVM/Clang 18.1.0 的开发构建树编译 `native/clang-indexer`，将批量工具、Clang 库及 resource headers 一起安装至包内 `tools/llvm18/`，通过 `bin/zscope-clang-indexer` 启动。禁止复制 WSL 宿主开发包编译的工具；Java 包不包含该工具。批量组件以源码、构建脚本、架构和 LLVM 构建指纹独立失效，并核对已安装产物摘要；变更后实际重编译，不修改完成标记冒充重建。

   Portable 用户解压即可使用批量工具，不需要安装 LLVM 开发包或再运行 `build_clang_indexer.py`。默认 `indexing.clang.frontend: auto` 从包内定位工具，显式 `indexing.tools.clang_indexer` 仍优先，模板不写绝对工具路径。验收必须验证含标准库头文件的 C++ TU、USR 引用/宏/类型/调用边和热缓存复用；严格 `batch` 下禁止 LSP 降级，成功 TU 的派生 LSP 请求必须为零。这些检查与原有 clangd、bitcode、WPA/Saber、WebUI、MCP 检查一起在普通用户、只读包、含空格路径和断网容器内运行。

   编译数据库前置处理也是 C/C++ 包验收门禁：批量工具必须声明 `zscope.clang-arguments.v1` 并支持 `--check-arguments`，使用包内 Clang SDK 做无 AST 的参数检查。验证原始数据库备份、warning 提升降级、未知转发参数删除、x86_64 的 `-m32`→`-m64`、热准备不启动检查进程且不改变数据库时间戳；结果记录为 `compile-commands-preparation`。`ArgumentCheck.h` 与共用参数策略参与批量组件构建指纹，不能只更新 Python 而沿用旧工具。原始响应文件保持不变，兼容副本及报告由项目侧 `.zscope-compile-commands/` 管理，不写只读发布包。

   `source-materials.json` 索引本次真实源码快照及分卷第三方源码包；`system-sources.lock.json` 固定 Ubuntu 对应源码，`redistribution.lock.json` 固定完整 JDK 源码。源码材料是附属发布资产，不装入运行目录。manifest v2 记录全部输入锁摘要、每包语言/架构、符号下限和实际测试下限；许可证在每包 `licenses/` 中，SBOM 同时列出文件、Python、Maven、Joern 和实际系统运行包。

4. 模板与运行时约定：`zscope.c_cpp.yaml`、`zscope.java.yaml`、随包示例及 `zscope-init` 不展示工具路径和 extractor/provider 命令。public config v2 的工具字段仍完整保留，实验可以手工写入；显式配置优先于包内默认，显式无效配置不得退回其他工具，源码安装继续使用 PATH。不得把运行时解析出的绝对路径写回配置。clangd 22.1.7 只用于索引；gllvm/SVF 3.2 的 bitcode 链路固定 LLVM/Clang 18.1.0。Java 包使用预编译 JAR、JDK 21 和 Maven，不包含 Gradle；Maven 业务依赖由工程提供，可用 `zscope-maven-cache` 导入用户缓存。CodeQL 和 LLM 服务由用户自备。

5. 本地允许保留已有源码修改，产物记录实际源码快照并标记 `unsigned-local`。正式发布必须干净提交、匹配 `v{version}` tag，构建加 `--formal`；无私钥时不能绕过正式签名门禁：

   ```bash
   python3 scripts/portable_release.py sign --output dist/portable --private-key /secure/release-key.pem
   python3 scripts/portable_release.py verify --formal --output dist/portable
   ```

   每个资产必须小于 2 GiB。签名覆盖 manifest 与所有资产校验和；签名后不要重写 manifest/smoke 文件。正式 `.github/workflows/release.yml` 仍须验证相同源码 SHA 的 Formal Benchmark 和受保护 Balanced Default Attestation，再运行 release-candidate 门禁并创建 draft。portable smoke 只验证发行环境和实际工具链，不替代正式准确率 benchmark。旧 manifest v1 分体资产继续走原校验路径。

6. 发布代码或交接文档改动后，运行配置、后端、发布和交接文档测试，以及仓库要求的 compileall/mypy；不能把工具缺失、Java builtin 回退、SVF/Saber 不可用或未运行的 smoke 标记为通过。对外发布前同时核对许可证、对应源码材料及全部四包的证据。

## 中文与编码

- 仓库 Markdown 使用 UTF-8 无 BOM、LF 换行并保留文件末尾换行。
- Windows PowerShell 读取中文时显式使用 `Get-Content -Encoding utf8`；不要用默认编码读取后再覆盖原文件。
- 不使用默认编码的 `Set-Content`、`Out-File` 或 shell 重定向改写中文文档。优先使用能保持 UTF-8 的补丁或编辑工具。
- 终端显示乱码不代表文件已损坏。先以严格 UTF-8 解码或检查原始字节，再决定是否修复；禁止凭显示结果盲目转码。
- 修改交接文档后运行 `python -m pytest -q tests/test_agent_docs.py`。

## 文档维护边界

- Agent 与专业扫描后续开发以 [`docs/Z-Scope_Agent_Implementation_Plan/zscope-agent-implementation-plan/README.md`](docs/Z-Scope_Agent_Implementation_Plan/zscope-agent-implementation-plan/README.md) 为规划入口。该包区分本地现状与待开发能力；其中新配置、命令和状态不是当前产品接口。
- 此路线优先级为低误报、高召回、扫描性能、项目理解、使用体验；专业扫描优先，通用 Coding 后置。默认面向非工作时间运行，交互集中于启动和验收；自动复现使用独立目录，默认不改业务源码。Linux 先闭环，再扩展嵌入式/RTOS。
- 此路线不承担旧接口兼容负担，可替换冗余实现；采用相关正反例和实际验证，不新增代码冻结、多级审批或权限/沙箱平台。产品不增加网页搜索、抓取、浏览器或任意 URL 读取能力，本地 WebUI 与已有模型连接继续保留。
- 实施时同步用户指南、配置模板/初始化器、对应模块与必要的规则/Skill 契约；不把计划文字直接当已实现行为，不改写历史 benchmark 或发行验证结果。
- 此计划的实际落地状态见 [实施记录](docs/Z-Scope_Agent_Implementation_Plan/zscope-agent-implementation-plan/21_IMPLEMENTATION_STATUS.md)。构建实例事实与旧函数导航投影必须区分；不能把新增实例存储当作全部扫描消费者已完成多变体隔离。
- 条件资源协议维护时区分引用留存、清理责任和逻辑池归还。单槽协议的源码核验依赖当前 native 资源事实收据；修改 `native/clang-indexer/ProgramEvents.h` 后先重建再运行真实 native 正反例，不能用旧工具或仅合成事件宣布通过。相关入口和测试见配置/状态模块文档。
- 槽位归还路径回归见 `tests/test_retained_slot_teardown.py`。本地摘除只描述槽位值，不能证明归还 guard 成立、代次一致或跨 complete/cancel 安全；未闭合义务必须传到 Validator。新增规则 `zscope.c_cpp.cpp_clang_cfg.retained_slot_release` 仍为实验性、默认关闭，不把显式启用实验的候选结果写成正式准确率。
- 同 TU 对象路径回归见 `tests/test_lifecycle_paths.py`。`object_protocol_path` 使用 native CFG 入口/出口和 `lifecycle-value-facts.v1`，按真实调用帧、参数、字段、池实例及获取代次解释具体路径；没有入口输入、未知调用、循环或未支持的类型转换时保留缺口。获取代次复用 `ObjectRef`，不等于业务计数器永不回绕。源码留存和实际清理路径不能代替业务释放规范；业务责任、责任终点的专门义务不能被普通补证或模型高分关闭。该规则同样实验性、默认关闭。
- S04 对象协议验收见 `tests/test_protocol_assessment.py`。Validator 使用当前 native 事实和运行时契约注册表重放路径，绑定源码/契约摘要后才投影 `business_conditional`；技术缺口、失效或未核验路径投影 `protocol_pending`。两者仍属于统一 `needs_review`。业务前提标记为分析提出的未确认要求，源码效果不代表业务规范，入口退出不自动成为责任终点。报告载入不能复用进程内重放收据，关闭模型也需重放；不要用序列化字段、模型高分或删除缺口清单授权确认。问题集中在报告验收，不新增扫描中途交互。

- 模块文档记录稳定职责、入口、不变量和测试，不记录容易过期的文件数量、漏洞数量或历史 benchmark 成绩。
- 业务前提反馈见 `tests/test_protocol_feedback.py` 和 `tests/test_protocol_review_ui.py`。Web 验收页只对服务端报告中的具体前提写入项目现有 `user_config.state.db`，保留来源、精确对象/构建/路径范围与回答版本历史，不写 suppression/baseline。全部前提明确成立且当前技术路径完整时，由专门程序检查器签发限定范围的确认；否定或撤销前提不等于代码安全。修改回答后，下次扫描按依赖重新验证并重新登记候选台账；扫描中修改也需重核验。前端草稿、版本冲突和迟到响应必须有回归，不能把普通报告导入或模型文本当业务回答来源。
- `docs/architecture.md` 负责端到端架构，`README.md` 负责用户使用，`docs/range-benchmark.md` 负责 Range 协议；模块文档不要重复维护这些全文。
- 新增 `zscope/` 顶层包时，必须在 `docs/modules/README.md` 和某一份模块文档的 `covers` 元数据中登记，且只能登记一次。

调用方 cond_wait 的受限 drain 复用现有同 TU 队列解释器：释放精确 mutex 后推进工作者至真实通知及原锁释放，返回前重获锁并执行当前谓词 CFG；最多四次调用方等待，只有实际进入等待的调用帧获得有界循环重检。相同条件变量同时绑定不同 mutex 保持缺口；通知、清空 active 或等待返回不设置 worker complete/joined，也不授权销毁队列。调度调用路径必须保留入口到调用方 helper 的边及工作者活动帧；cleanup 根注册帧按实际调度前缀深度展开。调用方超时、无通知返回、取消与多工作者仍未支持，实验规则默认关闭；新增/删改谓词、通知、回调、根契约与释放次序沿原 S04/增量链复核。
