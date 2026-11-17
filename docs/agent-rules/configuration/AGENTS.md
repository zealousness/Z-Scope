# 配置文件定位与公共配置

[返回根入口](../../../AGENTS.md) · 配置、工程定位、Web 项目/计划、执行窗口及项目原语准备变化时读取相关章节。

## 配置文件定位

- 启动前可用 `zscope-config prepare --config <path>` 或 Web 项目配置页的“检查已保存配置”核对实际路径、编译变体与工具存在性；共用只读准备接口，不执行模型、索引、扩展 provider 或历史 rollout。准备视图不代表工具运行、模型连接或扫描完整性已验证。
- 命令显式传入 `zscope -c <path>/zscope.yaml` 或 `--config` 时，以该文件为准。
- 普通扫描 CLI 未显式传入配置时，使用进程执行目录中的 `./zscope.yaml`；找不到时应报错，而不是回退到本仓库配置。`zscope --web` 是例外：可以无配置进入最近工程与创建向导，不自动绑定本仓库配置。
- 仓库根目录的 `zscope.c_cpp.yaml` 与 `zscope.java.yaml` 只是按语言划分的参考配置，不是其他目标项目的全局配置入口；复制到目标项目后通常命名为 `zscope.yaml`。
- 操作配置前必须确认：当前工作目录、命令中的 `-c/--config`、实际加载的 YAML 绝对路径及其父目录。
- 当前仅接受 v3，以 YAML 所在目录为唯一工程根，不再接受公共 `project.root` 或 `source_root` 字段。编译数据库、入口列表、扫描目录等工程相对路径从该目录解析；跨目录运行不会改变工程根。旧双根配置和 quick/overnight 预设必须显式迁移：旧 v2 相对根须提供原执行目录，迁移输出须放回原工程根；分离的源码根不能静默合并，先人工核对范围。
- Web 最近工程 registry 为执行用户的 `~/.zscope/web/projects.json`，只记录 YAML 路径与定位元数据，不保存模型密钥。目录浏览属于实际 Linux/WSL 执行机；请求必须绑定已选工程身份，标签页、迟到响应和符号链接变化不能借用另一工程。配置可随相对工程路径迁移；绝对编译数据库、链接记录及 native 收据须在目标机重建，不承诺跨机缓存直接复用。

### 当前 public config v3

`zscope-init` 与两语言模板生成严格 v3。顶层允许 `config_version`、`llms`、`project`、`scan`，以及可选 `execution/indexing/concurrency/rules`；project 使用 `language/platform/targets` 和 C/C++ 的 `semantics_file`，各 target 使用 `id/compile_commands`。`semantics_file` 必须相对 YAML 所在工程目录且不得越出工程；Java 禁止该字段。三种模式统一为 fast/balanced/deep（快速/均衡/深度）；Java 不填写编译数据库且只接受 fast。llms 保留全部命名 profile，scan 使用 preset/focus/reproduction，execution 使用 timezone/stop_at/max_workers。

CLI prepare 与默认 Web saved-config 准备共用只读接口；validate 区分文档有效与当前执行组合。结构化编辑复用正式 parser，多目标可保存和检查，执行仍禁启，不能偷偷选择首目标。focus/reproduction/max_workers/platform 尚未消费；配置 execution.stop_at 已由 CLI 和新建持久作业消费，显式作业窗口优先，同 request_id 重放不重解析窗口；resume 不重新套用配置窗口。解析出的配置窗口若已过期，新建持久作业（Web `/api/jobs`、MCP `zscope.scan.run`）在创建时以 `stop_window_closed` 拒绝，不接受开局即停的作业；显式请求窗口不受该检查影响。owner 启动的 CLI 仅消费当前 job/run/owner/input 与运行目录绑定核实后的持久窗口；合法空窗口不回退配置，部分或失效绑定拒绝启动。其余消费端（停止新调度后的公平批次、完整 resume 语义）仍有剩余，不把此切片视为完整 U01/S08。v2 不再加载；迁移器显式转换旧 depth 与编译数据库字段，保留现有高级设置。省略 preset 时两语言统一为 fast。

扫描时间计划独立于模式：可指定开始、直到完成或总截止，并可选择每日跨午夜窗口。`/api/schedules` 在当前已选 YAML 作用域持久保存，独立协调器复用 ScanJobService/owner；新窗口同 job 使用新 run/token 和未来截止，不继承过期窗口。默认每日循环只在后台真实作业完成时终止，零问题或前端百分比不授权完成；输入变化、外部 rearm 和失效 owner 不得自动接管。取消须核对计划版本与 job/run/input；只承诺复用经核对的可恢复状态，不保证精确仅剩余。关闭网页或切换工程不停止已启动后台；关闭 WSL/主机或休眠时无法计算，重开原工程可唤起计划，不是 OS 自启动。回归见 `tests/test_scan_schedules.py`。

项目原语准备独立于扫描：CLI `--discover-primitives` 与 Web 原语页共享准备核心，`zscope.semantics.yaml` 是唯一人工配置权威。当前 native 标准根与受限包装器可自动推导，其余项目接口需审阅；扫描只读消费当前 BuildContext/USR 下的 confirmed 契约，pending/stale/unresolved 不能授权执行。旧 XLSX 仅作单向迁移输入，反馈与业务回答仍在状态库。相关回归入口为 `tests/test_project_semantics.py`、`tests/test_automatic_semantics.py`、`tests/test_primitive_contract_proposals.py`、`tests/test_semantics_workflow.py`，按实际受影响的准备、推导、提案或消费路径选择；native 事实变更仍须先重建真实工具，再验证相关路径。

### 唯一 public config v3 字段清单

顶层只允许 `config_version`、`llms`、`project`、`scan`、`execution`、`indexing`、`concurrency` 和 `rules`，未知键严格报错。两份语言模板只展示常用子集，下列字段均合法；默认值、取值约束与相对路径基准以 `README.md` 的“配置字段参考”为准，本节只列字段与作用。

- `llms`：profile 表，`default` 必需，可新增命名 profile。字段：`base_urls`（多 endpoint 最闲优先分流）、`models`（按序回退）、`api_key`、`max_tokens`（默认 8192）、`context_window`（输入加输出容量，默认 192000）、`model_context_windows`（精确模型名覆盖容量）、`timeout`、`max_retries`、`retry_until_available`（瞬态错误无限重试）、`base_url_rate_limit_per_minute`、`base_url_max_concurrent_requests`、`supports_structured_output`（JSON 输出走 response_format）。`scan.llm_profiles` 把 modeling/analysis/validation 三角色绑定到命名 profile；Wiki 编译器读取 `wiki_compiler` profile。
- `project`：`language`、`id`（持久化标识）、单入口 `entry_function`（配 `entry_file_path`/`entry_signature` 消歧）、批量 `entry_functions_list`、`entry_discovery`（`enabled`/`search_root`/`interface_files`/`max_entries`/`max_functions`）、`include_paths`（源码扫描目录，相对 YAML 所在工程根，非空即替换）、`exclude_paths`、`targets`（id 必填，C/C++ 还需 compile_commands，Java 禁止编译数据库）、`semantics_file`（C/C++ 项目语义 YAML）、`user_config_file`（旧工作簿定位与迁移字段，不再授予 C/C++ 执行语义）、`wiki`（`mode`/`auto_maintain`/`state_dir`/`compiler_enabled`/`documents.exclude`/`documents.classify.explanatory`/`documents.classify.generated`/`max_file_bytes`/`max_files`/`max_total_bytes`/`compiler_max_tokens`/`max_wall_seconds`/`max_constraints`）、`review_memory`（项目级人工误报模式归档和 advisory hint 配置）。
- `scan`：`preset`（fast/balanced/deep，两语言默认 fast，Java 仅 fast）、`focus/reproduction`（仅声明）、`task`（空串启用全部 Skill）、`llm_profiles`。
- `indexing`：`backend`（C/C++：unified/clang/regex；Java：java_unified/java_source/joern）；`clang.frontend`（auto/batch/lsp，仅 C/C++）；`svf`（仅 C/C++：`scope`/`entry_depth`/`max_selected_tus`/`fallback`/`groups_file`/`always_include`/`exclusive_pools`/`shared_pools`/`heap_limit_mb`/`timeout_seconds`）；`java`（仅 Java：`structure_frontend`/`signals`/`extractor_command`/`provider_commands`）；`tools`（C/C++：`clangd`/`clang_indexer`/`gclang`/`get_bc`/`llvm_link`/`svf_bin_dir`；Java：`joern.command`/`joern.host`/`joern.port`/`joern.heap`）。
- `execution`：timezone/stop_at 提供本轮窗口；max_workers 尚未消费，实际 worker 数使用 concurrency。
- `concurrency`：`entry_workers`、`validator_workers`、`investigator_workers`、`evidence_completion_workers`、`index_workers`、`wiki_compiler_workers`（可省略）、`svf_workers`（仅 C/C++）、`llm_max_inflight`，全部正整数。
- `rules`：`packs`（YAML 规则包）、`providers`（Python provider 入口）、`enabled_ids`、`disabled_ids`（优先于 enabled_ids，不抑制 backend signal）。

Agent 启停、分析预算、deadline、缓存与报告策略属于 RuntimeSpec（`zscope/config/runtime_defaults.yaml`），不进入用户 YAML；仅在 `Z_SCOPE_DEVELOPER_MODE=1` 时可用 `Z_SCOPE_RUNTIME_SPEC` 覆盖。
