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
4. 优先运行与变更直接相关的测试，再按风险补充：

   ```bash
   python -m pytest -q <相关测试>
   python -m compileall -f -q zscope scripts test tests
   python -m mypy zscope
   ```

   测试与质量命令一律在 Linux 环境执行；Windows 上必须在 WSL Linux 用户态中运行（在 WSL 虚拟环境安装并执行），不要用原生 Windows 解释器形成测试结论。

5. 仅对需要格式化的 Python 变更运行 Black，避免无关的大范围格式化。

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

- 命令显式传入 `zscope -c <path>/zscope.yaml` 或 `--config` 时，以该文件为准。
- CLI 未显式传入配置时，使用进程执行目录中的 `./zscope.yaml`；找不到时应报错，而不是回退到本仓库配置。
- 仓库根目录的 `zscope.c_cpp.yaml` 与 `zscope.java.yaml` 只是按语言划分的参考配置，不是其他目标项目的全局配置入口；复制到目标项目后通常命名为 `zscope.yaml`。
- 操作配置前必须确认：当前工作目录、命令中的 `-c/--config`、配置内的 `project.root`。
- `project.root` 的相对路径按进程工作目录解析；`source_root`、`compile_commands_path`、`entry_functions_list` 等项目相对路径再依据 `project.root` 解析。跨目录运行时优先使用明确路径，避免把缓存和报告写到错误项目。

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

- 模块文档记录稳定职责、入口、不变量和测试，不记录容易过期的文件数量、漏洞数量或历史 benchmark 成绩。
- `docs/architecture.md` 负责端到端架构，`README.md` 负责用户使用，`docs/range-benchmark.md` 负责 Range 协议；模块文档不要重复维护这些全文。
- 新增 `zscope/` 顶层包时，必须在 `docs/modules/README.md` 和某一份模块文档的 `covers` 元数据中登记，且只能登记一次。
