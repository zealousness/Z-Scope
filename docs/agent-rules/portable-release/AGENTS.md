# Linux Portable 发布路线

[返回根入口](../../../AGENTS.md) · portable 构建、依赖锁、发行、ABI/SBOM、smoke 或发布交接文档变化时读取。

发布入口为 `python3 scripts/portable_release.py`，在 Linux 或 WSL Ubuntu 中执行。构建基线是锁定的 Ubuntu 23.10 / glibc 2.38；不能直接拿 WSL 宿主 Ubuntu 24.04 的二进制拼包。运行时使用宿主 glibc，最低要求由逐包 ABI 报告和实际 smoke 结果决定，不能把构建版本或符号下限直接写成实测下限。

## 按交付目标选择范围

- 日常修复和发布脚本开发先运行受影响的检查，不默认构建四包、冻结源码、制作额外快照或执行 dry-run。
- 单平台/单语言本地交付直接选择对应 `--arch`、`--profile`，运行该包的 `verify-package --run-smoke`；可保留工作区修改，产物如实标为 `unsigned-local`，不等待其他平台、签名或正式 benchmark。
- 只有交付目标是完整四包集时才使用完整 `verify`；只有选择现有 `--formal` / 发布 CI 渠道时才适用其干净提交、同源码、签名、Formal Benchmark 和 attestation 条件。“准备一个新版本”不自动增加上述全部渠道要求，也不能把本地包宣称为正式验收通过。
- 构建器自动捕获的源码快照用于标记实际输入，不冻结可编辑工作区，不要求额外人工冻结/签发。根据实际质量目标验证交付物，已有有效检查不重复执行；真正更换产物或受影响输入时再补对应验证。

## 构建与发布参考

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

3. 下载、构建、逐包验收。下面是完整四包交付的命令；单包任务使用后面的 `build --arch/--profile` 与 `verify-package`，不默认执行全矩阵：

   ```bash
   python3 scripts/portable_release.py fetch --work "$build_work"
   python3 scripts/portable_release.py build --work "$build_work" --output dist/portable --arm-compiler-helper
   python3 scripts/portable_release.py verify --run-smoke --work "$build_work" --output dist/portable
   ```

   `--arm-compiler-helper` 在 x86_64 的 LLVM 已构建后创建包外辅助编译器；ARM 容器中的配置探针、目标 sysroot、生成的工具和验收仍使用 ARM/QEMU，辅助工具清单记录于构建证据。省略该参数则连编译器也在 QEMU 中执行。单独构建 ARM C/C++ 并启用此参数时，先构建 x86_64 C/C++。辅助工具、Go 和 Rust 不进入发布包。

   不要同时对同一 `--work` 的同一架构执行多个 `build`。Python 构建会在编译参数改变时清理旧对象；ARM CMake 构建会在辅助编译器指纹改变时清理旧构建目录。不能仅更新完成标记来跳过重建，否则 manifest 中的工具与真实对象来源会不一致。

   只有要把分架构构建的包组合为同一完整发布集时，后续 `build` 才用 `--source-snapshot "$build_work/snapshots/<首次构建的摘要>"` 复用首次捕获的源码；入口会核对快照摘要。工作区仍可继续修改，旧快照只代表那次构建。要交付新改动时捕获新的输入：单包目标只重建所选包；完整四包目标在组装时仍须满足同一快照，构建器可复用指纹未变化的组件。实际重建的包会删除其旧 smoke 证据，需要验证新包；不因此重跑无关单测、LLM benchmark 或其他未交付平台。

   下载必须完成后再启动构建，不要同时更新锁与运行构建。大文件代理截断时可在能直连官方来源的环境设置 `ZSCOPE_DOWNLOAD_DIRECT=1` 后运行 `fetch`，使用分段重试并核对最终完整 SHA-256；不得接受截断文件或跳过摘要检查。

   每包验收最多同时运行两个 glibc 容器，各自使用独立的 HOME、工程目录、网络命名空间和日志；不要再对同一个归档重复启动验收。

   `fetch` 在 WSL 宿主预先解压已经校验的源码，避免 QEMU 文件解压成为瓶颈；目标编译及执行仍在对应架构容器中。WebUI 的本地资源及许可证随 Python 包发布，`web-assets.lock.json` 校验其摘要；新增 Tailwind 类或升级前端依赖后显式运行 `web_assets.py --update`，审查生成的静态 CSS 与锁。Tailwind 制作程序不进入发布件，WebUI 不依赖外部 CDN、在线字体或 Node.js。

   `--profile cpp|java|all`、`--arch x86_64|aarch64|all` 可用于单包定位问题；完整发布必须齐备四个 `zscope-{version}-linux-{arch}-{profile}-portable.tar.gz` 及各自 ABI JSON/Markdown、SPDX SBOM、smoke 证据和校验和。`verify` 不因选择了单 profile 而放宽完整发布矩阵。最高 GLIBC/GLIBCXX/CXXABI 需求、对应文件与符号见 ABI JSON；编译 sysroot 单列。测试包含 glibc 2.38、2.39、推导下限及 2.34 尝试，2.34 失败必须记录真实原因，ARM 结果注明 QEMU。

   交付目标为单平台/单语言本地包时，选择对应架构和 profile，使用独立输出目录并执行单包路线。以下以 Linux x86 C/C++（`x86_64` / `cpp`）为例。`verify-package` 检查真实归档、源码材料、校验和、ABI、SBOM 及离线运行证据，只接受 `unsigned-local`，不会生成正式四包发布通过报告；正式发布仍执行上面的完整 `verify`。

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

4. 模板与运行时约定：`zscope.c_cpp.yaml`、`zscope.java.yaml`、随包示例及 `zscope-init` 不展示工具路径和 extractor/provider 命令。public config v3 的工具字段仍完整保留，实验可以手工写入；显式配置优先于包内默认，显式无效配置不得退回其他工具，源码安装继续使用 PATH。不得把运行时解析出的绝对路径写回配置。clangd 22.1.7 只用于索引；gllvm/SVF 3.2 的 bitcode 链路固定 LLVM/Clang 18.1.0。Java 包使用预编译 JAR、JDK 21 和 Maven，不包含 Gradle；Maven 业务依赖由工程提供，可用 `zscope-maven-cache` 导入用户缓存。CodeQL 和 LLM 服务由用户自备。

5. 本地交付允许已有源码修改，产物记录实际源码快照并标记 `unsigned-local`，无需先整理成干净提交、tag 或签名。只有选择现有正式发布渠道时，才按其实际要求使用干净提交、匹配 `v{version}` tag 和 `--formal`；该渠道需要真实签名：

   ```bash
   python3 scripts/portable_release.py sign --output dist/portable --private-key /secure/release-key.pem
   python3 scripts/portable_release.py verify --formal --output dist/portable
   ```

   每个资产必须小于 2 GiB。签名覆盖 manifest 与所有资产校验和；签名后不要重写 manifest/smoke 文件。正式 `.github/workflows/release.yml` 仍须验证相同源码 SHA 的 Formal Benchmark 和受保护 Balanced Default Attestation，再运行 release-candidate 门禁并创建 draft。portable smoke 只验证发行环境和实际工具链，不替代正式准确率 benchmark。旧 manifest v1 分体资产继续走原校验路径。

6. 发布代码或发布交接文档改动后，按实际影响选择配置、后端、发布或交接文档的相关测试，不默认把它们全部重跑。纯文档改动按[文档维护规则](../documentation/AGENTS.md)验证；Python 改动的 compileall/mypy 范围按[开发者路线](../development/AGENTS.md)确定，只有明确跨模块影响、真实故障证据或用户明确要求时才扩大测试范围。真正构建或发布时，执行所选包/渠道的实际验证；单包需要该包的 smoke，签名与完整发布验证只适用于对应正式渠道；不能把工具缺失、Java builtin 回退、SVF/Saber 不可用或未运行的 smoke 标记为通过。交付前核对实际交付资产的许可证、对应源码材料和验证结果；只有完整四包渠道才核对全部四包证据，不把它扩大成每次开发和本地交付的门槛。
