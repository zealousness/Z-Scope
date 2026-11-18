# 离线安装与发布

## Portable 四版本

Linux portable 发布按语言与宿主架构提供四个独立的 `tar.gz`：`zscope-{version}-linux-{x86_64|aarch64}-{cpp|java}-portable.tar.gz`。每包已经安装 CPython 3.13、Z-SCOPE 和对应 Python 依赖，解压后直接使用 `bin/` 中的 CLI、WebUI 和 MCP 入口。构建环境为 glibc 2.38，运行时使用宿主 glibc；实际兼容下限以该包 `.abi.json` 与 `.smoke.json` 为准。

```bash
sha256sum -c SHA256SUMS
tar -xzf zscope-1.3.2-linux-x86_64-cpp-portable.tar.gz
export PATH="$PWD/zscope-1.3.2-linux-x86_64-cpp-portable/bin:$PATH"
cd /path/to/project
zscope-init --help
zscope-doctor --json-output
zscope --help
```

正式资产还需使用可信发布公钥验证 `SHA256SUMS.sig`：`openssl dgst -sha256 -verify public-key.pem -signature SHA256SUMS.sig SHA256SUMS`。本地无密钥构建标记为 `unsigned-local`，不能作为已签名正式发布。发布目录可以移动、包含空格、通过符号链接访问或挂载为只读；配置、索引、报告仍位于工程或用户目录。启动器保持调用者工作目录。

| 包 | 分析环境 |
|---|---|
| cpp | 源码构建的 zscope-clang-indexer 批量前端、clangd 22.1.7；独立 LLVM/Clang 18.1.0、gllvm、SVF 3.2/WPA/Saber；GCC/G++、binutils、CMake、Make、Ninja、pkg-config、file/libmagic、编译 sysroot |
| java | JDK 21、Maven、JavaParser/Spoon/SootUp/WALA 预编译 JAR、Joern Java 建图与共享查询服务、工具 Maven 缓存 |

C/C++ 包不含 Java 专属依赖，Java 包不含 C/C++ 开发工具链或 Gradle。Git、证书及必要原生运行库随包提供。Java 工具默认使用预编译 JAR；Maven 种子缓存复制到 `~/.cache/zscope/maven`，与业务依赖导入共用目录，也可通过 `Z_SCOPE_MAVEN_REPO` 或 Maven 原生 `-Dmaven.repo.local` 指定工程缓存。

两份语言模板和 `zscope-init` 只展示分析配置。工具字段仍保留在 public config v3 中，开发实验可手工覆盖，优先级为显式配置、包内资源，源码安装继续使用 PATH；错误显式覆盖会失败，不改用其他工具。CodeQL、业务工程依赖和 LLM 服务由用户提供。维护、构建、兼容性验证及签名命令见 [AGENTS.md 的 Linux Portable 发布路线](../../AGENTS.md#linux-portable-发布路线)。

## 旧版分体资产兼容

以下说明保留给旧 manifest v1 分体资产及 `install.sh`，不用于安装 portable 包。旧资产面向 Ubuntu 24.04、glibc 2.38 及以上、Linux x86_64。主机须预装 `bash`、GNU `tar`、`zstd`、`sha256sum` 和 `openssl`。源码要求 Python 3.13 及以上。

旧分体 Release 包含：

- `zscope-app-{version}-linux-x86_64.tar.zst`：CPython 3.13、Z-SCOPE wheel、带哈希依赖 wheelhouse、pip zipapp 和启动所需文件。
- `zscope-deps-cpp-{toolset}-linux-x86_64.tar.zst`：C/C++ 工具链，不含 Joern。
- `zscope-deps-java-{toolset}-linux-x86_64.tar.zst`：Temurin 21、Maven、Joern、SootUp/WALA runner 和工具自身 Maven 依赖。
- `install.sh`、`release-manifest.json`、`SHA256SUMS`、`SHA256SUMS.sig`、`public-key.pem`、每个资产的 SPDX 2.3 SBOM、Python 约束和第三方许可证包。

CodeQL CLI 只支持用户自备探测与配置，不进入任何官方资产，原因与使用边界见 [CodeQL CLI 许可](https://github.com/github/codeql-cli-binaries/blob/main/LICENSE.md)。客户业务 Maven 依赖也不属于 Java 工具包；用 `zscope-maven-cache` 在联网机准备，在隔离机导入。发行二进制和 Maven 仓库只作为 GitHub Release 资产发布，仓库不跟踪这些对象；单资产限制与使用方式见 [GitHub Release 资产说明](https://docs.github.com/en/repositories/releasing-projects-on-github/about-releases)。

## 用户安装

把应用包、所需语言包、安装器、清单、签名和公钥放在同一目录：

```bash
./install.sh --profile cpp --asset-dir .
./install.sh --profile java --asset-dir .
./install.sh --profile all --asset-dir .
```

默认目录：

| 内容 | 路径 |
|---|---|
| 应用版本 | `~/.local/share/zscope/releases/{version}` |
| 语言工具链 | `~/.local/share/zscope/deps/{language}/{toolset}` |
| 当前版本链接 | `~/.local/share/zscope/current` |
| 用户配置 | `~/.config/zscope` |
| 缓存 | `~/.cache/zscope` |
| 启动器链接 | `~/.local/bin/zscope` |

安装器先验证签名和全部 SHA-256，再解压到 staging 目录、创建内部 venv、运行 `pip check`，最后原子切换 `current`。`cpp` profile 只安装基础 Python 依赖，`java`/`all` 才安装 `zscope[java]`（包含 Joern 客户端）；它不会编辑 shell profile，只会提示用户把 `~/.local/bin` 加入 PATH。

回滚已安装版本：

```bash
./install.sh --rollback 1.3.1
```

## 业务 Maven 缓存

联网机：

```bash
zscope-maven-cache prepare --project /path/to/customer-project --output ./customer-maven-cache
```

隔离机：

```bash
zscope-maven-cache install --source ./customer-maven-cache
```

缓存 manifest 对每个文件记录 SHA-256；导入时拒绝符号链接、缺失文件和内容篡改。不要把客户缓存提交到 Git 仓库或上传到公开 Release。

## 旧分体资产手工制作（兼容保留）

以下旧脚本仅用于维护已有 manifest v1 分体资产，需要预置 CPython 3.13 runtime、工具集、pip zipapp 和许可证目录。当前正式 `.github/workflows/release.yml` 使用本文开头及 AGENTS.md 中的 portable 统一入口；受保护 tag 必须等于 `v{zscope._version.__version__}`。

```bash
scripts/build_release_assets.sh \
  --runtime "$Z_SCOPE_CPYTHON_313_RUNTIME" \
  --wheelhouse dist/wheelhouse \
  --pip-pyz "$Z_SCOPE_PIP_PYZ" \
  --cpp-deps "$Z_SCOPE_CPP_TOOLSET" \
  --java-deps "$Z_SCOPE_JAVA_TOOLSET" \
  --licenses "$Z_SCOPE_THIRD_PARTY_LICENSES" \
  --private-key /secure/path/release-key.pem
```

脚本拒绝 Java 工具目录中的 CodeQL、拒绝超过 2 GiB 的单资产，并生成签名、哈希、SBOM 和包含 Git SHA/tree 的确定性资产 manifest。`scripts/verify_release_assets.py` 会复核资产名称、manifest/SHA-256、签名、SPDX、2 GiB 上限和 Java 包的 CodeQL 禁入边界。发布首先创建 draft；正式 benchmark 产物关联、Release notes 和最终发布均需人工批准。

## 旧分体资产验收（兼容保留）

旧分体资产的测试可用伪 runtime 覆盖确定性构建、安装、签名/篡改校验、启动、升级布局和回滚；这类结果须标记为 synthetic，不能替代真实资产验收。若仍交付旧分体资产，须在外部强制断网的 Ubuntu 24.04 普通用户环境，用审批后的 C/Java smoke 脚本执行：

```bash
Z_SCOPE_NETWORK_ISOLATION_CONFIRMED=1 \
bash scripts/smoke_release_assets.sh \
  --asset-dir ./release-assets \
  --cpp-smoke-script /approved/smoke-cpp.sh \
  --java-smoke-script /approved/smoke-java.sh \
  --evidence ./offline-smoke.json
```

该证据绑定 `release-manifest.json` 的 SHA-256，并包含 doctor、C 扫描和 Java 扫描结果。缺少 SVF/Saber 或 Java 默认结构/信号后端的结果不得标为正式 benchmark。执行真实资产验收需备齐 CPython 3.13 runtime、C/Java toolset、pip.pyz、许可证目录和发布密钥；缺少这些输入时，只能报告已完成的验证范围，不能将 synthetic smoke 当作真实离线资产验收。
