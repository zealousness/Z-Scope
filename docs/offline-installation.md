# 离线安装与发布

## 支持边界

官方离线资产面向 Ubuntu 24.04、glibc 2.38 及以上、Linux x86_64。Windows 用户通过匹配版本的 WSL2 使用；不承诺原生 Windows 包。主机须预装 `bash`、GNU `tar`、`zstd`、`sha256sum` 和 `openssl`；这些是安装器校验和解压所需的系统基础工具。应用包内置最新补丁版 CPython 3.13，不修改系统 Python。源码仍须兼容 Python 3.9–3.14。

每个 Release 必须包含：

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

## 发布制作

发布构建环境必须预置经过审批的 CPython 3.13 relocatable runtime、C/C++ 工具集、Java 工具集、pip zipapp 和第三方许可证目录。受保护 tag 必须等于 `v{zscope._version.__version__}`。GitHub Release 工作流已移除；准备好 wheelhouse 与审批后的发布材料后，手工调用：

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

## 验收

手工运行 `bash scripts/smoke_offline_install.sh`，用伪 runtime 执行确定性构建、安装、签名/篡改校验、启动、升级布局和回滚 smoke；该结果必须标记为 synthetic，不能替代生产资产验收。正式发布须在外部强制断网的 Ubuntu 24.04 普通用户环境，用审批后的 C/Java smoke 脚本执行：

```bash
Z_SCOPE_NETWORK_ISOLATION_CONFIRMED=1 \
bash scripts/smoke_release_assets.sh \
  --asset-dir ./release-assets \
  --cpp-smoke-script /approved/smoke-cpp.sh \
  --java-smoke-script /approved/smoke-java.sh \
  --evidence ./offline-smoke.json
```

该证据绑定 `release-manifest.json` 的 SHA-256，并包含 doctor、C 扫描和 Java 扫描结果。缺少 SVF/Saber 或 Java 默认结构/信号后端的结果不得标为正式 benchmark。当前本地 WSL 只有 Python 3.12.3，且未配置审批后的 CPython 3.13 runtime、C/Java toolset、pip.pyz、许可证目录和发布私钥，因此只能执行 synthetic smoke，不能伪装成生产离线资产构建。
