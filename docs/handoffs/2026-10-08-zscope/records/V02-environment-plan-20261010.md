# V02 只读环境调查与待批准兼容方案 — 2026-10-10

**推荐先复用宿主现有 Clang 18.1.3 的固定工具包，在原固定 Python 镜像上离线构建独立验收镜像，然后只申请一次无缺陷兼容探针。** 这是低成本兼容性试验，尚未证实能解决映射错误。若仍失败，停止该配置；不要靠重复启动碰到可用布局。官方 LLVM 23.1.3 的独立包作为备选，其版本更新本身没有成功保证。

本轮仅读取已安装文件、动态库依赖、容器镜像元数据和官方文档，编写可审查方案；**0 容器启动、0 编译/探针/线程 fixture 执行、0 软件安装/下载、0 模型派发**。V01 保持 done，V02 保持 blocked/not_run。主模型、长期配置、隔离、ASLR、内核、网络和权限均未改动。

## 已取得的本地事实

起点为 [当前 V01 ASAN 记录](V01-current-ASAN-acceptance-20261010.md)。产品摘要仍为 `77fdcd1671849348bffcbff643e711b2c260d3ff73907f3d9ac4297b19f6aba7`，本轮不重复 V01 验收。现有工具与镜像读取结果见 [inventory.json](V02-environment-plan-20261010/inventory.json)。

| 对象 | 已读取事实 | 对方案的意义 |
| --- | --- | --- |
| Cindala WSL | Ubuntu 24.04.4 LTS，x86_64，内核 `6.6.87.2-microsoft-standard-WSL2`；宿主 glibc `2.39-0ubuntu8.9` | 容器共享该内核，换基础发行版不能独自消除内核相关布局风险 |
| 已批准固定镜像 | ID `1cbbca32768c3c2d7c0dfa6888790808c05672438f20718472f43f0ac8d9707c`，amd64，GCC/libtsan `14.2.0-19`，glibc `2.41-12+deb13u3` | 保留原边界和基础用户态，仅增加受控工具包；既有 GCC14 探针不重试 |
| 宿主 Clang | `/usr/lib/llvm-18/bin/clang`，Ubuntu 包 `1:18.1.3-1ubuntu1`；SHA256 `8ef402d453d1ba4902e4ee0f0f847f6cfa01400c95aa43c24e97818b9c0e3f45` | 已存在的另一套 compiler-rt 实现，可先做无需联网的兼容试验 |
| Clang TSAN | `.so` SHA256 `dfb5ab5d511f84a08fbb380b04b2d3d30db69ee8817c427e73c131ff7e7c596b`；`.a` SHA256 `2252b875dd1f3bdcf67417a43497f8b0e418b9218e33031bf332c63f679917d4`，位于 `/usr/lib/llvm-18/lib/clang/18/lib/linux/` | 默认链接可能选择静态 sanitizer archive，不能只核对 `.so` |
| Clang 动态依赖 | clang、llvm-symbolizer、TSAN `.so` 的 `ldd` 无 `not found`；ELF 为 x86-64。clang 依赖 libclang-cpp.so.18.1、libLLVM.so.18.1、libffi、libedit、libxml2、ICU74 等 | 不能只复制 clang 小入口；工具包须带明确的非核心依赖闭包，容器内 ABI 尚需验证 |
| 宿主 GCC13 | `13.3.0-6ubuntu2~24.04.1`，`cc1` 实际在 `/usr/libexec/gcc/x86_64-linux-gnu/13/cc1`；`libtsan.so` 指向发行版 `libtsan2 14.2.0-4ubuntu2~24.04.1` | GCC13 的路径名称不代表另一个上游 TSAN 主版本，不作为优先切换目标 |
| Portable 缓存 | 存在 `.../x86_64/prefix/llvm18/bin/clang`，未发现该 prefix 下 TSAN runtime；发布脚本仅构建 LLVM 工具/clangd，未配置 compiler-rt runtime | 不能把项目锁定的 clangd 22.1.7 当成 TSAN 工具链，也不修改 Portable 锁或构建缓存 |
| 其他现有镜像 | 共读 17 个 image 元数据；x86_64 Portable builder `e227baaabba6…` 为 GCC/libtsan 13.2.0、glibc 2.38；其他 amd64 Ubuntu/Debian 为基础用户态，ARM 镜像架构不同；Rocky 无 dpkg 清单 | 镜像已安装不等于获准 TSAN 环境。旧 GCC13 无兼容改善证据，ARM/QEMU 会改变验证架构，不优先启用 |

镜像包版本来自只读 layer 的 dpkg status，按上层优先保存；它不是容器实际运行检查。Rocky 未解析 RPM 数据，因此不宣称完整盘点所有镜像中的自定义工具。宿主依赖完整也不证明工具包在新镜像内可运行。

读取 `/proc/sys/vm/mmap_rnd_bits` 被系统拒绝，原错误为 `PermissionError: [Errno 13] Permission denied: '/proc/sys/vm/mmap_rnd_bits'`。保留该错误，未改用其他接口或提权绕过，熵值保持未知。WSL 无 `rg`，文件搜索改用限定路径的 pathlib glob；`dpkg-query` 因无 `containers-common` 返回 1，其余软件版本仍成功返回，未把这个退出码写成全成功。

## 官方要求与可能原因

官方 TSAN 支持 Linux x86_64，编译需要 `-fsanitize=thread`，调试信息用于文件/行号；不支持静态链接 libc，非 PIE 也不受支持，运行时会映射大量虚拟地址空间。项目当前 fixture 使用独立 TSAN 构建、`-g -O0 -fno-omit-frame-pointer -std=c11 -pthread`，按现有测试保持这些参数；不与 ASAN 混用。[Clang TSAN 文档](https://clang.llvm.org/docs/ThreadSanitizer.html)

产品 `availability()` 会真实编译并运行 `int main(void){return 0;}`，不能在本轮只读阶段调用。fixture 还分别调用 availability，正例之后有两次重放；一次探针成功并不保证后续所有进程布局都成功。产品的 TSAN 内存边界是采样 RSS watchdog，不能改成限制大量虚拟映射的 RLIMIT_AS。真实验收还需保留全局对象 `shared_counter`、线程访问栈、站点、锁与候选资格；环境兼容通过不能替代这些断言。

LLVM 18.1.3、22.1.7 和 23.1.3 的 Linux TSAN 源码都含布局不兼容时尝试 `personality(ADDR_NO_RANDOMIZE)` 的分支。18 与 23 的 x86_64 `Mapping48AddressSpace` 主要区间相同；本次读取没有找到足以宣称 23 已修复本机映射问题的证据。高熵 ASLR 只是与错误相符的可能原因，本机熵值未知，也未建立唯一根因。[18 平台代码](https://github.com/llvm/llvm-project/blob/llvmorg-18.1.3/compiler-rt/lib/tsan/rtl/tsan_platform_linux.cpp)、[23 平台代码](https://github.com/llvm/llvm-project/blob/llvmorg-23.1.3/compiler-rt/lib/tsan/rtl/tsan_platform_linux.cpp)、[23 地址映射](https://github.com/llvm/llvm-project/blob/llvmorg-23.1.3/compiler-rt/lib/tsan/rtl/tsan_platform.h)

本机 `/usr/share/containers/seccomp.json` SHA256 为 `cc374cf23846ce1f62f4dc807a8e2b8673c783c6f56cb475467621035d281e6c`，默认动作为 `SCMP_ACT_ERRNO`。读取到的 personality allowlist 为 0、8、131072、131080、4294967295，未包含 `ADDR_NO_RANDOMIZE` 的 262144 组合。它支持保留默认过滤器并让关闭 ASLR 的退路失败；最终有效过滤器还要在实际验收中核对，不能仅凭磁盘 profile 宣称已实测。

**任何方案都只接受原 ASLR 和 seccomp 条件下成功的结果。** 若日志要求降低熵、关闭 ASLR、放宽 sandbox，或触发被拒绝的 personality 调用，记录失败并停止，不执行该建议，也不把该版本称为可用解决方案。

## 推荐 A：复用已安装 Clang18，离线派生镜像

已准备 [397 项工具文件清单](V02-environment-plan-20261010/proposed-bundle-manifest.json)，合计 **299,239,592 字节，约 285.4 MiB**。只记录路径、权限、大小、摘要，尚未复制文件。包含 clang、llvm-symbolizer、LLVM/Clang 两个共享库、resource headers/runtime 和非核心依赖；不复制宿主 glibc、loader、libstdc++、libgcc_s，不覆盖基础镜像核心库。包装入口只为工具设置固定库搜索路径，不修改产品运行环境或系统配置。

已准备可审查的 [stage 脚本](V02-environment-plan-20261010/stage_bundle.proposed.py)、[仅 COPY 的 Containerfile](V02-environment-plan-20261010/Containerfile.clang18.proposed)、[单无缺陷探针](V02-environment-plan-20261010/compat-probe.proposed.py) 和 [有界外层 driver](V02-environment-plan-20261010/compat-container.proposed.py)。它们均未执行；只做语法解析。外层保留原镜像验收的断网、非 root、只读、cap-drop、no-new-privileges、默认 seccomp、pids256、2 GiB/2 CPU、tmpfs512 MiB、900 秒截止和 8 MiB 输出预算，且不运行 pytest 或线程 fixture。

待批准后拟执行的 WSL 命令如下，**本轮不执行**：

```bash
plan='/mnt/c/Users/10273/home/work/Z-Scope_1.31/Z-Scope/docs/handoffs/2026-10-08-zscope/records/V02-environment-plan-20261010'
work="$HOME/.cache/zscope-v02-compat-clang18-20261010"
/home/zeal/venv313/bin/python "$plan/stage_bundle.proposed.py" \
  "$plan/proposed-bundle-manifest.json" "$work/context"
podman build --network=none --pull=never \
  --file "$work/context/Containerfile" \
  --tag localhost/zscope-v02-compat:clang18-20261010 "$work/context"
image_id=$(podman image inspect --format '{{.Id}}' localhost/zscope-v02-compat:clang18-20261010)
mkdir -p "$work/run"
cp --no-clobber "$plan/compat-container.proposed.py" "$work/run/"
cp --no-clobber "$plan/compat-probe.proposed.py" "$work/run/"
cmp "$plan/compat-container.proposed.py" "$work/run/compat-container.proposed.py"
cmp "$plan/compat-probe.proposed.py" "$work/run/compat-probe.proposed.py"
# driver 先核对新 image ID、实际隔离、403项输入、版本和工具/库身份，
# 库缺失或版本不符即停；随后仅编译运行一个无缺陷 main。
/home/zeal/venv313/bin/python "$work/run/compat-container.proposed.py" "$image_id"
```

stage 脚本拒绝已有 context，复制前后逐文件核对摘要；构建没有 RUN 指令，不联网、不拉新 base。派生镜像是新验收输入，必须单独批准并记录最终 image ID，不能沿用旧镜像已通过的结论。若直接从归档目录启动 driver，其专用结果/临时日志会新增到该目录；实施时应先复制两个 driver 到新本地任务目录，避免污染本轮封存材料。

磁盘新增约 285.4 MiB 的 context，再加同量级镜像层和构建存储开销，准确占用未测；不修改 `/usr` 宿主安装、WSL venv、Portable 缓存或长期配置。环境 metadata 检查、一次无缺陷探针及其新容器启动需要批准；线程 fixture 不在此次探针动作中。若探针通过，另行按既有 V02 标准执行最小正反例/重放/模型不完整边界，并检查每次原始 stderr；任一次 runtime 启动失败则仍为 blocked，不降低断言。

A 可能改善的依据仅是换用现有另一套 LLVM compiler-rt、完整符号化和依赖闭包，避免把 GCC 的失败直接推广到所有实现。地址布局风险仍存在；运行时可能在相同内核上失败，或派生镜像出现 ABI、链接器、符号化与内存边界问题。方案不保证成功。

## 备选 B：官方 LLVM23 独立包；备选 C：已有另一台 Linux

若 A 因同类布局错误失败，优先取得另一台已存在 Linux x86_64 主机的具体标识、内核、现有编译器/runtime 和隔离证据，使用相同固定镜像及相同安全边界做一次兼容核验，不更改那台主机的安全参数。当前没有已提供且已批准的目标主机，C 暂不能实施；后续只转移批准的微型 fixture/driver，不默认复制私有仓库或凭据。

B 使用 LLVM 官方 **23.1.3** Linux-X64 二进制包，不安装到宿主系统。官方资产列表给出 `LLVM-23.1.3-Linux-X64.tar.xz` 约 **1.88 GB**，SHA256 `ca9fe385a5d9e2d88132dc0e23a00e9f87f38fa75f67207b5e457d208e71d013`；解压与新镜像层实际大小未知，实施前需确认磁盘容量。[官方 Release](https://github.com/llvm/llvm-project/releases/tag/llvmorg-23.1.3)、[官方资产清单](https://github.com/llvm/llvm-project/releases/expanded_assets/llvmorg-23.1.3)

版本选择理由是明确的官方 x86_64 compiler/runtime 配套包，便于固定身份及复跑；**不是已验证的映射修复版本**。当前没有必须下载它的证据，因此 B 为有新增磁盘/下载成本的后备试验，不能优先承诺它会解决问题。不提供未经核验的第三方 LLVM 镜像名。

待独立批准后拟下载/准备命令如下，**本轮未下载或执行**：

```bash
work="$HOME/.cache/zscope-v02-llvm23-20261010"
mkdir -p "$work/downloads" "$work/context/rootfs/opt/llvm-23.1.3"
curl --fail --location --proto '=https' --tlsv1.2 \
  'https://github.com/llvm/llvm-project/releases/download/llvmorg-23.1.3/LLVM-23.1.3-Linux-X64.tar.xz' \
  --output "$work/downloads/LLVM-23.1.3-Linux-X64.tar.xz"
printf '%s  %s\n' \
  'ca9fe385a5d9e2d88132dc0e23a00e9f87f38fa75f67207b5e457d208e71d013' \
  "$work/downloads/LLVM-23.1.3-Linux-X64.tar.xz" | sha256sum --check --strict -
tar --list --file "$work/downloads/LLVM-23.1.3-Linux-X64.tar.xz"
# 先审查归档根目录及路径，核对 compiler-rt TSAN archive、共享库和符号化工具，
# 然后在新目录解压；不能跳过上面的摘要和目录检查。
tar --extract --file "$work/downloads/LLVM-23.1.3-Linux-X64.tar.xz" \
  --directory "$work/context/rootfs/opt/llvm-23.1.3" --strip-components=1
```

随后使用同一已存在 Python base 的 COPY-only 派生镜像，将 `/usr/bin/clang`、`/usr/bin/llvm-symbolizer` 固定包装至 `/opt/llvm-23.1.3/bin/`，不修改宿主 PATH；在相同 seccomp/ASLR 边界先核对 ELF/ldd/版本/摘要再做同样的一次 main 探针。官方包的具体运行依赖在下载前未实测，缺库应停止并形成明确依赖方案，不临时联网 apt 安装。新下载、解压、镜像构建/运行和探针均需批准；本报告不授权实施。

## 状态与记录

V01 done；V02 blocked/not_run。最小下一步是审查 A 的固定清单及四个 proposed 文件，批准离线派生镜像与单无缺陷兼容探针，或指定可复用的既有 Linux 主机；本轮不提前执行这些动作。自动生成器与 CBMC 不新增为所选 TSAN 路线门槛。

本轮原始 metadata、未执行的方案脚本、官方来源索引、语法与交接检查保存于 [同名目录](V02-environment-plan-20261010/)，最终检查见 [final-validation.json](V02-environment-plan-20261010/final-validation.json)。
