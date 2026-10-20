# V02 统一镜像启动阻塞与 Kimi 独立复核 — 2026-10-12

**V01 保持 done；V02 保持 blocked，真实隔离 TSAN 为 not_run。** 统一候选镜像已构建，但无缺陷探针失败，尚未通过共同基线验收。本轮 Kimi 仅提供审查意见，Codex 未据此制造产品补丁或重复失败配置。

## 已发生的构建和失败

用户批准 `SINGLE-IMAGE-PLAN.md` 后，固定397项工具、299,239,592字节经核验，由原固定基础镜像离线COPY-only追加构建。共同候选镜像为 `60e3b821beb946564925285acdc7c87b55bcdf587f4e3006321728dce2900fff`，基础镜像为 `1cbbca32768c3c2d7c0dfa6888790808c05672438f20718472f43f0ac8d9707c`；新增层299,545,834字节，镜像Size字段1,434,020,035字节。

唯一获准无缺陷探针 `int main(void){return 0;}` 使用Clang18.1.3编译成功，真实链接的TSAN archive SHA256为 `2252b875dd1f3bdcf67417a43497f8b0e418b9218e33031bf332c63f679917d4`。单次运行退出-11（SIGSEGV），stderr为：

```text
ThreadSanitizer: CHECK failed: tsan_platform_linux.cpp:282 "((personality(old_personality | ADDR_NO_RANDOMIZE))) != ((-1))" (0xffffffffffffffff, 0xffffffffffffffff) (tid=21)
```

该探针不经过Z-Scope产品代码。已证实的是runtime启动阶段调用返回-1并触发CHECK；没有syscall errno跟踪，不能将seccomp、no-new-privileges或re-exec中的某一个认定为唯一根因。此前GCC14.2的 `unexpected memory mapping` 作为另一历史失败保留，不合并归因。

原隔离核验全部通过：network none、UID/GID1000、只读根/输入、全部capabilities dropped、no-new-privileges、默认seccomp、原ASLR、pids256、2GiB/2CPU、可执行tmpfs512MiB、外层900秒/8MiB。探针失败后按用户要求停止，没有执行条件阶段三。

真实构建、link map、探针/隔离原始日志和冻结摘要位于本地：

`C:/Users/10273/Documents/Codex/2026-10-10/task-3/v02-single-image-execution-20261010/`

入口为 `EXECUTION-RESULT.md`、`execution-summary.json`、`phase1-result.json`、`phase2-result.json`、`probe-evidence/compat-probe.json`、`final-artifact-manifest.json`。本记录更正TASKS中“方案尚未批准或实施”的过期原因，未覆盖历史方案或证据。

## Kimi 实际审查及独立核验

较晚恢复开发授权由协调任务提供时间顺序和原文后接纳；此前的一次最小鉴权请求与本次审查分别归档。本次只经正式Agent-Bridge派发，工作目录为本项目，request_id `1a6e9b3f-43c2-4d05-ae02-c54fcb6108d9`，task `task_d8e3a1b1a7`，session `sess_bf4b445abc`，模型别名 `volceapi/kimi-k3`。没有重复派发或切换网关。

本次请求23,323字节，SHA256 `697b12c6f51dc8b2cd68ffbb56bf0b72c98a5279cdef059d8a55a05ddf779e5b`，只含错误/约束、runner及真实fixture测试的选定片段，不含凭据。禁用工具和子代理的agent覆盖配置、单步/单尝试设置用于限制本轮审查；Bridge的manual模式本身不构成工具沙箱，正常工具权限也没有因此被验收。

实际wire显示1次LLM请求、0工具调用、tools/subagents均为空；第二条消息为通用日期提醒。Bridge返回completed/end_turn、无warning/error、完整非空结果、files_changed为空。session已关闭，临时配置恢复到原SHA256 `f732186f6a5b8d16f29489d78140034b01893ad3c333796a0098cfd5f0311403`，临时项目agent文件已移除。

审查前后tracked `git diff --binary HEAD`摘要相同；两个选定输入摘要相同。git status快照摘要与准备记录未匹配，缺少原始快照不能还原差异，因此不扩大为“全部未跟踪文件均未变”的结论；已有脏工作区保留，不清理或复原未知文件。

Kimi认为当前启动失败不需要产品补丁，提出personality errno诊断及条件性LLVM23备选。Codex独立复核后：

- 现有 `availability()` 在probe非零退出时返回不可用/`sanitizer_probe_failed`；当前失败没有证据要求为此改变runner、parser或裁决策略。此次不修改产品/测试，不把受限审查当成真实验收。
- 不执行Kimi建议的personality置位诊断，因为它会尝试设置 `ADDR_NO_RANDOMIZE`，不符合保留原ASLR的边界。单个EPERM也不足以证明唯一策略来源；errno为0亦不能排除其他后续调用被过滤。
- 不盲目下载/安装LLVM23。独立比对18.1.3和23.1.3的 `Mapping48AddressSpace`，16个关键常量相同，平台实现均保留布局检查失败时关闭ASLR并重启的退路。该事实不能证明两个版本行为完全相同，但未提供“升级即可解决本机启动失败”的依据。
- Kimi另提无帧WARNING可能跨报告合并帧；源码中下一WARNING仅在已有frames时终止扫描，确有此结构。该观察未执行验证，不作为已完成修复或当前启动阻塞的解释，留待独立parser用例审查。

原始请求、范围清单、Kimi最终答复、Bridge结果、wire审计、配置恢复结果及上游源码摘要在本地：

`C:/Users/10273/Documents/Codex/2026-10-12/task-3/v01-v02-kimi-resume-20261012/`

重点文件为 `request-manifest.json`、`kimi-review-result.md`、`bridge-review-result.json`、`request-audit.json`、`restoration-result.json`、`llvm-source-review.json`。私有endpoint和凭据不写入本仓库记录。

## 上游依据与结论边界

[LLVM18.1.3平台实现](https://github.com/llvm/llvm-project/blob/llvmorg-18.1.3/compiler-rt/lib/tsan/rtl/tsan_platform_linux.cpp)与[LLVM23.1.3平台实现](https://github.com/llvm/llvm-project/blob/llvmorg-23.1.3/compiler-rt/lib/tsan/rtl/tsan_platform_linux.cpp)均保留上述personality退路；映射常量见[18.1.3头文件](https://github.com/llvm/llvm-project/blob/llvmorg-18.1.3/compiler-rt/lib/tsan/rtl/tsan_platform.h)和[23.1.3头文件](https://github.com/llvm/llvm-project/blob/llvmorg-23.1.3/compiler-rt/lib/tsan/rtl/tsan_platform.h)。独立下载的四份公开源码及SHA256已归档，没有安装或执行新工具链。

[官方TSAN限制](https://clang.llvm.org/docs/ThreadSanitizer.html)列明非PIE执行及静态链接libc不受支持；因此不以 `-no-pie`、静态libc、屏蔽报告或跳过runtime映射检查作为本轮解决路径。

当前证据仅证明已固定Clang18镜像在当前隔离执行环境中失败；**尚未证明必须改变安全设置，也不证明所有单镜像或其他Linux主机均不可行。**

## 进一步静态归因与可审查修复

继续修复TSAN环境的要求已接纳；没有把整项工作视为未授权。只读检查Podman4.9.3及其实际默认profile `/usr/share/containers/seccomp.json`，SHA256 `cc374cf23846ce1f62f4dc807a8e2b8673c783c6f56cb475467621035d281e6c`，发现该profile只允许personality参数0、8、131072、131080、4294967295，均不包含ADDR_NO_RANDOMIZE(0x40000)。默认拒绝是 `SCMP_ACT_ERRNO/defaultErrnoRet=38`（ENOSYS），不能假设为EPERM。本机原ASLR开启（randomize_va_space=2），读取mmap_rnd_bits仍errno13，未绕过。当前规则会拒绝runtime的相应参数，这是具体策略冲突；历史探针没有errno记录，不进一步认定唯一历史根因。

在上述本地证据目录中准备了 `TSAN-STARTUP-REPAIR-PLAN.md`、`tsan-personality-seccomp.proposed.json`、`policy-delta.json`、两个单次探针driver和 `security-proposal-manifest.json`。profile仅向完整默认规则追加对personality参数262144的精确相等允许，SHA256 `a56f617057f60b6b569678d7f8cf569a771aab7b721ca5e980199078e0a1a46b`；其余规则与顶层字段已静态核对相同。driver仅AST解析，未运行。

具体作用范围为本轮明确选定的TSAN验收容器内全部进程；允许调用者关闭自身ASLR及后代继承，无法按程序身份区分。只通过该容器的 `--security-opt=seccomp=<profile>` 传入，不修改宿主默认profile/sysctl/镜像；网络、只读、非root、无cap、no-new-privileges及全部预算保留。ASAN/普通检查继续使用默认profile，所有组复用同一不可变镜像。清理自有容器、下次不传该参数即回滚，没有宿主持久设置需要恢复。

由于原批准SINGLE-IMAGE-PLAN明确要求保留默认seccomp和原ASLR，这个局部例外仍需具体批准，**尚未应用、未新增探针**。方案移除一个已确认策略阻断，但不保证解决全部映射/re-exec问题。批准范围应同时明确：仅本轮TSAN验收容器使用该精确参数例外，新增一个无缺陷兼容探针，失败停止，通过后才按原清单继续真实V02及同镜像矩阵。

保持原安全边界的替代是指定另一台已经获准、可运行Podman的Linux x86_64主机及执行入口，保持相同镜像/全部限制并批准一次兼容探针。当前没有这样的另一主机；不擅自建VM或盲目下载LLVM23，也不宣称所有环境都必须关闭ASLR。

任一路线通过兼容探针后，真实V02正/负例、两次独立重放、固定flaky采样、内存边界、必要ASAN五节点、原1736普通矩阵及compileall/mypy/文档检查仍须完成。对象/站点/线程/source mapping、失败关闭和反例断言全部保留，CBMC及自动harness/input生成器不新增为门禁。历史宿主运行和旧ASAN通过不能移作新共同镜像的证据。

## 本轮验证范围

产品 `zscope/core/validation/dynamic_reproduction.py` SHA256仍为 `77fdcd1671849348bffcbff643e711b2c260d3ff73907f3d9ac4297b19f6aba7`；相关执行测试SHA256仍为 `3205acd925075b04dff129f8876b30da3509d6e717856df4f352f3eb7327fa3b`。V01既有验收见 [当前ASAN记录](V01-current-ASAN-acceptance-20261010.md)，其done状态保留。

本轮只对交接变更运行现有 `tests/test_agent_docs.py` 及UTF-8/LF/任务状态检查，使用WSL Linux用户态和现有共同候选镜像，保留原隔离/预算，挂载经过摘要核对的最小文档快照与已有只读Python依赖。实际命令、计数、隔离检查和日志摘要单列于 [文档验证结果](V02-environment-review-docs-20261012.json)；它不替代产品回归或sanitizer门禁。

本轮新增TSAN探针/真实V02/ASAN/完整普通矩阵/compileall/mypy均为not_run，没有工具链安装、镜像拉取、安全设置变更、提交或推送。
