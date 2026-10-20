# V02 当前 TSAN 真实执行及共同镜像剩余门禁 — 2026-10-12

V01 保持 **done**。当前源码在同一不可变镜像完成 TSAN **5 passed、0 skipped** 和 ASAN **5 passed、0 skipped**，独立证据核对均通过。普通矩阵实际完成 **1734 passed、2 skipped**，compileall/mypy 均 exit 0。原要求为 1736 passed、零跳过，因此 **V02 整体仍 blocked，共同候选镜像尚未晋升**；剩余两项是 Java sidecar 的工具前置条件。

## 本轮授权与实际边界

协调通过正式接口提供了较晚的人类批准证据：只为本轮 TSAN 容器在完整默认 seccomp 上追加 `personality` 参数精确等于 `262144` 的放行规则，先一次无缺陷启动探针，成功后继续同镜像原验收。原始接续记录保存在 [批准证据](V02-current-TSAN-acceptance-20261012/approved-continuation-evidence.json)。此授权发生在早先暂停开发和最小鉴权请求之后，不能把它倒写为早先就已获准。

镜像固定为 `60e3b821beb946564925285acdc7c87b55bcdf587f4e3006321728dce2900fff`。没有重建、下载、安装或引入第二条镜像路线。默认 profile SHA256 为 `cc374cf23846ce1f62f4dc807a8e2b8673c783c6f56cb475467621035d281e6c`；本轮精确例外 profile 为 `a56f617057f60b6b569678d7f8cf569a771aab7b721ca5e980199078e0a1a46b`。ASAN、普通检查和文档检查使用默认规则。

所有执行容器均保留断网、非 root、只读根与源码输入、cap-drop=all、no-new-privileges、pids256、2GiB/2CPU、可执行 tmpfs512MiB，以及外层900秒/8MiB上限。宿主 `randomize_va_space` 前后为 2，父进程 personality 为 0；没有修改全局 profile 或 sysctl。**TSAN runtime 实际采用了关闭自身 ASLR 后重新执行的退路**，不能称 TSAN 进程自身 ASLR 未变。例外仅作用于随后已移除的选定 TSAN 容器。

## 探针、失败与修正

获准的独立启动探针只执行一次，exit 0；claim 保留，不删除重跑。它只证明本次 runtime 可以启动，不计入真实 V02 通过。[探针回执](V02-current-TSAN-acceptance-20261012/probe-result.json)、[claim](V02-current-TSAN-acceptance-20261012/probe-claim.json) 和原始 stderr 均已封存。原五节点测试内部已有 availability 调用及重放属于原真实验收预算。

第一次真实 V02 正例报告 data race，但栈为 `<null>`，产品正确记为 `engine_failed`，pytest 1 failed 后停止。已保留 [首失败](V02-current-TSAN-acceptance-20261012/tsan-first-failure.json)。runtime 实际内嵌 `/usr/bin/llvm-symbolizer-18`，固定工具则位于 `/opt/zscope-test`；发行版相关 [symbolizer 路径补丁](https://sources.debian.org/patches/llvm-toolchain-18/1:18.1.8-20/symbolizer-path.diff/) 与 archive 字符串相互印证。修正是在预期路径只读挂载同一份已冻结 wrapper，未修改产品、测试、镜像或断言。

符号化 wrapper SHA256 为 `e658766da63d258579dc5f1a8eb9ebb28f17b9d30fe18e4e5e51bcc7f04e83b8`；LLVM18 TSAN archive 为 `2252b875dd1f3bdcf67417a43497f8b0e418b9218e33031bf332c63f679917d4`。实际命令、只读挂载、编译器/库身份和工具路由见 [真实 TSAN 回执](V02-current-TSAN-acceptance-20261012/tsan-result.json) 及 [符号化变更清单](V02-current-TSAN-acceptance-20261012/symbolizer-route-manifest.json)。

## 真实验收与普通回归

| 检查 | 实际结果 | 证据 |
| --- | --- | --- |
| TSAN 原五节点 | 5 passed，0 failed/errors/skipped | [结果](V02-current-TSAN-acceptance-20261012/tsan-result.json)、[独立核对](V02-current-TSAN-acceptance-20261012/tsan-independent-review.json) |
| ASAN 原五节点 | 5 passed，0 failed/errors/skipped，默认 profile | [结果](V02-current-TSAN-acceptance-20261012/asan-result.json)、[独立核对](V02-current-TSAN-acceptance-20261012/asan-independent-review.json) |
| 普通矩阵前六组 | 193 passed，0 skipped | [首轮回执的前六组](V02-current-TSAN-acceptance-20261012/ordinary-attempt1.json) |
| 原 77 文件兼容集 | 1541 passed，2 skipped；原三项重型 native 排除保留 | [逐节点接续与最终核对](V02-current-TSAN-acceptance-20261012/ordinary-attempt5.json) |
| compileall / mypy | 均 exit 0，同镜像、冻结依赖 | [质量检查回执](V02-current-TSAN-acceptance-20261012/ordinary-attempt3.json) |

TSAN 正例对象 `shared_counter`、`data_race_positive.c:17`、线程、源映射及两次独立重放均核对成功；反例不确认、不拒绝候选。内存模式如实记录采样式 RSS watchdog，未配置限额时不宣称已强制限制。flaky 的 10 次实际采样为 3 次 data race、7 次无报告，混合重放仍未确认，未强制调度或放宽资格。

ASAN 覆盖正例、反例、无关 crash、构建产物绑定/重放及构建失败未决。真实构建确认的对象、站点、缺陷族、二进制身份和重放资格均通过，未将无关 witness 计作本候选确认。

普通验证首次快照遗漏 `tools/java_structure_frontend.py`，随后遗漏 `install.sh`、真实 Git HEAD/tree，依次停止；全部失败保留于 attempt1–3。补齐的是现有公开源码及当前真实 commit/tree 对象，未复制 Git 登录/远端配置。质量检查通过后不重复。接续保留 1259 项兼容通过结果，余下 279 项得到 248 passed、31 个 Clang 前置条件跳过；再以原镜像内已冻结 Clang18 的私有临时入口，仅复验原先 3 项和随后 31 项编译器用例，得到 **34 passed、0 skipped**。其他 248 项和前 1259 项未重复运行。最终兼容计数为 `1259 + 248 + 34 = 1541`，加前六组 193 项得到 1734；它是原矩阵执行项计数，不宣称互异断言数量。

## 剩余缺项与具体接续条件

以下两项保持 skipped，不能冒充通过：

- `tests/test_java_source_backend.py::test_spoon_structure_frontend_lombok_processor_real_cli_contract`
- `tests/test_java_source_backend.py::test_javaparser_structure_frontend_real_cli_contract`

本机已有 JDK21 `21.0.12.1`、Maven `3.8.7` 和离线 Maven cache；只读候选盘点为 **3510 个唯一文件、481,028,886 字节**：JDK 299,604,430，Maven runtime 9,962,646，cache 171,461,810。逐文件摘要、符号链接及宿主 ldd 见 [只读盘点](V02-current-TSAN-acceptance-20261012/java-maven-readonly-inventory.json)。未执行 Java/Maven、未读取或复制用户/全局 Maven settings 或凭据；宿主 ldd 不代表共同镜像兼容性或离线闭包已通过。

这些文件不属于已批准的397项工具追加或既有 Python 依赖挂载。具体补充方案是保持现有 image ID，为这两项测试加入经审查的固定只读 JDK/Maven/cache 输入；Maven 强制 offline、使用空 settings、禁用 rc，源码继续只读，两个 sidecar 的 `target` 仅指向既有512MiB tmpfs中的自有输出。任何缺依赖或超限都停止，不在线解析、安装或增加资源。批准新增输入和预算之前不挂载或执行；详见 [待审查补充方案](V02-current-TSAN-acceptance-20261012/JAVA-MAVEN-SAME-IMAGE-SUPPLEMENT.md)。不重跑已成功的独立 TSAN 启动探针。

## 最终身份与限制

403 项原冻结输入均未变，runner SHA256 仍为 `77fdcd1671849348bffcbff643e711b2c260d3ff73907f3d9ac4297b19f6aba7`，真实执行测试为 `3205acd925075b04dff129f8876b30da3509d6e717856df4f352f3eb7327fa3b`。本执行阶段产品/测试代码改动为零、模型请求为零；仅修正验收基础设施并维护交接材料。Kimi 最小鉴权此前实际一次请求返回 `OK`，未因连接恢复重复发送。

所有本轮自有测试容器已清理，后续使用默认 profile；封存 [汇总](V02-current-TSAN-acceptance-20261012/acceptance-summary.json) 和 [逐文件清单](V02-current-TSAN-acceptance-20261012/evidence-manifest.json)。交接更新后文档检查单列于 [文档回执](V02-current-TSAN-acceptance-20261012/final-docs-result.json)，不计入普通矩阵或真实 sanitizer 通过数。

该结果限于已批准的微型 fixture 路线。外层容器隔离属于验收基础设施，产品仍为进程执行能力；自动 harness/输入生成器、CBMC、任意第三方工程安全性、正式 Range benchmark 和发行验证没有新增通过结论。没有提交或推送。
