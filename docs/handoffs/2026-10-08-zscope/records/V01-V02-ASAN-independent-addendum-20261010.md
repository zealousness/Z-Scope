# 独立 ASAN 第一批结果（修改前）

2026-10-10 03:03:02.649–03:03:17.725 UTC，主机 CINDALA。五个明确授权的 ASAN 节点全部通过，exit=0，0 skipped；观察器无错误。产品未修改，DeepSeek 尚未发送。此前四项普通证明漂移失败仍未修复，因此 V01 仍不放行、V02 blocked；不能将本批通过与后续修改后的代码混算。

| 节点 | 主运行及独立重放 | 实际分类/退出 |
|---|---|---|
| 正例确认 | 1 主运行 + 2 replay | 三次 heap-buffer-overflow / exit 1；匹配候选后确认 |
| 安全反例 | 1 + 2 | 三次 none / exit 0；not_reproduced，保持未决 |
| 无关崩溃 | 1 + 2 | 三次 heap-buffer-overflow / exit 1；不匹配原候选，禁止确认 |
| build 后二进制确认 | 1 + 2 | 三次 build exit 0、run exit 1；匹配并绑定 post_build_output |
| 构建失败 | 仅一次 build；0 run、0 replay | build exit 1，engine_failed/build_failed；保持未决 |

合计 12 次 fixture 运行（4 次主运行、8 次独立 replay），另一次构建失败没有启动产物。五个无缺陷 sanitizer 探针各完成编译/运行；直接预编译与 build-produced 路径的命令也已记录。不是运行整个真实测试文件。

实际隔离核验在同一个容器内先于 pytest 完成：
- UID/GID=1000:1000，非 root；CapEff/CapPrm/CapBnd 全为 0；NoNewPrivs=1；Seccomp=2。
- 根挂载以及 /repo 和依赖挂载选项均为 ro；仅自有 /work 与 /tmp 可写。
- network=none，仅 lo，无 IPv4 route；无外部网络探测。
- memory.max=2147483648；pids.max=256；cpu.max=200000 100000（2 CPU）。
- /tmp tmpfs=536870912 bytes，exec，nosuid/nodev。
- 固定已有镜像 digest de8ba566572ebcb35cbd10e03f5f351cad00a0d0d50a11e084f1a0fd24a0c41a，--pull=never。
- 外层 900 秒/8 MiB 输出上限；本批实际约 15.077 秒，证据输出 249432 bytes，无超时或超限。自有容器清理 exit=0。

只读 staging 为 313 个明确允许输入：zscope 非隐藏 Python 文件、runtime_defaults.yaml、这一测试文件及四个 C fixture；未挂载整个仓库、.git、配置凭据、range 或 truth。现有依赖挂载收窄到 site-packages，外向符号链接检查通过。
staging 组合 SHA-256：`b1259cfb11ae6c0cecb417c2ea024c456c8250f3e452dabb7cab08a50ac643bd`。
既有 403 个记录输入前后无变化。本批未执行 TSAN、allocation_oversize、400 MiB 压力或无上限测试。

内部产品 plan 仍声明 isolation=process、sanitizer_allocation_cap；外层容器是本次独立验收边界，不能报告产品自身实现了容器隔离。

证据：
- [精确外层命令与结果](V01-V02-ASAN-independent-20261010.json)
- [真实隔离核验](zscope-v01-v02-asan-independent-20261010-ua7_swgo/isolation-verification.json)
- [全部节点/执行/replay/输入摘要](zscope-v01-v02-asan-independent-20261010-ua7_swgo/observed-executions.json)
- [JUnit](zscope-v01-v02-asan-independent-20261010-ua7_swgo/asan.xml)
- [原始容器输出](zscope-v01-v02-asan-independent-20261010-ua7_swgo/container.stdout.log)；逐个 compiler/probe/runner 原始流保存在 raw/。
- [外层 driver](V01-V02-ASAN-container-20261010.py)、[内部只读观察器](V01-V02-ASAN-inside-20261010.py)。

观察器用 sys.setprofile 记录返回的 plan/ExecutionRecord/ReplayEvidence，并在产品正常清理前复制它生成的原始 stdout/stderr；没有 monkeypatch、改测试、改 policy 或生产信任控制。所有 68 个证据文件摘要记录于结果 JSON。

这是此前 [独立验收报告](V01-V02-independent-reacceptance-20261010.md) 的追加结果。用户随后已明确同意四项普通逻辑修复所需代码/测试/要求/日志外发；待该批输入证据保存后再提交，避免并发修改。

