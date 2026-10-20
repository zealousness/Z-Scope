# V01/V02 独立复验：不予放行

主机 CINDALA；日期 2026-10-10 UTC。项目：`C:\Users\10273\home\work\Z-Scope_1.31\Z-Scope`。

**V01 不予放行，V02 继续 blocked。** 本次实际普通验收 1711 项通过、4 项失败；语法和类型检查通过。四项失败证明：执行后、登记前源码变更/删除，或登记后二进制变更/删除，仍会获得 confirm。真实 ASAN/TSAN 缺陷样例在本次独立验收中均为 **not_run**，不能用作者自验替代。

## 实际执行与输入窗口

主批次 2026-10-10 02:33:33.815–02:38:50.953 UTC；clang 补跑 02:43:29.641–02:43:39.035 UTC。
Python `/home/zeal/venv313/bin/python`，3.13.15；Linux 6.6.87.2 WSL2；pytest 可用。
现有 `/usr/lib/llvm-18/bin/clang` 只读版本预检：Ubuntu clang 18.1.3，退出码 0。

| 检查 | 通过 | 失败 | 跳过 | 退出码 |
|---|---:|---:|---:|---:|
| tests/test_dynamic_reproduction.py | 126 | 0 | 0 | 0 |
| V01-V02-acceptance-regressions.py | 25 | 0 | 0 | 0 |
| V01-V02-reacceptance-regressions.py（R01–R09） | 16 | 0 | 0 | 0 |
| 新增纯 fake 文件漂移回归 | 0 | 4 | 0 | 1 |
| 普通无 provider 集成节点 | 1 | 0 | 0 | 0 |
| 所选 77 文件兼容集，初次运行 | 1509 | 0 | 34 | 0 |
| 上述 34 个 clang 节点，现有 LLVM PATH 补跑 | 34 | 0 | 0 | 0 |
| compileall zscope scripts test tests | — | — | — | 0 |
| mypy zscope | 307 个源文件无问题 | — | — | 0 |

兼容集最终为 1543 个不同节点全部通过。初次 34 skipped 的原因全部是 `compiler integration requires clang`；通过现有、已记录的 LLVM 18 路径补跑，未安装工具。命令保留作者兼容集的三项 `-k` 排除：
`test_real_mutation_replay`、`test_real_direct_bitcode_dependency_cache_and_svf`、`test_native_code_to_real_terminal_tool_workbook_and_pool_consumers`。
没有把被排除项目计为通过。兼容节点含普通编译事实检查；未选择真实 sanitizer 执行文件或带 isolated 标记的真实构建集成节点。

403 个记录输入在主批次前、每批后、补跑前后及归档窗口一致：
`66c1ab9a6272d854a12ff7e332a2f09e302a6f5cee9a1913f3e781e1cac9d63e`。
范围：18 个冻结输入、所选兼容测试、全部非隐藏 zscope Python 文件、AGENTS.md、pyproject.toml、权威验收文档及原/R01–R09/集成回归文件。不是全仓库 812 文件快照；未读取 .git。此前 18 输入组合 `0db2783c…` 与本次 403 输入组合不能直接比较。

每次 pytest 使用自有 /tmp basetemp、禁用缓存插件及自动插件加载；子进程只继承 PATH/语言/TZ/LD_LIBRARY_PATH 等非凭据 allowlist，并明确设置 PYTHONPATH/TMPDIR/XDG_CACHE_HOME。没有转发模型凭据。compileall 的字节码缓存重定向到自有 /tmp；mypy 缓存亦为自有。
单测/负例/新漂移/普通集成各 300 秒；兼容 900 秒；compileall 300 秒；mypy 600 秒；clang 补跑 600 秒。各批输出上限 8 MiB，超限/超时仅终止本批自有进程组。本次无超时/输出超限。普通验收没有宣称容器或内核总内存隔离。

## 已实际复现的失败与最小原因

复现文件：[test_v01_v02_independent_drift.py](test_v01_v02_independent_drift.py)；完整断言：[new-file-drift.stdout.log](V01-V02-independent-evidence-20261010-ag7xwe18/new-file-drift.stdout.log)；[JUnit](V01-V02-independent-evidence-20261010-ag7xwe18/new-file-drift.xml)。

四个节点：
1. `test_drift_between_last_execution_and_registration_never_confirms[mutate]`
2. 同节点 `[delete]`
3. `test_binary_drift_after_registration_revokes_confirmation[mutate]`
4. 同节点 `[delete]`

第一组：主执行与两次重放后，登记前修改或删除自有临时源码；登记仍成功；预期
`deterministic_decision_proof(issue, outcome="confirm") is None`，实际返回 `DecisionProof(outcome='confirm', proof_kind='dynamic_witness_candidate_match', ...)`。
断言信息为 `current source changed after execution but before proof registration`。

第二组：登记后先确认有效控制，再修改或删除自有临时 fake 二进制；同一无 confirm 断言失败。
断言信息为 `registered proof survived an actual binary-file change`。

这些用例只调用 FakeDynamicReproductionRunner，并调用项目明确用于测试的 production promotion hook 来隔离检查证明生命周期；文件名为 fake-program 的内容从未执行。它们不能证明普通 fake 能越过 production 信任门，也不能证明真实 sanitizer 已通过。但在 production 门被测试控制设为有效时，登记/最终证明验证未按合同撤销漂移证明，足以阻止 V01 放行。

定位：
- [dynamic_reproduction.py:3560](../../../../zscope/core/validation/dynamic_reproduction.py#L3560) 在登记时调用 `frozen_source_digests`，把登记时当前文件当成冻结快照，未比对执行时已接受摘要。
- `frozen_source_digests` 1434–1456，尤其 1446/1451–1455：只枚举 candidate source、harness、inputs；缺失/不可读文件被略过。
- `dynamic_witness_proof_is_live` 1473–1508，1497：空摘要列表不进行文件校验。
- 冻结列表不包含 binary_path，最终存活校验不重新读取二进制；receipt 中有 binary_digest 不能替代当前文件核对。

建议返修必须绑定执行时已经接受的源码/harness/input 快照；登记时与当前内容核对，缺失、不可读或变化均拒绝授予 confirm。二进制应绑定批准的路径及真实 build 后接受摘要，并在最终 proof 使用时核对变更/删除。未复现、失败或过期仍保持未决。当前未修改产品代码。

## 权威验收标准与当前覆盖

完整来源：[WORK_PACKAGES.md](../WORK_PACKAGES.md)、[ACCEPTANCE.md](../ACCEPTANCE.md)。本报告保留上轮静态标准，新增实际执行证据；[上轮报告](V01-V02-local-static-review-20261010.md) 不被覆盖。

- V01（依赖 D01；AC06/10/11/17/18）：先 provider/fake 后真实 ASAN；独立新增正例/安全反例；计划绑定项目、源码/版本、候选对象/站点/缺陷族、build/toolchain/harness/input/binary。限定 argv/cwd、环境 allowlist、自有临时写区、资源/时间与进程组取消，如实记录隔离。逐轮命令/摘要/日志/退出/分类/调用栈与源码映射、独立重放及实际限制完整。只有生产信任且每轮匹配原候选的输入已核验 witness 可确认；其它崩溃、未复现、失败/超时/OOM/取消/缺工具保持未决。源码/二进制漂移必须使旧证明失效。没有真实运行环境不能标 done。
- V02（依赖 V01；AC06/11/15/18）：复用 runner/receipt；当前选择 TSAN，单独 sanitizer 构建，不混用 ASAN；记录线程入口、对象、锁、访问栈和不确定性分布。TSAN 缺 runtime 或其它前置条件保持 blocked/not_run。CBMC 未实现；若将来采用，只能给明确模型/harness/bounds/unwinding 的有界结论。不能凭 provider 完成声称真实工具完成。
- AC06：只接受登记引用；拒绝过期/跨项目/TU 漂移、篡改/自证；序列化不恢复授权；不得拼接漂移前后证据。
- AC10：保留冻结 Ledger、未决/失败/中断/人工状态、处置/来源/基线；不改规则或 Ledger 来迎合测试。
- AC11：正例/安全反例、错误对象/站点/崩溃、构建失败、无输出、超时、缺工具、源码/二进制漂移、空格路径、非零退出、进程取消、伪造日志；真实工具不以 mock 代替。本次纯 fake 及已有边界回归通过，新增两类漂移失败，真实工具仍未独立运行。
- AC15：记录版本、许可/API/实际权限；缺依赖不能令普通扫描崩溃；不自动安装、发布或伪装完成。
- AC17：truth 只用于入口预检及完成后独立评分；不进入扫描证据，不修 range/truth；只用独立 fixture。
- AC18：默认禁用兼容不退化；保留用户缓存/产物；仅清理自有后端，不关闭借用客户端。

另外 `docs/architecture.md:531,666` 仍写 V4 仅预留，而模块文档/实现已有动态路径，是尚待同步的文档差异。本次 docs 兼容测试通过并不自动解决这项语义差异。

## 真实 ASAN 第一批待审核范围（本次未执行）

只读 `podman image inspect` 已验证本地镜像存在：
`docker.io/library/python@sha256:de8ba566572ebcb35cbd10e03f5f351cad00a0d0d50a11e084f1a0fd24a0c41a`；
ImageId `1cbbca32768c3c2d7c0dfa6888790808c05672438f20718472f43f0ac8d9707c`，linux/amd64，镜像 Config.User 未设。
本次未启动容器、拉镜像、执行 sanitizer 探针或编译/运行缺陷 fixture。容器当前实际 compiler/runtime/隔离限制仍需在后续批准范围内核验。

候选节点仅为 `tests/test_dynamic_reproduction_execution.py` 内：
- `test_asan_positive_fixture_confirms_through_shared_adjudication`
- `test_asan_negative_fixture_is_not_reproduced_and_never_rejects`
- `test_asan_unrelated_crash_never_confirms_the_candidate`
- `test_asan_build_generated_binary_confirms_without_a_declared_digest`
- `test_asan_build_failure_stays_undecided`

仅涉及 `heap_overflow_positive.c`、`heap_overflow_negative.c`、`unrelated_crash.c`、`broken_build.c`；不选 allocation_oversize 或 TSAN 样例。先将允许的 zscope Python package、这一测试文件及四个 fixture 复制到本次自有 staging，记录摘要；不挂载整个仓库，不带 .git、.env、配置凭据、test/range 或 truth。已安装依赖目录只读，不安装缺包。staging 及只读依赖目录的符号链接须确保不越出批准输入范围。

拟用外层 podman 条件：
`--pull=never --network=none --read-only --userns=keep-id --user <当前非 root UID:GID> --cap-drop=all --security-opt=no-new-privileges --pids-limit=256 --memory=2g --cpus=2 --tmpfs /tmp:rw,size=512m,exec`。
只读 staging 挂 /repo；既有 /home/zeal/venv313 挂 /venv:ro；自己的证据目录挂 /work:rw。外层总 deadline 900 秒、输出 8 MiB；限制/身份预检先确认 uid 非 0、只读挂载、断网/no-new-privileges、capabilities、cgroup memory.max=2147483648、pids.max=256、CPU quota=2。缺少限制或工具即停止并记 blocked，不降低限制、sudo、改权限或换已拒绝入口。

命令仅为镜像内 `python -m pytest -q -p no:cacheprovider --tb=short --basetemp=/tmp/pytest-asan --junitxml=/work/asan.xml <上述五个节点>`，禁用第三方自动插件。PYTHONPATH=/repo:/venv/lib/python3.13/site-packages，bytecode 禁写，TMPDIR=/tmp，证据 JSON 指向 /work。镜像内固定批准 PATH=/usr/bin:/bin，仅采用已核验的编译器；若缺编译器/runtime 则 not_run，不自动下载。

测试的 `_require_sanitizer("asan")` 会先编译/运行无缺陷 C 探针，这也属于后续批准的真实执行范围。编译为 runner 的固定 argv：
`<compiler> -fsanitize=address -g -O0 -fno-omit-frame-pointer -o <自有临时 binary> <四选一 source>`；
正/反/无关崩溃运行 `<binary> 64`；broken build 使用
`<compiler> -fsanitize=address -c <broken_build.c>`，不运行未构建产物。
每个 plan 60 秒、512 MiB runner 预算、通常 max_replays=2；build-generated confirmation 为 3；另有两次独立 replay。512 MiB runner RSS 预算不是内核总内存硬限制，外层容器 2 GiB 才是额外验收边界。产品 plan 的 isolation 当前为 process，不能报告为产品实现了 container 隔离。

TSAN 暂不执行；作者容器结果的四次 skip 是 runtime probe failed，此信息只作历史证据。本次没有重新证明 TSAN runtime 不可用。V02 同时受 V01 未放行阻塞。若任何明确策略拒绝发生，记录具体操作与错误并停下，不寻找绕过方案。

## DeepSeek 与安全边界

原任务 `01a119b6-40a8-71b0-a6a7-cf0644a14119` 已用本地 read_thread 核实；其旧独立 review 早于最新 R01–R09。现有 DeepSeek session `bc51fb3a-c9e7-445e-b6e3-855461b3179c`，cwd 指向该仓库，preset=standard；最后保存 turn/end 为 2026-10-09 12:07:21.592 UTC completed。本次未恢复或向 DeepSeek/harness 发送命令，未读取凭据。Desktop controller 能按原 preset 恢复此 session；headless 拒绝带 agentPreset 的现有 session，不能代用接管。

建议父对话审核的返修内容：仅动态复现 proof 生命周期实现、相应回归与必要文档。保留生产信任门、登记对象身份、TTL、scoped cleanup、预算/取消、逐轮候选匹配、build 后二进制支持、默认禁用及既有 R01–R09 行为；不改 Ledger/rules/range/truth、不安装工具、不改权限、不自动发布。要求登记前漂移及登记后二进制漂移均无 confirm；返修后重跑本报告四个边界及既有回归。若 API 用明确异常拒绝登记，复验可断言拒绝且没有 proof，但不能屏蔽真实错误或将测试变成无条件通过。此建议尚未发送。

原失败回合 `01a11a92-7004-7481-9f09-a928e4fb55ef` 的可见错误：
`This content was flagged for possible cybersecurity risk.`，details=null；没有已记录命令或改动，故无法确定被拦的具体操作，不能推断 ASAN/TSAN 本身禁止。
cloud 的 unsupported placement region 4、Git 的 chdir Permission denied、默认 sandbox 的 Wsl/E_ACCESSDENIED 是不同问题。

已恢复默认 sandbox 失败的精确命令：PowerShell here-string 输入 JSON-only Python 环境预检，管道至
`wsl -d Ubuntu -- /usr/bin/env PYTHONDONTWRITEBYTECODE=1 /home/zeal/venv313/bin/python -`。
exit=1，1311 ms，chunk ae584a / exec-a51a987f-2c88-46b9-87b1-2e7a32047b8c；未产生 Linux Python 输出。
在父对话明确授权后，经正式单次 require_escalated 审批的 printf marker 成功，exit=0，精确输出为 `WSL_PERMISSION_CHECKn`（不是换行）；后续每个 WSL 调用均单次正式审批，无通用 prefix_rule、ACL 变更或 sudo。实际 Python 预检及普通测试随后成功。本次没有 auto-review 拒绝；Git 被拒绝路径没有重试。不能据此将原内容策略拦截视为已经解除。

父对话请求中间结果后，本地 send_message_to_thread 返回 thread not found；本任务 commentary 已报告首批数目，最终完成由平台通知父对话。没有把失败的投递声称成功。

## 证据与剩余条件

- [主批次结果 JSON](V01-V02-independent-acceptance-20261010-ag7xwe18.json)：逐项 argv/cwd/退出码/时长/JUnit 与日志摘要、403 输入快照。
- [clang 补跑 JSON](V01-V02-compatibility-skips-20261010.json)：34 个精确节点、allowlist 环境、前后摘要及结果。
- [证据清单](V01-V02-independent-evidence-20261010-ag7xwe18/evidence-manifest.json)：25 个日志/JUnit，已逐文件校验复制前后 SHA-256。
- [主 driver](V01-V02-independent-acceptance-20261010.py)、[补跑 driver](V01-V02-compatibility-skips-20261010.py)、[纯 fake 回归](test_v01_v02_independent_drift.py)。

当前没有活动测试进程。剩余放行条件：修复并独立复验四项证明漂移失败；审核具体真实 ASAN 方案后执行并保存完整 receipt/replay；V02 另行核验 TSAN 前置条件或明确保持 blocked。若要追溯原内容策略拦截的具体操作，仍需原失败请求/命令及完整平台错误；仅凭当前 details=null 不能再细化。

