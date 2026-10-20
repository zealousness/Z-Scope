# V01/V02 独立静态核对：运行验收阻塞

核对时间：2026-10-10T02:07:00.713Z（UTC）；主机：CINDALA。

## 结论

**V01 尚未获得 R01–R09 返修后的独立放行；V02 继续 blocked。** 本轮独立产品测试执行 0 项，全部记为 not_run。WSL 预检返回 `Wsl/E_ACCESSDENIED`；项目 [AGENTS.md](../../../../AGENTS.md) 要求测试及质量命令在 Linux/WSL 执行。已停止 WSL/Git 被拒绝路径，没有原生 Windows 测试替代、修改权限、安装依赖或启动/通信 DeepSeek。

原 Codex 任务 `01a119b6-40a8-71b0-a6a7-cf0644a14119` 可通过本地 read_thread 读取，状态 notLoaded，最近保存回合 completed。其最新独立验收在 2026-10-09 11:22:12 UTC 完成，早于随后 R01–R09 返修，不能用旧的 17 failed 断言当前仍失败。

## 当前输入和证据

18 个产品/测试/fixture 输入在 2026-10-10T02:03:26.203Z 与 2026-10-10T02:05:10.063Z 两次独立读取之间完全一致，组合 SHA-256 为 `0db2783c4509e7bf7a97b1e759cf69158e3cb5cad7457aabecce6a0e24f989d6`，与最新 r2 作者快照一致。旧 `V01-V02-final-workspace-round2.json` 有 8 文件摘要不同，属于较早快照；与最新作者 baseline 比较没有差异。这里仅证明静态核对窗口未观察到这些输入被修改，不证明测试通过，也不能排除 WSL 内其它活动。

作者自验记录：专项 126、原负例 25、新边界 16、兼容回归 1543、文档 6 均记录 passed；普通集成 1 passed/1 skipped，另一个带 isolated 标记的集成记录 2 passed；宿主 sanitizer 16 passed。断网容器 JSON 记录专项 126、原负例 25、新边界 16、集成 1 passed/1 skipped、sanitizer 12 passed/4 skipped。TSAN 跳过原因是 runtime probe failed。上述是作者报告，本轮没有独立重跑。

`PROGRESS.md` 对“容器无 clang，真实 sanitizer 未运行”的笼统描述与 JSON 不一致：JSON 有 GCC ASAN 执行记录。缺 clang 不等于无编译器；`ZSCOPE_REVIEW_ISOLATED=1` 也只是测试准入标记，不能独自证明隔离。

## 完整验收要求的摘要

权威来源为 [WORK_PACKAGES.md](../WORK_PACKAGES.md) 的 V01/V02 及 [ACCEPTANCE.md](../ACCEPTANCE.md) 的 AC06/10/11/15/17/18。

- V01（依赖 D01；AC06/10/11/17/18）：先完成 provider/fake，再完成真实 ASAN；使用独立新增正例和安全反例，不能用 test/range、未知脚本或模型任意命令。计划必须绑定项目、源码内容/版本、候选对象/站点/缺陷族、build、toolchain、harness、输入和二进制。运行必须限定 argv、cwd、环境 allowlist、自有临时写区、时间/资源、进程组取消，并如实记录隔离；缺少批准的隔离时只可 fake/not_run。执行记录必须有命令、摘要、输入、逐轮日志、退出/分类、调用栈与源码映射、独立重放和实际限制。只有每轮都命中原候选、生产信任且输入核验的 witness 才能进入统一确认；无关崩溃、未复现、失败、超时/OOM、取消或缺工具都保持未决。源码/二进制漂移必须使旧证明失效；产物必须完整；无真实运行环境不能标 done。
- V02（依赖 V01；AC06/11/15/18）：复用 runner/receipt，选择 TSAN 或 CBMC，当前选 TSAN；独立 sanitizer 构建，禁止混用 ASAN。TSAN 必须保留线程入口、对象、锁、访问栈、不确定性分布和工具不可用结果。CBMC 如选用则必须声明模型/harness/边界/unwinding，只作有界结论；当前未实现。超时、模型缺失、未知、资源不足、版本/身份未绑定都保持未决。缺工具只能交付 provider，真实验证单独记 not_run。
- AC06：只接受登记引用，拒绝过期/跨项目 TU、未声明/篡改/自证证据；不能把 alias/模型推断并入 proof；序列化不能恢复授权；不得拼接源码漂移前后的证据。
- AC10：不改变冻结 Ledger；生成规则只能追加，未决/失败/中断/人工状态、处置、来源及基线均须保留。
- AC11：覆盖正例、安全反例、错误对象/站点/崩溃、构建失败、无输出、超时、工具缺失、源码/二进制漂移、含空格路径、非零退出、进程取消及伪造日志；重放逐轮匹配，真实工具不能用 mock 代替。
- AC15：记录工具版本、许可/API 和实际权限；缺依赖不能使普通扫描崩溃，不自动安装、不伪装完成、不自动发布。
- AC17：truth 只用于入口预检和完成后的独立评分，不能进入扫描证据；不得修复 range/truth；需独立新增 fixture 和明确边界。
- AC18：默认禁用时兼容不退化；不删除用户缓存/产物；只清理自有后端，不能关闭借用客户端。

## 当前静态疑点（未运行复现）

1. `dynamic_reproduction.py:3560` 在登记 proof 时调用 `frozen_source_digests` 重新取当前文件哈希，而不是比对实际执行时已接受的摘要。该函数（1434–1456）还会略过缺失/不可读文件；最终 liveness 在摘要列表为空时跳过文件核验（1497）。需独立验证“最后一次重放后、登记前修改或删除源码/输入”的失效边界。
2. 冻结列表只包含 candidate source、harness、inputs（1446），没有 binary_path；最终 proof liveness（1473–1508）不重新读取二进制。需独立验证 receipt 后修改/删除二进制是否撤销确认。
3. `docs/architecture.md:531,666` 仍说 V4 仅预留、不调度动态执行，而模块文档与当前实现已有 ASAN/TSAN 路径，文档需核对同步。

这三项是可定位的静态观察，不能计为本轮 failed。未修改产品实现，未将这些内容发送给 DeepSeek。

## DeepSeek 会话与 harness

项目现有会话 `bc51fb3a-c9e7-445e-b6e3-855461b3179c` 的 cwd 精确指向本仓库，preset=standard；最后 turn/end 为 2026-10-09 12:07:21.592 UTC，reason=completed。压缩会话文件仍为 4,511,948 字节、mtime 12:07:21.596 UTC，未观察到对应 Windows DeepSeek/dsh 进程；WSL 活动未知。

Desktop 安装版本 0.2.0.0，内置 CLI 0.2.0-rc.2；PATH 上旧 CLI 是 0.1.2-rc.1。harness 是独立模型执行/会话持久化工具，不等于 Z-SCOPE 的受控 sanitizer runner。Desktop controller 源码 `@deepseek-ai/dsh-api-session-controller/lib/index.js:399–410` 从原 sessionId 观察持久化 header，按原 preset 组装，再执行 `ctx.agents.resume({resumeSessionId: sessionId, setup: composition.setup})`，支持保留原会话身份恢复；writer-held/subagent/不匹配身份会拒绝。未调用该接口，也未启动 Desktop。

headless 拒绝任何含 agentPreset 的现有会话，因此不能接管这个 standard 会话。profile 启动或 profile 范围 help 可能先写 cordis.yml，本轮未运行。session-log 默认启用，可能进入模型请求，独立于一般 telemetry；未读取凭据或发送请求。

## 原始安全拦截与当前限制

最早可定位的失败回合 `01a11a92-7004-7481-9f09-a928e4fb55ef` 报错首句为 `This content was flagged for possible cybersecurity risk.`，details=null，回合没有已记录消息、命令或修改。因此无法把拦截归因于某条 ASAN/TSAN 命令，更不能声称 ASAN/TSAN 本身被禁止。它与父端 cloud 读取路由错误 `unsupported placement region 4`、Git chdir Permission denied、当前 WSL `Wsl/E_ACCESSDENIED` 是不同问题。

正常、防御性的 unit/fake/身份/匹配/预算/取消测试已完成静态审阅，但运行状态仍是 not_run。没有访问被拒绝路径的替代手段、ACL/权限变更、提权试跑或绕过安全限制。

## 下一步所需最小条件

提供一个已获授权、可访问且满足项目规范的 Linux 执行环境，或由用户在正常环境运行指定非真实 fixture 测试并提供完整命令/退出码/JUnit/日志与输入快照。原任务与验收标准目前无需再提供。

真实 fixture 下一步若开展，应先明确仅运行已登记独立 ASAN 样例及构建确认测试：固定本地镜像/工具链、断网、源目录只读、自有 tmpfs 写区、CPU/PID/总内存与墙钟限制，禁止 test/range 与未知输入；当前容器缺 TSAN runtime 前置条件，TSAN 继续 blocked。具体隔离配置尚未独立核验，本轮不执行该方案。任何 DeepSeek 返修前，先展示独立失败及拟发送内容；不得以本报告的未复現静态疑点冒充已运行失败。

