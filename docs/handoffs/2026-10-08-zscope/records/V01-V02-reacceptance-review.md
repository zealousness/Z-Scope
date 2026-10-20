# V01 / V02 第二轮独立验收

日期：2026-10-09（Asia/Taipei）。验收对象为 [DeepSeek 修订回应](V01-V02-acceptance-response.md) 对应的当前工作区，保留 [首轮报告](V01-V02-acceptance-review.md) 及原始证据。

**结论：仍不放行。** 修订确实修复了多处边界，109 项提交方单测、原样的 25 项首轮负例及 1539 项兼容回归均通过；新增边界与集成用例共 **1 passed、17 failed**。真实 ASAN 原有用例通过，但构建产物进入确认链的新增真实用例失败；隔离容器内 TSAN 仍不具备运行条件。V01 保持 `in_progress`，V02 保持 `blocked`，不得登记 `done`。

## 版本、环境与证据归属

- 分支 `v1.3.1_feat/llm-wiki`，HEAD `010f40210b54ba0f79a088312ce5d8be3a82ace0`；未回退、未切分支、未提交或推送。
- 保留已有全部未提交实现。验证绑定实际工作区内容：提交方冻结的 18 个文件均与其记录一致；独立 driver 另捕获源码、测试、脚本、工具材料、模块文档等 **812 个文件**，测试前后 `changed_inputs=[]`。最终检查再核对这些文件。不能以 HEAD 相同代替内容相同。
- 核心实现 `zscope/core/validation/dynamic_reproduction.py` 的 SHA-256 为 `579e2a08f1e8f93746c54060d225c1294d4ca469b6a22c18c349792a3bfa7f47`。下列代码行号对应本内容。
- 普通测试、compileall、mypy、文档及 diff 检查均在 WSL Ubuntu，使用 `/home/zeal/venv313/bin/python`（3.13.15）和 driver 所列的显式 PATH；没有使用原生 Windows Python 形成结论。
- 故意缺陷 fixture 仅在已有 pinned 镜像的断网只读容器执行。实测仅 `lo`、仓库只读、`CapEff=0`、`NoNewPrivs=1`、内存 2 GiB、PID 256、CPU 2；无镜像下载、依赖安装或权限放宽。容器的边界属于验收设施，不能计入产品 runner 能力。
- 新增独立测试与脚本只放在 `records/`，没有改产品代码或提交方测试。首轮验收脚本及历史 JSON 不覆盖；旧的 `server.pid` 和 `m5tpr_replay_results.jsonl` 保留并复核摘要。

## 本轮确认有效的修订

完整 issue 字段比较、序列化 proof/replay 不恢复能力、fake 默认不授予生产确认、disabled 边界惰性、缺失请求隔离即停止、空执行根拒绝、首次启动前核验 harness/input/binary、截断保持未决，以及逐轮记录结构均已有通过的测试支持。ASAN 正反例、错误位点 crash、构建失败、旧二进制拒绝及现有统一裁决路径也在外层隔离中复验通过。

但首轮负例的通过不能单独证明当前生产资格完整。旧文件的 `qualified_issue()` 仅断言 `proof_attached`；修订后 fake 可附加描述性未决 proof，因此部分后续拒绝断言未实际经历“先有有效确认、再失效”的路径。本轮增加了初始 selector 必须接受确认的正向控制，再验证失效；需要生产信任时只使用明确带理由的受控测试注入，不修改产品授权规则。

## 仍需修订的具体问题

### R01 / P1：实际文件变化没有贯穿执行与最终确认边界

位置：`dynamic_reproduction.py:1277`、`:1749`、`:1818`、`:1959`、`:2748`。

最终 `dynamic_witness_proof_is_live` 重算的是 issue 字典身份，没有重新核验执行所绑定的实际源码或冻结快照。测试先建立可被 selector 接受的 live confirmation，再改动对应真实源码文件、保持尚未刷新的 issue；selector 仍返回确认。

执行阶段也只在初次进入时校验输入。第一轮后更改 harness、input 或 binary，第二轮仍启动；build 更改已验证的 harness 后仍执行 run。四个启动 spy 用例分别观察到 2 次运行、或 `build + run-0`。这不是要求调用方及时改写字符串能解决的边界：执行器需要冻结输入，或在每个消费点校验实际身份并在漂移时停止；最终裁决须消费可核验的当前版本/快照资格。

复现：`test_filesystem_source_change_revokes_live_confirmation`、`test_each_execution_revalidates_current_files`（3 项）、`test_build_cannot_change_verified_source_before_run`。

### R02 / P1：具名对象仍使用子串匹配

位置：`dynamic_reproduction.py:1490–1496`。

回应声称具名 token 必须相同，实际代码还接受双向子串。`shared_counter` 与 `shared_counter_backup`（两个方向）、`buffer` 与 `other_buffer`，在相同站点/缺陷族下均被视为同一对象。三个独立负例失败；另一个不同 token 的负例通过。去掉同位点兜底是有效修订，但不能用名称包含关系证明对象身份。匿名地址匹配也仍需明确描述其能力边界，函数名出现在栈中不能普遍代替对象/分配身份。

复现：`test_similar_named_resources_are_not_the_same_object`。

### R03 / P1：确认链没有核验所有执行的生产资格及逐轮 witness

位置：`dynamic_reproduction.py:2714–2865`。

重放资格检查只要求关联 execution token live，没有要求每个 replay execution 具备生产信任、verified inputs 和对应完整身份。独立用例仅把主执行显式提升为受控生产正向控制，保留所有 replay 为 `TRUST_TEST`，最后仍取得可被 selector 接受的确认；这说明生产主记录与测试重放可混合授予生产能力。

此外，主记录 `record.runs` 没有被逐轮匹配，只消费聚合 `record.findings` 与分类字符串。第二轮实际位点为 `other.c:999`、第一轮匹配原候选时，只要分类同类，资格仍为 true。真实 runner 的独立 replay 又调用多轮 execute，receipt 仅投影其聚合 finding，因此嵌套轮次也不能由分类一致代替对象/站点一致。

复现：`test_untrusted_fake_replays_cannot_complete_production_confirmation`、`test_every_primary_run_must_match_the_candidate`。测试信任提升均通过公开的显式测试注入，不是序列化伪造。

### R04 / P1：runner 支持的 build 产物无法完成资格确认

位置：`dynamic_reproduction.py:2753–2760`。

计划允许 `binary_digest=""` 且由 `BuildSpec` 创建程序；执行器计算并记录构建后的实际摘要，得到真实 `witness_observed`。但资格判定仍要求计划中预先存在摘要，最终返回 `binary_identity_unbound`。提交方现有 real-build 用例只验证执行 outcome，没有走到确认。

新增隔离真实用例完整编译授权 ASAN fixture、执行、独立重放、登记，稳定在上述资格检查失败。需要建立本次获准 build 到其产物身份的可信绑定，再供重放及裁决共同消费，不能仅把非空字符串当成来源证明。

复现：`V01-V02-reacceptance-integration.py::test_build_generated_binary_can_complete_qualified_confirmation`。完整 record/replay/facts 见 [构建证据](V01-V02-reacceptance-build-evidence.json)。

### R05 / P1：默认产品入口固定选择 ASAN

位置：`dynamic_reproduction.py:3094`；调用方 `runner.py:650`。

未显式传入 runner 时固定 `AsanReproductionRunner`，没有按 `plan.provider_kind` 分派。主扫描接缝不传 runner，因此 TSAN 计划通过默认入口会发生 provider kind 不匹配，而独立 TSAN 测试手动创建 runner，未覆盖这条运行链。本问题由无工具依赖的 factory spy 复现，与当前容器 TSAN runtime 不可用相互独立。

复现：`test_default_product_entry_selects_tsan_provider`，实际 factory 为 `asan`，期望 `tsan`。

### R06 / P1：授权运行次数被嵌套重放放大

位置：`dynamic_reproduction.py:1959`、`:2650–2709`、`:3088–3105`。

`required_replays=2`、`plan.max_replays=2` 能通过“执行次数已获准”的检查；主 execute 执行 2 轮，两个 independent replay 各再次 execute 2 轮，合计 **6 次**。含 build 的计划还会重复构建。当前检查只比较参数，没有计量真正的进程启动数，也没有实施整个验证流程共享的预算。每次进程超时亦不能代替任务总 deadline。

复现：`test_execution_budget_counts_primary_and_independent_runs`，实际 spy 调用 6 次，计划上限 2。需要明确 primary/replay 的计数口径并让真实调度遵守授权总量，不能靠增大声明上限掩盖嵌套执行。

### R07 / P2：同一计划后续执行覆盖已有 artifact

位置：`dynamic_reproduction.py:2370–2400`。

发布路径为 `artifact_dir / plan_id / run-<i>.stdout|stderr`，同计划的主执行与独立重放反复覆盖相同名字。用获准的无害 `date` 命令连续执行同一计划，第一条 receipt 引用的文件内容摘要在第二次之后已改变；并发执行还存在相同覆盖路径。普通存储是否 immutable 不是本问题的前提，每个 execution 至少需要独立目录，并核对发布成功/摘要，缺失产物不能自称完整可重放。

复现：`test_published_artifacts_survive_next_execution_of_same_plan`。

### R08 / P1：无计划时的退化路径仍可使扫描抛错

位置：`dynamic_reproduction.py:3212`；`runner.py:650–674`。

在查询 plan provider 前先调用 `bind_candidate(issue)`，缺少 source revision 时抛 `incomplete_candidate_binding`，此异常位于保护块之外，扫描调用方也没有处理。新增测试使用正常 `annotate_issue_identity` 生成 project_id 合法、revision 为空的本地项目候选：未注册 provider 时仍抛错，不能得到回应承诺的 `no_plan_provider` 或身份 unavailable 的未决结果。未注册可执行验证源不应要求所有普通候选具有执行计划身份；身份不足必须记录并继续既有扫描。

复现：`V01-V02-reacceptance-integration.py::test_missing_optional_candidate_identity_does_not_abort_scan_without_provider`。

### R09 / P2：启动取消与关闭生命周期仍未闭合

位置：`dynamic_reproduction.py:2151–2228`、`:1255`。

已取消 token 在 Popen 之前没有检查；独立 Popen spy 证明仍会启动进程，短命进程甚至先 poll 退出而避开取消检查。循环中的取消可杀进程组是已有通过能力，但不能代替启动前检查。

源码搜索未发现产品调用 `release_dynamic_reproduction_authority()`；它是清空全局注册表的函数，TTL 也不等同于 scan-owned 的关闭释放。需要任务作用域的 authority/provider 生命周期，避免未释放或清理其他并发任务的能力。正常父进程退出后的子进程树收尾本轮未单独执行验证，仍不得宣称完整关闭验收。

复现：`test_already_cancelled_execution_does_not_spawn`；生命周期接线为静态审查项。

### 仍未满足的资源验收及平台观测

- **资源约束（F06 剩余项）**：修订已准确披露 ASAN 是单次分配上限、TSAN 无内存限制。但 `output_capture_limit_bytes` 只限制进程退出后保留的前缀，stdout/stderr 实际写入磁盘、完整 hash、发布复制仍没有总字节上限；也没有实际总 RSS 限额。工作包要求的资源边界尚未完整实现。本轮不做资源耗尽试验，静态审查不能登记为硬资源门禁 passed，外层容器限额不能代替产品能力。
- **平台观测**：默认关闭仍从 `runner.py` 无条件导入顶层 `resource`。在 Linux 子进程模拟该 POSIX 模块缺失时导入失败；该用例计入新增测试失败。没有运行原生 Windows 测试，也没有把它外推为已实测的 Windows 发布失败。README 推荐 Windows 通过 WSL 使用 Linux 包，因此此项需明确受支持入口的边界，不单靠该模拟结果阻止 Linux 验收。
- **计划获取范围**：已确认新增扫描接缝，默认 off 的兼容回归通过；approved-plan provider 仍是进程内单槽，harness/输入生成器未交付，序列化请求仍 `reserved_not_implemented`。保留此能力声明限制，不要求模型自动执行任意命令，也不把手工 fixture 的成功扩大为任意项目端到端能力。

## 实际执行结果

所有命令、PATH、退出码、JUnit 计数及完整失败输出见 [WSL 验证 JSON](V01-V02-reacceptance-validation.json)、[容器验证 JSON](V01-V02-reacceptance-container-validation.json) 和 [收尾检查 JSON](V01-V02-reacceptance-final-check.json)。重跑入口为本目录对应的 `reacceptance-driver.py`、`reacceptance-container.py`、`reacceptance-final-check.py`，不要运行提交方脚本覆盖其自验证据。

| 组 | 结果 | 退出码 / 口径 |
| --- | --- | --- |
| `tests/test_dynamic_reproduction.py` | 109 passed，0 failed，0 skipped | 0 |
| 首轮独立负例（原样文件） | 25 passed，0 failed，0 skipped | 0；存在上文所述正向控制限制 |
| 新增确定性边界 | 1 passed，15 failed，0 skipped | 1；含 1 项平台模拟观测 |
| 新增扫描接缝 | 0 passed，1 failed，0 skipped | 1；真实构建用例在该组 deselected |
| 77 文件兼容回归 | 1539 passed，0 failed，0 skipped | 0；3 项重型 native 用例 deselected，记 not_run |
| 隔离容器的原有 ASAN/证据测试 | 9 passed，0 failed | 与新增构建项同组运行 |
| 隔离容器新增 real-build 确认链 | 0 passed，1 failed | 容器 pytest 合计 exit 1 |
| 隔离容器 TSAN | 0 passed，4 skipped | runtime `sanitizer_probe_failed`；真实 TSAN not_run |
| `compileall -f -q zscope scripts test tests` | passed | 0 |
| `mypy zscope`（独立 cache） | passed，307 source files | 0 |
| `tests/test_agent_docs.py`（状态更新后） | 6 passed | 0；见收尾检查 |
| Linux `git diff --check`（保留既有 CRLF 口径） | passed | 0；见两个 driver |

TSAN 的 4 skipped 只表示本环境未执行，不能写成失败候选或验证成功；提交方在宿主 WSL 的 13 passed 保留为其自验证据，不替代本轮隔离条件下的 G3。CBMC 未实施；3 项重型索引测试、正式 benchmark、真实模型、第三方工程、性能收益及原生 Windows 验收均 not_run。没有测试 infrastructure error 或 xfail 掩盖以上功能失败。

## 状态与后续复验

- **G1 未通过**：R01–R09 中的功能/权限/预算/产物问题仍在；F01–F08 只能登记为部分修订，不能整体关闭。
- **G2 兼容回归通过，集成放行未通过**：保持六工具、Config v2、现有 Ledger 与统一裁决路径的回归结果；build、TSAN dispatch 和退化接缝仍阻止完成交付。
- **G3 部分通过**：原有 ASAN 场景通过，build 确认链失败；TSAN 真实执行因环境条件未满足保持 not_run。
- **G4 未执行**：无晋升或收益结论，默认 off 不变。

后续保留全部记录，优先修正实际输入/候选失效、对象匹配和完整重放资格；随后闭合 build、provider 分派、运行预算、artifact 与取消/关闭。将本轮边界用例迁入产品测试时保留初始确认正向控制，不能通过削弱断言、修改为 xfail 或把全部 fake 场景变成无权限状态来消除失败。修订后以新的内容摘要重跑专项、集成和获准隔离下的真实执行。缺少 TSAN 运行条件时只阻塞该真实 provider 门禁，不安装替代工具或降低隔离。
