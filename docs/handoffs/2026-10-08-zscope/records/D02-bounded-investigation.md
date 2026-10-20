# D02：有界主动调查 Worker

## 基本信息

- 日期：2026-10-08，Asia/Taipei；执行者：Agent A / topology_dependencies。
- 开始／结束 HEAD：`010f40210b54ba0f79a088312ce5d8be3a82ace0`；分支：`v1.3.1_feat/llm-wiki`。保留全部既有及其他 agent 修改；无提交、推送、安装或网络模型调用。
- implementation_status：implemented；verification_status：G1_targeted_passed，等待总控 G2；真实模型收益未验证。
- WSL Ubuntu；解释器 `/home/zeal/venv313/bin/python`；cwd `/mnt/c/Users/10273/home/work/Z-Scope_1.31/Z-Scope`；project.root 与配置均使用 pytest 临时 fixture。
- PATH：`/home/zeal/venv313/bin:/home/zeal/go/bin:/usr/lib/llvm-18/bin:/home/zeal/.local/svf/SVF-linux-x86_64/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin`。

## 实现与接线

新增 `zscope/orchestration/bounded_investigation.py`，导出 `make_investigation_runner(config, semantic_map, client, cancellation=None)`。off 在任何运行时构造前返回 None；shadow 返回三参 callable `(projection, profile, AuditUnit)`。总控在单入口 Analyzer 与 ParallelAnalyzer 接同一工厂，传入共享 client 与取消 token；Agent A 未编辑这两个入口或公共配置。

调查使用现有 JsonToolAgent 结构化终止路径，每次产生 query、finish 或 unknown 决策；内部 finalizer 不增加公共六工具。最多 4 个逻辑决策，包括失败／非法／截断及最终报告；失败不能改 ID 重置预算。工具失败后仍有剩余轮次可继续，重复同查询或相同证据内容停止，不追加第 5 个总结调用。默认最多一次程序授权范围扩展。沿用现有 max_subagent_tickets 限制 shadow 总单元数，超限单独记录 deferred/uncovered。

普通一次式发现仍先执行，原 report cache、可见性和来源不变。Coordinator 可选 investigation_runner 在程序判定存在 gap、风险达到门槛且源码可查询后执行独立 shadow 阶段。一次式报告内容不传给 Worker。调查候选经同一 CandidateRegistrar，source/candidate_source 为 active_investigation，公共 discovered_by 仍为 llm_active_discovery，discovery_details.method 为 bounded_investigation。

调查使用已有 validator_contract 将 shadow 验证策略组与 active 组分开；同一 canonical obligation 保持相同 obligation_uid，不修改 Ledger 或 canonical obligation 的生成逻辑。统计保留两个来源，但不能把两个验证组当成两个独占发现。所有新增候选都无 proof 权限，不能晋升为确定性结论。

RuntimeSpec 内部字段由总控实现：active_investigation_mode(off/shadow)、active_investigation_max_rounds(1..4)、active_investigation_timeout_seconds(有限正数)、active_investigation_max_scope_extensions(0..1)。public Config v2 不增加字段。Worker 自身也拒绝 bool、NaN、Inf、非数值或非正 deadline。

## 只读、身份与取消边界

工厂只构造 CachedCodeIndex、ReadonlySnapshotStore 和 candidate_blind ToolsRuntime；不构造 live CodeIndex、可写快照、后端或建模 resolver。初始 Map.function.code_hash 必须等于当前函数的精确 raw／CodeIndex 编号源码摘要（按已知通用换行规则生成）；未知、过期、范围越界拒绝调查且不请求模型。不能用 HEAD 代替工作树身份。

授权扩展只取原 Map 的 direct callee：精确 index_name 优先；bare name 只有唯一匹配才可请求。同名多个 TU 的 helper 不获授权。扩展时重新验证对应函数源码；成功后下一轮上下文显示真实 granted_scopes。身份绑定 tool 实现及 schema、rule catalog、Map、prompt、STEP_SCHEMA、已有 finalizer、模型及 provider 配置摘要；不保存密钥或 private endpoint 明文。

源码工具取证使用 D01 Session，语义只用 cache_only。旧索引缺少可核验 build receipt，因此当前实际工厂均为 source-only；graph/flow 保持 unavailable，不能以 Map revision 或 hash 冒充 TU proof。

执行使用调用方 CancellationToken 的子 token 与同步 JsonToolAgent，不新增进程或后台线程；只关闭自有 CachedCodeIndex，不关闭共享 LLM client。父取消或自定义 runner 抛 CancellationError 时，停止本阶段，余下 eligible 单元记 cancelled_deferred/uncovered。局部 deadline 只停止本单元，后续单元仍可尝试；工厂依据真正 owner token 区分两者。

每次 query 成功登记后立即保存 trace 与 manifest，再观察取消／新增内容。no-gain 或工具返回期间取消仍保留最后一条已登记引用。身份有效的终态再统一 snapshot；过期证据标 stale_or_unavailable，撤销 report 和运行时引用。原始 artifact 沿用 D01 session_only，持久审计只有可信投影和摘要，不声称可重新加载 proof 或完整 raw artifact。

计量明确区分 decision_calls/rounds、tool_attempts、registered_ref_count 与 unique evidence_count；physical_llm_attempts 为 unknown。usage 只累计现有响应提供的非负 token 字段，不用工具次数推断模型成本或质量收益。

## 验证结果

| 执行 | passed | failed | errors | skipped | exit | 说明 |
|---|---:|---:|---:|---:|---:|---|
| run1 | 94 | 3 | 0 | 0 | 1 | 2 项 FakeClient 未模拟真实 finalizer tool-call 的 fixture 错误；1 项新来源误用公共枚举，已保持既有枚举并在详情区分方法 |
| run2 | 96 | 1 | 0 | 0 | 1 | 同 canonical root 的 shadow 与 active 合并，已用既有 validator_contract 分开策略组 |
| run3 | 108 | 0 | 0 | 0 | 0 | 当时专项回归通过；后续输入变化已重验 |
| final | 140 | 0 | 0 | 0 | 0 | pytest 通过；mypy 有 3 条 context 推断诊断，已补显式类型；compileall 通过 |
| final2 | 140 | 0 | 0 | 0 | 0 | mypy/compileall 均通过，但总控双入口测试在过程中变化，结果不绑定最终输入 |
| final3 | 146 | 4 | 0 | 0 | 1 | 新多单元取消 fixture 错误提供空 positive refs，报告构造即失败；已修测试构造；mypy/compileall 通过 |
| final4 / G1 | 150 | 0 | 0 | 0 | 0 | 6 个相关测试文件，43 个输入摘要前后一致 |
| final4 mypy | N/A | 0 | 0 | 0 | 0 | 两产品模块 |
| final4 compileall | N/A | 0 | 0 | 0 | 0 | 两产品模块与专项测试 |
| 所属文件 git diff --check | N/A | 0 | 0 | 0 | 0 | 通过 |

AC08 fake 场景覆盖一次终止、第二次查询取证完成、工具 unavailable、重复同查询／同内容、非法 ref、越界扩展、输出截断／格式错误、轮次耗尽、用户取消和 Worker 异常。增加工具返回中取消保留记录、多单元父取消／owner deadline／局部 deadline、同名 callee 歧义、模型变化失效等负例。AC07/AC10/AC18 同时复跑 D01、CandidateLedger、旧一次式发现、双入口接线和 RuntimeSpec 回归。冻结 Ledger、候选盲与无 proof 约束保持。

AC16：pytest 命令、exit、前后摘要、150/0/0 统计持久化于 `D02-G1-validation.json`。临时输出位于 `/tmp/zscope-parallel-20261008/D02/{run1,run2,run3,final,final2,final3,final4}/`；每次使用独立 basetemp/cache。final4 输入清单摘要 `531322e18ec043a7ce0d56db493e4a0fddfac77fd2c4d3e763dc83b11b024bae`。

实际 final4 命令（固定上述 WSL 环境）：

```text
python -m pytest -q --tb=short tests/test_bounded_investigation.py tests/test_investigation_evidence.py tests/test_active_discovery.py tests/test_candidate_ledger.py tests/test_single_entry_active_discovery.py tests/test_investigation_runtime.py --basetemp=/tmp/zscope-parallel-20261008/D02/final4/tmp -o cache_dir=/tmp/zscope-parallel-20261008/D02/final4/cache
python -m mypy zscope/orchestration/bounded_investigation.py zscope/orchestration/active_discovery.py --cache-dir=/tmp/zscope-parallel-20261008/D02/final4/mypy
python -m compileall -f -q zscope/orchestration/bounded_investigation.py zscope/orchestration/active_discovery.py tests/test_bounded_investigation.py
```

## 未执行与续接

- not_run：真实 LLM、真实服务重试／成本、独占 TP/FP、正式 benchmark、native backend 重建与性能比较。没有配置外部模型；不声明真实收益。fake 测试没有请求网络。
- 当前支持源码调查和 cache-only 状态；不宣称已恢复 TU graph/flow、完整跨变体关系或跨进程 artifact 重放。
- 总控负责 TASKS.yaml、PROGRESS.md、模块文档与 G2。D03 必须在 D02 G2 正式通过后才解锁；本记录不声明 D03 已实现。

G1 冻结文件 SHA256：

| 文件 | SHA256 |
|---|---|
| `zscope/orchestration/bounded_investigation.py` | `421b0cb88c4970e99d9677babf0c1d9a036fcbe0cb93ba8147003a96215925bd` |
| `zscope/orchestration/active_discovery.py` | `fae83fd38afa9734ec5cf86081a4a099988076ef3a91e4b3848180cd929d01bc` |
| `tests/test_bounded_investigation.py` | `f784af5f94b4ffb9a6cad6e32054599efc5484221a3f8d826ba5f17df56589d9` |
