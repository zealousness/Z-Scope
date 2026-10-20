# D01：动态证据登记与版本绑定

## 基本信息

- 日期：2026-10-08，Asia/Taipei；执行者：Agent A / topology_dependencies。
- 开始／结束 HEAD：`010f40210b54ba0f79a088312ce5d8be3a82ace0`；分支：`v1.3.1_feat/llm-wiki`。
- 保留 B00–T03 及其他并行工作者已有修改；未提交、推送、切换或重置。
- implementation_status：implemented；verification_status：targeted_passed，等待总控 G2 组合验收。
- WSL Ubuntu；解释器 `/home/zeal/venv313/bin/python`；cwd `/mnt/c/Users/10273/home/work/Z-Scope_1.31/Z-Scope`；配置／project.root 均为 pytest 临时 fixture，无真实项目扫描。
- 固定 PATH：`/home/zeal/venv313/bin:/home/zeal/go/bin:/usr/lib/llvm-18/bin:/home/zeal/.local/svf/SVF-linux-x86_64/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin`。

## 变更与接口

新增 `zscope/orchestration/investigation.py`：内部 `InvestigationIdentity`、`SourceScope`、`InvestigationRequest`、进程内 `InvestigationSession` 和 `InvestigationResult(report, session)`。身份包含 project/revision/build context/tool/rule/prompt/model/policy。Scope 来自程序解析；模型只能请求已有 scope 或提交函数 UID 供程序授权扩展，不能提供自签范围。初始 scope 必须对应固定 projection 的文件及范围；扩展限额不更改原 AuditUnit。

Session 以受限 executor 调用原六工具中的五个候选盲工具；不支持 static findings、scan、shell 或网络。search/read 经已有 ProjectSourceAccess 读取并核验，返回片段与真实源码逐项对应。工具结果只有类型化许可字段进入调查证据；嵌套 verdict/proof/verification、契约提议及任意 metadata 不授予证明资格。flow/graph 始终保持 may 与 partial；缺 build context 时拒绝这两类查询。cache_only 语义只记录可观察缓存状态，不导入旧契约或怀疑点。

每次执行前、执行后、投影后及报告校验时重新核对身份、所有已登记源版本和原始 artifact 摘要。源码变化、同名不同 TU、规则／工具／prompt／model／policy 变化使会话失效。动态主 location 必须匹配其函数的获准文件及行区间。复用 ImmutableEvidencePool 隔离 mutable view；随机会话 ref 只在本进程 Session 有效，序列化 hash 不恢复权限。

`active_discovery.py` 的旧两参 ReportRunner 保持兼容；可选返回 InvestigationResult。Coordinator 增量引用只在当前 Session 校验期间生效，随后仍进入现有 CandidateRegistrar；不修改 disposition、Ledger 或注册器。动态报告不写入只按原 Unit 身份寻址的旧 report cache；候选 evidence_pack 保存调查 manifest。登记结束或异常时关闭会话。

原始工具 artifact 仅保留至 Session 关闭，明确标记 `artifact_retention/session_only`、`replayable=false`；持久 manifest 保存可信投影与原始 payload 摘要供审计，**不宣称原始输出可持久重放**。没有新增持久能力加载器、数据库迁移、Config v2 或默认开关。

## 验收结果

| 执行 | passed | failed | errors | skipped | exit | 说明 |
|---|---:|---:|---:|---:|---:|---|
| run1 | 0 | 0 | 1 | 0 | 2 | 新测试使用 pytest 保留参数名 `request`，collect 失败；测试定义错误，已修正 |
| run2 | 47 | 0 | 38 | 0 | 1 | 新 fixture 风险低于默认 planner 门槛，setup 取空列表；测试构造错误，已以局部测试 profile 修正；既有 47 项通过 |
| run3 | 85 | 0 | 0 | 0 | 0 | D01 + active discovery + candidate ledger；后续改动后已由 final 重验 |
| final | 89 | 0 | 0 | 0 | 0 | 新增 single-entry 回归；38 项 D01 专项和 51 项共享回归 |
| 首次定向 mypy | N/A | 4 诊断 | 0 | 0 | 1 | 新模块 Optional narrowing / Any 返回类型已修正 |
| final 定向 mypy | N/A | 0 | 0 | 0 | 0 | 2 source files |
| final 定向 compileall | N/A | 0 | 0 | 0 | 0 | 两产品模块及新测试 |
| git diff --check（所属文件） | N/A | 0 | 0 | 0 | 0 | 通过 |

验收 AC06：真实 text/files search→read 两步闭环（无 AST/LLM）；伪造 ref、反序列化恢复、跨项目／revision/build/rule/tool/prompt/model/policy、未授权扩展、错误主 location、源码在工具执行及投影期间变化、artifact 篡改、同名不同 symbol、partial 完整度冒领均有断言。

验收 AC07：受保护路径、任意工具／路径／范围在 executor 前拒绝；嵌套结论／proof 无法进入许可投影；伪造源码和搜索片段失败；保留普通源文本。

验收 AC10：动态 hypothesis 通过既有 registrar，保持 needs_review；冻结 Ledger 拒绝新注册；旧 CandidateLedger 全部相关回归通过。

验收 AC18：旧 report_runner 与单入口回归通过；旧默认未启用调查；Session close 失效引用且释放原始 artifact；无持久迁移。取消和多轮 Worker 属于 D02，未在 D01 宣称完成。

所有执行日志及输入摘要位于 `/tmp/zscope-parallel-20261008/D01/{run1,run2,run3,final}/`。final 的 41 个相关源码／测试输入在命令前后完全一致；摘要文件 SHA256 为 `93e243feec1d9cc1d81b3165c09430221227f30857d3a9314e0a5eb7ec509230`。并行其他任务的文件不计入本专项证明；总控 G2 应冻结组合输入重验。

final 实际命令（均在上述固定 WSL 环境）：

```text
python -m pytest -q --tb=short tests/test_investigation_evidence.py tests/test_active_discovery.py tests/test_candidate_ledger.py tests/test_single_entry_active_discovery.py --basetemp=/tmp/zscope-parallel-20261008/D01/final/tmp -o cache_dir=/tmp/zscope-parallel-20261008/D01/final/cache
python -m mypy zscope/orchestration/investigation.py zscope/orchestration/active_discovery.py --cache-dir=/tmp/zscope-parallel-20261008/D01/final/mypy
python -m compileall -f -q zscope/orchestration/investigation.py zscope/orchestration/active_discovery.py tests/test_investigation_evidence.py
```

## 局限与续接

- 未运行：真实模型、付费服务、Clang/SVF 重建、benchmark、性能或 TP/FP 测量；D01 不依赖这些外部验收。
- Session 的 source_revision 是完整文件摘要；冻结 Semantic Map 的 function code_hash 是函数源码摘要，二者不能混用。D02 factory 在创建真实会话前必须核对 Map 记录与当前函数源码；旧 Map 无法核验时返回 unknown/拒绝调查，不能用 HEAD 代替工作树身份。
- 当前 get_semantic_context 投影仅提供缓存状态；graph/flow 在既有 candidate_blind runtime 下仍可能 unavailable，Session 不启动后端或绕过 runtime 权限。
- 新代码和测试已冻结，等待总控 G2；D02 尚未实施。总控负责 TASKS.yaml、PROGRESS.md、共享模块文档与双入口后续接线。

冻结源码 SHA256：

| 文件 | SHA256 |
|---|---|
| `zscope/orchestration/investigation.py` | `ceb0834f9ae85837f3fb38ba586c3c61f5bec3c33374783d43913902386724b9` |
| `zscope/orchestration/active_discovery.py` | `3c45a89426c5e60f3356d851fd3cbdee3ca9df594a420fb3fbba1c357803b324` |
| `tests/test_investigation_evidence.py` | `c105008d6ee7c9a8863cfcb70f63f3e1b2e071ba1503265da16c1cc37912c285` |
