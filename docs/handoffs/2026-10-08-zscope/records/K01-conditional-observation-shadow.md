# K01 条件观察 shadow 增量

日期：2026-10-08。Agent A。分支 `v1.3.1_feat/llm-wiki`，HEAD `010f40210b54ba0f79a088312ce5d8be3a82ace0`。本记录对应工作区增量，未提交、未推送。

## 实现与接线

- `snapshot_observations.py` 增加按模式复制的 schema。off 与原 schema 结构相等且不修改全局常量；shadow 增加有界 `conditional_observations`，旧 `suspicious_points` 继续作为背景。
- typed 观察必须包含可解析源码位点、精确 source anchor、源码可见对象或 source/sink、违反性质、结构化条件、missing facts。常量条件折叠不代表路径可行性；符号条件保留 unknown。返回所有权的局部缺失释放观察不自行形成调用方义务。
- `bind_snapshot_observation` 只接受实际建模前捕获的进程内输入 callback/摘要。源码全文摘要、精确函数身份、schema、contract、snapshot 与当前 callback 均须一致；复制、序列化、旧缓存不能恢复资格。
- B 在真实 IncrementalSemanticModeling schema、输入指纹、执行与发布屏障接入 helper。只有本轮实际模型任务保有 receipt；custom schema 无法无副作用重新获取时保守不授资格，热缓存仍可作为原建模背景。B 的细节与回归见 `P02-G1-validation.json`。
- Root 在两入口原生 blind discovery 后、主 Ledger freeze 前接 `register_conditional_snapshot_candidates`，默认 off。注册仍走 CandidateRegistrar，`semantic_snapshot` 来源、`semantic_modeling` 公共归因，方法 `conditional_snapshot_observation`，无 proof 权限；独立 shadow validator_contract 保留 canonical obligation，同时隔离 active validation group。
- 路径终点核对完整 SymbolIdentity，含 file/signature；无入口或错误 overload 不注册。最终注册前再次核对输入。候选盲调查只保留类型化语义状态，不能看到新增 typed 观察。
- 统计分别记录背景、未覆盖原因、same-source repeated、cross-source canonical overlap、pending/terminal shadow obligations。独占 TP 为 `not_measured`，额外模型成本 `unknown`，不会因未测收益打开 active。

## 首版范围与限制

可授资格范围是有界、许可项目内、自包含的 source-only 输入。出现编译数据库（含空数据库）、显式非标准数据库路径、外部或不可解析 include、Java classpath、非空隐式编译环境、扫描预算耗尽、权限/链接/编码问题时不授当前观察资格。未接独立 TU/current compiler receipt，不能通过文件或 Git HEAD 相等猜测构建 freshness。

这意味着普通带编译库的 C/C++ 工程暂时只保留建模背景；Clang AST+SVF、六工具、原建模/候选/Validator 路径不受此实验关闭状态影响。未运行真实 LLM、正式 benchmark、独占 TP/FP、人工成本或收益测量，不宣称已验证这些指标。

## 验证

所有命令在 WSL Ubuntu 执行，解释器 `/home/zeal/venv313/bin/python`，cwd `/mnt/c/Users/10273/home/work/Z-Scope_1.31/Z-Scope`。PATH 固定为 `/home/zeal/venv313/bin:/home/zeal/go/bin:/usr/lib/llvm-18/bin:/home/zeal/.local/svf/SVF-linux-x86_64/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin`。日志、basetemp、pytest/mypy cache 独立位于 `/tmp/zscope-parallel-20261008/K01/`；逐条命令、退出码、前后 SHA256 与最终文件摘要保存在 `K01-G1-validation.json`。

| 轮次 | passed | failed | errors | skipped | 结果 |
|---|---:|---:|---:|---:|---|
| unit1 | 0 | 0 | 1 | 0 | 新测试 decorator 多余冒号，收集失败，exit 2；原始日志保留 |
| unit2 | 45 | 0 | 0 | 0 | exit 0，输入稳定 |
| unit3 | 51 | 1 | 0 | 0 | 测试误把 Registrar 规范化 missing_fact_kinds 当作原始字段；改验 evidence_pack 原始缺口及规范缺口非空，未改产品 |
| unit4 | 54 | 0 | 0 | 0 | exit 0，输入稳定 |
| G1 组合 | 269 | 0 | 0 | 0 | 10 个相关测试文件，exit 0，27 个输入前后摘要稳定 |
| 最终 typed 产出闭环专项 | 55 | 0 | 0 | 0 | exit 0，4 个输入稳定；包含真实 fake-agent→正常重试/提交/发布→非空 typed 观察→Registrar→freeze |

以上计数存在重复，不相加当作独立覆盖。组合含旧 incremental modeling、D01/D02/D03、双入口、Ledger/Registrar、ValidationPipeline 回归。

`mypy` 两个 owned 产品模块、`compileall`、新文件 Black 与已有文件变更区段 Black 均 exit 0。原始 WSL `git diff --check` exit 2，将 Windows checkout 的大量未改 CRLF 文件识别为尾空白；没有格式化或恢复这些文件。以 `git -c core.autocrlf=true diff --check` 复核 exit 0，原始与复核日志均保留。最终新增测试后 Black/compileall 再验 exit 0、输入稳定。

验收覆盖 AC07 类型化 blind 隔离，AC10 主 freeze 与同 Registrar/统一裁决，AC13 条件/所有权/错误出口/过期/无路径/重复，AC18 off 兼容和进程内资格。AC16 提供指标与 unknown 标记；真实能力/成本收益属于 not_run，不作为通过。

## 冻结与继续

G1 269 项之后只新增一条真实 typed 产出全链路测试，产品文件未变。通知 root 追加测试后，与 root 的 G2 冻结消息发生交错；收到冻结通知时该测试已写完并通过。已立即说明事实，停止产品/测试写入。当前测试文件与 269 项轮次不同，不能把旧轮次冒充最终输入门禁；root 最终 G2 必须按 `K01-G1-validation.json` 的 `final_owned_sha256` 核对。当前只允许 records 续写，等待 root 最终验收。
