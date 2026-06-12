# test/range C 语言内存/并发 Benchmark 扫描对比报告

生成时间：2026-06-12 10:23:45 +08:00

## 结论摘要

在当前 `test/range` benchmark 上，Z-Scope full pipeline 仍是召回率和误报率综合表现最好的方案：default view 召回率 `0.7603`、误报率 `0.0800`；补充 `with_needs_review` 视图后召回率升至 `0.9339`，误报率为 `0.1172`。CodeQL 官方 selected 内存/并发规则非常快，但召回率只有 `0.0661`；官方高召回组合把 TP 从 8 提到 11，同时误报率升到 `0.8333`。把同一批 CodeQL 高召回 SARIF 交给 Z-Scope 验证后，confirmed-only 视图 TP 为 14，误报率降到 `0.4815`，说明验证模式主要价值是过滤噪声和改善最终报告视图，而不是扩展 CodeQL 原始候选覆盖。

opencode 纯 LLM 扫描使用 GLM-5，输出较少，precision 达到 `0.7059`，但召回率只有 `0.0992`。它更像高置信人工审计辅助，不适合作为这个 benchmark 的唯一高召回扫描器。

## Benchmark 范围

本 benchmark 名称为 `zscope-range-service-runtime`，当前 ground truth 版本为 v13，共 121 条漏洞。它面向 C 语言服务运行时中的内存安全、资源生命周期和并发缺陷，代码形态包括 runtime lifecycle、worker/thread、protocol/parser、executor、plugin、network 等模块。

严重度分布为：critical 21、high 71、medium 27、low 2。主要 CWE 包括 CWE-362 race 17 条、CWE-772 missing release 17 条、CWE-401 memory leak 7 条、CWE-416 use-after-free 5 条、CWE-833/CWE-667 deadlock/locking 各 4 条，以及整数溢出、TOCTOU、double free、command injection、stack escape、uninitialized read 等问题。按语义类别看，`memory_leak` 20 条、`race` 8 条、`bounds` 7 条、`deadlock` 4 条、`use_after_free` 4 条，另有 refcount race、lost wakeup、held-lock callback、realloc misuse、stack overflow、stale fd、busy loop 等更贴近真实 C 服务代码的问题。

难度上，这不是单纯的单行告警集合：35 条 ground truth 带 additional locations，28 条带 related functions。许多问题需要跨函数资源生命周期、线程间状态、锁保护关系、引用计数或释放路径推理；局部规则更容易命中 double free、明显 leak、stack/bounds 和注入类问题，但对复杂并发、状态机和跨函数释放路径覆盖较弱。

## 指标口径

召回率为 `TP / 121`。误报率使用当前 benchmark evaluator 的 effective FP 口径，即 `effective FP / (TP + effective FP)`；表中同时列出 `FP(raw)` 和 `duplicate-of-matched`，后者表示评估器认为是已命中 ground truth 的重复报告，不计入 effective FP。CodeQL 时间均为复用既有 CodeQL database 后的 query analyze 时间；冷启动还需要额外 database create。CodeQL 高召回 + Z-Scope 验证的端到端时间包含 CodeQL 高召回组合 analyze 和 SARIF alert verify 两段。

## 总览数据

| 方案 | 结果数 | TP | FP | FP(raw) | 重复命中 | FN | 召回率 | 误报率 | Precision | F1 | 执行时间 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| CodeQL 内存/并发 selected 规则 | 41 | 8 | 30 | 33 | 3 | 113 | 0.0661 | 0.7895 | 0.2105 | 0.1006 | 13s |
| opencode 纯 LLM，GLM-5 | 17 | 12 | 5 | 5 | 0 | 109 | 0.0992 | 0.2941 | 0.7059 | 0.1739 | 258s |
| CodeQL 官方高召回组合 | 69 | 11 | 55 | 58 | 3 | 110 | 0.0909 | 0.8333 | 0.1667 | 0.1176 | 98s |
| CodeQL 官方高召回组合 + Z-Scope 验证模式 | 34 | 14 | 13 | 20 | 7 | 107 | 0.1157 | 0.4815 | 0.5185 | 0.1892 | 2286s |
| Z-Scope full pipeline，default view | 144 | 92 | 8 | 52 | 44 | 29 | 0.7603 | 0.0800 | 0.9200 | 0.8326 | 10201s |
| Z-Scope full pipeline，with_needs_review 补充视图 | 220 | 113 | 15 | 107 | 92 | 8 | 0.9339 | 0.1172 | 0.8828 | 0.9076 | 10201s |

## 方案分析

### CodeQL 内存/并发 selected 规则

该组选择了 64 条偏内存、并发、生命周期相关的 CodeQL C/C++ 查询，最终产生 41 条 alert。当前 evaluator 下命中 8 个 TP：`ISSUE41-006`、`RANGE-006`、`RANGE-007`、`RANGE-013`、`REAL-003`、`REAL-008`、`REAL-015`、`REAL-018`。主要触发规则包括 `cpp/conversion-changes-sign` 17 条、`cpp/memory-may-not-be-freed` 13 条，以及 stack escape、double free、static buffer overflow、uninitialized、tainted arithmetic 等少量规则。

它的优点是快，复用 database 后 analyze 约 13 秒；缺点是对 benchmark 主体问题覆盖不足，尤其是跨函数资源生命周期、并发 race、锁语义、引用计数和状态机问题。备注：旧版 scorer 曾给出 TP=9；本报告统一采用当前 evaluator 结果 TP=8，以便与后续高召回和验证模式横向比较。

### opencode 纯 LLM，GLM-5

opencode 纯 LLM 扫描使用 `alibaba-cn/glm-5`，复用了 Z-Scope 风格的审计 prompt，但不使用 Z-Scope 的程序分析工具链和验证闭环。它输出 17 条 finding，命中 12 个 TP：`ISSUE41-006`、`ISSUE42-006`、`ISSUE42-010`、`ISSUE42-028`、`RANGE-004`、`RANGE-006`、`RANGE-021`、`RANGE-024`、`RANGE-030`、`RANGE-032`、`RANGE-047`、`REAL-018`。

该方案误报率 `0.2941`，precision `0.7059`，明显优于 raw CodeQL 高召回；但召回率只有 `0.0992`，说明纯 LLM 在有限上下文下可以抓到部分语义明显的问题，却很难系统覆盖 121 条 ground truth。它适合作为快速人工审计草稿或高置信样本来源，不适合作为完整 benchmark 的主扫描器。

### CodeQL 官方高召回组合

官方高召回组合把 selected 内存/并发规则与更宽的官方 CodeQL C/C++ suite 结果合并，结果数从 41 增加到 69，TP 从 8 增加到 11，新增命中包括 `ISSUE41-008`、`RANGE-011`、`RANGE-012` 等。对应代价是 effective FP 上升到 55，误报率达到 `0.8333`。

该组合的结论比较直接：扩大官方规则范围确实能多覆盖一些漏洞类型，例如 command/path injection、useless expression、bounds 等，但对本 benchmark 的复杂内存/并发主体仍然不够。它更适合作为“尽量多给候选”的上游 SARIF，而不是直接给用户消费的最终报告。

### CodeQL 官方高召回组合 + Z-Scope 验证模式

该方案把 CodeQL 官方高召回组合产生的 69 条 SARIF alert 传入 Z-Scope alert verify。验证结果为 34 confirmed、34 rejected、1 uncertain；只保留 confirmed 后，最终报告数为 34，TP 为 14，effective FP 为 13。相比 raw CodeQL 高召回，precision 从 `0.1667` 提升到 `0.5185`，误报率从 `0.8333` 降到 `0.4815`。

TP 从 11 变成 14，并不表示 Z-Scope 让 CodeQL 新发现了 3 个原始 alert。这 3 个额外 TP，`RANGE-030`、`ISSUE41-005`、`ISSUE41-011`，本来就在 CodeQL 原始 SARIF 候选中；Z-Scope 验证过滤掉大量噪声后，confirmed-only 视图改变了 evaluator 的候选池和一对一匹配结果，使这些 CodeQL alert 被最终计入 TP。因此报告中应表述为“验证后的最终报告视图 TP=14”，而不是“CodeQL 原始检测能力 TP=14”。

执行时间上，高召回 CodeQL analyze 约 98 秒；Z-Scope 验证阶段 `verify_wall_seconds` 为 2188 秒，2 个 alert worker；端到端约 2286 秒，约 38.1 分钟。这个时间明显慢于纯 CodeQL，但比完整 Z-Scope pipeline 快得多，适合作为 CodeQL 高噪声候选的后处理验证层。

### Z-Scope full pipeline

Z-Scope full pipeline 是当前整体效果最强的方案。default view 报告 144 条，命中 92 个 TP，effective FP 只有 8，召回率 `0.7603`，误报率 `0.0800`。with_needs_review 补充视图报告 220 条，命中 113 个 TP，召回率 `0.9339`，误报率 `0.1172`。这个视图的用途是给评测和人工复核提供更激进的候选集合，default view 则更接近直接交付的高置信报告。

完整扫描耗时较长：latest completed full scan run 的 batch wall seconds 为 10201.08 秒，约 2.83 小时；日志中的 scan elapsed 为 2:51:25。该成本来自 82 个入口的并行分析、LLM 漏洞挖掘和验证循环，验证迭代 3574 次，工具调用 4802 次。需要注意：这里引用的是当前文件中最新完成的 full pipeline 评测产物；它早于 REAL-018 去重边界修复，因此若要把修复后的 REAL-018 default-view 行为写进最终论文/正式报告，还需要重新跑一次 full pipeline 或至少跑覆盖 `src/lifecycle.c` 的增量评测。

## 社区 CodeQL 规则补充

Trail of Bits `codeql-queries` C++ full suite 已在本地跑通，standalone 只产生 4 条结果，命中 2 个 TP：`ISSUE42-028` 和 `RANGE-052`，召回率 `0.0165`，误报率 `0.5000`。把它与官方高召回组合合并后，结果数为 73，TP 为 13，effective FP 为 57，召回率 `0.1074`，误报率 `0.8143`。

这说明社区规则确实能补到官方规则漏掉的少量特定问题，例如 async-unsafe signal handler 和 legacy algorithm，但对本 benchmark 的复杂 C 内存/并发主干覆盖仍然有限。当前可见的社区 CodeQL C/C++ 规则更多集中在 crypto、API misuse、字符串/返回值处理、信号处理等模式化缺陷；对跨函数释放路径、线程间状态竞争、锁顺序、引用计数生命周期这类问题，没有看到能显著提升召回率的通用规则组。

## 关键结论

CodeQL 的最佳使用方式不是直接作为最终报告，而是作为低成本候选生成器。selected 规则速度最快但覆盖太窄；官方高召回组合扩大了候选面，但 FP 很高；Z-Scope 验证模式能把 raw CodeQL 的 69 条 alert 压到 34 条 confirmed，并将误报率从 `0.8333` 降到 `0.4815`。这条链路已经调通，适合后续继续优化 SARIF 到验证 prompt 的证据组织。

纯 LLM 的 GLM-5 扫描 precision 尚可，但缺少稳定覆盖能力。它可以补充 CodeQL 无法表达的语义判断，却不能替代 Z-Scope 的工具化上下文、跨函数检索和验证循环。

Z-Scope full pipeline 在这个 C 内存/并发 benchmark 上优势最大，尤其是 with_needs_review 视图接近完整覆盖。但它的时间成本是小时级，适合深度审计和 benchmark 主结果；CodeQL + Z-Scope 验证则是更轻量的折中方案，适合先用静态规则铺候选，再用 LLM/工具验证降 FP。

## 数据来源

- CodeQL selected evaluation：`test/range/codeql_runs/codeql_mem_concurrency_20260611_145300/codeql_evaluation_current_scorer.json`
- CodeQL selected timing：`test/range/codeql_runs/codeql_high_recall_20260611_170306/codeql_selected_rerun_summary.json`
- opencode GLM-5 evaluation：`test/range/benchmark_runs/opencode_pure_llm_glm5_20260611_162216/opencode_evaluation.json`
- CodeQL official high recall evaluation：`test/range/codeql_runs/codeql_high_recall_20260611_170306/codeql_high_recall_combo_evaluation.json`
- CodeQL official high recall timing：`test/range/codeql_runs/codeql_high_recall_20260611_170306/codeql_run_summary.json`
- Z-Scope alert verify run summary：`test/range/benchmark_runs/alert_verify_codeql_high_recall_glm5_curl_full_cfg_20260611_2052/run_summary.json`
- Z-Scope verified confirmed-only evaluation：`test/range/benchmark_runs/alert_verify_codeql_high_recall_glm5_curl_full_cfg_20260611_2052/zscope_verified_confirmed_only_evaluation.json`
- Z-Scope full pipeline evaluation：`test/range/benchmark_runs/perf_toolfunc_20260609_105807/evaluation.json`
- Z-Scope with_needs_review evaluation：`test/range/benchmark_runs/perf_toolfunc_20260609_105807/evaluation.with_needs_review.json`
- Z-Scope performance summary：`test/range/benchmark_runs/perf_toolfunc_20260609_105807/perf_summary.json`
- Trail of Bits community rule evaluation：`test/range/codeql_runs/trailofbits_queries_20260611_2040/codeql_high_recall_plus_trailofbits_evaluation.json`
