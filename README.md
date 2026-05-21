# Z-SCOPE v0.7

Z-SCOPE 是一个面向 C/C++ 项目的 evidence-first 多智能体静态审计工具。它把 Clang/clangd 索引、SVF/Saber、Joern CPG、用户配置、图/协议候选和 LLM 验证组合起来，目标是在可控成本下提高真实内存安全、协议和并发缺陷的检出率。

## v0.7 重点

- 候选证据层继续收敛：regex、Clang AST/CFG、SVF/Saber、Joern CPG 和 graph/protocol 都只生成 `validation_required=true` 的候选，不直接当作最终漏洞。
- Clang/CFG 结构化候选覆盖更多 range FN：unchecked `strchr`、registry unlink/free-after-unlock、raw-fd/encoded-fd mismatch、协议版本忽略、magic guard 缺失、固定 byte limit/spec count 不一致、recv retry 无 timeout/budget、global dynamic array resize race、refcount protocol 缺失等。
- 去重和报告视图更稳：结构化候选优先于冗长自由文本；`needs_review` 会尽量附着到同根因问题，独立问题才进入 with-needs-review 视图；Validator 的 `rejected` 不再作为宽泛 future baseline。
- 工程闭环升级：`ToolPolicy` 已在 agent/tool runtime 和 MCP provider 中强制执行 allow/ask/deny、strict schema、pre/post hooks、敏感路径阻断和 credential-safe JSONL 审计。
- MCP 从本地 stdio 扩展到实验性 Streamable HTTP：支持 tool/resource/prompt policy gate、namespaced aliases、分页和输出上限；HTTP 传输仅用于可信网络早期集成。
- Deep Worker 支持受控并行、per-ticket timeout/trace、spawn allowlist、model/effort 选择和失败隔离；`RiskBudgetPlanner` 根据入口风险自适应分配递归、premodel、graph 和 subagent 预算。
- Benchmark 产品化：`zscope.benchmark.v3` 支持 candidate/pure LLM/full pipeline 多条件评测、default/with-needs-review 双视图、matched_pairs、cost、trajectory、grader 和 multi-trial stability。
- SARIF 集成起步：CLI 支持 `--export-sarif`，`alert-verify --sarif` 可把外部 SARIF alert 转成 Z-SCOPE 验证任务。

## 核心原则

- 候选先于结论：所有规则、图分析和后端信号都只生成 evidence-only candidate。
- 后端各司其职：`regex` 做低依赖兜底；`clang` 做本地 AST/CFG 风格检查；`unified` 同时使用 Clang 与 SVF/Saber；`joern` 使用 CPG 查询和规则。
- 用户配置是优势：项目自定义 allocator/free、锁、宏、函数指针目标、dispatcher、生命周期、函数意图和 suppression 会被编译为 semantic overlay。
- LLM 负责审核而不是凭空扫描：Validator 基于 source、sink、路径、守卫、反证和用户配置判断候选是否可达、可触发、可报告。

## Backend 能力

| backend | 候选来源 | 适用场景 |
| --- | --- | --- |
| `regex` | `RegexCandidateGenerator` | 无编译数据库或工具链不完整时的本地模式兜底 |
| `clang` | Clang AST/CFG、clang tooling evidence、KnowledgeDB call edges | 需要函数体、调用边、类型、局部控制流和结构化证据 |
| `unified` | Clang AST/CFG + SVF/Saber value-flow + KnowledgeDB | 默认推荐的深度模式 |
| `joern` | Joern `run.scan`、paired-function、配置驱动 CPG data-flow、semantic sink/operator 规则 | 需要 CPG 查询、规则脚本或 Joern 数据流能力 |

## 候选层定位

候选层的职责是把不同事实源转换成统一证据，而不是“定罪”。候选会携带：

- `candidate_source`：如 `regex_local_rule`、`clang_ast_cfg`、`svf_value_flow`、`joern_cpg`、`graph`。
- `source` / `sink` / `entry_function` / `sink_function` / `call_path`：可审计的数据来源、危险操作和路径归因。
- `positive_evidence` / `negative_evidence`：支持证据和需要 Validator 复核的反证点。
- `evidence_pack`：后端、checker、路径、AST/CFG 事件、semantic overlay 和原始 backend row。
- `dedup_key`：用于根因级去重，最终报告前还会经过 `issue_dedup` 归一化。

## 用户配置

用户可以通过 Web UI 或 `user_config.xlsx` 维护项目语义：

- external functions：资源申请/释放、copy sink、锁、宏等。
- paired functions：多对多 acquire/release 或 lock/unlock。
- pointer targets：函数指针、ops 表、回调目标。
- dispatcher：消息分发和 handler。
- module lifecycle：模块初始化/清理入口。
- function intents：外部 API、线程/通信边界、并发约束。
- finding suppressions / baselines：误报抑制和历史验证反馈。

这些配置会进入 semantic overlay，被 Clang、Graph、Joern、Deep Worker 和 Validator 共享。

## 常用命令

```bash
# 默认扫描
zscope --config zscope.yaml

# 自动发现 public API、通信、线程等入口后扫描
zscope --config zscope.yaml --discover-entries

# 推断/刷新 user_config.xlsx
zscope --config zscope.yaml --infer-user-config

# 导出 SARIF
zscope --config zscope.yaml --export-sarif zscope.sarif

# 验证外部 SARIF alert
zscope --config zscope.yaml --mode alert-verify --sarif alerts.sarif
```

## Benchmark

Range benchmark 支持两套统计视图：

- 默认报告：只统计 Validator 后进入 `issues` 的结果。
- with-needs-review：把独立 `needs_review` 和附着的复核观察也纳入评估。

外部 benchmark harness 位于 `scripts/external_benchmark.py`，支持 Juliet、SV-COMP、Magma，并输出 `zscope.benchmark.v3`：

```bash
python scripts/external_benchmark.py run-matrix \
  --suite-root benchmarks/external/workspace/juliet_memory_sample \
  --conditions pure_llm_entry_source pure_llm_repo_context full_zscope_pipeline \
  --trials 3 \
  --run-kind sample
```

每个 run 会写入 `summary.json`、`evaluation.json`、`evaluation_views.json`，包含环境元数据、default/with-needs-review 指标、`matched_pairs`、cost、trajectory 和稳定性摘要。

## MCP

本地 stdio MCP：

```bash
zscope --config zscope.yaml --mcp-stdio
```

实验性 Streamable HTTP MCP：

```bash
zscope --config zscope.yaml --mcp-http --mcp-host 127.0.0.1 --mcp-port 8765
```

Endpoint:

```text
http://127.0.0.1:8765/mcp
```

HTTP MCP 当前没有内置认证，只应绑定到可信网络。响应会带有 `X-ZScope-Experimental-MCP: streamable-http`。远程生产化仍需要 HTTPS/OAuth audience/resource/scope validation。

## 常用验证

```bash
python -m compileall -q zscope tests scripts
python -m pytest -q
```

针对本轮 v0.7 关键面可先跑：

```bash
python -m pytest tests/test_tool_policy.py tests/test_mcp_policy.py tests/test_mcp_http_server.py
python -m pytest tests/test_benchmark_protocol.py tests/test_report_views.py tests/test_issue_dedup.py
python -m pytest tests/test_clang_ast_cfg_candidates.py tests/test_regex_candidates.py tests/test_graph_candidates.py
```

## 当前已知限制

- Clang AST/CFG checker 仍主要基于 clangd/CodeIndex 函数体重建局部事实，不是完整 libclang visitor。
- SVF/Saber 已有 `svf_value_flow` 候选，但 source-level path reconstruction 仍可继续增强。
- Joern CPG 已接入配置驱动 data-flow、semantic sink 和 operator 规则，跨函数查询与规则库还可以扩展。
- HTTP MCP 是实验性集成入口，不应作为无认证公网服务暴露。
- benchmark v3 已能做多条件和多 trial 对比，但 patch-level benchmark 仍是后续方向。
