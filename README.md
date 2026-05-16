# Z-SCOPE

Z-SCOPE 是一个面向 C/C++ 项目的多智能体静态审计工具。它把 Clang/clangd 索引、SVF/Saber、Joern CPG、用户配置和 LLM 验证组合起来，目标是在保持低成本的同时提高真实缺陷的检出率。

## 核心原则

- 候选先于结论：所有规则、图分析和后端信号都只生成 evidence-only candidate，不直接进入最终漏洞报告。
- 后端各司其职：regex 提供最低依赖兜底；clang 提供本地 AST/CFG 风格检查；unified 同时使用 Clang 和 SVF/Saber；joern 使用 CPG 查询和规则。
- 用户配置是优势：项目自定义 allocator/free、锁、宏、函数指针目标、dispatcher、生命周期和函数意图都会被编译成 semantic overlay，进入候选层和 Validator 证据包。
- LLM 负责审核而不是凭空扫描：Validator 需要基于 source、sink、路径、守卫、反证和用户配置判断候选是否可达、可触发、可报告。

## Backend 能力

| backend | 候选来源 | 适用场景 |
| --- | --- | --- |
| `regex` | `RegexCandidateGenerator` | 无编译数据库或工具链不完整时的本地模式兜底 |
| `clang` | Clang AST/CFG 候选、KnowledgeDB call_edges | 需要函数体、调用边、类型和局部控制流证据 |
| `unified` | Clang AST/CFG + SVF/Saber value-flow + KnowledgeDB | 默认推荐的深度模式 |
| `joern` | Joern `run.scan`、paired-function、配置驱动 CPG data-flow、semantic sink/operator 规则 | 需要 CPG 查询、规则脚本或 Joern 数据流能力 |

## 候选层定位

候选层的职责是把不同事实源转换成统一证据，而不是“定罪”。候选会携带：

- `candidate_source`：如 `regex_local_rule`、`clang_ast_cfg`、`svf_value_flow`、`joern_cpg`。
- `source` / `sink`：可审计的源和危险操作。
- `positive_evidence` / `negative_evidence`：支持和待验证点。
- `evidence_pack`：后端、checker、路径、语义 overlay、原始 backend row 或 AST/CFG 事件。
- `dedup_key`：用于根因级去重。

当前所有候选都会被标记为 `validation_required=true`，必须经过 Validator 三态审核后才会进入默认报告或 `needs_review`。

## Clang AST/CFG Checkers

`ClangAstCfgCandidateGenerator` 在 `clang` 和 `unified` backend 下启用。它基于 clangd/CodeIndex 返回的函数体构造 statement/CFG 事件视图，并吸收用户配置中的 allocator/free、出参资源、lock/unlock 语义。

当前已覆盖：

- double free：同一路径重复释放同一对象。
- use-after-release：释放后继续解引用或传参。
- acquire-without-release：资源到 return/exit 仍未释放。
- return-with-lock-held：持锁返回。
- unchecked alloc dereference：分配/获取结果未空值检查即解引用。
- realloc lost original：直接用 `p = realloc(p, ...)` 覆盖原 owner。
- out-param use before status guard：出参资源在状态返回值成功检查前被使用或释放。

证据包包含声明表、条件守卫、scope/return 摘要、事件列表和 CFG 路径，供 Validator 判断路径是否真实闭合。

## SVF/Saber Value Flow

`unified` backend 会把 KnowledgeDB 中的 SVF/Saber `taint_signatures` 归一化为 `svf_value_flow` 候选。候选保留：

- Saber bug type，如 `NeverFree`、`DoubleFree`、UAF 类信号。
- `source_func`、`sink_func`、文件、行号、函数范围和签名。
- `svf_group` 和原始 backend row。

这类候选不是最终漏洞。Validator 仍需要回到 C 源码确认所有权转移、包装函数语义、失败路径和用户配置是否会否决该信号。

## Joern CPG

`joern` backend 当前使用这些 CPG 候选：

- Joern 内置 `run.scan` 结果。
- 用户配置 paired-function 检查，例如 acquire 有调用但 release 缺失。
- 用户配置函数意图到危险 sink 的 CPG data-flow 检查，例如外部 API 参数流入 `memcpy` 或项目配置的 copy sink。
- semantic sink 批量规则：copy/string、format、command/exec、file path、allocation size 等危险 API 调用。
- semantic operator 规则：除法/取模 divisor、shift amount、指针解引用等局部 CPG operator 证据。

Joern 候选也会统一转为 `joern_cpg` evidence-only candidate，再进入去重、Deep Worker 和 Validator。

## 用户配置

用户可以通过 Web UI 或 `user_config.xlsx` 维护项目语义：

- external functions：资源申请/释放、copy sink、锁、宏等。
- paired functions：多对多 acquire/release 或 lock/unlock。
- pointer targets：函数指针、ops 表、回调目标。
- dispatcher：消息分发和 handler。
- module lifecycle：模块初始化/清理入口。
- function intents：外部 API、线程/通信边界、并发约束。
- finding suppressions / baselines：误报抑制和历史验证反馈。

这些配置会进入 semantic overlay，被 Clang、Graph、Joern 和 Validator 共享。

## Benchmark

Range benchmark 支持两套统计视图：

- 默认报告：只统计 Validator 后进入 `issues` 的结果。
- with-needs-review：把 `needs_review` 也纳入检出。

regex/graph 候选覆盖测试使用：

```bash
python scripts/evaluate_range_regression.py --project-root test/range --regex-candidates
```

外部 benchmark 支持 `regex`、`clang`、`unified`、`joern` backend，并输出带/不带 `needs_review` 的检出率和误报率。

## 常用验证

```bash
python -m compileall -q zscope tests scripts
python -m pytest
```

## 当前已知限制

- Clang AST/CFG checker 仍是基于 clangd 函数体的本地语句/CFG 模型，不是完整 libclang AST 遍历器。
- SVF/Saber 候选已经独立为 `svf_value_flow`，但更细粒度的 value-flow path reconstruction 还可以继续增强。
- Joern CPG 已接入配置驱动 data-flow、semantic sink 和 operator 规则，但规则库还可以继续扩展到更多 CWE 和项目协议。
- 文档已恢复核心可读口径，历史细节型文档仍可能需要按新架构继续压缩整理。
