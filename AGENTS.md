# Z-SCOPE 项目交接指南

本文件是仓库级协作说明，帮助后续模型先识别用户诉求，再进入正确的代码、文档和验证路径。具体实现以源码和测试为最终事实来源；端到端架构以 [`docs/architecture.md`](docs/architecture.md) 为准。

## 项目速览

Z-SCOPE 是面向 Java 与 C/C++ 项目的 AI 静态分析平台。典型数据流为：

`CLI / WebUI / MCP` → 配置加载与入口规划 → 代码索引和后端事实 → 候选生成 → Agent 分析与 Validator 验证 → 去重、报告和反馈持久化。

关键位置：

- `zscope/`：产品代码、运行时 Agent/Skill、Workflow 和内置语义。
- `tests/`：Python 自动化测试。
- `test/range/`：故意植入缺陷的 Range Benchmark fixture，不是普通示例项目。
- `scripts/`：回归评测、外部 benchmark、发布聚合和维护脚本。
- `docs/modules/`：按稳定子系统组织的开发导航。
- `README.md`：安装、配置、CLI、WebUI、MCP 和常用开发命令。

根目录的 `AGENTS.md` 是仓库交接说明；`zscope/agents/*/AGENT.md` 是 Z-SCOPE 产品运行时加载的 Agent prompt。二者用途不同，不要把运行时 prompt 当作仓库说明，也不要为更新开发文档而改写它们。

## 先路由用户诉求

### 使用者路线

适用于安装、配置目标项目、执行扫描、选择后端、启动 WebUI/MCP、解释报告和排查运行问题。

1. 先读 `README.md` 的安装、端到端使用指南和后端对比。
2. 确认实际执行目录和实际配置文件，不要默认使用本仓库的配置。
3. 只在用户明确要求开发或修复产品时进入源码修改；普通使用问题优先给出配置、命令和环境诊断。
4. 涉及输出时区分单入口报告、批量报告、SARIF、快照目录和 KnowledgeDB，不把生成物当作源码。

### 开发者路线

适用于功能开发、缺陷修复、架构调整，以及 Agent、Skill、Workflow、后端、候选、验证、报告或测试变更。

1. 先读 `docs/architecture.md`，再按 [`docs/modules/README.md`](docs/modules/README.md) 进入对应子系统。
2. 修改前搜索调用方、配置模型和现有测试；不要仅凭文件名推断所有权。
3. 保持用户已有修改，不重写无关文件，不提交密钥、私有 endpoint 或本地 benchmark 配置。
4. 优先运行与变更直接相关的测试，再按风险补充：

   ```bash
   python -m pytest -q <相关测试>
   python -m compileall -f -q zscope scripts test tests
   python -m mypy zscope
   ```

5. 仅对需要格式化的 Python 变更运行 Black，避免无关的大范围格式化。

### 规则开发路线

适用于新增、修改或禁用 Java/C/C++ 确定性规则，以及 YAML rule pack 或 Python provider 开发。

1. 先读 [`docs/rule-development.md`](docs/rule-development.md) 和 [`docs/modules/analysis-pipeline.md`](docs/modules/analysis-pipeline.md)，区分确定性规则、backend signal、Skill trigger 与 finding suppression；不要用一类机制替代另一类。
2. 修改内置检测逻辑时，同一变更必须同步 `zscope/rules/builtin_catalog.yaml`：保持 canonical ID，并在规则语义、CWE、Skill 或验证要求变化时递增 `revision`。
3. 每条规则至少增加一个正例和一个反例，并运行目录一致性、候选快照和相关引擎测试；不得让实现产生未登记 ID。
4. 验证 `rules.disabled_ids` 只停止指定确定性检测器，不得意外抑制 SVF/Saber、Joern 等 backend signal、LLM 独立发现或已持久化的 finding suppression。
5. 规则治理变更不要改写 `zscope/agents/*/AGENT.md`。`SKILL.md` 只在 Skill 语言归属或证据契约本身变化时同步。

### Range Benchmark 路线

只要诉求涉及 `test/range`、recall、precision、F1、ground truth、发布门禁、正式扫描或回归比较，就必须同时遵循本路线。

1. 先读 [`docs/range-benchmark.md`](docs/range-benchmark.md) 和 [`docs/modules/benchmarking.md`](docs/modules/benchmarking.md)。
2. 正式 unified benchmark 需要 Linux 用户态和完整的 gcc、cmake、clangd、gllvm、LLVM、SVF/Saber 工具链：
   - 原生 Linux 运行 `zscope-benchmark`；Windows 上的 C/C++ 命令由该前端自动重启到 WSL。
   - 不得用原生 Windows Python 或 Windows 构建工具形成正式结果。
3. 扫描阶段不得把 `GROUND_TRUTH.md` 或 `benchmark/ground_truth.json` 放入 Z-SCOPE/LLM 分析上下文；ground truth 只能用于入口覆盖预检和扫描完成后的独立评分。
4. 不把 SVF/Saber 不可用后自动降级的结果标为正式 unified 结果。
5. `test/range` 含故意危险的 C 代码。除非任务明确要求演进 fixture 和 truth，否则不要“修复”其中植入的漏洞。

混合诉求采用叠加规则。例如修复 Range 漏检时，代码和测试修改遵循开发者路线；执行环境、答案隔离、评分和结论遵循 Range Benchmark 路线。

## 配置文件定位

- 命令显式传入 `zscope -c <path>/zscope.yaml` 或 `--config` 时，以该文件为准。
- CLI 未显式传入配置时，使用进程执行目录中的 `./zscope.yaml`；找不到时应报错，而不是回退到本仓库配置。
- 仓库根目录的 `zscope.c_cpp.yaml` 与 `zscope.java.yaml` 只是按语言划分的参考配置，不是其他目标项目的全局配置入口；复制到目标项目后通常命名为 `zscope.yaml`。
- 操作配置前必须确认：当前工作目录、命令中的 `-c/--config`、配置内的 `project.root`。
- `project.root` 的相对路径按进程工作目录解析；`source_root`、`compile_commands_path`、`entry_functions_list` 等项目相对路径再依据 `project.root` 解析。跨目录运行时优先使用明确路径，避免把缓存和报告写到错误项目。

## 模块导航

- [执行与编排](docs/modules/execution-orchestration.md)
- [分析流水线](docs/modules/analysis-pipeline.md)
- [代码检索与后端](docs/modules/retrieval-backends.md)
- [Agent 运行时](docs/modules/agent-runtime.md)
- [配置、语义与状态](docs/modules/configuration-state.md)
- [接口与报告](docs/modules/interfaces-reporting.md)
- [Benchmark](docs/modules/benchmarking.md)

当子系统职责、公共行为、关键不变量或所有权发生变化时，同一变更中更新对应模块文档。纯内部重构不应复制大量实现细节到文档。

## 中文与编码

- 仓库 Markdown 使用 UTF-8 无 BOM、LF 换行并保留文件末尾换行。
- Windows PowerShell 读取中文时显式使用 `Get-Content -Encoding utf8`；不要用默认编码读取后再覆盖原文件。
- 不使用默认编码的 `Set-Content`、`Out-File` 或 shell 重定向改写中文文档。优先使用能保持 UTF-8 的补丁或编辑工具。
- 终端显示乱码不代表文件已损坏。先以严格 UTF-8 解码或检查原始字节，再决定是否修复；禁止凭显示结果盲目转码。
- 修改交接文档后运行 `python -m pytest -q tests/test_agent_docs.py`。

## 文档维护边界

- 模块文档记录稳定职责、入口、不变量和测试，不记录容易过期的文件数量、漏洞数量或历史 benchmark 成绩。
- `docs/architecture.md` 负责端到端架构，`README.md` 负责用户使用，`docs/range-benchmark.md` 负责 Range 协议；模块文档不要重复维护这些全文。
- 新增 `zscope/` 顶层包时，必须在 `docs/modules/README.md` 和某一份模块文档的 `covers` 元数据中登记，且只能登记一次。
