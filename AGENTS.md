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

## 通用协作约定

- 按当前任务和项目实际用途设计，不预设企业级或现网要求，不新增无关的防御层、审批或流程门禁。已授权范围内的常规实现与相关验证自主推进；任务描述聚焦目标、范围和验收，汇报先给结论。
- 保持用户已有修改，不重写无关文件，不提交密钥、私有 endpoint 或本地 benchmark 配置。
- 修改前搜索调用方、配置模型和现有测试；不要仅凭文件名推断所有权。
- 制定计划（包括计划模式）与执行时，按实际改动影响选择针对性测试；不默认对未受影响的既有功能全量回归，也不重复已通过且未受新改动影响的检查。只有明确跨模块影响、真实故障证据或用户明确要求时，才扩大测试范围；命中专题的必要实际验证仍须完成。
- 计划可随实现证据调整；不以代码哈希冻结、整仓快照、dry-run 或历史验收清单作为开发前提。只有当前任务确实需要时才选用这些手段；产品内部的哈希/快照校验不等于锁定工作区。交付按实际平台、产物和质量目标选择验证，完整正式发布要求不扩展为日常修改或单包交付的默认门槛。
- 测试与质量命令一律在 Linux 环境执行；Windows 上使用 WSL Linux 虚拟环境，不用原生 Windows 解释器形成测试结论。
- Markdown 使用 UTF-8 无 BOM、LF 和文件末尾换行。Windows 读取中文显式指定 UTF-8；终端乱码先核对原始字节，不凭显示结果转码。

## 先路由用户诉求

开始相关工作前，按下表**只读取命中的规则文件及章节**；它们是本文件按任务引用的仓库规则，适用于对应工作，不受归档目录限制。混合任务叠加相关路线；任务范围扩大时再补读，不一次加载全部文件。源码路径和命令默认以仓库根为基准，Markdown 链接按所在文件解析。

| 任务触发条件 | 按需读取 |
|---|---|
| 安装、配置目标项目、运行扫描、后端选择、WebUI/MCP、报告解释或排障 | [使用者路线](docs/agent-rules/usage/AGENTS.md) |
| 功能、修复、架构，以及 Agent/Skill/Workflow、后端、候选、验证、报告或测试变更 | [开发者路线](docs/agent-rules/development/AGENTS.md)，再按模块导航定位 |
| 配置路径、v3 字段、工程迁移、Web 项目/计划、执行窗口、项目原语准备 | [配置规则](docs/agent-rules/configuration/AGENTS.md)的对应章节 |
| 候选、证明、缓存、报告聚合、人工反馈、SVF/Saber 信号归属 | [构建身份](docs/agent-rules/build-identity/AGENTS.md) |
| native 资源事实、包装器、留存槽位、对象路径、验收/反馈、跨 TU、引用计数、句柄、锁、RAII、协议增量 | [Native 与对象协议](docs/agent-rules/protocols/AGENTS.md)的命中章节 |
| pthread、异步队列、等待/唤醒/时钟、cleanup、helper、drain | [pthread 规则](docs/agent-rules/pthread/AGENTS.md) |
| 新增、修改或禁用确定性规则、YAML rule pack、Python provider | [规则开发路线](docs/agent-rules/rule-development/AGENTS.md) |
| test/range、recall、precision、F1、ground truth、发布门禁、正式扫描或回归比较 | [Range Benchmark 路线](docs/agent-rules/benchmark/AGENTS.md) |
| Linux portable 构建、依赖锁、发行、ABI/SBOM、smoke 或发布交接文档 | [Linux Portable 发布路线](docs/agent-rules/portable-release/AGENTS.md) |
| Markdown/交接文档、模块职责、Agent 与专业扫描规划及其实施 | [文档维护与规划边界](docs/agent-rules/documentation/AGENTS.md) |

专题文件靠上表显式读取，不会因为存在链接就自动加载。不要依赖某个子目录的 AGENTS.md 为全项目提供规则；现有 `tests/fixtures/wiki_project/AGENTS.md` 仅是该 fixture 的指令文档。

## 配置定位摘要

操作配置前确认当前工作目录、`-c/--config`、实际 YAML 绝对路径及父目录。普通 CLI 未指定配置时使用 `./zscope.yaml`（Web 无配置启动例外）；两语言参考模板不是其他目标项目的全局配置入口。当前仅接受 v3，以 YAML 所在目录为唯一工程根，不再接受公共 `project.root` 或 `source_root` 字段；完整规则见[配置规则](docs/agent-rules/configuration/AGENTS.md)。

## 模块导航

- [执行与编排](docs/modules/execution-orchestration.md)
- [分析流水线](docs/modules/analysis-pipeline.md)
- [代码检索与后端](docs/modules/retrieval-backends.md)
- [Agent 运行时](docs/modules/agent-runtime.md)
- [配置、语义与状态](docs/modules/configuration-state.md)
- [Validator Review Memory](docs/modules/review-memory.md)
- [LLM Wiki](docs/modules/wiki.md)
- [接口与报告](docs/modules/interfaces-reporting.md)
- [Benchmark](docs/modules/benchmarking.md)

当子系统职责、公共行为、关键不变量或所有权发生变化时，同一变更中更新对应模块文档。纯内部重构不应复制大量实现细节到文档。
