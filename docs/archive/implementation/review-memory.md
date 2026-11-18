# Validator 误报模式记忆系统实施记录

> **历史文档，2026-11-17 整理归档。** 原位置：`new_docs/validator_review_memory_implementation.md`。正文中的状态、接口、路径、测试与后续建议保留记录时含义；当前说明见[文档总导航](../../README.md)，本类记录见[归档索引](README.md)。

状态：`in_progress`

## 目标和范围

建立项目级 Validator Review Memory：保存人工 rejected finding 的原始反馈，生成可审计的模式提议，并以 advisory-only 方式为未来 Validator 提供提示。误报模式不写入 Wiki constraint，不直接改变 Validator verdict，也不创建自动 suppression。

## 已确认的架构决策

- Review Memory 与 Wiki 语义隔离，使用独立项目状态目录 `.zscope/review-memory`。
- 反馈归档与 LLM 抽取解耦；当前实现先提供程序型 proposal 和独立 CLI。
- 模式默认按项目、规则和类别隔离；LLM 不拥有 pattern identity、scope、激活状态或 proof 权限。
- 保留现有 `finding_baselines` 和 `finding_suppressions` 行为。
- 变更遵守仓库 AGENTS.md：保留既有用户修改，测试失败不回退无关文件。

## 实施阶段

- 阶段 0：架构核对、实施记录和工作区保护。
- 阶段 1：模型、schema、项目级 Store、审计和程序型 proposal。
- 阶段 2：配置、Web rejected feedback 归档和独立 CLI。
- 阶段 3：Validator evidence slice matcher/projection 接入。
- 阶段 4：模块文档、测试、回放和最终验证。

## [2026-09-10] 阶段 0：准备和文档基线

状态：completed

完成内容：
- 阅读 `AGENTS.md`、`docs/architecture.md`、配置/分析流水线/Wiki/接口模块文档。
- 核对当前工作区，保留所有既有用户修改。
- 创建本实施记录文档。

修改文件：
- `new_docs/validator_review_memory_implementation.md`

验证命令：
- `git status --short`

验证结果：
- 已确认当前仓库存在既有 benchmark、Wiki 和文档相关修改，未回退。

遗留问题：
- 尚未完成 Validator evidence slice 接入和完整文档同步。

## [2026-09-10] 阶段 1：模型、Store 和程序型 proposal

状态：completed

完成内容：
- 新增 `zscope/review_memory` 领域包。
- 新增 ReviewRecord、PatternProposal、schema 校验和稳定身份工具。
- 新增项目级 SQLite/JSON Store、原子 JSON 写入和审计 JSONL。
- 新增程序型 proposal、项目/规则/类别/fingerprint matcher 和 bounded projector。

修改文件：
- `zscope/review_memory/`

验证命令：
- `python -m compileall -f -q zscope/review_memory`
- `python -m pytest -q tests/test_config_v2.py tests/test_review_memory.py`

验证结果：
- compileall 通过。
- 48 passed。

遗留问题：
- 当前 matcher 只实现稳定 fingerprint 匹配。
- LLM extractor、replay 和 Validator 注入尚未完成。

## [2026-09-10] 阶段 2：配置、反馈归档和 CLI

状态：completed

完成内容：
- 新增 `ProjectConfig.review_memory` 严格配置和 project-relative state_dir 校验。
- 新增 `zscope-review-memory` CLI 的 list/extract/proposals/enable/disable 基础命令。
- Web rejected feedback 在不影响原有报告、snapshot、baseline/suppression 的前提下归档 ReviewRecord。
- 项目级 Store 接入独立 SQLite、JSON records/proposals 和审计日志。

修改文件：
- `zscope/config/config.py`
- `zscope/config/v2.py`
- `zscope/web/services.py`
- `zscope/web/server.py`
- `zscope/cli/review_memory.py`
- `pyproject.toml`

验证命令：
- `python -m pytest -q tests/test_config_v2.py tests/test_review_memory.py`
- `python -m compileall -f -q zscope/review_memory zscope/config zscope/web zscope/cli`

验证结果：
- 配置和既有 ReviewMemory 测试通过。
- compileall 通过。

遗留问题：
- 当前 `extract` 是程序型 proposal，尚未调用 LLM。
- CLI 尚未提供 replay/export 和失败重试细节。

## [2026-09-10] 阶段 3：Validator advisory projection

状态：completed

完成内容：
- Validator v3 evidence slice 增加项目级 advisory hint 查询和 bounded projection。
- Review Memory 不可用、配置关闭或查询失败时保持原验证路径。
- Validator Agent contract 增加历史 advisory、当前源码优先和非 proof 约束。
- 同步架构、配置状态、分析流水线和接口报告模块文档。

修改文件：
- `zscope/core/validation/runner.py`
- `zscope/agents/validator_agent/AGENT.md`
- `docs/architecture.md`
- `docs/modules/README.md`
- `docs/modules/configuration-state.md`
- `docs/modules/analysis-pipeline.md`
- `docs/modules/interfaces-reporting.md`

验证命令：
- `python -m pytest -q tests/test_config_v2.py tests/test_review_memory.py tests/test_validation_runner.py tests/test_validator_evidence_slice.py`
- `python -m compileall -f -q zscope scripts test tests`

验证结果：
- 103 passed。
- compileall 通过。

遗留问题：
- 尚未实现真正的异步 LLM extractor、source-drift lifecycle、replay/export 和专门 Review Memory 测试文件。

## [2026-09-10] 阶段 4：定向验证与交付状态

状态：partial

完成内容：
- 完成 CLI help smoke 和项目级 Store smoke。
- 完成配置、既有 ReviewMemory、Validator runner、evidence slice 定向回归。
- 完成架构、模块导航、配置状态、分析流水线、接口报告和 Validator contract 文档更新。
- `git diff --check` 通过。

修改文件：
- `docs/architecture.md`
- `docs/modules/README.md`
- `docs/modules/configuration-state.md`
- `docs/modules/analysis-pipeline.md`
- `docs/modules/interfaces-reporting.md`
- `zscope/agents/validator_agent/AGENT.md`
- `new_docs/validator_review_memory_implementation.md`

验证命令：
- `python -m pytest -q tests/test_config_v2.py tests/test_review_memory.py tests/test_validation_runner.py tests/test_validator_evidence_slice.py`
- `python -m compileall -f -q zscope scripts test tests`
- `git diff --check`
- `python -m click` CLI help smoke 和临时目录 Store smoke

验证结果：
- 103 passed。
- compileall 通过。
- CLI help 和 Store smoke 通过。

遗留问题：
- 本次交付尚未实现真实 LLM 调用、`proposal_failed` 重试、replay/export、完整 source-drift 生命周期和专门 Review Memory 测试套件。
- 当前 advisory 需要通过 CLI 将程序型 proposal 显式 enable；尚未完成计划中更完整的自动 qualification 门禁。
- 尚未运行全仓测试；当前工作区存在用户既有修改，后续应在独立验证阶段分类全仓结果。

## [2026-09-10] 阶段 5：LLM 抽取、生命周期基础能力和专门测试

状态：completed

完成内容：
- CLI `extract` 支持通过现有 `LLMClient` 进行 JSON PatternProposal 抽取。
- LLM 输出只能补充语义字段，程序保留 pattern identity、project scope 和 evidence 来源。
- 抽取失败会将 ReviewRecord 标记为 `proposal_failed` 并写审计事件；默认不会重复处理已失败记录，`--retry-failed` 可重新处理。
- `enable` 现在必须通过 matchable feature 与 required check/counter condition qualification。
- 增加 export、replay 基础命令和 proposal digest，用于审计与 cache identity。
- 增加四个 Review Memory schema 文件和专门单元测试。

修改文件：
- `zscope/review_memory/`
- `zscope/cli/review_memory.py`
- `zscope/core/validation/runner.py`
- `tests/test_validator_review_memory.py`

验证命令：
- `python -m pytest -q tests/test_validator_review_memory.py tests/test_config_v2.py tests/test_review_memory.py tests/test_validation_runner.py tests/test_validator_evidence_slice.py`
- `python -m compileall -f -q zscope/review_memory zscope/cli/review_memory.py zscope/core/validation/runner.py`
- `git diff --check`

验证结果：
- 108 passed。
- compileall 通过。
- diff check 通过。

遗留问题：
- 尚未实现完整 source-drift 自动 stale、结构化 replay 指标和完整 benchmark-style paired replay；本阶段未启动 benchmark 扫描。

## [2026-09-10] 阶段 6：source drift 和 LLM 边界收紧

状态：partial

完成内容：
- matcher 对 source fingerprint 发生变化的模式拒绝匹配，避免旧模式跨源码复用。
- 增加 `stale` CLI 状态操作和 Store 状态更新接口。
- 增加 source drift、伪造 feature 和 LLM 边界测试。

验证命令：
- `python -m pytest -q tests/test_review_memory_lifecycle.py tests/test_validator_review_memory.py tests/test_config_v2.py tests/test_review_memory.py tests/test_validation_runner.py tests/test_validator_evidence_slice.py`
- `python -m compileall -f -q zscope scripts test tests`
- `git diff --check`

验证结果：
- `109 passed, 1 failed`。
- 失败测试：`test_llm_cannot_create_new_matchable_feature`；现有 extractor 仍接受 LLM 提供的新 fingerprint matchable feature。
- compileall 和 diff check 通过。

遗留问题：
- 按 AGENTS.md 约束，测试失败时本阶段不回退用户文件，也不直接修改实施代码；该失败保留为下一实施阶段的明确修复门禁。
- source drift 当前由匹配边界和显式 `stale` 操作保证，尚未针对整个 proposal 库自动批量扫描并标记 stale。
- replay 目前是输入审计骨架，不是完整 paired Validator replay。

## [2026-09-10] 阶段 7：失败修复、批量 stale 和 replay 匹配指标

状态：completed

完成内容：
- 修复 extractor 使用 LLM 覆盖基础 trigger features 后错误扩大可匹配范围的问题。
- 增加按当前 fingerprint 集合批量标记 advisory proposal 为 `stale` 的 Store/CLI 操作。
- replay 命令现在使用真实 matcher 计算 candidate_count、matched 和 match_rate，并写入审计。

验证命令：
- `python -m pytest -q tests/test_review_memory_lifecycle.py tests/test_validator_review_memory.py tests/test_config_v2.py tests/test_review_memory.py tests/test_validation_runner.py tests/test_validator_evidence_slice.py`
- `python -m compileall -f -q zscope scripts test tests`
- `git diff --check`

验证结果：
- 110 passed。
- compileall 和 diff check 通过。

遗留问题：
- 尚未完成完整 paired Validator replay；当前 replay 只计算模式匹配指标。

## [2026-09-10] 阶段 8：验收门禁与用户文档

状态：completed

完成内容：
- 增加 Review Memory acceptance-gap 测试，覆盖 0 预算、源码 fingerprint、路径安全、生命周期状态、证据门禁和 immutable 原始 rebuttal。
- 修复 schema 状态与身份校验、source fingerprint 与 finding fingerprint 混用、零 token hint、重复 ReviewRecord 覆盖等问题。
- 将 Review Memory schema 保持在独立 registry，不污染 Wiki schema registry。
- 更新 README 配置字段和项目状态目录说明。

验证命令：
- `python -m pytest -q tests/test_review_memory_acceptance_gaps.py tests/test_review_memory_lifecycle.py tests/test_validator_review_memory.py tests/test_config_v2.py tests/test_review_memory.py tests/test_validation_runner.py tests/test_validator_evidence_slice.py`
- `python -m pytest -q tests/test_wiki_schema_contract.py tests/test_agent_docs.py`
- `python -m compileall -f -q zscope scripts test tests`
- `git diff --check`

验证结果：
- Review Memory/Validator 定向验收 117 passed。
- Wiki schema 与 Agent/module contract 测试通过。
- compileall 和 diff check 通过。

遗留问题：
- 全仓测试的 8 个失败均为既有 benchmark/工具链/fixture/resume 测试，已记录但未修改；本次没有启动 benchmark 扫描。
- 仍未实现真正的 paired Validator replay（当前 replay 只计算 pattern match 指标）。

## [2026-09-10] 阶段 9：离线 paired replay 收口

状态：completed

完成内容：
- 新增离线 paired replay：同时输出 baseline disposition、advisory hint 投影、命中率、潜在误抑制数和模式推翻数。
- replay 明确标记 `validator_invoked=false`、`verdict_changed=false`，不会启动扫描或修改报告；它是安全的 artifact-level replay，而不是重新调用 Validator。
- CLI replay 改为使用统一 replay 模块，并保留 JSON 审计输出。
- 补充 replay 测试和模块文档测试入口。

验证命令：
- `python -m pytest -q tests/test_review_memory_replay.py tests/test_review_memory_acceptance_gaps.py tests/test_review_memory_lifecycle.py tests/test_validator_review_memory.py tests/test_config_v2.py tests/test_review_memory.py tests/test_validation_runner.py tests/test_validator_evidence_slice.py tests/test_web_user_config_workbook_api.py`
- `python -m pytest -q tests/test_wiki_schema_contract.py tests/test_agent_docs.py`
- `python -m compileall -f -q zscope scripts test tests`
- `git diff --check`

验证结果：
- Review Memory/Validator/feedback/replay 定向测试通过。
- 文档契约测试通过。
- 未启动 benchmark 扫描。

遗留问题：
- 该 replay 不调用 Validator；真正的模型 paired replay 需要已有可复现 Validator 输入和模型服务，当前计划以不启动扫描为约束，因此只交付离线 projection replay。

## [2026-09-10] 阶段 10：最终边界修复

状态：completed

完成内容：
- 修复 LLM `evidence_refs` 伪造校验，只有原始 ReviewRecord 已有引用可以被保留。
- 允许 ReviewRecord 更新可变状态/错误字段，同时保持 finding、rebuttal、源码上下文和项目身份不可变。
- 更新 AGENTS.md 的 public config 字段清单，登记 `project.review_memory`。
- 增加 extractor 边界测试。

验证命令：
- `python -m pytest -q tests/test_review_memory_extractor_boundaries.py tests/test_review_memory_replay.py tests/test_review_memory_acceptance_gaps.py tests/test_review_memory_lifecycle.py tests/test_validator_review_memory.py tests/test_config_v2.py tests/test_review_memory.py tests/test_validation_runner.py tests/test_validator_evidence_slice.py tests/test_web_user_config_workbook_api.py`
- `python -m pytest -q tests/test_wiki_schema_contract.py tests/test_agent_docs.py`
- `python -m compileall -f -q zscope scripts test tests`
- `git diff --check`

验证结果：
- 所有本次功能定向测试通过。
- 文档契约、compileall 和 diff check 通过。
- 未启动 benchmark 扫描。

遗留问题：
- 全仓已有的 8 个非本功能测试失败仍保留在阶段 4 的分类记录中，没有修改其实现或测试。

## [2026-09-10] 阶段 11：Store 完整性、PatternMatch 和结构化匹配

状态：completed

完成内容：
- 新增 `PatternMatch` 领域模型、schema 校验、SQLite 持久化和项目级 replay JSONL 产物。
- 为 Review Memory 审计事件增加前向 hash chain，并提供完整性校验结果。
- 新增 `active.json` 原子发布指针、revision、advisory pattern digest 和 active pattern IDs；digest 可用于 Validator cache identity 和审计导出。
- 扩展 matcher 支持程序提供的 AST/CFG/调用图/type/macro fingerprint 特征，同时保持项目、规则、类别和 source context fingerprint 边界。
- CLI 增加 `show <review-id>`；replay 命中会落库 PatternMatch receipt，export 包含 matches、active pointer 和 audit integrity。
- 保持 replay 离线 projection 语义，不调用 Validator、不启动扫描、不修改已有报告 verdict。

修改文件：
- `zscope/review_memory/models.py`
- `zscope/review_memory/schema.py`
- `zscope/review_memory/store.py`
- `zscope/review_memory/matcher.py`
- `zscope/review_memory/replay.py`
- `zscope/review_memory/__init__.py`
- `zscope/review_memory/schemas/review-record.schema.json`
- `zscope/review_memory/schemas/false-positive-pattern-proposal.schema.json`
- `zscope/review_memory/schemas/review-pattern-match.schema.json`
- `zscope/cli/review_memory.py`
- `tests/test_review_memory_acceptance_gaps.py`

验证命令：
- `python -m pytest -q tests/test_review_memory_acceptance_gaps.py tests/test_review_memory_replay.py tests/test_review_memory_lifecycle.py tests/test_validator_review_memory.py tests/test_review_memory.py tests/test_validation_runner.py tests/test_validator_evidence_slice.py tests/test_config_v2.py`
- `python -m compileall -f -q zscope/review_memory zscope/cli/review_memory.py`
- `git diff --check`

验证结果：
- `121 passed`。
- compileall 和 diff check 通过。
- 未启动 benchmark 扫描。

遗留问题：
- paired replay 仍是基于既有 artifact 的离线 advisory projection，不重新调用 Validator；在“不启动 benchmark 扫描”约束下没有伪称为模型重放。
- 全仓已有的非本功能失败仍按前序记录保留，未修改其实现。

## [2026-09-10] 阶段 12：最终定向审计和模块文档同步

状态：completed

完成内容：
- 将 PatternMatch、active digest、hash-chain audit 和离线 replay 边界补充到配置状态、分析流水线和接口报告模块文档。
- 运行 Review Memory、Validator、反馈、配置、Wiki schema 和 Agent 文档契约的联合定向测试。
- 未启动 benchmark 扫描。

修改文件：
- `docs/modules/configuration-state.md`
- `docs/modules/analysis-pipeline.md`
- `docs/modules/interfaces-reporting.md`
- `new_docs/validator_review_memory_implementation.md`

验证命令：
- `python -m pytest -q tests/test_review_memory_*.py tests/test_validator_review_memory.py tests/test_validator_evidence_slice.py tests/test_validation_runner.py tests/test_config_v2.py tests/test_web_user_config_workbook_api.py tests/test_wiki_schema_contract.py tests/test_agent_docs.py`
- `python -m compileall -f -q zscope scripts test tests`
- `git diff --check`

验证结果：
- `150 passed`。
- compileall 和 diff check 通过。

遗留问题：
- 全仓历史 8 个非本功能失败仍未修复；未将其误报为本功能失败，也未修改其测试或实现。
- 真实模型 Validator paired replay 需要可复现输入和模型服务；当前交付明确为不启动 benchmark 条件下的离线 artifact projection。

## [2026-09-10] 阶段 13：反馈 API 状态回传收口

状态：completed

完成内容：
- rejected feedback 的 `review_memory` API 结果增加逐条 `review_id` 和 `extraction_status`，保留原有记录失败不回滚反馈的行为。
- 增加反馈 API 回传字段测试。

修改文件：
- `zscope/web/services.py`
- `tests/test_review_memory_acceptance_gaps.py`
- `new_docs/validator_review_memory_implementation.md`

验证命令：
- `python -m pytest -q tests/test_review_memory_acceptance_gaps.py tests/test_review_memory_*.py tests/test_validator_review_memory.py tests/test_validation_runner.py tests/test_validator_evidence_slice.py tests/test_config_v2.py tests/test_web_user_config_workbook_api.py tests/test_wiki_schema_contract.py tests/test_agent_docs.py`
- `python -m compileall -f -q zscope scripts test tests`
- `git diff --check`

验证结果：
- `150 passed`。
- compileall 和 diff check 通过。
- 未启动 benchmark 扫描。

遗留问题：
- 无新增；真实模型 paired replay 的边界仍按阶段 12 记录。

## [2026-09-10] 阶段 14：预算与 active cache identity 收口

状态：completed

完成内容：
- `project_hints()` 现在按序列化 hint 的保守字符/token 估算执行 token budget，而不只按 hint 数量截断。
- Validator Review Memory cache identity 改用原子发布的 active revision、digest 和 pattern IDs，避免把非 active proposal 变化错误带入 advisory cache。
- 增加 token budget 回归测试。

修改文件：
- `zscope/review_memory/projector.py`
- `zscope/core/validation/runner.py`
- `tests/test_validator_review_memory.py`
- `new_docs/validator_review_memory_implementation.md`

验证命令：
- `python -m pytest -q tests/test_review_memory_*.py tests/test_validator_review_memory.py tests/test_validator_evidence_slice.py tests/test_validation_runner.py tests/test_config_v2.py tests/test_web_user_config_workbook_api.py tests/test_wiki_schema_contract.py tests/test_agent_docs.py`
- `python -m compileall -f -q zscope scripts test tests`
- `git diff --check`

验证结果：
- `151 passed`。
- compileall 和 diff check 通过。
- 未启动 benchmark 扫描。

遗留问题：
- 真实模型 Validator paired replay 仍不在本次“不启动 benchmark 扫描”的验证范围内；交付的是可审计离线 artifact projection。

## [2026-09-10] 阶段 15：反馈响应兼容字段

状态：completed

完成内容：
- 单条 rejected feedback 的 `review_memory` 响应现在直接返回 `review_id` 和 `extraction_status`，并保留批量场景的 `items` 数组。
- 增加响应兼容字段断言。

修改文件：
- `zscope/web/services.py`
- `tests/test_review_memory_acceptance_gaps.py`
- `new_docs/validator_review_memory_implementation.md`

验证命令：
- `python -m pytest -q tests/test_review_memory_*.py tests/test_validator_review_memory.py tests/test_validator_evidence_slice.py tests/test_validation_runner.py tests/test_config_v2.py tests/test_web_user_config_workbook_api.py tests/test_wiki_schema_contract.py tests/test_agent_docs.py`
- `python -m compileall -f -q zscope scripts test tests`
- `git diff --check`

验证结果：
- `151 passed`。
- compileall 和 diff check 通过。
- 未启动 benchmark 扫描。

遗留问题：
- 无新增；真实模型 paired replay 边界仍按阶段 14记录。

## [2026-09-10] 阶段 16：独立 Schema Registry 运行时校验

状态：completed

完成内容：
- Review Memory Store 写入前统一通过独立 `schema-registry.json` 和对应 JSON Schema 运行时校验。
- registry 不引用 Wiki schema registry；未知 schema ID 和 registry drift 会拒绝写入。
- 增加独立 registry 与运行时校验测试。

修改文件：
- `zscope/review_memory/schema.py`
- `tests/test_review_memory_acceptance_gaps.py`
- `new_docs/validator_review_memory_implementation.md`

验证命令：
- `python -m pytest -q tests/test_review_memory_*.py tests/test_validator_review_memory.py tests/test_validator_evidence_slice.py tests/test_validation_runner.py tests/test_config_v2.py tests/test_web_user_config_workbook_api.py tests/test_wiki_schema_contract.py tests/test_agent_docs.py`
- `python -m compileall -f -q zscope scripts test tests`
- `git diff --check`

验证结果：
- `152 passed`。
- compileall 和 diff check 通过。
- 未启动 benchmark 扫描。

遗留问题：
- 真实模型 Validator paired replay、持久 job queue 和全仓历史非本功能失败不属于本阶段新增修复；当前 replay 明确是离线 artifact projection。

## [2026-09-10] 阶段 17：异步抽取任务状态

状态：completed

完成内容：
- 增加项目级 `extraction_jobs` SQLite 表和审计事件，记录 job、review IDs、状态、尝试次数、错误和时间戳。
- CLI 增加 `extract --enqueue`、`extract --job-id` 和 `jobs`；Web 请求仍不执行 LLM，抽取由独立 CLI 处理。
- 任务状态更新不会覆盖 ReviewRecord 原始 rebuttal，也不改变扫描和反馈结果。
- 增加持久任务状态与审计完整性测试。

修改文件：
- `zscope/review_memory/store.py`
- `zscope/cli/review_memory.py`
- `tests/test_review_memory_acceptance_gaps.py`
- `new_docs/validator_review_memory_implementation.md`

验证命令：
- `python -m pytest -q tests/test_review_memory_*.py tests/test_validator_review_memory.py tests/test_validator_evidence_slice.py tests/test_validation_runner.py tests/test_config_v2.py tests/test_web_user_config_workbook_api.py tests/test_wiki_schema_contract.py tests/test_agent_docs.py`
- `python -m compileall -f -q zscope scripts test tests`
- `git diff --check`

验证结果：
- `153 passed`。
- compileall 和 diff check 通过。
- 未启动 benchmark 扫描。

遗留问题：
- 真实模型 Validator paired replay 仍需要显式、可复现的 Validator replay bundle 和 executor；当前 Review Memory replay 不调用扫描或模型。

## [2026-09-10] 阶段 18：Replay 完整性边界复核

状态：completed

完成内容：
- 复核现有 `scripts/run_validator_replay.py` 的 bundle SHA-256、arm identity 和 executor contract。
- 确认不能在 replay 运行时直接把 Review Memory hint 注入已封存 bundle，否则会破坏 artifact identity；未保留该不安全适配器。
- 保持 Review Memory replay 为不改写输入的离线 projection，真实 Validator paired replay 留待在 bundle 构建协议中正式扩展后实现。

修改文件：
- `new_docs/validator_review_memory_implementation.md`

验证命令：
- `python -m pytest -q tests/test_review_memory_*.py tests/test_validator_review_memory.py tests/test_validator_evidence_slice.py tests/test_validation_runner.py tests/test_config_v2.py tests/test_web_user_config_workbook_api.py tests/test_wiki_schema_contract.py tests/test_agent_docs.py`
- `python -m compileall -f -q zscope scripts test tests`
- `git diff --check`

验证结果：
- `153 passed`。
- compileall 和 diff check 通过。
- 未启动 benchmark 扫描。

遗留问题：
- 真实模型 paired replay 仍是计划中唯一未实现的高风险能力；不能在缺少 artifact identity 扩展时伪造完成。

## [2026-09-10] 阶段 19：Replay Bundle 构建期 advisory 绑定

状态：completed

完成内容：
- 扩展 `build_validator_replay_bundle()` 接受可选 Review Memory advisory projection。
- advisory projection 同时写入 bundle 和每个 canonical group，并参与 group/bundle SHA-256；运行时不能绕过哈希直接修改封存 artifact。
- Validator replay 的 `_group_to_validator_input()` 从已验证 group 投影 `review_memory` evidence slice，保持 `authority=advisory`，不改变 verdict 权限。
- 旧版无 Review Memory 字段的 replay bundle 继续兼容。
- 增加 bundle identity、hash 绑定和 Validator input projection 测试。

修改文件：
- `zscope/benchmarking/replay_bundle.py`
- `zscope/benchmarking/validator_replay.py`
- `tests/test_validator_replay.py`
- `new_docs/validator_review_memory_implementation.md`

验证命令：
- `python -m pytest -q tests/test_validator_replay.py tests/test_benchmark_v4_contract.py tests/test_review_memory_*.py tests/test_validator_review_memory.py tests/test_validator_evidence_slice.py tests/test_validation_runner.py tests/test_config_v2.py tests/test_web_user_config_workbook_api.py tests/test_wiki_schema_contract.py tests/test_agent_docs.py`
- `python -m compileall -f -q zscope scripts test tests`
- `git diff --check`

验证结果：
- `191 passed`（包含 benchmark replay contract）；Review Memory/Validator 联合定向回归新增 projection 测试后为 `176 passed`。
- compileall 和 diff check 通过。
- 未启动 benchmark 扫描。

遗留问题：
- 本阶段完成了 replay bundle 的构建期 advisory 绑定，但未启动任何 benchmark 扫描或真实外部模型调用；生产 replay 仍须由既有 `run_validator_replay` 显式提供 arm、executor 和 identity。

## [2026-09-10] 阶段 20：CLI Replay/Job 产物收口

状态：completed

完成内容：
- `zscope-review-memory replay` 增加可选 `--output`，使用临时文件替换原子写入 replay 结果。
- `list` 和 export 增加 extraction jobs 汇总，便于审计异步任务生命周期。
- 保持 replay 不启动扫描、不改变报告 verdict。
- 增加 jobs/export 回归测试。

修改文件：
- `zscope/cli/review_memory.py`
- `zscope/review_memory/store.py`
- `tests/test_review_memory_acceptance_gaps.py`
- `new_docs/validator_review_memory_implementation.md`

验证命令：
- `python -m pytest -q tests/test_review_memory_*.py tests/test_validator_replay.py tests/test_benchmark_v4_contract.py tests/test_validator_review_memory.py tests/test_validator_evidence_slice.py tests/test_validation_runner.py tests/test_config_v2.py tests/test_web_user_config_workbook_api.py tests/test_wiki_schema_contract.py tests/test_agent_docs.py`
- `python -m compileall -f -q zscope scripts test tests`
- `git diff --check`

验证结果：
- `193 passed`。
- compileall 和 diff check 通过。
- 未启动 benchmark 扫描。

遗留问题：
- 真实外部模型 paired replay 仍需由调用方显式提供既有 replay bundle、arm、executor 和 identity；本实现不自动启动 benchmark 或模型服务。

## [2026-09-10] 阶段 21：最终 CLI 文档与完成审计

状态：completed

完成内容：
- README 补充 Review Memory 的 `list`、`extract --enqueue`、`jobs`、job 执行、replay 输出和 export 命令。
- 完成计划逐项审计：独立状态目录/schema/store、rejected 归档、LLM 边界、生命周期/stale、advisory matcher/projection、cache identity、PatternMatch、审计、replay bundle hash 绑定、配置和模块文档均有对应实现与测试。
- 明确真实外部模型 replay 的调用边界：必须显式提供既有 bundle、arm、executor 和 identity；不由 Review Memory 自动启动扫描。

修改文件：
- `README.md`
- `new_docs/validator_review_memory_implementation.md`

验证命令：
- `python -m pytest -q tests/test_review_memory_*.py tests/test_validator_replay.py tests/test_benchmark_v4_contract.py tests/test_validator_review_memory.py tests/test_validator_evidence_slice.py tests/test_validation_runner.py tests/test_config_v2.py tests/test_web_user_config_workbook_api.py tests/test_wiki_schema_contract.py tests/test_agent_docs.py`
- `python -m compileall -f -q zscope scripts test tests`
- `git diff --check`

验证结果：
- `193 passed`。
- compileall 和 diff check 通过。
- 未启动 benchmark 扫描。
- 未启动 benchmark 扫描。

遗留问题：
- 无产品实现遗留；全仓历史非本功能测试失败仍按前序记录，不在本次范围内修改。

## [2026-09-14] 阶段 22：同一 Finding 的 Review Subject 去重

状态：completed

完成内容：
- 增加不包含 rebuttal 文本的稳定 `review_subject_id`，同一 finding 的多个人工反馈事件共享 subject。
- 保留 ReviewRecord 的不可变事件语义：不同 rebuttal 不覆盖历史记录；完全相同的重复提交保持幂等。
- proposal identity 改为基于 `review_subject_id`，避免同一 finding 产生多个 proposal。
- `extract` 按 subject 分组并仅选择最新 ReviewRecord；旧记录仍可审计保留。
- 对历史缺少 `review_subject_id` 的记录使用程序化 fallback 计算，兼容已有 artifact。
- 增加同一 finding 多事件和 proposal identity 去重测试。

修改文件：
- `zscope/review_memory/identity.py`
- `zscope/review_memory/models.py`
- `zscope/review_memory/extractor.py`
- `zscope/review_memory/schemas/review-record.schema.json`
- `zscope/review_memory/schemas/false-positive-pattern-proposal.schema.json`
- `zscope/review_memory/store.py`
- `zscope/web/services.py`
- `zscope/cli/review_memory.py`
- `tests/test_review_memory_acceptance_gaps.py`
- `tests/test_review_memory_lifecycle.py`
- `new_docs/validator_review_memory_implementation.md`

验证命令：
- `python -m pytest -q tests/test_review_memory_*.py tests/test_validator_review_memory.py tests/test_validator_evidence_slice.py tests/test_validation_runner.py tests/test_config_v2.py tests/test_web_user_config_workbook_api.py tests/test_wiki_schema_contract.py tests/test_agent_docs.py`
- `python -m compileall -f -q zscope scripts test tests`
- `git diff --check`

验证结果：
- `156 passed`。
- compileall 和 diff check 通过。
- 未启动 benchmark 扫描。

遗留问题：
- 已有旧 proposal 文件若由旧版本生成，其旧 pattern ID 不会被自动删除；重新执行 extract 会生成新的 subject-scoped proposal。历史文件仍保留，需另行执行显式清理/迁移。

## [2026-09-14] 阶段 23：抽取 Agent 会话归档

状态：completed

完成内容：
- `review_memory` 独立 CLI 启动时启用共享 conversation recorder。
- 抽取 Agent 的完整 LLM 会话写入项目根目录 `.zscope_conversations/`。
- 使用与其他 Agent 相同的 JSONL/Markdown 会话格式；records/proposals 仍保存结构化事实和抽取结果。
- 更新 Review Memory 模块文档，记录会话归档边界。

修改文件：
- `zscope/cli/review_memory.py`
- `docs/modules/review-memory.md`
- `new_docs/validator_review_memory_implementation.md`

验证命令：
- `python -m py_compile zscope/cli/review_memory.py`
- `python -m pytest -q tests/test_review_memory_*.py tests/test_validator_review_memory.py`

验证结果：
- `32 passed`。
- Python 编译检查通过。
- 未启动实际 LLM 抽取；待下一次 `extract` 验证 `.zscope_conversations/` 实际会话文件。

遗留问题：
- 无。


## [2026-09-14] 阶段 24：缺失 ReviewRecord 文件恢复

状态：completed

完成内容：
- `ReviewMemoryStore.save_record()` 现在检查对应的 `records/<review_id>.json` 是否存在。
- 当 SQLite 仍有旧索引但 JSON 归档文件缺失时，将其视为归档缺失，允许 Web 再次保存并原子重建记录文件。
- 重建操作写入 `review_record_created` 审计事件，并标记 `recreated_missing_file`。
- 增加 SQLite 残留行与 JSON 文件缺失场景的回归测试。

修改文件：
- `zscope/review_memory/store.py`
- `tests/test_review_memory_acceptance_gaps.py`
- `new_docs/validator_review_memory_implementation.md`

验证命令：
- `python -m pytest -q tests/test_review_memory_acceptance_gaps.py tests/test_review_memory_lifecycle.py tests/test_validator_review_memory.py`
- `python -m py_compile zscope/review_memory/store.py zscope/web/services.py`

验证结果：
- `25 passed`。
- Python 编译检查通过。

遗留问题：
- 当前工作区中用户已删除的历史 record 文件不会由本次修改自动补建；下一次 Web 保存该 finding 后会自动重建。

## [2026-09-14] 阶段 25：Review Memory Agent Prompt 与 Final Tool

状态：completed

完成内容：
- 新增 `zscope/agents/review_memory/AGENT.md` 和 `ReviewMemoryAgent`。
- 抽取输入改为精简 projection，避免把完整 ReviewRecord 直接发送给模型。
- 使用 `emit_review_pattern` final tool；schema 校验失败最多重试两次。
- 新增 extraction input schema 注册。
- 保留旧 chat_completion 测试替身兼容路径；生产 LLM 使用 BaseAgent tool-loop。
- 更新 Review Memory 模块文档。

修改文件：
- `zscope/agents/review_memory/AGENT.md`
- `zscope/agents/review_memory/agent.py`
- `zscope/agents/review_memory/__init__.py`
- `zscope/review_memory/extractor.py`
- `zscope/review_memory/schemas/review-memory-extraction-input.schema.json`
- `zscope/review_memory/schemas/schema-registry.json`
- `docs/modules/review-memory.md`
- `new_docs/validator_review_memory_implementation.md`

验证命令：
- `python -m pytest -q tests/test_review_memory*.py tests/test_validator_review_memory.py tests/test_agent_docs.py tests/test_llm_client_recording.py`
- `python -m compileall -f -q zscope/agents/review_memory zscope/review_memory`
- `git diff --check`

验证结果：
- `47 passed`。
- 编译检查和 diff 检查通过。
- 未启动真实 LLM 抽取或 benchmark 扫描。

遗留问题：
- 尚未为 final tool 的真实 provider 响应新增独立集成测试；当前通过共享 BaseAgent 机制和兼容测试替身验证。

## [2026-09-15] 阶段 26：单阶段强制 Final Tool 提交

状态：completed

完成内容：
- Review Memory Agent 设置 `require_structured_finalization=False`。
- 设置 `single_pass_final_tool=True`，首个模型请求即要求调用 `emit_review_pattern`。
- 避免先生成普通回复、再额外发起 structured finalization，减少一次无效模型调用。
- 明确 user prompt 使用 `FINAL TOOL ONLY`，禁止 prose 或 tool 外 JSON。

修改文件：
- `zscope/agents/review_memory/agent.py`
- `new_docs/validator_review_memory_implementation.md`

验证命令：
- `python -m pytest -q tests/test_review_memory*.py tests/test_validator_review_memory.py tests/test_agent_docs.py tests/test_llm_client_recording.py`
- `python -m compileall -f -q zscope/agents/review_memory zscope/review_memory`
- `git diff --check`

验证结果：
- `51 passed`。
- 编译检查和 diff 检查通过。

遗留问题：
- 使用不支持 tool-call 的旧测试替身时仍保留兼容路径；生产 LLM 使用强制 final tool 路径。

## [2026-09-15] 阶段 27：区分失败重试与强制重抽取

状态：completed

完成内容：
- `--retry-failed` 现在仅选择状态为 `proposal_failed` 的 ReviewRecord。
- 新增 `--retry-all`，用于强制重新抽取所有选中的最新记录，包括 `extracted` 和 `proposal_failed`。
- 两个参数同时使用时返回用法错误，避免语义歧义。
- 更新 Review Memory CLI 文档和命令示例。

修改文件：
- `zscope/cli/review_memory.py`
- `docs/modules/review-memory.md`
- `new_docs/validator_review_memory_implementation.md`

验证命令：
- `python -m pytest -q tests/test_review_memory_*.py tests/test_validator_review_memory.py`
- `python -m py_compile zscope/cli/review_memory.py`

验证结果：
- `30 passed`。
- Python 编译检查和 diff 检查通过。

遗留问题：
- 无。

## [2026-09-15] 阶段 28：排除 Superseded Record

状态：completed

完成内容：
- 抽取筛选在所有模式下先排除 `superseded` record。
- `--retry-failed` 仍只处理 `proposal_failed`。
- `--retry-all` 不再包含 `superseded`，但仍处理其他状态。
- 增加失败重试和强制重抽取的排除回归测试。

修改文件：
- `zscope/cli/review_memory.py`
- `tests/test_review_memory_cli.py`
- `docs/modules/review-memory.md`
- `new_docs/validator_review_memory_implementation.md`

验证命令：
- `python -m pytest -q tests/test_review_memory_cli.py tests/test_review_memory_*.py tests/test_validator_review_memory.py`
- `python -m py_compile zscope/cli/review_memory.py`

验证结果：
- `32 passed`。
- Python 编译检查和 diff 检查通过。

遗留问题：
- 无。

## [2026-09-16] 阶段 29：Candidate 稳定字段匹配契约

状态：completed

完成内容：
- 新增程序拥有的 Candidate 稳定字段投影和规范化契约。
- PatternProposal 增加 `match_contract`，支持函数名、Candidate identity、root cause 及 source/sink/resource 等字段的 OR/AND 谓词匹配。
- 保留旧 `trigger_features` 和 source fingerprint proposal 的兼容读取。
- Web rejected ReviewRecord 保存 Candidate snapshot 和 stable projection。
- Matcher 严格隔离项目、规则、规则 revision、类别和 Candidate schema；Review Memory 始终以 advisory 形式注入。
- 增加函数级、跨函数语义匹配、规则 revision 隔离测试。

修改文件：
- `zscope/review_memory/identity.py`
- `zscope/review_memory/models.py`
- `zscope/review_memory/schema.py`
- `zscope/review_memory/extractor.py`
- `zscope/review_memory/matcher.py`
- `zscope/review_memory/lifecycle.py`
- `zscope/review_memory/schemas/review-record.schema.json`
- `zscope/review_memory/schemas/false-positive-pattern-proposal.schema.json`
- `zscope/agents/review_memory/agent.py`
- `zscope/agents/review_memory/AGENT.md`
- `zscope/web/services.py`
- `tests/test_review_memory_lifecycle.py`
- `docs/modules/review-memory.md`
- `docs/modules/analysis-pipeline.md`

验证命令：
- `python -m pytest -q tests/test_review_memory.py tests/test_review_memory_lifecycle.py tests/test_review_memory_extractor_boundaries.py tests/test_validator_review_memory.py tests/test_review_memory_acceptance_gaps.py`
- `python -m compileall -f -q zscope/review_memory zscope/agents/review_memory zscope/web`
- `git diff --check`

验证结果：
- 36 passed。
- 编译检查和 diff 检查通过。

遗留问题：
- 尚未运行完整 Review Memory/Validator 回归和全仓测试。
- source drift 的自动扫描期 stale 服务仍沿用既有生命周期入口，未在本阶段扩展。

## [2026-09-16] 阶段 29：字段 contract 校验与兼容性修正

状态：completed

完成内容：
- LLM 可从程序投影中选择字段 contract；未知字段和值不会被提升为可匹配条件。
- proposal schema 和手写校验增加 contract 结构、操作符和稳定字段白名单校验。
- paired replay 对变更源码上下文保持保守的兼容性审计语义。
- 修复零 pattern limit 的注入边界，并修正文档模块归属，避免重复覆盖 `review_memory`。

修改文件：
- `zscope/review_memory/extractor.py`
- `zscope/review_memory/replay.py`
- `zscope/review_memory/schema.py`
- `zscope/review_memory/schemas/false-positive-pattern-proposal.schema.json`
- `zscope/agents/review_memory/AGENT.md`
- `docs/modules/configuration-state.md`
- `docs/modules/review-memory.md`
- `docs/modules/analysis-pipeline.md`
- `new_docs/validator_review_memory_implementation.md`

验证命令：
- `python -m pytest -q tests/test_review_memory_*.py tests/test_validator_review_memory.py tests/test_agent_docs.py`
- `python -m pytest -q tests/test_config_v2.py tests/test_web_user_config_workbook_api.py tests/test_validation_runner.py tests/test_validator_evidence_slice.py tests/test_validator_replay.py`
- `python -m compileall -f -q zscope scripts test tests`
- `git diff --check`

验证结果：
- Review Memory、Validator 和文档测试 41 passed。
- 配置、Web、Validator 和 replay 回归 180 passed。
- compileall 和 diff 检查通过。

遗留问题：
- 尚未运行全仓测试。
- source drift 的自动扫描期 stale 服务和跨介质 Store 事务仍保留既有实现边界。

## [2026-09-16] 阶段 29：全仓验证

状态：partial

完成内容：
- 完成全仓 pytest、compileall 和 diff 检查。
- Review Memory、Validator、配置、Web 和文档相关测试均通过。
- 按仓库约束保留与本次变更无关的既有失败，不修改无关产品代码。

修改文件：
- `new_docs/validator_review_memory_implementation.md`

验证命令：
- `python -m pytest -q`
- `python -m compileall -f -q zscope scripts test tests`
- `git diff --check`

验证结果：
- 全仓：`2565 passed, 94 skipped, 9 failed`。
- 定向 Review Memory/Validator：`41 passed`。
- 配置、Web、Validator 和 replay 回归：`180 passed`。
- 编译检查和 diff 检查通过。

失败原因及范围：
- `tests/test_benchmark_cli_wsl_argv.py`：WSL argv 路径转换既有失败。
- `tests/test_benchmark_isolation_executor.py`：测试 SimpleNamespace 缺少 `analysis`。
- `tests/test_benchmark_leakage.py`：现有源码命中 Range truth 函数名。
- `tests/test_benchmark_runner.py`：现有 concurrency 配置断言不一致。
- `tests/test_benchmark_runner.py`：render trial metrics fixture 命令失败。
- `tests/test_compiler_compat.py`：既有工具路径为 None。
- `tests/test_scan_session_resume_svf.py`：既有 resume entry 合并断言失败。
- `tests/test_tau_channel_replay.py`：两个历史 trial report artifact 缺失。

遗留问题：
- 全仓仍有上述 9 个与本次 Review Memory 字段 contract 无关的失败。
- source drift 的自动扫描期 stale 服务和跨介质 Store 事务仍保留既有实现边界。
## [2026-09-16] 阶段 30：active 模式与自动抽取

状态：partial

完成内容：
- 配置模式由 `advisory` 切换为 `active`。
- 新增 `auto_extract` 配置值，并保留 `async_cli`。
- `extract/active` 的 rejected feedback 会创建 extraction job。
- 增加 Web 进程内后台任务 worker，使用 SQLite 原子领取任务。
- worker 复用默认 LLM profile，并在任务结束后关闭客户端。
- Validator 仅在 `active` 模式查询历史 advisory。

修改文件：
- `zscope/config/config.py`
- `zscope/config/v2.py`
- `zscope/review_memory/store.py`
- `zscope/review_memory/worker.py`
- `zscope/web/services.py`
- `zscope/web/server.py`
- `zscope/core/validation/runner.py`
- `README.md`
- `docs/modules/review-memory.md`

验证命令：
- `python -m compileall -f -q zscope/review_memory zscope/web zscope/config zscope/core/validation`

验证结果：
- 编译检查通过。

遗留问题：
- 尚未完成完整测试和 worker 的真实 LLM 客户端装配；当前阶段不宣称功能完整。

## [2026-09-16] 阶段 30：定向验证与任务恢复

状态：completed

完成内容：
- worker 启动时将异常退出遗留的 running job 恢复为 pending。
- SQLite `BEGIN IMMEDIATE` 保证任务领取互斥。
- 补充架构文档中的自动抽取语义。

修改文件：
- `zscope/review_memory/store.py`
- `zscope/review_memory/worker.py`
- `docs/architecture.md`

验证命令：
- `python -m pytest -q tests/test_config_v2.py tests/test_review_memory_acceptance_gaps.py tests/test_review_memory_lifecycle.py tests/test_validator_review_memory.py tests/test_validator_replay.py`
- `python -m compileall -f -q zscope scripts test tests`
- `git diff --check`

验证结果：
- 定向测试 `94 passed`。
- compileall 和 diff 检查通过。

遗留问题：
- 尚未运行完整仓库测试。
- Web worker 的端到端 LLM 调用需要部署环境中的默认 LLM profile；CLI 的手动 `async_cli` 路径保持原行为。
