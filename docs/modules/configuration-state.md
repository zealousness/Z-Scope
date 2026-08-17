---
doc_contract: zscope-module-v1
covers:
  - zscope/config
  - zscope/semantics
  - zscope/snapshots
  - zscope/memory
  - zscope/common
  - zscope/compat
sources:
  - zscope/config/config.py
  - zscope/config/v2.py
  - zscope/config/runtime_defaults.yaml
  - zscope/config/function_entry.py
  - zscope/config/user_config_store.py
  - zscope/config/user_config_workbook.py
  - zscope/semantics/defaults.yaml
  - zscope/semantics/user_config_context.py
  - zscope/semantics/security_map.py
  - zscope/semantics/security_specs
  - zscope/snapshots/store.py
  - zscope/memory/review_memory.py
  - zscope/common/issue_identity.py
  - zscope/compat/config.py
  - zscope/compat/reports.py
  - zscope/compat/usage.py
tests:
  - tests/test_config_v2.py
  - tests/test_config_migration.py
  - tests/test_concurrency_config.py
  - tests/test_user_config_workbook.py
  - tests/test_parallel_custom_prompt.py
  - tests/test_semantics_defaults.py
  - tests/test_security_semantic_map.py
  - tests/test_security_specs.py
  - tests/test_p3_security_spec_qualification.py
  - tests/test_snapshot_store.py
  - tests/test_review_memory.py
  - tests/test_issue_dedup.py
  - tests/test_p1_compat.py
---

# 配置、语义与状态

## 职责与非职责

本子系统负责解析和校验用户配置、合并内置/项目语义、维护快照和人工反馈状态，并提供稳定 finding identity、取消和运行限制等公共设施。它连接用户领域知识、历史分析结果和当前扫描。

它不负责选择 CLI 运行模式、不实现后端索引，也不决定报告的展示格式。

## 主入口和数据流

- `ConfigLoader` 只读取严格的 `UserConfigV2`，再与打包的 `RuntimeSpec` 组合为 `EffectiveConfig`；`ProjectConfig` 负责项目路径解析。
- public YAML 顶层只允许 `config_version`、`llms`、`project`、`scan`、`indexing`、`concurrency` 和可选 `rules`。`project.language` 只能显式为 `c_cpp` 或 `java`。
- `scan.depth` 公开为 `fast|balanced|deep`；CLI 的 `--scan-depth` 高于 YAML，YAML 高于打包默认。省略 depth 目前解析为 `fast`。public config 不提供 scan-wide token 预算字段。
- 三档不带产品侧 token 上限；Range Benchmark policy 分别维护完成后成本预期，并按 agent/stage 的真实 usage 验收。
- `runtime_defaults.yaml` 管理 Agent 启用状态/LLM 角色、分析预算、缓存和稳定算法默认值；`AGENT.md`、`SKILL.md`、workflow YAML 不在此重复。P3 继续保留 P1 的 `semantic_modeler`、`active_discovery`、`validator_agent` 与 `history_maintenance_agent`；Security Spec 模型适配器只在系统已冻结 subject/scope/evidence/slot ID 的 unknown audit unit 上提出 `proposed` 对象，不是可配置 runtime Agent。
- `zscope.compat` 集中提供旧配置显式迁移、旧报告只读视图与旧 usage 维度映射；它不导入 Agent、LLM client、执行器或 promotion 代码。
- 根目录 `zscope.c_cpp.yaml` 与 `zscope.java.yaml` 是语言隔离的精简参考文件；Java 不接受 SVF/clang/compile database，C/C++ 不接受 Java provider 字段。
- `Z_SCOPE_RUNTIME_SPEC` 只在 `Z_SCOPE_DEVELOPER_MODE=1` 时接受绝对覆盖路径。有效规格版本、来源和 SHA-256 进入配置哈希、缓存身份及报告 provenance。
- `UserConfigWorkbook`/`UserConfigStore` 维护人工可审阅语义以及 suppression、baseline 等旁路状态。
- semantics 合并内置 defaults、工作簿、源码推断和历史信息，为候选与 prompt 提供当前入口相关的语义片段。
- `security_map.db` 是独立于历史函数 snapshot 的只读安全语义 sidecar：零 LLM 骨架记录入口、调用、危险事件和 backend coverage；有证据引用的选择性 LLM delta 才能成为 claim，无可解析引用的内容仅是 observation。
- `security_specs/security_specs.db` 与同目录不可变 CAS 保存 SecuritySpec revision、qualification、review chain、shadow compilation 和 root manifest。P3 的 13 类有限 DSL 不接受脚本、正则、查询代码或自然语言条件；程序事实若不能精确绑定 subject、slot、scope、evidence 与 dependency hash，只能保留为 observation。
- snapshot policy 决定完整、轻量或语法快照，store 负责持久化与复用。
- `ReviewMemory` 是验证反馈门面；`issue_identity.py` 为报告、baseline、SARIF 和 benchmark 提供统一身份。

## 必须保持的不变量

- 产品运行时不解析 v1；旧字段只允许由 `zscope-config migrate` 读取。未知键、重复 YAML 键、错误类型、非法枚举和未展开必需环境变量必须失败。
- 已删除的 Agent 名、subagent 字段和 `runtime.reporting.semantic_dedup` 即使出现在 developer runtime override 中也必须带迁移指引失败。迁移结果只有显式保存并由严格 v2 loader 重新加载后才能用于新扫描。
- public YAML 不能包含 Agent、analysis、reporting、workflow、缓存、逐 Agent 轮数、rollout 开关或 scan-wide token 预算；扫描档位是明确允许的公共资源控制。
- Java 尚未通过独立门禁，只接受 `fast`；显式请求 `balanced/deep` 必须报错，不能静默降级。C/C++ 默认切换到 balanced 之前仍以 fast 解析省略值。
- `rules.disabled_ids` 优先于 `enabled_ids`，同一 ID 同时出现时以禁用为准；表内重复或未知 ID 必须在启动外部工具/LLM 前失败。未通过资格的新内置规则必须是 experimental 且默认关闭；遗留 stable/pending 规则只保留迁移期兼容，正式发布门禁会拒绝任何默认启用但未 qualified 的规则。
- C/C++ 后端只能显式为 `unified|clang|regex`，Java 只能为 `java_unified|java_source|joern`；深度后端不可用时不得静默切换到弱后端。
- `scan.task` 空串必须激活当前语言全部适用 Skill；非空文本只覆盖审计重点。
- `concurrency` 的全部字段必须是正整数，并由调度、索引、SVF、Validator、evidence completion 与 LLM 全局限流统一读取。
- CLI 配置路径和目标项目路径必须区分：`project.root` 相对进程工作目录解析，其余项目相对路径依据 `project.root` 解析。
- KnowledgeDB、snapshot 和默认 user config 状态路径必须相对 `project.root`，不能因跨目录执行写入进程工作目录。
- 用户配置只向当前函数/入口注入相关片段，不能把整个工作簿无差别放入 prompt。
- 人工填写的配置不能被自动推断静默覆盖；推断行必须保留来源和置信度。
- 历史 snapshot cache key 必须覆盖影响其内容的代码、public config、RuntimeSpec provenance、Agent/Skill 和后端版本因素。Security Semantic Map 则分层缓存：程序骨架只依赖 code/symbol/type/call-edge/IR/backend 版本，LLM delta 再依赖 model/prompt/skill/用户语义；规则变化只重算 gap plan，callee 契约变化按反向消费者和 SCC 原子传播。
- Security Spec cache 额外绑定 audit-unit fingerprint、registry/compiler/prompt revision、model profile 与依赖 hashes；dependency 或 scope 变化只通过反向索引失效命中的 spec、函数与调用依赖。P5 前 `security_spec_mode` 固定为不可配置的 `shadow`，compiled artifact 不得回流 Candidate Ledger、Proof closure 或 terminal disposition。
- 入口 canonical identity 必须保留实现文件和可调用实体；当后端给出的 signature 不含方法名时（如 Java 的返回值/参数描述符），必须同时保留全限定函数名，不能因去重而丢失入口。
- canonical key、stable fingerprint 和 source-context fingerprint 的用途不能互换；身份算法变更要考虑历史 baseline 兼容性。

## 常见变更应落到哪里

- public YAML 字段和严格校验：`zscope/config/v2.py`；组合类型在 `config.py`，内部默认在 `runtime_defaults.yaml`。三者变更要同步 README、迁移器和配置测试。
- v1 到 v2 的一次性字段映射：`zscope/compat/config.py`；`zscope/cli/config_cli.py` 只负责显式读写命令，禁止把别名兼容加回产品 loader。
- 工作簿 schema/导入导出：`user_config_workbook.py`、`user_config_store.py`。
- 内置 API 语义或 overlay：`zscope/semantics/`。
- 快照策略和存储：`zscope/snapshots/`。
- 反馈、baseline 和 suppression：`zscope/memory/` 与 config store。
- 稳定 issue identity、公共取消/限时能力：`zscope/common/`。

## 对应测试与验证命令

```bash
python -m pytest -q tests/test_user_config_workbook.py tests/test_semantics_defaults.py
python -m pytest -q tests/test_security_semantic_map.py
python -m pytest -q tests/test_security_specs.py tests/test_p3_security_spec_qualification.py
python -m pytest -q tests/test_config_v2.py tests/test_config_migration.py tests/test_concurrency_config.py
python -m pytest -q tests/test_snapshot_store.py tests/test_snapshot_refresh_decision_prompt.py
python -m pytest -q tests/test_review_memory.py tests/test_issue_dedup.py
```

## 权威源码和关联文档

- 稳定入口见本文 frontmatter 的 `sources`。
- 路径和使用说明见 `README.md`，完整配置参考见根目录 `zscope.c_cpp.yaml` 与 `zscope.java.yaml`；状态分层见 `docs/architecture.md` 的“持久化与反馈平面”。
- 不在模块文档中复制完整工作簿列定义或历史 schema 迁移记录。
