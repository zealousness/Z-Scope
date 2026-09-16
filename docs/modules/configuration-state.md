---
doc_contract: zscope-module-v1
covers:
  - zscope/config
  - zscope/semantics
  - zscope/snapshots
  - zscope/memory
  - zscope/common
sources:
  - zscope/config/config.py
  - zscope/config/v2.py
  - zscope/config/runtime_defaults.yaml
  - zscope/config/function_entry.py
  - zscope/config/user_config_store.py
  - zscope/config/user_config_workbook.py
  - zscope/orchestration/user_config_inference.py
  - zscope/semantics/models.py
  - zscope/semantics/inference.py
  - zscope/semantics/defaults.yaml
  - zscope/semantics/user_config_context.py
  - zscope/semantics/security_map.py
  - zscope/snapshots/store.py
  - zscope/memory/review_memory.py
  - zscope/review_memory/identity.py
  - zscope/review_memory/store.py
  - zscope/common/issue_identity.py
  - zscope/common/portable.py
tests:
  - tests/test_portable_runtime.py
  - tests/test_config_v2.py
  - tests/test_config_migration.py
  - tests/test_concurrency_config.py
  - tests/test_user_config_workbook.py
  - tests/test_user_config_workbook_readme.py
  - tests/test_risk_api_semantics.py
  - tests/test_user_config_overlay_new_kinds.py
  - tests/test_clang_cfg_custom_apis.py
  - tests/test_user_config_inference_new_roles.py
  - tests/test_llm_review_new_roles.py
  - tests/test_parallel_custom_prompt.py
  - tests/test_semantics_defaults.py
  - tests/test_security_semantic_map.py
  - tests/test_snapshot_store.py
  - tests/test_review_memory.py
  - tests/test_review_memory_acceptance_gaps.py
  - tests/test_review_memory_replay.py
  - tests/test_issue_dedup.py
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
- `runtime_defaults.yaml` 管理 Agent 启用状态/LLM 角色、分析预算、缓存、报告策略和稳定算法默认值；`AGENT.md`、`SKILL.md`、workflow YAML 不在此重复。
- Review 实验开关仅属于 RuntimeSpec：`validation_review_checkpoint`、`validation_review_protocol`、`validation_checked_proofs`、`validation_positive_case`、`validation_related_findings` 默认均为 false。checkpoint 单独启用时只保留完整事实和前序结果，不向模型新增事实工具；protocol 组只改变封套与验收；checked_proofs 组才启用共享编译器事实和检查工具。正面举证不修改现有置信度门槛。实验期间禁用候选结果缓存，避免复用缺少封套、事实增量或有效签名的结果。
- 根目录 `zscope.c_cpp.yaml` 与 `zscope.java.yaml` 是语言隔离的精简参考文件；Java 不接受 SVF/clang/compile database，C/C++ 不接受 Java provider 字段。
- `Z_SCOPE_RUNTIME_SPEC` 只在 `Z_SCOPE_DEVELOPER_MODE=1` 时接受绝对覆盖路径。有效规格版本、来源和 SHA-256 进入配置哈希、缓存身份及报告 provenance。
- `UserConfigWorkbook`/`UserConfigStore` 维护人工可审阅语义以及 suppression、baseline 等旁路状态。
- semantics 合并内置 defaults、工作簿、源码推断和历史信息，为候选与 prompt 提供当前入口相关的语义片段。用户自定义风险接口覆盖 13 类角色（allocator/calloc/reallocator/deallocator/copy/lock/unlock/io_acquire/io_release/send_sink/recv_source/format_sink/callback_register）；内置 API 名集合保持不变，用户自定义名只能通过非 builtin 来源增量进入。`--infer-user-config` 在廉价启发式之外提供 LLM 深挖：逐行筛选（保留/丢弃/修订 + 定位标记回写）、配对校验、低置信度行的独立二轮复核（冲突行降级为 llm:needs_review 而非静默生效），并对体检查未分类的歧义符号做 LLM 定向分类；退出前输出 `user_config.infer_report.md` 汇总。扫描时 `analysis.llm_interface_inference`（默认开启，预算 `analysis.llm_interface_inference_budget`，默认 50）会用 LLM 为无名字提示的轻量 wrapper 快照补打 role 标记，语义层同时从快照的结构化 effects 分类（fast 档同样受益）。
- `security_map.db` 是独立于历史函数 snapshot 的只读安全语义 sidecar：零 LLM 骨架记录入口、调用、危险事件和 backend coverage；有证据引用的选择性 LLM delta 才能成为 claim，无可解析引用的内容仅是 observation。
- snapshot policy 决定完整、轻量或语法快照，store 负责持久化与复用。
- `ReviewMemory` 是验证反馈门面；`issue_identity.py` 为报告、baseline、SARIF 和 benchmark 提供统一身份。

独立的 `zscope/review_memory/` 归属 [Validator Review Memory](review-memory.md)，
保存项目级误报模式与 advisory context。其状态、抽取、匹配、回放及当前限制见该文档；
本模块继续负责 `zscope/memory/` 的既有 baseline/suppression 门面与公共配置。

## 必须保持的不变量

- 产品运行时不解析 v1；旧字段只允许由 `zscope-config migrate` 读取。未知键、重复 YAML 键、错误类型、非法枚举和未展开必需环境变量必须失败。
- public YAML 不能包含 Agent、analysis、reporting、workflow、缓存、逐 Agent 轮数、rollout 开关或 scan-wide token 预算；扫描档位是明确允许的公共资源控制。
- Java 尚未通过独立门禁，只接受 `fast`；显式请求 `balanced/deep` 必须报错，不能静默降级。C/C++ 默认切换到 balanced 之前仍以 fast 解析省略值。
- `rules.disabled_ids` 优先于 `enabled_ids`，同一 ID 同时出现时以禁用为准；表内重复或未知 ID 必须在启动外部工具/LLM 前失败。未通过资格的新内置规则必须是 experimental 且默认关闭；遗留 stable/pending 规则只保留迁移期兼容，正式发布门禁会拒绝任何默认启用但未 qualified 的规则。
- C/C++ 后端只能显式为 `unified|clang|regex`，Java 只能为 `java_unified|java_source|joern`；深度后端不可用时不得静默切换到弱后端。
- `scan.task` 空串必须激活当前语言全部适用 Skill；非空文本只覆盖审计重点。
- `concurrency` 的全部字段必须是正整数，并由调度、索引、SVF、Validator、evidence completion 与 LLM 全局限流统一读取。
- CLI 配置路径和目标项目路径必须区分：`project.root` 相对进程工作目录解析，其余项目相对路径依据 `project.root` 解析。
- KnowledgeDB、snapshot 和默认 user config 状态路径必须相对 `project.root`，不能因跨目录执行写入进程工作目录。
- 用户配置只向当前函数/入口注入相关片段，不能把整个工作簿无差别放入 prompt。
- 人工填写的配置不能被自动推断静默覆盖；推断行必须保留来源和置信度；未再生成的 inferred 行会被清理，manual 行永不清理。
- 修改内置检测逻辑涉及的内置 API 名集合时必须保持行为等价：checkers 的 builtin 基础名集合逐字不变，用户自定义名经由 semantics/checker defaults/semantic overlay 追加（`names_from_nondefault_sources`）。
- 工作簿 `README` sheet 只写不读（不在 `SHEET_HEADERS` 白名单）；kind 枚举外的新取值读取时记入 `read_warnings` 并进入推理报告。
- 历史 snapshot cache key 必须覆盖影响其内容的代码、public config、RuntimeSpec provenance、Agent/Skill 和后端版本因素。Security Semantic Map 则分层缓存：程序骨架只依赖 code/symbol/type/call-edge/IR/backend 版本，LLM delta 再依赖 model/prompt/skill/用户语义；规则变化只重算 gap plan，callee 契约变化按反向消费者和 SCC 原子传播。
- 入口 canonical identity 必须保留实现文件和可调用实体；当后端给出的 signature 不含方法名时（如 Java 的返回值/参数描述符），必须同时保留全限定函数名，不能因去重而丢失入口。
- canonical key、stable fingerprint 和 source-context fingerprint 的用途不能互换；身份算法变更要考虑历史 baseline 兼容性。

## 常见变更应落到哪里

- public YAML 字段和严格校验：`zscope/config/v2.py`；组合类型在 `config.py`，内部默认在 `runtime_defaults.yaml`。三者变更要同步 README、迁移器和配置测试。
- v1 到 v2 的一次性字段映射：`zscope/cli/config_cli.py`；禁止把别名兼容加回产品 loader。
- 工作簿 schema/导入导出：`user_config_workbook.py`、`user_config_store.py`。
- 内置 API 语义或 overlay：`zscope/semantics/`；新增用户自定义角色时需同步 `models.py` 角色桶、`defaults.yaml`、`inference.py` kind 映射、候选生成器（regex/clang_ast_cfg/cpp_domains）、`evidence.py` overlay 路由与受影响 `builtin_catalog.yaml` revision。
- 快照策略和存储：`zscope/snapshots/`。
- 反馈、baseline 和 suppression：`zscope/memory/` 与 config store。
- 稳定 issue identity、公共取消/限时能力：`zscope/common/`。

## 对应测试与验证命令

```bash
python -m pytest -q tests/test_user_config_workbook.py tests/test_semantics_defaults.py
python -m pytest -q tests/test_security_semantic_map.py
python -m pytest -q tests/test_config_v2.py tests/test_config_migration.py tests/test_concurrency_config.py
python -m pytest -q tests/test_snapshot_store.py tests/test_snapshot_refresh_decision_prompt.py
python -m pytest -q tests/test_review_memory.py tests/test_issue_dedup.py
```

## 权威源码和关联文档

- 稳定入口见本文 frontmatter 的 `sources`。
- 路径和使用说明见 `README.md`，完整配置参考见根目录 `zscope.c_cpp.yaml` 与 `zscope.java.yaml`；状态分层见 `docs/architecture.md` 的“持久化与反馈平面”。
- 不在模块文档中复制完整工作簿列定义或历史 schema 迁移记录。

## Portable 工具定位

`zscope.common.portable` 读取启动器提供的 bundle 根目录及资源清单，只为未显式填写的工具字段提供默认值。显式 public config v2 覆盖仍可用于实验，无需模式开关；解析不回写用户文件，错误覆盖不得改用其他工具。语言模板和 `zscope-init` 隐藏工具定位配置。源码安装不设置 bundle 根目录，保留原有 PATH 行为。

## 快照版本提交

快照正文使用唯一临时文件写入不可变版本，SQLite 事务同时发布版本指针和指纹。读取先查询已提交版本，再访问按版本缓存的正文，避免独立 SnapshotStore 实例之间的旧缓存污染。保存返回版本标识，版本化读取同时返回正文与标识；最终报告只能绑定分析时观察到的版本，冲突报告保存在快照目录的 `conflicts/`，不会覆盖新快照的报告。

旧固定文件名继续可读。保存、重协调和删除回收无引用旧版本，普通失败路径清理本次临时文件；读者遇到并发回收时重新查询指针。`get_fingerprints` 附带 `snapshot_generation`，快照与指纹版本不一致时要求刷新。

内置资源家族定义位于 `semantics/defaults.yaml` 的 `resource_families`，不把 FILE/DIR 句柄混入整数 fd 集合。该内部语义表不增加 public config v2 必填项。
