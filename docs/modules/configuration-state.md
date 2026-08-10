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
  - zscope/config/function_entry.py
  - zscope/config/user_config_store.py
  - zscope/config/user_config_workbook.py
  - zscope/semantics/defaults.yaml
  - zscope/semantics/user_config_context.py
  - zscope/snapshots/store.py
  - zscope/memory/review_memory.py
  - zscope/common/issue_identity.py
tests:
  - tests/test_user_config_workbook.py
  - tests/test_parallel_custom_prompt.py
  - tests/test_semantics_defaults.py
  - tests/test_snapshot_store.py
  - tests/test_review_memory.py
  - tests/test_issue_dedup.py
---

# 配置、语义与状态

## 职责与非职责

本子系统负责解析和校验用户配置、合并内置/项目语义、维护快照和人工反馈状态，并提供稳定 finding identity、取消和运行限制等公共设施。它连接用户领域知识、历史分析结果和当前扫描。

它不负责选择 CLI 运行模式、不实现后端索引，也不决定报告的展示格式。

## 主入口和数据流

- `ConfigLoader` 将 YAML 和环境变量转换为强类型配置，`ProjectConfig` 负责项目路径解析。
- `project.language=auto|c_cpp|java` 决定语言隔离；`indexing.java` 和 `rules` 分别承载 Java provider 与显式规则扩展配置。
- `UserConfigWorkbook`/`UserConfigStore` 维护人工可审阅语义以及 suppression、baseline 等旁路状态。
- semantics 合并内置 defaults、工作簿、源码推断和历史信息，为候选与 prompt 提供当前入口相关的语义片段。
- snapshot policy 决定完整、轻量或语法快照，store 负责持久化与复用。
- `ReviewMemory` 是验证反馈门面；`issue_identity.py` 为报告、baseline、SARIF 和 benchmark 提供统一身份。

## 必须保持的不变量

- `analysis.workflow_name` 不能从用户 YAML 注入。
- `backend=auto` 必须按已检测语言解析为 `unified` 或 `java_unified`，不允许 Java/C 后端静默串线。
- CLI 配置路径和目标项目路径必须区分：`project.root` 相对进程工作目录解析，其余项目相对路径依据 `project.root` 解析。
- 用户配置只向当前函数/入口注入相关片段，不能把整个工作簿无差别放入 prompt。
- 人工填写的配置不能被自动推断静默覆盖；推断行必须保留来源和置信度。
- snapshot cache key 必须覆盖影响语义的代码、配置、Agent/Skill 和后端版本因素。
- 入口 canonical identity 必须保留实现文件和可调用实体；当后端给出的 signature 不含方法名时（如 Java 的返回值/参数描述符），必须同时保留全限定函数名，不能因去重而丢失入口。
- canonical key、stable fingerprint 和 source-context fingerprint 的用途不能互换；身份算法变更要考虑历史 baseline 兼容性。

## 常见变更应落到哪里

- YAML 字段、默认值和校验：`zscope/config/config.py`，同步 README 示例和配置测试。
- 工作簿 schema/导入导出：`user_config_workbook.py`、`user_config_store.py`。
- 内置 API 语义或 overlay：`zscope/semantics/`。
- 快照策略和存储：`zscope/snapshots/`。
- 反馈、baseline 和 suppression：`zscope/memory/` 与 config store。
- 稳定 issue identity、公共取消/限时能力：`zscope/common/`。

## 对应测试与验证命令

```bash
python -m pytest -q tests/test_user_config_workbook.py tests/test_semantics_defaults.py
python -m pytest -q tests/test_snapshot_store.py tests/test_snapshot_refresh_decision_prompt.py
python -m pytest -q tests/test_review_memory.py tests/test_issue_dedup.py
```

## 权威源码和关联文档

- 稳定入口见本文 frontmatter 的 `sources`。
- 路径和配置示例见 `README.md`；状态分层见 `docs/architecture.md` 的“持久化与反馈平面”。
- 不在模块文档中复制完整工作簿列定义或历史 schema 迁移记录。
