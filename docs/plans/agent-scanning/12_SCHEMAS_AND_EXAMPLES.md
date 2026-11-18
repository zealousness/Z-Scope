# 12 · 数据合同与配置提案

> 配置部分已按当前 public config v3 校正；后续数据合同仍是分阶段设计，不代表全部实现。现行配置以[根 README](../../../README.md)及 `zscope/config/v3.py` 为准，实际进度见[实施记录](21_IMPLEMENTATION_STATUS.md)。旧配置不要求双版本运行，字段从代码模型生成 schema。

## 一个用户配置入口

当前仅接受 `config_version: 3`，继续一个 `zscope.yaml`；UI 与 CLI 使用同一配置模型。内部 ScanIntent/ExecutionProfile 按实际消费者逐步接入，不要求用户再写 task.yaml、资源 profile 和重复的模型凭据。

最小交互只需工程路径、模型连接和必要的构建选择；以下展示用户可覆盖的字段，不表示所有字段必须手填：

```yaml
config_version: 3
llms:
  default:
    base_urls: ["${Z_SCOPE_LLM_BASE_URL}"]
    models: ["${Z_SCOPE_LLM_MODEL}"]
    api_key: "${Z_SCOPE_API_KEY}"
project:
  language: c_cpp
  platform: linux_user
  semantics_file: zscope.semantics.yaml
  targets:
    - id: service
      compile_commands: build/compile_commands.json
scan:
  preset: balanced
  focus: [memory, resources, async_lifecycle]
  reproduction: auto
execution:
  timezone: Asia/Taipei
  stop_at: "08:00"
  max_workers: 4
```

工程根唯一取 YAML 所在目录，不接受公共 `project.root` 或 `source_root`。编译数据库、语义文件等工程相对路径从该目录解析；`semantics_file` 不得越出工程根，扫描前需完成原语发现与审阅。CLI、模板、初始化器、Web、MCP 与 README 使用同一语义。

stop_at 表示下一个对应本地时间的停止新工作边界，运行时解析为带时区的绝对时间；它不创建周期任务。当前 CLI 和新建持久作业已消费该配置，显式作业窗口优先。`focus`、`reproduction`、`execution.max_workers` 和 `platform` 仍是未消费声明；实际并发使用 `concurrency`，示例 4 不表示已限制 worker 数。

当前模式统一为 fast/balanced/deep，省略时默认 fast，Java 仅接受 fast。quick/overnight 只在显式迁移中转换为 fast/deep，不能在运行配置中使用。非工作时间运行由独立时间计划表达，不新增同义模式，也不通过 preset 暗中启用 shadow 实验。

结构/算法细节留内部 RuntimeSpec，用户只见有产品意义的偏好。自动生成的业务模型有专门 UI 和内部存储，配置仅引用项目身份，不要求复制全部契约。

## 程序身份合同

逻辑字段如下，按 S01/S02 的实际消费者实现，不预建无用协议：

```text
BuildContext:
  project_id, target_id, compile_instance_id, source_revision,
  argv/cwd/response/dependency digests, toolchain, triple, abi, coverage

ObjectRef:
  build_context, origin_site, call_context, resource_family, resource_domain,
  instance_abstraction, generation, region, identity_status

SemanticEvent:
  object_ref, kind, source_ref, execution_context, guard,
  provenance, completeness, dependencies

ConditionalSummary:
  symbol_ref, build_context, preconditions, effect_cases,
  aliases/escapes, ownership, synchronization, unknown_effects,
  authority, dependencies, revision
```

instance_abstraction 表示集合或具体实例，不能用抽象相等签发同对象证明。未知字段显式 unknown，不填空字符串后当已知。摘要沿用/扩展 ApiContract 的前置条件、条件效果、载体和资源域。

## 义务与证据

```yaml
candidate: example-uaf
build_context: example-build
object_ref: example-object
defect_family: use_after_free
obligations:
  - kind: same_object_generation
    state: open
    evidence_refs: []
  - kind: release_semantics
    state: established
    evidence_refs: [example-source-effect]
  - kind: feasible_release_then_use
    state: open
    evidence_refs: []
assumptions: []
evidence_revision: 1
dependencies: [example-source, example-contract]
```

示例 ID 均为占位。程序签发身份/authority，模型只能提交假设和实际引用；“established”由相应 checker/provider 检查后设置。每项义务可为 open/established/refuted/unsupported；候选终态不简单等于某一行 refuted，需要检查反证是否覆盖候选全部主张。

Witness 保存原程序源码/事件映射、构建、对象、输入/执行顺序、前提、检查结果和适用范围；静态/动态/模型检查 provenance 分开。外部工具“有告警”不是 witness 合格。

## 用户四态与现有状态的关系

当前有 model_verdict、policy_disposition、needs_review 子状态和 shadow observation；**不能按字符串直接重命名**。

| 目标用户状态 | 判断条件 | 现有记录处理 |
|---|---|---|
| confirmed | 当前关键义务成立、有可核查见证、无未解决冲突 | 已有 confirmed/validated 需经过相同有效性核对；仅模型 verified 不足 |
| conditional | 错误机制已有证据，但真实环境/业务前提尚未确认 | 从 needs_review/相关记录中有条件地投影；明确列出缺失前提 |
| pending | 对象、路径、模型、工具或时窗等不足 | 包括 uncertain、未证实 rejected、未处理/失败工作项 |
| ruled_out | 有当前、足够范围的反证排除候选主张 | 仅模型 rejected 或某次未复现不可映射 |

job_status、coverage、severity、suppression、baseline、shadow 分别保留。shadow 只记录实验观察，不自动成为四态正式结果。条件性不是把所有未决重新命名；不同缺口仍需可统计。

已落地的 S04 投影限于 `object_protocol_path`：`protocol_assessment.v2` 保存当前源码/契约重放结果、对象范围、依赖摘要、业务前提、技术缺口和 `feedback_revisions`。前提初始 `source_kind=analysis_requirement`，`source_refs` 只是描述性效果依据；用户回答通过单独的 `answer.origin=user_acceptance` 保留来源、版本和 yes/no/unknown，不伪装为源码事实。全部必要前提成立且当前技术证据完整时，程序检查器通过现有 proof 路由确认；否则仍按缺口投影 `business_conditional` 或 `protocol_pending`。否定前提不自动 ruled_out。恢复扫描重新核验，报告序列化不保存程序授权，回答版本改变撤回并重算相关业务事实。尚未对所有规则统一改造四态。

规则/候选身份变更可破坏旧 schema，但人工反馈保留旧引用与失配说明，不能误套到新对象。

## ScanJob 与未决工作

```text
job_id / run_id / intent_revision / input_revision / status / phase
target_refs / knowledge_revision / contract_revision
work_items: key, kind, object/candidate, obligations, state, defer_reason, attempts
active_executions / artifacts / usage_ref / coverage
questions: id, business_question, affected_scope, current_assumption, impact
last_event_seq / resolved_stop_time / next_resume_actions
```

小状态与事件同一事务提交，日志原文外置。问题队列不阻塞其他工作，不默认为答案；用户在验收时回答后失效并重算相应依赖。进程身份与输入绑定来自执行器。

## Execution 与经验记录

复用现有 ExecutionPlan/Record，补 session ownership 和模型生成来源；字段至少包含 argv/cwd/build profile、源码/harness/输入/二进制、操作 ID、状态/退出码、日志、超时/资源和 replay 分布。

经验记录仅包含范围、经过实际验证的方法、来源、适用性、active/stale/conflict，不存另一个“已确认缺陷”真源。TaskSpec 与通用补丁模型留到 Q01/Q02，避免用户提前承受两套任务配置。

## 数据演进

自动派生数据库/缓存可按新版重建，不维护旧格式读写分支。人工模型、反馈和未交付产物先导出或保留，再显式导入；失败不覆盖旧文件。数据保护是对用户内容的责任，不意味着承诺兼容旧应用版本。
