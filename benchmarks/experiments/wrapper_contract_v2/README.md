# Wrapper 契约链路回放

这些脚本验证建模、源码组合、工作簿重读和规则消费，产物不提供正式 benchmark 资格。使用 WSL/Linux Python 3.13，以及当前源码构建的 Clang 批量索引器。

执行顺序：

1. `replay_reported_contracts.py --contracts <历史契约 JSON> --output <目录> --clang-indexer <工具>`：对历史模型响应执行本地源码组合；禁止 LLM 调用。隔离复制扫描源码，构建索引，写入并重新读取真实 XLSX。
2. `probe.py --output <目录> --clang-indexer <工具>`：真实 SemanticModeler 终结工具响应的小样本，包含函数、宏、参数换位、输出参数、成员、全局锁与内部平衡业务函数。显式提供 `Z_SCOPE_LLM_BASE_URL`、`Z_SCOPE_LLM_MODEL`、`Z_SCOPE_API_KEY`。保留工作区及原始/规范化契约；第二轮检查建模零调用与契约版本不变。
3. `replay_contracts.py --workspace <probe 保留目录> --output <目录>`：禁止 LLM 调用，重放已保存的真实模型响应，检查 Clang、Regex、Graph 和 KnowledgeDB 配对输入。
4. `trial_with_hot_rescan.py --output <新 trial 目录>`：完整工具链预检后，使用官方 unified trial 入口。冷扫结果归档后、隔离工作区清理前执行保留缓存的重扫；两轮分别评分。过程中冻结当前 matcher，不向扫描器提供 truth。
5. 完成两轮评分后执行 `compare_runs.py --run <run-01>` 和 `audit_run.py --run <run-01>`，生成逐项回退对照、契约消费事件及用量归因。

`publication.json` 包含版本、原始及规范化契约、拒绝原因、发布契约与配对、调用站点事件和建模统计。工作簿保留模型来源与源码核验信息；核验信息不赋予自动契约确定性证明权限。中断的 trial 仅归档已提交快照，并标记不完整，不能用于准确率结论。

来源归因使用 `candidate_source`；Clang 的 `semantic_suspicious_point` 优先组仍是规则候选。快照怀疑点保留作 Validator 的未验证背景，自动登记关闭。大报告审计检查是否存在任何快照来源信封，同时独立统计每次 LLM 用量；重复序列化计数不冒充唯一候选数量。

缓存验收区分有效快照复用和失败重试。源码未变且快照有效时不重新建模；缺失、失败或规范版本过期的快照仍需重建。外部声明/类型信息缺失可能使覆盖状态为 `partial`，不能将契约通过或模型调用成功等同于完整覆盖。

`pool_probe.py --output <目录> --clang-indexer <工具>` 使用独立合成 C 源码验证未知池协议发现、实现校验、函数/宏静态组合及同一对象/同一池消费。两轮同时保存快照、真实工作簿、发布与调用站点清单，断言热扫描零建模和工作簿不变；不使用 Range fixture/truth，也不运行独立快照候选验证。归档的 usage 文件是快照目录的累计内容，跨轮汇总必须按用量日志会话和 `call_id/sequence` 联合去重，不能将旧事件算作热扫描调用，也不能合并不同会话的局部调用编号。可用 `replay_contracts.py --workspace <保留目录> --output <新目录>` 禁止 LLM 重放实际响应，核对发布版本一致。


## 持久目录与断电恢复

`persistent_trial.py --control <控制目录> --base-url <已授权端点>` 创建新的持久 trial，底层使用官方 `--work-directory`，执行目录位于 WSL 原生文件系统；输出与监控文件保存在控制目录指定的位置。这个入口总是新建一轮，不能用它恢复旧进程。

先确认原扫描进程已经退出，再使用 `recover_persistent_scan.py --control <原控制目录> --base-url <原已授权端点>`。恢复器核对产品源码哈希、隔离输入清单、JSON/SQLite 完整性和完整工具链，备份旧日志、用量及语义状态后，在同一目录和配置中继续。它复用有效语义缓存，不能恢复尚未提交的供应商调用或验证会话。配置仍从 `execution.json` 中记录的路径读取，不能临时改成仓库模板。

评分前在控制目录的 `scoring-inputs/manifest.json` 封存 truth 路径、SHA-256 与 matcher SHA-256；历史报告也使用同一份 truth 独立重评分。truth 始终位于扫描工作区外。恢复状态达到 `scan_finished` 后，运行 `finalize_recovered_trial.py --control <原控制目录> --base-url <原已授权端点>`：保存完整报告、真实工作簿、发布契约、快照和回放包，再运行独立官方评分。扫描和归档结束前保持产品源码冻结；完整快照归档必须等扫描退出，以免并发摘要刷新替换旧版本文件。原工作目录保留，历史产物不覆盖。

`recovery-usage.json` 合并断电前后已提交的会话，用（会话文件，call_id）消歧；保留原始尾部和服务商报告值/保守估算值。普通 `score.json` 用量仍只对应最终扫描进程，不能把它当作恢复全过程费用。缓存 prompt 和 reasoning 分别是输入/输出 token 的子集，不重复加入总数。断电未落盘的费用未知。

恢复产物标为 `interrupted_trial_recovery`，明确不是连续冷扫描，也不具备正式发布资格。`live_validator_audit.py --workspace <持久工作目录> --output <审计 JSON>` 只读取已有会话，记录费用、工具查询与原始模型意见；原始 `verified/rejected` 不是最终候选裁决，更不是 TP/FP。`analyze_trial.py` 只在报告冻结并评分后使用，基线应先用相同 matcher 重评分。
