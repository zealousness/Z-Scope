# Benchmark v5 与 Range Truth v16

## 定位

Range是分布内开发回归集，不是生产泛化证明。Z-SCOPE 2.0正式结果必须区分产品finding质量、
Security Spec Mining、Hypothesis Hunting、Proof Engine和成本，不能把它们压缩成单一recall数字。

## Truth v16

v15保持只读。v16的每条记录使用`zscope.range-truth-contract.v2`：

- kind：concrete_trigger、public_api_contract、pattern_model、retired
- adjudication状态和独立review artifact hash
- primary/secondary/additional结构化锚点
- defect family、CWE和具体trigger
- 通用威胁假设
- required evidence clauses
- paired fixed/near-miss safe unit
- vulnerable/fixed源码和manifest hash

只有concrete_trigger与public_api_contract进入confirmed分母。pattern_model单列design-risk/with-review，
retired不进入分母。

要求：

- 每个confirmable truth有fixed或near-miss对照；
- safe unit数量不少于confirmable truth数量；
- 当前争议项完成双人独立审阅，分歧由第三人仲裁；
- product、truth和Scorer由不同变更提交；
- scanner运行环境不挂载truth、review queue或Scorer。

## Scorer v5

正式匹配继续使用`zscope.truth-matcher.v2`：

- keyword、自由文本和related_functions不能独立形成TP；
- file/function/line必须来自同一结构化锚点；
- Finding-root v2只负责产品展示投影；
- raw FP、same_product_root、truth_covered_additional、cross_anchor_overlap和weak_legacy_overlap分别报告。

类别族移到版本化`defect-taxonomy.v1`，taxonomy hash写入artifact。

## 分层指标

产品结果：

- confirmed及with-review的TP、precision、recall、F1、FDR
- raw/root-effective FP、safe-entry alert rate、vulnerable-fixed一致性
- per-project/CWE/contract macro指标

Security Spec：

- atomic clause precision/recall
- scope准确率、过度泛化率、evidence可解析率、compiler接受率
- 用户批准/缩小/reject/revoke的一致性

Hypothesis Hunting：

- attack surface覆盖、hypothesis有效率、独占confirmed TP
- 错误family/subject/sink/region比例、tokens/独占TP

Proof Engine：

- 证书可重放率、false acceptance、clause闭合率、unknown/conflict率
- confirmed的程序证书覆盖率、proof后多余调用数

成本与稳定性：

- agent/stage/V1/V2/V3 tokens、tokens/KLOC、tokens/confirmed TP
- marginal tokens/新增TP、p50/p95墙钟、五轮Jaccard和recall极差

formal输入必须携带完整且无额外字段的上述三个组件合同、Finding-root v2投影、answer-isolation、100% provider usage和token守恒；按agent和stage汇总必须分别重新求和并等于总token，缺字段不能以0代替。paired结果逐条绑定Truth v16的pair UID、manifest/source hash和两侧scanner report hash。五轮formal聚合重新验证每份score hash，分别输出default/with-review稳定性、三个组件、safe-pair与成本分布，并由调用方提供冻结baseline actionable precision，统一执行`zscope.benchmark-policy.v2`；attestation正文不得自行提供可信workflow run ID。

## 版本边界

- Benchmark v4和truth v15只读、不可作为2.0 Release证据。
- v4/v5对比必须标记分母和评分合同变化，不得宣称直接回归。
- formal只接受v5、v16 contract、matcher v2、Finding-root v2及独立attestation。
- Range通过不自动切换默认档位；仍需public external、sealed和shadow。
