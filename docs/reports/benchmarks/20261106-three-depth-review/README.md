# Range 三档 cold trial 系统分析

日期：2026-11-06 UTC。范围：Fast、Balanced 的 20261104-03 批次和 Deep 的已完成重试 20261105-01 批次。本文是离线分析报告，不改变原评分，不代表 formal/release 验收。

## 结论

**Fast 尚未达到静态分析的能力上限。当前最值得优先修复的是候选到证据的衔接、验证调用和统计完整性，而不是继续加大 Deep 的预算。**

- 三档确认 65 / 79 / 82 个 truth；Deep 相对 Balanced 新增 11 个、丢失 8 个，净增 3 个。Deep 的新增命中全部来自既有确定性候选，不能归功于其新增的 180 个主动发现候选。后者没有形成最终确认报告。
- Fast 与 Balanced 的语义候选覆盖都是 125/141，Deep 为 129/141；但“覆盖”只是评分器的候选匹配层，不等于对应根因已被完整表达，更不等于已证明。Deep 的 59 个漏检中，12 个无合格候选，47 个已有匹配候选；其中还有“类别相同、实际主张不同”的假性覆盖。
- Balanced、Deep 的主要 token 增量在 V3 调查阶段，分别占总量 92.79%、81.85%。已记录的同会话完全相同工具查询重复很少，无法把高成本主要归因于死循环或重复计费；大量候选分别开展多轮调查、反复携带上下文和证据无法落地才是更有证据的方向。
- 通过唯一 cluster UID 恢复逐候选成本后，Deep 的主动发现及其 180 个候选的验证合计 **102,020,972 token**，占 Deep 相对 Balanced 增量的 **99.38%**，却没有产生独占的最终确认报告。这是当前最明确的成本收益失衡；删除该阶段后能否保留全部命中仍需受控验证。
- Deep 的 210,879,316 token **包含 6,270,943 的失败请求保守计量**；服务端实际回报为 204,608,373。154 次请求缺少 provider usage，故总量不是完整账单，也不能据此计算精确费用。
- 误报需拆开：91 条三档合计未匹配报告中，67 条被评分器归为 truth 已覆盖的附加报告，24 条仍计入 effective FP。源码复核确实发现错误主张，例如把固定字符数组当成独立堆资源、忽略已经执行的 1 MiB 配额校验；也发现真实缺陷因根因位置或分类不符未计 TP。详见 [逐例误报审查](false-positive-review.md)。

本文的“事实”指最终结构化产物或源码直接支持的观察；“推断”指据此提出的因果解释；“未验证”指本轮没有动态复现或缺少运行时记录的部分。模型在原报告中的 reasoning 只是待核对的证据，不自动成为本文事实。

## 输入、完成状态和可比性

|项目|Fast|Balanced|Deep|
|---|---|---|---|
|结果目录前缀|`/home/zeal/range-baseline-20261104-03/results/fast`|同批次 `results/balanced`|`/home/zeal/range-baseline-20261105-01/results/deep`|
|轮次|单次 cold trial|单次 cold trial|单次 cold trial 重试|
|最终状态|completed|completed|completed，launcher exit 0|
|模型|`volcengine/deepseek-v4.1-flash`|相同|相同|
|运行环境|WSL Ubuntu，Python 3.13.15，ijson 3.5.1|相同|相同|
|SVF worker|1|1|1|

最终评分、summary 与 aggregate 一致，三档均 queue drained、backend valid、truth isolated。Deep 于 **2026-11-06 00:42:57 UTC** 退出。它的资源监测于 00:43:11 自动停止；这与评分通过是两回事。三档均没有通过整体质量/发布门禁。

三份 `input-manifest.json` 字节 SHA-256 均为 `c0d82721fc01ab68a3e2a54d6f1bd2c291a809f7ebd95e47b96e02612efc1430`，逻辑 manifest digest 均为 `243634d2440cf86ae9a4933f2109e2a6ca5273e3a96d222992b1ef5f596ca15a`。本轮逐文件计算了三份留存 `scan-input/` 的 23 个文件：**69/69 与各自 manifest 一致；当前 fixture 同样 69/69 一致**。证据在 [input-verification.csv](input-verification.csv)。这包括 60 条效果、55 个接口的自定义语义文件；它的 SHA-256 为 `c4e7d9dba7351276595307bb800f81f44b81d4e930d8b82a04fb999614b0656a`。

记录的 git SHA 为 `2b483628008e8c270ff36746903192d47ddfd4f3`，tree 为 `b630ebc658898cd3ab20696d3c8d664c6c369b2f`，policy SHA 为 `b2306f3d949f8fe62ae4d0d773989455c232cf8fe67d00793a724efdc9c3b6e0`。本轮所引用的候选规则、LLM 计量、claims 与评分 protocol 源码字节和该 HEAD 一致；`benchmarking/runner.py` 有本地修改，引用其当前实现解释字段，并以最终产物数字核对公式。仓库另有未提交工作，**git SHA 不是整个试跑运行时加载内容的完整指纹**。逐文件状态在 source-index 中；本报告没有冻结、复制整个工作区或覆盖已有修改。

这些是同一 fixture 的三次观察，不是重复实验：Fast/Balanced 与 Deep 的开始时间、并发竞争和服务端状态不同；单次 trial 的 Jaccard=1、recall range=0 不能证明稳定性。旧的中断 Deep 不纳入成绩或成本，故本文成本也不是所有失败尝试的总花费。

## 成绩与评分口径

|指标|Fast|Balanced|Deep|
|---|---:|---:|---:|
|确认的不同 truth / 141|65|79|82|
|漏检 FN|76|62|59|
|最终默认报告条数|84|113|120|
|raw FP：未获一对一匹配的报告|19|34|38|
|effective FP：扣除同根/已覆盖附加报告后|2|10|12|
|主指标 actionable precision|77.38%|69.91%|68.33%|
|主指标 distinct root recall|46.10%|56.03%|58.16%|
|主指标 actionable F1|0.5778|0.6220|0.6284|
|辅助 root-cause precision|97.01%|88.76%|87.23%|
|辅助 root-cause F1 / legacy f1|0.6250|0.6870|0.6979|
|包含 needs-review 视图的 TP|125|118|124|
|默认报告之外的 needs-review 数|291|125|301|
|语义候选覆盖|125/141|125/141|129/141|
|扫描耗时（秒）|9,931.09|34,390.82|85,147.75|
|端到端耗时（秒）|10,369.94|35,294.46|85,627.21|

`actionable_precision = TP / (TP + raw_FP)`；辅助 root-cause precision 使用 effective FP。不得把后者当用户实际看到的报告准确率。`false_positive_audit.effective_records` 为空也不意味着 FP=0：本轮 effective FP 全在 overlap 记录中。评分器源码见 [protocol.py](../../../../zscope/benchmarking/protocol.py) 1736–1781 行。没有 safe-entry 负样本（count=0，rate=null），所以这里的 FP 比例也不是统计学意义上有 TN 分母的 false-positive rate。

`with_review_tp` 是扩大输出视图后的匹配数，既不是已确认数，也不能直接当“还差多少次确认”。不同视图中的去重和候选主张变化会影响匹配，Fast 的该数高于 Balanced 不代表 Fast 的确认质量更高。

候选计数同样要分层：三档终态明细有 458 / 458 / 638 行，唯一 candidate UID 为 443 / 443 / 623。每档都有 **15 个 UID 各出现两行**，例如同一 VLA 被 regex 与 clang 规则同时描述。Balanced 的 RANGE-033 同 UID 一行 confirmed、另一行 needs_review；用 UID 覆盖式建字典会错误地解释为“TP 没有确认候选”。本文逐例索引用 `mode + candidate_terminal_index`，最终命中始终取 `matched_pairs.issue_index`。详见 [candidate-uid-collisions.json](candidate-uid-collisions.json)。归并后的 Deep 漏斗是 confirmed 120、alias 51、needs_review 301、rejected_with_evidence 159、rejected_with_proof 3、engine_failed 4；不要和原始行的 `terminal_disposition` 直接混加。

### 门禁为什么没过

当前 range policy 的 confirmed TP 门槛为 111；truth contract 的 `required_confirmed_tp=120` 是另一个字段，不能混称一个阈值。token 门槛为 Fast 2M、Balanced median 10M / per-run 12M、Deep 30M；三档均超限。这些是跑完后的评价阈值，本轮没有因此在阈值处强制中断。

Fast 另有 confirmed precision <0.9、fast_static_formal_qualified=false；三档 protocol anomaly 非零；Deep 的 provider usage coverage <1、telemetry_complete=false。Arm-A、sealed、安全负样本和独立 truth verification contract 等正式评价资料缺失，也使 release eligibility 为 false。**这些缺项说明本次只是第一版 trial，不能反过来成为继续开发或读报告的新增前置流程。** 完整原始失败列表保留在各档 aggregate，索引见文末。

## token、重复调用与协议异常

### token 花在哪

|层次（账本计量）|Fast|Balanced|Deep|
|---|---:|---:|---:|
|总量|6,851,565|108,219,614|210,879,316|
|validation 阶段|6,851,565|7,807,022|38,277,508|
|reserve / R2 V3 调查|0|100,412,592|172,601,808|
|其中：主动发现 agent（包含在上面阶段内）|0|0|27,470,533|
|其中：Validator agent|6,831,943|108,200,131|183,388,956|
|其中：decision explainer|19,622|19,483|19,827|
|prompt tokens|4,806,258|102,631,970|199,159,074|
|cached prompt（prompt 的子集）|1,240,960|83,286,528|151,290,496|
|completion tokens|2,045,307|5,587,644|11,720,242|
|reasoning（completion 的子集）|812,805|3,132,782|5,896,446|

阶段与 agent 是两种交叉分组，不可相加；cached/reasoning 也不能再加到 total。缓存 token 很多，说明输入复用多，**不代表可把这部分当作零费用**。未读取价格或账单，本文不估人民币成本。

Balanced 比 Fast 多 101,368,049 token，净多 14 TP；Deep 比 Balanced 多 102,659,702 token，净多 3 TP（描述性比值约 34.22M token/净新增 TP）。Deep 是 Balanced 的 1.95 倍 token、2.48 倍扫描时间。这不是某项功能的因果成本：模式会同时改变调查、发现、上下文与随机结果。

最终账本虽然没有 candidate_uid，却保留了 Validator 的 validation_cluster_uid；三档分别有 458 / 458 / 638 个唯一 cluster，与候选明细一对一关联，**所有 Validator 调用均能恢复成本归属，没有未匹配 cluster**。逐候选结果见 [candidate-costs.csv](candidate-costs.csv)，汇总见 [candidate-cost-summary.json](candidate-cost-summary.json)。

|Deep 成本按候选来源恢复|token|说明|
|---|---:|---|
|458 条既有确定性候选的验证|108,838,517|Balanced 对应为108,200,131，只差638,386|
|180 条 active 候选的验证|74,550,439|其中71,187,619在reserve；没有最终确认报告|
|主动发现本身|27,470,533|共享单元/层级成本，未强摊到某个候选|
|解释器|19,827|共享报告说明|

主动发现加其验证共102,020,972，占Deep总计量的48.38%，解释了相对Balanced增量的99.38%；其余差额为确定性候选验证与解释器。这里是**调用归属的账本分解**，不是功能消融的反事实结论：主动发现是否间接改变确定性候选的上下文/轨迹尚未证明。Deep最高的单候选验证成本为 `_runtime_require_normal_process` 的1,519,523 token（终态needs_review）；Balanced最高为 `_executor_handle_network_request` 的1,452,261（needs_review）。不能以这些个例替代总体，但它们给出了可直接复核的预算控制样本。

V3 入口当前只要非 shadow 且 security obligation 有效便可选；`readonly_closable_gap` 被记录但不是必须满足的选择条件，见 [validation/runner.py](../../../../zscope/core/validation/runner.py) 880–920 行。Balanced 422 个 eligible 中 343 个进入，得到 26 个最终确认报告；Deep 606 中 529 个进入，得到 35 个。大量成本也花在有价值的否证和保留不确定项上，不能把未新增 TP 的调用全部叫浪费；但低选择性提供了明确优化空间。

Deep 的 35 个 V3 最终报告中只有 17 个一对一命中 truth，另 18 个为 raw FP；V0 最终报告 29 个命中 27，V1 最终报告 56 个命中 38。这里是最终报告归因，不是各阶段候选数。

### 重试不等于重复计费

|账本观察|Fast|Balanced|Deep|
|---|---:|---:|---:|
|调用事件数|607|4,160|7,456|
|服务端回报 usage 的调用|607|4,160|7,302|
|retry=true 次数|152|170|248|
|这些 retry 行计入的 token|1,383,476|1,762,015|2,574,499|
|finish_reason=length|123|125|216|
|重复 call_id / sequence 额外行|0 / 0|0 / 0|0 / 0|
|解析失败的 Validator audit 行|2|60|118|
|最终门禁 protocol_anomaly_count|2|60|426|

retry 标记通过 attempt、trace label 等得到；这列是带标记调用的消耗，不含触发它的原始失败调用，因此不是全部“重试开销”。`repair=true` 三档都为 0，而 Validator `repair_thinking_disabled_count` 为 152 / 170 / 241：两个埋点语义不同，不能据前者声称从未修复。代码见 [llm_client.py](../../../../zscope/framework/llm_client.py) 492–516 行和 [validator agent](../../../../zscope/agents/validator_agent/agent.py) 332–415 行。

本轮还逐行统计了已完成 conversation 的**最新 response**，未反复计数 request 中携带的历史消息。607 / 4160 / 7302 个 exchange 与成功账本事件相符，没有重复 usage_event_id。Balanced 的 read_code 1726、search_code 2417；Deep 的 read_code 2702、search_code 4189，另有 read_semantic_evidence 910、read_semantic_unit 353。同一 conversation 文件内同工具、完全相同规范化参数的额外调用，Balanced 只有 search_code 3 次，Deep 有 search_code 4 次和结果提交工具 1 次。**本次证据不支持“原样反复查相同东西是主要费用来源”。** 跨会话对同一源码重复阅读、参数变化但信息等价的查询，以及历史上下文重传仍存在可能；尚未进行语义等价去重，不能给出其精确可节省量。详见 [conversation-call-statistics.json](conversation-call-statistics.json)。

Deep 154 次缺失 usage 分为：

|记录原因|次数|保守计量 token|
|---|---:|---:|
|provider_request_failed（未细分）|124|5,444,310|
|HTTP 400: max_tokens rejected|23|631,254|
|Cancellable HTTP transport failed|7|195,379|
|合计|154|6,270,943|

`settle_unknown` 使用请求预留 prompt 和 completion limit 计量，见 [llm_usage.py](../../../../zscope/framework/llm_usage.py) 558–578 行。`conservation_passed=true` 只证明账本内部对得上，不证明失败请求的实际收费已知。23 次 400 明确指向参数兼容问题，但目前的分类日志没有保存允许的具体上限；不能据此猜测该 endpoint 支持多少输出 token。124 次通用失败也不能全部归于限流、超时或模型容量。

Deep 的门禁 426 = `max(6 个 exhausted, 118 个 malformed audit) + 308 个 usage errors`，其中每个缺失 usage 的调用同时缺 provider usage 与 finish reason，154×2=308。它**不是 426 次独立模型格式错误**。源码见 [runner.py](../../../../zscope/benchmarking/runner.py) 867–875 行。

### 当前统计无法回答什么

- 三档 usage 事件顶层和嵌套 candidate_uid 均为空，但 validation_cluster_uid 足以恢复本轮全部 Validator 成本；主动发现与解释器的共享成本没有一对一候选归属。应补全直接身份，不能把 `explicit_attribution_coverage=1` 误读为这些字段都已完备——它衡量的是最终 finding 的归因。
- Deep `active_discovery.model_calls=383` 是单元级 agent.run 次数，账本 hierarchical_discovery 为 1030 个请求；其局部摘要 token=9,091,822 且 incomplete，而账本该 agent 为 27,470,533。中断单元的费用不能靠局部摘要统计；源码 764–800 行在单元超时时跳过 response metadata 累加。两套数字不可简单相加或直接互相替代。
- reserve 的 `new_fact_count=0` 不证明“调查没有证据”。conversation 中有事实登记工具，汇总/初始验证埋点有 912 / 1490；阶段归属和重复登记都需修正后才能量化“每新增事实成本”。
- `investigation_exhausted` 不一定用满 50 轮。Balanced 54 次、Deep 112 次该终态；Deep 有 18 次记录 0 轮，全部记录中的最大轮数只有 25。源码会把异常后的空结果与缺有效终态合并到调查未完成路径，故不能一律通过增加 iteration limit 解决。

## 候选为什么没有覆盖全

完整 141×3 的逐例状态、候选行、规则、模型停止原因与证据门禁在 [case-evidence.md](case-evidence.md) 和 [truth-evidence.csv](truth-evidence.csv)。下表专门解释 Deep 仍未达到语义候选匹配的 12 个 truth。它们的目标函数均已分析，评分器也记录了期望规则已调度；这排除了“文件完全没扫到”的解释，**没有排除函数实例中的具体规则被语义绑定、事实过滤或匹配条件挡住**。

|truth / 源码位置|直接看到的缺口|可支持的原因及边界|
|---|---|---|
|RANGE-009，`src/main.c:87`|`g_shared_counter++` 无候选|增量位于 `state_mutex` 解锁之后；源码有 worker 创建及多个访问者。当前 SharedAccessIndex 依赖 exact native access 及词法锁前缀；应核查该访问事实/锁状态进入消费者的路径。最终产物没有记录具体未 emit 分支，不能断言是某一行过滤造成。|
|RANGE-027，`src/lifecycle.c:288`|active 描述了 if-wait 后直接减计数，但类别为 state_inconsistency / unchecked_return，truth 是 lost_wakeup|语义内容已部分发现，类别/obligation 不一致；不能把类别别名一改就当完成。regex 与 clang 的 if-cond-wait 规则已存在，需查标准 API 授权和实例匹配路径，不能说产品没写该规则。|
|RANGE-036，`lifecycle.c:415–428`|active 关注 check-then-act race，没有对应 munmap 后悬空全局 UAF|417 解除映射却不清空，428 之后解引用，甚至无需并发。应组合 release、持久槽、后续访问和 epoch；当前“race”假设不能替代这条顺序生命周期见证。|
|RANGE-038，`lifecycle.c:588–606`|OPEN → 全局 session；transport cleanup 仅日志，无合格候选|必须跨函数理解注册表拥有权和 transport 结束义务，单个 allocator/free 清单不足。Deep 还报告 pfnAdd/Expire/Drop 等函数指针边无法链接。并非补几个接口名字即可完成。|
|RANGE-039，`lifecycle.c:526–568`|DETACH 解链后不销毁，目标入口无合格候选|需把全局表摘除、session/owner/guard 的生命周期串成一条根因；当前局部分配错误路径候选不能代替解链泄漏。|
|RANGE-050，`lifecycle.c:373–392`|出现接收返回值/未初始化缓冲候选，没有 watched fd 并发冲突候选|关键是不同入口对同一全局 fd 的读写与关闭代际，不是 recv_source 的名字或缓冲污点；需跨入口访问对及 happens-before。|
|RANGE-052，`main.c:217,626–647`|匹配到清理类型和分配失败候选，没有 g_ready/queue 生命周期 race|“已经分析了 submit”不等于分析了 submit 与 cleanup 的并行关系。需要清理开始、ready 读写和队列使用的共同身份与时序。|
|ISSUE41-004，`lifecycle.c:1668–1684,1738`|active 提了数组越界/竞态；truth 是 encoded/raw fd 契约错位|`_peer_is_inter_fd` 只接受 [0,1024)，高位编码值应先经 raw-fd 转换。当前 graph 规则依赖 signature 和名字样式，实际是否收到 signature/授权语义没有最终收据。需要表示域/解码关系，而不是把“变量名像 reliable_fd”当证明。|
|ISSUE44-003，`network.c:101–102`|只有 send 重试忙等候选，没有 SIGPIPE|调用是 `send(...,0)`；现有 `write_without_sigpipe_handling` 的直接匹配只抓 write，不能涵盖 send 的 flags 语义。应扩展标准操作族并核对进程级 signal 策略。|
|ISSUE44-005，`lifecycle.c:1967–1985`|候选是接收循环/错误返回；未表达输出容量与 frame.length 的不等式|response_len 已计算却未传给 receive；1977 将不可信长度直接作为 want，1727 持续写 dst+received。需要 recv 目的区容量、请求长度、实际长度的跨函数关系，不能靠 tainted buffer 单一标签。|
|ISSUE44-008，`executor.c:257–260`|active 的 unchecked_return 描述确实提到 status 未初始化，但不匹配 uninitialized_read|同时存在真实 caller/reachability 限制：当前源码没有仓内调用/头文件导出该函数。需分开“waitpid 失败时不定义 out 值”的标准语义、类别归一和 truth 的可达性口径；不能仅重命名类别后宣布检出。|
|ISSUE44-009，`lifecycle.c:1634–1638`|只有路由 key 截断/分配失败候选，没有错误码被后续成功掩盖|这两次调用均跨行；`_emit_unchecked_native_status_masking` 1019–1027 行用单行 fullmatch 要求完整调用，1046 行也从单行查 return 调用。源码形态与匹配前提直接不符，是可执行的修复点：改用 native call/result/control-flow 事实，保留依赖结果的证明。|

Fast/Balanced 另缺 RANGE-016（shutdown flag）、RANGE-035（close 后 watched fd 未清）、RANGE-048（解锁后重读共享计数）、REAL-031（条件编译下无效锁）。Deep 的 active discovery 让这四项达到候选覆盖，但没有因此获得四个确认 TP。

标准/自定义语义本轮不是“完整”的：清单文件绑定了接口，不等于每个实例都把返回值、出参内容、锁成功条件、宏展开、函数指针槽位、对象释放代际正确投射到每个消费者。当前可表达的接收语义已经补齐并留在 manifest 中；剩余主要是能力和消费路径，不能要求用户把所有跨函数关系手工写进同一 YAML。清单填写标准和自动发现改造应独立推进，见先前 [语义基线记录](../../../archive/implementation/2026-11-04-range-semantics.md)，本轮未修改清单。

## 有候选为什么还漏检

|已匹配但漏检的 truth，按关联候选终态集合分组|Fast|Balanced|Deep|
|---|---:|---:|---:|
|仅 needs_review|60|35|35|
|仅 rejected_with_evidence|0|7|5|
|needs_review 与 rejected_with_evidence 并存|0|4|5|
|仅 engine_failed|0|0|1|
|engine_failed 与 needs_review 并存|0|0|1|
|合计|60|46|47|

这是 truth 分组，每个 truth 只占一行；同一 truth 的候选可能不止一个。它不意味着每个被拒候选都在拒绝真实根因。

**证据转交失败是真实损失。** ISSUE41-009 在 Fast/Balanced 已确认，Deep V3 也说 verified，却因 `unknown_evidence_ref:FACT_V3_...` 落到 needs_review；ISSUE43-008 的 calloc 失败未判空，一条 Deep 候选 verified 但 `required_roles_not_replayable:contract`；RANGE-033 的 VLA 一条缺调查证据闭环，另一条缺 `runtime_bound_controllable` 的可回放事实。修复应把已有调查事实按对象、build context、角色注册并回放，而不是删除证据门禁。代码入口：[claims.py](../../../../zscope/core/validation/claims.py) 211、276、303、314 行。

**候选主张和真实问题不同，也会制造“已覆盖”的错觉。** ISSUE42-028 的 truth 是 signal 上下文的锁/格式化安全问题，匹配候选却主张普通同步调用中的递归阻塞；内层实际为 trylock，拒绝该递归阻塞主张合理，但外层 signal handler 被打断重入、以及非信号安全调用的问题并未因此安全。RANGE-045 的若干合格候选关注 attach 时分配失败的空指针分支，truth 却是 delete OS node 时漏掉孩子链表。局部候选被正确否证后，真正的生命周期缺陷仍需另一条见证。

**入口威胁模型有不一致。** RANGE-017 的拒绝理由用“仓库内 parser 将长度限制为 1 MiB”证明 serialize 不会溢出，但 `td_serialize_task_message` 是公开头文件接口，可接受调用方提供的 Task，见 `task_dispatcher.h:112`、`main.c:329–330`、`parser.ph:10`。把内部调用点当作所有调用者的完整约束并不充分。反过来，某些资源配额 FP 又把“头文件公开”直接等同于攻击者可控。应统一 API 边界、可信调用者与契约前提，不能按想要的结论选择口径。

**部分 truth 本身只有模式/功能层的见证。** Deep 完全拒绝的五项为 RANGE-017、REAL-016、ISSUE42-011、ISSUE42-020、ISSUE42-028。ISSUE42-011 的 fixture 使用匿名 mmap、fd=-1，类型仅日志分支，模型在回答安全破坏问题而 truth 记的是设备/常规文件尺寸语义；ISSUE42-020 队列没有可见消费方，模型不能完成真实 lost-wakeup 路径。应人工核定“功能性缺陷应否报告、需要怎样的外部契约或 witness”；本文保留原 FN，既不把模型否证一概认作正确，也不为了提高分数放宽规则。

**Deep 主动发现未形成确认闭环。** 180 个 active 候选全为 unresolved 归因；179 个进入 V3、无最终确认。发现阶段有 19 个 ambiguous/unlinked callee、35 个 model_incomplete、164 个 unit_deadline_exceeded（原因记录数可跨层，不是 218 个唯一函数）。函数指针 g_entry_callback、MeshControlHooks 的 pfnAdd/Expire/Drop 位于未链接列表。模型产出的假设还需消解假设、对齐类别和所需角色，并产生可回放证据；仅生成更多自然语言候选会增加审查与 token 负担。

## 新增与退化案例

Deep 与 Balanced 的命中交集 71，新增 11、退化 8；Fast 与 Deep 的交集 63，Fast 独有的 ISSUE41-009、ISSUE42-002 也都被 Balanced 命中。三档事后命中并集为 90，这只是回归观察集合，不是下一轮保证能达到的目标。

|Deep 新增，相对 Balanced|Deep 决策层|Balanced 未确认的直接证据|
|---|---|---|
|ISSUE42-007 线程名容量|V3|调查未得有效终态|
|ISSUE42-008 部分初始化统计结构|V3|verified 后调查证据闭环不完整|
|ISSUE42-027 定时器回调自锁|V3|缺事实后调查未完成|
|ISSUE43-007 batch 配额|V3|缺事实后调查未完成|
|ISSUE43-012 过期快照异步使用|V1|调查未完成；Deep 初判即确认|
|ISSUE43-013 replay window 配额|V3|缺事实后调查未完成|
|ISSUE44-001 header allocation 加法回绕|V1|verified 后证据闭环不完整|
|ISSUE44-007 高 fd 关闭遗漏|V1|相关候选被拒或缺事实；Deep 区分数组索引上界和 close 义务|
|RANGE-014 清理参数类型错位|V3|调查未完成|
|RANGE-028 realloc 覆盖唯一指针|V3|调查未完成|
|RANGE-051 平台命令执行|V1|缺事实/协议失败及调查未完成|

|Deep 退化，相对 Balanced|Deep 的直接阻断|
|---|---|
|ISSUE41-009 引用仍存活时释放|V3 verified，但 FACT_V3 引用未知|
|ISSUE42-002 TLS cache 成员泄漏|确定性候选调查 0 轮后无有效终态；active 候选另受假设/角色/引用门禁阻断|
|ISSUE42-014 pool cache 数组界限|确定性候选 engine_failed，active 调查 0 轮后未完成|
|ISSUE43-008 calloc 失败后解引用|一条调查失败，另一条 contract 角色无法回放|
|ISSUE44-004 task table 容量回绕|verified，但调查证据闭环不完整|
|ISSUE44-006 覆盖旧 mmap 槽|调查 16 轮、22 次工具调用后无有效终态|
|RANGE-033 VLA|verified，但缺证据闭环或可控运行时边界事实|
|REAL-021 role 清理参数错位|主候选调查 0 轮后未完成；相邻“NULL 分配失败泄漏”候选被正确拒绝|

全部变化含 Fast/Balanced 独有情况见 [changed-cases.csv](changed-cases.csv)，全部 141 个 truth 的三档命中布尔值见 [truth-comparison.csv](truth-comparison.csv)。本轮没有用随机性作为所有退化的解释；上述门禁/异常是可以直接定位的事实，至于为何同一模型这次给出另一条轨迹，单样本不能确定。

## Fast 的能力边界

Fast 是“确定性候选 + 有限验证”的产品档位，不是零 LLM 的静态扫描。本轮它用了 6.85M token，候选中 V0 决策 32 行，其余 426 行走 V1。它与 Balanced 使用同一批 458 条确定性候选；Deep 的最终 120 条确认报告也全部归因于确定性发现。因而 **65 个 TP 不是静态候选生成上限**，更不是传统静态分析技术的理论上限。

至少有三类尚可开发的空间：已有候选的低成本证据闭环（如分配器失败契约和 caller 数据来源）、目前漏发的简单协议形态（多行状态掩盖、send flags、if/while wait）、跨函数的对象/锁/长度关系。不能把 125/141 当作保证可确认的上限，因为候选覆盖本身有上述主张偏差；也不能从一份 C fixture 推断真实项目上的速度/召回极限。

## 按收益和成本排序的改进与验证

以下是下一步可实施方案，本轮没有改代码或执行新扫描。优先级以减少错误决策、恢复已有证据和降低无效开销为准；不能保证指定 TP 增益。

|顺序|改进与具体入口|收益 / 代价|针对性验证及完成判据|
|---|---|---|---|
|1|修复 provider 参数兼容与终态错误分类；usage 加 candidate/cluster/attempt 身份；分开 actual 与 conservative|低到中成本；23 次 400 和未知计量有直接证据，便于后续定位成本|用已留存失败类别做离线 transport 测试；参数不支持时有明确处理，不能盲目重试同参数；usage 守恒且每个调用可追到会话，保守值单列；不需新外部扫描|
|2|修复 FACT_V3 登记、build/context 身份与 role 回放；有效事实跨初判/调查转交；保留严格证据门禁|中成本；直接针对 ISSUE41-009、ISSUE43-008、RANGE-033 等已有 verified 漏检|用最终 replay bundle 和精简本地证据 fixture 验证合法引用可消费、过期/异对象证据仍被拒；不能以放开 unknown ref/assumption 换召回|
|3|把 NULL 失败分支、固定数组成员、所有权转移和已执行的 callee guard 放到便宜判定层|中成本；降低大量错误分配泄漏候选的验证负担，修复明确 FP|正反例：ControlSession.key 数组 vs 堆指针；owner=NULL vs 已成功分配；MAX_TASK_SIZE 支配 vs 仅输入长度不足。必须同时保留父对象真实成员泄漏和跨调用持有义务|
|4|补候选消费的断点收据，并优先修复多行调用/send flags/cond-wait 的 native 事实路径|中成本；12 个缺口中有可局部验证的问题，避免为每个漏检盲加清单条目|记录“函数实例→规则调度→语义授权→匹配→过滤→候选”的首个失败条件；用重排换行、宏包装和等价变量名的正反例验证，不写仅匹配 Range 名字的规则|
|5|主动发现先完成小规模候选到证据闭环；建立跨函数容量、持久槽释放、引用/回调和并发访问证据；active 类别/义务映射并消解假设|较高成本，但直接涉及本轮102M增量；RANGE-038/039、ISSUE44-005、跨入口race的关键能力|先对现有180个候选分层重放/审查，解决假设与角色不能消费的问题，再考虑扩大发现；用独立消融验证其独占收益。宏、函数指针、out长度、释放代际分别有小型witness；清单仅补可表达部分|
|6|V3 按可补全的事实和预期收益选择；复用同 build/object 的事实；无证据增益时早结束并输出具体缺口|中到高成本；主费用在 343/529 次调查，不在少量完全相同工具重查|先修身份/计量再做受控消融：相同输入比较 TP 集合、真实反例、阶段 token、有效事实、终态覆盖；不默认加轮数、扩大并发或全量重跑|
|7|校正报告主张和根因锚点；人工审查 truth 的 API/安全契约；用户 YAML 增加审查投影和填写标准|中成本；减少真实缺陷以错误对象/类别重复上报，改善可解释性|逐例保留原评分与人工裁决两列；更改 truth/匹配规则要单独版本化并重算两边，不能悄悄调整本次成绩。填写说明明确对象载体、成功条件、长度单位/容量、回调槽和 unsupported 边界|

下一版目标宜先用可验证的硬条件：已知 400 参数失败不再发生；provider usage 缺失显式分类；候选调用身份完整；明确错误的 ControlSession/配额主张被拒；既有 19 个 Deep-vs-Balanced 变化案例逐例回归。召回目标可参考 90 个事后并集建立验证队列，但应逐例证明再承诺数字。资源/预算目标应按上述阶段计量与真实价目另行制定，不能把 legacy F1 或缓存 token 当成低成本证据。

## 运行资源与中断的边界

本次完成的 Deep 重试记录了 1428 个有效资源样本，最大单调时钟采样间隔 60.357 秒，无 >90 秒缺口；WSL boot ID 与 Windows 启动时间未变。OOM=0，swap=0；最低 WSL 可用内存约 26.94 GiB，Windows 可用约 30.32 GiB，最低 WSL home 可用磁盘约 354.27 GiB；最大单进程 RSS 约 3.15 GiB。32 CPU 总体 CPU 峰值约 3.29%，不支持“CPU/内存耗尽导致这次 Deep 长达一天”的解释。资源摘要位于 `/home/zeal/range-baseline-20261105-01/resource-monitor/summary.json`，SHA-256 `65291d176c59e1f087a7b1e69aa87f6af8bc7ddd0ab0ab7f6a46448da7e7f7b1`。

本次 observer 的多次 transport 断连不等于扫描中止，原进程和采样在恢复后仍连续。更早 batch-03 的 Deep 中断曾有 Windows Application Hang 1002 / WER 1001（wslhost）证据，未证明 Windows 重启或 OOM；不能用完成重试的健康资源反证之前的故障原因。受限 Hyper-V 通道未重试，本轮没有读取旧中断扫描内容。UTC 与单调时钟曾存在速率差异，耗时比较采用 benchmark 的 scan/end-to-end 计量，不混用墙钟字符串相减。

## 证据索引与完成范围

|证据|文件与定位方式|
|---|---|
|原始产物路径、大小、SHA-256|[artifact-index.json](artifact-index.json)：三档 score/summary/report/aggregate/usage/input/tool-health|
|指标原值|[metrics.json](metrics.json)；原始 `score.json#/matched_pairs`、`#/candidate_coverage_audit/rows`、`#/usage_accounting`|
|所有 truth 的人读索引|[case-evidence.md](case-evidence.md)：141 节；对应 [truth-comparison.csv](truth-comparison.csv)、[truth-evidence.csv](truth-evidence.csv)|
|完整选取的候选审计理由和门禁|[candidate-evidence.jsonl](candidate-evidence.jsonl)：1554 行，`mode + candidate_terminal_index`；未包含原始提示词|
|所有 91 条未匹配报告|[unmatched-findings.csv](unmatched-findings.csv)：mode + issue_index；人工判读见 [false-positive-review.md](false-positive-review.md)|
|阶段/agent/重试的费用分组|[usage-breakdown.json](usage-breakdown.json)、[usage-breakdown.csv](usage-breakdown.csv)|
|通过cluster恢复的逐候选验证费用|[candidate-costs.csv](candidate-costs.csv)、[candidate-cost-summary.json](candidate-cost-summary.json)|
|重复调用统计及计数定义|[conversation-call-statistics.json](conversation-call-statistics.json)|
|漏检、协议、调查终态分组|[analysis-statistics.json](analysis-statistics.json)|
|truth 和输入校验|[truth-reference.json](truth-reference.json)、[input-verification.csv](input-verification.csv)|
|同 UID 多行关联|[candidate-uid-collisions.json](candidate-uid-collisions.json)|
|源码引用清单和当前字节身份|[source-index.json](source-index.json)|
|本报告的完整性检查|[validation.json](validation.json)|

原始 report 为共享对象编码，提取使用项目 `zscope.reporting.json_io.read_report(strict=True, immutable=True)`，没有把普通 json.load 的存储节点当作实际报告。case 附录中的理由为原始审计摘要，全文在 JSONL；人工复核结论只写在本文和 FP 审查，二者分开。

已完成：三档最终评分与费用分层、全部 Validator 调用的逐候选费用恢复、69 项输入哈希校验、141 项逐例关联、91 条未匹配报告索引、24 条 effective-FP 观察的源码审查、19 个 Deep/Balanced 变化案例归因、候选缺口和优先改进方案、离线证据和交付校验。

尚未证明：12 个缺口在候选发射前究竟命中哪个内部过滤分支（部分已有明确源码形态证据，但缺完整运行轨迹）；154 次失败请求的真实账单及全部网络原因；主动发现共享成本如何归到某个候选、以及去掉主动发现后的反事实成绩；所有 truth 的真实利用条件及跨项目泛化；改进的实际收益和多次运行稳定性。没有为了填补这些不确定性新开扫描、外部模型调用或修改系统。本文不声称完成了新的动态复现。
