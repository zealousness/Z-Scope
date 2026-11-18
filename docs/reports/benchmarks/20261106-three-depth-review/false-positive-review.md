# 未匹配报告的逐例源码审查

本附录与 [主报告](README.md) 配套。F/B/D 分别指 Fast / Balanced / Deep；`#n` 为对应最终 `report.json#/issues/n`，从 0 起算。候选 UID、规则和原模型理由见 [unmatched-findings.csv](unmatched-findings.csv)，评分匹配诊断保留在原始 score。

三档 raw FP 共 91 条：Fast 19、Balanced 34、Deep 38；其中 `truth_covered_additional` 合计 67 条（17/24/26），表示评分器认为 truth 根因已有主报告占用，另一条未获一对一 TP。剩余 24 条（2/10/12）由 cross_anchor_overlap 与 weak_legacy_overlap 构成，仍计 effective FP。**分类是评分事实，不是对这 91 条逐一安全性的裁决。** 67 条附加报告已提供完整逐例索引，本轮没有把它们全部当作“正确且无需审核”。以下 18 个源码点覆盖全部 24 条 effective-FP 观察，进行了针对性源码核对。

## 有直接反证或错误主张的报告

|最终报告记录|所报主张 / 官方分类|源码复核与归因|处理方向|
|---|---|---|---|
|F#73、B#70；`lifecycle.c:490`|释放 session 却未释放 owner；F weak overlap，B cross overlap|`ControlSession.key` 是 `char[64]`（431–437），STR_COPY 调用 `_str_copy_wrapper`，只 memcpy、没有堆分配（common.h:47；utils.c:50–60）。489 的分支仅当 owner=NULL 才到490，SAFE_FREE(session) 已完整释放该分支的父对象。原理由把 key 当成另一块堆内存，**该泄漏主张有明确反证**。owner 为 NULL 本身也不可能构成存活资源泄漏。|候选生成与 Validator 均须区分内嵌数组、独立分配和成功分支；将该分支变成确定性负例，不能为了查出全局 session 泄漏而保留这个错误候选。|
|B#34；`parser.c:93`|payload_len 分配无配额；weak overlap|`_parse_task_buffer` 在36行先调用 `_validate_task_header`，168–169行拒绝 payload_length > MAX_TASK_SIZE；common.h:8 定义为 1 MiB。模型所谓“无任何业务上限”与源码相反。其后 memcpy 没有对实际输入 len 做完整约束是另一个真实 bounds 问题，不能证明“无上限分配”。|守卫证据必须跨 callee 回放，分开输入缓冲界限与业务配额；拒绝本条无上限主张，保留原 bounds truth。|
|F#45；`lifecycle.c:125`|entry->value 分配后错误返回泄漏；weak overlap|错误分支 value=NULL；entry->key 是内嵌数组（12–18），并非原理由声称的第二次分配。entry 已在122–123挂入全局表，`_lifecycle_service_shutdown` 75–84会逐个释放 value 和 entry，`main.c:648` 调用它。因此“没有句柄、没有卸载协议、key 堆泄漏”的理由不成立。失败后留下半初始化节点及其累计保留确是另外的问题，但未由所报 allocation/value 路径证明永久丢失。|把主张改为实际对象与错误状态恢复责任；核对持有者生命周期。不能只看局部 return 未 free 就确认泄漏。|
|B#17；`lifecycle.c:273`|UNLOCK 没有匹配 LOCK；cross overlap|263–274：264 已 LOCK，成功路径273 UNLOCK 正常匹配；真正错误是267分配失败提前 return 时不解锁。模型最后理由也改称“持锁提前返回”。这是一条真实缺陷被**错误规则、方向和锚点**报告。|修正 claim/规则身份到 lock leak 的错误分支，再和已有同根报告去重；不能将成功路径的 UNLOCK 标为缺陷。|

## 源码确有问题，但主张、根因或匹配位置需要修正

|最终报告记录|官方分类|源码复核与限定结论|处理方向|
|---|---|---|---|
|B#13、D#31；`lifecycle.c:1310`|weak overlap|message → `_str_dup` → LOG_ERROR(log_copy) → `_log_wrapper` → vfprintf 的格式串路径成立（1304–1315、common.h:41、utils.c:63–83）。公开 `td_run_service_cleanup_cases` 的 key/mode 在 main.c:490–501 透传。该点另有错误分支漏释放 log_copy；format string 是独立机制，弱匹配到 RANGE-001 不证明它就是 parser bounds 的同根。|将格式串源、sink 和调用链保留为独立根因供 truth 人工审核；与下面 wrapper 报告去重。|
|B#27、D#50；`utils.c:82`|cross overlap，关联 RANGE-004|通用日志 wrapper 是可变格式串 sink，但多数 caller 使用安全字面量。本轮实证恶意格式串路径来自上一行的 `_runtime_flush_log_buffer`，而非把所有 `fmt` 调用都当漏洞。|以不安全调用链为根因，避免同时对调用点和通用 wrapper 重复上报；不能修改 wrapper 的所有合法 printf 风格调用来掩盖问题。|
|B#36；`executor.c:80`|weak overlap|`_executor_log_message` 171–195 把 message 复制入 g_log_buffer 后在192执行 `printf(g_log_buffer)`，格式串风险确有后续 sink；原理由没有读被调体、只相信 format contract，论证质量不足但并非因此无缺陷。|绑定真实 printf sink 和上游内容传播，核对现有 `_executor_log_message` truth/报告是否同根，减少 wrapper 与 callee 分开报告。|
|B#42、D#14；`lifecycle.c:2681`|cross overlap，分别弱关联 ISSUE42-002 / ISSUE44-006|allocator 返回 raw+8 本身是 interior-pointer 所有权转移，不应仅据“没 free raw”定罪。真正路径：2695–2696选择 header allocator 和 noop free，2698分配、2702调用空释放，2904传 use_header_pool=1。组合后有真实释放遗漏；两个评分关联都不是该函数指针释放根因的可靠身份。|报告 allocator/free 组合和调用者释放义务，支持 base/interior 指针关系；不要建议在合法 allocator 返回前 free。|
|D#25；`lifecycle.c:1124`|cross overlap，关联 REAL-002|`_service_alloc_node` 返回 node 转移所有权。模型起始主张 name 泄漏，最后举例却是调用者 `_runtime_remove_system_node` 1213–1214、`_runtime_remove_file_record` 1262–1263释放 name+node，漏掉 payload；这两个调用者的 payload 泄漏成立，**不是所锚定 name 在 allocator 内泄漏**。|按实际未释放成员 payload 和责任调用者重新锚定，与已有成员清理报告合并。|
|B#20、D#41；`lifecycle.c:2548`|cross overlap，关联 ISSUE42-002|每次写 g_runtime_named_pipe.addr 都新分配，未先处理旧值；2875可重复调用，2442还会用 mmap 指针覆盖同槽。直接源码支持丢失旧拥有值的风险；它不是 TLS cached_blocks 清理根因。|形成 persistent-slot overwrite 见证，明确每一代对象及 malloc/mmap 释放族，避免和所有内存泄漏做宽泛跨锚点匹配。|
|B#93；`main.c:427`|weak overlap|`_lifecycle_avl_register_route(route_key,1)` 在938–940固定进入失败分支，调用方忽略返回，430仍 return0；错误状态掩盖真实存在。callee 还会释放已插入节点，是另一 UAF。|报告忽略失败的具体调用和对外状态契约；同函数其他忽略返回不能只按“unchecked_return”全合并，也不要混成已有 UAF truth。|
|D#118；`main.c:423`|weak overlap|`_lifecycle_register_os_node` 对NULL和分配失败均return -1（776–784），caller不检查且最终return0。功能性状态传播缺陷有代码见证；是否具有单独安全影响需明确 API 契约和调用方行为。|与上一项共同呈现复合操作错误传播问题，保留每个可失败动作，避免重复用户告警。|
|D#111；`main.c:369`|weak overlap|`_lifecycle_format_topic` 对非法 prefix/out/size 返回-1（326–328），caller丢弃结果且后续最终return0；声明层面的错误传播缺失成立。该 caller 还执行 VLA、错误释放等其他危险操作，本文没有运行它来证明某一故障顺序。|按 API 成功状态与结果有效性报告，区分功能契约和已证明安全后果。|

## 配额与回调契约：不能只用“没有反证”确认

|最终报告记录|官方分类|源码复核与限定结论|处理方向|
|---|---|---|---|
|D#54；`lifecycle.c:1531`|weak overlap|公开 coordination API 的 count 经main.c:531进入 realloc(count*sizeof(size_t))，函数内没有配额。**请求大小无上限成立，但调用方是否是不可信主体、允许配额是多少，源码未给出完整契约**；不能仅凭 public API 把任意大合法申请都确认为安全漏洞。另有realloc直接覆盖旧槽的独立生命周期风险。|明确 source threat model、配额责任与乘法溢出/旧槽保留等不同义务，不能用 proven_absent 的本地守卫替代源可控证明。|
|D#58；`lifecycle.c:2631`|weak overlap|main.c:712–714公开传map_size，2901即使上一项rc失败也继续申请；2633–2635把zone持久挂表。存在按输入大小申请和保留。是否需单次/累计上限及拒绝条件，需契约；不同名字重复调用的资源累积应有精确根因。|区分外部配额、容器重复注册与真正不可回收泄漏；保留调用边、拥有者和名称去重条件。|
|D#72；`lifecycle.c:2286`|weak overlap|block_size经main.c:706–709、lifecycle.c:2889传入，没有上限；2289紧接着释放承载cached_blocks的父容器，成员块丢失。实际生命周期问题正是 ISSUE42-002；Deep没有确认那个主张，却确认了较宽的“无配额”主张。|优先报告可直接证明的成员泄漏，避免因换类别丢掉真实 TP 并新增 FP；配额结论仍需外部信任边界。|
|B#82、D#101；`lifecycle.c:2674`|B cross overlap，D weak overlap|2876–2877将接收帧的size传给malloc，函数的2668/2674两个出口都没有配额；调用者只把指针折算为bool并丢弃返回值。相比纯公开API假设，此处有帧字段来源和返回值丢失证据，资源耗用/泄漏更明确；评分关联的stream replay-window truth不是同一资源对象。|报告确切帧长度→申请及返回所有权丢失路径，使用真实对象锚点；配额和泄漏可分机制但应避免重复根因告警。|
|D#108；`lifecycle.c:228`|weak overlap，关联 RANGE-017|226持锁、228调用可注册函数指针、230解锁，事实成立；204–213允许设置回调。但原理由拿“回调可独立演化”证明所有注册场景危险，且所举 `_lifecycle_fire_registered_callback` 自身不加锁，不能单独证明同锁重入。确切风险应给出回调再次调用持锁 API 的 witness，或 API 明确禁止/允许重入的契约。|区分“持锁执行未知回调”的协议风险和已证明死锁；核验可能目标、外部回调契约、锁类型，不盲目按类别别名匹配无关的 serializer overflow truth。|

所有源码行号相对于已校验与三档留存一致的 `test/range/`。有效 FP 24 条不是24个独立根因：跨档和上下游有重复。本文没有给出“人工修正后的新精度”，因为需要一套统一、经审查的 truth/主张口径后才能合法重算；当前原始分数仍保留。

最小修复顺序是：先消除明确不成立的对象/守卫主张，再把真实缺陷锚定到正确对象与负责调用点，最后在独立评审中处理配额/回调/API信任边界。不能通过把 weak overlap 全部变成 TP、扩大类别兼容集或取消证据门禁来提高数字。
