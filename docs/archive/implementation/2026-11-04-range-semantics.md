# Range 首版语义基线与识别增强分析（2026-11-04）

> **历史文档，2026-11-17 整理归档。** 原位置：`docs/range-semantics-baseline-2026-11-04.md`。正文中的状态、接口、路径、测试与后续建议保留记录时含义；当前说明见[文档总导航](../../README.md)，本类记录见[归档索引](README.md)。

本记录描述任务 1 的实际改动和第二阶段设计，不是三档 benchmark 结果。未读取历史扫描输出或任何运行中 trial 的输出，未调用模型，未运行 benchmark。源码与当前人工清单是本次分析证据。

## 第一阶段已完成

仓库：`C:\Users\10273\home\work\Z-Scope`，WSL 对应 `/mnt/c/Users/10273/home/work/Z-Scope`。验证从 `/home/zeal` 使用 `/home/zeal/.venvs/zscope-audit-fixes-20261104/bin/python` 执行。

四个文件存在 CRLF：`test/range/CMakeLists.txt`（62 处）、`internal/lifecycle.ph`（135 处）、`internal/network.ph`（9 处）、`src/lifecycle.c`（2623 处）。仅把 CRLF 换成 LF 后，四者分别与原清单记录的字节 SHA-256 完全一致。未修改源码逻辑、source 摘要或校验函数；新增 `.gitattributes` 路径规则约束 CMakeLists 和 `.ph`，`.c` 原有 LF 规则继续保留。

`zscope.semantics.yaml` 新增四条独立 `recv_source` 效果：

| 接口 | 源码 | 本次声明 | 实际验证边界 |
|---|---|---|---|
| `_net_recv_string` | `src/network.c:174-188` | 非空 return 可能含网络输入，may | 精确 native 绑定、编译后的 return carrier 和角色发布 |
| `td_receive_string` | `src/main.c:313-315` | 转发上述 return 内容，may | 同上；不宣称完整返回污点传播 |
| `_lifecycle_recv_packet` | `src/lifecycle.c:311-325` | 非空 arg1、正容量时可能收到网络内容，may | native 绑定和整数接收返回值的有符号长度规则 |
| `td_receive_message` | `src/main.c:317-319` | 转发上述 arg1 内容与整数结果，may | 同上 |

这些新增条目均保留其他情况 unknown，没有从错误返回推出 no_effect。原有分配条目保持独立。清单从 56 条/53 个不同接口变为 60 条/55 个不同接口，只更新真实新增审阅决定对应的 decisions_digest。共同配置增加 `concurrency.svf_workers: 1`，不改变其他并发项。

实际验证：`tests/test_benchmark_semantics.py` 原有 37 项通过，新增接收回归 4 项通过。在独立、无答案的 Linux 临时副本中，使用真实 CMake/Clang/native 工具构建并重绑定 60 条契约，全部成功，`unresolved=[]`；四个新接收条目各形成 8 个当前 native 变体。未编译 Windows 文件的导航参考不完整仍是既有范围外情况，不是 Linux 契约绑定失败。临时构建已由任务自身清理。

`BASELINE READY` 发出后不再修改共同输入、生产代码或构建产物。以下增强为分析和隔离候选，不声称已被三档 trial 使用。

## 与 Astra 参考清单比较：要区分四层能力和两条识别路径

四层分别是 **schema 能表示、proposal 能提出、manifest 能发布、消费者实际生效**。结构校验通过不证明模型会提出；提出后仍需人工复核及当前 native 重绑；精确发布也不证明每个 carrier 都有完整的规则消费。

两条识别路径分别是：无模型的自动 native 推导（`zscope/semantics/automatic.py`），以及项目原语发现与模型提案（`primitive_discovery.py` / `primitive_contract_proposals.py`）。前者从当前构建已授权 builtin 根推导，故意不以人工 YAML 为种子；资源包装器和严格单调用转发器可以进入机器事实。后者以精确 native 实体调度并产生待审阅效果，模型不能自行 confirmed。任一路径的缺口都不代表函数无效果。

没有运行新的独立发现评测，所以本记录不报告自动发现 recall/precision，也不把标准清单的 self-score 当成自动识别成绩。现有 `semantic_scoring.score_discovery` 已按效果义务区分 matched、invalid_candidate、contract_difference 和 absent_effect；之后的独立发现评测应使用它，且模型输入不能包含参考清单。

## 有代码证据的差距与增强顺序

| 差距 | 当前证据 | 建议实现 | 验收应观察什么 |
|---|---|---|---|
| 局部缓冲中转后的接收来源 | lifecycle 包装器先收进 temp，再 memcpy 到 dst；automatic._forwarder 仅接受一次直接调用、无局部赋值/循环/复杂映射 | 增加受限对象流组合：同一 native 实体的 recv 目的对象 → copy 源 → 调用者目标；追踪别名和覆盖，不按名字猜 | 中转正例、零字节、错误前部分写入、目标重绑定、非网络 memcpy 反例；先比较效果再查候选 |
| 返回分配与返回内容来源被混同 | 两个字符串接口原清单只有 allocator；本次新增独立 recv；memory_bounds_integer 的接收规则只在若干整数返回模式下消费名称角色 | 将返回载体作为真实对象进入现有实例对象/污点传播链，明确分配身份与内容来源两条效果 | caller 把返回指针传给 sink 的端到端正例；NULL、常量内容、返回不同对象和跨构建反例 |
| 复制接口只有主要目的 carrier | `_str_copy_wrapper` 和 `STR_COPY` 只记录目的对象，真实源、容量和有效长度不由该字段完整描述 | 先定义 typed operand mapping，再让编译器、调用映射和边界规则共同使用；容量事实与用户传入上限分开 | 参数重排、宏中的 sizeof(pointer)、零长度、终止符、整数转换及局部复制不能假装安全 |
| 自定义任务创建上下文没有执行映射 | `VOS_TaskCreate` carrier 是 arg2 回调；arg3 仅在 review_reason；async_paths 当前要求受限直接系统 API 与同 TU callback | 显式 callback/context/handle/success 映射，沿真实包装器调用闭合，再接入有界生命周期消费者 | 创建失败、detach 不等于完成、上下文提前释放、回调 target 不明仍 unknown |
| 角色级支持被误读为载体级支持 | `EFFECT_CONSUMERS` 只按 role 列适配器；完整协议、return/argument/global 组合有不同边界 | 提供“可解析/已编译/已发布/具体消费者已验证”的审阅列，附失败原因 | return recv 不显示全绿，未实现 length/context 字段不得显示已覆盖 |
| 自动推导部分成功会隐藏剩余效果 | `derive_automatic_contracts` 的 unit 只要有 accepted 就标 derived，并将 reasons 清空 | 在隔离候选中设计逐 effect obligation 的状态；保留已推导效果与未闭合原因，不让一个 allocator 掩盖 recv 缺口 | 同函数 allocator 成功但 recv 缺失仍明确显示；无证据不制造“必需人工配置”结论 |
| 较复杂转发器可能未进入传递调度 | `_semantics_relevant_scopes` 对传递调用者使用 events≤64、calls≤8；直接可信根调用另有保留 | 为调度排除留下可读原因，后续只在有实际遗漏证据时扩充；不要取消证明边界 | 超阈值包装器显示调度缺口；业务大函数不自动变成 confirmed 接口 |

`primitive_contract_proposals.SYSTEM` 已要求“局部 recv 再 copy 到输出时分别枚举 recv_source 和 copy”，也已区分回调函数和 void* 数据。因此现阶段简单重复提示词不能解决消费链缺口。优先使用现有 object evidence、精确 USR/BuildContext 与失效机制，避免另造全局名字表。

## YAML 审核体验与隔离候选

原清单同时包含人工判定和大量重复 native 变体、长哈希与 YAML 锚点。机器可读，但人很难快速看出“哪个参数、什么条件、哪种强度”，还容易把 `&id`/`*id` 的共享谓词改坏。建议保留唯一 YAML 与现有 round-trip writer，先改善读取，不立即迁移 schema。

本任务已制作只读候选 `candidate/scripts/render_semantics_review.py`：调用正式 schema loader，把条目按文件/接口排列，展示角色、对象、分支、强度、来源、配对和审阅理由；把机器变体缩为计数，保留证据引用；协议、扩展字段和其他顶层内容仍可见。对 return recv、copy 多操作数、callback context、must/no_effect 生成具体核对项。它不写 YAML、不产生收据、不自动确认、不显示“扫描就绪”。

候选还提供 `--reference`：仅在独立发现结束后调用现有评分器，把 matched、invalid_candidate、contract_difference、absent_effect 按每条效果展开；不会把同函数的 allocator 匹配折叠成 recv 也已覆盖。该模式目前仅用合成输入测试，未读取本轮或历史扫描输出，也未报告真实发现召回率。

候选保留在本任务独立目录，未接入生产脚本或 UI。同步提供 `project-semantics-review.md` 填写规范。三档结束后可把此只读投影接入现有原语页面/导出入口；它应复用现有 revision/工程锁，不形成第二个可编辑配置。随后把逐效果诊断接到自动推导报告，再分别处理返回内容传播与 typed operand mapping；高级生命周期支持继续作为独立功能。

## 后续比较标准

独立发现得到新候选后，再由结束后的评分器对照本次来源清单；保留未知新增接口供源码复核，不自动计成错误。比较必须绑定相同输入和角色范围。每项改善同时报告发现是否产生、条件/载体是否正确、是否被消费者使用，不把接口计数当质量指标。

当前基线没有证明接口语义全面覆盖，也没有证明无人工配置即可保持同样发现质量。`automatic.configuration_requirements` 的 `minimum_proven: false` 已明确提醒：机器等价或自动缺口都不足以单独决定删除人工条目，需要实际消费者对照。
