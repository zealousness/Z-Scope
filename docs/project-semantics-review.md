# 自定义接口清单填写与审阅规范

`project.semantics_file` 指向的 `zscope.semantics.yaml` 是唯一人工语义配置。主配置使用 `config_version: 3`；语义文件使用 `schema_version: zscope.project-semantics.v1`，两个版本号属于不同文件，不能互换。审阅表、Markdown 导出和发现证据都是辅助材料，不是第二份可执行配置。

本规范适用于用户与协助填写的 Agent。目标是把“某个精确接口，在什么条件下，可能或必然影响哪个对象”写清楚，不以接口名字数量、YAML 能解析或全部标为 confirmed 代表完整覆盖。

## 填写前先确定对象与边界

先读函数实现、声明、被调者和调用方式；名称或注释只能提供线索。确认目标平台、编译目标和实际编译数据库，尤其注意宏、同名静态函数和不同构建变体。

每条契约先用一句话描述：

> 在条件 G 下，接口 F 对调用者可见的对象 O 产生效果 E；强度为 may / must_under_guard；其余情况未知或另有已证明的分支。

把分配、接收、复制、关闭、回调登记分别检查。一个接收函数可能同时返回新分配的内存和网络内容；分配契约不会自动提供输入来源契约。相反，普通参数被 memcpy 复制不等于它来自网络。临时分配、函数内部配对完成的锁和借用地址也不自动变成对外所有权。

## 用户字段与机器字段

| 字段 | 应检查的内容 | 维护方式 |
|---|---|---|
| `id` | 稳定且唯一，便于 review 和来源引用 | 保留生成 ID；人工添加时避免重名 |
| `primitive` / `basis` | 是否是人工声明的项目根；是外部假设还是已读实现的包装器 | 不为绕过检查把包装器改成根原语 |
| `selector` | kind、name、file、signature、USR 精确对应同一个实体 | 以当前 native 识别为准，不能凭同名合并 |
| `cases` / `otherwise` | 守卫与效果成立、无效果、未知的关系 | 人工按成功、失败、部分效果逐条核对 |
| `effects` | role、carrier、strength、资源族、前提及受支持 protocol | 按实际消费者能力填写 |
| `pairs` | 释放接口确实接受同种对象与资源族 | 不是“名字看起来成对” |
| `derived_from` | 包装器直接调用的已复核来源 | 普通包装器需要真实直接调用边 |
| `review_reason` | 实现位置、对象流、失败边界、未作出的保证 | 写简短可复查的证据，不写置信度口号 |
| `status` | pending / confirmed / rejected / stale | 有未决问题就保留 pending，不批量伪确认 |
| `variants`、构建 ID、证据哈希、`evidence_ref`、收据 | 当前构建身份与失效判断 | 由 discovery / 重新绑定生成；不要手工编造 |

`expected_contract` 是模型可提出的假设，不是自动证明；`external_model` 是明确人工外部假设，不应伪装成已读实现。`review_reason` 中提到的参数关系不会自动编译成可执行效果。接口扩展字段能被保留也不代表消费者使用它。

## 对象路径：最容易填错的部分

参数编号从 **0** 开始。`phase: pre` 指调用前的对象，`phase: post` 指返回或发布后的对象。`dereference` 是额外的指针加载，不是“这是一个指针参数”标记。

| C 接口中的含义 | carrier 示例 | 不要混淆 |
|---|---|---|
| `char *dst` 指向的既有缓冲区 | `root: argument, index: 1, phase: pre, dereference: 0` | 不额外写 dereference: 1 |
| 返回新分配指针 | `root: return, phase: post, dereference: 0` | 不把状态码当资源 |
| `void **out` 发布新指针 | `root: argument, index: 2, phase: post, dereference: 1` | `out` 槽与 `*out` 对象不同 |
| 返回结构中的成员 | `root: return, phase: post, members: [payload]` | 同时检查父指针与成员非空 |
| 全局锁对象 | `root: global, name: g_lock`，按实际语义保留 address_of | 全局对象地址和值不相同 |

对象阶段、取地址、成员和指针偏移必须与实际代码一致。当前格式不能忠实表示的内部偏移、动态索引或复杂对象关系应记录为边界，不能退化成根指针来“凑齐覆盖”。

## 条件、强度与失败路径

`pending` 表示尚待审阅，`may` 表示效果可能发生；它们不是同一维度。`confirmed + may` 可以是正确且保守的已审阅声明。

- `applies + may`：守卫满足时，效果可能发生，不保证字节数、成功次数或已完全初始化。
- `applies + must_under_guard`：每条满足守卫的支持路径都产生该效果。必须检查提前返回、分配失败、零长度及下层调用失败。
- `no_effect`：该分支确实不产生本条效果，是独立声明。负返回值之前可能已经读写了一部分数据，不能直接写 no_effect。
- `otherwise: unknown`：其他情况仍未知。未填写的失败行为不会自动变成安全。

条件必须用结构化谓词和可观察的参数/返回/支持的全局量表达；不要把局部变量、函数调用、sizeof 或任意算术字符串放进守卫。布尔操作符写字符串 `op: 'true'`，不能让 YAML 解析成布尔 `true`。存在相反效果的重叠条件时不能靠顺序决定哪条优先。

以下只是 `interfaces` 中的一条 **pending 行片段**，不是可直接扫描的完整配置。它描述 `int receive_packet(int fd, char *dst, size_t capacity)` 的可能输出来源，不保证完整接收、容量足够或错误后无写入：

```yaml
- id: project:receive_packet:recv
  primitive: false
  basis: derived_wrapper
  status: pending
  selector:
    kind: function
    name: receive_packet
    file: src/io.c
    signature: int (int, char *, unsigned long)
  cases:
    - when:
        op: all
        items:
          - op: compare
            left: {kind: argument, index: 1}
            operator: '!='
            right: {kind: literal, value: null}
          - op: compare
            left: {kind: argument, index: 2}
            operator: '>'
            right: {kind: literal, value: 0}
      effect: applies
  effects:
    - domain: taint
      role: recv_source
      operation: recv_source
      carrier: {root: argument, index: 1, phase: pre, dereference: 0, members: []}
      strength: may
      resource_family: ''
      protocol: {}
  otherwise: unknown
  pairs: []
  derived_from: [builtin:recv]
  review_reason: '待核查 src/io.c 的直接 recv 调用及写入对象；失败后的部分效果未知。'
  variants: []
```

示例的签名来自 Linux LP64，必须换成项目实际 native 签名；只有真实直接调用 recv 才能保留这条 derived_from。发现后由程序补充精确 USR 与变体，再核对语义，不要复制示例身份作为证据。

## 必须按角色单独检查的内容

| 角色 | 审阅问题 | 常见错误 |
|---|---|---|
| allocator / calloc / reallocator | 新所有权的对象、NULL 失败、旧对象是否保留、释放端 | 把借用、内部指针或状态整数当新分配 |
| deallocator / io_release | 消费的是哪一代对象；底层结果是否被丢弃 | 包装器固定返回 0 就认定必然关闭 |
| lock / unlock | 同一锁实例、共享/独占、成功条件、释放与重获 | 用读锁声明写保护；未知状态当成功 |
| recv_source | 来源确实是输入根；载体是出参还是返回对象 | 只有 allocator；或把普通 memcpy 当网络接收 |
| copy | 目的对象、实际源、长度、容量分别有哪些事实 | 只有目的 carrier 却声称完整边界约束 |
| callback_register | 函数指针位置、上下文位置、异步时机与生命周期 | 把 void* 数据当回调；把 detach 当完成 |

能力还要分四层核实：**schema 能表示 → proposal 能提出 → manifest 能发布 → 消费者实际生效**。第三层包含契约编译保留及当前 BuildContext/USR 发布；第二层需用独立发现验证，不能用手填清单代替。`EFFECT_CONSUMERS` 是角色级目录，不是每种 carrier / protocol 的完整支持证明。尤其是返回缓冲区 recv、复制多操作数关系、自定义线程包装器上下文，不应仅因角色存在就宣称覆盖。

## 用户或 Agent 的逐条检查流程

1. 记录实际主配置路径、工程根、平台、目标和语义文件路径；确认读的是待扫描版本。
2. 从源代码列出调用者可观察效果，同时列出“没有该效果”的反例：借用查询、空释放、内部偏移返回等。
3. 对每条效果核对精确实体、对象、守卫、强度、失败路径、资源族和来源边。不同条件或不同释放关系的效果用独立条目更容易审阅。
4. 对照实际编译器和消费者判断支持到哪层。不支持的声明写入 review_reason/开发差距记录；不要添加自创 executable 字段假装已经支持。
5. 通过项目正式 discovery 工作流生成/刷新机器证据。逐条确认或拒绝，保留理由；源码或构建变化后按 stale/重新发现提示处理。
6. 用正常只读 review 命令核对状态；只有实际审阅完成后才执行完成审阅操作。

```bash
zscope --config /absolute/project/zscope.yaml --discover-primitives
zscope-config review-semantics --config /absolute/project/zscope.yaml --json
# 人工核对并完成决定后，再记录审阅完成：
zscope-config review-semantics --config /absolute/project/zscope.yaml --complete
```

discovery 会调用模型并写入原语准备材料，应在项目准备阶段执行；正常扫描只读消费。不要在正在运行的基线共用输入上执行 discovery、完成审阅或编辑 YAML。不要用 `--declare-none` 隐藏已知自定义接口。

Agent 的交付应写清：检查了哪些实体和失败路径、每项实际消费到哪层、哪些仍 unknown、实际运行了哪些检查。不得仅输出“配置完整”或把未运行的发现准确率称为通过。

## Range 的额外约束

Range 的 `benchmark_review.sources` 绑定源文件原始字节，`decisions_digest` 绑定审阅决定，`scope_digest` 绑定范围及反例。换行差异要恢复受支持的 LF 输入；不能改 source 摘要绕过失配。真实改变审阅效果后才重算对应的决定摘要，并保留范围边界。每轮隔离工程仍需从真实 native 构建重新绑定，不能复用另一目录的构建收据。

首版清单包含保守接收角色，不包含完整复制长度关系、自定义异步上下文或所有函数指针绑定。三档基线比较的是这个共同支持范围；清单自比得分为 1 只证明评分器能识别相同输入，不是自动识别系统的召回率。

关联实现：[语义配置与编译](../zscope/config/project_semantics.py)、[自动 native 推导](../zscope/semantics/automatic.py)、[项目原语发现](../zscope/orchestration/primitive_discovery.py)、[配置模块说明](modules/configuration-state.md)。
