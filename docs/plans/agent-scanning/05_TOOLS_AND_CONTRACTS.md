# 05 · 工具、执行与错误合同

## 已有六工具直接复用

| 工具 | 现有能力与限制 |
|---|---|
| search_code | symbols/text/files，版本绑定与分页；文本命中不是数据流证明 |
| read_code | symbol_id 或文件行范围、源码版本/续读；不推断调用关系 |
| get_semantic_context | cache_only 或 ensure_current；前者不刷新，后者可能建模/写快照；freshness 不足仍不可标 current |
| query_code_graph | 精确身份的图查询，缺后端事实返回能力缺口 |
| trace_data_flow | 流/路径证据；may/unknown 不可直接确认同一对象 |
| query_static_findings | 已有信号和候选；盲发现输入不提供已有结论 |

名称可在后续统一时更改，不承担历史客户端兼容；但当前调用方、schema、MCP、Prompt、测试须同一变更更新。不为了改名制造重复工具。

## 按需求补专业接口

以下是拟实现逻辑接口，先作为内部服务，由任务需要决定是否暴露为独立模型工具：

| 接口 | 输入 → 输出 | 落地 |
|---|---|---|
| query_object_events | build/object/scope → 获取、转移、访问、回收、共享事件及缺口 | S01/S03 |
| query_protocol | 资源族/接口/条件 → 已发布契约、案例、来源与冲突 | S02 |
| get_lifecycle_slice | candidate/obligation → 数据、控制、别名、并发干扰切片 | S03/S04 |
| resolve_evidence_gap | 未闭合义务 → 对应 fact provider 结果 | S04 |
| prepare_reproduction | candidate/build/test profile → harness、输入、命令和适用条件 | S05 |
| run_reproduction | 有效计划 → 执行记录、匹配 witness 或未决原因 | S05，复用现有 runner |
| diagnose_backend | 失败阶段/目标 → 原因、可修配置、缺少能力 | S01/U01 |
| query_project_knowledge | 主题/范围 → Wiki 原文、契约、冲突、经验提示 | 复用现有 Wiki 门面 |
| job_status / cancel / resume | job ID → 当前状态或控制结果 | S08 |
| propose_question | 业务缺口 → 去重的验收问题及受影响范围 | U02 |

扫描角色无需任意业务源码补丁工具。Q01/Q02 后置提供 apply_patch、run_command、manage_process、read_artifact；复现阶段只生成独立测试资产。**无 web_search、fetch_url、browser 等接口，也不使用命令工具代做网页访问。**

## 一致结果语义

优先复用现有 `success/status/data/coverage/page/warnings/next_actions/error` 信封。大对象返回引用和首屏；状态、来源、依赖与未知原因不能在投影中丢失。

“工具成功取得退出码 2”可以是工具成功、命令失败；“复现得到预期 ASan 报告”可以是执行非零、复现成功；“无结果”可能是没有命中、未解析、不支持或超时，必须分别表达。

最低错误类：invalid_arguments、not_found、unavailable、unsupported、conflict、timeout、cancelled、unknown_outcome、internal_error。原方案的 approval_required 续接平台不再建设。

## 参数与身份

schema 和跨字段条件程序校验；provider strict 不能替代本地验证。symbol/object/build/candidate ID 使用实际返回值，模型不拼 ID。来源位置、对象代际、构建目标和条件要传递到下游，不能只靠同文件同行匹配。

执行输入优先 argv、cwd、环境 profile、timeout；必要脚本明确记录。原始命令、退出码、真实日志与二进制身份由执行器生成，模型不得填写“已通过”。

## 批处理与去重

独立读可并行，同一对象/版本重复查询共享缓存；有因果依赖的查询等待前序结果。编译后运行、补丁后重测、语义发布后候选重算保持顺序。相同 operation ID 查询既有状态，不因传输丢包重复启动进程。

工具是否有效，以缺口是否被解决、是否减少错误结论和重复成本评价，不以工具数目评价。
