# 17 · 后续开发接手说明

## 当前任务状态

本包 v2.0 已改为专业扫描优先，用户确认允许独立目录自动复现，并选择 Linux 先闭环、之后扩展嵌入式/RTOS。通用 Coding 后置。不要继续执行旧 AG01–AG05“先造通用修复内核”的排期。

用户已授权直接实施；已核对的原始基线见 02/15，最新代码进度、实际测试和未完成消费者见 [21](21_IMPLEMENTATION_STATUS.md)。接手时先读该记录，不重复已完成切片，也不要把整个 S01 标为已完成。

## 最小接手动作

1. 读根 AGENTS.md、docs/architecture.md 和相关 modules，核对 cwd/config/project.root。
2. 看 git status/diff，保留用户未提交与未跟踪内容。HEAD 与旧计划相同也不代表代码相同。
3. 读本包 README、19、11 当前工作包与 16 对应场景；查当前调用方/配置/测试。
4. 复用已有搜索/只读语义、调查、条件契约、ASan/TSan 执行、Wiki 和统一验证，不再开发第二套。
5. 直接实现可运行切片，不做长期基线审计、代码冻结、多级审批或空框架。

本轮未授权自动提交/推送、正式扫描或修改 Range truth；后续任务按用户实际指令执行。

## 首条闭环

先限定一个 Linux 编译目标：pool 获取 → queue 成功转移/失败保留 → complete/cancel 回收 → 候选/义务 → 证据与可选自动复现 → 报告/验收。

S01 把构建/符号/对象身份真正贯穿消费者；S02 扩展现有条件契约；S03/S04 接对象候选与统一验证；S05 接自动计划生成；U01/U02 与 S08 完成使用闭环。不能以创建 schema、写 prompt 或更新状态代替实际行为。

没有兼容性要求，允许更改配置/数据/API 和删除重复路径；所有当前消费者与文档同时修改。保护用户内容、真实证据与可追踪结果，不等于必须保留旧实现。

## 技术易错点

- fast 当前仍有前置语义建模；需求 planner 目前仅 shadow。
- ASan/TSan runner 已有，缺自动 plan/harness/input 生成与默认接入；V01/V02 历史最新状态不是 blocked。
- 多变体 inventory 已有，但 TU 存储仍按文件唯一；添加字段不足以解决串线。
- 外部调查是 offline 意图导入，不是完整外部 Agent 集成。
- 当前动态确认依赖进程内 receipt，恢复不能靠读 JSON 获得确认。
- 锁集反证不能抹掉同锁 UAF；资源泄漏按责任终点，未知调用/长期保留需建模。
- 对象盲探索必须覆盖无候选区域，不能只优化验证已知告警。
- 产品不增加网页访问能力；本地 WebUI 与模型 API 继续作为现有产品组件。

## 验证方法

在 Linux/WSL 环境中使用已安装当前 checkout 的虚拟环境，先相关测试，再按变更风险补真实工具/模型验证。下列为已存在入口，按涉及模块选择：

```bash
python -m pytest -q tests/test_source_search.py tests/test_semantic_cache_only.py tests/test_mcp_read_only.py
python -m pytest -q tests/test_conditional_ownership_contracts.py tests/test_semantic_demand.py
python -m pytest -q tests/test_bounded_investigation.py tests/test_investigation_runtime.py
python -m pytest -q tests/test_dynamic_reproduction.py
python -m pytest -q tests/test_agent_docs.py
python -m compileall -f -q zscope scripts test tests
python -m mypy zscope
```

真实 sanitizer 验收按可用 Linux 工具链执行对应 execution 测试，报告 skipped 和平台条件；Fake runner 通过不代表真实运行。正式 unified benchmark 另读 range 协议、确认完整工具链与答案隔离，不以本地单测冒充。

无需每次小改动重跑正式发布矩阵；新增检测逻辑须同步规则目录、revision、CWE/Skill 和正反例，disabled_ids 不能抑制 backend/LLM 独立信号。

## 文档维护

| 改动 | 同步文档 |
|---|---|
| 用户行为/配置/路径/CLI | README、语言模板、init、配置字段说明 |
| 构建/身份/缓存 | retrieval-backends、configuration-state、architecture |
| 候选/义务/见证/四态 | analysis-pipeline、interfaces-reporting、相关 Skill |
| 任务调度/夜间/恢复 | execution-orchestration、agent-runtime、用户说明 |
| 项目模型/Wiki/反馈 | configuration-state、wiki、review-memory |
| 顶层新包 | modules/README 及唯一 covers 所有者，根 AGENTS 导航 |
| 计划决策或包完成 | 本包对应章节，实际结果单列，不倒写历史记录 |

Markdown 用 UTF-8 无 BOM、LF、末尾换行；改交接文档跑 test_agent_docs。运行时 AGENT 不当开发交接文档修改。

## 简短交付格式

问题与新行为；复用/改动；真实测试结果；源码/构建/模型与未测范围；文档更新；一个明确的后续步骤。常规动作自主完成，方向与业务目标出现真正分歧时再问用户。
