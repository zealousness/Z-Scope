# Native 与对象协议

[返回根入口](../../../AGENTS.md) · 资源包装器、留存槽位、生命周期/对象路径、业务验收与反馈、跨 TU、引用计数、句柄、锁、RAII 或协议增量变化时读取命中章节。

按本次改动读取下面对应章节；对象路径相关改动同时读取“验收与业务反馈”，涉及构建/缓存/反馈再读[构建身份](../build-identity/AGENTS.md)。pthread 专题在[独立文件](../pthread/AGENTS.md)。

下列测试是按子域组织的回归入口，选择实际受影响的用例/模块，不因出现“现有回归”就全跑所有协议。改动公共解释器、事实模型或验证合同后，按具体消费者扩大覆盖。native 提取或 ABI/收据语义变更仍须重建对应工具并跑真实正反例；纯 Python、文档或未改变 native 输入的改动不默认触发全工具链重建。源码/契约摘要用于判定证据当前性，不冻结开发工作区。

| 改动涉及 | 章节 |
|---|---|
| 条件资源与对象路径 | [条件资源与对象路径](#条件资源与对象路径) |
| 验收与业务反馈 | [验收与业务反馈](#验收与业务反馈) |
| 资源包装器 | [资源包装器](#资源包装器) |
| 跨 TU 对象路径 | [跨 TU 对象路径](#跨-tu-对象路径) |
| 引用计数与池状态 | [引用计数与池状态](#引用计数与池状态) |
| 句柄 | [句柄](#句柄) |
| 锁模式与反证 | [锁模式与反证](#锁模式与反证) |
| 有限 RAII | [有限 RAII](#有限-raii) |
| 协议增量 | [协议增量](#协议增量) |

## 条件资源与对象路径

- 条件资源协议维护时区分引用留存、清理责任和逻辑池归还。单槽协议的源码核验依赖当前 native 资源事实收据；修改 `native/clang-indexer/ProgramEvents.h` 后先重建再运行真实 native 正反例，不能用旧工具或仅合成事件宣布通过。相关入口和测试见配置/状态模块文档。

- 槽位归还路径回归见 `tests/test_retained_slot_teardown.py`。本地摘除只描述槽位值，不能证明归还 guard 成立、代次一致或跨 complete/cancel 安全；未闭合义务必须传到 Validator。新增规则 `zscope.c_cpp.cpp_clang_cfg.retained_slot_release` 仍为实验性、默认关闭，不把显式启用实验的候选结果写成正式准确率。

- 同 TU 对象路径回归见 `tests/test_lifecycle_paths.py`。`object_protocol_path` 使用 native CFG 入口/出口和 `lifecycle-value-facts.v1`，按真实调用帧、参数、字段、池实例及获取代次解释具体路径；没有入口输入、未知调用、循环或未支持的类型转换时保留缺口。获取代次复用 `ObjectRef`，不等于业务计数器永不回绕。源码留存和实际清理路径不能代替业务释放规范；业务责任、责任终点的专门义务不能被普通补证或模型高分关闭。该规则同样实验性、默认关闭。

## 验收与业务反馈

- S04 对象协议验收见 `tests/test_protocol_assessment.py`。Validator 使用当前 native 事实和运行时契约注册表重放路径，绑定源码/契约摘要后才投影 `business_conditional`；技术缺口、失效或未核验路径投影 `protocol_pending`。两者仍属于统一 `needs_review`。业务前提标记为分析提出的未确认要求，源码效果不代表业务规范，入口退出不自动成为责任终点。报告载入不能复用进程内重放收据，关闭模型也需重放；不要用序列化字段、模型高分或删除缺口清单授权确认。问题集中在报告验收，不新增扫描中途交互。

- 业务前提反馈见 `tests/test_protocol_feedback.py` 和 `tests/test_protocol_review_ui.py`。Web 验收页只对服务端报告中的具体前提写入项目现有 `user_config.state.db`，保留来源、精确对象/构建/路径范围与回答版本历史，不写 suppression/baseline。全部前提明确成立且当前技术路径完整时，由专门程序检查器签发限定范围的确认；否定或撤销前提不等于代码安全。修改回答后，下次扫描按依赖重新验证并重新登记候选台账；扫描中修改也需重核验。前端草稿、版本冲突和迟到响应必须有回归，不能把普通报告导入或模型文本当业务回答来源。

## 资源包装器

资源包装器 native 核验的相关回归入口为 `tests/test_native_wrapper_inference.py`、`tests/test_resource_inference_coverage.py` 和 `tests/test_native_model_cache.py`；真实提取测试需在 Linux 设置 `Z_SCOPE_TEST_CLANG_INDEXER` 指向实际构建的批量工具。合成事实只验证隔离逻辑，不能代替 native 验收；缺收据或源码/CFG 冲突不能回退弱路径授权。覆盖诊断区分契约核验、消费者能力和规则实际执行，不能将入口外未测量 cleanup 或实验规则关闭解释为安全。

## 跨 TU 对象路径

跨 TU 对象路径的相关回归入口为 `tests/test_link_targets.py`、`tests/test_linked_lifecycle_paths.py` 及现有 lifecycle/protocol 回归。链接归属来自 `zscope-link-record` 实际重建并链接的记录，不来自 compile_commands、文件名或相同 BuildContext。native 签名/const ops 收据改动必须重编译真实工具后验收；各 TU 保留自身身份，未知目标/选择不可推广为全部清理，实验规则仍默认关闭。准备命令会重建所列对象，普通扫描只读记录。

## 引用计数与池状态

引用计数及池状态的相关回归入口为 `tests/test_refcount_protocols.py`、`tests/test_refcount_integration.py` 和现有单槽池/路径/反馈回归。首批是 signed 32-bit 非原子计数，发布为 `standard_operation`，不能加入 deallocator 配对；零计数的 callback 必须实际重放到对应对象，逻辑归还不是物理 free。非并发执行前提独立进入验收及回答撤回链，默认实验开关不变；位宽、位域或 volatile/atomic 写入事实变化需实际重建 native 工具。

## 句柄

句柄子域的相关回归入口为 `tests/test_handle_protocols.py`、`tests/test_handle_integration.py` 及现有 native/路径/反馈回归。当前为源码核验的 2–4 槽 signed 32-bit 自定义表；描述符代次、整数值和 dup 共享的底层对象分开，close 错误的状态不替代实际消费效果。标准 close 错误保持 unknown；此子域不模拟 OS fd/dup2。命名空间顺序独占与业务责任在验收阶段核实，回答撤销必须重开缺口；实验规则默认关闭。调用结果和局部写入的 native 类型事实改动须实际重建工具。

## 锁模式与反证

锁模式或锁反证的相关回归入口为 `tests/test_lock_modes.py`、`tests/test_lock_coverage.py`、现有 review fact/契约/候选及规则治理测试。shared/exclusive/unknown 和成功条件必须随契约、转换及调用事件保留；读锁不能过滤写入候选，未知解锁及 cond_wait 不能遗留旧保护。强反证仅限当前编译事实中非逃逸 TU-static 锁与受限访问，透明 return 包装器需重新核对当前 AST；递归计数、升级、成员锁、任意辅助调用及 RAII 未支持时保持 unknown。调用方词法摘要只作上下文，不能授予强反证；实验规则默认关闭。

## 有限 RAII

有限 RAII 的相关回归入口为 `tests/test_raii_lifecycle.py` 及现有 lifecycle/review/native/构建身份回归。当前只核验单指针成员的局部 scoped heap guard：构造映射、真实析构与受限 custom deleter 都重新读取当前 AST，并与 native 构造/析构 USR、源码位置及精确 BuildContext 核对。正常退出与函数内明确 throw→catch(...) 的展开分别解释；未知异常、move/adopt/defer/release/reset、逃逸和锁 guard 保留缺口。`implicit_release` 标签和源码注解不授权 free/unlock；不把 guard 加入全局 deallocator 配对。native 生命周期事实变化必须实际重编译；实验规则默认关闭。

## 协议增量

当前协议增量的相关回归入口为 `tests/test_protocol_incremental_equivalence.py`、`tests/test_native_model_cache.py`、`tests/test_build_context.py` 及既有链接/协议反馈回归。头文件不存在、较高优先级查找及新增静态访问者也属于依赖；旧 depfile 不能证明这些否定前提仍成立。Review 热路径复核实际预处理输出后复用 AST/CFG，进程内收据同时检查当前契约版本；磁盘 JSON 不授权执行保存的命令。native `include-probes.v1` 记录存在性查询，独立于真正读取文件的摘要；查询结果进入 BuildContext，在发布/复用/消费前核对，新增或消失的文件必须失效。真实 native 改动先重建；本地受限对照不代表完整扫描、异步回调或需求调度已验收。
