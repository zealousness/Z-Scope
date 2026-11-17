# pthread 回调寿命与等待

[返回根入口](../../../AGENTS.md) · pthread、异步队列、等待/唤醒/时钟、cleanup、helper 或 drain 变化时读取。

同时遵循[对象协议的验收与业务反馈](../protocols/AGENTS.md#验收与业务反馈)及[构建身份](../build-identity/AGENTS.md)。

## 回调与工作者路径

按本次受影响的行为选择下表中的用例或模块，不默认每次跑全部 17 个文件。共同 CFG、对象身份或等待/取消合同变化时，再覆盖受影响的相邻行为与对象路径/反馈/构建回归；仅改 helper 文档不触发时钟、队列等全套验收。

| 改动涉及 | 回归入口 |
|---|---|
| 共同契约、路径或增量身份 | `tests/test_async_contracts.py`、`tests/test_async_paths.py`、`tests/test_async_incremental.py` |
| 队列 | `tests/test_async_queue.py`、`tests/test_async_queue_incremental.py` |
| 等待 | `tests/test_async_wait.py`、`tests/test_async_wait_incremental.py` |
| cleanup | `tests/test_async_cleanup.py`、`tests/test_async_cleanup_incremental.py` |
| helper | `tests/test_async_helpers.py`、`tests/test_async_helpers_incremental.py` |
| 无通知唤醒 | `tests/test_async_wake.py`、`tests/test_async_wake_incremental.py` |
| 时钟与超时 | `tests/test_async_clock.py`、`tests/test_async_clock_incremental.py` |
| 调用方 drain | `tests/test_async_drain.py`、`tests/test_async_drain_incremental.py` |

当前解释 Linux glibc LP64、同 TU、直接系统 API、默认属性的一个工作者与 malloc/calloc 对象；单槽队列可在调用方首次 unlock 后推进工作者到其首次 unlock，保留局部任务引用，随后在 join 期间继续。实际同 TU 调用方 helper 的字段写入/返回守卫决定提交、取消和停止接收效果，不按名称授予 drain。只有成功 join 与真实回调退出才闭合该等待；同锁不能消除 UAF，清空槽位不撤销已取走的对象代次。`pthread-storage.v1` 限定当前系统声明的 opaque mutex/cond 字段，不解释 libc union，改 native 后先实际重建。单等待者 cond_wait 先释放精确 mutex，匹配当前条件变量实例的通知后才重获锁并发布返回值，再由实际 CFG 重检条件。提前通知不存额度，通知不等于完成，UAF 记录实际解锁/通知/join 恢复位置。默认延迟取消仅支持 cond_wait/testcancel 和最多四层的同 TU C/glibc cleanup，重获等待锁后才 LIFO 执行注册时保存的对象；取消不返回到被中断调用，pop(0)/pop(1) 分开。`pthread-cleanup.v1` 同时核对当前系统宏和展开 AST，保持原始 CFG；原样工具也不能用缺失收据授权。改写宏、异常/C++ 变体、控制跳出和 cleanup 内任意 helper/取消点保持缺口。新增 `PthreadCleanup.h` 参与 portable 批量组件指纹。同一 C 源文件和精确构建中的工作者直接 helper 可保留有界调用帧，参数/返回值只接受已知堆根指针、空值和受限整数；unlock/cond_wait 暂停期间不发布返回值，重复调用隔离局部帧，取消按注册帧归属执行清理且不伪造 helper 返回。递归、局部/字段地址传递或返回、间接目标、cleanup 内 helper 保留缺口；物理 free 仍核对实际标准根与对象代次。未覆盖唤醒序列、一般超时/时钟、调用方超时/无通知等待、取消模式切换/任意取消点、一般工作者 helper、未知锁属性、不同锁下共享访问、多工作者、动态目标和跨 TU 异步保留缺口。默认通知路径未闭合时可额外尝试一次无通知唤醒与一次独立的 timedwait 超时路径，单条路径最多一次无通知返回。`pthread-wait.v3` 核对当前系统 timespec 的 64-bit 字段、16-byte 大小/8-byte 对齐/0 与 64-bit 字段偏移、本地截止时间和直接系统 ETIMEDOUT 宏；timedwait 使用默认 CLOCK_REALTIME，clockwait 只接受直接系统 CLOCK_REALTIME/CLOCK_MONOTONIC 常量并核对宏出处及当前数值；返回 0 不证明时间早于截止，返回前必须重获原 mutex，普通返回发布 0、超时发布核验常量并执行当前 CFG。取消优先且不伪造返回；完整探索后再次核验源码和 Registry 当前性。修改 native 后实际重建，旧工具不能授权此切片。循环与调度有界，只覆盖成功分配/创建/同步及上述有界等待结果的选定路径，首次非法访问即停止，无观察不证明安全。默认关闭的 `object_protocol_path` 复用 S04 重放和集中业务验收；helper/回调/根契约/构建/回答变化撤回旧见证，局部冷/热对照不代表全扫描或完整 RAPI09/RAPI10 完成。

## 调用方 cond_wait 与 drain

调用方 cond_wait 的受限 drain 复用现有同 TU 队列解释器：释放精确 mutex 后推进工作者至真实通知及原锁释放，返回前重获锁并执行当前谓词 CFG；最多四次调用方等待，只有实际进入等待的调用帧获得有界循环重检。相同条件变量同时绑定不同 mutex 保持缺口；通知、清空 active 或等待返回不设置 worker complete/joined，也不授权销毁队列。调度调用路径必须保留入口到调用方 helper 的边及工作者活动帧；cleanup 根注册帧按实际调度前缀深度展开。调用方超时、无通知返回、取消与多工作者仍未支持，实验规则默认关闭；新增/删改谓词、通知、回调、根契约与释放次序沿原 S04/增量链复核。
