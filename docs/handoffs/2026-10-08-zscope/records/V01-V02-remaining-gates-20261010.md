# V01/V02 剩余门禁核对 — 2026-10-10

结论：四项漂移修复和已验收 ASAN 结果保持通过。V01 仍有两个资源边界实现缺口；V02 的所选 TSAN 真实验收被运行时启动错误阻塞。本轮不修改产品，不发送新 DeepSeek 请求。

## 原始范围与必须项

| 门禁 | 必须性与结果 |
| --- | --- |
| V01 绑定源码/候选/build/toolchain/harness/input 的计划、独立 runner、日志、重放、原统一裁决 | 必须；已在获准 fixture 范围通过，普通1715 passed、隔离 ASAN 5 passed |
| V01 资源限制 | 必须；构建内存和输出捕获边界未闭合，见下文 RG01/RG02 |
| 真实 TSAN 正反例及语义资格 | 所选 V02 分支必须；本轮真实 fixture 未执行，保持 blocked/not_run |
| 实际隔离授权与如实记录 | 必须；本轮实际边界核验全通过，产品 subprocess 仍如实记为 process |
| 自动计划/harness/输入生成器 | 原 V01 最小闭环没有明确要求自动生成；已提供的计划/harness/input 必须有效。自动生成及序列化请求是尚未交付的后续能力限制 |
| CBMC、正式 Range、未知项目脚本、第三方工程、性能收益、原生 Windows | 不新增为此 TSAN 路线的完成门禁；不得宣称这些已执行 |

依据：原 [V01/V02工作包](../WORK_PACKAGES.md)、[验收协议](../ACCEPTANCE.md)、[HANDOFF 4.5](../HANDOFF.md)。完整逐项矩阵与行号快照见 [gate-matrix.json](V01-V02-remaining-gates-20261010/gate-matrix.json)、[original-standard-snapshots.json](V01-V02-remaining-gates-20261010/original-standard-snapshots.json)。G1/G2/G3 是后续记录的专项、集成和真实执行简称，不能借此增加原标准没有的功能要求。

## TSAN 观测

固定已有镜像与原 ASAN 边界：断网、非 root、只读根/输入、全部 capabilities dropped、no-new-privileges、seccomp、pids256、memory2GiB、cpu2、tmpfs512MiB。全部检查通过，406输入前后摘要相同。没有安装、下载、改 ASLR/内核/权限/安全设置。

首先运行产品 availability() 自带的无缺陷 int main(void){return 0;} 探针，编译/运行均 exit0。随后两项已批准最小用例的前置无缺陷探针均编译成功、运行 exit66：

```text
FATAL: ThreadSanitizer: unexpected memory mapping 0x5d75a42a8000-0x5d75a42a9000
FATAL: ThreadSanitizer: unexpected memory mapping 0x7424b6d72000-0x7424b7200000
```

合计只运行3个无缺陷探针；0个线程 fixture 编译、0个 fixture 执行、0次真实线程 witness/replay。pytest为0passed/0failed/2skipped、exit0；这个退出码不代表验收通过。没有继续重试或运行 flaky/压力组。原始日志和退出码见 [TSAN运行时补充](V01-V02-remaining-gates-20261010/TSAN-runtime-addendum.json)；wrapper原始TSAN=executed仅表示探针运行，不代表fixture执行。首轮证据脚本清单KeyError发生在容器启动前，旧记录也保留。

## 当前源码资源缺口

源码摘要：511c33409b4f9abf283c7a9c8719cff21c2f6c79101e2f121d746064d3487e0e。

- **RG01 / 构建内存未限制**：build 的 _run_once()调用明确 address_space_limit_mb=0，未传 rss_limit_mb（默认0）。因此两条产品内存约束都未启用；外层容器2GiB不能代替产品实现。证据为 dynamic_reproduction.py:2254及:2588。
- **RG02 / 输出捕获不是硬上限**：stdout/stderr直接写文件；_spool_within_cap只轮询文件大小并杀进程，不能阻止写入超限；process.poll退出判断先于大小检查。_read_output对整个文件hash，只有excerpt读取受限。已有超限保持未决测试通过，不能证明spool实际字节有硬上限。证据为:2632、:2651、:2705、:2750。

这是静态源码结论，未做新的内存或输出压力复现。run RSS看门狗已实现且如实声明采样式边界；test_rss_watchdog_records_and_kills_a_memory_hog在重型execution文件，**不在普通126项**中，不能错误借用1715计数声称已独立验收。详见 [静态证据](V01-V02-remaining-gates-20261010/static-resource-findings.json)。原标准要求资源约束，这两项是此前F06/R06的未闭合部分，不是新增架构需求。原文并不要求产品自行提供容器架构，也没有要求58次flaky测试。

## 最小下一步与安全边界

1. 父端先确认扩大普通返修材料范围到RG01/RG02的必要源码片段、原文、测试/日志；确认后才可向同一已有DeepSeek harness提交。本轮没有发送新材料。
2. 修复资源约束并用小规模有界无缺陷数据独立验证，保留正例、反例、漂移、取消和信任规则；不做压力组。
3. TSAN须在另一个已存在且重新核验同等批准边界的可运行环境验收，或继续blocked；不得从本错误推断ASAN/TSAN本身禁止，也不得改ASLR或安全条件取得通过。
4. 父端统一更正TASKS/PROGRESS旧阻碍口径：真实TSAN是V02门禁，不是V01依赖；自动生成器和CBMC是能力限制。状态暂仍V01=in_progress（资源项）、V02=blocked（依赖V01及真实TSAN）。本轮未改共享状态文件。

原任务历史拦截只留下风险中止、无具体被禁止命令/明细；本错误是有完整stderr的本地运行时失败，和cloud region4读取路由错误分开记录。本轮正式工具审批均通过，没有安全拒绝。没有读取凭据，没有访问被拒绝路径，没有Git操作。当前无新模型请求，本轮容器已清理。
