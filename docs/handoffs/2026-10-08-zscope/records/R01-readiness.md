# R01 启动条件审查

## 结论

**建议任务状态：deferred。** 本轮仅完成只读启动条件审查，没有启动增量 SVF 原型。现有证据不足以确认获准实际工程的主要耗时来自 WPA／指针分析，因此不能据此判断增量 SVF 的适用性或收益。此结论不是对增量算法无效的判断。

## 基本信息

| 字段 | 实际值 |
|---|---|
| 日期／时区 | 2026-10-08 / Asia/Taipei |
| 执行者／所有者 | Agent B / topology_ownership |
| 开始 HEAD／结束 HEAD | `010f40210b54ba0f79a088312ce5d8be3a82ace0`，未创建提交 |
| branch | `v1.3.1_feat/llm-wiki` |
| 工作区 | 保留原有及本轮各 owner 修改，基线见 `parallel-G0.json`；本审查仅新增本记录 |
| cwd | `C:/Users/10273/home/work/Z-Scope_1.31/Z-Scope` |
| 配置／project.root | N/A，未启动扫描或读取用户工程配置 |
| implementation_status | not_started |
| verification_status | not_run；readiness 已审查 |

## 已有证据与缺口

- [P01 八类差分](P01-native-replay.json)验证选定小型 Clang fixture 的增量／干净重建事实一致性；范围不包含 SVF 指向集和完整值流等价。
- [P01 五次隔离采样](P01-isolated-sampling.json)仅测量 `function_body`、3 个 TU、1 个 worker。其阶段指标没有 WPA/Saber 阶段，不能证明真实工程 WPA 是瓶颈。
- [LLVM／SVF preflight](P01-llvm-preflight.json)与[兼容 smoke](P01-llvm-execution.json)证明现有工具链在限定环境下可运行。小 fixture 的一次真实执行是兼容性证据，不是隔离性能实验，也没有真实工程价值评估。
- 尚无明确授权实际工程的阶段耗时、工作负载特征、实际分析配置及主要成本占比记录；尚未完成候选算法的版本、许可证、构建与删除传播适用性核对。

P01 已由总控通过集成门禁，不等于 R01 的研究启动条件自动满足。没有获取论文、下载实现、安装依赖、创建实验分支或改变生产／Portable 工具链。

## 验收逐项状态

| 验收 | 本轮动作／证据 | 结果 | exit code／计数 |
|---|---|---|---|
| 启动条件 | 对照 WORK_PACKAGES 的 R01、AC12/15/16 与 P01 已保存 JSON | 已审查，条件不足 | 非测试，不计 passed |
| AC12 SVF 增量／全量等价 | 指向集、调用边、候选、覆盖及删除传播比较 | not_run | N/A |
| AC15 外部算法兼容与许可证 | 一手论文、实现、版本及可重复构建核验 | not_run | N/A |
| AC16 实际工程瓶颈与收益 | 固定授权工程的分阶段、资源与冷／热采样 | not_run | N/A |
| 新测试 | 本轮未启动测试或重型工具 | not_run | passed 0 / failed 0 / skipped 0 |

本轮只读命令为 `git rev-parse HEAD`、`git branch --show-current` 及 UTF-8 文档／源码读取，均 exit 0。此前 P01 的执行结果保留原归属，未计入 R01 的研究验收。本记录的交接文档回归由总控在集成阶段执行。

## 恢复条件与下一步

1. 明确一个获准本地实际工程或有代表性的公开 fixture，以及允许分析的源码版本、构建输入、缓存目录和输出范围。没有该授权时，不搜索用户私有工程代替。
2. 固定工具摘要、实际 SVF 分析类型、配置、TU／链接覆盖、硬件、并发和冷／热条件；由总控分配独占性能窗口，收集分阶段 wall、CPU、RSS、临时盘和等价覆盖，确认 WPA／指针分析确有值得研究的成本。样本量与局限单列，不以单个小 fixture 外推。
3. 有瓶颈证据后再核对一手算法／实现、LLVM/SVF 版本、许可证、删除与变更传播前提；对不兼容或适配成本过高保留否定结论。
4. 只有适用性成立后才请求独立实验分支／工具链的明确范围；生产和 Portable 依赖保持原状。原型比较添加／删除边、递归、函数指针和库模型变更，要求零未解释语义差异后再评估资源收益。

第一条恢复操作是确定授权 workload 并登记测量协议，而不是下载或实现算法。没有通过正确性、兼容性和本地资源收益门禁，不提出生产集成。
