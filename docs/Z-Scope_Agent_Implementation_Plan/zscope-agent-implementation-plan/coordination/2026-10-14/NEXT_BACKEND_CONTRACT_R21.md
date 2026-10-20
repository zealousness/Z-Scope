# R21 后端依赖与独占审计合同

状态：准备合同，未派发、未执行。普通非 UI 优先 ZCode 固定 `glm-5.3`；Kimi 暂停新派单，已验交付保留。CURRENT-JOINT-R22 于2026-10-16 01:11:29完成2539项通过、0失败/错误/跳过及六命令0，1056输入/native稳定，发布前实时复核通过。新派发仍须先核对原 Bridge owner、现有任务、隔离副本及所有权。R21 为2538通过、1计时断言失败、五项质量检查通过，历史收据保留；不相加为本次结果。

## 可并行的两个只读准备项

| 逻辑项 | 当前输入 | 独占产物目录 | 实际目的 |
|---|---|---|---|
| S01-INSTANCE-MODELING-DESIGN-R21 | 通过联合门槛的 R22 源码、精确 ScopedCodeIndex、GlobalModeler/semantic_modeling、已验 R19 contract/validator 上下文 | 隔离副本的 `artifacts/instance-modeling-design-r21/` | 确定真正逐实例语义建模的调用、身份、缓存、发布和消费者迁移合同，列出最小可执行开发包与正反例 |
| S08-PARTIAL-RECOVERY-DESIGN-R21 | 通过联合门槛的 R22 owner/window/queue/whole-plan checkpoint、候选台账和集中 Validator | 隔离副本的 `artifacts/partial-recovery-design-r21/` | 确定逐实例／候选／义务恢复的持久单位、当前性重验、继续批次与公平性合同 |

两个任务均只读产品源码和已有交付，不写 Root、既有测试、native、配置、凭据或共享文档，不启动模型扫描、服务或 Bridge。通过确定当前剩余接口及互相依赖推进后续实施；审计产物不是功能实现或工作包验收。分别冻结通过联合验证的 R22 实际输入 SHA，不能用仓库 HEAD 替代 dirty 工作区的实际输入。逻辑项保留 R21 名称，依赖更新为 CURRENT-JOINT-R22，不重置任何既有失败历史。

## S01 已确认边界与待核实问题

- 当前 `ScanSessionRunner._build_instance_analyzer` 不传 semantic_result；`ParallelAnalyzer._analyze_single_entry` 对精确实例使用空 LocalPatternSemantics/overlay；`Analyzer.prepare_semantics` 明确跳过。不能仅移除保护条件或回退全局索引、全局语义来声称接入。
- `GlobalModeler.FunctionKey` 当前公开键为 name/file/signature。审计须追踪真实图、上下文、snapshot inputs、registry 和模型发布的全部身份链；键字段本身不证明当前泄漏，现有下游校验与跳过保护可能已经阻止消费。明确区分“当前缺口”和“若直接启用会产生的风险”。
- 对精确 BuildContext/native USR、同源双宏、同名不同 TU/目标、callee 选择和未知身份分别给出合同；未知构建不能是通配符。
- 核对模型输出如何经当前 AST/native/契约核验发布、不同实例并发写入同一 workbook/store 的责任，以及缓存如何携带构建、回答与版本身份。源码注释或模型 metadata 不授予 must 效果。
- 最小后续开发包必须使真实消费者执行，而非只增加 identity 标签；同时列出仍不支持的 graph/link/backend/规则范围。

## S08 已确认边界与待核实问题

- 当前 `scan_work.handle_instance_analysis` 的持久 detail 记录 identity/analyzed，实际结果与共享台账通过进程内 batch 进入后续 validation；当前跨 run 接续核验 whole-plan completion checkpoint，不等于逐实例候选／义务恢复。
- 当前 `ScanSessionRunner._run_instance_job_queue` 实际在 run_dir 下新建带 UUID 后缀的队列（`WORK_QUEUE_FILENAME.<uuid>`），无合法完整 checkpoint 时重新分析当前精确计划；不能依据 `scan_work.py` 旧模块说明推断新 run 复用 canonical queue 的完成项，更不能未经调用链/探针确认便报告候选丢失。逐实例恢复、跨 run 未决年龄和尝试累计仍需另行设计并验证。
- `compute_plan_fingerprint` 明确包括 `instance_semantics: defaults_only`。S01 建模能力变化必须进入恢复身份，不能只改 UI 标记而复用旧完成状态。
- 逐项追踪已分析／已验证／待验候选、失败或延期、当前 lease 与 run/input/registry/回答/native/tool 的绑定。磁盘 JSON 不恢复进程内证明权限；恢复需重验或保守重新排入未决。
- 核对持续新发现、下一批追加、去重、未决年龄与有界尝试的真实实现，不重新建设已有 SQLite 队列，也不能用固定分母或无限 retry 掩盖饥饿。
- 给出逐实例结果持久模块与共享 ScanSession/ParallelAnalyzer/jobs 接口的最小所有权划分；共享接线由协调者负责，与 S01 共同触及的文件不得同时派给两个写者。

## 输出与后续派发

每项交付 `DELIVERY.md`、结构化审计 JSON、源码路径/行/SHA、已确认能力/缺口/非缺陷、待开发接口、独占路径、依赖与实际正反例。若运行必要的受控短探针，必须真实 WSL/Linux、默认 fd、ext4 临时目录、单层两槽，记录全部结果；不以合成事实代替 native，不把受控模型当真实项目效果。

先做上述只读依赖准备的原因是 S01 与 S08 后续均涉及 `scan_session.py`、`parallel_analyzer.py` 与 `scan_work.py` 的共享身份和恢复语义，需要明确接口后才能安排真正不冲突的并行开发。UI 独占任务可在其稳定投影合同上另行并行。S02–S07 的额外协议和统一义务仍保留父 DAG，不因本轮审计或某个切片通过而关闭。

历史 S06-R02 已由用户确认完成归档，不查询、恢复或重派旧会话；仅按授权读取已有源码与交付的集成事实。S10、Q01/Q02 未启用，真实项目效果、formal benchmark、portable smoke 继续单列，未探测的前置不虚报为外部阻塞。
