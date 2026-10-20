# K01 / P02 总控接线与迭代记录

日期：2026-10-08。HEAD `010f40210b54ba0f79a088312ce5d8be3a82ace0`，工作区未提交。最终验收需另附冻结输入记录，本节迭代结果不替代 G2。

## 接线

- 两个内部 RuntimeSpec 模式默认 off，只允许 off / shadow，不扩展 public Config v2。
- K01 在单入口和批量的盲调查之后、主 Ledger 冻结之前使用同一 Registrar 登记，保留独立来源及 shadow 验证分组。
- 统一裁决的模型结果、确定性 proof、Validator disabled、反馈与故障路径均隔离 sole K01 shadow；引擎失败仍保留 operational / engine_failed 状态，不隐藏失败。旧来源和混合真实来源资格保持。
- sole K01 shadow 不能通过 review appendix 生成普通可见的第二代关联发现。
- 两入口报告在有 P02 计划时记录 semantic_model_demand；当前实验或历史实验报告不参与 resume/maintain 的整报告复用。默认 off 与无实验历史继续原路径。

## 总控迭代测试

解释器 `/home/zeal/venv313/bin/python`，WSL Ubuntu，使用 G0 固定 PATH。每次独立 pytest basetemp/cache/JUnit，目录前缀 `/tmp/zscope-parallel-20261008/`。

| 运行 | 测试文件 | exit | passed | failed | errors | skipped |
|---|---|---:|---:|---:|---:|---:|
| root-shadow-1 | investigation_runtime / single_entry_active_discovery / parallel_shared_semantics / validation_pipeline | 1 | 66 | 0 | 20 | 0 |
| root-shadow-2 | 同上，补齐临时目录后重跑 | 0 | 91 | 0 | 0 | 0 |
| root-shadow-3 | 上述四项与 scan_session_resume_svf | 0 | 118 | 0 | 0 | 0 |

首轮 20 个 errors 均由测试驱动未先创建 basetemp 父目录引起；真实 JUnit 保留，未将其记作产品通过。后两轮分别用时 12.73 / 26.45 秒；完整命令形态为 `python -m pytest -q <上述 tests/test_*.py> --basetemp=<独立目录>/pytest -o cache_dir=<独立目录>/cache --junitxml=<独立目录>/junit.xml`。第二、三轮 stdout 保存在各目录 pytest.log。A/B 当时仍在实施，不将这些诊断轮次作为冻结 G2。

真实 LLM、实验收益、ASAN/TSAN、外部扫描和正式 benchmark 均 not_run。V01/V02 已按用户指示搁置；其阻塞不阻止 K01/P02 确定性验收。

## 首轮 G2 的冻结窗口漂移

首轮 70 文件 G2 捕获 K01 专项旧摘要 `ea9025de…` 后，A 的新增全链路测试在冻结消息交接窗口写入，最终摘要为 `3fb35294…`。产品未改变，但该轮输入已经漂移，不能作为稳定验收。总控只向此运行的 pytest PID 183602 发送 SIGINT，没有终止其他 agent、服务或缓存。

真实 pytest 摘要为 **309 passed、0 failed、0 skipped、2 deselected**，另有 1 个被中断用例及其余未执行项；pytest 退出码 2。JUnit 对中断用例留下没有 failure 节点的 testcase，最初机械统计为 310 passed，已保存 raw_junit_counts 并改按终端摘要计 309，不能将中断记为通过。完整命令、变化路径和原因见 [中断记录](K01-P02-G2-interrupted.json)。

A 最终专项 **55 passed**，含非空 typed 观察从 fake SemanticModeler 经发布、Registrar 到冻结的闭环；此前 269 项组合与这 55 项是不同测试集合，不相加为独立通过数量。所有产品和测试随后重新冻结，完整 G2 使用新目录 `G2-final-frozen` 执行。

## 最终 G2 与质量门禁

[冻结 G2 机器记录](K01-P02-G2-validation.json)：70 文件 **1297 passed、0 failed、0 errors、0 skipped**，另有 2 项明确 deselected；pytest exit 0，211.52 秒，完整驱动 219.272 秒。全部产品、测试、fixture、配置及模块文档输入前后 SHA 一致，`changed_inputs=[]`。最终 K01 专项文件 SHA 为 `3fb35294f89558e3eede5bd9ea445a33aaedab7bd1b36a3120020b7d6be384ef`，包含新增端到端用例。

本轮排除 `test_real_mutation_replay` 与 `test_real_direct_bitcode_dependency_cache_and_svf`，两项真实执行在 P01 独立记录已经通过，不重复累计；`test_native_code_to_real_terminal_tool_workbook_and_pool_consumers` 本轮实际通过。所有真实模型响应仍使用可控 fake，真实部分为已有 Clang/native 工具及消费者链，不宣称真实 LLM 验收。

[质量记录](final-quality.json) 使用同一冻结输入：`python -m compileall -f -q zscope scripts test tests` exit 0；`python -m mypy zscope` exit 0，306 source files；`git -c core.whitespace=blank-at-eol,blank-at-eof,space-before-tab,cr-at-eol diff --check` exit 0。该 Git 选项识别 Windows checkout 已有 CRLF，仍检查实际行尾空格；没有重写旧文件，原始 CRLF 检查失败保留。质量检查前后的输入亦稳定。

K01/P02 登记 done 的范围为默认关闭的确定性 shadow 实现。真实模型、收益、生产跳过与 G4 晋升仍 not_run；不可从 selected 数量或 shadow verdict 推导准确率、独占 TP 或节约成本。
