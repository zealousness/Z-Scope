# ADR-0005：Z-SCOPE 2.0采用破坏式运行时清理

- 状态：accepted-for-design
- 日期：2026-08-17
- 影响阶段：P1、P5

## 决策

2.0直接删除不可达Agent、subagent配置、C/C++ ruledriven旁路和LLM报告判重。旧配置和artifact仅由
只读compat工具处理，不长期打包旧执行路径。

## 理由

长期兼容会保留重复调度、错误Agent命名和两套验证语义，增加每次架构修改的组合测试成本。

## 后果

- 已删除配置触发明确迁移错误。
- compatibility测试保证历史数据可读，而不是旧工作流可执行。
- 删除前必须有runtime reachability和冻结replay证据。
