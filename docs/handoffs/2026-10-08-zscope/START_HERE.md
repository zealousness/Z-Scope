# Z-Scope：本地 Codex 实施入口

> 交接日期：2026-10-08（Asia/Taipei）  
> 仓库：`zealousness/Z-Scope`  
> 参考分支：`v1.3.1_feat/llm-wiki`  
> 远端核对提交：`010f40210b54ba0f79a088312ce5d8be3a82ace0`  
> 交接状态：**方案已整理，产品代码未在本次交接中修改，产品测试未执行。**

## 1. 交付目标

在现有 Clang AST＋SVF、接口契约、Candidate Ledger 与 V0～V3 验证框架上，逐步增强大型 C/C++ 仓的索引效率、主动漏洞发现、接口语义和可执行验证。支持外部 Coding Agent 使用 Z-Scope 的事实，也支持未来将其作为受限调查执行器；不重写为通用 Coding Agent。

**当前第一批：B00 → T01／T02 → T03。** 先核对本地基线，再交付全文／文件检索、语义上下文严格只读模式及 MCP 只读访问回归。后续工作按任务依赖继续，不要一次性铺开全部研究方案。

## 2. 安装这个交接包

将本包内容放到仓库的：

```text
docs/handoffs/2026-10-08-zscope/
```

压缩包已包含上述目录层级，可直接解压到仓库根目录；若目标处已有同名交接文件，先保留已有记录再合并。

确认本文件最终位于 `docs/handoffs/2026-10-08-zscope/START_HERE.md`，不要多嵌套一层同名目录。包内相对链接以此目录为基准；产品代码路径则一律以仓库根目录为基准。

**不要覆盖仓库已有的 `AGENTS.md`，不要创建 `AGENTS.override.md` 来屏蔽原规范。** 本包不依赖整份文档自动注入。请在本地 Codex 的目标仓库会话中明确要求读取本文件，完整启动指令见 [CODEX_PROMPT.md](CODEX_PROMPT.md)。Codex 官方说明见 [E01](REFERENCES.md#e01)。

本包是开发控制资料，不是被测项目知识。扫描 Z-Scope 自身时，应通过已有文档分类／排除配置将本交接目录和运行记录排除出 Wiki 语料及候选盲扫描上下文；不得把计划、预期结果或评分信息注入扫描模型。

## 3. 分层读取顺序

| 时机 | 阅读内容 | 目的 |
|---|---|---|
| 首次接手 | 仓库根 `AGENTS.md`、相关子目录规范、本文件 | 确认工作边界 |
| 开始计划 | [HANDOFF.md](HANDOFF.md)、[DECISIONS.md](DECISIONS.md) | 理解设计及不做事项 |
| 每次选任务 | [TASKS.yaml](TASKS.yaml)、[PROGRESS.md](PROGRESS.md) | 找到未完成且依赖满足的任务 |
| 开发当前任务 | [WORK_PACKAGES.md](WORK_PACKAGES.md) 的对应 ID、[CODE_MAP.md](CODE_MAP.md) 的对应项 | 明确代码落点和验收 |
| 测试／交付 | [ACCEPTANCE.md](ACCEPTANCE.md) 的对应检查项 | 确认完成，不混淆跳过与通过 |
| 核对外部方案 | [REFERENCES.md](REFERENCES.md) | 验证版本、许可证、接口可用性 |

无需每轮重读全部参考资料，也不要将本包全部复制到运行时 Agent prompt。

## 4. 开始前必须核对

在现有本地工作树中确认 HEAD、分支、未提交改动、Python 与 Linux/WSL 环境。参考提交不是要求回滚到该提交：本地有更新时先定位相同功能，按真实实现修订代码落点。

```bash
# 在仓库根目录执行；只读检查，不自动切分支、拉取或清理。
git status --short
git branch --show-current
git rev-parse HEAD
git diff --stat
python -c "import sys,platform,sqlite3; print(sys.executable); print(sys.version); print(platform.platform()); print('SQLite', sqlite3.sqlite_version)"
```

当前远端 `pyproject.toml` 要求 Python ≥3.13；仓库要求产品测试和质量验证在 Linux 用户态执行，Windows 使用 WSL。具体依赖与规则按本地 `AGENTS.md`、`pyproject.toml` 重新核对。[R01、R02](REFERENCES.md)

不要自动运行 `reset --hard`、`clean -fd`、覆盖式 checkout、强推或提交用户原有改动。没有明确提交授权时，保留可审查 diff，给出建议 commit 边界，不自动 commit／push。

## 5. 不可破坏的边界

1. 旧工具默认行为、strict Config v2、默认扫描深度和现有漏洞终态语义保持兼容。新算法策略先进入 RuntimeSpec／开发实验层，不向用户 YAML 随意添加内部字段。
2. LLM 可以提出 hypothesis、补充语义解释；不得直接签发程序 proof、伪造证据引用或覆盖统一裁决。既有模型裁决路径不在本任务中整体重定义。
3. 候选盲调查不能读取现有候选／报告／ground truth／人工 verdict。普通源码里的同名词汇不是自动删减理由。
4. 主 Ledger 冻结后不改候选集合与身份；验证中发现的新问题复用独立追加 Ledger，不重新打开主发现阶段。
5. `partial`、`unsupported`、`unavailable`、超时、未复现、构建失败不是安全反证。
6. 无批准不安装新外部工具、不出网发送私有源码、不修改认证配置、不运行未知构建脚本或漏洞样本。可先实现 fake runner、单测和离线导入路径。
7. 本文数值实验参数不是性能承诺。不得用论文加速倍数、模拟结果或其他提交的测试记录声明本地已经达标。

## 6. 每轮工作与续接

选择一个依赖已完成的任务 → 阅读关联实现及调用方 → 补充失败用例 → 做最小实现 → 执行针对性测试 → 按风险补回归 → 更新任务状态和记录。

`TASKS.yaml` 是任务状态唯一真源；`PROGRESS.md` 只记录本轮摘要、阻塞和下一步。任务完成必须关联 `records/` 下的结果记录，包含实际 HEAD／diff、命令、通过／失败／跳过和未验证部分。无必要不新增工作流数据库、哈希链或复杂审批系统。

没有真实 LLM endpoint、SVF、ASAN 或外部 SDK 时，不要卡住全部实施：继续完成不依赖它们的实现及测试，并将相应集成项标为 `blocked`／`not_run`，禁止宣称端到端通过。

## 7. 当前第一步

执行 **B00 本地基线对齐**。它的完成不要求完成全仓重型 benchmark；应先完成代码差异检查、目标测试收集和无网络 smoke。随后推进 **T01、T02**，最后 **T03**。第一阶段可交付后，按依赖推进 D01／D02 和 P01；研究任务 R01／R02 暂不进入默认开发批次。
