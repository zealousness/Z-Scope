# 复制到本地 Codex 的启动指令

在 Codex 中打开目标 Z-Scope 仓库，并将下面文本作为新任务发送。路径与解压位置一致时无需改动。

```text
请继续实施 Z-Scope 的性能与漏洞挖掘增强方案，不要只重新输出计划。

先读取仓库根 AGENTS.md 及适用子目录规范，再读取：
docs/handoffs/2026-10-08-zscope/START_HERE.md
然后按其导航读取 HANDOFF.md、DECISIONS.md、TASKS.yaml、PROGRESS.md，以及当前任务的 WORK_PACKAGES.md / ACCEPTANCE.md 条目。

参考分支是 v1.3.1_feat/llm-wiki，交接核对的提交是
010f40210b54ba0f79a088312ce5d8be3a82ace0。
先比较本地 HEAD 和工作区，不要回滚、清理或覆盖已有改动。文档里的新增字段与对象名是设计提议，以本地源码、测试和现有契约为准；已有等价实现应复用。

从 B00 开始，然后实施 T01、T02、T03，形成首个可交付增量。
完成一个任务后检查依赖与验收，再推进下一项。后续按 TASKS.yaml 推进；研究任务和外部付费能力不能阻塞首批交付。没有环境或权限的测试明确标注 not_run/blocked，并继续不依赖它们的工作。

保留 Clang AST+SVF、六工具、strict Config v2、默认扫描模式、候选冻结与统一裁决边界。新调查先关闭或 shadow；模型不得签发程序 proof。禁止向私有源码之外的服务出网、安装新依赖、运行未知漏洞样本或自动提交/推送，除非已获得相应明确授权。

在 Linux/WSL 和符合本地 pyproject 要求的 Python 环境运行测试。每个任务都补针对性用例，记录真实通过、失败、跳过与未验证项。更新 TASKS.yaml 的状态，写 records/ 结果记录，并维护 PROGRESS.md 的下一步，便于新会话继续。

首轮先简要列出：本地基线差异、真实代码落点、准备实施的任务；随后开始实际修改和测试。不要把论文数据或之前提交的测试结果当成本轮验证结果，也不要一次性实施全部研究方案。
```

## 新会话继续时的简版

```text
继续 docs/handoffs/2026-10-08-zscope/START_HERE.md 中的实施任务。
先读根 AGENTS.md、TASKS.yaml、PROGRESS.md 和最近 records/，核对当前 HEAD 与未提交改动；选择依赖满足的下一个非研究任务，按对应规格实施、测试并更新记录。不要重做已完成工作，也不要仅输出计划。
```

本地模型无需访问这段 ChatGPT 会话。方案、代码基线、决策、任务与续接信息均在文件中。不要把全部长文写入根 AGENTS.md；官方 AGENTS.md 加载存在范围和大小限制，详见 [E01](REFERENCES.md#e01)。
