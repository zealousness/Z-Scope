# P5：运行时切换

## 目标

将全部公共入口切换到SecuritySpec、Hypothesis Hunter、Proof Engine和Decision Trace，并删除被替代的旧语义建模和验证执行代码。

## 当前状态

`complete`。产品候选`1797389af9807c74c1261f1ad85a3a18b17c23e2`、tree
`325b3c6a6cf7caf85200088af1a17324adafeb5d`已通过完整本地门禁、cJSON answer-free
资格、Claude Opus 5 product-architecture审核和DeepSeek-V4-Pro Max proof-security审核；
两份审核均绑定同一候选树、decision为`approved`且blocking finding为空。release latch只由
该候选的qualification与双审核SHA-256放行；P4回退wheel继续按已冻结hash保留。

## 进入条件

- P2通过soundness门禁。
- P3 shadow达到规格门禁。
- P4 shadow链路完整且无泄漏。

## 工作包

1. 用SecuritySpecCompiler替代SemanticModeler/GlobalModeler。
2. 删除enable_global_model和on-demand旧LLM snapshot补全。
3. 删除live Validator v2和generic forced-final入口。
4. default、resume、maintain、alert-verify、Web和MCP统一终态契约。
5. 迁移或失效旧缓存和snapshot schema。
6. 更新当前架构和模块文档，但只记录已落地事实。
7. 用cJSON v1.7.19未修改源码执行零模型cold/repeat fast与公共入口smoke，模型路径仅使用本地counting fake。
8. 将P5阶段完成状态放在内容寻址的打包数据中，使候选审核后只需review、evidence与阶段状态变更即可放行。

## 验收

- 产品wheel不含旧SemanticModeler/GlobalModeler执行代码。
- 全部公共入口使用Ledger、Proof Engine、Trace、Finding-root和usage ledger。
- 旧缓存不能误复用为新证据。
- 所有P0冻结结果差异均可归因到具体trace事件。
- 100% confirmed/needs-review具有完整trace。
- required confirmation/counterproof clause必须逐项取得Checker `accepted/verified_true`
  closure；non-executable、未选择或unknown clause一律保持needs-review。
- full pytest、compileall、mypy、Black、docs和package-data通过。
- 最终Claude Opus 5 product-architecture与DeepSeek-V4-Pro Max proof-security审核绑定同一clean commit/tree，均approved且blocking finding为空。
- 完整候选门禁结果为`1819 passed, 7 skipped`，compileall、mypy、Black 25.11、P1-P5
  package/reachability、P2-P4 qualification、trace/proof/cache tamper和公共入口smoke均通过。
- cJSON v1.7.19 cold/repeat fast与CLI/Web/MCP smoke均为零模型、零网络；balanced/deep
  只使用本地counting fake，没有向外部模型发送源码。

## 停止与回退

公共入口存在旁路语义、旧缓存造成漂移或finding无法离线解释时，不删除旧版本安装包，并回退流量到P4 shadow版本。
