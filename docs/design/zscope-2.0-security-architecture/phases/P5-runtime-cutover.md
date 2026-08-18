# P5：运行时切换

## 目标

将全部公共入口切换到SecuritySpec、Hypothesis Hunter、Proof Engine和Decision Trace，并删除被替代的旧语义建模和验证执行代码。

## 当前状态

`in_progress`。P2-P4均已完成，P4回退wheel及其SHA-256已冻结；P5 authority
契约、新cache epoch和cJSON answer-free资格源已进入候选实现。release gate在同树双审核、
完整资格清单和全部强制门禁通过前固定拒绝发布，测试通过不等于阶段完成。

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
- full pytest、compileall、mypy、Black、docs和package-data通过。
- 最终Claude Opus 5 product-architecture与DeepSeek-V4-Pro Max proof-security审核绑定同一clean commit/tree，均approved且blocking finding为空。

## 停止与回退

公共入口存在旁路语义、旧缓存造成漂移或finding无法离线解释时，不删除旧版本安装包，并回退流量到P4 shadow版本。
