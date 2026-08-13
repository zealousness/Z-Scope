# Adaptive balanced GLM-5.1 cold pilot — 2026-08-13

本目录归档自适应证据闭合实现合入 `main` 后的单轮 Range cold pilot。扫描绑定
提交 `5e741706c481ffe2f0d98dfefa0321309950e289`，使用 C/C++ unified backend、
`balanced` 深度和 GLM-5.1。

这是开发用单轮 trial，不是五轮 formal、sealed 或 release 结果。Range 仍然只是
分布内开发回归集；本结果不能证明真实项目泛化能力。

## 结果

| 指标 | 默认视图 | With-needs-review |
|---|---:|---:|
| TP | 124 / 136 | 135 / 136 |
| Recall | 91.18% | 99.26% |
| 报告数量 | 145 | 236 |
| Raw FP | 21 | 101 |
| Effective FP | 0 | 5 |
| Actionable precision | 85.52% | 57.20% |
| Effective/root-cause precision | 100.00% | 96.43% |
| Actionable F1 | 88.26% | 72.58% |
| Effective/root-cause F1 | 95.38% | 97.83% |

默认视图124个TP按最终判定层级分为：V0确定性57、LLM V1为8、LLM V3为59。
所有匹配TP都来自确定性规则候选；本轮主动发现没有生成候选。

## 成本与调查

- 原始provider token总量：20,395,319；coverage为100%，账本守恒。
- Validator：18,861,182 tokens，其中V1为1,348,455、V2为0、V3为17,512,727。
- Semantic Modeler：1,534,137 tokens；Active Discovery：0 tokens。
- 端到端耗时7,949.29秒；scan wall time为7,884.34秒。
- V3：144组eligible、135组entered、74组confirmed；模型迭代median 7、p95 17、max 34；
  工具调用median 15、p95 39、max 61。
- V3 pass history记录267个结构化事实；122组完成必需事实闭合，13组没有形成可接受的
  引用fact。

相比修复前本地pilot6，默认TP从103增至124，token从19,552,201增至20,395,319。
召回目标通过，但actionable precision从88.79%下降到85.52%，下降3.27个百分点，未满足
“相对基线下降不超过1个百分点”的目标。新增的21个raw FP均被 scorer 判为已匹配根因的
重复项，因此effective FP仍为0；两个precision口径必须同时保留，不能相互替代。

本轮仍有176个本地fact请求没有产生deterministic evidence delta，因此V2调用为0。这是
确定性fact provider覆盖缺口，不应误读为V2已经证明无价值。

精简机器可读结果见 [`run_summary.json`](run_summary.json)，原始本地产物的字节大小和
SHA-256见 [`artifact_manifest.json`](artifact_manifest.json)。原始 `report.json`、
`score.json`、usage JSONL和日志仍保留在被Git忽略的本地benchmark目录中，未推送到仓库。
