# 内部数据流样例

这些 JSON 是交接用设计草案，**不是现有 Z-Scope schema，不应直接导入生产或作为真实扫描证据**。`example_only=true`、占位 ID、空 artifact 都必须被生产导入路径拒绝或要求由程序真实登记。

- `investigation_request.example.json`：父调度器给只读 Worker 的任务形状；证据与范围由程序产生。
- `investigation_result.example.json`：Worker 提交观察／缺失事实；不能自造 proof 或直接确认漏洞。
- `verification_receipt.example.json`：独立执行器结果字段；示例明确 not_run，没有模拟“已通过”。

优先映射到已存在的 AuditUnit、DiscoveryReport、evidence store 和 provider 元数据。不要为了和本例逐字段一致而新增整个公共协议。时间／轮次是内部局部策略，不是 `zscope.yaml` 新字段。
