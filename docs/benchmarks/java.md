# Java Preview benchmark

## 当前可声明基线

`test/java_range/benchmark/structural_baseline.json` 是结构基线的机器真源；运行入口在 `entries.json`，规则覆盖关系单独保存在 maintenance mapping 中，扫描不会看到覆盖答案。

首个五轮 Java Preview 正式聚合已在 `c047dca722474b2e21b13f7dedaef89de3656662` 完成并归档到 `docs/reports/benchmarks/v1.4.0-java-preview-c047dca.json`。中位数为 confirmed TP 18、raw FP 4、precision 80.00%；with-review TP 45、raw FP 30、needs-review 53；tokens 760,658、wall time 761.3101 秒。五轮均有报告、评分、队列清空、truth 隔离和 SootUp/WALA/Joern 健康证据。

这是一条 `v1.4.0-preview` 基线，不是 v1.3.1 发布指标，也不是预先设定精度门槛后的 GA 结论；运行时包版本仍为 1.3.1。以后发布 Java Preview 或 GA 时必须在对应受保护发布 SHA 重跑并重新绑定。

第 3 轮耗时 4,518.0725 秒，是显著异常值。脱敏日志时间证据显示，在 54 个入口完成 53 个后，一个 Joern WebSocket 查询静默等待 3,502 秒并失败，随后 Validator 又发生两次 120 秒模型读超时。Joern 查询现已改为有界等待；正式 runner v2 会直接记录 health、scan、score、total 分阶段耗时和异常轮次，避免再次依赖事后日志反推。

## 正式执行协议

正式基线仅在 Linux x86_64 自托管 runner 手工触发，固定 Git SHA、配置、prompt、工具版本和 GLM-5.1 参数。每轮必须：

1. 验证 Temurin 21、Maven、SootUp、WALA、Joern 和目录权限；CodeQL 若启用则为用户自备。
2. 新建扫描副本和缓存，不复制 `GROUND_TRUTH.md` 或 `benchmark/ground_truth.json`。
3. 扫描完成且报告落盘后，才把 truth 路径传给独立 scorer。
4. 归档报告、评分、候选统计、token、耗时、失败和工具健康日志；不归档 API Key、认证头或本地环境文件。
5. 连续完成五次冷启动，队列清空且默认结构/信号后端健康。

`.github/workflows/formal-benchmark.yml` 直接调用 `zscope-benchmark run --language java --mode formal --runs 5`。环境只提供 LLM 凭据、模型和工具位置；health/index/scan 子进程不会获得 truth 路径，独立 score 阶段才注入。

评分 artifact 同时给出 `confirmed_recall`/`confirmed_precision` 与 `with_review_recall`/`with_review_precision`；后者将 needs-review 作为人工复核队列纳入。旧顶层 `recall` 仅是 confirmed 视图的兼容字段。性能字段同样区分用于比较的 `scan_wall_seconds` 和完整 runner 的 `end_to_end_wall_seconds`。

Preview 首次门禁只要求五轮全部成功、结构覆盖完整、队列清空、产物可复现并发布，不预设精度数字。当前归档满足该首次基线门禁；GA 门禁再相对这条基线检查 recall/precision、raw FP、token 与耗时回归。
