# Java Preview benchmark

## 当前可声明基线

`test/java_range` 当前固化的是结构基线：58 条 truth 记录（覆盖 49 个规则 ID）、54 个入口、48 条 Java 本地规则，所有规则均有 fixture 覆盖。仓库没有可信、已提交的 Java LLM 精度结果，因此不得把结构数量描述成 recall/precision，也不得虚构“当前精度”。

## 正式执行协议

正式基线仅在 Linux x86_64 自托管 runner 手工触发，固定 Git SHA、配置、prompt、工具版本和 GLM-5.1 参数。每轮必须：

1. 验证 Temurin 21、Maven、SootUp、WALA、Joern 和目录权限；CodeQL 若启用则为用户自备。
2. 新建扫描副本和缓存，不复制 `GROUND_TRUTH.md` 或 `benchmark/ground_truth.json`。
3. 扫描完成且报告落盘后，才把 truth 路径传给独立 scorer。
4. 归档报告、评分、候选统计、token、耗时、失败和工具健康日志；不归档 API Key、认证头或本地环境文件。
5. 连续完成五次冷启动，队列清空且默认结构/信号后端健康。

`.github/workflows/formal-benchmark.yml` 调用 `scripts/run_formal_benchmark.py`。自托管环境配置三个不含密钥的 argv 命令：`Z_SCOPE_JAVA_HEALTH_COMMAND`、`Z_SCOPE_JAVA_SCAN_COMMAND`、`Z_SCOPE_JAVA_SCORE_COMMAND`；路径通过 `Z_SCOPE_BENCHMARK_SOURCE/CACHE/REPORT/SCORE/TRUTH` 环境变量传入。`TRUTH` 只在 scorer 阶段存在。

Preview 首次门禁只要求五轮全部成功、结构覆盖完整、队列清空、产物可复现并发布，不预设精度数字。形成首个正式聚合后，GA 门禁才相对该基线检查 recall/precision、raw FP、token 与耗时回归。
