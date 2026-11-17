# Range Benchmark 路线

[返回根入口](../../../AGENTS.md) · test/range、recall、precision、F1、ground truth、发布门禁、正式扫描或回归比较均触发。

只要诉求涉及 `test/range`、recall、precision、F1、ground truth、发布门禁、正式扫描或回归比较，就必须同时遵循本路线。

开发定位先选择能验证当前问题的用例或入口，不默认运行正式多轮 benchmark、整套准确率矩阵或先做一次完整 dry-run。已有试验满足当前诊断目标就继续修复/交付；只有质量目标需要稳定性或统计比较、实际波动需要解释，或用户明确要求时才增加轮次，并说明比较范围。

若选择现有 `formal` 模式或正式发布资格评测，仍按 runner 的实际轮次、环境与证据要求执行；不能把单次 trial 改称 formal。准备由正常 trial/formal 的已有步骤完成，除环境变化或排障需要，不重复手动跑同等 preflight/smoke。历史固定源码/评分记录仅约束它们对应的结果，不禁止继续修改工作区。

1. 先读 [`docs/range-benchmark.md`](../../../docs/range-benchmark.md) 和 [`docs/modules/benchmarking.md`](../../../docs/modules/benchmarking.md)。
2. 正式 unified benchmark 需要 Linux 用户态和完整的 gcc、cmake、clangd、gllvm、LLVM、SVF/Saber 工具链：
   - 原生 Linux 运行 `zscope-benchmark`；Windows 上的 C/C++ 命令由该前端自动重启到 WSL。
   - 不得用原生 Windows Python 或 Windows 构建工具形成正式结果。
   - 执行 trial/formal 前先在实际运行的 Linux/WSL 用户态确认 `cmake`、`gcc`、`clang`、`clangd`、`gclang`、`get-bc`、`llvm-link`、`llvm-nm`、`wpa`、`saber` 均可由 `PATH` 解析，并用 `ldd` 确认 `wpa`/`saber` 没有缺失共享库。
   - trial/formal 必须显式提供 `Z_SCOPE_LLM_BASE_URL`、`Z_SCOPE_LLM_MODEL`、`Z_SCOPE_API_KEY`；benchmark 不会自动读取 `test/range/zscope.local.env`。Windows 前端只转发当前 Windows 进程中已经设置的变量。
   - WSL 中的 Python 环境必须已经安装当前 Z-SCOPE（推荐在 WSL 虚拟环境中执行 `python3 -m pip install -e .`），不能依赖 Windows Python 或仅依赖源码 checkout 恰好位于当前目录。
   - 完整安装、环境变量和 preflight 命令以 [`docs/range-benchmark.md`](../../../docs/range-benchmark.md) 的“环境与门禁”为准；不要在工具缺失、SVF 动态库加载失败或 backend 降级后继续形成正式结论。
3. 扫描阶段不得把 `GROUND_TRUTH.md` 或 `benchmark/ground_truth.json` 放入 Z-SCOPE/LLM 分析上下文；ground truth 只能用于入口覆盖预检和扫描完成后的独立评分。
4. 不把 SVF/Saber 不可用后自动降级的结果标为正式 unified 结果。
5. `test/range` 含故意危险的 C 代码。除非任务明确要求演进 fixture 和 truth，否则不要“修复”其中植入的漏洞。

混合诉求采用叠加规则。例如修复 Range 漏检时，代码和测试修改遵循开发者路线；执行环境、答案隔离、评分和结论遵循 Range Benchmark 路线。
