# B00 → T03 批次验证

执行目录：`/mnt/c/Users/10273/home/work/Z-Scope_1.31/Z-Scope`。产品测试、compileall、mypy 均在 WSL Ubuntu `/home/zeal/venv313/bin/python`（3.13.15）执行。HEAD 始终为 010f40210b54ba0f79a088312ce5d8be3a82ace0，分支未变；交付为工作区增量。

## 最终自动回归

2026-10-08 实际执行（非建议命令）：

```bash
/home/zeal/venv313/bin/python -m pytest -q --junitxml=/tmp/zscope-b00-t03.xml \
  tests/test_source_search.py tests/test_semantic_cache_only.py tests/test_mcp_read_only.py \
  tests/test_tool_registry.py tests/test_evidence_tools.py tests/test_tool_schema_strict.py \
  tests/test_tool_policy.py tests/test_tool_use_eval.py tests/test_analyzer_tool_policy.py \
  tests/test_mcp_policy.py tests/test_mcp_http_server.py tests/test_mcp_security.py \
  tests/test_config_v2.py tests/test_cli_config_v2.py tests/test_candidate_ledger.py \
  tests/test_active_discovery.py tests/test_single_entry_active_discovery.py \
  tests/test_balanced_rollout.py tests/test_balanced_rollout_operator.py tests/test_json_output_agents.py \
  tests/test_java_source_backend.py tests/test_java_joern_backend.py tests/test_java_analyzer_candidates.py \
  tests/test_java_semantic_modeler_schema.py tests/test_java_evidence_merge.py \
  tests/test_reference_configs.py tests/test_agent_docs.py
```

结果：exit 0；**356 passed、0 failed、0 skipped**，pytest 墙钟 82.65 秒。此时间是测试套件用时，不是产品性能基准。JUnit 分组计数持久化于 [batch-validation.json](batch-validation.json)，各任务记录中的计数是同组子集，不重复累计。

## 质量与环境

| 命令/检查 | 最终结果 | exit code |
|---|---|---|
| `python -m compileall -f -q zscope scripts test tests` | passed，无输出 | 0 |
| `python -m mypy zscope` | passed，299 source files | 0 |
| `git diff --check` | passed | 0 |
| `python -m pytest -q tests/test_agent_docs.py` | 最终组合内 6 passed；交接更新后独立重跑 6 passed、0 failed、0 skipped | 0 |
| 修改 Python 文件的 Black | passed，使用已有 WSL formatter | 0 |
| Codex CLI Windows→WSL 真实 MCP 客户端 | passed，独立摘要见 T03 | 0 |

主 venv 无 Black，`python -m black ...` 实际失败（exit 1，No module named black），未安装依赖。只读查找发现已有 `/home/zeal/.cache/zscope-p1-black-venv/bin/black`，版本 25.11.0（自身 Python 3.12.3），仅用于编辑文件格式化，不形成产品测试结论。格式化后撤掉 config/CLI/runtime 三处无关格式差异。mypy 首轮报告新增代码 3 个类型错误；补全局部类型后最终通过，未更改类型检查策略。

B00 的 197 passed/4 failed 基线及固定时钟诊断完整保留在 [B00](B00-baseline.md)。生产 rollout 签名与到期检查未改，只将运行策略测试 helper 的签发时间改为测试执行时；独立确定性过期测试保留。最终 test_balanced_rollout 17 项通过。

其余开发迭代的失败与修复见各任务记录，均未归咎为基线失败。测试没有框架跳过项。当前没有必需自动验收阻塞。

## 未执行与边界

- not_run：真实模型、正式 unified Range、扫描准确率/性能采集、冷/热完整后端性能、发布 portable smoke。三个 LLM 环境变量未提供，未安装或申请模型/工具权限；相关结果不能声称通过。
- not_run：旧存储之外的完整 cache freshness 收据验证；当前安全返回 unverifiable/unavailable，详见 T02。
- 未执行后续 D01/D02/P01 等批次，没有开启任何新的发现策略，没有扩展 Config v2 或增加第七个工具。
- 未执行 git commit/push/pull/reset/clean，未改 truth 或故意缺陷，原有未跟踪产物保留。
