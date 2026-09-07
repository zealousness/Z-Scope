# GitHub 仓库与本地验证

## 自动化状态

本仓库已移除 GitHub Actions 工作流、复合 Action 和自托管 runner。GitHub 仓库设置关闭 Actions，不再通过 push、pull request 或手工 dispatch 执行 CI、AI Review、benchmark、attestation 或 Release。

`.github/CODEOWNERS` 继续声明代码所有权。分支保护若配置了旧工作流的 required checks，应移除这些检查要求，避免合并等待不会再运行的检查。代码审查、线性历史和禁止 force-push 等独立策略仍可保留。

历史 run、artifact、workflow path 和来源 SHA 继续用于验证既有证据；保留这些身份字段不表示对应工作流仍可执行。依赖 GitHub workflow run 的发布或 attestation 校验仍严格检查既有来源，不将本地结果伪装成受保护工作流产物。

## 本地验证

开发验证按变更范围手工执行，入口与环境要求见 `AGENTS.md`：

```bash
python -m pytest -q tests/test_agent_docs.py tests/test_release_contract.py
python -m compileall -f -q zscope scripts tests tools test/range/benchmark test/java_range/benchmark
python scripts/check_mypy_baseline.py
python scripts/check_black_baseline.py
```

当前 mypy 与 Black 存在显式、可审计的存量债务基线：mypy 按归一化错误及次数校验，不允许新增错误；Black 按未格式化文件的内容哈希锁定，新增文件或再次修改存量未格式化文件时必须完成格式化。基线只允许在人工审查确认后用 `scripts/check_mypy_baseline.py --update` 或 `scripts/check_black_baseline.py --update` 收敛，不得为绕过失败而扩张。新代码仍以 Python 3.9 为类型和格式目标。

`compileall` 覆盖产品代码、维护脚本、自动化测试、工具和一方 C/Java benchmark runner，不递归编译 `test/range/codeql_runs` 等归档的第三方 benchmark 数据集；这些数据可能故意包含不能作为独立 Python 模块执行的测试片段，不能据此判断 Z-SCOPE 的 Python 兼容性。

需要检查凭据时，手工运行 `scripts/scan_git_history_secrets.py --ref HEAD` 和 `scripts/scan_git_history_secrets.py --current-only`。仓库级全引用审计使用不带 `--ref` 的命令。

## Benchmark 与发布资产

Benchmark 通过 `zscope-benchmark` 在满足要求的 Linux/WSL 环境手工执行，遵循 [`range-benchmark.md`](range-benchmark.md) 和 [`java-benchmark.md`](java-benchmark.md) 的工具链、truth 隔离与评分协议。

发布资产可按 [`offline-installation.md`](offline-installation.md) 手工构建和验证。`verify_release_assets.py`、`evaluate_release_candidate.py` 与离线 smoke 保留原有证据门禁；停止 GitHub 自动化不改变发布资格，也不会自动创建或发布 Release。
