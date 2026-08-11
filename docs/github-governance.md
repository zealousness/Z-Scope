# GitHub 合并与发布治理

## main 保护

仓库管理员应启用 GitHub ruleset：禁止直接 push 和 force-push，要求线性历史、至少一名 CODEOWNER 审批、对话解决并通过所有必需检查。功能分支应短生命周期并使用 squash merge；不重写现有 main 历史。

必需检查对应 `.github/workflows/ci.yml`：Python 3.9–3.14 全量测试与 wheel/pip check、mypy、Black、compileall、文档与规则 schema、Java build/test、benchmark 泄漏回归、secret scan、依赖/许可证 review 和离线安装 smoke。

当前 mypy 与 Black 存在显式、可审计的存量债务基线：mypy 按归一化错误及次数校验，不允许新增错误；Black 按未格式化文件的内容哈希锁定，新增文件或再次修改存量未格式化文件时必须完成格式化。基线只允许在人工审查确认后用 `scripts/check_mypy_baseline.py --update` 或 `scripts/check_black_baseline.py --update` 收敛，不得为绕过失败而扩张。新代码仍以 Python 3.9 为类型和格式目标。

`compileall` 覆盖产品代码、维护脚本、自动化测试、工具和一方 C/Java benchmark runner，不递归编译 `test/range/codeql_runs` 等归档的第三方 benchmark 数据集；这些数据可能故意包含不能作为独立 Python 模块执行的测试片段，不能据此判断 Z-SCOPE 的 Python 兼容性。

push/PR 的 `secret-scan` 对 `HEAD` 的完整可达历史和当前工作树分别扫描，因此某个短分支只能被其自身历史阻断，不会因无关远端分支而误判。仓库级全引用审计仍使用不带 `--ref` 的 `scripts/scan_git_history_secrets.py`；管理员应在分支清理或历史迁移窗口执行它，并单独处置仍引用已吊销凭据历史的遗留分支。

建议在仓库设置中把以下 job 设为 required：六个 `Python x.y`、`quality`、`java`、`offline-smoke`、`secret-scan`，PR 上再要求 `dependency-review`。

## CODEOWNERS 与 AI Review

`.github/CODEOWNERS` 将产品、发布、规则/Agent、benchmark truth 分配给对应团队；部署前用实际组织团队替换示例 owner。

AI Review 使用普通 `pull_request` 事件，不使用 `pull_request_target`，fork 不获得密钥。只有同仓 PR 且 `AI_REVIEW_ENABLED=true` 才调用组织批准的 OpenAI-compatible endpoint；仅发送限长 PR diff，diff 视作不可信数据，不执行模型命令。结论是 advisory，不能代替 CODEOWNER 和硬门禁。

## Release

1. 从受保护 main 创建与包版本相等的 tag：`v{package_version}`。
2. 手工触发 Draft Release workflow；受保护 `release` environment 人工批准后才可读取签名密钥。
3. 自托管 runner 从带哈希 Python 3.13 约束、审批工具目录和许可证目录构建分拆资产。
4. 手工正式 benchmark 成功后记录 workflow run ID；Draft Release 只下载名为 `formal-cpp-{release_sha}` 的不可变 artifact，并同时验证 run 的 workflow、事件、结论和 `head_sha`。仓库内 `docs/releases/benchmark-provenance.json` 仅索引历史基线，不承载待发布 SHA 的运行结果，避免“提交结果会再次改变发布 SHA”的自引用。
5. Release job 校验 artifact 内的五轮聚合、逐轮报告/评分/health/队列、truth 隔离、数值门禁和 sealed-set，再运行 `verify_release_assets.py`，并提交绑定同一 asset manifest 的断网普通用户 C/Java smoke 证据。
6. `evaluate_release_candidate.py` 汇总 benchmark、sealed-set、资产和离线 smoke：存在硬阻断时禁止创建 Release，仅缺 sealed-set 时最多为 RC；全部通过后才保持 draft 等待人工发布。

正式 benchmark workflow 只允许手工触发，在自托管 Linux runner 上把 truth 与扫描副本隔离。仓库变量 `Z_SCOPE_{CPP,JAVA}_{HEALTH,SCAN,SCORE}_COMMAND` 指向经审批且不输出认证信息的命令。runner v2 记录 health/scan/score/total 分阶段耗时、命令哈希、Git tree、逐轮完整性和显著异常轮次。C 评分 JSON 必须包含 `sealed_confirmed_recall_delta_pp` 与 `sealed_precision_delta_pp`；缺失或任一低于 `-2.0` 时 artifact 只能用于 RC，不能通过正式发布评估。即使某轮失败，workflow 也会归档已经产生的日志和单轮产物。

所有 JavaScript Action 使用 Node 24 主版本；自托管 `zscope-release` 与 `zscope-benchmark` runner 必须至少为 Actions Runner `v2.327.1`。升级 Action 或 runner 后先在非发布任务验证 checkout、artifact 上传和环境审批，再冻结正式 Release SHA。
