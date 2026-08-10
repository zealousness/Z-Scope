# GitHub 合并与发布治理

## main 保护

仓库管理员应启用 GitHub ruleset：禁止直接 push 和 force-push，要求线性历史、至少一名 CODEOWNER 审批、对话解决并通过所有必需检查。功能分支应短生命周期并使用 squash merge；不重写现有 main 历史。

必需检查对应 `.github/workflows/ci.yml`：Python 3.9–3.14 全量测试与 wheel/pip check、mypy、Black、compileall、文档与规则 schema、Java build/test、benchmark 泄漏回归、secret scan、依赖/许可证 review 和离线安装 smoke。

当前 mypy 与 Black 存在显式、可审计的存量债务基线：mypy 按归一化错误及次数校验，不允许新增错误；Black 按未格式化文件的内容哈希锁定，新增文件或再次修改存量未格式化文件时必须完成格式化。基线只允许在人工审查确认后用 `scripts/check_mypy_baseline.py --update` 或 `scripts/check_black_baseline.py --update` 收敛，不得为绕过失败而扩张。新代码仍以 Python 3.9 为类型和格式目标。

建议在仓库设置中把以下 job 设为 required：六个 `Python x.y`、`quality`、`java`、`offline-smoke`、`secret-scan`，PR 上再要求 `dependency-review`。

## CODEOWNERS 与 AI Review

`.github/CODEOWNERS` 将产品、发布、规则/Agent、benchmark truth 分配给对应团队；部署前用实际组织团队替换示例 owner。

AI Review 使用普通 `pull_request` 事件，不使用 `pull_request_target`，fork 不获得密钥。只有同仓 PR 且 `AI_REVIEW_ENABLED=true` 才调用组织批准的 OpenAI-compatible endpoint；仅发送限长 PR diff，diff 视作不可信数据，不执行模型命令。结论是 advisory，不能代替 CODEOWNER 和硬门禁。

## Release

1. 从受保护 main 创建与包版本相等的 tag：`v{package_version}`。
2. 手工触发 Draft Release workflow；受保护 `release` environment 人工批准后才可读取签名密钥。
3. 自托管 runner 从带哈希 Python 3.13 约束、审批工具目录和许可证目录构建分拆资产。
4. 关联五轮正式 benchmark 聚合、哈希和复现参数，人工检查资产小于 2 GiB、SBOM/许可证完整且无 CodeQL。
5. 保持 draft，完成签名验证和 release notes 后再人工发布。

正式 benchmark workflow 只允许手工触发，在自托管 Linux runner 上把 truth 与扫描副本隔离。仓库变量 `Z_SCOPE_{CPP,JAVA}_{HEALTH,SCAN,SCORE}_COMMAND` 指向经审批且不输出认证信息的命令。C 评分 JSON 必须包含 `sealed_confirmed_recall_delta_pp` 与 `sealed_precision_delta_pp`；任一低于 `-2.0` 时只能发布 RC。即使某轮失败，workflow 也会归档已经产生的日志和单轮产物。
