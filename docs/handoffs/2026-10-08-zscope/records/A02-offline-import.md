# A02 离线导入专项记录

- 日期：2026-10-08。
- 范围：被动 JSON / SARIF 导入及合成微型项目测试；不启动外部扫描器，不执行导入内容。
- 整体任务状态：`deferred/blocked`，不得标 `done`。真实外部供应商资格、许可、CLI / SDK、认证、成本和独立对照均 `not_run`。
- 专项实现状态：`passed_g1`，已冻结交总控 G2；此结论不替代整体 A02 的真实外部对照。
- 写权限：仅新增 `zscope/orchestration/external_findings.py`、`tests/test_external_findings_import.py` 和本记录；未改 shared Registrar / proof / 配置 / RuntimeSpec / public tools。

## 接口与身份

`ExternalFindingsImporter(source_access, *, project_id, revision, build_identity, rule_identity, allowed_tools)` 接收程序确定的项目、版本和获准工具版本。`parse(payload: bytes, *, format="json" | "sarif")` 返回冻结 dataclass `ExternalImportBatch`；`register(batch | Sequence[batch], registrar)` 在当前源码许可与摘要复核后调用同一 `CandidateRegistrar(force_unconfirmed=True)`。

`ExternalRegistration` 返回共享 registration 结果、导入 statistics、未确认 issues 和完整冻结 `batches`。候选保存 coverage manifest 摘要、声明文件数量、状态及命中源文件摘要；`batches` 保留完整 coverage 文件清单，空结果也保留，便于离线审计和重放。该清单仍是普通数据，不具有证明权限。

项目和 revision 必须同时匹配 importer、Registrar 和 Ledger。build / rule identity 不一致拒绝；源文件每次 parse 与 register 均通过 `ProjectSourceAccess` 重新核验。底层使用已有 POSIX `O_NOFOLLOW` 相对目录描述符读取，不追随文件或目录链接。受保护路径、秘密内容、truth / report / handoff 语料、二进制和非法编码遵循现有源码许可。导入器不创建索引，不查 Git，不请求网络，不运行命令。

全部外部来源始终为 `source_only`；未知 build 的原因记作 `build_unverifiable`，其余为 `external_observation_unverified`。source SHA 只做版本绑定，不是证明。外部 `verdict` / `proof` / `validator_contract` / `attribution` 只进入摘要 `external_claims_sha256`，不复制进内部裁决字段。内部 `validator_contract` 由程序创建，仅携带 import schema、build / rule 和当前 source SHA 以隔离不同验证变体。

来源使用现有 `backend_signal` 归因大类，detail 明确 `external_offline`、tool、version；普通外部文本保留为未信任来源数据。外部结果与序列化副本经现有 `deterministic_decision_proof(confirm/reject)` 均不得形成证明；复制不会恢复任何 live authority，也没有另造证书系统。

## 受支持输入

JSON 是严格 `zscope.external-findings.v1` 信封，必需字段：

- `context`：`project_id`、`revision`、`build_identity`、`rule_identity`。
- `tool`：固定的 `name`、`version`，必须命中调用方 `allowed_tools`。
- `coverage`：`status=complete|partial|unknown`，`files=[{path, sha256}]`；即使自报 complete 也只具有 `source_reported` 权重。
- `findings`：`path`、正整数 `line`、可选正整数 `column`、`defect_class`、`function`、`resource`、`rule_id`、`message`、字符串数组 `evidence`。位置必须在当前源码内并在 coverage 清单登记。

SARIF 只接受明确的 inline 2.1.0 子集：`runs[].tool.driver` 固定 name 与 semanticVersion / version；`run.properties.zscope` 必须提供同样 context / coverage；result 使用 ruleId、message.text、唯一 physicalLocation 与 `properties.zscope` 中的 defect_class / function / resource / evidence。外部文件引用、uriBaseId、额外位置、未支持结构或缺少身份均拒绝，不解引用 `$schema` 或任何 URI。本次未对真实供应商格式作资格或兼容性承诺。

预算：每份 payload 2 MiB；最多 16 runs / batches、合计 1000 findings、2000 coverage 文件；JSON 最深 24 层 / 100000 节点；单路径最多 512 字符且必须是无 URI、无编码转义的规范 POSIX 相对路径；单 message / evidence 4096 字符、最多 16 条 evidence；沿用 ProjectSourceAccess 单文件上限，合计读取源内容最多 32 MiB。错误仅给稳定原因，不回显秘密正文或导入文本。

## 去重与指标边界

候选身份复用 `CandidateEnvelope`，不按文本相似度或外部 verdict 合并。一个批次中的同源重复数与跨工具 overlap groups 分开统计，合并后保留各来源与版本；不同 TU 不合并。build、rule 或当前源摘要不同可保持相同候选站点，但使用不同 validation cluster。

统计只提供 input findings、unique candidate sites、same source duplicates、cross tool overlap groups、needs_review；没有 TP / FP / FN / 独占 TP 指标。空 findings 不表示项目安全，也不能绕过已冻结 Ledger。

## 已执行验证

环境：WSL Ubuntu，`/home/zeal/venv313/bin/python`，固定 PATH 与此前基线一致；只用 `/tmp/zscope-parallel-20261008/A02/`。没有安装依赖、浏览、外部 SDK、凭据、扫描器、容器、sanitizer、私有源码外发、提交或推送。

公共测试命令主体：

```bash
/home/zeal/venv313/bin/python -m pytest -q tests/test_external_findings_import.py \
  --basetemp=/tmp/zscope-parallel-20261008/A02/run-N \
  -o cache_dir=/tmp/zscope-parallel-20261008/A02/cache-N \
  --junitxml=/tmp/zscope-parallel-20261008/A02/run-N-record/pytest.xml
```

| 执行 | exit | passed | failed | skipped | 说明 |
|---|---:|---:|---:|---:|---|
| run-1 | 0 | 61 | 0 | 0 | 首轮专项；1.95 秒 |
| run-2 | 0 | 69 | 0 | 0 | 加入现有 proof checker、复制 JSON、变体分组及整批拒绝；2.30 秒 |
| run-3 | 0 | 124 | 0 | 0 | 新增专项 73 项及相关共享回归 51 项；pytest 7.82 秒，命令 wall 8.29 秒，16 输入摘要稳定 |

仅对两个新增 Python 文件运行已有 `/home/zeal/.cache/zscope-p1-black-venv/bin/black`，退出 0。D02 G2 隔离窗口开始时两文件已冻结且无运行中测试，按总控要求暂停源码 / 测试写入。

最终 run-3 命令的测试列表：

```text
tests/test_external_findings_import.py
tests/test_candidate_ledger.py
tests/test_candidate_decision_context.py
tests/test_finding_attribution_contract.py
tests/test_source_search.py
tests/test_active_discovery.py::test_shared_registrar_strips_spoofed_confirmed_status
tests/test_active_discovery.py::test_shared_registrar_rejects_unversioned_or_wrong_explicit_attribution
tests/test_active_discovery.py::test_shared_registrar_merges_discovery_attribution_as_sets
```

质量检查：

- 首次 scoped mypy：exit 1，`runs` 被推断为单元素 tuple，与多 run SARIF 分支冲突；加显式 `tuple[ExternalRun, ...]` 注解后修复。该失败属于实现迭代，不归为环境失败。
- 最终 `/home/zeal/venv313/bin/python -m mypy --cache-dir /tmp/zscope-parallel-20261008/A02/mypy-cache zscope/orchestration/external_findings.py`：exit 0，1 source file 无错误。
- 最终 `/home/zeal/venv313/bin/python -m compileall -f -q zscope/orchestration/external_findings.py tests/test_external_findings_import.py`：exit 0。
- 两新文件各自 `git diff --no-index --check /dev/null <file>`：原始 exit 1，零诊断；`--no-index` 的新文件差异状态如实保留。另以严格 UTF-8 解码、无 BOM、LF、末尾换行和逐行尾随空白检查确认通过。
- 补跑裸 WSL 全仓 `git diff --check`：exit 2，大量其他文件的 CRLF 被识别为尾随空白，例如 `.github/CODEOWNERS`。总控确认 G0 已记录此原有差异。未据此修改全仓换行，也不把失败写成通过。完整原始输出留在 `/tmp/zscope-parallel-20261008/A02/run-3-record/quality-summary.json`，总控按既有跨平台换行策略复核。对两新文件补充显式 `git -c core.whitespace=blank-at-eol,blank-at-eof,space-before-tab,cr-at-eol diff --no-index --check /dev/null <file>`，仍为新文件差异 exit 1、零诊断。
- 文档测试待总控共享模块文档冻结后执行；全仓 compileall/mypy 由总控整合门禁执行，本专项未代替它们。

最终 SHA-256：

| 文件 | SHA-256 |
|---|---|
| `zscope/orchestration/external_findings.py` | `c4b9083aed15fc1a1bcb807eeecd7ed7ffcb9b680d98933417f8b157f28fafac` |
| `tests/test_external_findings_import.py` | `a03abfa23c8135882f9095a24aa32183d818df3ccee9940ddd0fb7992c7a57f2` |

完整最终 argv、退出码、wall、16 文件前后摘要与结果分类见 `records/A02-G1-validation.json`。运行日志和 JUnit XML 位于 `/tmp/zscope-parallel-20261008/A02/run-3-record/`。

## 验收与恢复条件

- AC06：专项测试已覆盖项目 / revision / build / rule 错配、过期源码、同名不同 TU、未登记路径、跨工具来源保留、恶意证明白名单隔离、源码更改与序列化副本无证明权限。
- AC15：仅离线适配。真实供应商工具版本、许可、访问资格、认证和运行权限均未核实，保持 `not_run`；无工具也不改变原生扫描行为。
- AC16：只记录专项测试时间和导入去重计数；真实成本、扫描时间、人工复核、去重 TP 和独占价值均 `not_run/unavailable`。
- AC17：只有独立临时合成微型项目；没有读取或修改 Range fixture / truth，没有给外部扫描器发送任何源码或对照结果。

后续恢复真实 A02 对照，须另获明确授权，核对实际工具版本 / 许可 / 资格 / 认证，先限定获准微型项目并保持双方输入隔离，再记录真实成本、时间和独立裁决结果。不得以本专项测试通过替代 A02 整体验收。
