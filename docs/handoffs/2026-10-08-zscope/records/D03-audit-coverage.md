# D03：对象、操作位点与入口覆盖

## 基本信息

- 日期：2026-10-08，Asia/Taipei；Agent A / topology_dependencies。
- HEAD：`010f40210b54ba0f79a088312ce5d8be3a82ace0`；分支：`v1.3.1_feat/llm-wiki`。开始／结束一致，保留所有既有和其他 agent 修改，无提交、推送、安装或外部模型调用。
- implementation_status：implemented；verification_status：G1_targeted_passed，等待总控 G2。
- WSL Ubuntu；解释器 `/home/zeal/venv313/bin/python`；cwd `/mnt/c/Users/10273/home/work/Z-Scope_1.31/Z-Scope`；配置和 project.root 均来自临时 pytest fixture。
- PATH：`/home/zeal/venv313/bin:/home/zeal/go/bin:/usr/lib/llvm-18/bin:/home/zeal/.local/svf/SVF-linux-x86_64/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin`。

## 实现和下游接口

`security_map.py` 新增 frozen `CoverageKey(family, function_uid, object_ref, operation_site, build_context, scope_discriminator)`，提供 `to_dict/from_dict/identity()`；以及 `AuditOccurrence(entry_identity, entry_path, event_refs, reachability)`。SecurityEvent 保存词法 object_ref、精确 operation_site、可选 build_context 和 callback_target；FunctionSecurityRecord 保存程序收集的 entry_occurrences。AuditUnit 保存 coverage_keys、occurrences 和 migration_status。

首次精细粒度只支持 resource_lifecycle 与 callback_concurrency。相同函数内同一词法对象的多个操作位点组成一个单元，保留每个位点的键；不同对象、不同 build context 或不能解析的独立位点不因同文件／成员函数重叠合并。复杂别名、数组／指针表达式、复杂赋值左值与未经许可契约绑定退回 site/unknown；不据变量名称推断跨函数 alias 或对象生命周期等价。

标准调用的 token 与参数位置提供词法调度观察，不授予 effects_trusted，也不成为确定性告警或 proof。资源关系和回调的真实语义仍由现有 Clang AST+SVF、发布契约和统一 Validator 负责。新增观察没有修改规则目录或规则启停语义。

build_context 使用 P01 command_identity/context 的 64 位十六进制摘要形态，拒绝 unknown/unavailable 等占位字符串。只有程序已有可信 TU／artifact 对应关系才能设置已知值；当前 public Map builder 无此逐事件绑定，故保持 None，不能据源码出现在 CDB、单一 source_variant、dependency_fingerprint 或 HEAD 猜测。未知构建用 project/revision + function UID/index/file/range/signature/source hash 生成稳定 scope discriminator；不随机、不受入口顺序影响、不跨不同 record/TU 共享。

Planner 的精细单位只在键与单元 fingerprint 等价时合并。entry occurrence 与审计任务分离：共享函数的等价对象只调度一次，但每个实际入口路径仍分别进入既有 CandidateRegistrar。候选仍是 needs_review；不修改 Ledger、冻结规则、统一裁决或公共 disposition。一个 occurrence 只绑定其 event_refs；与当前单元没有交集的入口不会被添加为新候选发生点。旧分离入口／路径数组不能恢复精确关联时明确 legacy_unknown，不做交叉乘积。

`candidate_coverage_keys(ledger, *, semantic_map=None)` 保持旧调用兼容。传入 Map 后，候选 location（支持行号＋列号）、函数和可选 resource 只映射到唯一程序位点；不消费候选自报的 CoverageKey 或 build 授权。公共 ledger 暂无可信 TU 映射，不能用其自报 build 匹配已知变体。精细两类忽略 coarse family/file 的全覆盖含义；同一对象仅一个位点有候选时，其他位点仍是 desert。该信息仅用于排序，绝不表示已检查完整或进入候选盲 prompt。总控已在单入口和批量入口传入同一个实际 semantic_map。

## 回调、预算和可复算覆盖

源码中明确 register_callback／pthread_create 参数可生成注册线索，关联可解析的目标，即使没有直接 caller；reachability 标 callback_registration，同时保留 callback_dispatch_unproven。未知回调目标、间接调用、复杂对象别名、达到 callee 页限制和函数遍历预算均留 SemanticUnknown。回调注册不是可执行可达性的证明。

Map builder 对入口稳定排序，并在函数预算已达上限时仍记录已经解析函数的新入口 occurrence；仅新的函数解析被 deferred。Planner.last_plan / Coordinator.coverage_plan 报告 planned、eligible、selected、budget-deferred、risk-threshold not_selected、occurrence 与 enhanced-family 计数。未入选单元保留 ID、原因与 occurrence。extra_units_from_granularity 单列精细粒度增加的选中单元数量；没有把它当作收益或实际模型成本。

Coordinator 的 uncovered_unit_ids 包含失败、未尝试、partial、仍有 unknown、legacy、未知 build、预算 deferred 和风险门槛未选单元。coverage_completed_unit_count 与报告数量区分。模型报告写 complete 但还含 unresolved_facts，或只提供 source-only 单元，不形成完整覆盖；旧回归相应由状态 complete 更新为 partial。风险字段、候选存在性和裁决内容不进入 candidate-blind projection。

## Schema 与缓存兼容

- SecuritySemanticMap、AuditUnit 和 discovery prompt projection 升为 v2；DiscoveryReport 既有结构保持。
- 读取 v1 Map 时先验证原 v1 map_fingerprint，再转换成 legacy_unverifiable；旧 AuditUnit 重新生成 fingerprint/ID，仅保留 site/unknown 能力，旧 report cache 不命中。
- 迁移标记同时绑定在 fingerprints.coverage_schema；删除未绑定 coverage 字典中的标记不能恢复 current，v2 loader 拒绝标记不一致或嵌套混合 schema。
- 普通 event、deep 无 event 分支和单元合并都保留 legacy 状态及 occurrence；deep claim_refs 保持 claim_id 字符串。
- legacy 单元不能读取为 current report cache，也不能提交 complete report；D02 factory 返回 legacy_map_unverifiable，不初始化调查客户端。没有原地数据库迁移、自动重建或以 JSON 恢复 proof 权限。

## 验证结果

| 执行 | passed | failed | errors | skipped | exit | 说明 |
|---|---:|---:|---:|---:|---:|---|
| run1 | 155 | 2 | 0 | 0 | 1 | 普通标准库调用无 contract binding，导致对象均 unknown，已补实际调用 token 的词法观察；旧测试把 unresolved 报告视为 complete，按未覆盖语义更新预期 |
| run2 | 158 | 0 | 0 | 0 | 0 | 当时专项全部通过；定向 mypy 1 条 Optional 局部变量诊断，已修正 |
| final1 | 215 | 0 | 0 | 0 | 0 | 11 个相关测试文件；mypy／compileall 通过，48 个输入稳定 |
| final2 / G1 | 217 | 0 | 0 | 0 | 0 | 补同 record/同 object/同 site 不同 build 和共享函数预算边界两个验收负例，全部通过，48 个输入稳定 |
| final2 mypy | N/A | 0 | 0 | 0 | 0 | security_map、active_discovery、bounded_investigation 三模块 |
| final2 compileall | N/A | 0 | 0 | 0 | 0 | 三产品模块及新专项测试 |
| 所属文件 git diff --check | N/A | 0 | 0 | 0 | 0 | 通过 |

AC09：同文件两个对象、同对象两个位点、同对象两个入口、同名／同记录不同 build、无直接 caller 的注册回调、未知 callback/alias、预算 deferred、入口乱序稳定均有 fake/确定性专项。AC10/AC17/AC18：CandidateLedger、D01/D02、RuntimeSpec、双入口、只读语义工具和契约链同时回归；未修改候选冻结与统一裁决。AC16：命令、退出码、统计及前后输入摘要保存于 `D03-G1-validation.json`。

所有日志位于 `/tmp/zscope-parallel-20261008/D03/{run1,run2,final1,final2}/`，每次独立 basetemp/cache/output。final2 输入清单 SHA256：`76ed170d410b1b03e1006cca6de7d88dca0bc8e12ab0eacdecf00a4f94343b68`。

实际 final2 命令（固定上述 WSL 环境）：

```text
python -m pytest -q --tb=short tests/test_audit_coverage.py tests/test_security_semantic_map.py tests/test_security_semantics_tool.py tests/test_semantic_contract_chain.py tests/test_semantic_contract_schema.py tests/test_active_discovery.py tests/test_bounded_investigation.py tests/test_investigation_evidence.py tests/test_single_entry_active_discovery.py tests/test_candidate_ledger.py tests/test_investigation_runtime.py --basetemp=/tmp/zscope-parallel-20261008/D03/final2/tmp -o cache_dir=/tmp/zscope-parallel-20261008/D03/final2/cache
python -m mypy zscope/semantics/security_map.py zscope/orchestration/active_discovery.py zscope/orchestration/bounded_investigation.py --cache-dir=/tmp/zscope-parallel-20261008/D03/final2/mypy
python -m compileall -f -q zscope/semantics/security_map.py zscope/orchestration/active_discovery.py zscope/orchestration/bounded_investigation.py tests/test_audit_coverage.py
```

## 未执行与续接

- not_run：真实模型、正式 benchmark、native Clang/SVF 重建、真实 variant-to-event receipt、性能及独占 TP/FP。新增 build 区分测试使用确定性 typed fixture，不宣称真实 TU 证明链完成。
- 仅资源生命周期与回调单元增强；输入路径、协议、鉴权等其他家族沿用原有粒度。复杂跨函数 alias、完整回调调度和全构建变体展开仍未支持。
- 总控维护 TASKS.yaml、PROGRESS.md、模块文档并执行 G2；在 G2 通过前不实施 K01。B/C 独立复核可引用本次冻结摘要。

G1 冻结 SHA256：

| 文件 | SHA256 |
|---|---|
| `zscope/semantics/security_map.py` | `adf9b042ec822402337db3f6f333a2f8c7eef8b7cd03d4da13b1b3fe266627ba` |
| `zscope/orchestration/active_discovery.py` | `0c118d146b076e3ab40be55c7f8b14c1a0f6626e1fd70af2f9f30758e2f0b408` |
| `zscope/orchestration/bounded_investigation.py` | `c43bc3932ac20671fb0e08ed8f0137edb53237a894cf281887df463961a1b4e6` |
| `tests/test_audit_coverage.py` | `353a2c609d3b490e3eeb9e6a8421d1f28eca4666d3981503fa7422705cb405dd` |
| `tests/test_active_discovery.py` | `411581f114d9d825c89a6342b7325300c5d2bdcc6ecff6ab48615fa01a4e6e8c` |
