# K02 只读缺口审查

日期：2026-10-08。批次 parallel-20261008，Agent C。当前仅审查；D01 G2 前没有修改产品或测试。实施状态由总控另行更新。

## 已存在并必须复用的能力

- `zscope/semantics/contracts.py` 的 ApiContract 已有 preconditions、effect_cases、verification、effects_trusted、resource_domain。applicability 返回 applies / does_not_apply / unknown，模型置信度本身不授予效果权限。
- `contract_conditions.py` 已实现结构化引用、布尔组合、比较、三值解释，不执行自然语言条件。
- `contract_compiler.py` 已从源码组合 wrapper，冻结每次调用对象/返回身份，传播参数换位和池域，保留不透明调用的 unknown；已实现 source_composition / must_under_guard 与源码 hash / compiler_version。
- `pool_protocols.py` 已实现受限 intrusive_freelist 的 source_protocol 资格。它根据源码确定 allocator / deallocator，不以模型的 ownership_transfer 标签授予资格。
- 工作簿发布屏障、manual 优先、契约版本、源码/输入失效、SCC 建模和审核身份已有实现，不能另建一套契约 schema 或发布系统。
- 现有 `test_wrapper_contract_compiler.py`、`test_pool_protocol_modeling.py`、`test_wrapper_failure_guards.py`、`test_contract_only_publication.py`、`test_review_proof_identity.py` 可作为回归入口。

## 已复现的最小缺口

受信任契约同时声明 `return >= 0 → applies` 与 `return == 0 → no_effect` 时，validate_contract 当前返回空错误列表；applicability 在 return=0 时依据数组顺序分别返回 applies 或 does_not_apply。这会令冲突契约的效果权限取决于声明顺序。

2026-10-08 在固定 WSL Python/PATH 下执行内联只读 Python 探针（`python -B -`），未创建产品/测试文件。实际输出：

```text
overlap_validate_errors= []
return_zero_forward= applies
return_zero_reverse= does_not_apply
```

命令退出码 0：这是缺口复现成功，不是 K02 验收通过；pytest 尚未执行。

## 解锁后的最小实施方向

复用现有解释器，使相互冲突或未闭合的效果在消费端保守 unknown，不再按第一条匹配获得权限；在现有编译校验中拒绝可证明重叠的矛盾条件。补齐成功转移/失败保留/未知返回条件、声明重排、参数换位 wrapper、对象与池域、manual 优先、未验证提议及版本失效回归。不要为了本任务引入通用求解器或任意协议状态机。

所有权预计局限 contracts.py / contract_conditions.py / contract_compiler.py 与新增专项测试。语义版本变化同步现有 compiler_version，跨域建模缓存/发布调整先交总控协调。是否存在其他缺口以新增回归实际结果为准。

## D01 接口边界

D01 只能登记程序获取的事实和允许范围，不能把工具 JSON 的 source=user、verification、proof 字段转为契约资格。T02 历史 payload 的 unverifiable、T03 图/流的 unavailable 保持。需要源码、构建、rule、tool、policy 等身份的引用分别验证；缺失构建身份只登记源码证据。持久化 artifact 不恢复进程内证明能力。

implementation_status: not_started

verification_status: gap_reproduced_read_only; acceptance_not_run
