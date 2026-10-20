# D03 独立迁移与 occurrence 复核

- 日期：2026-10-08。
- 审查者：Agent C，独立于 D03 实现者 Agent A。
- 状态：`passed_independent_review`，本记录不替代总控 G2。
- 结果：**12 passed、0 failed、0 skipped**，退出码 **0**；unittest 用时 0.005 秒。
- 输入：8 个相关文件前后 SHA-256 一致；三个 D03 产品模块与 A 正式 G1 冻结摘要一致。

## 范围与方法

本轮不修改产品或仓库测试文件。先只读检查此前报告的资格丢失路径，再于独立 Linux 临时目录创建标准库 unittest 脚本，用新构造的冻结 `SecuritySemanticMap` / `FunctionSecurityRecord` / `AuditOccurrence` 数据及内存 cache spy 直接调用真实 planner / coordinator / serializer。

独立脚本没有导入或调用 A 的 `tests/test_audit_coverage.py` fixture；该文件仅纳入输入摘要清单，便于核对审查基线。没有启动真实模型、扫描器、Clang/SVF、容器或 sanitizer，没有网络访问、依赖安装、源码外发、提交或推送。

运行命令：

```bash
/home/zeal/venv313/bin/python \
  /tmp/zscope-parallel-20261008/D03/C-independent-1/review.py
```

工作目录为 `/mnt/c/Users/10273/home/work/Z-Scope_1.31/Z-Scope`；PATH 固定为：

```text
/home/zeal/venv313/bin:/home/zeal/go/bin:/usr/lib/llvm-18/bin:/home/zeal/.local/svf/SVF-linux-x86_64/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
```

脚本 SHA-256：`4966d6773badbf402778ce94f594cb58a8e87e7a396d6a67b68ad60ab277fc33`。

证据目录 `/tmp/zscope-parallel-20261008/D03/C-independent-1/` 保留 `review.py`、`review.log`、`result.json`、`input-before.json`、`input-after.json`。

## 独立负例结果

| 用例 | 实际观察 | 结果 |
|---|---|---|
| v1 无 event、有 unknown 的 deep 单元 | 保持 `legacy_unverifiable`，两个入口以 `legacy_unknown` occurrence 保留，v2 序列化重读仍 legacy | passed |
| legacy cache 消费 | `_load_cached` 返回 None；cache spy 调用次数为 0 | passed |
| legacy complete report | 真实 `_validate_report` 以 legacy 原因拒绝 | passed |
| 两个普通 legacy 单元合并 | 正反输入顺序结果相等；迁移状态与三个入口 occurrence 保留 | passed |
| current 与 legacy 普通单元合并 | 结果继续为 `legacy_unverifiable` | passed |
| 删除 / 改写未绑定 coverage marker | 反序列化均以 migration marker mismatch 拒绝 | passed |
| 在内存中清空 coverage | 仍由已绑定 `fingerprints.coverage_schema` 派生 legacy；replan 不升级 | passed |
| 同时篡改绑定与非绑定 marker | 原指纹校验失败，拒绝加载 | passed |
| occurrence 事件集合无交集 | 无交集入口被过滤；真实 `_hypothesis_issues` 只生成有交集入口的单个候选及原入口路径 | passed |
| 入口、路径、occurrence、event 顺序翻转 | planner 选择与单元内容完全相同 | passed |
| unknown build 的 record 范围变化 | file / start / end / signature / code hash 任一变化都会改变 coverage identity | passed |
| 假 build 身份 | `unknown`、`unavailable`、空串、布尔值全部拒绝，不能成为已知构建身份 | passed |

此前指出的 deep / 普通合并丢资格、未绑定 marker 可降级、空事件交集被错误扩展三类问题在冻结版本中均已关闭。此次审查没有发现新的阻断项。

## 冻结输入

下列 SHA-256 在运行前后完全相同：

| 文件 | SHA-256 |
|---|---|
| `zscope/semantics/security_map.py` | `adf9b042ec822402337db3f6f333a2f8c7eef8b7cd03d4da13b1b3fe266627ba` |
| `zscope/orchestration/active_discovery.py` | `0c118d146b076e3ab40be55c7f8b14c1a0f6626e1fd70af2f9f30758e2f0b408` |
| `zscope/orchestration/bounded_investigation.py` | `c43bc3932ac20671fb0e08ed8f0137edb53237a894cf281887df463961a1b4e6` |
| `zscope/orchestration/candidates.py` | `d9ba071869880fe8d67ffe2adb1ac1efce4b11399c2112a9dd6e8322d729a816` |
| `zscope/orchestration/candidate_envelope.py` | `bd300ae20897ef0e2170e7fe95d59d83e3a3d795beadc74cb4c7af9026b621a9` |
| `zscope/core/candidates/decision_facts.py` | `e5fc52777d22516ad50c87d10e32e8d8a7c8c9b80060d391862e8260144e5ad9` |
| `zscope/semantics/contracts.py` | `f4b881979887e5b23a5dea8a00295bfa3868c9858a514d8e2a298e24b0913101` |
| `tests/test_audit_coverage.py` | `353a2c609d3b490e3eeb9e6a8421d1f28eca4666d3981503fa7422705cb405dd` |

## 未执行与后续

- `not_run`：真实模型收益 / 成本、正式 benchmark、真实外部扫描、重型后端回归。本次标准库合成验证不替代这些结果。
- `not_run`：本记录新增后的文档测试，纳入总控随后 G2 / 文档门禁；未自行修改共享文档状态或将 D03 标 done。
- 总控可据稳定的冻结版本继续 D03 G2；若产品输入摘要改变，应按具体变更重审有关边界。
