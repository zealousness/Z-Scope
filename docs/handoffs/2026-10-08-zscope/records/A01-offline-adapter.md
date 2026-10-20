# A01：受限外部调查离线接口

## 当前结论

离线实现已经落地，稳定输入下的 G1 已通过，待总控 G2。真实供应商接入保持 **deferred / not_run**。本任务没有启动外部 SDK、CLI 或真实模型，没有发送源码、安装依赖或接入默认扫描流程。

| 字段 | 实际值 |
|---|---|
| 日期／时区 | 2026-10-08 / Asia/Taipei |
| 所有者 | Agent B / topology_ownership，获总控临时分配 A01 |
| HEAD | `010f40210b54ba0f79a088312ce5d8be3a82ace0`，无新提交 |
| branch | `v1.3.1_feat/llm-wiki` |
| implementation_status | implemented_offline_only |
| verification_status | offline_G1_passed，等待总控 G2；真实 adapter 未执行 |
| 实际 cwd | `/mnt/c/Users/10273/home/work/Z-Scope_1.31/Z-Scope` |
| 解释器 | WSL Ubuntu `/home/zeal/venv313/bin/python` |
| 配置／目标工程 | 不加载 public config；测试使用独立临时项目，无真实用户工程 |

## 交付与接口

仅新增 `zscope/orchestration/external_investigation.py`、`tests/test_external_investigation.py` 和本记录。没有修改公共工具入口、D01/D02 模块、RuntimeSpec 或 public Config v2，没有第七工具。

- `ExternalInvestigationTask.from_session(session, unit, projection, ...)` 由程序基于现有 D01 session 建立不可变任务：绑定完整调查身份、unit／projection、scope、工具策略、命题与 missing facts。`to_dict()` 明示网络 none、无 shell／scan、可写路径为空、child depth 为 0、最多 4 步及最长 120 秒。
- `run_external_investigation(task, document, session, cancellation=...)` 是供未来受控集成调用的入口。document 只能是严格 JSON；顶层只接受 `schema_version/provider/task_id/task_fingerprint/decisions`。`provider` 是 kind/name/version，当前仅 `kind=offline, version=1` 受支持；所有真实 SDK／CLI provider 返回 `unsupported/provider_permissions_unenforced`，保存来源与 document 摘要且不访问 session。
- 每条 decision 仅可为 `query`（tool、function_uid、arguments）、`finish`（结构化 report）或 `unknown`。不接受命令、回调、任意 cwd/env、网络／写入配置、嵌套 adapter 或 scan 请求。工具调用只经过已受限的 `InvestigationSession.query`；精确路径／范围、build 身份、source revision 与语料隔离继续由 D01 强制。A01 不扩展 scope。
- finish 仅在 evidence 字段识别 `@evidence:1` 等本轮位置引用，再映射为本轮程序登记 ref。不能导入 artifact、manifest 或自报 proof；旧 session ref 和未登记引用拒绝。报告只允许 partial、获准函数／位置和候选盲投影中存在的 claim。
- 返回 `ExternalInvestigationOutcome` 中的 typed report、本轮 evidence、trace、明确 external/offline provenance 与 unknown usage。`independent_blind_discovery=false`、`real_provider_executed=false`、`proof_authority=false`，没有自动 CandidateRegistrar 注册，不能被归因为现有一次式或 bounded 内部独立发现。

这是一条程序执行的离线数据协议，没有声称 subprocess 或 prompt 形成安全沙箱。真实执行器没有可强制的路径／工具／网络／写入控制前不启用。入口不接受 provider callable，因此离线消息不能加载可执行代码。调用方传入的 D01 session／ToolsRuntime 是受信程序边界，不能换成不受限的外部执行器。

## 所有权与失败行为

调用方拥有并关闭 borrowed session。A01 只建立当前操作的 child cancellation token，不关闭借用客户端，不启动进程／线程；nested adapter 在进程内 context 级拒绝。查询后先保留程序 receipt 再响应取消。任务身份在执行前、每步前后和终态重验；过期时移除 report，已获取 evidence 仅保留为标记 stale 的审计数据。

错误消息不回显外部任意正文／路径／异常。失败意图受步数约束；相同查询停止。未知 usage 使用 `status=unknown, physical_attempts=null, tokens=null`，不伪造付费模型使用量。模块完全 opt-in，仅 callable，无默认扫描接线；不调用它即保持原运行行为。

## 已执行验证

全部测试／质量命令在 WSL 执行，显式 PATH 为：

```text
/home/zeal/venv313/bin:/home/zeal/go/bin:/usr/lib/llvm-18/bin:/home/zeal/.local/svf/SVF-linux-x86_64/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
```

环境设置 `PYTHONDONTWRITEBYTECODE=1`；质量组合另设置 `PYTHONPYCACHEPREFIX=/tmp/zscope-parallel-20261008/A01/g1/pycache`。测试使用独立 basetemp/cache，mypy 使用独立 cache。未清用户缓存。

| 轮次／检查 | 实际结果 | 状态／限制 |
|---|---|---|
| unit1 初始专项 | 62 passed / 0 failed / 0 skipped，2.15 秒，exit 0，六输入文件前后摘要一致 | passed；后续补了 unsupported provenance、stale 标记和 3 个负例，非最终版本门禁 |
| g1 组合 pytest | 162 passed / 0 failed / 0 skipped，8.57 秒，exit 0 | 实际功能断言 passed；共享 `active_discovery.py` 期间改变，不认定稳定 G1 |
| g1 mypy | exit 1：`active_discovery.py:1771` 的 `set(object)` overload 错误 | failed；来自同期 D03 修改，已发所有者处理；尚未以新的稳定运行消除此失败 |
| g1 compileall（两个新增文件） | exit 0 | passed；组合输入漂移仍保留 |
| g1 Black --check（两个新增文件） | exit 0 | passed |
| g1 git diff --check（两个新增文件路径） | exit 0 | passed；新文件未跟踪，Git 不检查其内容，Black/compileall 为实际内容检查 |
| 真实 SDK／CLI／模型 smoke | 无调用 | not_run，供应商接口／版本／许可证／认证／强制权限和数据流未核验 |
| 真实外部进程取消／沙箱 | 未启动外部进程 | not_run；只验证离线 child token 及借用所有权 |
| 文档回归／全仓 compileall/mypy | 本任务未执行 | not_run，待总控集成 |

实际命令（WSL cwd 如上）：

```bash
/home/zeal/venv313/bin/python -m pytest -q tests/test_external_investigation.py \
  --basetemp=/tmp/zscope-parallel-20261008/A01/unit1/tmp \
  -o cache_dir=/tmp/zscope-parallel-20261008/A01/unit1/cache

/home/zeal/venv313/bin/python -m pytest -q \
  tests/test_external_investigation.py tests/test_investigation_evidence.py \
  tests/test_bounded_investigation.py tests/test_investigation_runtime.py \
  --basetemp=/tmp/zscope-parallel-20261008/A01/g1/tmp \
  -o cache_dir=/tmp/zscope-parallel-20261008/A01/g1/cache
/home/zeal/venv313/bin/python -m mypy zscope/orchestration/external_investigation.py \
  --cache-dir /tmp/zscope-parallel-20261008/A01/g1/mypy-cache
/home/zeal/venv313/bin/python -m compileall -f -q \
  zscope/orchestration/external_investigation.py tests/test_external_investigation.py
/home/zeal/.cache/zscope-p1-black-venv/bin/black --check \
  zscope/orchestration/external_investigation.py tests/test_external_investigation.py
git diff --check -- zscope/orchestration/external_investigation.py tests/test_external_investigation.py
```

格式化仅对本任务两个新增 Python 文件执行，使用已存在 WSL Black，无安装。`/tmp/zscope-parallel-20261008/A01/{unit1,g1}/execution.json` 保存命令、退出码、stdout/stderr 摘要和输入前后 SHA；同目录保存日志。

## 验收映射

| 验收 | 本次覆盖 | 尚未验证 |
|---|---|---|
| AC06 | task/schema/identity 错配、source 变化、report scope、当前 ref slot、旧 ref／manifest 不恢复证明权限 | 真实供应商端身份及传输 |
| AC07 | 正常 read、拒绝私有／truth／越界路径、禁止 findings，错误不回显 private 路径／正文 | 真实执行器材料发送隔离 |
| AC08 | 步数／重复查询、有界失败恢复、局部 deadline、父取消、递归 adapter 拒绝及后续复用 | 真实 SDK 物理请求／子进程取消 |
| AC15 | 真实 provider unsupported、不安装、不加载 callback、无外部依赖的新原生路径 | 供应商版本、许可证、认证和真实 smoke |
| AC18 | 借用 session 不关闭、相邻 token 不取消、源码不写、无默认 runtime 调用 | 真实 provider 资源释放 |

没有真实性能或能力收益测量；所有离线结果来源独立标注，不计独占 TP 或模型成本。

## 当前冻结输入与续接

| 自有文件 | SHA-256 |
|---|---|
| `zscope/orchestration/external_investigation.py` | `db86b4578777654dd5352bccf755fcfcf55937d5190205a8fa86d0770fea6708` |
| `tests/test_external_investigation.py` | `6c11625fa91c75927299b94afde392fc98e5cd5899d9f5e2ebedba70f3d42ead` |

g1 中 `active_discovery.py` 从 `a5b2ca9f73f4a27042ce3214ad0a35d72e60aee8aace41c57553c94d2489d142` 变为 `49d707bc0fd9bff83274e948171653b9961c8af4b9c6647233a4857c51481d3b`；其余列入本轮摘要的八文件稳定。原失败和漂移记录保持，不把并行诊断当稳定门禁。

下一步：总控负责 G2 和共享文档／TASKS／PROGRESS。A01 整体真实验收仍 deferred：先明确获准供应商、接口版本、许可、独立认证环境与可强制权限能力，再考虑获准微型项目 smoke；不自动向私有仓库或真实模型扩展。

## D03 冻结后的 A01 G1

总控授权 D03 产品代码冻结窗口后，使用新目录 `/tmp/zscope-parallel-20261008/A01/g1-final1/` 重跑同一套 pytest／mypy／compileall／Black／diff-check。命令与前述 g1 相同，所有 basetemp、cache、mypy-cache 与 PYTHONPYCACHEPREFIX 均替换为新目录。**本轮未格式化或修改任何产品／测试源码。**

| 检查 | 实际结果 |
|---|---|
| pytest，4 文件组合 | **162 passed / 0 failed / 0 skipped，8.17 秒，exit 0** |
| mypy，新产品模块 | Success: no issues found in 1 source file，exit 0 |
| compileall，两个新增 Python 文件 | exit 0 |
| Black --check，两个新增 Python 文件 | exit 0，均无需修改 |
| git diff --check，两个新增路径 | exit 0；未跟踪文件限制同上 |
| 输入稳定性 | 9 文件前后 SHA-256 完全一致 |

完整命令、输出、退出码和九输入前后摘要已持久化到 [A01-G1-validation.json](A01-G1-validation.json)，不依赖 `/tmp`。A01 自有两个文件摘要与上表冻结值一致；共享依赖分别为 `active_discovery.py=0c118d146b076e3ab40be55c7f8b14c1a0f6626e1fd70af2f9f30758e2f0b408`、`security_map.py=adf9b042ec822402337db3f6f333a2f8c7eef8b7cd03d4da13b1b3fe266627ba`、`bounded_investigation.py=c43bc3932ac20671fb0e08ed8f0137edb53237a894cf281887df463961a1b4e6`。

此前 g1 的 162 passed、mypy failed 和输入漂移记录不覆盖。新的稳定执行解决了该质量验证缺口；**offline G1 passed** 不代表真实供应商 smoke 完成，真实項仍 not_run／deferred，等待总控 G2。
