# D02 独立只读审查

日期：2026-10-08 / Asia/Taipei。审查者：Agent B（topology_ownership）；实现所有者：Agent A。审查对象是 D02 bounded investigation 及 D01 evidence session，不包含 V01。

本轮只读产品／测试代码；复现仅向独立 `/tmp/zscope-parallel-20261008/D02-review-B/` 写受控 fixture 和结果，没有网络、真实模型、Clang/SVF 或原生二进制执行，没有产品修改。开始 HEAD 为 `010f40210b54ba0f79a088312ce5d8be3a82ace0`，branch 为 `v1.3.1_feat/llm-wiki`；共享脏工作树保留。

## 发现状态

以下为**修复前确认结果**，已通知总控及 Agent A。实现者正在修复；本记录不提前宣布修复验收通过。

| ID | 位置（修复前） | 具体问题 | 状态 |
|---|---|---|---|
| D02-R1 | `bounded_investigation.py:464` 的 `expansion_uids` | 仅按 bare callee name／index name 匹配授权额外 scope；map 内不同 TU 的同名 `static helper` 都获授权，模型可任选其中一个，即使无法证明是实际 callee | reproduced；修复待复核 |
| D02-R2 | `bounded_investigation.py:293–307` | `session.query` 已登记新 entry，随后 `no_evidence_gain` 提前退出，`outcome.evidence` 仍保存旧 manifest；fallback report 引用的 ref 数多于最终 summary 保存的取证项 | reproduced；修复待复核 |
| D02-R2c | 同处查询返回后的 `token.raise_if_cancelled` | 查询成功并登记后取消，抛异常早于 manifest 更新；最终 report 引用了已登记 ref，但 summary 没有其身份、参数或 artifact 摘要 | reproduced；同 R2 修复范围 |

R1 应在 program 端对歧义保持拒绝／未知，不能仅靠模型选择消除同名 TU 歧义；精确已验证身份与唯一 bare name 的处理应分开。R2 应在身份仍有效的所有终态保存最新会话清单，保留成功登记与无新增内容／取消的不同含义；内容增益计数不能代替登记项计数。关闭 session 后原始 artifact 会释放，遗漏不能指望后续持久化补回。

## 实际复现环境和命令

WSL Ubuntu，cwd `/mnt/c/Users/10273/home/work/Z-Scope_1.31/Z-Scope`，解释器 `/home/zeal/venv313/bin/python`。两个命令均使用同一显式 PATH：

```text
/home/zeal/venv313/bin:/home/zeal/go/bin:/usr/lib/llvm-18/bin:/home/zeal/.local/svf/SVF-linux-x86_64/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
```

实际通过 PowerShell here-string 把下列 Python stdin 交给 WSL；入口为：

```powershell
@'
<以下对应 Python stdin>
'@ | wsl -d Ubuntu --cd /mnt/c/Users/10273/home/work/Z-Scope_1.31/Z-Scope -- env PYTHONDONTWRITEBYTECODE=1 PATH=/home/zeal/venv313/bin:/home/zeal/go/bin:/usr/lib/llvm-18/bin:/home/zeal/.local/svf/SVF-linux-x86_64/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin /home/zeal/venv313/bin/python -
```

R1／R2 使用的 Python stdin：

```python
import hashlib, json, sys
from dataclasses import replace
from pathlib import Path
import pytest
sys.path.insert(0, str(Path.cwd() / 'tests'))
from test_investigation_evidence import case as fixture, search
from test_bounded_investigation import FakeClient, Steps, config, query, unknown, run
from zscope.orchestration.active_discovery import candidate_blind_prompt_projection
from zscope.orchestration.bounded_investigation import make_investigation_runner
from zscope.orchestration.investigation import InvestigationRequest
files = ['zscope/orchestration/bounded_investigation.py', 'zscope/orchestration/active_discovery.py', 'zscope/orchestration/investigation.py', 'tests/test_bounded_investigation.py', 'tests/test_investigation_evidence.py']
def hashes():
    return {p: hashlib.sha256(Path(p).read_bytes()).hexdigest() for p in files}
before = hashes()
base = Path('/tmp/zscope-parallel-20261008/D02-review-B/scope1')
base.mkdir(parents=True, exist_ok=False)
with pytest.MonkeyPatch.context() as mp:
    c = fixture.__wrapped__(base, mp)
    record = replace(c.semantic_map.functions[0], callees=('helper',))
    extra = []
    for suffix in ['a', 'b']:
        rel = 'src/helper_' + suffix + '.c'
        (base / rel).write_text('static void helper(void) {}\n', encoding='utf-8')
        extra.append(replace(record, function_uid='FUNC_helper_' + suffix,
                             index_name='helper@' + rel + ':1-1', function_name='helper',
                             file_path=rel, start_line=1, end_line=1,
                             signature='static void helper(void)',
                             code_hash=c.access.read(rel)[1], callees=(), events=()))
    sem = replace(c.semantic_map, functions=(record, *extra))
    projection = candidate_blind_prompt_projection(sem, c.unit)
    def choose(ctx):
        return query(InvestigationRequest('read_code', 'FUNC_helper_b',
                     {'file_path': 'src/helper_b.c', 'start_line': 1, 'end_line': 1}))
    steps = Steps([choose, unknown()])
    outcome = make_investigation_runner(config(c), sem, FakeClient(steps))(projection, c.profile, c.unit)
    scope_result = {'offered': steps.contexts[0]['available_scope_requests'],
                    'stop_reason': outcome.stop_reason,
                    'evidence_count': outcome.evidence_count,
                    'granted_members': sorted(outcome.session.member_functions)}
    outcome.session.close()
    req = search()
    second = replace(req, arguments={**req.arguments, 'match_mode': 'substring'})
    outcome = run(c, Steps([query(req), query(second)]))
    gain_result = {'stop_reason': outcome.stop_reason, 'attempts': outcome.attempts,
                   'manifest_entries': len(outcome.evidence['entries']),
                   'session_entries': len(outcome.session.manifest()['entries']),
                   'report_refs': len(outcome.report.tool_evidence_refs),
                   'trace': outcome.trace}
    outcome.session.close()
result = {'scope': scope_result, 'no_gain': gain_result, 'input_stable': before == hashes(),
          'input_sha256': before}
(base / 'review.json').write_text(json.dumps(result, indent=2), encoding='utf-8')
print(json.dumps(result, indent=2))
```

实际 **exit 0**。`scope1/review.json` 保存原输出：offered 同时包含 `FUNC_helper_a` 与 `FUNC_helper_b`；选择 B 后 `granted_members=[FUNC_copy,FUNC_helper_b]`、`evidence_count=1`。no-gain 结果为 `attempts=2`、summary `manifest_entries=1`、`session_entries=2`、`report_refs=2`，第二次只有终止 trace 而没有登记 trace。脚本正常退出不表示产品检查通过；它成功复现了上述缺陷。

R2c 使用的 Python stdin：

```python
import json, sys
from pathlib import Path
import pytest
sys.path.insert(0, str(Path.cwd() / 'tests'))
from test_investigation_evidence import case as fixture, read
from test_bounded_investigation import Steps, query, run
from zscope.common.cancellation import CancellationToken
base=Path('/tmp/zscope-parallel-20261008/D02-review-B/cancel1')
base.mkdir(parents=True, exist_ok=False)
with pytest.MonkeyPatch.context() as mp:
    c=fixture.__wrapped__(base,mp)
    token=CancellationToken()
    def execute(name,args):
        value=c.runtime.execute_tool(name,args)
        token.cancel('review_cancel')
        return value
    session=c.session(execute_tool=execute)
    out=run(c,Steps([query(read())]),session=session,cancellation=token)
    result={'stop_reason':out.stop_reason,'evidence_count':out.evidence_count,
            'manifest_entries':len(out.evidence.get('entries',[])),
            'session_entries':len(session.manifest()['entries']),
            'report_refs':len(out.report.tool_evidence_refs)}
    print(json.dumps(result))
    (base/'review.json').write_text(json.dumps(result,indent=2),encoding='utf-8')
    session.close()
```

实际 **exit 0**；输出为 `stop_reason=cancelled`、`evidence_count=0`、`manifest_entries=0`、`session_entries=1`、`report_refs=1`，保存在 `cancel1/review.json`。该补充诊断没有独立前后输入摘要，不用于单独冻结版本门禁；正式修复回归需由所有者重跑。

## 首次复现输入摘要

R1／R2 的五个文件前后 SHA-256 完全一致：

| 文件 | SHA-256 |
|---|---|
| `zscope/orchestration/bounded_investigation.py` | `73e0ab531ce4d408875e2dacb41b4d450606bc0fbfcde9c2e4725dc9cb3184da` |
| `zscope/orchestration/active_discovery.py` | `5717ccb42b4cb26c94943def9e5b9b6e017ad5cf8cad4af8695b2518375bb7d1` |
| `zscope/orchestration/investigation.py` | `ceb0834f9ae85837f3fb38ba586c3c61f5bec3c33374783d43913902386724b9` |
| `tests/test_bounded_investigation.py` | `8a8a4106ff1fc6a489ca5477e9eb5b52d5a9aed987943e69e960d1eb03fd593c` |
| `tests/test_investigation_evidence.py` | `c105008d6ee7c9a8863cfcb70f63f3e1b2e071ba1503265da16c1cc37912c285` |

## 其他审查范围与限制

源码审查确认：factory 的 off 判断先于 reader／agent 构造；worker 子 token 继承父取消与更紧 deadline；model/provider/schema/工具源码参与 identity；source-only 无 build receipt 时 graph/flow 被拒；shadow 注册提供单独 validator contract，不修改原一次式报告缓存。以上是只读核对，不计作新增自动化 passed 项。现有测试覆盖并不替代本轮重跑。

本轮 pytest：**not_run**，passed 0 / failed 0 / skipped 0；两条诊断脚本 exit 0。真实模型／原生后端／重型测试：not_run。没有声称真实请求中断延迟、物理 LLM attempt 数或性能收益得到本轮验证。

续接：Agent A 修复 R1、R2/R2c 并增加独立断言；冻结后重跑 D02 专项和总控 G2。后续只读确认可以追加在本记录，不覆盖上述原始发现。文档测试由总控下次交接回归覆盖。

## 修复后独立确认

总控下发 D02 G1 冻结摘要后，Agent B 于同日只读核对改动，并在同一 WSL／解释器／PATH／`PYTHONDONTWRITEBYTECODE=1` 下重新执行上文两个原始 Python 复现块。为保留原产物，仅将临时目录 `scope1`／`cancel1` 改为 `scope-fixed1`／`cancel-fixed1`。执行入口仍是上述 PowerShell→WSL Python stdin 命令；外层脚本在执行前断言三份冻结摘要，执行后断言五文件摘要稳定，并对下面三个结果作独立断言。

| 负例 | 修复后实际输出和断言 | 结果 |
|---|---|---|
| D02-R1 | `offered=[]`；`stop_reason=scope_expansion_denied`；`granted_members=[FUNC_copy]`；`evidence_count=0` | passed |
| D02-R2 | `stop_reason=no_evidence_gain`；manifest／session entries／report refs 全部为 2；第二条 trace 为 `registered_no_gain`，保留其程序登记 ref | passed |
| D02-R2c | `stop_reason=cancelled`；evidence_count／manifest entries／session entries／report refs 全部为 1 | passed |

实际 **exit 0，3 个独立复现断言 passed、0 failed、0 skipped**。这不是 pytest 测试计数；本轮 pytest、真实模型及 native backend 仍为 not_run。前后输入稳定，执行摘要在 `/tmp/zscope-parallel-20261008/D02-review-B/fix-confirmation1/execution.json`；关键结论和冻结身份已保存在本记录，无需依赖临时目录判断修复状态。

| 文件 | 修复后前后相同 SHA-256 |
|---|---|
| `zscope/orchestration/bounded_investigation.py` | `421b0cb88c4970e99d9677babf0c1d9a036fcbe0cb93ba8147003a96215925bd` |
| `zscope/orchestration/active_discovery.py` | `fae83fd38afa9734ec5cf86081a4a099988076ef3a91e4b3848180cd929d01bc` |
| `zscope/orchestration/investigation.py` | `ceb0834f9ae85837f3fb38ba586c3c61f5bec3c33374783d43913902386724b9` |
| `tests/test_bounded_investigation.py` | `f784af5f94b4ffb9a6cad6e32054599efc5484221a3f8d826ba5f17df56589d9` |
| `tests/test_investigation_evidence.py` | `c105008d6ee7c9a8863cfcb70f63f3e1b2e071ba1503265da16c1cc37912c285` |

源码确认：扩展先尝试精确 index identity，仅唯一命中可授权，bare name 多个匹配不授权；查询返回后立即保存 manifest 与注册 trace，随后才检查取消／无增益；身份仍有效的终态再次捕获完整 manifest。**R1、R2、R2c 在上述冻结版本已关闭。** 本结论不替代总控 D02 G2，也不扩展到尚未执行的真实模型取消延迟与性能验证。
