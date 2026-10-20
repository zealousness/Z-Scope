"""Prepare shared documentation alongside the independently checked code changes."""
from pathlib import Path
import datetime as dt
import hashlib
import json

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
STAGE = ROOT / ".coordination/20261014/workspaces/coordinator-instance-integration-r24"
OUT = ROOT / "artifacts/coordinator-shared-docs-r33-20261017"
OUT.mkdir(exist_ok=False)
sha = lambda path: hashlib.sha256(path.read_bytes()).hexdigest()
paths = ["docs/modules/execution-orchestration.md", "docs/modules/configuration-state.md", "docs/modules/retrieval-backends.md"]
before = {path: sha(STAGE / path) for path in paths}
for path in paths:
    source = (STAGE / path).read_text(encoding="utf-8")
    if path.endswith("execution-orchestration.md"):
        old = "提交后观察者才计量恢复集合 R、本轮执行集合 E 与已结算集合 P，要求 R∩E 为空、R∪E=P。"
        new = "提交后观察者才计量恢复集合 R、本轮执行集合 E 与计划集合 P，要求 R∩E 为空、已结算集合 R∪E 是 P 的子集；全部计划实例成功结算时才有 R∪E=P。"
        assert source.count(old) == 1
        source = source.replace(old, new)
        marker = "### 配置停止窗口与真实预算"
        paragraph = "恢复结果保留生产 run 的原始 duration/context/token 指标与绑定收据，另列历史成本来源；本轮报告总计只包含本轮实际执行结果和本轮集中验证、建模及去重成本。全部实例恢复仍执行当前集中验证，其实际成本照常计入。响应 token 三元组来自同一份当前成功响应统计，合法的零值不回落到旧累计量；同一共享客户端只计一次。历史结果对象被当前新结果替换后，旧恢复成本标记不随结果键继承。\n\n"
        assert source.count(marker) == 1
        source = source.replace(marker, paragraph + marker)
    elif path.endswith("configuration-state.md"):
        old = "标准安装文件及父目录必须属于 root 且非 group/world 可写。"
        new = "标准安装文件及父目录必须属于 root 且非 group/world 可写。冻结后的每次消费继续复核当前 native 二进制、已记录的实际动态库摘要与该物理安装的所有权、权限和符号链接状态；缺失、未知或变化均撤回旧效果，消费前后使用同一精确作用域。"
        assert source.count(old) == 1
        source = source.replace(old, new)
    else:
        source += "\n逐实例入口保留真实 native 完整签名、USR、BuildContext、源码与定义字节位置。入口的私有查询适配器只把这些坐标共同核实的完整签名映射到当前物理函数，不清空签名或借用同名函数。外部标准调用分类同时要求当前 native caller/target 调用事实、同一进程工厂签发且仍有效的实例快照，以及已核验标准来源和可执行契约；项目同名函数、缺少当前事实或冲突提示保留 source_unavailable。调用记录只能收紧权限，分类前后重新检查精确快照，不委托未限定实例的全局分类器。此有界接线不表示所有函数调度、语义域或真实项目效果已覆盖。\n"
    candidate, previous = OUT / "candidate" / path, OUT / "before" / path
    candidate.parent.mkdir(parents=True, exist_ok=True)
    previous.parent.mkdir(parents=True, exist_ok=True)
    previous.write_bytes((STAGE / path).read_bytes())
    candidate.write_text(source, encoding="utf-8", newline="\n")
assert all(sha(STAGE / path) == digest for path, digest in before.items())
receipt = dict(actual_task="/root", prepared_at=dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat(), before_sha256=before, candidate_sha256={path: sha(OUT / "candidate" / path) for path in paths}, source_review_pending=True, product_dependency_acceptance_pending=True, stage_intake=False, root_intake=False)
(OUT / "candidate.json").write_text(json.dumps(receipt, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
print(json.dumps(dict(candidate=receipt["candidate_sha256"])))
