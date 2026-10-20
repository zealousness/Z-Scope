"""Preserve the first draft and describe the final receipt-set and usage boundaries."""
from pathlib import Path
import datetime as dt
import hashlib
import json

HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[4]
OLD=ROOT/"artifacts/coordinator-shared-docs-r33-20261017"
OUT=ROOT/"artifacts/coordinator-shared-docs-v2-r33-20261017"
read=lambda p:json.loads(p.read_text(encoding="utf-8"))
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
old=read(OLD/"candidate.json")
assert all(sha(OLD/"candidate"/p)==digest for p,digest in old["candidate_sha256"].items())
OUT.mkdir(exist_ok=False)
for p in old["candidate_sha256"]:
    text=(OLD/"candidate"/p).read_text(encoding="utf-8")
    if p.endswith("execution-orchestration.md"):
        marker="### 配置停止窗口与真实预算"
        paragraph="共享客户端的累计统计按本轮起点计算增量；重复批次重新取起点，不清空客户端的全生命周期账本。由本轮工厂创建并交接的客户端映射只领取一次原始起点，因此 Session 的 Wiki 前置建模与后续逐实例分析共属本轮；外部已使用的普通映射从 Analyzer 接收时计起。实例构造同时接收同一项目知识服务，避免重复构造；项目级 semantic_result 仍不能进入精确实例语义链。无法从累计统计相减得到的分位数等指标保留未知，不能伪造本轮值。\n\n"
        assert text.count(marker)==1
        text=text.replace(marker,paragraph+marker)
    elif p.endswith("configuration-state.md"):
        marker="这是有界标准根来源契约，不代表完整实例扫描或真实项目效果已验收。"
        addition="冻结时保留同一构建完整 native 收据内容，消费时先核对收据集合未删改，再核对其当前物理依赖；不能删去曾使用的 features 记录来缩减信任检查。没有标准头/标准授权的实例仍可按原范围执行，不强制引入标准根。"
        assert text.count(marker)==1
        text=text.replace(marker,addition+marker)
    target=OUT/"candidate"/p
    target.parent.mkdir(parents=True,exist_ok=True)
    target.write_text(text,encoding="utf-8",newline="\n")
receipt=dict(actual_task="/root",prepared_at=dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat(),previous_draft_receipt_sha256=sha(OLD/"candidate.json"),before_sha256=old["before_sha256"],candidate_sha256={p:sha(OUT/"candidate"/p) for p in old["candidate_sha256"]},product_sources=dict(context="b5dd96fa64c07db65fbd46340b9137418a6a0a6f5be290d5e1e0f21fed93e17b",parallel="f0f5edb9a858a8855401d9eb637306609626cc1aa8769f60927df1c07032d989",session="bc0c216bb3c08ce46b0e48b7943dd72ebc5a4db5cfd885e934100b239450066c"),source_review_pending=True,stage_intake=False,root_intake=False,whole_package_complete=False)
(OUT/"candidate.json").write_text(json.dumps(receipt,ensure_ascii=False,indent=2)+"\n",encoding="utf-8",newline="\n")
print(json.dumps(dict(candidate=receipt["candidate_sha256"])))
