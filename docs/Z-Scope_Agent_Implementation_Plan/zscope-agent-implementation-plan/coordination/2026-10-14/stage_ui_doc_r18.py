"""Prepare the next accepted UI/doc batch without modifying the current root."""
from pathlib import Path
import hashlib
import json
import re

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
astra = json.loads((ROOT / "artifacts/coordinator-astra-instance-r18-acceptance-20261015/review.json").read_text(encoding="utf-8"))
dsh = json.loads((ROOT / "artifacts/coordinator-dsh-doc-r18-acceptance-20261015/review.json").read_text(encoding="utf-8"))
assert astra["independent_acceptance_passed"] and dsh["independent_acceptance_passed"]
old_html = (ROOT / "zscope/web/static/index.html").read_text(encoding="utf-8")
new_html = (Path(astra["source_snapshot"]) / "zscope/web/static/index.html").read_text(encoding="utf-8")
classes = lambda s: {t for v in re.findall(r'(?<!:)class="([^"]+)"', s) for t in v.split()}
assert not classes(new_html) - classes(old_html), "new utilities require explicit CSS regeneration"
lock_path = ROOT / "requirements/portable/web-assets.lock.json"
lock = json.loads(lock_path.read_text(encoding="utf-8"))
for name in ("index.html", "dashboard_workbench.js"):
    lock["first_party"][name]["sha256"] = astra["delivered_hashes"]["zscope/web/static/" + name]
lock_contents = json.dumps(lock, ensure_ascii=False, indent=2) + "\n"
module_path = ROOT / "docs/modules/interfaces-reporting.md"
module = module_path.read_text(encoding="utf-8")
needle = "  - tests/test_job_result_http_binding.py\n"
assert module.count(needle) == 1
module = module.replace(needle, needle + "  - tests/test_instance_coverage_ui.py\n  - tests/test_lightweight_instance_metadata.py\n")
module += "\n## 编译实例结果视图\n\nDashboard 从当前报告投影中的 `metadata.entry_instances` 展示精确 BuildContext 与 native USR 对应的实例结果；作业结果始终来自同轮绑定快照，不能借当前报告补齐旧任务的数据。轻量投影保留固定的实例与 `metadata.job` 字段，展示元数据不替代外层 job/run/input/report 绑定权限。\n\n计划、调度、已分析与本轮执行、复用分别计量；作业执行计数还须与外层 job/run 相符，缺字段或未知 schema 保持未测量。实例身份范围完整不等于 `scan_coverage_complete`，零候选不授予安全结论。USR 等精确身份折叠展示，按实例查找不合并同名编译变体。本轮新增浏览器链使用真实双宏 native fixture、ScanSession、owner、SQLite 与 HTTP；它只验证受限 fixture 与界面消费，未验收真实项目、模型效果或完整扫描。\n"
updates = {}
for relative, contents in (("requirements/portable/web-assets.lock.json", lock_contents), ("docs/modules/interfaces-reporting.md", module)):
    updates[relative] = {"before_sha256": hashlib.sha256((ROOT / relative).read_bytes()).hexdigest(), "after_sha256": hashlib.sha256(contents.encode("utf-8")).hexdigest(), "contents": contents}
out = HERE / "staged-ui-doc-r18.json"
assert not out.exists()
out.write_text(json.dumps({"updates": updates, "new_literal_classes": [], "vendor_or_css_changed": False, "root_changed": False, "intake_requires_current_joint_pass": True}, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
print(json.dumps({"prepared": str(out), "root_changed": False}))
