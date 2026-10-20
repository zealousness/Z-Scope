"""Append accurate integration boundaries, keeping historical status bytes."""
from pathlib import Path
import datetime as dt

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
STAMP = "2026-10-14 当前持久作业与只读准备切片"

def save(path: Path, text: str) -> None:
    with path.open("w", encoding="utf-8", newline="\n") as stream:
        stream.write(text.rstrip("\n") + "\n")

config_path = ROOT / "docs/modules/configuration-state.md"
config = config_path.read_text(encoding="utf-8")
config = config.replace("完整 CLI/init/MCP/模板、准备视图和 UX 迁移尚未交付。", "完整 CLI/init/MCP/模板和 UX 迁移尚未交付。")
config = config.replace("`ConfigLoader` 只读取严格的 `UserConfigV2`", "`ConfigLoader` 按版本读取严格的 `UserConfigV2`/`UserConfigV3`")
if STAMP not in config:
    config += """
## 2026-10-14 当前持久作业与只读准备切片

`v3_preparation.prepare_saved_config` 返回与既有准备字段兼容的机器数据；默认 Web saved-config 准备通过同一后端读取 v2/v3。v3 扩展完整列出目标、平台、preset 到现有 depth 的映射、一次窗口的解析值及未消费声明。多个 target 保留全部身份并禁止启动，不把首目标投影为全部；显式服务端 depth override 暂走旧 effective-config 组合路径，多目标仍拒绝。旧 v2 编辑表单不得回写 v3。准备只检查配置/路径/工具存在，不执行扫描、模型、构建或索引。

focus/reproduction/max_workers/platform 与配置 execution.stop_at 暂未接实际消费者；配置时窗与作业显式 stop_at 分开，不能因为字段合法就显示调度已启用。单 target 配置可使用保存的 preset 启动作业，完整初始化器、模板、CLI/MCP 与编辑体验迁移仍待完成。
"""
save(config_path, config)

additions = {
    "docs/modules/interfaces-reporting.md": """
## 2026-10-14 当前持久作业与只读准备切片

Web `GET/POST /api/jobs` 与 detail/events/result/cancel/resume 适配同一 `ScanJobService`：工程侧 SQLite 是状态真源，独立 owner 持有扫描进程，页面或 Web 服务断开不丢 owner。查询核对 PID/启动身份，失联为 lost；启动异常保留真实失败并返回503，版本/运行冲突409。request_id 幂等、取消范围和新 attempt 输入摘要由服务端绑定，不能传任意命令/环境或伪造状态。测试替换的 scanner 明确为受控合成，不能算真实模型扫描。

result 的外层 report_id 是绑定报告原始字节摘要；嵌套 findings 是既有轻量 API 的完整 payload，列表键为 findings，内部 report_id 是集中复核范围，二者分开。正式报告读取器核验 shared-json 对象图，缺引用/摘要冲突拒绝；历史快照不替换当前报告或借当前 scope 写入处置。未知进度分母保留 null，entry_instances 尚未逐实例执行时 coverage 保留缺口。

当前 deadline 由 owner 对扫描进程实施有界终止并标 partial；协作停止新调度/真实剩余队列和公平批次仍未接 scan_session，不将该路径当完整 JOB04/JOB06。resume 是新 run 的重新尝试，重新核对输入和失效事件，不保证只执行剩余项，也不继承已结束窗口。配置 execution.stop_at 解析展示与显式作业 stop_at 请求分开。
""",
    "docs/modules/execution-orchestration.md": """
## 2026-10-14 当前持久作业与只读准备切片

`jobs` 持有项目侧 SQLite、独立 owner、每次 attempt 的输入和报告绑定；控制面复用同一 service，不依赖旧内存 scan 状态。取消/崩溃/重试按精确启动身份核验，PID 重用或 zombie 不授权重复扫描。每次新 attempt 重算真实源/构建输入，配置 stat 缓存只定位 store；持久报告通过正式 shared-json reader 读取，不恢复确认资格。

`entry_instances` 在索引后枚举精确 BuildContext+USR 并拒绝外来身份/错误文件；metadata 分开 planned_instances 和 scheduled_instances（未接入时 null）。目前入口分析仍使用旧导航投影，scan_coverage_complete=false，coverage 向集中验收传递实际缺口。该边界模块不证明全部编译数据库命令已索引、不证明逐实例 Analyzer/Validator 或真实链接；后续核对与消费者迁移分别验收。

当前 owner 截止仅对扫描进程执行有界停止，resume 启动新 attempt；协作停止新工作、持续剩余队列、公平后续批次尚待与真实扫描器接线。独立 producer 的测试通过不能关闭 JOB04/JOB06、INC05 或完整主包。
""",
}
for name, addition in additions.items():
    path = ROOT / name
    text = path.read_text(encoding="utf-8")
    if STAMP not in text:
        text += addition
    save(path, text)

readme_path = ROOT / "README.md"
readme = readme_path.read_text(encoding="utf-8")
new_text = """持久作业使用 `GET/POST /api/jobs` 与 detail/events/result/cancel/resume，SQLite 状态和独立 owner 支持页面断开后重新读取真实作业。结果核对每次运行绑定的报告，未知分母/覆盖保持未测；重新尝试会重核输入，不保证只运行剩余队列，也不沿用旧停止时间。目前窗口是进程级停止，完整协作调度和公平剩余队列尚未接入。

v3 已保存配置的准备视图完整列出 targets、preset 映射与未消费设置；多目标禁止启动，旧 v2 表单不回写 v3。单目标启动默认沿用保存的 preset。配置中的 execution.stop_at 暂只解析展示，任务的显式 stop_at 才是本次作业窗口；focus/reproduction/max_workers/platform 尚不代表已执行。

"""
anchor = "仪表盘提供五个主要页面："
if new_text not in readme:
    assert anchor in readme
    readme = readme.replace(anchor, new_text + anchor, 1)
save(readme_path, readme)

status_path = HERE.parents[1] / "21_IMPLEMENTATION_STATUS.md"
status = status_path.read_bytes()
appendix = """
### 2026-10-14 17:00 UTC+8 后端集成边界

S01 实例边界、U01 v3只读准备与 S08 owner/store/input/report 修复已受控导入。S01 拒绝 foreign BuildContext 与绕过显式文件；U01 多目标完整保留并禁止启动；S08 lost/spawn失败不丢 input_revision、PID重用/zombie与新attempt fresh fingerprint已核对，当前shared-json对象图正式解码。独立66/87/69集合不相加，真实HTTP/SQLite/detached owner控制样本3pass。同根后端集合493passed/174.03s、0skip，compileall/mypy347+S09/Black通过，直接源码前后同字节，证据 artifacts/coordinator-jobs-backend-20261014。UI正在变化的字节未进入此集合，旧370/86不能相加为当前整体验收。

Astra实际恢复工具与真实owner浏览器联调，使用明确受控scanner/合成报告、真实HTTP/SQLite/进程；其最终UI与全版本联合回归尚待固定字节。独立 CDB覆盖与公平队列 producer 各在965文件项目内隔离开发，暂未验收；不修改公共scan_session、不代做此前被拦caller任务。用户已确认旧S06-R02观察线程完成并归档，不作为待用户处理阻塞；本轮没有独立验收该交付或获准重试旧被拦实施。

本阶段不关闭完整S01、U01或S08：逐实例Analyzer/Validator/CDB全覆盖、完整配置入口迁移与实际协作窗口/公平remaining接线仍缺；真实模型扫描、完整增量质量/成本、formal Range/sealed/attestation、portable实物smoke与Kita整体最终验收未运行。S10/Q01/Q02原条件保留。应用更新后新的只读MCP快照显示两项新producer原进程丢失、failed/bridge_restarted；原产物保全、终态和输入字节核实后的原会话普通传输续接单独记录，不能把accepted当完成或实际模型证明。
""".encode("utf-8")
if b"17:00 UTC+8" not in status:
    with status_path.open("ab") as stream:
        stream.write(appendix)
assert status_path.read_bytes().startswith(status)
print(dt.datetime.now(dt.timezone.utc).isoformat())
