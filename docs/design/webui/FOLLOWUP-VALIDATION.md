# Z-SCOPE WebUI 本轮交付与验证记录

日期：2026-10-24。本文记录工程选择、配置单根与三种模式、扫描时间计划的追加实现；[首轮记录](VALIDATION.md)保留 2026-10-23 的原始结果与失败日志，不用本轮通过覆盖旧证据。

## 本轮交付与契约

| 用户流程 | 本轮行为 | 边界 |
|---|---|---|
| 启动工具 | `zscope --web` 不要求预先配置，进入最近工程、打开已有 YAML 或创建向导 | 目录浏览属于执行机器；WSL 下浏览 Linux／挂载目录，不上传浏览器本机目录 |
| 创建工程 | 选择工程目录、语言、相对编译数据库、模型参数与扫描模式，生成 YAML 后检查 | 不覆盖已有配置；检查只读，不代表工具运行、模型连通或完整扫描已验证 |
| 保存与切换 | `~/.zscope/web/projects.json` 记录路径、工程 ID 和最近时间，业务请求绑定明确工程 | registry 不存密钥和模型参数；标签页或迟到响应不能借用另一工程写入 |
| 配置范围 | YAML 父目录是唯一工程根；v2/v3 不再接受独立 root/source_root；v3 preset 为 fast/balanced/deep | Java 仅 fast；多目标可检查／编辑，执行仍拒绝，不偷偷选首目标 |
| 单次时间安排 | 立即或指定开始，结束可直到完成或总截止 | 直到完成不继承配置旧停止时间；总截止耗尽不冒充扫描完成 |
| 每日窗口 | 支持 IANA 时区及跨午夜，默认循环，窗口结束停止新增工作并有界收尾 | 仅后台真实作业完整完成才终止后续窗口；不按问题数、百分比或通知推断完成 |
| 后台续作 | SQLite 保存计划，独立协调器与既有 owner 执行；新窗口用同 job、新 run/token/未来截止 | 输入变更或外部 rearm 阻止接管；只复用验证过的可恢复状态，不保证精确仅剩余工作 |
| 取消 | 默认撤销未来计划并请求停止仍匹配的当前运行；可显式只撤未来窗口 | 核对计划版本及 job/run/input；不能停止另一调用方替换的尝试 |
| 网页重开 | 关网页／切换工程后后台继续，返回原工程可管理 | 关闭 WSL／主机或休眠时无法计算；重开工程可唤起计划，不是 OS 开机自启动 |
| 问题工作台 | 保留首轮接入能力，本轮方案待决 | 不把原有页面标为本轮重新改造完成 |

计划接口为当前已选 YAML 下的 `GET/POST /api/schedules`、`POST /api/schedules/cancel`；扫描仍复用 `ScanJobService`，接口不接受任意 argv、环境、cwd 或另一配置路径。请求先保留动作再启动，重放使用原请求身份；取消与启动竞争、协调进程重启、旧窗口及启动前输入变化都有独立处理。详见[执行与编排](../../modules/execution-orchestration.md)和[接口与报告](../../modules/interfaces-reporting.md)。

工程内相对配置路径可随工程迁移到另一执行机；目标机重新选择 YAML。包含绝对路径的编译数据库、链接记录、native 事实与收据须按目标机真实编译／工具输入重建，不能宣称跨机缓存直接可用。历史报告保持可读，但不会因此获得当前输入下的复用权限。

## 已确认验证

全部 Python 测试在 WSL Linux 用户态、Python 3.13 环境 `<venv>/bin/python` 执行。各组可能重叠，不能相加作为独立用例总数；最终集成结果单独记录，不与已有分组重复计数。

| 检查 | 已确认结果 | 证据与范围 |
|---|---|---|
| 持久计划、作业与 HTTP 回归 | 109 passed | `test_scan_schedules.py`、`test_scan_jobs.py`、`test_scan_jobs_http_api.py`；日历／跨午夜／DST、幂等、崩溃重放、取消竞争、单根作业读取与输入隔离 |
| 浏览器与 API 最终组 | 14 passed | 实际界面与接口行为验证，包含跨窗口、项目与时间计划；不是正式扫描 |
| 普通配置 fixture 迁移回归 | 141 passed，7 skipped | 单根配置下的既有业务回归；跳过项不视为通过，不累计其他重叠分组 |
| CLI、MCP、报告与 Web 接口 | 80 passed | 六个接口／组件测试文件，迁移普通合成 fixture 与相对路径，不削弱原断言 |
| 真实项目选择与时间计划浏览器 | 1 passed（13.23s） | 最终实际 HTTP/SQLite 与 HTML/CSS/JS；包含带 `-c` 切换项目、刷新保留 B、保存后清除旧执行警告；合成工程，未启动协调器、扫描器或模型 |
| 其余公共配置输入迁移 | 190 / 136 passed（两组） | 旧双根与模式输入迁移；Wiki 配置位于实际工程目录，generic 路径参数及非执行 hash 投影保持原契约 |
| 配置核心、迁移、准备与编辑器 | 193 passed | 单根配置、三种模式、严格解析与显式迁移、准备和编辑器回归；不启动正式扫描 |
| Benchmark 协议与 OCI 隔离 | 67 passed | 协议与隔离回归，属于测试验证，不形成正式 benchmark 扫描结果 |
| 唯一根、停止窗口与外部 Benchmark 隔离 | 59 passed | 根目录定位、窗口及隔离不变量；不构成真实工程或正式 benchmark 扫描 |
| Web 工程库、CLI 与真实 HTTP | 29 passed | 无 YAML 启动、双工程请求隔离、无模型环境变量时可先建可编辑配置但禁启扫描、registry 无密钥与恢复、符号链接竞态与同源检查 |
| 最终工程服务与工作簿回归 | 60 passed | 覆盖上述工程库与既有工作簿接口；CPG 按需构建、工程间隔离、索引／复核记忆 worker 生命周期、配置竞态、服务关闭及独立 Library 并发记录 |
| 本地资源与请求边界 | 14 passed，1 skipped | 离线资源锁和篡改拒绝、导航／请求约束；该次独立浏览器条件跳过不计通过，真实页面另见上方最终浏览器组 |
| Native 真实正例 | 2 passed | 受限真实工具正例，独立于页面链路，不代表全工程扫描 |
| Native 身份回归 | 32 passed | 精确构建／符号／输入身份不变量，独立记录不累计 |
| Native 拒绝路径 | 11 passed | 无效、缺失或不匹配收据等拒绝行为，独立记录不累计 |
| 定向静态检查 | 通过 | jobs 目录与 HTTP 绑定 17 文件 mypy；另对 Web 工程库、服务、CLI、配置／迁移／编辑器 9 文件定向 mypy 通过；全仓 `compileall -f -q zscope scripts test tests` 通过 |
| 全仓类型检查 | 未通过：4 errors / 2 files | 当前工作区 `instance_semantics.py` 与 `parallel_analyzer.py` 的赋值、Optional 收据及 object 下标类型问题；未为本轮前端任务重写这些已有引擎改动。定向通过不等于全仓 mypy 通过 |
| 真实 native 到页面完整链路 | 1 passed | native-current/browser.log（原始产物定位：`../../../artifacts/ui-redesign-validation/py313/native-current/browser.log`）、native-evidence.json（原始产物定位：`../../../artifacts/ui-redesign-validation/py313/native-current/native-evidence.json`）、HTTP 结果（原始产物定位：`../../../artifacts/ui-redesign-validation/py313/native-current/http-result.json`） |
| 本轮独立原型 | 通过 | 创建向导、三模式／Java 限制、定时与每日计划本地保存／刷新／取消、工程隔离；390/1280/1440/1920px 六页及对话框无横向溢出，无外部请求或页面异常 |

持久计划验收包括真实 SQLite 与 launch 文件：下一日仍是同一 job，但有新的 run、owner token 与截止；配置中旧窗口没有被继承；源码变化时拒绝续作且保留原运行身份。还使用真实独立协调进程和真实 owner 启动**明确标注的安全收据子进程**，确认开始前不启动、重开管理可见及 Linux PID/start ticks/boot ID 记录；子进程不调用模型、不进行漏洞分析，其完成状态不能当作实际扫描效果验收。

本轮 native 证据使用真实工具解析受限双宏 fixture，覆盖两个精确构建实例，并经过 ScanSession、独立 owner、SQLite、HTTP、桌面和手机页面。它验证该 fixture 的实际数据链路；模型边界未执行，不等于全工程扫描、真实业务效果、完整工具矩阵或正式 Range Benchmark。首轮的 `job_runtime_output_lookup_unverifiable` 失败日志仍保留在 `artifacts/ui-redesign-validation/py313/native/`，本轮新结果保存在 `native-current/`。

可复现的后端命令：

```bash
validation_python=<venv>/bin/python
"$validation_python" -m pytest -q tests/test_scan_schedules.py tests/test_scan_jobs.py tests/test_scan_jobs_http_api.py
"$validation_python" -m mypy zscope/orchestration/jobs zscope/web/scan_jobs_service.py
"$validation_python" -m compileall -f -q zscope/orchestration/jobs zscope/web/scan_jobs_service.py scripts/night_watchman.py tests/test_scan_schedules.py tests/test_scan_jobs.py
/usr/local/bin/node docs/design/webui/verify-followup.cjs
```

## 展示材料与未决事项

[本轮追加原型](followup.html)与[首轮原型](prototype.html)、[原对照与取舍清单](index.html)分别标注。追加原型使用合成工程和浏览器内计划，不写真实配置、不发 API、不启动扫描；原截图及 source/media 清单是其采集时的阶段证据，不用追加原型冒充当前实际实现。[本轮实际实现画廊](index.html#current-implementation)展示工程选择、向导、设置、扫描与计划历史五页的 1440/390px 共 10 张实际页面截图；可切换或并排、单独打开。采集使用真实 HTTP/SQLite 和合成工程，没有启动协调器、扫描器或模型。源码与媒体摘要、浏览器收据见 [followup/manifest.json](assets/followup/manifest.json)；新图与下方首轮历史媒体分开，问题工作台本轮仍待决。

问题工作台的进一步交互取舍仍待用户决定。尚未形成全工程扫描、付费模型调用、跨机器缓存直接复用、Safari／Firefox 或万级问题列表性能结论。时间窗口限制运行安排，不核验模型提供方的优惠或免费政策。
