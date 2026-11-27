# 项目原语 Web 接入：实现与验证记录

日期：2026-10-27。入口：[可点击的新旧对照](primitives.html)。

## 已接入流程

新增“项目原语”一级导航，连接工程创建、声明、native 接口目录、后台发现、人工审阅和扫描就绪。新建 C/C++ 工程同时创建主配置与语义 YAML；已有文件不覆盖。Java 明确显示不适用。

常见申请、释放、重分配、锁、解锁和拷贝声明可从精确接口目录选择函数实例，填写参数、载体、条件和配对。复杂声明保留高级 YAML。接口目录准备不调用模型，尚未绑定的声明不授权扫描。没有已知自定义原语也需要明确声明，再执行内置原语包装发现。

发现复用 CLI 的同一执行核心，后台任务保留阶段、计数、耗时、诊断与事件游标。浏览器关闭或切换工程不会停止工作；取消核对进程启动身份并有界终止。native 输入不完整时不发布新结果；模型初审失败保留确定性候选，模型意见始终不等于人工确认。

审阅按稳定接口 ID 分页，展开精确构建变体、源码、派生证据、条件、配对、模型意见和变化。单项与显式勾选批次都经过正式校验；整批预检失败不部分提交。草稿、文档版本、条目身份和证据版本共同防止迟到响应、其他标签页或外部编辑覆盖当前决定。

共享门禁用于 CLI、Web、MCP、计划创建与实际扫描启动。空文档与零候选都不能跳过发现及审阅完成。命令行可用 `zscope-config review-semantics --config <path>` 查看状态，`--declare-none` 明确声明，`--complete` 完成人工审阅。语义 YAML 是人工配置来源；任务数据库只记录运行状态，业务回答仍保存在独立状态库。

本轮没有调整待决的问题工作台布局。XLSX 的执行语义入口转向单向迁移，保留原工作簿；函数意图转向 Wiki，问题复核、误报反馈和业务回答继续独立。

## 对照材料与取舍

- 左侧旧图来自此前保留的项目配置页，基线提交为 `2693b74665991508affec2d71a181077324ff677`。旧版没有同等的原语 Web 审阅页，不能将新增能力伪装成旧版已有功能。
- 右侧使用实际产品 HTML/CSS/JS、实际 HTTP 服务，以及明确标注的 95 项合成候选；不是静态设计稿，也不代表真实项目覆盖率。
- 六张截图覆盖“首次配置原语”“发现并审阅”“接口更新后复核”的 1440px 和 390px 视图。浏览器同时检查 1280px 与 1920px。
- 原始操作录屏（`.webm`）为控制开源仓库体积已移出源码仓，页面保留 1440px/390px 截图并支持并排对照、放大、单独打开、逐项选择及 JSON 导出；选择不会修改产品。
- [浏览器收据](assets/primitives/browser-receipt.json)记录截图时间、对应前端源码摘要、图片摘要、断网请求与页面错误检查。

可选择的是导航位置、表单与 YAML 的呈现、队列与详情布局及手机切换方式。应保留的是统一就绪门禁、精确身份、有效执行条件、整批原子提交、版本冲突保护和覆盖未知状态。

## 执行环境与验证边界

所有 Python 测试与质量命令在 WSL Linux 的 Python 3.13 虚拟环境执行。真实 native 测试使用由本次 `native/clang-indexer` 源码实际重编译的工具；未用 Windows Python、合成事实或旧二进制替代 native 验收。

重建命令：

```bash
python scripts/build_clang_indexer.py --llvm-prefix /usr/lib/llvm-18 \
  --build-dir "$HOME/.cache/zscope-build-context/build" \
  --prefix "$HOME/.cache/zscope-build-context/install" --jobs 2
export Z_SCOPE_TEST_CLANG_INDEXER="$HOME/.cache/zscope-build-context/install/bin/zscope-clang-indexer"
```

真实 native 用例验证 C 申请／释放包装链、精确 callee USR、宏、自定义根、C++ 标准头文件、重载和双构建实例。CLI 与 Web 共用发现执行入口；独立进程的接口目录任务验证后台持久化、幂等重放及无模型执行，随后从引导表单声明进入真实后台发现任务，验证完成后停留在待人工审阅。表单声明绑定用户选中的精确构建实例，不自动推广到同名的另一构建。控制面用例的合成收据只用于权限、版本和调度边界，代码中有明确标注。

输入核验保留实际源码、编译命令、依赖、native 二进制与共享库的检查。发现收据在完整 native lookup 证明可用时记录所有可能查找路径（包括不存在的候选），使新增报告与队列不触发无意义的重新发现；同名高优先级头文件或无常规后缀的 `__has_include` 目标出现仍会失效。无法完整证明 lookup 时保持保守的目录变化判定。

本地完整命令输出位于 `artifacts/primitive-validation/`，这些运行日志属于本地生成物，不包含在源码交付要求内。以下为最终验证结果；不同批次包含重叠测试，不相加为独立用例总数。

| 验证范围 | 结果与记录 |
| --- | --- |
| native 工具重编译 | 成功；`native-rebuild-final.log` |
| 控制面、配置、作业、MCP、计划、语义与构建身份 | 433 项通过，2 个 native 用例在本批未配置工具而跳过，已在下面浏览器／构建身份批次使用真实工具补验；`control-final.log` |
| 原语与真实扫描／恢复 | 35 项通过，覆盖单入口、批量、检查点复用、输入变化、取消、截止时间及错误 owner；`scan-session-final2.log` |
| native 包装、覆盖、缓存、构建身份、增量等价与实例快照 | 116 项通过；`native-final.log` |
| 最终原语工作流 | 18 项通过，含精确构建声明、真实 native 包装链、后台目录与完整发现任务，以及实际独立进程取消／SIGKILL 退出后的恢复；`workflow-delivery.log` |
| 实际原语 UI、项目选择 UI 与 native 候选身份 | 17 项通过，含上述 2 个 native 补验；`browser-final.log` |
| Python 静态检查与编译 | mypy：375 个源码文件无问题；compileall 成功；`mypy-final.log`、`compile-final.log` |
| 可点击对照与离线资源 | 12 个尺寸／流程组合、图片、放大、持久选择及导出通过，无外部请求；`comparison-final.log`。随包资源摘要校验通过；`assets-final.log` |

主要复现命令（在已安装项目的 Linux 虚拟环境执行）：

```bash
python -m pytest -q tests/test_semantics_workflow.py tests/test_scan_session_jobs.py tests/test_scan_session_instances.py
python -m pytest -q tests/test_native_wrapper_inference.py tests/test_resource_inference_coverage.py tests/test_native_model_cache.py tests/test_build_context.py tests/test_clang_batch.py tests/test_protocol_incremental_equivalence.py tests/test_instance_semantics_context.py
python -m pytest -q tests/test_project_semantics.py tests/test_config_v2.py tests/test_config_v3.py tests/test_config_v3_entrypoints.py tests/test_config_v3_preparation.py tests/test_cli_config_v2.py tests/test_project_preparation.py tests/test_scan_jobs.py tests/test_scan_jobs_http_api.py tests/test_mcp_jobs.py tests/test_scan_schedules.py tests/test_scan_interface_overrides.py tests/test_web_projects.py tests/test_web_user_config_workbook_api.py tests/test_candidate_build_identity.py
# 指定本机安装的 Playwright 模块及 Chromium；它们只参与开发验收。
export ZSCOPE_UI_PLAYWRIGHT_MODULE=/absolute/path/to/node_modules/playwright
export ZSCOPE_UI_CHROMIUM=/absolute/path/to/chromium
python -m pytest -q tests/test_semantics_ui.py tests/test_web_project_picker_ui.py tests/test_candidate_build_identity.py
node docs/design/webui/verify-primitives.cjs
python -m mypy zscope
python -m compileall -f -q zscope scripts test tests
```

native 回归同时定位并修复了 Linux `/lib` 符号链接下 C++ 头文件路径规范化、包装链 callee USR 传递和验证阶段重新冻结实例时的作业输出范围问题。资源工具已重新构建；这些修复没有放宽普通工程符号链接或错误 owner 的权限。较早失败日志保留，最终结果以上表为准。

## 已知限制

- 未使用真实外部付费模型服务完成端到端验收；模型建议／失败边界由受控测试验证，真实 native 路径独立验收。
- 既有通用 C++ 资源包装器值流仍有限制。此次验证了 C++ 标准头、重载身份、宏及配置原语根，不宣称所有 C++ 包装链都能推导；无法证明的项继续记录机器缺口。
- 关闭 WSL、主机或休眠时不能继续计算。再次打开工程可看到失联状态并重试，不提供操作系统自启动承诺。
- 未验证旧发现输入的收据要求重新发现。源码或相关 native 输入变化可能要求再次发现；普通确认、拒绝和备注不触发无限重跑，撤回原语根会撤销依赖授权。
- 本轮没有制作四架构／语言组合的 portable 发布件，也没有形成正式 Range Benchmark 或全项目扫描效果结论。
