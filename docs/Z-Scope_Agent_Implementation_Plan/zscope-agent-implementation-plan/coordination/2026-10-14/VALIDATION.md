# 协调与发布索引验证

当前已集成的本轮变化仅为 Astra 前端的发布索引/静态资源锁，以及任务台账/基线/API合同。外部后端实现尚无本轮验收交付，不能宣称同一最终集成版本通过。

实际环境：WSL Ubuntu，`/home/zeal/venv313/bin/python` 3.13.15。无共享 native 重建、无网络下载、无 Tailwind 重编、无 formal 扫描/实物 portable smoke。

| 命令 | 结果 |
|---|---|
| `python scripts/portable/web_assets.py` | 当前所有vendor/first_party静态资源摘要核验通过 |
| `python -m pytest -q tests/test_agent_docs.py tests/test_portable_runtime.py tests/test_portable_release.py --junitxml=.../packaging-tests.xml` | **32 passed，9.18s，0 failed/0 skipped** |
| `python -m pytest -q tests/test_config_v2.py tests/test_reference_configs.py tests/test_clang_derived_reference_resolution.py --junitxml=.../config-backend-tests.xml` | **73 passed，21.33s，0 failed/0 skipped** |
| `python -m compileall -f -q zscope scripts test tests` | 通过 |
| `python -m mypy zscope` | **330源文件通过** |
| 台账/协调脚本/Markdown只读校验 | **41节点/11拓扑层；脚本AST语法；UTF8无BOM/LF/末尾换行通过** |
| `git diff --check -- scripts/portable/web_assets.py requirements/portable/web-assets.lock.json` | 通过 |

集合分别报告，不累加成整体验收。Astra 的 UI7、报告/接口44、文档6与可见fixture浏览器证据是其独立记录 [ASTRA_UI.md](ASTRA_UI.md)；本轮后台真实API/作业/处置联调为pending。

`dashboard_workbench.js` SHA256 `1547d0dfb26ff2bf4be4e0eaaa5af5e76b42cbe7f7b11975e959fbfd1224fbfa`；CSS `27a7604e62919ac40c36b53b77cdcc367262b726b3b8d1d757707a40664f1a54`。两文件实际字节已独立核对，并纳入 `scripts/portable/web_assets.py FIRST_PARTY` 与 `requirements/portable/web-assets.lock.json`。原有vendor和first_party摘要保持原值。

尚未跑：外部任务实际交付回归、真实job/disposition HTTP/CLI/UI完整联调、完整变体扫描/动态调度/需求替换、真实LLM/完整Sanitizer矩阵、正式准确率/泛化与portable实物。失败记录：Kimi bare ID选择错误、两个Kimi bridge_restarted、DeepSeek native ACP路由/模型不匹配；ZCode未派发。用户保留task_0947f2854f未操作；其代码/恢复不归本轮。
