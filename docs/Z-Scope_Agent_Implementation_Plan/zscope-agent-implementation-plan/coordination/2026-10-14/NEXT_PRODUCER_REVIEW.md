# 两项未导入 producer 的身份边界复核

两个分支仍在开发；本记录不提前把中间版本当最终交付。稳定源字节下的只读 probe 已形成复现，不能因为正常正例通过而绕过。收到正式终态后由原会话修复，不向 busy session 重复派发或让两作者写同一文件。

## S01-CDB-COVERAGE：缺失/外来构建身份仍显示命令覆盖完整

证据 `review-repro/producer-identity-s01/a113229e/review.json`。明确合成 BuildContext（不算 native 证明），复用该分支自己的 `_stored_context`、现有真实 `context_input_status`，先得到有效两宏上下文；随后只把 build_context_id 清空或换成 foreign-arbitrary-identity。两者仍 command_coverage_complete=true/current_commands，source SHA 前后同字节。receipt 的 command_id/依赖一致不能替代构建身份。

验收要求：缺失、未知、错误或不对应当前 manifest 的 BuildContext 身份必须 gap，不能补齐预期 command 分母；source/command_id/BuildContext 互相核对。复用既有 BuildContext 生成/摘要合同，不自行创造另一身份算法；保留 native publisher 对 relative source 的既有表达，不能为修正合成反例拒绝正确 native 上下文。正式 native 双宏与 stale/CDB/response/include 正反例须仍通过，scan_coverage_complete 继续 false，无链接或 Analyzer 授权。

## S08-QUEUE-CORE：旧 owner 省略 token 可以完成已经重新分派的工作

证据 `review-repro/producer-identity-s08/efea6523/review.json`。真实独立 SQLite、受控时间，lease_seconds=1：100时第一次 claim；102时 lease过期同项重新 claim，token已变。旧token显式回传时被正确拒绝，但旧调用方按现有默认 `complete(item_id)` 省略 token 后仍成功 completed 新claim，source SHA 前后同字节。`defer` 同样有 token-less 路径，需要一并核对。

验收要求：完成/延期要绑定当前 claim；未知/缺失 token 不能绕过 old-claim 拒绝。当前无产品消费者，优先把 claim_token 设为明确必需并更新机器API/测试，不为尚不存在的兼容调用保留洞。若另行保留独占模式，必须用真实可核验的独占所有权且该模式不能 lease重取或跨owner使用；不能靠文字“调用方独占”假设。稳定反例覆盖首次、过期、重取、重开实例/恢复输入、complete与defer，真实SQLite不能mock。queue仍不等于scanner接线或完整JOB04/JOB06。
