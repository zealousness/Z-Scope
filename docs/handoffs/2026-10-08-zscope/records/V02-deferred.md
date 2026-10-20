# V02：依赖门禁未解锁

> **历史记录，已被取代。** V01 恢复并通过后 V02 已解锁，TSAN 适配已实施并完成真实执行验收；当前状态见 [V02-dynamic-reproduction.md](V02-dynamic-reproduction.md)。本文件只保留当时的门禁判断。

日期：2026-10-08；总控记录。HEAD 为 `010f40210b54ba0f79a088312ce5d8be3a82ace0`，工作区内容基线见 `parallel-G0-native.json`。

状态为 deferred；implementation 为 not_started，verification 为 not_run。默认选 TSAN，未安装或改选 CBMC。

V01 被平台内容安全检查中止，尚无通过 G1/G2 的 runner、执行记录或重放接口。依赖未满足，不提前创建另一套执行系统，也不运行 TSAN fixture。详见 [V01-blocked.md](V01-blocked.md)。

本工作包没有测试命令，exit code 为 N/A；passed 0、failed 0、skipped 0。AC06、AC11、AC15、AC18 全部未执行，不借用工具存在性、K02 或其他任务的测试计数。

后续仅在 V01 的平台限制得到允许范围内的解决、所需实现及 G1/G2/G3 均有真实证据后解锁。再核验已安装 TSAN 与独立构建环境，复用获准 runner；资源或工具不具备时继续保留未决。当前回合不重试被中止任务，不自动安装依赖。
