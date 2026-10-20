# T02：严格只读语义

日期：2026-10-08，Asia/Taipei。开始/结束 HEAD：010f40210b54ba0f79a088312ce5d8be3a82ace0；分支 v1.3.1_feat/llm-wiki；保持已有未跟踪产物。WSL `/home/zeal/venv313/bin/python`（3.13.15），工作目录为当前 checkout 的 /mnt/c 路径；测试均使用临时 config/project。

implementation_status: complete

verification_status: passed_local_acceptance

## 变更与决定

新增 refresh_policy=cache_only/ensure_current。普通函数查询省略时保持原 resolver/model-input 路径；非函数 kind 不接受 ensure_current，只读 profile 显式刷新为 forbidden。独立缓存路径不调用 resolver、build_semantic_model_input 或旧 SnapshotStore 的 load/needs_refresh 接口。

`common/readonly.py` 按文件描述符固定各级路径，读取项目内 checkpoint 后 SQLite，以 mode=ro、immutable、query_only 避免 journal/shm/迁移。活动 WAL、链接、缺权限返回 unavailable；读取前后核验文件身份。SQLite 单值与元数据读取设有界限。`snapshots/readonly.py` 对已提交快照登记与 payload 做身份/源码摘要核对。

**旧存储没有完整独立输入收据。** 未变的函数体不能证明头文件、编译参数、callee、人工契约、Wiki 与 spec 仍有效，因此返回 unverifiable，绝不伪造 current。源码明确变化为 stale；missing、corrupt、unavailable 分别可观察。没有添加不可靠的 mtime=current 判定，也没有为返回 current 偷调会补索引的 helper。真正 current 的完整收据验证/发布不在这批实现中。

只读结果 contract 为空。普通 cache_only 可读标明历史/advisory 的 payload；candidate_blind 完全去掉 payload，Security Semantic Map 用字段/类型投影，只保留程序/用户来源 claim 身份和引用、unit 成员等，不透传 value、怀疑点、候选、review hint 和嵌套结论 metadata。

## 验收

| 验收 | 实际断言 | 结果 |
|---|---|---|
| AC02 | 新参数严格校验、普通默认刷新兼容、混合 annotation false/强制只读 true | passed；契约及既有 evidence tests |
| AC04 | 未变/missing/stale/corrupt/header/build/contract/document/spec；resolver、LLM、model input、快照、UserConfigStore、KnowledgeDB、CodeIndex、线程提交 spy 均零调用 | passed；test_semantic_cache_only 14 项，exit 0 |
| AC04 | 查询前后持久文件内容与 mtime 不变、SQLite 写入失败、活动 WAL 拒绝、缺失不建库、嵌套目录链接拒绝 | passed；同上及 MCP 生命周期测试 |
| AC04 | 有完整独立收据且能证明 current 的真实缓存 | not_run；现有格式不提供此能力，保守归为 unverifiable |
| AC07 | 恶意嵌套 map/快照结论字段不出现在盲角色结果；图/流未知不返回未核验 metadata | passed |
| AC18 | 正常默认、Config v2、Java、候选冻结和主动发现回归 | passed；最终组合 356 passed/0 failed/0 skipped，exit 0 |
| 真实模型刷新/全后端完整快照集成、性能 | 未执行 | not_run |

具体命令见 [批次验证](batch-validation.md)。上述 current 项记录的是不支持的强化能力，并非绕过本任务“身份不足不能 current”的验收。缓存的五类适用情况都走独立只读路径；没有把 fixture 变成正式分析准确率结果。

## 限制、回退与续接

profile 外省略 refresh_policy 仍是原行为；没有快照 schema 迁移、删除或重建。只读服务遇到 WAL 需由写入方结束并 checkpoint；服务自身不 checkpoint。历史快照/Map 只能作为导航和背景。未来若需要 cache_only=current，先设计并验证涵盖全部输入依赖的持久身份，再扩大可信输出；不能直接翻转这里的状态。
