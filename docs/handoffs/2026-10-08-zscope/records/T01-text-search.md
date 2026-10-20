# T01：全文与文件检索

日期：2026-10-08，Asia/Taipei。开始/结束 HEAD：010f40210b54ba0f79a088312ce5d8be3a82ace0；分支 v1.3.1_feat/llm-wiki。原有交接目录、server.pid 和 m5tpr_replay_results.jsonl 保留；未提交或推送。解释器、运行目录见 [B00](B00-baseline.md)，测试项目/config 均为临时 fixture。

implementation_status: complete

verification_status: passed_local_acceptance

## 变更与决定

- 新增 `zscope/tools/source_access.py` 标准库内核，search_code 增加 symbols/text/files，默认符号行为不变。text/files 在访问 catalog 前分流，不引入 rg、向量库或外部进程依赖。
- search/read 共用项目根、exclude_paths 和语料边界；POSIX nofollow 逐段打开，读取后重新核验文件身份，保护 secrets、truth、报告、运行指令与交接目录。结构化序列化结论键受隔离，普通源码词汇不删除。
- 固定查询 view_id 绑定参数、文件/目录身份，缓存最多 4 个、300 秒；稳定路径/行号排序，视图失效重启。预算、不可读、非法编码、链接等未覆盖原因与结果页独立报告。
- read_code 返回原始 SHA-256 revision；runtime 缓存使用当前许可、文件身份/摘要与 index epoch，撤权或变更后不复用旧结果。修正长输出裁剪循环，保留可续读的完整行。
- 同步 ToolContract、strict schema、工具选择 fixture、README 及 Agent/runtime 模块文档；仍是六工具。没有改 Runtime Agent prompt、Config v2、扫描默认或候选裁决。

## 验收

完整命令与共享结果见 [批次验证](batch-validation.md)、[机器可读结果](batch-validation.json)。

| 验收 | 实际断言 | 结果 |
|---|---|---|
| AC02 | 旧符号形状/ID/排序、read 两入口、strict nullable-required、fallback、Java 工具、schema 大小门禁 | passed；最终组合 356/0/0，exit 0 |
| AC03 | 日志/配置/测试/文件搜索→read；中文/CRLF/长行/二进制/非法编码/无权限/空语料 | passed；test_source_search 26 项，exit 0 |
| AC03 | 路径逃逸、目录/文件链接与打开前替换、分页变化、无重复遗漏、六类扫描预算 | passed；同上 |
| AC07 | secrets/truth/report/AGENTS/交接及嵌套 JSONL 结论隔离；普通 candidate_rule 与注入文本仍为数据 | passed；源码与 MCP/semantic 负例 |
| AC17 | 未触碰 Range 漏洞 fixture 或 truth，未向模型提交扫描源码/答案 | passed；实现/命令核对 |
| AC18 | symbols 默认、工具策略、Java、Ledger freeze、active discovery 回归 | passed；最终组合 |
| 真实模型的工具选择收益、正式 benchmark、全仓检索性能 | 无模型环境，未执行 | not_run；不构成收益结论 |

框架 skipped：0。最终 failed：0。开发迭代出现过 90 passed/2 failed（编号源码格式遗漏），修复后另一轮 90 passed/2 failed（新增 schema 文本超出既有大小门禁）；保留编号输出、压缩描述后 159 项共享回归通过。没有降低门禁；最终 356 项包含上述回归。

## 限制、回退与续接

字面检索不是完整索引。扫描时间、字节、文件数等预算可能造成 partial；分页不会继续扫描语料。只读读取依赖 Linux/WSL 的 dir_fd/O_NOFOLLOW，原生 Windows 无安全实现时返回 unavailable，不降级成不受约束读取。对项目额外私密目录应使用 exclude_paths；内置规则不是任意格式的通用密钥识别器。

源码 revision 只标识当前读取内容，不能充当 D01 的新证据资格。性能未测。省略 scope 恢复旧符号入口；没有持久检索缓存和迁移。下一批若实施 D01，复用这些身份与显式 coverage，不提升文本命中为流或漏洞证明。
