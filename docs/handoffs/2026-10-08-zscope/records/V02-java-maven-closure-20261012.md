# V01 / V02 同镜像验收闭环 — 2026-10-12

V01、V02 所选 TSAN 路线已完成真实验收。新增的两个原始 Java 节点 **2 passed、0 skipped**，独立核对通过；原普通矩阵合并为 **1736 passed、0 failed/errors/skipped**。同一不可变镜像上的 TSAN、ASAN 各 **5 passed、0 skipped**，既有 compileall/mypy exit 0 继续有效。没有重复启动探针、sanitizer或原1734项，没有产品/测试代码修改。

这两个 Java 节点属于原77文件普通门禁；WORK_PACKAGES中的V02本体选择TSAN，并未新增Java功能要求。此前 [1734 passed / 2 skipped 封存](V02-current-TSAN-acceptance-20261012.md) 及全部首失败、文档6项回执保持原字节，不倒写成旧时已经通过。

## 授权及具体接线

较晚正式接续明确允许按既有开发请求复用已识别的本机官方JDK/Maven及缓存、完成普通接线，无需为一般预算文档重复确认。[原始接续](V02-java-maven-closure-20261012/continuation-authorization.json) 保留了“只准备”被后续“继续执行”替换的时间顺序。原计划的固定397项描述不等于明确禁止普通只读Java输入；此前要求另批是保守解释，已纠正。对应准确原文、条目和执行动作见 [具体方案](V02-java-maven-closure-20261012/JAVA-MAVEN-EXECUTION-PLAN.md)。

继续使用 image ID `60e3b821beb946564925285acdc7c87b55bcdf587f4e3006321728dce2900fff`，未重建、下载、安装或新增并行镜像。JDK21 `21.0.12.1`、Maven `3.8.7`及原离线cache冻结为3510个唯一源文件，481,028,886字节；链接物化后3579个目标文件，481,141,439字节。源路径、真实路径、目标路径、权限、全部SHA256及被省略的非运行时docs/legal链接逐项列于 [输入清单](V02-java-maven-closure-20261012/input-manifest.json)。

新工具/cache、项目快照、控制文件和原Python site-packages分别只读挂载；不挂载用户HOME、Maven登录settings或rc。固定wrapper强制offline、无登录settings和本地只读cache，覆盖通过MavenHome直接找到bin/mvn的路径。源码只读，两套target明确链接到原512MiB tmpfs内自有目录。只对这两个节点设置PATH/JAVA_HOME/MAVEN_HOME，原工具及全局环境不改。

保留默认seccomp、断网、non-root、只读根、cap-drop、NNP、pids256、2GiB/2CPU、tmpfs512MiB和原900秒/8MiB预算，未复用已经撤销的TSAN personality例外。实际整轮20.669秒，证据29,064字节；复制工具/cache481,141,439字节、项目11,272,329字节、控制文件3,386,290字节，WORK分配文件块514,670,592字节，均在已具体记录的限额内。tmpfs峰值未单独测量，不以生成jar大小冒充峰值。

## 真实结果与独立核对

原节点源码和断言未变，仅运行：

- `tests/test_java_source_backend.py::test_spoon_structure_frontend_lombok_processor_real_cli_contract`
- `tests/test_java_source_backend.py::test_javaparser_structure_frontend_real_cli_contract`

[外层实际回执](V02-java-maven-closure-20261012/java-two-nodes-result.json)、[原始XML](V02-java-maven-closure-20261012/java-two-nodes-evidence/two-nodes.xml) 和 [独立审查](V02-java-maven-closure-20261012/independent-java-review.json) 均已归档。实际两次Maven构建成功，Spoon的Lombok on与JavaParser进程成功。Lombok off进程exit 2，包含原测试预期的编译错误；这是负控断言通过，不是pytest失败。

独立读取原始JSON，确认Spoon精确结构、Lombok字段及info调用，JavaParser近似结构、PostMapping和trim调用；同时核对所有stdout/stderr摘要、被执行jar与生成jar的绑定：

| 产物 | 字节 | SHA256 |
| --- | ---: | --- |
| Spoon jar | 17,580,061 | `778a64a4a5072e6b1d043e245a4ec45288ae02472adf4443b6291d25e7be9b47` |
| JavaParser jar | 1,464,939 | `a169e68d3be3b9cad3d4b487e3a188a985e1f868e69bcdf5226ee9e16a3ae497` |

兼容节点集合独立比对：旧1259项、后续248项、Clang接线34项和新Java2项互不重复，集合恰好等于原1543个兼容节点。加原前六组193次执行，得到 **1736 passed**。原三项重型native排除保留；1736是原矩阵执行项计数，不宣称1736个互异断言。原TSAN/ASAN各5项与质量检查以同源码/依赖/镜像证据复用，未为凑新结果重跑。

## 终态、完整性与范围

403项原冻结输入、398项本次源码快照、原Python依赖及工具/cache摘要均无漂移。runner SHA256仍为 `77fdcd1671849348bffcbff643e711b2c260d3ff73907f3d9ac4297b19f6aba7`。本轮是验收环境接线，无必要产品补丁，未派发Kimi或其他模型，没有新增资料外发。

自有Java容器已移除，宿主ASLR仍为2、默认seccomp摘要不变；只读工具快照保留供复核，受控 [回滚脚本](V02-java-maven-closure-20261012/rollback-java-stage.proposed.py) 可在核对claim与已归档证据后仅清理自有副本，未执行删除原工具/cache/仓库的动作。

TASKS更新为V01/V02 done。本次交接变化所需的文档检查单列于 [新文档回执](V02-java-maven-closure-20261012/final-docs-result.json)，最终源码、配置、镜像、容器与旧封存完整性见 [终态证明](V02-java-maven-closure-20261012/final-integrity-proof.json)，完整文件身份见 [证据清单](V02-java-maven-closure-20261012/evidence-manifest.json)。新检查不改写旧6项文档回执。

共同候选镜像已覆盖本轮明确门禁，仍依赖冻结的只读Python/Java工具输入，不宣称自包含发行包。外层容器是验收基础设施；自动计划/harness生成器、CBMC、任意工程安全性、正式Range benchmark及发行验证未新增结论。未提交或推送。
