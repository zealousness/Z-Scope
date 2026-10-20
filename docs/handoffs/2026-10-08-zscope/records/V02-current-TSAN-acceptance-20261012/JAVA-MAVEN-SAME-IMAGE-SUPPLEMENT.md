# 同镜像剩余两项 Java 验收的补充方案（尚未执行）

当前共同镜像仍为 `60e3b821beb946564925285acdc7c87b55bcdf587f4e3006321728dce2900fff`。真实 TSAN/ASAN 各5项通过，普通矩阵1734 passed、2 skipped，compileall/mypy通过。本方案只补剩余两项，不重复成功的独立启动探针、已通过普通项或 sanitizer。

## 已只读核对的输入

| 现有输入 | 身份/位置 | 唯一文件 | 字节 |
| --- | --- | ---: | ---: |
| JDK21 | Ubuntu 21.0.12.1，`/usr/lib/jvm/java-21-openjdk-amd64` | 237 | 299,604,430 |
| Maven runtime | 3.8.7，`/usr/share/maven` 的启动脚本、boot/lib与m2.conf及实际jar引用 | 45 | 9,962,646 |
| 离线 Maven cache | `/home/zeal/.m2/repository` | 3228 | 171,461,810 |
| 合计 | 逐文件SHA256及链接见 [盘点清单](java-maven-readonly-inventory.json) | 3510 | 481,028,886 |

约458.7MiB是唯一源文件内容量，不含清单、路径规范化可能产生的重复内容和测试输出；不是已经批准的新增磁盘总上限。读取了宿主ldd，没有启动Java/Maven、编译、联网、安装或新增挂载。未读取/复制用户或全局Maven settings、rc文件或凭据。候选在原镜像中的动态库兼容性、全部离线依赖闭包、实际临时输出占用仍未验证。

## 待批准后的限定动作

1. 保持同一image ID，不建立另一条镜像路线。按上述摘要复核并冻结必要的既有工具/cache输入；若规范化复制所需空间超出审查后的预算，停止，不自动扩大。逐文件核对符号链接目标，使用独立只读测试输入目录；不复制Maven登录配置。
2. 为两个Java节点加入固定的JDK/Maven/cache只读挂载和仅该组使用的PATH/JAVA_HOME。Maven入口强制offline、`MAVEN_SKIP_RC=1`，以自有空settings覆盖用户和全局settings，明确指定冻结cache；不使用host网络或在线补依赖。镜像内缺库或cache缺项即失败停止。
3. 源码继续只读。两套sidecar的`target`在准备快照中指向既有512MiB tmpfs内独立自有输出目录；不添加更大的tmpfs或把仓库改为可写。运行预算保持2GiB/2CPU、pids256、断网、non-root、cap-drop、NNP、默认seccomp、900秒/8MiB。必要的JVM堆上限在审查driver中固定并记录，不提高外层限额。
4. 只运行下列两个原始节点，保留其测试源码及断言。保存工具、cache、源码、命令、输出与XML摘要；任一失败、跳过或资源不足即停止。通过后把两项新证据与稳定的1734项、质量检查合并核对，再更新整体状态。

```text
tests/test_java_source_backend.py::test_spoon_structure_frontend_lombok_processor_real_cli_contract
tests/test_java_source_backend.py::test_javaparser_structure_frontend_real_cli_contract
```

本补充需决定的是：**是否允许在既有同一镜像的验收中新增上述固定只读Java/Maven/cache输入及其受限输出接线**。原SINGLE-IMAGE-PLAN仅批准397项追加和既有Python依赖挂载；本次候选3510项、约459MiB额外输入超出该明确清单。没有把“继续开发”的授权解释为已批准这份新增工具/预算。批准后仍须先形成完整路径/预算/driver清单再执行，当前仅为只读盘点与方案。
