# 两项原 Java 普通门禁：同镜像接续执行方案

本文件形成时尚未复制工具、创建新挂载或启动Java/Maven/容器/测试。较晚的正式接续已明确授权复用既有已识别工具和缓存完成普通接线，记录于 [接续授权](continuation-authorization.json)。执行后只以独立结果文件报告实际状态，不倒写准备时事实。

## 原验收条目及授权解释

原 [SINGLE-IMAGE-PLAN.md 第47行](C:/Users/10273/Documents/Codex/2026-10-10/task-3/v02-single-image-execution-20261010/approved-plan/SINGLE-IMAGE-PLAN.md:47) 明确要求：“普通组：在共同镜像重跑原批准的1736次执行矩阵（含重复覆盖），保留原节点选择、断言及三项重型native用例排除”。旧兼容XML已经独立核对两节点原先均通过，属于原77文件普通矩阵，非新增V02功能要求；V02本体在WORK_PACKAGES中选择TSAN，未要求Java。

原计划 [第58行](C:/Users/10273/Documents/Codex/2026-10-10/task-3/v02-single-image-execution-20261010/approved-plan/SINGLE-IMAGE-PLAN.md:58) 写明“仍为原397项、299,239,592字节（约285.4MiB），源文件摘要完全沿用，不增加软件下载”；[第21行](C:/Users/10273/Documents/Codex/2026-10-10/task-3/v02-single-image-execution-20261010/approved-plan/SINGLE-IMAGE-PLAN.md:21) 要求将依赖COPY入镜像时先追加清单与预算。**此前据此把所有新增只读测试输入都视为必须另获批准，是保守解释，不是原文明确禁止Java/Maven普通接线。** 当前较晚授权允许现有官方工具/cache复用；本方案据此继续，不再次请求普通开发批准。不新增安装、下载、安全例外或不可逆仓库操作。

## 精确输入和规范化

[input-manifest.json](input-manifest.json) 逐文件列出逻辑源路径、解析后的物理源路径、目标相对路径、SHA256、字节数和权限。3510个唯一源文件共481,028,886字节；物化文件链接后3579个目标文件共481,141,439字节，增加112,553字节。所有文件链接物化为常规只读文件，目录链接仅显式省略非运行时docs/legal，断开的非运行时src.zip显式省略；未识别的运行时目录链接会在准备时失败，不跟随到未知输入。

归一化根为 `/home/zeal/.cache/zscope-common-java-20261012/tool-inputs`，只读挂载至 `/java-inputs`：

- JDK源 `/usr/lib/jvm/java-21-openjdk-amd64` → `jdk/`。
- Maven启动脚本与boot/lib/m2.conf的实际引用 → `maven/`；原脚本保存为 `maven/bin/mvn.original`，身份不变。
- 既有 `/home/zeal/.m2/repository` → `cache/`，物化后只读；不复制settings、rc或凭据。
- [python-dependencies.json](python-dependencies.json) 冻结原只读site-packages的7891项身份，不复制、升级或替换。
- 398个原产品/测试/Java源输入共11,272,329字节，逐项列于input-manifest的project_files；复制到自有快照 `/repo`，原源码不改。

生成的 [Maven入口](generated/mvn)、[离线settings](generated/settings.xml) 和 [日志配置](generated/simplelogger.properties) 逐项摘要及容器路径见 [control-manifest.json](control-manifest.json)。无server/proxy/mirror或登录配置；settings只声明offline、非交互和固定本地repo。

## 最大预算

| 范围 | 最大字节/限额 |
| --- | ---: |
| 唯一新增源内容（只读观察） | 481,028,886 |
| 工具/cache归一化复制一次 | 481,141,439 |
| 项目只读快照复制一次 | 11,272,329 |
| 控制文件复制 | 16,777,216 |
| 本次日志/XML/结果输出 | 8,388,608 |
| WORK内常规文件内容合计 | 517,579,592 |
| 准备资料自身内容 | 16,777,216 |
| 最终证据另存一次（不另存工具/cache） | 8,388,608 |
| 上述内容峰值合计 | 542,745,416 |
| WORK已分配文件块观测停止阈值 | 671,088,640 |
| 原tmpfs硬上限 | 536,870,912 |
| 原容器内存硬上限 | 2,147,483,648 |
| CPU / pids / 整轮墙钟 | 2 / 256 / 900秒 |

复制前后逐文件核对，并按固定内容限额检查。640MiB是观测的文件块停止阈值，不是文件系统quota；不谎称内核限制了inode或全局Podman元数据。900秒包含准备和收尾，实际容器执行预留最后40秒清理。超限停止，不扩大资源。

## 拟执行 driver、挂载与环境

外层 [java-two-nodes-container.proposed.py](java-two-nodes-container.proposed.py) 和内层 [java-two-nodes-inside.proposed.py](java-two-nodes-inside.proposed.py) 已做AST解析，尚未用执行冒充静态验证。全部准备文件在prepared-artifact-manifest.json封存，执行命令用其实际SHA256参数绑定，不以flag本身当作人类授权。

```text
wsl -d Ubuntu --exec /home/zeal/venv313/bin/python
  /mnt/c/Users/10273/Documents/Codex/2026-10-12/task-3/v01-v02-kimi-resume-20261012/java-maven-preparation-20261012/java-two-nodes-container.proposed.py
  --approved-java-maven-inputs-20261012
  --prepared-manifest-sha256 <prepared-artifact-manifest.sha256内的精确值>
```

Podman保持image ID `60e3b821beb946564925285acdc7c87b55bcdf587f4e3006321728dce2900fff`，`--pull=never --network=none --read-only --userns=keep-id --user 1000:1000 --cap-drop=all --security-opt=no-new-privileges --pids-limit=256 --memory=2g --cpus=2 --tmpfs /tmp:rw,size=512m,exec`。使用默认seccomp，不复用已撤销的TSAN personality例外。

只读挂载：tool-inputs→`/java-inputs`，project→`/repo`，control→`/control`，原site-packages→`/venv/lib/python3.13/site-packages`。自有evidence→`/work:rw`。完整argv保存在外层源码并会记录实际回执。

仅该容器设置 `PATH=/java-inputs/maven/bin:/java-inputs/jdk/bin:/usr/local/bin:/usr/bin:/bin`、`JAVA_HOME=/java-inputs/jdk`、`MAVEN_HOME=M2_HOME=/java-inputs/maven`、`MAVEN_SKIP_RC=1`；MAVEN_CONFIG/MAVEN_ARGS清空。所有JVM固定Xms32m/Xmx512m/Metaspace256m、tmp目录和自有user.home；Maven的两份settings路径都指向自有离线settings，cache只读。原启动脚本仍执行，包含Java内部通过MavenHome找到bin/mvn的路径亦经过固定wrapper。

快照中两个sidecar的target是明确指向 `/tmp/java-targets/spoon`、`/tmp/java-targets/javaparser` 的链接；源码挂载继续只读，输出都计入原512MiB tmpfs，不额外挂载更大的可写层。不存在用户HOME/settings/rc/凭据挂载。

只运行原两节点，保留原源码/断言，`pytest -x`，必须2 passed、0 failed/errors/skipped：

```text
tests/test_java_source_backend.py::test_spoon_structure_frontend_lombok_processor_real_cli_contract
tests/test_java_source_backend.py::test_javaparser_structure_frontend_real_cli_contract
```

记录真实命令、Maven/Java stdout/stderr、生成jar摘要、被执行jar摘要、XML、隔离核对和输入漂移。JDK/Maven动态库兼容性及offline闭包仍须以本次实际节点结果验证；缺库、缓存不足、输出/时间/内存不足都失败停止，不联网兜底。通过只产生两节点结果，之后独立核对再与原稳定1734项合并，绝不重复计数。

## 停止、回滚与证据

固定容器名 `zscope-common-java-20261012-two-nodes`、固定WORK及exclusive claim防止盲重试；同名已有容器时停止准备，不操作别的实例。任何失败清理该自有容器，保留WORK、claim和首失败供审查。无需回写系统配置或重建镜像即可撤销接线，后续默认profile。

证据封存后可执行 [rollback-java-stage.proposed.py](rollback-java-stage.proposed.py) 的 `--remove-owned-stage-after-review`：核对固定绝对路径、claim、镜像、容器名及已归档证据后，仅删除自有WORK；不会删除原工具/cache/仓库/旧封存。准备阶段不执行这个回滚脚本。
