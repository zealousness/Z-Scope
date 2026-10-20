# P01 — 构建变体清单与增量／全量差分

## 基本信息

| 字段 | 实际值 |
|---|---|
| 日期／时区 | 2026-10-08 / Asia/Taipei |
| 执行者 | Agent B（topology_ownership）；总控管理集成与重型执行窗口 |
| 开始／结束 HEAD | `010f40210b54ba0f79a088312ce5d8be3a82ace0`；无提交 |
| 分支 | `v1.3.1_feat/llm-wiki`；保留 G0 原有脏工作区 |
| cwd | `/mnt/c/Users/10273/home/work/Z-Scope_1.31/Z-Scope` |
| 解释器 | WSL Ubuntu `/home/zeal/venv313/bin/python`，Python 3.13.15 |
| 目标工程／配置 | 自建固定 C fixture；不加载用户 YAML，不启动扫描或 LLM |
| implementation_status | complete |
| verification_status | task_specific_passed；共享集成门由总控登记 |

全部质量／运行命令使用 G0 的 Linux PATH：

```text
/home/zeal/venv313/bin:/home/zeal/go/bin:/usr/lib/llvm-18/bin:/home/zeal/.local/svf/SVF-linux-x86_64/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
```

实际 native 工具为仓库现有 `build/clang-indexer/zscope-clang-indexer`，没有编译、安装或升级外部依赖。能力：Clang 18.1.3、facts protocol v2、argument-check v1、argument-policy revision 3。工具 SHA-256：`8b8014fa8b405c40478d335ea45435c990c9104e5a6b9fb2f971704d0b4d69ba`。

## 变更与边界

- `indexing_inventory.compilation_contexts()` 复用原 `command_identity()` 与 `digest_json()`。原 identity 及生产缓存 key 未改变。逐原始命令保留 context、source、selected/equivalent/uncovered/unverified、重复命令指向和同源 variant 清单；只有完全相同的命令／响应文件／环境 identity 才计为 equivalent。宏、include、ABI、响应文件变化不合并。无法解释的 selected context 会阻止 selection/coverage verified。
- 现有 `inventory()` 兼容增加上述字段，仍区分编译覆盖、链接组与运行身份；只有有 manifest 证据的选择才标 selected。选中了命令不等于对应 bitcode 已通过完整性检查。
- 新增 `retrieval/incremental_replay.py`，只创建受控、无答案的固定 C fixture。每类 mutation 都从独立 baseline 开始；A 保留增量状态，B 使用全新数据库、native/derived cache 及参数预检状态。两路最终源码和编译数据库路径相同。A 的参数预检产物移动到本次新 work 的 `incremental-preparation/` 保留，绝不清理用户真实缓存。
- 比较全部已发布事实表以及所选 TU 原始记录，分别保留宏、类型引用、调用边、程序／资源事件、删除传播、编译变体和 coverage。SQL 存储 ID 映射为逻辑外键，忽略明确的索引时间、调度 generation/retry 字段；原始 TU 只剔除 complete footer 中参数检查 attempt 的 `wall_seconds`。不递归按通用字段名删内容；嵌套程序事实中的同名字段仍比较。
- 新 CLI 路线：`zscope-index-audit --replay-fixture --work-directory <全新目录> --clang-indexer <已有工具> --output <报告>`。普通 `--config/--bitcode-dir` 用法保持；replay 不接受项目配置、SVF 输入或任意 mutation/build 命令，不启动 LSP fallback。public Config v2、六工具、生产 Clang AST+SVF 和扫描默认均未改变。
- `report.complete` 表示指定 replay 各例执行及比较完成，不表示整个工程／所有变体完整。未选变体明确列为 uncovered；SVF/Saber、LLM 语义、任意实际 C/C++ 工程不在这次等价范围。

## 验收结果

最终专项测试与回归分别为 **28 passed / 0 failed / 0 skipped** 和 **79 passed / 0 failed / 1 skipped**。它们是两套测试结果，不累加中途重跑形成虚增。

| 验收 | 实际执行／断言 | 结果 | 退出码／数量 |
|---|---|---|---|
| AC12 编译上下文 | 完整原始命令、重复项、macro/include/ABI/response 差异、无证据选择、unknown selected context | passed | 包含在最终 28 项中 |
| AC12 比较器 | 存储 ID／时间规范化，事实类别删除、重复数、coverage/build context、嵌套数据、未知事实表不丢失 | passed | 同上 |
| AC12 真实 native mutation | 8 类，各 baseline cold/hot → 增量 → 独立干净重建，两个完整事实视图比较 | passed | 8/8；未解释差异 0 |
| AC16 隔离采样 | 总控确认 A/C/root 停止源码写入与所有测试；5 个全新 Python 进程，仅 function_body | passed | 5/5，全部输入前后摘要一致 |
| AC17 答案／fixture 隔离 | 仅 runner 内固定 C 源码，未读取或修改 Range/truth；不运行 fixture 二进制 | passed | 设计与真实执行一致 |
| AC18 缓存隔离 | 已存在 work 路径拒绝；预检目录保留；符号链接拒绝；无 native 工具不退到 LSP | passed | 包含在最终 28 项中 |
| 索引身份／增量／SVF 缓存回归 | 4 个既有测试文件 | passed + skipped | 79 passed、1 skipped；exit 0 |
| Black --check | 本任务 3 个产品文件和 1 个测试文件 | passed | exit 0 |
| 定向 compileall／mypy | 同上产品／测试编译；mypy 3 个产品文件 | passed | 均 exit 0 |
| 定向 git diff --check | 本任务文件 | passed | exit 0 |
| 交接文档与编码 | `python -m pytest -q tests/test_agent_docs.py`；本记录 UTF-8 无 BOM、LF、末尾换行 | passed | 6 passed、exit 0 |
| 全仓 compileall/mypy、共享文档与跨模块集成 | 总控执行并记录 | not_run by Agent B | 由总控门禁记录补充 |
| 原回归中的 LLVM/SVF 项 | `test_real_direct_bitcode_dependency_cache_and_svf` 因 `Z_SCOPE_TEST_LLVM` 未设置被框架跳过 | skipped | 保留原结果，后续独立补验见末节 |
| 真实 LLVM/SVF 独立补验 | 同一受控 fixture 测试，显式 `Z_SCOPE_TEST_LLVM=1` 并核对已有动态库 | passed | 1 passed、0 skipped；exit 0 |
| 实际大仓、统一后端／模型、WPA 瓶颈、正式 benchmark | 未执行 | not_run | 不据此给出端到端速度或准确率结论 |

### 可复跑命令

WSL 工作目录如上。每次用新的 run 目录；先建立 `--basetemp` 的父目录，不能复用其他 worker 的临时目录。

```bash
# 本次 native4 的 pytest argv（父目录由外层 Python 创建）。
Z_SCOPE_TEST_CLANG_INDEXER=/mnt/c/Users/10273/home/work/Z-Scope_1.31/Z-Scope/build/clang-indexer/zscope-clang-indexer \
Z_SCOPE_CLANG_BATCH_MEMORY_MB=512 \
/home/zeal/venv313/bin/python -m pytest -q tests/test_incremental_replay.py \
  --basetemp=/tmp/zscope-parallel-20261008/P01/native4/tmp \
  -o cache_dir=/tmp/zscope-parallel-20261008/P01/native4/cache

/home/zeal/venv313/bin/python -m pytest -q \
  tests/test_indexing_pipeline.py tests/test_clang_identity_validation.py \
  tests/test_clang_incremental_extraction.py tests/test_svf_cache.py \
  --basetemp=/tmp/zscope-parallel-20261008/P01/regression1/tmp \
  -o cache_dir=/tmp/zscope-parallel-20261008/P01/regression1/cache

/home/zeal/.cache/zscope-p1-black-venv/bin/black --check \
  zscope/retrieval/indexing_inventory.py zscope/retrieval/incremental_replay.py \
  zscope/cli/index_audit.py tests/test_incremental_replay.py
/home/zeal/venv313/bin/python -m compileall -f -q \
  zscope/retrieval/indexing_inventory.py zscope/retrieval/incremental_replay.py \
  zscope/cli/index_audit.py tests/test_incremental_replay.py
/home/zeal/venv313/bin/python -m mypy \
  zscope/retrieval/indexing_inventory.py zscope/retrieval/incremental_replay.py \
  zscope/cli/index_audit.py --cache-dir=/tmp/zscope-parallel-20261008/P01/quality2/mypy
```

### 真实差分结果

下表 rebuild/reuse 为实际 TU 数。每行的输入根和 A/B 缓存均独立于其他行。

| mutation | hot rebuild/reuse | incremental rebuild/reuse | clean rebuild/reuse | 未解释语义差异 |
|---|---:|---:|---:|---:|
| function_body | 0 / 3 | 1 / 2 | 3 / 0 | 0 |
| shared_header | 0 / 3 | 2 / 1 | 3 / 0 | 0 |
| macro | 0 / 3 | 1 / 2 | 3 / 0 | 0 |
| compile_command | 0 / 3 | 1 / 2 | 3 / 0 | 0 |
| delete | 0 / 3 | 2 / 0 | 2 / 0 | 0 |
| rename | 0 / 3 | 3 / 0 | 3 / 0 | 0 |
| callback_target | 0 / 3 | 1 / 2 | 3 / 0 | 0 |
| negative_include | 1 / 2 | 3 / 0 | 3 / 0 | 0 |

negative include 的缺失头导致 native dependency completeness 为 false，现有生产逻辑保守地重新提取该 TU；本任务没有把它伪造为可复用缓存。最终新增 `late.h` 的效果进入两路事实比较。所有 mutation 相对其 baseline 都产生了可观察变化。最终非删除例包含 9 个函数记录、4 条调用边、3 个类型定义、3 个宏定义、8 条类型引用及 17 个嵌入程序事件；删除例对应 8 个函数与 15 个程序事件。不是空数据库之间的比较。

### AC16 五次隔离采样

这组仅为 **function_body**；八类 correctness 与五次性能采样不是同一口径。每个样本启动新 Python 进程和应用缓存，1 个 TU worker，512 MiB reservation。OS 页缓存没有清空，不标 OS-cold；CPU/RAM 环境与工具身份保存在原始报告。采样前由总控确认其他 agents 已暂停写入／测试，后比较整个 `zscope/*.py` 树、RuntimeSpec、专项测试与 native 工具摘要一致。

| 阶段 | wall 中位数秒 [min, max] | CPU 中位数秒 | 20 ms 采样进程树峰值 RSS 中位数 bytes |
|---|---|---:|---:|
| baseline cold | 2.061844 [2.050894, 2.107609] | 1.528319 | 105967616 |
| baseline hot | 0.646820 [0.630070, 0.653959] | 0.527210 | 91103232 |
| incremental | 1.152736 [1.133758, 1.217965] | 0.909138 | 100618240 |
| clean | 1.999728 [1.970130, 2.018409] | 1.498456 | 113647616 |

RSS 是 Python 加当前子进程的采样值，可能漏掉极短峰值；不是精确内核 peak。每样本保留的全部 fixture/cache/比较报告约 1.50 MB，实测 bytes 为 1507881、1507902、1499709、1499733、1507904。无置信区间／p95／真实工程速度承诺。这里没有 WPA/Saber 测量，R01 是否有价值仍未知。

## 产物与输入摘要

关键 JSON 已按原始字节复制进交接目录并核对 SHA-256，后续会话不依赖 `/tmp` 即可读取验收摘要。它们只含命令、路径、摘要、工具／动态库身份、计数和采样值，不含凭据、私有源码正文、原始 TU 事实或数据库：

- [八类真实增量／全量差分摘要](P01-native-replay.json)
- [五次隔离采样及输入前后摘要](P01-isolated-sampling.json)
- [LLVM／SVF 工具与动态库预检](P01-llvm-preflight.json)
- [LLVM／SVF 实际补验与身份稳定性](P01-llvm-execution.json)

- 最终专项运行日志／前后输入摘要：`/tmp/zscope-parallel-20261008/P01/native4/{pytest.log,execution.json}`。
- 8 类原始数据库、native artifact、参数预检、两路规范化事实与 differences：`/tmp/zscope-parallel-20261008/P01/native4/tmp/test_real_mutation_replay0/real replay/`。总报告 SHA-256：`d06398038d1d365dce21936dee8b262fab1183911d4a81dceee34e9b9ca731b3`。
- 隔离 5 样本、独立子进程日志、全部 producer 前后摘要与聚合：`/tmp/zscope-parallel-20261008/P01/isolated5/sampling.json`，SHA-256：`4fbcb8d2c02b07c0049fdec92a7b02fdf3069b456cd81993b5a4932c172265d6`。
- 回归与质量日志：`/tmp/zscope-parallel-20261008/P01/regression1/`、`/tmp/zscope-parallel-20261008/P01/quality2/`、`/tmp/zscope-parallel-20261008/P01/docs1/`。大型数据库／raw cache 仍仅在临时目录，重启前应按需保留；关键小型验收／采样 JSON 已归档到上述交接链接。

| 本任务交付文件 | SHA-256 |
|---|---|
| zscope/retrieval/indexing_inventory.py | `dcca9edd5bd910f6098f564e61c19b39ba7e65040dc41e5c1af3e4c719a1e85f` |
| zscope/retrieval/incremental_replay.py | `5e5d93e8b8d839c74d52e0bccc06ab83afeed7fc9cd740acf8d5fb48877a6874` |
| zscope/cli/index_audit.py | `a82040bc26d0fba8d66004c70058b3f557fef63228afc5cc5d8920873e8ba563` |
| tests/test_incremental_replay.py | `6b403abf8da175f7b166f6097f0992a5fdfdc02bf28eb9cfda9033a45aca4b3c` |

## 中途失败与修正

没有把中途失败改写为通过：首个单测命令遗漏 basetemp 父目录，结果 6 passed、19 setup errors、1 deselected；后续独立 `unit2` 实际 25 passed。最初 native1 在当前提取读取时误用了严格缓存复用门，遇到缺失 include 的 `dependencies_complete=false` 而拒绝读取；修正为核对当次 artifact／输入并保留不完整标记，未放宽生产缓存规则。native2 单类和 native3 的 26 项已通过；随后补强 B 路参数预检冷启动，最终 native4 的 28 项通过。所有中途 native 原始目录保留。

## 续接与回滚

新 replay 仅显式 CLI 启动，不改变默认扫描或现有缓存格式。停止调用 replay 即恢复原运行行为；不得删除既有用户产物。总控接续更新 TASKS/PROGRESS 与稳定模块文档；P02 仍须等 P01、D03、K02 共同通过集成门，Agent B 尚未修改建模调度文件。R01／真实大仓及完整 unified 增量差分另行安排，不把这次 selected Clang fixture 结果外推。

## 后续补验：真实 LLVM／SVF 兼容 smoke

总控再次授予唯一重型名额，在产品代码保持冻结的情况下单独运行原先被 opt-in 条件跳过的测试。首次仅设置固定 PATH 的 preflight 中，所有工具均解析成功，但 `ldd wpa/saber` 显示 `libLLVM.so.18.1rc => not found`，因此停止，未启动测试。原失败输出保留于 `/tmp/zscope-parallel-20261008/P01/llvm1/preflight.json`。

确认现有 `/home/zeal/.local/svf/llvm-18.1.0.obj/lib/libLLVM.so.18.1rc` 可用后，只给补验子进程设置如下环境；没有下载、安装、重建、修改全局环境或降低检查要求。再次 `ldd` 均无缺失库，并记录解析工具／库的内容摘要。

```bash
LD_LIBRARY_PATH=/home/zeal/.local/svf/SVF-linux-x86_64/lib:/home/zeal/.local/svf/llvm-18.1.0.obj/lib \
Z_SCOPE_TEST_LLVM=1 /home/zeal/venv313/bin/python -m pytest -q -rs \
  tests/test_indexing_pipeline.py::test_real_direct_bitcode_dependency_cache_and_svf \
  --basetemp=/tmp/zscope-parallel-20261008/P01/llvm2/tmp \
  -o cache_dir=/tmp/zscope-parallel-20261008/P01/llvm2/cache
```

结果为 **1 passed、0 failed、0 skipped，9.53 秒，exit 0**。验证了真实 bitcode 冷构建、热复用、aggregate manifest 丢失后的 checkpoint 恢复、头文件改变后的 inventory 失效与重建，以及实际 WPA/Saber 成功返回并有 CPU／RSS 指标。测试只分析临时 fixture 的 bitcode，不执行生成的 C 二进制。

源码、工具和 LLVM 库的前后摘要全部稳定。证据在 `/tmp/zscope-parallel-20261008/P01/llvm2/`：`preflight.json` SHA-256 为 `0152f99b01eec8ad13875ced655c0e5c508436fe503fd1d900a9dda81842a3da`；`execution.json` 为 `2daa74cdcc70c0569a665c26d6ecba7a3de1539868e48ef0a6969dfe0d13c3c9`；`pytest.log` 为 `1e725cac59b380c4fa3b76fcb9e83143c19e5aea7f7331385d168d034ed337f0`。加载的 LLVM 共享库 SHA-256 为 `7b82c9ef64c63b6d70a07ae0cc699ef6a1b179d79cd94d95a1778a2cb6c47f39`。

原 79 passed／1 skipped 记录保持原样。这次补验是独立的兼容 smoke，不是 SVF 事实增量／全量等价矩阵，也不是隔离性能测量；不能据此判断 WPA 瓶颈或 R01 的收益。
