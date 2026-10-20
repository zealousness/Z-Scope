# K02：条件所有权契约的冲突保护

日期：2026-10-08。Agent C，parallel-20261008。HEAD 保持 010f40210b54ba0f79a088312ce5d8be3a82ace0，分支保持 v1.3.1_feat/llm-wiki；未提交、推送、安装依赖或调用真实模型。

implementation_status: complete

verification_status: passed_g1; awaiting_root_g2

## 实际变更

现有 v4 契约、三值 conditions、所有权角色、资源对象/池域、wrapper 组合、人工优先及工作簿发布屏障已具备目标基础；本任务没有重建这些能力。先通过只读探针复现冲突条件按数组顺序授予不同效果权限，详见 K02-gap-audit.md。

- ApiContract.applicability 汇总所有匹配及仍可能成立的效果；冲突 applies/no_effect 或未闭合 unknown 返回 unknown，不再由第一条匹配决定。已知一致效果保留；失败仍为 does_not_apply，未经核验提议始终 unknown。
- 现有契约编译校验增加简单整数比较/合取的有界重叠检查；证明矛盾效果可能同时匹配时拒绝发布。最多 64 个原子/待处理项，不引入求解器。未知、析取或不支持的条件不伪造不相交证明，消费端仍保守判定。
- CONTRACT_COMPILER_VERSION 从 v15 增至 v16，沿用既有输入失效链；旧 inferred 凭据不能继续授予效果资格。契约 schema、public Config v2、工作簿格式、候选 disposition 均未改。
- 新增 26 项条件所有权测试；成功/失败/未检查返回、声明重排、冲突、参数换位、资源池、人工优先、未验证提议、同名不同文件、文档与源码冲突、旧编译版本、callee 条件变更后的 wrapper 依赖及版本变化均覆盖。

未修改 modeling/SCC/publication、Security Map、公共验证 runner/pipeline 或 RuntimeSpec；这些文件没有被本任务占用，下游可按总控派工接管。

## 最终 G1 验证

所有测试在 WSL Ubuntu，解释器 `/home/zeal/venv313/bin/python`（3.13.15）。固定 PATH 见 parallel-dispatch.md。源码工作目录为 `/mnt/c/Users/10273/home/work/Z-Scope_1.31/Z-Scope`，临时目录均位于 `/tmp/zscope-parallel-20261008/K02/`。

最终轻量命令：

```bash
/home/zeal/venv313/bin/python -m pytest -q \
  tests/test_conditional_ownership_contracts.py \
  tests/test_wrapper_failure_guards.py tests/test_wrapper_contract_compiler.py \
  tests/test_source_contract_boundaries.py tests/test_pool_protocol_modeling.py \
  tests/test_semantic_next_round.py tests/test_semantic_contract_schema.py \
  tests/test_semantic_contract_chain.py tests/test_security_map_contracts.py \
  tests/test_review_proof_identity.py tests/test_contract_only_publication.py \
  -k 'not native_code_to_real_terminal' \
  --basetemp=/tmp/zscope-parallel-20261008/K02/run-4 \
  -o cache_dir=/tmp/zscope-parallel-20261008/K02/cache-4 \
  --junitxml=/tmp/zscope-parallel-20261008/K02/run-4-record/pytest.xml
```

结果：exit 0，**172 passed、0 failed、0 skipped、1 deselected**，25.67 秒。14 个输入文件运行前后 SHA-256 一致。完整 argv、输入摘要和日志存于同目录 validation.json / pytest.log。

获得总控唯一重型名额后，单独执行被排除的真实 native 消费者测试：

```bash
Z_SCOPE_TEST_CLANG_INDEXER=/mnt/c/Users/10273/home/work/Z-Scope_1.31/Z-Scope/build/clang-indexer/zscope-clang-indexer \
  /home/zeal/venv313/bin/python -m pytest -q \
  tests/test_pool_protocol_modeling.py::test_native_code_to_real_terminal_tool_workbook_and_pool_consumers \
  --basetemp=/tmp/zscope-parallel-20261008/K02/native-2 \
  -o cache_dir=/tmp/zscope-parallel-20261008/K02/native-cache-2 \
  --junitxml=/tmp/zscope-parallel-20261008/K02/native-2-record/pytest.xml
```

结果：exit 0，**1 passed、0 failed、0 skipped**，6.54 秒；4 个相关输入与工具摘要稳定。indexer SHA-256 为 `8b8014fa8b405c40478d335ea45435c990c9104e5a6b9fb2f971704d0b4d69ba`，ldd 无缺失库。实际 PATH clang 为 `/usr/lib/llvm-18/bin/clang`，18.1.3。原有 native 测试使用 fake terminal/model response，真实执行的是 native 索引与工作簿/消费者链，不能声称真实 LLM 验收。重型名额已释放。

`python -m mypy zscope/semantics/contracts.py zscope/semantics/contract_conditions.py zscope/semantics/contract_compiler.py --cache-dir /tmp/zscope-parallel-20261008/K02/mypy-cache`：exit 0，3 source files；本任务路径 `git diff --check`：exit 0。仅格式化修改文件，撤回三处无关 Black 格式差异。

## 验收映射

| 验收 | 结果 |
|---|---|
| AC06 | 未验证模型/旧编译版本无效果权限，callee 条件变更传播依赖与契约版本；passed |
| AC13 | 成功/失败、对象/池、冲突/未知、同名消歧、参数换位、manual 优先、文档冲突、源码失效；passed |
| AC17 | 只使用独立临时 fixture 与既有测试；未读 truth、未修改 Range、无真实模型调用 |
| AC18 | 契约/工作簿/消费者/既有建模回归 passed；跨模块最终回归由总控 G2 运行 |
| 真实 LLM、正式 Range、性能/准确率 | not_run；本任务未生成此类结论 |

## 迭代事实

- 第一轮：82 passed、43 setup errors，exit 1。原因是指定 basetemp 的 K02 父目录尚不存在；这些 fixture 未执行，不能算通过。未修改产品来规避，先 mkdir 后重验。
- 第二轮：124 passed、1 deselected，exit 0。
- 格式后扩展回归：171 passed、1 deselected，exit 0；增加 callee 变化专项断言后最终为 172 passed。
- native 首轮：1 skipped，exit 0，原因是 Z_SCOPE_TEST_CLANG_INDEXER 未设。只在下一条命令显式复用 B/P01 已存在工具，补验 1 passed；原 skip 保留。

## 冻结交接

| 文件 | SHA-256 |
|---|---|
| zscope/semantics/contracts.py | f4b881979887e5b23a5dea8a00295bfa3868c9858a514d8e2a298e24b0913101 |
| zscope/semantics/contract_conditions.py | cc0a4656b822f76c3bb38377e46c29fb00f36e0c64b2fdba980f0653c9d38965 |
| zscope/semantics/contract_compiler.py | cb8335f24f22a917442e8f205c8dcbb7c3620f9e8da07ac08a44f3f5f61bbcdb |
| tests/test_conditional_ownership_contracts.py | ef1bd95ea78443a84bd035729aa5d11a88fd4cdd32fb16b8dbd690314096ef09 |

上述产品/测试文件冻结等待总控 G2。通用复杂协议、任意条件求解及完整 cache_only freshness receipt 不在此次增量中；原有 unknown/unverifiable 不提升为 current/proof。
