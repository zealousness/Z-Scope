# Review 完整事实实验：实现与验证记录

状态：**experimental，默认关闭，尚未证明 review 真误报下降 50%**。

## 实现范围

- 完整事实存储：保存 Clang AST、CFG 原文与函数图、预处理结果及宏条件树；绑定源码、依赖头文件、编译命令、编译器、目标参数及相关环境。模型可按 `ast_nodes/functions/types/cfg/macros` 分页查询。展示截断与事实完整性分离；图身份同时隔离 TU 和函数。
- 共用检查服务：类型与对象身份、受限所有权路径、固定数组常量／规范归纳循环、成功条件明确的互斥锁访问。可信检查器签发进程内凭据，统一策略重新核对候选义务和依赖身份；磁盘中的 `complete` 或旧证明不授予拒绝权限。
- 双证据封套：`zscope.review-adjudication.v1` 分别描述旧拒绝审查和正面案例，经程序验收后交回原 ValidatorResult v3 路径。仅推翻拒绝保持 review；正反完整证据冲突保持 review。新原因存在封套／报告中，旧 `stop_reason` 枚举不变。
- V3 uncertain 正面举证、V2b 拒绝审查分别记录入口、目标、工具结果、事实增量和结果。一般关联问题最多扩展一代，进入冻结追加 Ledger，正常验证；真实指针成员和条件宏分支可登记为关联假设。
- 当前构建之外的宏风险保留 review，计入总量；与当前配置的 confirmed 项分别去重。事实组发现的条件风险不依赖一般关联回收开关。
- 完整检查点保存前序结果、验证证据包、函数上下文、完整事实和工具返回。恢复保留原候选 UID／cluster；进程凭据重新生成。恢复粒度为候选阶段，不承诺续接供应商会话或跳过已消耗的 HTTP 请求。
- 实验脚本包含 baseline/protocol/facts/neutral/positive/related 消融、独立审计冻结、官方评分、拒绝证明重放及五轮验收。审计未知、候选缺失、TP 覆盖丢失、confirmed 真 FP 增加或证明失效均不能通过。记录 token 和耗时，不增加本阶段成本硬门槛。

主要入口：

- `zscope/retrieval/validation_facts.py`
- `zscope/core/validation/review_{checks,protocol,checkpoint,session}.py`
- `zscope/core/validation/runner.py`、`pipeline.py`、`proofs.py`
- `zscope/benchmarking/review_experiment.py`
- `scripts/pilot_review_claims.py`：编译器诊断，不是最终模型回放。
- `scripts/replay_review_experiment.py`：从完整检查点经过实际最终分流。
- `scripts/score_review_experiment.py`：扫描结束后独立评分，不调用模型。

## 基线核对

使用用户提供的 `benchmark-artifacts/c_cpp/trial/20260905T130307Z/run-01`。

- confirmed 报告 139 项，官方 TP 为 119/136。
- with-review 为 237 项，其中 review 98 项；原 uncertain 池 40 项，无证拒绝池 48 项。
- 官方 raw FP 20 项均为 `duplicate_of_gt`；effective FP 为 0。不能将这些重复项当成真误报下降。
- `score.json.false_positive_audit` 没有 review 池的独立真假分类。生成的 `audit-pending.json` 全部为 unknown，未用“没有匹配 truth”填成 FP。
- `validator-replay-bundle.v1` 的契约明确排除了 prior verdict、prior disposition、prior decision proof，且没有本实验所需的完整编译事实。不能从报告字段拼造“原始检查点”。
- 编译器诊断所用 `test/range` 的 C／头文件／`.ph` 内容与该次归档的 `scan-input` 逐文件一致；编译配置是新收集的 Clang 配置，不能冒充旧运行的构建身份。

## 编译器 pilot

产物：`benchmark-artifacts/review-evidence-v1/compiler-pilot.json`，包含报告 SHA、实现 SHA、逐候选检查、检查范围、反证、宏风险和关联提议。完整事实位于同目录 `facts/`。

完整诊断覆盖 237 项，LLM token 为 0，耗时 506.17 秒：review 中 4 个、confirmed 中 1 个“不存在成员”的主张得到类型反证，其余 232 项为 unknown。逐项记录绑定当轮实现 SHA。

随后收紧关联提议，针对上述 5 项进行了 19.88 秒的定向再检查，类型结论保持一致；5 项各生成一个基于构造函数实际赋值的父对象清理假设，不再逐指针字段泛化。产物位于 `related-refinement/compiler-pilot.json`，绑定收紧后的实现。它只检查受该改动影响的 5 项，不能当作新一轮完整配对回放。

在扫描后独立执行的“仅移除这 5 项”报告投影中，官方 confirmed TP 为 119→119，with-review TP 为 135→135，confirmed effective FP 为 0→0。产物：`compiler-projection-score.json`。这是一次假设性分流检查，尚不包含关联假设的最终验证，也不能替代真实模型回放和五轮非回归验收。

这不是 4 个净 FP 已从最终报告消失的证据：还需要独立审计、关联问题验证、最终分流与去重。confirmed 中存在错误成员名，也不代表同一函数中没有真正的 payload 泄漏；因此登记实际指针成员作为关联假设。不能用此结果宣称 TP 不回退或误报减少 50%。

## 验证记录

- WSL Python 3.12 隔离虚拟环境安装当前 checkout，避免误用指向另一目录的旧环境。
- 相关回归：447 passed、2 skipped。日志：`benchmark-artifacts/review-evidence-v1/pytest.log`。
- 包含真实 Clang 编译测试：分页后仍可查全、伪造／过期事实、TU／函数 CFG 隔离、宏分支与目标位数、间接调用和公开零调用者、所有权失败路径、整数溢出、trylock 失败、同一语句多线程访问、解锁后邻近访问、互斥锁重置／逃逸、C++ 未建模隐式清理、关联去重与检查点恢复。
- 双证据测试覆盖“只推翻拒绝保持 review”、正面证据完整时不因 truth 未匹配而压下，以及高置信 uncertain 不绕过封套门禁。
- 后续局部修改另通过 36 项检查器／运行时测试，以及 37 项回放／benchmark runner 测试；后者明确排除了下面记录的既有配置断言不一致，不累计成新的独立测试总数。
- 新增事实／检查器／协议及验证主链等 10 个模块的定向 mypy 通过。全仓 mypy 已执行，仍有 137 个错误、涉及 28 个现有文件；日志：`benchmark-artifacts/review-evidence-v1/mypy.log`。不据此声称全仓类型检查通过。
- 完整 `python -m compileall -f -q zscope scripts test tests` 已执行，日志为同目录 `compileall.log`。
- WSL C/C++ smoke 通过：真实构建、214 个确定性候选、无缺失入口实现；产物：`linux-smoke/smoke.json`。这是无网络 smoke，不是完整 unified 模型端到端结果。
- gcc/cmake/clang/clangd/gclang/get-bc/llvm-link/llvm-nm/wpa/saber 均能由实际 WSL 登录环境解析；wpa、saber 的 `ldd` 未报告缺失库。
- 另运行 benchmark runner 测试发现既有配置断言不一致：测试预期 validator_workers=4，当前工作区配置为 6；未覆盖用户配置。hygiene 检查仍报告两个已跟踪的 Wiki 示例配置不在允许清单中，未删除这些无关文件。

## 当前限制与未完成验收

1. 检查器覆盖的是明确可证明的子集。尚未实现一般跨过程别名／递归证明、完整全程序调用图、任意算术的 SMT 求解或任意并发语义闭合。已知 caller 的常量实参表只用于局部义务，不能证明所有入口安全。无法解释的 CFG 边返回 unknown。
2. 当前只认证与事实编译器绑定的 Clang driver。GCC、包装器、PCH／模块在等价性适配完成前返回 unknown，避免错误声称验证了同一构建。
3. 正面案例的证据引用由程序校验，语义确认仍走现有 Validator 与 promotion policy；它不等同于形式化漏洞证明。不能承诺消灭所有 FP，`safe_malloc` 类有正面路径的案例仍需独立审计。
4. 尚未取得冻结的 review 独立审计标签，也没有旧运行的完整前序检查点。因此没有启动 40 项 uncertain 的有效配对模型消融、五轮配对验收和后续完整 unified 模型扫描；没有新增 TP 或 50% 抑制收益结论。
5. 首版完整事实为单独的内容寻址补充存储；检查点会保留完整载荷，存储／重复读取成本尚未优化。成本需在真实模型 replay 中继续测量。

类型、所有权及数组检查当前显式绑定以下规则 revision 1：`clang_cfg_parent_release_without_owned_member_cleanup`、`clang_cfg_acquire_without_release_on_exit`、`clang_cfg_unchecked_insert_after_ownership_handoff`、`clang_cfg_unbounded_count_indexes_fixed_array`。未修改默认规则语义或正式验证要求，因此不提升这些规则的正式 revision／资格；实验检查器以 `zscope.review-checkers.v1` 单独管理。契约版本不符或旧报告缺少 revision 时保持 unknown。正式资格仍未取得。

## 复现与下一阶段入口

本次编译器诊断命令（在已配置工具链的 Linux／WSL 中执行）：

```bash
cmake -S test/range -B benchmark-artifacts/review-evidence-v1/build \
  -DCMAKE_EXPORT_COMPILE_COMMANDS=ON -DCMAKE_C_COMPILER=clang
python scripts/pilot_review_claims.py \
  --report benchmark-artifacts/c_cpp/trial/20260905T130307Z/run-01/report.json \
  --project test/range \
  --compile-commands benchmark-artifacts/review-evidence-v1/build/compile_commands.json \
  --output benchmark-artifacts/review-evidence-v1/compiler-pilot.json
```

下一阶段先对待审计清单做独立审计，通过 `freeze_audit` 生成不可覆盖的 `AUDIT_*.json`。在新基线采集时仅启用 `validation_review_checkpoint`，保留实际运行的前序结果；完整事实必须可收集。RuntimeSpec override 使用已有开发模式入口，公共 YAML 不增加字段：

```yaml
analysis:
  validation_review_checkpoint: true
```

`validation_review_protocol`、`validation_checked_proofs`、`validation_positive_case` 和 `validation_related_findings` 仍默认 false。一般关联回收与正面举证按消融 arm 单独启用。

实验 trial 将原生工作目录保留在 `review-workspace.json` 指定位置，供保持原依赖路径的回放使用；默认 trial 行为不变。formal 入口拒绝尚未获得资格的实验开关。扫描进程只接收审计摘要身份，不接收审计内容。

```bash
python scripts/replay_review_experiment.py --help
python scripts/score_review_experiment.py --help
```

baseline 和 protocol 对无证拒绝执行同一 V2b 调查，只有终端封套与验收规则不同，避免将“多跑一次调查”误当协议增益。单轮带审计 pilot 达标后，再从同一冻结 manifest 执行五个不同 pair ID 的同一 arm；neutral 与 positive 使用相同模型和调查上限。独立评分命令检查最终分流、根因去重、原 TP 集合、关联项、拒绝证明可重放性与中位数收益。未达门槛保持实验状态，不切换默认配置。
