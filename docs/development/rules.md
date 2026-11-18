# 规则开发与治理

本文面向内置 Java/C/C++ 检测器、YAML rule pack 和第三方 Python provider 的开发者。普通用户只需在 `zscope.yaml` 中引用 pack/provider，或用 `rules.enabled_ids`/`disabled_ids` 显式控制规则；内置目录不是 public YAML 的一部分。

## 先区分四类机制

| 机制 | 用途 | 身份 | 如何关闭 |
|------|------|------|----------|
| 确定性规则 | Regex、Clang CFG/matcher、Graph、Java local、YAML pack 或 Python 算法产生可重现候选 | 必须有目录内 canonical `rule_id` 与 revision | `rules.disabled_ids`；实验规则可由 `rules.enabled_ids` 显式启用 |
| Backend signal | SVF/Saber、Joern 或 Java signal provider 产生的原生后端事实 | `candidate_kind: backend_signal`，保留 `signal_source` 和 `native_rule_id` | 修改 `indexing` 后端/信号源 |
| Skill trigger | 把任务或候选路由给合适的 Agent/Deep Worker | Skill ID，不是规则 ID | `scan.task` 与内部路由策略 |
| Finding suppression | 记住人工确认的误报/例外 | finding 稳定身份与 scope | Web 或用户配置状态 |

不要把 backend signal 登记成确定性规则，也不要用 `disabled_ids` 代替 finding suppression。禁用一条确定性规则只停止该检测器；其他规则、后端信号和 LLM 仍可独立发现等价问题。

## 内置规则目录

`zscope/rules/builtin_catalog.yaml` 只管理元数据；`zscope/rules/qualification_registry.yaml` 保存与 `(rule_id, revision)` 绑定的资格证据；AST/CFG、Graph 等检测算法继续使用 Python。目录在扫描前与资格记录、实现、Skill 和当前 backend 能力一起预检，任一未登记 ID、重复 ID/alias、CWE 错误或 Skill 语言错配都会终止扫描。

```yaml
rule_catalog_version: 2
rules:
  - id: clang_cfg_use_after_release
    language: c_cpp
    engine: cpp_clang_cfg
    defect_class: use_after_free
    cwe: CWE-416
    additional_cwes: [CWE-825]
    skill: temporal_memory
    default_severity: high
    revision: 1
    status: stable
    default_enabled: true
    title: Use after release
    summary: Released object is subsequently used on a feasible local path.
    required_capabilities: [source_text, clang_structure]
    aliases: []
    legacy_id: true
```

字段要求：

- `language` 只能是 `c_cpp` 或 `java`。
- 内置 `engine` 只能是 `cpp_regex`、`cpp_clang_cfg`、`cpp_clang_matcher`、`cpp_graph` 或 `java_local`。YAML pack 与 provider 的 engine/source 由注册器赋值，扩展不得冒充内置引擎。
- `status` 只能是 `stable`、`experimental` 或 `deprecated`；`default_enabled` 是独立的执行开关。新内置规则默认 `experimental + default_enabled: false`，取得当前 revision 的 qualified 记录后才能晋升为 stable/default-enabled。
- `revision` 必须是正整数。规则语义、CWE（含 `additional_cwes`）、Skill、required capability 或验证要求变化时必须递增。
- `cwe` 是唯一的治理主 CWE；可选 `additional_cwes` 声明该规则根因额外覆盖的 CWE 列表（每项必须匹配 `CWE-<数字>`、不得与主值或彼此重复）。候选经 `enrich_issue` 后获得 `issue["cwes"]` = 主 CWE + 规则附加 CWE + 候选既有 CWE + 类别级映射（`zscope/common/defect_cwe_map.py`）的有序并集；`cwe` 主值仍必须与目录一致。
- `required_capabilities` 从代码定义的固定能力集选取；不要自由造字符串。
- 已有 ID 始终作为 canonical ID，并保留 `legacy_id: true`。新内置 ID 使用 `zscope.<language>.<engine>.<slug>`；外部规则不得占用 `zscope.` 命名空间。
- `aliases` 仅用于查询/迁移，不用新 alias 替代历史 canonical ID。

唯一的历史多态例外是 `clang_cfg_unchecked_pointer_backtrack`：同一旧 ID 会按实际 sink 保留 `buffer_underread / CWE-127` 或 `buffer_underwrite / CWE-124`。运行时只接受这两个封闭 variant，其他组合严格失败；后续若拆为新规则必须作为单独的 revision/迁移设计，不能在本轮重写历史 ID。

### Skill 语言与标准映射

每个 `SKILL.md` 的 frontmatter 必须声明 `languages: [c_cpp]`、`[java]` 或 `[c_cpp, java]`。规则 descriptor 只能引用支持相同语言的 Skill。空 `scan.task` 根据该归属启用当前语言的全部适用 Skill，不再依赖 Java Skill 硬编码列表。

| 规则语义 | 标准 Skill |
|------------|------------|
| 资源获取/泄漏、fd 生命周期 | `resource_lifecycle` |
| double-free、UAF、invalid-free、提前销毁 | `temporal_memory` |
| 越界、整数、指针偏移、未初始化缓冲区 | `bounds_and_integer` |
| 空指针、失败返回、错误路径 | `null_and_failure` |
| 格式串和字符串契约 | `string_and_format` |
| 栈地址逃逸 | `stack_escape` |
| 锁平衡、死锁、锁顺序 | `concurrency_lock_order` |
| 数据竞态、发布顺序、共享状态 | `shared_state_race` |
| 所有权、协议、状态机和逻辑契约 | `ownership_contract` |

CWE、defect class 与 Skill 以规则目录为唯一真源，生成器不应再维护另一份通用类别映射；资源类型、API role 等纯运行时映射可继续留在引擎中。类别级的兜底 CWE 覆盖（无规则声明时由 defect class 反推 CWE 集合）集中在 `zscope/common/defect_cwe_map.py`，新增类别时必须同步该映射并保持其不变量测试。

### 修改内置检测器

一次完整变更应同时包含：

1. Python 检测逻辑，通过公共 emitter 输出 canonical `rule_id` 和规则特有 evidence。
2. `builtin_catalog.yaml` descriptor；语义性变化递增 `revision`。
3. 至少一个正例和一个反例，并在需要时增加候选 golden/snapshot。
4. 目录与实现一致性测试，覆盖 language、CWE、Skill、capability 和 disabled 行为。
5. 如果 raw candidate、Worker 路由或最终报告发生变化，按 Range/Java benchmark 协议补做回归。
6. 更新当前 revision 的 qualification 证据；只有单元测试或 Range 证据的规则必须保持 experimental/default-disabled。

仅修正实现 bug 但保持完全相同的规则契约时，实现源码摘要本身会改变 effective hash；是否递增 revision 应以候选语义/验证要求是否变化为准。

## YAML rule pack

局部、可用安全正则表达的扩展使用 `rule_pack_version: 1`。该 public schema 保持不变，YAML 只描述数据，绝不执行代码。

```yaml
rule_pack_version: 1
name: acme
rules:
  - id: acme.unsafe_copy
    language: c_cpp
    cwe: CWE-120
    defect_class: buffer_overflow
    severity: high
    match:
      pattern: '\bstrcpy\s*\('
      flags: [MULTILINE]
    guards:
      - '\bstrcpy_s\s*\('
    evidence:
      rationale: unbounded copy
    skill: bounds_and_integer
tests:
  - rule_id: acme.unsafe_copy
    expect: true
    file: demo.c
    code: 'strcpy(dst, src);'
    candidate:
      defect_class: buffer_overflow
  - rule_id: acme.unsafe_copy
    expect: false
    file: demo.c
    code: 'memcpy(dst, src, size);'
```

规则字段固定为 `id`、`language`、`cwe`、`defect_class`、`severity`、`match`、`guards`、`evidence`、`skill`。加载器将其转换为 descriptor，并把 pack 原始内容 SHA-256 纳入 effective ruleset 身份。未知字段、非法正则、未知 Skill、缺失正/反例、重复 ID 或语言不匹配都会失败。

## Python provider V2

需要调用图、框架模型、外部事实或复杂状态机时，实现严格 V2 `ExecutableRule`：

```python
class ExecutableRule(Protocol):
    descriptor: RuleDescriptor

    def evaluate(self, context: RuleContext) -> Iterable[Candidate]:
        ...
```

descriptor 必须在导入 provider 时即可读，预检只导入显式选中的 provider，不执行 `evaluate()`。注册器强制将 engine 标记为 `python_provider`，并把 source 标记为实际 distribution；provider 不得冒充内置引擎或伪造来源。

预检完成后 registry 会冻结，后续不能再注册规则。并行入口共享 provider 实例时，同一条 provider 规则的 `evaluate()` 由 registry 串行调用，不同规则仍可并行；provider 不应依赖跨扫描的可变全局状态。发行版名称/版本、provider 工厂、`rules()` 与每条 `evaluate()` 的可读源码摘要（不可读时使用稳定实现身份）共同进入 provenance 和 effective hash。

`evaluate()` 只能返回强类型 `Candidate`，不能返回任意 dict。Candidate 只提供：

- 与 descriptor 相同的 `rule_id`。
- 函数、文件和行号定位。
- 该规则特有的 evidence。

language、CWE、defect class、severity 和 Skill 都由 descriptor 注入。Candidate 使用其他 ID、携带冲突元数据或返回未登记规则时立即失败。provider 的 descriptor、distribution 版本和可读的实现摘要会进入 provenance。

第三方包通过 entry point 注册：

```toml
[project.entry-points."zscope.rule_providers"]
acme_rules = "acme_zscope_rules:AcmeProvider"
```

Provider 是可执行代码；只安装来自受信来源且经过依赖/许可证审查的 wheel。未列入 `rules.providers` 的 entry point 不会导入。旧的 descriptor 推断或 dict 返回协议不兼容，provider 需一次性升级到 V2。

同一个 provider rule 实例可能被多个入口 worker 共享。运行时会按 rule 实例串行调用 `evaluate()`，不同 rule 仍可并行，因此 provider 不得依赖跨 rule 的调用顺序；如需共享缓存，仍应自行使用线程安全的数据结构。预检绑定 `EffectiveRuleSet` 后 registry 会被封存，扫描期间不能再注册 pack/provider 或替换 descriptor。

## 检测与抑制实现不变量

确定性规则的抑制证据必须强于命中证据：guard 需要绑定同一对象、receiver 或算术操作数，并由 CFG/程序事实证明危险分支终止、危险操作未执行或安全效果支配 sink。附近出现 `NULL`、`MAX`、`Principal`、安全配置字符串、日志调用或注释都不能单独抑制候选；另一对象上的等名配置同样无效。

对象成员、helper、回调参数和容器链路优先从语义契约、调用绑定、字段/类型事实和对象流关系识别。兼容旧规则时可以保留名称提示作为低置信候选来源，但固定成员名、函数前后缀或局部变量名不能是规则成立或安全抑制的唯一条件。正反例除漏洞/修复对外，还应覆盖标识符重命名、前后缀自增等价写法、receiver 替换、无关 guard 和只记录日志但继续执行的分支。

## Public YAML 与禁用语义

```yaml
rules:
  packs:
    - security-rules/acme.yaml
  providers:
    - acme_rules
  disabled_ids:
    - clang_cfg_use_after_release
```

相对 pack 路径按 YAML 所在工程目录解析；这是唯一工程根，不再读取独立根目录字段。两份根目录参考 YAML 在没有扩展/禁用需求时省略空 `rules` 区块。

`disabled_ids` 对 Java local、C/C++ Regex、Clang CFG/matcher、Graph、YAML pack 和 Python provider 全局生效，并优先于 `enabled_ids`；同一 ID 同时出现在两表时以禁用为准。表内重复、未知 ID 或跨语言 ID 会严格报错；同语言但当前 backend 不会运行的规则可以禁用，`validate` 会输出“当前 backend 不适用”警告。

## Stable 资格门禁

`qualification_registry.yaml` 的证据哈希必须对应当前 revision。`qualified` 记录还必须能在同目录的 `qualification_evidence/<rule_id>.r<revision>.json` 解引用；加载器校验 manifest SHA、descriptor commitment，并从逐案例记录重新计算所有计数和 precision，不能只信任 registry 里的汇总数字。

默认启用的 C/C++ 规则还必须在 `zscope.validation-obligation-catalog.v1` 中按 canonical ID 与当前 revision 绑定验证义务；规则名称、类别描述或 `free/thread/lock` 等子串不得推导缺失事实。义务 profile 定义必需角色、正向/反向 claim checker 和实际可请求 provider，身份进入 Validator 缓存及报告。修改规则机制或所需事实时应同步 rule revision 与该绑定，并增加正向确认、反证拒绝和缺事实 needs_review 回归。

`zscope.rule-qualification-evidence.v1` 的 `leakage_lint`、每个 `metamorphic_cases` / `external_cases` 条目以及每个 `vulnerable_fixed_pairs` 条目都必须同时提供 `artifact_path` 和 `artifact_sha256`。`artifact_path` 是相对 `qualification_evidence/` 根目录的规范 POSIX 相对路径：不接受绝对路径、Windows drive、反斜杠、`.` / `..`、重复分隔符或符号链接/reparse point。加载器要求目标是 evidence root 内的实际普通文件，并重新计算文件字节的 SHA-256；缺失、越界、链接或哈希不符都会使预检 fail closed。只有 artifact 通过这些检查后，对应布尔值和案例结果才参与资格指标计算。

Stable 规则至少满足：

- 标识符重命名、wrapper 提取/内联、宏或等价分支重排三类语义保持变换仍能命中；安全修复变体不命中。
- 至少 3 个无关项目或模式家族，累计至少 10 个 external positive 与 20 个 near-miss negative。
- vulnerable/fixed 版本成对一致，external raw precision 至少 90%。
- 单测、metamorphic、外部正反例、pair 与证据 artifact 均有可校验哈希；任一过期、失败或缺失使资格变为 pending/failed。

Range 只作为分布内开发回归，不能单独为规则取得 stable 资格。对历史默认规则应一次性执行结构泄漏 lint 和变形测试；不能通过可移植性验证的规则改为 `experimental + default_enabled: false`，仍可由用户显式启用做定向审计。

扫描完成后，可将报告与 truth 成对交给资格审计脚本，核对哪些确定性规则实际参与了 benchmark TP：

```bash
python scripts/audit_rule_qualifications.py \
  --benchmark-report report.json \
  --benchmark-truth benchmark/ground_truth.json \
  --view default \
  --output rule_qualification_audit.json
```

外部资格材料可先用 campaign 工具生成逐 revision 工作清单；它不会生成或伪造证据，也拒绝 Range GT。`verify` 对项目独立性、案例数量、变形、漏洞/修复对、泄漏检查与外部 precision 重新计算，只有全部当前规则通过后 `assemble` 才会生成 registry：

```bash
python scripts/rule_qualification_campaign.py prepare --output /path/to/campaign
python scripts/rule_qualification_campaign.py verify --root /path/to/campaign --output /path/to/report.json
python scripts/rule_qualification_campaign.py assemble --root /path/to/campaign --output /path/to/qualification_registry.json
```

`--benchmark-report` 与 `--benchmark-truth` 必须同时提供；`--view` 可选 `default` 或 `with_needs_review`。该步骤复用统一 scorer 的 `matched_issue_indices`，只能在扫描完成且答案隔离解除后运行。输出会 canonicalize alias，列出每条参与规则的 TP 数、truth ID、当前 revision、资格状态、证据验证状态和默认启用状态，并单列目录未知 detector。一个 TP 可以同时归因到多条规则，因此 per-rule TP count 有重叠，不能相加后当作 distinct TP。省略 benchmark 参数时，脚本仍只输出原有目录和资格状态审计。

SVF/Joern/provider 原生信号不是目录规则 ID，不能写入 `disabled_ids`。如需停止信号源，修改 `indexing`；如需抑制已确认误报，使用 finding suppression。

## 命令、预检与测试

```bash
# 查看当前配置的全部规则及 effective status
zscope-rules list --config zscope.yaml
zscope-rules list --config zscope.yaml --language c_cpp --engine cpp_graph --status stable
zscope-rules list --config zscope.yaml --json

# 查看 descriptor、启停原因、capability、来源与 hash
zscope-rules show clang_cfg_use_after_release --config zscope.yaml
zscope-rules show clang_cfg_use_after_release --config zscope.yaml --json

# 验证/执行 YAML pack 内的正反例
zscope-rules validate security-rules/acme.yaml
zscope-rules test security-rules/acme.yaml

# 完整配置预检与环境检查
zscope-config validate --config zscope.yaml
zscope-doctor --config zscope.yaml
```

`zscope`、`zscope-config validate`、`zscope-doctor`、Web、批量扫描和 MCP 复用同一预检工厂。扫描前会完成目录/qualification/Skill/pack/provider/enabled/disabled ID 的全局校验，再生成不可变 `EffectiveRuleSet`。Analyzer 保留防御性预检，避免第三方直接调用绕过入口校验。

最低测试集应包括：

- 目录 schema、重复键、ID/alias 冲突、CWE、revision、Skill/language 和 capability 校验。
- 每条规则的正例、反例与必要的 candidate golden。
- 启用与禁用路径，确认禁用候选不进入 merge、ledger、Worker、Validator、JSON、Markdown 或 SARIF。
- qualification revision/hash 过期、pending/failed 默认隔离，以及 experimental 显式启用路径。
- pack/provider 冲突、跨语言输出、Candidate ID 错配和旧 provider 协议拒绝。
- descriptor、实现、disabled IDs、pack 或 provider revision 变化时，effective/config/cache/Validator fingerprint 随之变化。

只要更改会影响 Range 候选、Worker 路由或最终 finding，就必须额外遵守 `docs/benchmarks/range.md` 的工具链、ground truth 隔离和正式 unified 回归要求。
