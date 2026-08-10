# 规则扩展开发

## 选择 YAML 还是 Python

局部、可由安全正则表达的规则使用 `rule_pack_version: 1` YAML。需要调用图、框架模型、外部事实或复杂状态机的规则实现 Python `ExecutableRule`，由 `zscope.rule_providers` entry point 注册。YAML 只描述数据，绝不执行代码。

用户规则包必须在 `zscope.yaml` 中显式启用：

```yaml
rules:
  packs:
    - security-rules/acme.yaml
  providers:
    - acme_rules
  disabled_ids:
    - builtin.rule_to_disable
```

相对 pack 路径按 `project.root` 解析。用户 pack 不能覆盖同名内置或第三方规则。

## YAML schema

```yaml
rule_pack_version: 1
name: acme
rules:
  - id: acme.unsafe_copy
    language: c_cpp              # c_cpp | java
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

规则字段固定为 `id`、`language`、`cwe`、`defect_class`、`severity`、`match`、`guards`、`evidence`、`skill`。未知字段、非法正则、未知 Skill、重复 ID 或语言不匹配都会失败。每条规则至少有一个正例、一个反例；正例可带候选快照断言。

## Python provider

Provider 返回一个或多个实现 `evaluate(RuleContext) -> Iterable[Candidate]` 的规则。输出必须是 `zscope.rules.extensions.Candidate`，不能返回任意 dict。

```python
class AcmeProvider:
    def rules(self):
        return [AcmeExecutableRule()]
```

第三方包注册：

```toml
[project.entry-points."zscope.rule_providers"]
acme_rules = "acme_zscope_rules:AcmeProvider"
```

Provider 是可执行代码，只安装来自受信来源且经过依赖/许可证扫描的 wheel。未列入 `rules.providers` 的 entry point 不会加载。

## 命令与测试

```bash
zscope-rules list --config zscope.yaml
zscope-rules validate security-rules/acme.yaml
zscope-rules test security-rules/acme.yaml
```

内置 C 与 Java 规则将逐步迁入同一注册表；迁移期间仍必须输出标准候选并进入统一 Validator/报告流水线，不能建立旁路告警。
