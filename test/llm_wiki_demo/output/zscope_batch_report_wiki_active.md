# Z-SCOPE Batch Analysis Report

## Summary
- **Completeness**: complete
- **Functions Analyzed**: 5
- **Issues Found**: 0
- **No Issues Found**: 3
- **Errors**: 0
- **Total Issues Detected**: 0
- **Audit Observations**: 2
- **Deferred Entry Candidates**: 0

## Function Details

| Function | Verdict | Issues | Needs Review / Audit | Duration |
| :--- | :--- | :--- | :--- | :--- |
| wiki_copy_label | needs_review | 0 | 1 / 1 | 0.1s |
| wiki_decode_frame | no_issue_found | 0 | 0 / 0 | 0.0s |
| wiki_execute_command | needs_review | 0 | 1 / 1 | 0.0s |
| wiki_parse_port | no_issue_found | 0 | 0 / 0 | 0.0s |
| wiki_register_callback | no_issue_found | 0 | 0 / 0 | 0.0s |

## Detected Issues

*No issues detected.*

## Needs Review Findings

### Entry Function: `wiki_copy_label`

#### 1. [HIGH] CLANG_CFG_OUT_OF_BOUNDS_WRITE_e2ad86226a: wiki_copy_label
- **Location**: `src/label_store.c:20`
- **Confidence**: `0.82`
- **Category**: out_of_bounds_write (out_of_bounds_write)
- **Relevant Code**:
```c
14 |         return -1;
15 |     }
17 |     label_len = strlen(label);
19 |     for (index = 0; index < label_len; ++index) {
20 |         stored_label[index] = label[index];
21 |     }
22 |     stored_label[label_len] = '\0';
24 |     return stored_label[0] == '\0' ? 0 : 1;
25 | }
```
- **Description**: Loop count `label_len` indexes fixed array `stored_label[LABEL_CAPACITY]` without a visible array-size guard.
- **Analysis Reasoning**: Clang AST/CFG checker `clang_cfg_unbounded_count_indexes_fixed_array` produced an evidence candidate for `out_of_bounds_write`.
Location: `wiki_copy_label` at `src/label_store.c:20`.
Observation: Loop count `label_len` indexes fixed array `stored_label[LABEL_CAPACITY]` without a visible array-size guard.
Source: stored_label declaration at line 9; loop at line 19
Sink: stored_label[index] = label[index];
Positive evidence: line 9: `stored_label` is a fixed-size local array | line 19: loop bound is `label_len` | line 20: `stored_label[index]` is written inside the loop
Validation notes: Validator must confirm the loop count is not constrained by a caller-side or earlier protocol guard.
- **Root Cause**: An externally derived count can drive writes past the local fixed-size buffer.
- **Suggested Fix**: Validate `label_len` against `ARRAY_SIZE(stored_label)` before the loop or clamp the loop bound.
- **Validation Status**: 🟡 needs_review
- **Validation Reasoning**: Validator proposed rejection without a deterministic contradiction; the candidate remains reviewable. 候选缺陷的结构模式属实：第 9 行 32 字节固定缓冲区，第 19-20 行循环仅以 strlen(label) 为上界写入，函数内无长度检查。但确定性反证完整：(1) src/label_store.c:6 定义 LABEL_CAPACITY=32，第 20 行写越界当且仅当 strlen(label) >= 32；(2) 唯一文档化调用路径是项目外部 API 网关（公有 API，仓库内零调用方，reachable_from_entry=false），网关在调用前强制校验 label 非空且字节长度 1..31（active/required/无冲突约束），未通过验证的请求不会调用该函数，源文件不重复检查是文档化的有意设计；(3) 因此所有契约内调用的最大写入下标为 31（循环 0..30，第 22 行终止符下标 31），均小于 32，不可能越界。触发越界需要外部网关违反其自身文档化契约（len>=32），且仓库内不存在可传递超长 label 的任何调用路径——属于无具体 source-to-sink 路径的防御性加固建议，而非可触发缺陷。代码事实与文档契约一致，无冲突。

### Entry Function: `wiki_execute_command`

#### 1. [CRITICAL] CLANG_CFG_COMMAND_INJECTION_27aa0c0861: wiki_execute_command
- **Location**: `src/command_runner.c:10`
- **Confidence**: `0.84`
- **Category**: command_injection (command_injection)
- **Relevant Code**:
```c
5 | int wiki_execute_command(const char *command) {
6 |     if (command == NULL || command[0] == '\0') {
7 |         return -1;
8 |     }
10 |     return system(command);
11 | }
```
- **Description**: `system` executes non-literal command buffer `command`.
- **Analysis Reasoning**: Clang AST/CFG checker `clang_cfg_system_with_nonliteral_command` produced an evidence candidate for `command_injection`.
Location: `wiki_execute_command` at `src/command_runner.c:10`.
Observation: `system` executes non-literal command buffer `command`.
Source: command
Sink: return system(command);
Positive evidence: line 10: `system` executes non-literal `command`
Validation notes: Validator must trace whether the command buffer is attacker-controlled.
- **Root Cause**: Shell command text is constructed in process and can carry user or environment-controlled tokens.
- **Suggested Fix**: Avoid `system`; pass argv directly to execve/posix_spawn and validate each argument.
- **Validation Status**: 🟡 needs_review
- **Validation Reasoning**: 汇点与守卫缺失均已证实：第10行将非字面量 command 直接传入 system()，唯一前置检查仅为 NULL/空串判断，不过滤 shell 元字符，对命令注入不构成防护；wiki 约束亦证实参数契约来自调用方且项目无统一白名单。但验证所需的具体触发路径缺失：该函数是 wiki_demo_api.h 导出的公共 API 门面兼本候选的扫描根入口，get_callers 与 get_call_graph(深度2)均返回零仓库调用者，语义图 entry_paths 仅含自身、scc_size=1，reachable_from_entry=false，且前序 source_sink_reachability 事实检索已穷尽（proof_added=false），仓库内不存在任何已证实的攻击者可控源→汇路径；攻击面完全取决于仓库外调用方是否将未经验证的用户输入传入该公共 API，这一决定性事实无法由仓库证据或已穷尽的事实检索确定。既有具体正面证据（源→汇直连、守卫无效），最终证明又依赖缺失的调用方契约；零调用者对头文件导出的公共 API 入口不构成死代码反证，也不存在支配性守卫等阻断性反证，故不得拒绝亦不能验证，判 uncertain 留审计。
