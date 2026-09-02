# Z-SCOPE Batch Analysis Report

## Summary
- **Completeness**: complete
- **Functions Analyzed**: 5
- **Issues Found**: 1
- **No Issues Found**: 3
- **Errors**: 0
- **Total Issues Detected**: 1
- **Audit Observations**: 1
- **Deferred Entry Candidates**: 0

## Function Details

| Function | Verdict | Issues | Needs Review / Audit | Duration |
| :--- | :--- | :--- | :--- | :--- |
| wiki_copy_label | needs_review | 0 | 1 / 1 | 0.1s |
| wiki_decode_frame | no_issue_found | 0 | 0 / 0 | 0.0s |
| wiki_execute_command | issues_found | 1 | 0 / 0 | 0.0s |
| wiki_parse_port | no_issue_found | 0 | 0 / 0 | 0.0s |
| wiki_register_callback | no_issue_found | 0 | 0 / 0 | 0.1s |

## Detected Issues

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
- **Validation Status**: ✅ validated
- **Validation Reasoning**: Fact resolution produced no new decision evidence.


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
- **Validation Reasoning**: Validator proposed rejection without a deterministic contradiction; the candidate remains reviewable. 候选机制（以 strlen 为界的循环写入固定大小栈数组）在抽象上成立，但被确定性证据否决为不可触发缺陷。(1) 容量事实：LABEL_CAPACITY=32（src/label_store.c:6），合法下标0..31。(2) 显式调用方契约：README.md 明确记载所有有效调用必经项目外部唯一 API 网关，网关在调用前强制校验非空、UTF-8、字节长度1--31，不合规请求不会调用本函数，且源文件按设计不重复长度检查——这正是证据包 negative[0] 要求确认的调用方协议守卫。(3) 算术推导：契约内最大 label_len=31 ⇒ 第20行最大写入下标30、第22行最大下标31，均 <32，不越界；容量32恰为"最大长度31+NUL"的设计配对，代码与契约一致无冲突。(4) 可达性：get_callers 为空、语义映射确认该函数即扫描入口（SCC大小1，唯一被调函数 strlen），仓库内不存在任何能传递 label_len>=32 的调用方。触发第20行 sink 越界需 strlen>=33，即必须绕过已文档化且强制执行的外部网关契约——在被分析代码内不可构造该源到汇路径。候选退化为"建议源文件增加防御性长度复查"的加固建议（针对假想契约违例调用方），按验证标准予以拒绝。
