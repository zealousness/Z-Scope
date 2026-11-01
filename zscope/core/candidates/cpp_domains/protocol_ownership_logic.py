# mypy: disable-error-code="attr-defined"
"""Protocol, ownership, state-machine, and general logic implementations."""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Sequence, Set, Tuple

from .models import (
    ClangCfgLine,
    CodeLine,
    FunctionView,
    GraphLine,
    LockOrderEdge,
    LockState,
    ResourceState,
)

from .models import DetectorStage
from .shared_access import SharedAccessIndex


_PATH_STATE_QUERY_ROOTS = frozenset({"access", "stat", "lstat", "faccessat", "fstatat"})


def _trusted_path_state_query(generator: Any, text: str) -> bool:
    """Recognize a path query only through current executable semantics.

    A project helper's spelling is never authority.  The call must resolve to
    one exact trusted ``standard_operation`` contract, and that contract must
    either be a verified system path query or transparently delegate to one.
    """

    registry = generator.semantics.contracts
    for match in re.finditer(r"\b(?P<name>[A-Za-z_]\w*)\s*\(", text):
        name = match.group("name")
        for contract in registry.find_for_call(name, "standard_operation"):
            if not contract.effects_trusted:
                continue
            roots = {contract.symbol.name}
            for delegate in contract.delegates or []:
                if not isinstance(delegate, dict):
                    continue
                symbol = delegate.get("symbol")
                if isinstance(symbol, dict):
                    roots.add(str(symbol.get("name") or ""))
            if not roots.intersection(_PATH_STATE_QUERY_ROOTS):
                continue
            if registry.effect_possibility(name, "standard_operation", text) in {
                "applies",
                "possible",
            }:
                return True
    return False


STAGES = (
    DetectorStage(
        "regex",
        "function",
        100,
        "protocol_ownership_logic",
        "null_pointer_contracts",
        "_rule_null_pointer",
        ("lines", "emit"),
    ),
    DetectorStage(
        "regex",
        "function",
        120,
        "protocol_ownership_logic",
        "common_c_sinks",
        "_rule_common_c_sinks",
        ("lines", "emit"),
        covers=("memory_bounds_integer",),
    ),
    DetectorStage(
        "regex",
        "function",
        130,
        "protocol_ownership_logic",
        "protocol_and_system_contracts",
        "_rule_protocol_and_system_contracts",
        ("lines", "emit"),
    ),
    DetectorStage(
        "graph",
        "view",
        50,
        "protocol_ownership_logic",
        "tree_and_liveness_protocols",
        "_rule_tree_and_liveness_protocols",
        ("view", "issues"),
    ),
    DetectorStage(
        "graph",
        "view",
        70,
        "protocol_ownership_logic",
        "protocol_state_contracts",
        "_rule_protocol_state_contracts",
        ("view", "issues"),
    ),
    DetectorStage(
        "graph",
        "view",
        80,
        "protocol_ownership_logic",
        "unchecked_ownership_transfer_return",
        "_rule_unchecked_ownership_transfer_return",
        ("view", "issues"),
    ),
    DetectorStage(
        "graph",
        "batch",
        30,
        "protocol_ownership_logic",
        "paired_key_normalization_protocols",
        "_rule_paired_key_normalization_protocols",
        ("views", "issues"),
    ),
    DetectorStage(
        "graph",
        "batch",
        40,
        "protocol_ownership_logic",
        "paired_self_link_log_traversal",
        "_rule_paired_self_link_log_traversal",
        ("views", "issues"),
    ),
)


class RegexProtocolOwnershipLogicRules:
    def _rule_null_pointer(self, lines: List[CodeLine], emit) -> None:
        strchr_results: Dict[str, CodeLine] = {}
        guarded: set[str] = set()
        for line in lines:
            assign = re.search(
                self._literal_api_pattern(r"\b(?P<var>[A-Za-z_]\w*)\s*=\s*strchr\s*\("), line.text
            )
            if assign:
                strchr_results[assign.group("var")] = line
                guarded.discard(assign.group("var"))
                continue
            for var in list(strchr_results):
                if re.search(
                    rf"\bif\s*\([^)]*(?:!\s*{re.escape(var)}|{re.escape(var)}\s*==\s*NULL|NULL\s*==\s*{re.escape(var)})",
                    line.text,
                ):
                    guarded.add(var)
                elif var not in guarded and re.search(
                    rf"(\*{re.escape(var)}\b|{re.escape(var)}\s*\[|{re.escape(var)}\s*-)", line.text
                ):
                    src_line = strchr_results[var]
                    emit(
                        defect_class="null_pointer_dereference",
                        rule="unchecked_strchr_result",
                        line=line,
                        description=f"来自 strchr 的 `{var}` 被使用，但缺少可见的 NULL 检查。",
                        root_cause="当定界符不存在时，strchr 可能返回 NULL。",
                        suggested_fix=f"在进行指针运算或解引用之前，检查 `{var}` 是否为 NULL。",
                        source=f"strchr result at line {src_line.number}",
                        sink=line.text.strip(),
                        confidence=0.83,
                        positive=[
                            f"line {src_line.number}: `{var}` receives strchr result",
                            f"line {line.number}: `{var}` is used before NULL check",
                        ],
                    )
                    guarded.add(var)

    def _rule_common_c_sinks(self, lines: List[CodeLine], emit) -> None:
        permission_check_line: Optional[CodeLine] = None
        length_field_defs: Dict[str, Tuple[CodeLine, str]] = {}
        held_locks: List[CodeLine] = []
        for line in lines:
            length_def = re.search(
                rf"\b(?:{self._size_type_pattern})\s+"
                r"(?P<var>[A-Za-z_]\w*(?:len|length|size)[A-Za-z_0-9]*)\s*=\s*"
                r"(?P<src>[A-Za-z_]\w*(?:->|\.)[A-Za-z_0-9]*(?:len|length|size)[A-Za-z_0-9]*)\s*;",
                line.text,
                re.IGNORECASE,
            )
            if length_def:
                length_field_defs[length_def.group("var")] = (line, length_def.group("src"))
            for len_var, (src_line, src_expr) in list(length_field_defs.items()):
                if line.index <= src_line.index:
                    continue
                if not re.search(
                    rf"\b(?:{self._names_pattern(self._copy_sink_names)})\s*\([^;]*\b{re.escape(len_var)}\b",
                    line.text,
                ):
                    continue
                guard_window = "\n".join(
                    item.text for item in lines[max(0, line.index - 12) : line.index]
                )
                if re.search(
                    rf"\b{re.escape(len_var)}\b\s*[<>]=?\s*[^;]*(?:data_len|buf_len|buffer_len|remaining|capacity|sizeof)",
                    guard_window,
                ):
                    continue
                emit(
                    defect_class="bounds",
                    rule="external_length_field_reaches_copy",
                    line=line,
                    description=f"长度字段 `{src_expr}` 到达一个复制/IO 汇点，但缺少可见的缓冲区边界检查。",
                    root_cause="序列化或结构化的长度字段被信任，却没有证明其底层缓冲区包含那么多字节。",
                    suggested_fix="在复制之前，将长度与剩余输入缓冲区或目标容量进行校验。",
                    source=f"{src_expr} at line {src_line.number}",
                    sink=line.text.strip(),
                    confidence=0.78,
                    impact_level="high",
                    positive=[
                        f"line {src_line.number}: length is loaded from an object field",
                        f"line {line.number}: length reaches copy/IO sink",
                    ],
                )
                length_field_defs.pop(len_var, None)

            from ....semantics.call_operands import call_operands, is_literal_string

            for fmt in call_operands(self.semantics.contracts, line.text, "format_sink"):
                if is_literal_string(fmt.expression):
                    continue
                emit(
                    defect_class="format_string",
                    rule="nonliteral_format_string",
                    line=line,
                    description=f"`{fmt.expression}` 被用作 printf 风格的格式字符串。",
                    root_cause="攻击者可控的百分号序列可能被解释为格式指令。",
                    suggested_fix="使用字面量格式，并通过数据参数传入待显示的文本。",
                    source=fmt.expression,
                    sink=line.text.strip(),
                    confidence=0.86,
                    impact_level="high",
                    positive=[f"line {line.number}: contract format argument {fmt.argument_index}"],
                )

            if self._lock_re.search(line.text):
                held_locks.append(line)
            nested_lookup = re.search(
                r"\b(?P<fn>[A-Za-z_]\w*(?:find|lookup|search|get)[A-Za-z_0-9]*)\s*\(",
                line.text,
                re.IGNORECASE,
            )
            if held_locks and nested_lookup:
                lock_line = held_locks[-1]
                nearby = "\n".join(
                    item.text for item in lines[max(0, line.index - 30) : line.index + 30]
                )
                fn_name = nested_lookup.group("fn")
                if re.search(r"(?:_nolock|_locked|locked_)", fn_name, re.IGNORECASE):
                    nested_lookup = None
                elif not re.search(rf"\b{re.escape(fn_name)}\s*\(", lock_line.text):
                    has_local_lock_evidence = re.search(
                        rf"\b{re.escape(fn_name)}\s*\([^)]*\)\s*{{[^}}]*(?:{self._names_pattern(self._lock_names)})\s*\(",
                        nearby,
                        re.S,
                    ) or re.search(
                        rf"\b{re.escape(fn_name)}\s*[:=].*(?:requires|takes|locks)", nearby, re.I
                    )
                    emit(
                        defect_class="deadlock",
                        rule="lookup_like_call_under_held_lock",
                        line=line,
                        description=f"`{fn_name}` 在已持有锁的情况下被调用；查找（lookup）类辅助函数通常有自己的加锁约定。",
                        root_cause="若辅助函数的加锁约定不是“无锁/已加锁”，它可能递归地获取同一把锁或反转锁的所有权。",
                        suggested_fix="对于已加锁的调用方应使用无锁辅助函数，记录锁的所有权，或在调用前释放锁。",
                        source=f"lock at line {lock_line.number}",
                        sink=line.text.strip(),
                        confidence=0.74 if has_local_lock_evidence else 0.62,
                        impact_level="high",
                        positive=[
                            f"line {lock_line.number}: lock acquired before helper call",
                            f"line {line.number}: lookup-like helper called while lock is held",
                        ],
                        negative=(
                            []
                            if has_local_lock_evidence
                            else ["callee locking behavior requires validation"]
                        ),
                    )
                    nested_lookup = None
            if held_locks and nested_lookup:
                lock_line = held_locks[-1]
                nearby = "\n".join(
                    item.text for item in lines[max(0, line.index - 30) : line.index + 30]
                )
                fn_name = nested_lookup.group("fn")
                if re.search(
                    rf"\b{re.escape(fn_name)}\s*\([^)]*\)\s*{{[^}}]*(?:{self._names_pattern(self._lock_names)})\s*\(",
                    nearby,
                    re.S,
                ) or re.search(
                    rf"\b{re.escape(fn_name)}\s*[:=].*(?:requires|takes|locks)", nearby, re.I
                ):
                    emit(
                        defect_class="deadlock",
                        rule="lookup_like_call_under_held_lock",
                        line=line,
                        description=f"`{fn_name}` 在已持有锁的情况下被调用，并且看起来自身也会获取锁。",
                        root_cause="查找/辅助例程可能递归地获取同一把锁或反转锁的所有权。",
                        suggested_fix="对于已加锁的调用方应使用无锁辅助函数，记录锁的所有权，或在调用前释放锁。",
                        source=f"lock at line {lock_line.number}",
                        sink=line.text.strip(),
                        confidence=0.74,
                        impact_level="high",
                        positive=[
                            f"line {lock_line.number}: lock acquired before helper call",
                            f"line {line.number}: lookup-like helper called while lock is held",
                        ],
                    )
            if self._unlock_re.search(line.text) and held_locks:
                held_locks.pop()

            if _trusted_path_state_query(self, line.text) or (
                not self.restrict_to_semantics
                and re.search(
                    r"\b[A-Za-z_]\w*(?:check|validate|verify)[A-Za-z_0-9]*(?:permission|access|path|file)[A-Za-z_0-9]*\s*\(",
                    line.text,
                    re.IGNORECASE,
                )
            ):
                permission_check_line = line
            if permission_check_line and re.search(
                self._literal_api_pattern(r"\b(?:open|fopen|creat)\s*\("), line.text
            ):
                emit(
                    defect_class="toctou",
                    rule="path_check_before_open",
                    line=line,
                    description="路径名被单独检查，而后续的 open/use 操作是分开进行的。",
                    root_cause="在检查与 open 操作之间，路径可能发生变化。",
                    suggested_fix="先用安全标志打开文件，再对已打开的描述符进行校验/使用。",
                    source=f"path check at line {permission_check_line.number}",
                    sink=line.text.strip(),
                    confidence=0.76,
                    positive=[
                        f"line {permission_check_line.number}: pathname check",
                        f"line {line.number}: separate pathname open/use",
                    ],
                )
                permission_check_line = None

            system_call = re.search(
                self._literal_api_pattern(r"\bsystem\s*\(\s*(?P<arg>[A-Za-z_]\w*)\s*\)"), line.text
            )
            if system_call:
                emit(
                    defect_class="command_injection",
                    rule="system_with_constructed_command",
                    line=line,
                    description=f"`{system_call.group('arg')}` 被传递给 system。",
                    root_cause="构造出的命令文本可能包含 shell 元字符或来自环境的内容。",
                    suggested_fix="避免使用 system；直接向 execve/posix_spawn 传递 argv 并校验每个参数。",
                    source=system_call.group("arg"),
                    sink=line.text.strip(),
                    confidence=0.78,
                    impact_level="critical",
                    positive=[f"line {line.number}: system executes a non-literal command string"],
                )

    def _rule_protocol_and_system_contracts(self, lines: List[CodeLine], emit) -> None:
        text = "\n".join(line.text for line in lines)

        for line in lines:
            if not re.search(r"\bwhile\s*\(", line.text):
                continue
            window = "\n".join(item.text for item in lines[line.index : line.index + 14])
            if not re.search(self._semantic_api_pattern(r"\b(?:recv|read)\s*\("), window):
                continue
            if (
                re.search(r"\b(?:sleep|usleep|nanosleep|poll|select|break)\b", window)
                if not self.restrict_to_semantics
                else re.search(r"\bbreak\b", window)
                or re.search(
                    self._literal_api_pattern(r"\b(?:sleep|usleep|nanosleep|poll|select)\s*\("),
                    window,
                )
            ):
                continue
            if re.search(r"\bif\s*\([^)]*(?:rc|ret|got|received)\s*<=\s*0", window) and re.search(
                r"\bcontinue\s*;", window
            ):
                emit(
                    defect_class="busy_loop",
                    rule="recv_retry_without_backoff",
                    line=line,
                    description="当 IO 调用没有取得进展时，接收循环会立即重试。",
                    root_cause="该循环没有 break、sleep、poll，也没有对反复出现的瞬时失败施加重试上限。",
                    suggested_fix="添加带超时/退避的有界重试策略，并处理永久性错误。",
                    source=line.text.strip(),
                    sink="continue on rc <= 0",
                    confidence=0.8,
                    impact_level="high",
                    positive=[
                        f"line {line.number}: receive loop",
                        "nearby branch continues on non-progress without backoff or timeout",
                    ],
                )

        for idx, line in enumerate(lines):
            if re.search(
                r"\b(?:uint32_t|uint64_t|size_t|int)\s+\w+\s*=\s*(?:\([^)]*\)\s*)?[^;]*(?:\*|<<)\s*[^;]*;",
                line.text,
            ):
                later = "\n".join(item.text for item in lines[idx + 1 : idx + 10])
                if re.search(
                    self._literal_api_pattern(r"\b(?:memcpy|memmove)\s*\("), later
                ) and re.search(r"\b(?:packet|wire|blob|frame|payload)_?len\b", text):
                    if not re.search(
                        r"(?:packet|wire|blob|frame|payload)_?len\s*[-+*/<>]=?", later
                    ):
                        emit(
                            defect_class="bounds",
                            rule="derived_protocol_length_reaches_copy_without_input_bound",
                            line=line,
                            description="推导出的协议长度到达一个复制点，却没有证明输入缓冲区包含那么多字节。",
                            root_cause="目标边界已检查，但源数据包长度并未与该推导出的复制长度绑定。",
                            suggested_fix="将推导出的长度同时与源数据包剩余字节和目标容量进行校验。",
                            source=line.text.strip(),
                            sink="copy using derived protocol length",
                            confidence=0.74,
                            impact_level="high",
                            positive=[
                                f"line {line.number}: protocol length is derived by arithmetic",
                                "nearby copy uses the derived length without an input-buffer bound",
                            ],
                        )
                        break

        for idx, line in enumerate(lines):
            length_from_header = re.search(
                r"\b(?:size_t|uint32_t|uint64_t|int)?\s*(?P<lenvar>[A-Za-z_]\w*(?:len|length|size)[A-Za-z_0-9]*)\s*="
                r"\s*(?:\([^)]*\)\s*)?[A-Za-z_]\w*(?:->|\.)[A-Za-z_0-9]*(?:len|length|size)[A-Za-z_0-9]*\s*-",
                line.text,
                re.IGNORECASE,
            )
            if not length_from_header:
                continue
            len_var = length_from_header.group("lenvar")
            later = "\n".join(item.text for item in lines[idx + 1 : idx + 9])
            if re.search(
                self._literal_api_pattern(
                    rf"\b(?:memcpy|memmove)\s*\([^;]*\b{re.escape(len_var)}\b"
                ),
                later,
            ):
                emit(
                    defect_class="bounds",
                    rule="header_length_subtraction_reaches_copy",
                    line=line,
                    description=f"序列化长度 `{len_var}` 通过减法推导得到，并到达一个复制点。",
                    root_cause="在没有剩余长度检查的情况下，头部长度可能下溢或超出接收到的线缆缓冲区。",
                    suggested_fix="在复制之前检查 header.length >= header size 且 header.length <= wire_len。",
                    source=line.text.strip(),
                    sink=f"copy using {len_var}",
                    confidence=0.82,
                    impact_level="high",
                    positive=[
                        f"line {line.number}: length is derived from serialized header length",
                        "nearby copy uses the derived body length",
                    ],
                )
                break

        # Detect a decoded control/discriminator field that is explicitly
        # discarded while a sibling field from the same input record drives a
        # branch.  Identity names are irrelevant: the evidence is the local
        # use-def relation, sibling decode, and validation asymmetry.
        decoded_field_re = re.compile(
            r"\b(?:u?int(?:8|16|32|64)_t|unsigned\s+(?:char|short|int|long)|"
            r"signed\s+(?:char|short|int|long)|char|short|int|long)\s+"
            r"(?P<var>[A-Za-z_]\w*)\s*=\s*"
            r"(?P<base>[A-Za-z_]\w*(?:(?:->|\.)[A-Za-z_]\w*)*)"
            r"\s*\[\s*(?P<index>[^\]]+)\s*\]\s*;"
        )
        decoded_fields: List[tuple[CodeLine, re.Match[str]]] = []
        for decoded_line in lines:
            match = decoded_field_re.search(decoded_line.text)
            if match:
                decoded_fields.append((decoded_line, match))
        has_input_bound_guard = bool(
            re.search(
                r"\bif\s*\([^)]*\b[A-Za-z_]\w*\s*"
                r"(?:<|<=|>|>=)\s*(?:\d+|sizeof\s*\([^)]*\))"
                r"[^)]*\)\s*\{?[\s\S]{0,120}\breturn\b",
                text,
                re.IGNORECASE,
            )
        )
        for decoded_line, decoded in decoded_fields:
            discarded = decoded.group("var")
            base = decoded.group("base")
            if not has_input_bound_guard or not re.search(
                rf"\(\s*void\s*\)\s*{re.escape(discarded)}\s*;",
                text,
            ):
                continue
            if re.search(
                rf"\b(?:if|while|switch)\s*\([^)]*\b{re.escape(discarded)}\b",
                text,
            ) or re.search(
                rf"\b{re.escape(discarded)}\b\s*(?:==|!=|<=|>=|<|>)",
                text,
            ):
                continue
            sibling = next(
                (
                    (sibling_line, sibling_match)
                    for sibling_line, sibling_match in decoded_fields
                    if sibling_match.group("var") != discarded
                    and sibling_match.group("base") == base
                    and (
                        re.search(
                            rf"\b(?:if|while|switch)\s*\([^)]*"
                            rf"\b{re.escape(sibling_match.group('var'))}\b",
                            text,
                        )
                        or re.search(
                            rf"\b{re.escape(sibling_match.group('var'))}\b\s*"
                            r"(?:==|!=|<=|>=|<|>)",
                            text,
                        )
                    )
                ),
                None,
            )
            if sibling is None:
                continue
            sibling_name = sibling[1].group("var")
            emit(
                defect_class="protocol_validation",
                rule="decoded_control_field_ignored",
                line=decoded_line,
                description=(
                    f"解码出的控制/鉴别字段 `{discarded}` 被显式忽略，而兄弟字段 `{sibling_name}` 驱动着校验。"
                ),
                root_cause=(
                    "某个输入记录的鉴别/版本字段没有任何比较、switch 或范围过滤，"
                    "尽管另一个被解码的兄弟字段经过了检查。"
                ),
                suggested_fix=(
                    "在处理兄弟状态之前，对照受支持的协议契约校验每个被解码的控制/鉴别字段。"
                ),
                source=decoded_line.text.strip(),
                sink=f"(void){discarded}",
                confidence=0.78,
                impact_level="high",
                positive=[
                    f"line {decoded_line.number}: `{discarded}` is decoded from `{base}`",
                    f"`{discarded}` is explicitly discarded without a filter",
                    f"sibling decoded field `{sibling_name}` controls a branch",
                ],
            )
            break

        if (
            re.search(rf"\b(?:{self._names_pattern(self._format_sink_names)})\s*\(", text)
            and re.search(r"\breturn\s+(?:ret|rc|status)\s*;", text)
            and re.search(r"\breturn\s+0\s*;", text)
        ):
            success_line = self._first_line_matching(
                lines,
                re.compile(r"\breturn\s+0\s*;"),
            )
            if success_line:
                emit(
                    defect_class="unchecked_return",
                    rule="error_probe_can_return_success",
                    line=success_line,
                    description="错误/探测路径可能落入成功的返回值。",
                    root_cause="该函数在一个分支中记录或返回低级状态，却把其他失败/不明确的探测状态当作成功处理。",
                    suggested_fix="归一化低级的返回码，并对不明确的探测结果显式判为失败。",
                    source="error/probe branch",
                    sink=success_line.text.strip(),
                    confidence=0.7,
                    positive=[
                        "function contains error logging/status return and a final success return"
                    ],
                )

        state_assign = next(
            (
                line
                for line in lines
                if re.search(r"\bg_[A-Za-z_0-9.]*state[A-Za-z_0-9.]*\s*=", line.text)
            ),
            None,
        )
        state_name = None
        if state_assign:
            state_match = re.search(
                r"\b(?P<state>g_[A-Za-z_0-9.]*state[A-Za-z_0-9.]*)\s*=",
                state_assign.text,
            )
            if state_match:
                state_name = state_match.group("state")
        state_restored = bool(
            state_name and re.search(rf"\b{re.escape(state_name)}\s*=\s*previous\s*;", text)
        )
        if state_assign and re.search(r"\breturn\s+-1\s*;", text) and not state_restored:
            emit(
                defect_class="state_inconsistency",
                rule="global_state_not_restored_on_error",
                line=state_assign,
                description="全局状态在错误路径之前被修改，却没有可见的恢复。",
                root_cause="失败的 syscall 或校验路径可能使共享状态停留在某个临时值上。",
                suggested_fix="在返回之前，在每个失败路径上恢复之前的状态。",
                source=state_assign.text.strip(),
                sink="error return before restore",
                confidence=0.72,
                impact_level="high",
                positive=[
                    f"line {state_assign.number}: shared state assignment",
                    "function has an error return and no assignment restoring `previous`",
                ],
            )

        unchecked_insert = next(
            (line for line in lines if self._bound_api_calls(line.text, {"ownership_transfer"})),
            None,
        )
        if unchecked_insert:
            prior_alloc = any(
                self._alloc_re.search(item.text) or self._calloc_re.search(item.text)
                for item in lines[max(0, unchecked_insert.index - 8) : unchecked_insert.index]
            )
            if (
                prior_alloc
                and "=" not in unchecked_insert.text.split("(", 1)[0]
                and not re.search(r"\b(?:if|while|for)\s*\(", unchecked_insert.text)
            ):
                emit(
                    defect_class="memory_leak",
                    rule="unchecked_insert_after_ownership_handoff",
                    line=unchecked_insert,
                    description="在分配/链接一个节点之后，与所有权相关的 insert 返回值被忽略。",
                    root_cause="如果 insert 辅助函数在报告失败之前就先链接了状态，调用方就会失去一个可靠的清理决策点。",
                    suggested_fix="检查 insert 的返回值，并明确在每种失败模式下所有权是否发生转移。",
                    source=unchecked_insert.text.strip(),
                    sink="ignored insert return value",
                    confidence=0.74,
                    impact_level="high",
                    positive=[
                        f"line {unchecked_insert.number}: insert-like helper return value is ignored",
                        "nearby code allocates an ownership-bearing node before the insert",
                    ],
                )

        trunc = self._first_line_matching(
            lines,
            re.compile(
                self._literal_api_pattern(
                    r"\bstrncpy\s*\([^;]*,\s*[A-Za-z_]\w*(?:key|name)[A-Za-z_0-9]*\s*,\s*\d+\s*\)"
                ),
                re.I,
            ),
        )
        if trunc and re.search(r"\[[^\]]+\]\s*=\s*'\\0'", text):
            emit(
                defect_class="key_truncation",
                rule="truncated_key_used_for_route_insert",
                line=trunc,
                description="路由/键插入在存储之前截断了完整键。",
                root_cause="查找与插入可能使用不同的键宽，从而可能引发冲突或选择错误的路由。",
                suggested_fix="拒绝过长的键，或一致地存储/比较同一完整键表示。",
                source=trunc.text.strip(),
                sink="truncated key stored in route node",
                confidence=0.8,
                impact_level="high",
                positive=[f"line {trunc.number}: bounded strncpy truncates a key before insertion"],
            )

        write_line = self._first_line_matching(
            lines,
            re.compile(
                self._literal_api_pattern(
                    r"\bwrite\s*\(\s*(?P<fd>[A-Za-z_]\w*(?:->[A-Za-z_]\w*)?)"
                )
            ),
        )
        write_match = (
            re.search(
                r"\bwrite\s*\(\s*(?P<fd>[A-Za-z_]\w*(?:->[A-Za-z_]\w*)?)",
                write_line.text,
            )
            if write_line
            else None
        )
        peer_fd = str(write_match.group("fd") if write_match else "")
        peer_evidence = bool(
            re.search(r"(?:peer|socket|sock|pipe|conn|control|reply)", peer_fd, re.I)
            or re.search(
                rf"\b{re.escape(peer_fd)}\s*=\s*(?:::)?(?:socket|accept|accept4)\s*\(",
                text,
            )
            or re.search(
                rf"\b(?:pipe|socketpair)\s*\([^;]*\b{re.escape(peer_fd)}\b", text
            )
        )
        if (
            write_line
            and peer_evidence
            and "SIGPIPE" not in text
            and "MSG_NOSIGNAL" not in text
        ):
            emit(
                defect_class="sigpipe_unhandled",
                rule="write_without_sigpipe_handling",
                line=write_line,
                description="对等端写入在没有可见的 SIGPIPE 抑制或处理的情况下被发出。",
                root_cause="已关闭的对等端可能引发 SIGPIPE 并终止进程，或绕过正常的错误处理。",
                suggested_fix="使用 send(..., MSG_NOSIGNAL)，忽略/处理 SIGPIPE，或使用特定平台的无信号标志。",
                source=write_line.text.strip(),
                sink="closed peer write",
                confidence=0.74,
                impact_level="high",
                positive=[f"line {write_line.number}: write to peer fd without SIGPIPE handling"],
            )

        for idx, line in enumerate(lines):
            cpp_new = re.search(
                r"\b(?:[A-Za-z_]\w*(?:::[A-Za-z_]\w*)*(?:\s*<[^;=]+>)?\s*)?"
                r"\*\s*(?P<owner>[A-Za-z_]\w*)\s*=\s*new\b",
                line.text,
            )
            if cpp_new:
                self._emit_cpp_new_failed_status_leak(
                    lines,
                    idx,
                    line,
                    cpp_new.group("owner"),
                    emit,
                )

            alloc = re.search(
                self._semantic_api_pattern(
                    r"\b(?P<owner>[A-Za-z_]\w*(?:->[A-Za-z_]\w*)?)\s*=\s*(?:\([^)]*\)\s*)?"
                    r"(?P<alloc>(?:malloc|calloc|realloc|strdup))\s*\("
                ),
                line.text,
                re.IGNORECASE,
            )
            if not alloc:
                continue
            owner = alloc.group("owner")
            later_lines = lines[idx + 1 : idx + 18]
            release_re = re.compile(
                self._semantic_api_pattern(rf"\b(?:free)\s*\(\s*{re.escape(owner)}\s*\)")
            )
            error_return = next(
                (
                    item
                    for item in later_lines
                    if re.search(r"\breturn\s+-1\s*;", item.text)
                    and not any(
                        release_re.search(prior.text)
                        for prior in later_lines[: max(0, item.index - idx - 1)]
                    )
                ),
                None,
            )
            if error_return:
                emit(
                    defect_class="memory_leak",
                    rule="error_path_allocation_not_released",
                    line=line,
                    description=f"`{owner}` 在不会释放它的错误 return 之前被分配。",
                    root_cause="后续的失败路径在该分配的 owner 完成清理之前就返回了。",
                    suggested_fix="在错误路径上释放该分配，或跳转到共享的清理标签。",
                    source=line.text.strip(),
                    sink=error_return.text.strip(),
                    confidence=0.78,
                    impact_level="high",
                    positive=[
                        f"line {line.number}: `{owner}` receives allocated storage",
                        f"line {error_return.number}: error return before release",
                    ],
                )
            if "->" in owner:
                base = owner.split("->", 1)[0]
                later = "\n".join(item.text for item in later_lines)
                if re.search(
                    self._semantic_api_pattern(rf"\b(?:free)\s*\(\s*{re.escape(base)}\s*\)"), later
                ) and not release_re.search(later):
                    emit(
                        defect_class="memory_leak",
                        rule="member_allocation_not_released_with_parent",
                        line=line,
                        description=f"成员分配 `{owner}` 在 `{base}` 被释放之前未被释放。",
                        root_cause="释放父对象并不会释放单独分配的子节点/成员存储。",
                        suggested_fix="在释放父对象之前释放其所拥有的成员。",
                        source=line.text.strip(),
                        sink=f"free parent `{base}`",
                        confidence=0.8,
                        impact_level="high",
                        positive=[
                            f"line {line.number}: member allocation `{owner}`",
                            f"later path frees parent `{base}` without freeing the member",
                        ],
                    )

        self._emit_unchecked_native_status_masking(lines, emit)

    def _emit_cpp_new_failed_status_leak(
        self,
        lines: Sequence[CodeLine],
        alloc_index: int,
        alloc_line: CodeLine,
        owner: str,
        emit: Callable[..., None],
    ) -> None:
        """Find a raw ``new`` owner transferred only on a success branch.

        Merely seeing ``new`` followed by a return is intentionally
        insufficient.  The path must contain a status produced by an
        operation on the new object, an ``ok()`` guard around the only
        visible ownership handoff, and an unconditional return of that same
        status after the guard.
        """

        tail = list(lines[alloc_index + 1 :])
        if not tail:
            return
        release_re = re.compile(
            rf"\b(?:delete\s*(?:\[\s*\])?\s*{re.escape(owner)}\b|"
            rf"free\s*\(\s*{re.escape(owner)}\s*\))"
        )
        if any(release_re.search(item.text) for item in tail):
            return

        status_assignments: Dict[str, CodeLine] = {}
        for item in tail:
            status = re.search(
                rf"\b(?:[A-Za-z_]\w*(?:::[A-Za-z_]\w*)*\s+)?"
                rf"(?P<status>[A-Za-z_]\w*)\s*=\s*[^;]*\b{re.escape(owner)}\s*"
                rf"(?:->|\.)\s*[A-Za-z_]\w*\s*\(",
                item.text,
            )
            if status:
                status_assignments.setdefault(status.group("status"), item)
        if not status_assignments:
            return

        for guard_index, guard_line in enumerate(
            lines[alloc_index + 1 :], start=alloc_index + 1
        ):
            guard = re.search(
                r"\bif\s*\(\s*(?P<status>[A-Za-z_]\w*)\s*\.\s*ok\s*\(\s*\)\s*\)",
                guard_line.text,
            )
            if not guard:
                continue
            status_name = guard.group("status")
            status_line = status_assignments.get(status_name)
            if status_line is None or status_line.index >= guard_line.index:
                continue
            block_end = self._source_block_end(lines, guard_index)
            if block_end is None:
                continue
            guarded = lines[guard_index : block_end + 1]
            transfer_line = next(
                (
                    item
                    for item in guarded
                    if re.search(
                        rf"(?:^|[^=!<>])=\s*{re.escape(owner)}\s*;",
                        item.text,
                    )
                ),
                None,
            )
            if transfer_line is None:
                continue

            return_line = next(
                (
                    item
                    for item in lines[block_end + 1 :]
                    if re.search(rf"\breturn\s+{re.escape(status_name)}\s*;", item.text)
                ),
                None,
            )
            if return_line is None:
                continue
            between = lines[alloc_index + 1 : return_line.index]
            if any(release_re.search(item.text) for item in between):
                continue
            # A handoff outside the success guard also covers the failure
            # return and therefore breaks this particular leak chain.
            if any(
                re.search(rf"(?:^|[^=!<>])=\s*{re.escape(owner)}\s*;", item.text)
                for item in between
                if item.index < guard_index or item.index > block_end
            ):
                continue

            emit(
                defect_class="memory_leak",
                rule="error_path_allocation_not_released",
                line=alloc_line,
                description=(
                    f"`{owner}` 由 C++ `new` 创建，但仅在 `{status_name}.ok()` 成功分支"
                    "转移所有权；失败状态返回前没有释放它。"
                ),
                root_cause=(
                    "原始指针的所有权转移受成功条件保护，而同一状态的失败路径直接返回，"
                    "没有对应的 delete 或其他可见清理。"
                ),
                suggested_fix=(
                    "在失败返回前 delete 该对象，或先用 std::unique_ptr 持有并仅在成功时 release。"
                ),
                source=alloc_line.text.strip(),
                sink=return_line.text.strip(),
                confidence=0.9,
                impact_level="high",
                positive=[
                    f"line {alloc_line.number}: raw owner `{owner}` is created with C++ new",
                    f"line {status_line.number}: `{status_name}` is produced by an operation on `{owner}`",
                    f"line {transfer_line.number}: ownership is transferred only under `{status_name}.ok()`",
                    f"line {return_line.number}: the same status is returned without deleting `{owner}` on failure",
                ],
                negative=[
                    "no delete/free of the raw owner is visible before the status return",
                    "no ownership handoff is visible outside the success-only branch",
                ],
                evidence={
                    "path": {
                        "function": getattr(self, "_function_name", ""),
                        "complete_in_function": True,
                        "source_line": alloc_line.number,
                        "status_line": status_line.number,
                        "guard_line": guard_line.number,
                        "transfer_line": transfer_line.number,
                        "sink_line": return_line.number,
                        "path_constraints": [
                            f"failure of {status_name}.ok() skips ownership transfer",
                            f"return {status_name} executes on that failure path",
                        ],
                    },
                    "ownership": {
                        "object": owner,
                        "acquire": "cxx_new",
                        "success_transfer": transfer_line.text.strip(),
                        "failure_release": "absent",
                    },
                },
            )
            return

    @staticmethod
    def _source_block_end(lines: Sequence[CodeLine], start_index: int) -> Optional[int]:
        """Return the line index that closes a braced source block."""

        depth = 0
        opened = False
        for index in range(start_index, len(lines)):
            text = re.sub(r'"(?:\\.|[^"\\])*"', "", lines[index].text)
            for char in text:
                if char == "{":
                    depth += 1
                    opened = True
                elif char == "}" and opened:
                    depth -= 1
                    if depth == 0:
                        return index
        return None

    def _emit_unchecked_native_status_masking(self, lines: List[CodeLine], emit) -> None:
        """Find an ignored, exact non-void call masked by a later return.

        Source spelling alone cannot establish that a project call returns a
        status.  The fast planner already supplies the current native
        ``program_function`` receipt, so require the exact call event and its
        canonical non-void signature before producing this candidate.
        """

        bodies = [
            value
            for value in (self.program_facts.get("functions") or [])
            if isinstance(value, Mapping)
        ]
        if len(bodies) != 1:
            return
        events_by_line: Dict[int, List[Mapping[str, Any]]] = {}
        for event in bodies[0].get("events") or []:
            if not isinstance(event, Mapping) or event.get("event_kind") != "call":
                continue
            location = event.get("location")
            if not isinstance(location, Mapping):
                continue
            line_number = int(location.get("line") or 0)
            if line_number > 0:
                events_by_line.setdefault(line_number, []).append(event)

        def nonvoid_project_call(event: Mapping[str, Any]) -> tuple[str, str] | None:
            callee = event.get("callee")
            if not isinstance(callee, Mapping):
                return None
            name = str(callee.get("name") or event.get("callee_name") or "")
            signature = str(
                callee.get("canonical_signature") or callee.get("signature") or ""
            ).strip()
            result = signature.split("(", 1)[0].strip().lower()
            if (
                not name
                or not signature
                or result in {"", "void"}
                or bool(callee.get("is_system_header"))
                or not str(callee.get("usr") or callee.get("referenced_usr") or "")
            ):
                return None
            return name, signature

        for line in lines:
            stripped = line.text.strip()
            standalone = re.fullmatch(r"(?P<callee>[A-Za-z_]\w*)\s*\([^;]*\)\s*;", stripped)
            if (
                standalone is None
                or stripped.startswith("(void)")
                or re.match(r"(?:return|if|while|for|switch)\b", stripped)
                or "=" in stripped.split("(", 1)[0]
            ):
                continue
            native = next(
                (
                    details
                    for event in events_by_line.get(line.number, [])
                    if (details := nonvoid_project_call(event)) is not None
                    and details[0] == standalone.group("callee")
                    and not str(event.get("assignment_target") or "")
                ),
                None,
            )
            if native is None:
                continue
            returned_line = None
            returned_native = None
            for later in lines[line.index + 1 : line.index + 8]:
                if re.search(r"\b(?:if|while|switch)\s*\(", later.text):
                    break
                returned = re.search(r"\breturn\s+(?P<callee>[A-Za-z_]\w*)\s*\(", later.text)
                if returned:
                    returned_native = next(
                        (
                            details
                            for event in events_by_line.get(later.number, [])
                            if (details := nonvoid_project_call(event)) is not None
                            and details[0] == returned.group("callee")
                        ),
                        None,
                    )
                    if returned_native is not None:
                        returned_line = later
                    break
                if re.search(r"\breturn\s+(?:0|true)\s*;", later.text):
                    returned_line = later
                    returned_native = ("success_literal", "int")
                    break
            if returned_line is None or returned_native is None:
                continue
            emit(
                defect_class="unchecked_return",
                rule="error_probe_can_return_success",
                line=line,
                description=(
                    f"`{native[0]}` 的非 void 返回状态被丢弃，随后函数返回了"
                    f" `{returned_native[0]}` 的独立结果。"
                ),
                root_cause=(
                    "前一个可失败操作的状态没有参与控制流或最终返回值，"
                    "后续成功结果可能掩盖该失败。"
                ),
                suggested_fix="保存并检查每个状态；任一步失败时立即返回或合并错误状态。",
                source=f"{native[0]}: {native[1]}",
                sink=returned_line.text.strip(),
                confidence=0.82,
                impact_level="high",
                positive=[
                    f"line {line.number}: current native receipt identifies `{native[0]}` as `{native[1]}`",
                    f"line {line.number}: the returned status is neither assigned nor checked",
                    f"line {returned_line.number}: an independent result is returned instead",
                ],
                negative=[],
            )

    def _emit_borrowed_after_unlock(
        self, lines: List[CodeLine], return_line: CodeLine, emit
    ) -> None:
        match = re.search(r"\breturn\s+(?P<ret>[A-Za-z_]\w+)\s*;", return_line.text)
        if not match:
            return
        ret = match.group("ret")
        if ret not in self._pointer_owner_vars(lines):
            return
        previous = list(reversed(lines[max(0, return_line.index - 12) : return_line.index]))
        assigned = None
        saw_unlock = False
        for item in previous:
            if self._unlock_re.search(item.text):
                saw_unlock = True
            if re.search(rf"\b{re.escape(ret)}\s*=\s*[^;]*->[A-Za-z_]\w*", item.text):
                assigned = item
                break
        if assigned and saw_unlock:
            emit(
                defect_class="use_after_free",
                rule="borrowed_pointer_returned_after_unlock",
                line=return_line,
                description=f"借用指针 `{ret}` 在保护它的锁被释放之后被返回。",
                root_cause="并发的修改可能在解锁之后、调用方使用之前释放或替换所指向的对象。",
                suggested_fix="返回一个拥有所有权的副本，或在解锁之前持有该锁下的引用。",
                source=f"borrowed pointer assigned at line {assigned.number}",
                sink=return_line.text.strip(),
                confidence=0.82,
                impact_level="high",
                positive=[
                    f"line {assigned.number}: borrowed pointer is read from shared object",
                    "a matching unlock appears before return",
                    f"line {return_line.number}: borrowed pointer escapes to caller",
                ],
            )

    @staticmethod
    def _first_line_matching(lines: List[CodeLine], pattern: re.Pattern[str]) -> Optional[CodeLine]:
        return next((line for line in lines if pattern.search(line.text)), None)


class GraphProtocolOwnershipLogicRules:
    def _rule_tree_and_liveness_protocols(
        self,
        view: FunctionView,
        issues: List[Dict[str, Any]],
    ) -> None:
        for line in view.lines:
            self_link = re.search(r"\b(?P<obj>[A-Za-z_]\w*)->next\s*=\s*(?P=obj)\s*;", line.text)
            if self_link:
                obj = self_link.group("obj")
                issues.append(
                    self._issue(
                        defect_class="infinite_loop",
                        rule="self_referential_list_link",
                        view=view,
                        line=line,
                        description=f"`{obj}->next` 被设置为 `{obj}`，从而形成了一个自引用链表节点。",
                        root_cause=(
                            "后续的遍历，或者某个在解除链接之前保留了该节点的并发遍历者，"
                            "可能沿着被污染的 next 指针永远回到同一个节点。"
                        ),
                        suggested_fix="使用 NULL 或一个不可遍历的毒值，并确保后续的遍历者能够发现已移除的节点。",
                        source=obj,
                        sink=line.text.strip(),
                        confidence=0.84,
                        impact_level="high",
                        positive=[
                            f"line {line.number}: self-link assignment `{line.text.strip()}`",
                            "self-link poisoning is unsafe when any sibling traversal can hold a stale iterator",
                        ],
                        negative=[
                            "Validator must reason about stale/current iterators, not only a fresh traversal from the current head."
                        ],
                    )
                )

        text = "\n".join(line.text for line in view.lines)
        if (
            re.search(r"LOG_(?:ERROR|WARN|INFO)", text)
            and re.search(r"=\s*[A-Za-z_]\w*->next", text)
            and re.search(
                r"poison|self|diagnostic_marker|parked|marker",
                text,
                re.I,
            )
        ):
            line = (
                self._first_line_matching(view, re.compile(r"LOG_(?:ERROR|WARN|INFO)"))
                or view.lines[0]
            )
            marker_kind = (
                "poison marker"
                if re.search(r"poison|self", text, re.I)
                else "diagnostic/parked marker"
            )
            issues.append(
                self._issue(
                    defect_class="log_amplification",
                    rule="log_inside_poisoned_traversal",
                    view=view,
                    line=line,
                    description="对被污染的或被停靠的节点进行的遍历会在循环内部输出日志。",
                    root_cause="存活检查失败可能让遍历在同一个元素上停滞，同时循环不断输出重复的日志。",
                    suggested_fix="遇到毒值/停靠标记时中断遍历，并对循环内的错误日志进行限速或抑制。",
                    source="poisoned traversal",
                    sink=line.text.strip(),
                    confidence=0.8,
                    impact_level="medium",
                    positive=[
                        "loop follows next pointers",
                        f"line {line.number}: log call occurs inside traversal",
                        f"{marker_kind} appears in the traversal logic",
                    ],
                )
            )

        if re.search(
            self._literal_api_pattern(r"\bstrncpy\s*\([^;]*(?:KEY_LIMIT|KEY_MAX|MAX_KEY|LIMIT)"),
            text,
        ) and re.search(
            r"full_key|strcmp|find_[A-Za-z_0-9]*key",
            text,
        ):
            line = (
                self._first_line_matching(
                    view, re.compile(self._literal_api_pattern(r"\bstrncpy\s*\("))
                )
                or view.lines[0]
            )
            issues.append(
                self._issue(
                    defect_class="key_truncation",
                    rule="full_key_lookup_truncated_insert",
                    view=view,
                    line=line,
                    description="查找路径使用完整键，而插入只存储一个有界的/被截断的键。",
                    root_cause="查找与插入对键的归一化方式不同，因此不同的完整键可能发生冲突或绕过查找。",
                    suggested_fix="对查找与插入使用同一规范键表示，并显式拒绝过长的键。",
                    source="full-key lookup",
                    sink=line.text.strip(),
                    confidence=0.76,
                    impact_level="medium",
                    positive=[
                        "function compares or references full keys",
                        f"line {line.number}: bounded copy can truncate the stored key",
                    ],
                )
            )

        node_free_re = re.compile(
            rf"\b(?:{self._names_pattern(self._free_names)})\s*\(\s*node\s*\)",
            re.I,
        )
        if (
            re.search(r"(?:insert|add).*node", text, re.I)
            and node_free_re.search(text)
            and not re.search(
                (
                    r"(?:remove|unlink|delete).*node"
                    if not self.restrict_to_semantics
                    or self._semantic_call_allowed("delete", "deallocator")
                    else r"(?:remove|unlink|delete(?!\s*\()).*node"
                ),
                text,
                re.I,
            )
        ):
            line = self._first_line_matching(view, node_free_re) or view.lines[0]
            issues.append(
                self._issue(
                    defect_class="use_after_free",
                    rule="insert_failure_leaves_stale_tree_node",
                    view=view,
                    line=line,
                    description="一个节点可能在后续失败释放它之前被插入到索引/树中，却未移除陈旧的链接。",
                    root_cause="失败清理释放了节点，但并未回滚此前建立的索引/链表所有权。",
                    suggested_fix="在后续失败路径释放节点之前，回滚每一次成功的插入/链接。",
                    source="index/tree insertion",
                    sink=line.text.strip(),
                    confidence=0.82,
                    impact_level="high",
                    positive=[
                        "function inserts/adds a node into an index-like structure",
                        f"line {line.number}: failure cleanup frees `node`",
                        "no remove/unlink rollback is visible before free",
                    ],
                )
            )

    def _rule_protocol_state_contracts(
        self,
        view: FunctionView,
        issues: List[Dict[str, Any]],
    ) -> None:
        text = "\n".join(line.text for line in view.lines)

        mismatch_line = self._first_line_matching(
            view,
            re.compile(
                r"\b[A-Za-z_]\w*(?:sleep|window|timer|callback|schedule)[A-Za-z_0-9]*\s*\([^;]*(?:busy|work)[A-Za-z_0-9]*",
                re.I,
            ),
        )
        if mismatch_line and re.search(r"\b(?:busy|work)[A-Za-z_0-9]*\s*=", text, re.I):
            issues.append(
                self._issue(
                    defect_class="semantic_mismatch",
                    rule="cross_domain_counter_passed_to_callback_contract",
                    view=view,
                    line=mismatch_line,
                    description="来自某个运行时域的计数器被传入来自另一个域的回调/调度器契约。",
                    root_cause="调用路径保留了类型兼容性，却丢失了被调用方契约所期望的语义单位。",
                    suggested_fix="显式传递被调用方期望的域值，或重命名/拆分计数器，以便在边界处拒绝单位不匹配。",
                    source="domain counter",
                    sink=mismatch_line.text.strip(),
                    confidence=0.72,
                    impact_level="medium",
                    positive=[
                        "local code derives a busy/work counter",
                        f"line {mismatch_line.number}: the counter is passed to a sleep/window/timer/callback contract",
                    ],
                    negative=[
                        "Validator must confirm the callee expects a different counter domain."
                    ],
                )
            )

        endian_line = self._first_line_matching(
            view, re.compile(self._literal_api_pattern(r"__builtin_ctz(?:ll)?\s*\("))
        )
        if (
            endian_line
            and re.search(
                self._literal_api_pattern(r"\bmemcpy\s*\(\s*&[A-Za-z_]\w+\s*,\s*[^;]*input\s*\+"),
                text,
            )
            and not (
                re.search(r"\b(?:be(?:16|32|64)toh|ntoh(?:s|l)|bswap|__builtin_bswap)", text)
                if not self.restrict_to_semantics
                else re.search(
                    self._literal_api_pattern(
                        r"\b(?:be16toh|be32toh|be64toh|ntohs|ntohl|bswap|__builtin_bswap|__builtin_bswap16|__builtin_bswap32|__builtin_bswap64)\s*\("
                    ),
                    text,
                )
            )
        ):
            issues.append(
                self._issue(
                    defect_class="byte_order_logic",
                    rule="wire_bitmap_ctz_without_endian_normalization",
                    view=view,
                    line=endian_line,
                    description="线缆字节被复制进主机整数并用 ctz 扫描，却没有进行字节序归一化。",
                    root_cause="尾随零操作返回的位索引依赖于主机序，在大端数据上可能指向错误的线缆字节。",
                    suggested_fix="在位扫描之前先归一化字节序，或按协议顺序扫描线缆字节数组。",
                    source="wire bitmap bytes",
                    sink=endian_line.text.strip(),
                    confidence=0.82,
                    impact_level="medium",
                    positive=[
                        "function copies byte-buffer data into integer words",
                        f"line {endian_line.number}: trailing-zero scan is applied to the host integer",
                        "no endian conversion is visible before the scan",
                    ],
                )
            )

        reader_line = self._first_line_matching(
            view,
            re.compile(r"(?:\.|->)?(?:[A-Za-z_]\w*)?reader[A-Za-z_0-9]*\s*="),
        )
        if (
            reader_line
            and "__atomic_fetch_add" in text
            and "__atomic_fetch_sub" in text
            and self._semantic_call_allowed("__atomic_fetch_add", "standard_operation")
            and self._semantic_call_allowed("__atomic_fetch_sub", "standard_operation")
            and not re.search(
                self._semantic_api_pattern(r"\b(?:pthread_mutex_lock|spin_lock)\s*\("), text
            )
        ):
            issues.append(
                self._issue(
                    defect_class="reader_state_race",
                    rule="single_reader_field_under_shared_reader_count",
                    view=view,
                    line=reader_line,
                    description="在共享读取计数允许多个读取者的同时，共享的读取者-所有者字段被写入。",
                    root_cause="原子计数更新保护的是计数值，而不是存储某个读取者标识的旁路字段。",
                    suggested_fix="使用按读取者区分的状态、用 rwlock 写者协议保护该标识字段，或移除单一所有者字段。",
                    source="shared reader field",
                    sink=reader_line.text.strip(),
                    confidence=0.84,
                    impact_level="high",
                    positive=[
                        "function increments/decrements a reader count atomically",
                        f"line {reader_line.number}: reader identity state is assigned outside a lock",
                    ],
                )
            )

        protocol_mismatch = self._first_line_matching(
            view,
            re.compile(
                r"\bif\s*\([^)]*(?:protocol|proto)[^)]*!=[^)]*(?:PROTOCOL|PROTO)[^)]*\)", re.I
            ),
        )
        if (
            protocol_mismatch
            and re.search(r"\bauth[A-Za-z_0-9]*", text, re.I)
            and "STRICT" in text.upper()
            and re.search(r"\breturn\s+0\s*;", text)
            and re.search(r"\breturn\s+-1\s*;", text)
        ):
            issues.append(
                self._issue(
                    defect_class="protocol_mixup",
                    rule="protocol_mismatch_accepted_under_non_strict_auth",
                    view=view,
                    line=protocol_mismatch,
                    description="当认证模式不严格时，协议不匹配可能被接受。",
                    root_cause=(
                        "协议边界检测到了意外的协议值，但一个非严格认证分支仍返回成功，"
                        "导致消息能够跨越协议上下文。"
                    ),
                    suggested_fix="在认证放宽之前拒绝协议不匹配，或对跨协议路由要求严格认证。",
                    source=protocol_mismatch.text.strip(),
                    sink="non-strict authentication branch returns success",
                    confidence=0.84,
                    impact_level="high",
                    positive=[
                        f"line {protocol_mismatch.number}: protocol mismatch is explicitly detected",
                        "auth/STRICT branch is used to decide whether the mismatch is fatal",
                        "the same function has a success return in the mismatch handling path",
                    ],
                    negative=[
                        "Validator must confirm the success return is reachable from the mismatch branch."
                    ],
                )
            )

        stack_line = self._first_line_matching(
            view,
            re.compile(
                self._literal_api_pattern(
                    r"\bmem(?:cpy|move)\s*\([^;]*\b[A-Za-z_]\w*\.name\s*,\s*[A-Za-z_]\w+\s*,\s*strlen\s*\("
                ),
                re.I,
            ),
        )
        if stack_line and re.search(self._literal_api_pattern(r"\bsnprintf\s*\([^;]*%s"), text):
            issues.append(
                self._issue(
                    defect_class="stack_overflow",
                    rule="composed_string_copied_to_member_buffer_without_bound",
                    view=view,
                    line=stack_line,
                    description="一个变长的拼接字符串以 strlen 的长度被复制进固定的成员缓冲区。",
                    root_cause="格式化缓冲区是有界的，但目标成员更小的固定尺寸并未被用作复制上限。",
                    suggested_fix="以目标成员尺寸进行复制，并在组装线程标签之前拒绝或截断名称。",
                    source="composed string",
                    sink=stack_line.text.strip(),
                    confidence=0.82,
                    impact_level="high",
                    positive=[
                        "function composes a string containing external text",
                        f"line {stack_line.number}: strlen(composed)+1 controls a member-buffer copy",
                    ],
                )
            )

        self._emit_uninitialized_output_candidate(view, issues)

        file_type_line = self._first_line_matching(
            view, re.compile(r"\bfile_size\s*<\s*map_size\b|\bmap_size\s*>\s*file_size\b")
        )
        if file_type_line and re.search(r"(?:IS_CHR|S_ISCHR|character device|chr)", text, re.I):
            issues.append(
                self._issue(
                    defect_class="file_type_validation",
                    rule="regular_file_size_check_applied_to_device_mapping",
                    view=view,
                    line=file_type_line,
                    description="映射校验在区分字符设备底层之前就套用了常规文件的尺寸语义。",
                    root_cause="字符设备/共享内存映射与常规文件并不具有相同的文件尺寸契约。",
                    suggested_fix="先根据底层类型分支，再在映射之前应用特定类型的尺寸校验。",
                    source="mapping size validation",
                    sink=file_type_line.text.strip(),
                    confidence=0.78,
                    impact_level="medium",
                    positive=[
                        f"line {file_type_line.number}: file-size check guards mapping size",
                        "the same function accepts character-device/shared-memory backing modes",
                    ],
                )
            )

        self._emit_index_bound_candidate(view, issues)
        self._emit_cached_group_iteration_candidate(view, issues)
        self._emit_global_mode_candidate(view, issues)
        self._emit_cas_slot_candidate(view, issues)
        self._emit_lost_wakeup_candidate(view, issues)
        self._emit_find_before_insert_lock_candidate(view, issues)
        self._emit_state_transition_candidate(view, issues)
        self._emit_signal_handler_candidate(view, issues)
        self._emit_role_release_candidate(view, issues)
        self._emit_fd_contract_candidate(view, issues)
        self._emit_sigpipe_unhandled_candidate(view, issues)
        self._emit_direct_index_bound_candidate(view, issues)
        self._emit_premature_destroy_candidate(view, issues)
        self._emit_registration_race_candidate(view, issues)
        self._emit_alloc_free_mismatch_candidate(view, issues)
        self._emit_key_generation_race_candidate(view, issues)
        self._emit_callee_external_length_to_buffer_candidate(view, issues)

    def _emit_fd_contract_candidate(
        self,
        view: FunctionView,
        issues: List[Dict[str, Any]],
    ) -> None:
        signature = view.signature or ""
        if not re.search(r"\b(?:reliable|encoded)[A-Za-z_0-9]*fd\b", signature, re.I):
            return
        line = self._first_line_matching(
            view,
            re.compile(
                r"\b[A-Za-z_]\w*(?:inter|raw|lower)[A-Za-z_0-9]*fd[A-Za-z_0-9]*\s*\([^;]*(?:reliable|encoded)[A-Za-z_0-9]*fd",
                re.I,
            ),
        )
        if not line:
            return
        issues.append(
            self._issue(
                defect_class="fd_type_mismatch",
                rule="encoded_or_reliable_fd_passed_to_raw_fd_contract",
                view=view,
                line=line,
                description="一个经过编码/可靠的描述符被传递给期望原始描述符的底层 API。",
                root_cause="由于两种表示都是类整数的值，描述符的表示契约被丢失了。",
                suggested_fix="在调用原始 fd 辅助函数之前解码/剥离校验位，或修改被调用方以接受经过编码的描述符类型。",
                source=signature,
                sink=line.text.strip(),
                confidence=0.86,
                impact_level="medium",
                positive=[
                    "function signature exposes an encoded/reliable descriptor parameter",
                    f"line {line.number}: descriptor is passed to an inter/raw-fd helper",
                ],
            )
        )

    def _rule_unchecked_ownership_transfer_return(
        self,
        view: FunctionView,
        issues: List[Dict[str, Any]],
    ) -> None:
        allocs = self._local_allocated_variables(view)
        if not allocs:
            return
        text = "\n".join(line.text for line in view.lines)
        for var, alloc_line in allocs.items():
            transfer_line = None
            transfer_callee = ""
            for line in view.lines:
                if line.index <= alloc_line.index:
                    continue
                call = re.search(
                    rf"\b(?P<callee>[A-Za-z_]\w*(?:insert|link|register|publish|add)[A-Za-z_0-9]*)\s*\([^;]*\b{re.escape(var)}\b",
                    line.text,
                    re.I,
                )
                if not call:
                    continue
                transfer_line = line
                transfer_callee = call.group("callee")
                break
            if not transfer_line:
                continue
            if re.search(r"^\s*(?:return|if|while|for)\b|=", transfer_line.text):
                continue
            callee_view = self._view_for(transfer_callee)
            if callee_view and re.match(r"\s*(?:static\s+)?void\b", callee_view.signature):
                continue
            if re.search(
                self._semantic_api_pattern(rf"\b(?:free|delete)\s*\([^;]*\b{re.escape(var)}\b"),
                text,
                re.I,
            ):
                continue
            success_after_transfer = any(
                line.index > transfer_line.index and re.search(r"\breturn\s+0\s*;", line.text)
                for line in view.lines
            )
            if not success_after_transfer:
                continue
            issues.append(
                self._issue(
                    defect_class="memory_leak",
                    rule="unchecked_ownership_transfer_return_loses_node",
                    view=view,
                    line=transfer_line,
                    description="一个已分配的对象被交给 insert/register 风格的所有权 API，而该 API 的返回值被忽略。",
                    root_cause=(
                        "转移辅助函数可能在链接或部分接受该对象之后失败；"
                        "由于调用方忽略了返回值且没有清理路径，所有权和注册表状态可能丢失。"
                    ),
                    suggested_fix="检查转移 API 的返回值，并在失败时回滚或销毁已分配的对象。",
                    source=alloc_line.text.strip(),
                    sink=transfer_line.text.strip(),
                    confidence=0.82,
                    impact_level="high",
                    positive=[
                        f"line {alloc_line.number}: `{var}` is allocated",
                        f"line {transfer_line.number}: `{var}` is passed to an ownership-transfer API as an unchecked expression statement",
                        "a later success return is visible and no cleanup of the transferred object is present",
                    ],
                    negative=[
                        "Validator must confirm the callee can fail or partially link the object before failure."
                    ],
                    evidence={
                        "path": {
                            "function": view.name,
                            "source_line": alloc_line.number,
                            "sink_line": transfer_line.number,
                            "complete_in_function": True,
                            "path_constraints": ["unchecked ownership-transfer return"],
                        }
                    },
                )
            )
            return

    def _local_allocated_variables(self, view: FunctionView) -> Dict[str, GraphLine]:
        allocs: Dict[str, GraphLine] = {}
        for line in view.lines:
            match = re.search(
                self._semantic_api_pattern(
                    r"\b(?P<var>[A-Za-z_]\w*)\s*=\s*(?:\([^)]*\)\s*)?"
                    r"(?:calloc|malloc|kzalloc|kmalloc)\s*\("
                ),
                line.text,
                re.I,
            )
            if match:
                allocs.setdefault(match.group("var"), line)
        return allocs

    @staticmethod
    def _line_publishes_object(text: str, var: str) -> bool:
        escaped = re.escape(var)
        return bool(
            re.search(
                rf"\b[A-Za-z_]\w*(?:insert|link|publish|register|add)[A-Za-z_0-9]*\s*\([^;]*\b{escaped}\b",
                text,
                re.I,
            )
            or re.search(rf"\bg_[A-Za-z_0-9.]*\s*=\s*{escaped}\b", text)
        )

    def _rule_paired_key_normalization_protocols(
        self,
        views: Sequence[FunctionView],
        issues: List[Dict[str, Any]],
    ) -> None:
        lookup_views = [
            view
            for view in views
            if re.search(r"(?:lookup|find|get|search)", view.name, re.I)
            and re.search(
                self._literal_api_pattern(r"\b(?:strcmp|strncmp|memcmp)\s*\("),
                "\n".join(line.text for line in view.lines),
            )
            and re.search(
                r"(?:full[_-]?key|\bkey\b)", "\n".join(line.text for line in view.lines), re.I
            )
        ]
        if not lookup_views:
            return
        for view in views:
            if not re.search(r"(?:insert|add|register|create|store|set)", view.name, re.I):
                continue
            for line in view.lines:
                bounded_copy = re.search(
                    self._literal_api_pattern(
                        r"\b(?P<api>strncpy|strlcpy|snprintf|memcpy)\s*\([^;]*"
                        r"(?P<limit>[A-Z][A-Z0-9_]*(?:KEY|KEYS)[A-Z0-9_]*(?:LIMIT|MAX|LEN|SIZE)|"
                        r"[A-Z][A-Z0-9_]*(?:LIMIT|MAX|LEN|SIZE)[A-Z0-9_]*KEY[A-Z0-9_]*)"
                    ),
                    line.text,
                )
                if not bounded_copy:
                    continue
                if not re.search(r"\bkey\b|->key|\.key", line.text, re.I):
                    continue
                lookup = lookup_views[0]
                if lookup.file_path != view.file_path and not self._views_share_protocol_terms(
                    lookup, view
                ):
                    continue
                lookup_line = (
                    self._first_line_matching(
                        lookup,
                        re.compile(self._literal_api_pattern(r"\b(?:strcmp|strncmp|memcmp)\s*\(")),
                    )
                    or lookup.lines[0]
                )
                issues.append(
                    self._issue(
                        defect_class="key_truncation",
                        rule="paired_full_key_lookup_truncated_insert",
                        view=view,
                        line=line,
                        description="完整键查找路径与一个存储有界/截断键的插入路径相配对。",
                        root_cause="查找与插入使用不同的键规范化方式，导致过长的键可能发生冲突或绕过查找。",
                        suggested_fix="对键只规范化一次，拒绝过长的键，并对查找与插入使用相同的存储表示。",
                        source=f"{lookup.name}:{lookup_line.number}:{lookup_line.text.strip()}",
                        sink=line.text.strip(),
                        confidence=0.84,
                        impact_level="high",
                        positive=[
                            f"{lookup.name} line {lookup_line.number}: lookup compares the full key",
                            f"{view.name} line {line.number}: `{bounded_copy.group('api')}` stores a key using `{bounded_copy.group('limit')}`",
                        ],
                        negative=[
                            "Validator must confirm the bounded copy truncates rather than rejecting overlong input."
                        ],
                        evidence={
                            "path": {
                                "lookup_function": lookup.name,
                                "insert_function": view.name,
                                "source_line": lookup_line.number,
                                "sink_line": line.number,
                                "complete_in_function": False,
                                "path_constraints": [
                                    "paired lookup/insert key normalization contract"
                                ],
                            }
                        },
                    )
                )
                break

    def _rule_paired_self_link_log_traversal(
        self,
        views: Sequence[FunctionView],
        issues: List[Dict[str, Any]],
    ) -> None:
        self_links: List[Tuple[FunctionView, GraphLine, str, str]] = []
        for view in views:
            for line in view.lines:
                match = re.search(
                    r"\b(?P<obj>[A-Za-z_]\w*)->(?P<field>next)\s*=\s*(?P=obj)\s*;", line.text
                )
                if match:
                    self_links.append((view, line, match.group("obj"), match.group("field")))
        if not self_links:
            return

        for view in views:
            text = "\n".join(line.text for line in view.lines)
            if not re.search(r"\b(?:while|for)\s*\(", text):
                continue
            if not re.search(r"\bLOG_(?:ERROR|WARN|INFO|DEBUG)\s*\(", text):
                continue
            if not re.search(r"=\s*[A-Za-z_]\w*->next\b", text):
                continue
            log_line = self._first_line_matching(
                view, re.compile(r"\bLOG_(?:ERROR|WARN|INFO|DEBUG)\s*\(")
            )
            if not log_line:
                continue
            for link_view, link_line, obj, field in self_links:
                if link_view.name == view.name:
                    continue
                stem_terms = (
                    set(self._identifier_terms(link_view.name))
                    | set(self._identifier_terms(view.name))
                    | set(self._identifier_terms(text))
                )
                if (
                    obj.lower() not in stem_terms
                    and "pipe" not in stem_terms
                    and not re.search(r"\bpipe\b", text, re.I)
                ):
                    continue
                issues.append(
                    self._issue(
                        defect_class="log_amplification",
                        rule="paired_self_referential_traversal_log_amplification",
                        view=view,
                        line=log_line,
                        description="在循环内部输出日志的遍历可能重新访问由兄弟路径产生的自引用节点。",
                        root_cause="让节点自我链接会使遍历停留在同一元素上，而循环内部的日志会放大这种存活失败。",
                        suggested_fix="使用不可遍历的毒值标记或 NULL，在遇到被污染/自我链接的节点时中断，并对循环日志进行限速。",
                        source=f"{link_view.name}:{link_line.number}:{link_line.text.strip()}",
                        sink=log_line.text.strip(),
                        confidence=0.82,
                        impact_level="high",
                        positive=[
                            f"{link_view.name} line {link_line.number}: `{obj}->{field}` is assigned to itself",
                            f"{view.name}: traversal follows `next` pointers",
                            f"{view.name} line {log_line.number}: traversal emits a log inside the loop",
                        ],
                        negative=[
                            "Validator must confirm the traversal can reach nodes handled by the self-linking path."
                        ],
                        evidence={
                            "path": {
                                "self_link_function": link_view.name,
                                "traversal_function": view.name,
                                "source_line": link_line.number,
                                "sink_line": log_line.number,
                                "complete_in_function": False,
                                "path_constraints": ["sibling lifecycle/traversal relationship"],
                            }
                        },
                    )
                )
                break


class ClangProtocolOwnershipLogicRules:
    def _run_common_sast_rules(
        self,
        issues: List[Dict[str, Any]],
        func_name: str,
        file_path: str,
        lines: Sequence[ClangCfgLine],
        allowed_skills: Optional[Set[str]],
    ) -> None:
        length_fields: Dict[str, Tuple[ClangCfgLine, str]] = {}
        permission_check_line: Optional[ClangCfgLine] = None
        unaligned_ptrs: Dict[str, ClangCfgLine] = {}
        held_locks: List[ClangCfgLine] = []
        emitted_shared_state: Set[str] = set()
        shared_accesses = SharedAccessIndex(
            lines,
            self.program_facts,
            self._lock_names,
            self._unlock_names,
            self.semantics.contracts,
            restrict_to_semantics=self.restrict_to_semantics,
        )
        local_aggregates: Dict[str, Tuple[ClangCfgLine, str]] = {}
        aggregate_field_writes: Dict[str, Set[str]] = {}
        signed_io_reads: Dict[str, ClangCfgLine] = {}
        signed_size_casts: Dict[str, Tuple[ClangCfgLine, str]] = {}
        command_env_vars: Dict[str, ClangCfgLine] = {}
        heap_thread_allocs: Dict[str, ClangCfgLine] = {}
        heap_thread_released: Set[str] = set()
        heap_thread_sinks: Dict[str, Tuple[ClangCfgLine, str]] = {}

        for idx, line in enumerate(lines):
            text = line.text
            self._track_local_aggregate(line, local_aggregates, aggregate_field_writes)
            self._track_heap_thread_argument_owner(
                line,
                heap_thread_allocs,
                heap_thread_released,
                heap_thread_sinks,
            )

            length_def = re.search(
                r"\b(?:size_t|uint(?:32|64)_t|int|unsigned(?:\s+int)?)\s+"
                r"(?P<var>[A-Za-z_]\w*(?:len|length|size)[A-Za-z_0-9]*)\s*=\s*"
                r"(?P<src>[A-Za-z_]\w*(?:->|\.)[A-Za-z_0-9]*(?:len|length|size)[A-Za-z_0-9]*)\s*;",
                text,
                re.IGNORECASE,
            )
            if length_def:
                length_fields[length_def.group("var")] = (line, length_def.group("src"))

            for len_var, (src_line, src_expr) in list(length_fields.items()):
                if line.index <= src_line.index:
                    continue
                if not self._copy_uses_length(text, len_var):
                    continue
                guard_window = "\n".join(
                    item.text for item in lines[max(0, line.index - 12) : line.index]
                )
                if re.search(
                    rf"\b{re.escape(len_var)}\b\s*[<>]=?\s*[^;]*(?:data_len|buf_len|buffer_len|remaining|capacity|sizeof|len\s*-)",
                    guard_window,
                    re.IGNORECASE,
                ):
                    continue
                self._emit(
                    issues,
                    func_name,
                    file_path,
                    lines,
                    allowed_skills,
                    defect_class="bounds",
                    rule="clang_cfg_external_length_field_reaches_copy",
                    line=line,
                    description=f"长度字段 `{src_expr}` 到达一个复制汇点，但没有可见的底层缓冲区长度检查。",
                    root_cause="序列化或结构化的长度字段被信任，却没有证明输入缓冲区包含那么多字节。",
                    suggested_fix="在复制或索引之前，将该字段与剩余输入长度进行校验。",
                    source=f"{src_expr} at line {src_line.number}",
                    sink=text,
                    confidence=0.82,
                    impact_level="high",
                    positive=[
                        f"line {src_line.number}: `{len_var}` is loaded from `{src_expr}`",
                        f"line {line.number}: `{len_var}` controls a copy length",
                    ],
                    negative=[
                        "Validator must confirm no earlier whole-buffer guard constrains the field."
                    ],
                    ast_cfg=self._ast_cfg_pack(
                        lines,
                        [
                            self._event("length_field_load", src_line, len_var, "", src_line.text),
                            self._event("copy_length_use", line, len_var, "", text),
                        ],
                        [src_line.number, line.number],
                    ),
                )
                length_fields.pop(len_var, None)

            self._maybe_emit_integer_overflow(
                issues, func_name, file_path, lines, allowed_skills, line
            )
            self._maybe_emit_format_string(
                issues, func_name, file_path, lines, allowed_skills, line
            )
            self._maybe_emit_command_injection(
                issues,
                func_name,
                file_path,
                lines,
                allowed_skills,
                line,
                command_env_vars,
            )
            self._maybe_emit_signed_unsigned(
                issues,
                func_name,
                file_path,
                lines,
                allowed_skills,
                line,
                signed_io_reads,
                signed_size_casts,
            )
            self._maybe_emit_off_by_one(issues, func_name, file_path, lines, allowed_skills, line)
            self._maybe_emit_stack_array_overflow(
                issues, func_name, file_path, lines, allowed_skills, line
            )
            self._maybe_emit_heap_copy_length_mismatch(
                issues, func_name, file_path, lines, allowed_skills, line
            )
            self._maybe_emit_offset_length_copy_overread(
                issues, func_name, file_path, lines, allowed_skills, line
            )
            self._maybe_emit_pointer_backtrack_underflow(
                issues, func_name, file_path, lines, allowed_skills, line
            )
            self._maybe_emit_invalid_free(issues, func_name, file_path, lines, allowed_skills, line)
            self._maybe_emit_interior_free_alias(
                issues, func_name, file_path, lines, allowed_skills, line
            )
            self._maybe_emit_unchecked_allocation_result(
                issues, func_name, file_path, lines, allowed_skills, line
            )
            self._maybe_emit_fixed_array_count_overflow(
                issues, func_name, file_path, lines, allowed_skills, line
            )
            self._maybe_emit_key_truncation(
                issues, func_name, file_path, lines, allowed_skills, line
            )
            self._maybe_emit_wire_integer_pointer_deref(
                issues, func_name, file_path, lines, allowed_skills, line
            )
            self._maybe_emit_unchecked_object_offset_access(
                issues, func_name, file_path, lines, allowed_skills, line
            )
            self._maybe_emit_uninitialized_pointer_use(
                issues, func_name, file_path, lines, allowed_skills, line
            )
            self._maybe_emit_unbounded_heap_allocation(
                issues, func_name, file_path, lines, allowed_skills, line
            )
            self._maybe_emit_slot_overwrite_leak(
                issues, func_name, file_path, lines, allowed_skills, line
            )
            self._maybe_emit_key_generation_race(
                issues, func_name, file_path, lines, allowed_skills, line
            )
            self._maybe_emit_file_type_validation_order(
                issues, func_name, file_path, lines, allowed_skills, line
            )
            self._maybe_emit_active_owner_premature_destroy(
                issues, func_name, file_path, lines, allowed_skills, line
            )
            self._maybe_emit_fd_leak_on_error_return(
                issues, func_name, file_path, lines, allowed_skills, line
            )
            self._maybe_emit_global_mapping_overwrite(
                issues, func_name, file_path, lines, allowed_skills, line
            )
            self._maybe_emit_guarded_fd_release_gap(
                issues, func_name, file_path, lines, allowed_skills, line
            )
            self._maybe_emit_unchecked_strchr_result(
                issues, func_name, file_path, lines, allowed_skills, line
            )
            self._maybe_emit_unchecked_wait_status_read(
                issues, func_name, file_path, lines, allowed_skills, line
            )
            self._maybe_emit_thread_stack_escape(
                issues, func_name, file_path, lines, allowed_skills, line, local_aggregates
            )
            self._maybe_emit_partial_aggregate_send(
                issues,
                func_name,
                file_path,
                lines,
                allowed_skills,
                line,
                local_aggregates,
                aggregate_field_writes,
            )
            self._maybe_track_or_emit_alignment(
                issues,
                func_name,
                file_path,
                lines,
                allowed_skills,
                line,
                unaligned_ptrs,
            )
            self._maybe_emit_macro_lock_race(
                issues, func_name, file_path, lines, allowed_skills, line
            )
            self._maybe_emit_fd_encoding_mismatch(
                issues, func_name, file_path, lines, allowed_skills, line
            )
            self._maybe_emit_global_state_not_restored_on_error(
                issues,
                func_name,
                file_path,
                lines,
                allowed_skills,
                line,
            )
            self._maybe_emit_wide_count_without_magic_guard(
                issues,
                func_name,
                file_path,
                lines,
                allowed_skills,
                line,
            )
            self._maybe_emit_fixed_limit_spec_mismatch(
                issues,
                func_name,
                file_path,
                lines,
                allowed_skills,
                line,
            )
            self._maybe_emit_recv_retry_without_budget(
                issues,
                func_name,
                file_path,
                lines,
                allowed_skills,
                line,
            )
            self._maybe_emit_global_dynamic_array_resize_race(
                issues,
                func_name,
                file_path,
                lines,
                allowed_skills,
                line,
            )
            self._maybe_emit_ignored_protocol_version(
                issues,
                func_name,
                file_path,
                lines,
                allowed_skills,
                line,
            )
            self._maybe_emit_unchecked_param_global_array_index(
                issues,
                func_name,
                file_path,
                lines,
                allowed_skills,
                line,
            )

            if self._match_lock(text):
                held_locks.append(line)
            self._maybe_emit_callback_under_lock(
                issues, func_name, file_path, lines, allowed_skills, line, held_locks
            )
            if self._match_unlock(text) and held_locks:
                held_locks.pop()

            if self._is_path_check(text):
                permission_check_line = line
            elif permission_check_line and re.search(
                self._literal_api_pattern(r"\b(?:open|fopen|creat)\s*\("), text
            ):
                self._emit(
                    issues,
                    func_name,
                    file_path,
                    lines,
                    allowed_skills,
                    defect_class="toctou",
                    rule="clang_cfg_path_check_before_open",
                    line=line,
                    description="路径名被单独检查，而后续的 open/use 操作是分开进行的。",
                    root_cause="在权限/存在性检查与后续 open 之间，路径可能发生变化。",
                    suggested_fix="先用安全标志打开文件，再对已打开的描述符进行校验。",
                    source=f"path check at line {permission_check_line.number}",
                    sink=text,
                    confidence=0.8,
                    positive=[
                        f"line {permission_check_line.number}: pathname check",
                        f"line {line.number}: later pathname open/use",
                    ],
                    negative=[],
                    ast_cfg=self._ast_cfg_pack(
                        lines,
                        [
                            self._event(
                                "path_check",
                                permission_check_line,
                                "path",
                                "",
                                permission_check_line.text,
                            ),
                            self._event("path_use", line, "path", "", text),
                        ],
                        [permission_check_line.number, line.number],
                    ),
                )
                permission_check_line = None

            self._maybe_emit_concurrency_protocols(
                issues,
                func_name,
                file_path,
                lines,
                allowed_skills,
                line,
                idx,
                emitted_shared_state,
                shared_accesses,
            )
            self._maybe_emit_refcount_update_after_unlock(
                issues, func_name, file_path, lines, allowed_skills, line, idx
            )
            self._maybe_emit_stale_fd(issues, func_name, file_path, lines, allowed_skills, line)
            self._maybe_emit_borrowed_callback_global(
                issues,
                func_name,
                file_path,
                lines,
                allowed_skills,
                line,
                idx,
            )
            self._maybe_emit_mapping_unmap_without_invalidation(
                issues,
                func_name,
                file_path,
                lines,
                allowed_skills,
                line,
            )
            self._maybe_emit_error_log_allocation_leak(
                issues,
                func_name,
                file_path,
                lines,
                allowed_skills,
                line,
            )
            self._maybe_emit_role_release_mismatch(
                issues,
                func_name,
                file_path,
                lines,
                allowed_skills,
                line,
            )
            self._maybe_emit_registry_unlink_free_after_unlock(
                issues,
                func_name,
                file_path,
                lines,
                allowed_skills,
                line,
            )
            self._maybe_emit_owned_member_leak_on_parent_release(
                issues,
                func_name,
                file_path,
                lines,
                allowed_skills,
                line,
            )
            self._maybe_emit_unchecked_insert_handoff(
                issues,
                func_name,
                file_path,
                lines,
                allowed_skills,
                line,
            )
            self._maybe_emit_protocol_length_copy_without_packet_bound(
                issues,
                func_name,
                file_path,
                lines,
                allowed_skills,
                line,
            )
            self._maybe_emit_header_length_copy_without_wire_bound(
                issues,
                func_name,
                file_path,
                lines,
                allowed_skills,
                line,
            )
            self._maybe_emit_probe_error_returns_success(
                issues,
                func_name,
                file_path,
                lines,
                allowed_skills,
                line,
                idx,
            )
            self._maybe_emit_refcount_free_without_protocol(
                issues,
                func_name,
                file_path,
                lines,
                allowed_skills,
                line,
                idx,
            )

        self._emit_heap_thread_argument_owner_leaks(
            issues,
            func_name,
            file_path,
            lines,
            allowed_skills,
            heap_thread_allocs,
            heap_thread_released,
            heap_thread_sinks,
        )
        self._emit_unlocked_global_state_write_candidates(
            issues, func_name, file_path, lines, allowed_skills
        )
        self._emit_permission_mode_candidate(issues, func_name, file_path, lines, allowed_skills)
        self._emit_timer_callback_lock_order_candidate(
            issues, func_name, file_path, lines, allowed_skills
        )
        self._emit_container_unlink_lifecycle_candidate(
            issues, func_name, file_path, lines, allowed_skills
        )
        self._emit_incomplete_owner_cleanup_candidate(
            issues, func_name, file_path, lines, allowed_skills
        )

    def _maybe_emit_registry_unlink_free_after_unlock(
        self,
        issues: List[Dict[str, Any]],
        func_name: str,
        file_path: str,
        lines: Sequence[ClangCfgLine],
        allowed_skills: Optional[Set[str]],
        line: ClangCfgLine,
    ) -> None:
        release = self._match_release(line.text)
        if not release:
            return
        _api, raw_released = release
        released = self._resource_expr(raw_released) or self._resource_var(raw_released)
        if not re.fullmatch(r"[A-Za-z_]\w*", released):
            return
        root = released
        prefix = lines[: line.index]
        unlink_match = None
        unlink_line = None
        for item in reversed(prefix):
            match = re.search(
                rf"(?P<container>[A-Za-z_]\w*(?:\s*(?:->|\.)\s*[A-Za-z_]\w*)*)\s*=\s*"
                rf"{re.escape(root)}\s*->\s*(?P<link>[A-Za-z_]\w*)\s*;",
                item.text,
            )
            if match and not re.fullmatch(
                rf"{re.escape(root)}\s*->.*", match.group("container").strip()
            ):
                unlink_line, unlink_match = item, match
                break
        if unlink_line is None or unlink_match is None:
            return

        lock_line = None
        lock_object = ""
        for item in reversed(lines[: unlink_line.index]):
            matched_lock = self._match_lock(item.text)
            matched_unlock = self._match_unlock(item.text)
            if matched_unlock:
                break
            if matched_lock:
                lock_line, lock_object = item, matched_lock[1]
                break
        if lock_line is None:
            return

        unlock_line = None
        normalized_lock = re.sub(r"\s+|^&", "", lock_object)
        for item in lines[unlink_line.index + 1 : line.index]:
            matched_unlock = self._match_unlock(item.text)
            if matched_unlock and re.sub(r"\s+|^&", "", matched_unlock[1]) == normalized_lock:
                unlock_line = item
                break
        if unlock_line is None:
            return
        for item in lines[unlock_line.index + 1 : line.index]:
            matched_lock = self._match_lock(item.text)
            if matched_lock and re.sub(r"\s+|^&", "", matched_lock[1]) == normalized_lock:
                return
        self._emit(
            issues,
            func_name,
            file_path,
            lines,
            allowed_skills,
            defect_class="race",
            rule="clang_cfg_registry_unlink_free_after_unlock",
            line=line,
            description="一个共享的注册表节点在注册表锁下被解除链接，却在锁释放之后才被释放。",
            root_cause="并发的读取者可能仍从注册表保留着借用指针，而清理过程又释放了锁并释放了节点的成员。",
            suggested_fix="在整个移除/释放流程中持有生命周期锁，或在释放节点之前加入引用计数式的交接。",
            source=unlink_line.text,
            sink=line.text,
            confidence=0.82,
            impact_level="critical",
            positive=[
                f"line {lock_line.number}: `{lock_object}` protects the container update",
                f"line {unlink_line.number}: `{unlink_match.group('container').strip()}` bypasses `{root}` through `{unlink_match.group('link')}`",
                f"line {unlock_line.number}: the same protection lock is released before cleanup",
                f"line {line.number}: unlinked object `{root}` is freed after the unlock window",
            ],
            negative=[
                "Validator must confirm whether registry readers can retain borrowed node pointers across this unlock window."
            ],
            ast_cfg=self._ast_cfg_pack(
                lines,
                [
                    self._event("registry_unlink", unlink_line, root, "", unlink_line.text),
                    self._event("registry_unlock", unlock_line, lock_object, "", unlock_line.text),
                    self._event("post_unlock_release", line, released, "", line.text),
                ],
                [unlink_line.number, unlock_line.number, line.number],
            ),
        )

    def _emit_permission_mode_candidate(
        self,
        issues: List[Dict[str, Any]],
        func_name: str,
        file_path: str,
        lines: Sequence[ClangCfgLine],
        allowed_skills: Optional[Set[str]],
    ) -> None:
        mode_assignment = None
        request_check = None
        special_name_branch = None
        body = "\n".join(line.text for line in lines)
        for line in lines:
            if mode_assignment is None and re.search(
                r"\b(?:g_[A-Za-z_0-9]+(?:\.|->))?(?:perm|mode|permission)\b\s*=\s*0[0-7]{2,4}u?\s*;",
                line.text,
                re.IGNORECASE,
            ):
                mode_assignment = line
            if request_check is None and re.search(
                r"\b(?:requested|request|desired|required)[A-Za-z_0-9]*(?:perm|permission|mode)\b[^;]*(?:&|==|!=)",
                line.text,
                re.IGNORECASE,
            ):
                request_check = line
            if special_name_branch is None and re.search(
                self._literal_api_pattern(r"\bstrcmp\s*\([^;]*(?:pipe|segment|shm|shared|product)"),
                line.text,
                re.IGNORECASE,
            ):
                special_name_branch = line

        if mode_assignment is None or request_check is None:
            return
        if re.search(
            self._literal_api_pattern(
                r"\b(?:chmod|fchmod|open|creat|shm_open|mmap)\s*\([^;]*(?:requested|request|desired|required)[A-Za-z_0-9]*(?:perm|permission|mode)\b"
            ),
            body,
            re.IGNORECASE,
        ):
            return

        positive = [
            f"line {mode_assignment.number}: file/shared-memory permission or mode is hard-coded",
            f"line {request_check.number}: requested permission is only compared locally",
        ]
        if special_name_branch is not None:
            positive.append(
                f"line {special_name_branch.number}: special name/deployment branch does not update the mode policy"
            )
        self._emit(
            issues,
            func_name,
            file_path,
            lines,
            allowed_skills,
            defect_class="permission",
            rule="clang_cfg_requested_permission_not_applied_to_mode",
            line=request_check,
            description="请求的文件/共享内存权限与被硬编码的模式进行了比较，但并未应用到底层对象之上。",
            root_cause="代码把权限当作一个本地校验标志，而实际的底层模式仍然保持固定。",
            suggested_fix="从经过校验的请求中推导出 open/chmod/mmap 的模式，或在发布该资源之前拒绝不受支持的请求。",
            source=mode_assignment.text,
            sink=request_check.text,
            confidence=0.72,
            positive=positive,
            negative=[
                "Validator must confirm no later platform-specific permission update applies the requested mode."
            ],
            ast_cfg=self._ast_cfg_pack(
                lines,
                [
                    self._event(
                        "hardcoded_permission",
                        mode_assignment,
                        "permission",
                        "",
                        mode_assignment.text,
                    ),
                    self._event(
                        "requested_permission_check",
                        request_check,
                        "permission",
                        "",
                        request_check.text,
                    ),
                ],
                [mode_assignment.number, request_check.number],
            ),
        )

    @staticmethod
    def _function_name_hint(func_name: str, lines: Sequence[ClangCfgLine]) -> str:
        signature = next((line.text for line in lines[:6] if "(" in line.text), "")
        match = re.search(r"\b(?P<name>[A-Za-z_]\w*)\s*\([^;]*\)\s*\{?", signature)
        parsed = match.group("name") if match else ""
        if parsed and parsed not in {"if", "for", "while", "switch"}:
            return parsed
        return str(func_name or "")

    def _known_refcount_fields(self) -> Set[str]:
        """Return compiler-verified/configured refcount carriers by field identity.

        The protocol registry owns the meaning; detector spelling is only a
        backward-compatible fallback for legacy ``ref_count`` candidates.
        """

        fields: Set[str] = set()
        for contract in self.semantics.contracts.contracts:
            protocol = contract.protocol or {}
            if protocol.get("family", protocol.get("kind")) != "non_atomic_refcount":
                continue
            path = str(protocol.get("count_path") or "")
            match = re.fullmatch(r"(?:->|\.)([A-Za-z_]\w*)", path)
            if match:
                fields.add(match.group(1))
        return fields

    def _find_owned_member_assignment(
        self,
        lines: Sequence[ClangCfgLine],
        release_line: ClangCfgLine,
        parent: str,
    ) -> Optional[Tuple[ClangCfgLine, str, str]]:
        for item in reversed(lines[max(0, release_line.index - 80) : release_line.index]):
            match = re.search(
                rf"\b{re.escape(parent)}\s*->\s*(?P<member>[A-Za-z_]\w*)\s*=\s*(?P<rhs>[^;]+);",
                item.text,
            )
            if not match:
                continue
            member = match.group("member")
            rhs = match.group("rhs").strip()
            if not self._looks_like_owned_member_rhs(rhs):
                continue
            if re.fullmatch(r"(?:NULL|nullptr|0)", rhs):
                continue
            return item, member, rhs
        return None

    def _looks_like_owned_member_rhs(self, rhs: str) -> bool:
        return bool(
            re.search(
                rf"\b(?:{self._names_pattern(self._return_acquirers | self._io_acquire_names)})\s*\(",
                str(rhs or ""),
                0 if self.restrict_to_semantics else re.IGNORECASE,
            )
        )

    def _owned_member_has_cleanup(
        self,
        lines: Sequence[ClangCfgLine],
        start_index: int,
        end_index: int,
        parent: str,
        member: str,
    ) -> bool:
        region = lines[start_index:end_index]
        member_expr = rf"{re.escape(parent)}\s*->\s*{re.escape(member)}"
        for item in region:
            release = self._match_release(item.text)
            if release and re.search(member_expr, release[1]):
                return True
            if re.search(member_expr, item.text) and re.search(r"\b(?:while|for)\b", item.text):
                return True
            if re.search(
                self._semantic_api_pattern(rf"\b(?:free)\s*\([^;]*{member_expr}"), item.text
            ):
                return True
        return False

    def _find_missing_common_owned_member_cleanup(
        self,
        lines: Sequence[ClangCfgLine],
        release_line: ClangCfgLine,
        parent: str,
    ) -> Optional[Tuple[ClangCfgLine, str]]:
        create_line = None
        api = ""
        for item in reversed(lines[max(0, release_line.index - 60) : release_line.index]):
            assignment = re.search(
                rf"\b{re.escape(parent)}\s*=\s*(?:\([^)]*\)\s*)?"
                r"(?P<api>[A-Za-z_]\w*)\s*\(",
                item.text,
            )
            if not assignment:
                continue
            candidate = assignment.group("api")
            if any(
                contract.carrier.kind == "return" and contract.carrier.member_path
                for contract in self.semantics.contracts.find(candidate)
            ):
                create_line, api = item, candidate
                break
        if create_line is None or not api:
            return None
        region = "\n".join(item.text for item in lines[create_line.index + 1 : release_line.index])
        owned_members = {
            c.carrier.member_path.removeprefix("->").removeprefix(".")
            for c in self.semantics.contracts.find(api)
            if c.carrier.kind == "return" and c.carrier.member_path and not c.conditions
        }
        if owned_members:
            for member in sorted(owned_members):
                if not re.search(
                    self._semantic_api_pattern(
                        rf"\b(?:free)\s*\([^;]*{re.escape(parent)}\s*->\s*{member}"
                    ),
                    region,
                    re.IGNORECASE,
                ):
                    return create_line, member
        return None

    def _looks_like_parent_delete_without_member_cleanup(
        self,
        func_name: str,
        lines: Sequence[ClangCfgLine],
        release_line: ClangCfgLine,
        parent: str,
    ) -> bool:
        effective_name = self._function_name_hint(func_name, lines)
        if not self.semantics.contracts.find(effective_name, "deallocator"):
            return False
        declaration = self._parent_declaration_text(lines, release_line, parent)
        if not re.search(
            r"(?:Node|Entry|Record|Object|Item|Session|Subscription|Group|Container)", declaration
        ):
            return False
        prefix = lines[max(0, release_line.index - 60) : release_line.index]
        if any(
            re.search(rf"\b{re.escape(parent)}\s*->", item.text) and self._match_release(item.text)
            for item in prefix
        ):
            return False
        if any(
            re.search(r"\b(?:while|for)\b", item.text)
            and re.search(r"(?:child|children|head|list|next)", item.text, re.IGNORECASE)
            for item in prefix
        ):
            return False
        return True

    @staticmethod
    def _parent_declaration_text(
        lines: Sequence[ClangCfgLine],
        release_line: ClangCfgLine,
        parent: str,
    ) -> str:
        for item in reversed(lines[max(0, release_line.index - 40) : release_line.index + 1]):
            if re.search(rf"\b[A-Za-z_]\w*\s*\*+\s*{re.escape(parent)}\b", item.text):
                return item.text
        return ""

    @staticmethod
    def _global_write_lhs(text: str) -> str:
        stripped = str(text or "")
        if re.search(r"\b(?:if|while|for|switch)\s*\(", stripped):
            return ""
        assign = re.search(
            r"\b(?P<lhs>g_[A-Za-z_]\w*(?:\s*(?:->|\.)\s*[A-Za-z_]\w*)?)\s*(?:=|\+=|-=|\*=|/=|%=)",
            stripped,
        )
        if assign and not re.search(
            r"[=!<>]=", stripped[max(0, assign.end() - 3) : assign.end() + 2]
        ):
            return re.sub(r"\s+", "", assign.group("lhs"))
        inc = re.search(
            r"\b(?P<lhs>g_[A-Za-z_]\w*(?:\s*(?:->|\.)\s*[A-Za-z_]\w*)?)\s*(?:\+\+|--)", stripped
        )
        return re.sub(r"\s+", "", inc.group("lhs")) if inc else ""

    @staticmethod
    def _global_state_family(lhs: str) -> str:
        text = re.sub(r"\s+", "", str(lhs or ""))
        tail = text.split("->")[-1].split(".")[-1]
        for token in ("watermark", "rules", "map", "mode", "state", "len", "length", "size"):
            if token in tail.lower() or token in text.lower():
                if token in {"len", "length", "size", "map"}:
                    base = re.sub(r"_(?:map|len|length|size|bytes|count|num)$", "", text)
                    return base or text
                return token
        return re.sub(r"_(?:ptr|map|len|length|size|bytes|count|num)$", "", text)

    @staticmethod
    def _is_global_pointer_length_publication(
        family_writes: Sequence[Tuple[ClangCfgLine, str, bool]],
    ) -> bool:
        if len(family_writes) < 2 or any(locked for _line, _lhs, locked in family_writes):
            return False
        names = {lhs.lower() for _line, lhs, _locked in family_writes}
        has_pointer = any(re.search(r"(?:map|ptr|addr|base|buffer|window)", name) for name in names)
        has_length = any(re.search(r"(?:len|length|size|bytes|count|num)", name) for name in names)
        return has_pointer and has_length

    def _maybe_emit_fd_encoding_mismatch(
        self,
        issues: List[Dict[str, Any]],
        func_name: str,
        file_path: str,
        lines: Sequence[ClangCfgLine],
        allowed_skills: Optional[Set[str]],
        line: ClangCfgLine,
    ) -> None:
        validate = re.search(
            r"\b(?P<api>[A-Za-z_]\w*validate_encoded_fd)\s*\(\s*(?P<arg>[A-Za-z_]\w*)\s*\)",
            line.text,
        )
        if not validate:
            return
        arg = validate.group("arg")
        raw_line = None
        for item in reversed(lines[max(0, line.index - 8) : line.index + 1]):
            if re.search(
                rf"\b(?:int\s+)?{re.escape(arg)}\s*=\s*[A-Za-z_]\w*\s*(?:[+%-]|$)", item.text
            ):
                raw_line = item
                break
        if raw_line is None and re.search(r"\braw_[A-Za-z_0-9]*fd\b", arg):
            raw_line = line
        if raw_line is None:
            return
        if re.search(r"ENCODE|CHECK_VALUE|encode_fd", raw_line.text, re.I):
            return
        audit_only = self._encoded_fd_validation_result_is_not_security_sink(lines, line)
        self._emit(
            issues,
            func_name,
            file_path,
            lines,
            allowed_skills,
            defect_class="fd_encoding_mismatch",
            rule="clang_cfg_raw_fd_revalidated_as_encoded",
            line=raw_line,
            description="原始的 fd 运算随后被当作经过编码/带校验值的 fd 来进行校验。",
            root_cause="在原始 fd 值到达编码 fd 校验之前，编码/校验位并没有被构造出来。",
            suggested_fix="在调用编码 fd 校验器之前，用期望的校验值对原始 fd 进行编码。",
            source=raw_line.text,
            sink=line.text,
            confidence=0.86,
            impact_level="high",
            positive=[
                f"line {raw_line.number}: raw fd value is derived without encoding bits",
                f"line {line.number}: `{validate.group('api')}` validates `{arg}` as an encoded fd",
            ],
            negative=(
                [
                    "The encoded-fd validation result is not visibly consumed by a security-sensitive sink in this local body.",
                    "Keep as an audit observation unless a caller uses the return value to authorize a dangerous operation.",
                ]
                if audit_only
                else []
            ),
            ast_cfg=self._ast_cfg_pack(
                lines,
                [
                    self._event("raw_fd_derive", raw_line, arg, "", raw_line.text),
                    self._event("encoded_fd_validate", line, arg, validate.group("api"), line.text),
                ],
                [raw_line.number, line.number],
            ),
            validation_required=not audit_only,
            finding_kind="audit_observation" if audit_only else "clang_ast_cfg_candidate",
            audit_observation_reason=(
                "原始 fd/编码 fd 语义不匹配，且在本地 CFG 中没有可见的安全相关汇点"
                if audit_only
                else ""
            ),
        )

    def _maybe_emit_global_state_not_restored_on_error(
        self,
        issues: List[Dict[str, Any]],
        func_name: str,
        file_path: str,
        lines: Sequence[ClangCfgLine],
        allowed_skills: Optional[Set[str]],
        line: ClangCfgLine,
    ) -> None:
        assign = re.search(
            r"\b(?P<state>g_[A-Za-z_0-9.]*state[A-Za-z_0-9.]*)\s*=\s*(?P<value>[^;]+);",
            line.text,
        )
        if not assign:
            return
        state = assign.group("state")
        previous = next(
            (
                item
                for item in reversed(lines[max(0, line.index - 6) : line.index])
                if re.search(
                    rf"\b(?P<prev>[A-Za-z_]\w*)\s*=\s*{re.escape(state)}\s*;",
                    item.text,
                )
            ),
            None,
        )
        previous_var = ""
        if previous:
            previous_match = re.search(
                rf"\b(?P<prev>[A-Za-z_]\w*)\s*=\s*{re.escape(state)}\s*;",
                previous.text,
            )
            previous_var = previous_match.group("prev") if previous_match else ""
        later = lines[line.index + 1 : line.index + 12]
        error_return = next(
            (item for item in later if re.search(r"\breturn\s+-1\s*;", item.text)), None
        )
        if not error_return:
            return
        branch_window = "\n".join(
            item.text for item in later[: max(1, error_return.index - line.index)]
        )
        if not re.search(
            self._literal_api_pattern(
                r"\b(?:fcntl|ioctl|setsockopt|getsockopt|validate|verify|check)\s*\("
            ),
            branch_window,
        ):
            return
        if previous_var:
            restore_before_error = any(
                item.index < error_return.index
                and re.search(
                    rf"\b{re.escape(state)}\s*=\s*{re.escape(previous_var)}\s*;", item.text
                )
                for item in later
            )
            if restore_before_error:
                return
        self._emit(
            issues,
            func_name,
            file_path,
            lines,
            allowed_skills,
            defect_class="state_inconsistency",
            rule="clang_cfg_global_state_not_restored_on_error",
            line=line,
            description=f"`{state}` 在返回错误且未恢复之前值之前被修改。",
            root_cause="失败的 syscall 或校验路径可能使共享的本地注册表状态停留在某个临时值上。",
            suggested_fix="在每条返回错误的失败路径上，恢复此前保存的状态。",
            source=line.text,
            sink=error_return.text,
            confidence=0.82,
            impact_level="high",
            positive=[
                f"line {line.number}: shared state `{state}` is overwritten",
                f"line {error_return.number}: error return is reachable after the syscall/validation check",
                "no restore of the saved previous state is visible before the error return",
            ],
            negative=[
                "Validator must confirm the state value is observable outside this function."
            ],
            ast_cfg=self._ast_cfg_pack(
                lines,
                [
                    *(
                        [
                            self._event(
                                "state_snapshot", previous, state, previous_var, previous.text
                            )
                        ]
                        if previous
                        else []
                    ),
                    self._event("state_overwrite", line, state, "", line.text),
                    self._event(
                        "error_return_without_restore", error_return, state, "", error_return.text
                    ),
                ],
                [line.number, error_return.number],
            ),
        )

    def _maybe_emit_ignored_protocol_version(
        self,
        issues: List[Dict[str, Any]],
        func_name: str,
        file_path: str,
        lines: Sequence[ClangCfgLine],
        allowed_skills: Optional[Set[str]],
        line: ClangCfgLine,
    ) -> None:
        parse = re.search(
            r"\b(?:uint(?:8|16|32)_t|unsigned\s+char|int)\s+"
            r"(?P<var>[A-Za-z_]\w*)\s*=\s*"
            r"(?P<src>[A-Za-z_]\w*)\s*\[[^]]+\]\s*;",
            line.text,
            re.IGNORECASE,
        )
        if not parse:
            return
        var = parse.group("var")
        if not re.search(r"(?:version|ver)", var, re.IGNORECASE):
            return
        later = lines[line.index + 1 : line.index + 12]
        ignored = next(
            (
                item
                for item in later
                if re.search(rf"\(\s*void\s*\)\s*{re.escape(var)}\s*;", item.text)
            ),
            None,
        )
        if not ignored:
            return
        comparison_window = "\n".join(
            item.text for item in later[: max(1, ignored.index - line.index)]
        )
        if re.search(rf"\b{re.escape(var)}\b\s*(?:==|!=|<|>|<=|>=)", comparison_window):
            return
        self._emit(
            issues,
            func_name,
            file_path,
            lines,
            allowed_skills,
            defect_class="version_filtering",
            rule="clang_cfg_parsed_protocol_version_is_ignored",
            line=line,
            description=f"协议版本 `{var}` 从消息中被解析出来，随后却被显式忽略。",
            root_cause="来自不受支持或低版本对等端的消息，可以在没有版本门控的情况下仅通过状态校验。",
            suggested_fix="在处理状态字段之前，将解析出的版本与受支持的协议集合进行校验。",
            source=line.text,
            sink=ignored.text,
            confidence=0.86,
            impact_level="high",
            positive=[
                f"line {line.number}: protocol version `{var}` is parsed from the report",
                f"line {ignored.number}: `{var}` is marked unused instead of checked",
                "no version comparison is visible before the ignored-version marker",
            ],
            negative=[
                "Validator must confirm whether caller-side version filtering cannot cover this parser."
            ],
            ast_cfg=self._ast_cfg_pack(
                lines,
                [
                    self._event("protocol_version_parse", line, var, parse.group("src"), line.text),
                    self._event("protocol_version_ignored", ignored, var, "", ignored.text),
                ],
                [line.number, ignored.number],
            ),
        )

    def _maybe_emit_recv_retry_without_budget(
        self,
        issues: List[Dict[str, Any]],
        func_name: str,
        file_path: str,
        lines: Sequence[ClangCfgLine],
        allowed_skills: Optional[Set[str]],
        line: ClangCfgLine,
    ) -> None:
        if not re.search(r"\bwhile\s*\([^)]*<[^)]*\)", line.text):
            return
        window = lines[line.index : line.index + 16]
        text = "\n".join(item.text for item in window)
        if not re.search(self._semantic_api_pattern(r"\b(?:recv|read)\s*\("), text):
            return
        if not re.search(r"\bcontinue\s*;", text):
            return
        status = re.search(
            self._semantic_api_pattern(r"\b(?P<result>[A-Za-z_]\w*)\s*=\s*(?:recv|read)\s*\("), text
        )
        if status is None or not re.search(
            rf"\bif\s*\(\s*{re.escape(status['result'])}\s*(?:<=\s*0|<\s*0|==\s*-1)\s*\)\s*\{{?\s*continue\s*;",
            text,
        ):
            return
        if re.search(self._literal_api_pattern(r"\b(?:sleep|usleep|poll|select)\s*\("), text):
            return
        retry_line = self._first_line_matching_in(window, re.compile(r"\bcontinue\s*;")) or line
        self._emit(
            issues,
            func_name,
            file_path,
            lines,
            allowed_skills,
            defect_class="busy_loop",
            rule="clang_cfg_recv_retry_loop_without_timeout_or_budget",
            line=line,
            description="接收返回非正值的路径直接继续循环，需验证是否存在无进展重试。",
            root_cause="接收失败或无数据路径可能重复，而循环进度变量尚未更新。",
            suggested_fix="添加重试预算、截止时间、poll/select 等待，或将瞬时失败向上传播给调用方。",
            source=retry_line.text,
            sink=line.text,
            confidence=0.86,
            impact_level="high",
            positive=[
                f"line {line.number}: receive loop waits for progress",
                f"line {retry_line.number}: non-progress receive status reaches continue",
            ],
            negative=[
                "Validator must resolve termination, retry bounds and blocking behavior on this branch."
            ],
            ast_cfg=self._ast_cfg_pack(
                lines,
                [
                    self._event("receive_loop", line, "recv", "", line.text),
                    self._event(
                        "transient_retry", retry_line, status["result"], "", retry_line.text
                    ),
                ],
                [line.number, retry_line.number],
            ),
        )

    def _maybe_emit_unchecked_insert_handoff(
        self,
        issues: List[Dict[str, Any]],
        func_name: str,
        file_path: str,
        lines: Sequence[ClangCfgLine],
        allowed_skills: Optional[Set[str]],
        line: ClangCfgLine,
    ) -> None:
        if "=" in line.text.split("(", 1)[0] or re.search(r"\b(?:if|while|for)\s*\(", line.text):
            return
        for api, args in self._calls(line.text):
            split = self._split_args(args)
            if not split:
                continue
            owners = {
                event.object
                for event in self.semantics.contracts.match_call(api, "ownership_transfer", split)
                if event.applicability != "does_not_apply"
            }
            owner = next(iter(owners)) if len(owners) == 1 else ""
            if not owner:
                continue
            previous = lines[max(0, line.index - 12) : line.index]
            alloc_line = next(
                (
                    item
                    for item in reversed(previous)
                    if re.search(
                        self._semantic_api_pattern(
                            rf"\b{re.escape(owner)}\s*=\s*(?:\([^)]*\)\s*)?"
                            r"(?:malloc|calloc|realloc|strdup)\s*\("
                        ),
                        item.text,
                        re.IGNORECASE,
                    )
                ),
                None,
            )
            if not alloc_line:
                continue
            later = "\n".join(item.text for item in lines[line.index + 1 : line.index + 8])
            if re.search(
                self._semantic_api_pattern(rf"\b(?:free)\s*\(\s*{re.escape(owner)}\s*\)"), later
            ):
                continue
            self._emit(
                issues,
                func_name,
                file_path,
                lines,
                allowed_skills,
                defect_class="memory_leak",
                rule="clang_cfg_unchecked_insert_after_ownership_handoff",
                line=line,
                description=f"所有权/链接辅助函数 `{api}` 的返回值在 `{owner}` 被分配之后被忽略。",
                root_cause="如果该辅助函数先链接了对象随后又报告失败，调用方就会丢失该已分配节点的清理/错误状态所有权。",
                suggested_fix="检查 insert/link 的返回值，要么回滚已链接的节点，要么明确定义所有权转移契约。",
                source=f"{owner} allocated at line {alloc_line.number}",
                sink=line.text,
                confidence=0.8,
                impact_level="high",
                positive=[
                    f"line {alloc_line.number}: `{owner}` is allocated before the handoff",
                    f"line {line.number}: `{api}` is called as a standalone statement and its return value is ignored",
                    "no immediate rollback/free is visible after the handoff call",
                ],
                negative=[
                    "Validator must inspect the callee contract to confirm whether failure can occur after linking."
                ],
                ast_cfg=self._ast_cfg_pack(
                    lines,
                    [
                        self._event("owner_alloc", alloc_line, owner, "", alloc_line.text),
                        self._event("unchecked_handoff", line, owner, api, line.text),
                    ],
                    [alloc_line.number, line.number],
                ),
            )
            return

    def _maybe_emit_protocol_length_copy_without_packet_bound(
        self,
        issues: List[Dict[str, Any]],
        func_name: str,
        file_path: str,
        lines: Sequence[ClangCfgLine],
        allowed_skills: Optional[Set[str]],
        line: ClangCfgLine,
    ) -> None:
        match = re.search(
            r"\b(?:size_t|uint(?:32|64)_t|int)\s+(?P<len>[A-Za-z_]\w*(?:len|length|size)[A-Za-z_0-9]*)\s*="
            r"\s*(?:\([^)]*\)\s*)?\(?\s*(?P<src>[A-Za-z_]\w*)\s*(?:\*|<<)\s*[^;]+;",
            line.text,
            re.IGNORECASE,
        )
        if not match:
            return
        len_var = match.group("len")
        source_var = match.group("src")
        previous = "\n".join(item.text for item in lines[max(0, line.index - 8) : line.index + 1])
        if not re.search(
            rf"\b{re.escape(source_var)}\s*=\s*(?:packet|frame|wire|blob)\s*\[", previous
        ):
            return
        later_lines = lines[line.index + 1 : line.index + 10]
        copy_line = next(
            (
                item
                for item in later_lines
                if self._copy_uses_length(item.text, len_var)
                and re.search(r"\b(?:packet|frame|wire|blob)\s*\+", item.text)
            ),
            None,
        )
        if not copy_line:
            return
        guard_window = "\n".join(
            item.text for item in lines[max(0, copy_line.index - 8) : copy_line.index]
        )
        if re.search(
            rf"\b{re.escape(len_var)}\b\s*[<>]=?\s*[^;]*(?:packet_len|frame_len|wire_len|blob_len|remaining)",
            guard_window,
        ):
            return
        self._emit(
            issues,
            func_name,
            file_path,
            lines,
            allowed_skills,
            defect_class="bounds",
            rule="clang_cfg_protocol_units_length_reaches_copy_without_packet_bound",
            line=line,
            description=f"协议推导出的长度 `{len_var}` 到达从数据包进行的复制，却没有被接收到的数据包长度所约束。",
            root_cause="代码只检查了目标容量；并未证明源帧包含推导出的字节数。",
            suggested_fix="将推导出的复制长度同时与目标容量和剩余输入数据包字节进行校验。",
            source=line.text,
            sink=copy_line.text,
            confidence=0.84,
            impact_level="high",
            positive=[
                f"line {line.number}: `{len_var}` is derived from a packet-controlled unit count",
                f"line {copy_line.number}: `{len_var}` controls a packet copy",
                "nearby guards do not bound the copy length by packet_len/frame_len/remaining bytes",
            ],
            negative=[],
            ast_cfg=self._ast_cfg_pack(
                lines,
                [
                    self._event("protocol_length_derive", line, len_var, source_var, line.text),
                    self._event("packet_copy", copy_line, len_var, "", copy_line.text),
                ],
                [line.number, copy_line.number],
            ),
        )

    def _maybe_emit_header_length_copy_without_wire_bound(
        self,
        issues: List[Dict[str, Any]],
        func_name: str,
        file_path: str,
        lines: Sequence[ClangCfgLine],
        allowed_skills: Optional[Set[str]],
        line: ClangCfgLine,
    ) -> None:
        assign = re.search(
            r"\b(?:size_t|uint(?:32|64)_t|int)\s+(?P<len>[A-Za-z_]\w*(?:len|length|size)[A-Za-z_0-9]*)\s*="
            r"\s*(?:\([^)]*\)\s*)?(?P<header>[A-Za-z_]\w*)\s*\.\s*(?:len|length|size)\s*-\s*sizeof\s*\(",
            line.text,
            re.IGNORECASE,
        )
        if not assign:
            return
        len_var = assign.group("len")
        header_var = assign.group("header")
        prior = "\n".join(item.text for item in lines[max(0, line.index - 10) : line.index])
        if not re.search(
            self._literal_api_pattern(rf"\bmemcpy\s*\(\s*&\s*{re.escape(header_var)}\s*,"), prior
        ):
            return
        later = lines[line.index + 1 : line.index + 12]
        copy_line = next(
            (item for item in later if self._copy_uses_length(item.text, len_var)), None
        )
        if copy_line is None:
            return
        guard_window = "\n".join(
            item.text for item in lines[max(0, copy_line.index - 8) : copy_line.index]
        )
        if re.search(
            rf"\b{re.escape(len_var)}\b\s*(?:<=|<)\s*(?:wire_len|packet_len|frame_len|payload_len|remaining)",
            guard_window,
        ):
            return
        self._emit(
            issues,
            func_name,
            file_path,
            lines,
            allowed_skills,
            defect_class="bounds",
            rule="clang_cfg_header_length_reaches_copy_without_wire_bound",
            line=copy_line,
            description=f"头部长度 `{len_var}` 到达一个复制点，却没有被输入的线缆长度所约束。",
            root_cause="校验头部魔数并不能证明声明的主体长度确实存在于接收到的缓冲区中。",
            suggested_fix="在复制之前，将声明的主体长度与剩余线缆长度进行校验。",
            source=line.text,
            sink=copy_line.text,
            confidence=0.84,
            impact_level="high",
            positive=[
                f"line {line.number}: `{len_var}` is derived from `{header_var}.length`",
                f"line {copy_line.number}: `{len_var}` controls a copy sink",
            ],
            negative=[
                "Validator must confirm no earlier full-frame length guard dominates the copy."
            ],
            ast_cfg=self._ast_cfg_pack(
                lines,
                [
                    self._event("header_length", line, len_var, header_var, line.text),
                    self._event("header_length_copy", copy_line, len_var, "", copy_line.text),
                ],
                [line.number, copy_line.number],
            ),
        )

    def _maybe_emit_probe_error_returns_success(
        self,
        issues: List[Dict[str, Any]],
        func_name: str,
        file_path: str,
        lines: Sequence[ClangCfgLine],
        allowed_skills: Optional[Set[str]],
        line: ClangCfgLine,
        idx: int,
    ) -> None:
        cond = re.search(
            r"\bif\s*\(\s*(?P<status>[A-Za-z_]\w*)\s*!=\s*0\s*\|\|\s*(?P<flag>[A-Za-z_]\w*)\s*\)",
            line.text,
        )
        if not cond:
            return
        status = cond.group("status")
        previous = lines[max(0, idx - 8) : idx]
        recv_line = next(
            (
                item
                for item in reversed(previous)
                if re.search(
                    self._semantic_api_pattern(
                        rf"\b{re.escape(status)}\s*=\s*(?:recv|read|recvfrom)\s*\("
                    ),
                    item.text,
                )
            ),
            None,
        )
        if not recv_line:
            return
        branch = lines[idx + 1 : idx + 8]
        return_line = next(
            (
                item
                for item in branch
                if re.search(rf"\breturn\s+{re.escape(status)}\s*;", item.text)
            ),
            None,
        )
        if not return_line:
            return
        self._emit(
            issues,
            func_name,
            file_path,
            lines,
            allowed_skills,
            defect_class="unchecked_return",
            rule="clang_cfg_probe_error_branch_can_return_success_status",
            line=line,
            description=f"探测失败分支返回 `{status}`，当 `{cond.group('flag')}` 触发了该分支时，`{status}` 仍可能为零。",
            root_cause="该分支把状态码失败与分类器失败混为一谈，并返回传输状态而不是显式错误。",
            suggested_fix="当分类器标志指示失败时返回负数/错误码，即便接收调用本身返回了成功。",
            source=recv_line.text,
            sink=return_line.text,
            confidence=0.82,
            impact_level="high",
            positive=[
                f"line {recv_line.number}: `{status}` receives a receive/probe API status",
                f"line {line.number}: branch also fires on classifier flag `{cond.group('flag')}`",
                f"line {return_line.number}: branch returns `{status}` rather than a definite error",
            ],
            negative=[],
            ast_cfg=self._ast_cfg_pack(
                lines,
                [
                    self._event("probe_status", recv_line, status, "", recv_line.text),
                    self._event(
                        "probe_error_condition", line, status, cond.group("flag"), line.text
                    ),
                    self._event(
                        "success_possible_return", return_line, status, "", return_line.text
                    ),
                ],
                [recv_line.number, line.number, return_line.number],
            ),
        )

    def _maybe_emit_format_string(
        self,
        issues: List[Dict[str, Any]],
        func_name: str,
        file_path: str,
        lines: Sequence[ClangCfgLine],
        allowed_skills: Optional[Set[str]],
        line: ClangCfgLine,
    ) -> None:
        api = ""
        arg = ""
        from ....semantics.call_operands import call_operands, is_literal_string

        for operand in call_operands(
            self.semantics.contracts, line.text, "format_sink", file_path=file_path
        ):
            candidate = operand.expression
            if is_literal_string(candidate):
                continue
            api = operand.name
            arg = candidate
            break
        if not arg:
            return
        if self._is_format_forwarding_wrapper(func_name, lines, arg):
            return
        self._emit(
            issues,
            func_name,
            file_path,
            lines,
            allowed_skills,
            defect_class="format_string",
            rule="clang_cfg_nonliteral_format_string",
            line=line,
            description=f"`{arg}` 被用作 printf 风格的格式字符串。",
            root_cause="攻击者可控文本中的百分号序列可能被解释为格式指令。",
            suggested_fix=f'使用如 `printf("%s", {arg})` 一样的字面量格式。',
            source=arg,
            sink=line.text,
            confidence=0.88,
            impact_level="high",
            positive=[f"line {line.number}: published contract selects non-literal format operand"],
            negative=[],
            ast_cfg=self._ast_cfg_pack(
                lines, [self._event("format_sink", line, arg, api, line.text)], [line.number]
            ),
        )

    def _maybe_emit_command_injection(
        self,
        issues: List[Dict[str, Any]],
        func_name: str,
        file_path: str,
        lines: Sequence[ClangCfgLine],
        allowed_skills: Optional[Set[str]],
        line: ClangCfgLine,
        env_vars: Dict[str, ClangCfgLine],
    ) -> None:
        getenv = re.search(
            self._literal_api_pattern(
                r"\b(?:const\s+char\s*\*\s*)?(?P<var>[A-Za-z_]\w*)\s*=\s*getenv\s*\("
            ),
            line.text,
        )
        if getenv:
            env_vars[getenv.group("var")] = line

        from ....semantics.call_operands import call_operands, is_literal_string

        command = next(
            (
                operand
                for operand in call_operands(
                    self.semantics.contracts,
                    line.text,
                    "command_sink",
                    file_path=file_path,
                )
                if not is_literal_string(operand.expression)
            ),
            None,
        )
        if command is not None:
            arg = command.expression
            api = command.name
            self._emit(
                issues,
                func_name,
                file_path,
                lines,
                allowed_skills,
                defect_class="command_injection",
                rule="clang_cfg_system_with_nonliteral_command",
                line=line,
                description=f"`{api}` 使用了非字面量的命令参数 `{arg}`。",
                root_cause="shell 命令文本是在进程内构造的，可能携带用户或环境可控的令牌。",
                suggested_fix="避免使用 `system`；直接向 execve/posix_spawn 传递 argv 并校验每个参数。",
                source=arg,
                sink=line.text,
                confidence=0.84,
                impact_level="critical",
                positive=[f"line {line.number}: `{api}` consumes non-literal `{arg}`"],
                negative=[
                    "Validator must trace whether the command buffer is attacker-controlled."
                ],
                ast_cfg=self._ast_cfg_pack(
                    lines,
                    [self._event("command_sink", line, arg, api, line.text)],
                    [line.number],
                ),
            )
            return

        concat = re.search(
            self._literal_api_pattern(
                r"\bstrcat\s*\(\s*(?P<dst>[A-Za-z_]\w*)\s*,\s*(?P<src>[A-Za-z_]\w*)\s*\)"
            ),
            line.text,
        )
        if not concat or concat.group("src") not in env_vars:
            return
        src = concat.group("src")
        dst = concat.group("dst")
        env_line = env_vars[src]
        later = "\n".join(item.text for item in lines[line.index + 1 : line.index + 8])
        if not re.search(rf"\breturn\s+{re.escape(dst)}\s*;", later):
            return
        self._emit(
            issues,
            func_name,
            file_path,
            lines,
            allowed_skills,
            defect_class="command_injection",
            rule="clang_cfg_shell_command_concat_env",
            line=line,
            description=f"来自环境的 `{src}` 被拼接到命令缓冲区 `{dst}` 中并被返回。",
            root_cause="环境文本可能把 shell 元字符引入到稍后由 shell 执行的命令中。",
            suggested_fix="不要将环境文本拼接到 shell 命令中；构建一个 argv 向量或校验/转义参数。",
            source=f"getenv at line {env_line.number}",
            sink=line.text,
            confidence=0.82,
            impact_level="critical",
            positive=[
                f"line {env_line.number}: `{src}` receives `getenv(...)`",
                f"line {line.number}: `{src}` is appended to `{dst}` with `strcat`",
                f"`{dst}` is returned by the command-builder function nearby",
            ],
            negative=["Validator must confirm the returned buffer reaches a shell execution sink."],
            ast_cfg=self._ast_cfg_pack(
                lines,
                [
                    self._event("environment_source", env_line, src, "getenv", env_line.text),
                    self._event("command_concat", line, dst, "strcat", line.text),
                ],
                [env_line.number, line.number],
            ),
        )

    def _maybe_emit_file_type_validation_order(
        self,
        issues: List[Dict[str, Any]],
        func_name: str,
        file_path: str,
        lines: Sequence[ClangCfgLine],
        allowed_skills: Optional[Set[str]],
        line: ClangCfgLine,
    ) -> None:
        if not self._is_file_type_check(line.text):
            return
        prior = lines[max(0, line.index - 28) : line.index]
        stat_line = self._last_line_matching(
            prior,
            re.compile(
                self._literal_api_pattern(r"\b(?:fstat|stat|lstat|fstatat)\s*\("), re.IGNORECASE
            ),
        )
        size_or_map_line = self._last_line_matching(
            lines[
                (
                    (stat_line.index + 1) if stat_line is not None else max(0, line.index - 28)
                ) : line.index
            ],
            re.compile(
                r"\b(?:mmap|MapViewOfFile|st_size|file_size|map_size|mapping_size|length|len|size)\b.*(?:<|>|==|!=|<=|>=)",
                re.IGNORECASE,
            ),
        )
        if size_or_map_line is None:
            return
        earlier_start = (stat_line.index + 1) if stat_line is not None else max(0, line.index - 28)
        if any(
            self._is_file_type_check(item.text)
            for item in lines[earlier_start : size_or_map_line.index]
        ):
            return
        metadata_line = stat_line or (lines[0] if lines else size_or_map_line)
        self._emit(
            issues,
            func_name,
            file_path,
            lines,
            allowed_skills,
            defect_class="file_type_validation",
            rule="clang_cfg_file_type_validation_after_mapping_size_check",
            line=line,
            description="文件尺寸或映射校验发生在文件类型被校验之前。",
            root_cause=(
                "本地路径在证明描述符确实指向可接受的常规/设备文件类型之前，"
                "就先依据映射尺寸进行了推理。"
            ),
            suggested_fix="在 stat/fstat 之后、做出尺寸或 mmap 决策之前，立即校验文件类型/模式。",
            source=size_or_map_line.text,
            sink=line.text,
            confidence=0.72,
            positive=[
                f"line {metadata_line.number}: file mode/size metadata is available",
                f"line {size_or_map_line.number}: mapping/size decision uses metadata before type validation",
                f"line {line.number}: file type is checked only later",
            ],
            negative=[
                "Validator must confirm the earlier mapping/size decision can affect security before the type check."
            ],
            ast_cfg=self._ast_cfg_pack(
                lines,
                [
                    self._event(
                        "file_metadata", metadata_line, "", "stat_or_params", metadata_line.text
                    ),
                    self._event(
                        "mapping_size_decision", size_or_map_line, "", "", size_or_map_line.text
                    ),
                    self._event("late_file_type_validation", line, "", "", line.text),
                ],
                [metadata_line.number, size_or_map_line.number, line.number],
            ),
        )

    def _encoded_fd_validation_result_is_not_security_sink(
        self,
        lines: Sequence[ClangCfgLine],
        line: ClangCfgLine,
    ) -> bool:
        validate = re.search(
            r"\b(?P<api>[A-Za-z_]\w*validate_encoded_fd)\s*\(\s*(?P<arg>[A-Za-z_]\w*)\s*\)",
            line.text,
        )
        if not validate:
            return False
        arg = validate.group("arg")
        window = "\n".join(item.text for item in lines[line.index : line.index + 10])
        dangerous_use = re.search(
            self._literal_api_pattern(
                rf"\b(?:read|recv|write|send|close|dup|fcntl|ioctl|mmap|munmap)\s*"
                rf"\([^;]*\b{re.escape(arg)}\b"
            ),
            window,
        )
        if dangerous_use:
            return False
        return True

    def _is_format_forwarding_wrapper(
        self,
        func_name: str,
        lines: Sequence[ClangCfgLine],
        fmt_arg: str,
    ) -> bool:
        if "[" in fmt_arg or not re.fullmatch(r"[A-Za-z_]\w*", fmt_arg):
            return False
        text = "\n".join(line.text for line in lines)
        signature = lines[0].text if lines else ""
        name_hint = bool(
            re.search(
                r"(?:log|printf|format|trace|debug|warn|error).*wrapper|wrapper", func_name, re.I
            )
        )
        varargs_signature = "..." in signature or re.search(
            self._literal_api_pattern(rf"\bva_start\s*\([^,]+,\s*{re.escape(fmt_arg)}\s*\)"), text
        )
        forwards_to_va_sink = re.search(
            self._literal_api_pattern(rf"\bv(?:f)?printf\s*\([^;]*\b{re.escape(fmt_arg)}\b[^;]*\)"),
            text,
        ) or re.search(
            self._literal_api_pattern(rf"\bvfprintf\s*\([^;]*\b{re.escape(fmt_arg)}\b[^;]*\)"),
            text,
        )
        return bool((name_hint or varargs_signature) and varargs_signature and forwards_to_va_sink)

    def _is_path_check(self, text: str) -> bool:
        return bool(
            _trusted_path_state_query(self, text)
            or (
                not self.restrict_to_semantics
                and re.search(
                    r"\b[A-Za-z_]\w*(?:check|validate|verify)[A-Za-z_0-9]*(?:permission|access|path|file)[A-Za-z_0-9]*\s*\(",
                    text,
                    re.IGNORECASE,
                )
            )
        )

    @staticmethod
    def _is_file_type_check(text: str) -> bool:
        return bool(
            re.search(r"\bS_IS(?:REG|CHR|BLK|FIFO|SOCK|LNK)\s*\(", text)
            or re.search(r"\b[A-Z_]*IS_(?:REG|CHR|BLK|FIFO|SOCK|LNK)\s*\(", text)
            or re.search(r"\bst_mode\b\s*&\s*S_IF(?:REG|CHR|BLK|FIFO|SOCK|LNK)", text)
            or re.search(
                r"\b(?:file|fd|descriptor)_[A-Za-z_0-9]*(?:type|mode)\b", text, re.IGNORECASE
            )
            or re.search(
                r"\b(?:is|validate|check)[A-Za-z_0-9]*(?:regular|character|device|file_type|fd_type)\b",
                text,
                re.IGNORECASE,
            )
        )

    @staticmethod
    def _is_string_literal(expr: str) -> bool:
        return bool(re.match(r'^\s*(?:L|u8|u|U)?".*"\s*$', str(expr or "")))
