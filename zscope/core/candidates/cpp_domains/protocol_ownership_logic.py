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
            assign = re.search(r"\b(?P<var>[A-Za-z_]\w*)\s*=\s*strchr\s*\(", line.text)
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
                        description=f"`{var}` from strchr is used without a visible NULL check.",
                        root_cause="strchr can return NULL when the delimiter is absent.",
                        suggested_fix=f"Check `{var}` for NULL before pointer arithmetic or dereference.",
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
                    description=f"Length field `{src_expr}` reaches a copy/IO sink without a visible buffer-bound guard.",
                    root_cause="A serialized or structured length field is trusted without proving the backing buffer contains that many bytes.",
                    suggested_fix="Validate the length against the remaining input buffer or destination capacity before copying.",
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

            fmt = re.search(
                r"\b(?:printf|fprintf|syslog)\s*\(\s*(?P<arg>[A-Za-z_]\w*)\s*\)", line.text
            )
            if fmt:
                emit(
                    defect_class="format_string",
                    rule="nonliteral_format_string",
                    line=line,
                    description=f"`{fmt.group('arg')}` is used as a printf-style format string.",
                    root_cause="Attacker-controlled percent sequences can be interpreted as format directives.",
                    suggested_fix=f"Use `printf(\"%s\", {fmt.group('arg')})` or an equivalent literal format.",
                    source=fmt.group("arg"),
                    sink=line.text.strip(),
                    confidence=0.86,
                    impact_level="high",
                    positive=[f"line {line.number}: non-literal printf-style format"],
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
                        description=f"`{fn_name}` is called while a lock is already held; lookup-style helpers often have their own lock contract.",
                        root_cause="A helper can recursively acquire the same lock or invert lock ownership if its locking contract is not no-lock/locked.",
                        suggested_fix="Use a no-lock helper for locked callers, document lock ownership, or release before calling.",
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
                        description=f"`{fn_name}` is called while a lock is already held and appears to acquire a lock itself.",
                        root_cause="A lookup/helper routine can recursively acquire the same lock or invert lock ownership.",
                        suggested_fix="Use a no-lock helper for locked callers, document lock ownership, or release before calling.",
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

            if re.search(r"\b(?:access|stat|lstat|faccessat|fstatat)\s*\(", line.text) or re.search(
                r"\b[A-Za-z_]\w*(?:check|validate|verify)[A-Za-z_0-9]*(?:permission|access|path|file)[A-Za-z_0-9]*\s*\(",
                line.text,
                re.IGNORECASE,
            ):
                permission_check_line = line
            if permission_check_line and re.search(r"\b(?:open|fopen|creat)\s*\(", line.text):
                emit(
                    defect_class="toctou",
                    rule="path_check_before_open",
                    line=line,
                    description="A pathname is checked separately from a later open/use operation.",
                    root_cause="The path can change between the check and the open operation.",
                    suggested_fix="Open the file first with secure flags, then validate/use the opened descriptor.",
                    source=f"path check at line {permission_check_line.number}",
                    sink=line.text.strip(),
                    confidence=0.76,
                    positive=[
                        f"line {permission_check_line.number}: pathname check",
                        f"line {line.number}: separate pathname open/use",
                    ],
                )
                permission_check_line = None

            system_call = re.search(r"\bsystem\s*\(\s*(?P<arg>[A-Za-z_]\w*)\s*\)", line.text)
            if system_call:
                emit(
                    defect_class="command_injection",
                    rule="system_with_constructed_command",
                    line=line,
                    description=f"`{system_call.group('arg')}` is passed to system.",
                    root_cause="Constructed command text can contain shell metacharacters or environment-derived content.",
                    suggested_fix="Avoid system; pass argv directly to execve/posix_spawn and validate each argument.",
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
            if not re.search(r"\b(?:recv|read|_net_recv_data)\s*\(", window):
                continue
            if re.search(r"\b(?:sleep|usleep|nanosleep|poll|select|break)\b", window):
                continue
            if re.search(r"\bif\s*\([^)]*(?:rc|ret|got|received)\s*<=\s*0", window) and re.search(
                r"\bcontinue\s*;", window
            ):
                emit(
                    defect_class="busy_loop",
                    rule="recv_retry_without_backoff",
                    line=line,
                    description="Receive loop retries immediately when the IO call returns no progress.",
                    root_cause="The loop does not break, sleep, poll, or apply a retry limit on repeated transient failures.",
                    suggested_fix="Add a bounded retry policy with timeout/backoff and handle permanent errors.",
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
                    r"\b(?:memcpy|memmove|_net_send_data|_net_recv_data)\s*\(", later
                ) and re.search(r"\b(?:packet|wire|blob|frame|payload)_?len\b", text):
                    if not re.search(
                        r"(?:packet|wire|blob|frame|payload)_?len\s*[-+*/<>]=?", later
                    ):
                        emit(
                            defect_class="bounds",
                            rule="derived_protocol_length_reaches_copy_without_input_bound",
                            line=line,
                            description="A derived protocol length reaches a copy without proving the input buffer contains that many bytes.",
                            root_cause="The destination bound is checked, but the source packet length is not tied to the derived copy length.",
                            suggested_fix="Validate derived length against both source packet remaining bytes and destination capacity.",
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
            if re.search(rf"\b(?:memcpy|memmove)\s*\([^;]*\b{re.escape(len_var)}\b", later):
                emit(
                    defect_class="bounds",
                    rule="header_length_subtraction_reaches_copy",
                    line=line,
                    description=f"Serialized length `{len_var}` is derived by subtraction and reaches a copy.",
                    root_cause="Header length can underflow or exceed the received wire buffer without a remaining-length guard.",
                    suggested_fix="Check header.length >= header size and header.length <= wire_len before copying.",
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
                    f"Decoded control/discriminator field `{discarded}` is explicitly "
                    f"ignored while sibling field `{sibling_name}` drives validation."
                ),
                root_cause=(
                    "One input-record discriminator/version field has no comparison, "
                    "switch, or range filter although a sibling decoded field is checked."
                ),
                suggested_fix=(
                    "Validate every decoded control/discriminator field against the "
                    "supported protocol contract before processing sibling state."
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
            "LOG_ERROR" in text
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
                    description="Error/probe path can fall through to a success return.",
                    root_cause="The function logs or returns a low-level status in one branch but treats other failed/ambiguous probe states as success.",
                    suggested_fix="Normalize low-level return codes and explicitly fail ambiguous probe results.",
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
                description="Global state is changed before an error path without a visible restore.",
                root_cause="A failed syscall or validation path can leave shared state set to a transient value.",
                suggested_fix="Restore the previous state on every failure path before returning.",
                source=state_assign.text.strip(),
                sink="error return before restore",
                confidence=0.72,
                impact_level="high",
                positive=[
                    f"line {state_assign.number}: shared state assignment",
                    "function has an error return and no assignment restoring `previous`",
                ],
            )

        unchecked_insert = self._first_line_matching(
            lines,
            re.compile(r"\b[A-Za-z_]\w*(?:insert|Insert)[A-Za-z_0-9]*\s*\([^;]+\)\s*;"),
        )
        if unchecked_insert and re.search(
            r"\b(?:node|entry|item|record)\b", unchecked_insert.text, re.I
        ):
            prior_alloc = any(
                self._alloc_re.search(item.text) or self._calloc_re.search(item.text)
                for item in lines[max(0, unchecked_insert.index - 8) : unchecked_insert.index]
            )
            if prior_alloc and not re.search(
                r"\b(?:if|rc|ret|status)\b.*insert", unchecked_insert.text, re.I
            ):
                emit(
                    defect_class="memory_leak",
                    rule="unchecked_insert_after_ownership_handoff",
                    line=unchecked_insert,
                    description="Ownership-sensitive insert return value is ignored after allocating/linking a node.",
                    root_cause="If the insert helper links state before returning failure, the caller loses a reliable cleanup decision point.",
                    suggested_fix="Check the insert return value and define whether ownership transfers on every failure mode.",
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
                r"\bstrncpy\s*\([^;]*,\s*[A-Za-z_]\w*(?:key|name)[A-Za-z_0-9]*\s*,\s*\d+\s*\)", re.I
            ),
        )
        if trunc and re.search(r"\[[^\]]+\]\s*=\s*'\\0'", text):
            emit(
                defect_class="key_truncation",
                rule="truncated_key_used_for_route_insert",
                line=trunc,
                description="Route/key insertion truncates the full key before storing it.",
                root_cause="Lookup and insert can use different key widths, allowing collisions or wrong route selection.",
                suggested_fix="Reject overlong keys or store/compare the same full key representation consistently.",
                source=trunc.text.strip(),
                sink="truncated key stored in route node",
                confidence=0.8,
                impact_level="high",
                positive=[f"line {trunc.number}: bounded strncpy truncates a key before insertion"],
            )

        write_line = self._first_line_matching(lines, re.compile(r"\bwrite\s*\("))
        if write_line and "SIGPIPE" not in text and "MSG_NOSIGNAL" not in text:
            emit(
                defect_class="sigpipe_unhandled",
                rule="write_without_sigpipe_handling",
                line=write_line,
                description="Peer write is issued without visible SIGPIPE suppression or handling.",
                root_cause="A closed peer can raise SIGPIPE and terminate the process or bypass normal error handling.",
                suggested_fix="Use send(..., MSG_NOSIGNAL), ignore/handle SIGPIPE, or use platform-specific no-signal flags.",
                source=write_line.text.strip(),
                sink="closed peer write",
                confidence=0.74,
                impact_level="high",
                positive=[f"line {write_line.number}: write to peer fd without SIGPIPE handling"],
            )

        for idx, line in enumerate(lines):
            alloc = re.search(
                r"\b(?P<owner>[A-Za-z_]\w*(?:->[A-Za-z_]\w*)?)\s*=\s*(?:\([^)]*\)\s*)?"
                r"(?P<alloc>[A-Za-z_]\w*(?:alloc|dup|create|new)[A-Za-z_0-9]*)\s*\(",
                line.text,
                re.IGNORECASE,
            )
            if not alloc:
                continue
            owner = alloc.group("owner")
            later_lines = lines[idx + 1 : idx + 18]
            release_re = re.compile(rf"\b(?:SAFE_FREE|free)\s*\(\s*{re.escape(owner)}\s*\)")
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
                    description=f"`{owner}` is allocated before an error return that does not release it.",
                    root_cause="A later failure path returns before cleanup for the allocated owner.",
                    suggested_fix="Release the allocation on the error path or jump to a shared cleanup label.",
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
                    rf"\b(?:SAFE_FREE|free)\s*\(\s*{re.escape(base)}\s*\)", later
                ) and not release_re.search(later):
                    emit(
                        defect_class="memory_leak",
                        rule="member_allocation_not_released_with_parent",
                        line=line,
                        description=f"Member allocation `{owner}` is not released before `{base}` is freed.",
                        root_cause="Freeing the parent object does not release separately allocated child/member storage.",
                        suggested_fix="Release owned members before freeing the parent object.",
                        source=line.text.strip(),
                        sink=f"free parent `{base}`",
                        confidence=0.8,
                        impact_level="high",
                        positive=[
                            f"line {line.number}: member allocation `{owner}`",
                            f"later path frees parent `{base}` without freeing the member",
                        ],
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
                description=f"Borrowed pointer `{ret}` is returned after the protecting lock is released.",
                root_cause="Concurrent mutation can free or replace the pointee after unlock and before caller use.",
                suggested_fix="Return an owned copy or keep a reference under the lock before unlocking.",
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
                        description=f"`{obj}->next` is set to `{obj}`, creating a self-referential list node.",
                        root_cause=(
                            "Later traversal, or a concurrent walker that retained the node before unlink, "
                            "can follow the poisoned next pointer back to the same node forever."
                        ),
                        suggested_fix="Use NULL or a non-traversable poison value and ensure later walkers detect removed nodes.",
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
                    description="A traversal over poisoned or parked nodes emits logs inside the loop.",
                    root_cause="A liveness failure can keep traversal progress on the same element while the loop emits repeated logs.",
                    suggested_fix="Break traversal on poison/park markers and rate-limit or suppress loop-internal error logs.",
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

        if re.search(r"\bstrncpy\s*\([^;]*(?:KEY_LIMIT|KEY_MAX|MAX_KEY|LIMIT)", text) and re.search(
            r"full_key|strcmp|find_[A-Za-z_0-9]*key",
            text,
        ):
            line = self._first_line_matching(view, re.compile(r"\bstrncpy\s*\(")) or view.lines[0]
            issues.append(
                self._issue(
                    defect_class="key_truncation",
                    rule="full_key_lookup_truncated_insert",
                    view=view,
                    line=line,
                    description="The lookup path uses a full key while insertion stores only a bounded/truncated key.",
                    root_cause="Lookup and insertion normalize keys differently, so distinct full keys can collide or evade lookups.",
                    suggested_fix="Use the same canonical key representation for lookup and insertion and reject overlong keys explicitly.",
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
            and not re.search(r"(?:remove|unlink|delete).*node", text, re.I)
        ):
            line = self._first_line_matching(view, node_free_re) or view.lines[0]
            issues.append(
                self._issue(
                    defect_class="use_after_free",
                    rule="insert_failure_leaves_stale_tree_node",
                    view=view,
                    line=line,
                    description="A node can be inserted into an index/tree before a later failure frees it without removing stale links.",
                    root_cause="Failure cleanup releases the node but does not roll back index/list ownership established earlier.",
                    suggested_fix="Rollback every successful insertion/link before freeing the node on later failure paths.",
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
                    description="A counter derived from one runtime domain is passed into a callback/scheduler contract from another domain.",
                    root_cause="The call path preserves type compatibility but loses the semantic unit expected by the callee contract.",
                    suggested_fix="Pass the callee's expected domain value explicitly or rename/split the counters so unit mismatches are rejected at the boundary.",
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

        endian_line = self._first_line_matching(view, re.compile(r"__builtin_ctz(?:ll)?\s*\("))
        if (
            endian_line
            and re.search(r"\bmemcpy\s*\(\s*&[A-Za-z_]\w+\s*,\s*[^;]*input\s*\+", text)
            and not re.search(r"\b(?:be(?:16|32|64)toh|ntoh(?:s|l)|bswap|__builtin_bswap)", text)
        ):
            issues.append(
                self._issue(
                    defect_class="byte_order_logic",
                    rule="wire_bitmap_ctz_without_endian_normalization",
                    view=view,
                    line=endian_line,
                    description="Wire bytes are copied into host integers and scanned with ctz without endian normalization.",
                    root_cause="The bit index returned by trailing-zero operations is host-order dependent and can point at the wrong wire byte on big-endian data.",
                    suggested_fix="Normalize byte order before bit scans or scan the wire byte array in protocol order.",
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
            and not re.search(r"\b(?:pthread_mutex_lock|LOCK|spin_lock)\s*\(", text)
        ):
            issues.append(
                self._issue(
                    defect_class="reader_state_race",
                    rule="single_reader_field_under_shared_reader_count",
                    view=view,
                    line=reader_line,
                    description="A shared reader-owner field is written while a shared reader count allows multiple readers.",
                    root_cause="Atomic count updates protect the count value, but not the side field that stores one reader identity.",
                    suggested_fix="Use per-reader state, protect the identity field with the rwlock writer protocol, or remove the single-owner field.",
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
                    description="A protocol mismatch can be accepted when the authentication mode is not strict.",
                    root_cause=(
                        "The protocol boundary detects an unexpected protocol value but a non-strict "
                        "auth branch still returns success, allowing messages to cross protocol contexts."
                    ),
                    suggested_fix="Reject protocol mismatches before auth relaxation, or require strict authentication for cross-protocol routing.",
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
                r"\bmem(?:cpy|move)\s*\([^;]*\b[A-Za-z_]\w*\.name\s*,\s*[A-Za-z_]\w+\s*,\s*strlen\s*\(",
                re.I,
            ),
        )
        if stack_line and re.search(r"\bsnprintf\s*\([^;]*%s", text):
            issues.append(
                self._issue(
                    defect_class="stack_overflow",
                    rule="composed_string_copied_to_member_buffer_without_bound",
                    view=view,
                    line=stack_line,
                    description="A variable-length composed string is copied into a fixed member buffer using strlen length.",
                    root_cause="The formatting buffer is bounded, but the destination member's smaller fixed size is not used as the copy limit.",
                    suggested_fix="Copy with the destination member size and reject or truncate names before composing the thread label.",
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
                    description="Mapping validation applies regular-file size semantics before distinguishing character-device backings.",
                    root_cause="Character-device/shared-memory mappings do not have the same file-size contract as regular files.",
                    suggested_fix="Branch on backing type first and apply type-specific size validation before mapping.",
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
                description="An encoded/reliable descriptor is passed to a lower-level API that expects a raw descriptor.",
                root_cause="The descriptor representation contract is lost because both representations are integer-like values.",
                suggested_fix="Decode/strip check bits before calling raw-fd helpers, or change the callee to accept the encoded descriptor type.",
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
                rf"\b(?:SAFE_FREE|free|destroy|release|cleanup|delete)[A-Za-z_0-9]*\s*\([^;]*\b{re.escape(var)}\b",
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
                    description="An allocated object is handed to an insert/register-style ownership API while the API return is ignored.",
                    root_cause=(
                        "The transfer helper may fail after linking or partially accepting the object; "
                        "because the caller ignores the return and has no cleanup path, ownership and registry state can be lost."
                    ),
                    suggested_fix="Check the transfer API return value and roll back or destroy the allocated object on failure.",
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

    @staticmethod
    def _local_allocated_variables(view: FunctionView) -> Dict[str, GraphLine]:
        allocs: Dict[str, GraphLine] = {}
        for line in view.lines:
            match = re.search(
                r"\b(?P<var>[A-Za-z_]\w*)\s*=\s*(?:\([^)]*\)\s*)?"
                r"(?:_safe_calloc|_safe_malloc|calloc|malloc|kzalloc|kmalloc|[A-Za-z_]\w*(?:alloc|create|new)[A-Za-z_0-9]*)\s*\(",
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
                r"\b(?:strcmp|strncmp|memcmp)\s*\(", "\n".join(line.text for line in view.lines)
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
                    r"\b(?P<api>strncpy|strlcpy|snprintf|memcpy)\s*\([^;]*"
                    r"(?P<limit>[A-Z][A-Z0-9_]*(?:KEY|KEYS)[A-Z0-9_]*(?:LIMIT|MAX|LEN|SIZE)|"
                    r"[A-Z][A-Z0-9_]*(?:LIMIT|MAX|LEN|SIZE)[A-Z0-9_]*KEY[A-Z0-9_]*)",
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
                        lookup, re.compile(r"\b(?:strcmp|strncmp|memcmp)\s*\(")
                    )
                    or lookup.lines[0]
                )
                issues.append(
                    self._issue(
                        defect_class="key_truncation",
                        rule="paired_full_key_lookup_truncated_insert",
                        view=view,
                        line=line,
                        description="A full-key lookup path is paired with an insertion path that stores a bounded/truncated key.",
                        root_cause="Lookup and insertion use different key canonicalization, allowing overlong keys to collide or evade lookup.",
                        suggested_fix="Canonicalize keys once, reject overlong keys, and use the same stored representation for lookup and insert.",
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
                        description="A traversal that logs inside the loop can revisit a self-referential node produced by a sibling path.",
                        root_cause="Self-linking a node keeps traversal progress on the same element, and loop-internal logging amplifies the liveness failure.",
                        suggested_fix="Use a non-traversable poison marker or NULL, break on poisoned/self-linked nodes, and rate-limit loop logs.",
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
                    description=f"Length field `{src_expr}` reaches a copy sink without a visible backing-buffer length guard.",
                    root_cause="A serialized or structured length field is trusted without proving the input buffer contains that many bytes.",
                    suggested_fix="Validate the field against the remaining input length before copying or indexing.",
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
            self._maybe_emit_unchecked_strchr_result(
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
            elif permission_check_line and re.search(r"\b(?:open|fopen|creat)\s*\(", text):
                self._emit(
                    issues,
                    func_name,
                    file_path,
                    lines,
                    allowed_skills,
                    defect_class="toctou",
                    rule="clang_cfg_path_check_before_open",
                    line=line,
                    description="A pathname is checked separately from a later open/use operation.",
                    root_cause="The path can change between the permission/existence check and the later open.",
                    suggested_fix="Open the file first with secure flags, then validate the opened descriptor.",
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
        if not (released == "node" or released.startswith("node->")):
            return
        body = "\n".join(item.text for item in lines)
        if "children" in body:
            return
        prefix = lines[: line.index]
        insert_line = self._last_line_matching(
            prefix, re.compile(r"\b[A-Za-z_]\w*insert_locked\s*\(\s*node\s*\)")
        )
        unlink_line = self._last_line_matching(
            prefix,
            re.compile(r"\bg_[A-Za-z_0-9.]*registry[A-Za-z_0-9.]*\.head\s*=\s*node->next\s*;"),
        )
        unlock_line = self._last_line_matching(
            prefix, re.compile(r"\bUNLOCK\s*\([^)]*registry[^)]*\)")
        )
        lock_line = self._last_line_matching(prefix, re.compile(r"\bLOCK\s*\([^)]*registry[^)]*\)"))
        if not (insert_line and unlink_line and unlock_line and lock_line):
            return
        if not (
            lock_line.index < insert_line.index < unlink_line.index < unlock_line.index < line.index
        ):
            return
        for item in lines[unlock_line.index + 1 : line.index]:
            prior_release = self._match_release(item.text)
            if not prior_release:
                continue
            prior_arg = self._resource_expr(prior_release[1]) or self._resource_var(
                prior_release[1]
            )
            if prior_arg == "node" or prior_arg.startswith("node->"):
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
            description="A shared registry node is unlinked under the registry lock but freed after the lock is released.",
            root_cause="Concurrent readers can retain a borrowed pointer from the registry while cleanup drops the lock and releases the node members.",
            suggested_fix="Hold the lifetime lock through the full removal/free protocol or add reference-counted handoff before freeing the node.",
            source=unlink_line.text,
            sink=line.text,
            confidence=0.82,
            impact_level="critical",
            positive=[
                f"line {insert_line.number}: node is inserted into shared registry state",
                f"line {unlink_line.number}: registry head is advanced to unlink `node`",
                f"line {unlock_line.number}: registry lock is released before cleanup",
                f"line {line.number}: node-owned storage is freed after the unlock window",
            ],
            negative=[
                "Validator must confirm whether registry readers can retain borrowed node pointers across this unlock window."
            ],
            ast_cfg=self._ast_cfg_pack(
                lines,
                [
                    self._event("registry_insert", insert_line, "node", "", insert_line.text),
                    self._event("registry_unlink", unlink_line, "node", "", unlink_line.text),
                    self._event("registry_unlock", unlock_line, "registry", "", unlock_line.text),
                    self._event("post_unlock_release", line, released, "", line.text),
                ],
                [insert_line.number, unlink_line.number, unlock_line.number, line.number],
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
                r"\bstrcmp\s*\([^;]*(?:pipe|segment|shm|shared|product)", line.text, re.IGNORECASE
            ):
                special_name_branch = line

        if mode_assignment is None or request_check is None:
            return
        if re.search(
            r"\b(?:chmod|fchmod|open|creat|shm_open|mmap)\s*\([^;]*(?:requested|request|desired|required)[A-Za-z_0-9]*(?:perm|permission|mode)\b",
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
            description="Requested file/shared-memory permission is compared against a hard-coded mode but is not applied to the backing object.",
            root_cause="The code treats permission as a local validation flag while the actual backing mode remains fixed.",
            suggested_fix="Derive the open/chmod/mmap mode from the validated request or reject unsupported requests before publishing the resource.",
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
            if not (self._is_owned_member_name(member) or self._looks_like_owned_member_rhs(rhs)):
                continue
            if re.fullmatch(r"(?:NULL|nullptr|0)", rhs):
                continue
            return item, member, rhs
        return None

    @staticmethod
    def _is_owned_member_name(member: str) -> bool:
        return bool(
            re.search(
                r"(?:child|children|proc_head|head$|_head$|list$|_list$|items$|_items$|entries$|_entries$)",
                str(member or ""),
                re.IGNORECASE,
            )
        )

    @staticmethod
    def _looks_like_owned_member_rhs(rhs: str) -> bool:
        return bool(
            re.search(
                r"\b[A-Za-z_]\w*(?:alloc|calloc|malloc|dup|new|create|clone|open)[A-Za-z_0-9]*\s*\(",
                str(rhs or ""),
                re.IGNORECASE,
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
                rf"\b(?:free|SAFE_FREE|safe_free|_safe_free)\s*\([^;]*{member_expr}", item.text
            ):
                return True
        return False

    def _find_missing_common_owned_member_cleanup(
        self,
        lines: Sequence[ClangCfgLine],
        release_line: ClangCfgLine,
        parent: str,
    ) -> Optional[Tuple[ClangCfgLine, str]]:
        create_line = next(
            (
                item
                for item in reversed(lines[max(0, release_line.index - 40) : release_line.index])
                if re.search(
                    rf"\b{re.escape(parent)}\s*=\s*(?:\([^)]*\)\s*)?"
                    r"[A-Za-z_]\w*(?:alloc|calloc|malloc|new|create)[A-Za-z_0-9]*\s*\(",
                    item.text,
                    re.IGNORECASE,
                )
            ),
            None,
        )
        if create_line is None:
            return None
        region = "\n".join(item.text for item in lines[create_line.index + 1 : release_line.index])
        common_members = ("payload", "context", "ctx", "tag", "buffer", "data", "value")
        for member in common_members:
            member_expr = rf"{re.escape(parent)}\s*->\s*{member}"
            if re.search(member_expr, region) and not re.search(
                rf"\b(?:free|SAFE_FREE|safe_free|_safe_free|destroy|release)[A-Za-z_0-9]*\s*\([^;]*{member_expr}",
                region,
                re.IGNORECASE,
            ):
                return create_line, member
        if re.search(r"_alloc_node|create_node|new_node", create_line.text, re.IGNORECASE):
            for member in ("payload", "tag", "value"):
                if not re.search(
                    rf"\b(?:free|SAFE_FREE|safe_free|_safe_free|destroy|release)[A-Za-z_0-9]*\s*\([^;]*{re.escape(parent)}\s*->\s*{member}",
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
        if not re.search(
            r"(?:delete|remove|destroy|free|cleanup|unregister|release)",
            effective_name,
            re.IGNORECASE,
        ):
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
            description="Raw fd arithmetic is later validated as if it were an encoded/check-value fd.",
            root_cause="The encoding/check bits are not constructed before the raw fd value reaches encoded-fd validation.",
            suggested_fix="Encode raw fds with the expected check value before calling encoded-fd validators.",
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
                "raw fd/encoded fd semantic mismatch has no visible security sink in the local CFG"
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
            r"\b(?:fcntl|ioctl|setsockopt|getsockopt|validate|verify|check)\s*\(", branch_window
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
            description=f"`{state}` is changed before an error path that returns without restoring the previous value.",
            root_cause="A failed syscall or validation path can leave shared local registry state set to a transient value.",
            suggested_fix="Restore the saved previous state on every failure path before returning an error.",
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
            description=f"Protocol version `{var}` is parsed from the message and then explicitly ignored.",
            root_cause="Messages from unsupported or low-version peers can pass state-only validation without a version gate.",
            suggested_fix="Validate the parsed version against the supported protocol set before processing state fields.",
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
        if not re.search(r"\b(?:recv|read|_net_recv_data)\s*\(", text):
            return
        if not re.search(r"\bEAGAIN\b", text) or not re.search(r"\bEINTR\b", text):
            return
        if not re.search(r"\bcontinue\s*;", text):
            return
        if re.search(
            r"\b(?:timeout|deadline|retry|budget|max_attempt|sleep|usleep|poll|select)\b",
            text,
            re.IGNORECASE,
        ):
            return
        retry_line = (
            self._first_line_matching_in(window, re.compile(r"\bEAGAIN\b|\bEINTR\b")) or line
        )
        self._emit(
            issues,
            func_name,
            file_path,
            lines,
            allowed_skills,
            defect_class="busy_loop",
            rule="clang_cfg_recv_retry_loop_without_timeout_or_budget",
            line=line,
            description="Receive loop retries transient errors without a timeout, retry budget, or backoff.",
            root_cause="EAGAIN/EINTR paths can repeat forever and the outer loop continues on non-progressing reads.",
            suggested_fix="Add a retry budget, deadline, poll/select wait, or propagate transient failures to the caller.",
            source=retry_line.text,
            sink=line.text,
            confidence=0.86,
            impact_level="high",
            positive=[
                f"line {line.number}: receive loop waits for progress",
                f"line {retry_line.number}: transient EAGAIN/EINTR retry is visible",
                "no timeout, retry budget, or backoff is visible in the loop window",
            ],
            negative=[],
            ast_cfg=self._ast_cfg_pack(
                lines,
                [
                    self._event("receive_loop", line, "recv", "", line.text),
                    self._event("transient_retry", retry_line, "EAGAIN/EINTR", "", retry_line.text),
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
            if not re.search(r"(?:insert|link|attach|register|publish|add)", api, re.IGNORECASE):
                continue
            split = self._split_args(args)
            if not split:
                continue
            owner = self._resource_var(split[0])
            if not owner:
                continue
            previous = lines[max(0, line.index - 12) : line.index]
            alloc_line = next(
                (
                    item
                    for item in reversed(previous)
                    if re.search(
                        rf"\b{re.escape(owner)}\s*=\s*(?:\([^)]*\)\s*)?"
                        r"[A-Za-z_]\w*(?:alloc|calloc|malloc|new)[A-Za-z_0-9]*\s*\(",
                        item.text,
                        re.IGNORECASE,
                    )
                ),
                None,
            )
            if not alloc_line:
                continue
            later = "\n".join(item.text for item in lines[line.index + 1 : line.index + 8])
            if re.search(rf"\b(?:free|SAFE_FREE)\s*\(\s*{re.escape(owner)}\s*\)", later):
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
                description=f"Return value from ownership/linking helper `{api}` is ignored after `{owner}` is allocated.",
                root_cause="If the helper links the object and then reports failure, the caller loses cleanup/error-state ownership for the allocated node.",
                suggested_fix="Check the insert/link return value and either roll back the linked node or define a clear ownership transfer contract.",
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
            description=f"Protocol-derived length `{len_var}` reaches a copy from the packet without being bounded by the received packet length.",
            root_cause="The code checks only destination capacity; it does not prove the source frame contains the derived number of bytes.",
            suggested_fix="Check the derived copy length against both destination capacity and remaining input packet bytes.",
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
        if not re.search(rf"\bmemcpy\s*\(\s*&\s*{re.escape(header_var)}\s*,", prior):
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
            description=f"Header length `{len_var}` reaches a copy without being bounded by the input wire length.",
            root_cause="Validating a header magic does not prove the declared body length is present in the received buffer.",
            suggested_fix="Check declared body length against the remaining wire length before copying.",
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
                    rf"\b{re.escape(status)}\s*=\s*(?:recv|read|recvfrom|_net_recv_data)\s*\(",
                    item.text,
                )
            ),
            None,
        )
        if not recv_line:
            return
        branch = lines[idx + 1 : idx + 8]
        log_line = next((item for item in branch if "LOG_ERROR" in item.text), None)
        return_line = next(
            (
                item
                for item in branch
                if re.search(rf"\breturn\s+{re.escape(status)}\s*;", item.text)
            ),
            None,
        )
        if not log_line or not return_line:
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
            description=f"Probe failure branch logs an error but returns `{status}`, which can still be zero when `{cond.group('flag')}` caused the branch.",
            root_cause="The branch conflates status-code failure with classifier failure and returns the transport status instead of an explicit error.",
            suggested_fix="Return a negative/error code when the classifier flag indicates failure, even if the receive call itself returned success.",
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
        for call_api, args in self._calls(line.text):
            if call_api not in self._format_sink_names:
                continue
            split_args = self._split_args(args)
            arg_index = 1 if call_api in {"fprintf", "vfprintf"} else 0
            if len(split_args) <= arg_index:
                continue
            candidate = split_args[arg_index].strip()
            if self._is_string_literal(candidate):
                continue
            if not re.match(r"^[A-Za-z_]\w*(?:\[[^]]+\])?$", candidate):
                continue
            api = call_api
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
            description=f"`{arg}` is used as a printf-style format string.",
            root_cause="Percent sequences in attacker-controlled text can be interpreted as format directives.",
            suggested_fix=f'Use a literal format such as `printf("%s", {arg})`.',
            source=arg,
            sink=line.text,
            confidence=0.88,
            impact_level="high",
            positive=[
                f"line {line.number}: printf-style call uses non-literal first format argument"
            ],
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
            r"\b(?:const\s+char\s*\*\s*)?(?P<var>[A-Za-z_]\w*)\s*=\s*getenv\s*\(", line.text
        )
        if getenv:
            env_vars[getenv.group("var")] = line

        system_call = re.search(r"\bsystem\s*\(\s*(?P<arg>[A-Za-z_]\w*)\s*\)", line.text)
        if system_call:
            arg = system_call.group("arg")
            self._emit(
                issues,
                func_name,
                file_path,
                lines,
                allowed_skills,
                defect_class="command_injection",
                rule="clang_cfg_system_with_nonliteral_command",
                line=line,
                description=f"`system` executes non-literal command buffer `{arg}`.",
                root_cause="Shell command text is constructed in process and can carry user or environment-controlled tokens.",
                suggested_fix="Avoid `system`; pass argv directly to execve/posix_spawn and validate each argument.",
                source=arg,
                sink=line.text,
                confidence=0.84,
                impact_level="critical",
                positive=[f"line {line.number}: `system` executes non-literal `{arg}`"],
                negative=[
                    "Validator must trace whether the command buffer is attacker-controlled."
                ],
                ast_cfg=self._ast_cfg_pack(
                    lines,
                    [self._event("system_call", line, arg, "system", line.text)],
                    [line.number],
                ),
            )
            return

        concat = re.search(
            r"\bstrcat\s*\(\s*(?P<dst>[A-Za-z_]\w*)\s*,\s*(?P<src>[A-Za-z_]\w*)\s*\)",
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
            description=f"Environment-derived `{src}` is concatenated into command buffer `{dst}` and returned.",
            root_cause="Environment text can introduce shell metacharacters into a command later executed by a shell.",
            suggested_fix="Do not concatenate environment text into shell commands; build an argv vector or validate/escape arguments.",
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
            re.compile(r"\b(?:fstat|stat|lstat|fstatat)\s*\(", re.IGNORECASE),
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
            description="File size or mapping validation occurs before the file type is validated.",
            root_cause=(
                "The local path reasons about mapping size before proving the descriptor refers "
                "to an acceptable regular/device file type."
            ),
            suggested_fix="Validate the file type/mode immediately after stat/fstat and before size or mmap decisions.",
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
            rf"\b(?:read|recv|write|send|close|dup|fcntl|ioctl|mmap|munmap|_net_[A-Za-z_0-9]+)\s*"
            rf"\([^;]*\b{re.escape(arg)}\b",
            window,
        )
        if dangerous_use:
            return False
        return True

    @staticmethod
    def _is_format_forwarding_wrapper(
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
            rf"\bva_start\s*\([^,]+,\s*{re.escape(fmt_arg)}\s*\)", text
        )
        forwards_to_va_sink = re.search(
            rf"\bv(?:f)?printf\s*\([^;]*\b{re.escape(fmt_arg)}\b[^;]*\)",
            text,
        ) or re.search(
            rf"\bvfprintf\s*\([^;]*\b{re.escape(fmt_arg)}\b[^;]*\)",
            text,
        )
        return bool((name_hint or varargs_signature) and varargs_signature and forwards_to_va_sink)

    @staticmethod
    def _is_path_check(text: str) -> bool:
        return bool(
            re.search(r"\b(?:access|stat|lstat|faccessat|fstatat)\s*\(", text)
            or re.search(
                r"\b[A-Za-z_]\w*(?:check|validate|verify)[A-Za-z_0-9]*(?:permission|access|path|file)[A-Za-z_0-9]*\s*\(",
                text,
                re.IGNORECASE,
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
