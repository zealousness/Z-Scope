# mypy: disable-error-code="attr-defined"
"""Memory safety, bounds, pointer, and integer detector implementations."""

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
        10,
        "memory_bounds_integer",
        "allocation_size_overflow",
        "_rule_allocation_size_overflow",
        ("lines", "emit"),
    ),
    DetectorStage(
        "regex",
        "function",
        40,
        "memory_bounds_integer",
        "double_and_invalid_free",
        "_rule_double_and_invalid_free",
        ("lines", "emit"),
    ),
    DetectorStage(
        "regex",
        "function",
        50,
        "memory_bounds_integer",
        "stack_escape",
        "_rule_stack_escape",
        ("lines", "emit"),
        covers=("protocol_ownership_logic",),
    ),
    DetectorStage(
        "regex",
        "function",
        80,
        "memory_bounds_integer",
        "signed_unsigned",
        "_rule_signed_unsigned",
        ("lines", "emit"),
    ),
    DetectorStage(
        "regex",
        "function",
        90,
        "memory_bounds_integer",
        "bounds_and_uninitialized",
        "_rule_bounds_and_uninit",
        ("lines", "emit"),
    ),
    DetectorStage(
        "clang_ast_cfg",
        "function",
        30,
        "memory_bounds_integer",
        "common_sast_single_pass",
        "_run_common_sast_rules",
        ("issues", "func_name", "file_path", "lines", "allowed_skills"),
        covers=(
            "resource_lifecycle",
            "concurrency_shared_state",
            "protocol_ownership_logic",
        ),
    ),
)


class RegexMemoryBoundsIntegerRules:
    def _rule_allocation_size_overflow(self, lines: List[CodeLine], emit) -> None:
        params = self._function_params(lines)
        arithmetic_defs: Dict[str, Tuple[CodeLine, str, List[str]]] = {}
        for line in lines:
            clean = line.text
            assign = re.search(
                rf"\b(?:{self._size_type_pattern})\s+"
                r"(?P<var>[A-Za-z_]\w*)\s*=\s*(?P<expr>[^;]*[+*][^;]*);",
                clean,
            )
            if assign:
                expr = assign.group("expr").strip()
                operands = [
                    item
                    for item in self._IDENT_RE.findall(expr)
                    if item not in {"sizeof", "SIZE_MAX", "UINT_MAX"}
                ]
                arithmetic_defs[assign.group("var")] = (line, expr, operands)
                if (
                    self._next_window_has_sink(lines, line.index, assign.group("var"))
                    and not self._has_pre_overflow_guard(lines, line.index, operands)
                    and not self._has_post_wrap_check(
                        lines, line.index, assign.group("var"), operands
                    )
                    and self._is_high_risk_size_expr(expr, params)
                ):
                    emit(
                        defect_class="integer_overflow",
                        rule="arithmetic_size_before_sink",
                        line=line,
                        description=(
                            f"`{assign.group('var')}` is computed from `{expr}` before it is "
                            "used as a size/length argument; wraparound can shrink the allocation "
                            "or copy bound."
                        ),
                        root_cause="Size arithmetic is performed before proving operands are bounded.",
                        suggested_fix="Check operands before the arithmetic, or use a checked size helper.",
                        source=expr,
                        sink=f"{assign.group('var')} used by allocation/copy",
                        confidence=0.82,
                        positive=[
                            f"line {line.number}: arithmetic size expression `{expr}`",
                            "nearby allocation/copy consumes the computed size",
                        ],
                        negative=self._guard_evidence(lines, line.index, operands),
                    )

            alloc_call = self._match_call(clean, self._allocator_names, "expr")
            if alloc_call:
                expr = alloc_call.group("expr")
                if not re.search(r"[+*]", expr) or not self._is_high_risk_size_expr(expr, params):
                    continue
                identifiers = [
                    item
                    for item in self._IDENT_RE.findall(expr)
                    if item not in {"sizeof"} | self._allocator_names | self._reallocator_names
                ]
                if identifiers and not self._has_pre_overflow_guard(lines, line.index, identifiers):
                    emit(
                        defect_class="integer_overflow",
                        rule="inline_allocation_size_overflow",
                        line=line,
                        description="Allocation size is computed inline with unchecked addition/multiplication.",
                        root_cause="The allocation expression can wrap before the allocator sees it.",
                        suggested_fix="Validate operands before the allocation expression or use checked arithmetic.",
                        source=expr.strip(),
                        sink=clean.strip(),
                        confidence=0.84,
                        positive=[
                            f"line {line.number}: allocator call contains arithmetic `{expr.strip()}`",
                        ],
                        negative=self._guard_evidence(lines, line.index, identifiers),
                    )

        for line in lines:
            clean = line.text
            call = self._match_call(clean, self._calloc_names, "args", until=";")
            if not call:
                continue
            args = call.group("args")
            identifiers = [
                item
                for item in self._IDENT_RE.findall(args)
                if item not in {"calloc", "_safe_calloc", "sizeof", "NULL"}
            ]
            nearby = "\n".join(item.text for item in lines[max(0, line.index - 4) : line.index + 1])
            if (
                len(identifiers) >= 2
                and any(item in params for item in identifiers)
                and "_parse_arguments" not in nearby
                and not self._has_pre_overflow_guard(lines, line.index, identifiers)
            ):
                emit(
                    defect_class="integer_overflow",
                    rule="calloc_product_overflow",
                    line=line,
                    description="calloc-like allocation multiplies two caller-sized operands without a visible precheck.",
                    root_cause="The element count and size product may overflow before allocation.",
                    suggested_fix="Check `count <= SIZE_MAX / elem_size` before calloc or rely on a proven checked wrapper.",
                    source=args.strip(),
                    sink=clean.strip(),
                    confidence=0.67,
                    positive=[f"line {line.number}: calloc-like call `{clean.strip()}`"],
                    negative=self._guard_evidence(lines, line.index, identifiers),
                )

    def _rule_double_and_invalid_free(self, lines: List[CodeLine], emit) -> None:
        last_free: Dict[str, CodeLine] = {}
        pointer_owners = self._pointer_owner_vars(lines)
        for line in lines:
            free = self._match_call(line.text, self._deallocator_names, "arg")
            if not free:
                if re.search(r"\breturn\b", line.text):
                    last_free.clear()
                    continue
                for var in list(last_free):
                    if re.search(
                        rf"\b{re.escape(var)}\s*=\s*(?:NULL|0|{self._names_pattern(self._allocator_names | self._calloc_names)})",
                        line.text,
                    ):
                        last_free.pop(var, None)
                continue

            arg = free.group("arg").strip()
            if arg.startswith("&") or re.search(r"[+\-]\s*\d+", arg):
                emit(
                    defect_class="invalid_free",
                    rule="free_non_owner_pointer",
                    line=line,
                    description=f"`{arg}` is freed even though it is not the base owner pointer.",
                    root_cause="A deallocator receives an interior or stack-address expression.",
                    suggested_fix="Free only the owning base pointer returned by the allocator.",
                    source=arg,
                    sink=line.text.strip(),
                    confidence=0.84,
                    positive=[f"line {line.number}: frees non-owner expression `{arg}`"],
                )
                continue

            previous_expr = last_free.get(arg)
            if previous_expr and not re.match(r"^[A-Za-z_]\w*$", arg):
                emit(
                    defect_class="double_free",
                    rule="same_expression_freed_twice",
                    line=line,
                    description=f"`{arg}` is released twice on the same local path.",
                    root_cause="No reassignment or nulling of the owner expression is visible between releases.",
                    suggested_fix="Remove the duplicate release or clear ownership after the first release.",
                    source=arg,
                    sink=line.text.strip(),
                    confidence=0.84,
                    impact_level="high",
                    positive=[
                        f"line {previous_expr.number}: first release of `{arg}`",
                        f"line {line.number}: second release of `{arg}`",
                    ],
                )
            if not re.match(r"^[A-Za-z_]\w*$", arg):
                last_free[arg] = line
                continue

            var_match = re.match(r"([A-Za-z_]\w*)$", arg)
            if not var_match:
                continue
            var = var_match.group(1)
            if var not in pointer_owners:
                continue
            previous = last_free.get(var)
            if previous:
                emit(
                    defect_class="double_free",
                    rule="same_pointer_freed_twice",
                    line=line,
                    description=f"`{var}` is released twice on the same local path.",
                    root_cause="No reassignment or nulling of the owner is visible between releases.",
                    suggested_fix="Remove the duplicate release or set ownership to NULL after the first release.",
                    source=var,
                    sink=line.text.strip(),
                    confidence=0.88,
                    positive=[
                        f"line {previous.number}: first release of `{var}`",
                        f"line {line.number}: second release of `{var}`",
                    ],
                )
            last_free[var] = line

    def _rule_stack_escape(self, lines: List[CodeLine], emit) -> None:
        locals_seen = self._collect_local_vars(lines)
        for line in lines:
            create = re.search(r"\bpthread_create\s*\((?P<args>[^;]+)\)", line.text)
            if create:
                for var, decl in locals_seen.items():
                    if f"&{var}" in create.group("args") and decl.index < line.index:
                        emit(
                            defect_class="stack_escape",
                            rule="stack_address_to_thread",
                            line=line,
                            description=f"Address of stack local `{var}` is passed to a new thread.",
                            root_cause="The thread may outlive the stack frame that owns the argument.",
                            suggested_fix="Allocate a heap-owned argument or join before returning from the frame.",
                            source=f"&{var}",
                            sink=line.text.strip(),
                            confidence=0.87,
                            impact_level="high",
                            positive=[
                                f"line {decl.number}: local `{var}` is stack allocated",
                                f"line {line.number}: `{var}` address escapes through pthread_create",
                            ],
                        )
                continue
            retaining_call = self._retaining_address_call(line.text)
            if retaining_call:
                for var, decl in locals_seen.items():
                    if decl.index < line.index and re.search(rf"&\s*{re.escape(var)}\b", line.text):
                        emit(
                            defect_class="stack_escape",
                            rule="stack_address_to_retaining_api",
                            line=line,
                            description=f"Address of stack local `{var}` is passed to retaining/asynchronous API `{retaining_call}`.",
                            root_cause="The callee name indicates it may store, register, enqueue, or asynchronously use the borrowed address after this stack frame returns.",
                            suggested_fix="Pass heap-owned storage, copy the value into callee-owned storage, or prove the API consumes the address synchronously as an out-parameter.",
                            source=f"&{var}",
                            sink=line.text.strip(),
                            confidence=0.74,
                            impact_level="high",
                            positive=[
                                f"line {decl.number}: local `{var}` is stack allocated",
                                f"line {line.number}: `{var}` address is passed to retaining/asynchronous-looking API `{retaining_call}`",
                            ],
                            negative=[
                                "ordinary create/open/get functions with scalar out-parameters are treated as synchronous borrows unless their name indicates retention"
                            ],
                        )
            ret = re.search(r"\breturn\s+&(?P<var>[A-Za-z_]\w*)\s*;", line.text)
            if ret and ret.group("var") in locals_seen:
                decl = locals_seen[ret.group("var")]
                emit(
                    defect_class="stack_escape",
                    rule="return_stack_address",
                    line=line,
                    description=f"Function returns the address of stack local `{ret.group('var')}`.",
                    root_cause="Returned pointer refers to storage destroyed when the function returns.",
                    suggested_fix="Return owned heap storage or write into caller-provided storage.",
                    source=f"&{ret.group('var')}",
                    sink=line.text.strip(),
                    confidence=0.9,
                    impact_level="high",
                    positive=[
                        f"line {decl.number}: stack local declaration",
                        f"line {line.number}: address returned",
                    ],
                )

    @staticmethod
    def _retaining_address_call(text: str) -> str:
        match = re.search(r"\b(?P<name>[A-Za-z_]\w*(?:->|\.)?[A-Za-z_]\w*)\s*\(", text)
        if not match:
            return ""
        name = match.group("name").split("->")[-1].split(".")[-1]
        lower = name.lower()
        retaining_terms = (
            "register",
            "retain",
            "store",
            "save",
            "cache",
            "remember",
            "subscribe",
            "enqueue",
            "queue",
            "defer",
            "async",
            "thread",
            "schedule",
            "submit",
            "callback",
            "cb",
            "context",
            "ctx",
        )
        synchronous_out_param_terms = (
            "create",
            "open",
            "init",
            "get",
            "read",
            "write",
            "query",
            "find",
            "lookup",
            "parse",
            "decode",
        )
        if any(term in lower for term in retaining_terms):
            return name
        if any(term in lower for term in synchronous_out_param_terms):
            return ""
        return ""

    def _rule_signed_unsigned(self, lines: List[CodeLine], emit) -> None:
        signed_reads: Dict[str, CodeLine] = {}
        casts: Dict[str, Tuple[CodeLine, str]] = {}
        user_recv = self._names_pattern(getattr(self, "_user_recv_source_names", set()) or set())
        user_io_len = self._names_pattern(
            (getattr(self, "_user_send_sink_names", set()) or set())
            | (getattr(self, "_user_recv_source_names", set()) or set())
        )
        for line in lines:
            read = re.search(
                rf"\bint\s+(?P<var>[A-Za-z_]\w*)\s*=\s*(?:recv|read|_net_recv_data|{user_recv})\s*\(",
                line.text,
            )
            if read:
                signed_reads[read.group("var")] = line
            cast = re.search(
                r"\bsize_t\s+(?P<size>[A-Za-z_]\w*)\s*=\s*\(size_t\)\s*(?P<src>[A-Za-z_]\w*)\s*;",
                line.text,
            )
            if cast and cast.group("src") in signed_reads:
                casts[cast.group("size")] = (line, cast.group("src"))
            for size_var, (cast_line, src_var) in list(casts.items()):
                if re.search(
                    rf"\b(?:memcpy|memmove|_net_send_data|_net_recv_data|{user_io_len})\s*\([^;]*\b{re.escape(size_var)}\b",
                    line.text,
                ):
                    emit(
                        defect_class="signed_unsigned",
                        rule="negative_length_cast_to_size_t",
                        line=cast_line,
                        description=f"Signed length `{src_var}` is cast to size_t and later used as a copy/IO length.",
                        root_cause="Negative error values can become very large unsigned sizes.",
                        suggested_fix=f"Check `{src_var} >= 0` and upper bounds before casting to size_t.",
                        source=src_var,
                        sink=line.text.strip(),
                        confidence=0.86,
                        impact_level="high",
                        positive=[
                            f"line {signed_reads[src_var].number}: signed result from IO",
                            f"line {cast_line.number}: cast to size_t",
                            f"line {line.number}: unsigned length reaches copy/IO sink",
                        ],
                    )

    def _rule_bounds_and_uninit(self, lines: List[CodeLine], emit) -> None:
        struct_locals: Dict[str, Tuple[CodeLine, int, bool]] = {}
        unaligned_ptrs: Dict[str, CodeLine] = {}
        integer_ptr_type = (
            rf"(?:const\s+|volatile\s+|restrict\s+)*(?:{self._integer_pointer_type_pattern})"
            r"(?:\s+const|\s+volatile|\s+restrict)*"
        )
        for line in lines:
            off = re.search(
                r"\b(?P<array>[A-Za-z_]\w*)\s*\[\s*sizeof\s*\(\s*(?P=array)\s*\)\s*\]\s*=",
                line.text,
            )
            if off:
                emit(
                    defect_class="off_by_one",
                    rule="sizeof_index_write",
                    line=line,
                    description="Array write indexes `array[sizeof(array)]`, one element past the end.",
                    root_cause="sizeof(array) is the byte count and is outside the zero-based index range.",
                    suggested_fix="Use `sizeof(array) - 1` for the terminator or a length-aware helper.",
                    source=off.group("array"),
                    sink=line.text.strip(),
                    confidence=0.9,
                    impact_level="high",
                    positive=[f"line {line.number}: writes at sizeof(array) index"],
                )

            vla = re.search(
                rf"\b(?:{self._size_type_pattern})\s+(?P<var>[A-Za-z_]\w*)\s*\[\s*(?P<expr>[^]\d][^]]*)\s*\]\s*;",
                line.text,
            )
            if (
                vla
                and not self._is_macro_size_expr(vla.group("expr"))
                and re.search(r"[+*]|[A-Za-z_]\w*", vla.group("expr"))
            ):
                emit(
                    defect_class="stack_overflow",
                    rule="unbounded_vla_or_stack_array",
                    line=line,
                    description="Stack array size is derived from a runtime expression without a visible cap.",
                    root_cause="Caller-controlled or data-dependent stack allocation can exhaust the stack.",
                    suggested_fix="Cap the size before stack allocation or allocate bounded heap storage.",
                    source=vla.group("expr").strip(),
                    sink=line.text.strip(),
                    confidence=0.76,
                    impact_level="high",
                    positive=[
                        f"line {line.number}: stack allocation size `{vla.group('expr').strip()}`"
                    ],
                )

            align = re.search(
                rf"\*\s*\(\s*(?:{integer_ptr_type})\s*\*\s*\)\s*\([^)]*\+\s*1\s*\)",
                line.text,
            )
            if align:
                emit(
                    defect_class="alignment",
                    rule="unaligned_integer_pointer_cast",
                    line=line,
                    description="Potentially unaligned byte pointer is cast to an integer pointer and dereferenced.",
                    root_cause="The cast requires alignment that the byte-offset expression does not guarantee.",
                    suggested_fix="Use memcpy into an aligned local integer or byte-wise decoding.",
                    source=line.text.strip(),
                    sink=line.text.strip(),
                    confidence=0.78,
                    positive=[f"line {line.number}: dereferences integer pointer from byte offset"],
                )
            ptr_cast = re.search(
                rf"\b(?P<var>[A-Za-z_]\w*)\s*=\s*\([^;]*(?:{integer_ptr_type})\s*\*\s*\)"
                r"\s*\([^;]*\+\s*1\s*\)",
                line.text,
            )
            if ptr_cast:
                unaligned_ptrs[ptr_cast.group("var")] = line
            for var, cast_line in list(unaligned_ptrs.items()):
                if line.index > cast_line.index and re.search(rf"\*{re.escape(var)}\b", line.text):
                    emit(
                        defect_class="alignment",
                        rule="unaligned_integer_pointer_cast",
                        line=line,
                        description="Potentially unaligned byte pointer is cast to an integer pointer and later dereferenced.",
                        root_cause="The cast requires alignment that the byte-offset expression does not guarantee.",
                        suggested_fix="Use memcpy into an aligned local integer or byte-wise decoding.",
                        source=cast_line.text.strip(),
                        sink=line.text.strip(),
                        confidence=0.82,
                        positive=[
                            f"line {cast_line.number}: integer pointer is formed from byte offset",
                            f"line {line.number}: pointer is dereferenced",
                        ],
                    )
                    unaligned_ptrs.pop(var, None)

            decl = re.search(
                r"\b(?:struct\s+)?(?P<type>[A-Z][A-Za-z_0-9]*)\s+(?P<var>[A-Za-z_]\w*)\s*;",
                line.text,
            )
            if decl and "=" not in line.text and "typedef" not in line.text:
                struct_locals[decl.group("var")] = (line, 0, False)
            for var, (decl_line, field_writes, has_memset) in list(struct_locals.items()):
                if re.search(rf"\bmemset\s*\(\s*&{re.escape(var)}\s*,", line.text):
                    struct_locals[var] = (decl_line, field_writes, True)
                elif re.search(rf"\b{re.escape(var)}\.[A-Za-z_]\w*\s*=", line.text):
                    struct_locals[var] = (decl_line, field_writes + 1, has_memset)
                elif re.search(
                    rf"\b(?:_net_send_data|send|write|{self._names_pattern(getattr(self, '_user_send_sink_names', set()) or set())})\s*\([^;]*&{re.escape(var)}\s*,\s*sizeof\s*\(\s*{re.escape(var)}\s*\)",
                    line.text,
                ):
                    if not has_memset and field_writes > 0:
                        emit(
                            defect_class="uninitialized_read",
                            rule="partial_struct_sent",
                            line=line,
                            description=f"`{var}` is partially initialized and then sent/copied with sizeof.",
                            root_cause="Padding or unassigned fields can leak stale stack bytes.",
                            suggested_fix="Zero-initialize the struct before field assignments or serialize fields explicitly.",
                            source=var,
                            sink=line.text.strip(),
                            confidence=0.82,
                            positive=[
                                f"line {decl_line.number}: local aggregate `{var}` declared without initializer",
                                f"line {line.number}: entire aggregate is sent/copied",
                            ],
                        )

    @classmethod
    def _match_call(
        cls,
        text: str,
        names: Iterable[str],
        arg_group: str,
        *,
        until: str = ")",
    ) -> Optional[re.Match[str]]:
        terminator = r";" if until == ";" else r"\)"
        return re.search(
            rf"\b(?:{cls._names_pattern(names)})\s*\(\s*(?P<{arg_group}>[^{terminator}]+)",
            text,
        )

    def _collect_local_vars(self, lines: List[CodeLine]) -> Dict[str, CodeLine]:
        locals_seen: Dict[str, CodeLine] = {}
        for line in lines:
            if "(" in line.text and ")" in line.text and "{" in line.text:
                continue
            decl = re.search(
                r"^\s*(?:const\s+)?(?:struct\s+)?[A-Za-z_][A-Za-z_0-9]*(?:\s*\*)?\s+"
                r"(?P<var>[A-Za-z_]\w*)\s*(?:=\s*[^;]+)?;",
                line.text,
            )
            if decl and not line.text.startswith(("return", "if", "for", "while")):
                locals_seen[decl.group("var")] = line
        return locals_seen

    def _next_window_has_sink(self, lines: List[CodeLine], idx: int, var: str) -> bool:
        window = "\n".join(item.text for item in lines[idx + 1 : idx + 9])
        return bool(
            re.search(rf"\b{re.escape(var)}\b", window) and self._copy_or_alloc_re.search(window)
        )

    def _has_pre_overflow_guard(
        self, lines: List[CodeLine], idx: int, operands: Iterable[str]
    ) -> bool:
        operand_list = [item for item in operands if item]
        window = "\n".join(item.text for item in lines[max(0, idx - 8) : idx + 1])
        if "SIZE_MAX" not in window and "UINT_MAX" not in window:
            return False
        if "/" in window or "-" in window:
            return any(re.search(rf"\b{re.escape(op)}\b", window) for op in operand_list)
        return False

    def _has_post_wrap_check(
        self, lines: List[CodeLine], idx: int, var: str, operands: Iterable[str]
    ) -> bool:
        window = "\n".join(item.text for item in lines[idx + 1 : idx + 5])
        if not window:
            return False
        return any(
            re.search(rf"\bif\s*\([^)]*\b{re.escape(var)}\s*<\s*{re.escape(op)}\b", window)
            for op in operands
            if op
        )

    def _is_high_risk_size_expr(self, expr: str, params: Iterable[str]) -> bool:
        identifiers = [
            item
            for item in self._IDENT_RE.findall(expr)
            if item not in {"sizeof", "SIZE_MAX", "UINT_MAX"}
        ]
        if "*" in expr:
            return bool(identifiers)
        param_set = set(params)
        if any(item in param_set for item in identifiers):
            return True
        return any(
            (
                re.search(r"(payload|packet|max|field|count|size|data|cmd|total)", item)
                or (item.endswith("_len") and not item.startswith("key_"))
            )
            for item in identifiers
        )

    def _function_params(self, lines: List[CodeLine]) -> set[str]:
        if not lines:
            return set()
        signature = lines[0].text
        match = re.search(r"\((?P<params>.*)\)", signature)
        if not match:
            return set()
        params: set[str] = set()
        for part in match.group("params").split(","):
            part = part.strip()
            if not part or part == "void":
                continue
            name_match = re.search(r"([A-Za-z_]\w*)\s*(?:\[[^]]*\])?$", part.replace("*", " "))
            if name_match:
                params.add(name_match.group(1))
        return params

    @staticmethod
    def _is_macro_size_expr(expr: str) -> bool:
        text = str(expr or "").strip()
        return bool(re.fullmatch(r"[A-Z_][A-Z0-9_]*", text))

    def _guard_evidence(
        self, lines: List[CodeLine], idx: int, operands: Iterable[str]
    ) -> List[str]:
        if self._has_pre_overflow_guard(lines, idx, operands):
            return [
                "nearby SIZE_MAX/UINT_MAX precondition may guard this arithmetic; validator must prove it"
            ]
        return []


class GraphMemoryBoundsIntegerRules:
    def _emit_uninitialized_output_candidate(
        self,
        view: FunctionView,
        issues: List[Dict[str, Any]],
    ) -> None:
        text = "\n".join(line.text for line in view.lines)
        if "memset" in text:
            return
        for line in view.lines:
            match = re.search(
                r"\b(?P<type>[A-Z][A-Za-z_0-9]*)\s+(?P<var>[A-Za-z_]\w*)\s*;", line.text
            )
            if not match:
                continue
            var = match.group("var")
            copy_line = next(
                (
                    item
                    for item in view.lines
                    if item.index > line.index
                    and re.search(rf"\*\s*[A-Za-z_]\w+\s*=\s*{re.escape(var)}\s*;", item.text)
                ),
                None,
            )
            if not copy_line:
                continue
            assigned_fields = {
                m.group(1)
                for item in view.lines
                if line.index < item.index < copy_line.index
                for m in re.finditer(rf"\b{re.escape(var)}\.(\w+)\s*=", item.text)
            }
            if not assigned_fields or len(assigned_fields) >= 6:
                continue
            issues.append(
                self._issue(
                    defect_class="uninitialized_output",
                    rule="partial_stack_struct_copied_to_output",
                    view=view,
                    line=copy_line,
                    description="A stack struct is copied to an output parameter after only a subset of fields are initialized.",
                    root_cause="Uninitialized padding or fields can leak stale stack data or produce nondeterministic API results.",
                    suggested_fix="Zero-initialize the temporary struct before filling fields or assign every field before copying it out.",
                    source=f"{match.group('type')} {var}",
                    sink=copy_line.text.strip(),
                    confidence=0.82,
                    impact_level="medium",
                    positive=[
                        f"line {line.number}: local output struct `{var}` is declared without initialization",
                        f"line {copy_line.number}: `{var}` is copied to an output parameter",
                        f"assigned fields before copy: {', '.join(sorted(assigned_fields))}",
                    ],
                )
            )
            return

    def _emit_index_bound_candidate(
        self,
        view: FunctionView,
        issues: List[Dict[str, Any]],
    ) -> None:
        local_arrays: Dict[str, Tuple[str, GraphLine]] = {}
        for line in view.lines:
            match = re.search(
                r"\b(?:[A-Za-z_]\w*\s+)+(?P<name>[A-Za-z_]\w*)\s*"
                r"\[\s*(?P<limit>[A-Z][A-Z0-9_]*(?:LIMIT|MAX|SIZE|COUNT|NUM)[A-Z0-9_]*)\s*\]",
                line.text,
            )
            if match:
                local_arrays[match.group("name")] = (match.group("limit"), line)

        for idx, line in enumerate(view.lines):
            loop = re.search(
                r"\bfor\s*\([^;]*\b(?P<idx>[A-Za-z_]\w*)\s*=\s*[^;]*;\s*"
                r"(?P=idx)\s*<\s*(?P<limit>[A-Za-z_]\w*)\s*(?=;|\)|&&|\|\|)",
                line.text,
            )
            if not loop:
                continue
            idx_name = loop.group("idx")
            limit_name = loop.group("limit")
            window = view.lines[idx + 1 : min(len(view.lines), idx + 8)]
            access_line = next(
                (
                    item
                    for item in window
                    if re.search(rf"->\s*[A-Za-z_]\w*\s*\[\s*{re.escape(idx_name)}\s*\]", item.text)
                    or re.search(rf"\.[A-Za-z_]\w*\s*\[\s*{re.escape(idx_name)}\s*\]", item.text)
                ),
                None,
            )
            if not access_line:
                local_access = next(
                    (
                        item
                        for item in window
                        for array_name in local_arrays
                        if re.search(
                            rf"\b{re.escape(array_name)}\s*\[\s*{re.escape(idx_name)}\s*\]",
                            item.text,
                        )
                    ),
                    None,
                )
                if not local_access:
                    continue
                array_name = next(
                    name
                    for name in local_arrays
                    if re.search(
                        rf"\b{re.escape(name)}\s*\[\s*{re.escape(idx_name)}\s*\]", local_access.text
                    )
                )
                array_limit, array_line = local_arrays[array_name]
                guard_text = "\n".join(item.text for item in view.lines[max(0, idx - 8) : idx + 1])
                if "ARRAY_SIZE" in guard_text or re.search(
                    rf"\b{re.escape(limit_name)}\s*<=\s*(?:{re.escape(array_limit)}|ARRAY_SIZE|sizeof)",
                    guard_text,
                ):
                    continue
                issues.append(
                    self._issue(
                        defect_class="bounds",
                        rule="caller_limit_indexes_fixed_local_array",
                        view=view,
                        line=local_access,
                        description="A caller-controlled limit indexes a fixed local array without proving it is within the local capacity.",
                        root_cause="The loop bound comes from configuration or a function argument, while the temporary array has a smaller fixed capacity.",
                        suggested_fix="Clamp the configured limit to the local array length before indexing.",
                        source=f"{idx_name} < {limit_name}",
                        sink=local_access.text.strip(),
                        confidence=0.84,
                        impact_level="high",
                        positive=[
                            f"line {array_line.number}: local array `{array_name}` has fixed capacity `{array_limit}`",
                            f"line {line.number}: loop uses `{limit_name}` as the bound",
                            f"line {local_access.number}: `{array_name}` is indexed by `{idx_name}`",
                        ],
                    )
                )
                return
            guard_text = "\n".join(item.text for item in view.lines[max(0, idx - 5) : idx + 1])
            if "ARRAY_SIZE" in guard_text or re.search(
                rf"\b{re.escape(limit_name)}\s*<=\s*(?:ARRAY_SIZE|sizeof)", guard_text
            ):
                continue
            issues.append(
                self._issue(
                    defect_class="bounds",
                    rule="caller_limit_indexes_fixed_member_array",
                    view=view,
                    line=access_line,
                    description="A caller-controlled limit indexes a fixed member array without proving it is within the array size.",
                    root_cause="The loop bound is a function argument or protocol limit, while the indexed member has its own fixed capacity.",
                    suggested_fix="Clamp the loop bound to the destination array length before indexing.",
                    source=f"{idx_name} < {limit_name}",
                    sink=access_line.text.strip(),
                    confidence=0.8,
                    impact_level="high",
                    positive=[
                        f"line {line.number}: loop uses `{limit_name}` as the bound",
                        f"line {access_line.number}: member array is indexed by `{idx_name}`",
                        "no nearby ARRAY_SIZE/sizeof guard for the member array is visible",
                    ],
                )
            )
            return

    def _emit_cached_group_iteration_candidate(
        self,
        view: FunctionView,
        issues: List[Dict[str, Any]],
    ) -> None:
        text = "\n".join(line.text for line in view.lines)
        if not (
            "group_idx" in text
            and "pt_no_idx" in text
            and re.search(r"\b[A-Za-z_]\w*grp\b|\barena_grp\b", text)
        ):
            return
        stale_line = self._first_line_matching(
            view, re.compile(r"\barena_grp\s*=\s*&[A-Za-z_]\w+\[group_idx\]")
        )
        use_line = self._first_line_matching(view, re.compile(r"\barena_grp->\w+\[pt_no_idx\]"))
        if not stale_line or not use_line:
            return
        issues.append(
            self._issue(
                defect_class="logic_error",
                rule="cached_group_pointer_reused_across_partition_index",
                view=view,
                line=use_line,
                description="A cached group pointer is reused while a per-iteration group index changes.",
                root_cause="Traversal state is refreshed from one index dimension but used with another, so later iterations can read the wrong group.",
                suggested_fix="Recompute the group pointer whenever the group index changes, or derive both group and member from the same canonical index.",
                source=stale_line.text.strip(),
                sink=use_line.text.strip(),
                confidence=0.78,
                impact_level="medium",
                positive=[
                    f"line {stale_line.number}: group pointer is cached from `group_idx`",
                    f"line {use_line.number}: cached pointer is used with `pt_no_idx`",
                ],
            )
        )

    def _emit_direct_index_bound_candidate(
        self,
        view: FunctionView,
        issues: List[Dict[str, Any]],
    ) -> None:
        params = set(self._signature_param_names(view.signature))
        if not params:
            return
        for line in view.lines:
            match = re.search(
                r"\b(?P<array>g_[A-Za-z_0-9]+)\s*\[\s*(?P<idx>[A-Za-z_]\w*)\s*\]",
                line.text,
            )
            if not match or match.group("idx") not in params:
                continue
            array_name = match.group("array")
            idx_name = match.group("idx")
            guard_text = "\n".join(item.text for item in view.lines[: line.index + 1])
            if (
                re.search(
                    rf"\b{re.escape(idx_name)}\s*(?:<|<=)\s*(?:ARRAY_SIZE\s*\(\s*{re.escape(array_name)}\s*\)|[A-Z][A-Z0-9_]*(?:MAX|LIMIT|COUNT|NUM)[A-Z0-9_]*)",
                    guard_text,
                )
                or re.search(
                    rf"\b{re.escape(idx_name)}\s*>?=\s*(?:ARRAY_SIZE\s*\(\s*{re.escape(array_name)}\s*\)|[A-Z][A-Z0-9_]*(?:MAX|LIMIT|COUNT|NUM)[A-Z0-9_]*)",
                    guard_text,
                )
                or re.search(
                    rf"\b[A-Za-z_]\w*(?:is|valid|validate|check)[A-Za-z_0-9]*(?:fd|index|slot|core|bound)[A-Za-z_0-9]*\s*\(\s*{re.escape(idx_name)}\s*\)",
                    guard_text,
                    re.I,
                )
            ):
                continue
            issues.append(
                self._issue(
                    defect_class="bounds",
                    rule="unchecked_param_indexes_fixed_global_array",
                    view=view,
                    line=line,
                    description="A public or caller-supplied index directly indexes a fixed global array without a visible upper-bound check.",
                    root_cause="The function trusts an index parameter before proving it is within the backing global array capacity.",
                    suggested_fix="Reject or clamp the index against ARRAY_SIZE/the concrete maximum before indexing.",
                    source=idx_name,
                    sink=line.text.strip(),
                    confidence=0.86,
                    impact_level="high",
                    positive=[
                        f"function signature exposes index parameter `{idx_name}`",
                        f"line {line.number}: `{array_name}` is indexed by `{idx_name}`",
                        "no prior ARRAY_SIZE or maximum-core guard is visible",
                    ],
                )
            )
            return

    @staticmethod
    def _signature_param_names(signature: str) -> List[str]:
        match = re.search(r"\((?P<params>.*)\)", str(signature or ""))
        if not match:
            return []
        names: List[str] = []
        for raw_param in match.group("params").split(","):
            param = raw_param.strip()
            if not param or param == "void" or "..." in param:
                continue
            param = re.sub(r"\[[^]]*\]", "", param)
            tokens = re.findall(r"\b[A-Za-z_]\w*\b", param)
            if not tokens:
                continue
            candidate = tokens[-1]
            if candidate in {"const", "volatile", "unsigned", "signed", "struct", "enum"}:
                continue
            names.append(candidate)
        return names


class ClangMemoryBoundsIntegerRules:
    def _maybe_emit_unchecked_strchr_result(
        self,
        issues: List[Dict[str, Any]],
        func_name: str,
        file_path: str,
        lines: Sequence[ClangCfgLine],
        allowed_skills: Optional[Set[str]],
        line: ClangCfgLine,
    ) -> None:
        risky_use = re.search(
            r"\b(?P<var>[A-Za-z_]\w*)\s*(?:-|\[|->|\.)",
            line.text,
        )
        if not risky_use:
            return
        var = risky_use.group("var")
        assign_line = None
        for item in reversed(lines[max(0, line.index - 10) : line.index]):
            if re.search(rf"\b{re.escape(var)}\s*=\s*strchr\s*\(", item.text):
                assign_line = item
                break
        if assign_line is None:
            return
        between = lines[assign_line.index + 1 : line.index]
        if any(re.search(rf"\b{re.escape(var)}\s*(?:-|\[|->|\.)", item.text) for item in between):
            return
        guard_window = "\n".join(item.text for item in between)
        if re.search(
            rf"\b{re.escape(var)}\s*(?:!=\s*NULL|==\s*NULL|!=\s*0|==\s*0|\?)|!\s*{re.escape(var)}\b",
            guard_window,
        ):
            return
        self._emit(
            issues,
            func_name,
            file_path,
            lines,
            allowed_skills,
            defect_class="null_pointer_dereference",
            rule="clang_cfg_unchecked_strchr_result",
            line=line,
            description=f"`{var}` from `strchr` is used without a visible NULL check.",
            root_cause="When the delimiter is absent, `strchr` returns NULL and later pointer arithmetic or indexing dereferences that NULL-derived value.",
            suggested_fix=f"Check `{var}` for NULL before pointer arithmetic, indexing, or dereference.",
            source=f"strchr result at line {assign_line.number}",
            sink=line.text,
            confidence=0.88,
            impact_level="high",
            positive=[
                f"line {assign_line.number}: `{var}` receives `strchr(...)`",
                f"line {line.number}: `{var}` is used before any visible NULL guard",
            ],
            negative=[],
            ast_cfg=self._ast_cfg_pack(
                lines,
                [
                    self._event("strchr_result", assign_line, var, "strchr", assign_line.text),
                    self._event("unchecked_pointer_use", line, var, "", line.text),
                ],
                [assign_line.number, line.number],
            ),
        )

    def _maybe_emit_unchecked_param_global_array_index(
        self,
        issues: List[Dict[str, Any]],
        func_name: str,
        file_path: str,
        lines: Sequence[ClangCfgLine],
        allowed_skills: Optional[Set[str]],
        line: ClangCfgLine,
    ) -> None:
        params = set(self._signature_param_names(lines))
        if not params:
            return
        match = re.search(
            r"\b(?P<array>g_[A-Za-z_0-9]+)\s*\[\s*(?P<idx>[A-Za-z_]\w*)\s*\]",
            line.text,
        )
        if not match:
            return
        idx_name = match.group("idx")
        if idx_name not in params:
            return
        array_name = match.group("array")
        guard_window = "\n".join(item.text for item in lines[: line.index + 1])
        explicit_bound = re.search(
            rf"\b{re.escape(idx_name)}\s*(?:<|<=|>=|>)\s*"
            rf"(?:ARRAY_SIZE\s*\(\s*{re.escape(array_name)}\s*\)|"
            r"[A-Z][A-Z0-9_]*(?:MAX|LIMIT|COUNT|NUM|CORES|SIZE)[A-Z0-9_]*)",
            guard_window,
        )
        validator_guard = re.search(
            rf"\b[A-Za-z_]\w*(?:is|valid|validate|check)[A-Za-z_0-9]*(?:fd|index|slot|core|bound)[A-Za-z_0-9]*\s*\(\s*{re.escape(idx_name)}\s*\)",
            guard_window,
            re.I,
        )
        if explicit_bound or validator_guard:
            return
        if self._has_dynamic_array_capacity_guard(lines, line, array_name, idx_name):
            return
        self._emit(
            issues,
            func_name,
            file_path,
            lines,
            allowed_skills,
            defect_class="bounds",
            rule="clang_cfg_unchecked_param_indexes_fixed_global_array",
            line=line,
            description="A caller-supplied index parameter directly indexes a fixed global array without a visible upper-bound check.",
            root_cause="The function trusts an index parameter before proving it is within the backing global array capacity.",
            suggested_fix="Reject or clamp the index against ARRAY_SIZE or the concrete global-array capacity before indexing.",
            source=idx_name,
            sink=line.text,
            confidence=0.86,
            impact_level="high",
            positive=[
                f"function signature exposes index parameter `{idx_name}`",
                f"line {line.number}: `{array_name}` is indexed by `{idx_name}`",
                "no prior ARRAY_SIZE/concrete-capacity guard or index validator is visible",
            ],
            negative=[],
            ast_cfg=self._ast_cfg_pack(
                lines,
                [self._event("global_array_index", line, idx_name, array_name, line.text)],
                [line.number],
            ),
        )

    def _maybe_emit_wide_count_without_magic_guard(
        self,
        issues: List[Dict[str, Any]],
        func_name: str,
        file_path: str,
        lines: Sequence[ClangCfgLine],
        allowed_skills: Optional[Set[str]],
        line: ClangCfgLine,
    ) -> None:
        copy = re.search(
            r"\bmemcpy\s*\(\s*&\s*(?P<count>[A-Za-z_]\w*)\s*,\s*"
            r"(?P<src>[A-Za-z_]\w*)\s*\+\s*(?P<offset>\d+)\s*,\s*sizeof\s*\(\s*(?P=count)\s*\)\s*\)",
            line.text,
            re.IGNORECASE,
        )
        if not copy:
            return
        if not re.search(r"(?:count|cnt|num)", copy.group("count"), re.IGNORECASE):
            return
        offset = int(copy.group("offset"))
        if offset < 4:
            return
        before = "\n".join(item.text for item in lines[: line.index + 1])
        has_magic_symbol = re.search(r"(?:magic|signature|cookie)", before, re.IGNORECASE)
        has_magic_guard = re.search(
            r"\b(?:magic|signature|cookie)\b[^;\n]*(?:==|!=)|(?:==|!=)[^;\n]*\b(?:MAGIC|magic|signature|cookie)\b",
            before,
            re.IGNORECASE,
        )
        if has_magic_guard:
            return
        name_hint = self._function_name_hint(func_name, lines)
        if not has_magic_symbol and not re.search(
            r"(?:magic|header|protocol|parser|decode)", name_hint, re.IGNORECASE
        ):
            return
        sink_line = self._find_dependent_count_sink(lines, line, copy.group("count"))
        concrete_sink = (
            sink_line.text
            if sink_line is not None
            else f"{copy.group('count')} used before protocol magic validation"
        )
        defect_class = "bounds" if sink_line is not None else "protocol_validation"
        rule = (
            "clang_cfg_wide_count_before_magic_reaches_memory_sink"
            if sink_line is not None
            else "clang_cfg_wide_count_read_without_magic_guard"
        )
        positive = [
            f"line {line.number}: protocol field is copied from a wire buffer offset",
            "no magic/signature comparison is visible before the count read",
        ]
        events = [
            self._event("wide_count_read", line, copy.group("count"), copy.group("src"), line.text)
        ]
        cfg_path = [line.number]
        if sink_line is not None:
            positive.append(
                f"line {sink_line.number}: unchecked `{copy.group('count')}` reaches a memory/dispatch sink"
            )
            events.append(
                self._event("wide_count_sink", sink_line, copy.group("count"), "", sink_line.text)
            )
            cfg_path.append(sink_line.number)
        self._emit(
            issues,
            func_name,
            file_path,
            lines,
            allowed_skills,
            defect_class=defect_class,
            rule=rule,
            line=sink_line or line,
            description=f"Protocol field `{copy.group('count')}` is read from `{copy.group('src')} + {offset}` without a visible magic/signature guard.",
            root_cause="The parser uses a dependent protocol field before proving the record layout with the expected magic value.",
            suggested_fix="Decode and validate the magic/signature field before reading dependent count fields.",
            source=line.text,
            sink=concrete_sink,
            confidence=0.82,
            impact_level="high",
            positive=positive,
            negative=[
                "Validator must confirm whether a caller-side magic check dominates this parser."
            ],
            ast_cfg=self._ast_cfg_pack(
                lines,
                events,
                cfg_path,
            ),
        )

    def _maybe_emit_fixed_limit_spec_mismatch(
        self,
        issues: List[Dict[str, Any]],
        func_name: str,
        file_path: str,
        lines: Sequence[ClangCfgLine],
        allowed_skills: Optional[Set[str]],
        line: ClangCfgLine,
    ) -> None:
        assign = re.search(
            r"\b(?P<len>[A-Za-z_]\w*(?:len|size)[A-Za-z_0-9]*)\s*=\s*"
            r"\([^;]*\)\s*(?P<count>[A-Za-z_]\w*(?:count|num|index)[A-Za-z_0-9]*)\s*\*\s*(?P<unit>[A-Z][A-Z0-9_]*(?:SIZE|LEN|BYTES))\b",
            line.text,
        )
        if not assign:
            return
        length_var = assign.group("len")
        count_var = assign.group("count")
        later_text = "\n".join(item.text for item in lines[line.index + 1 : line.index + 14])
        limit_match = re.search(
            rf"\b{re.escape(length_var)}\b\s*>\s*(?P<limit>[A-Z][A-Z0-9_]*(?:LIMIT|CAP|MAX))",
            later_text,
        )
        spec_match = re.search(
            rf"\b{re.escape(count_var)}\b\s*<=\s*(?P<spec>[A-Z][A-Z0-9_]*(?:SPEC|MAX)[A-Z0-9_]*)",
            later_text,
        )
        if not (limit_match and spec_match):
            return
        if limit_match.group("limit") == spec_match.group("spec"):
            return
        audit_only = not self._limit_mismatch_reaches_unsafe_sink(lines, line, length_var)
        self._emit(
            issues,
            func_name,
            file_path,
            lines,
            allowed_skills,
            defect_class="size_limit_mismatch",
            rule="clang_cfg_fixed_byte_limit_before_spec_count_check",
            line=line,
            description=(
                f"`{length_var}` is constrained by `{limit_match.group('limit')}` before "
                f"`{count_var}` is checked against `{spec_match.group('spec')}`."
            ),
            root_cause="A fixed byte cache limit can reject or size the allocation differently from the stated element-count specification.",
            suggested_fix="Validate element count against the specification before computing bytes, and derive byte limits from the same contract.",
            source=line.text,
            sink=limit_match.group("limit"),
            confidence=0.84,
            impact_level="medium",
            positive=[
                f"line {line.number}: element count is converted to a byte length",
                f"later guard uses fixed byte limit `{limit_match.group('limit')}`",
                f"later return/contract uses separate spec `{spec_match.group('spec')}`",
            ],
            negative=(
                [
                    "The local CFG does not show the mismatched byte limit reaching an unsafe copy, index, or allocation sink.",
                    "Treat as a design/contract observation unless a downstream sink consumes the mismatched length.",
                ]
                if audit_only
                else []
            ),
            ast_cfg=self._ast_cfg_pack(
                lines,
                [self._event("spec_byte_limit_mismatch", line, length_var, count_var, line.text)],
                [line.number],
            ),
            validation_required=not audit_only,
            finding_kind="audit_observation" if audit_only else "clang_ast_cfg_candidate",
            audit_observation_reason=(
                "大小/规格上限不匹配，且在本地 CFG 中没有可见的不安全汇点"
                if audit_only
                else ""
            ),
        )

    def _maybe_emit_integer_overflow(
        self,
        issues: List[Dict[str, Any]],
        func_name: str,
        file_path: str,
        lines: Sequence[ClangCfgLine],
        allowed_skills: Optional[Set[str]],
        line: ClangCfgLine,
    ) -> None:
        patterns = [
            (
                re.search(
                    r"\b(?P<var>[A-Za-z_]\w*)\s*=\s*(?:\([^)]*\)\s*)?"
                    r"(?P<api>[A-Za-z_]\w*(?:alloc|malloc|calloc|realloc)[A-Za-z_0-9]*)\s*\((?P<expr>[^;]*(?:\+|\*)[^;]*)\)",
                    line.text,
                    re.IGNORECASE,
                ),
                "allocation_size_arithmetic_without_overflow_guard",
                "Allocation size is computed with arithmetic without a visible overflow guard.",
            ),
            (
                re.search(
                    r"\b(?:size_t|uint(?:32|64)_t|unsigned(?:\s+int)?|int)\s+"
                    r"(?P<var>[A-Za-z_]\w*(?:len|size|total)[A-Za-z_0-9]*)\s*=\s*(?P<expr>[^;]*(?:sizeof\s*\([^)]*\)|[A-Za-z_]\w*)\s*\+\s*[^;]+);",
                    line.text,
                    re.IGNORECASE,
                ),
                "size_addition_without_overflow_guard",
                "Size expression uses addition without a visible overflow guard.",
            ),
            (
                re.search(
                    r"\(\s*uint32_t\s*\)\s*(?P<expr>[A-Za-z_]\w*(?:len|length|size)[A-Za-z_0-9]*)",
                    line.text,
                ),
                "narrowing_size_cast_without_range_guard",
                "A size-like value is narrowed to uint32_t without a visible range guard.",
            ),
        ]
        for match, rule, description in patterns:
            if not match:
                continue
            expr = match.groupdict().get("expr") or line.text
            guard_window = "\n".join(
                item.text for item in lines[max(0, line.index - 8) : line.index]
            )
            if self._has_overflow_guard(guard_window, expr):
                continue
            if self._has_small_count_bound_proof(lines, line, expr):
                continue
            if self._has_narrowing_bound_proof(lines, line, expr):
                continue
            self._emit(
                issues,
                func_name,
                file_path,
                lines,
                allowed_skills,
                defect_class="integer_overflow",
                rule=f"clang_cfg_{rule}",
                line=line,
                description=description,
                root_cause="Integer arithmetic on a size or length value can wrap before allocation, copy, or serialization.",
                suggested_fix="Check the arithmetic bound before evaluating the allocation/copy size or narrowing cast.",
                source=str(expr).strip(),
                sink=line.text,
                confidence=0.8,
                impact_level="high",
                positive=[f"line {line.number}: arithmetic/narrowing expression `{line.text}`"],
                negative=[
                    "Validator must confirm whether an equivalent range guard exists on all paths."
                ],
                ast_cfg=self._ast_cfg_pack(
                    lines,
                    [self._event("integer_size_arithmetic", line, "", "", line.text)],
                    [line.number],
                ),
            )
            break

    def _maybe_emit_signed_unsigned(
        self,
        issues: List[Dict[str, Any]],
        func_name: str,
        file_path: str,
        lines: Sequence[ClangCfgLine],
        allowed_skills: Optional[Set[str]],
        line: ClangCfgLine,
        signed_reads: Dict[str, ClangCfgLine],
        casts: Dict[str, Tuple[ClangCfgLine, str]],
    ) -> None:
        read = re.search(
            rf"\b(?:int|ssize_t)\s+(?P<var>[A-Za-z_]\w*)\s*=\s*"
            rf"(?:recv|read|recvfrom|_net_recv_data|{self._names_pattern(getattr(self, '_user_recv_source_names', set()) or set())})\s*\(",
            line.text,
        )
        if read:
            signed_reads[read.group("var")] = line

        cast = re.search(
            r"\bsize_t\s+(?P<size>[A-Za-z_]\w*)\s*=\s*\(size_t\)\s*(?P<src>[A-Za-z_]\w*)\s*;",
            line.text,
        )
        if cast and cast.group("src") in signed_reads:
            casts[cast.group("size")] = (line, cast.group("src"))

        for size_var, (cast_line, src_var) in list(casts.items()):
            if line.index <= cast_line.index:
                continue
            if not self._copy_uses_length(line.text, size_var):
                continue
            src_line = signed_reads[src_var]
            self._emit(
                issues,
                func_name,
                file_path,
                lines,
                allowed_skills,
                defect_class="signed_unsigned",
                rule="clang_cfg_negative_length_cast_to_size_t",
                line=cast_line,
                description=f"Signed IO length `{src_var}` is cast to `size_t` as `{size_var}` and reaches a copy length.",
                root_cause="Negative error returns can become very large unsigned sizes after the cast.",
                suggested_fix=f"Check `{src_var} >= 0` and the upper bound before casting to `size_t`.",
                source=f"{src_var} at line {src_line.number}",
                sink=line.text,
                confidence=0.88,
                impact_level="high",
                positive=[
                    f"line {src_line.number}: signed result `{src_var}` comes from an IO/read API",
                    f"line {cast_line.number}: `{src_var}` is cast to `size_t` as `{size_var}`",
                    f"line {line.number}: `{size_var}` is used as a copy/IO length",
                ],
                negative=[],
                ast_cfg=self._ast_cfg_pack(
                    lines,
                    [
                        self._event("signed_io_result", src_line, src_var, "", src_line.text),
                        self._event(
                            "signed_to_unsigned_cast", cast_line, size_var, src_var, cast_line.text
                        ),
                        self._event("unsigned_length_sink", line, size_var, "", line.text),
                    ],
                    [src_line.number, cast_line.number, line.number],
                ),
            )
            casts.pop(size_var, None)

    def _maybe_emit_off_by_one(
        self,
        issues: List[Dict[str, Any]],
        func_name: str,
        file_path: str,
        lines: Sequence[ClangCfgLine],
        allowed_skills: Optional[Set[str]],
        line: ClangCfgLine,
    ) -> None:
        match = re.search(
            r"\b(?P<array>[A-Za-z_]\w*)\s*\[\s*sizeof\s*\(\s*(?P=array)\s*\)\s*\]\s*=", line.text
        )
        if not match:
            return
        array = match.group("array")
        self._emit(
            issues,
            func_name,
            file_path,
            lines,
            allowed_skills,
            defect_class="off_by_one",
            rule="clang_cfg_sizeof_index_write",
            line=line,
            description=f"`{array}[sizeof({array})]` writes one element past the end of the array.",
            root_cause="`sizeof(array)` is the byte count and is outside the zero-based index range.",
            suggested_fix=f"Use `sizeof({array}) - 1` for the terminator or a length-aware helper.",
            source=array,
            sink=line.text,
            confidence=0.9,
            impact_level="high",
            positive=[f"line {line.number}: writes at `sizeof({array})` index"],
            negative=[],
            ast_cfg=self._ast_cfg_pack(
                lines, [self._event("off_by_one_write", line, array, "", line.text)], [line.number]
            ),
        )

    def _track_local_aggregate(
        self,
        line: ClangCfgLine,
        local_aggregates: Dict[str, Tuple[ClangCfgLine, str]],
        aggregate_field_writes: Dict[str, Set[str]],
    ) -> None:
        decl = re.search(
            r"^\s*(?P<type>(?:struct\s+)?[A-Z][A-Za-z_0-9]*|[A-Za-z_]\w*(?:Reply|Msg|Message|Packet|Header|Record|Job|Ctx|Context))\s+"
            r"(?P<var>[A-Za-z_]\w*)\s*;",
            line.text,
        )
        if decl:
            var = decl.group("var")
            local_aggregates[var] = (line, decl.group("type"))
            aggregate_field_writes.setdefault(var, set())
        field = re.search(r"\b(?P<var>[A-Za-z_]\w*)\s*\.\s*(?P<field>[A-Za-z_]\w*)\s*=", line.text)
        if field and field.group("var") in aggregate_field_writes:
            aggregate_field_writes[field.group("var")].add(field.group("field"))
        memset = re.search(
            r"\bmemset\s*\(\s*&?\s*(?P<var>[A-Za-z_]\w*)\s*,\s*0\s*,\s*sizeof\s*\(\s*(?P=var)\s*\)\s*\)",
            line.text,
        )
        if memset and memset.group("var") in aggregate_field_writes:
            aggregate_field_writes[memset.group("var")].add("*zero_initialized*")

    def _maybe_emit_stack_array_overflow(
        self,
        issues: List[Dict[str, Any]],
        func_name: str,
        file_path: str,
        lines: Sequence[ClangCfgLine],
        allowed_skills: Optional[Set[str]],
        line: ClangCfgLine,
    ) -> None:
        match = re.search(
            r"\b(?:char|unsigned\s+char|uint8_t|int|uint32_t|size_t)\s+"
            r"(?P<array>[A-Za-z_]\w*)\s*\[\s*(?P<size>[^\]]*[A-Za-z_]\w*[^\]]*)\s*\]\s*;",
            line.text,
        )
        if not match:
            return
        size = match.group("size").strip()
        if self._is_compile_time_size_expr(size):
            return
        guard_window = "\n".join(item.text for item in lines[max(0, line.index - 8) : line.index])
        if re.search(rf"\b{re.escape(size)}\b\s*(?:<|<=)\s*\d+", guard_window):
            return
        self._emit(
            issues,
            func_name,
            file_path,
            lines,
            allowed_skills,
            defect_class="stack_overflow",
            rule="clang_cfg_unbounded_vla_or_stack_array",
            line=line,
            description=f"Stack array `{match.group('array')}` uses runtime size `{size}` without a visible cap.",
            root_cause="Caller-controlled or data-dependent stack allocation can exhaust or overflow the stack.",
            suggested_fix="Cap the size before stack allocation or allocate bounded heap storage.",
            source=size,
            sink=line.text,
            confidence=0.86,
            impact_level="high",
            positive=[f"line {line.number}: stack allocation size `{size}` is runtime-derived"],
            negative=["Validator must confirm no caller-side bound constrains this size."],
            ast_cfg=self._ast_cfg_pack(
                lines,
                [self._event("runtime_stack_array", line, match.group("array"), "", line.text)],
                [line.number],
            ),
        )

    def _maybe_emit_heap_copy_length_mismatch(
        self,
        issues: List[Dict[str, Any]],
        func_name: str,
        file_path: str,
        lines: Sequence[ClangCfgLine],
        allowed_skills: Optional[Set[str]],
        line: ClangCfgLine,
    ) -> None:
        copy_call = re.search(
            r"\b(?P<api>memcpy|memmove)\s*\(\s*(?P<dst>[A-Za-z_]\w*)\s*,\s*[^,]+,\s*(?P<len>[^)]+)\)",
            line.text,
        )
        if not copy_call:
            return
        dst = copy_call.group("dst")
        copy_len = copy_call.group("len").strip()
        alloc_data = self._find_allocation_size_assignment(lines, line, dst)
        if alloc_data is None:
            return
        alloc_line, alloc_size = alloc_data
        alloc_base = self._allocation_base_from_size(lines, alloc_line, alloc_size)
        copy_base = self._expression_origin_base(lines, line, copy_len)
        if not alloc_base or not copy_base or alloc_base != copy_base:
            if not self._looks_like_external_length_pair(lines, line, alloc_size, copy_len):
                return
        if self._copy_length_bounded_by_alloc(lines, line, copy_len, alloc_size):
            return
        self._emit(
            issues,
            func_name,
            file_path,
            lines,
            allowed_skills,
            defect_class="heap_overflow",
            rule="clang_cfg_narrowed_allocation_original_length_copy",
            line=line,
            description=(
                f"`{dst}` is allocated from narrowed size `{alloc_size}` but copied with original length `{copy_len}`."
            ),
            root_cause="A truncated allocation size can be smaller than the subsequent copy length.",
            suggested_fix="Allocate from the same checked length used by the copy, or reject values that do not fit the allocation type.",
            source=alloc_line.text,
            sink=line.text,
            confidence=0.88,
            impact_level="high",
            positive=[
                f"line {alloc_line.number}: allocation for `{dst}` uses narrowed size `{alloc_size}`",
                f"line {line.number}: `{copy_len}` reaches `{copy_call.group('api')}` as the copy length",
            ],
            negative=[
                "Validator must confirm the original length can exceed the narrowed allocation length."
            ],
            ast_cfg=self._ast_cfg_pack(
                lines,
                [
                    self._event(
                        "narrowed_heap_allocation", alloc_line, dst, alloc_size, alloc_line.text
                    ),
                    self._event("original_length_heap_copy", line, dst, copy_len, line.text),
                ],
                [alloc_line.number, line.number],
            ),
        )

    def _maybe_emit_offset_length_copy_overread(
        self,
        issues: List[Dict[str, Any]],
        func_name: str,
        file_path: str,
        lines: Sequence[ClangCfgLine],
        allowed_skills: Optional[Set[str]],
        line: ClangCfgLine,
    ) -> None:
        copy_call = re.search(
            r"\b(?P<api>memcpy|memmove)\s*\(\s*[^,]+,\s*(?P<src>[A-Za-z_]\w*)\s*,\s*(?P<len>[^)]+)\)",
            line.text,
        )
        if not copy_call:
            return
        src = copy_call.group("src")
        copy_len = copy_call.group("len").strip()
        source_line = self._find_offset_pointer_assignment(lines, line, src)
        if source_line is None:
            return
        offset_expr = self._offset_expr_from_pointer_assignment(source_line.text, src)
        if not offset_expr:
            return
        guard_window = "\n".join(
            item.text for item in lines[max(0, source_line.index - 8) : line.index + 1]
        )
        if re.search(
            rf"\b{re.escape(offset_expr)}\b\s*\+\s*{re.escape(copy_len)}\s*(?:<=|<)\s*(?:[A-Za-z_]\w*len|[A-Za-z_]\w*_len|sizeof\s*\()",
            guard_window,
        ):
            return
        if not re.search(
            r"(?:offset|digest|header|wire|len|length|size)", f"{offset_expr} {copy_len}", re.I
        ):
            return
        self._emit(
            issues,
            func_name,
            file_path,
            lines,
            allowed_skills,
            defect_class="buffer_overread",
            rule="clang_cfg_offset_length_copy_without_source_bound",
            line=line,
            description=f"`{src}` is derived from unchecked offset `{offset_expr}` and copied with `{copy_len}`.",
            root_cause="The code validates neither the offset nor offset-plus-length against the backing input buffer.",
            suggested_fix="Require `offset <= buffer_len` and `copy_len <= buffer_len - offset` before deriving the source pointer.",
            source=source_line.text,
            sink=line.text,
            confidence=0.84,
            impact_level="high",
            positive=[
                f"line {source_line.number}: `{src}` is derived from a buffer plus `{offset_expr}`",
                f"line {line.number}: `{src}` reaches `{copy_call.group('api')}` with length `{copy_len}`",
            ],
            negative=[
                "Validator must confirm no caller-side packet bound dominates the offset and length."
            ],
            ast_cfg=self._ast_cfg_pack(
                lines,
                [
                    self._event("offset_pointer", source_line, src, offset_expr, source_line.text),
                    self._event("offset_length_copy", line, src, copy_len, line.text),
                ],
                [source_line.number, line.number],
            ),
        )

    def _maybe_emit_pointer_backtrack_underflow(
        self,
        issues: List[Dict[str, Any]],
        func_name: str,
        file_path: str,
        lines: Sequence[ClangCfgLine],
        allowed_skills: Optional[Set[str]],
        line: ClangCfgLine,
    ) -> None:
        sink = re.search(
            r"\b(?P<api>memcpy|memmove|memset|strncpy)\s*\(\s*(?P<args>.*)\)",
            line.text,
        )
        if not sink:
            return
        args = self._split_args(sink.group("args"))
        if not args:
            return
        api = sink.group("api")
        pointer_arg = (
            args[1] if api in {"memcpy", "memmove", "strncpy"} and len(args) > 1 else args[0]
        )
        pointer_arg = pointer_arg.strip()
        if not re.fullmatch(r"[A-Za-z_]\w*", pointer_arg):
            return
        source_line = self._find_pointer_backtrack_assignment(lines, line, pointer_arg)
        if source_line is None:
            return
        defect = (
            "buffer_underwrite"
            if api == "memset"
            or (api in {"memcpy", "memmove", "strncpy"} and args[0].strip() == pointer_arg)
            else "buffer_underread"
        )
        self._emit(
            issues,
            func_name,
            file_path,
            lines,
            allowed_skills,
            defect_class=defect,
            rule="clang_cfg_unchecked_pointer_backtrack",
            line=line,
            description=f"`{pointer_arg}` is derived by subtracting an unchecked offset and then used by `{api}`.",
            root_cause="A caller- or wire-controlled backtrack can move a pointer before the start of the buffer.",
            suggested_fix="Validate the backtrack/offset against the available buffer length before deriving the pointer.",
            source=source_line.text,
            sink=line.text,
            confidence=0.84,
            impact_level="high",
            positive=[
                f"line {source_line.number}: `{pointer_arg}` is derived with subtraction from a buffer pointer",
                f"line {line.number}: `{pointer_arg}` is used by `{api}`",
            ],
            negative=[
                "Validator must confirm the subtracted offset is externally controlled and lacks a dominating bound."
            ],
            ast_cfg=self._ast_cfg_pack(
                lines,
                [
                    self._event(
                        "pointer_backtrack", source_line, pointer_arg, "", source_line.text
                    ),
                    self._event("backtracked_pointer_sink", line, pointer_arg, api, line.text),
                ],
                [source_line.number, line.number],
            ),
        )

    def _maybe_emit_invalid_free(
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
        api, arg = release
        cleaned = arg.strip()
        if re.fullmatch(r"[A-Za-z_]\w*", cleaned):
            return
        if not re.search(r"(?<!-)\+|\s-\s|-\s*\d|&\s*[A-Za-z_]|\[[^\]]+\]", cleaned):
            return
        if self._is_owned_pointer_array_element_release(lines, line, cleaned):
            return
        self._emit(
            issues,
            func_name,
            file_path,
            lines,
            allowed_skills,
            defect_class="invalid_free",
            rule="clang_cfg_free_non_owner_pointer_expression",
            line=line,
            description=f"`{api}` is called on non-owner pointer expression `{cleaned}`.",
            root_cause="A deallocator receives an interior, stack, or adjusted pointer rather than the owning allocation base.",
            suggested_fix="Free only the owning base pointer returned by the allocator.",
            source=cleaned,
            sink=line.text,
            confidence=0.9,
            impact_level="high",
            positive=[
                f"line {line.number}: deallocator argument is `{cleaned}`, not a plain owner variable"
            ],
            negative=[],
            ast_cfg=self._ast_cfg_pack(
                lines, [self._event("invalid_free", line, cleaned, api, line.text)], [line.number]
            ),
        )

    def _maybe_emit_interior_free_alias(
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
        api, arg = release
        var = arg.strip()
        if not re.fullmatch(r"[A-Za-z_]\w*", var):
            return
        derivation = self._find_pointer_derivation(lines, line, var)
        if derivation is None:
            return
        source_line, base, operation = derivation
        self._emit(
            issues,
            func_name,
            file_path,
            lines,
            allowed_skills,
            defect_class="invalid_free",
            rule="clang_cfg_free_derived_pointer_alias",
            line=line,
            description=f"`{api}` is called on `{var}`, which was derived from `{base}` by pointer arithmetic.",
            root_cause="The deallocator receives an alias to an interior/adjusted address rather than the owning allocation base.",
            suggested_fix=f"Keep `{base}` as the owner passed to `{api}` and use a separate non-owning cursor for offsets.",
            source=source_line.text,
            sink=line.text,
            confidence=0.86,
            impact_level="high",
            positive=[
                f"line {source_line.number}: `{operation}` derives `{var}` from `{base}`",
                f"line {line.number}: `{api}` releases derived alias `{var}`",
            ],
            negative=[
                "Validator must confirm the base object was heap-owned and the alias does not equal the allocation base on all paths."
            ],
            ast_cfg=self._ast_cfg_pack(
                lines,
                [
                    self._event("pointer_derivation", source_line, var, base, source_line.text),
                    self._event("invalid_free_alias", line, var, api, line.text),
                ],
                [source_line.number, line.number],
            ),
        )

    def _maybe_emit_unchecked_allocation_result(
        self,
        issues: List[Dict[str, Any]],
        func_name: str,
        file_path: str,
        lines: Sequence[ClangCfgLine],
        allowed_skills: Optional[Set[str]],
        line: ClangCfgLine,
    ) -> None:
        var = self._first_direct_deref_var(line.text)
        if not var:
            return
        alloc_line = self._find_allocation_assignment(lines, line, var)
        if alloc_line is None:
            return
        if self._has_terminating_null_guard(lines, alloc_line, line, var):
            return
        self._emit(
            issues,
            func_name,
            file_path,
            lines,
            allowed_skills,
            defect_class="unchecked_allocation",
            rule="clang_cfg_allocation_result_used_without_null_check",
            line=line,
            description=f"Allocation result `{var}` is used before a visible NULL check.",
            root_cause="The allocation return value can be NULL and the local path dereferences or indexes it first.",
            suggested_fix=f"Check `{var}` for NULL before any dereference, indexing, or write.",
            source=alloc_line.text,
            sink=line.text,
            confidence=0.76,
            impact_level="high",
            positive=[
                f"line {alloc_line.number}: `{var}` receives an allocation result",
                f"line {line.number}: `{var}` is consumed before a visible NULL guard",
            ],
            negative=["Validator must confirm no wrapper contract guarantees a non-NULL result."],
            ast_cfg=self._ast_cfg_pack(
                lines,
                [
                    self._event("allocation_result", alloc_line, var, "", alloc_line.text),
                    self._event("unchecked_allocation_use", line, var, "", line.text),
                ],
                [alloc_line.number, line.number],
            ),
        )

    def _maybe_emit_fixed_array_count_overflow(
        self,
        issues: List[Dict[str, Any]],
        func_name: str,
        file_path: str,
        lines: Sequence[ClangCfgLine],
        allowed_skills: Optional[Set[str]],
        line: ClangCfgLine,
    ) -> None:
        write = re.search(
            r"\b(?P<array>[A-Za-z_]\w*)\s*\[\s*(?P<index>[A-Za-z_]\w*)\s*\]"
            r"\s*(?:\.|->)?\s*[A-Za-z_0-9]*\s*=",
            line.text,
        )
        if not write:
            return
        array = write.group("array")
        index_var = write.group("index")
        decl_line, array_size = self._find_fixed_array_decl(lines, line, array)
        if decl_line is None:
            return
        loop_line, count_expr = self._find_count_loop_for_index(lines, line, index_var)
        if loop_line is None:
            return
        if self._count_is_obviously_bounded(lines, line, array, array_size, count_expr):
            return
        self._emit(
            issues,
            func_name,
            file_path,
            lines,
            allowed_skills,
            defect_class="out_of_bounds_write",
            rule="clang_cfg_unbounded_count_indexes_fixed_array",
            line=line,
            description=f"Loop count `{count_expr}` indexes fixed array `{array}[{array_size}]` without a visible array-size guard.",
            root_cause="An externally derived count can drive writes past the local fixed-size buffer.",
            suggested_fix=f"Validate `{count_expr}` against `ARRAY_SIZE({array})` before the loop or clamp the loop bound.",
            source=f"{array} declaration at line {decl_line.number}; loop at line {loop_line.number}",
            sink=line.text,
            confidence=0.82,
            impact_level="high",
            positive=[
                f"line {decl_line.number}: `{array}` is a fixed-size local array",
                f"line {loop_line.number}: loop bound is `{count_expr}`",
                f"line {line.number}: `{array}[{index_var}]` is written inside the loop",
            ],
            negative=[
                "Validator must confirm the loop count is not constrained by a caller-side or earlier protocol guard."
            ],
            ast_cfg=self._ast_cfg_pack(
                lines,
                [
                    self._event("fixed_array", decl_line, array, array_size, decl_line.text),
                    self._event("count_loop", loop_line, index_var, count_expr, loop_line.text),
                    self._event("array_write", line, array, index_var, line.text),
                ],
                [decl_line.number, loop_line.number, line.number],
            ),
        )

    def _maybe_emit_key_truncation(
        self,
        issues: List[Dict[str, Any]],
        func_name: str,
        file_path: str,
        lines: Sequence[ClangCfgLine],
        allowed_skills: Optional[Set[str]],
        line: ClangCfgLine,
    ) -> None:
        trunc = re.search(
            r"\bstrncpy\s*\(\s*(?P<dst>[A-Za-z_]\w*\s*->\s*(?:key|name|id)|[A-Za-z_]\w*\.(?:key|name|id))\s*,\s*"
            r"(?P<src>[A-Za-z_]\w*)\s*,\s*(?P<limit>\d+|[A-Z_][A-Z0-9_]*)\s*\)",
            line.text,
        )
        if not trunc:
            return
        src = trunc.group("src")
        lookup_line = self._find_prior_full_key_lookup(lines, line, src)
        if lookup_line is None:
            return
        guard_window = "\n".join(
            item.text for item in lines[max(0, lookup_line.index - 4) : line.index + 1]
        )
        if re.search(
            rf"\bstrlen\s*\(\s*{re.escape(src)}\s*\)\s*(?:<|<=)\s*{re.escape(trunc.group('limit'))}\b",
            guard_window,
        ):
            return
        self._emit(
            issues,
            func_name,
            file_path,
            lines,
            allowed_skills,
            defect_class="key_truncation",
            rule="clang_cfg_full_key_lookup_truncated_key_insert",
            line=line,
            description=f"`{src}` is looked up at full length but stored through fixed-length `{trunc.group('dst')}`.",
            root_cause="Lookup and insertion use different key equivalence domains, so long keys can collide or bypass an existing record.",
            suggested_fix="Validate key length before lookup or use the same bounded key representation for lookup and insertion.",
            source=lookup_line.text,
            sink=line.text,
            confidence=0.84,
            impact_level="high",
            positive=[
                f"line {lookup_line.number}: lookup/find uses full key `{src}`",
                f"line {line.number}: `{src}` is copied into `{trunc.group('dst')}` with fixed limit `{trunc.group('limit')}`",
            ],
            negative=[
                "Validator must confirm the destination key length is shorter than accepted input keys."
            ],
            ast_cfg=self._ast_cfg_pack(
                lines,
                [
                    self._event("full_key_lookup", lookup_line, src, "", lookup_line.text),
                    self._event("truncated_key_store", line, src, trunc.group("limit"), line.text),
                ],
                [lookup_line.number, line.number],
            ),
        )

    def _maybe_emit_wire_integer_pointer_deref(
        self,
        issues: List[Dict[str, Any]],
        func_name: str,
        file_path: str,
        lines: Sequence[ClangCfgLine],
        allowed_skills: Optional[Set[str]],
        line: ClangCfgLine,
    ) -> None:
        direct = re.search(
            r"\*\s*\([^;)]*\*\s*\)\s*(?:\([^)]*\)\s*)?(?P<src>[A-Za-z_]\w*(?:->|\.)[A-Za-z_]\w*)",
            line.text,
        )
        if direct and self._looks_wire_pointer_source(direct.group("src")):
            source_line = line
            var = direct.group("src")
        else:
            var = self._first_direct_deref_var(line.text)
            if not var:
                return
            found_source_line = self._find_wire_pointer_assignment(lines, line, var)
            if found_source_line is None:
                return
            source_line = found_source_line
        self._emit(
            issues,
            func_name,
            file_path,
            lines,
            allowed_skills,
            defect_class="untrusted_pointer",
            rule="clang_cfg_wire_integer_cast_to_pointer_deref",
            line=line,
            description="A serialized/header integer is converted to a process pointer and dereferenced.",
            root_cause="Wire data cannot be trusted as an in-process address; dereferencing it can access arbitrary memory.",
            suggested_fix="Treat wire values as opaque offsets or handles and resolve them through a validated table.",
            source=source_line.text,
            sink=line.text,
            confidence=0.88,
            impact_level="critical",
            positive=[
                f"line {source_line.number}: wire/header-derived value is cast into pointer `{var}`",
                f"line {line.number}: the resulting pointer is dereferenced",
            ],
            negative=[],
            ast_cfg=self._ast_cfg_pack(
                lines,
                [
                    self._event("wire_pointer_cast", source_line, var, "", source_line.text),
                    self._event("wire_pointer_deref", line, var, "", line.text),
                ],
                [source_line.number, line.number],
            ),
        )

    def _maybe_emit_unchecked_object_offset_access(
        self,
        issues: List[Dict[str, Any]],
        func_name: str,
        file_path: str,
        lines: Sequence[ClangCfgLine],
        allowed_skills: Optional[Set[str]],
        line: ClangCfgLine,
    ) -> None:
        var = self._first_direct_deref_var(line.text)
        if not var:
            return
        offset_data = self._find_object_offset_assignment(lines, line, var)
        if offset_data is None:
            return
        source_line, object_name, offset_expr = offset_data
        guard_window = "\n".join(
            item.text for item in lines[source_line.index + 1 : line.index + 1]
        )
        if re.search(
            rf"\b{re.escape(offset_expr)}\b\s*(?:<|<=)\s*sizeof\s*\(\s*&?\s*{re.escape(object_name)}\s*\)",
            guard_window,
        ):
            return
        self._emit(
            issues,
            func_name,
            file_path,
            lines,
            allowed_skills,
            defect_class="out_of_range_pointer_offset",
            rule="clang_cfg_unchecked_object_offset_deref",
            line=line,
            description=f"Offset `{offset_expr}` is applied inside local object `{object_name}` and then dereferenced without a `sizeof` guard.",
            root_cause="An external offset can form a pointer outside the local object before the later access.",
            suggested_fix=f"Validate `{offset_expr} < sizeof({object_name})` and the requested access width before deriving the pointer.",
            source=source_line.text,
            sink=line.text,
            confidence=0.84,
            impact_level="high",
            positive=[
                f"line {source_line.number}: `{var}` is derived from `&{object_name}` plus `{offset_expr}`",
                f"line {line.number}: `{var}` is dereferenced",
            ],
            negative=[
                "Validator must confirm the offset is externally controlled and not already range checked."
            ],
            ast_cfg=self._ast_cfg_pack(
                lines,
                [
                    self._event(
                        "object_offset_pointer", source_line, var, offset_expr, source_line.text
                    ),
                    self._event("object_offset_access", line, var, "", line.text),
                ],
                [source_line.number, line.number],
            ),
        )

    def _maybe_emit_uninitialized_pointer_use(
        self,
        issues: List[Dict[str, Any]],
        func_name: str,
        file_path: str,
        lines: Sequence[ClangCfgLine],
        allowed_skills: Optional[Set[str]],
        line: ClangCfgLine,
    ) -> None:
        var = self._first_direct_deref_var(line.text)
        if not var:
            return
        decl_line = self._find_uninitialized_pointer_decl(lines, line, var)
        if decl_line is None:
            return
        assigns = [
            item
            for item in lines[decl_line.index + 1 : line.index]
            if re.search(rf"\b{re.escape(var)}\s*=", item.text)
        ]
        if assigns and any(not self._is_conditional_statement(lines, item) for item in assigns):
            return
        if any(
            self._is_null_guard(item.text, var)
            for item in lines[decl_line.index + 1 : line.index + 1]
        ):
            return
        assignment_note = (
            "only conditional assignments appear before use"
            if assigns
            else "no assignment appears before use"
        )
        self._emit(
            issues,
            func_name,
            file_path,
            lines,
            allowed_skills,
            defect_class="uninitialized_pointer",
            rule="clang_cfg_pointer_may_be_uninitialized_before_use",
            line=line,
            description=f"Pointer `{var}` may be read before being initialized on all local paths.",
            root_cause="The local CFG view finds a pointer declaration without an initializer and no unconditional assignment before use.",
            suggested_fix=f"Initialize `{var}` to NULL and gate every dereference on a successful assignment.",
            source=decl_line.text,
            sink=line.text,
            confidence=0.78,
            impact_level="high",
            positive=[
                f"line {decl_line.number}: `{var}` is declared without an initializer",
                f"line {line.number}: `{var}` is dereferenced; {assignment_note}",
            ],
            negative=[
                "Validator must confirm no macro or control-flow contract initializes the pointer on all paths."
            ],
            ast_cfg=self._ast_cfg_pack(
                lines,
                [
                    self._event("uninitialized_pointer_decl", decl_line, var, "", decl_line.text),
                    self._event("uninitialized_pointer_use", line, var, "", line.text),
                ],
                [decl_line.number, line.number],
            ),
        )

    def _maybe_emit_unbounded_heap_allocation(
        self,
        issues: List[Dict[str, Any]],
        func_name: str,
        file_path: str,
        lines: Sequence[ClangCfgLine],
        allowed_skills: Optional[Set[str]],
        line: ClangCfgLine,
    ) -> None:
        for api, args in self._calls(line.text):
            if api not in self._return_acquirers and not re.search(
                r"(?:malloc|calloc|alloc|realloc)$", api, re.IGNORECASE
            ):
                continue
            count_expr = self._allocation_count_expression(api, args)
            if not count_expr:
                continue
            resolved_count_expr = count_expr
            if not self._looks_external_size_expr(resolved_count_expr):
                resolved = self._resolve_recent_assignment_expr(lines, line, resolved_count_expr)
                if resolved and self._looks_external_size_expr(resolved):
                    resolved_count_expr = resolved
            if not self._looks_external_size_expr(resolved_count_expr):
                continue
            guard_window = "\n".join(
                item.text for item in lines[max(0, line.index - 12) : line.index]
            )
            if self._has_allocation_limit_guard(guard_window, resolved_count_expr):
                continue
            if self._has_small_count_bound_proof(lines, line, resolved_count_expr):
                continue
            if self._has_narrowing_bound_proof(
                lines, line, resolved_count_expr
            ) and self._allocation_has_total_local_lifetime_proof(lines, line, resolved_count_expr):
                continue
            if self._allocation_has_total_local_lifetime_proof(lines, line, resolved_count_expr):
                continue
            self._emit(
                issues,
                func_name,
                file_path,
                lines,
                allowed_skills,
                defect_class="resource_allocation_without_limits",
                rule="clang_cfg_external_size_allocation_without_limit",
                line=line,
                description=f"Heap allocation size `{resolved_count_expr}` is externally/data derived without a visible quota or protocol cap.",
                root_cause="A caller- or wire-controlled size can allocate unbounded heap memory on this local path.",
                suggested_fix="Enforce a protocol, per-client, or global maximum before allocating.",
                source=resolved_count_expr,
                sink=line.text,
                confidence=0.7,
                positive=[
                    f"line {line.number}: `{api}` allocation is driven by `{resolved_count_expr}`"
                ],
                negative=[
                    "Validator must confirm the size is externally controlled and no earlier caller-side cap dominates this path."
                ],
                ast_cfg=self._ast_cfg_pack(
                    lines,
                    [
                        self._event(
                            "unbounded_allocation", line, resolved_count_expr, api, line.text
                        )
                    ],
                    [line.number],
                ),
            )
            return

    def _maybe_emit_thread_stack_escape(
        self,
        issues: List[Dict[str, Any]],
        func_name: str,
        file_path: str,
        lines: Sequence[ClangCfgLine],
        allowed_skills: Optional[Set[str]],
        line: ClangCfgLine,
        local_aggregates: Dict[str, Tuple[ClangCfgLine, str]],
    ) -> None:
        for api, args in self._calls(line.text):
            if api != "pthread_create":
                continue
            split = self._split_args(args)
            if len(split) < 4:
                continue
            arg = split[3].strip()
            match = re.match(r"&\s*(?P<var>[A-Za-z_]\w*)$", arg)
            if not match:
                continue
            var = match.group("var")
            decl_line, type_name = local_aggregates.get(var, (None, ""))  # type: ignore[assignment]
            if decl_line is None:
                continue
            worker = split[2].strip()
            self._emit(
                issues,
                func_name,
                file_path,
                lines,
                allowed_skills,
                defect_class="stack_escape",
                rule="clang_cfg_stack_address_passed_to_thread",
                line=line,
                description=f"Stack object `{var}` is passed to thread entry `{worker}`.",
                root_cause="The spawned thread can outlive the caller's stack frame and dereference a dangling thread argument.",
                suggested_fix="Allocate the thread argument with an ownership handoff or join before returning.",
                source=f"{type_name} {var} at line {decl_line.number}",
                sink=line.text,
                confidence=0.9,
                impact_level="high",
                positive=[
                    f"line {decl_line.number}: `{var}` is a local stack object",
                    f"line {line.number}: `pthread_create` passes `&{var}` to `{worker}`",
                ],
                negative=[],
                ast_cfg=self._ast_cfg_pack(
                    lines,
                    [
                        self._event("stack_object", decl_line, var, type_name, decl_line.text),
                        self._event("thread_arg_escape", line, var, worker, line.text),
                    ],
                    [decl_line.number, line.number],
                ),
            )

    def _maybe_emit_partial_aggregate_send(
        self,
        issues: List[Dict[str, Any]],
        func_name: str,
        file_path: str,
        lines: Sequence[ClangCfgLine],
        allowed_skills: Optional[Set[str]],
        line: ClangCfgLine,
        local_aggregates: Dict[str, Tuple[ClangCfgLine, str]],
        aggregate_field_writes: Dict[str, Set[str]],
    ) -> None:
        for api, args in self._calls(line.text):
            split = self._split_args(args)
            if api not in self._send_sink_names and api not in self._copy_sink_names:
                continue
            for var, (decl_line, type_name) in local_aggregates.items():
                if not any(re.search(rf"&\s*{re.escape(var)}\b", arg) for arg in split):
                    continue
                if not any(
                    re.search(rf"sizeof\s*\(\s*{re.escape(var)}\s*\)", arg) for arg in split
                ):
                    continue
                writes = aggregate_field_writes.get(var, set())
                if "*zero_initialized*" in writes:
                    continue
                if len(writes) == 0:
                    continue
                self._emit(
                    issues,
                    func_name,
                    file_path,
                    lines,
                    allowed_skills,
                    defect_class="uninitialized_read",
                    rule="clang_cfg_partial_aggregate_sent_with_sizeof",
                    line=line,
                    description=f"Partially initialized local aggregate `{var}` is sent/copied with `sizeof({var})`.",
                    root_cause="Padding or unassigned fields can leak stale stack bytes when the whole object is serialized.",
                    suggested_fix="Zero-initialize the aggregate or serialize only initialized fields.",
                    source=f"{type_name} {var} at line {decl_line.number}",
                    sink=line.text,
                    confidence=0.86,
                    impact_level="high",
                    positive=[
                        f"line {decl_line.number}: local aggregate `{var}` is declared without initializer",
                        f"fields assigned before send: {', '.join(sorted(writes))}",
                        f"line {line.number}: `{api}` consumes `&{var}` with `sizeof({var})`",
                    ],
                    negative=[
                        "Validator must confirm the type has padding or unassigned fields relevant to the serialized boundary."
                    ],
                    ast_cfg=self._ast_cfg_pack(
                        lines,
                        [
                            self._event(
                                "aggregate_decl", decl_line, var, type_name, decl_line.text
                            ),
                            self._event("aggregate_send", line, var, api, line.text),
                        ],
                        [decl_line.number, line.number],
                    ),
                )
                return

    def _maybe_track_or_emit_alignment(
        self,
        issues: List[Dict[str, Any]],
        func_name: str,
        file_path: str,
        lines: Sequence[ClangCfgLine],
        allowed_skills: Optional[Set[str]],
        line: ClangCfgLine,
        unaligned_ptrs: Dict[str, ClangCfgLine],
    ) -> None:
        cast = re.search(
            r"\b(?:const\s+)?(?:uint(?:16|32|64)_t|int(?:16|32|64)_t|unsigned\s+int|int)\s*\*\s*"
            r"(?P<var>[A-Za-z_]\w*)\s*=\s*\([^;]*\*\s*\)\s*\([^;]*\+\s*1\s*\)",
            line.text,
        )
        if cast:
            unaligned_ptrs[cast.group("var")] = line
        for var, cast_line in list(unaligned_ptrs.items()):
            if line.index <= cast_line.index:
                continue
            if not re.search(rf"\*\s*{re.escape(var)}\b", line.text):
                continue
            self._emit(
                issues,
                func_name,
                file_path,
                lines,
                allowed_skills,
                defect_class="alignment",
                rule="clang_cfg_unaligned_integer_pointer_cast",
                line=cast_line,
                description="Byte-buffer data is cast to an integer pointer at an unaligned offset and later dereferenced.",
                root_cause="The cast requires alignment that `packet + 1` style byte offsets do not guarantee.",
                suggested_fix="Use memcpy into an aligned integer object or decode bytes explicitly.",
                source=cast_line.text,
                sink=line.text,
                confidence=0.84,
                impact_level="high",
                positive=[
                    f"line {cast_line.number}: integer pointer formed from byte offset",
                    f"line {line.number}: pointer is dereferenced",
                ],
                negative=[],
                ast_cfg=self._ast_cfg_pack(
                    lines,
                    [
                        self._event("unaligned_pointer_cast", cast_line, var, "", cast_line.text),
                        self._event("unaligned_deref", line, var, "", line.text),
                    ],
                    [cast_line.number, line.number],
                ),
            )
            unaligned_ptrs.pop(var, None)

    def _has_dynamic_array_capacity_guard(
        self,
        lines: Sequence[ClangCfgLine],
        line: ClangCfgLine,
        array_name: str,
        idx_name: str,
    ) -> bool:
        cap_candidates = {
            f"{array_name}_cap",
            f"{array_name}_capacity",
            re.sub(r"(?:_array|s|_list)$", "", array_name) + "_cap",
            re.sub(r"(?:_array|s|_list)$", "", array_name) + "_capacity",
        }
        window = lines[max(0, line.index - 28) : line.index + 1]
        for cap in cap_candidates:
            guard_line = self._last_line_matching(
                window,
                re.compile(rf"\bif\s*\(\s*{re.escape(idx_name)}\s*>=\s*{re.escape(cap)}\s*\)"),
            )
            if not guard_line:
                continue
            guarded_text = "\n".join(item.text for item in lines[guard_line.index : line.index + 1])
            if not re.search(rf"\b{re.escape(cap)}\s*=", guarded_text):
                continue
            if not re.search(rf"\b{re.escape(array_name)}\s*=", guarded_text):
                continue
            if not re.search(
                r"\b(?:calloc|malloc|realloc|_safe_calloc|_safe_malloc|_safe_realloc)\s*\(",
                guarded_text,
            ):
                continue
            if re.search(
                rf"\bnew_[A-Za-z_0-9]*(?:cap|capacity)\b\s*=.*\b{re.escape(idx_name)}\b",
                guarded_text,
            ):
                return True
            if re.search(
                rf"\b{re.escape(idx_name)}\s*/\s*\d+u?\s*\)\s*\+\s*1u?\s*\)\s*\*", guarded_text
            ):
                return True
        return False

    def _has_small_count_bound_proof(
        self,
        lines: Sequence[ClangCfgLine],
        line: ClangCfgLine,
        expr: Any,
    ) -> bool:
        text = str(expr or "")
        vars_in_expr = {
            name
            for name in re.findall(r"\b[A-Za-z_]\w*\b", text)
            if name not in {"sizeof", "size_t", "uint32_t", "uint64_t", "int"}
        }
        if not vars_in_expr:
            return False
        window = "\n".join(item.text for item in lines[max(0, line.index - 14) : line.index])
        for var in vars_in_expr:
            parser_bound = re.search(
                rf"\b{re.escape(var)}\s*=\s*[A-Za-z_]\w*(?:parse|split|count)[A-Za-z_0-9]*\s*"
                r"\([^;]*,\s*(?P<limit>\d+)u?\s*\)",
                window,
                re.IGNORECASE,
            )
            if parser_bound and int(parser_bound.group("limit")) < 1000000:
                return True
            explicit_bound = re.search(
                rf"\b{re.escape(var)}\s*(?:<=|<)\s*(?P<limit>\d+)u?\b",
                window,
            )
            if explicit_bound and int(explicit_bound.group("limit")) < 1000000:
                return True
        return False

    def _has_narrowing_bound_proof(
        self,
        lines: Sequence[ClangCfgLine],
        line: ClangCfgLine,
        expr: Any,
    ) -> bool:
        text = str(expr or "")
        if self._narrowed_origin_base(text):
            return True
        for name in self._expr_identifiers(text):
            for item in reversed(lines[max(0, line.index - 16) : line.index]):
                assign = re.search(rf"\b{re.escape(name)}\s*=\s*(?P<rhs>[^;]+);", item.text)
                if assign and self._narrowed_origin_base(assign.group("rhs")):
                    return True
                decl = re.search(
                    rf"\b(?:uint8_t|uint16_t|unsigned\s+short|unsigned\s+char)\s+{re.escape(name)}\b",
                    item.text,
                )
                if decl:
                    return True
        return False

    def _limit_mismatch_reaches_unsafe_sink(
        self,
        lines: Sequence[ClangCfgLine],
        line: ClangCfgLine,
        length_var: str,
    ) -> bool:
        later = "\n".join(item.text for item in lines[line.index + 1 : line.index + 16])
        return bool(
            re.search(
                rf"\b(?:memcpy|memmove|strncpy|read|recv|fread|malloc|calloc|_safe_malloc|_safe_calloc)\s*"
                rf"\([^;]*\b{re.escape(length_var)}\b",
                later,
            )
        )

    def _first_direct_deref_var(self, text: str) -> str:
        patterns = [
            r"\b(?P<var>[A-Za-z_]\w*)\s*->",
            r"\b(?P<var>[A-Za-z_]\w*)\s*\[",
            r"\*\s*(?P<var>[A-Za-z_]\w*)\b",
        ]
        for pattern in patterns:
            match = re.search(pattern, text)
            if match:
                return match.group("var")
        return ""

    def _find_allocation_assignment(
        self,
        lines: Sequence[ClangCfgLine],
        line: ClangCfgLine,
        var: str,
    ) -> Optional[ClangCfgLine]:
        escaped = re.escape(var)
        for item in reversed(lines[max(0, line.index - 16) : line.index]):
            prev = lines[item.index - 1] if item.index > 0 else None
            if (
                prev
                and re.search(rf"\b{escaped}\s*=\s*$", prev.text)
                and re.search(
                    r"\b[A-Za-z_]\w*(?:alloc|calloc|malloc|realloc)[A-Za-z_0-9]*\s*\(",
                    item.text,
                    re.IGNORECASE,
                )
            ):
                return item
            for api, _args in self._calls(item.text):
                if api not in self._return_acquirers and not re.search(
                    r"(?:malloc|calloc|alloc|realloc)$", api, re.IGNORECASE
                ):
                    continue
                if re.search(
                    rf"\b{escaped}\s*=\s*(?:\([^)]*\)\s*)?\b{re.escape(api)}\s*\(", item.text
                ):
                    return item
                if prev and re.search(rf"\b{escaped}\s*=\s*$", prev.text):
                    return item
        return None

    def _find_allocation_size_assignment(
        self,
        lines: Sequence[ClangCfgLine],
        line: ClangCfgLine,
        var: str,
    ) -> Optional[Tuple[ClangCfgLine, str]]:
        for item in reversed(lines[max(0, line.index - 32) : line.index]):
            match = re.search(
                rf"\b(?:[A-Za-z_][\w\s\*]*\s+)?{re.escape(var)}\s*=\s*"
                r"(?:\([^)]*\)\s*)?(?P<api>[A-Za-z_]\w*(?:alloc|malloc|calloc|realloc)[A-Za-z_0-9]*)"
                r"\s*\((?P<args>[^;]*)\)",
                item.text,
                re.IGNORECASE,
            )
            if not match:
                continue
            size_expr = self._allocation_count_expression(match.group("api"), match.group("args"))
            if size_expr:
                return item, size_expr
        return None

    def _allocation_base_from_size(
        self,
        lines: Sequence[ClangCfgLine],
        alloc_line: ClangCfgLine,
        size_expr: str,
    ) -> str:
        direct = self._narrowed_origin_base(size_expr)
        if direct:
            return direct
        for name in self._expr_identifiers(size_expr):
            for item in reversed(lines[max(0, alloc_line.index - 24) : alloc_line.index]):
                assign = re.search(
                    rf"\b{re.escape(name)}\s*=\s*(?P<expr>[^;]+);",
                    item.text,
                )
                if assign:
                    base = self._narrowed_origin_base(
                        assign.group("expr")
                    ) or self._expr_base_token(assign.group("expr"))
                    if base:
                        return base
        return ""

    def _expression_origin_base(
        self,
        lines: Sequence[ClangCfgLine],
        line: ClangCfgLine,
        expr: str,
    ) -> str:
        base = self._expr_base_token(expr)
        if base and not re.fullmatch(r"[A-Za-z_]\w*", str(expr).strip()):
            return base
        name = str(expr or "").strip()
        if re.fullmatch(r"[A-Za-z_]\w*", name):
            for item in reversed(lines[max(0, line.index - 24) : line.index]):
                assign = re.search(rf"\b{re.escape(name)}\s*=\s*(?P<rhs>[^;]+);", item.text)
                if assign:
                    return self._expr_base_token(assign.group("rhs"))
        return base

    def _looks_like_external_length_pair(
        self,
        lines: Sequence[ClangCfgLine],
        line: ClangCfgLine,
        alloc_size: str,
        copy_len: str,
    ) -> bool:
        text = f"{alloc_size} {copy_len}"
        for name in self._expr_identifiers(f"{alloc_size} {copy_len}"):
            for item in reversed(lines[max(0, line.index - 24) : line.index]):
                assign = re.search(rf"\b{re.escape(name)}\s*=\s*(?P<rhs>[^;]+);", item.text)
                if assign:
                    text += " " + assign.group("rhs")
        return bool(
            re.search(
                r"(?:header|wire|packet|payload|fragment|copy|len|length|size|count)", text, re.I
            )
        )

    @staticmethod
    def _narrowed_origin_base(expr: str) -> str:
        match = re.search(
            r"\(\s*(?:u?int(?:8|16)_t|unsigned\s+short|unsigned\s+char|short|char)\s*\)\s*(?P<src>[A-Za-z_]\w*(?:->|\.)?[A-Za-z_0-9]*)",
            str(expr or ""),
        )
        return ClangMemoryBoundsIntegerRules._expr_base_token(match.group("src")) if match else ""

    @staticmethod
    def _expr_base_token(expr: str) -> str:
        text = re.sub(r"\([^)]*\)", " ", str(expr or ""))
        candidates = re.findall(r"[A-Za-z_]\w*(?:(?:->|\.)[A-Za-z_]\w*)?", text)
        ignored = {
            "sizeof",
            "size_t",
            "uint8_t",
            "uint16_t",
            "uint32_t",
            "uint64_t",
            "int",
            "char",
            "short",
            "unsigned",
            "const",
        }
        candidates = [item for item in candidates if item not in ignored]
        if not candidates:
            return ""
        member_candidates = [item for item in candidates if "->" in item or "." in item]
        return str(member_candidates[-1] if member_candidates else candidates[-1]).lower()

    @staticmethod
    def _expr_identifiers(expr: str) -> List[str]:
        ignored = {
            "sizeof",
            "size_t",
            "uint8_t",
            "uint16_t",
            "uint32_t",
            "uint64_t",
            "int",
            "char",
            "short",
            "unsigned",
            "const",
        }
        return [
            item for item in re.findall(r"\b[A-Za-z_]\w*\b", str(expr or "")) if item not in ignored
        ]

    def _copy_length_bounded_by_alloc(
        self,
        lines: Sequence[ClangCfgLine],
        line: ClangCfgLine,
        copy_len: str,
        alloc_size: str,
    ) -> bool:
        window = "\n".join(item.text for item in lines[max(0, line.index - 12) : line.index + 1])
        copy_token = re.escape(str(copy_len).strip())
        alloc_token = re.escape(str(alloc_size).strip())
        return bool(
            re.search(rf"\b{copy_token}\b\s*(?:<=|<)\s*\b{alloc_token}\b", window)
            or re.search(rf"\bmin\s*\(\s*{copy_token}\s*,\s*{alloc_token}\s*\)", window)
            or re.search(rf"\bmin\s*\(\s*{alloc_token}\s*,\s*{copy_token}\s*\)", window)
        )

    def _find_pointer_backtrack_assignment(
        self,
        lines: Sequence[ClangCfgLine],
        line: ClangCfgLine,
        var: str,
    ) -> Optional[ClangCfgLine]:
        for item in reversed(lines[max(0, line.index - 20) : line.index]):
            decrement = re.search(rf"\b{re.escape(var)}\s*-=\s*(?P<offset>[^;]+);", item.text)
            if decrement:
                offset = decrement.group("offset")
                if re.search(
                    r"(?:offset|backtrack|prefix|count|size|len|length|window)", offset, re.I
                ):
                    guard_window = "\n".join(
                        row.text for row in lines[max(0, item.index - 10) : item.index]
                    )
                    if not re.search(
                        rf"\b{re.escape(offset.strip())}\b\s*(?:<=|<)\s*(?:[A-Za-z_]\w*len|[A-Za-z_]\w*_len|sizeof\s*\()",
                        guard_window,
                    ):
                        return item
            match = re.search(
                rf"\b(?:[A-Za-z_][\w\s\*]*\s+)?{re.escape(var)}\s*=\s*(?P<expr>[^;]*-[^;]+);",
                item.text,
            )
            if not match:
                continue
            expr = match.group("expr")
            if re.search(r"\bsizeof\s*\(", expr):
                continue
            offset_names = [
                token
                for token in self._expr_identifiers(expr.split("-", 1)[-1])
                if re.search(
                    r"(?:len|length|offset|backtrack|prefix|count|size|window)", token, re.I
                )
            ]
            if not offset_names:
                continue
            guard_window = "\n".join(
                row.text for row in lines[max(0, item.index - 10) : item.index]
            )
            if any(
                re.search(
                    rf"\b{re.escape(name)}\b\s*(?:<=|<)\s*(?:[A-Za-z_]\w*len|[A-Za-z_]\w*_len|sizeof\s*\()",
                    guard_window,
                )
                for name in offset_names
            ):
                continue
            return item
        return None

    def _find_offset_pointer_assignment(
        self,
        lines: Sequence[ClangCfgLine],
        line: ClangCfgLine,
        var: str,
    ) -> Optional[ClangCfgLine]:
        escaped = re.escape(var)
        for item in reversed(lines[max(0, line.index - 24) : line.index]):
            match = re.search(
                rf"\b(?:[A-Za-z_][\w\s\*]*\s+)?{escaped}\s*=\s*"
                r"(?P<base>[A-Za-z_]\w*)\s*\+\s*(?P<offset>[A-Za-z_]\w*(?:->|\.)?[A-Za-z_0-9]*)\s*;",
                item.text,
            )
            if match:
                return item
        return None

    @staticmethod
    def _offset_expr_from_pointer_assignment(text: str, var: str) -> str:
        match = re.search(
            rf"\b(?:[A-Za-z_][\w\s\*]*\s+)?{re.escape(var)}\s*=\s*"
            r"[A-Za-z_]\w*\s*\+\s*(?P<offset>[A-Za-z_]\w*(?:->|\.)?[A-Za-z_0-9]*)\s*;",
            str(text or ""),
        )
        return match.group("offset") if match else ""

    def _find_pointer_derivation(
        self,
        lines: Sequence[ClangCfgLine],
        line: ClangCfgLine,
        var: str,
    ) -> Optional[Tuple[ClangCfgLine, str, str]]:
        escaped = re.escape(var)
        recent = lines[max(0, line.index - 18) : line.index]
        for item in reversed(recent):
            assign = re.search(
                rf"\b{escaped}\s*=\s*(?:\([^)]*\)\s*)*(?P<base>[A-Za-z_]\w*)\s*(?P<op>[+-])\s*(?P<offset>[^;]+)\s*;",
                item.text,
            )
            if assign:
                return (
                    item,
                    assign.group("base"),
                    f"{var} = {assign.group('base')} {assign.group('op')} {assign.group('offset').strip()}",
                )
            object_addr = re.search(
                rf"\b{escaped}\s*=\s*(?:\([^)]*\)\s*)*[^;]*&\s*(?P<base>[A-Za-z_]\w*)[^;]*(?:\+|-)\s*(?P<offset>[A-Za-z_]\w*|\d+)",
                item.text,
            )
            if object_addr:
                return (
                    item,
                    object_addr.group("base"),
                    f"{var} derived from &{object_addr.group('base')}",
                )
            inc = re.search(
                rf"\b{escaped}\s*(?:\+=|=\s*{escaped}\s*\+)\s*(?P<offset>[^;]+)\s*;", item.text
            )
            if inc:
                base = self._find_pointer_alias_base(lines, item, var)
                return item, base or var, f"{var} += {inc.group('offset').strip()}"
        return None

    def _find_pointer_alias_base(
        self,
        lines: Sequence[ClangCfgLine],
        line: ClangCfgLine,
        var: str,
    ) -> str:
        escaped = re.escape(var)
        for item in reversed(lines[max(0, line.index - 12) : line.index]):
            assign = re.search(
                rf"\b{escaped}\s*=\s*(?:\([^)]*\)\s*)?(?P<base>[A-Za-z_]\w*)\s*;", item.text
            )
            if assign and assign.group("base") != var:
                return assign.group("base")
        return ""

    def _find_fixed_array_decl(
        self,
        lines: Sequence[ClangCfgLine],
        line: ClangCfgLine,
        array: str,
    ) -> Tuple[Optional[ClangCfgLine], str]:
        escaped = re.escape(array)
        for item in reversed(lines[max(0, line.index - 32) : line.index]):
            match = re.search(
                rf"\b{escaped}\s*\[\s*(?P<size>[A-Za-z_]\w*|\d+)\s*\]\s*(?:=|;)", item.text
            )
            if match:
                return item, match.group("size")
        return None, ""

    def _find_count_loop_for_index(
        self,
        lines: Sequence[ClangCfgLine],
        line: ClangCfgLine,
        index_var: str,
    ) -> Tuple[Optional[ClangCfgLine], str]:
        escaped = re.escape(index_var)
        for item in reversed(lines[max(0, line.index - 12) : line.index]):
            match = re.search(
                rf"\bfor\s*\([^;]*\b{escaped}\b[^;]*;\s*\b{escaped}\b\s*<\s*(?P<count>[A-Za-z_]\w*(?:->|\.)?[A-Za-z_0-9]*)",
                item.text,
            )
            if match:
                return item, match.group("count")
        return None, ""

    def _find_prior_full_key_lookup(
        self,
        lines: Sequence[ClangCfgLine],
        line: ClangCfgLine,
        key_var: str,
    ) -> Optional[ClangCfgLine]:
        escaped = re.escape(key_var)
        for item in reversed(lines[max(0, line.index - 32) : line.index]):
            if re.search(
                rf"\b[A-Za-z_]\w*(?:find|lookup|get|search)[A-Za-z_0-9]*\s*\([^;]*\b{escaped}\b",
                item.text,
                re.IGNORECASE,
            ):
                return item
        return None

    def _count_is_obviously_bounded(
        self,
        lines: Sequence[ClangCfgLine],
        line: ClangCfgLine,
        array: str,
        array_size: str,
        count_expr: str,
    ) -> bool:
        window = "\n".join(item.text for item in lines[max(0, line.index - 16) : line.index])
        count = re.escape(count_expr)
        array_escaped = re.escape(array)
        size_escaped = re.escape(array_size)
        if re.fullmatch(r"\d+", count_expr) and re.fullmatch(r"\d+", array_size):
            return int(count_expr) <= int(array_size)
        patterns = [
            rf"\b{count}\b\s*(?:<|<=)\s*(?:ARRAY_SIZE\s*\(\s*{array_escaped}\s*\)|sizeof\s*\(\s*{array_escaped}\s*\)|{size_escaped})",
            rf"\bif\s*\([^)]*\b{count}\b\s*>\s*(?:ARRAY_SIZE\s*\(\s*{array_escaped}\s*\)|sizeof\s*\(\s*{array_escaped}\s*\)|{size_escaped})[^)]*\)\s*(?:return|goto|break)",
            rf"\b{count}\b\s*=\s*(?:MIN|min)\s*\(\s*\b{count}\b\s*,\s*(?:ARRAY_SIZE\s*\(\s*{array_escaped}\s*\)|{size_escaped})",
        ]
        return any(re.search(pattern, window) for pattern in patterns)

    @staticmethod
    def _looks_wire_pointer_source(expr: str) -> bool:
        return bool(
            re.search(
                r"\b(?:wire|header|hdr|packet|pkt|frame|request|req|msg|message|payload)\b",
                expr,
                re.IGNORECASE,
            )
        )

    def _find_wire_pointer_assignment(
        self,
        lines: Sequence[ClangCfgLine],
        line: ClangCfgLine,
        var: str,
    ) -> Optional[ClangCfgLine]:
        escaped = re.escape(var)
        for item in reversed(lines[max(0, line.index - 16) : line.index]):
            if not re.search(rf"\b{escaped}\s*=", item.text):
                continue
            if not re.search(
                r"\([^)]*\*\s*\)|uintptr_t|intptr_t|uint64_t|uint32_t|size_t", item.text
            ):
                continue
            rhs = item.text.split("=", 1)[1]
            if self._looks_wire_pointer_source(rhs):
                return item
        return None

    def _find_object_offset_assignment(
        self,
        lines: Sequence[ClangCfgLine],
        line: ClangCfgLine,
        var: str,
    ) -> Optional[Tuple[ClangCfgLine, str, str]]:
        escaped = re.escape(var)
        for item in reversed(lines[max(0, line.index - 16) : line.index]):
            if not re.search(rf"\b{escaped}\s*=", item.text):
                continue
            match = re.search(
                r"&\s*(?P<object>[A-Za-z_]\w*)[^;]*\+\s*(?P<offset>[A-Za-z_]\w*(?:->|\.)?[A-Za-z_0-9]*)",
                item.text,
            )
            if match:
                return item, match.group("object"), match.group("offset")
        return None

    @staticmethod
    def _find_uninitialized_pointer_decl(
        lines: Sequence[ClangCfgLine],
        line: ClangCfgLine,
        var: str,
    ) -> Optional[ClangCfgLine]:
        escaped = re.escape(var)
        for item in reversed(lines[max(0, line.index - 32) : line.index]):
            if re.search(
                rf"\b(?:const\s+|volatile\s+|unsigned\s+|signed\s+|struct\s+\w+\s+)*[A-Za-z_]\w*(?:\s*\*)+\s*{escaped}\s*;",
                item.text,
            ):
                return item
        return None

    @staticmethod
    def _is_conditional_statement(lines: Sequence[ClangCfgLine], line: ClangCfgLine) -> bool:
        if re.search(r"\b(?:if|else|switch|case)\b", line.text):
            return True
        for item in reversed(lines[max(0, line.index - 3) : line.index]):
            stripped = item.text.strip()
            if not stripped or stripped in {"{", "}"}:
                continue
            return bool(re.match(r"(?:if|else|switch|case)\b", stripped))
        return False

    def _allocation_count_expression(self, api: str, args: str) -> str:
        split = self._split_args(args)
        if not split:
            return ""
        if api in {"calloc", "_safe_calloc"} and len(split) >= 2:
            return f"{split[0]} * {split[1]}"
        return str(split[0])

    @staticmethod
    def _looks_external_size_expr(expr: str) -> bool:
        clean = re.sub(r"sizeof\s*\([^)]*\)", "", expr)
        identifiers = re.findall(r"\b[A-Za-z_]\w*\b", clean)
        count_names = [
            name
            for name in identifiers
            if re.search(
                r"(?:count|cnt|num|nr|len|length|size|window|batch|segment|entry|item|client|quota)",
                name,
                re.IGNORECASE,
            )
        ]
        if not count_names:
            return False
        return not re.fullmatch(r"\d+\s*(?:\*\s*\d+)?", clean.strip())

    @staticmethod
    def _has_allocation_limit_guard(guard_window: str, expr: str) -> bool:
        lowered = guard_window.lower()
        if re.search(r"\b(?:max|limit|cap|quota|budget|threshold)\b", lowered):
            return True
        identifiers = re.findall(r"\b[A-Za-z_]\w*\b", expr)
        for name in identifiers:
            if re.search(r"(?:sizeof|malloc|calloc)", name, re.IGNORECASE):
                continue
            if re.search(
                rf"\b{re.escape(name)}\b\s*(?:<|<=|>|>=)\s*(?:\d+|[A-Za-z_]\w*MAX|MAX_[A-Za-z_]\w*)",
                guard_window,
            ):
                return True
        return False

    def _has_terminating_null_guard(
        self,
        lines: Sequence[ClangCfgLine],
        allocation_line: ClangCfgLine,
        use_line: ClangCfgLine,
        var: str,
    ) -> bool:
        """Return true only for a null branch that exits before this use.

        A null test on its own is not a proof: it might just log or recover.
        For a candidate produced from an allocation result, the false path is
        safe only when the guarded branch terminates before the dereference.
        This also handles compound guards such as ``if (!task || !frame)``.
        """

        escaped = re.escape(var)
        null_condition = re.compile(
            rf"(?:!\s*{escaped}\b|\b{escaped}\s*==\s*(?:NULL|nullptr|0)\b|\b(?:NULL|nullptr|0)\s*==\s*{escaped}\b)"
        )
        start = allocation_line.index + 1
        end = use_line.index
        for index in range(start, end):
            text = lines[index].text
            if not re.search(r"\bif\s*\(", text) or not null_condition.search(text):
                continue
            branch = text
            brace_depth = text.count("{") - text.count("}")
            cursor = index + 1
            if brace_depth > 0:
                while cursor < end and brace_depth > 0:
                    next_text = lines[cursor].text
                    branch += "\n" + next_text
                    brace_depth += next_text.count("{") - next_text.count("}")
                    cursor += 1
            if re.search(r"\b(?:return|goto)\b", branch):
                return True
        return False

    def _find_dependent_count_sink(
        self,
        lines: Sequence[ClangCfgLine],
        line: ClangCfgLine,
        count_var: str,
    ) -> Optional[ClangCfgLine]:
        escaped = re.escape(count_var)
        for item in lines[line.index + 1 : line.index + 18]:
            text = item.text
            if self._is_var_redefined(text, count_var):
                return None
            if re.search(
                rf"\b(?:memcpy|memmove|strncpy|read|recv|fread|malloc|calloc|_safe_malloc|_safe_calloc)\s*"
                rf"\([^;]*\b{escaped}\b",
                text,
            ):
                return item
            if re.search(rf"\[[^\]]*\b{escaped}\b[^\]]*\]", text):
                return item
            for api, args in self._calls(text):
                if re.search(
                    r"(?:route|dispatch|apply|process|reserve|alloc|copy|decode|parse|policy)",
                    api,
                    re.I,
                ) and re.search(
                    rf"\b{escaped}\b",
                    args,
                ):
                    return item
        return None

    @staticmethod
    def _has_overflow_guard(guard_window: str, expr: str) -> bool:
        text = str(guard_window or "")
        identifiers = re.findall(r"\b[A-Za-z_]\w*\b", str(expr or ""))
        size_names = [
            name
            for name in identifiers
            if re.search(r"(?:len|length|size|count|num|total|max)", name, re.I)
        ]
        if re.search(
            r"\b(?:SIZE_MAX|UINT32_MAX|UINT_MAX|INT_MAX|__builtin_(?:add|mul)_overflow)\b", text
        ):
            return True
        return any(
            re.search(
                rf"\b{re.escape(name)}\b\s*(?:>|>=|<|<=)\s*[^;]*(?:-\s*|/|MAX|SIZE|UINT|INT)", text
            )
            for name in size_names
        )

    @staticmethod
    def _is_compile_time_size_expr(expr: str) -> bool:
        text = str(expr or "").strip()
        if re.fullmatch(r"\d+", text) or "sizeof" in text:
            return True
        return bool(re.fullmatch(r"[A-Z_][A-Z0-9_]*(?:\s*[-+*/]\s*\d+)?", text))

    @staticmethod
    def _signature_param_names(lines: Sequence[ClangCfgLine]) -> List[str]:
        signature = next(
            (
                line.text
                for line in lines[:8]
                if "(" in line.text and not re.match(r"^(?:if|for|while|switch)\b", line.text)
            ),
            "",
        )
        match = re.search(r"\((?P<params>.*)\)", signature)
        if not match:
            return []
        names: List[str] = []
        for raw_param in match.group("params").split(","):
            param = raw_param.strip()
            if not param or param == "void" or "..." in param:
                continue
            param = re.sub(r"\[[^]]*\]", "", param)
            tokens = re.findall(r"\b[A-Za-z_]\w*\b", param)
            if not tokens:
                continue
            candidate = tokens[-1]
            if candidate in {"const", "volatile", "unsigned", "signed", "struct", "enum"}:
                continue
            names.append(candidate)
        return names
