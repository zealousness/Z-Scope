# mypy: disable-error-code="attr-defined"
"""Memory safety, bounds, pointer, and integer detector implementations."""

from __future__ import annotations

import hashlib
import json
import re
from .source_events import (
    has_terminating_guard,
    null_rejection_condition,
    ordered_lines,
    overflow_rejection_condition,
)
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
                ] + re.findall(r"\b\d+\b", expr)
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
                            f"`{assign.group('var')}` 由 `{expr}` 计算得出，随后被用作大小/长度参数；"
                            "回绕可能使分配或拷贝的边界变小。"
                        ),
                        root_cause="在证明操作数有界之前就进行了大小算术运算。",
                        suggested_fix="在算术运算前检查操作数，或使用带检查的大小辅助函数。",
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
                # Comments such as ``mmap(/*addr=*/nullptr, size, ...)`` are
                # not arithmetic.  Treating the ``*`` in a block comment as a
                # multiplication operator produced an integer-overflow lead
                # with no arithmetic operation in the source expression.
                expr = re.sub(r"/\*.*?\*/|//.*$", "", alloc_call.group("expr")).strip()
                if not re.search(r"[+*]", expr) or not self._is_high_risk_size_expr(expr, params):
                    continue
                identifiers = [
                    item
                    for item in self._IDENT_RE.findall(expr)
                    if item not in {"sizeof"} | self._allocator_names | self._reallocator_names
                ] + re.findall(r"\b\d+\b", expr)
                if identifiers and not self._has_pre_overflow_guard(lines, line.index, identifiers):
                    emit(
                        defect_class="integer_overflow",
                        rule="inline_allocation_size_overflow",
                        line=line,
                        description="分配大小以内联的、未经检查的加法/乘法计算得出。",
                        root_cause="分配表达式可能在任何分配器看到它之前就发生回绕。",
                        suggested_fix="在分配表达式之前校验操作数，或使用带检查的算术运算。",
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
            called = re.search(rf"\b(?P<api>{self._names_pattern(self._calloc_names)})\s*\(", clean)
            # ISO/POSIX calloc performs the nmemb*size overflow check itself.
            # Keep the rule for configured calloc-like wrappers whose contract
            # does not establish that property, but do not report libc calloc.
            if called and called.group("api") == "calloc":
                continue
            args = call.group("args")
            identifiers = [
                item
                for item in self._IDENT_RE.findall(args)
                if item not in {"calloc", "sizeof", "NULL"}
            ]
            if (
                len(identifiers) >= 2
                and any(item in params for item in identifiers)
                and not self._has_pre_overflow_guard(lines, line.index, identifiers)
            ):
                emit(
                    defect_class="integer_overflow",
                    rule="calloc_product_overflow",
                    line=line,
                    description="类 calloc 的分配对两个由调用方决定大小的操作数相乘，且缺少可见的预先检查。",
                    root_cause="元素个数与大小的乘积可能在分配前溢出。",
                    suggested_fix="在调用 calloc 之前检查 `count <= SIZE_MAX / elem_size`，或依赖已被证明的带检查的封装。",
                    source=args.strip(),
                    sink=clean.strip(),
                    confidence=0.67,
                    positive=[f"line {line.number}: calloc-like call `{clean.strip()}`"],
                    negative=self._guard_evidence(lines, line.index, identifiers),
                )

    def _rule_double_and_invalid_free(self, lines: List[CodeLine], emit) -> None:
        lines = ordered_lines(lines, CodeLine)
        last_free: Dict[str, CodeLine] = {}
        pointer_owners = self._pointer_owner_vars(lines)
        signature = lines[0].text if lines else ""
        pointer_owners.update(re.findall(r"\*\s*([A-Za-z_]\w*)\s*(?:,|\))", signature))
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
                    description=f"`{arg}` 被释放，尽管它并不是基础的所有者指针。",
                    root_cause="释放函数接收到了一个内部或栈地址表达式。",
                    suggested_fix="只释放分配器返回的、拥有所有权的基础指针。",
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
                    description=f"`{arg}` 在同一条本地路径上被释放两次。",
                    root_cause="在两次释放之间没有看到对所有者表达式的重新赋值或置空。",
                    suggested_fix="删除重复的释放，或在第一次释放后清除所有权。",
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
                    description=f"`{var}` 在同一条本地路径上被释放两次。",
                    root_cause="在两次释放之间没有看到对所有者变量的重新赋值或置空。",
                    suggested_fix="删除重复的释放，或在第一次释放后将所有权设置为 NULL。",
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
            create = re.search(
                self._literal_api_pattern(r"\bpthread_create\s*\((?P<args>[^;]+)\)"), line.text
            )
            if create:
                for var, decl in locals_seen.items():
                    if f"&{var}" in create.group("args") and decl.index < line.index:
                        emit(
                            defect_class="stack_escape",
                            rule="stack_address_to_thread",
                            line=line,
                            description=f"栈上局部变量 `{var}` 的地址被传入一个新线程。",
                            root_cause="该线程可能比拥有该参数的栈帧存活得更久。",
                            suggested_fix="分配一个堆上持有的参数，或在从该栈帧返回前进行 join。",
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
                            description=f"栈上局部变量 `{var}` 的地址被传入保留/异步 API `{retaining_call}`。",
                            root_cause="被调用者的名称表明它可能在此栈帧返回后存储、注册、入队或异步使用该借用地址。",
                            suggested_fix="传入堆上持有的存储、把值拷贝进被调用者持有的存储，或证明该 API 作为输出参数同步消费该地址。",
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
                    description=f"函数返回了栈上局部变量 `{ret.group('var')}` 的地址。",
                    root_cause="返回的指针指向在函数返回时即被销毁的存储。",
                    suggested_fix="返回持有所有权的堆存储，或写入调用方提供的存储。",
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
                self._semantic_api_pattern(
                    rf"\bint\s+(?P<var>[A-Za-z_]\w*)\s*=\s*(?:recv|read|{user_recv})\s*\("
                ),
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
                    self._literal_api_pattern(
                        rf"\b(?:memcpy|memmove|{user_io_len})\s*\([^;]*\b{re.escape(size_var)}\b"
                    ),
                    line.text,
                ):
                    emit(
                        defect_class="signed_unsigned",
                        rule="negative_length_cast_to_size_t",
                        line=cast_line,
                        description=f"有符号长度 `{src_var}` 被转换为 size_t 并随后用作拷贝/IO 长度。",
                        root_cause="负的错误值可能变成非常大的无符号大小。",
                        suggested_fix=f"在转换为 size_t 之前检查 `{src_var} >= 0` 以及上界。",
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
                    description="数组写入使用了 `array[sizeof(array)]` 作为下标，越过数组末尾一个元素。",
                    root_cause="sizeof(array) 是字节数，位于从零开始的下标范围之外。",
                    suggested_fix="对终止符使用 `sizeof(array) - 1`，或使用感知长度的辅助函数。",
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
                and not self._is_compile_time_stack_extent(vla.group("expr"))
                and re.search(r"[+*]|[A-Za-z_]\w*", vla.group("expr"))
            ):
                emit(
                    defect_class="stack_overflow",
                    rule="unbounded_vla_or_stack_array",
                    line=line,
                    description="栈数组大小由运行时表达式得出，且缺少可见的上限。",
                    root_cause="由调用方控制或依赖数据的栈分配可能耗尽栈空间。",
                    suggested_fix="在栈分配之前限制大小，或分配有界的堆存储。",
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
                    description="可能未对齐的字节指针被转换为整数指针并被解引用。",
                    root_cause="该转换所要求的对齐，字节偏移表达式并不能保证。",
                    suggested_fix="使用 memcpy 拷贝到已对齐的局部整数，或按字节解码。",
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
                        description="可能未对齐的字节指针被转换为整数指针并随后被解引用。",
                        root_cause="该转换所要求的对齐，字节偏移表达式并不能保证。",
                        suggested_fix="使用 memcpy 拷贝到已对齐的局部整数，或按字节解码。",
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
                if re.search(
                    self._literal_api_pattern(rf"\bmemset\s*\(\s*&{re.escape(var)}\s*,"), line.text
                ):
                    struct_locals[var] = (decl_line, field_writes, True)
                elif re.search(rf"\b{re.escape(var)}\.[A-Za-z_]\w*\s*=", line.text):
                    struct_locals[var] = (decl_line, field_writes + 1, has_memset)
                elif re.search(
                    self._semantic_api_pattern(
                        rf"\b(?:send|write|{self._names_pattern(getattr(self, '_user_send_sink_names', set()) or set())})\s*\([^;]*&{re.escape(var)}\s*,\s*sizeof\s*\(\s*{re.escape(var)}\s*\)"
                    ),
                    line.text,
                ):
                    if not has_memset and field_writes > 0:
                        emit(
                            defect_class="uninitialized_read",
                            rule="partial_struct_sent",
                            line=line,
                            description=f"`{var}` 仅被部分初始化，随后使用 sizeof 进行发送/拷贝。",
                            root_cause="填充字节或未赋值的字段可能泄漏陈旧的栈字节。",
                            suggested_fix="在字段赋值之前将结构体零初始化，或显式序列化各字段。",
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
        window = lines[max(0, idx - 12) : idx]
        return has_terminating_guard(
            window,
            len(window),
            lambda condition: overflow_rejection_condition(condition, operand_list),
            lookback=len(window) or 1,
        )

    def _has_post_wrap_check(
        self, lines: List[CodeLine], idx: int, var: str, operands: Iterable[str]
    ) -> bool:
        window = lines[idx + 1 : idx + 6]
        operand_list = [item for item in operands if item]
        return has_terminating_guard(
            window,
            len(window),
            lambda condition: any(
                re.search(
                    rf"\b{re.escape(var)}\b\s*<\s*\b{re.escape(operand)}\b",
                    condition,
                )
                for operand in operand_list
            ),
            lookback=len(window) or 1,
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
    def _is_compile_time_stack_extent(expr: str) -> bool:
        text = str(expr or "").strip()
        if re.fullmatch(r"sizeof\s*\([^()]+\)", text):
            return True
        constant = r"(?:[A-Za-z_]\w*::)*(?:[A-Z_][A-Z0-9_]*|k[A-Z][A-Za-z0-9_]*)"
        return bool(re.fullmatch(rf"{constant}(?:\s*[-+*/]\s*\d+)?", text))

    def _guard_evidence(
        self, lines: List[CodeLine], idx: int, operands: Iterable[str]
    ) -> List[str]:
        if self._has_pre_overflow_guard(lines, idx, operands):
            return [
                "nearby SIZE_MAX/UINT_MAX precondition may guard this arithmetic; validator must prove it"
            ]
        return []


class GraphMemoryBoundsIntegerRules:
    @staticmethod
    def _graph_call_arguments(value: str) -> List[str]:
        arguments: List[str] = []
        current: List[str] = []
        depth = 0
        for char in value:
            if char in "([{":
                depth += 1
            elif char in ")]}" and depth:
                depth -= 1
            if char == "," and depth == 0:
                arguments.append("".join(current).strip())
                current = []
                continue
            current.append(char)
        if current or value.strip():
            arguments.append("".join(current).strip())
        return arguments

    def _emit_callee_external_length_to_buffer_candidate(
        self,
        view: FunctionView,
        issues: List[Dict[str, Any]],
    ) -> None:
        caller_text = "\n".join(line.text for line in view.lines)
        caller_params = set(self._signature_param_names(view.signature))
        for line in view.lines:
            for callee_name in self._called_names(line.text):
                call = re.search(
                    rf"\b{re.escape(callee_name)}\s*\((?P<args>[^;]*)\)\s*;?",
                    line.text,
                )
                if not call:
                    continue
                arguments = self._graph_call_arguments(call.group("args"))
                if len(arguments) < 3:
                    continue
                length_index = next(
                    (
                        index
                        for index, argument in enumerate(arguments)
                        if re.search(r"(?:->|\.)[A-Za-z_0-9]*(?:len|length|size)\b", argument, re.I)
                    ),
                    None,
                )
                if length_index is None or length_index == 0:
                    continue
                destination_index = length_index - 1
                destination = arguments[destination_index]
                callee = self._view_for(callee_name)
                if callee is None:
                    continue
                callee_params = self._signature_param_names(callee.signature)
                if length_index >= len(callee_params) or destination_index >= len(callee_params):
                    continue
                destination_param = callee_params[destination_index]
                length_param = callee_params[length_index]
                callee_text = "\n".join(item.text for item in callee.lines)
                index_match = re.search(
                    rf"\b(?P<index>[A-Za-z_]\w*)\s*<\s*{re.escape(length_param)}\b",
                    callee_text,
                )
                if not index_match:
                    continue
                index_name = index_match.group("index")
                bounded_write = bool(
                    re.search(
                        rf"\b{re.escape(destination_param)}\s*\+\s*{re.escape(index_name)}\b"
                        rf"[^;]*(?:{re.escape(length_param)}\s*-\s*{re.escape(index_name)})",
                        callee_text,
                        re.S,
                    )
                )
                if not bounded_write:
                    continue
                # Accept a direct caller buffer parameter or a transparent
                # ternary alias between that parameter and a fixed local array.
                destination_from_caller = destination in caller_params
                alias = re.search(
                    rf"\b{re.escape(destination)}\s*=\s*(?P<external>[A-Za-z_]\w*)\s*\?\s*"
                    rf"(?P=external)\s*:\s*(?P<fallback>[A-Za-z_]\w*)\s*;",
                    caller_text,
                )
                if alias and alias.group("external") in caller_params:
                    destination_from_caller = True
                if not destination_from_caller:
                    continue
                length_expr = arguments[length_index]
                before = "\n".join(item.text for item in view.lines[: line.index])
                if re.search(
                    rf"{re.escape(length_expr)}\s*<=?\s*(?:[A-Za-z_]\w*(?:len|size|capacity)|sizeof\s*\()",
                    before,
                    re.I,
                ):
                    continue
                issues.append(
                    self._issue(
                        defect_class="bounds",
                        rule="caller_limit_indexes_fixed_local_array",
                        view=view,
                        line=line,
                        description=(
                            f"外部长度 `{length_expr}` 被传入 `{callee_name}` 作为写入长度，"
                            f"但调用方没有将它约束到 `{destination}` 的容量。"
                        ),
                        root_cause="跨函数写入契约使用协议长度控制目标缓冲区，而调用方已知的输出容量未参与该调用。",
                        suggested_fix="在调用前将协议长度与输出容量比较，或把容量传入被调用方并在写入循环中强制检查。",
                        source=length_expr,
                        sink=line.text.strip(),
                        confidence=0.91,
                        impact_level="high",
                        positive=[
                            f"line {line.number}: `{length_expr}` is passed as the callee write bound",
                            f"{callee_name}: `{destination_param}` is advanced while `{index_name} < {length_param}`",
                            f"{callee_name}: the remaining write length is `{length_param} - {index_name}`",
                            "no caller-side comparison to the output capacity is visible",
                        ],
                        evidence={
                            "path": {
                                "caller": view.name,
                                "callee": callee_name,
                                "source_line": line.number,
                                "sink_line": line.number,
                                "complete_in_function": False,
                                "path_constraints": [
                                    "direct exact callee body exposes destination-plus-offset and remaining-length write contract"
                                ],
                            }
                        },
                    )
                )
                return

    def _emit_uninitialized_output_candidate(
        self,
        view: FunctionView,
        issues: List[Dict[str, Any]],
    ) -> None:
        text = "\n".join(line.text for line in view.lines)
        if "memset" in text and self._semantic_call_allowed("memset", "copy"):
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
                    description="一个栈结构体在仅初始化了部分字段后就被拷贝到输出参数。",
                    root_cause="未初始化的填充字节或字段可能泄漏陈旧的栈数据，或产生不确定的 API 结果。",
                    suggested_fix="在填充字段之前对临时结构体进行零初始化，或在拷贝出去之前为每个字段赋值。",
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
        array_size_allowed = self._semantic_call_allowed("ARRAY_SIZE", "standard_operation")
        array_size_name = "ARRAY_SIZE" if array_size_allowed else "(?!)"
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
                if (array_size_allowed and "ARRAY_SIZE" in guard_text) or re.search(
                    rf"\b{re.escape(limit_name)}\s*<=\s*(?:{re.escape(array_limit)}|{array_size_name}|sizeof)",
                    guard_text,
                ):
                    continue
                issues.append(
                    self._issue(
                        defect_class="bounds",
                        rule="caller_limit_indexes_fixed_local_array",
                        view=view,
                        line=local_access,
                        description="由调用方控制的上限用于索引固定大小的局部数组，但没有证明它处于局部容量之内。",
                        root_cause="循环上界来自配置或函数参数，而临时数组具有更小的固定容量。",
                        suggested_fix="在索引之前将该配置上限钳制到局部数组长度。",
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
            if (array_size_allowed and "ARRAY_SIZE" in guard_text) or re.search(
                rf"\b{re.escape(limit_name)}\s*<=\s*(?:{array_size_name}|sizeof)", guard_text
            ):
                continue
            issues.append(
                self._issue(
                    defect_class="bounds",
                    rule="caller_limit_indexes_fixed_member_array",
                    view=view,
                    line=access_line,
                    description="由调用方控制的上限用于索引固定大小的成员数组，但没有证明它处于数组大小之内。",
                    root_cause="循环上界是函数参数或协议上限，而被索引的成员有其自己的固定容量。",
                    suggested_fix="在索引之前将循环上界钳制到目标数组长度。",
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
                description="缓存的组指针被复用，而每次迭代的组下标却在变化。",
                root_cause="遍历状态从一个下标维度刷新，却被用在另一个维度上，因此后续迭代可能读取错误的组。",
                suggested_fix="每当组下标变化时重新计算组指针，或让组和成员都从同一个规范下标推导得出。",
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
                    self._literal_api_pattern(
                        rf"\b{re.escape(idx_name)}\s*(?:<|<=)\s*(?:ARRAY_SIZE\s*\(\s*{re.escape(array_name)}\s*\)|[A-Z][A-Z0-9_]*(?:MAX|LIMIT|COUNT|NUM)[A-Z0-9_]*)"
                    ),
                    guard_text,
                )
                or re.search(
                    self._literal_api_pattern(
                        rf"\b{re.escape(idx_name)}\s*>?=\s*(?:ARRAY_SIZE\s*\(\s*{re.escape(array_name)}\s*\)|[A-Z][A-Z0-9_]*(?:MAX|LIMIT|COUNT|NUM)[A-Z0-9_]*)"
                    ),
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
                    description="公开的或由调用方提供的下标直接索引固定大小的全局数组，且缺少可见的上界检查。",
                    root_cause="该函数在证明下标参数处于其后备全局数组容量之内前就信任了它。",
                    suggested_fix="在索引前依据 ARRAY_SIZE/具体最大值拒绝或钳制该下标。",
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
    def _maybe_emit_unchecked_wait_status_read(
        self,
        issues: List[Dict[str, Any]],
        func_name: str,
        file_path: str,
        lines: Sequence[ClangCfgLine],
        allowed_skills: Optional[Set[str]],
        line: ClangCfgLine,
    ) -> None:
        use = re.search(
            r"\bW(?:IFEXITED|EXITSTATUS|IFSIGNALED|TERMSIG|IFSTOPPED|STOPSIG)\s*"
            r"\(\s*(?P<status>[A-Za-z_]\w*)\s*\)",
            line.text,
        )
        if not use or not self._semantic_call_allowed("waitpid", "standard_operation"):
            return
        status = use.group("status")
        declaration = next(
            (
                item
                for item in reversed(lines[: line.index])
                if re.search(rf"\bint\s+{re.escape(status)}\s*;", item.text)
            ),
            None,
        )
        if declaration is None:
            return
        wait_line = next(
            (
                item
                for item in lines[declaration.index + 1 : line.index]
                if re.search(
                    rf"\bwaitpid\s*\([^;]*&\s*{re.escape(status)}\b[^;]*\)",
                    item.text,
                )
            ),
            None,
        )
        if wait_line is None:
            return
        if re.search(r"\b(?:if|while)\s*\([^)]*waitpid\s*\(", wait_line.text):
            return
        if re.search(r"(?:^|[^=!<>])=\s*waitpid\s*\(", wait_line.text):
            return
        between = "\n".join(item.text for item in lines[declaration.index + 1 : line.index])
        if re.search(rf"\b{re.escape(status)}\s*=", between):
            return
        self._emit(
            issues,
            func_name,
            file_path,
            lines,
            allowed_skills,
            defect_class="uninitialized_read",
            rule="zscope.c_cpp.cpp_clang_cfg.waitpid_status_read_without_success_check",
            line=line,
            description=f"`waitpid` 的返回值未检查，随后读取了输出状态 `{status}`。",
            root_cause="waitpid 失败时不保证写入状态输出，WIF*/WEXITSTATUS 随后可能读取未初始化的栈值。",
            suggested_fix="检查 waitpid 返回目标 pid；对 EINTR 重试，并在任何 WIF*/W*STATUS 使用前处理失败。",
            source=wait_line.text,
            sink=line.text,
            confidence=0.93,
            impact_level="medium",
            positive=[
                f"line {declaration.number}: `{status}` is declared without initialization",
                f"line {wait_line.number}: waitpid writes `{status}` but its return value is ignored",
                f"line {line.number}: a wait-status macro reads `{status}`",
            ],
            negative=[],
            ast_cfg=self._ast_cfg_pack(
                lines,
                [
                    self._event("uninitialized_status", declaration, status, "", declaration.text),
                    self._event("unchecked_waitpid", wait_line, status, "waitpid", wait_line.text),
                    self._event("wait_status_read", line, status, "", line.text),
                ],
                [declaration.number, wait_line.number, line.number],
            ),
        )

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
            if re.search(
                self._literal_api_pattern(rf"\b{re.escape(var)}\s*=\s*strchr\s*\("), item.text
            ):
                assign_line = item
                break
        if assign_line is None:
            return
        between = lines[assign_line.index + 1 : line.index]
        if any(re.search(rf"\b{re.escape(var)}\s*(?:-|\[|->|\.)", item.text) for item in between):
            return
        if has_terminating_guard(
            between,
            len(between),
            lambda condition: null_rejection_condition(condition, var),
            lookback=len(between) or 1,
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
            description=f"来自 `strchr` 的 `{var}` 被使用，但缺少可见的空指针检查。",
            root_cause="当分隔符不存在时，`strchr` 返回 NULL，后续的指针运算或下标索引会对这个由 NULL 派生的值进行解引用。",
            suggested_fix=f"在进行指针运算、下标索引或解引用之前检查 `{var}` 是否为 NULL。",
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
            self._literal_api_pattern(
                rf"\b{re.escape(idx_name)}\s*(?:<|<=|>=|>)\s*"
                rf"(?:ARRAY_SIZE\s*\(\s*{re.escape(array_name)}\s*\)|"
                r"[A-Z][A-Z0-9_]*(?:MAX|LIMIT|COUNT|NUM|CORES|SIZE)[A-Z0-9_]*)"
            ),
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
            description="由调用方提供的下标参数直接索引固定大小的全局数组，且缺少可见的上界检查。",
            root_cause="该函数在证明下标参数处于其后备全局数组容量之内前就信任了它。",
            suggested_fix="在索引前依据 ARRAY_SIZE 或具体的全局数组容量拒绝或钳制该下标。",
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
            self._literal_api_pattern(
                r"\bmemcpy\s*\(\s*&\s*(?P<count>[A-Za-z_]\w*)\s*,\s*"
                r"(?P<src>[A-Za-z_]\w*)\s*\+\s*(?P<offset>\d+)\s*,\s*sizeof\s*\(\s*(?P=count)\s*\)\s*\)"
            ),
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
            description=f"协议字段 `{copy.group('count')}` 从 `{copy.group('src')} + {offset}` 读取，且缺少可见的 magic/签名防护。",
            root_cause="解析器在使用依赖性的协议字段之前，没有用预期的 magic 值证明记录布局。",
            suggested_fix="在读取依赖性的计数字段之前，先解码并校验 magic/签名字段。",
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
                f"`{length_var}` 受 `{limit_match.group('limit')}` 约束，而 `{count_var}` 则是依据 `{spec_match.group('spec')}` 进行检查。"
            ),
            root_cause="固定的字节缓存上限可能以不同于所声明的元素计数规格的方式拒绝或确定分配大小。",
            suggested_fix="在计算字节数之前先依据规格校验元素计数，并从同一契约推导字节上限。",
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
                "大小/规格上限不匹配，且在本地 CFG 中没有可见的不安全汇点" if audit_only else ""
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
                    self._semantic_api_pattern(
                        r"\b(?P<var>[A-Za-z_]\w*)\s*=\s*(?:\([^)]*\)\s*)?"
                        r"(?P<api>(?:malloc|calloc|realloc|strdup))\s*\((?P<expr>[^;]*(?:\+|\*)[^;]*)\)"
                    ),
                    line.text,
                    re.IGNORECASE,
                ),
                "allocation_size_arithmetic_without_overflow_guard",
                "分配大小通过算术运算计算，但缺少可见的溢出防护。",
            ),
            (
                re.search(
                    r"\b(?:size_t|uint(?:32|64)_t|unsigned(?:\s+int)?|int)\s+"
                    r"(?P<var>[A-Za-z_]\w*(?:len|size|total)[A-Za-z_0-9]*)\s*=\s*(?P<expr>[^;]*(?:sizeof\s*\([^)]*\)|[A-Za-z_]\w*)\s*\+\s*[^;]+);",
                    line.text,
                    re.IGNORECASE,
                ),
                "size_addition_without_overflow_guard",
                "大小表达式使用了加法，但缺少可见的溢出防护。",
            ),
            (
                re.search(
                    r"\(\s*uint32_t\s*\)\s*(?P<expr>[A-Za-z_]\w*(?:len|length|size)[A-Za-z_0-9]*)",
                    line.text,
                ),
                "narrowing_size_cast_without_range_guard",
                "一个类似大小的值被窄化转换为 uint32_t，但缺少可见的范围防护。",
            ),
        ]
        for match, rule, description in patterns:
            if not match:
                continue
            expr = match.groupdict().get("expr") or line.text
            if self._has_overflow_guard(lines, line, expr):
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
                root_cause="对大小或长度值进行的整数算术运算可能在分配、拷贝或序列化之前发生回绕。",
                suggested_fix="在计算分配/拷贝大小或进行窄化转换之前检查算术边界。",
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
            self._semantic_api_pattern(
                rf"\b(?:int|ssize_t)\s+(?P<var>[A-Za-z_]\w*)\s*=\s*"
                rf"(?:recv|read|recvfrom|{self._names_pattern(getattr(self, '_user_recv_source_names', set()) or set())})\s*\("
            ),
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
                description=f"有符号 IO 长度 `{src_var}` 被转换为 `size_t` 作为 `{size_var}`，并到达拷贝长度。",
                root_cause="负的错误返回值在该转换之后可能变成非常大的无符号大小。",
                suggested_fix=f"在转换为 `size_t` 之前检查 `{src_var} >= 0` 以及上界。",
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
            description=f"`{array}[sizeof({array})]` 会越过数组末尾写入一个元素。",
            root_cause="`sizeof(array)` 是字节数，位于从零开始的下标范围之外。",
            suggested_fix=f"对终止符使用 `sizeof({array}) - 1`，或使用感知长度的辅助函数。",
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
            self._literal_api_pattern(
                r"\bmemset\s*\(\s*&?\s*(?P<var>[A-Za-z_]\w*)\s*,\s*0\s*,\s*sizeof\s*\(\s*(?P=var)\s*\)\s*\)"
            ),
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
            description=f"栈数组 `{match.group('array')}` 使用了运行时大小 `{size}`，但缺少可见的上限。",
            root_cause="由调用方控制或依赖数据的栈分配可能耗尽栈空间或使栈溢出。",
            suggested_fix="在栈分配之前限制大小，或分配有界的堆存储。",
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
            self._literal_api_pattern(
                r"\b(?P<api>memcpy|memmove)\s*\(\s*(?P<dst>[A-Za-z_]\w*)\s*,\s*[^,]+,\s*(?P<len>[^)]+)\)"
            ),
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
        # A narrowing claim needs an actual conversion on the allocation
        # operand. Words such as 'length' or 'packet' are not type evidence.
        if not alloc_base:
            return
        if re.sub(r"\s+", "", copy_len) == re.sub(r"\s+", "", alloc_size):
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
                f"`{dst}` 是从窄化后的大小 `{alloc_size}` 分配的，但拷贝时却使用了原始长度 `{copy_len}`。"
            ),
            root_cause="被截断的分配大小可能小于后续的拷贝长度。",
            suggested_fix="使用与拷贝相同的、经过检查的长度进行分配，或拒绝不适合分配类型的值。",
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
            self._literal_api_pattern(
                r"\b(?P<api>memcpy|memmove)\s*\(\s*[^,]+,\s*(?P<src>[A-Za-z_]\w*)\s*,\s*(?P<len>[^)]+)\)"
            ),
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
            description=f"`{src}` 由未经检查的偏移 `{offset_expr}` 派生，并以 `{copy_len}` 进行拷贝。",
            root_cause="代码既没有针对后备输入缓冲区校验偏移，也没有校验偏移加长度。",
            suggested_fix="在派生源指针之前，要求 `offset <= buffer_len` 且 `copy_len <= buffer_len - offset`。",
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
            self._literal_api_pattern(
                r"\b(?P<api>memcpy|memmove|memset|strncpy)\s*\(\s*(?P<args>.*)\)"
            ),
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
            description=f"`{pointer_arg}` 通过减去一个未经检查的偏移派生而来，随后被 `{api}` 使用。",
            root_cause="由调用方或线上数据控制的回溯可能使指针移动到缓冲区起始位置之前。",
            suggested_fix="在派生指针之前，依据可用的缓冲区长度校验回溯量/偏移。",
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
            description=f"`{api}` 被调用并作用于非所有者的指针表达式 `{cleaned}`。",
            root_cause="释放函数接收到的是内部、栈或经过调整的指针，而不是拥有所有权的分配基址。",
            suggested_fix="只释放分配器返回的、拥有所有权的基础指针。",
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
            description=f"`{api}` 被调用并作用于 `{var}`，而它是通过指针运算从 `{base}` 派生而来的。",
            root_cause="释放函数接收到的是指向内部/调整后地址的别名，而不是拥有所有权的分配基址。",
            suggested_fix=f"在把 `{base}` 作为所有者传给 `{api}` 的同时，另用一个非持有指针游标处理偏移。",
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
            description=f"分配结果 `{var}` 在可见的空指针检查之前就被使用了。",
            root_cause="分配的返回值可能为 NULL，而本地路径却先对其解引用或索引。",
            suggested_fix=f"在进行任何解引用、索引或写入之前，检查 `{var}` 是否为 NULL。",
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
            description=f"循环计数 `{count_expr}` 用于索引固定数组 `{array}[{array_size}]`，但缺少可见的数组大小防护。",
            root_cause="由外部派生的计数可能驱动写入越过本地固定大小的缓冲区。",
            suggested_fix=f"在循环之前依据 `ARRAY_SIZE({array})` 校验 `{count_expr}`，或钳制循环上界。",
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
            self._literal_api_pattern(
                r"\bstrncpy\s*\(\s*(?P<dst>[A-Za-z_]\w*\s*->\s*(?:key|name|id)|[A-Za-z_]\w*\.(?:key|name|id))\s*,\s*"
                r"(?P<src>[A-Za-z_]\w*)\s*,\s*(?P<limit>\d+|[A-Z_][A-Z0-9_]*)\s*\)"
            ),
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
            self._literal_api_pattern(
                rf"\bstrlen\s*\(\s*{re.escape(src)}\s*\)\s*(?:<|<=)\s*{re.escape(trunc.group('limit'))}\b"
            ),
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
            description=f"`{src}` 以完整长度进行查找，却通过固定长度的 `{trunc.group('dst')}` 存储。",
            root_cause="查找和插入使用了不同的键等价域，因此较长的键可能发生碰撞或绕过已存在的记录。",
            suggested_fix="在查找之前校验键长度，或对查找和插入使用相同的有界键表示。",
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
        if direct and self._looks_wire_pointer_source(line.text):
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
            description="整数经过显式指针转换后被解引用，需要核验地址来源与有效范围。",
            root_cause="整数转换不能单独证明地址有效；需要检查输入来源、对象身份及边界。",
            suggested_fix="核验该值对应的对象或句柄及其存活范围，再允许解引用。",
            source=source_line.text,
            sink=line.text,
            confidence=0.88,
            impact_level="critical",
            positive=[
                f"line {source_line.number}: explicitly converted integer is cast into pointer `{var}`",
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
            description=f"偏移 `{offset_expr}` 被应用于局部对象 `{object_name}` 内部，随后在没有 `sizeof` 防护的情况下被解引用。",
            root_cause="外部偏移可能在后续访问之前形成指向局部对象之外的指针。",
            suggested_fix=f"在派生指针之前校验 `{offset_expr} < sizeof({object_name})` 以及请求的访问宽度。",
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
        if any(self._conditional_assignment_dominates_use(lines, item, line) for item in assigns):
            return
        if self._out_parameter_initializes_before_guarded_use(lines, decl_line, line, var):
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
            description=f"指针 `{var}` 可能在所有本地路径上都未被初始化就被读取了。",
            root_cause="本地 CFG 视图发现一个没有初始化器的指针声明，并且在被使用前不存在无条件赋值。",
            suggested_fix=f"将 `{var}` 初始化为 NULL，并让每次解引用都依赖于一次成功的赋值。",
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
            if api not in self._return_acquirers:
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
                description=f"堆分配大小 `{resolved_count_expr}` 由外部/数据派生，且缺少可见的配额或协议上限。",
                root_cause="由调用方或线上数据控制的大小可能在此本地路径上分配不受限制的堆内存。",
                suggested_fix="在分配之前强制执行协议、每客户端或全局的最大值。",
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
            if api != "pthread_create" or not self._semantic_call_allowed(api, "thread_create"):
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
                description=f"栈对象 `{var}` 被传入线程入口 `{worker}`。",
                root_cause="被创建的线程可能比调用方的栈帧存活得更久，并解引用一个悬空的线程参数。",
                suggested_fix="以所有权移交的方式分配线程参数，或在返回前进行 join。",
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
                    description=f"部分初始化的局部聚合 `{var}` 用 `sizeof({var})` 进行发送/拷贝。",
                    root_cause="当整个对象被序列化时，填充字节或未赋值的字段可能泄漏陈旧的栈字节。",
                    suggested_fix="对聚合进行零初始化，或仅序列化已初始化的字段。",
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
                description="字节缓冲区数据在未对齐的偏移处被转换为整数指针并随后被解引用。",
                root_cause="该转换所要求的对齐，`packet + 1` 这样的字节偏移并不能保证。",
                suggested_fix="使用 memcpy 拷贝到已对齐的整数对象，或显式按字节解码。",
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
                self._semantic_api_pattern(r"\b(?:calloc|malloc|realloc)\s*\("),
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
                self._literal_api_pattern(
                    rf"\b(?:memcpy|memmove|strncpy|read|recv|fread|malloc|calloc)\s*"
                    rf"\([^;]*\b{re.escape(length_var)}\b"
                ),
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
                    self._semantic_api_pattern(r"\b(?:malloc|calloc|realloc|strdup)\s*\("),
                    item.text,
                    re.IGNORECASE,
                )
            ):
                return item
            for api, _args in self._calls(item.text):
                if api not in self._return_acquirers:
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
                self._semantic_api_pattern(
                    rf"\b(?:[A-Za-z_][\w\s\*]*\s+)?{re.escape(var)}\s*=\s*"
                    r"(?:\([^)]*\)\s*)?(?P<api>(?:malloc|calloc|realloc|strdup))"
                    r"\s*\((?P<args>[^;]*)\)"
                ),
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
                    base = self._narrowed_origin_base(assign.group("expr"))
                    if not base and re.search(
                        rf"\b(?:u?int(?:8|16)_t|unsigned\s+(?:short|char)|short|char)\s+{re.escape(name)}\s*=",
                        item.text,
                    ):
                        base = self._expr_base_token(assign.group("expr"))
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
            or re.search(
                self._literal_api_pattern(rf"\bmin\s*\(\s*{copy_token}\s*,\s*{alloc_token}\s*\)"),
                window,
            )
            or re.search(
                self._literal_api_pattern(rf"\bmin\s*\(\s*{alloc_token}\s*,\s*{copy_token}\s*\)"),
                window,
            )
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
                rf"(?:^|[;{{}}])\s*(?!(?:return|else)\b)"
                rf"(?:[A-Za-z_]\w*\s+)+(?:\*\s*)?{escaped}\s*\[\s*(?P<size>[A-Za-z_]\w*|\d+)\s*\]\s*(?:=|;)",
                item.text,
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
            self._literal_api_pattern(
                rf"\b{count}\b\s*(?:<|<=)\s*(?:ARRAY_SIZE\s*\(\s*{array_escaped}\s*\)|sizeof\s*\(\s*{array_escaped}\s*\)|{size_escaped})"
            ),
            self._literal_api_pattern(
                rf"\bif\s*\([^)]*\b{count}\b\s*>\s*(?:ARRAY_SIZE\s*\(\s*{array_escaped}\s*\)|sizeof\s*\(\s*{array_escaped}\s*\)|{size_escaped})[^)]*\)\s*(?:return|goto|break)"
            ),
            self._literal_api_pattern(
                rf"\b{count}\b\s*=\s*(?:MIN|min)\s*\(\s*\b{count}\b\s*,\s*(?:ARRAY_SIZE\s*\(\s*{array_escaped}\s*\)|{size_escaped})"
            ),
        ]
        return any(re.search(pattern, window) for pattern in patterns)

    @staticmethod
    def _looks_wire_pointer_source(expr: str) -> bool:
        return bool(
            re.search(
                r"\(\s*(?:uintptr_t|intptr_t|u?int(?:32|64)_t|size_t)\s*\)",
                expr,
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
            statement = " ".join(row.text for row in lines[item.index : line.index]).split(";", 1)[
                0
            ]
            if not re.search(r"\([^)]*\*\s*\)", statement):
                continue
            rhs = statement.split("=", 1)[1]
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

    @staticmethod
    def _conditional_assignment_dominates_use(
        lines: Sequence[ClangCfgLine], assignment: ClangCfgLine, use: ClangCfgLine
    ) -> bool:
        """Recognize an assignment and use inside the same braced branch."""

        if assignment.index >= use.index or re.search(r"\bif\s*\(", assignment.text):
            return False
        opener = None
        for item in reversed(lines[max(0, assignment.index - 6) : assignment.index]):
            if re.search(r"\b(?:if|else)\b", item.text) and "{" in item.text:
                opener = item
                break
            if "}" in item.text:
                break
        if opener is None:
            return False
        depth = sum(
            row.text.count("{") - row.text.count("}")
            for row in lines[opener.index : assignment.index + 1]
        )
        if depth <= 0:
            return False
        for item in lines[assignment.index + 1 : use.index + 1]:
            depth += item.text.count("{") - item.text.count("}")
            if depth <= 0 and item.index < use.index:
                return False
        return depth > 0

    @staticmethod
    def _out_parameter_initializes_before_guarded_use(
        lines: Sequence[ClangCfgLine],
        declaration: ClangCfgLine,
        use: ClangCfgLine,
        var: str,
    ) -> bool:
        """Recognize a checked status-returning call that writes ``&var``."""

        escaped = re.escape(var)
        for item in lines[declaration.index + 1 : use.index]:
            match = re.search(
                rf"\b(?P<status>[A-Za-z_]\w*)\s*=\s*[^;]*\([^;]*&\s*{escaped}\b[^;]*\)\s*;",
                item.text,
            )
            if not match:
                continue
            status = re.escape(match.group("status"))
            window = "\n".join(
                row.text for row in lines[item.index + 1 : min(use.index, item.index + 8)]
            )
            if re.search(
                rf"\bif\s*\([^)]*(?:!\s*{status}\s*\.\s*ok\s*\(\s*\)|{status}\s*(?:!=|==)\s*[^)]*)[^)]*\)"
                r"[\s\S]{0,180}\b(?:return|goto)\b",
                window,
            ):
                return True
        return False

    def _allocation_count_expression(self, api: str, args: str) -> str:
        return str(self.semantics.contracts.allocation_extent(api, self._split_args(args)))

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
                self._literal_api_pattern(
                    rf"\b(?:memcpy|memmove|strncpy|read|recv|fread|malloc|calloc)\s*"
                    rf"\([^;]*\b{escaped}\b"
                ),
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

    def _has_overflow_guard(
        self,
        lines: Sequence[ClangCfgLine],
        line: ClangCfgLine,
        expr: str,
    ) -> bool:
        identifiers = list(
            dict.fromkeys(
                name
                for name in re.findall(r"\b[A-Za-z_]\w*\b", str(expr or ""))
                if name
                not in {
                    "sizeof",
                    "SIZE_MAX",
                    "UINT_MAX",
                    "UINT32_MAX",
                    "UINT64_MAX",
                    "INT_MAX",
                }
            )
        )
        identifiers.extend(
            literal
            for literal in re.findall(r"\b\d+\b", str(expr or ""))
            if literal not in identifiers
        )
        window = lines[max(0, line.index - 12) : line.index]

        def rejects(condition: str) -> bool:
            if overflow_rejection_condition(condition, identifiers):
                return True
            if len(identifiers) != 1:
                return False
            variable = re.escape(identifiers[0])
            return bool(
                re.search(
                    rf"\b{variable}\b\s*>\s*(?:UINT32_MAX|UINT_MAX|SIZE_MAX|INT_MAX)\b",
                    condition,
                )
            )

        return has_terminating_guard(
            window,
            len(window),
            rejects,
            lookback=len(window) or 1,
        )

    @staticmethod
    def _is_compile_time_size_expr(expr: str) -> bool:
        text = str(expr or "").strip()
        if re.fullmatch(r"\d+", text) or "sizeof" in text:
            return True
        constant = r"(?:[A-Za-z_]\w*::)*" r"(?:[A-Z_][A-Z0-9_]*|k[A-Z][A-Za-z0-9_]*)"
        return bool(re.fullmatch(rf"{constant}(?:\s*[-+*/]\s*\d+)?", text))

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
