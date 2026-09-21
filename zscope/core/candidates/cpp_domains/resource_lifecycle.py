# mypy: disable-error-code="attr-defined"
"""Resource acquisition, release, and lifetime detector implementations."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import replace
from ....semantics.object_flow import ObjectFlow
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
from .source_events import ordered_lines

# FILE*-style stdlib openers must not enter the int-fd leak state machine;
# they were excluded before user-defined io_acquire wrappers were introduced.
_FD_OPEN_EXCLUDED_NAMES = {"fopen", "fdopen", "freopen", "popen"}


STAGES = (
    DetectorStage(
        "regex",
        "function",
        20,
        "resource_lifecycle",
        "same_function_resource_leak",
        "_rule_same_function_resource_leak",
        ("lines", "emit"),
    ),
    DetectorStage(
        "regex",
        "function",
        30,
        "resource_lifecycle",
        "realloc_misuse",
        "_rule_realloc_misuse",
        ("lines", "emit"),
    ),
    DetectorStage(
        "regex",
        "function",
        140,
        "resource_lifecycle",
        "stale_resources",
        "_rule_stale_resources",
        ("lines", "emit"),
    ),
    DetectorStage(
        "clang_ast_cfg",
        "function",
        10,
        "resource_lifecycle",
        "resource_state_machines",
        "_run_resource_state_machines",
        ("issues", "func_name", "file_path", "lines", "allowed_skills"),
    ),
    DetectorStage(
        "clang_ast_cfg",
        "function",
        11,
        "resource_lifecycle",
        "typed_resources",
        "_run_typed_resource_lifetimes",
        ("issues", "func_name", "file_path", "lines", "allowed_skills"),
    ),
    DetectorStage(
        "graph",
        "view",
        20,
        "resource_lifecycle",
        "wrong_cleanup_type",
        "_rule_wrong_cleanup_type",
        ("view", "by_name", "issues"),
    ),
    DetectorStage(
        "graph",
        "view",
        30,
        "resource_lifecycle",
        "thread_argument_lifetime",
        "_rule_thread_argument_lifetime",
        ("view", "issues"),
        covers=("memory_bounds_integer",),
    ),
    DetectorStage(
        "graph",
        "view",
        40,
        "resource_lifecycle",
        "global_container_lifecycle",
        "_rule_global_container_lifecycle",
        ("view", "issues"),
    ),
    DetectorStage(
        "graph",
        "batch",
        10,
        "resource_lifecycle",
        "paired_lifecycle_protocols",
        "_rule_paired_lifecycle_protocols",
        ("views", "issues"),
        covers=("protocol_ownership_logic",),
    ),
    DetectorStage(
        "graph",
        "batch",
        20,
        "resource_lifecycle",
        "paired_member_cleanup_protocols",
        "_rule_paired_member_cleanup_protocols",
        ("views", "issues"),
        covers=("protocol_ownership_logic",),
    ),
    DetectorStage(
        "graph",
        "batch",
        50,
        "resource_lifecycle",
        "paired_global_registration_cleanup",
        "_rule_paired_global_registration_cleanup",
        ("views", "issues"),
        covers=("concurrency_shared_state",),
    ),
)


class RegexResourceLifecycleRules:
    def _rule_realloc_misuse(self, lines: List[CodeLine], emit) -> None:
        for line in lines:
            match = re.search(
                r"\b(?P<lhs>[A-Za-z_]\w*)\s*=\s*(?:\([^)]*\)\s*)?"
                rf"(?P<api>{self._names_pattern(self._reallocator_names)})\s*\((?P<args>[^;]+)\)",
                line.text,
            )
            if not match:
                continue
            registry = self.semantics.contracts
            args = registry.call_arguments(match.group("api"), line.text) or []
            if (registry.reallocation_input(match.group("api"), args) != match.group("lhs")
                    or registry.reallocation_failure_preservation(match.group("api"), args) == "does_not_apply"):
                continue
            emit(
                defect_class="realloc_misuse",
                rule="direct_realloc_assignment",
                line=line,
                description=(f"`{match.group('lhs')}` 被 realloc 覆盖；失败时原有的分配会丢失。"),
                root_cause="realloc 的结果被直接赋值给唯一的持有指针。",
                suggested_fix="将 realloc 赋值给临时指针，仅在成功后再更新持有者。",
                source=match.group("lhs"),
                sink=line.text.strip(),
                confidence=0.86,
                positive=[f"line {line.number}: direct realloc assignment `{line.text.strip()}`"],
            )

    def _rule_same_function_resource_leak(self, lines: List[CodeLine], emit) -> None:
        allocations: Dict[str, CodeLine] = {}
        acquisition_apis: Dict[str, str] = {}
        identities: dict[str, str] = {}
        domains: dict[str, tuple[str, str]] = {}
        flow = ObjectFlow()
        released: set[str] = set()
        uncertain_release: set[str] = set()
        escaped: set[str] = set()
        for line in lines:
            flow.observe(line.text)
            for api, obj in self._bound_api_calls(
                line.text, {"allocator", "calloc", "reallocator"}
            ):
                allocations[obj] = line
                acquisition_apis[obj] = api
                identities[obj] = flow.resolve(obj)
                domain, family = self.semantics.contracts.acquisition_domain(api, line.text)
                domains[obj] = (flow.resolve(domain) if domain else "", family)
                released.discard(obj)
                escaped.discard(obj)
            for var in list(allocations):
                for api, obj in self._bound_api_calls(line.text, {"deallocator"}):
                    if flow.resolve(obj) != identities[var] or not self.semantics.contracts.allows(
                        acquisition_apis[var], api
                    ):
                        continue
                    status = self.semantics.contracts.release_in_text(
                        acquisition_apis[var],
                        api,
                        line.text,
                        identities[var],
                        acquired_domain=domains[var][0],
                        acquired_family=domains[var][1],
                        object_resolver=flow.resolve,
                    )
                    if status == "applies":
                        released.add(var)
                    elif status == "unknown":
                        uncertain_release.add(var)
                if re.search(rf"\breturn\s+{re.escape(var)}\s*;", line.text):
                    escaped.add(var)
                if re.search(
                    rf"\b[A-Za-z_]\w*(?:->|\.)[A-Za-z_]\w*\s*=\s*{re.escape(var)}\b", line.text
                ):
                    escaped.add(var)
        if not allocations:
            return
        return_lines = [line for line in lines if re.search(r"\breturn\b", line.text)]
        sink_line = return_lines[-1] if return_lines else lines[-1]
        leaked: List[Tuple[str, CodeLine]] = []
        for var, alloc_line in allocations.items():
            if var in released or var in escaped:
                continue
            leaked.append((var, alloc_line))
        if not leaked:
            return
        _, first_line = leaked[0]
        leaked_names = ", ".join(f"`{var}`" for var, _ in leaked)
        emit(
            defect_class="memory_leak",
            rule="same_function_allocation_not_released",
            line=first_line,
            description=f"{leaked_names} 已分配，但未见局部的释放、返回或所有权转移。",
            root_cause="函数返回时仍有已持有的分配处于存活状态。",
            suggested_fix="在每个退出路径上释放该分配，或显式转移所有权。",
            source=", ".join(var for var, _ in leaked),
            sink=f"return at line {sink_line.number}",
            confidence=0.72,
            positive=[
                *(
                    f"line {alloc_line.number}: allocation assigned to `{var}`"
                    for var, alloc_line in leaked
                ),
                "no matching release/return/ownership transfer found in the function body",
                *(
                    f"unresolved release effect for `{var}`; requires validation"
                    for var, _ in leaked
                    if var in uncertain_release
                ),
            ],
        )

    def _rule_stale_resources(self, lines: List[CodeLine], emit) -> None:
        for line in lines:
            close = re.search(r"\bclose\s*\(\s*(?P<fd>[A-Za-z_]\w*)\s*\)\s*;", line.text)
            if close:
                later = "\n".join(item.text for item in lines[line.index + 1 : line.index + 7])
                if not self._previous_assignment_from_open(
                    lines, line.index, close.group("fd")
                ) and not re.search(r"(?:g_[A-Za-z_]\w*fd|fd)\s*=\s*-1", later):
                    emit(
                        defect_class="stale_fd",
                        rule="fd_closed_without_invalidation",
                        line=line,
                        description="文件描述符被关闭，但缺少相邻的持有者失效处理。",
                        root_cause="其他路径可能在 close 之后重用陈旧的描述符值。",
                        suggested_fix="在 close 之后于同一同步下将持有描述符置为 -1。",
                        source=close.group("fd"),
                        sink=line.text.strip(),
                        confidence=0.62,
                        positive=[f"line {line.number}: close without nearby fd=-1 assignment"],
                    )

            if "munmap" in line.text:
                later = "\n".join(item.text for item in lines[line.index + 1 : line.index + 8])
                if "NULL" not in later:
                    emit(
                        defect_class="use_after_free",
                        rule="mapping_unmapped_without_pointer_clear",
                        line=line,
                        description="内存映射被解除，但未在附近清除共享的指针/长度。",
                        root_cause="稍后的读取者可能在 munmap 之后观察到陈旧的映射指针。",
                        suggested_fix="在持有保护锁的同时清除共享指针和长度。",
                        source=line.text.strip(),
                        sink=line.text.strip(),
                        confidence=0.7,
                        impact_level="high",
                        positive=[f"line {line.number}: munmap without nearby NULL reset"],
                    )

    def _previous_assignment_from_open(self, lines: List[CodeLine], idx: int, fd: str) -> bool:
        previous = "\n".join(item.text for item in lines[max(0, idx - 12) : idx])
        user_open_names: Set[str] = set(getattr(self, "_user_io_acquire_names", ()))
        user_open = self._names_pattern(user_open_names - _FD_OPEN_EXCLUDED_NAMES)
        return bool(
            re.search(
                rf"\b{re.escape(fd)}\s*=\s*(?:open|socket|accept|accept4|{user_open})\s*\(",
                previous,
            )
        )


class GraphResourceLifecycleRules:
    def _rule_wrong_cleanup_type(
        self,
        view: FunctionView,
        by_name: Dict[str, FunctionView],
        issues: List[Dict[str, Any]],
    ) -> None:
        for line in view.lines:
            for call_name in self._called_names(line.text):
                if (
                    call_name not in self._free_names
                    and call_name not in self.semantics.io_releasers
                ):
                    continue
                callee = by_name.get(call_name) or self._view_for(call_name)
                if not callee:
                    continue
                param_type = self._first_param_type(callee.signature)
                if not param_type:
                    continue
                first_arg = self._first_call_arg(line.text, call_name)
                if not first_arg or not first_arg.startswith("&"):
                    continue
                arg_terms = set(self._identifier_terms(first_arg))
                type_terms = set(self._identifier_terms(param_type))
                if not type_terms:
                    continue
                overlap = arg_terms & type_terms
                if overlap:
                    continue
                if "." not in first_arg and "->" not in first_arg:
                    continue
                issues.append(
                    self._issue(
                        defect_class="type_confusion",
                        rule="cleanup_contract_type_mismatch",
                        view=view,
                        line=line,
                        description=(
                            f"`{call_name}` 期望 `{param_type}`，却接收到 `{first_arg}`，"
                            "后者看起来是另一个不同的结构体字段地址。"
                        ),
                        root_cause="用一个静态契约与被调用参数不匹配的对象调用了清理/销毁例程。",
                        suggested_fix="传入与清理契约匹配的对象，或按具体类型拆分清理函数。",
                        source=first_arg,
                        sink=f"{call_name}({param_type})",
                        confidence=0.82,
                        impact_level="high",
                        positive=[
                            f"line {line.number}: call argument `{first_arg}`",
                            f"{call_name} signature: `{callee.signature}`",
                        ],
                    )
                )

    def _rule_thread_argument_lifetime(
        self,
        view: FunctionView,
        issues: List[Dict[str, Any]],
    ) -> None:
        allocations: Dict[str, GraphLine] = {}
        released: set = set()
        thread_args: Dict[str, GraphLine] = {}
        for line in view.lines:
            alloc = self._alloc_assign_re.search(line.text)
            if alloc:
                allocations[alloc.group("var")] = line
            free = self._free_re.search(line.text)
            if free:
                arg = free.group("arg")
                for var in allocations:
                    if re.search(rf"\b{re.escape(var)}\b", arg):
                        released.add(var)
            if "pthread_create" not in line.text:
                continue
            for var in allocations:
                if re.search(rf"&\s*{re.escape(var)}\s*(?:\[|\b)", line.text):
                    thread_args[var] = line
        for var, alloc_line in allocations.items():
            if var not in thread_args or var in released:
                continue
            issues.append(
                self._issue(
                    defect_class="memory_leak",
                    rule="heap_thread_argument_not_released",
                    view=view,
                    line=alloc_line,
                    description=(
                        f"`{var}` 被堆分配，且其元素地址被传给 `pthread_create`，"
                        "但持有者的分配在该函数中从未被释放。"
                    ),
                    root_cause="线程参数存储仍由初始化者持有，但没有任何清理路径释放它。",
                    suggested_fix="将分配存入分发者占有的字段并在关闭期间释放，或在所有工作线程加入后再释放。",
                    source=var,
                    sink=f"pthread_create at line {thread_args[var].number}",
                    confidence=0.78,
                    impact_level="medium",
                    positive=[
                        f"line {alloc_line.number}: `{var}` allocated",
                        f"line {thread_args[var].number}: `{var}` address escapes to worker thread",
                        "no matching release was found in the same ownership scope",
                    ],
                    evidence={
                        "path": {
                            "function": view.name,
                            "source_line": alloc_line.number,
                            "sink_line": thread_args[var].number,
                            "path_constraints": [
                                "worker may outlive initializer",
                                "owner remains local",
                            ],
                        }
                    },
                )
            )

    def _rule_global_container_lifecycle(
        self,
        view: FunctionView,
        issues: List[Dict[str, Any]],
    ) -> None:
        text = "\n".join(line.text for line in view.lines)
        optional_hooks = [
            c.symbol.name
            for c in self.semantics.contracts.contracts
            if c.role == "deallocator"
            and c.conditions
            and re.search(rf"\b{re.escape(c.symbol.name)}\s*\(", text)
        ]
        if optional_hooks and not self._free_re.search(text):
            line = self._first_line_containing(view, optional_hooks[0]) or view.lines[0]
            issues.append(
                self._issue(
                    defect_class="memory_leak",
                    rule="registered_global_object_missing_release_hook",
                    view=view,
                    line=line,
                    description="一个全局/容器占有的会话仅通过可选的 drop 钩子处理，缺少回退的释放路径。",
                    root_cause="清理协议依赖的钩子可能保持为 NULL 或未注册。",
                    suggested_fix="在初始化期间注册释放钩子，或增加一条无条件的回退释放路径。",
                    source="global container add/register path",
                    sink=line.text.strip(),
                    confidence=0.76,
                    impact_level="high",
                    positive=[
                        f"line {line.number}: cleanup depends on optional hook `{line.text.strip()}`"
                    ],
                )
            )

        global_acquisitions = [
            c
            for c in self.semantics.contracts.contracts
            if c.role in {"allocator", "io_acquire"}
            and c.carrier.kind == "global"
            and c.effects_trusted
            and not c.conditions
            and re.search(rf"\b{re.escape(c.symbol.name)}\s*\(", text)
        ]
        for contract in global_acquisitions:
            releases = {
                name for name in self.semantics.contracts.releases(contract.symbol.name)
                if self.semantics.contracts.allows(contract.symbol.name, name)
            }
            line = self._first_line_containing(view, contract.symbol.name) or view.lines[0]
            if releases and not self._global_contract_release_observed(view, text, contract):
                issues.append(
                    self._issue(
                        defect_class="memory_leak",
                        rule="global_container_registration_without_cleanup_path",
                        view=view,
                        line=line,
                        description="消息/动作路径将对象注册进全局所有权，却缺少可见的清理路径。",
                        root_cause="全局容器所有权已被获取，但没有与之配套的取消注册/移除(drop)释放协议。",
                        suggested_fix="为每个全局 add/register 动作配一条可到达的、针对同一对象的移除/释放路径。",
                        source="global registration action",
                        sink=line.text.strip(),
                        confidence=0.74,
                        impact_level="high",
                        positive=[f"line {line.number}: global registration action is visible"],
                    )
                )

        detached = re.search(
            r"(?P<owner>[A-Za-z_]\w*)->(?P<link>[A-Za-z_]\w*)\s*=\s*(?P<node>[A-Za-z_]\w*)->(?P=link)\s*;",
            text,
        )
        if (
            detached
            and not self._free_re.search(text)
            and re.search(
                rf"\b{re.escape(detached['node'])}->[A-Za-z_]\w*\s*=\s*(?:NULL|nullptr|0)\s*;", text
            )
        ):
            line = self._first_line_containing(view, detached[0]) or view.lines[0]
            issues.append(
                self._issue(
                    defect_class="memory_leak",
                    rule="container_unlink_without_release",
                    view=view,
                    line=line,
                    description="容器的 detach/unlink 操作移除了所有权可达性，却未释放被分离的对象。",
                    root_cause="对象已与其持有容器解除链接，但其分配及嵌套资源仍保持存活。",
                    suggested_fix="在解除链接后释放被分离对象及其嵌套资源，或显式转移所有权。",
                    source=line.text.strip(),
                    sink="container unlink/detach",
                    confidence=0.82,
                    impact_level="high",
                    positive=[
                        f"line {line.number}: a link bypasses the detached node and its linkage is cleared without release"
                    ],
                )
            )

        free_line = self._first_line_matching(view, self._free_re)
        if (
            re.search(r"pthread_mutex_init", text)
            and free_line
            and not re.search(r"pthread_mutex_destroy", text)
        ):
            line = free_line
            issues.append(
                self._issue(
                    defect_class="memory_leak",
                    rule="nested_mutex_cleanup_omitted",
                    view=view,
                    line=line,
                    description="一个初始化了嵌套互斥锁的节点被释放，却未销毁该互斥锁资源。",
                    root_cause="节点清理释放了分配，却遗漏了内嵌的同步原语。",
                    suggested_fix="在释放持有节点之前先销毁内嵌的 mutex/condition 资源。",
                    source="pthread_mutex_init in paired creation path",
                    sink=line.text.strip(),
                    confidence=0.8,
                    impact_level="medium",
                    positive=[
                        "function body references initialized mutex ownership",
                        f"line {line.number}: node allocation is freed",
                        "no pthread_mutex_destroy is visible in the cleanup path",
                    ],
                )
            )

        if (
            re.search(r"proc_head|child|children", text, re.I)
            and free_line
            and not re.search(
                r"\bwhile\b[^{;]*(?:proc|child)|for\s*\([^;]*(?:proc|child)", text, re.I
            )
        ):
            line = free_line
            issues.append(
                self._issue(
                    defect_class="memory_leak",
                    rule="child_list_cleanup_omitted",
                    view=view,
                    line=line,
                    description="父节点被释放，而其子节点/链表占有的字段未被遍历和释放。",
                    root_cause="复合容器的清理只释放了主节点，却跳过了嵌套的已持有子节点。",
                    suggested_fix="在释放父对象之前先遍历并释放每个子节点。",
                    source="nested child/list field",
                    sink=line.text.strip(),
                    confidence=0.78,
                    impact_level="high",
                    positive=[
                        "function references a child/list ownership field",
                        f"line {line.number}: parent object is freed",
                        "no child/list cleanup loop is visible",
                    ],
                )
            )

    def _global_contract_release_observed(self, view, text, contract) -> bool:
        """A cleanup name alone cannot discharge a global resource obligation."""
        from ....semantics.contract_compiler import read_source_facts

        registry = self.semantics.contracts
        context = {"func_name": view.name, "file_path": view.file_path, "code": text}
        facts = read_source_facts(context, registry)
        if not facts.complete or facts.unknown_calls:
            return False
        events = registry.trace_calls(context)
        acquisitions = [
            e for e in events
            if e["symbol"] == contract.to_dict()["symbol"] and e["role"] == contract.role
            and e["applicability"] != "does_not_apply"
        ]
        if len(acquisitions) != 1:
            return False
        acquire = acquisitions[0]
        obj = acquire["object"]
        if any(obj == lhs or obj.startswith((lhs + ".", lhs + "->")) for lhs in facts.assignments):
            return False
        return any(
            release["call_ordinal"] > acquire["call_ordinal"]
            and release["role"] in {"deallocator", "io_release"}
            and release["guard"] in ({"op": "true"}, acquire["guard"])
            and registry.release_status(
                contract.symbol.name, release["symbol"]["name"], release["arguments"],
                acquired_object=obj, acquired_domain=acquire["resource_domain"],
                acquired_family=acquire["resource_family"],
            ) == "applies"
            for release in events
        )

    def _emit_role_release_candidate(
        self,
        view: FunctionView,
        issues: List[Dict[str, Any]],
    ) -> None:
        text = "\n".join(line.text for line in view.lines)
        role_assign = self._first_line_matching(
            view, re.compile(r"->\s*role\s*=\s*(?P<role>[A-Za-z_]\w*)\s*;")
        )
        release_line = self._first_line_matching(
            view,
            re.compile(self._semantic_api_pattern(r"\b(?:free|close)\s*\([^;]*,\s*0\s*\)"), re.I),
        )
        if not (role_assign and release_line):
            return
        role_match = re.search(r"->\s*role\s*=\s*(?P<role>[A-Za-z_]\w*)\s*;", role_assign.text)
        role_name = role_match.group("role") if role_match else "role"
        if role_name not in text:
            return
        issues.append(
            self._issue(
                defect_class="memory_leak",
                rule="role_specific_release_uses_hardcoded_role",
                view=view,
                line=release_line,
                description="针对具体角色的释放辅助函数使用硬编码角色调用，而非对象所存储的角色。",
                root_cause="清理仅释放某一角色的资源，可能泄漏其他角色所占有的、角色特定的成员。",
                suggested_fix="将存储的角色/成员角色传给释放辅助函数，或按对象实际角色分派清理。",
                source=role_assign.text.strip(),
                sink=release_line.text.strip(),
                confidence=0.84,
                impact_level="high",
                positive=[
                    f"line {role_assign.number}: object role is set from `{role_name}`",
                    f"line {release_line.number}: role-specific release is called with literal `0`",
                ],
            )
        )

    def _emit_sigpipe_unhandled_candidate(
        self,
        view: FunctionView,
        issues: List[Dict[str, Any]],
    ) -> None:
        text = "\n".join(line.text for line in view.lines)
        if "SIGPIPE" in text or "MSG_NOSIGNAL" in text:
            return
        line = self._first_line_matching(
            view, re.compile(self._semantic_api_pattern(r"\b(?:write|send)\s*\("))
        )
        if not line:
            return
        if not re.search(
            r"(?:peer|socket|sock|fd|conn|control|reply)", view.signature + "\n" + line.text, re.I
        ):
            return
        issues.append(
            self._issue(
                defect_class="sigpipe_unhandled",
                rule="peer_write_without_sigpipe_handling",
                view=view,
                line=line,
                description="对端写入已发出，却缺少可见的 SIGPIPE 抑制或处理。",
                root_cause="向已关闭的对端写入可能在正常错误处理返回之前触发 SIGPIPE。",
                suggested_fix="使用 send(..., MSG_NOSIGNAL)、忽略/处理 SIGPIPE，或使用平台特定的无信号标志。",
                source=line.text.strip(),
                sink="closed peer write",
                confidence=0.84,
                impact_level="high",
                positive=[
                    f"line {line.number}: peer/control fd is written with `{line.text.strip()}`",
                    "no SIGPIPE handler, ignore policy, or MSG_NOSIGNAL flag is visible in the function",
                ],
            )
        )

    def _emit_alloc_free_mismatch_candidate(
        self,
        view: FunctionView,
        issues: List[Dict[str, Any]],
    ) -> None:
        text = "\n".join(line.text for line in view.lines)
        if not ("mem_alloc_func" in text and "mem_free_func" in text):
            return
        alloc_assign = self._first_line_matching(
            view, re.compile(r"\b[A-Za-z_]\w*\.mem_alloc_func\s*=")
        )
        free_assign = self._first_line_matching(
            view, re.compile(r"\b[A-Za-z_]\w*\.mem_free_func\s*=")
        )
        alloc_call = self._first_line_matching(
            view, re.compile(r"\b[A-Za-z_]\w*\s*=\s*[A-Za-z_]\w*\.mem_alloc_func\s*\(")
        )
        free_call = self._first_line_matching(
            view, re.compile(r"\b[A-Za-z_]\w*\.mem_free_func\s*\(")
        )
        if not (alloc_assign and free_assign and alloc_call and free_call):
            return
        if not re.search(r"\?|noop|free|header|pool|custom", text, re.I):
            return
        issues.append(
            self._issue(
                defect_class="alloc_free_mismatch",
                rule="callback_allocator_pair_not_enforced",
                view=view,
                line=alloc_assign,
                description="分配与释放回调被独立选择，而未强制保证分配器的配对。",
                root_cause="由某一回调族分配的节点可能经由不兼容的回调/no-op/free 路径被释放。",
                suggested_fix="将分配器身份与分配一起存储，或将 allocator/free 回调注册为经校验的原子配对。",
                source=f"{alloc_assign.text.strip()} / {free_assign.text.strip()}",
                sink=free_call.text.strip(),
                confidence=0.84,
                impact_level="high",
                positive=[
                    f"line {alloc_assign.number}: allocator callback is selected",
                    f"line {free_assign.number}: free callback is selected separately",
                    f"line {alloc_call.number}: allocation uses the selected callback",
                    f"line {free_call.number}: release uses the selected free callback",
                ],
            )
        )

    def _rule_paired_member_cleanup_protocols(
        self,
        views: Sequence[FunctionView],
        issues: List[Dict[str, Any]],
    ) -> None:
        for view in views:
            self._rule_same_function_helper_alloc_member_cleanup_gap(view, issues)

        member_allocs: List[Dict[str, Any]] = []
        for view in views:
            if view.name not in self._alloc_names:
                continue
            for line in view.lines:
                match = re.search(
                    self._semantic_api_pattern(
                        r"\b(?P<obj>[A-Za-z_]\w*)->(?P<field>[A-Za-z_]\w*)\s*=\s*"
                        r"(?:\([^)]*\)\s*)?"
                        r"(?P<api>(?:malloc|calloc|realloc|strdup))\s*\("
                    ),
                    line.text,
                    re.I,
                )
                if not match:
                    continue
                field = match.group("field")
                if not re.search(
                    r"(?:payload|data|buf|buffer|key|name|str|child|children|list)", field, re.I
                ):
                    continue
                member_allocs.append(
                    {
                        "view": view,
                        "line": line,
                        "object": match.group("obj"),
                        "field": field,
                        "api": match.group("api"),
                    }
                )
        if not member_allocs:
            return

        for view in views:
            if view.name not in self._free_names:
                continue
            text = "\n".join(line.text for line in view.lines)
            free_line = self._first_line_matching(view, self._free_re)
            if not free_line:
                continue
            free_arg = ""
            free_match = self._free_re.search(free_line.text)
            if free_match:
                free_arg = (
                    self._resource_arg(free_match.group("arg")) or free_match.group("arg").strip()
                )
            if not free_arg:
                continue
            for alloc in member_allocs:
                field = str(alloc["field"])
                creator = alloc["view"]
                if creator.name == view.name:
                    continue
                if not self._cleanup_pair_matches(creator, view, field, text):
                    continue
                if self._member_release_visible(text, free_arg, field):
                    continue
                alloc_line = alloc["line"]
                issues.append(
                    self._issue(
                        defect_class="memory_leak",
                        rule="paired_free_wrapper_omits_dynamic_member",
                        view=view,
                        line=free_line,
                        description=(
                            f"`{view.name}` 释放了 `{free_arg}`，却遗漏了由 `{creator.name}` 分配的、"
                            f"被动态持有的成员 `{field}`。"
                        ),
                        root_cause=(
                            "free 包装函数在未释放由配对构造函数初始化的已持有动态负载的情况下，"
                            "就释放了外围对象。"
                        ),
                        suggested_fix=f"在释放 `{free_arg}` 之前先释放 `{free_arg}->{field}`，或调用该成员的清理辅助函数。",
                        source=f"{creator.name}:{alloc_line.number}:{alloc_line.text.strip()}",
                        sink=free_line.text.strip(),
                        confidence=0.82,
                        impact_level="high",
                        positive=[
                            f"{creator.name} line {alloc_line.number}: `{field}` receives dynamic storage via `{alloc['api']}`",
                            f"{view.name} line {free_line.number}: wrapper releases `{free_arg}`",
                            f"`{view.name}` has no visible release of `{free_arg}->{field}`",
                        ],
                        negative=[
                            "Validator must confirm the member is not intentionally transferred before wrapper cleanup."
                        ],
                        evidence={
                            "path": {
                                "allocator_function": creator.name,
                                "cleanup_function": view.name,
                                "source_line": alloc_line.number,
                                "sink_line": free_line.number,
                                "complete_in_function": False,
                                "path_constraints": [
                                    "paired constructor/free-wrapper ownership contract"
                                ],
                            }
                        },
                    )
                )
                break

    def _rule_same_function_helper_alloc_member_cleanup_gap(
        self,
        view: FunctionView,
        issues: List[Dict[str, Any]],
    ) -> None:
        text = "\n".join(line.text for line in view.lines)
        alloc_match = re.search(
            self._semantic_api_pattern(
                r"\b(?P<var>[A-Za-z_]\w*)\s*=\s*" r"(?P<api>(?:malloc|calloc|realloc|strdup))\s*\("
            ),
            text,
            re.I,
        )
        if not alloc_match:
            return
        alloc_context = alloc_match.group(0)
        alloc_line_for_context = self._first_line_matching(
            view,
            re.compile(
                rf"\b{re.escape(alloc_match.group('var'))}\s*=\s*{re.escape(alloc_match.group('api'))}\s*\(",
                re.I,
            ),
        )
        if alloc_line_for_context:
            alloc_context = alloc_line_for_context.text
        owned_members = {
            c.carrier.member_path.removeprefix("->").removeprefix(".")
            for c in self.semantics.contracts.find(alloc_match.group("api"))
            if c.carrier.kind == "return" and c.carrier.member_path and not c.conditions
        }
        if not owned_members:
            return
        var_name = alloc_match.group("var")
        if not re.search(
            self._semantic_api_pattern(rf"\b(?:free)\s*\(\s*{re.escape(var_name)}\s*\)"), text
        ):
            return
        released_members = {
            match.group(1).lower()
            for match in re.finditer(
                self._semantic_api_pattern(
                    rf"\b(?:free)\s*\(\s*{re.escape(var_name)}\s*->\s*([A-Za-z_]\w*)\s*\)"
                ),
                text,
                re.I,
            )
        }
        if not released_members:
            return
        likely_owned_members = sorted(owned_members)
        missing_member = next(
            (member for member in likely_owned_members if member not in released_members), ""
        )
        if not missing_member:
            return
        free_line = self._first_line_matching(
            view,
            re.compile(
                self._semantic_api_pattern(rf"\b(?:free)\s*\(\s*{re.escape(var_name)}\s*\)"), re.I
            ),
        )
        alloc_line = self._first_line_matching(
            view,
            re.compile(
                rf"\b{re.escape(var_name)}\s*=\s*{re.escape(alloc_match.group('api'))}\s*\(", re.I
            ),
        )
        if not free_line:
            return
        issues.append(
            self._issue(
                defect_class="memory_leak",
                rule="same_function_helper_alloc_wrapper_member_leak",
                view=view,
                line=free_line,
                description=(
                    f"`{view.name}` 注销了由 `{alloc_match.group('api')}` 分配的文件节点包装，"
                    f"并释放了 `{var_name}`，却遗漏了所占有的 `{missing_member}` payload/path 成员，"
                    "导致负载泄漏。"
                ),
                root_cause=(
                    "注销清理释放了包装节点，而动态分配的文件节点 payload/path 成员仍由"
                    "该包装节点所有并发生泄漏。"
                ),
                suggested_fix=f"在释放 `{var_name}` 之前先释放 `{var_name}->{missing_member}`，或委托给完整的节点析构函数。",
                source=alloc_line.text.strip() if alloc_line else alloc_match.group(0),
                sink=free_line.text.strip(),
                confidence=0.83,
                impact_level="high",
                positive=[
                    f"line {alloc_line.number if alloc_line else free_line.number}: wrapper node is allocated via `{alloc_match.group('api')}`",
                    f"cleanup releases member(s) {sorted(released_members)} and then frees `{var_name}`",
                    f"no release of likely owned `{var_name}->{missing_member}` payload/path is visible",
                ],
                negative=[
                    "Validator must confirm the allocation helper does not transfer or omit this member by contract."
                ],
                evidence={
                    "path": {
                        "allocation_function": alloc_match.group("api"),
                        "cleanup_function": view.name,
                        "source_line": alloc_line.number if alloc_line else free_line.number,
                        "sink_line": free_line.number,
                        "complete_in_function": True,
                        "path_constraints": ["same-function helper allocation cleanup contract"],
                    }
                },
            )
        )

    def _rule_paired_lifecycle_protocols(
        self,
        views: Sequence[FunctionView],
        issues: List[Dict[str, Any]],
    ) -> None:
        texts = {view.name: "\n".join(line.text for line in view.lines) for view in views}
        creation_views = [view for view in views if view.name in self._alloc_names]
        for view in views:
            if view.name not in self._free_names:
                continue
            text = texts[view.name]
            free_line = self._first_line_matching(view, self._free_re)
            if not free_line:
                continue

            if not re.search(r"pthread_mutex_destroy", text):
                paired_init = next(
                    (
                        creator
                        for creator in creation_views
                        if creator.name != view.name
                        and "pthread_mutex_init" in texts[creator.name]
                        and self.semantics.contracts.allows(creator.name, view.name)
                    ),
                    None,
                )
                if paired_init:
                    issues.append(
                        self._issue(
                            defect_class="memory_leak",
                            rule="paired_nested_mutex_cleanup_omitted",
                            view=view,
                            line=free_line,
                            description=(
                                f"`{view.name}` 释放了一个协议对象，而配对的创建者 "
                                f"`{paired_init.name}` 初始化了一个内嵌互斥锁。"
                            ),
                            root_cause="destroy/注销路径释放了分配，却遗漏了由配对的创建/注册路径建立的嵌套同步清理。",
                            suggested_fix="在释放已注册对象之前先销毁内嵌的 mutex/condition 资源。",
                            source=f"{paired_init.name}:pthread_mutex_init",
                            sink=free_line.text.strip(),
                            confidence=0.82,
                            impact_level="medium",
                            positive=[
                                f"{paired_init.name}: paired creation path initializes a mutex",
                                f"line {free_line.number}: cleanup frees the object",
                                "no pthread_mutex_destroy is visible in the cleanup function",
                            ],
                        )
                    )

            child_owner = next(
                (
                    creator
                    for creator in creation_views
                    if creator.name != view.name
                    and re.search(
                        r"->\s*(?:proc_head|child|children|next_child)", texts[creator.name], re.I
                    )
                    and self.semantics.contracts.allows(creator.name, view.name)
                ),
                None,
            )
            if child_owner and not re.search(
                r"\bwhile\b[^{;]*(?:proc|child)|for\s*\([^;]*(?:proc|child)", text, re.I
            ):
                issues.append(
                    self._issue(
                        defect_class="memory_leak",
                        rule="paired_child_list_cleanup_omitted",
                        view=view,
                        line=free_line,
                        description=(
                            f"`{view.name}` 释放了一个父对象，而配对的变更者 "
                            f"`{child_owner.name}` 附加了子节点/链表节点。"
                        ),
                        root_cause="delete/移除路径丢弃了父节点的分配，却未遍历嵌套的已持有子节点。",
                        suggested_fix="在释放父对象之前先遍历并释放每个子节点/链表节点。",
                        source=f"{child_owner.name}:child attachment",
                        sink=free_line.text.strip(),
                        confidence=0.82,
                        impact_level="high",
                        positive=[
                            f"{child_owner.name}: paired path attaches child/list nodes",
                            f"line {free_line.number}: cleanup frees the parent object",
                            "no child/list cleanup loop is visible in the delete path",
                        ],
                    )
                )

    def _cleanup_pair_matches(
        self, creator: FunctionView, cleanup: FunctionView, field: str, cleanup_text: str
    ) -> bool:
        return bool(self.semantics.contracts.allows(creator.name, cleanup.name))

    @staticmethod
    def _is_primitive_pointer_type(type_name: str) -> bool:
        normalized = re.sub(r"\s+", " ", str(type_name or "").replace("const", "").strip())
        return normalized in {"char*", "unsigned char*", "void*", "int*", "size_t*", "uint8_t*"}

    @staticmethod
    def _member_release_visible(text: str, owner: str, field: str) -> bool:
        owner_re = re.escape(owner)
        field_re = re.escape(field)
        direct_member = rf"\b{owner_re}\s*->\s*{field_re}\b"
        if re.search(
            rf"\b(?:free|delete)\s*\([^;]*{direct_member}",
            text,
            re.I,
        ):
            return True
        if re.search(
            rf"\b(?:free|delete)\s*\([^;]*\b{field_re}\b",
            text,
            re.I,
        ):
            return True
        return False

    @staticmethod
    def _resource_arg(value: str) -> str:
        text = str(value or "").strip()
        text = re.sub(r"^[(&*\s]+", "", text)
        text = re.sub(r"[)\]\s]+$", "", text)
        match = re.match(r"([A-Za-z_]\w*(?:\s*->\s*[A-Za-z_]\w*|\s*\.\s*[A-Za-z_]\w*)?)", text)
        return re.sub(r"\s+", "", match.group(1)) if match else ""

    def _rule_paired_global_registration_cleanup(
        self,
        views: Sequence[FunctionView],
        issues: List[Dict[str, Any]],
    ) -> None:
        texts = {view.name: "\n".join(line.text for line in view.lines) for view in views}
        cleanup_views = [
            view
            for view in views
            if view.name in self._free_names or view.name in self.semantics.io_releasers
        ]
        for view in views:
            text = texts[view.name]
            global_contracts = [
                c
                for c in self.semantics.contracts.find(view.name)
                if c.role in {"allocator", "io_acquire"}
                and c.carrier.kind == "global"
                and c.carrier.global_name
                and not c.conditions
            ]
            if not global_contracts:
                continue
            line = next(
                (
                    item
                    for item in view.lines
                    if any(c.carrier.global_name in item.text for c in global_contracts)
                ),
                None,
            )
            if line is None:
                continue
            paired_cleanup = next(
                (
                    cleanup
                    for cleanup in cleanup_views
                    if cleanup.name != view.name
                    and self.semantics.contracts.allows(view.name, cleanup.name)
                    and self._first_line_matching(cleanup, self._free_re) is None
                ),
                None,
            )
            if not paired_cleanup:
                continue
            cleanup_line = (
                self._first_line_matching(paired_cleanup, re.compile(r"LOG_|return", re.I))
                or paired_cleanup.lines[0]
            )
            issues.append(
                self._issue(
                    defect_class="memory_leak",
                    rule="paired_global_registration_cleanup_omitted",
                    view=view,
                    line=line,
                    description=(
                        f"`{view.name}` 将会话/对象注册进全局所有权，而配对的清理 "
                        f"`{paired_cleanup.name}` 在返回时未移除或释放该对象。"
                    ),
                    root_cause="契约中的全局资源获取路径将所有权转移进全局容器，但协议清理端点未注销或释放已注册的对象。",
                    suggested_fix="为全局资源获取路径配一条清理路径，将准确的 key/对象从全局容器中移除并释放其分配。",
                    source=f"{view.name}:{line.number}:global registration",
                    sink=f"{paired_cleanup.name}:{cleanup_line.number}:missing remove/release",
                    confidence=0.82,
                    impact_level="high",
                    positive=[
                        f"{view.name} line {line.number}: global registration path `{line.text.strip()}`",
                        f"{paired_cleanup.name} line {cleanup_line.number}: cleanup path `{cleanup_line.text.strip()}`",
                        "paired cleanup contains no remove/drop/release/free operation for the global session/object",
                    ],
                    evidence={
                        "path": {
                            "function": view.name,
                            "cleanup_function": paired_cleanup.name,
                            "source_line": line.number,
                            "sink_line": cleanup_line.number,
                            "complete_in_function": False,
                            "path_constraints": [
                                "global acquisition succeeds",
                                "cleanup is later invoked for the same protocol",
                            ],
                        },
                        "lifecycle_pair": {
                            "registration_function": view.name,
                            "cleanup_function": paired_cleanup.name,
                        },
                    },
                )
            )

    @staticmethod
    def _first_param_type(signature: str) -> str:
        match = re.search(r"\((?P<params>[^)]*)\)", signature)
        if not match:
            return ""
        first = match.group("params").split(",", 1)[0].strip()
        if not first or first == "void":
            return ""
        first = re.sub(r"\bconst\b|\bvolatile\b", "", first).strip()
        first = re.sub(r"\s+", " ", first)
        first = re.sub(r"\b[A-Za-z_]\w*$", "", first).strip()
        return first.strip()

    @staticmethod
    def _identifier_terms(value: str) -> List[str]:
        parts = re.findall(r"[A-Za-z_]\w*", value)
        terms: List[str] = []
        for part in parts:
            split = re.sub(r"([a-z])([A-Z])", r"\1 \2", part).replace("_", " ")
            terms.extend(piece.lower() for piece in split.split() if len(piece) > 2)
        return terms

    @staticmethod
    def _first_call_arg(text: str, call_name: str) -> str:
        match = re.search(rf"\b{re.escape(call_name)}\s*\((?P<args>[^;]*)\)", text)
        if not match:
            return ""
        return match.group("args").split(",", 1)[0].strip()

    @staticmethod
    def _first_line_containing(view: FunctionView, needle: str) -> Optional[GraphLine]:
        return next((line for line in view.lines if needle in line.text), None)


class ClangResourceLifecycleRules:
    def _run_resource_state_machines(
        self,
        issues: List[Dict[str, Any]],
        func_name: str,
        file_path: str,
        lines: Sequence[ClangCfgLine],
        allowed_skills: Optional[Set[str]],
    ) -> None:
        lines = ordered_lines(lines, ClangCfgLine, self.program_facts)
        live: Dict[str, ResourceState] = {}
        uncertain_releases: Set[str] = set()
        null_values: Set[str] = set()
        freed: Dict[str, Tuple[ClangCfgLine, str]] = {}
        released_resources: Dict[str, ResourceState] = {}
        terminal_branch_freed: Dict[Tuple[int, str], Tuple[ClangCfgLine, str]] = {}
        emitted_null_deref: Set[str] = set()
        emitted_uaf: Set[str] = set()
        emitted_realloc: Set[Tuple[str, int]] = set()
        emitted_status_misuse: Set[str] = set()
        flow = ObjectFlow()

        for line in lines:
            flow.observe(line.text)
            terminal_branch_line = self._is_terminal_conditional_branch_line(lines, line)
            reset_var = self._match_null_reset(line.text)
            if reset_var:
                freed.pop(reset_var, None)
                null_values.add(reset_var)

            reassigned = self._match_assignment_call(line.text, self._alloc_call_re)
            if reassigned:
                var, api, args = reassigned
                null_values.discard(var)
                if api in self._reallocator_names:
                    arguments = self._split_args(args)
                    old_object = self.semantics.contracts.reallocation_input(api, arguments)
                    preserves = self.semantics.contracts.reallocation_failure_preservation(api, arguments)
                    if old_object == var and preserves != "does_not_apply" and (var, line.number) not in emitted_realloc:
                        self._emit(
                            issues,
                            func_name,
                            file_path,
                            lines,
                            allowed_skills,
                            defect_class="realloc_misuse",
                            rule="clang_cfg_realloc_lost_original",
                            line=line,
                            description=(f"`{var}` 在原始指针被确认保留之前就被 `{api}` 覆盖。"),
                            root_cause=(
                                "在 realloc 失败时原有分配仍保持存活，"
                                "但代码丢失了唯一的局部持有者。"
                            ),
                            suggested_fix=(
                                "将 realloc 赋值给临时指针，仅在调用成功后再更新持有者。"
                            ),
                            source=f"{api}({args})",
                            sink=f"{var} = {api}(...)",
                            confidence=0.83,
                            positive=[
                                f"line {line.number}: assignment overwrites `{var}` with `{api}` result",
                                f"line {line.number}: contract maps the original `{api}` object to `{var}`",
                            ],
                            negative=[],
                            ast_cfg=self._ast_cfg_pack(
                                lines,
                                [self._event("realloc_assign", line, var, api, line.text)],
                                [line.number],
                            ),
                        )
                        emitted_realloc.add((var, line.number))
                # Assignment directly into an explicit global lvalue transfers
                # this local acquisition to durable program ownership.  It may
                # still be subject to a separate global-lifetime analysis, but
                # it is not a leak on this function's return path.
                if self._is_global_owner_lvalue(var):
                    freed.pop(var, None)
                    continue
                domain, family = self.semantics.contracts.acquisition_domain(api, line.text)
                live[var] = ResourceState(
                    var=var,
                    api=api,
                    line=line,
                    carrier="return_value",
                    object_identity=flow.resolve(var),
                    resource_domain=flow.resolve(domain) if domain else "",
                    resource_family=family,
                )
                freed.pop(var, None)
                continue

            out_acquired = self._match_out_param_acquire(line.text)
            if out_acquired:
                var, api, args, status_var = out_acquired
                domain, family = self.semantics.contracts.acquisition_domain(api, line.text)
                live[var] = ResourceState(
                    var=var,
                    api=api,
                    line=line,
                    carrier="output_argument",
                    status_var=status_var,
                    object_identity=flow.resolve(var),
                    resource_domain=flow.resolve(domain) if domain else "",
                    resource_family=family,
                )
                freed.pop(var, None)

            for state_var, state in list(live.items()):
                if self._is_null_guard(line.text, state_var):
                    live[state_var] = replace(state, null_guarded=True)

            for state_var, state in list(live.items()):
                if not state.status_var:
                    continue
                if self._is_status_guard_line(line.text, state.status_var):
                    live[state_var] = replace(state, status_guarded=True)

            for state_var, state in list(live.items()):
                if (
                    state.carrier != "output_argument"
                    or not state.status_var
                    or state.status_guarded
                    or state.var in emitted_status_misuse
                    or line.index <= state.line.index
                    or self._is_status_guard_line(line.text, state.status_var)
                ):
                    continue
                if self._uses_resource_value(line.text, state.var):
                    self._emit(
                        issues,
                        func_name,
                        file_path,
                        lines,
                        allowed_skills,
                        defect_class="bad_parameter_or_api_misuse",
                        rule="clang_cfg_out_param_used_before_success_check",
                        line=line,
                        description=(
                            f"`{state.var}` 由输出参数 API `{state.api}` 产生，"
                            f"却在检查 `{state.status_var}` 是否成功之前就被使用了。"
                        ),
                        root_cause=(
                            "合成的 CFG 路径在产生该资源的 API 的状态返回约束成功路径之前，"
                            "就观察到了对输出资源的使用。"
                        ),
                        suggested_fix=(
                            "在使用或释放输出资源之前先检查状态返回，"
                            "并避免失败路径读取未定义的输出值。"
                        ),
                        source=f"{state.api}(..., &{state.var}) at line {state.line.number}",
                        sink=line.text,
                        confidence=0.78,
                        positive=[
                            f"line {state.line.number}: `{state.api}` writes `{state.var}` through an output argument",
                            f"line {line.number}: `{state.var}` is used before `{state.status_var}` success is established",
                        ],
                        negative=[
                            "Validator must confirm the API does not define the output argument on failure."
                        ],
                        ast_cfg=self._ast_cfg_pack(
                            lines,
                            [
                                self._event(
                                    "out_param_acquire",
                                    state.line,
                                    state.var,
                                    state.api,
                                    state.line.text,
                                ),
                                self._event(
                                    "use_before_status_guard", line, state.var, "", line.text
                                ),
                            ],
                            [state.line.number, line.number],
                        ),
                    )
                    emitted_status_misuse.add(state.var)

            release = self._match_release(line.text)
            if release:
                api, arg = release
                resource = next(
                    (s for s in live.values() if s.object_identity == flow.resolve(arg)), None
                )
                if resource is None:
                    resource = released_resources.get(flow.resolve(arg))
                if resource is not None and not self.semantics.contracts.allows(resource.api, api):
                    continue
                if resource is not None:
                    status = self.semantics.contracts.release_in_text(
                        resource.api,
                        api,
                        line.text,
                        resource.object_identity,
                        acquired_domain=resource.resource_domain,
                        acquired_family=resource.resource_family,
                        object_resolver=flow.resolve,
                    )
                else:
                    status = self.semantics.contracts.effect_status(
                        api, "deallocator", line.text, object_name=arg, acquired=True
                    )
                if status != "applies":
                    if status == "unknown":
                        uncertain_releases.add(arg)
                    continue
                uncertain_releases.discard(arg)
                if resource is not None:
                    arg = resource.var
                if arg.strip() in {"NULL", "nullptr", "0"} | null_values:
                    continue
                var = self._resource_expr(arg) or self._resource_var(arg)
                terminal_branch_release = bool(var and terminal_branch_line)
                terminal_key = (line.block_id, var) if terminal_branch_release and var else None
                if terminal_key and terminal_key in terminal_branch_freed:
                    previous_line, previous_api = terminal_branch_freed[terminal_key]
                    self._emit_double_free(
                        issues,
                        func_name,
                        file_path,
                        lines,
                        allowed_skills,
                        var,
                        previous_line,
                        previous_api,
                        line,
                        api,
                        arg,
                    )
                elif var and var in freed:
                    previous_line, previous_api = freed[var]
                    self._emit_double_free(
                        issues,
                        func_name,
                        file_path,
                        lines,
                        allowed_skills,
                        var,
                        previous_line,
                        previous_api,
                        line,
                        api,
                        arg,
                    )
                elif var:
                    if terminal_key:
                        terminal_branch_freed[terminal_key] = (line, api)
                    if not terminal_branch_release:
                        live.pop(var, None)
                        if resource is not None:
                            released_resources[resource.object_identity] = resource
                    return_line = self._return_line_after_release(lines, line)
                    if return_line is not None and self._uses_freed_var(
                        return_line.text, var, release_api_names=self._release_names
                    ):
                        self._emit_use_after_release(
                            issues,
                            func_name,
                            file_path,
                            lines,
                            allowed_skills,
                            var,
                            line,
                            api,
                            return_line,
                        )
                        emitted_uaf.add(var)
                    if not terminal_branch_release and return_line is None:
                        freed[var] = (line, api)

            for var, (free_line, free_api) in list(freed.items()):
                if var in emitted_uaf:
                    continue
                if line.index <= free_line.index:
                    continue
                if (
                    self._is_var_redefined(line.text, var)
                    or self._match_null_reset(line.text) == var
                ):
                    freed.pop(var, None)
                    continue
                if self._uses_freed_var(line.text, var, release_api_names=self._release_names):
                    self._emit_use_after_release(
                        issues,
                        func_name,
                        file_path,
                        lines,
                        allowed_skills,
                        var,
                        free_line,
                        free_api,
                        line,
                    )
                    emitted_uaf.add(var)

            for var, state in list(live.items()):
                if var in emitted_null_deref:
                    continue
                if line.index <= state.line.index:
                    continue
                if self._is_transfer(line.text, var):
                    live[var] = replace(state, transferred=True)
                    continue
                if self._is_null_guard(line.text, var):
                    continue
                if self._is_direct_deref(line.text, var) and not state.null_guarded:
                    self._emit(
                        issues,
                        func_name,
                        file_path,
                        lines,
                        allowed_skills,
                        defect_class="null_pointer_dereference",
                        rule="clang_cfg_alloc_result_deref_without_null_guard",
                        line=line,
                        description=f"`{var}` 在可见的空指针检查之前就被解引用了。",
                        root_cause=(
                            "分配/获取的结果在尚无守护证明其为非空的情况下，"
                            "就在局部 CFG 路径上被使用。"
                        ),
                        suggested_fix=(
                            "在解引用之前先检查分配结果，并将失败路径" "导向清理/错误处理。"
                        ),
                        source=f"{state.api}(...) at line {state.line.number}",
                        sink=line.text,
                        confidence=0.74,
                        positive=[
                            f"line {state.line.number}: `{var}` receives `{state.api}` result",
                            f"line {line.number}: `{var}` is dereferenced",
                        ],
                        negative=[
                            "No null guard for the acquired value appears before the dereference."
                        ],
                        ast_cfg=self._ast_cfg_pack(
                            lines,
                            [
                                self._event("acquire", state.line, var, state.api, state.line.text),
                                self._event("deref", line, var, "", line.text),
                            ],
                            [state.line.number, line.number],
                        ),
                    )
                    emitted_null_deref.add(var)

            if self._is_return(line.text):
                for var, state in list(live.items()):
                    if (
                        state.transferred
                        or self._return_excludes_resource(line.text, var)
                        or self._return_exits_null_failure_path(lines, line, var)
                        or self._resource_released_in_terminal_branch_before_return(
                            lines, line, var, state.api
                        )
                    ):
                        continue
                    if state.carrier == "output_argument" and self._return_is_status_failure_exit(
                        lines, line, state.status_var
                    ):
                        continue
                    self._emit_leak_on_exit(
                        issues,
                        func_name,
                        file_path,
                        lines,
                        allowed_skills,
                        state,
                        line,
                        is_return=True,
                    )
                    if not terminal_branch_line:
                        live.pop(var, None)
                if not terminal_branch_line:
                    live.clear()
                    freed.clear()

        if lines:
            exit_line = lines[-1]
            for state in list(live.values()):
                if state.transferred:
                    continue
                self._emit_leak_on_exit(
                    issues,
                    func_name,
                    file_path,
                    lines,
                    allowed_skills,
                    state,
                    exit_line,
                    is_return=False,
                )

    def _emit_double_free(
        self,
        issues: List[Dict[str, Any]],
        func_name: str,
        file_path: str,
        lines: Sequence[ClangCfgLine],
        allowed_skills: Optional[Set[str]],
        var: str,
        previous_line: ClangCfgLine,
        previous_api: str,
        line: ClangCfgLine,
        api: str,
        arg: str,
    ) -> None:
        self._emit(
            issues,
            func_name,
            file_path,
            lines,
            allowed_skills,
            defect_class="double_free",
            rule="clang_cfg_same_object_released_twice",
            line=line,
            description=f"`{var}` 在同一条局部 CFG 路径上被释放了两次。",
            root_cause=(
                "资源状态在没有中间重分配、所有权转移或 NULL 重置的情况下" "达到了第二次释放。"
            ),
            suggested_fix=("仅释放资源一次，释放后清除持有者，或" "通过单一出口块合并清理路径。"),
            source=f"{previous_api}({var}) at line {previous_line.number}",
            sink=f"{api}({arg})",
            confidence=0.88,
            impact_level="high",
            positive=[
                f"line {previous_line.number}: first release of `{var}` via `{previous_api}`",
                f"line {line.number}: second release of `{var}` via `{api}`",
            ],
            negative=[],
            ast_cfg=self._ast_cfg_pack(
                lines,
                [
                    self._event("release", previous_line, var, previous_api, previous_line.text),
                    self._event("release", line, var, api, line.text),
                ],
                [previous_line.number, line.number],
            ),
        )

    def _emit_container_unlink_lifecycle_candidate(
        self,
        issues: List[Dict[str, Any]],
        func_name: str,
        file_path: str,
        lines: Sequence[ClangCfgLine],
        allowed_skills: Optional[Set[str]],
    ) -> None:
        """Find a detached container member that loses all visible ownership.

        This is deliberately based on the unlink/transfer/release protocol,
        not on container API names.  An unlink by itself is harmless when the
        member is returned, stored in another owner, or released locally.
        """

        for line in lines:
            unlink = re.search(
                r"(?P<link>[A-Za-z_]\w*(?:->|\.)[A-Za-z_]\w*)\s*=\s*"
                r"(?P<object>[A-Za-z_]\w*)\s*->\s*(?:next|prev)\s*;",
                line.text,
            )
            if not unlink:
                continue
            obj = unlink.group("object")
            tail = "\n".join(item.text for item in lines[line.index + 1 :])
            if re.search(
                self._semantic_api_pattern(rf"\b(?:free|close)\s*\([^;]*\b{re.escape(obj)}\b"),
                tail,
                re.IGNORECASE,
            ):
                continue
            if re.search(
                rf"\breturn\s+{re.escape(obj)}\s*;|"
                rf"\b[A-Za-z_]\w*(?:->|\.)[A-Za-z_]\w*\s*=\s*{re.escape(obj)}\s*;",
                tail,
            ):
                continue
            self._emit(
                issues,
                func_name,
                file_path,
                lines,
                allowed_skills,
                defect_class="memory_leak",
                rule="clang_cfg_container_unlink_without_release",
                line=line,
                description=(f"容器成员 `{obj}` 被解除链接，却缺少可见的释放或所有权转移。"),
                root_cause=(
                    "该对象已无法从其容器到达，且后续没有任何局部操作"
                    "为其建立新的持有者或将其释放。"
                ),
                suggested_fix="在返回之前释放被分离的对象，或将其转移给显式的持有者。",
                source=f"{obj} ownership before line {line.number}",
                sink=line.text,
                confidence=0.86,
                impact_level="high",
                positive=[
                    f"line {line.number}: container link is reassigned around `{obj}`",
                    "no local release or ownership transfer follows the unlink",
                ],
                negative=[
                    "Validator must confirm no callee retains ownership of the detached object."
                ],
                ast_cfg=self._ast_cfg_pack(
                    lines,
                    [
                        self._event("container_unlink", line, obj, "unlink", line.text),
                        self._event("exit_without_release", lines[-1], obj, "", lines[-1].text),
                    ],
                    [line.number, lines[-1].number],
                ),
            )
            return

    def _emit_incomplete_owner_cleanup_candidate(
        self,
        issues: List[Dict[str, Any]],
        func_name: str,
        file_path: str,
        lines: Sequence[ClangCfgLine],
        allowed_skills: Optional[Set[str]],
    ) -> None:
        """Emit only when initialized owner fields and cleanup are explicit."""

        initialized: Dict[Tuple[str, str], ClangCfgLine] = {}
        released: Dict[Tuple[str, str], ClangCfgLine] = {}
        for line in lines:
            assign = re.search(
                self._semantic_api_pattern(
                    r"(?P<owner>[A-Za-z_]\w*)\s*(?:->|\.)\s*(?P<field>[A-Za-z_]\w*)\s*=\s*"
                    r"[^;]*(?:malloc|calloc|realloc|strdup|open|create|dup(?:licate)?)\s*\("
                ),
                line.text,
                re.IGNORECASE,
            )
            if assign:
                initialized[(assign.group("owner"), assign.group("field"))] = line
            release = re.search(
                self._semantic_api_pattern(
                    r"\b(?:free|close)\s*\(\s*"
                    r"(?P<owner>[A-Za-z_]\w*)\s*(?:->|\.)\s*(?P<field>[A-Za-z_]\w*)"
                ),
                line.text,
                re.IGNORECASE,
            )
            if release:
                released[(release.group("owner"), release.group("field"))] = line
        owners = sorted({owner for owner, _field in initialized})
        for owner in owners:
            owned = {
                (candidate_owner, field)
                for candidate_owner, field in initialized
                if candidate_owner == owner
            }
            cleaned = owned & set(released)
            missing = sorted(
                field for candidate_owner, field in owned - cleaned if candidate_owner == owner
            )
            if len(owned) < 2 or not cleaned or not missing:
                continue
            cleanup_line = min((released[item] for item in cleaned), key=lambda item: item.index)
            first_init = min((initialized[item] for item in owned), key=lambda item: item.index)
            self._emit(
                issues,
                func_name,
                file_path,
                lines,
                allowed_skills,
                defect_class="incomplete_cleanup",
                rule="clang_cfg_incomplete_owned_member_cleanup",
                line=cleanup_line,
                description=(
                    f"持有者 `{owner}` 初始化了多个资源字段，但其可见清理遗漏了 "
                    f"`{', '.join(missing)}`。"
                ),
                root_cause="复合持有者只重置了其显式获取的资源中的一部分。",
                suggested_fix="在 destroy/reset 路径上释放或转移每个已初始化的持有字段。",
                source=f"{owner} owned fields at line {first_init.number}",
                sink=cleanup_line.text,
                confidence=0.88,
                impact_level="high",
                positive=[
                    f"line {first_init.number}: `{owner}` initializes {len(owned)} owned fields",
                    f"line {cleanup_line.number}: cleanup releases only a strict subset of those fields",
                ],
                negative=[
                    "Validator must confirm omitted fields are not released by an owner destructor called on this path."
                ],
                ast_cfg=self._ast_cfg_pack(
                    lines,
                    [
                        self._event("owner_init", first_init, owner, "", first_init.text),
                        self._event(
                            "partial_owner_cleanup", cleanup_line, owner, "", cleanup_line.text
                        ),
                    ],
                    [first_init.number, cleanup_line.number],
                ),
            )
            return

    def _track_heap_thread_argument_owner(
        self,
        line: ClangCfgLine,
        allocations: Dict[str, ClangCfgLine],
        released: Set[str],
        thread_sinks: Dict[str, Tuple[ClangCfgLine, str]],
    ) -> None:
        alloc = re.search(
            self._semantic_api_pattern(
                r"\b(?P<var>[A-Za-z_]\w*)\s*=\s*(?:\([^)]*\)\s*)?"
                r"(?P<api>(?:malloc|calloc|realloc|strdup))\s*\("
            ),
            line.text,
            re.IGNORECASE,
        )
        if alloc:
            allocations.setdefault(alloc.group("var"), line)

        for api, args in self._calls(line.text):
            split = self._split_args(args)
            if api in self._release_names or api in {"free"}:
                if split:
                    var = self._resource_var(split[0])
                    if var:
                        released.add(var)
                continue
            if api != "pthread_create" or len(split) < 4:
                continue
            thread_arg = split[3]
            for var in allocations:
                if re.search(rf"&\s*{re.escape(var)}\s*(?:\[|\b)", thread_arg):
                    worker = split[2].strip() if len(split) >= 3 else ""
                    thread_sinks[var] = (line, worker)

    def _emit_heap_thread_argument_owner_leaks(
        self,
        issues: List[Dict[str, Any]],
        func_name: str,
        file_path: str,
        lines: Sequence[ClangCfgLine],
        allowed_skills: Optional[Set[str]],
        allocations: Dict[str, ClangCfgLine],
        released: Set[str],
        thread_sinks: Dict[str, Tuple[ClangCfgLine, str]],
    ) -> None:
        for var, alloc_line in allocations.items():
            sink_data = thread_sinks.get(var)
            if not sink_data or var in released:
                continue
            sink_line, worker = sink_data
            self._emit(
                issues,
                func_name,
                file_path,
                lines,
                allowed_skills,
                defect_class="memory_leak",
                rule="clang_cfg_heap_thread_argument_owner_not_released",
                line=alloc_line,
                description=(
                    f"`{var}` 被堆分配，且其元素地址被传给 `pthread_create`，"
                    "但持有者的分配在此所有权作用域中从未被释放。"
                ),
                root_cause="线程参数存储仍由初始化者持有，而工作线程只接收到元素地址。",
                suggested_fix="将持有者数组存入分发者状态并在关闭期间释放，或以明确的工作线程侧释放契约为每线程分配参数。",
                source=f"{var} allocation at line {alloc_line.number}",
                sink=sink_line.text,
                confidence=0.82,
                impact_level="high",
                positive=[
                    f"line {alloc_line.number}: `{var}` receives heap storage",
                    f"line {sink_line.number}: `pthread_create` passes an address derived from `{var}` to `{worker}`",
                    "no matching configured release for the owner allocation appears in the function",
                ],
                negative=[
                    "Validator must confirm ownership is not intentionally retained in a global field."
                ],
                ast_cfg=self._ast_cfg_pack(
                    lines,
                    [
                        self._event("heap_thread_arg_owner", alloc_line, var, "", alloc_line.text),
                        self._event("thread_arg_escape", sink_line, var, worker, sink_line.text),
                    ],
                    [alloc_line.number, sink_line.number],
                ),
            )

    def _maybe_emit_role_release_mismatch(
        self,
        issues: List[Dict[str, Any]],
        func_name: str,
        file_path: str,
        lines: Sequence[ClangCfgLine],
        allowed_skills: Optional[Set[str]],
        line: ClangCfgLine,
    ) -> None:
        release = re.search(
            r"\b(?P<api>[A-Za-z_]\w*release_by_role)\s*\(\s*(?P<node>[A-Za-z_]\w*)\s*,\s*(?P<release_role>\d+)\s*\)",
            line.text,
        )
        if not release:
            return
        node = release.group("node")
        release_role = release.group("release_role")
        role_line = None
        role_value = ""
        for item in reversed(lines[max(0, line.index - 8) : line.index]):
            match = re.search(
                rf"\b{re.escape(node)}->role\s*==\s*(?P<role>\d+)",
                item.text,
            )
            if match:
                role_line = item
                role_value = match.group("role")
                break
        if role_line is None or role_value == release_role:
            return
        if any("release_by_role" in item.text for item in lines[role_line.index + 1 : line.index]):
            return
        self._emit(
            issues,
            func_name,
            file_path,
            lines,
            allowed_skills,
            defect_class="memory_leak",
            rule="clang_cfg_role_specific_release_argument_mismatch",
            line=line,
            description="角色特定清理忽略了存储的角色，并调用了不匹配的释放路径。",
            root_cause="清理辅助函数仅释放由其字面角色参数选定的资源类，却把实际存储角色对应的资源遗留了下来。",
            suggested_fix="将存储的角色传给释放辅助函数，或显式释放每个角色占有的成员。",
            source=role_line.text,
            sink=line.text,
            confidence=0.84,
            impact_level="high",
            positive=[
                f"line {role_line.number}: branch checks stored role `{role_line.text.strip()}`",
                f"line {line.number}: `{release.group('api')}` is called with literal role `{release_role}`",
            ],
            negative=[],
            ast_cfg=self._ast_cfg_pack(
                lines,
                [
                    self._event(
                        "role_check", role_line, f"{node}->role", role_value, role_line.text
                    ),
                    self._event("role_release", line, node, release_role, line.text),
                ],
                [role_line.number, line.number],
            ),
        )

    def _maybe_emit_owned_member_leak_on_parent_release(
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
        _api, raw_parent = release
        parent = self._resource_var(raw_parent)
        if not parent or "->" in raw_parent or "." in raw_parent:
            return

        explicit = self._find_owned_member_assignment(lines, line, parent)
        if explicit is not None:
            member_line, member, rhs = explicit
            if self._owned_member_has_cleanup(
                lines, member_line.index + 1, line.index, parent, member
            ):
                return
            resource = f"{parent}->{member}"
            description = f"父对象 `{parent}` 被释放，而所占有的成员 `{resource}` 仍保持存活。"
            source = f"{resource} = {rhs} at line {member_line.number}"
            positive = [
                f"line {member_line.number}: `{resource}` receives an owned child/list resource",
                f"line {line.number}: parent `{parent}` is released without releasing `{resource}`",
            ]
        else:
            missing_common = self._find_missing_common_owned_member_cleanup(lines, line, parent)
            if missing_common is not None:
                member_line, member = missing_common
                resource = f"{parent}->{member}"
                description = f"父对象 `{parent}` 被释放，而共同的持有成员 `{resource}` 未被清理。"
                source = member_line.text
                positive = [
                    f"line {member_line.number}: `{parent}` is created by an allocator/helper that initializes owned members",
                    f"line {line.number}: parent `{parent}` is released without releasing `{resource}`",
                ]
            else:
                if not self._looks_like_parent_delete_without_member_cleanup(
                    func_name, lines, line, parent
                ):
                    return
                resource = f"{parent}->child_list"
                description = (
                    f"父对象 `{parent}` 被释放，却缺少对所占有的子节点/链表成员的可见清理。"
                )
                source = self._parent_declaration_text(lines, line, parent) or parent
                positive = [
                    f"line {line.number}: parent `{parent}` is released in a delete/remove/destroy-style function",
                    "no visible walk or release of child/list members appears before the parent release",
                ]

        self._emit(
            issues,
            func_name,
            file_path,
            lines,
            allowed_skills,
            defect_class="memory_leak",
            rule="clang_cfg_parent_release_without_owned_member_cleanup",
            line=line,
            description=description,
            root_cause="释放容器对象并不会释放所占有的子节点/链表成员，除非清理先遍历并释放这些成员。",
            suggested_fix="在释放父对象之前先释放或转移每个持有子节点/链表成员。",
            source=source,
            sink=line.text,
            confidence=0.78,
            impact_level="high",
            positive=positive,
            negative=[
                "Validator must confirm the member is owned by the parent and no out-of-line destructor dominates this release."
            ],
            ast_cfg=self._ast_cfg_pack(
                lines,
                [self._event("owned_member_leak", line, resource, "", line.text)],
                [line.number],
            ),
        )

    def _maybe_emit_error_log_allocation_leak(
        self,
        issues: List[Dict[str, Any]],
        func_name: str,
        file_path: str,
        lines: Sequence[ClangCfgLine],
        allowed_skills: Optional[Set[str]],
        line: ClangCfgLine,
    ) -> None:
        alloc = re.search(
            self._semantic_api_pattern(
                r"\b(?P<var>[A-Za-z_]\w*)\s*=\s*(?:\([^)]*\)\s*)?"
                r"(?P<api>(?:malloc|calloc|realloc|strdup))\s*\("
            ),
            line.text,
            re.IGNORECASE,
        )
        if not alloc:
            return
        var = alloc.group("var")
        later = lines[line.index + 1 : line.index + 16]
        release_re = re.compile(
            self._semantic_api_pattern(rf"\b(?:free)\s*\(\s*{re.escape(var)}\s*\)")
        )
        log_line: Optional[ClangCfgLine] = None
        for item in later:
            if release_re.search(item.text):
                return
            if re.search(rf"\bLOG_[A-Z_]*\s*\([^;]*\b{re.escape(var)}\b", item.text):
                log_line = item
                continue
            if log_line and re.search(r"\breturn\s+-1\s*;", item.text):
                self._emit(
                    issues,
                    func_name,
                    file_path,
                    lines,
                    allowed_skills,
                    defect_class="memory_leak",
                    rule="clang_cfg_log_error_path_allocation_not_released",
                    line=line,
                    description=f"`{var}` 为日志记录而被分配，而某个错误分支在未释放它的情况下就返回了。",
                    root_cause="错误日志路径消费了已分配的消息，却在返回前既未转移也未释放所有权。",
                    suggested_fix="在错误返回之前释放已分配的日志缓冲区，或改用栈上/静态日志缓冲区。",
                    source=line.text,
                    sink=item.text,
                    confidence=0.84,
                    impact_level="high",
                    positive=[
                        f"line {line.number}: `{var}` receives allocated storage",
                        f"line {log_line.number}: error logging uses `{var}`",
                        f"line {item.number}: error return occurs before a matching configured release",
                    ],
                    negative=[],
                    ast_cfg=self._ast_cfg_pack(
                        lines,
                        [
                            self._event(
                                "log_buffer_alloc", line, var, alloc.group("api"), line.text
                            ),
                            self._event("log_error_use", log_line, var, "LOG", log_line.text),
                            self._event("error_return", item, var, "", item.text),
                        ],
                        [line.number, log_line.number, item.number],
                    ),
                )
                return

    def _maybe_emit_refcount_free_without_protocol(
        self,
        issues: List[Dict[str, Any]],
        func_name: str,
        file_path: str,
        lines: Sequence[ClangCfgLine],
        allowed_skills: Optional[Set[str]],
        line: ClangCfgLine,
        idx: int,
    ) -> None:
        release = re.search(
            self._semantic_api_pattern(r"\b(?:free)\s*\(\s*(?P<var>[A-Za-z_]\w*)\s*\)"), line.text
        )
        if not release:
            return
        var = release.group("var")
        window_lines = lines[max(0, idx - 18) : idx + 1]
        window = "\n".join(item.text for item in window_lines)
        ref_line = next(
            (
                item
                for item in reversed(window_lines)
                if re.search(rf"\b{re.escape(var)}->ref_count\s*=", item.text)
                or re.search(rf"\b{re.escape(var)}->ref_count\b", item.text)
            ),
            None,
        )
        if not ref_line:
            return
        if re.search(rf"\b{re.escape(var)}->ref_count\s*(?:--|-=)", window):
            return
        if re.search(rf"\b{re.escape(var)}->ref_count\s*(?:==|<=|<)\s*1", window):
            return
        self._emit(
            issues,
            func_name,
            file_path,
            lines,
            allowed_skills,
            defect_class="missing_refcount",
            rule="clang_cfg_shared_resource_freed_without_refcount_protocol",
            line=line,
            description=f"共享资源 `{var}` 在未检查或更新其引用计数协议的情况下就被释放了。",
            root_cause="关闭路径在释放共享/入表对象之前绕过了对未决引用的核算。",
            suggested_fix="在释放资源之前先递减/检查引用计数并将其取消链接。",
            source=f"ref_count evidence at line {ref_line.number}",
            sink=line.text,
            confidence=0.82,
            impact_level="high",
            positive=[
                f"line {ref_line.number}: `{var}->ref_count` is maintained for the resource",
                f"line {line.number}: `{var}` is freed without a visible ref_count decrement or zero/one check",
            ],
            negative=[
                "Validator must confirm no helper on the same path performs the refcount protocol."
            ],
            ast_cfg=self._ast_cfg_pack(
                lines,
                [
                    self._event("refcount_state", ref_line, var, "ref_count", ref_line.text),
                    self._event("free_without_refcount", line, var, "", line.text),
                ],
                [ref_line.number, line.number],
            ),
        )

    def _maybe_emit_fd_leak_on_error_return(
        self,
        issues: List[Dict[str, Any]],
        func_name: str,
        file_path: str,
        lines: Sequence[ClangCfgLine],
        allowed_skills: Optional[Set[str]],
        line: ClangCfgLine,
    ) -> None:
        if not self._is_return(line.text):
            return
        fd_data = self._find_open_fd_without_close(lines, line)
        if fd_data is None:
            return
        open_line, fd, api = fd_data
        self._emit(
            issues,
            func_name,
            file_path,
            lines,
            allowed_skills,
            defect_class="fd_leak",
            rule="clang_cfg_fd_open_return_without_close",
            line=line,
            description=f"由 `{api}` 打开的文件描述符 `{fd}` 可能在缺少对应 close 的情况下从函数返回。",
            root_cause="错误/提前返回路径在描述符持有者仍存活的情况下退出了。",
            suggested_fix="在每个返回路径上关闭描述符，或让退出都经过共享清理。",
            source=open_line.text,
            sink=line.text,
            confidence=0.78,
            impact_level="high",
            positive=[
                f"line {open_line.number}: `{fd}` receives `{api}` descriptor",
                f"line {line.number}: return occurs before a visible `close({fd})`",
            ],
            negative=[
                "Validator must confirm the descriptor was not transferred to a durable owner before this return."
            ],
            ast_cfg=self._ast_cfg_pack(
                lines,
                [
                    self._event("fd_open", open_line, fd, api, open_line.text),
                    self._event("return_without_fd_close", line, fd, "", line.text),
                ],
                [open_line.number, line.number],
            ),
        )

    def _maybe_emit_slot_overwrite_leak(
        self,
        issues: List[Dict[str, Any]],
        func_name: str,
        file_path: str,
        lines: Sequence[ClangCfgLine],
        allowed_skills: Optional[Set[str]],
        line: ClangCfgLine,
    ) -> None:
        body_hint = f"{self._function_name_hint(func_name, lines)}\n" + "\n".join(
            item.text for item in lines[: min(len(lines), 6)]
        )
        if not re.search(
            r"(?:register|upsert|insert|set|install|add|registry|slot|plugin)",
            body_hint,
            re.IGNORECASE,
        ):
            return
        assign = re.search(
            r"\b(?P<slot>[A-Za-z_]\w*)\s*->\s*(?P<field>context|ctx|cleanup)\s*=\s*(?P<rhs>[^;]+);",
            line.text,
        )
        if not assign:
            return
        slot = assign.group("slot")
        if not self._slot_pointer_is_indexed_registry(lines, line, slot):
            return
        region = "\n".join(item.text for item in lines[max(0, line.index - 12) : line.index])
        if re.search(
            self._semantic_api_pattern(rf"\b(?:free)\s*\([^;]*\b{re.escape(slot)}\s*->"),
            region,
            re.I,
        ):
            return
        if re.search(
            rf"\bif\s*\([^)]*\b{re.escape(slot)}\s*->\s*(?:context|ctx|cleanup|handle|name)", region
        ):
            return
        self._emit(
            issues,
            func_name,
            file_path,
            lines,
            allowed_skills,
            defect_class="memory_leak",
            rule="clang_cfg_slot_overwrite_without_existing_owner_cleanup",
            line=line,
            description=f"注册表槽位 `{slot}` 在未清理其现有持有字段的情况下被覆盖。",
            root_cause="当冲突或重名复用槽位时，哈希/注册表槽位更新可能使其先前的插件或上下文状态失去所有引用。",
            suggested_fix="检查该槽位是否已被占用，并在覆盖持有字段之前先运行旧的清理/释放路径。",
            source=self._slot_pointer_source(lines, line, slot) or slot,
            sink=line.text,
            confidence=0.76,
            impact_level="high",
            positive=[
                f"line {line.number}: `{slot}->{assign.group('field')}` is overwritten in a registration/update path",
                "no cleanup of the previous slot owner is visible before the overwrite",
            ],
            negative=[
                "Validator must confirm the slot can already contain an owned context or plugin instance."
            ],
            ast_cfg=self._ast_cfg_pack(
                lines,
                [self._event("slot_overwrite", line, slot, assign.group("field"), line.text)],
                [line.number],
            ),
        )

    def _maybe_emit_stale_fd(
        self,
        issues: List[Dict[str, Any]],
        func_name: str,
        file_path: str,
        lines: Sequence[ClangCfgLine],
        allowed_skills: Optional[Set[str]],
        line: ClangCfgLine,
    ) -> None:
        match = re.search(r"\bclose\s*\(\s*(?P<fd>[A-Za-z_]\w*)\s*\)\s*;", line.text)
        if not match:
            return
        fd = match.group("fd")
        if not fd.startswith("g_") and self._release_followed_by_failure_return(lines, line):
            return
        if not fd.startswith("g_") and not self._fd_has_shared_owner_or_later_use(lines, line, fd):
            return
        later = "\n".join(item.text for item in lines[line.index + 1 : line.index + 8])
        if re.search(r"(?:g_[A-Za-z_]\w*fd|fd)\s*=\s*-1", later):
            return
        self._emit(
            issues,
            func_name,
            file_path,
            lines,
            allowed_skills,
            defect_class="stale_fd",
            rule="clang_cfg_fd_closed_without_owner_invalidation",
            line=line,
            description="文件描述符被关闭，却未在附近使持有/被监视的描述符失效。",
            root_cause="后续的事件分发可能在 close 之后重用陈旧的 fd 值。",
            suggested_fix="在 close 之后的同一同步下立即将持有描述符置为 -1。",
            source=fd,
            sink=line.text,
            confidence=0.7,
            positive=[f"line {line.number}: close without nearby fd=-1 invalidation"],
            negative=["Validator must confirm whether the fd is stored in shared watcher state."],
            ast_cfg=self._ast_cfg_pack(
                lines, [self._event("fd_close", line, fd, "close", line.text)], [line.number]
            ),
        )

    def _emit_leak_on_exit(
        self,
        issues: List[Dict[str, Any]],
        func_name: str,
        file_path: str,
        lines: Sequence[ClangCfgLine],
        allowed_skills: Optional[Set[str]],
        state: ResourceState,
        line: ClangCfgLine,
        *,
        is_return: bool,
    ) -> None:
        carrier_text = "output argument" if state.carrier == "output_argument" else "return value"
        exit_text = "return edge" if is_return else "function exit"
        self._emit(
            issues,
            func_name,
            file_path,
            lines,
            allowed_skills,
            defect_class="memory_leak",
            rule="clang_cfg_acquire_without_release_on_exit",
            line=line,
            description=f"`{state.var}` 从 `{state.api}` 获取，却未释放地到达了 {exit_text}。",
            root_cause=(
                "局部 CFG 状态存在获取事件，但在到达退出边之前" "没有匹配的释放或所有权转移。"
            ),
            suggested_fix=("在所有退出路径上释放该资源，或显式将所有权" "转移给调用者/容器。"),
            source=f"{state.api}(...) at line {state.line.number}",
            sink=line.text or exit_text,
            confidence=0.76 if is_return else 0.7,
            positive=[
                f"line {state.line.number}: `{state.var}` acquired from `{state.api}` ({carrier_text})",
                f"line {line.number}: {exit_text} without a matching release in this function",
            ],
            negative=[
                "Validator must confirm whether ownership is transferred outside this local body."
            ],
            ast_cfg=self._ast_cfg_pack(
                lines,
                [
                    {
                        **self._event("acquire", state.line, state.var, state.api, state.line.text),
                        "object_identity": state.object_identity,
                        "resource_domain": state.resource_domain,
                        "resource_family": state.resource_family,
                    },
                    self._event("exit", line, state.var, "", line.text),
                ],
                [state.line.number, line.number],
            ),
        )

    def _allocation_is_short_lived(
        self,
        lines: Sequence[ClangCfgLine],
        line: ClangCfgLine,
    ) -> Tuple[bool, str, Optional[ClangCfgLine]]:
        assigned = re.search(
            self._semantic_api_pattern(
                r"\b(?P<var>[A-Za-z_]\w*)\s*=\s*(?:\([^)]*\)\s*)?"
                r"(?:malloc|calloc|realloc|strdup)\s*\("
            ),
            line.text,
            re.IGNORECASE,
        )
        if not assigned:
            return False, "", None
        var = assigned.group("var")
        for item in lines[line.index + 1 : line.index + 20]:
            if re.search(
                self._semantic_api_pattern(rf"\b(?:free)\s*\(\s*{re.escape(var)}\s*\)"),
                item.text,
            ):
                return True, var, item
        return False, var, None

    def _allocation_has_total_local_lifetime_proof(
        self,
        lines: Sequence[ClangCfgLine],
        line: ClangCfgLine,
        count_expr: str,
    ) -> bool:
        short_lived, var, release_line = self._allocation_is_short_lived(lines, line)
        if not short_lived or not var or release_line is None:
            return False
        if self._is_lifetime_sensitive_allocation_expr(
            count_expr, line.text
        ) and not self._has_narrowing_bound_proof(lines, line, count_expr):
            return False
        later = lines[line.index + 1 : release_line.index + 1]
        later_text = "\n".join(item.text for item in later)
        escapes = re.search(
            rf"\b(?:return\s+{re.escape(var)}|g_[A-Za-z_0-9]+\s*=\s*{re.escape(var)}|"
            rf"[A-Za-z_]\w*(?:->|\.)[A-Za-z_0-9]+\s*=\s*{re.escape(var)}|"
            rf"\*\s*[A-Za-z_]\w+\s*=\s*{re.escape(var)})",
            later_text,
        )
        if escapes:
            return False
        for item in later:
            if item.index >= release_line.index:
                break
            text = item.text.strip()
            if re.search(
                rf"\bif\s*\(\s*(?:!\s*{re.escape(var)}|{re.escape(var)}\s*==\s*(?:NULL|nullptr|0)|(?:NULL|nullptr|0)\s*==\s*{re.escape(var)})\s*\)\s*return\b",
                text,
            ):
                continue
            if re.search(r"\b(?:return|goto|break|continue)\b", text):
                return False
            if self._is_conditional_branch_header(text):
                return False
        return True

    @staticmethod
    def _is_lifetime_sensitive_allocation_expr(count_expr: str, line_text: str = "") -> bool:
        text = f"{count_expr} {line_text}".lower()
        return bool(
            re.search(
                r"\b[a-z0-9_]*(?:quota|limit|reserve|reserved|segment|window|cache|tls|thread|pool|"
                r"global|session|client|wire|header|packet|frame|record|payload|mmap|map)[a-z0-9_]*\b",
                text,
            )
            and not re.search(r"\b(?:uint8_t|uint16_t|unsigned\s+char|unsigned\s+short)\b", text)
        )

    @staticmethod
    def _resolve_recent_assignment_expr(
        lines: Sequence[ClangCfgLine],
        line: ClangCfgLine,
        expr: str,
    ) -> str:
        name = str(expr or "").strip()
        if not re.fullmatch(r"[A-Za-z_]\w*", name):
            return ""
        for item in reversed(lines[max(0, line.index - 10) : line.index]):
            match = re.search(
                rf"\b{re.escape(name)}\s*=\s*(?P<rhs>[^;]+);",
                item.text,
            )
            if match:
                return match.group("rhs").strip()
            decl = re.search(
                rf"\b(?:size_t|uint(?:32|64)_t|int|unsigned(?:\s+int)?|long|unsigned\s+long)\s+"
                rf"{re.escape(name)}\s*=\s*(?P<rhs>[^;]+);",
                item.text,
            )
            if decl:
                return decl.group("rhs").strip()
        return ""

    def _is_owned_pointer_array_element_release(
        self,
        lines: Sequence[ClangCfgLine],
        line: ClangCfgLine,
        expr: str,
    ) -> bool:
        match = re.match(r"(?P<base>.+?)\s*\[[^\]]+\]\s*$", expr.strip())
        if not match:
            return False
        base = re.sub(r"\s+", "", match.group("base"))
        previous = "\n".join(item.text for item in lines[max(0, line.index - 80) : line.index])
        later = "\n".join(item.text for item in lines[line.index + 1 : line.index + 20])
        base_re = re.escape(base)
        element_allocated = re.search(
            self._semantic_api_pattern(
                rf"{base_re}\s*\[[^\]]+\]\s*=\s*(?:\([^)]*\)\s*)?"
                r"(?:malloc|calloc|realloc|strdup)\s*\("
            ),
            previous,
            re.IGNORECASE,
        )
        base_released = re.search(
            self._semantic_api_pattern(rf"\b(?:free)\s*\(\s*{base_re}\s*\)"),
            later,
        )
        conventional_pointer_array = re.search(
            r"(?:args|argv|items|children|entries|array|list)$", base
        )
        return bool(element_allocated or (base_released and conventional_pointer_array))

    def _fd_has_shared_owner_or_later_use(
        self,
        lines: Sequence[ClangCfgLine],
        line: ClangCfgLine,
        fd: str,
    ) -> bool:
        before = "\n".join(item.text for item in lines[max(0, line.index - 16) : line.index])
        if re.search(
            rf"(?:\bg_[A-Za-z_0-9]*fd\b|->[A-Za-z_0-9]*fd\b|\.[A-Za-z_0-9]*fd\b)\s*=\s*{re.escape(fd)}\b",
            before,
        ):
            return True
        if re.search(
            rf"\b(?:watch|register|cache|store)[A-Za-z_0-9]*\s*\([^;]*\b{re.escape(fd)}\b",
            before,
            re.I,
        ):
            return True
        later_lines = []
        for item in lines[line.index + 1 : line.index + 10]:
            if self._is_return(item.text):
                break
            later_lines.append(item.text)
        later = "\n".join(later_lines)
        user_io = self._names_pattern(
            set(getattr(self, "_user_io_release_names", set()) or set())
            | set(getattr(self, "_user_send_sink_names", set()) or set())
            | set(getattr(self, "_user_recv_source_names", set()) or set())
        )
        return bool(
            re.search(
                rf"\b(?:read|recv|write|send|close|dup|fcntl|ioctl|mmap|munmap|{user_io})\s*"
                rf"\([^;]*\b{re.escape(fd)}\b",
                later,
            )
            or re.search(rf"\bg_[A-Za-z_0-9]*fd\b", later)
        )

    def _emit_use_after_release(
        self,
        issues: List[Dict[str, Any]],
        func_name: str,
        file_path: str,
        lines: Sequence[ClangCfgLine],
        allowed_skills: Optional[Set[str]],
        var: str,
        free_line: ClangCfgLine,
        free_api: str,
        use_line: ClangCfgLine,
    ) -> None:
        self._emit(
            issues,
            func_name,
            file_path,
            lines,
            allowed_skills,
            defect_class="use_after_free",
            rule="clang_cfg_use_after_release",
            line=use_line,
            description=f"`{var}` 在其已被释放之后仍被使用。",
            root_cause=(
                "局部 CFG 状态将该资源标记为已释放，且在使用之前"
                "没有出现重置、重分配或所有权重新获取。"
            ),
            suggested_fix=(
                "将使用移到释放之前，保留一个有效的持有引用，或" "在释放之后清除并守护该指针。"
            ),
            source=f"{free_api}({var}) at line {free_line.number}",
            sink=use_line.text,
            confidence=0.86,
            impact_level="high",
            positive=[
                f"line {free_line.number}: `{var}` released via `{free_api}`",
                f"line {use_line.number}: `{var}` is dereferenced or passed after release",
            ],
            negative=[],
            ast_cfg=self._ast_cfg_pack(
                lines,
                [
                    self._event("release", free_line, var, free_api, free_line.text),
                    self._event("use", use_line, var, "", use_line.text),
                ],
                [free_line.number, use_line.number],
            ),
        )

    def _slot_pointer_is_indexed_registry(
        self,
        lines: Sequence[ClangCfgLine],
        line: ClangCfgLine,
        slot: str,
    ) -> bool:
        return bool(self._slot_pointer_source(lines, line, slot))

    def _slot_pointer_source(
        self,
        lines: Sequence[ClangCfgLine],
        line: ClangCfgLine,
        slot: str,
    ) -> str:
        escaped = re.escape(slot)
        for item in reversed(lines[max(0, line.index - 16) : line.index]):
            if re.search(
                rf"\b{escaped}\s*=\s*&?\s*[A-Za-z_]\w*(?:->|\.)[A-Za-z_]\w*\s*\[[^\]]+\]",
                item.text,
            ):
                return item.text
        return ""

    def _find_open_fd_without_close(
        self,
        lines: Sequence[ClangCfgLine],
        line: ClangCfgLine,
    ) -> Optional[Tuple[ClangCfgLine, str, str]]:
        fd_open_pattern = self._names_pattern(self._fd_open_names())
        fd_close_pattern = self._names_pattern(self._fd_close_names())
        for item in reversed(lines[max(0, line.index - 28) : line.index]):
            match = re.search(
                rf"\b(?P<fd>[A-Za-z_]\w*)\s*=\s*(?P<api>{fd_open_pattern})\s*\(",
                item.text,
            )
            if not match:
                continue
            fd = match.group("fd")
            between = "\n".join(next_line.text for next_line in lines[item.index + 1 : line.index])
            if re.search(rf"\b{re.escape(fd)}\s*(?:<\s*0|==\s*-1)\b[^;]*\breturn\b", line.text):
                continue
            if re.search(rf"\b(?:{fd_close_pattern})\s*\(\s*{re.escape(fd)}\s*\)", between):
                return None
            # A callee's spelling does not prove ownership transfer. The
            # object-sensitive checker resolves contract and exit obligations.
            return item, fd, match.group("api")
        return None

    def _match_assignment_call(
        self, text: str, call_re: re.Pattern[str]
    ) -> Optional[Tuple[str, str, str]]:
        call = call_re.search(text)
        if not call:
            return None
        prefix = text[: call.start()]
        assign = re.search(
            r"(?P<lhs>[A-Za-z_]\w*(?:\s*(?:->|\.)\s*[A-Za-z_]\w*)?)\s*=\s*(?:\([^)]*\)\s*)?$",
            prefix,
        )
        if not assign:
            return None
        lhs = re.sub(r"\s+", "", assign.group("lhs"))
        contracts = [
            c
            for c in self.semantics.contracts.find(call.group("api"))
            if c.role in {"allocator", "calloc", "reallocator", "io_acquire"}
            and c.carrier.kind == "return"
            and not c.conditions
        ]
        objects = {c.carrier.resolve(self._split_args(call.group("args")), lhs) for c in contracts}
        if objects and lhs not in objects:
            if len(objects) != 1:
                return None
            lhs = next(iter(objects))
        return lhs, call.group("api"), call.group("args")

    def _match_out_param_acquire(self, text: str) -> Optional[Tuple[str, str, str, str]]:
        if not self._out_param_acquirers:
            return None
        call = self._out_acquire_call_re.search(text)
        if not call:
            return None
        status_var = ""
        prefix = text[: call.start()]
        assign = re.search(r"(?P<lhs>[A-Za-z_]\w*)\s*=\s*(?:\([^)]*\)\s*)?$", prefix)
        if assign:
            status_var = assign.group("lhs")
        api = call.group("api")
        arguments = self._split_args(call.group("args"))
        objects = {
            contract.carrier.resolve(arguments)
            for contract in self.semantics.contracts.find(api)
            if contract.carrier.kind == "output_argument" and not contract.conditions
        }
        if len(objects) == 1 and next(iter(objects)):
            return next(iter(objects)), api, call.group("args"), status_var
        return None

    def _match_null_reset(self, text: str) -> str:
        match = re.search(r"\b(?P<var>[A-Za-z_]\w*)\s*=\s*(?:NULL|nullptr|0)\s*;", text)
        return match.group("var") if match else ""

    def _uses_freed_var(self, text: str, var: str, *, release_api_names: Set[str]) -> bool:
        if self._is_call_to(text, release_api_names):
            return False
        if self._is_var_redefined(text, var):
            return False
        if self._is_direct_deref(text, var):
            return True
        for api, args in self._calls(text):
            if api in release_api_names:
                continue
            if any(
                self._resource_var(arg) == var or self._resource_expr(arg) == var
                for arg in self._split_args(args)
            ):
                return True
        return False

    def _is_direct_deref(self, text: str, var: str) -> bool:
        escaped = re.escape(var)
        if re.search(rf"\b{escaped}\s*->", text):
            return True
        if re.search(rf"\*\s*{escaped}\b", text):
            return True
        if re.search(rf"\b{escaped}\s*\[", text):
            return True
        return False

    def _return_excludes_resource(self, text: str, var: str) -> bool:
        escaped = re.escape(var)
        if re.search(rf"\breturn\s+{escaped}\s*;", text):
            return True
        if re.search(rf"\bif\s*\(\s*!\s*{escaped}\s*\)\s*return\b", text):
            return True
        return False

    def _return_exits_null_failure_path(
        self,
        lines: Sequence[ClangCfgLine],
        line: ClangCfgLine,
        var: str,
    ) -> bool:
        if not re.search(r"\breturn\s+(?:NULL|nullptr|0|-1)\s*;", line.text):
            return False
        escaped = re.escape(var)
        null_guard = rf"\bif\s*\([^)]*(?:!\s*{escaped}|{escaped}\s*==\s*(?:NULL|nullptr|0)|(?:NULL|nullptr|0)\s*==\s*{escaped})"
        if re.search(null_guard, line.text):
            return True
        branch_start = self._enclosing_branch_start(lines, line)
        return bool(branch_start and re.search(null_guard, branch_start.text))

    def _resource_released_in_terminal_branch_before_return(
        self,
        lines: Sequence[ClangCfgLine],
        line: ClangCfgLine,
        var: str,
        acquire_api: str,
    ) -> bool:
        if not self._is_terminal_conditional_branch_line(lines, line):
            return False
        branch_start = self._enclosing_branch_start(lines, line)
        start_idx = branch_start.index if branch_start is not None else line.index
        for item in lines[start_idx : line.index + 1]:
            if item.block_id != line.block_id:
                continue
            if self._line_releases_resource_before_return(item.text, var, acquire_api):
                return True
        return False

    def _line_releases_resource_before_return(self, text: str, var: str, acquire_api: str) -> bool:
        release = self._release_call_re.search(text)
        if not release:
            return False
        resolved = self._match_release(text)
        if (
            not resolved
            or resolved[1] != var
            or self.semantics.contracts.release_in_text(acquire_api, resolved[0], text, var)
            != "applies"
        ):
            return False
        ret = re.search(r"\breturn\b", text)
        return ret is None or release.start() < ret.start()

    def _return_line_after_release(
        self, lines: Sequence[ClangCfgLine], line: ClangCfgLine
    ) -> Optional[ClangCfgLine]:
        for item in lines[line.index + 1 : line.index + 5]:
            text = item.text.strip()
            if not text or text in {"}", "};"}:
                continue
            if self._match_unlock(text) and not re.search(r"\breturn\b", text):
                continue
            return item if re.search(r"\breturn\b", text) else None
        return None

    @staticmethod
    def _release_followed_by_failure_return(
        lines: Sequence[ClangCfgLine], line: ClangCfgLine
    ) -> bool:
        for item in lines[line.index + 1 : line.index + 5]:
            text = item.text.strip()
            if not text or text in {"}", "};"}:
                continue
            return bool(re.search(r"\breturn\s+(?:NULL|nullptr|-1)\s*;", text))
        return False

    def _is_status_failure_return(self, text: str, status_var: str) -> bool:
        return self._is_status_failure_condition(text, status_var) and bool(
            re.search(r"\breturn\b", text)
        )

    def _return_is_status_failure_exit(
        self,
        lines: Sequence[ClangCfgLine],
        line: ClangCfgLine,
        status_var: str,
    ) -> bool:
        if self._is_status_failure_return(line.text, status_var):
            return True
        if not self._is_return(line.text):
            return False
        branch_start = self._enclosing_branch_start(lines, line)
        return bool(
            branch_start and self._is_status_failure_condition(branch_start.text, status_var)
        )

    def _is_status_guard_line(self, text: str, status_var: str) -> bool:
        return self._is_status_failure_condition(text, status_var) or self._is_status_success_guard(
            text, status_var
        )

    @staticmethod
    def _is_status_failure_condition(text: str, status_var: str) -> bool:
        if not status_var:
            return False
        escaped = re.escape(status_var)
        patterns = [
            rf"\bif\s*\(\s*{escaped}\s*!=\s*0\s*\)",
            rf"\bif\s*\(\s*0\s*!=\s*{escaped}\s*\)",
            rf"\bif\s*\(\s*{escaped}\s*<\s*0\s*\)",
            rf"\bif\s*\(\s*{escaped}\s*\)",
            rf"\bif\s*\(\s*(?:FAILED|IS_ERR)\s*\(\s*{escaped}\s*\)\s*\)",
        ]
        return any(re.search(pattern, text) for pattern in patterns)

    @staticmethod
    def _is_status_success_guard(text: str, status_var: str) -> bool:
        if not status_var:
            return False
        escaped = re.escape(status_var)
        patterns = [
            rf"\bif\s*\(\s*{escaped}\s*==\s*0\s*\)",
            rf"\bif\s*\(\s*0\s*==\s*{escaped}\s*\)",
            rf"\bif\s*\(\s*{escaped}\s*>=\s*0\s*\)",
            rf"\bif\s*\(\s*SUCCESS\s*==\s*{escaped}\s*\)",
            rf"\bif\s*\(\s*{escaped}\s*==\s*SUCCESS\s*\)",
            rf"\bif\s*\(\s*(?:SUCCEEDED|OK)\s*\(\s*{escaped}\s*\)\s*\)",
        ]
        return any(re.search(pattern, text) for pattern in patterns)

    def _is_transfer(self, text: str, var: str) -> bool:
        escaped = re.escape(var)
        transfer_patterns = [
            rf"\breturn\s+{escaped}\s*;",
            rf"^\s*\*\s*[A-Za-z_]\w*\s*=\s*{escaped}\s*;",
            rf"\b[A-Za-z_]\w*(?:\s*(?:->|\.)\s*[A-Za-z_]\w*)+\s*=\s*{escaped}\s*;",
            rf"\b[A-Za-z_]\w*\s*\[[^\]]+\]\s*=\s*{escaped}\s*;",
        ]
        if any(re.search(pattern, text) for pattern in transfer_patterns):
            return True
        return any(
            event.object == var and event.applicability == "applies"
            for api, args in self._calls(text)
            for event in self.semantics.contracts.match_call(
                api, "ownership_transfer", self._split_args(args)
            )
        )

    def _uses_resource_value(self, text: str, var: str) -> bool:
        if self._is_var_redefined(text, var):
            return False
        if self._is_direct_deref(text, var):
            return True
        for _api, args in self._calls(text):
            if any(self._resource_var(arg) == var for arg in self._split_args(args)):
                return True
        return False

    def _is_global_owner_lvalue(self, value: str) -> bool:
        """Identify explicit global storage, not a naming-only local alias."""

        return any(
            c.effects_trusted
            and c.carrier.kind == "global"
            and c.carrier.resolve([]) == re.sub(r"\s+", "", value)
            for c in self.semantics.contracts.contracts
        )

    def _is_call_to(self, text: str, names: Set[str]) -> bool:
        if not names:
            return False
        return any(api in names for api, _ in self._calls(text))
