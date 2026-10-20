# mypy: disable-error-code="attr-defined"
"""Locking, ordering, publication, and shared-state detector implementations."""

from __future__ import annotations

import hashlib
import json
import re
from .shared_access import SharedAccessIndex
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
        60,
        "concurrency_shared_state",
        "lock_balance_and_callbacks",
        "_rule_lock_balance_and_callbacks",
        ("lines", "emit"),
    ),
    DetectorStage(
        "regex",
        "function",
        70,
        "concurrency_shared_state",
        "condition_variable_wait",
        "_rule_condvar_wait",
        ("lines", "emit"),
    ),
    DetectorStage(
        "regex",
        "function",
        110,
        "concurrency_shared_state",
        "concurrency_state",
        "_rule_concurrency_state",
        ("lines", "emit"),
    ),
    DetectorStage(
        "clang_ast_cfg",
        "function",
        20,
        "concurrency_shared_state",
        "lock_state_machine",
        "_run_lock_state_machine",
        ("issues", "func_name", "file_path", "lines", "allowed_skills"),
    ),
    DetectorStage(
        "graph",
        "view",
        10,
        "concurrency_shared_state",
        "recursive_lock",
        "_rule_recursive_lock",
        ("view", "by_name", "issues"),
    ),
    DetectorStage(
        "graph",
        "view",
        60,
        "concurrency_shared_state",
        "publication_and_lifetime_order",
        "_rule_publication_and_lifetime_order",
        ("view", "issues"),
        covers=("resource_lifecycle",),
    ),
    DetectorStage(
        "graph",
        "view",
        90,
        "concurrency_shared_state",
        "callee_key_generation_race",
        "_rule_callee_key_generation_race",
        ("view", "by_name", "issues"),
    ),
    DetectorStage(
        "graph",
        "batch",
        60,
        "concurrency_shared_state",
        "timer_cascade_wait",
        "_rule_timer_cascade_wait",
        ("views", "issues"),
    ),
    DetectorStage(
        "graph",
        "batch",
        70,
        "concurrency_shared_state",
        "callback_self_destroy_protocols",
        "_rule_callback_self_destroy_protocols",
        ("views", "issues"),
        covers=("resource_lifecycle", "protocol_ownership_logic"),
    ),
    DetectorStage(
        "graph",
        "batch",
        80,
        "concurrency_shared_state",
        "lock_order_inversion",
        "_rule_lock_order_inversion",
        ("views", "issues"),
    ),
)


class RegexConcurrencySharedStateRules:
    def _rule_lock_balance_and_callbacks(self, lines: List[CodeLine], emit) -> None:
        held: List[Tuple[str, str, CodeLine]] = []
        uncertain: set[str] = set()
        for line in lines:
            for api, obj in self._bound_api_calls(line.text, {"lock"}):
                held.append((api, obj, line))
            for api, obj in self._bound_api_calls(line.text, {"unlock"}):
                for index in range(len(held) - 1, -1, -1):
                    if held[index][1] == obj and self.semantics.contracts.allows(
                        held[index][0], api
                    ):
                        if (
                            self.semantics.contracts.release_in_text(
                                held[index][0], api, line.text, obj
                            )
                            == "applies"
                        ):
                            held.pop(index)
                        else:
                            uncertain.add(obj)
                        break
            callback_call = self._callback_like_call(line.text)
            if held and held[-1][1] not in uncertain and callback_call:
                lock_line = held[-1][2]
                emit(
                    defect_class="held_lock_callback",
                    rule="callback_while_lock_held",
                    line=line,
                    description="在持有锁的情况下发起了回调/函数指针风格的调用。",
                    root_cause="外部回调代码可能重新进入同一子系统，或获取冲突的锁。",
                    suggested_fix="在锁内复制所需状态，释放锁后再调用回调。",
                    source=f"lock at line {lock_line.number}",
                    sink=line.text.strip(),
                    confidence=0.78,
                    impact_level="high",
                    positive=[
                        f"line {lock_line.number}: lock acquired",
                        f"line {line.number}: callback-like call `{callback_call}` before unlock",
                    ],
                )
            if held and held[-1][1] not in uncertain and re.search(r"\breturn\b", line.text):
                lock_line = held[-1][2]
                emit(
                    defect_class="missing_unlock",
                    rule="return_while_lock_held",
                    line=line,
                    description="函数在互斥锁/读写锁看似仍被持有的时候返回。",
                    root_cause="某条路径在匹配的解锁发生之前就退出了函数。",
                    suggested_fix="在每个返回路径之前释放锁，或使用单一的清理标签。",
                    source=f"lock at line {lock_line.number}",
                    sink=line.text.strip(),
                    confidence=0.8,
                    impact_level="high",
                    positive=[
                        f"line {lock_line.number}: lock acquired",
                        f"line {line.number}: return before matching unlock",
                    ],
                )

    def _callback_like_call(self, text: str) -> str:
        pointer_call = re.search(r"\(\s*\*\s*(?P<name>[A-Za-z_]\w*)\s*\)\s*\(", text)
        if pointer_call:
            name = pointer_call.group("name")
            if re.search(r"(?:callback|cb|handler|hook|pfn|^on_|^on[A-Z])", name, re.I):
                return f"(*{name})"
        call = re.search(
            r"\b(?P<name>[A-Za-z_]\w*(?:(?:->|\.)[A-Za-z_]\w*)?)\s*\(",
            text,
        )
        if not call:
            return ""
        name = call.group("name")
        leaf = name.split("->")[-1].split(".")[-1]
        if leaf in {"if", "for", "while", "switch", "return", "sizeof"}:
            return ""
        registrar_names = set(getattr(self, "_callback_registrar_names", set()) or set())
        if leaf in registrar_names:
            return name
        if re.search(r"(?:callback|cb|handler|hook|pfn|^on_|^on[A-Z])", leaf, re.I):
            return name
        return ""

    def _rule_condvar_wait(self, lines: List[CodeLine], emit) -> None:
        for line in lines:
            if not re.search(
                self._literal_api_pattern(r"\bpthread_cond_(?:timed)?wait\s*\("), line.text
            ):
                continue
            previous = self._previous_nonempty(lines, line.index, limit=4)
            if any(re.search(r"\bif\s*\(", item.text) for item in previous) and not any(
                re.search(r"\bwhile\s*\(", item.text) for item in previous
            ):
                emit(
                    defect_class="lost_wakeup",
                    rule="cond_wait_guarded_by_if",
                    line=line,
                    description="条件变量等待被 `if` 而非谓词循环所保护。",
                    root_cause="虚假唤醒或遗漏的谓词变化可能使线程错误地继续执行。",
                    suggested_fix="用 while 循环保护 pthread_cond_wait，以重新检查共享谓词。",
                    source="condition predicate",
                    sink=line.text.strip(),
                    confidence=0.83,
                    impact_level="high",
                    positive=[
                        "nearby branch uses `if` before pthread_cond_wait",
                        f"line {line.number}: condition variable wait",
                    ],
                )

    def _rule_concurrency_state(self, lines: List[CodeLine], emit) -> None:
        seen_race_globals: set[str] = set()
        shared_accesses = SharedAccessIndex(
            lines,
            getattr(self, "program_facts", {}),
            self._lock_names,
            self._unlock_names,
            self.semantics.contracts,
            restrict_to_semantics=self.restrict_to_semantics,
        )
        for idx, line in enumerate(lines):
            dcl = re.search(r"\bif\s*\(\s*!\s*(?P<obj>g_[A-Za-z_]\w*)\s*\)", line.text)
            if dcl:
                obj = dcl.group("obj")
                window = "\n".join(item.text for item in lines[idx + 1 : idx + 9])
                if self._lock_re.search(window) and re.search(
                    rf"\bif\s*\(\s*!\s*{re.escape(obj)}\s*\)", window
                ):
                    emit(
                        defect_class="double_checked_locking",
                        rule="double_checked_global_without_atomic",
                        line=line,
                        description=f"`{obj}` 使用了双重检查锁定，却缺少可见的原子发布。",
                        root_cause="锁外的读者可能观察到部分初始化的对象或过期的指针。",
                        suggested_fix="用同一把锁保护所有访问，或通过原子的获取/释放(acquire/release)进行发布。",
                        source=obj,
                        sink="double checked locking",
                        confidence=0.74,
                        impact_level="high",
                        positive=[
                            f"line {line.number}: first check of `{obj}` occurs outside lock"
                        ],
                    )

            publish = re.search(
                r"\b(?P<global>g_[A-Za-z_0-9.]+)\s*=\s*(?P<obj>[A-Za-z_]\w*)\s*;", line.text
            )
            if publish:
                obj = publish.group("obj")
                later = lines[idx + 1 : idx + 8]
                if any(
                    re.search(rf"\b{re.escape(obj)}->[A-Za-z_]\w*\s*=", item.text) for item in later
                ):
                    emit(
                        defect_class="object_publication",
                        rule="object_published_before_initialization",
                        line=line,
                        description=f"`{obj}` 在后续字段初始化之前就通过 `{publish.group('global')}` 被发布。",
                        root_cause="并发读者可能在所有字段都被初始化之前就观察到该对象。",
                        suggested_fix="在将该对象链接/发布到共享状态之前，先完成其初始化。",
                        source=obj,
                        sink=line.text.strip(),
                        confidence=0.81,
                        impact_level="high",
                        positive=[
                            f"line {line.number}: object is assigned to shared/global state",
                            "later lines initialize fields after publication",
                        ],
                    )

            for helper_name, obj in self._bound_api_calls(line.text, {"ownership_transfer"}):
                if (
                    self.semantics.contracts.effect_status(
                        helper_name, "ownership_transfer", line.text, object_name=obj
                    )
                    != "applies"
                ):
                    continue
                earlier = lines[max(0, idx - 12) : idx]
                later = lines[idx + 1 : idx + 10]
                allocated_before = any(
                    re.search(
                        rf"\b{re.escape(obj)}\s*=\s*(?:\([^)]*\)\s*)?"
                        rf"(?:{self._names_pattern(self._allocator_names | self._calloc_names)})\s*\(",
                        item.text,
                    )
                    for item in earlier
                )
                initialized_after = next(
                    (
                        item
                        for item in later
                        if re.search(rf"\b{re.escape(obj)}->[A-Za-z_]\w*\s*=", item.text)
                        or re.search(
                            self._literal_api_pattern(
                                rf"\bpthread_mutex_init\s*\(\s*&\s*{re.escape(obj)}->"
                            ),
                            item.text,
                        )
                    ),
                    None,
                )
                if allocated_before and initialized_after:
                    emit(
                        defect_class="object_publication",
                        rule="object_published_by_helper_before_initialization",
                        line=line,
                        description=(
                            f"`{obj}` 被传给发布辅助函数 `{helper_name}`，" "随后才进行字段初始化。"
                        ),
                        root_cause="并发读者可能在对象经辅助函数发布之后、所有字段初始化完成之前就观察到它。",
                        suggested_fix="在调用负责链接/发布对象的辅助函数之前，先完成所有字段初始化。",
                        source=obj,
                        sink=line.text.strip(),
                        confidence=0.78,
                        impact_level="high",
                        positive=[
                            f"line {line.number}: object is passed to configured ownership-transfer API `{helper_name}`",
                            f"line {initialized_after.number}: field initialization occurs after publication",
                        ],
                    )

            find_locked = re.search(
                r"\b(?P<var>[A-Za-z_]\w*)\s*=\s*[A-Za-z_]\w*find[A-Za-z_0-9]*locked\s*\(", line.text
            )
            if find_locked:
                var = find_locked.group("var")
                later = lines[idx + 1 : idx + 12]
                unlock_idx = next(
                    (item.index for item in later if self._unlock_re.search(item.text)), None
                )
                if unlock_idx is not None:
                    for item in later:
                        if item.index <= unlock_idx:
                            continue
                        if re.search(
                            rf"\b{re.escape(var)}->ref_count\s*(?:\+\+|--|\+=|-=)", item.text
                        ):
                            emit(
                                defect_class="refcount_race",
                                rule="refcount_update_after_unlock",
                                line=item,
                                description=f"`{var}->ref_count` 在释放保护锁之后被修改。",
                                root_cause="引用计数的更新不是原子的，也未受到定位该对象的那把锁的保护。",
                                suggested_fix="在同一把锁下增减引用计数，或改用原子操作。",
                                source=var,
                                sink=item.text.strip(),
                                confidence=0.84,
                                impact_level="high",
                                positive=[
                                    f"line {line.number}: object is found under lock",
                                    "unlock occurs before the refcount update",
                                    f"line {item.number}: ref_count is updated",
                                ],
                            )
                            break

            callback_ctx = re.search(
                r"\b(?P<global>g_[A-Za-z_0-9]*(?:callback|cb)[A-Za-z_0-9]*)\s*="
                r"\s*(?P<obj>[A-Za-z_]\w*find[A-Za-z_0-9]*locked\s*\([^;]+)",
                line.text,
                re.IGNORECASE,
            )
            if callback_ctx:
                later = lines[idx + 1 : idx + 8]
                if any(self._unlock_re.search(item.text) for item in later):
                    emit(
                        defect_class="use_after_free",
                        rule="global_callback_context_borrowed_under_lock",
                        line=line,
                        description="全局回调上下文保存了一个之后可能被释放的借用缓存条目。",
                        root_cause="该条目指针被保存到全局，却既未取得所有权，也未持有受保护的引用。",
                        suggested_fix="保存一份拥有所有权的引用/副本，或在移除条目之前注销/清除该回调。",
                        source=callback_ctx.group("obj"),
                        sink=line.text.strip(),
                        confidence=0.8,
                        impact_level="high",
                        positive=[
                            f"line {line.number}: global callback context assigned from locked lookup",
                            "the lock is released after storing the borrowed pointer",
                        ],
                    )

            race = shared_accesses.match(line)
            if race and not (self._lock_re.search(line.text) or self._unlock_re.search(line.text)):
                global_name = race.group("global")
                if global_name not in seen_race_globals and re.search(
                    r"\+\+|--|while\s*\(|if\s*\(|=[^=]", line.text
                ):
                    seen_race_globals.add(global_name)
                    emit(
                        defect_class="race",
                        rule="unsynchronized_shared_flag_or_counter",
                        line=line,
                        description=f"`{global_name}` 在未见到明显锁或原子操作的情况下被访问。",
                        root_cause="共享标志/计数器的访问未能跨线程一致地同步。",
                        suggested_fix="对该共享状态的所有读写都使用互斥锁或原子操作。",
                        source=global_name,
                        sink=line.text.strip(),
                        confidence=0.68,
                        positive=[f"line {line.number}: unsynchronized shared global access"],
                    )

            if re.search(r"\breturn\s+[A-Za-z_]\w+\s*;", line.text):
                self._emit_borrowed_after_unlock(lines, line, emit)

    @staticmethod
    def _previous_nonempty(lines: List[CodeLine], idx: int, limit: int) -> List[CodeLine]:
        result: List[CodeLine] = []
        for item in reversed(lines[max(0, idx - limit) : idx]):
            if item.text:
                result.append(item)
        return result


class GraphConcurrencySharedStateRules:
    def _rule_recursive_lock(
        self,
        view: FunctionView,
        by_name: Dict[str, FunctionView],
        issues: List[Dict[str, Any]],
    ) -> None:
        held: List[Tuple[str, GraphLine]] = []
        uncertain: Set[str] = set()
        for line in view.lines:
            lock = self._lock_arg(line.text)
            if lock:
                held.append((lock, line))
                continue
            if self._release_held_lock(line.text, held, uncertain):
                continue
            possible = [item for item in held if item[0] not in uncertain]
            if not possible:
                continue
            for call_name in self._call_targets_for_line(view.name, line):
                callee = by_name.get(call_name) or self._view_for(call_name)
                if not callee:
                    continue
                callee_locks = [(self._lock_arg(item.text), item) for item in callee.lines]
                callee_locks = [(lock_id, item) for lock_id, item in callee_locks if lock_id]
                if not callee_locks:
                    continue
                held_lock, held_line = possible[-1]
                same_lock = next(
                    (
                        (lock_id, lock_line)
                        for lock_id, lock_line in callee_locks
                        if self._locks_may_match(held_lock, lock_id)
                    ),
                    None,
                )
                if not same_lock:
                    continue
                call_evidence = self._callee_evidence.get((view.name, call_name), {})
                reachability = self._callee_reachability_text(call_name, call_evidence)
                issues.append(
                    self._issue(
                        defect_class="deadlock",
                        rule="cross_function_recursive_lock",
                        view=view,
                        line=line,
                        description=(
                            f"`{view.name}` 可能在 `{held_lock}` 被持有期间调用 `{call_name}`；"
                            f"而 `{call_name}` 可能再次获取 `{same_lock[0]}`。"
                        ),
                        root_cause="一个自带加锁约定的辅助函数在锁已被持有的情况下被调用。",
                        suggested_fix="使用不加锁的辅助函数变体、记录调用方持锁约定，或在调用前先释放锁。",
                        source=f"{view.name}:{held_line.number}:{held_lock}",
                        sink=f"{call_name}:{same_lock[1].number}:{same_lock[0]}",
                        confidence=0.86,
                        impact_level="high",
                        positive=[
                            f"line {held_line.number}: caller acquires `{held_lock}`",
                            f"line {line.number}: caller invokes `{call_name}` while lock is held",
                            reachability,
                            f"{call_name} line {same_lock[1].number}: callee acquires `{same_lock[0]}`",
                        ],
                        negative=[
                            "Verify feasible acquisition-success branches, lock identity and recursive mutex attributes; lexical order is not a path proof."
                        ],
                        evidence={
                            "proof_authority": False,
                            "acquisition_applicability": "possible_success",
                            "path": {
                                "caller": view.name,
                                "callee": call_name,
                                "call_line": line.number,
                                "call_evidence": call_evidence,
                                "path_constraints": [
                                    "same thread",
                                    "callee reachable from locked region",
                                    "both acquisitions succeed on the same feasible execution",
                                ],
                            },
                        },
                    )
                )

    def _rule_publication_and_lifetime_order(
        self,
        view: FunctionView,
        issues: List[Dict[str, Any]],
    ) -> None:
        allocs = self._local_allocated_variables(view)
        if not allocs:
            return

        for var, alloc_line in allocs.items():
            publish_line: Optional[GraphLine] = None
            unlock_after_publish: Optional[GraphLine] = None
            for line in view.lines:
                if line.index <= alloc_line.index:
                    continue
                if publish_line is None and self._line_publishes_object(line.text, var):
                    publish_line = line
                    continue
                if (
                    publish_line is not None
                    and line.index > publish_line.index
                    and self._unlock_call_re.search(line.text)
                ):
                    unlock_after_publish = line
                    break
            if publish_line and unlock_after_publish:
                late_init = next(
                    (
                        line
                        for line in view.lines
                        if line.index > unlock_after_publish.index
                        and (
                            (
                                re.search(rf"\b{re.escape(var)}->\w+\s*=", line.text)
                                and not re.search(r"=\s*(?:0|NULL|nullptr)\s*;", line.text)
                            )
                            or re.search(
                                self._literal_api_pattern(
                                    rf"\bpthread_(?:mutex|cond|rwlock)_init\s*\([^;]*\b{re.escape(var)}->"
                                ),
                                line.text,
                            )
                        )
                    ),
                    None,
                )
                if late_init:
                    issues.append(
                        self._issue(
                            defect_class="object_publication",
                            rule="published_before_member_initialization",
                            view=view,
                            line=publish_line,
                            description=(f"`{var}` 在后续成员初始化完成之前就被链接或发布。"),
                            root_cause="并发读者可能在该对象被插入共享状态之后观察到部分初始化的对象。",
                            suggested_fix="在发布对象之前，先初始化所有字段和内嵌的同步原语。",
                            source=f"{view.name}:{alloc_line.number}:{var}",
                            sink=publish_line.text.strip(),
                            confidence=0.84,
                            impact_level="high",
                            positive=[
                                f"line {alloc_line.number}: `{var}` is allocated",
                                f"line {publish_line.number}: `{var}` is published to shared/container state",
                                f"line {unlock_after_publish.number}: publication lock is released",
                                f"line {late_init.number}: member initialization occurs after publication",
                            ],
                            evidence={
                                "path": {
                                    "function": view.name,
                                    "source_line": alloc_line.number,
                                    "publish_line": publish_line.number,
                                    "late_init_line": late_init.number,
                                    "complete_in_function": True,
                                    "path_constraints": [
                                        "shared/container readers can observe the object after publication"
                                    ],
                                }
                            },
                        )
                    )

            unlink_line = next(
                (
                    line
                    for line in view.lines
                    if line.index > alloc_line.index
                    and re.search(rf"\bg_[A-Za-z_0-9.]*\s*=\s*{re.escape(var)}->next\b", line.text)
                ),
                None,
            )
            if not unlink_line:
                continue
            unlock_line = next(
                (
                    line
                    for line in view.lines
                    if line.index > unlink_line.index and self._unlock_call_re.search(line.text)
                ),
                None,
            )
            free_line = next(
                (
                    line
                    for line in view.lines
                    if unlock_line
                    and line.index > unlock_line.index
                    and re.search(
                        self._semantic_api_pattern(
                            rf"\b(?:free|kfree)\s*\(\s*(?:{re.escape(var)}(?:->\w+)?|{re.escape(var)})\s*\)"
                        ),
                        line.text,
                    )
                ),
                None,
            )
            if unlink_line and unlock_line and free_line:
                issues.append(
                    self._issue(
                        defect_class="race",
                        rule="container_unlink_free_after_unlock",
                        view=view,
                        line=unlink_line,
                        description=(f"`{var}` 在容器锁下被解除链接，随后该锁被释放才被释放内存。"),
                        root_cause="在解除链接之前就观察到该节点的并发读者，可能与解锁后的成员或节点释放产生竞态。",
                        suggested_fix="使用引用计数/RCU，或将生存期锁一直持有到没有任何读者仍可能解引用该节点为止。",
                        source=unlink_line.text.strip(),
                        sink=free_line.text.strip(),
                        confidence=0.82,
                        impact_level="high",
                        positive=[
                            f"line {unlink_line.number}: global/container link is changed to `{var}->next`",
                            f"line {unlock_line.number}: container lock is released",
                            f"line {free_line.number}: `{var}` or one of its members is freed after unlock",
                        ],
                        evidence={
                            "path": {
                                "function": view.name,
                                "source_line": unlink_line.number,
                                "sink_line": free_line.number,
                                "complete_in_function": True,
                                "path_constraints": [
                                    "concurrent readers can retain references across unlink"
                                ],
                            }
                        },
                    )
                )

    def _emit_global_mode_candidate(
        self,
        view: FunctionView,
        issues: List[Dict[str, Any]],
    ) -> None:
        text = "\n".join(line.text for line in view.lines)
        assign_line = self._first_line_matching(
            view, re.compile(r"\bg_[A-Za-z_0-9]*(?:mode|use|algorithm)[A-Za-z_0-9]*\s*=")
        )
        if not assign_line or self._lock_call_re.search(text):
            return
        branch_line = self._first_line_matching(
            view, re.compile(r"\bif\s*\([^)]*g_[A-Za-z_0-9]*(?:mode|use|algorithm)[A-Za-z_0-9]*")
        )
        callback_line = self._first_line_matching(
            view, re.compile(r"\b[A-Za-z_]\w+\[[^]]+\]\.[A-Za-z_]\w+\s*\(")
        )
        if not (branch_line and callback_line):
            return
        issues.append(
            self._issue(
                defect_class="global_mode_race",
                rule="mutable_global_mode_drives_callback_without_lock",
                view=view,
                line=assign_line,
                description="一个可变的全局模式在注册与使用之间缺少同步的情况下，选择了回调路径。",
                root_cause="并发调用方可能在回调注册与派发之间改变该全局模式。",
                suggested_fix="用同一把锁保护模式和回调表，或在操作中传递一个不可变的模式快照。",
                source=assign_line.text.strip(),
                sink=callback_line.text.strip(),
                confidence=0.82,
                impact_level="high",
                positive=[
                    f"line {assign_line.number}: global mode is updated",
                    f"line {branch_line.number}: global mode controls the branch",
                    f"line {callback_line.number}: callback/function table dispatch follows that mode",
                    "no lock is visible in the function",
                ],
            )
        )

    def _emit_cas_slot_candidate(
        self,
        view: FunctionView,
        issues: List[Dict[str, Any]],
    ) -> None:
        cas_line = self._first_line_matching(
            view,
            re.compile(r"\(void\)\s*__sync_bool_compare_and_swap|__sync_bool_compare_and_swap"),
        )
        if not cas_line or not self._semantic_call_allowed(
            "__sync_bool_compare_and_swap", "standard_operation"
        ):
            return
        text = "\n".join(line.text for line in view.lines)
        if not re.search(r"\(void\)\s*__sync_bool_compare_and_swap", text):
            return
        write_line = next(
            (
                line
                for line in view.lines
                if line.index > cas_line.index
                and re.search(r"\b[A-Za-z_]\w*->(?:pid|name|state|id|proc)", line.text)
            ),
            None,
        )
        if not write_line:
            return
        issues.append(
            self._issue(
                defect_class="slot_race",
                rule="cas_result_ignored_before_slot_publication",
                view=view,
                line=cas_line,
                description="一次比较并交换(CAS)的声明结果在写入共享槽位之前被忽略。",
                root_cause="如果另一个调用方赢得了 CAS，后续的字段写入就可能破坏由该调用方所占有的槽位。",
                suggested_fix="在写入任何槽位字段之前检查 CAS 结果，并在必要时重试或失败。",
                source=cas_line.text.strip(),
                sink=write_line.text.strip(),
                confidence=0.86,
                impact_level="high",
                positive=[
                    f"line {cas_line.number}: CAS result is explicitly discarded",
                    f"line {write_line.number}: slot fields are written after the unchecked CAS",
                ],
            )
        )

    def _emit_lost_wakeup_candidate(
        self,
        view: FunctionView,
        issues: List[Dict[str, Any]],
    ) -> None:
        text = "\n".join(line.text for line in view.lines)
        if not re.search(r"\b[A-Za-z_]\w*Event\s+[A-Za-z_]\w+\s*;", text):
            return
        enqueue_line = self._first_line_matching(
            view, re.compile(r"\bg_[A-Za-z_0-9.]*list\s*=\s*&[A-Za-z_]\w+")
        )
        if not enqueue_line:
            return
        if re.search(
            self._literal_api_pattern(
                r"\b(?:pthread_cond_signal|pthread_cond_broadcast|eventfd_write|notify|trigger|wakeup)\s*\("
            ),
            text,
            re.I,
        ):
            return
        issues.append(
            self._issue(
                defect_class="lost_wakeup",
                rule="queued_local_event_without_scheduler_wakeup",
                view=view,
                line=enqueue_line,
                description="一个本地事件被加入共享调度状态，却没有相应的唤醒/触发操作。",
                root_cause="生产者发布了工作，却没有通知消费者路径已有新工作可用。",
                suggested_fix="在将事件入队之后，触发本地调度器或通过条件变量/eventfd 发出信号。",
                source="local event enqueue",
                sink=enqueue_line.text.strip(),
                confidence=0.82,
                impact_level="high",
                positive=[
                    "function creates a local event object",
                    f"line {enqueue_line.number}: local event address is linked into shared event state",
                    "no scheduler trigger or wakeup call is visible",
                ],
            )
        )

    def _emit_find_before_insert_lock_candidate(
        self,
        view: FunctionView,
        issues: List[Dict[str, Any]],
    ) -> None:
        find_line = self._first_line_matching(
            view,
            re.compile(r"\bif\s*\([^)]*(?:find|lookup)[A-Za-z_0-9]*\([^)]*\)\s*!=\s*NULL", re.I),
        )
        if not find_line:
            return
        lock_line = next(
            (
                line
                for line in view.lines
                if line.index > find_line.index and self._lock_arg(line.text)
            ),
            None,
        )
        insert_line = next(
            (
                line
                for line in view.lines
                if lock_line
                and line.index > lock_line.index
                and re.search(r"\bg_[A-Za-z_0-9.]*\s*=\s*[A-Za-z_]\w+", line.text)
            ),
            None,
        )
        if not insert_line:
            return
        issues.append(
            self._issue(
                defect_class="shared_memory_race",
                rule="lookup_before_insert_lock",
                view=view,
                line=find_line,
                description="在获取保护插入操作的锁之前，先进行了一次重复存在性/查找检查。",
                root_cause="两个创建方可能同时观察到“不存在”，进而插入重复的共享资源。",
                suggested_fix="在查找与插入过程中始终持有插入锁，或使用原子的“不存在则创建”原语。",
                source=find_line.text.strip(),
                sink=insert_line.text.strip(),
                confidence=0.84,
                impact_level="high",
                positive=[
                    f"line {find_line.number}: existence lookup occurs before lock acquisition",
                    f"line {insert_line.number}: shared/global list is updated after the lock is acquired",
                ],
            )
        )

    def _emit_state_transition_candidate(
        self,
        view: FunctionView,
        issues: List[Dict[str, Any]],
    ) -> None:
        state_lines = [
            line for line in view.lines if re.search(r"->\s*(?:proc_)?state\s*=", line.text)
        ]
        if len(state_lines) != 1:
            return
        state_line = state_lines[0]
        later_write = next(
            (
                line
                for line in view.lines
                if line.index > state_line.index
                and re.search(r"->\s*(?:pid|name|id)\s*=", line.text)
            ),
            None,
        )
        if not later_write:
            return
        issues.append(
            self._issue(
                defect_class="state_machine",
                rule="partial_state_machine_publication",
                view=view,
                line=state_line,
                description="一个状态机分支发布了状态转换，而另一个分支在未发布状态转换的情况下发布了相关的标识字段。",
                root_cause="消费者可能观察到已初始化的标识数据，而共享状态却仍对外公告一个旧的生命周期状态。",
                suggested_fix="对每个成功的发布分支，都要一致地更新生命周期状态。",
                source=state_line.text.strip(),
                sink=later_write.text.strip(),
                confidence=0.76,
                impact_level="medium",
                positive=[
                    f"line {state_line.number}: a lifecycle state is assigned in one branch",
                    f"line {later_write.number}: related identity fields are written later without another state assignment",
                ],
                negative=[
                    "Validator must confirm the later branch represents a successful publication path."
                ],
            )
        )

    def _emit_signal_handler_candidate(
        self,
        view: FunctionView,
        issues: List[Dict[str, Any]],
    ) -> None:
        text = "\n".join(line.text for line in view.lines)
        if not re.search(r"\b(?:sig|signal|exception)\b", view.name + "\n" + text, re.I):
            return
        lock_line = self._first_line_matching(
            view,
            re.compile(
                self._literal_api_pattern(
                    r"\b(?:pthread_mutex_trylock )\s*\([^;]*(?:sem|signal|exception)"
                ),
                re.I,
            ),
        )
        log_line = self._first_line_matching(
            view,
            re.compile(
                self._literal_api_pattern(
                    rf"\b(?:{self._names_pattern(set(self.semantics.format_sinks) | {'snprintf', 'printf'})})\s*\("
                )
            ),
        )
        if not (lock_line and log_line):
            shared_write = self._first_line_matching(
                view,
                re.compile(
                    self._literal_api_pattern(
                        r"\bg_[A-Za-z_0-9]+(?:->|\.)[A-Za-z_]\w+\s*=|__atomic_store_n\s*\(\s*&\s*g_"
                    ),
                    re.I,
                ),
            )
            alloc_line = self._first_line_matching(
                view,
                re.compile(self._semantic_api_pattern(r"\b(?:calloc|malloc)\s*\("), re.I),
            )
            unsafe_line = log_line or alloc_line or shared_write
            if not (unsafe_line and shared_write):
                return
            issues.append(
                self._issue(
                    defect_class="signal_race",
                    rule="signal_path_mutates_shared_state_or_logs",
                    view=view,
                    line=unsafe_line,
                    description="信号/异常路径修改了共享全局状态，并/或执行了非异步信号安全的工作。",
                    root_cause=(
                        "异步信号路径写入了共享的调用栈/运行时状态，并执行日志/内存分配，"
                        "却没有使用信号安全的交接协议。"
                    ),
                    suggested_fix="只捕获原子的/最小的信号安全数据，并将内存分配、日志和共享状态更新推迟到普通线程执行。",
                    source="signal/exception handler path",
                    sink=shared_write.text.strip(),
                    confidence=0.84,
                    impact_level="high",
                    positive=[
                        f"line {unsafe_line.number}: signal path performs logging/allocation/shared-state work",
                        f"line {shared_write.number}: signal path writes shared global runtime state",
                        "no signal-safe queue or common lock protects the shared state mutation",
                    ],
                )
            )
            return
        issues.append(
            self._issue(
                defect_class="signal_deadlock",
                rule="signal_path_uses_locking_and_formatting",
                view=view,
                line=lock_line,
                description="信号/异常路径执行了加锁以及格式化/日志操作。",
                root_cause="信号处理程序可能打断拥有同一把锁、或使用非异步信号安全例程的代码。",
                suggested_fix="只在处理程序中记录异步信号安全的数据，并将格式化/日志推迟到普通线程执行。",
                source=lock_line.text.strip(),
                sink=log_line.text.strip(),
                confidence=0.84,
                impact_level="high",
                positive=[
                    f"line {lock_line.number}: signal path takes or probes a lock",
                    f"line {log_line.number}: signal path formats or logs data",
                ],
            )
        )

    def _emit_premature_destroy_candidate(
        self,
        view: FunctionView,
        issues: List[Dict[str, Any]],
    ) -> None:
        text = "\n".join(line.text for line in view.lines)
        if not re.search(r"\bactive_[A-Za-z_0-9]*\b|active tasks", text, re.I):
            return
        condition_line = self._first_line_matching(
            view, re.compile(r"\bif\s*\([^)]*active[A-Za-z_0-9]*\s*>\s*0", re.I)
        )
        if not condition_line:
            return
        free_line = next(
            (
                line
                for line in view.lines
                if line.index > condition_line.index
                and re.search(
                    self._semantic_api_pattern(
                        r"\b(?:free)\s*\([^;]*(?:pool|pbuf|g_[A-Za-z_0-9]+)"
                    ),
                    line.text,
                    re.I,
                )
            ),
            None,
        )
        if not free_line:
            return
        publish_line = next(
            (
                line
                for line in view.lines
                if line.index < condition_line.index
                and re.search(r"\bg_[A-Za-z_0-9.]*\s*=\s*[A-Za-z_]\w+\s*;", line.text)
            ),
            None,
        )
        dangling_line = next(
            (
                line
                for line in view.lines
                if line.index > condition_line.index
                and re.search(
                    self._semantic_api_pattern(r"\b(?:free)\s*\(\s*g_[A-Za-z_0-9.]+"),
                    line.text,
                    re.I,
                )
            ),
            None,
        )
        issues.append(
            self._issue(
                defect_class="premature_destroy",
                rule="destroy_shared_pool_while_active_tasks_remain",
                view=view,
                line=condition_line,
                description="即使活动任务计数表明仍有用户存在，共享池对象也可能被销毁。",
                root_cause=(
                    "销毁路径发布了共享池指针，随后在活动任务分支中释放了全局池/缓冲区，"
                    "导致仍活跃的用户持有一个悬空的共享对象。"
                ),
                suggested_fix="对池进行引用计数，或在活动任务非零时拒绝/推迟销毁。",
                source=condition_line.text.strip(),
                sink=free_line.text.strip(),
                confidence=0.86,
                impact_level="critical",
                positive=[
                    (
                        f"line {publish_line.number}: pool pointer is published to shared/global state"
                        if publish_line
                        else "pool pointer is shared before the active-task branch"
                    ),
                    f"line {condition_line.number}: active task count is checked as non-zero",
                    f"line {free_line.number}: pool storage is released on that branch",
                    (
                        f"line {dangling_line.number}: release uses the shared/global pool pointer"
                        if dangling_line
                        else "shared pool lifetime is ended while users remain"
                    ),
                ],
            )
        )

    def _emit_registration_race_candidate(
        self,
        view: FunctionView,
        issues: List[Dict[str, Any]],
    ) -> None:
        check_line = self._first_line_matching(
            view,
            re.compile(r"\bif\s*\([^)]*g_[A-Za-z_0-9]+\s*\[[^]]+\]\s*!=\s*NULL", re.I),
        )
        if not check_line:
            return
        prior_text = "\n".join(line.text for line in view.lines[: check_line.index + 1])
        if self._lock_call_re.search(prior_text):
            return
        lock_line = next(
            (
                line
                for line in view.lines
                if line.index > check_line.index and self._lock_arg(line.text)
            ),
            None,
        )
        if lock_line is None:
            return
        update_line = next(
            (
                line
                for line in view.lines
                if line.index > lock_line.index
                and re.search(
                    r"\bg_[A-Za-z_0-9]+\s*\[[^]]+\]\s*=|->\s*(?:enqueue|dequeue|ops)\s*=", line.text
                )
            ),
            None,
        )
        if not update_line:
            return
        issues.append(
            self._issue(
                defect_class="registration_race",
                rule="global_registration_slot_checked_before_lock",
                view=view,
                line=check_line,
                description="在获取保护槽位更新的锁之前，先对全局注册槽位进行了检查。",
                root_cause="并发注册方可能在“先检查后操作”的窗口内观察或更新同一个 ops 槽位。",
                suggested_fix="在槽位的校验、查找与更新的整个过程中都持有注册锁。",
                source=check_line.text.strip(),
                sink=update_line.text.strip(),
                confidence=0.86,
                impact_level="high",
                positive=[
                    f"line {check_line.number}: global ops slot is read before lock acquisition",
                    f"line {lock_line.number}: registration lock is taken later",
                    f"line {update_line.number}: slot or old ops are updated after the delayed lock",
                ],
            )
        )

    def _emit_key_generation_race_candidate(
        self,
        view: FunctionView,
        issues: List[Dict[str, Any]],
    ) -> None:
        text = "\n".join(line.text for line in view.lines)
        path_check = self._first_line_matching(
            view, re.compile(self._literal_api_pattern(r"\b(?:access|stat|lstat)\s*\("))
        )
        key_line = self._first_line_matching(
            view, re.compile(self._literal_api_pattern(r"\b(?:ftok)\s*\("))
        )
        if not (path_check and key_line):
            return
        lock_line = self._first_line_matching(view, self._lock_call_re)
        if lock_line and lock_line.index < path_check.index:
            return
        if "path" not in text:
            return
        issues.append(
            self._issue(
                defect_class="key_generation_race",
                rule="path_state_checked_separately_from_key_generation",
                view=view,
                line=path_check,
                description="文件路径的检查与 ftok 风格的键生成以及后续的同步过程是分开进行的。",
                root_cause="路径的存在性/状态可能在检查与键推导之间发生变化，从而产生不稳定或冲突的共享键。",
                suggested_fix="在单把锁下、使用一个稳定的已打开文件描述符来生成/注册键，或拒绝路径状态发生变化。",
                source=path_check.text.strip(),
                sink=key_line.text.strip(),
                confidence=0.82,
                impact_level="medium",
                positive=[
                    f"line {path_check.number}: path state is checked",
                    f"line {key_line.number}: key is derived after the separate check",
                    "no lock covers both path check and key derivation",
                ],
            )
        )

    def _rule_callee_key_generation_race(
        self,
        view: FunctionView,
        by_name: Dict[str, FunctionView],
        issues: List[Dict[str, Any]],
    ) -> None:
        for callee in view.callees:
            if callee in by_name:
                continue
            callee_view = self._view_for(callee)
            if not callee_view:
                continue
            callee_text = "\n".join(line.text for line in callee_view.lines)
            path_check = self._first_line_matching(
                callee_view, re.compile(self._literal_api_pattern(r"\b(?:access|stat|lstat)\s*\("))
            )
            key_line = self._first_line_matching(
                callee_view, re.compile(self._literal_api_pattern(r"\b(?:ftok)\s*\("))
            )
            if not (path_check and key_line and "path" in callee_text):
                continue
            lock_line = self._first_line_matching(callee_view, self._lock_call_re)
            if lock_line and lock_line.index < path_check.index:
                continue
            call_line = self._first_line_matching(view, re.compile(rf"\b{re.escape(callee)}\s*\("))
            if not call_line:
                continue
            issues.append(
                self._issue(
                    defect_class="key_generation_race",
                    rule="callee_path_state_checked_separately_from_key_generation",
                    view=view,
                    line=call_line,
                    description="调用方到达了一个辅助函数，该辅助函数将路径状态的检查与 ftok 风格的键生成分开进行。",
                    root_cause=(
                        "某个路径/键辅助函数在一次无锁的路径状态检查之后才推导共享键，"
                        "因此调用方继承了非原子的键生成竞态。"
                    ),
                    suggested_fix="让辅助函数在单把锁下完成路径检查、键推导与注册，或使用一个稳定的已打开文件描述符。",
                    source=f"{callee}:{path_check.text.strip()}",
                    sink=f"{callee}:{key_line.text.strip()}",
                    confidence=0.8,
                    impact_level="medium",
                    positive=[
                        f"{view.name} line {call_line.number}: caller invokes `{callee}`",
                        f"{callee} line {path_check.number}: path state is checked",
                        f"{callee} line {key_line.number}: key is derived after the separate check",
                    ],
                    evidence={
                        "path": {
                            "caller_function": view.name,
                            "callee_function": callee,
                            "source_line": path_check.number,
                            "sink_line": key_line.number,
                            "complete_in_function": False,
                            "path_constraints": ["caller reaches non-atomic key generation helper"],
                        }
                    },
                )
            )

    def _rule_timer_cascade_wait(
        self,
        views: Sequence[FunctionView],
        issues: List[Dict[str, Any]],
    ) -> None:
        edges = self._lock_order_edges(views)
        for view in views:
            if not re.search(r"(?:timer|callback|tick)", view.name, re.I):
                continue
            for line in view.lines:
                callback_lock = self._lock_arg(line.text)
                if not callback_lock:
                    continue
                blocking_edge = next(
                    (
                        edge
                        for edge in edges
                        if self._locks_may_match(edge.first_lock, callback_lock)
                        and not edge.function == view.name
                    ),
                    None,
                )
                if not blocking_edge:
                    continue
                scheduler_edge = next(
                    (
                        edge
                        for edge in edges
                        if self._locks_may_match(edge.first_lock, blocking_edge.second_lock)
                        and self._locks_may_match(edge.second_lock, callback_lock)
                        and edge.function != blocking_edge.function
                    ),
                    None,
                )
                description = (
                    f"`{view.name}` 可能在等待 `{callback_lock}` 时，`{blocking_edge.function}` "
                    f"已经持有它，并随后等待 `{blocking_edge.second_lock}`。"
                )
                positive = [
                    f"line {line.number}: timer/callback takes `{callback_lock}`",
                    f"{blocking_edge.function} line {blocking_edge.first_line}: another path already holds `{blocking_edge.first_lock}`",
                    f"{blocking_edge.function} line {blocking_edge.second_line}: that path then waits on `{blocking_edge.second_lock}`",
                ]
                evidence: Dict[str, Any] = {
                    "path": {
                        "function": view.name,
                        "source_line": line.number,
                        "sink_line": blocking_edge.second_line,
                        "complete_in_function": False,
                        "path_constraints": [
                            "callback/timer path can run concurrently with close/remove path"
                        ],
                    },
                    "cascade_wait": {
                        "callback": {
                            "function": view.name,
                            "line": line.number,
                            "waits_for": callback_lock,
                        },
                        "holder": {
                            "function": blocking_edge.function,
                            "holds": blocking_edge.first_lock,
                            "holds_line": blocking_edge.first_line,
                            "waits_for": blocking_edge.second_lock,
                            "waits_line": blocking_edge.second_line,
                        },
                    },
                }
                confidence = 0.78
                impact_level = "medium"
                sink = f"{blocking_edge.function}:{blocking_edge.first_line}->{blocking_edge.second_line}"
                if scheduler_edge:
                    description = (
                        f"`{view.name}` 可能在等待 `{callback_lock}` 时，`{blocking_edge.function}` "
                        f"持有它并等待 `{blocking_edge.second_lock}`；`{scheduler_edge.function}` "
                        f"可能在持有 `{scheduler_edge.first_lock}` 的同时等待 `{scheduler_edge.second_lock}`，"
                        "从而形成多方的回调/关闭锁级联。"
                    )
                    positive.append(
                        f"{scheduler_edge.function} lines {scheduler_edge.first_line}-{scheduler_edge.second_line}: holds `{scheduler_edge.first_lock}` before waiting on `{scheduler_edge.second_lock}`"
                    )
                    evidence["cascade_wait"]["scheduler_holder"] = {
                        "function": scheduler_edge.function,
                        "holds": scheduler_edge.first_lock,
                        "holds_line": scheduler_edge.first_line,
                        "waits_for": scheduler_edge.second_lock,
                        "waits_line": scheduler_edge.second_line,
                    }
                    evidence["path"]["path_constraints"].append(
                        "scheduler/dispatch path can concurrently hold the scheduler lock"
                    )
                    confidence = 0.82
                    impact_level = "high"
                    sink = (
                        f"{blocking_edge.function}:{blocking_edge.first_line}->{blocking_edge.second_line};"
                        f"{scheduler_edge.function}:{scheduler_edge.first_line}->{scheduler_edge.second_line}"
                    )
                issues.append(
                    self._issue(
                        defect_class="deadlock",
                        rule="timer_callback_cascade_wait",
                        view=view,
                        line=line,
                        description=description,
                        root_cause="定时器/回调代码参与了经由 close/remove 路径所持锁的级联等待。",
                        suggested_fix="避免定时器/回调路径阻塞在 close/remove 所用的控制锁上，或重排关闭路径以遵循调度器/控制锁协议。",
                        source=f"{view.name}:{line.number}:{callback_lock}",
                        sink=sink,
                        confidence=confidence,
                        impact_level=impact_level,
                        positive=positive,
                        evidence=evidence,
                    )
                )
                break

    def _rule_callback_self_destroy_protocols(
        self,
        views: Sequence[FunctionView],
        issues: List[Dict[str, Any]],
    ) -> None:
        free_callbacks: Dict[str, GraphLine] = {}
        for view in views:
            arg_aliases = {"arg"}
            for line in view.lines:
                alias = re.search(
                    r"\b(?P<var>[A-Za-z_]\w*)\s*=\s*(?:\([^)]*\)\s*)?arg\b", line.text
                )
                if alias:
                    arg_aliases.add(alias.group("var"))
            free_line = next(
                (
                    line
                    for line in view.lines
                    if any(
                        re.search(
                            self._semantic_api_pattern(
                                rf"\b(?:free|kfree)\s*\(\s*{re.escape(alias)}\s*\)"
                            ),
                            line.text,
                        )
                        for alias in arg_aliases
                    )
                ),
                None,
            )
            if free_line:
                free_callbacks[view.name] = free_line

        for view in views:
            text = "\n".join(line.text for line in view.lines)
            self_arg = re.search(r"\b(?P<obj>[A-Za-z_]\w*)->callback_arg\s*=\s*(?P=obj)\s*;", text)
            cb_assign = re.search(r"\b(?P<obj>[A-Za-z_]\w*)->callback\s*=\s*(?P<rhs>[^;]+)", text)
            if not (self_arg and cb_assign and self_arg.group("obj") == cb_assign.group("obj")):
                continue
            callback_name = ""
            free_line = None
            for candidate_name in self._callback_assignment_targets(cb_assign.group("rhs")):
                candidate_free = free_callbacks.get(candidate_name)
                if not candidate_free:
                    callback_view = next(
                        (item for item in views if item.name == candidate_name), None
                    ) or self._view_for(candidate_name)
                    if callback_view:
                        candidate_free = self._callback_free_line(callback_view)
                if candidate_free:
                    callback_name = candidate_name
                    free_line = candidate_free
                    break
            if not free_line:
                continue
            obj = self_arg.group("obj")
            call_line = self._first_line_matching(
                view,
                re.compile(rf"\b{re.escape(obj)}->callback\s*\(\s*{re.escape(obj)}->callback_arg"),
            )
            if not call_line:
                continue
            post_use = next(
                (
                    line
                    for line in view.lines
                    if line.index > call_line.index
                    and re.search(rf"\b{re.escape(obj)}->", line.text)
                ),
                None,
            )
            if not post_use:
                continue
            issues.append(
                self._issue(
                    defect_class="callback_self_destroy_race",
                    rule="callback_can_free_current_event_before_reacquire",
                    view=view,
                    line=call_line,
                    description="回调将当前对象作为其上下文接收，并且可能在调用方恢复使用该对象之前将其释放。",
                    root_cause="回调约定允许自我销毁，但调用方在回调返回后仍继续解引用该对象。",
                    suggested_fix="跨回调执行期间持有引用，或在调用可能销毁该对象的回调之前标记/分离当前对象。",
                    source=f"{callback_name}:{free_line.number}",
                    sink=post_use.text.strip(),
                    confidence=0.88,
                    impact_level="high",
                    positive=[
                        f"{view.name}: callback_arg is set to the current object `{obj}`",
                        f"line {call_line.number}: callback is invoked with `{obj}->callback_arg`",
                        f"{callback_name} line {free_line.number}: callback frees the argument object",
                        f"line {post_use.number}: caller uses `{obj}` after callback returns",
                    ],
                    evidence={
                        "path": {
                            "caller": view.name,
                            "callback": callback_name,
                            "callback_free_line": free_line.number,
                            "source_line": call_line.number,
                            "sink_line": post_use.number,
                            "complete_in_function": False,
                            "path_constraints": [
                                "callback may execute synchronously and destroy its context"
                            ],
                        }
                    },
                )
            )

    @staticmethod
    def _callback_assignment_targets(rhs: str) -> List[str]:
        skip = {"NULL", "nullptr", "true", "false"}
        names = re.findall(r"\b[A-Za-z_]\w*\b", str(rhs or ""))
        return [name for name in names if name not in skip and name.startswith("_")]

    def _callback_free_line(self, view: FunctionView) -> Optional[GraphLine]:
        arg_aliases = {"arg"}
        for line in view.lines:
            alias = re.search(r"\b(?P<var>[A-Za-z_]\w*)\s*=\s*(?:\([^)]*\)\s*)?arg\b", line.text)
            if alias:
                arg_aliases.add(alias.group("var"))
        return next(
            (
                line
                for line in view.lines
                if any(
                    re.search(
                        self._literal_api_pattern(
                            rf"\b(?:free|kfree)\s*\(\s*{re.escape(alias)}\s*\)"
                        ),
                        line.text,
                    )
                    for alias in arg_aliases
                )
            ),
            None,
        )

    def _rule_lock_order_inversion(
        self,
        views: Sequence[FunctionView],
        issues: List[Dict[str, Any]],
    ) -> None:
        edges = self._lock_order_edges(views)
        seen_pairs = set()
        buckets: Dict[Tuple[str, str], List[LockOrderEdge]] = {}
        by_name = {view.name: view for view in views}

        def key(lock: str) -> str:
            return self._normalize_lock(lock).split(".")[-1]

        for edge in edges:
            buckets.setdefault((key(edge.first_lock), key(edge.second_lock)), []).append(edge)
        for left in edges:
            for right in buckets.get((key(left.second_lock), key(left.first_lock)), []):
                if left is right:
                    continue
                if not (
                    self._locks_may_match(left.first_lock, right.second_lock)
                    and self._locks_may_match(left.second_lock, right.first_lock)
                ):
                    continue
                pair_key = tuple(sorted([left.function, right.function])) + tuple(
                    sorted([left.first_lock, left.second_lock])
                )
                if pair_key in seen_pairs:
                    continue
                seen_pairs.add(pair_key)
                view = by_name.get(right.function)
                if not view:
                    continue
                line = self._line_by_number(view, right.second_line) or view.lines[0]
                issues.append(
                    self._issue(
                        defect_class="deadlock",
                        rule="cross_function_lock_order_inversion",
                        view=view,
                        line=line,
                        description=(
                            f"锁顺序反转：`{left.function}` 先取 `{left.first_lock}` 再取 `{left.second_lock}`，"
                            f"而 `{right.function}` 先取 `{right.first_lock}` 再取 `{right.second_lock}`。"
                        ),
                        root_cause="两条可达路径以相反的顺序获取同一对锁。",
                        suggested_fix="定义一个单一的全局锁顺序，并重构其中一条路径以遵循它。",
                        source=f"{left.function}:{left.first_line}->{left.second_line}",
                        sink=f"{right.function}:{right.first_line}->{right.second_line}",
                        confidence=0.84,
                        impact_level="high",
                        positive=[
                            f"{left.function} lines {left.first_line}-{left.second_line}: {left.first_lock} before {left.second_lock}",
                            f"{right.function} lines {right.first_line}-{right.second_line}: {right.first_lock} before {right.second_lock}",
                        ],
                        negative=[
                            "Verify both lock-order paths are feasible and acquisition outcomes succeed; mutually exclusive branches must not be merged."
                        ],
                        evidence={
                            "proof_authority": False,
                            "acquisition_applicability": "possible_success",
                        },
                    )
                )

    def _lock_order_edges(self, views: Sequence[FunctionView]) -> List[LockOrderEdge]:
        edges: List[LockOrderEdge] = []
        for view in views:

            def build() -> List[LockOrderEdge]:
                local_edges: List[LockOrderEdge] = []
                held: List[Tuple[str, GraphLine]] = []
                uncertain: Set[str] = set()
                for line in view.lines:
                    lock = self._lock_arg(line.text)
                    if lock:
                        for prior, prior_line in held:
                            if prior != lock and prior not in uncertain:
                                local_edges.append(
                                    LockOrderEdge(
                                        function=view.name,
                                        file_path=view.file_path,
                                        first_lock=prior,
                                        second_lock=lock,
                                        first_line=prior_line.number,
                                        second_line=line.number,
                                    )
                                )
                        held.append((lock, line))
                        continue
                    if self._release_held_lock(line.text, held, uncertain):
                        pass
                return local_edges

            cache = getattr(self, "fact_cache", None)
            if cache is None:
                edges.extend(build())
            else:
                edges.extend(cache.compute((self.fact_context, "lock-edges", view), build))
        return edges

    def _call_targets_for_line(self, caller: str, line: GraphLine) -> List[str]:
        targets = list(self._called_names(line.text))
        for (source_func, callee), evidence in self._callee_evidence.items():
            if source_func != caller or callee in targets:
                continue
            pointer_location = str(evidence.get("pointer_location") or "")
            call_line = evidence.get("call_line")
            if pointer_location and pointer_location in line.text:
                targets.append(callee)
            elif call_line and str(call_line).isdigit() and int(call_line) == line.number:
                targets.append(callee)
            elif evidence.get("dispatcher_name") == caller:
                targets.append(callee)
        return targets

    @staticmethod
    def _callee_reachability_text(callee: str, evidence: Dict[str, Any]) -> str:
        source = str(evidence.get("source") or "lexical_call")
        pointer_location = str(evidence.get("pointer_location") or "")
        dispatcher_name = str(evidence.get("dispatcher_name") or "")
        if pointer_location:
            return f"`{callee}` is a configured target of `{pointer_location}` via {source}"
        if dispatcher_name:
            return (
                f"`{callee}` is a configured handler of dispatcher `{dispatcher_name}` via {source}"
            )
        if source != "lexical_call":
            return f"`{callee}` is reachable via {source} call graph evidence"
        return f"`{callee}` appears as a direct lexical call"

    def _lock_arg(self, text: str) -> str:
        match = self._lock_call_re.search(text)
        if not match:
            return ""
        api = match.group("api")
        arguments = self.semantics.contracts.call_arguments(api, text)
        objects = {
            event.object
            for event in self.semantics.contracts.match_call(api, "lock", arguments or [])
            if event.effects_trusted and event.applicability == "applies" and event.object
        }
        return self._normalize_lock(next(iter(objects))) if len(objects) == 1 else ""

    def _release_held_lock(
        self, text: str, held: List[Tuple[str, GraphLine]], uncertain: Optional[Set[str]] = None
    ) -> bool:
        release = self._unlock_call_re.search(text)
        if release is None:
            return False
        raw_obj = self.semantics.contracts.resolve_object(
            release.group("api"),
            "unlock",
            self.semantics.contracts.call_arguments(release.group("api"), text) or [],
        )
        obj = self._normalize_lock(raw_obj)
        for index in range(len(held) - 1, -1, -1):
            lock_id, line = held[index]
            acquire = self._lock_call_re.search(line.text)
            if obj and lock_id == obj and acquire:
                status = self.semantics.contracts.release_in_text(
                    acquire.group("api"), release.group("api"), text, lock_id
                )
                if status == "applies":
                    held.pop(index)
                    if uncertain is not None:
                        uncertain.discard(obj)
                    return True
                if status == "unknown" and uncertain is not None:
                    # Retain the obligation, but it cannot establish a later
                    # recursive acquisition or lock-order edge by itself.
                    uncertain.add(obj)
                    return True
        return False

    @staticmethod
    def _normalize_lock(value: str) -> str:
        from ....semantics.contracts import ObjectBinding

        return ObjectBinding("return").resolve([], str(value or ""))

    @classmethod
    def _locks_may_match(cls, left: str, right: str) -> bool:
        if not left or not right:
            return False
        left_norm = cls._normalize_lock(left)
        right_norm = cls._normalize_lock(right)
        return left_norm == right_norm

    @staticmethod
    def _line_by_number(view: FunctionView, number: int) -> Optional[GraphLine]:
        return next((line for line in view.lines if line.number == number), None)


class ClangConcurrencySharedStateRules:
    def _run_lock_state_machine(
        self,
        issues: List[Dict[str, Any]],
        func_name: str,
        file_path: str,
        lines: Sequence[ClangCfgLine],
        allowed_skills: Optional[Set[str]],
    ) -> None:
        from ....semantics.contract_compiler import read_source_facts

        # Only the operation certified as consuming the caller's lock can be
        # exempted. An unlock effect on a business function says nothing about
        # its other acquisitions, exits, or recursive calls.
        facts = read_source_facts(
            {
                "func_name": func_name,
                "file_path": file_path,
                "code": "\n".join(item.text for item in lines),
            },
            self.semantics.contracts,
        )
        inherited_unlocks: set[tuple[str, str]] = set()
        if (
            facts.complete
            and not facts.unknown_calls
            and len(facts.calls) == 1
            and any(
                c.effects_trusted
                for c in self.semantics.contracts.find(func_name, "unlock", file_path)
            )
        ):
            operation = facts.calls[0]
            inherited_unlocks = {
                (operation.name, effect.object)
                for effect in self.semantics.contracts.match_call(
                    operation.name, "unlock", operation.arguments
                )
                if effect.effects_trusted and effect.object
            }
        held: List[LockState] = []
        uncertain_releases: set[str] = set()
        for line in lines:
            # Macro definitions and thin unlock wrappers describe a protocol;
            # they are not call sites that can establish whether a caller
            # holds the lock.  Treating their bodies as ordinary functions
            # produced one false candidate for every use of the macro.
            if line.text.lstrip().startswith("#"):
                continue
            lock = self._match_lock(line.text)
            if lock:
                api, lock_id = lock
                held.append(
                    LockState(
                        lock_id=lock_id,
                        api=api,
                        line=line,
                        definite=self.semantics.contracts.effect_status(
                            api, "lock", line.text, object_name=lock_id
                        )
                        == "applies",
                    )
                )
            unlock = self._match_unlock(line.text)
            if unlock and not held:
                api, lock_id = unlock
                if (api, lock_id) in inherited_unlocks:
                    continue
                if (
                    self.semantics.contracts.effect_status(
                        api, "unlock", line.text, object_name=lock_id
                    )
                    == "applies"
                ):
                    self._emit_unlock_without_matching_lock(
                        issues,
                        func_name,
                        file_path,
                        lines,
                        allowed_skills,
                        line,
                        api,
                        lock_id,
                    )
            elif unlock and held:
                release_api, lock_id = unlock
                # An unlock on a branch that returns does not release the
                # fall-through path.  Keeping it in the linear state machine
                # made the later normal-path unlock look unmatched.
                if not self._is_terminal_conditional_branch_line(lines, line):
                    match_idx = next(
                        (
                            idx
                            for idx in range(len(held) - 1, -1, -1)
                            if held[idx].lock_id == lock_id
                            and self.semantics.contracts.allows(held[idx].api, release_api)
                        ),
                        None,
                    )
                    if match_idx is not None:
                        if (
                            self.semantics.contracts.release_in_text(
                                held[match_idx].api, release_api, line.text, lock_id
                            )
                            == "applies"
                        ):
                            held.pop(match_idx)
                            uncertain_releases.discard(lock_id)
                        else:
                            uncertain_releases.add(lock_id)
            if not held or not self._is_return(line.text):
                continue
            lock_state = held[-1]
            if not lock_state.definite and lock_state.lock_id in uncertain_releases:
                # Two unknown effects do not establish a missing-unlock defect.
                # A definitely acquired lock retains its obligation instead.
                continue
            branch_return = self._is_terminal_conditional_branch_line(lines, line)
            if branch_return:
                # 终态分支内的 return：仅当分支体没有释放该锁、而
                # fall-through 路径会释放（说明锁确实需要释放）时，
                # 这才是"特定分支漏解锁"缺陷。其余情形维持原来的
                # 保守豁免（线性状态机对分支解锁建模会产生误报）。
                if not self._branch_return_misses_unlock(lines, line, lock_state.lock_id):
                    continue
            elif self._return_is_error_guard_for_lock(line.text, lock_state.lock_id):
                continue
            self._emit(
                issues,
                func_name,
                file_path,
                lines,
                allowed_skills,
                defect_class="missing_unlock",
                rule="clang_cfg_return_with_lock_held",
                line=line,
                description=(
                    f"函数在 `{lock_state.lock_id}` 看似仍被持有的时候返回。"
                    + ("（早退分支未释放锁，正常路径会释放。）" if branch_return else "")
                ),
                root_cause=("合成的 CFG 路径在一次锁获取之后进入返回边，" "却没有相应的解锁事件。"),
                suggested_fix=("在每条返回路径上释放锁，或让所有退出都经由一个" "公共清理块。"),
                source=f"{lock_state.api}({lock_state.lock_id}) at line {lock_state.line.number}",
                sink=line.text,
                confidence=0.8,
                positive=[
                    f"line {lock_state.line.number}: lock acquired via `{lock_state.api}`",
                    f"line {line.number}: return edge reached before matching unlock",
                ],
                negative=[],
                ast_cfg=self._ast_cfg_pack(
                    lines,
                    [
                        self._event(
                            "lock",
                            lock_state.line,
                            lock_state.lock_id,
                            lock_state.api,
                            lock_state.line.text,
                        ),
                        self._event("return", line, lock_state.lock_id, "", line.text),
                    ],
                    [lock_state.line.number, line.number],
                ),
            )
            held.clear()

    def _emit_unlock_without_matching_lock(
        self,
        issues: List[Dict[str, Any]],
        func_name: str,
        file_path: str,
        lines: Sequence[ClangCfgLine],
        allowed_skills: Optional[Set[str]],
        line: ClangCfgLine,
        api: str,
        lock_id: str,
    ) -> None:
        recent = "\n".join(item.text for item in lines[max(0, line.index - 8) : line.index])
        if re.search(r"\b(?:expects|requires|must_hold|held_by_caller)\b", recent, re.IGNORECASE):
            return
        self._emit(
            issues,
            func_name,
            file_path,
            lines,
            allowed_skills,
            defect_class="lock_protocol_violation",
            rule="clang_cfg_unlock_without_matching_lock",
            line=line,
            description=f"`{api}` 释放了 `{lock_id}`，但在本地函数体中缺少可见的匹配获取。",
            root_cause=("本地锁状态路径到达了一次解锁操作，" "却未观察到任何匹配的锁获取。"),
            suggested_fix=(
                "在解锁之前获取同一把锁、移除多余的解锁，或记录" "并强制一个“调用方持锁”的约定。"
            ),
            source="local lock-state machine",
            sink=line.text,
            confidence=0.72,
            positive=[
                f"line {line.number}: `{api}` releases `{lock_id}` with no prior local acquire"
            ],
            negative=[
                "Validator must confirm the function is not exclusively called with this lock already held."
            ],
            ast_cfg=self._ast_cfg_pack(
                lines,
                [self._event("unlock_without_local_lock", line, lock_id, api, line.text)],
                [line.number],
            ),
        )

    def _emit_unlocked_global_state_write_candidates(
        self,
        issues: List[Dict[str, Any]],
        func_name: str,
        file_path: str,
        lines: Sequence[ClangCfgLine],
        allowed_skills: Optional[Set[str]],
    ) -> None:
        writes: List[Tuple[ClangCfgLine, str, str, bool]] = []
        held: List[Tuple[str, str]] = []
        for line in lines:
            lock = self._match_lock(line.text)
            if (
                lock
                and self.semantics.contracts.effect_status(
                    lock[0], "lock", line.text, object_name=lock[1]
                )
                == "applies"
            ):
                held.append(lock)
            lhs = self._global_write_lhs(line.text)
            if lhs:
                writes.append((line, lhs, self._global_state_family(lhs), bool(held)))
            unlock = self._match_unlock(line.text)
            if unlock:
                for index in range(len(held) - 1, -1, -1):
                    if (
                        held[index][1] == unlock[1]
                        and self.semantics.contracts.release_in_text(
                            held[index][0], unlock[0], line.text, unlock[1]
                        )
                        == "applies"
                    ):
                        held.pop(index)
                        break

        families: Dict[str, List[Tuple[ClangCfgLine, str, bool]]] = {}
        for line, lhs, family, locked in writes:
            families.setdefault(family, []).append((line, lhs, locked))

        emitted: Set[str] = set()
        for family, family_writes in families.items():
            locked_writes = [item for item in family_writes if item[2]]
            unlocked_writes = [item for item in family_writes if not item[2]]
            if locked_writes and unlocked_writes and family not in emitted:
                locked_line, locked_lhs, _ = locked_writes[0]
                unlocked_line, unlocked_lhs, _ = unlocked_writes[0]
                self._emit_shared_state_candidate(
                    issues,
                    func_name,
                    file_path,
                    lines,
                    allowed_skills,
                    rule="clang_cfg_global_state_written_with_and_without_lock",
                    line=unlocked_line,
                    source=locked_line.text,
                    sink=unlocked_line.text,
                    resource=family,
                    description=f"全局共享状态 `{family}` 有时在有锁、有时在无锁的情况下被写入。",
                    positive=[
                        f"line {locked_line.number}: `{locked_lhs}` is written while a lock appears held",
                        f"line {unlocked_line.number}: `{unlocked_lhs}` is written without the same local lock evidence",
                    ],
                )
                emitted.add(family)
                continue

            if self._is_global_pointer_length_publication(family_writes) and family not in emitted:
                first_line, first_lhs, _ = family_writes[0]
                last_line, last_lhs, _ = family_writes[-1]
                self._emit_shared_state_candidate(
                    issues,
                    func_name,
                    file_path,
                    lines,
                    allowed_skills,
                    rule="clang_cfg_global_pointer_length_pair_published_without_lock",
                    line=last_line,
                    source=first_line.text,
                    sink=last_line.text,
                    resource=family,
                    description=f"全局指针/长度状态 `{family}` 在缺少可见同步的情况下被发布。",
                    positive=[
                        f"line {first_line.number}: `{first_lhs}` is written as part of a global state pair",
                        f"line {last_line.number}: `{last_lhs}` is written without a common lock around the publication",
                    ],
                )
                emitted.add(family)

    def _emit_timer_callback_lock_order_candidate(
        self,
        issues: List[Dict[str, Any]],
        func_name: str,
        file_path: str,
        lines: Sequence[ClangCfgLine],
        allowed_skills: Optional[Set[str]],
    ) -> None:
        effective_name = self._function_name_hint(func_name, lines)
        if not re.search(r"(?:timer|tick|callback|cb)", effective_name, re.IGNORECASE):
            return
        global_walk = self._first_line_matching_in(
            lines,
            re.compile(
                r"\b[A-Za-z_]\w*\s*=\s*&?\s*g_[A-Za-z_0-9]+(?:\.|->)[A-Za-z_0-9]*(?:head|list|queue|scheduler)?",
                re.IGNORECASE,
            ),
        )
        object_lock = None
        for line in lines:
            lock = self._match_lock(line.text)
            if lock and re.search(
                r"(?:->|\.)[A-Za-z_0-9]*(?:lock|mutex)", line.text, re.IGNORECASE
            ):
                object_lock = line
                break
        if global_walk is None or object_lock is None:
            return
        if any(
            self._match_lock(item.text) and "g_" in item.text for item in lines[: object_lock.index]
        ):
            return
        self._emit(
            issues,
            func_name,
            file_path,
            lines,
            allowed_skills,
            defect_class="deadlock",
            rule="clang_cfg_timer_callback_object_lock_without_scheduler_lock",
            line=object_lock,
            description="定时器/回调路径在未持有调度器锁的情况下，对来自全局调度器/链表的对象加锁。",
            root_cause="close/destroy 路径可能持有对象锁，同时等待调度器/全局锁，从而与回调路径形成锁顺序循环。",
            suggested_fix="对调度器/链表锁和逐对象锁使用统一的锁顺序，或在释放调度器锁之前对对象进行快照/引用计数。",
            source=global_walk.text,
            sink=object_lock.text,
            confidence=0.74,
            impact_level="high",
            positive=[
                f"line {global_walk.number}: callback path traverses a global scheduler/list",
                f"line {object_lock.number}: callback path then acquires a per-object lock",
            ],
            negative=[
                "Validator must confirm a reachable close/destroy path takes these locks in the opposite order."
            ],
            ast_cfg=self._ast_cfg_pack(
                lines,
                [
                    self._event(
                        "global_scheduler_walk", global_walk, "scheduler", "", global_walk.text
                    ),
                    self._event(
                        "object_lock_in_callback", object_lock, "object_lock", "", object_lock.text
                    ),
                ],
                [global_walk.number, object_lock.number],
            ),
        )

    def _emit_shared_state_candidate(
        self,
        issues: List[Dict[str, Any]],
        func_name: str,
        file_path: str,
        lines: Sequence[ClangCfgLine],
        allowed_skills: Optional[Set[str]],
        *,
        rule: str,
        line: ClangCfgLine,
        source: str,
        sink: str,
        resource: str,
        description: str,
        positive: List[str],
    ) -> None:
        self._emit(
            issues,
            func_name,
            file_path,
            lines,
            allowed_skills,
            defect_class="unsynchronized_shared_state",
            rule=rule,
            line=line,
            description=description,
            root_cause="全局共享状态的更新，缺少一个保护所有相关读写方的单一同步协议。",
            suggested_fix="用同一把锁保护该状态族的所有写入方与读取方，或以原子方式发布一个不可变快照。",
            source=source,
            sink=sink,
            confidence=0.74,
            impact_level="high",
            positive=positive,
            negative=[
                "Validator must confirm there is no higher-level serialization contract around these calls."
            ],
            ast_cfg=self._ast_cfg_pack(
                lines,
                [self._event("unsynchronized_global_state", line, resource, "", line.text)],
                [line.number],
            ),
        )

    def _maybe_emit_global_dynamic_array_resize_race(
        self,
        issues: List[Dict[str, Any]],
        func_name: str,
        file_path: str,
        lines: Sequence[ClangCfgLine],
        allowed_skills: Optional[Set[str]],
        line: ClangCfgLine,
    ) -> None:
        guard = re.search(
            r"\bif\s*\(\s*(?P<index>[A-Za-z_]\w*)\s*>=\s*(?P<cap>g_[A-Za-z_0-9]*(?:cap|capacity)[A-Za-z_0-9]*)\s*\)",
            line.text,
        )
        if not guard:
            return
        cap = guard.group("cap")
        stem = re.sub(r"(?:_cap|_capacity)$", "", cap)
        window = lines[line.index : line.index + 24]
        text = "\n".join(item.text for item in window)
        global_assign = re.search(
            rf"\b(?P<array>{re.escape(stem)}(?:_array|s|_list)?)\s*=\s*(?P<new>[A-Za-z_]\w*)\s*;",
            text,
        )
        cap_assign = re.search(rf"\b{re.escape(cap)}\s*=\s*[A-Za-z_]\w*\s*;", text)
        old_free = re.search(
            self._semantic_api_pattern(r"\b(?:free)\s*\(\s*(?:old_[A-Za-z_]\w*|old_array)\s*\)"),
            text,
        )
        if not (global_assign and cap_assign and old_free):
            return
        pre_window = "\n".join(item.text for item in lines[max(0, line.index - 5) : line.index])
        if re.search(
            self._semantic_api_pattern(r"\b(?:pthread_mutex_lock|spin_lock|mtx_lock)\s*\("),
            pre_window,
        ):
            return
        assign_line = (
            self._first_line_matching_in(
                window, re.compile(rf"\b{re.escape(global_assign.group('array'))}\s*=")
            )
            or line
        )
        self._emit(
            issues,
            func_name,
            file_path,
            lines,
            allowed_skills,
            defect_class="dynamic_array_race",
            rule="clang_cfg_global_dynamic_array_resize_without_lock",
            line=line,
            description=f"全局动态数组 `{global_assign.group('array')}` 被调整大小，旧存储则在缺少可见锁的情况下被释放。",
            root_cause="并发创建方可能在发布新的全局数组指针/容量对、并释放旧数组时发生竞态。",
            suggested_fix="用同一把互斥锁或原子所有权协议来保护容量检查、分配交接、指针发布和旧数组释放。",
            source=line.text,
            sink=assign_line.text,
            confidence=0.87,
            impact_level="high",
            positive=[
                f"line {line.number}: resize guard reads shared capacity `{cap}`",
                f"line {assign_line.number}: global array pointer is republished",
                "old array storage is freed in the resize window",
                "no lock acquisition is visible before the resize window",
            ],
            negative=[
                "Validator must confirm there is no caller-held lock dominating this helper."
            ],
            ast_cfg=self._ast_cfg_pack(
                lines,
                [
                    self._event(
                        "dynamic_array_resize_guard",
                        line,
                        global_assign.group("array"),
                        cap,
                        line.text,
                    ),
                    self._event(
                        "dynamic_array_publish",
                        assign_line,
                        global_assign.group("array"),
                        "",
                        assign_line.text,
                    ),
                ],
                [line.number, assign_line.number],
            ),
        )

    def _maybe_emit_key_generation_race(
        self,
        issues: List[Dict[str, Any]],
        func_name: str,
        file_path: str,
        lines: Sequence[ClangCfgLine],
        allowed_skills: Optional[Set[str]],
        line: ClangCfgLine,
    ) -> None:
        body_hint = f"{self._function_name_hint(func_name, lines)}\n" + "\n".join(
            item.text for item in lines
        )
        if not re.search(r"(?:key|ftok|file_exists)", body_hint, re.IGNORECASE):
            return
        if not re.search(
            r"\b[A-Za-z_]\w*\s*=\s*[^;]*(?:hash|ftok|project|path)[^;]*;", line.text, re.IGNORECASE
        ):
            return
        prefix = lines[max(0, line.index - 12) : line.index]
        suffix = lines[line.index + 1 : min(len(lines), line.index + 12)]
        path_check = next(
            (
                item
                for item in reversed(prefix)
                if re.search(
                    self._literal_api_pattern(r"\b(?:access|stat|lstat|file_exists)\s*\("),
                    item.text,
                )
            ),
            None,
        )
        locked_lookup = next(
            (
                item
                for item in suffix
                if self._match_lock(item.text)
                and re.search(
                    r"\b[A-Za-z_]\w*(?:find|lookup|register|zone)[A-Za-z_0-9]*\s*\(",
                    item.text,
                    re.I,
                )
            ),
            None,
        )
        if path_check is None or locked_lookup is None:
            return
        self._emit(
            issues,
            func_name,
            file_path,
            lines,
            allowed_skills,
            defect_class="key_generation_race",
            rule="clang_cfg_path_state_key_generation_before_locked_registration",
            line=line,
            description="路径/键状态在被锁保护的注册查找之前就被检查并哈希。",
            root_cause="基于文件/路径的键，可能在保护注册与冲突检查的那把锁之前，根据过期的路径状态生成。",
            suggested_fix="在路径校验、键生成与注册查找的整个过程中持有单把锁，或使用原子的创建/注册操作。",
            source=path_check.text,
            sink=line.text,
            confidence=0.74,
            impact_level="high",
            positive=[
                f"line {path_check.number}: path state is checked before key generation",
                f"line {line.number}: key material is computed outside the registration lock",
                f"line {locked_lookup.number}: registration/collision lookup happens later under lock",
            ],
            negative=[
                "Validator must confirm the path/key namespace is shared across concurrent callers."
            ],
            ast_cfg=self._ast_cfg_pack(
                lines,
                [
                    self._event("path_state_check", path_check, "", "", path_check.text),
                    self._event("key_generation", line, "", "", line.text),
                    self._event(
                        "locked_registration_lookup", locked_lookup, "", "", locked_lookup.text
                    ),
                ],
                [path_check.number, line.number, locked_lookup.number],
            ),
        )

    def _maybe_emit_active_owner_premature_destroy(
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
        resource = self._resource_expr(arg) or self._resource_var(arg)
        if not resource:
            return
        if not re.search(r"(?:^g_|->|\.|pool|cache|shared|global)", resource, re.IGNORECASE):
            return
        branch = self._enclosing_branch_start(lines, line)
        branch_text = branch.text if branch is not None else ""
        if not re.search(
            r"\b(?:active|users?|tasks?|refs?|refcount|inflight|pending|busy)[A-Za-z_0-9]*\b\s*(?:>|!=|>=)\s*0",
            branch_text,
            re.IGNORECASE,
        ):
            return
        guard_window = "\n".join(
            item.text for item in lines[max(0, line.index - 12) : line.index + 1]
        )
        if re.search(
            self._semantic_api_pattern(
                r"\b(?:pthread_mutex_lock|spin_lock|refcount_dec_and_test|atomic_dec_and_test)\s*\("
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
            defect_class="premature_destroy",
            rule="clang_cfg_active_owner_destroy_without_quiescence",
            line=line,
            description=f"共享资源 `{resource}` 在活动使用保护为真时被销毁。",
            root_cause=(
                "某个池/缓存/全局所有者，在显式观察到活动用户或任务的路径上被释放，"
                "却缺少可见的静默/引用计数保护。"
            ),
            suggested_fix="等待活动用户排空，或在释放之前通过引用计数的关闭路径转移所有权。",
            source=branch_text or line.text,
            sink=f"{api}({arg})",
            confidence=0.76,
            impact_level="high",
            positive=[
                f"line {branch.number if branch is not None else line.number}: active-use condition guards the branch",
                f"line {line.number}: `{resource}` is released inside that branch",
            ],
            negative=[
                "Validator must confirm no external synchronization or quiescence contract dominates this release."
            ],
            ast_cfg=self._ast_cfg_pack(
                lines,
                [
                    self._event(
                        "active_use_branch", branch or line, resource, "", branch_text or line.text
                    ),
                    self._event("premature_destroy", line, resource, api, line.text),
                ],
                [branch.number if branch is not None else line.number, line.number],
            ),
        )

    def _maybe_emit_macro_lock_race(
        self,
        issues: List[Dict[str, Any]],
        func_name: str,
        file_path: str,
        lines: Sequence[ClangCfgLine],
        allowed_skills: Optional[Set[str]],
        line: ClangCfgLine,
    ) -> None:
        macro_locks = self._macro_guard_names(lines, lock=True)
        macro_unlocks = self._macro_guard_names(lines, lock=False)
        if not macro_locks or not macro_unlocks:
            return
        match = re.search(
            r"\b(?P<global>g_[A-Za-z_0-9]*(?:counter|state|flag)[A-Za-z_0-9]*)\s*=", line.text
        )
        if not match:
            return
        if not self._line_between_macro_guards(lines, line, macro_locks, macro_unlocks):
            return
        self._emit(
            issues,
            func_name,
            file_path,
            lines,
            allowed_skills,
            defect_class="race",
            rule="clang_cfg_macro_guarded_lock_may_compile_to_noop",
            line=line,
            description=f"`{match.group('global')}` 在某个类似宏的锁保护下被更新，而在某些目标平台上该宏可能被编译为空操作(no-op)。",
            root_cause="对配置敏感的宏加锁，在不被支持的构建上可能会消失，而共享状态仍保持可变。",
            suggested_fix="使用在每个受支持目标上都存在的锁实现，或拒绝不支持的构建。",
            source=", ".join(sorted(macro_locks)),
            sink=line.text,
            confidence=0.74,
            positive=[
                "function uses macro-like lock/unlock guards",
                f"line {line.number}: shared global state is updated",
            ],
            negative=[
                "Validator must confirm the active build configuration includes a no-op macro variant."
            ],
            ast_cfg=self._ast_cfg_pack(
                lines,
                [self._event("macro_guarded_write", line, match.group("global"), "", line.text)],
                [line.number],
            ),
        )

    def _maybe_emit_callback_under_lock(
        self,
        issues: List[Dict[str, Any]],
        func_name: str,
        file_path: str,
        lines: Sequence[ClangCfgLine],
        allowed_skills: Optional[Set[str]],
        line: ClangCfgLine,
        held_locks: Sequence[ClangCfgLine],
    ) -> None:
        if not held_locks:
            return
        callback_shape = re.search(
            r"\b[A-Za-z_]\w*(?:callback|cb|handler)[A-Za-z_0-9]*\s*\(", line.text, re.IGNORECASE
        )
        registrar_call = getattr(self, "_callback_registrar_call_re", None)
        registrar_hit = bool(registrar_call and registrar_call.search(line.text))
        if not callback_shape and not registrar_hit:
            return
        lock_line = held_locks[-1]
        self._emit(
            issues,
            func_name,
            file_path,
            lines,
            allowed_skills,
            defect_class="held_lock_callback",
            rule="clang_cfg_callback_while_lock_held",
            line=line,
            description="在持有锁的情况下发起了回调/函数指针风格的调用。",
            root_cause="如果调用方能够注册非平凡的回调代码，回调约定就可能重新进入同一子系统或获取冲突的锁。",
            suggested_fix="在锁内复制所需状态，释放锁后再调用回调。",
            source=f"lock at line {lock_line.number}",
            sink=line.text,
            confidence=0.68,
            impact_level="medium",
            positive=[
                f"line {lock_line.number}: lock acquired",
                f"line {line.number}: callback-like call before unlock",
            ],
            negative=[
                "Validator must confirm whether callback registration is externally controllable or can re-enter this lock domain."
            ],
            ast_cfg=self._ast_cfg_pack(
                lines,
                [
                    self._event("lock", lock_line, "lock", "", lock_line.text),
                    self._event("callback_call", line, "callback", "", line.text),
                ],
                [lock_line.number, line.number],
            ),
        )

    def _maybe_emit_concurrency_protocols(
        self,
        issues: List[Dict[str, Any]],
        func_name: str,
        file_path: str,
        lines: Sequence[ClangCfgLine],
        allowed_skills: Optional[Set[str]],
        line: ClangCfgLine,
        idx: int,
        emitted_shared_state: Set[str],
        shared_accesses: SharedAccessIndex,
    ) -> None:
        dcl = re.search(r"\bif\s*\(\s*!\s*(?P<obj>g_[A-Za-z_]\w*)\s*\)", line.text)
        if dcl:
            obj = dcl.group("obj")
            window = "\n".join(item.text for item in lines[idx + 1 : idx + 10])
            if self._lock_call_re.search(window) and re.search(
                rf"\bif\s*\(\s*!\s*{re.escape(obj)}\s*\)", window
            ):
                self._emit(
                    issues,
                    func_name,
                    file_path,
                    lines,
                    allowed_skills,
                    defect_class="double_checked_locking",
                    rule="clang_cfg_double_checked_global_without_atomic",
                    line=line,
                    description=f"`{obj}` 在惰性初始化之前于互斥锁外被检查。",
                    root_cause="锁外的读者可能观察到过期或部分初始化的共享状态。",
                    suggested_fix="用同一把锁保护所有访问，或使用原子的获取/释放(acquire/release)发布。",
                    source=obj,
                    sink="double checked locking",
                    confidence=0.78,
                    impact_level="high",
                    positive=[f"line {line.number}: first `{obj}` check occurs outside the lock"],
                    negative=[],
                    ast_cfg=self._ast_cfg_pack(
                        lines,
                        [self._event("double_checked_read", line, obj, "", line.text)],
                        [line.number],
                    ),
                )

        publish = re.search(
            r"\b(?P<global>g_[A-Za-z_0-9.]+)\s*=\s*(?P<obj>[A-Za-z_]\w*)\s*;", line.text
        )
        if publish:
            obj = publish.group("obj")
            later = lines[idx + 1 : idx + 9]
            if any(
                re.search(rf"\b{re.escape(obj)}->[A-Za-z_]\w*\s*=", item.text) for item in later
            ):
                last_init = max(
                    (
                        item.index
                        for item in later
                        if re.search(rf"\b{re.escape(obj)}->[A-Za-z_]\w*\s*=", item.text)
                    ),
                    default=line.index,
                )
                if self._same_lock_region_without_escape(lines, idx, last_init):
                    return
                self._emit(
                    issues,
                    func_name,
                    file_path,
                    lines,
                    allowed_skills,
                    defect_class="object_publication",
                    rule="clang_cfg_object_published_before_initialization",
                    line=line,
                    description=f"`{obj}` 在后续字段初始化完成之前就被链接进共享状态。",
                    root_cause="并发读者可能在发布之后观察到部分初始化的对象。",
                    suggested_fix="在将对象插入全局/共享容器之前，先初始化所有字段。",
                    source=obj,
                    sink=line.text,
                    confidence=0.84,
                    impact_level="high",
                    positive=[
                        f"line {line.number}: object is published to `{publish.group('global')}`",
                        "later statements initialize fields after publication",
                    ],
                    negative=[],
                    ast_cfg=self._ast_cfg_pack(
                        lines,
                        [self._event("unsafe_publication", line, obj, "", line.text)],
                        [line.number],
                    ),
                )

        if re.search(self._literal_api_pattern(r"\bpthread_cond_(?:timed)?wait\s*\("), line.text):
            previous = lines[max(0, idx - 4) : idx]
            if any(re.search(r"\bif\s*\(", item.text) for item in previous) and not any(
                re.search(r"\bwhile\s*\(", item.text) for item in previous
            ):
                self._emit(
                    issues,
                    func_name,
                    file_path,
                    lines,
                    allowed_skills,
                    defect_class="lost_wakeup",
                    rule="clang_cfg_cond_wait_guarded_by_if",
                    line=line,
                    description="条件变量等待被 `if` 而非谓词循环所保护。",
                    root_cause="虚假唤醒或遗漏的谓词变化可能让执行在谓词为假的情况下继续。",
                    suggested_fix="用 while 循环保护 pthread_cond_wait，以重新检查共享谓词。",
                    source="condition predicate",
                    sink=line.text,
                    confidence=0.86,
                    impact_level="high",
                    positive=[
                        "nearby branch uses `if` before pthread_cond_wait",
                        f"line {line.number}: condition variable wait",
                    ],
                    negative=[],
                    ast_cfg=self._ast_cfg_pack(
                        lines,
                        [self._event("cond_wait", line, "cond", "pthread_cond_wait", line.text)],
                        [line.number],
                    ),
                )

        self._maybe_emit_borrowed_return_after_unlock(
            issues,
            func_name,
            file_path,
            lines,
            allowed_skills,
            line,
        )

        race = shared_accesses.match(line)
        if not race or self._match_lock(line.text) or self._match_unlock(line.text):
            return
        global_name = race.group("global")
        if global_name in emitted_shared_state:
            return
        if re.search(r"\+\+|--|while\s*\(|if\s*\(|=[^=]", line.text):
            emitted_shared_state.add(global_name)
            self._emit(
                issues,
                func_name,
                file_path,
                lines,
                allowed_skills,
                defect_class="race",
                rule="clang_cfg_unsynchronized_shared_flag_or_counter",
                line=line,
                description=f"`{global_name}` 在未见到明显锁或原子操作的情况下被访问。",
                root_cause="共享标志/计数器的访问未能跨线程一致地同步。",
                suggested_fix="对该共享状态的所有读写都使用互斥锁或原子操作。",
                source=global_name,
                sink=line.text,
                confidence=0.72,
                positive=[f"line {line.number}: unsynchronized shared global access"],
                negative=[
                    "Validator must confirm the variable is shared across threads or signal paths."
                ],
                ast_cfg=self._ast_cfg_pack(
                    lines,
                    [self._event("shared_state_access", line, global_name, "", line.text)],
                    [line.number],
                ),
            )

    def _maybe_emit_borrowed_return_after_unlock(
        self,
        issues: List[Dict[str, Any]],
        func_name: str,
        file_path: str,
        lines: Sequence[ClangCfgLine],
        allowed_skills: Optional[Set[str]],
        line: ClangCfgLine,
    ) -> None:
        match = re.search(r"\breturn\s+(?P<ret>[A-Za-z_]\w*)\s*;", line.text)
        if not match:
            return
        ret = match.group("ret")
        previous = list(reversed(lines[max(0, line.index - 14) : line.index]))
        assigned: Optional[ClangCfgLine] = None
        saw_unlock = False
        for item in previous:
            if self._match_unlock(item.text):
                saw_unlock = True
            if re.search(rf"\b{re.escape(ret)}\s*=\s*[^;]*->[A-Za-z_]\w*", item.text):
                assigned = item
                break
        if not assigned or not saw_unlock:
            return
        self._emit(
            issues,
            func_name,
            file_path,
            lines,
            allowed_skills,
            defect_class="use_after_free",
            rule="clang_cfg_borrowed_pointer_returned_after_unlock",
            line=line,
            description=f"借用指针 `{ret}` 在保护锁被释放之后被返回。",
            root_cause="并发的修改可能在解锁之后、调用方使用之前释放或替换所指向的对象。",
            suggested_fix="返回一份拥有所有权的副本，或在释放锁之前保留一个受保护的引用。",
            source=f"borrowed pointer assigned at line {assigned.number}",
            sink=line.text,
            confidence=0.84,
            impact_level="high",
            positive=[
                f"line {assigned.number}: borrowed pointer is read from a shared object",
                "an unlock appears before the return",
                f"line {line.number}: borrowed pointer escapes to caller",
            ],
            negative=[],
            ast_cfg=self._ast_cfg_pack(
                lines,
                [
                    self._event("borrowed_pointer_read", assigned, ret, "", assigned.text),
                    self._event("borrowed_pointer_return", line, ret, "", line.text),
                ],
                [assigned.number, line.number],
            ),
        )

    def _maybe_emit_refcount_update_after_unlock(
        self,
        issues: List[Dict[str, Any]],
        func_name: str,
        file_path: str,
        lines: Sequence[ClangCfgLine],
        allowed_skills: Optional[Set[str]],
        line: ClangCfgLine,
        idx: int,
    ) -> None:
        find_locked = re.search(
            r"\b(?P<var>[A-Za-z_]\w*)\s*=\s*[A-Za-z_]\w*(?:find|lookup|get)[A-Za-z_0-9]*locked\s*\(",
            line.text,
            re.IGNORECASE,
        )
        if not find_locked:
            return
        var = find_locked.group("var")
        later = lines[idx + 1 : idx + 14]
        unlock_line = next((item for item in later if self._match_unlock(item.text)), None)
        if not unlock_line:
            return
        for item in later:
            if item.index <= unlock_line.index:
                continue
            if not re.search(rf"\b{re.escape(var)}->ref_count\s*(?:\+\+|--|\+=|-=)", item.text):
                continue
            self._emit(
                issues,
                func_name,
                file_path,
                lines,
                allowed_skills,
                defect_class="refcount_race",
                rule="clang_cfg_refcount_update_after_unlock",
                line=item,
                description=f"`{var}->ref_count` 在释放用于查找的锁之后被修改。",
                root_cause="对象引用在互斥锁下被找到，但引用计数的更新却发生在该保护被解除之后。",
                suggested_fix="在同一把锁下增减引用计数，或使用原子的引用计数。",
                source=f"lookup at line {line.number}",
                sink=item.text,
                confidence=0.88,
                impact_level="high",
                positive=[
                    f"line {line.number}: `{var}` is found by a locked lookup helper",
                    f"line {unlock_line.number}: protecting lock is released",
                    f"line {item.number}: `{var}->ref_count` is updated after unlock",
                ],
                negative=[
                    "Validator must confirm the lookup helper's lock matches the object lifetime lock."
                ],
                ast_cfg=self._ast_cfg_pack(
                    lines,
                    [
                        self._event("locked_lookup", line, var, "", line.text),
                        self._event("unlock", unlock_line, "lock", "", unlock_line.text),
                        self._event("refcount_update", item, var, "ref_count", item.text),
                    ],
                    [line.number, unlock_line.number, item.number],
                ),
            )
            return

    def _maybe_emit_borrowed_callback_global(
        self,
        issues: List[Dict[str, Any]],
        func_name: str,
        file_path: str,
        lines: Sequence[ClangCfgLine],
        allowed_skills: Optional[Set[str]],
        line: ClangCfgLine,
        idx: int,
    ) -> None:
        match = re.search(
            r"\b(?P<global>g_[A-Za-z_0-9]*(?:callback|cb)?[A-Za-z_0-9]*(?:entry|ctx|context|object|node)[A-Za-z_0-9]*)\s*=\s*"
            r"(?P<lookup>[A-Za-z_]\w*(?:find|lookup|get)[A-Za-z_0-9]*)\s*\(",
            line.text,
            re.IGNORECASE,
        )
        if not match:
            return
        window = "\n".join(item.text for item in lines[max(0, idx - 6) : idx + 8])
        if not self._match_lock(window):
            return
        if not re.search(
            r"\bg_[A-Za-z_0-9]*(?:callback|cb|handler)[A-Za-z_0-9]*\s*=", window, re.IGNORECASE
        ):
            return
        self._emit(
            issues,
            func_name,
            file_path,
            lines,
            allowed_skills,
            defect_class="use_after_free",
            rule="clang_cfg_global_callback_stores_borrowed_object",
            line=line,
            description=f"全局回调上下文 `{match.group('global')}` 保存了一个由 `{match.group('lookup')}` 返回的借用对象。",
            root_cause="另一条路径移除或释放该对象之后，全局回调仍可能随后使用这个借用对象。",
            suggested_fix="为回调上下文保存一份拥有所有权的引用，并在注销/移除期间释放它。",
            source=line.text,
            sink="global callback context",
            confidence=0.78,
            impact_level="high",
            positive=[
                f"line {line.number}: global callback context stores lookup result `{match.group('lookup')}`",
                "nearby code also stores a global callback/handler",
            ],
            negative=[
                "Validator must confirm a reachable remove/unregister path can free the stored object."
            ],
            ast_cfg=self._ast_cfg_pack(
                lines,
                [
                    self._event(
                        "callback_borrow_store",
                        line,
                        match.group("global"),
                        match.group("lookup"),
                        line.text,
                    )
                ],
                [line.number],
            ),
        )

    def _maybe_emit_mapping_unmap_without_invalidation(
        self,
        issues: List[Dict[str, Any]],
        func_name: str,
        file_path: str,
        lines: Sequence[ClangCfgLine],
        allowed_skills: Optional[Set[str]],
        line: ClangCfgLine,
    ) -> None:
        for api, args in self._calls(line.text):
            if api not in {"munmap", "UnmapViewOfFile"} or not self._semantic_call_allowed(
                api, "io_release"
            ):
                continue
            first = self._resource_var(self._first_arg(args))
            if not first or not first.startswith("g_"):
                continue
            later = "\n".join(item.text for item in lines[line.index + 1 : line.index + 8])
            if re.search(rf"\b{re.escape(first)}\s*=\s*(?:NULL|nullptr|0|MAP_FAILED)\s*;", later):
                continue
            self._emit(
                issues,
                func_name,
                file_path,
                lines,
                allowed_skills,
                defect_class="use_after_free",
                rule="clang_cfg_global_mapping_unmapped_without_invalidation",
                line=line,
                description=f"全局映射指针 `{first}` 在附近没有任何失效操作的情况下被解除映射。",
                root_cause="之后的读取方可能通过非空检查，并对一个已解除映射的全局映射进行解引用。",
                suggested_fix="在解除映射之后，于相同的同步机制下清除全局映射指针和长度。",
                source=first,
                sink=line.text,
                confidence=0.84,
                impact_level="high",
                positive=[
                    f"line {line.number}: `{api}` releases global mapping `{first}` without setting it to NULL nearby"
                ],
                negative=[
                    "Validator must confirm a reachable later reader uses the global mapping."
                ],
                ast_cfg=self._ast_cfg_pack(
                    lines,
                    [self._event("global_unmap_without_clear", line, first, api, line.text)],
                    [line.number],
                ),
            )
            return

    def _same_lock_region_without_escape(
        self,
        lines: Sequence[ClangCfgLine],
        start_idx: int,
        end_idx: int,
    ) -> bool:
        lock_idx = None
        for item in reversed(lines[max(0, start_idx - 12) : start_idx + 1]):
            if self._match_unlock(item.text):
                break
            if self._match_lock(item.text):
                lock_idx = item.index
                break
        if lock_idx is None:
            return False
        region = lines[lock_idx : end_idx + 1]
        if any(self._match_unlock(item.text) for item in region[:-1]):
            return False
        between = "\n".join(item.text for item in lines[start_idx : end_idx + 1])
        if re.search(
            r"\b(?:pthread_create|thrd_create|CreateThread|_beginthreadex)\s*\(",
            between,
        ):
            return False
        if re.search(r"\b[A-Za-z_]\w*(?:callback|cb|handler)\s*\(", between, re.IGNORECASE):
            return False
        return True

    def _branch_return_misses_unlock(
        self,
        lines: Sequence[ClangCfgLine],
        line: ClangCfgLine,
        lock_id: str,
    ) -> bool:
        """分支早退漏解锁判定（确定性）。

        终态条件分支内的 return：分支体（分支头到 return）没有释放
        ``lock_id``，而分支之后的 fall-through 路径会释放同一把锁——
        说明锁确实需要释放，但早退路径跳过了它（如分配失败的
        error-guard 早退）。两侧任一不成立则维持豁免。
        """
        branch_start = self._enclosing_branch_start(lines, line)
        if branch_start is None:
            return False
        for item in lines[branch_start.index : line.index + 1]:
            unlock = self._match_unlock(item.text)
            if unlock and unlock[1] == lock_id:
                return False
        for item in lines[line.index + 1 :]:
            unlock = self._match_unlock(item.text)
            if unlock and unlock[1] == lock_id:
                return True
        return False

    def _return_is_error_guard_for_lock(self, text: str, lock_id: str) -> bool:
        if lock_id == "global_lock":
            return False
        escaped = re.escape(lock_id)
        return bool(re.search(rf"\bif\s*\(\s*!\s*{escaped}\s*\)\s*return\b", text))

    def _macro_guard_names(self, lines: Sequence[ClangCfgLine], *, lock: bool) -> Set[str]:
        configured = self._macro_lock_names if lock else self._macro_unlock_names
        return set(configured)

    def _line_between_macro_guards(
        self,
        lines: Sequence[ClangCfgLine],
        line: ClangCfgLine,
        macro_locks: Set[str],
        macro_unlocks: Set[str],
    ) -> bool:
        held: list[tuple[str, str]] = []
        for item in lines:
            lock = self._match_lock(item.text)
            if (
                lock
                and lock[0] in macro_locks
                and item.index < line.index
                and self.semantics.contracts.effect_status(
                    lock[0], "lock", item.text, object_name=lock[1]
                )
                == "applies"
            ):
                held.append(lock)
            unlock = self._match_unlock(item.text)
            if unlock and unlock[0] in macro_unlocks and item.index > line.index:
                if any(
                    obj == unlock[1]
                    and self.semantics.contracts.release_in_text(api, unlock[0], item.text, obj)
                    == "applies"
                    for api, obj in held
                ):
                    return True
            if item.index > line.index and held and re.search(r"\breturn\b", item.text):
                return False
        return False
