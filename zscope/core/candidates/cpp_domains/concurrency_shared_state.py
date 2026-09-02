# mypy: disable-error-code="attr-defined"
"""Locking, ordering, publication, and shared-state detector implementations."""

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
        held: List[CodeLine] = []
        for line in lines:
            if self._lock_re.search(line.text):
                held.append(line)
            callback_call = self._callback_like_call(line.text)
            if held and callback_call:
                lock_line = held[-1]
                emit(
                    defect_class="held_lock_callback",
                    rule="callback_while_lock_held",
                    line=line,
                    description="Callback/function-pointer style call is made while a lock is held.",
                    root_cause="External callback code can re-enter the same subsystem or acquire conflicting locks.",
                    suggested_fix="Copy required state under the lock, release the lock, then invoke the callback.",
                    source=f"lock at line {lock_line.number}",
                    sink=line.text.strip(),
                    confidence=0.78,
                    impact_level="high",
                    positive=[
                        f"line {lock_line.number}: lock acquired",
                        f"line {line.number}: callback-like call `{callback_call}` before unlock",
                    ],
                )
            if held and re.search(r"\breturn\b", line.text):
                lock_line = held[-1]
                emit(
                    defect_class="missing_unlock",
                    rule="return_while_lock_held",
                    line=line,
                    description="Function returns while a mutex/rwlock appears to be held.",
                    root_cause="A path exits the function before the matching unlock.",
                    suggested_fix="Release the lock before every return path or use a single cleanup label.",
                    source=f"lock at line {lock_line.number}",
                    sink=line.text.strip(),
                    confidence=0.8,
                    impact_level="high",
                    positive=[
                        f"line {lock_line.number}: lock acquired",
                        f"line {line.number}: return before matching unlock",
                    ],
                )
            if self._unlock_re.search(line.text) and held:
                held.pop()

    @staticmethod
    def _callback_like_call(text: str) -> str:
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
        if re.search(r"(?:callback|cb|handler|hook|pfn|^on_|^on[A-Z])", leaf, re.I):
            return name
        return ""

    def _rule_condvar_wait(self, lines: List[CodeLine], emit) -> None:
        for line in lines:
            if "pthread_cond_wait" not in line.text:
                continue
            previous = self._previous_nonempty(lines, line.index, limit=4)
            if any(re.search(r"\bif\s*\(", item.text) for item in previous) and not any(
                re.search(r"\bwhile\s*\(", item.text) for item in previous
            ):
                emit(
                    defect_class="lost_wakeup",
                    rule="cond_wait_guarded_by_if",
                    line=line,
                    description="Condition variable wait is guarded by `if` rather than a predicate loop.",
                    root_cause="Spurious wakeups or missed predicate changes can make the thread continue incorrectly.",
                    suggested_fix="Guard pthread_cond_wait with a while loop that rechecks the shared predicate.",
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
                        description=f"`{obj}` uses double-checked locking without visible atomic publication.",
                        root_cause="Readers outside the lock can observe a partially initialized object or stale pointer.",
                        suggested_fix="Guard all accesses with the same lock or publish through atomic acquire/release.",
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
                        description=f"`{obj}` is published through `{publish.group('global')}` before later field initialization.",
                        root_cause="Concurrent readers can observe the object before all fields are initialized.",
                        suggested_fix="Fully initialize the object before linking/publishing it to shared state.",
                        source=obj,
                        sink=line.text.strip(),
                        confidence=0.81,
                        impact_level="high",
                        positive=[
                            f"line {line.number}: object is assigned to shared/global state",
                            "later lines initialize fields after publication",
                        ],
                    )

            helper_publish = re.search(
                r"\b(?P<fn>[A-Za-z_]\w*(?:insert|add|publish|register|attach|link)[A-Za-z_0-9]*)"
                r"\s*\(\s*(?P<obj>[A-Za-z_]\w*)\s*(?:,|\))",
                line.text,
                re.IGNORECASE,
            )
            if helper_publish:
                obj = helper_publish.group("obj")
                earlier = lines[max(0, idx - 12) : idx]
                later = lines[idx + 1 : idx + 10]
                allocated_before = any(
                    re.search(
                        rf"\b{re.escape(obj)}\s*=\s*(?:\([^)]*\)\s*)?"
                        rf"(?:{self._names_pattern(self._allocator_names | self._calloc_names)}|[A-Za-z_]\w*(?:Alloc|Create|New))\s*\(",
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
                            rf"\bpthread_mutex_init\s*\(\s*&\s*{re.escape(obj)}->", item.text
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
                            f"`{obj}` is passed to publication helper `{helper_publish.group('fn')}` "
                            "before later field initialization."
                        ),
                        root_cause="Concurrent readers can observe the object after helper publication but before all fields are initialized.",
                        suggested_fix="Complete all field initialization before calling the helper that links/publishes the object.",
                        source=obj,
                        sink=line.text.strip(),
                        confidence=0.78,
                        impact_level="high",
                        positive=[
                            f"line {line.number}: object is passed to publication helper `{helper_publish.group('fn')}`",
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
                                description=f"`{var}->ref_count` is modified after releasing the protecting lock.",
                                root_cause="Reference count update is not atomic or protected by the lock that found the object.",
                                suggested_fix="Increment/decrement the reference count under the same lock or use atomics.",
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
                        description="A global callback context stores a borrowed cache entry that can be freed later.",
                        root_cause="The entry pointer is saved globally without taking ownership or a protected reference.",
                        suggested_fix="Store an owned reference/copy or unregister/clear the callback before entry removal.",
                        source=callback_ctx.group("obj"),
                        sink=line.text.strip(),
                        confidence=0.8,
                        impact_level="high",
                        positive=[
                            f"line {line.number}: global callback context assigned from locked lookup",
                            "the lock is released after storing the borrowed pointer",
                        ],
                    )

            race = re.search(
                r"\b(?P<global>g_[A-Za-z_0-9]*(?:counter|flag|running|shutdown|state|status|ready|stop|done|active|enabled)[A-Za-z_0-9]*)\b",
                line.text,
                re.IGNORECASE,
            )
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
                        description=f"`{global_name}` is accessed without an evident lock or atomic operation.",
                        root_cause="Shared flag/counter access is not consistently synchronized across threads.",
                        suggested_fix="Use a mutex or atomic operations for all reads and writes of the shared state.",
                        source=global_name,
                        sink=line.text.strip(),
                        thread_object=global_name,
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
        for line in view.lines:
            lock = self._lock_arg(line.text)
            if lock:
                held.append((lock, line))
                continue
            if self._unlock_call_re.search(line.text) and held:
                held.pop()
                continue
            if not held:
                continue
            for call_name in self._call_targets_for_line(view.name, line):
                callee = by_name.get(call_name) or self._view_for(call_name)
                if not callee:
                    continue
                callee_locks = [(self._lock_arg(item.text), item) for item in callee.lines]
                callee_locks = [(lock_id, item) for lock_id, item in callee_locks if lock_id]
                if not callee_locks:
                    continue
                held_lock, held_line = held[-1]
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
                            f"`{view.name}` calls `{call_name}` while `{held_lock}` is held; "
                            f"`{call_name}` can acquire `{same_lock[0]}` again."
                        ),
                        root_cause="A helper with its own locking contract is reached under an already-held lock.",
                        suggested_fix="Use a no-lock helper variant, document the caller-held lock contract, or release before calling.",
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
                        evidence={
                            "path": {
                                "caller": view.name,
                                "callee": call_name,
                                "call_line": line.number,
                                "call_evidence": call_evidence,
                                "path_constraints": [
                                    "same thread",
                                    "callee reachable from locked region",
                                ],
                            }
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
                                rf"\bpthread_(?:mutex|cond|rwlock)_init\s*\([^;]*\b{re.escape(var)}->",
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
                            description=(
                                f"`{var}` is linked or published before later member initialization completes."
                            ),
                            root_cause="Concurrent readers can observe a partially initialized object after it is inserted into shared state.",
                            suggested_fix="Initialize all fields and embedded synchronization primitives before publishing the object.",
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
                        rf"\b(?:SAFE_FREE|free|kfree)\s*\(\s*(?:{re.escape(var)}(?:->\w+)?|{re.escape(var)})\s*\)",
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
                        description=(
                            f"`{var}` is unlinked under the container lock, then released after the lock is dropped."
                        ),
                        root_cause="Concurrent readers that observed the node before unlink can race with member or node release after unlock.",
                        suggested_fix="Use refcounts/RCU or keep the lifetime lock held until no reader can still dereference the node.",
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
                description="A mutable global mode selects a callback path without synchronization across registration and use.",
                root_cause="Concurrent callers can change the global mode between callback registration and dispatch.",
                suggested_fix="Protect the mode and callback table with the same lock or pass an immutable mode snapshot through the operation.",
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
        if not cas_line:
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
                description="A compare-and-swap claim result is ignored before writing into the shared slot.",
                root_cause="If another caller wins the CAS, subsequent field writes can corrupt a slot owned by that caller.",
                suggested_fix="Check the CAS result and retry or fail before writing any slot fields.",
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
            r"\b(?:pthread_cond_signal|pthread_cond_broadcast|eventfd_write|notify|trigger|wakeup)\s*\(",
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
                description="A local event is queued into shared scheduling state without a wakeup/trigger operation.",
                root_cause="The producer publishes work but does not notify the consumer path that new work is available.",
                suggested_fix="Trigger the local scheduler or signal the condition/eventfd after queueing the event.",
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
                description="A duplicate/existence lookup is performed before taking the lock that protects insertion.",
                root_cause="Two creators can both observe absence and then insert duplicate shared resources.",
                suggested_fix="Hold the insertion lock across lookup and insert, or use an atomic create-if-absent primitive.",
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
                description="One state-machine branch publishes a state transition while another publishes related identity fields without the state transition.",
                root_cause="Consumers can observe initialized identity data while the shared state still advertises an old lifecycle state.",
                suggested_fix="Update the lifecycle state consistently for every successful publication branch.",
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
            re.compile(r"\b(?:pthread_mutex_trylock|LOCK)\s*\([^;]*(?:sem|signal|exception)", re.I),
        )
        log_line = self._first_line_matching(
            view, re.compile(r"\b(?:snprintf|LOG_ERROR|printf)\s*\(")
        )
        if not (lock_line and log_line):
            shared_write = self._first_line_matching(
                view,
                re.compile(
                    r"\bg_[A-Za-z_0-9]+(?:->|\.)[A-Za-z_]\w+\s*=|__atomic_store_n\s*\(\s*&\s*g_",
                    re.I,
                ),
            )
            alloc_line = self._first_line_matching(
                view,
                re.compile(r"\b(?:_safe_calloc|_safe_malloc|calloc|malloc)\s*\(", re.I),
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
                    description="A signal/exception path mutates shared global state and/or performs non-async-signal-safe work.",
                    root_cause=(
                        "The asynchronous signal path writes shared callstack/runtime state and performs logging/allocation "
                        "without a signal-safe handoff protocol."
                    ),
                    suggested_fix="Capture only atomic/minimal signal-safe data and defer allocation, logging, and shared-state updates to a normal thread.",
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
                description="A signal/exception path performs locking and formatting/logging work.",
                root_cause="Signal handlers can interrupt code that owns the same lock or uses non-async-signal-safe routines.",
                suggested_fix="Record only async-signal-safe data in the handler and defer formatting/logging to a normal thread.",
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
                    r"\b(?:SAFE_FREE|free|destroy|release)[A-Za-z_0-9]*\s*\([^;]*(?:pool|pbuf|g_[A-Za-z_0-9]+)",
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
                and re.search(r"\b(?:SAFE_FREE|free)\s*\(\s*g_[A-Za-z_0-9.]+", line.text, re.I)
            ),
            None,
        )
        issues.append(
            self._issue(
                defect_class="premature_destroy",
                rule="destroy_shared_pool_while_active_tasks_remain",
                view=view,
                line=condition_line,
                description="A shared pool object can be destroyed even when the active-task count indicates users still exist.",
                root_cause=(
                    "The destroy path publishes a shared pool pointer and then frees the global pool/buffer "
                    "in the active-tasks branch, leaving active users with a dangling shared object."
                ),
                suggested_fix="Refcount the pool or reject/defer destruction while active tasks are non-zero.",
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
                description="A global registration slot is checked before taking the lock that protects slot updates.",
                root_cause="Concurrent registrants can observe or update the same ops slot across a check-then-act window.",
                suggested_fix="Hold the registration lock across validation, lookup, and update of the slot.",
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
            view, re.compile(r"\b(?:_file_exists|access|stat|lstat)\s*\(")
        )
        key_line = self._first_line_matching(view, re.compile(r"\b(?:ftok|_hash_string)\s*\("))
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
                description="A file path is checked separately from ftok-style key generation and later synchronization.",
                root_cause="Path existence/state can change between the check and key derivation, creating unstable or colliding shared keys.",
                suggested_fix="Generate/register the key under a single lock using a stable opened file descriptor or reject changing path state.",
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
                callee_view, re.compile(r"\b(?:_file_exists|access|stat|lstat)\s*\(")
            )
            key_line = self._first_line_matching(
                callee_view, re.compile(r"\b(?:ftok|_hash_string)\s*\(")
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
                    description="The caller reaches a helper that checks path state separately from ftok-style key generation.",
                    root_cause=(
                        "A path/key helper derives a shared key after an unlocked path-state check, "
                        "so callers inherit a non-atomic key-generation race."
                    ),
                    suggested_fix="Make the helper perform path check, key derivation, and registration under one lock or use a stable opened file descriptor.",
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
                    f"`{view.name}` can wait on `{callback_lock}` while `{blocking_edge.function}` "
                    f"holds it before waiting on `{blocking_edge.second_lock}`."
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
                        f"`{view.name}` can wait on `{callback_lock}` while `{blocking_edge.function}` "
                        f"holds it and waits on `{blocking_edge.second_lock}`; `{scheduler_edge.function}` "
                        f"can hold `{scheduler_edge.first_lock}` while waiting on `{scheduler_edge.second_lock}`, "
                        "forming a multi-party callback/close lock cascade."
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
                        root_cause="Timer/callback code participates in a cascade wait through a lock held by a close/remove path.",
                        suggested_fix="Avoid blocking timer/callback paths on control locks used by close/remove, or reorder the close path to follow the scheduler/control lock protocol.",
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
                            rf"\b(?:SAFE_FREE|free|kfree)\s*\(\s*{re.escape(alias)}\s*\)", line.text
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
                    description="A callback receives the current object as its context and can free it before the caller resumes using it.",
                    root_cause="The callback contract permits self-destruction, but the caller keeps dereferencing the object after the callback returns.",
                    suggested_fix="Hold a reference across callback execution or mark/detach the current object before invoking callbacks that may destroy it.",
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

    @staticmethod
    def _callback_free_line(view: FunctionView) -> Optional[GraphLine]:
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
                        rf"\b(?:SAFE_FREE|free|kfree)\s*\(\s*{re.escape(alias)}\s*\)", line.text
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
        for left in edges:
            for right in edges:
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
                view = next((item for item in views if item.name == right.function), None)
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
                            f"Lock order inversion: `{left.function}` takes `{left.first_lock}` then `{left.second_lock}`, "
                            f"while `{right.function}` takes `{right.first_lock}` then `{right.second_lock}`."
                        ),
                        root_cause="Two reachable paths acquire the same lock pair in opposite order.",
                        suggested_fix="Define a single global lock order and refactor one path to follow it.",
                        source=f"{left.function}:{left.first_line}->{left.second_line}",
                        sink=f"{right.function}:{right.first_line}->{right.second_line}",
                        confidence=0.84,
                        impact_level="high",
                        positive=[
                            f"{left.function} lines {left.first_line}-{left.second_line}: {left.first_lock} before {left.second_lock}",
                            f"{right.function} lines {right.first_line}-{right.second_line}: {right.first_lock} before {right.second_lock}",
                        ],
                    )
                )

    def _lock_order_edges(self, views: Sequence[FunctionView]) -> List[LockOrderEdge]:
        edges: List[LockOrderEdge] = []
        for view in views:
            held: List[Tuple[str, GraphLine]] = []
            for line in view.lines:
                lock = self._lock_arg(line.text)
                if lock:
                    for prior, prior_line in held:
                        if prior != lock:
                            edges.append(
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
                if self._unlock_call_re.search(line.text) and held:
                    held.pop()
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
        return self._normalize_lock(match.group("arg"))

    @staticmethod
    def _normalize_lock(value: str) -> str:
        text = re.sub(r"\s+", "", str(value or ""))
        text = text.strip("&()")
        text = text.replace("->", ".")
        return text

    @classmethod
    def _locks_may_match(cls, left: str, right: str) -> bool:
        if not left or not right:
            return False
        left_norm = cls._normalize_lock(left)
        right_norm = cls._normalize_lock(right)
        if left_norm == right_norm:
            return True
        left_tail = left_norm.split(".")[-1]
        right_tail = right_norm.split(".")[-1]
        return bool(left_tail and left_tail == right_tail)

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
        signature = "\n".join(item.text for item in lines[:3])
        if re.search(r"\b[A-Za-z_]\w*unlock[A-Za-z_]\w*\s*\(", signature, re.I) and any(
            re.search(r"\bpthread_(?:mutex|rwlock)_unlock\s*\(", item.text) for item in lines
        ):
            return
        held: List[LockState] = []
        for line in lines:
            # Macro definitions and thin unlock wrappers describe a protocol;
            # they are not call sites that can establish whether a caller
            # holds the lock.  Treating their bodies as ordinary functions
            # produced one false candidate for every use of the macro.
            if line.text.lstrip().startswith("#"):
                continue
            if "wrapper" in func_name.lower() and re.search(
                r"\b(?:unlock|pthread_mutex_unlock|pthread_rwlock_unlock)\b", line.text, re.I
            ):
                continue
            lock = self._match_lock(line.text)
            if lock:
                api, lock_id = lock
                held.append(LockState(lock_id=lock_id, api=api, line=line))
            unlock = self._match_unlock(line.text)
            if unlock and not held:
                api, lock_id = unlock
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
                _, lock_id = unlock
                # An unlock on a branch that returns does not release the
                # fall-through path.  Keeping it in the linear state machine
                # made the later normal-path unlock look unmatched.
                if not self._is_terminal_conditional_branch_line(lines, line):
                    match_idx = next(
                        (
                            idx
                            for idx in range(len(held) - 1, -1, -1)
                            if held[idx].lock_id == lock_id
                        ),
                        len(held) - 1,
                    )
                    held.pop(match_idx)
            if not held or not self._is_return(line.text):
                continue
            if self._is_terminal_conditional_branch_line(lines, line):
                continue
            if self._return_is_error_guard_for_lock(line.text, held[-1].lock_id):
                continue
            lock_state = held[-1]
            self._emit(
                issues,
                func_name,
                file_path,
                lines,
                allowed_skills,
                defect_class="missing_unlock",
                rule="clang_cfg_return_with_lock_held",
                line=line,
                description=f"Function returns while `{lock_state.lock_id}` appears to be held.",
                root_cause=(
                    "The synthesized CFG path enters a return edge after a lock acquire "
                    "without a matching unlock event."
                ),
                suggested_fix=(
                    "Release the lock on every return path or route exits through a common "
                    "cleanup block."
                ),
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
            description=f"`{api}` releases `{lock_id}` without a visible matching acquire in the local function body.",
            root_cause=(
                "The local lock-state path reaches an unlock operation while no matching lock "
                "acquire has been observed."
            ),
            suggested_fix=(
                "Acquire the same lock before the unlock, remove the stray unlock, or document "
                "and enforce a caller-held-lock contract."
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
        held: List[str] = []
        for line in lines:
            lock = self._match_lock(line.text)
            if lock:
                held.append(lock[1])
            lhs = self._global_write_lhs(line.text)
            if lhs:
                writes.append((line, lhs, self._global_state_family(lhs), bool(held)))
            unlock = self._match_unlock(line.text)
            if unlock and held:
                held.pop()

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
                    description=f"Global shared state `{family}` is written both with and without a lock.",
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
                    description=f"Global pointer/length state `{family}` is published without visible synchronization.",
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
            description="Timer/callback path locks an object from a global scheduler/list without holding the scheduler lock.",
            root_cause="A close/destroy path can hold the object lock while waiting for the scheduler/global lock, creating a lock-order cycle with the callback path.",
            suggested_fix="Use one lock order for scheduler/list and per-object locks, or snapshot/refcount the object before dropping the scheduler lock.",
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
            root_cause="Global shared state is updated without a single synchronization protocol protecting all related writes/readers.",
            suggested_fix="Protect all writes and readers of the state family with the same lock or publish an immutable snapshot atomically.",
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
            r"\b(?:SAFE_FREE|free)\s*\(\s*(?:old_[A-Za-z_]\w*|old_array)\s*\)", text
        )
        if not (global_assign and cap_assign and old_free):
            return
        pre_window = "\n".join(item.text for item in lines[max(0, line.index - 5) : line.index])
        if re.search(r"\b(?:LOCK|pthread_mutex_lock|spin_lock|mtx_lock)\s*\(", pre_window):
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
            description=f"Global dynamic array `{global_assign.group('array')}` is resized and the old storage is freed without a visible lock.",
            root_cause="Concurrent creators can race while publishing a new global array pointer/capacity pair and freeing the old array.",
            suggested_fix="Protect the capacity check, allocation handoff, pointer publish, and old-array free with the same mutex or atomic ownership protocol.",
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
        if not re.search(r"(?:key|ftok|_file_exists|file_exists)", body_hint, re.IGNORECASE):
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
                if re.search(r"\b(?:access|stat|lstat|_file_exists|file_exists)\s*\(", item.text)
            ),
            None,
        )
        locked_lookup = next(
            (
                item
                for item in suffix
                if re.search(r"\bLOCK\s*\(", item.text)
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
            description="Path/key state is checked and hashed before the locked registration lookup.",
            root_cause="A file/path based key can be generated from stale path state before the lock that protects registration and collision checks.",
            suggested_fix="Hold one lock or use an atomic create/register operation across path validation, key generation, and registration lookup.",
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
            r"\b(?:LOCK|pthread_mutex_lock|spin_lock|refcount_dec_and_test|atomic_dec_and_test)\s*\(",
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
            description=f"Shared resource `{resource}` is destroyed while an active-use guard is true.",
            root_cause=(
                "A pool/cache/global owner is released on a path that explicitly observes active users "
                "or tasks, without a visible quiescence/refcount guard."
            ),
            suggested_fix="Wait for active users to drain or transfer ownership through a refcounted shutdown path before freeing.",
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
            description=f"`{match.group('global')}` is updated under a macro-like lock guard that may compile to a no-op on some targets.",
            root_cause="Configuration-sensitive macro locking can disappear on unsupported builds while the shared state remains mutable.",
            suggested_fix="Use a lock implementation that is present on every supported target or reject unsupported builds.",
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
        if not re.search(
            r"\b[A-Za-z_]\w*(?:callback|cb|handler)[A-Za-z_0-9]*\s*\(", line.text, re.IGNORECASE
        ):
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
            description="Callback/function-pointer style call is made while a lock is held.",
            root_cause="A callback contract can re-enter the same subsystem or acquire conflicting locks if callers can register nontrivial callback code.",
            suggested_fix="Copy required state under the lock, release the lock, then invoke the callback.",
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
                    description=f"`{obj}` is checked outside the mutex before lazy initialization.",
                    root_cause="Readers outside the lock can observe stale or partially initialized shared state.",
                    suggested_fix="Guard all accesses with the same lock or use atomic acquire/release publication.",
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
                    description=f"`{obj}` is linked into shared state before later field initialization completes.",
                    root_cause="Concurrent readers can observe a partially initialized object after publication.",
                    suggested_fix="Initialize all fields before inserting the object into global/shared containers.",
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

        if "pthread_cond_wait" in line.text:
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
                    description="Condition variable wait is guarded by `if` rather than a predicate loop.",
                    root_cause="Spurious wakeups or missed predicate changes can let execution continue with a false predicate.",
                    suggested_fix="Guard pthread_cond_wait with a while loop that rechecks the shared predicate.",
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

        race = re.search(
            r"\b(?P<global>g_[A-Za-z_0-9]*(?:counter|flag|running|shutdown|state|status|ready|stop|done|active|enabled)[A-Za-z_0-9]*)\b",
            line.text,
            re.IGNORECASE,
        )
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
                description=f"`{global_name}` is accessed without an evident lock or atomic operation.",
                root_cause="Shared flag/counter access is not consistently synchronized across threads.",
                suggested_fix="Use a mutex or atomic operations for all reads and writes of the shared state.",
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
            description=f"Borrowed pointer `{ret}` is returned after the protecting lock is released.",
            root_cause="Concurrent mutation can free or replace the pointee after unlock and before caller use.",
            suggested_fix="Return an owned copy or keep a protected reference before releasing the lock.",
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
                description=f"`{var}->ref_count` is modified after releasing the lock used for lookup.",
                root_cause="The object reference is found under a mutex, but the reference count update happens after the protection is dropped.",
                suggested_fix="Increment/decrement the reference count under the same lock or use atomic reference counting.",
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
        if not self._match_lock(window) and "LOCK" not in window:
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
            description=f"Global callback context `{match.group('global')}` stores a borrowed object returned by `{match.group('lookup')}`.",
            root_cause="A global callback can later use the borrowed object after another path removes or frees it.",
            suggested_fix="Store an owned reference for callback context and release it during unregister/remove.",
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
            if api not in {"munmap", "UnmapViewOfFile"}:
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
                description=f"Global mapping pointer `{first}` is unmapped without nearby invalidation.",
                root_cause="Later readers can pass non-null guards and dereference an unmapped global mapping.",
                suggested_fix="Clear the global mapping pointer and length under the same synchronization after unmap.",
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
            r"\b(?:pthread_create|thrd_create|VOS_TaskCreate|CreateThread|_beginthreadex)\s*\(",
            between,
        ):
            return False
        if re.search(r"\b[A-Za-z_]\w*(?:callback|cb|handler)\s*\(", between, re.IGNORECASE):
            return False
        return True

    def _return_is_error_guard_for_lock(self, text: str, lock_id: str) -> bool:
        if lock_id == "global_lock":
            return False
        escaped = re.escape(lock_id)
        return bool(re.search(rf"\bif\s*\(\s*!\s*{escaped}\s*\)\s*return\b", text))

    def _macro_guard_names(self, lines: Sequence[ClangCfgLine], *, lock: bool) -> Set[str]:
        configured = self._macro_lock_names if lock else self._macro_unlock_names
        result = set(configured)
        for line in lines:
            for api, _args in self._calls(line.text):
                upper = api.upper()
                if lock and "LOCK" in upper and "UNLOCK" not in upper:
                    result.add(api)
                elif not lock and "UNLOCK" in upper:
                    result.add(api)
        return result

    def _line_between_macro_guards(
        self,
        lines: Sequence[ClangCfgLine],
        line: ClangCfgLine,
        macro_locks: Set[str],
        macro_unlocks: Set[str],
    ) -> bool:
        saw_lock = False
        for item in lines:
            for api, _args in self._calls(item.text):
                if api in macro_locks and item.index < line.index:
                    saw_lock = True
                if api in macro_unlocks and item.index > line.index and saw_lock:
                    return True
            if item.index > line.index and saw_lock and re.search(r"\breturn\b", item.text):
                return False
        return False
