"""Regex/local-pattern C memory/concurrency candidate generation.

These rules are intentionally conservative enough to produce evidence-backed
review candidates, not final findings. The validator decides whether a
candidate is verified, rejected, or only an audit observation.
"""

from __future__ import annotations

import hashlib
from copy import deepcopy
from functools import lru_cache
import re
from typing import TYPE_CHECKING, Any, Dict, Iterable, List, Optional, Tuple

from ...semantics.models import LocalPatternSemantics
from .cpp_domains.models import CodeLine
from .cpp_domains.resource_lifecycle import RegexResourceLifecycleRules
from .cpp_domains.memory_bounds_integer import RegexMemoryBoundsIntegerRules
from .cpp_domains.concurrency_shared_state import RegexConcurrencySharedStateRules
from .cpp_domains.protocol_ownership_logic import RegexProtocolOwnershipLogicRules

from .cpp_domains import (
    RegexRuleContext,
    resolve_emitter_descriptor,
    resolve_rule_descriptor,
    run_detector_plan,
)

if TYPE_CHECKING:
    from ...orchestration.subagents import SubAgentTicket


def default_local_semantics() -> LocalPatternSemantics:
    """Load packaged default API roles without creating an import cycle at module load."""

    from ...semantics.defaults import default_local_pattern_semantics

    return default_local_pattern_semantics()


# This policy narrows an already verified instance materialization. It is not
# a factory receipt and does not verify native origins, scope or currentness.
INSTANCE_CONSUMER_POLICY = "zscope.instance-builtin-consumers.v1"

# Compiler-reserved operations are not C/POSIX library declarations, so they
# intentionally do not live in the system-header primitive catalog.  They are
# nevertheless safe semantic roots when the current native AST binds the
# reserved spelling to Clang's canonical builtin USR and finds no definition.
_COMPILER_INTRINSIC_OPERATIONS = frozenset(
    {
        "__atomic_fetch_add",
        "__atomic_fetch_sub",
        "__atomic_store_n",
        "__builtin_add_overflow",
        "__builtin_bswap",
        "__builtin_bswap16",
        "__builtin_bswap32",
        "__builtin_bswap64",
        "__builtin_ctz",
        "__builtin_ctzll",
        "__builtin_mul_overflow",
        "__sync_bool_compare_and_swap",
    }
)


def current_compiler_intrinsic_names(program_facts: Any) -> frozenset[str]:
    """Return compiler intrinsics proven by the current exact native facts."""

    if not isinstance(program_facts, dict):
        return frozenset()
    names: set[str] = set()
    for function in program_facts.get("functions") or []:
        if not isinstance(function, dict):
            continue
        for event in function.get("events") or []:
            if not isinstance(event, dict) or event.get("event_kind") not in {
                "call",
                "compiler_intrinsic",
            }:
                continue
            callee = event.get("callee")
            if not isinstance(callee, dict):
                continue
            emitted_name = str(callee.get("name") or callee.get("qualified_name") or "")
            name = re.sub(r"_(?:1|2|4|8|16)$", "", emitted_name)
            if name not in _COMPILER_INTRINSIC_OPERATIONS:
                continue
            usr = str(callee.get("usr") or callee.get("referenced_usr") or "")
            if (
                usr == f"c:@F@{emitted_name}"
                and callee.get("external_linkage") is True
                and callee.get("has_definition") is False
                and str(callee.get("canonical_signature") or "")
                and (
                    event.get("event_kind") == "call"
                    or callee.get("compiler_intrinsic") is True
                )
            ):
                names.add(name)
    return frozenset(names)


def _restricted_semantics(semantics: Optional[LocalPatternSemantics]) -> LocalPatternSemantics:
    """Own a filtered copy; never fill missing instance roles from defaults."""
    from ...semantics.models import CATEGORY_BY_ATTR

    if semantics is None:
        raise ValueError("restrict_to_semantics requires explicit instance semantics")
    result = deepcopy(semantics)
    registry = result.contracts
    # Generator construction happens before a function's BuildContext is
    # bound.  Calling ``registry.find`` here used the empty ambient scope and
    # silently discarded every exact project contract carrying a
    # ``build_context_id``.  Preserve all trusted published identities at this
    # stage; ``find_for_call``/``match_call`` still require the current native
    # BuildContext and callee USR at each actual call site.  This keeps custom
    # wrappers and macros executable without turning a name into authority.
    nondefault_names = {
        contract.symbol.name
        for contract in registry.contracts
        if contract.source != "builtin_defaults"
    }
    eligible = [
        contract
        for contract in registry.contracts
        if contract.effects_trusted
        and not (
            contract.source == "builtin_defaults"
            and (
                contract.symbol.name in nondefault_names
                or contract.symbol.name in registry.shadowed_symbols
            )
        )
    ]
    registry.contracts = eligible
    for attr, role in CATEGORY_BY_ATTR.items():
        bucket = getattr(result, attr)
        for name in list(bucket):
            if not any(c.symbol.name == name and c.role == role for c in eligible):
                del bucket[name]
    names = {contract.symbol.name for contract in eligible}
    registry.pairs = [
        pair for pair in registry.pairs if pair.acquire.name in names and pair.release.name in names
    ]
    return result


def _semantic_call_allowed(
    semantics: LocalPatternSemantics,
    restricted: bool,
    name: str,
    *roles: str,
    exact_compiler_intrinsics: Iterable[str] = (),
) -> bool:
    """Restriction only: missing or shadowed contracts never authorize a call."""
    return not restricted or name in set(exact_compiler_intrinsics) or any(
        contract.effects_trusted and (not roles or contract.role in roles)
        for contract in semantics.contracts.find(name)
    )


@lru_cache(maxsize=1)
def _builtin_pattern_roles() -> Dict[str, frozenset[str]]:
    """Spelling identifies a slot to restrict, never an allowed operation."""
    from ...semantics.defaults import default_checker_api_names

    roles: Dict[str, set[str]] = {}
    for contract in default_local_semantics().contracts.contracts:
        roles.setdefault(contract.symbol.name, set()).add(contract.role)
    for checker, role in {
        "extended_allocators": "allocator",
        "string_copy_sinks": "copy",
        "extended_lock_apis": "lock",
        "extended_unlock_apis": "unlock",
        "graph_release_apis": "deallocator",
        "extended_send_sinks": "send_sink",
        "extended_recv_sources": "recv_source",
        "extended_format_sinks": "format_sink",
        "extended_io_acquirers": "io_acquire",
        "extended_io_releasers": "io_release",
        "extended_callback_registrars": "callback_register",
    }.items():
        for name in default_checker_api_names(checker):
            roles.setdefault(name, set()).add(role)
    # Historical lexical alternatives without a packaged contract must also
    # fail closed. These entries confer no role on the instance registry.
    for name, role in {
        "kfree": "deallocator",
        "kmalloc": "allocator",
        "kzalloc": "allocator",
        "refcount_dec_and_test": "standard_operation",
        "atomic_dec_and_test": "standard_operation",
    }.items():
        roles.setdefault(name, set()).add(role)
    for name in (
        "strncmp",
        "memcmp",
        "fstat",
        "sleep",
        "usleep",
        "nanosleep",
        "poll",
        "select",
        "va_start",
        "__builtin_add_overflow",
        "__builtin_mul_overflow",
        "__builtin_ctz",
        "__builtin_ctzll",
        "__sync_bool_compare_and_swap",
        "__atomic_fetch_add",
        "__atomic_fetch_sub",
        "be16toh",
        "be32toh",
        "be64toh",
        "bswap",
        "__builtin_bswap",
        "__builtin_bswap16",
        "__builtin_bswap32",
        "__builtin_bswap64",
        "min",
        "MIN",
        "ARRAY_SIZE",
        "FAILED",
        "IS_ERR",
        "SUCCEEDED",
        "OK",
        "access",
        "stat",
        "lstat",
        "faccessat",
        "fstatat",
        "ftok",
        "getenv",
        "system",
        "strlen",
        "strchr",
        "strcmp",
        "chmod",
        "fchmod",
        "fcntl",
        "ioctl",
        "__atomic_store_n",
        "eventfd_write",
        "notify",
        "trigger",
        "wakeup",
        "file_exists",
    ):
        roles.setdefault(name, set()).add("standard_operation")
    for name, role in {
        "memset": "copy",
        "strlcpy": "copy",
        "snprintf": "format_sink",
        "mmap": "io_acquire",
        "shm_open": "io_acquire",
        "accept4": "io_acquire",
        "munmap": "io_release",
        "UnmapViewOfFile": "io_release",
        "pthread_create": "thread_create",
        "pthread_cond_signal": "condition_signal",
        "pthread_cond_broadcast": "condition_signal",
        "pthread_cond_init": "condition_init",
        "pthread_rwlock_init": "lock_init",
    }.items():
        roles.setdefault(name, set()).add(role)
    return {name: frozenset(values) for name, values in roles.items()}


def _consumer_api_pattern(
    pattern: str,
    semantics: LocalPatternSemantics,
    restricted: bool,
    *,
    expand_slots: bool = True,
    exact_compiler_intrinsics: Iterable[str] = (),
) -> str:
    from ...semantics.contracts import expand_api_pattern, return_acquisition_names

    if not restricted:
        return expand_api_pattern(pattern, semantics) if expand_slots else pattern
    if r"\s*\(" not in pattern:
        return pattern
    slots = {
        "malloc": ("allocators", "allocator"),
        "calloc": ("calloc_allocators", "calloc"),
        "realloc": ("reallocators", "reallocator"),
        "free": ("deallocators", "deallocator"),
        "recv": ("recv_sources", "recv_source"),
        "send": ("send_sinks", "send_sink"),
        "pthread_mutex_lock": ("lock_apis", "lock"),
        "pthread_mutex_unlock": ("unlock_apis", "unlock"),
    }
    roots = _builtin_pattern_roles()
    denied = semantics.contracts.shadowed_symbols
    native_intrinsics = set(exact_compiler_intrinsics)

    def replace(match: re.Match[str]) -> str:
        name = match[0]
        if expand_slots and name in slots:
            attr, role = slots[name]
            names = {
                candidate
                for candidate in getattr(semantics, attr)
                if _semantic_call_allowed(semantics, True, candidate, role)
            }
            if role in {"allocator", "calloc", "reallocator"}:
                names = return_acquisition_names(semantics, names, role)
            return (
                "(?-i:" + "|".join(re.escape(n) for n in sorted(names)) + ")" if names else "(?!)"
            )
        if name in roots:
            return (
                "(?-i:" + re.escape(name) + ")"
                if _semantic_call_allowed(
                    semantics,
                    True,
                    name,
                    *roots[name],
                    exact_compiler_intrinsics=native_intrinsics,
                )
                else "(?!)"
            )
        return "(?!)" if name in denied else name

    # Normalize the historical grouped spellings before checking each exact root.
    pattern = pattern.replace(
        "pthread_cond_(?:timed)?wait", "(?:pthread_cond_wait|pthread_cond_timedwait)"
    )
    pattern = pattern.replace(
        "pthread_(?:mutex|cond|rwlock)_init",
        "(?:pthread_mutex_init|pthread_cond_init|pthread_rwlock_init)",
    )
    pattern = pattern.replace("mem(?:cpy|move)", "(?:memcpy|memmove)")
    pattern = pattern.replace("__builtin_ctz(?:ll)?", "(?:__builtin_ctz|__builtin_ctzll)")
    pattern = pattern.replace("v(?:f)?printf", "(?:vprintf|vfprintf)")
    names = set(roots) | set(denied)
    return re.sub(
        r"(?:(?<=\\b)|(?<![A-Za-z0-9_]))(?:"
        + "|".join(re.escape(n) for n in sorted(names, key=len, reverse=True))
        + r")(?![A-Za-z0-9_])",
        replace,
        pattern,
    )


class RegexCandidateGenerator(
    RegexResourceLifecycleRules,
    RegexMemoryBoundsIntegerRules,
    RegexConcurrencySharedStateRules,
    RegexProtocolOwnershipLogicRules,
):
    """Generate structured candidates for high-signal C memory/concurrency bugs."""

    _LINE_RE = re.compile(r"^\s*(\d+)\s*\|\s?(.*)$")
    _IDENT_RE = re.compile(r"\b[A-Za-z_]\w*\b")
    _DEFAULT_SIZE_TYPES = {
        "size_t",
        "uint16_t",
        "uint32_t",
        "uint64_t",
        "int16_t",
        "int32_t",
        "int64_t",
        "uint8_t",
        "unsigned char",
        "unsigned int",
        "unsigned long",
        "int",
        "char",
    }

    def __init__(
        self,
        semantics: Optional[LocalPatternSemantics] = None,
        rule_policy: Optional[Any] = None,
        program_facts_provider: Optional[Any] = None,
        *,
        restrict_to_semantics: bool = False,
    ):
        self.restrict_to_semantics = restrict_to_semantics
        self.semantics = (
            _restricted_semantics(semantics) if restrict_to_semantics else default_local_semantics()
        )
        if semantics is not None and not restrict_to_semantics:
            self.semantics.merge(semantics)
        self.rule_policy = rule_policy
        self.program_facts_provider = program_facts_provider
        self.program_facts: Dict[str, Any] = {}
        self._compile_patterns()

    def _compile_patterns(self) -> None:
        from ...semantics.contracts import return_acquisition_names

        self._allocator_names = return_acquisition_names(
            self.semantics, self.semantics.allocators, "allocator"
        )
        self._calloc_names = return_acquisition_names(
            self.semantics, self.semantics.calloc_allocators, "calloc"
        )
        self._reallocator_names = return_acquisition_names(
            self.semantics, self.semantics.reallocators, "reallocator"
        )
        self._deallocator_names = set(self.semantics.deallocators)
        self._copy_sink_names = set(self.semantics.copy_sinks)
        self._lock_names = set(self.semantics.lock_apis)
        self._unlock_names = set(self.semantics.unlock_apis)
        self._size_type_names = self._DEFAULT_SIZE_TYPES | set(self.semantics.type_aliases)
        self._io_acquire_names = return_acquisition_names(
            self.semantics, self.semantics.io_acquirers, "io_acquire"
        )
        self._io_release_names = set(self.semantics.io_releasers)
        self._send_sink_names = set(self.semantics.send_sinks)
        self._recv_source_names = set(self.semantics.recv_sources)
        self._format_sink_names = set(self.semantics.format_sinks)
        self._callback_registrar_names = set(self.semantics.callback_registrars)
        self._user_io_acquire_names = self.semantics.names_from_nondefault_sources("io_acquirers")
        self._user_io_release_names = self.semantics.names_from_nondefault_sources("io_releasers")
        self._user_send_sink_names = self.semantics.names_from_nondefault_sources("send_sinks")
        self._user_recv_source_names = self.semantics.names_from_nondefault_sources("recv_sources")

        self._alloc_re = self._call_re(self._allocator_names)
        self._calloc_re = self._call_re(self._calloc_names)
        self._realloc_re = self._call_re(self._reallocator_names)
        self._dealloc_re = self._call_re(self._deallocator_names)
        self._copy_or_alloc_re = self._call_re(
            self._allocator_names
            | self._calloc_names
            | self._reallocator_names
            | self._copy_sink_names
        )
        self._copy_sink_re = self._call_re(self._copy_sink_names)
        self._lock_re = self._call_re(
            self._lock_names,
            extra_patterns=(
                [] if self.restrict_to_semantics else [r"pthread_rwlock_(?:rdlock|wrlock)"]
            ),
        )
        self._unlock_re = self._call_re(self._unlock_names)
        self._size_type_pattern = self._type_pattern(self._size_type_names)
        self._integer_pointer_type_pattern = self._type_pattern(
            name for name in self._size_type_names if name != "char" and name != "unsigned char"
        )

    def _semantic_api_pattern(self, pattern: str) -> str:
        return _consumer_api_pattern(
            pattern,
            self.semantics,
            self.restrict_to_semantics,
            exact_compiler_intrinsics=current_compiler_intrinsic_names(self.program_facts),
        )

    def _literal_api_pattern(self, pattern: str) -> str:
        return _consumer_api_pattern(
            pattern,
            self.semantics,
            self.restrict_to_semantics,
            expand_slots=False,
            exact_compiler_intrinsics=current_compiler_intrinsic_names(self.program_facts),
        )

    def _semantic_call_allowed(self, name: str, *roles: str) -> bool:
        return _semantic_call_allowed(
            self.semantics,
            self.restrict_to_semantics,
            name,
            *roles,
            exact_compiler_intrinsics=current_compiler_intrinsic_names(self.program_facts),
        )

    def _bound_api_calls(self, text: str, roles: set[str]) -> List[Tuple[str, str]]:
        names = {c.symbol.name for c in self.semantics.contracts.contracts if c.role in roles}
        events: List[Tuple[str, str]] = []
        for call in re.finditer(
            rf"\b(?P<api>{self._names_pattern(names)})\s*\((?P<args>[^()]*)\)", text
        ):
            prefix = text[: call.start()]
            assignment = re.search(
                r"(?P<lhs>[A-Za-z_]\w*(?:(?:->|\.)[A-Za-z_]\w*)?)\s*=\s*(?:\([^)]*\)\s*)?$", prefix
            )
            returned = assignment["lhs"] if assignment else ""
            for role in roles:
                obj = self.semantics.contracts.resolve_object(
                    call["api"], role, call["args"].split(","), returned
                )
                if obj:
                    events.append((call["api"], obj))
        return events

    _RESOURCE_BY_CLASS = {
        "integer_overflow": "memory",
        "bounds": "memory",
        "format_string": "string",
        "deadlock": "lock",
        "toctou": "file",
        "command_injection": "process",
        "memory_leak": "memory",
        "type_confusion": "memory",
        "signed_unsigned": "memory",
        "off_by_one": "memory",
        "stack_overflow": "memory",
        "alignment": "memory",
        "uninitialized_read": "memory",
        "realloc_misuse": "memory",
        "double_free": "memory",
        "invalid_free": "memory",
        "use_after_free": "memory",
        "race": "shared_state",
        "stack_escape": "stack",
        "missing_unlock": "lock",
        "held_lock_callback": "lock",
        "lost_wakeup": "condition_variable",
        "refcount_race": "shared_state",
        "object_publication": "shared_state",
        "double_checked_locking": "shared_state",
        "stale_fd": "handle",
        "busy_loop": "cpu",
        "unchecked_return": "error_status",
        "state_inconsistency": "shared_state",
        "key_truncation": "key",
        "size_limit_mismatch": "memory",
        "fd_type_mismatch": "handle",
        "protocol_mixup": "protocol",
        "protocol_validation": "protocol",
        "partial_resource_leak": "memory",
        "dynamic_array_race": "shared_state",
        "version_filtering": "protocol",
        "missing_refcount": "resource_lifecycle",
        "sigpipe_unhandled": "signal",
        "fd_encoding_mismatch": "handle",
        "semantic_mismatch": "protocol",
        "byte_order_logic": "protocol",
        "reader_state_race": "shared_state",
        "uninitialized_output": "memory",
        "file_type_validation": "file",
        "log_level_misuse": "logging",
        "logic_error": "protocol",
        "global_mode_race": "shared_state",
        "slot_race": "shared_state",
        "shared_memory_race": "shared_memory",
        "state_machine": "shared_state",
        "signal_deadlock": "signal",
        "signal_race": "signal",
        "callback_self_destroy_race": "callback_lifetime",
    }

    def generate_issues(
        self,
        func_name: str,
        code: str,
        file_path: str,
        *,
        allowed_skills: Optional[Iterable[str]] = None,
    ) -> List[Dict[str, Any]]:
        self._function_name = str(func_name)
        self.program_facts = (
            self.program_facts_provider(func_name, file_path) if self.program_facts_provider else {}
        )
        semantic_context = {
            "func_name": func_name,
            "file_path": file_path,
            "code": code,
            "program_facts": self.program_facts,
        }
        self.last_semantic_events = self.semantics.contracts.trace_calls(semantic_context)
        lines = self._parse_lines(code)
        if not lines:
            return []
        allowed = set(allowed_skills) if allowed_skills is not None else None
        issues: List[Dict[str, Any]] = []
        emit = self._make_emit(issues, func_name, file_path, lines, allowed)
        from ...semantics.call_context import bind_call_context

        with bind_call_context(semantic_context, self.semantics.contracts):
            run_detector_plan(
                "regex",
                "function",
                RegexRuleContext(generator=self, lines=lines, emit=emit),
            )

        from ...semantics.build_scope import bind_candidate_build_scope

        bind_candidate_build_scope(issues, semantic_context)
        deduped: Dict[str, Dict[str, Any]] = {}
        for issue in issues:
            key = str(issue.get("dedup_key") or issue["id"])
            deduped.setdefault(key, issue)
        return list(deduped.values())

    def generate_tickets(
        self,
        func_name: str,
        code: str,
        file_path: str,
        *,
        allowed_skills: Optional[Iterable[str]] = None,
    ) -> List["SubAgentTicket"]:
        return [
            self.issue_to_ticket(issue)
            for issue in self.generate_issues(
                func_name,
                code,
                file_path,
                allowed_skills=allowed_skills,
            )
        ]

    def issue_to_ticket(self, issue: Dict[str, Any]) -> "SubAgentTicket":
        from ...orchestration.subagents import SubAgentTicket

        defect_class = str(issue.get("defect_class") or issue.get("subcategory") or "unknown")
        rule_id = str(issue.get("rule_id") or issue.get("rule") or "")
        descriptor = resolve_rule_descriptor(
            self.rule_policy,
            rule_id,
            defect_class=defect_class,
        )
        skill = str(
            issue.get("skill") or (descriptor.skill if descriptor else "resource_lifecycle")
        )
        evidence = dict(issue.get("evidence_pack") or {})
        evidence.setdefault("positive_evidence", issue.get("positive_evidence") or [])
        evidence.setdefault("negative_evidence", issue.get("negative_evidence") or [])
        line = self._line_from_location(str(issue.get("location") or ""))
        return SubAgentTicket(
            id=str(issue.get("candidate_id") or issue.get("id")),
            skill=skill,
            task=(
                f"Verify regex/local-pattern {defect_class} candidate. Confirm concrete "
                "source, sink, path feasibility, and guard sufficiency; reject if any "
                "required proof is missing."
            ),
            trigger=str(issue.get("rule") or defect_class),
            line=line,
            context_slice=str(issue.get("code_snippet") or ""),
            priority_score=self._priority_for_issue(issue),
            priority_reasons=[
                str(issue.get("candidate_source") or "regex_local_rule"),
                defect_class,
                f"rule_confidence={issue.get('rule_confidence', issue.get('confidence', 0.5))}",
            ],
            origin=str(issue.get("source") or issue.get("location") or ""),
            sink=str(issue.get("sink") or issue.get("location") or ""),
            resource_kind=self._RESOURCE_BY_CLASS.get(defect_class, "unknown"),
            source=str(issue.get("candidate_source") or "regex_local_rule"),
            evidence=evidence,
        )

    def _make_emit(
        self,
        issues: List[Dict[str, Any]],
        func_name: str,
        file_path: str,
        lines: List[CodeLine],
        allowed_skills: Optional[set[str]],
    ):
        def emit(
            *,
            defect_class: str,
            rule: str,
            line: CodeLine,
            description: str,
            root_cause: str,
            suggested_fix: str,
            sink: str,
            source: str = "",
            confidence: float = 0.78,
            impact_level: str = "medium",
            positive: Optional[List[str]] = None,
            negative: Optional[List[str]] = None,
            evidence: Optional[Dict[str, Any]] = None,
            context_start: int = -5,
            context_end: int = 8,
        ) -> None:
            should_emit, descriptor = resolve_emitter_descriptor(
                self.rule_policy,
                rule,
                defect_class=defect_class,
            )
            if not should_emit:
                return
            if (
                allowed_skills is not None
                and descriptor is not None
                and descriptor.skill not in allowed_skills
            ):
                return
            cwe = descriptor.cwe if descriptor is not None else ""
            skill = descriptor.skill if descriptor is not None else ""

            candidate_id = self._candidate_id(func_name, file_path, defect_class, line.number, sink)
            dedup_key = "|".join(
                [
                    defect_class,
                    file_path.replace("\\", "/").lower(),
                    str(line.number),
                    self._normalize_sink_key(sink),
                ]
            )
            pos = list(positive or [])
            pos.extend(self._api_evidence_for_line(line.text))
            neg = list(negative or [])
            pack = {
                "candidate_id": candidate_id,
                "candidate_source": "regex_local_rule",
                "defect_class": defect_class,
                "rule": rule,
                "rule_id": descriptor.rule_id if descriptor is not None else rule,
                "cwe": cwe,
                "skill": skill,
                "rule_confidence": confidence,
                "source": {
                    "expression": source,
                    "line": line.number,
                    "file": file_path,
                },
                "sink": {
                    "operation": sink,
                    "line": line.number,
                    "file": file_path,
                },
                "path": {
                    "function": func_name,
                    "complete_in_function": True,
                    "guard_status": "insufficient_or_absent" if not neg else "needs_validation",
                },
                "object": {
                    "id": source or sink or defect_class,
                    "aliases": [],
                },
                "evidence_refs": [],
                "positive_evidence": pos,
                "negative_evidence": neg,
            }
            if evidence:
                pack.update(evidence)

            reasoning = self._build_readable_reasoning(
                defect_class=defect_class,
                rule=rule,
                func_name=func_name,
                file_path=file_path,
                line=line.number,
                description=description,
                root_cause=root_cause,
                suggested_fix=suggested_fix,
                source=source,
                sink=sink,
                positive_evidence=pos,
                negative_evidence=neg,
                evidence_pack=pack,
                cwe=cwe,
            )

            issues.append(
                {
                    "id": candidate_id,
                    "candidate_id": candidate_id,
                    "function": func_name,
                    "location": f"{file_path}:{line.number}",
                    "category": defect_class,
                    "subcategory": defect_class,
                    "defect_class": defect_class,
                    "finding_kind": "regex_candidate",
                    "rule": rule,
                    "rule_id": descriptor.rule_id if descriptor is not None else rule,
                    "cwe": cwe,
                    "skill": skill,
                    "description": description,
                    "root_cause": root_cause,
                    "suggested_fix": suggested_fix,
                    "confidence": confidence,
                    "rule_confidence": confidence,
                    "impact_level": impact_level,
                    "reasoning": reasoning,
                    "code_snippet": self._context(
                        lines, line.index + context_start, line.index + context_end
                    ),
                    "source": source,
                    "sink": sink,
                    "dedup_key": dedup_key,
                    "positive_evidence": pos,
                    "negative_evidence": neg,
                    "evidence_pack": pack,
                    "evidence_refs": [],
                }
            )

        return emit

    @staticmethod
    def _build_readable_reasoning(
        *,
        defect_class: str,
        rule: str,
        func_name: str,
        file_path: str,
        line: int,
        description: str,
        root_cause: str,
        suggested_fix: str,
        source: str,
        sink: str,
        positive_evidence: List[str],
        negative_evidence: List[str],
        evidence_pack: Dict[str, Any],
        cwe: str,
    ) -> str:
        """Build Chinese human-readable reasoning from regex/local-pattern evidence."""

        raw_path = evidence_pack.get("path")
        path: Dict[str, Any] = raw_path if isinstance(raw_path, dict) else {}
        guard_status = str(path.get("guard_status") or "")
        if guard_status == "insufficient_or_absent":
            guard_text = "当前函数内未看到足够的边界检查、所有权转移或同步保护。"
        elif guard_status == "needs_validation":
            guard_text = "存在部分保护或反向证据，需要结合上下文继续确认。"
        else:
            guard_text = "规则证据未给出额外保护状态。"

        flow_parts = []
        if source:
            flow_parts.append(f"源/对象 `{source}`")
        if sink:
            flow_parts.append(f"汇点/操作 `{sink}`")
        flow = " -> ".join(flow_parts) if flow_parts else "规则命中的本地代码片段"

        lines = [
            f"Regex 本地规则 `{rule}` 在 `{func_name}` 的 `{file_path}:{line}` 命中 `{defect_class}`"
            + (f"（{cwe}）" if cwe else "")
            + " 候选。",
            f"问题判断：{description}",
            f"数据/资源路径：{flow}。",
            f"保护状态：{guard_text}",
        ]
        if positive_evidence:
            lines.append("关键证据：")
            lines.extend(f"- {item}" for item in positive_evidence[:6])
            if len(positive_evidence) > 6:
                lines.append(f"- 另有 {len(positive_evidence) - 6} 条结构化证据未展开。")
        if negative_evidence:
            lines.append("需要复核的反向证据：")
            lines.extend(f"- {item}" for item in negative_evidence[:4])
        else:
            lines.append("反向证据：未发现能否定该候选的本地保护或清理证据。")
        lines.append(f"根因：{root_cause}")
        lines.append(f"建议：{suggested_fix}")
        return "\n".join(lines)

    @staticmethod
    def _names_pattern(names: Iterable[str]) -> str:
        escaped = [
            re.escape(name).replace(r"\ ", r"\s+")
            for name in sorted({str(item) for item in names if item}, key=len, reverse=True)
        ]
        return "|".join(escaped) or r"a\bnothing_matches"

    @classmethod
    def _call_re(
        cls,
        names: Iterable[str],
        *,
        extra_patterns: Optional[Iterable[str]] = None,
    ) -> re.Pattern[str]:
        patterns = [cls._names_pattern(names)]
        patterns.extend(str(item) for item in extra_patterns or [] if item)
        return re.compile(rf"\b(?:{'|'.join(patterns)})\s*\(")

    @classmethod
    def _type_pattern(cls, names: Iterable[str]) -> str:
        return cls._names_pattern(names)

    def _api_evidence_for_line(self, text: str) -> List[str]:
        evidence: List[str] = []
        categories = [
            ("allocator", self.semantics.allocators),
            ("calloc", self.semantics.calloc_allocators),
            ("reallocator", self.semantics.reallocators),
            ("deallocator", self.semantics.deallocators),
            ("copy", self.semantics.copy_sinks),
            ("lock", self.semantics.lock_apis),
            ("unlock", self.semantics.unlock_apis),
            ("io_acquire", self.semantics.io_acquirers),
            ("io_release", self.semantics.io_releasers),
            ("send_sink", self.semantics.send_sinks),
            ("recv_source", self.semantics.recv_sources),
            ("format_sink", self.semantics.format_sinks),
            ("callback_register", self.semantics.callback_registrars),
        ]
        for category, mapping in categories:
            for name, sources in mapping.items():
                if re.search(rf"\b{re.escape(name)}\s*\(", text):
                    evidence.append(
                        f"`{name}` classified as {category} API via {', '.join(sources)}"
                    )
        return evidence

    def _parse_lines(self, code: str) -> List[CodeLine]:
        parsed: List[CodeLine] = []
        for idx, raw in enumerate(str(code or "").splitlines()):
            match = self._LINE_RE.match(raw)
            if match:
                number = int(match.group(1))
                text = match.group(2)
            else:
                number = idx + 1
                text = raw
            parsed.append(
                CodeLine(number=number, raw=raw, text=self._strip_comment(text).strip(), index=idx)
            )
        return parsed

    @staticmethod
    def _strip_comment(text: str) -> str:
        return re.sub(r"//.*$", "", text)

    def _context(self, lines: List[CodeLine], start: int, end: int) -> str:
        return "\n".join(line.raw for line in lines[max(0, start) : min(len(lines), end)])

    def _pointer_owner_vars(self, lines: List[CodeLine]) -> set[str]:
        owners: set[str] = set()
        alloc_names = self._allocator_names | self._calloc_names | self._reallocator_names
        for line in lines:
            pointer_decl = re.search(
                r"(?:^|[;{]\s*)(?:const\s+)?(?:struct\s+)?[A-Za-z_]\w*(?:\s*\*)+\s*"
                r"(?P<var>[A-Za-z_]\w*)\b",
                line.text,
            )
            if pointer_decl:
                owners.add(pointer_decl.group("var"))
            alloc_assign = re.search(
                rf"\b(?P<var>[A-Za-z_]\w*)\s*=\s*(?:\([^)]*\)\s*)?"
                rf"(?:{self._names_pattern(alloc_names)})\s*\(",
                line.text,
            )
            if alloc_assign:
                owners.add(alloc_assign.group("var"))
        return owners

    @staticmethod
    def _candidate_id(
        func_name: str, file_path: str, defect_class: str, line: int, sink: str
    ) -> str:
        digest = hashlib.sha1(
            f"{file_path}:{func_name}:{defect_class}:{line}:{sink}".encode("utf-8")
        ).hexdigest()[:10]
        prefix = re.sub(r"[^A-Za-z0-9]+", "_", defect_class).upper()
        return f"RULE_{prefix}_{line}_{digest}"

    @staticmethod
    def _line_from_location(location: str) -> int:
        match = re.search(r":(\d+)(?::|$)", location)
        return int(match.group(1)) if match else 0

    @staticmethod
    def _normalize_sink_key(value: str) -> str:
        return re.sub(r"\s+", " ", str(value or "").strip().lower())[:120]

    @staticmethod
    def _priority_for_issue(issue: Dict[str, Any]) -> int:
        confidence = issue.get("rule_confidence", issue.get("confidence", 0.5))
        try:
            score = float(confidence)
        except (TypeError, ValueError):
            score = 0.5
        severity = str(issue.get("impact_level") or "").lower()
        bonus = {"critical": 18, "high": 12, "medium": 6, "low": 0}.get(severity, 3)
        return max(1, min(100, int(score * 80) + bonus))
