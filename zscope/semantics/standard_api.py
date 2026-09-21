"""Reviewed C/POSIX API contracts, independent of project interface spelling."""

from __future__ import annotations
from typing import Any
from .contract_conditions import compare, negate

STANDARD_API_VERSION = "zscope.standard-api.v3"
POSIX_REFERENCE = "https://pubs.opengroup.org/onlinepubs/9799919799/functions/contents.html"


def standard_contracts() -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    ret = {"kind": "return"}

    def add(
        names, role, family="", pair="", *, argument=None, output=False, success=None, behavior=""
    ):
        for name in names.split():
            carrier = (
                {"kind": "return"}
                if argument is None
                else {
                    "kind": "output_argument" if output else "argument",
                    "argument_index": argument,
                }
            )
            condition = success or {"op": "true"}
            rows.append(
                {
                    "symbol": {"name": name},
                    "role": role,
                    "carrier": carrier,
                    "resource_family": family,
                    "pairs": [pair] if pair else [],
                    "source": "builtin_defaults",
                    "preconditions": {"op": "true"},
                    "effect_cases": [
                        {"when": condition, "effect": "applies"},
                        {
                            "when": (
                                negate(condition)
                                if condition != {"op": "true"}
                                else {"op": "false"}
                            ),
                            "effect": "no_effect",
                        },
                    ],
                    "verification": {
                        "method": "standard_specification",
                        "catalog_version": STANDARD_API_VERSION,
                        "behavior": behavior,
                    },
                    "evidence": [{"source": POSIX_REFERENCE, "api": name}],
                }
            )

    pointer = compare(ret, "!=", None)
    zero = compare(ret, "==", 0)
    descriptor = compare(ret, ">=", 0)
    robust = {
        "op": "any",
        "items": [
            zero,
            {
                "op": "compare",
                "left": ret,
                "operator": "==",
                "right": {"kind": "constant", "name": "EOWNERDEAD"},
            },
        ],
    }
    add("malloc aligned_alloc strdup strndup", "allocator", "malloc", "free", success=pointer)
    add(
        "calloc",
        "calloc",
        "malloc",
        "free",
        success=pointer,
        behavior="zero_initialized; checked_product",
    )
    add("posix_memalign", "allocator", "malloc", "free", argument=0, output=True, success=zero)
    add(
        "realloc reallocarray",
        "reallocator",
        "malloc",
        "free",
        success=pointer,
        behavior="success_replaces_argument_0; nonzero_size_failure_preserves_old; zero_size_platform_dependent",
    )
    add(
        "free",
        "deallocator",
        "malloc",
        argument=0,
        success=compare({"kind": "argument", "index": 0}, "!=", None),
        behavior="null_is_noop",
    )
    add(
        "open openat creat socket accept accept4 dup dup2 dup3",
        "io_acquire",
        "descriptor",
        "close",
        success=descriptor,
    )
    add("fopen fdopen freopen", "io_acquire", "file", "fclose", success=pointer)
    add("opendir fdopendir", "io_acquire", "directory", "closedir", success=pointer)
    add(
        "close",
        "io_release",
        "descriptor",
        argument=0,
        success=zero,
        behavior="error_release_state_platform_dependent",
    )
    add(
        "fclose",
        "io_release",
        "file",
        argument=0,
        behavior="stream_disassociated_even_on_flush_error",
    )
    add("closedir", "io_release", "directory", argument=0, success=zero)
    add(
        "pthread_mutex_lock pthread_mutex_trylock pthread_mutex_timedlock pthread_mutex_clocklock",
        "lock",
        "mutex",
        "pthread_mutex_unlock",
        argument=0,
        success=robust,
    )
    add("pthread_mutex_unlock", "unlock", "mutex", argument=0, success=zero)
    add(
        "pthread_mutex_init",
        "lock_init",
        "mutex",
        "pthread_mutex_destroy",
        argument=0,
        success=zero,
        behavior="initialize_unlocked",
    )
    add("pthread_mutex_destroy", "lock_destroy", "mutex", argument=0, success=zero)
    add(
        "pthread_mutex_consistent",
        "lock_state",
        "mutex",
        argument=0,
        success=zero,
        behavior="repair_robust_state; no_lock_acquisition",
    )
    add(
        "pthread_rwlock_rdlock pthread_rwlock_wrlock pthread_rwlock_tryrdlock pthread_rwlock_trywrlock pthread_rwlock_timedrdlock pthread_rwlock_timedwrlock",
        "lock",
        "rwlock",
        "pthread_rwlock_unlock",
        argument=0,
        success=zero,
    )
    add("pthread_rwlock_unlock", "unlock", "rwlock", argument=0, success=zero)
    add(
        "pthread_rwlock_init",
        "lock_init",
        "rwlock",
        "pthread_rwlock_destroy",
        argument=0,
        success=zero,
    )
    add("pthread_rwlock_destroy", "lock_destroy", "rwlock", argument=0, success=zero)
    add(
        "pthread_spin_lock pthread_spin_trylock",
        "lock",
        "spinlock",
        "pthread_spin_unlock",
        argument=0,
        success=zero,
    )
    add("pthread_spin_unlock", "unlock", "spinlock", argument=0, success=zero)
    add(
        "pthread_spin_init",
        "lock_init",
        "spinlock",
        "pthread_spin_destroy",
        argument=0,
        success=zero,
    )
    add("pthread_spin_destroy", "lock_destroy", "spinlock", argument=0, success=zero)
    wait_success = {
        "op": "any",
        "items": [
            robust,
            {
                "op": "compare",
                "left": ret,
                "operator": "==",
                "right": {"kind": "constant", "name": "ETIMEDOUT"},
            },
        ],
    }
    add(
        "pthread_cond_wait pthread_cond_timedwait pthread_cond_clockwait",
        "lock_wait",
        "mutex",
        argument=1,
        success=wait_success,
        behavior="requires_owned_mutex; release_then_reacquire; cancellation_reacquires_before_cleanup",
    )
    add(
        "pthread_cond_init",
        "condition_init",
        "condition",
        "pthread_cond_destroy",
        argument=0,
        success=zero,
    )
    add("pthread_cond_destroy", "condition_destroy", "condition", argument=0, success=zero)
    add(
        "pthread_cond_signal pthread_cond_broadcast",
        "condition_signal",
        "condition",
        argument=0,
        success=zero,
    )
    add(
        "pthread_create",
        "thread_create",
        "thread",
        argument=0,
        output=True,
        success=zero,
        behavior="callback_argument_2; context_argument_3",
    )
    add("pthread_join pthread_detach", "thread_release", "thread", argument=0, success=zero)
    add(
        "pthread_once",
        "callback_register",
        argument=1,
        success=zero,
        behavior="synchronous_once_callback",
    )
    add("memcpy memmove memset strcpy strncpy strcat strncat", "copy", argument=0)
    add("read recv recvfrom", "recv_source", argument=1)
    add("fread", "recv_source", argument=0)
    add("write send sendto sendmsg", "send_sink", argument=1)
    add("printf vprintf", "format_sink", argument=0)
    add("fprintf vfprintf syslog", "format_sink", argument=1)
    add("sprintf vsprintf", "format_sink", argument=1)
    add("snprintf vsnprintf", "format_sink", argument=2)
    add(
        "bind listen connect shutdown setsockopt getsockopt getsockname getpeername",
        "standard_operation",
        "descriptor",
        argument=0,
        behavior="updates_or_queries_socket_state; does_not_close_or_allocate_descriptor",
    )
    add(
        "htons htonl ntohs ntohl inet_ntoa inet_ntop inet_pton",
        "standard_operation",
        argument=0,
        behavior="address_conversion; no_resource_ownership_transition",
    )
    add(
        "localtime localtime_r gmtime gmtime_r strftime stat fstat lstat uname mkdir fflush fseek ftell rewind",
        "standard_operation",
        argument=0,
        behavior="may_read_or_write_external_state_and_output_storage; no_caller_resource_ownership_transfer",
    )
    add(
        "getpid getppid pthread_self",
        "standard_operation",
        behavior="returns_borrowed_process_or_thread_identity; no_resource_ownership_transition",
    )
    # Explicitly known non-resource operations close composition without claiming
    # general purity: their writes/aliasing still need the call's source facts.
    add(
        "strlen strnlen strcmp strncmp memcmp strchr strrchr strstr strtol strtoul strtoll strtoull atoi atol strerror getenv gettimeofday clock_gettime time usleep sleep nanosleep sched_yield",
        "standard_operation",
        argument=0,
        behavior="no_resource_ownership_transition",
    )
    add(
        "pthread_equal pthread_mutexattr_init pthread_mutexattr_destroy pthread_mutexattr_settype pthread_mutexattr_setrobust pthread_attr_init pthread_attr_destroy pthread_attr_setdetachstate",
        "standard_operation",
        argument=0,
        behavior="no_resource_ownership_transition",
    )

    # Composite effects are machine-readable; role summaries alone cannot
    # express realloc failure preservation or release/reacquire operations.
    for row in rows:
        name = row["symbol"]["name"]
        if name == "pthread_create":
            row["pairs"] = ["pthread_join", "pthread_detach"]
        transitions = []
        if name in {"realloc", "reallocarray"}:
            nonzero = compare({"kind": "argument", "index": 1}, ">", 0)
            zero_size = compare({"kind": "argument", "index": 1}, "==", 0)
            if name == "reallocarray":
                nonzero = {
                    "op": "all",
                    "items": [nonzero, compare({"kind": "argument", "index": 2}, ">", 0)],
                }
                zero_size = {
                    "op": "any",
                    "items": [zero_size, compare({"kind": "argument", "index": 2}, "==", 0)],
                }
            null_result = compare(ret, "==", None)
            transitions = [
                {
                    "when": pointer,
                    "actions": [
                        {
                            "kind": "replace",
                            "old": {"kind": "argument", "argument_index": 0},
                            "new": {"kind": "return"},
                        }
                    ],
                },
                {
                    "when": {"op": "all", "items": [nonzero, null_result]},
                    "actions": [
                        {"kind": "preserve", "object": {"kind": "argument", "argument_index": 0}}
                    ],
                },
                {
                    "when": {
                        "op": "all",
                        "items": [
                            compare({"kind": "target", "name": "target.libc"}, "==", "glibc"),
                            zero_size,
                            compare({"kind": "argument", "index": 0}, "!=", None),
                        ],
                    },
                    "actions": [
                        {"kind": "release", "object": {"kind": "argument", "argument_index": 0}}
                    ],
                },
            ]
        elif row["role"] == "lock_wait":
            transitions = [
                {
                    "when": row["effect_cases"][0]["when"],
                    "actions": [
                        {"kind": "release", "object": row["carrier"]},
                        {"kind": "acquire", "object": row["carrier"]},
                    ],
                }
            ]
        elif row["role"] in {"lock_init", "lock_destroy", "condition_init", "condition_destroy"}:
            transitions = [
                {"when": zero, "actions": [{"kind": row["role"], "object": row["carrier"]}]}
            ]
        extent_indices = {
            "malloc": [0],
            "aligned_alloc": [1],
            "calloc": [0, 1],
            "realloc": [1],
            "reallocarray": [1, 2],
            "posix_memalign": [2],
        }
        if transitions or name in extent_indices:
            row["protocol"] = {
                "kind": "standard_api_effects",
                "version": STANDARD_API_VERSION,
                "transitions": transitions,
            }
            if name in extent_indices:
                row["protocol"]["allocation_extent"] = [
                    {"kind": "argument", "index": i} for i in extent_indices[name]
                ]
    return rows
