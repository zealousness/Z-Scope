"""Reviewed C/POSIX API contracts, independent of project interface spelling."""

from __future__ import annotations
from typing import Any
from .contract_conditions import compare, negate

STANDARD_API_VERSION = "zscope.standard-api.v9"
POSIX_REFERENCE = "https://pubs.opengroup.org/onlinepubs/9799919799/functions/contents.html"


def standard_contracts() -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    ret = {"kind": "return"}

    def add(
        names,
        role,
        family="",
        pair="",
        *,
        argument=None,
        output=False,
        success=None,
        behavior="",
        lock_mode="unknown",
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
                    "protocol": ({"lock_mode": lock_mode} if role == "lock" else {}),
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
        "open openat creat shm_open socket accept accept4 dup dup2 dup3",
        "io_acquire",
        "descriptor",
        "close",
        success=descriptor,
    )
    add("fopen fdopen freopen", "io_acquire", "file", "fclose", success=pointer)
    add("opendir fdopendir", "io_acquire", "directory", "closedir", success=pointer)
    add("popen", "io_acquire", "file", "pclose", success=pointer)
    add(
        "close",
        "io_release",
        "descriptor",
        argument=0,
        success=zero,
        behavior="error_release_state_platform_dependent",
    )
    # The catalog already records that close errors have no universal release
    # state. Do not publish the generic helper's stronger no_effect fallback.
    rows[-1]["effect_cases"][1]["effect"] = "unknown"
    add(
        "fclose",
        "io_release",
        "file",
        argument=0,
        behavior="stream_disassociated_even_on_flush_error",
    )
    # A closedir invocation consumes the DIR stream obligation.  Its status is
    # diagnostic (for example EBADF), not evidence that a valid stream remains
    # owned by the caller and should be reported as leaked.
    add("closedir", "io_release", "directory", argument=0)
    add("pclose", "io_release", "file", argument=0)
    add(
        "epoll_create epoll_create1 inotify_init inotify_init1 eventfd timerfd_create signalfd mq_open",
        "io_acquire",
        "descriptor",
        "close",
        success=descriptor,
    )
    # POSIX message-queue descriptors have their own release primitive.
    for row in rows[-9:]:
        if row["symbol"]["name"] == "mq_open":
            row["pairs"] = ["mq_close"]
            row["resource_family"] = "message_queue"
    add("mq_close", "io_release", "message_queue", argument=0, success=zero)
    add(
        "mmap",
        "allocator",
        "mapping",
        "munmap",
        success=compare(ret, "!=", {"kind": "constant", "name": "MAP_FAILED"}),
        behavior="mapping_return; MAP_FAILED_is_failure",
    )
    add("munmap", "deallocator", "mapping", argument=0, success=zero)
    add(
        "dlopen dlmopen",
        "allocator",
        "dynamic_library",
        "dlclose",
        success=pointer,
        behavior="dynamic_loader_handle",
    )
    add("dlclose", "deallocator", "dynamic_library", argument=0, success=zero)
    add(
        "iconv_open",
        "allocator",
        "iconv_descriptor",
        "iconv_close",
        success=compare(ret, "!=", -1),
    )
    add("iconv_close", "deallocator", "iconv_descriptor", argument=0, success=zero)
    add("regcomp", "io_acquire", "regex_state", "regfree", argument=0, success=zero)
    add("regfree", "io_release", "regex_state", argument=0)
    add("glob", "io_acquire", "glob_state", "globfree", argument=3, success=zero)
    add("globfree", "io_release", "glob_state", argument=0)
    add("shmat", "allocator", "sysv_mapping", "shmdt", success=compare(ret, "!=", -1))
    add("shmdt", "deallocator", "sysv_mapping", argument=0, success=zero)
    add(
        "pthread_mutex_lock pthread_mutex_trylock pthread_mutex_timedlock pthread_mutex_clocklock",
        "lock",
        "mutex",
        "pthread_mutex_unlock",
        argument=0,
        success=robust,
        lock_mode="exclusive",
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
        "pthread_rwlock_rdlock pthread_rwlock_tryrdlock pthread_rwlock_timedrdlock",
        "lock",
        "rwlock",
        "pthread_rwlock_unlock",
        argument=0,
        success=zero,
        lock_mode="shared",
    )
    add(
        "pthread_rwlock_wrlock pthread_rwlock_trywrlock pthread_rwlock_timedwrlock",
        "lock",
        "rwlock",
        "pthread_rwlock_unlock",
        argument=0,
        success=zero,
        lock_mode="exclusive",
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
        lock_mode="exclusive",
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
    add(
        "mtx_lock mtx_trylock mtx_timedlock",
        "lock",
        "c11_mutex",
        "mtx_unlock",
        argument=0,
        success=zero,
        lock_mode="exclusive",
    )
    add("mtx_unlock", "unlock", "c11_mutex", argument=0, success=zero)
    add("mtx_init", "lock_init", "c11_mutex", "mtx_destroy", argument=0, success=zero)
    add("mtx_destroy", "lock_destroy", "c11_mutex", argument=0)
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
    add("cnd_init", "condition_init", "c11_condition", "cnd_destroy", argument=0, success=zero)
    add("cnd_destroy", "condition_destroy", "c11_condition", argument=0)
    add("cnd_signal cnd_broadcast", "condition_signal", "c11_condition", argument=0, success=zero)
    add(
        "cnd_wait cnd_timedwait",
        "lock_wait",
        "c11_mutex",
        argument=1,
        success=zero,
        behavior="release_then_reacquire",
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
    add("thrd_create", "thread_create", "c11_thread", argument=0, output=True, success=zero)
    add("thrd_join thrd_detach", "thread_release", "c11_thread", argument=0, success=zero)
    add(
        "pthread_cancel",
        "standard_operation",
        "thread",
        argument=0,
        success=zero,
        behavior="cancellation_request_is_not_callback_completion",
    )
    add(
        "pthread_once",
        "callback_register",
        argument=1,
        success=zero,
        behavior="synchronous_once_callback",
    )
    add(
        "pthread_testcancel",
        "standard_operation",
        "thread",
        behavior="deferred_cancellation_point; pending_request_runs_lifo_cleanup_without_return",
    )
    add(
        "signal",
        "callback_register",
        argument=1,
        behavior="process_signal_handler_registration; previous_handler_returned",
    )
    add(
        "sigaction kill raise shm_unlink",
        "standard_operation",
        argument=0,
        behavior="process_or_named_object_state_transition; no_local_resource_ownership_transfer",
    )
    add("memcpy memmove memset strcpy strncpy strcat strncat", "copy", argument=0)
    add("read recv recvfrom", "recv_source", argument=1)
    add("readv preadv preadv2 recvmsg mq_receive mq_timedreceive", "recv_source", argument=1)
    add("fread", "recv_source", argument=0)
    add("write send sendto sendmsg", "send_sink", argument=1)
    add("writev pwritev pwritev2 mq_send mq_timedsend", "send_sink", argument=1)
    add("printf vprintf", "format_sink", argument=0)
    add("fprintf vfprintf syslog", "format_sink", argument=1)
    add("sprintf vsprintf", "format_sink", argument=1)
    add("snprintf vsnprintf", "format_sink", argument=2)
    add("asprintf vasprintf", "format_sink", argument=1)
    add("dprintf vdprintf", "format_sink", argument=1)
    add("asprintf vasprintf", "allocator", "malloc", "free", argument=0, output=True, success=descriptor)
    add("getline getdelim", "allocator", "malloc", "free", argument=0, output=True, success=descriptor)
    add(
        "system popen execl execlp execle execv execvp execve fexecve execvpe posix_spawn posix_spawnp dlopen dlmopen",
        "command_sink",
        argument=0,
        behavior="process_or_dynamic_loader_execution_sink",
    )
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
    add(
        "sem_init sem_destroy sem_wait sem_trywait sem_timedwait sem_clockwait sem_post sem_getvalue pthread_barrier_init pthread_barrier_destroy pthread_barrier_wait shmget shmctl mq_unlink dlsym",
        "standard_operation",
        argument=0,
        behavior="protocol_or_namespace_state_transition; no_generic_lockset_or_ownership_claim",
    )

    # Composite effects are machine-readable; role summaries alone cannot
    # express realloc failure preservation or release/reacquire operations.
    for row in rows:
        name = row["symbol"]["name"]
        if name == "pthread_create":
            row["pairs"] = ["pthread_join", "pthread_detach"]
        transitions = []
        if name in {"pthread_create", "pthread_join", "pthread_detach", "pthread_cancel"}:
            action = {
                "kind": {
                    "pthread_create": "start_callback",
                    "pthread_join": "wait_callback_completion",
                    "pthread_detach": "release_join_handle",
                    "pthread_cancel": "request_cancellation",
                }[name],
                "object": row["carrier"],
            }
            if name == "pthread_create":
                action.update(
                    {
                        "callback": {"kind": "argument", "argument_index": 2},
                        "context": {"kind": "argument", "argument_index": 3},
                    }
                )
            transitions = [{"when": zero, "actions": [action]}]
        elif name in {"realloc", "reallocarray"}:
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
        elif row["role"] in {"lock", "unlock"}:
            transitions = [
                {
                    "when": row["effect_cases"][0]["when"],
                    "actions": [
                        {
                            "kind": "acquire" if row["role"] == "lock" else "release",
                            "object": row["carrier"],
                            "lock_mode": row["protocol"].get("lock_mode", "unknown"),
                        }
                    ],
                }
            ]
        elif row["role"] == "lock_wait":
            transitions = [
                {
                    "when": row["effect_cases"][0]["when"],
                    "actions": [
                        {"kind": "release", "object": row["carrier"]},
                        {"kind": "acquire", "object": row["carrier"], "lock_mode": "exclusive"},
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
            "mmap": [1],
        }
        if transitions or name in extent_indices:
            row["protocol"] = {
                **row["protocol"],
                "kind": "standard_api_effects",
                "version": STANDARD_API_VERSION,
                "transitions": transitions,
            }
            if name in extent_indices:
                row["protocol"]["allocation_extent"] = [
                    {"kind": "argument", "index": i} for i in extent_indices[name]
                ]
        from .c_linux_catalog import catalog_sources_for

        row["evidence"] = [
            {"source": source, "api": name} for source in catalog_sources_for(name)
        ]
    return rows
