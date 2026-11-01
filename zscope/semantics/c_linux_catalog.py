"""Versioned Linux glibc LP64 primitive catalog and completeness audit.

ABI strings in this module are generated from the current native indexer's
``getCanonicalType().getAsString()`` receipts, not from source spelling.  The
semantic rows remain in :mod:`standard_api` for compatibility, but every
runtime consumer is gated by this catalog and its audit.
"""

from __future__ import annotations

from copy import deepcopy
from functools import lru_cache
from typing import Any

from .posix_issue8_manifest import POSIX_ISSUE8_INTERFACES

CATALOG_VERSION = "zscope.c-linux-catalog.v2"
CATALOG_BASELINES = {
    "posix": "POSIX.1-2024 Issue 8",
    "glibc": "2.38",
    "linux_uapi": "6.5",
    "platform": "linux-glibc-lp64",
}
CATALOG_SOURCES = {
    "posix": "https://pubs.opengroup.org/onlinepubs/9799919799/functions/contents.html",
    "glibc": "https://sourceware.org/glibc/manual/",
    "linux_man_pages": "https://www.kernel.org/doc/man-pages/",
}

# glibc exposes accept's sockaddr parameter as a pointer when transparent
# unions are disabled (including strict C). Both declarations were extracted
# with the native Clang tool; origin/header/USR checks remain mandatory.
VERIFIED_STANDARD_ABI_ALTERNATIVES: dict[str, tuple[str, ...]] = {
    "accept": ("int (int, struct sockaddr *, unsigned int *)",),
}

# Actual canonical declaration output from the rebuilt native Clang 18 tool.
VERIFIED_STANDARD_ABI: dict[str, str] = {
    "accept": "int (int, __SOCKADDR_ARG, unsigned int *)",
    "accept4": "int (int, __SOCKADDR_ARG, unsigned int *, int)",
    "aligned_alloc": "void *(unsigned long, unsigned long)",
    "atoi": "int (const char *)",
    "atol": "long (const char *)",
    "bind": "int (int, __CONST_SOCKADDR_ARG, unsigned int)",
    "calloc": "void *(unsigned long, unsigned long)",
    "clock_gettime": "int (int, struct timespec *)",
    "close": "int (int)",
    "closedir": "int (struct __dirstream *)",
    "connect": "int (int, __CONST_SOCKADDR_ARG, unsigned int)",
    "creat": "int (const char *, unsigned int)",
    "dup": "int (int)",
    "dup2": "int (int, int)",
    "dup3": "int (int, int, int)",
    "fclose": "int (struct _IO_FILE *)",
    "fdopen": "struct _IO_FILE *(int, const char *)",
    "fdopendir": "struct __dirstream *(int)",
    "fflush": "int (struct _IO_FILE *)",
    "fopen": "struct _IO_FILE *(const char *, const char *)",
    "fprintf": "int (struct _IO_FILE *, const char *, ...)",
    "fread": "unsigned long (void *, unsigned long, unsigned long, struct _IO_FILE *)",
    "free": "void (void *)",
    "freopen": "struct _IO_FILE *(const char *, const char *, struct _IO_FILE *)",
    "fseek": "int (struct _IO_FILE *, long, int)",
    "fstat": "int (int, struct stat *)",
    "ftell": "long (struct _IO_FILE *)",
    "getenv": "char *(const char *)",
    "getpeername": "int (int, __SOCKADDR_ARG, unsigned int *)",
    "getpid": "int (void)",
    "getppid": "int (void)",
    "getsockname": "int (int, __SOCKADDR_ARG, unsigned int *)",
    "getsockopt": "int (int, int, int, void *, unsigned int *)",
    "gettimeofday": "int (struct timeval *, void *)",
    "gmtime": "struct tm *(const long *)",
    "gmtime_r": "struct tm *(const long *, struct tm *)",
    "htonl": "unsigned int (unsigned int)",
    "htons": "unsigned short (unsigned short)",
    "inet_ntoa": "char *(struct in_addr)",
    "inet_ntop": "const char *(int, const void *, char *, unsigned int)",
    "inet_pton": "int (int, const char *, void *)",
    "kill": "int (int, int)",
    "listen": "int (int, int)",
    "localtime": "struct tm *(const long *)",
    "localtime_r": "struct tm *(const long *, struct tm *)",
    "lstat": "int (const char *, struct stat *)",
    "malloc": "void *(unsigned long)",
    "memcmp": "int (const void *, const void *, unsigned long)",
    "memcpy": "void *(void *, const void *, unsigned long)",
    "memmove": "void *(void *, const void *, unsigned long)",
    "memset": "void *(void *, int, unsigned long)",
    "mkdir": "int (const char *, unsigned int)",
    "mmap": "void *(void *, unsigned long, int, int, int, long)",
    "munmap": "int (void *, unsigned long)",
    "nanosleep": "int (const struct timespec *, struct timespec *)",
    "ntohl": "unsigned int (unsigned int)",
    "ntohs": "unsigned short (unsigned short)",
    "open": "int (const char *, int, ...)",
    "openat": "int (int, const char *, int, ...)",
    "opendir": "struct __dirstream *(const char *)",
    "posix_memalign": "int (void **, unsigned long, unsigned long)",
    "printf": "int (const char *, ...)",
    "pthread_attr_destroy": "int (union pthread_attr_t *)",
    "pthread_attr_init": "int (union pthread_attr_t *)",
    "pthread_attr_setdetachstate": "int (union pthread_attr_t *, int)",
    "pthread_cancel": "int (unsigned long)",
    "pthread_cond_broadcast": "int (pthread_cond_t *)",
    "pthread_cond_clockwait": "int (pthread_cond_t *, pthread_mutex_t *, int, const struct timespec *)",
    "pthread_cond_destroy": "int (pthread_cond_t *)",
    "pthread_cond_init": "int (pthread_cond_t *, const pthread_condattr_t *)",
    "pthread_cond_signal": "int (pthread_cond_t *)",
    "pthread_cond_timedwait": "int (pthread_cond_t *, pthread_mutex_t *, const struct timespec *)",
    "pthread_cond_wait": "int (pthread_cond_t *, pthread_mutex_t *)",
    "pthread_create": "int (unsigned long *, const union pthread_attr_t *, void *(*)(void *), void *)",
    "pthread_detach": "int (unsigned long)",
    "pthread_equal": "int (unsigned long, unsigned long)",
    "pthread_join": "int (unsigned long, void **)",
    "pthread_mutex_clocklock": "int (pthread_mutex_t *, int, const struct timespec *)",
    "pthread_mutex_consistent": "int (pthread_mutex_t *)",
    "pthread_mutex_destroy": "int (pthread_mutex_t *)",
    "pthread_mutex_init": "int (pthread_mutex_t *, const pthread_mutexattr_t *)",
    "pthread_mutex_lock": "int (pthread_mutex_t *)",
    "pthread_mutex_timedlock": "int (pthread_mutex_t *, const struct timespec *)",
    "pthread_mutex_trylock": "int (pthread_mutex_t *)",
    "pthread_mutex_unlock": "int (pthread_mutex_t *)",
    "pthread_mutexattr_destroy": "int (pthread_mutexattr_t *)",
    "pthread_mutexattr_init": "int (pthread_mutexattr_t *)",
    "pthread_mutexattr_setrobust": "int (pthread_mutexattr_t *, int)",
    "pthread_mutexattr_settype": "int (pthread_mutexattr_t *, int)",
    "pthread_once": "int (int *, void (*)(void))",
    "pthread_rwlock_destroy": "int (pthread_rwlock_t *)",
    "pthread_rwlock_init": "int (pthread_rwlock_t *, const pthread_rwlockattr_t *)",
    "pthread_rwlock_rdlock": "int (pthread_rwlock_t *)",
    "pthread_rwlock_timedrdlock": "int (pthread_rwlock_t *, const struct timespec *)",
    "pthread_rwlock_timedwrlock": "int (pthread_rwlock_t *, const struct timespec *)",
    "pthread_rwlock_tryrdlock": "int (pthread_rwlock_t *)",
    "pthread_rwlock_trywrlock": "int (pthread_rwlock_t *)",
    "pthread_rwlock_unlock": "int (pthread_rwlock_t *)",
    "pthread_rwlock_wrlock": "int (pthread_rwlock_t *)",
    "pthread_self": "unsigned long (void)",
    "pthread_spin_destroy": "int (volatile int *)",
    "pthread_spin_init": "int (volatile int *, int)",
    "pthread_spin_lock": "int (volatile int *)",
    "pthread_spin_trylock": "int (volatile int *)",
    "pthread_spin_unlock": "int (volatile int *)",
    "pthread_testcancel": "void (void)",
    "raise": "int (int)",
    "read": "long (int, void *, unsigned long)",
    "realloc": "void *(void *, unsigned long)",
    "reallocarray": "void *(void *, unsigned long, unsigned long)",
    "recv": "long (int, void *, unsigned long, int)",
    "recvfrom": "long (int, void *, unsigned long, int, __SOCKADDR_ARG, unsigned int *)",
    "rewind": "void (struct _IO_FILE *)",
    "sched_yield": "int (void)",
    "send": "long (int, const void *, unsigned long, int)",
    "sendmsg": "long (int, const struct msghdr *, int)",
    "sendto": "long (int, const void *, unsigned long, int, __CONST_SOCKADDR_ARG, unsigned int)",
    "setsockopt": "int (int, int, int, const void *, unsigned int)",
    "shm_open": "int (const char *, int, unsigned int)",
    "shm_unlink": "int (const char *)",
    "shutdown": "int (int, int)",
    "sigaction": "int (int, const struct sigaction *, struct sigaction *)",
    "signal": "void (*(int, void (*)(int)))(int)",
    "sleep": "unsigned int (unsigned int)",
    "snprintf": "int (char *, unsigned long, const char *, ...)",
    "socket": "int (int, int, int)",
    "sprintf": "int (char *, const char *, ...)",
    "stat": "int (const char *, struct stat *)",
    "strcat": "char *(char *, const char *)",
    "strchr": "char *(const char *, int)",
    "strcmp": "int (const char *, const char *)",
    "strcpy": "char *(char *, const char *)",
    "strdup": "char *(const char *)",
    "strerror": "char *(int)",
    "strftime": "unsigned long (char *, unsigned long, const char *, const struct tm *)",
    "strlen": "unsigned long (const char *)",
    "strncat": "char *(char *, const char *, unsigned long)",
    "strncmp": "int (const char *, const char *, unsigned long)",
    "strncpy": "char *(char *, const char *, unsigned long)",
    "strndup": "char *(const char *, unsigned long)",
    "strnlen": "unsigned long (const char *, unsigned long)",
    "strrchr": "char *(const char *, int)",
    "strstr": "char *(const char *, const char *)",
    "strtol": "long (const char *, char **, int)",
    "strtoll": "long long (const char *, char **, int)",
    "strtoul": "unsigned long (const char *, char **, int)",
    "strtoull": "unsigned long long (const char *, char **, int)",
    "syslog": "void (int, const char *, ...)",
    "time": "long (long *)",
    "uname": "int (struct utsname *)",
    "usleep": "int (unsigned int)",
    "vfprintf": "int (struct _IO_FILE *, const char *, struct __va_list_tag *)",
    "vprintf": "int (const char *, struct __va_list_tag *)",
    "vsnprintf": "int (char *, unsigned long, const char *, struct __va_list_tag *)",
    "vsprintf": "int (char *, const char *, struct __va_list_tag *)",
    "write": "long (int, const void *, unsigned long)",
    "asprintf": "int (char **, const char *, ...)",
    "cnd_broadcast": "int (cnd_t *)",
    "cnd_destroy": "void (cnd_t *)",
    "cnd_init": "int (cnd_t *)",
    "cnd_signal": "int (cnd_t *)",
    "cnd_timedwait": "int (cnd_t *, mtx_t *, const struct timespec *)",
    "cnd_wait": "int (cnd_t *, mtx_t *)",
    "dlclose": "int (void *)",
    "dlmopen": "void *(long, const char *, int)",
    "dlopen": "void *(const char *, int)",
    "dlsym": "void *(void *, const char *)",
    "dprintf": "int (int, const char *, ...)",
    "epoll_create": "int (int)",
    "epoll_create1": "int (int)",
    "eventfd": "int (unsigned int, int)",
    "execl": "int (const char *, const char *, ...)",
    "execle": "int (const char *, const char *, ...)",
    "execlp": "int (const char *, const char *, ...)",
    "execv": "int (const char *, char *const *)",
    "execve": "int (const char *, char *const *, char *const *)",
    "execvp": "int (const char *, char *const *)",
    "execvpe": "int (const char *, char *const *, char *const *)",
    "fexecve": "int (int, char *const *, char *const *)",
    "getdelim": "long (char **, unsigned long *, int, struct _IO_FILE *)",
    "getline": "long (char **, unsigned long *, struct _IO_FILE *)",
    "glob": "int (const char *, int, int (*)(const char *, int), glob_t *)",
    "globfree": "void (glob_t *)",
    "iconv_close": "int (void *)",
    "iconv_open": "void *(const char *, const char *)",
    "inotify_init": "int (void)",
    "inotify_init1": "int (int)",
    "mq_close": "int (int)",
    "mq_open": "int (const char *, int, ...)",
    "mq_receive": "long (int, char *, unsigned long, unsigned int *)",
    "mq_send": "int (int, const char *, unsigned long, unsigned int)",
    "mq_timedreceive": "long (int, char *, unsigned long, unsigned int *, const struct timespec *)",
    "mq_timedsend": "int (int, const char *, unsigned long, unsigned int, const struct timespec *)",
    "mq_unlink": "int (const char *)",
    "mtx_destroy": "void (mtx_t *)",
    "mtx_init": "int (mtx_t *, int)",
    "mtx_lock": "int (mtx_t *)",
    "mtx_timedlock": "int (mtx_t *, const struct timespec *)",
    "mtx_trylock": "int (mtx_t *)",
    "mtx_unlock": "int (mtx_t *)",
    "pclose": "int (struct _IO_FILE *)",
    "popen": "struct _IO_FILE *(const char *, const char *)",
    "posix_spawn": "int (int *, const char *, const posix_spawn_file_actions_t *, const posix_spawnattr_t *, char *const *, char *const *)",
    "posix_spawnp": "int (int *, const char *, const posix_spawn_file_actions_t *, const posix_spawnattr_t *, char *const *, char *const *)",
    "preadv": "long (int, const struct iovec *, int, long)",
    "preadv2": "long (int, const struct iovec *, int, long, int)",
    "pthread_barrier_destroy": "int (pthread_barrier_t *)",
    "pthread_barrier_init": "int (pthread_barrier_t *, const pthread_barrierattr_t *, unsigned int)",
    "pthread_barrier_wait": "int (pthread_barrier_t *)",
    "pwritev": "long (int, const struct iovec *, int, long)",
    "pwritev2": "long (int, const struct iovec *, int, long, int)",
    "readv": "long (int, const struct iovec *, int)",
    "recvmsg": "long (int, struct msghdr *, int)",
    "regcomp": "int (struct re_pattern_buffer *, const char *, int)",
    "regfree": "void (struct re_pattern_buffer *)",
    "sem_clockwait": "int (sem_t *, int, const struct timespec *)",
    "sem_destroy": "int (sem_t *)",
    "sem_getvalue": "int (sem_t *, int *)",
    "sem_init": "int (sem_t *, int, unsigned int)",
    "sem_post": "int (sem_t *)",
    "sem_timedwait": "int (sem_t *, const struct timespec *)",
    "sem_trywait": "int (sem_t *)",
    "sem_wait": "int (sem_t *)",
    "shmat": "void *(int, const void *, int)",
    "shmctl": "int (int, int, struct shmid_ds *)",
    "shmdt": "int (const void *)",
    "shmget": "int (int, unsigned long, int)",
    "signalfd": "int (int, const __sigset_t *, int)",
    "system": "int (const char *)",
    "thrd_create": "int (unsigned long *, int (*)(void *), void *)",
    "thrd_detach": "int (unsigned long)",
    "thrd_join": "int (unsigned long, int *)",
    "timerfd_create": "int (int, int)",
    "vasprintf": "int (char **, const char *, struct __va_list_tag *)",
    "vdprintf": "int (int, const char *, struct __va_list_tag *)",
    "writev": "long (int, const struct iovec *, int)",
}

# Forms whose identity cannot be safely bound to one declaration/effect.
UNSUPPORTED_INTERFACES = {
    "syscall": "runtime syscall number and variadic ABI prevent safe static binding",
    "eventfd2": "kernel syscall spelling is not a glibc public function declaration",
    "pipe": "two independently-owned output descriptors require a multi-object effect adapter",
    "pipe2": "two independently-owned output descriptors require a multi-object effect adapter",
    "socketpair": "two independently-owned output descriptors require a multi-object effect adapter",
}

# Audited declarations that have no effect in the security domains currently
# modeled by Z-SCOPE.  They remain classified so an observed system call can
# be distinguished from a catalog omission.  This is intentionally an
# explicit allow-list, never a name/header fallback.
NEUTRAL_INTERFACES = frozenset(
    {
        "abs",
        "atoi",
        "atol",
        "atoll",
        "bcmp",
        "clock",
        "difftime",
        "endpwent",
        "endgrent",
        "feof",
        "ferror",
        "fileno",
        "getegid",
        "geteuid",
        "getgid",
        "getgrgid",
        "getgrnam",
        "getpid",
        "getppid",
        "getpwnam",
        "getpwuid",
        "getuid",
        "gmtime",
        "gmtime_r",
        "htonl",
        "htons",
        "inet_ntop",
        "inet_pton",
        "isalnum",
        "isalpha",
        "isascii",
        "isblank",
        "iscntrl",
        "isdigit",
        "isgraph",
        "islower",
        "isprint",
        "ispunct",
        "isspace",
        "isupper",
        "isxdigit",
        "labs",
        "localtime",
        "localtime_r",
        "llabs",
        "memchr",
        "memcmp",
        "ntohl",
        "ntohs",
        "pthread_equal",
        "pthread_self",
        "setgrent",
        "setpwent",
        "strcasecmp",
        "strcasestr",
        "strchr",
        "strcmp",
        "strcoll",
        "strcspn",
        "strerror",
        "strlen",
        "strncasecmp",
        "strncmp",
        "strnlen",
        "strpbrk",
        "strrchr",
        "strspn",
        "strstr",
        "strtod",
        "strtof",
        "strtok_r",
        "strtol",
        "strtold",
        "strtoll",
        "strtoul",
        "strtoull",
        "strxfrm",
        "time",
        "tolower",
        "toupper",
    }
)

_LINUX_MANPAGE_APIS = frozenset(
    {
        "accept4",
        "epoll_create",
        "epoll_create1",
        "eventfd",
        "inotify_init",
        "inotify_init1",
        "preadv2",
        "pwritev2",
        "signalfd",
        "timerfd_create",
    }
)
_GLIBC_EXTENSION_APIS = frozenset(
    {
        "asprintf",
        "dlmopen",
        "execvpe",
        "getdelim",
        "getline",
        "reallocarray",
        "sem_clockwait",
        "vasprintf",
    }
)


def catalog_sources_for(name: str) -> list[str]:
    if name in _LINUX_MANPAGE_APIS:
        return [CATALOG_SOURCES["linux_man_pages"]]
    if name in _GLIBC_EXTENSION_APIS:
        return [CATALOG_SOURCES["glibc"]]
    return [CATALOG_SOURCES["posix"]]


@lru_cache(maxsize=1)
def active_contracts() -> tuple[dict[str, Any], ...]:
    from .standard_api import standard_contracts

    rows = standard_contracts()
    names = {str(row.get("symbol", {}).get("name") or "") for row in rows}
    missing = sorted(names - set(VERIFIED_STANDARD_ABI))
    orphaned = sorted(set(VERIFIED_STANDARD_ABI) - names)
    if missing or orphaned:
        raise ValueError(
            "C/Linux catalog is inconsistent: "
            f"active_missing_abi={missing}; abi_without_active_contract={orphaned}"
        )
    return tuple(deepcopy(rows))


def catalog_audit() -> dict[str, Any]:
    rows = active_contracts()
    active_by_name: dict[str, dict[str, Any]] = {}
    for row in rows:
        name = str(row["symbol"]["name"])
        record = active_by_name.setdefault(
            name,
            {
                "name": name,
                "classification": "active",
                "abi": VERIFIED_STANDARD_ABI[name],
                "sources": deepcopy(row.get("evidence") or []),
                "consumers": [],
            },
        )
        record["sources"] = catalog_sources_for(name)
        role = str(row.get("role") or "")
        if role and role not in record["consumers"]:
            record["consumers"].append(role)
    records = [active_by_name[name] for name in sorted(active_by_name)]
    records.extend(
        {
            "name": name,
            "classification": "neutral",
            "reason": "audited; no effect in the current Z-SCOPE security domains",
            "sources": catalog_sources_for(name),
            "consumers": [],
        }
        for name in sorted(NEUTRAL_INTERFACES - set(active_by_name))
    )
    records.extend(
        {
            "name": name,
            "classification": "unsupported",
            "reason": reason,
            "sources": [CATALOG_SOURCES["linux_man_pages"]],
            "consumers": [],
        }
        for name, reason in sorted(UNSUPPORTED_INTERFACES.items())
    )
    classified = set(active_by_name) | set(NEUTRAL_INTERFACES) | set(UNSUPPORTED_INTERFACES)
    unaudited = sorted(POSIX_ISSUE8_INTERFACES - classified)
    return {
        "schema": "zscope.c-linux-catalog-audit.v1",
        "catalog_version": CATALOG_VERSION,
        "baselines": dict(CATALOG_BASELINES),
        "records": records,
        "baseline_interfaces": len(POSIX_ISSUE8_INTERFACES),
        "classified_interfaces": len(POSIX_ISSUE8_INTERFACES & classified),
        "active": len(active_by_name),
        "neutral": len(NEUTRAL_INTERFACES - set(active_by_name)),
        "unsupported": len(UNSUPPORTED_INTERFACES),
        "active_missing_abi": [],
        "active_missing_source": [
            row["name"]
            for row in records
            if row["classification"] == "active" and not row["sources"]
        ],
        "active_missing_consumer": [
            row["name"]
            for row in records
            if row["classification"] == "active" and not row["consumers"]
        ],
        # Never turn an absent model into an optimistic neutral entry.  The
        # full official baseline is pinned, so completeness is measurable and
        # formal qualification remains blocked until every name is reviewed.
        "unaudited": unaudited,
    }


def classified_names() -> frozenset[str]:
    """Every declaration spelling explicitly classified by this catalog."""

    return frozenset(VERIFIED_STANDARD_ABI) | NEUTRAL_INTERFACES | frozenset(UNSUPPORTED_INTERFACES)


def classification_for(name: str) -> str:
    if name in VERIFIED_STANDARD_ABI:
        return "active"
    if name in NEUTRAL_INTERFACES:
        return "neutral"
    if name in UNSUPPORTED_INTERFACES:
        return "unsupported"
    return ""
