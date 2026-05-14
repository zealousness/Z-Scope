#ifndef COMMON_H
#define COMMON_H

#include <stddef.h>
#include <stdint.h>
#include <pthread.h>

#define MAX_TASK_SIZE        (1024 * 1024)
#define MAX_PLUGIN_NAME      64
#define MAX_CONFIG_SIZE      (64 * 1024)
#define DEFAULT_THREAD_COUNT 4
#define DEFAULT_QUEUE_SIZE   1024
#define MAX_CLIENT_ID        128
#define MAX_COMMAND_LEN      4096
#define MAX_PATH_LEN         256

#define LOG_LEVEL_DEBUG      0
#define LOG_LEVEL_INFO       1
#define LOG_LEVEL_WARN       2
#define LOG_LEVEL_ERROR      3

extern int g_log_level;

#define SAFE_FREE(ptr)       do { if (ptr) { free(ptr); (ptr) = NULL; } } while(0)
#define ARRAY_SIZE(arr)      (sizeof(arr) / sizeof((arr)[0]))
#define OFFSET_OF(type, member) ((size_t)&(((type*)0)->member))

#define RETURN_IF_NULL(ptr)  do { if (!(ptr)) return -1; } while(0)
#define RETURN_IF_ERR(cond)  do { if ((cond) != 0) return -1; } while(0)
#define GOTO_IF_NULL(ptr, label) do { if (!(ptr)) goto label; } while(0)
#define GOTO_IF_ERR(cond, label) do { if ((cond) != 0) goto label; } while(0)

#define LOCK(mutex)           _lock_wrapper(mutex, __FILE__, __LINE__)
#define UNLOCK(mutex)         _unlock_wrapper(mutex, __FILE__, __LINE__)
#define LOCK_READ(rwlock)     _lock_read_wrapper(rwlock, __FILE__, __LINE__)
#define LOCK_WRITE(rwlock)    _lock_write_wrapper(rwlock, __FILE__, __LINE__)

#define LOG_DEBUG(fmt, ...)   _log_wrapper(LOG_LEVEL_DEBUG, __FILE__, __LINE__, fmt, ##__VA_ARGS__)
#define LOG_INFO(fmt, ...)    _log_wrapper(LOG_LEVEL_INFO, __FILE__, __LINE__, fmt, ##__VA_ARGS__)
#define LOG_WARN(fmt, ...)    _log_wrapper(LOG_LEVEL_WARN, __FILE__, __LINE__, fmt, ##__VA_ARGS__)
#define LOG_ERROR(fmt, ...)   _log_wrapper(LOG_LEVEL_ERROR, __FILE__, __LINE__, fmt, ##__VA_ARGS__)

#define MIN(x, y)            ((x) < (y) ? (x) : (y))
#define MAX(x, y)            ((x) > (y) ? (x) : (y))
#define CLAMP(x, lo, hi)     (MIN(MAX((x), (lo)), (hi)))

#define STR_COPY(dst, src)   _str_copy_wrapper(dst, src, sizeof(dst))
#define STR_LEN(s)           ((s) ? strlen(s) : 0)
#define STR_EQ(a, b)         ((a) && (b) && (strcmp((a), (b)) == 0))
#define STR_EMPTY(s)         (!(s) || *(s) == '\0')

#define IS_ALIGNED(ptr, n)   (((uintptr_t)(ptr) & ((n) - 1)) == 0)
#define ALIGN_UP(ptr, n)     (((uintptr_t)(ptr) + (n) - 1) & ~((n) - 1))

#define LIKELY(x)           __builtin_expect(!!(x), 1)
#define UNLIKELY(x)         __builtin_expect(!!(x), 0)

#ifdef __cplusplus
extern "C" {
#endif

void* _safe_malloc(size_t size);
void* _safe_calloc(size_t nmemb, size_t size);
void* _safe_realloc(void* ptr, size_t size);
char* _str_dup(const char* s);
int _str_copy_wrapper(char* dst, const char* src, size_t dst_size);
void _log_wrapper(int level, const char* file, int line, const char* fmt, ...);
void _lock_wrapper(pthread_mutex_t* mutex, const char* file, int line);
void _unlock_wrapper(pthread_mutex_t* mutex, const char* file, int line);
void _lock_read_wrapper(pthread_rwlock_t* rwlock, const char* file, int line);
void _lock_write_wrapper(pthread_rwlock_t* rwlock, const char* file, int line);
uint32_t _hash_string(const char* str);
uint64_t _get_timestamp_ms(void);
int _create_directory(const char* path);
int _file_exists(const char* path);
int _check_file_permission(const char* path, int required_perm);

#ifdef __cplusplus
}
#endif

#endif
