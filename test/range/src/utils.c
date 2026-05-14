#include "../include/common.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdarg.h>
#include <errno.h>
#include <sys/stat.h>
#include <unistd.h>

int g_log_level = LOG_LEVEL_INFO;

void* _safe_malloc(size_t size) {
    void* ptr = malloc(size);
    if (!ptr && size > 0) {
        LOG_ERROR("Memory allocation failed: %zu bytes", size);
        return NULL;
    }
    return ptr;
}

void* _safe_calloc(size_t nmemb, size_t size) {
    void* ptr = calloc(nmemb, size);
    if (!ptr && nmemb > 0 && size > 0) {
        LOG_ERROR("Memory allocation failed: %zu * %zu bytes", nmemb, size);
        return NULL;
    }
    return ptr;
}

void* _safe_realloc(void* ptr, size_t size) {
    void* new_ptr = realloc(ptr, size);
    if (!new_ptr && size > 0) {
        LOG_ERROR("Memory reallocation failed: %zu bytes", size);
        return NULL;
    }
    return new_ptr;
}

char* _str_dup(const char* s) {
    if (!s) return NULL;
    size_t len = strlen(s) + 1;
    char* dup = (char*)_safe_malloc(len);
    if (dup) {
        memcpy(dup, s, len);
    }
    return dup;
}

int _str_copy_wrapper(char* dst, const char* src, size_t dst_size) {
    if (!dst || dst_size == 0) return -1;
    if (!src) {
        dst[0] = '\0';
        return 0;
    }
    size_t len = strlen(src);
    size_t copy_len = MIN(len, dst_size - 1);
    memcpy(dst, src, copy_len);
    dst[copy_len] = '\0';
    return 0;
}

void _log_wrapper(int level, const char* file, int line, const char* fmt, ...) {
    if (level < g_log_level) return;
    
    const char* level_str = "DEBUG";
    switch (level) {
        case LOG_LEVEL_INFO:  level_str = "INFO"; break;
        case LOG_LEVEL_WARN:  level_str = "WARN"; break;
        case LOG_LEVEL_ERROR: level_str = "ERROR"; break;
    }
    
    const char* filename = strrchr(file, '/');
    if (!filename) filename = strrchr(file, '\\');
    if (filename) filename++;
    else filename = file;
    
    fprintf(stderr, "[%s] %s:%d: ", level_str, filename, line);
    
    va_list args;
    va_start(args, fmt);
    vfprintf(stderr, fmt, args);
    va_end(args);
    
    fprintf(stderr, "\n");
}

void _lock_wrapper(pthread_mutex_t* mutex, const char* file, int line) {
    if (!mutex) {
        LOG_ERROR("NULL mutex at %s:%d", file, line);
        return;
    }
    int ret = pthread_mutex_lock(mutex);
    if (ret != 0) {
        LOG_ERROR("Mutex lock failed at %s:%d: %d", file, line, ret);
    }
}

void _unlock_wrapper(pthread_mutex_t* mutex, const char* file, int line) {
    if (!mutex) {
        LOG_ERROR("NULL mutex at %s:%d", file, line);
        return;
    }
    int ret = pthread_mutex_unlock(mutex);
    if (ret != 0) {
        LOG_ERROR("Mutex unlock failed at %s:%d: %d", file, line, ret);
    }
}

void _lock_read_wrapper(pthread_rwlock_t* rwlock, const char* file, int line) {
    if (!rwlock) {
        LOG_ERROR("NULL rwlock at %s:%d", file, line);
        return;
    }
    int ret = pthread_rwlock_rdlock(rwlock);
    if (ret != 0) {
        LOG_ERROR("Read lock failed at %s:%d: %d", file, line, ret);
    }
}

void _lock_write_wrapper(pthread_rwlock_t* rwlock, const char* file, int line) {
    if (!rwlock) {
        LOG_ERROR("NULL rwlock at %s:%d", file, line);
        return;
    }
    int ret = pthread_rwlock_wrlock(rwlock);
    if (ret != 0) {
        LOG_ERROR("Write lock failed at %s:%d: %d", file, line, ret);
    }
}

uint32_t _hash_string(const char* str) {
    if (!str) return 0;
    uint32_t hash = 5381;
    int c;
    while ((c = *str++)) {
        hash = ((hash << 5) + hash) + c;
    }
    return hash;
}

uint64_t _get_timestamp_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

int _create_directory(const char* path) {
    if (!path) return -1;
#ifdef PLATFORM_WINDOWS
    return mkdir(path);
#else
    return mkdir(path, 0755);
#endif
}

int _file_exists(const char* path) {
    if (!path) return 0;
    struct stat st;
    return (stat(path, &st) == 0);
}

int _check_file_permission(const char* path, int required_perm) {
    if (!path) return -1;
    struct stat st;
    if (stat(path, &st) != 0) {
        return -1;
    }
    int mode = st.st_mode & 0777;
    return (mode & required_perm) == required_perm ? 0 : -1;
}
