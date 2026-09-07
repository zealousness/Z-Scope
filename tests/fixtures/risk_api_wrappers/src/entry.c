/* Entry functions exercising the custom wrappers. Each function embeds one
 * expected defect so tests can assert candidate generation end to end. */
#include "../include/wrap_api.h"

/* EXPECTED: memory_leak  (get_buffer is a user allocator; ptr never released) */
int leak_via_get_buffer(size_t n) {
    char* ptr = (char*)get_buffer(n);
    if (n > 100) {
        return -1; /* ptr leaked on early return */
    }
    ptr[0] = 0;
    put_buffer(ptr);
    return 0;
}

/* EXPECTED: missing_unlock (mutex_exit missing on error path) */
int unlock_missing_on_error(unsigned* lock) {
    mutex_enter(lock);
    if (load_config() != 0) {
        return -1; /* lock held on error return */
    }
    mutex_exit(lock);
    return 0;
}

/* EXPECTED: held_lock_callback (cb_register callback invoked while lock held) */
int callback_under_lock(unsigned* lock, int (*fn)(void*)) {
    mutex_enter(lock);
    cb_register(fn, NULL);
    mutex_exit(lock);
    return 0;
}

/* EXPECTED: fd_leak (file_open_wrap without file_close_wrap on error path) */
int fd_leak_on_error(const char* path) {
    int fd = file_open_wrap(path, 0);
    if (fd < 0) {
        return -1;
    }
    if (validate_path(path) != 0) {
        return -1; /* fd leaked */
    }
    file_close_wrap(fd);
    return 0;
}

/* EXPECTED: signed_unsigned (net_recv_wrap signed result cast to size_t) */
int recv_len_confusion(int fd) {
    int received = net_recv_wrap(fd, g_frame, sizeof(g_frame));
    size_t copy_len = (size_t)received;
    memcpy(g_out, g_frame, copy_len);
    return 0;
}

/* EXPECTED: format_string style candidate (audit_log is a format sink fed by
 * a non-literal first argument). */
int log_user_format(const char* user_fmt) {
    audit_log(user_fmt, 42);
    return 0;
}
