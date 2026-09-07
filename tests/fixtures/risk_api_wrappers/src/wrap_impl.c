/* Wrapper implementations. Bodies are what the body-classifier and the LLM
 * reviewer inspect; each wrapper funnels into exactly one standard risk API. */
#include "../include/wrap_api.h"
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <pthread.h>

extern int worker_subscribe(int (*fn)(void*));
extern int load_config(void);
extern int validate_path(const char* path);

static unsigned g_channel_lock;
static unsigned char g_frame[4096];
static unsigned char g_out[4096];

void* _safe_malloc(size_t size) {
    void* ptr = malloc(size);
    if (!ptr && size > 0) {
        return NULL;
    }
    return ptr;
}

void* get_buffer(size_t size) {
    return malloc(size);
}

void put_buffer(void* ptr) {
    free(ptr);
}

void mutex_enter(unsigned* lock) {
    pthread_mutex_lock((pthread_mutex_t*)lock);
}

void mutex_exit(unsigned* lock) {
    pthread_mutex_unlock((pthread_mutex_t*)lock);
}

void cb_register(int (*fn)(void*), void* arg) {
    (void)arg;
    worker_subscribe(fn); /* delegates to the project registrar */
}

int file_open_wrap(const char* path, int flags) {
    return open(path, flags);
}

void file_close_wrap(int fd) {
    close(fd);
}

int net_send_wrap(int fd, const void* buf, size_t len) {
    return (int)send(fd, buf, len, 0);
}

int net_recv_wrap(int fd, void* buf, size_t len) {
    return (int)recv(fd, buf, len, 0);
}

void audit_log(const char* fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
}
