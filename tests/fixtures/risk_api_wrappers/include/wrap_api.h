/* Custom risk-interface wrappers used by the risk_api_wrappers fixture.
 *
 * Every wrapper hides a standard risk API behind a project-specific name.
 * `channel_up`/`channel_down` and `get_buffer`/`put_buffer` intentionally
 * carry NO allocation/lock/open keyword so only the user-config / LLM
 * path can classify them.
 */
#ifndef WRAP_API_H
#define WRAP_API_H

#include <stddef.h>

/* memory */
void* _safe_malloc(size_t size);
void* get_buffer(size_t size);          /* allocator, no keyword hint */
void put_buffer(void* ptr);             /* deallocator, no keyword hint */

/* concurrency */
void mutex_enter(unsigned* lock);       /* lock, no "lock" keyword */
void mutex_exit(unsigned* lock);        /* unlock, no "lock" keyword */
void cb_register(int (*fn)(void*), void* arg);  /* callback_register */

/* io */
int file_open_wrap(const char* path, int flags);   /* io_acquire */
void file_close_wrap(int fd);                      /* io_release */

/* network sinks / sources */
int net_send_wrap(int fd, const void* buf, size_t len);     /* send_sink */
int net_recv_wrap(int fd, void* buf, size_t len);           /* recv_source */
void audit_log(const char* fmt, ...);                       /* format_sink */

#endif /* WRAP_API_H */
