#ifndef PLATFORM_IMPL_H
#define PLATFORM_IMPL_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

int platform_init(void);
void platform_cleanup(void);
int platform_get_info(char* buffer, size_t size);
int platform_execute_task(const char* task);

#ifdef __cplusplus
}
#endif

#endif
