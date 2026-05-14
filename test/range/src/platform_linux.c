#include "../include/platform_impl.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/utsname.h>

static struct utsname g_uname;

int platform_init(void) {
    if (uname(&g_uname) != 0) {
        return -1;
    }
    return 0;
}

void platform_cleanup(void) {
}

int platform_get_info(char* buffer, size_t size) {
    if (!buffer || size == 0) {
        return -1;
    }
    
    snprintf(buffer, size, "Linux Platform - %s %s %s", 
             g_uname.sysname, g_uname.release, g_uname.machine);
    return 0;
}

int platform_execute_task(const char* task) {
    if (!task) {
        return -1;
    }
    
    printf("[LINUX] Executing task: %s\n", task);
    
    int ret = system(task);
    
    if (ret == -1) {
        printf("[LINUX] Task execution failed\n");
        return -1;
    }
    
    printf("[LINUX] Task completed with exit code: %d\n", ret);
    return ret;
}
