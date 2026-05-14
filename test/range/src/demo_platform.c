#include "../include/platform_impl.h"
#include "../include/common.h"
#include <stdio.h>
#include <stdlib.h>

int main(void) {
    printf("=== Platform Polymorphism Demo ===\n\n");
    
    if (platform_init() != 0) {
        fprintf(stderr, "Failed to initialize platform\n");
        return 1;
    }
    
    char platform_info[256];
    if (platform_get_info(platform_info, sizeof(platform_info)) == 0) {
        printf("Platform Info: %s\n\n", platform_info);
    }
    
    printf("Executing platform-specific tasks:\n");
    printf("----------------------------------\n");
    
    platform_execute_task("echo 'Hello from platform polymorphism'");
    
    printf("\n----------------------------------\n");
    
#ifdef PLATFORM_LINUX
    printf("Compiled with PLATFORM_LINUX macro\n");
#elif defined(PLATFORM_WINDOWS)
    printf("Compiled with PLATFORM_WINDOWS macro\n");
#else
    printf("No platform macro defined\n");
#endif
    
    platform_cleanup();
    
    return 0;
}
