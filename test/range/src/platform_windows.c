#include "../include/platform_impl.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>

static char g_os_info[MAX_PATH] = {0};

int platform_init(void) {
    OSVERSIONINFOEX osvi;
    ZeroMemory(&osvi, sizeof(OSVERSIONINFOEX));
    osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEX);
    
    if (GetVersionEx((OSVERSIONINFO*)&osvi)) {
        snprintf(g_os_info, sizeof(g_os_info), 
                 "Windows Platform - Version %d.%d Build %d",
                 osvi.dwMajorVersion, osvi.dwMinorVersion, osvi.dwBuildNumber);
    } else {
        snprintf(g_os_info, sizeof(g_os_info), "Windows Platform - Unknown Version");
    }
    
    return 0;
}

void platform_cleanup(void) {
}

int platform_get_info(char* buffer, size_t size) {
    if (!buffer || size == 0) {
        return -1;
    }
    
    strncpy(buffer, g_os_info, size - 1);
    buffer[size - 1] = '\0';
    return 0;
}

int platform_execute_task(const char* task) {
    if (!task) {
        return -1;
    }
    
    printf("[WINDOWS] Executing task: %s\n", task);
    
    STARTUPINFO si;
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));
    
    char cmd[MAX_PATH * 2];
    strncpy(cmd, task, sizeof(cmd) - 1);
    cmd[sizeof(cmd) - 1] = '\0';
    
    BOOL success = CreateProcess(NULL, cmd, NULL, NULL, FALSE, 
                                0, NULL, NULL, &si, &pi);
    
    if (!success) {
        printf("[WINDOWS] Task execution failed, error code: %lu\n", GetLastError());
        return -1;
    }
    
    WaitForSingleObject(pi.hProcess, INFINITE);
    
    DWORD exit_code;
    GetExitCodeProcess(pi.hProcess, &exit_code);
    
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    
    printf("[WINDOWS] Task completed with exit code: %lu\n", exit_code);
    return (int)exit_code;
}
