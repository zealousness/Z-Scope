#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

// Global lock for demo
pthread_mutex_t global_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t logging_mutex = PTHREAD_MUTEX_INITIALIZER;

/**
 * 模拟一个带有缓冲区溢出风险的函数
 */
void process_packet(const char *input) {
    char buffer[64];
    // CRITICAL: 典型的缓冲区溢出漏洞，未检查输入长度
    strcpy(buffer, input);
    printf("Processed: %s\n", buffer);
}

/**
 * 模拟一个复杂的加锁逻辑，可能导致死锁 (AB-BA)
 */
void log_event(const char *msg) {
    pthread_mutex_lock(&logging_mutex);
    pthread_mutex_lock(&global_mutex);
    printf("LOG: %s\n", msg);
    pthread_mutex_unlock(&global_mutex);
    pthread_mutex_unlock(&logging_mutex);
}

void update_system_state() {
    pthread_mutex_lock(&global_mutex);
    // 这里如果调用 log_event 就会导致死锁
    log_event("Updating state...");
    pthread_mutex_unlock(&global_mutex);
}

int main(int argc, char **argv) {
    if (argc < 2) {
        return 1;
    }
    
    // 情景 1: 内存安全测试
    process_packet(argv[1]);
    
    // 情景 2: 并发死锁测试
    update_system_state();
    
    return 0;
}
