#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "handler.h"

/* 两个具体的 handler 实现 —— 用于测试函数指针解析 */
static int echo_handler(const char *data, int len) {
    char *buf = (char *)malloc(len + 1);
    if (!buf) return -1;
    memcpy(buf, data, len);
    buf[len] = '\0';
    printf("echo: %s\n", buf);
    free(buf);
    return 0;
}

static int leak_handler(const char *data, int len) {
    /* 故意泄漏：malloc 后未 free —— SVF 应能检出 */
    char *buf = (char *)malloc(len + 1);
    if (!buf) return -1;
    memcpy(buf, data, len);
    buf[len] = '\0';
    printf("leak: %s\n", buf);
    return 0;  /* missing free(buf) */
}

int main(void) {
    Handler *h1 = handler_create("echo", echo_handler);
    Handler *h2 = handler_create("leak", leak_handler);

    dispatch(h1, "hello", 5);
    dispatch(h2, "world", 5);

    handler_free(h1);
    handler_free(h2);
    /* h2 内部 leak_handler 分配的 buf 已泄漏 */
    return 0;
}
