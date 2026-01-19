#ifndef UTILS_H
#define UTILS_H

#include <stdlib.h>

// String utilities
char* safe_strdup(const char* str);
int safe_strlen(const char* str);

// Memory utilities
void* safe_malloc(size_t size);
void* safe_calloc(size_t nmemb, size_t size);
void safe_free(void** ptr);

// Math utilities
int max_int(int a, int b);
int min_int(int a, int b);

#endif // UTILS_H
