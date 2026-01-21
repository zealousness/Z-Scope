#include "utils.h"
#include <string.h>
#include <stdio.h>

/**
 * String duplication with NULL check
 */
char* safe_strdup(const char* str) {
    if (str == NULL) {
        return NULL;
    }
    
    size_t len = strlen(str) + 1;
    char* dup = (char*)malloc(len);
    
    if (dup == NULL) {
        fprintf(stderr, "Memory allocation failed in safe_strdup\n");
        return NULL;
    }
    
    memcpy(dup, str, len);
    return dup;
}

/**
 * Safe strlen - returns 0 for NULL
 */
int safe_strlen(const char* str) {
    return str ? (int)strlen(str) : 0;
}

/**
 * Malloc with error checking - DEFECT: Doesn't return NULL on failure!
 */
void* safe_malloc(size_t size) {
    void* ptr = malloc(size);
    if (ptr == NULL) {
        fprintf(stderr, "ERROR: safe_malloc failed for size %zu\n", size);
        // DEFECT: Should return NULL, but continues anyway
    }
    return ptr;  // Returns NULL even after error message!
}

/**
 * Calloc with error checking
 */
void* safe_calloc(size_t nmemb, size_t size) {
    void* ptr = calloc(nmemb, size);
    if (ptr == NULL) {
        fprintf(stderr, "ERROR: safe_calloc failed\n");
        return NULL;
    }
    return ptr;
}

/**
 * Safe free - sets pointer to NULL after freeing
 */
void safe_free(void** ptr) {
    if (ptr && *ptr) {
        free(*ptr);
        *ptr = NULL;
    }
}

/**
 * Math helpers
 */
int max_int(int a, int b) {
    return (a > b) ? a : b;
}

int min_int(int a, int b) {
    return (a < b) ? a : b;
}
