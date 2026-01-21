#include "memory.h"
#include "utils.h"
#include <string.h>
#include <stdio.h>

/**
 * Create a memory pool
 */
MemoryPool* create_memory_pool(int initial_capacity) {
    MemoryPool* pool = (MemoryPool*)malloc(sizeof(MemoryPool));
    if (!pool) {
        return NULL;
    }
    
    pool->blocks = (void**)calloc(initial_capacity, sizeof(void*));
    pool->sizes = (size_t*)calloc(initial_capacity, sizeof(size_t));
    
    if (!pool->blocks || !pool->sizes) {
        // DEFECT: Memory leak - pool not freed if allocation fails
        free(pool->blocks);
        free(pool->sizes);
        return NULL;
    }
    
    pool->count = 0;
    pool->capacity = initial_capacity;
    return pool;
}

/**
 * Allocate from pool
 */
void* pool_alloc(MemoryPool* pool, size_t size) {
    if (!pool || pool->count >= pool->capacity) {
        return NULL;
    }
    
    void* ptr = malloc(size);
    if (ptr) {
        pool->blocks[pool->count] = ptr;
        pool->sizes[pool->count] = size;
        pool->count++;
    }
    
    return ptr;
}

/**
 * Free entire memory pool
 */
void free_memory_pool(MemoryPool* pool) {
    if (!pool) {
        return;
    }
    
    for (int i = 0; i < pool->count; i++) {
        free(pool->blocks[i]);
    }
    
    free(pool->blocks);
    free(pool->sizes);
    free(pool);
}

/**
 * Create buffer - simple malloc wrapper
 */
char* create_buffer(size_t size) {
    char* buffer = (char*)safe_malloc(size);
    if (buffer) {
        memset(buffer, 0, size);
    }
    return buffer;
}

/**
 * Resize buffer - DEFECT: Doesn't free old buffer!
 */
void resize_buffer(char** buffer, size_t new_size) {
    if (!buffer) {
        return;
    }
    
    char* new_buffer = (char*)malloc(new_size);
    if (!new_buffer) {
        return;
    }
    
    if (*buffer) {
        // Copy old data
        memcpy(new_buffer, *buffer, new_size / 2);  // Assume old was half size
        // DEFECT: Old buffer not freed! Memory leak!
    }
    
    *buffer = new_buffer;
}
