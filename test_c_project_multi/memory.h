#ifndef MEMORY_H
#define MEMORY_H

#include <stdlib.h>

// Memory pool for reusable allocations
typedef struct {
    void** blocks;
    size_t* sizes;
    int count;
    int capacity;
} MemoryPool;

MemoryPool* create_memory_pool(int initial_capacity);
void* pool_alloc(MemoryPool* pool, size_t size);
void free_memory_pool(MemoryPool* pool);

// Buffer management
char* create_buffer(size_t size);
void resize_buffer(char** buffer, size_t new_size);

#endif // MEMORY_H
