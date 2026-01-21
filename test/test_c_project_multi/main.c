#include <stdio.h>
#include<stdlib.h>
#include "utils.h"
#include "memory.h"
#include "processor.h"

/**
 * Main entry point - tests all modules
 */
int main(int argc, char** argv) {
    printf("==================================\n");
    printf("Multi-module C Test Project\n");
    printf("==================================\n\n");

    // Test 1: Utils module
    printf("[Test 1] Testing utils...\n");
    char* str = safe_strdup("Hello, World!");
    if (str) {
        printf("  Duplicated: %s\n", str);
        printf("  Length: %d\n", safe_strlen(str));
        free(str);
    }

    // Test 2: Memory pool
    printf("\n[Test 2] Testing memory pool...\n");
    MemoryPool* pool = create_memory_pool(10);
    if (pool) {
        void* ptr1 = pool_alloc(pool, 100);
        void* ptr2 = pool_alloc(pool, 200);
        printf("  Allocated 2 blocks from pool\n");
        free_memory_pool(pool);
        printf("  Pool freed\n");
    }

    // Test 3: Single packet processing
    printf("\n[Test 3] Testing single packet...\n");
    DataPacket* packet = create_packet("testing", 7);
    if (packet) {
        process_packet(packet);
        free_packet(packet);
    }

    // Test 4: Batch processing
    printf("\n[Test 4] Testing batch processing...\n");
    char* batch_inputs[] = {
        "first",
        "second",
        "third"
    };
    int result = process_batch(batch_inputs, 3);
    printf("  Batch result: %d\n", result);

    // Test 5: Buffer operations
    printf("\n[Test 5] Testing buffer operations...\n");
    char* buffer = create_buffer(64);
    if (buffer) {
        printf("  Created buffer of 64 bytes\n");
        resize_buffer(&buffer, 128);
        printf("  Resized to 128 bytes\n");
        free(buffer);
    }

    // Test 6: Large input (triggers buffer overflow)
    printf("\n[Test 6] Testing with large input...\n");
    char large_input[256];
    for (int i = 0; i < 255; i++) {
        large_input[i] = 'A' + (i % 26);
    }
    large_input[255] = '\0';
    
    DataPacket* large_packet = create_packet(large_input, 100);  // Size mismatch!
    if (large_packet) {
        process_packet(large_packet);
        free_packet(large_packet);
    }

    printf("\n==================================\n");
    printf("Tests completed\n");
    printf("==================================\n");

    return 0;
}
