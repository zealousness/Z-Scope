#include "cache_internal.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>

#define MAGIC_NUMBER 0x43414348  // "CACH"

typedef struct {
    uint32_t magic;
    uint32_t version;
    uint32_t entry_count;
} storage_header_t;

typedef struct {
    char key[64];
    uint32_t value_size;
    uint64_t access_count;
    time_t last_access;
} storage_entry_header_t;

// Helper to write data with error checking
static int write_all(int fd, const void* buf, size_t count) {
    const char* ptr = (const char*)buf;
    size_t written = 0;
    
    while (written < count) {
        ssize_t n = write(fd, ptr + written, count - written);
        if (n <= 0) return -1;
        written += n;
    }
    
    return 0;
}

static int read_all(int fd, void* buf, size_t count) {
    char* ptr = (char*)buf;
    size_t bytes_read = 0;
    
    while (bytes_read < count) {
        ssize_t n = read(fd, ptr + bytes_read, count - bytes_read);
        if (n <= 0) return -1;
        bytes_read += n;
    }
    
    return 0;
}

// Recursive function to save AVL tree nodes
static int save_tree_node(int fd, avl_node_t* node) {
    if (!node) return 0;
    
    storage_entry_header_t header;
    strncpy(header.key, node->key, sizeof(header.key));
    header.value_size = node->value_size;
    header.access_count = node->access_count;
    header.last_access = node->last_access;
    
    if (write_all(fd, &header, sizeof(header)) < 0) return -1;
    if (write_all(fd, node->value, node->value_size) < 0) return -1;
    
    // Recursively save children
    if (save_tree_node(fd, node->left) < 0) return -1;
    if (save_tree_node(fd, node->right) < 0) return -1;
    
    return 0;
}

int storage_save_cache(const char* path, avl_node_t* root) {
    if (!path) return -1;
    
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) {
        return -1;
    }
    
    // Count nodes first
    int node_count = 0;
    avl_node_t* dummy_nodes[10000];
    avl_get_all_nodes(root, dummy_nodes, &node_count, 10000);
    
    storage_header_t header;
    header.magic = MAGIC_NUMBER;
    header.version = 1;
    header.entry_count = node_count;
    
    if (write_all(fd, &header, sizeof(header)) < 0) {
        return -1;
    }
    
    int result = save_tree_node(fd, root);
    
    if (result < 0) {
        return -1;
    }
    
    close(fd);
    return 0;
}

int storage_load_cache(const char* path, cache_handle_t handle) {
    if (!path || !handle) return -1;
    
    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        return -1;
    }
    
    storage_header_t header;
    if (read_all(fd, &header, sizeof(header)) < 0) {
        close(fd);
        return -1;
    }
    
    if (header.magic != MAGIC_NUMBER) {
        close(fd);
        return -1;
    }
    
    int loaded = 0;
    
    for (uint32_t i = 0; i < header.entry_count; i++) {
        storage_entry_header_t entry_header;
        
        if (read_all(fd, &entry_header, sizeof(entry_header)) < 0) {
            break;
        }
        
        void* value = malloc(entry_header.value_size);
        if (!value) {
            return -1;
        }
        
        if (read_all(fd, value, entry_header.value_size) < 0) {
            free(value);
            break;
        }
        
        // Insert into cache
        handle->index_root = avl_insert(handle->index_root, 
                                        entry_header.key, 
                                        value, 
                                        entry_header.value_size);
        
        // Also update LRU
        lru_node_t* lru_node = lru_create_node(entry_header.key);
        if (lru_node) {
            lru_move_to_front(&handle->lru_head, &handle->lru_tail, lru_node);
        }
        
        free(value);
        loaded++;
    }
    
    close(fd);
    return loaded;
}
