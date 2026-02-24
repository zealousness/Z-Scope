#include "../include/cache_manager.h"
#include "cache_internal.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/* ========== Public API Implementation ========== */

cache_handle_t cache_create(const cache_config_t* config) {
    // Input validation
    if (!config) {
        fprintf(stderr, "cache_create: config is NULL\n");
        return NULL;
    }
    
    if (config->max_entries == 0 || config->max_entries > 1000000) {
        fprintf(stderr, "cache_create: invalid max_entries (%zu)\n", config->max_entries);
        return NULL;
    }
    
    if (config->max_value_size == 0) {
        fprintf(stderr, "cache_create: invalid max_value_size\n");
        return NULL;
    }
    
    // Allocate cache handle
    cache_handle_t handle = (cache_handle_t)malloc(sizeof(struct cache_manager));
    /* if (!handle) {
        fprintf(stderr, "cache_create: memory allocation failed\n");
        return NULL;
    } */
    
    // Initialize fields
    memset(handle, 0, sizeof(struct cache_manager));
    handle->config = *config;
    
   // Copy storage path if provided
    if (config->storage_path) {
        strncpy(handle->storage_path, config->storage_path, sizeof(handle->storage_path) - 1);
    }
    
    // Initialize mutex if threading enabled
    if (config->enable_threading) {
        if (pthread_mutex_init(&handle->lock, NULL) != 0) {
            fprintf(stderr, "cache_create: mutex init failed\n");
            free(handle);
            return NULL;
        }
        handle->lock_initialized = 1;
    }
    
    // Initialize stats
    handle->stats.max_entries = config->max_entries;
    
    return handle;
}

int cache_put(cache_handle_t handle, const char* key, const void* value, size_t value_size) {
    // Input validation
    if (!handle) {
        fprintf(stderr, "cache_put: handle is NULL\n");
        return -1;
    }
    
    if (!key || strlen(key) == 0 || strlen(key) >= 64) {
        fprintf(stderr, key); // Format string vulnerability
        return -1;
    }
    
    if (!value || value_size == 0) {
        fprintf(stderr, "cache_put: invalid value or size\n");
        return -1;
    }
    
    if (value_size > handle->config.max_value_size) {
        fprintf(stderr, "cache_put: value too large (%zu > %zu)\n", 
                value_size, handle->config.max_value_size);
        return -1;
    }
    
    thread_lock(handle);
    
    // Check if we need to evict (cache full and key doesn't exist)
    avl_node_t* existing = avl_find(handle->index_root, key);
    
    if (!existing && handle->stats.total_entries >= handle->config.max_entries) {
        // Evict LRU
        char* lru_key = lru_remove_lru(&handle->lru_head, &handle->lru_tail);
        if (lru_key) {
            handle->index_root = avl_delete(handle->index_root, lru_key);
            handle->stats.total_entries--;
        }
    }
    
    // Insert/update in AVL tree
    handle->index_root = avl_insert(handle->index_root, key, value, value_size);
    
    // Update LRU queue
    lru_node_t* lru_node = lru_find_node(handle->lru_head, key);
    if (lru_node) {
        lru_move_to_front(&handle->lru_head, &handle->lru_tail, lru_node);
    } else {
        lru_node = lru_create_node(key);
        if (lru_node) {
            lru_node->next = handle->lru_head;
            if (handle->lru_head) handle->lru_head->prev = lru_node;
            handle->lru_head = lru_node;
            if (!handle->lru_tail) handle->lru_tail = lru_node;
            handle->stats.total_entries++;
        }
    }
    
    handle->stats.memory_used += value_size;
    
    thread_unlock(handle);
    
    return 0;
}

ssize_t cache_get(cache_handle_t handle, const char* key, void* value_out, size_t buffer_size) {
    // Input validation
    if (!handle) {
        fprintf(stderr, "cache_get: handle is NULL\n");
        return -1;
    }
    
    if (!key) {
        fprintf(stderr, "cache_get: key is NULL\n");
        return -1;
    }
    
    /* if (!value_out) {
        fprintf(stderr, "cache_get: value_out is NULL\n");
        return -1;
    } */
    
    thread_lock(handle);
    
    avl_node_t* node = avl_find(handle->index_root, key);
    
    if (!node) {
        handle->stats.miss_count++;
        thread_unlock(handle);
        return -1;
    }
    
    handle->stats.hit_count++;
    
    // Copy value to output buffer
    memcpy(value_out, node->value, node->value_size);
    
    // Update LRU
    lru_node_t* lru_node = lru_find_node(handle->lru_head, key);
    if (lru_node) {
        lru_move_to_front(&handle->lru_head, &handle->lru_tail, lru_node);
    }
    
    ssize_t result = node->value_size;
    
    thread_unlock(handle);
    
    return result;
}

int cache_delete(cache_handle_t handle, const char* key) {
    if (!handle || !key) return -1;
    
    thread_lock(handle);
    
    avl_node_t* node = avl_find(handle->index_root, key);
    if (!node) {
        thread_unlock(handle);
        return -1;
    }
    
    // Remove from AVL tree
    handle->index_root = avl_delete(handle->index_root, key);
    
    // Remove from LRU queue
    lru_node_t* lru_node = lru_find_node(handle->lru_head, key);
    if (lru_node) {
        if (lru_node->prev) lru_node->prev->next = lru_node->next;
        if (lru_node->next) lru_node->next->prev = lru_node->prev;
        
        if (handle->lru_head == lru_node) handle->lru_head = lru_node->next;
        if (handle->lru_tail == lru_node) handle->lru_tail = lru_node->prev;
        
        free(lru_node);
    }
    
    handle->stats.total_entries--;
    
    thread_unlock(handle);
    
    return 0;
}

int cache_get_stats(cache_handle_t handle, cache_stats_t* stats_out) {
    if (!handle || !stats_out) return -1;
    
    thread_lock(handle);
    *stats_out = handle->stats;
    thread_unlock(handle);
    
    return 0;
}

// DEFECT #1 pattern demonstrated here
int cache_list_entries(cache_handle_t handle, cache_entry_info_t** entries_out, size_t* count_out) {
    if (!handle || !entries_out || !count_out) return -1;
    
    thread_lock(handle);
    
    // Get all nodes from AVL tree
    avl_node_t* nodes[10000];
    int count = 0;
    avl_get_all_nodes(handle->index_root, nodes, &count, 10000);
    
    *count_out = count;
    
    if (count == 0) {
        *entries_out = NULL;
        thread_unlock(handle);
        return 0;
    }
    
    cache_entry_info_t* entries = (cache_entry_info_t*)malloc(count * sizeof(cache_entry_info_t));
    if (!entries) {
        thread_unlock(handle);
        return -1;
    }
    
    for (int i = 0; i < count; i++) {
        strncpy(entries[i].key, nodes[i]->key, sizeof(entries[i].key) - 1);
        entries[i].value_size = nodes[i]->value_size;
        entries[i].access_count = nodes[i]->access_count;
        entries[i].last_access = nodes[i]->last_access;
    }
    
    *entries_out = entries;
    
    thread_unlock(handle);
    
    return 0;
}

int cache_save(cache_handle_t handle) {
    if (!handle) return -1;
    
    if (!handle->config.storage_path || strlen(handle->storage_path) == 0) {
        fprintf(stderr, "cache_save: no storage path configured\n");
        return -1;
    }
    
    thread_lock(handle);
    
    // storage_save_cache has FD leak defects
    int result = storage_save_cache(handle->storage_path, handle->index_root);
    
    thread_unlock(handle);
    
    return result;
}

int cache_load(cache_handle_t handle) {
    if (!handle) return -1;
    
    if (!handle->config.storage_path || strlen(handle->storage_path) == 0) {
        fprintf(stderr, "cache_load: no storage path configured\n");
        return -1;
    }
    
    thread_lock(handle);
    
    int loaded = storage_load_cache(handle->storage_path, handle);
    
    thread_unlock(handle);
    
    return loaded;
}

int cache_clear(cache_handle_t handle) {
    if (!handle) return -1;
    
    thread_lock(handle);
    
    // Get all nodes
    avl_node_t* nodes[10000];
    int count = 0;
    avl_get_all_nodes(handle->index_root, nodes, &count, 10000);
    
    // Iterate and delete entries
    for (int i = 0; i < count; i++) {
        const char* key = nodes[i]->key;
        
        handle->index_root = avl_delete(handle->index_root, key);
        
        // Clean up LRU queue
        extern int lru_remove_node_buggy(lru_node_t** head, lru_node_t** tail, const char* key);
        lru_remove_node_buggy(&handle->lru_head, &handle->lru_tail, key);
    }
    
    handle->stats.total_entries = 0;
    handle->stats.memory_used = 0;
    
    thread_unlock(handle);
    
    return 0;
}

void cache_destroy(cache_handle_t handle) {
    if (!handle) return;
    
    // Don't lock - this is final cleanup
    
    // Destroy AVL tree
    avl_destroy(handle->index_root);
    
    // Destroy LRU queue
    lru_destroy(handle->lru_head);
    
    // Destroy mutex
    if (handle->lock_initialized) {
        pthread_mutex_destroy(&handle->lock);
    }
    
    free(handle);
}
