/**
 * @file cache_internal.h
 * @brief Internal data structures and helper functions
 */

#ifndef CACHE_INTERNAL_H
#define CACHE_INTERNAL_H

#include "../include/cache_manager.h"
#include <pthread.h>
#include <time.h>

/* Internal structures - not exposed to users */

/** AVL tree node for cache indexing */
typedef struct avl_node {
    char key[64];
    void* value;
    size_t value_size;
    uint64_t access_count;
    time_t last_access;
    
    struct avl_node* left;
    struct avl_node* right;
    int height;
} avl_node_t;

/** LRU queue node */
typedef struct lru_node {
    char key[64];
    struct lru_node* prev;
    struct lru_node* next;
} lru_node_t;

/** Cache manager instance */
struct cache_manager {
    /* Configuration */
    cache_config_t config;
    
    /* Data structures */
    avl_node_t* index_root;     /* AVL tree root */
    lru_node_t* lru_head;        /* MRU (most recently used) */
    lru_node_t* lru_tail;        /* LRU (least recently used) */
    
    /* Statistics */
    cache_stats_t stats;
    
    /* Thread safety */
    pthread_mutex_t lock;
    int lock_initialized;
    
    /* Persistence */
    char storage_path[256];
};

/* Internal function declarations */

/* AVL tree operations (cache_index.c) */
avl_node_t* avl_insert(avl_node_t* root, const char* key, const void* value, size_t value_size);
avl_node_t* avl_find(avl_node_t* root, const char* key);
avl_node_t* avl_delete(avl_node_t* root, const char* key);
void avl_destroy(avl_node_t* root);
int avl_get_all_nodes(avl_node_t* root, avl_node_t** nodes, int* count, int max_count);

/* LRU queue operations (cache_queue.c) */
lru_node_t* lru_create_node(const char* key);
void lru_move_to_front(lru_node_t** head, lru_node_t** tail, lru_node_t* node);
lru_node_t* lru_find_node(lru_node_t* head, const char* key);
char* lru_remove_lru(lru_node_t** head, lru_node_t** tail);
void lru_destroy(lru_node_t* head);

/* Storage operations (cache_storage.c) */
int storage_save_cache(const char* path, avl_node_t* root);
int storage_load_cache(const char* path, cache_handle_t handle);

/* Thread operations (cache_thread.c) */
int thread_lock(cache_handle_t handle);
int thread_unlock(cache_handle_t handle);

#endif /* CACHE_INTERNAL_H */
