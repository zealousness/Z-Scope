/**
 * @file cache_manager.h
 * @brief High-performance thread-safe data cache manager with persistent storage
 * 
 * This module provides a generic key-value cache with the following features:
 * - Thread-safe operations with mutex protection
 * - LRU (Least Recently Used) eviction policy
 * - AVL tree indexing for O(log n) lookups
 * - Persistent storage with file-based backup
 * - Configurable cache size limits
 * 
 * @author Cache Module Team
 * @version 1.0
 */

#ifndef CACHE_MANAGER_H
#define CACHE_MANAGER_H

#include <stddef.h>
#include <stdint.h>
#include <pthread.h>

/* ========== Public Data Types ========== */

/**
 * @brief Cache handle (opaque type)
 */
typedef struct cache_manager* cache_handle_t;

/**
 * @brief Cache entry metadata
 */
typedef struct {
    char key[64];           /**< Entry key (null-terminated string) */
    size_t value_size;      /**< Size of stored value in bytes */
    uint64_t access_count;  /**< Number of times accessed */
    time_t last_access;     /**< Last access timestamp */
} cache_entry_info_t;

/**
 * @brief Cache statistics
 */
typedef struct {
    size_t total_entries;   /**< Current number of entries */
    size_t max_entries;     /**< Maximum capacity */
    uint64_t hit_count;     /**< Cache hit count */
    uint64_t miss_count;    /**< Cache miss count */
    size_t memory_used;     /**< Total memory used (bytes) */
} cache_stats_t;

/**
 * @brief Cache configuration
 */
typedef struct {
    size_t max_entries;     /**< Maximum number of entries (must be > 0) */
    size_t max_value_size;  /**< Maximum value size in bytes (must be > 0) */
    const char* storage_path; /**< Path for persistent storage (NULL = no persistence) */
    int enable_threading;   /**< Enable thread-safe operations (1 = yes, 0 = no) */
} cache_config_t;

/* ========== Public API Functions ========== */

/**
 * @brief Initialize a new cache manager instance
 * 
 * Creates and initializes a cache manager with the specified configuration.
 * All configuration parameters are validated before initialization.
 * 
 * @param config Cache configuration (must not be NULL)
 * @return cache_handle_t Valid handle on success, NULL on failure
 * 
 * @note Caller must call cache_destroy() to free resources
 * @warning config->max_entries must be > 0 and < 1000000
 */
cache_handle_t cache_create(const cache_config_t* config);

/**
 * @brief Store a key-value pair in the cache
 * 
 * Stores the given value associated with the key. If the key already exists,
 * its value is updated. If cache is full, LRU entry is evicted.
 * 
 * @param handle Cache handle (must be valid)
 * @param key Entry key (must not be NULL, max 63 chars)
 * @param value Value data (must not be NULL)
 * @param value_size Size of value in bytes (must be > 0)
 * @return int 0 on success, -1 on failure
 * 
 * @note Thread-safe if threading is enabled
 */
int cache_put(cache_handle_t handle, const char* key, 
              const void* value, size_t value_size);

/**
 * @brief Retrieve a value from the cache
 * 
 * Looks up the value associated with the given key. Updates access statistics
 * and LRU position.
 * 
 * @param handle Cache handle (must be valid)
 * @param key Entry key (must not be NULL)
 * @param value_out Buffer to receive value (must not be NULL)
 * @param buffer_size Size of output buffer (must be >= value size)
 * @return ssize_t Actual value size on success, -1 on failure
 * 
 * @note Thread-safe if threading is enabled
 * @warning Buffer overflow possible if buffer_size < actual value size
 */
ssize_t cache_get(cache_handle_t handle, const char* key,
                  void* value_out, size_t buffer_size);

/**
 * @brief Remove an entry from the cache
 * 
 * Removes the entry with the given key if it exists.
 * 
 * @param handle Cache handle (must be valid)  
 * @param key Entry key (must not be NULL)
 * @return int 0 on success, -1 if not found or error
 * 
 * @note Thread-safe if threading is enabled
 */
int cache_delete(cache_handle_t handle, const char* key);

/**
 * @brief Get cache statistics
 * 
 * Retrieves current cache statistics including hit/miss ratios and memory usage.
 * 
 * @param handle Cache handle (must be valid)
 * @param stats_out Output buffer for statistics (must not be NULL)
 * @return int 0 on success, -1 on failure
 * 
 * @note Thread-safe if threading is enabled
 */
int cache_get_stats(cache_handle_t handle, cache_stats_t* stats_out);

/**
 * @brief List all cache entries
 * 
 * Returns an array of metadata for all current cache entries.
 * 
 * @param handle Cache handle (must be valid)
 * @param entries_out Pointer to receive entry array (allocated by function)
 * @param count_out Pointer to receive entry count (must not be NULL)
 * @return int 0 on success, -1 on failure
 * 
 * @note Caller must free(*entries_out) after use
 * @warning DEFECT: May return stack memory in certain conditions
 */
int cache_list_entries(cache_handle_t handle, 
                       cache_entry_info_t** entries_out,
                       size_t* count_out);

/**
 * @brief Save cache to persistent storage
 * 
 * Writes all cache entries to the configured storage path.
 * 
 * @param handle Cache handle (must be valid)
 * @return int 0 on success, -1 on failure
 * 
 * @note Requires valid storage_path in configuration
 * @warning DEFECT: May leak file descriptors on error paths
 */
int cache_save(cache_handle_t handle);

/**
 * @brief Load cache from persistent storage
 * 
 * Loads previously saved cache entries from storage.
 * 
 * @param handle Cache handle (must be valid)
 * @return int Number of entries loaded, -1 on failure
 */
int cache_load(cache_handle_t handle);

/**
 * @brief Clear all cache entries
 * 
 * Removes all entries from the cache and frees associated memory.
 * 
 * @param handle Cache handle (must be valid)
 * @return int 0 on success, -1 on failure
 * 
 * @note Thread-safe if threading is enabled
 * @warning DEFECT: May leak memory due to orphaned references
 */
int cache_clear(cache_handle_t handle);

/**
 * @brief Destroy cache and free all resources
 * 
 * Destroys the cache instance and frees all associated resources.
 * Handle becomes invalid after this call.
 * 
 * @param handle Cache handle (must be valid)
 * 
 * @note Not thread-safe - caller must ensure no concurrent access
 */
void cache_destroy(cache_handle_t handle);

#endif /* CACHE_MANAGER_H */
