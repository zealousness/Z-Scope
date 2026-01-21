#include "cache_internal.h"

int thread_lock(cache_handle_t handle) {
    if (!handle || !handle->config.enable_threading) {
        return 0;
    }
    
    if (!handle->lock_initialized) {
        return -1;
    }
    
    return pthread_mutex_lock(&handle->lock);
}

int thread_unlock(cache_handle_t handle) {
    if (!handle || !handle->config.enable_threading) {
        return 0;
    }
    
    if (!handle->lock_initialized) {
        return -1;
    }
    
    return pthread_mutex_unlock(&handle->lock);
}
