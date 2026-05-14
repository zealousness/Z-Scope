#ifndef TYPES_PH
#define TYPES_PH

#include "../include/types.h"

typedef struct {
    int fd;
    char buffer[8192];
    size_t buffer_pos;
    uint32_t client_id;
    uint32_t last_activity;
} Connection;

typedef struct {
    char magic[4];
    uint32_t version;
    uint32_t task_type;
    uint32_t flags;
    uint32_t payload_length;
    uint32_t checksum;
} TaskHeader;

typedef struct {
    char name[MAX_PLUGIN_NAME];
    void* symbol;
    int loaded;
    int ref_count;
} PluginModule;

typedef struct {
    Task* task;
    uint32_t retry_count;
    uint64_t start_time;
    char error_msg[256];
} TaskContext;

typedef struct {
    pthread_mutex_t lock_a;
    pthread_mutex_t lock_b;
    int resource_a;
    int resource_b;
} SharedResources;

#endif
