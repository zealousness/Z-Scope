#ifndef TYPES_H
#define TYPES_H

#include <stdint.h>
#include <stddef.h>
#include <pthread.h>

typedef uint32_t task_id_t;
typedef int32_t plugin_handle_t;
typedef uint64_t timestamp_t;

typedef enum {
    TASK_TYPE_CMD_EXECUTE = 0,
    TASK_TYPE_FILE_PROCESS = 1,
    TASK_TYPE_NETWORK_REQ = 2,
    TASK_TYPE_CUSTOM = 3
} task_type_t;

typedef enum {
    TASK_STATUS_PENDING = 0,
    TASK_STATUS_RUNNING = 1,
    TASK_STATUS_COMPLETED = 2,
    TASK_STATUS_FAILED = 3,
    TASK_STATUS_NORMAL = 4
} task_status_t;

typedef struct {
    uint32_t timeout_ms;
    uint32_t max_retries;
    uint8_t compression_enabled;
    uint8_t encryption_enabled;
} NetworkConfig;

typedef struct {
    uint32_t allowed_uid;
    uint32_t allowed_gid;
    uint8_t require_root;
    uint8_t sandbox_enabled;
} SecurityConfig;

typedef struct {
    uint32_t queue_size;
    uint32_t thread_count;
    uint32_t max_tasks_per_client;
    NetworkConfig network;
    SecurityConfig security;
} TaskConfig;

typedef union {
    struct {
        void* data;
        size_t size;
    } binary;
    struct {
        char* content;
        size_t length;
    } text;
    struct {
        char* command;
        char** args;
        int arg_count;
    } command;
} Payload;

typedef struct {
    uint32_t is_urgent : 1;
    uint32_t is_async : 1;
    uint32_t requires_auth : 1;
    uint32_t is_dry_run : 1;
    uint32_t reserved : 28;
} TaskFlags;

typedef struct Task {
    task_id_t id;
    task_type_t type;
    task_status_t status;
    TaskFlags flags;
    timestamp_t created_at;
    timestamp_t timeout_at;
    Payload payload;
    char* client_id;
    void* user_data;
    struct Task* next;
} Task;

typedef void (*task_handler_t)(Task* task);
typedef void (*plugin_callback_t)(void* context);
typedef int (*filter_func_t)(const Task* task);

typedef struct {
    char name[64];
    plugin_handle_t handle;
    task_handler_t handler;
    plugin_callback_t init;
    plugin_callback_t cleanup;
    void* context;
    int priority;
} Plugin;

typedef struct {
    Task** tasks;
    size_t capacity;
    size_t count;
    size_t head;
    size_t tail;
    pthread_mutex_t mutex;
    pthread_cond_t cond;
} TaskQueue;

typedef struct {
    Plugin* plugins;
    size_t capacity;
    size_t count;
    pthread_mutex_t mutex;
} PluginRegistry;

typedef struct {
    TaskConfig config;
    TaskQueue queue;
    PluginRegistry registry;
    pthread_t* threads;
    int running;
    pthread_mutex_t state_mutex;
    task_id_t next_task_id;
    uint32_t total_tasks;
    uint32_t completed_tasks;
    uint32_t failed_tasks;
} Dispatcher;

#endif
