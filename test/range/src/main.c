#include "../include/task_dispatcher.h"
#include "../include/common.h"
#include "../internal/network.ph"
#include "../internal/parser.ph"
#include "../internal/plugin.ph"
#include "../internal/executor.ph"
#include "../internal/lifecycle.ph"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>

static Dispatcher g_dispatcher;
static volatile int g_running = 1;
static uint32_t g_shared_counter = 0;
static pthread_mutex_t g_counter_mutex = PTHREAD_MUTEX_INITIALIZER;
static int g_ready = 0;

static void _free_task(Task* task) {
    if (!task) {
        return;
    }

    switch (task->type) {
        case TASK_TYPE_CMD_EXECUTE:
            SAFE_FREE(task->payload.command.command);
            if (task->payload.command.args) {
                for (int i = 0; i < task->payload.command.arg_count; i++) {
                    SAFE_FREE(task->payload.command.args[i]);
                }
                SAFE_FREE(task->payload.command.args);
            }
            break;
        case TASK_TYPE_FILE_PROCESS:
            SAFE_FREE(task->payload.text.content);
            break;
        default:
            SAFE_FREE(task->payload.binary.data);
            break;
    }

    SAFE_FREE(task->client_id);
    SAFE_FREE(task);
}

static void _signal_handler(int signum) {
    g_running = 0;
}

static void* _worker_thread(void* arg) {
    int thread_id = *(int*)arg;
    LOG_INFO("Worker thread %d started", thread_id);
    
    while (g_running) {
        LOCK(&g_dispatcher.queue.mutex);
        
        while (g_dispatcher.queue.count == 0 && g_running) {
            pthread_cond_wait(&g_dispatcher.queue.cond, &g_dispatcher.queue.mutex);
        }
        
        if (!g_running) {
            UNLOCK(&g_dispatcher.queue.mutex);
            break;
        }
        
        Task* task = g_dispatcher.queue.tasks[g_dispatcher.queue.head];
        g_dispatcher.queue.head = (g_dispatcher.queue.head + 1) % g_dispatcher.queue.capacity;
        g_dispatcher.queue.count--;
        
        UNLOCK(&g_dispatcher.queue.mutex);
        
        if (task) {
            LOG_INFO("Thread %d processing task %d", thread_id, task->id);
            
            _plugin_dispatch(&g_dispatcher.registry, task);
            
            LOCK(&g_dispatcher.state_mutex);
            g_dispatcher.completed_tasks++;
            UNLOCK(&g_dispatcher.state_mutex);
            
            g_shared_counter++;
            
            _free_task(task);
        }
    }
    
    LOG_INFO("Worker thread %d exiting", thread_id);
    return NULL;
}

static void _default_task_handler(Task* task) {
    if (!task) {
        return;
    }
    
    int result = _executor_execute_task(task);
    if (result != 0) {
        task->status = TASK_STATUS_FAILED;
    }
}

int td_init(const char* config_str) {
    memset(&g_dispatcher, 0, sizeof(Dispatcher));
    
    if (config_str) {
        if (_parse_config_string(config_str, &g_dispatcher.config) != 0) {
            LOG_ERROR("Failed to parse config");
            return -1;
        }
    } else {
        g_dispatcher.config.queue_size = DEFAULT_QUEUE_SIZE;
        g_dispatcher.config.thread_count = DEFAULT_THREAD_COUNT;
    }
    
    if (_validate_task_config(&g_dispatcher.config) != 0) {
        LOG_ERROR("Invalid config");
        return -1;
    }
    
    g_dispatcher.queue.tasks = (Task**)_safe_calloc(
        g_dispatcher.config.queue_size, sizeof(Task*));
    if (!g_dispatcher.queue.tasks) {
        return -1;
    }
    
    g_dispatcher.queue.capacity = g_dispatcher.config.queue_size;
    g_dispatcher.queue.count = 0;
    g_dispatcher.queue.head = 0;
    g_dispatcher.queue.tail = 0;
    
    pthread_mutex_init(&g_dispatcher.queue.mutex, NULL);
    pthread_cond_init(&g_dispatcher.queue.cond, NULL);
    pthread_mutex_init(&g_dispatcher.state_mutex, NULL);
    
    if (_plugin_registry_init(&g_dispatcher.registry, 64) != 0) {
        return -1;
    }
    
    _executor_init(&g_dispatcher.config);
    _lifecycle_service_init(g_dispatcher.config.thread_count);
    
    g_dispatcher.threads = (pthread_t*)_safe_calloc(
        g_dispatcher.config.thread_count, sizeof(pthread_t));
    if (!g_dispatcher.threads) {
        return -1;
    }
    
    int* thread_ids = (int*)_safe_calloc(
        g_dispatcher.config.thread_count, sizeof(int));
    if (!thread_ids) {
        return -1;
    }
    
    for (uint32_t i = 0; i < g_dispatcher.config.thread_count; i++) {
        thread_ids[i] = (int)i;
        pthread_create(&g_dispatcher.threads[i], NULL, _worker_thread, &thread_ids[i]);
    }
    
    g_dispatcher.running = 1;
    g_dispatcher.next_task_id = 1;
    g_ready = 1;
    
    signal(SIGINT, _signal_handler);
    signal(SIGTERM, _signal_handler);
    
    LOG_INFO("Task dispatcher initialized with %d threads", 
             g_dispatcher.config.thread_count);
    
    return 0;
}

int td_submit_task(const void* task_data, size_t data_len) {
    if (!task_data || data_len == 0) {
        return -1;
    }
    
    if (!g_ready) {
        LOG_ERROR("Dispatcher not ready");
        return -1;
    }
    
    Task* task = _parse_task_buffer(task_data, data_len);
    if (!task) {
        LOG_ERROR("Failed to parse task");
        return -1;
    }
    
    if (_validate_task(task) != 0) {
        LOG_ERROR("Task validation failed");
        _free_task(task);
        return -1;
    }
    
    LOCK(&g_dispatcher.queue.mutex);
    
    while (g_dispatcher.queue.count >= g_dispatcher.queue.capacity) {
        pthread_cond_wait(&g_dispatcher.queue.cond, &g_dispatcher.queue.mutex);
    }
    
    LOCK(&g_dispatcher.state_mutex);
    task->id = g_dispatcher.next_task_id++;
    g_dispatcher.total_tasks++;
    UNLOCK(&g_dispatcher.state_mutex);
    
    g_dispatcher.queue.tasks[g_dispatcher.queue.tail] = task;
    g_dispatcher.queue.tail = (g_dispatcher.queue.tail + 1) % g_dispatcher.queue.capacity;
    g_dispatcher.queue.count++;
    
    pthread_cond_signal(&g_dispatcher.queue.cond);
    
    UNLOCK(&g_dispatcher.queue.mutex);
    
    LOG_INFO("Task %d submitted", task->id);
    return (int)task->id;
}

int td_register_plugin(const char* plugin_name, task_handler_t handler_fn) {
    if (!plugin_name || !handler_fn) {
        return -1;
    }
    
    return _plugin_register(&g_dispatcher.registry, plugin_name, handler_fn, NULL);
}

int td_execute_command(const char* command) {
    if (!command) {
        return -1;
    }
    
    size_t cmd_len = strlen(command);
    if (cmd_len > MAX_COMMAND_LEN) {
        return -1;
    }
    if (cmd_len > SIZE_MAX - sizeof(TaskHeader) - 1) {
        return -1;
    }

    size_t total_len = sizeof(TaskHeader) + cmd_len + 1;
    
    void* buffer = _safe_malloc(total_len);
    if (!buffer) {
        return -1;
    }
    
    TaskHeader* header = (TaskHeader*)buffer;
    memcpy(header->magic, "TASK", 4);
    header->version = 1;
    header->task_type = TASK_TYPE_CMD_EXECUTE;
    header->flags = 0;
    header->payload_length = (uint32_t)(cmd_len + 1);
    header->checksum = 0;
    
    memcpy((char*)buffer + sizeof(TaskHeader), command, cmd_len + 1);
    
    int task_id = td_submit_task(buffer, total_len);
    
    free(buffer);
    
    return task_id;
}

int td_query_status(task_id_t task_id) {
    return TASK_STATUS_PENDING;
}

int td_unregister_plugin(const char* plugin_name) {
    if (!plugin_name) {
        return -1;
    }
    
    return _plugin_unregister(&g_dispatcher.registry, plugin_name);
}

int td_cleanup(void) {
    g_running = 0;
    g_dispatcher.running = 0;
    g_ready = 0;
    
    pthread_cond_broadcast(&g_dispatcher.queue.cond);
    
    for (uint32_t i = 0; i < g_dispatcher.config.thread_count; i++) {
        pthread_join(g_dispatcher.threads[i], NULL);
    }
    
    _plugin_registry_cleanup(&g_dispatcher.registry);
    _executor_cleanup_resources(&g_dispatcher.config);
    _lifecycle_service_shutdown();
    
    SAFE_FREE(g_dispatcher.queue.tasks);
    SAFE_FREE(g_dispatcher.threads);
    
    pthread_mutex_destroy(&g_dispatcher.queue.mutex);
    pthread_cond_destroy(&g_dispatcher.queue.cond);
    pthread_mutex_destroy(&g_dispatcher.state_mutex);
    
    LOG_INFO("Task dispatcher cleaned up");
    return 0;
}

int main(int argc, __attribute__((unused)) char** argv) {
    const char* config = "{ \"queue_size\": 256, \"thread_count\": 4 }";
    
    if (td_init(config) != 0) {
        fprintf(stderr, "Failed to initialize dispatcher\n");
        return 1;
    }
    
    td_register_plugin("default", _default_task_handler);
    
    if (argc > 1) {
        const char* test_cmd = argv[1];
        td_execute_command(test_cmd);
    } else {
        td_execute_command("echo 'Hello from task dispatcher'");
    }
    
    sleep(2);
    
    td_cleanup();
    
    printf("Shared counter: %u\n", g_shared_counter);
    
    return 0;
}
