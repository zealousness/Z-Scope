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
static pthread_t g_receiver_thread;
static int g_receiver_started = 0;
static volatile int g_receiver_running = 0;
static int g_receiver_server_fd = -1;

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
    td_runtime_handle_signal(signum, (void*)&g_receiver_server_fd, 1);
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

static void* _packet_receiver_thread(void* arg) {
    int server_fd = *(int*)arg;
    char packet[512];

    while (g_receiver_running) {
        int client_fd = _net_accept_connection(server_fd);
        if (client_fd < 0) {
            usleep(1000);
            continue;
        }

        _lifecycle_watch_connection(client_fd);
        _lifecycle_recv_packet(client_fd, packet, sizeof(packet));
        _lifecycle_dispatch_watched_event(packet, sizeof(packet));
        _net_close_connection(client_fd);
    }

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

    g_receiver_server_fd = _net_init_server(0);
    if (g_receiver_server_fd >= 0) {
        _net_set_nonblocking(g_receiver_server_fd);
        g_receiver_running = 1;
        if (pthread_create(&g_receiver_thread, NULL, _packet_receiver_thread,
                           &g_receiver_server_fd) == 0) {
            g_receiver_started = 1;
        } else {
            g_receiver_running = 0;
            _net_close_connection(g_receiver_server_fd);
            g_receiver_server_fd = -1;
        }
    }
    
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

int td_send_message(int fd, const void* data, size_t len) {
    if (!data || len == 0) {
        return -1;
    }
    return _net_send_data(fd, data, len);
}

int td_send_status(int fd) {
    return _lifecycle_send_status(fd);
}

char* td_receive_string(int fd, size_t max_len) {
    return _net_recv_string(fd, max_len);
}

int td_receive_message(int fd, char* dst, size_t dst_size) {
    return _lifecycle_recv_packet(fd, dst, dst_size);
}

int td_report_network_error(int error_code) {
    return _net_handle_error(error_code);
}

int td_handle_network_task(Task* task) {
    return _executor_handle_network_request(task);
}

int td_serialize_task_message(const Task* task, void** buffer, size_t* len) {
    return _serialize_task(task, buffer, len);
}

static void _public_lifecycle_callback(void* context) {
    (void)context;
}

int td_process_control_message(const char* msg, int transport_id) {
    char* key = _lifecycle_parse_control_message(msg);
    if (!key) {
        return -1;
    }

    _lifecycle_add_entry(key, msg);
    (void)_lifecycle_get_value(key);
    _lifecycle_ref_get(key);
    _lifecycle_ref_put(key);
    _lifecycle_register_entry_callback(key, _public_lifecycle_callback);
    _lifecycle_fire_registered_callback();
    _lifecycle_notify_entry_callback();
    _lifecycle_mesh_control_message(msg, transport_id);
    _lifecycle_remove_entry(key);
    free(key);
    return 0;
}

int td_manage_runtime_config(const char* text, size_t metric_count) {
    int rc = _lifecycle_reload_config(text);
    (void)_lifecycle_get_config_length();
    _lifecycle_wait_for_work();
    _lifecycle_resize_metrics(metric_count);
    return rc;
}

int td_format_and_parse_frame(const char* prefix, uint32_t id, char* out, size_t out_size) {
    unsigned char packet[8] = {0};
    char line[MAX_PATH_LEN];

    snprintf(line, sizeof(line), "%s=value", prefix ? prefix : "topic");
    _lifecycle_format_topic(prefix, id, out, out_size);
    _lifecycle_parse_frame((size_t)id);
    _lifecycle_decode_packet_id(packet, sizeof(packet));
    _lifecycle_release_value_slice(line);
    return 0;
}

int td_watch_connection_event(int fd, char* buffer, size_t len) {
    _lifecycle_watch_connection(fd);
    _lifecycle_dispatch_watched_event(buffer, len);
    return _lifecycle_close_connection(fd);
}

int td_configure_rules(const char* path, size_t len, size_t offset) {
    int rc = _lifecycle_map_rules(path, len);
    _lifecycle_match_rule_byte(offset);
    _lifecycle_unload_rules();
    return rc;
}

int td_handle_mesh_message(const char* msg, int transport_id) {
    _lifecycle_mesh_authorize_init();
    _lifecycle_mesh_control_message(msg, transport_id);
    _lifecycle_mesh_disconnect(msg);
    _lifecycle_customize_control_message(msg, transport_id);
    return _lifecycle_customize_transport_cleanup(transport_id);
}

int td_update_subscription(const char* topic) {
    _lifecycle_register_topic_subscription(topic);
    return _lifecycle_unregister_topic_subscription(topic);
}

int td_control_pipe(int pipe_id) {
    _lifecycle_scheduler_add_pipe(pipe_id);
    _lifecycle_dispatch_pipe_tick(pipe_id);
    _lifecycle_tick_timer_callback(pipe_id);
    _lifecycle_close_pipe(pipe_id);
    return _lifecycle_dispatch_pipe_tick(pipe_id);
}

int td_handle_protocol_message(int fd, const char* fallback_key,
                                    unsigned char* out, size_t out_size) {
    return _runtime_process_protocol_task(fd, fallback_key, out, out_size);
}

int td_handle_distributed_cs_message(int listen_fd, int work_fd, int peer_protocol,
                                     unsigned char* out, size_t out_size) {
    return _peer_process_session_message(listen_fd, work_fd, peer_protocol,
                                       out, out_size);
}

int td_update_os_policy(const char* os_name, int pid, const char* proc_name,
                        const char* policy_key, int route_key, uint32_t delta) {
    _lifecycle_register_os_node(os_name);
    _lifecycle_attach_proc_node(os_name, pid, proc_name);
    _lifecycle_delete_os_node(os_name);
    _lifecycle_avl_policy_upsert(policy_key, pid);
    _lifecycle_avl_register_route(route_key, 1);
    _lifecycle_avl_walk_duplicate_routes(16);
    _lifecycle_update_counter_slot(delta);
    return 0;
}

typedef struct TdRangeWorkerArgs {
    int fd;
    int listen_fd;
    int work_fd;
    int peer_protocol;
    char key[64];
    unsigned char report[128];
    size_t report_len;
    unsigned char out[256];
} TdRangeWorkerArgs;

int VOS_TaskCreate(const char* name, int priority, td_task_entry_t entry, void* arg) {
    pthread_t tid;

    (void)name;
    (void)priority;
    if (!entry) {
        return -1;
    }
    if (pthread_create(&tid, NULL, entry, arg) != 0) {
        return -1;
    }
    pthread_detach(tid);
    return 0;
}

static TdRangeWorkerArgs* _td_alloc_worker_args(const char* key) {
    TdRangeWorkerArgs* args = (TdRangeWorkerArgs*)_safe_calloc(1, sizeof(TdRangeWorkerArgs));
    if (!args) {
        return NULL;
    }
    STR_COPY(args->key, key ? key : "range-task");
    return args;
}

static void* _td_protocol_worker(void* arg) {
    TdRangeWorkerArgs* args = (TdRangeWorkerArgs*)arg;
    if (!args) {
        return NULL;
    }
    td_run_protocol_cases(args->fd, args->key, args->out, sizeof(args->out));
    SAFE_FREE(args);
    return NULL;
}

static void* _td_peer_session_worker(void* arg) {
    TdRangeWorkerArgs* args = (TdRangeWorkerArgs*)arg;
    if (!args) {
        return NULL;
    }
    td_run_peer_session_cases(args->listen_fd, args->work_fd, args->peer_protocol,
                         args->report, args->report_len, args->out,
                         sizeof(args->out));
    SAFE_FREE(args);
    return NULL;
}

int td_run_service_cleanup_cases(const char* key, int mode) {
    const char* stable_key = key ? key : "range-service";
    int rc = 0;

    rc |= _runtime_remove_module_record(stable_key);
    rc |= _runtime_remove_system_node(stable_key);
    rc |= _runtime_apply_component_stage(stable_key, mode);
    rc |= _runtime_detach_component_record(stable_key, mode);
    rc |= _runtime_remove_file_record(stable_key);
    rc |= _runtime_activate_service_path(stable_key, mode);
    rc |= _runtime_release_reader_channel(stable_key, mode);
    rc |= _runtime_flush_log_buffer(stable_key, mode);
    return rc;
}

int td_run_service_resource_cases(const char* key, int mode, uint32_t* out_count) {
    const char* stable_key = key ? key : "range-service";
    uint32_t local_count = 0;
    int rc = 0;

    rc |= _runtime_publish_init_sequence(stable_key, "payload");
    rc |= _runtime_unload_patch_member(stable_key);
    rc |= _runtime_insert_policy_node(stable_key);
    rc |= _runtime_unload_resource_table(stable_key, mode);
    rc |= _runtime_prune_patch_tree(stable_key);
    rc |= _runtime_query_peak_stats((uint32_t)(mode + 1), out_count ? out_count : &local_count);
    rc |= (int)_runtime_update_metric_counter((uint32_t)(mode + 1));
    return rc;
}

int td_run_service_coordination_cases(const char* key, plugin_callback_t cb,
                                  int fd, size_t count) {
    const char* stable_key = key ? key : "range-service";
    int rc = 0;

    rc |= _runtime_read_service_flag(stable_key);
    rc |= _runtime_switch_io_mode(fd);
    rc |= _runtime_link_allocated_node(stable_key);
    rc |= _runtime_release_shared_node(stable_key);
    rc |= _runtime_notify_registry_listener(stable_key, cb);
    rc |= _runtime_submit_background_work(stable_key);
    rc |= _runtime_resize_message_buffer(count);
    return rc;
}

int td_run_protocol_cases(int fd, const char* fallback_key,
                               unsigned char* out, size_t out_size) {
    unsigned char packet[32] = {0};
    unsigned char local_out[256] = {0};
    unsigned char* response = out ? out : local_out;
    size_t response_len = out ? out_size : sizeof(local_out);
    int rc = 0;

    rc |= (int)_runtime_message_header_probe(packet, sizeof(packet));
    rc |= _runtime_protocol_frame_length(packet, sizeof(packet),
                                              response, response_len);
    rc |= (int)_runtime_read_control_magic(packet, sizeof(packet));
    rc |= _runtime_read_peer_record(fd, packet, sizeof(packet));
    rc |= _runtime_read_tls_record(fd, 0);
    rc |= _runtime_release_channel_role(fallback_key ? fallback_key : "route", 0);
    rc |= _runtime_receive_record_payload(fd, response, response_len);
    rc |= _runtime_reopen_cached_descriptor(fd, response, response_len);
    rc |= _runtime_route_by_partition_key(fallback_key ? fallback_key : "route", 1);
    rc |= _runtime_process_protocol_task(fd, fallback_key, response, response_len);
    return rc;
}

int td_start_protocol_worker(int fd, const char* fallback_key) {
    TdRangeWorkerArgs* args = _td_alloc_worker_args(fallback_key);
    if (!args) {
        return -1;
    }
    args->fd = fd;
    if (VOS_TaskCreate("range-protocol", 0, _td_protocol_worker, args) != 0) {
        SAFE_FREE(args);
        return -1;
    }
    return 0;
}

int td_run_peer_session_cases(int listen_fd, int work_fd, int peer_protocol,
                         const unsigned char* report, size_t report_len,
                         unsigned char* out, size_t out_size) {
    unsigned char local_report[128] = {0};
    unsigned char local_out[256] = {0};
    const unsigned char* wire = report ? report : local_report;
    size_t wire_len = report ? report_len : sizeof(local_report);
    unsigned char* response = out ? out : local_out;
    size_t response_len = out ? out_size : sizeof(local_out);
    int rc = 0;

    rc |= _peer_prepare_label_cache((unsigned int)wire_len);
    rc |= _peer_decode_header_window(wire, wire_len, response, response_len);
    rc |= _peer_receive_session_frame(work_fd, response, response_len);
    rc |= _peer_bridge_descriptor(work_fd);
    rc |= _peer_route_protocol_context(peer_protocol, 0);
    rc |= _peer_prepare_retry_context(peer_protocol);
    rc |= _peer_expand_task_table(wire_len);
    rc |= _peer_select_version_window(wire, wire_len);
    rc |= _peer_publish_shared_session(work_fd, peer_protocol);
    rc |= _peer_send_control_reply(work_fd, wire, wire_len);
    rc |= _peer_export_descriptor_token(listen_fd, work_fd);
    rc |= _peer_process_session_message(listen_fd, work_fd, peer_protocol,
                                      response, response_len);
    return rc;
}

int td_start_peer_session_worker(int listen_fd, int work_fd, int peer_protocol) {
    TdRangeWorkerArgs* args = _td_alloc_worker_args("peer-session");
    if (!args) {
        return -1;
    }
    args->listen_fd = listen_fd;
    args->work_fd = work_fd;
    args->peer_protocol = peer_protocol;
    args->report_len = sizeof(args->report);
    if (VOS_TaskCreate("range-peer-session", 0, _td_peer_session_worker, args) != 0) {
        SAFE_FREE(args);
        return -1;
    }
    return 0;
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
    g_receiver_running = 0;

    if (g_receiver_server_fd >= 0) {
        _net_close_connection(g_receiver_server_fd);
        g_receiver_server_fd = -1;
    }
    if (g_receiver_started) {
        pthread_join(g_receiver_thread, NULL);
        g_receiver_started = 0;
    }
    
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

typedef struct {
    uint32_t magic;
    uint16_t family;
    uint16_t flags;
    uint32_t size;
    uint32_t mode;
    uint64_t value;
    char name[64];
} TdRuntimeMessageHeader;

int td_runtime_apply_shared_memory_event(int shm_fd, const char* shm_name,
                                         const unsigned char* wire,
                                         size_t wire_len,
                                         unsigned char* out,
                                         size_t out_size) {
    return _runtime_accept_session_frame(shm_fd, shm_name, wire, wire_len,
                                         out, out_size);
}

int td_runtime_refresh_cache(size_t block_size, const char* worker_name,
                             uint32_t worker_id, int active_tasks) {
    return _runtime_refresh_worker_context(block_size, worker_name, worker_id,
                                           active_tasks);
}

int td_runtime_configure_memory(const char* segment_name, uint32_t mode,
                                uint64_t file_size, uint64_t map_size) {
    return _runtime_apply_memory_plan(segment_name, mode, file_size, map_size);
}

int td_runtime_configure_pool(uint32_t lcore_limit, uint32_t configured_lcores) {
    return _runtime_apply_pool_plan(lcore_limit, configured_lcores);
}

int td_runtime_publish_process_state(uint32_t user_proc_id, uint32_t pid,
                                     const char* proc_name) {
    return _runtime_publish_process_record(user_proc_id, pid, proc_name);
}

int td_runtime_schedule_event(int same_core, int fast_mode,
                              int destroy_in_callback) {
    return _runtime_dispatch_event_cycle(same_core, fast_mode,
                                         destroy_in_callback);
}

int td_runtime_handle_signal(int sig, void* ucontext, int hold_sem) {
    return _runtime_handle_fault_signal(sig, ucontext, hold_sem);
}

int td_runtime_shutdown_session(const char* path, int project_id,
                                size_t reserve_size) {
    return _runtime_shutdown_local_session(path, project_id, reserve_size);
}

int td_runtime_process_stream_batch(int fd, const char* journal_path,
                                    const unsigned char* wire, size_t wire_len,
                                    uint32_t queue_id,
                                    unsigned char* out, size_t out_size) {
    return _runtime_process_stream_batch(fd, journal_path, wire, wire_len,
                                         queue_id, out, out_size);
}

int td_runtime_maintain_lock_cache(const char* cache_name,
                                   uint32_t worker_id,
                                   uint32_t flags,
                                   plugin_callback_t cb) {
    return _runtime_maintain_lock_cache(cache_name, worker_id, flags, cb);
}

int td_run_runtime_maintenance(int shm_fd, const char* shm_name,
                         const unsigned char* wire, size_t wire_len,
                         unsigned char* out, size_t out_size) {
    unsigned char local_wire[sizeof(TdRuntimeMessageHeader) + 32] = {0};
    unsigned char local_out[256] = {0};
    unsigned char* response = out ? out : local_out;
    size_t response_len = out ? out_size : sizeof(local_out);
    const char* stable_name = shm_name ? shm_name : "product-namedpipe";
    TdRuntimeMessageHeader* header = (TdRuntimeMessageHeader*)local_wire;
    int rc = 0;

    if (wire && wire_len >= sizeof(TdRuntimeMessageHeader)) {
        rc |= td_runtime_apply_shared_memory_event(
            shm_fd, stable_name, wire, wire_len, response, response_len);
    }

    memset(local_wire, 0, sizeof(local_wire));
    header->magic = 0x493432u;
    header->family = 1;
    header->flags = 1;
    header->size = 128;
    header->mode = 0020000u;
    header->value = 17;
    STR_COPY(header->name, stable_name);

    rc |= td_runtime_apply_shared_memory_event(
        shm_fd, stable_name, local_wire, sizeof(local_wire),
        response, response_len);
    rc |= td_runtime_refresh_cache(128, stable_name, 42, 1);
    rc |= td_runtime_configure_memory(stable_name, 0020000u, 64, 128);
    rc |= td_runtime_configure_pool(128, 96);
    rc |= td_runtime_publish_process_state(7, (uint32_t)shm_fd, stable_name);
    rc |= td_runtime_schedule_event(1, 1, 1);
    rc |= td_runtime_handle_signal(11, response, 1);
    rc |= td_runtime_shutdown_session(stable_name, 3, 4096);
    rc |= td_runtime_process_stream_batch(shm_fd, stable_name, local_wire,
                                          sizeof(local_wire), 3,
                                          response, response_len);
    rc |= td_runtime_maintain_lock_cache(stable_name, 7, 0, NULL);

    return rc;
}

static void* _td_runtime_worker(void* arg) {
    TdRangeWorkerArgs* args = (TdRangeWorkerArgs*)arg;
    if (!args) {
        return NULL;
    }
    td_run_runtime_maintenance(args->fd, args->key, args->report,
                         args->report_len, args->out, sizeof(args->out));
    SAFE_FREE(args);
    return NULL;
}

int td_start_runtime_worker(int shm_fd, const char* shm_name) {
    TdRangeWorkerArgs* args = _td_alloc_worker_args(shm_name ? shm_name : "runtime");
    if (!args) {
        return -1;
    }
    args->fd = shm_fd;
    args->report_len = sizeof(args->report);
    if (VOS_TaskCreate("range-runtime", 0, _td_runtime_worker, args) != 0) {
        SAFE_FREE(args);
        return -1;
    }
    return 0;
}
