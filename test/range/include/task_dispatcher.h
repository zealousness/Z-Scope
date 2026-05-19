#ifndef TASK_DISPATCHER_H
#define TASK_DISPATCHER_H

#include <stddef.h>
#include "types.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Initialize the task dispatcher with specified configuration
 * 
 * This function initializes the task dispatcher system with the provided
 * configuration string. The configuration should be in JSON format and
 * contains parameters such as thread pool size, queue capacity, network
 * settings, and security policies.
 * 
 * @param config_str Configuration string in JSON format. Must contain
 *                   valid configuration parameters. The string is parsed
 *                   internally and resources are allocated accordingly.
 * @return 0 on successful initialization, -1 on failure
 * 
 * @note This function must be called before any other dispatcher functions
 * @note The configuration string should specify queue_size, thread_count,
 *       and optional network/security parameters
 * @note Memory allocated during initialization should be freed by calling
 *       td_cleanup() when the dispatcher is no longer needed
 * 
 * Example config format:
 * {
 *   "queue_size": 1024,
 *   "thread_count": 4,
 *   "network": { "timeout_ms": 5000 },
 *   "security": { "sandbox_enabled": true }
 * }
 */
int td_init(const char* config_str);

/**
 * Submit a task to the dispatcher for processing
 * 
 * Submits a task to the dispatcher's work queue. The task data is copied
 * to an internal buffer and will be processed by one of the worker threads.
 * The caller receives a task ID that can be used to track the task status.
 * 
 * @param task_data Pointer to the task data buffer. The data format depends
 *                  on the task type specified in the buffer header.
 * @param data_len Length of the task data in bytes
 * @return Task ID on success (positive integer), -1 on failure
 * 
 * @note The task data is copied internally; the caller may free the original
 *       buffer after this function returns
 * @note Supported task types: CMD_EXECUTE, FILE_PROCESS, NETWORK_REQ, CUSTOM
 * @note If the queue is full, this function will block until space is available
 * @note The task ID can be used with td_query_status() to check progress
 * 
 * Task data format (first 4 bytes = task type):
 * [type:4][flags:4][payload_length:4][payload:...]
 */
int td_submit_task(const void* task_data, size_t data_len);

/**
 * Register a plugin handler for specific task types
 * 
 * Registers a plugin that will handle tasks of a specific type or name.
 * When a task matching the plugin's criteria is submitted, the plugin's
 * handler function will be called by the dispatcher.
 * 
 * @param plugin_name Unique name for the plugin. This name is used as a
 *                    hash key for plugin lookup and must be unique.
 * @param handler_fn  Function pointer to the task handler. This function
 *                    will be called when a matching task is dispatched.
 * @return 0 on successful registration, -1 on failure
 * 
 * @note Plugin names are case-sensitive
 * @note Registering a plugin with an existing name will replace the old one
 * @note The handler function will be called from a worker thread context
 * @note Plugins can be unregistered using td_unregister_plugin()
 * 
 * Handler function signature:
 * void handler(Task* task);
 */
int td_register_plugin(const char* plugin_name, task_handler_t handler_fn);

/**
 * Execute a command through the dispatcher
 * 
 * This is a convenience function that creates and submits a command execution
 * task. The command string will be executed by the system's shell after
 * passing through the dispatcher's security checks.
 * 
 * @param command Command string to execute. The command will be parsed and
 *               validated before execution.
 * @return 0 if the command was successfully queued, -1 on failure
 * 
 * @warning This function executes system commands; ensure proper input validation
 * @note The command is executed asynchronously by a worker thread
 * @note Command output is not captured; use td_submit_task() with custom
 *       handlers if output capture is required
 * @note Security policies defined in td_init() will be applied
 * 
 * Example:
 * td_execute_command("ls -l /tmp");
 */
int td_execute_command(const char* command);

int td_send_message(int fd, const void* data, size_t len);
int td_send_status(int fd);
char* td_receive_string(int fd, size_t max_len);
int td_receive_message(int fd, char* dst, size_t dst_size);
int td_report_network_error(int error_code);
int td_handle_network_task(Task* task);
int td_serialize_task_message(const Task* task, void** buffer, size_t* len);

int td_process_control_message(const char* msg, int transport_id);
int td_manage_runtime_config(const char* text, size_t metric_count);
int td_format_and_parse_frame(const char* prefix, uint32_t id, char* out, size_t out_size);
int td_watch_connection_event(int fd, char* buffer, size_t len);
int td_configure_rules(const char* path, size_t len, size_t offset);
int td_handle_mesh_message(const char* msg, int transport_id);
int td_update_subscription(const char* topic);
int td_control_pipe(int pipe_id);
int td_handle_real_protocol_message(int fd, const char* fallback_key,
                                    unsigned char* out, size_t out_size);
int td_handle_distributed_cs_message(int listen_fd, int work_fd, int peer_protocol,
                                     unsigned char* out, size_t out_size);
int td_update_os_policy(const char* os_name, int pid, const char* proc_name,
                        const char* policy_key, int route_key, uint32_t delta);

/**
 * Query the status of a previously submitted task
 * 
 * @param task_id Task ID returned by td_submit_task()
 * @return Task status code, or -1 if task not found
 */
int td_query_status(task_id_t task_id);

/**
 * Unregister a previously registered plugin
 * 
 * @param plugin_name Name of the plugin to unregister
 * @return 0 on success, -1 if plugin not found
 */
int td_unregister_plugin(const char* plugin_name);

/**
 * Cleanup and shutdown the dispatcher
 * 
 * Waits for all pending tasks to complete, releases all allocated resources,
 * and shuts down the dispatcher system.
 * 
 * @return 0 on success, -1 on failure
 */
int td_cleanup(void);

#ifdef __cplusplus
}
#endif

#endif
