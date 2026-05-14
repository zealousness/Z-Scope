#ifndef EXECUTOR_PH
#define EXECUTOR_PH

#include "../internal/types.ph"

int _executor_init(SharedResources* resources);
int _executor_execute_task(Task* task);
int _executor_execute_command(const char* command);
int _executor_process_file(const char* filepath);
int _executor_handle_network_request(Task* task);
int _executor_cleanup_resources(SharedResources* resources);
void _executor_log_message(const char* message);
int _executor_validate_command(const char* command);
char* _executor_build_command_args(const char* cmd);

#endif
